require "stringio"

module ActiveCipherStorage
  module Adapters
    class S3Adapter
      include KeyUtils

      DEFAULT_MULTIPART_THRESHOLD = 100 * 1024 * 1024

      def initialize(bucket:, region: nil, multipart_threshold: DEFAULT_MULTIPART_THRESHOLD,
                     s3_client: nil, config: nil)
        @bucket              = bucket
        @region              = region
        @multipart_threshold = multipart_threshold
        @client_override     = s3_client
        @config              = config || ActiveCipherStorage.configuration
        @config.validate!
      end

      def put_encrypted(key, io, **options)
        large_file?(io) ? multipart_put(key, io, **options) : single_put(key, io, **options)
      end

      def get_decrypted(key)
        resp = s3.get_object(bucket: @bucket, key: key)
        decrypt_io(StringIO.new(resp.body.read.b))
      end

      # Streams decrypted plaintext from S3 without buffering the whole object.
      # Yields each decrypted plaintext chunk as it becomes available.
      # Safe for multi-gigabyte files: memory usage is bounded by chunk_size.
      def stream_decrypted(key, &block)
        raise ArgumentError, "stream_decrypted requires a block" unless block_given?

        decryptor = StreamingDecryptor.new(@config)
        s3.get_object(bucket: @bucket, key: key) do |s3_chunk|
          decryptor.push(s3_chunk.b, &block)
        end
        decryptor.finish!
      end

      def presigned_url(key, expires_in: 3600)
        Aws::S3::Presigner.new(client: s3)
                          .presigned_url(:get_object, bucket: @bucket, key: key,
                                         expires_in: expires_in)
      end

      def exist?(key)
        s3.head_object(bucket: @bucket, key: key)
        true
      rescue Aws::S3::Errors::NotFound, Aws::S3::Errors::NoSuchKey
        false
      end

      def delete(key)
        s3.delete_object(bucket: @bucket, key: key)
      end

      private

      def single_put(key, io, **options)
        s3.put_object(bucket: @bucket, key: key,
                      body: Cipher.new(@config).encrypt(io),
                      **upload_options(options))
      end

      def multipart_put(key, io, **options)
        validate_multipart_chunk_size!
        upload_id = s3.create_multipart_upload(bucket: @bucket, key: key,
                                               **upload_options(options)).upload_id
        parts = stream_multipart_parts(key, io, upload_id)
        s3.complete_multipart_upload(bucket: @bucket, key: key, upload_id: upload_id,
                                     multipart_upload: { parts: parts })
      rescue StandardError
        abort_multipart_upload(key, upload_id)
        raise
      end

      def stream_multipart_parts(key, input_io, upload_id)
        dek_bundle    = @config.provider.generate_data_key
        plaintext_dek = dek_bundle.fetch(:plaintext_key)
        parts         = []
        part_number   = 0

        # Buffer header + chunks together. S3 requires parts >= 5 MiB except the
        # last, so we flush only when the buffer reaches chunk_size or at EOF.
        buffer = StringIO.new("".b)
        Format.write_header(buffer, Format::Header.new(
          version:       Format::VERSION,
          algorithm:     Format::ALGO_AES256GCM,
          chunked:       true,
          chunk_size:    @config.chunk_size,
          provider_id:   @config.provider.provider_id,
          encrypted_dek: dek_bundle.fetch(:encrypted_key)
        ))

        seq  = 0
        done = false
        until done
          chunk     = input_io.read(@config.chunk_size) || "".b
          done      = chunk.bytesize < @config.chunk_size
          seq      += 1
          frame_seq = done ? Format::FINAL_SEQ : seq
          iv        = SecureRandom.random_bytes(Format::IV_SIZE)

          c  = build_chunk_cipher(plaintext_dek, iv, frame_seq)
          ct = chunk.empty? ? c.final : (c.update(chunk.b) + c.final)
          Format.write_chunk(buffer, seq: frame_seq, iv: iv, ciphertext: ct, auth_tag: c.auth_tag)

          next unless buffer.pos >= @config.chunk_size || done

          buffer.rewind
          part_number += 1
          etag = s3.upload_part(bucket: @bucket, key: key, upload_id: upload_id,
                                 part_number: part_number, body: buffer.read).etag
          parts  << { part_number: part_number, etag: etag }
          buffer = StringIO.new("".b)
        end

        parts
      ensure
        zero_bytes!(plaintext_dek)
      end

      def decrypt_io(io)
        header = Format.read_header(io)
        io.rewind
        header.chunked ? StreamCipher.new(@config).decrypt_to_io(io)
                       : StringIO.new(Cipher.new(@config).decrypt(io))
      end

      def large_file?(io)
        size = io.respond_to?(:size) ? io.size : nil
        size&.> @multipart_threshold
      end

      def upload_options(opts)
        { content_type: "application/octet-stream" }.merge(opts.slice(:metadata, :tagging))
      end

      def build_chunk_cipher(key, iv, seq)
        c = OpenSSL::Cipher.new(Cipher::OPENSSL_ALGO)
        c.encrypt
        c.key      = key
        c.iv       = iv
        c.auth_data = [seq].pack("N")
        c
      end

      def validate_multipart_chunk_size!
        min_size = Configuration::MINIMUM_S3_MULTIPART_PART_SIZE
        return if @config.chunk_size >= min_size

        raise ArgumentError,
              "chunk_size must be at least 5 MiB for S3 multipart uploads"
      end

      def s3
        @s3 ||= begin
          require "aws-sdk-s3"
          @client_override || Aws::S3::Client.new(**{ region: @region }.compact)
        end
      rescue LoadError
        raise Errors::ProviderError, "aws-sdk-s3 is required: add it to your Gemfile"
      end

      def abort_multipart_upload(key, upload_id)
        return unless upload_id

        s3.abort_multipart_upload(bucket: @bucket, key: key, upload_id: upload_id)
      rescue StandardError => abort_error
        @config.logger.warn(
          "[ActiveCipherStorage] Could not abort multipart upload #{upload_id}: #{abort_error.message}"
        )
      end

      # Accumulates bytes from a streaming S3 response, parses ACS frames as
      # they arrive, and yields each decrypted plaintext chunk.
      # Frame layout: seq(4) + iv(12) + ct_len(4) + ciphertext(ct_len) + auth_tag(16).
      class StreamingDecryptor
        include KeyUtils

        FRAME_PREFIX_SIZE = 4 + Format::IV_SIZE + 4  # 20 bytes to determine ct_len

        def initialize(config)
          @config      = config
          @buffer      = "".b
          @dek         = nil
          @header_done = false
          @done        = false
          @expected_seq = 1
        end

        def push(bytes, &block)
          if @done
            raise Errors::InvalidFormat, "Trailing bytes after final frame" unless bytes.empty?

            return
          end

          @buffer += bytes.b
          try_parse_header unless @header_done
          drain_frames(&block) if @header_done
        end

        def finish!
          raise Errors::InvalidFormat, "Stream ended before final frame" unless @done
          raise Errors::InvalidFormat, "Trailing bytes after final frame" unless @buffer.empty?
        ensure
          zero_bytes!(@dek)
        end

        private

        def try_parse_header
          return if @buffer.bytesize < Format::MAGIC.bytesize

          unless @buffer.start_with?(Format::MAGIC)
            raise Errors::InvalidFormat, "Invalid magic bytes"
          end

          io     = StringIO.new(@buffer)
          header = Format.read_header(io)
          raise Errors::InvalidFormat, "Payload is not chunked; use #get_decrypted" unless header.chunked

          @dek   = @config.provider.decrypt_data_key(header.encrypted_dek)
          @buffer      = (@buffer.byteslice(io.pos..) || "".b).b
          @header_done = true
        rescue Errors::InvalidFormat => e
          raise unless e.message.start_with?("Unexpected end of stream") && @buffer.bytesize <= 8192

          # Need more bytes; keep buffering.
        end

        def drain_frames(&block)
          until @done
            break if @buffer.bytesize < FRAME_PREFIX_SIZE
            ct_len     = @buffer.byteslice(16, 4).unpack1("N")
            frame_size = FRAME_PREFIX_SIZE + ct_len + Format::AUTH_TAG_SIZE
            break if @buffer.bytesize < frame_size

            frame   = Format.read_chunk(StringIO.new(@buffer.byteslice(0, frame_size)))
            @buffer = (@buffer.byteslice(frame_size..) || "".b).b

            validate_frame_sequence!(frame[:seq])
            plaintext = decrypt_frame(frame)
            block.call(plaintext) unless plaintext.empty?
            @done = (frame[:seq] == Format::FINAL_SEQ)
            @expected_seq += 1 unless @done
          end
        end

        def validate_frame_sequence!(seq)
          return if [Format::FINAL_SEQ, @expected_seq].include?(seq)

          raise Errors::InvalidFormat,
                "Unexpected chunk sequence: expected #{@expected_seq}, got #{seq}"
        end

        def decrypt_frame(frame)
          c = OpenSSL::Cipher.new(Cipher::OPENSSL_ALGO)
          c.decrypt
          c.key       = @dek
          c.iv        = frame[:iv]
          c.auth_tag  = frame[:auth_tag]
          c.auth_data = [frame[:seq]].pack("N")
          ct = frame[:ciphertext]
          ct.empty? ? c.final : (c.update(ct) + c.final)
        rescue OpenSSL::Cipher::CipherError
          raise Errors::DecryptionError,
                "Authentication failed on chunk seq=#{frame[:seq]} — data may be tampered"
        end
      end
    end
  end
end
