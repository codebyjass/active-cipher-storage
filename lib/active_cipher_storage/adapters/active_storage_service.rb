module ActiveCipherStorage
  module Adapters
    # Active Storage service that transparently encrypts uploads and decrypts
    # downloads. Configure in config/storage.yml:
    #
    #   encrypted_s3:
    #     service: ActiveCipherStorage
    #     wrapped_service: s3
    #
    # Backward compatibility
    # ───────────────────────
    # Blobs uploaded before encryption was enabled are detected via the "ACS\x01"
    # magic header.  If the magic is absent the raw bytes are returned as-is,
    # so the service is safe to enable on a bucket with existing plaintext objects.
    #
    # Range requests (download_chunk) must decrypt the full blob first because
    # GCM authentication requires the complete ciphertext before any plaintext
    # can be safely released.
    class ActiveStorageService
      BlobRef = Struct.new(:key)

      attr_reader :inner

      def self.build(configurator:, wrapped_service:, **kwargs)
        new(wrapped_service: configurator.build(wrapped_service), **kwargs)
      end

      def initialize(wrapped_service:, **_kwargs)
        @inner         = wrapped_service
        @cipher        = Cipher.new
        @stream_cipher = StreamCipher.new
      end

      def upload(key, io, checksum: nil, content_type: nil, filename: nil,
                 disposition: nil, custom_metadata: {})
        @inner.upload(key, encrypt_io(io),
          checksum:        nil,  # checksum is over plaintext; skip for ciphertext
          content_type:    "application/octet-stream",
          filename:        filename,
          disposition:     disposition,
          custom_metadata: custom_metadata)

        BlobMetadata.write(key, ActiveCipherStorage.configuration.provider)
      end

      def download(key, &block)
        raw = collect_download(key)

        # Legacy plaintext blob — no magic header present.
        return (block ? yield(raw) : raw) unless cipher_payload?(raw)

        plaintext = decrypt_raw(raw)
        block ? yield(plaintext) : plaintext
      end

      def download_chunk(key, range)
        download(key).b[range]
      end

      # Used by KeyRotation to fetch raw ciphertext without decrypting.
      def download_raw(key)
        collect_download(key)
      end

      # Used by KeyRotation to overwrite a blob's bytes without re-encrypting.
      def upload_raw(key, io)
        @inner.upload(key, io, content_type: "application/octet-stream")
      end

      # Re-wraps the DEK in a single blob's header under new_provider without
      # decrypting or re-encrypting the file body.
      def rekey(key, old_provider:, new_provider:)
        KeyRotation.rotate_blob(
          BlobRef.new(key),
          old_provider: old_provider,
          new_provider: new_provider,
          service:      self
        )
      end

      def delete(key)          = @inner.delete(key)
      def delete_prefixed(pfx) = @inner.delete_prefixed(pfx)
      def exist?(key)          = @inner.exist?(key)

      def url(key, expires_in:, filename:, content_type:, disposition:, **)
        @inner.url(key, expires_in: expires_in, filename: filename,
                        content_type: content_type, disposition: disposition)
      end

      def url_for_direct_upload(*)
        raise Errors::UnsupportedOperation,
              "Direct uploads bypass encryption — use server-side upload instead"
      end

      def headers_for_direct_upload(*) = {}

      private

      def encrypt_io(io)
        config = ActiveCipherStorage.configuration
        if io.respond_to?(:size) && io.size && io.size > config.chunk_size
          @stream_cipher.encrypt_to_io(io)
        else
          StringIO.new(@cipher.encrypt(io))
        end
      end

      def collect_download(key)
        buffer = StringIO.new("".b)
        result = @inner.download(key) { |chunk| buffer.write(chunk) }
        # Some services return data instead of yielding; handle both.
        buffer.write(result.b) if buffer.pos.zero? && result.is_a?(String)
        buffer.string
      end

      def decrypt_raw(raw)
        io     = StringIO.new(raw.b)
        header = Format.read_header(io)
        io.rewind
        header.chunked ? @stream_cipher.decrypt_to_io(io).read
                       : @cipher.decrypt(io)
      end

      def cipher_payload?(data)
        data.b.start_with?(Format::MAGIC)
      end
    end
  end
end
