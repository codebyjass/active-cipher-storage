require "openssl"
require "securerandom"
require "concurrent"

module ActiveCipherStorage
  # Session-based multipart upload where the caller sends plaintext chunks
  # across separate HTTP requests. Each chunk is encrypted as an ACS frame
  # before being accumulated and flushed to S3.
  #
  # S3 requires every part except the last to be >= 5 MiB. Chunks can be any
  # size — this class buffers encrypted frames and flushes S3 parts only when
  # the buffer reaches chunk_size (default 5 MiB).
  #
  # Flow:
  #   uploader = EncryptedMultipartUpload.new(s3_client:, bucket:)
  #   session_id = uploader.initiate(key: "uploads/doc.pdf")
  #   uploader.upload_part(session_id:, chunk_io: io1)   # repeat per chunk
  #   uploader.complete(session_id:)
  #
  # Session state is kept in an in-memory store by default.
  # For multi-process deployments pass store: Rails.cache (or any object
  # that responds to read/write/delete with the same keyword signatures).
  class EncryptedMultipartUpload
    include KeyUtils

    SESSION_TTL = 24 * 3600

    def initialize(s3_client:, bucket:, config: nil, store: nil)
      @s3     = s3_client
      @bucket = bucket
      @config = config || ActiveCipherStorage.configuration
      @store  = store || MemorySessionStore.new
      @config.validate!
    end

    # Starts a new multipart upload. Returns an opaque session_id.
    def initiate(key:, metadata: {})
      dek_bundle = @config.provider.generate_data_key
      s3_opts    = { content_type: "application/octet-stream" }
      s3_opts[:metadata] = metadata unless metadata.empty?
      upload_id  = @s3.create_multipart_upload(bucket: @bucket, key: key, **s3_opts).upload_id

      header_io = StringIO.new("".b)
      Format.write_header(header_io, Format::Header.new(
        version:       Format::VERSION,
        algorithm:     Format::ALGO_AES256GCM,
        chunked:       true,
        chunk_size:    @config.chunk_size,
        provider_id:   @config.provider.provider_id,
        encrypted_dek: dek_bundle[:encrypted_key]
      ))

      session_id = SecureRandom.urlsafe_base64(24)
      save_session(session_id, {
        upload_id:     upload_id,
        key:           key,
        encrypted_dek: dek_bundle[:encrypted_key],
        seq:           0,
        parts:         [],
        pending:       header_io.string
      })
      session_id
    ensure
      zero_bytes!(dek_bundle&.dig(:plaintext_key))
    end

    # Encrypts a chunk and buffers it. Flushes complete S3 parts (>= chunk_size)
    # automatically. Returns { status: :ok, parts_uploaded: N }.
    def upload_part(session_id:, chunk_io:)
      session   = load_session!(session_id)
      plaintext = chunk_io.read.b
      session[:seq] += 1

      session[:pending] = (session[:pending] +
        build_frame(plaintext, session[:encrypted_dek], session[:seq])).b

      while session[:pending].bytesize >= @config.chunk_size
        flush_part(session, session[:pending].byteslice(0, @config.chunk_size))
        session[:pending] = (session[:pending].byteslice(@config.chunk_size..) || "".b).b
      end

      save_session(session_id, session)
      { status: :ok, parts_uploaded: session[:parts].length }
    ensure
      zero_bytes!(plaintext)
    end

    # Writes a zero-byte FINAL_SEQ sentinel frame, flushes remaining bytes as
    # the last S3 part, and completes the multipart upload.
    # Returns { status: :completed, key:, parts_count: }.
    def complete(session_id:)
      session = load_session!(session_id)

      # Zero-byte final frame signals end-of-stream to the decryptor.
      session[:pending] = (session[:pending] +
        build_frame("".b, session[:encrypted_dek], Format::FINAL_SEQ)).b

      flush_part(session, session[:pending]) unless session[:pending].empty?
      session[:pending] = "".b

      @s3.complete_multipart_upload(
        bucket: @bucket, key: session[:key],
        upload_id: session[:upload_id],
        multipart_upload: { parts: session[:parts] }
      )
      @store.delete(session_id)
      { status: :completed, key: session[:key], parts_count: session[:parts].length }
    rescue StandardError
      abort_s3(session)
      @store.delete(session_id)
      raise
    end

    # Aborts the in-progress S3 multipart upload and discards the session.
    def abort(session_id:)
      session = @store.read(session_id)
      return unless session
      abort_s3(session)
      @store.delete(session_id)
    end

    private

    def build_frame(plaintext, encrypted_dek, seq)
      dek = @config.provider.decrypt_data_key(encrypted_dek)
      iv  = SecureRandom.random_bytes(Format::IV_SIZE)
      c   = chunk_cipher(dek, iv, seq)
      ct  = plaintext.empty? ? c.final : (c.update(plaintext) + c.final)
      buf = StringIO.new("".b)
      Format.write_chunk(buf, seq: seq, iv: iv, ciphertext: ct, auth_tag: c.auth_tag)
      buf.string
    ensure
      zero_bytes!(dek)
    end

    def flush_part(session, bytes)
      pn   = session[:parts].length + 1
      etag = @s3.upload_part(bucket: @bucket, key: session[:key],
                              upload_id: session[:upload_id],
                              part_number: pn, body: bytes).etag
      session[:parts] << { part_number: pn, etag: etag }
    end

    def abort_s3(session)
      @s3.abort_multipart_upload(bucket: @bucket, key: session[:key],
                                  upload_id: session[:upload_id])
    rescue StandardError
      nil # best-effort abort
    end

    def chunk_cipher(key, iv, seq)
      c = OpenSSL::Cipher.new(Cipher::OPENSSL_ALGO)
      c.encrypt
      c.key       = key
      c.iv        = iv
      c.auth_data = [seq].pack("N")
      c
    end

    def load_session!(id)
      @store.read(id) or
        raise Errors::Error, "Upload session not found or expired: #{id}"
    end

    def save_session(id, data)
      @store.write(id, data, expires_in: SESSION_TTL)
    end

    # Thread-safe in-memory session store backed by Concurrent::Map.
    # Replace with a Rails.cache wrapper for multi-process deployments.
    class MemorySessionStore
      def initialize
        @data = Concurrent::Map.new
      end

      def read(id)
        entry = @data[id]
        return nil unless entry
        return nil if entry[:expires_at] && Time.now.to_i > entry[:expires_at]
        entry[:data]
      end

      def write(id, data, expires_in: nil)
        @data[id] = { data: data, expires_at: expires_in && Time.now.to_i + expires_in }
      end

      def delete(id) = @data.delete(id)
    end
  end
end
