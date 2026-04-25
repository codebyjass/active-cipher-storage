require "openssl"
require "securerandom"

module ActiveCipherStorage
  class StreamCipher
    include KeyUtils

    def initialize(config = ActiveCipherStorage.configuration)
      config.validate!
      @config     = config
      @provider   = config.provider
      @chunk_size = config.chunk_size
    end

    def encrypt(input_io, output_io)
      dek_bundle = @provider.generate_data_key
      key        = dek_bundle.fetch(:plaintext_key)

      Format.write_header(output_io, Format::Header.new(
        version:       Format::VERSION,
        algorithm:     Format::ALGO_AES256GCM,
        chunked:       true,
        chunk_size:    @chunk_size,
        provider_id:   @provider.provider_id,
        encrypted_dek: dek_bundle.fetch(:encrypted_key)
      ))

      seq  = 0
      done = false
      until done
        plaintext = input_io.read(@chunk_size) || "".b
        done      = plaintext.bytesize < @chunk_size
        seq      += 1
        frame_seq = done ? Format::FINAL_SEQ : seq
        iv        = SecureRandom.random_bytes(Format::IV_SIZE)
        ct, tag   = encrypt_chunk(plaintext, key, iv, frame_seq)
        Format.write_chunk(output_io, seq: frame_seq, iv: iv, ciphertext: ct, auth_tag: tag)
      end

      seq
    ensure
      zero_bytes!(key)
    end

    def decrypt(input_io, output_io)
      header = Format.read_header(input_io)
      raise Errors::InvalidFormat, "Payload is not chunked; use Cipher#decrypt" unless header.chunked

      key = @provider.decrypt_data_key(header.encrypted_dek)
      expected_seq = 1
      loop do
        frame = Format.read_chunk(input_io)
        raise Errors::InvalidFormat, "Unexpected end of stream — missing final frame" if frame.nil?

        validate_frame_sequence!(frame[:seq], expected_seq)
        output_io.write(decrypt_chunk(frame[:ciphertext], key, frame[:iv], frame[:auth_tag], frame[:seq]))
        break if frame[:seq] == Format::FINAL_SEQ

        expected_seq += 1
      end

      ensure_no_trailing_bytes!(input_io)
    ensure
      zero_bytes!(key)
    end

    def encrypt_to_io(io)
      out = StringIO.new("".b)
      encrypt(io, out)
      out.rewind
      out
    end

    def decrypt_to_io(io)
      out = StringIO.new("".b)
      decrypt(io, out)
      out.rewind
      out
    end

    private

    def encrypt_chunk(plaintext, key, iv, seq)
      c   = build_cipher(:encrypt, key, iv, nil, seq)
      # OpenSSL raises "data must not be empty" on update(""); call final directly.
      ct  = plaintext.empty? ? c.final : (c.update(plaintext.b) + c.final)
      [ct, c.auth_tag]
    end

    def decrypt_chunk(ciphertext, key, iv, auth_tag, seq)
      c = build_cipher(:decrypt, key, iv, auth_tag, seq)
      ciphertext.empty? ? c.final : (c.update(ciphertext) + c.final)
    rescue OpenSSL::Cipher::CipherError
      raise Errors::DecryptionError,
            "Authentication failed on chunk seq=#{seq} — data may be tampered"
    end

    def validate_frame_sequence!(seq, expected_seq)
      return if seq == Format::FINAL_SEQ || seq == expected_seq

      raise Errors::InvalidFormat,
            "Unexpected chunk sequence: expected #{expected_seq}, got #{seq}"
    end

    def ensure_no_trailing_bytes!(input_io)
      trailing = input_io.read(1)
      return if trailing.nil? || trailing.empty?

      raise Errors::InvalidFormat, "Trailing bytes after final frame"
    end

    def build_cipher(mode, key, iv, auth_tag, seq)
      c = OpenSSL::Cipher.new(Cipher::OPENSSL_ALGO)
      mode == :encrypt ? c.encrypt : c.decrypt
      c.key      = key
      c.iv       = iv
      c.auth_tag = auth_tag if auth_tag
      c.auth_data = [seq].pack("N")  # seq as AAD prevents chunk reordering attacks
      c
    end
  end
end
