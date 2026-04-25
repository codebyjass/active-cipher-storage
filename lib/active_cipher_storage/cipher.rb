require "openssl"
require "securerandom"
require "stringio"

module ActiveCipherStorage
  class Cipher
    include KeyUtils

    OPENSSL_ALGO = "aes-256-gcm"
    KEY_SIZE     = 32

    def initialize(config = ActiveCipherStorage.configuration)
      config.validate!
      @config   = config
      @provider = config.provider
    end

    def encrypt(io)
      plaintext  = io.read.b
      dek_bundle = @provider.generate_data_key
      key        = dek_bundle.fetch(:plaintext_key)
      iv         = SecureRandom.random_bytes(Format::IV_SIZE)

      c          = build_cipher(:encrypt, key, iv)
      ciphertext = c.update(plaintext) + c.final
      auth_tag   = c.auth_tag

      out = StringIO.new("".b)
      Format.write_header(out, header(dek_bundle, chunked: false))
      out.write(iv)
      out.write(ciphertext)
      out.write(auth_tag)
      out.string
    ensure
      zero_bytes!(key)
      zero_bytes!(plaintext)
    end

    def decrypt(encrypted_data)
      io     = to_binary_io(encrypted_data)
      header = Format.read_header(io)
      raise Errors::InvalidFormat, "Payload is chunked; use StreamCipher#decrypt" if header.chunked

      key       = @provider.decrypt_data_key(header.encrypted_dek)
      iv        = io.read(Format::IV_SIZE)
      tail      = drain(io)
      ciphertext = tail.byteslice(0, tail.bytesize - Format::AUTH_TAG_SIZE)
      auth_tag   = tail.byteslice(-Format::AUTH_TAG_SIZE, Format::AUTH_TAG_SIZE)

      c = build_cipher(:decrypt, key, iv, auth_tag)
      c.update(ciphertext) + c.final
    rescue OpenSSL::Cipher::CipherError
      raise Errors::DecryptionError, "Authentication failed — ciphertext may be tampered or the key is wrong"
    ensure
      zero_bytes!(key)
    end

    private

    def build_cipher(mode, key, iv, auth_tag = nil)
      c = OpenSSL::Cipher.new(OPENSSL_ALGO)
      mode == :encrypt ? c.encrypt : c.decrypt
      c.key      = key
      c.iv       = iv
      c.auth_tag = auth_tag if auth_tag
      c.auth_data = ""  # required by GCM even when empty
      c
    end

    def header(dek_bundle, chunked:)
      Format::Header.new(
        version:       Format::VERSION,
        algorithm:     Format::ALGO_AES256GCM,
        chunked:       chunked,
        chunk_size:    0,
        provider_id:   @provider.provider_id,
        encrypted_dek: dek_bundle.fetch(:encrypted_key)
      )
    end

    def to_binary_io(data)
      case data
      when StringIO then data.tap(&:rewind)
      when IO       then data
      else StringIO.new(data.to_s.b)
      end
    end

    def drain(io)
      buf = "".b
      while (chunk = io.read(65_536))
        buf << chunk
      end
      buf
    end
  end
end
