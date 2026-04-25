require "openssl"
require "securerandom"
require "base64"

module ActiveCipherStorage
  module Providers
    class EnvProvider < Base
      include KeyUtils

      PROVIDER_ID     = "env"
      WRAP_ALGO       = "aes-256-gcm"
      MASTER_KEY_SIZE = 32
      WRAP_IV_SIZE    = 12
      WRAP_TAG_SIZE   = 16

      def initialize(env_var: "ACTIVE_CIPHER_MASTER_KEY", old_env_var: nil)
        @env_var     = env_var
        @old_env_var = old_env_var
      end

      def provider_id = PROVIDER_ID
      def key_id      = @env_var

      def generate_data_key
        master = read_master_key(@env_var)
        dek    = SecureRandom.random_bytes(Cipher::KEY_SIZE)
        { plaintext_key: dek, encrypted_key: wrap_key(dek, master) }
      ensure
        zero_bytes!(master)
      end

      def decrypt_data_key(encrypted_key)
        master = read_master_key(@env_var)
        unwrap_key(encrypted_key, master)
      ensure
        zero_bytes!(master)
      end

      def wrap_data_key(plaintext_dek)
        master = read_master_key(@env_var)
        wrap_key(plaintext_dek, master)
      ensure
        zero_bytes!(master)
      end

      def rotate_data_key(encrypted_key, old_provider: nil)
        source = old_provider || begin
          raise Errors::UnsupportedOperation,
                "Supply :old_provider to rotate via EnvProvider" unless @old_env_var
          EnvProvider.new(env_var: @old_env_var)
        end

        plaintext_dek = source.decrypt_data_key(encrypted_key)
        new_master    = read_master_key(@env_var)
        wrap_key(plaintext_dek, new_master)
      ensure
        zero_bytes!(plaintext_dek)
        zero_bytes!(new_master)
      end

      private

      # Wrapped DEK: [12 IV][32 ciphertext][16 auth-tag] = 60 bytes
      def wrap_key(dek, master)
        iv     = SecureRandom.random_bytes(WRAP_IV_SIZE)
        c      = new_cipher(:encrypt, master, iv)
        ct     = c.update(dek) + c.final
        iv + ct + c.auth_tag
      end

      def unwrap_key(wrapped, master)
        expected = WRAP_IV_SIZE + Cipher::KEY_SIZE + WRAP_TAG_SIZE
        unless wrapped.bytesize == expected
          raise Errors::InvalidFormat, "Wrapped DEK has unexpected size #{wrapped.bytesize}"
        end

        iv  = wrapped.byteslice(0, WRAP_IV_SIZE)
        ct  = wrapped.byteslice(WRAP_IV_SIZE, Cipher::KEY_SIZE)
        tag = wrapped.byteslice(-WRAP_TAG_SIZE, WRAP_TAG_SIZE)

        new_cipher(:decrypt, master, iv, tag).then { |c| c.update(ct) + c.final }
      rescue OpenSSL::Cipher::CipherError
        raise Errors::KeyManagementError,
              "Master-key authentication failed — wrong key or tampered DEK"
      end

      def new_cipher(mode, key, iv, auth_tag = nil)
        c = OpenSSL::Cipher.new(WRAP_ALGO)
        mode == :encrypt ? c.encrypt : c.decrypt
        c.key      = key
        c.iv       = iv
        c.auth_tag = auth_tag if auth_tag
        c.auth_data = ""
        c
      end

      def read_master_key(var_name)
        encoded = ENV.fetch(var_name) do
          raise Errors::ProviderError,
                "Environment variable #{var_name.inspect} is not set. " \
                "Generate one with: ruby -rsecurerandom -e " \
                "'puts Base64.strict_encode64(SecureRandom.bytes(32))'"
        end

        key = begin
          Base64.strict_decode64(encoded)
        rescue ArgumentError
          raise Errors::ProviderError,
                "#{var_name} must be Base64-encoded (strict, no line breaks)"
        end

        unless key.bytesize == MASTER_KEY_SIZE
          raise Errors::ProviderError,
                "#{var_name} must decode to exactly #{MASTER_KEY_SIZE} bytes " \
                "(got #{key.bytesize})"
        end

        key
      end
    end
  end
end
