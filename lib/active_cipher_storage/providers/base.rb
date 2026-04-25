module ActiveCipherStorage
  module Providers
    class Base
      # Returns { plaintext_key: String (32 bytes), encrypted_key: String }
      def generate_data_key
        raise NotImplementedError, "#{self.class}#generate_data_key is not implemented"
      end

      # Returns the plaintext DEK (32 bytes). Caller must zero it after use.
      def decrypt_data_key(encrypted_key)
        raise NotImplementedError, "#{self.class}#decrypt_data_key is not implemented"
      end

      # Wraps an existing plaintext DEK under this provider's master key.
      # Used during key rotation to re-protect a DEK without re-encrypting the file.
      def wrap_data_key(plaintext_dek)
        raise NotImplementedError, "#{self.class}#wrap_data_key is not implemented"
      end

      # Short ASCII string embedded in every encrypted file header.
      def provider_id
        raise NotImplementedError, "#{self.class}#provider_id is not implemented"
      end

      # Stable identifier for the specific key material in use (e.g. CMK ARN,
      # env var name). Stored in blob metadata for rotation queries.
      # Returns nil for providers where key identity is not meaningful.
      def key_id
        nil
      end

      def rotate_data_key(encrypted_key)
        raise Errors::UnsupportedOperation,
              "#{self.class} does not support key rotation"
      end
    end
  end
end
