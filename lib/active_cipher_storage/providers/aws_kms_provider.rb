module ActiveCipherStorage
  module Providers
    class AwsKmsProvider < Base
      include KeyUtils

      PROVIDER_ID = "aws_kms"

      def initialize(key_id: nil, region: nil, encryption_context: {}, client: nil)
        @key_id             = key_id || ENV.fetch("AWS_KMS_KEY_ID") {
          raise Errors::ProviderError,
                "AwsKmsProvider requires :key_id or AWS_KMS_KEY_ID env var"
        }
        @region             = region
        @encryption_context = encryption_context || {}
        @client_override    = client
      end

      def provider_id = PROVIDER_ID
      def key_id      = @key_id

      def generate_data_key
        resp = kms_client.generate_data_key(
          key_id:             @key_id,
          key_spec:           "AES_256",
          encryption_context: @encryption_context
        )
        { plaintext_key: resp.plaintext.dup, encrypted_key: resp.ciphertext_blob.dup }
      rescue Aws::KMS::Errors::ServiceError => e
        raise Errors::KeyManagementError, "KMS GenerateDataKey failed: #{e.message}"
      ensure
        # AWS SDK may retain a reference to resp.plaintext; zero our copy too.
        resp&.plaintext&.then { |k| zero_bytes!(k) }
      end

      def decrypt_data_key(encrypted_key)
        resp = kms_client.decrypt(
          ciphertext_blob:    encrypted_key,
          encryption_context: @encryption_context
        )
        resp.plaintext.dup
      rescue Aws::KMS::Errors::InvalidCiphertextException,
             Aws::KMS::Errors::IncorrectKeyException => e
        raise Errors::KeyManagementError,
              "KMS Decrypt failed — wrong key or tampered DEK: #{e.message}"
      rescue Aws::KMS::Errors::ServiceError => e
        raise Errors::KeyManagementError, "KMS Decrypt failed: #{e.message}"
      ensure
        resp&.plaintext&.then { |k| zero_bytes!(k) }
      end

      # Encrypts an existing plaintext DEK using KMS Encrypt.
      # Prefer rotate_data_key (ReEncrypt) when both old and new providers are AWS KMS,
      # because ReEncrypt keeps the plaintext DEK entirely within KMS.
      def wrap_data_key(plaintext_dek)
        resp = kms_client.encrypt(
          key_id:             @key_id,
          plaintext:          plaintext_dek,
          encryption_context: @encryption_context
        )
        resp.ciphertext_blob.dup
      rescue Aws::KMS::Errors::ServiceError => e
        raise Errors::KeyManagementError, "KMS Encrypt failed: #{e.message}"
      end

      # Uses KMS ReEncrypt — the plaintext DEK never leaves KMS.
      def rotate_data_key(encrypted_key, destination_key_id: nil)
        resp = kms_client.re_encrypt(
          ciphertext_blob:                encrypted_key,
          source_encryption_context:      @encryption_context,
          destination_key_id:             destination_key_id || @key_id,
          destination_encryption_context: @encryption_context
        )
        resp.ciphertext_blob.dup
      rescue Aws::KMS::Errors::ServiceError => e
        raise Errors::KeyManagementError, "KMS ReEncrypt failed: #{e.message}"
      end

      private

      def kms_client
        @kms_client ||= begin
          require "aws-sdk-kms"
          @client_override || Aws::KMS::Client.new(**{ region: @region }.compact)
        end
      rescue LoadError
        raise Errors::ProviderError, "aws-sdk-kms is required: add it to your Gemfile"
      end
    end
  end
end
