module ActiveCipherStorage
  module Errors
    # Base class for all gem errors.
    class Error < StandardError; end

    # Raised when the binary header is malformed or the magic bytes are wrong.
    class InvalidFormat < Error; end

    # Raised when GCM authentication tag verification fails (data tampered or
    # wrong key). Deliberately vague to avoid oracle attacks.
    class DecryptionError < Error; end

    # Raised when a required KMS provider is not configured.
    class ProviderError < Error; end

    # Raised when the KMS provider cannot wrap/unwrap a data key.
    class KeyManagementError < ProviderError; end

    # Raised when a caller tries to use a feature the active provider doesn't
    # implement (e.g. key rotation on EnvProvider).
    class UnsupportedOperation < Error; end
  end

  # Convenience aliases at the top-level namespace.
  Error              = Errors::Error
  InvalidFormat      = Errors::InvalidFormat
  DecryptionError    = Errors::DecryptionError
  ProviderError      = Errors::ProviderError
  KeyManagementError = Errors::KeyManagementError
  UnsupportedOperation = Errors::UnsupportedOperation
end
