require "openssl"
require "securerandom"
require "base64"
require "stringio"
require "concurrent"

require_relative "active_cipher_storage/version"
require_relative "active_cipher_storage/errors"
require_relative "active_cipher_storage/key_utils"
require_relative "active_cipher_storage/format"
require_relative "active_cipher_storage/configuration"
require_relative "active_cipher_storage/providers/base"
require_relative "active_cipher_storage/providers/env_provider"
require_relative "active_cipher_storage/providers/aws_kms_provider"
require_relative "active_cipher_storage/cipher"
require_relative "active_cipher_storage/stream_cipher"
require_relative "active_cipher_storage/adapters/s3_adapter"
require_relative "active_cipher_storage/adapters/active_storage_service"
require_relative "active_cipher_storage/blob_metadata"
require_relative "active_cipher_storage/key_rotation"
require_relative "active_cipher_storage/multipart_upload"

# Rails Engine wires the service into ActiveStorage's service registry.
require_relative "active_cipher_storage/engine" if defined?(Rails)

module ActiveCipherStorage
  @config_mutex  = Mutex.new
  @configuration = Configuration.new

  class << self
    def configuration
      @configuration
    end

    def configure
      @config_mutex.synchronize { yield @configuration }
    end

    def reset_configuration!
      @config_mutex.synchronize { @configuration = Configuration.new }
    end
  end
end
