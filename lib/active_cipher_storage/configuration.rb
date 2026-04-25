require "logger"
require "active_support/ordered_options"

module ActiveCipherStorage
  class Configuration
    # Supported algorithm identifiers.
    ALGORITHMS = %w[aes-256-gcm].freeze

    # Bytes per plaintext chunk in streaming mode (default 5 MiB — matches the
    # minimum S3 multipart part size, so each chunk maps to exactly one part).
    MINIMUM_S3_MULTIPART_PART_SIZE = 5 * 1024 * 1024
    DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024

    attr_reader :config

    def initialize
      @config = ActiveSupport::OrderedOptions.new
      self.algorithm = "aes-256-gcm"
      self.chunk_size = DEFAULT_CHUNK_SIZE
      self.encrypt_uploads = true
      self.logger = Logger.new($stdout, level: Logger::WARN)
    end

    def algorithm
      config.algorithm
    end

    def algorithm=(value)
      config.algorithm = value
    end

    def chunk_size
      config.chunk_size
    end

    def chunk_size=(value)
      config.chunk_size = value
    end

    def encrypt_uploads
      config.encrypt_uploads
    end

    def encrypt_uploads=(value)
      config.encrypt_uploads = value
    end

    def logger
      config.logger
    end

    def logger=(value)
      config.logger = value
    end

    def provider
      config.provider
    end

    # Accept a provider instance or a symbol shorthand (:env, :aws_kms).
    def provider=(value)
      config.provider = case value
                        when Symbol then resolve_provider(value)
                        when Providers::Base then value
                        else
                          raise ArgumentError,
                                "provider must be a Providers::Base instance or " \
                                "one of :env, :aws_kms — got #{value.inspect}"
                        end
    end

    def validate!
      raise ProviderError, "No KMS provider configured. " \
            "Set ActiveCipherStorage.configuration.provider." unless provider

      unless ALGORITHMS.include?(algorithm)
        raise ArgumentError, "Unsupported algorithm: #{algorithm.inspect}. " \
              "Supported: #{ALGORITHMS.join(', ')}"
      end

      raise ArgumentError, "chunk_size must be positive" unless chunk_size.positive?

      return if [true, false].include?(encrypt_uploads)

      raise ArgumentError, "encrypt_uploads must be true or false"
    end

    private

    def resolve_provider(sym)
      case sym
      when :env     then Providers::EnvProvider.new
      when :aws_kms then Providers::AwsKmsProvider.new
      else
        raise ArgumentError, "Unknown provider shorthand: #{sym.inspect}"
      end
    end
  end
end
