require "logger"

module ActiveCipherStorage
  class Configuration
    # Supported algorithm identifiers.
    ALGORITHMS = %w[aes-256-gcm].freeze

    # Bytes per plaintext chunk in streaming mode (default 5 MiB — matches the
    # minimum S3 multipart part size, so each chunk maps to exactly one part).
    DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024

    attr_reader   :provider
    attr_accessor :algorithm, :chunk_size, :logger

    def initialize
      @algorithm  = "aes-256-gcm"
      @chunk_size = DEFAULT_CHUNK_SIZE
      @provider   = nil
      @logger     = Logger.new($stdout, level: Logger::WARN)
    end

    # Accept a provider instance or a symbol shorthand (:env, :aws_kms).
    def provider=(value)
      @provider = case value
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
            "Set ActiveCipherStorage.configuration.provider." unless @provider

      unless ALGORITHMS.include?(@algorithm)
        raise ArgumentError, "Unsupported algorithm: #{@algorithm.inspect}. " \
              "Supported: #{ALGORITHMS.join(', ')}"
      end

      raise ArgumentError, "chunk_size must be positive" unless @chunk_size.positive?
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
