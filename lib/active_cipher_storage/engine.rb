require "rails"

module ActiveCipherStorage
  class Engine < Rails::Engine
    isolate_namespace ActiveCipherStorage

    initializer "active_cipher_storage.setup" do
      ActiveSupport.on_load(:active_storage) do
        # Register our service so Rails' configurator can resolve it by name.
        # When config/storage.yml has `service: ActiveCipherStorage`, Rails
        # looks for ActiveStorage::Service::ActiveCipherStorageService or falls
        # back to a registered mapping.  We register both names for safety.
        require "active_cipher_storage/adapters/active_storage_service"

        # Rails 7.1+ uses Configurator#build which calls
        # SomeServiceClass.build(configurator:, **opts) when defined.
        # Older Rails falls back to .new(**opts).  Both are supported.
        ActiveStorage::Service.send(:const_set,
          :ActiveCipherStorageService,
          ActiveCipherStorage::Adapters::ActiveStorageService
        ) unless ActiveStorage::Service.const_defined?(:ActiveCipherStorageService, false)
      end
    end

    initializer "active_cipher_storage.log_subscriber" do
      ActiveSupport::LogSubscriber.logger ||= Logger.new($stdout)
    end
  end
end
