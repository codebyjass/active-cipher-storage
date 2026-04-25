require "active_storage/service"
require "active_cipher_storage/adapters/active_storage_service"

module ActiveStorage
  class Service
    unless const_defined?(:ActiveCipherStorageService, false)
      ActiveCipherStorageService = ::ActiveCipherStorage::Adapters::ActiveStorageService
    end
  end
end
