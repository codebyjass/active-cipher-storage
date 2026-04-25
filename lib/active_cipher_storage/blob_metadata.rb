module ActiveCipherStorage
  # Reads and writes encryption metadata on ActiveStorage::Blob records.
  #
  # Written fields (all stored under the blob's existing `metadata` JSON column):
  #   encrypted      => true
  #   cipher_version => Integer  (Format::VERSION)
  #   provider_id    => String   (e.g. "aws_kms", "env")
  #   kms_key_id     => String   (CMK ARN, env-var name, or nil)
  #
  # These are for operational visibility — rotation queries, auditing,
  # backward-compat detection. The encrypted file header is always the
  # authoritative source for decryption.
  module BlobMetadata
    def self.write(storage_key, provider)
      return unless active_storage_available?

      blob = ActiveStorage::Blob.find_by(key: storage_key)
      return unless blob

      blob.update_columns(
        metadata: blob.metadata.merge(
          "encrypted"      => true,
          "cipher_version" => Format::VERSION,
          "provider_id"    => provider.provider_id,
          "kms_key_id"     => provider.key_id
        ).compact
      )
    rescue => e
      ActiveCipherStorage.configuration.logger.warn(
        "[ActiveCipherStorage] Could not write blob metadata for #{storage_key}: #{e.message}"
      )
    end

    def self.update_after_rotation(storage_key, new_provider)
      return unless active_storage_available?

      blob = ActiveStorage::Blob.find_by(key: storage_key)
      return unless blob

      blob.update_columns(
        metadata: blob.metadata.merge(
          "provider_id" => new_provider.provider_id,
          "kms_key_id"  => new_provider.key_id
        ).compact
      )
    rescue => e
      ActiveCipherStorage.configuration.logger.warn(
        "[ActiveCipherStorage] Could not update rotation metadata for #{storage_key}: #{e.message}"
      )
    end

    # Returns the metadata hash for a blob, or nil if AR is unavailable.
    def self.for(storage_key)
      return nil unless active_storage_available?
      ActiveStorage::Blob.find_by(key: storage_key)&.metadata
    end

    # Finds all blobs whose metadata matches the given provider.
    # Iterates in batches to avoid loading all blobs into memory.
    # Yields each matching blob.
    #
    # For large tables, add a DB-level index on `metadata->>'kms_key_id'`
    # and narrow the scope before passing to this method.
    def self.blobs_for(provider)
      return enum_for(:blobs_for, provider) unless block_given?
      return unless active_storage_available?

      ActiveStorage::Blob.find_each do |blob|
        meta = blob.metadata
        next unless meta["encrypted"] == true
        next unless meta["provider_id"] == provider.provider_id
        next if provider.key_id && meta["kms_key_id"] != provider.key_id

        yield blob
      end
    end

    private_class_method def self.active_storage_available?
      defined?(ActiveStorage::Blob) && ActiveStorage::Blob.table_exists?
    rescue
      false
    end
  end
end
