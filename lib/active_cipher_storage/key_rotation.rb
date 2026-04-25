module ActiveCipherStorage
  # Re-wraps the per-file Data Encryption Key (DEK) stored in encrypted file
  # headers without decrypting or re-encrypting the file body.
  #
  # Why this matters
  # ─────────────────
  # Every encrypted file stores its DEK in the header, wrapped by the KMS
  # master key.  When you rotate the master key, only the wrapped DEK in the
  # header needs to change — the AES-256-GCM ciphertext body stays untouched.
  # This makes rotation O(n blobs) in API calls but O(header size) in data
  # transferred per file, not O(file size).
  #
  # AWS KMS optimisation
  # ─────────────────────
  # When both providers are AwsKmsProvider, KeyRotation uses KMS ReEncrypt.
  # The plaintext DEK never leaves KMS — it is re-wrapped entirely server-side.
  # Cross-provider rotations (e.g. EnvProvider → AwsKmsProvider) must briefly
  # hold the plaintext DEK in process memory, zeroed immediately after use.
  #
  # Usage
  # ─────
  #   old_kms = ActiveCipherStorage::Providers::AwsKmsProvider.new(key_id: old_arn)
  #   new_kms = ActiveCipherStorage::Providers::AwsKmsProvider.new(key_id: new_arn)
  #
  #   ActiveCipherStorage::KeyRotation.rotate(
  #     old_provider: old_kms,
  #     new_provider: new_kms,
  #     service:      MyEncryptedStorageService.new
  #   ) do |blob, result|
  #     Rails.logger.info "rotated #{blob.key}: #{result[:status]}"
  #   end
  #
  module KeyRotation
    extend self

    # Rotates every blob associated with old_provider.
    # Yields (blob, result_hash) for each blob processed so callers can log
    # progress and handle per-blob failures without aborting the batch.
    #
    # Options:
    #   dry_run: true  — parse headers and validate, but skip the upload step.
    def rotate(old_provider:, new_provider:, service:, dry_run: false)
      BlobMetadata.blobs_for(old_provider) do |blob|
        result = rotate_blob(blob, old_provider: old_provider,
                                   new_provider: new_provider,
                                   service:      service,
                                   dry_run:      dry_run)
        yield blob, result if block_given?
      end
    end

    # Rotates a single blob. Returns { status: :rotated | :skipped | :failed, ... }.
    def rotate_blob(blob, old_provider:, new_provider:, service:, dry_run: false)
      encrypted = service.download_raw(blob.key)

      unless Format::MAGIC == encrypted.b[0, 4]
        return { status: :skipped, reason: "not an encrypted blob" }
      end

      new_payload = rewrite_dek(encrypted, old_provider: old_provider, new_provider: new_provider)

      unless dry_run
        service.upload_raw(blob.key, StringIO.new(new_payload))
        BlobMetadata.update_after_rotation(blob.key, new_provider)
      end

      { status: dry_run ? :validated : :rotated }
    rescue => e
      { status: :failed, error: e.message }
    end

    # Rewrites the encrypted DEK inside an encrypted payload's header.
    # The IV, ciphertext, and auth tag(s) are copied byte-for-byte unchanged.
    def rewrite_dek(encrypted_data, old_provider:, new_provider:)
      io     = StringIO.new(encrypted_data.b)
      header = Format.read_header(io)
      body_offset = io.pos

      new_encrypted_dek = re_wrap_dek(
        header.encrypted_dek,
        old_provider: old_provider,
        new_provider: new_provider
      )

      out = StringIO.new("".b)
      Format.write_header(out, Format::Header.new(
        version:       header.version,
        algorithm:     header.algorithm,
        chunked:       header.chunked,
        chunk_size:    header.chunk_size,
        provider_id:   new_provider.provider_id,
        encrypted_dek: new_encrypted_dek
      ))
      out.write(encrypted_data.b[body_offset..])
      out.string
    end

    private

    # Chooses the optimal re-wrap strategy:
    # - Both AWS KMS → ReEncrypt (plaintext DEK stays in KMS)
    # - Otherwise    → decrypt with old, wrap with new (plaintext DEK in memory)
    def re_wrap_dek(encrypted_dek, old_provider:, new_provider:)
      if old_provider.is_a?(Providers::AwsKmsProvider) &&
         new_provider.is_a?(Providers::AwsKmsProvider)
        return old_provider.rotate_data_key(encrypted_dek,
                                            destination_key_id: new_provider.key_id)
      end

      plaintext_dek = old_provider.decrypt_data_key(encrypted_dek)
      new_provider.wrap_data_key(plaintext_dek)
    ensure
      zero_bytes!(plaintext_dek) if defined?(plaintext_dek)
    end

    def zero_bytes!(str)
      return unless str.is_a?(String)
      str.bytesize.times { |i| str.setbyte(i, 0) }
    end
  end
end
