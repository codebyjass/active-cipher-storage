# ActiveCipherStorage

[![CI](https://github.com/codebyjass/active-cipher-storage/actions/workflows/ruby.yml/badge.svg)](https://github.com/codebyjass/active-cipher-storage/actions/workflows/ruby.yml)

ActiveCipherStorage is a Ruby gem for Rails Active Storage encryption and decryption. It encrypts files before they are stored, decrypts them when they are read, and supports AWS S3, streaming downloads, multipart uploads, AES-256-GCM envelope encryption, AWS KMS, and custom key providers.

ActiveCipherStorage supports three upload paths:

- **Rails Active Storage** — application code keeps using normal attachment APIs while the storage service encrypts on upload and decrypts on download.
- **Direct S3 clients** — service objects and non-Rails apps can call `put_encrypted`, `get_decrypted`, and `stream_decrypted`.
- **Frontend chunk uploads** — the frontend sends plaintext chunks to your backend; the backend encrypts those chunks and uploads encrypted S3 multipart parts.

## Contents

1. [How it works](#how-it-works)
2. [Installation](#installation)
3. [Rails / Active Storage setup](#rails--active-storage-setup)
4. [Standalone S3 usage](#standalone-s3-usage)
5. [Chunked multipart upload](#chunked-multipart-upload)
6. [Streaming download](#streaming-download)
7. [Manual encrypt / decrypt](#manual-encrypt--decrypt)
8. [Blob metadata](#blob-metadata)
9. [KMS providers](#kms-providers)
   - [Environment-variable provider](#environment-variable-provider)
   - [AWS KMS provider](#aws-kms-provider)
   - [Custom provider](#custom-provider)
10. [Key rotation](#key-rotation)
11. [Configuration reference](#configuration-reference)
12. [Encryption format](#encryption-format)
13. [Security notes](#security-notes)
14. [Testing](#testing)
15. [Contributing](#contributing)
16. [Security reports](#security-reports)
17. [License](#license)
18. [Ruby and Rails compatibility](#ruby-and-rails-compatibility)

## How it works

Every encrypted file is self-contained.  No external metadata store is needed.

```
┌─────────────────────────────────────────────────────────┐
│  Plaintext file                                         │
└────────────────────────┬────────────────────────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  1. Generate random DEK      │  (32 bytes, AES-256)
          │     per-file, per-operation  │
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  2. Encrypt file with DEK    │  AES-256-GCM
          │     unique IV per operation  │  + auth tag
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  3. Wrap DEK with KMS        │  ENV, AWS KMS,
          │     master key               │  or custom
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  4. Binary payload           │  Header + IV +
          │     (stored in S3)           │  Ciphertext + Auth tag
          └─────────────────────────────┘
```

Decryption reverses the flow: the KMS provider unwraps the DEK from the header, then AES-GCM verifies the auth tag and decrypts the ciphertext.

Every encrypted payload uses the same self-describing format, whether it came from Active Storage, the direct S3 adapter, or the backend chunk upload API.

## Installation

```ruby
# Gemfile
gem "active_cipher_storage"

# For AWS KMS provider:
gem "aws-sdk-kms"

# For standalone S3 adapter:
gem "aws-sdk-s3"
```

```
bundle install
```

## Rails / Active Storage setup

### 1. Configure a KMS provider

```ruby
# config/initializers/active_cipher_storage.rb
ActiveCipherStorage.configure do |config|
  # Choose one provider:

  # Option A — environment variable (development / staging)
  config.provider = :env    # reads ACTIVE_CIPHER_MASTER_KEY

  # Option B — AWS KMS (production)
  config.provider = ActiveCipherStorage::Providers::AwsKmsProvider.new(
    key_id: Rails.application.credentials.dig(:aws, :kms_key_id),
    region: "us-east-1"
  )

  # Tuning (optional)
  config.chunk_size = 5 * 1024 * 1024   # 5 MiB per chunk (default)
  config.encrypt_uploads = true         # set false to store new Active Storage uploads as plaintext
end
```

Generate a master key for local development:

```bash
ruby -rsecurerandom -rbase64 \
  -e 'puts Base64.strict_encode64(SecureRandom.bytes(32))'
```

Add the output to `.env` (or `config/credentials.yml.enc`):

```
ACTIVE_CIPHER_MASTER_KEY=<base64-encoded-key>
```

### 2. Add the encrypted service to `config/storage.yml`

```yaml
# config/storage.yml

encrypted_s3:
  service: ActiveCipherStorage   # resolved by the Engine
  wrapped_service: s3            # name of another service in this file

s3:
  service: S3
  access_key_id:     <%= Rails.application.credentials.dig(:aws, :access_key_id) %>
  secret_access_key: <%= Rails.application.credentials.dig(:aws, :secret_access_key) %>
  region:            us-east-1
  bucket:            my-app-production
```

### 3. Attach files using the encrypted service

```ruby
class User < ApplicationRecord
  # All uploads for :document go through encryption automatically.
  has_one_attached :document, service: :encrypted_s3
end
```

```ruby
# Controller — no changes needed
user.document.attach(io: file, filename: "report.pdf")
url = rails_blob_url(user.document)
```

Active Storage transparently encrypts on upload and decrypts on download. Existing plaintext objects are still readable: if a blob does not start with the `ACS\x01` magic header, the service returns it unchanged.

`config.encrypt_uploads` controls new Active Storage writes only. When disabled, new uploads are stored as plaintext and marked with `"encrypted": false` metadata. Reads continue to auto-detect by payload header, so existing encrypted blobs still decrypt correctly and existing plaintext blobs still download unchanged.

Direct Active Storage browser uploads are intentionally disabled because they bypass the backend encryption layer.

## Standalone S3 usage

No Rails required.

```ruby
require "active_cipher_storage"

ActiveCipherStorage.configure do |c|
  c.provider = ActiveCipherStorage::Providers::EnvProvider.new
end

s3 = ActiveCipherStorage::Adapters::S3Adapter.new(
  bucket: "my-bucket",
  region: "us-east-1"
)

# Encrypt and upload
File.open("contract.pdf", "rb") do |f|
  s3.put_encrypted("legal/contract-2026.pdf", f)
end

# Download and decrypt — returns an IO
io = s3.get_decrypted("legal/contract-2026.pdf")
File.binwrite("decrypted_contract.pdf", io.read)
```

Large files are automatically uploaded via S3 multipart when the payload exceeds `multipart_threshold` (default 100 MiB):

```ruby
s3 = ActiveCipherStorage::Adapters::S3Adapter.new(
  bucket:              "my-bucket",
  multipart_threshold: 50 * 1024 * 1024   # 50 MiB
)
```

## Chunked multipart upload

For large files where the frontend sends data in separate HTTP requests, use `EncryptedMultipartUpload`. Each frontend chunk is encrypted by the backend as an authenticated ACS frame and buffered until the S3 multipart minimum part size is met, then flushed as an encrypted S3 multipart part.

This flow is backend-managed. The frontend never receives encryption keys and never uploads plaintext directly to S3.

```ruby
uploader = ActiveCipherStorage::EncryptedMultipartUpload.new(
  s3_client: Aws::S3::Client.new(region: "us-east-1"),
  bucket:    "my-bucket"
)

# --- Request 1: start the upload ---
session_id = uploader.initiate(key: "uploads/video.mp4")
# Keep session_id for this active upload lifecycle.

# --- Requests 2..N: send chunks (any size) ---
uploader.upload_part(session_id: session_id, chunk_io: request.body)

# --- Final request: seal and complete ---
result = uploader.complete(session_id: session_id)
# => { status: :completed, key: "uploads/video.mp4", parts_count: 12 }
```

**Rails controller example:**

```ruby
class UploadsController < ApplicationController
  before_action :set_uploader

  def create
    render json: { session_id: @uploader.initiate(key: upload_key) }
  end

  def update
    @uploader.upload_part(session_id: params[:session_id], chunk_io: request.body)
    render json: { ok: true }
  end

  def complete
    result = @uploader.complete(session_id: params[:session_id])
    render json: result
  end

  def destroy
    @uploader.abort(session_id: params[:session_id])
    head :no_content
  end

  private

  def set_uploader
    @uploader = ActiveCipherStorage::EncryptedMultipartUpload.new(
      s3_client: s3_client,
      bucket:    ENV.fetch("S3_BUCKET")
    )
  end
end
```

**Session storage:**
By default, session state is held in process memory (`MemorySessionStore`). This is intended for one active backend-managed upload lifecycle and is not durable across process restarts or deploys.

For multi-process deployments where chunks for the same active upload may land on different workers or hosts, pass a shared store:

```ruby
# Rails.cache backed by Redis — allows cross-worker active upload sessions
uploader = ActiveCipherStorage::EncryptedMultipartUpload.new(
  s3_client: s3_client,
  bucket:    "my-bucket",
  store:     Rails.cache        # any object with read/write/delete
)
```

**Security:** The plaintext DEK is never stored in the session. Only the KMS-wrapped encrypted DEK is persisted; it is decrypted fresh for each chunk and zeroed immediately after use.

## Streaming download

`stream_decrypted` pipes S3 bytes through the decryptor and yields plaintext chunks on the fly. Memory usage is bounded by one ACS chunk (default 5 MiB) regardless of file size.

```ruby
s3 = ActiveCipherStorage::Adapters::S3Adapter.new(
  bucket: "my-bucket",
  region: "us-east-1"
)

# Stream directly into a Rails response
def show
  response.headers["Content-Type"]        = "application/octet-stream"
  response.headers["Content-Disposition"] = "attachment; filename=\"doc.pdf\""
  response.headers["Transfer-Encoding"]   = "chunked"

  s3.stream_decrypted("uploads/doc.pdf") do |chunk|
    response.stream.write(chunk)
  end
ensure
  response.stream.close
end
```

```ruby
# Stream to a local file
File.open("output.bin", "wb") do |f|
  s3.stream_decrypted("uploads/large.bin") { |chunk| f.write(chunk) }
end
```

`stream_decrypted` handles S3 delivering data in any chunk size — the internal `StreamingDecryptor` buffers incoming bytes and emits plaintext only when a complete, authenticated ACS frame is available.

Use `stream_decrypted` for chunked ACS objects. If the object is non-chunked, call `get_decrypted`; streaming a non-chunked or non-ACS/plaintext object raises `InvalidFormat` with a clear error.

## Manual encrypt / decrypt

Use `Cipher` (in-memory) or `StreamCipher` (chunked, constant memory):

```ruby
require "active_cipher_storage"

ActiveCipherStorage.configure do |c|
  c.provider = ActiveCipherStorage::Providers::EnvProvider.new
end

# ── In-memory (small files) ─────────────────────────────
cipher    = ActiveCipherStorage::Cipher.new
encrypted = cipher.encrypt(File.open("secret.txt", "rb"))
# => Binary String with embedded header, IV, ciphertext, auth tag

plaintext = cipher.decrypt(encrypted)
# => Original plaintext String

# ── Streaming (large files) ─────────────────────────────
stream = ActiveCipherStorage::StreamCipher.new

File.open("large.bin", "rb") do |input|
  File.open("large.bin.enc", "wb") do |output|
    stream.encrypt(input, output)
  end
end

File.open("large.bin.enc", "rb") do |input|
  File.open("large.bin.dec", "wb") do |output|
    stream.decrypt(input, output)
  end
end
```

## Blob metadata

When using the Rails Active Storage adapter, encryption metadata is automatically written to `ActiveStorage::Blob#metadata` after each upload:

```json
{
  "encrypted":      true,
  "cipher_version": 1,
  "provider_id":    "aws_kms",
  "kms_key_id":     "arn:aws:kms:us-east-1:123:key/abc"
}
```

This metadata powers:

- **Key rotation queries** — find every blob encrypted under a given KMS key without scanning blob bodies
- **Backward compatibility** — blobs uploaded before encryption was enabled are detected by the absence of the `ACS\x01` magic header and served as raw bytes
- **Operational auditing** — know which key protects which blobs at a glance

The binary file header remains the ground truth for decryption; metadata is informational only and a mismatch does not affect correctness.

**Single-blob re-key** (re-wrap DEK without touching the file body):

```ruby
svc = ActiveCipherStorage::Adapters::ActiveStorageService.new(wrapped_service: inner)

result = svc.rekey(
  "storage/key/for/blob",
  old_provider: old_provider,
  new_provider: new_provider
)
# => { status: :rotated }
```

**Batch key rotation** across all blobs for a provider:

```ruby
ActiveCipherStorage::KeyRotation.rotate(
  old_provider: old_kms,
  new_provider: new_kms,
  service:      MyEncryptedStorageService.new
) do |blob, result|
  Rails.logger.info "#{blob.key}: #{result[:status]}"
end
```

Only the encrypted DEK in the file header is rewritten — the IV, ciphertext, and auth tags are copied byte-for-byte. This makes rotation O(header size) in data transferred per file, not O(file size). For AWS KMS → AWS KMS rotations, the plaintext DEK never leaves KMS (uses `ReEncrypt` API).

## KMS providers

### Environment-variable provider

```ruby
# Default env var: ACTIVE_CIPHER_MASTER_KEY
provider = ActiveCipherStorage::Providers::EnvProvider.new

# Custom env var name
provider = ActiveCipherStorage::Providers::EnvProvider.new(
  env_var: "MYAPP_ENCRYPTION_KEY"
)
```

The master key wraps each per-file DEK with AES-256-GCM.  The wrapped DEK is stored in the file header; the plaintext DEK exists only during the encrypt/decrypt operation.

### AWS KMS provider

```ruby
provider = ActiveCipherStorage::Providers::AwsKmsProvider.new(
  key_id:             "arn:aws:kms:us-east-1:123456789:key/mrk-abc123",
  region:             "us-east-1",

  # Bind the DEK to a specific resource.  The same context must be
  # present on decrypt — different context = decryption failure.
  encryption_context: { "app" => "my-app", "env" => Rails.env }
)
```

AWS credentials are resolved through the standard SDK chain (env vars, `~/.aws/credentials`, instance profile, EKS IRSA, etc.).

### Custom provider

Subclass `ActiveCipherStorage::Providers::Base` and implement the provider contract:

```ruby
class MyVaultProvider < ActiveCipherStorage::Providers::Base
  def provider_id
    "vault"   # short ASCII string stored in every file header
  end

  def generate_data_key
    dek = SecureRandom.bytes(32)
    encrypted = vault_client.encrypt(dek)   # your KMS/Vault call
    { plaintext_key: dek, encrypted_key: encrypted }
  end

  def decrypt_data_key(encrypted_key)
    vault_client.decrypt(encrypted_key)
  end

  def wrap_data_key(plaintext_dek)
    vault_client.encrypt(plaintext_dek)
  end

  private

  def vault_client
    # ... your Vault/KMS client setup
  end
end

ActiveCipherStorage.configure do |c|
  c.provider = MyVaultProvider.new
end
```

The `provider_id` is embedded in every encrypted file. Routing at decrypt time is handled by whichever provider is configured — it is the application's responsibility to configure the right provider for each environment.

Implement `rotate_data_key(encrypted_key)` as well if the provider can re-wrap encrypted DEKs without exposing plaintext key material.

## Key rotation

### AWS KMS automatic rotation

Enable automatic key rotation on the CMK in the AWS Console or via CLI. AWS transparently re-wraps all data keys on the next use — no application changes needed.

### Cross-key and cross-provider rotation

Use `KeyRotation.rotate` (covered in [Blob metadata](#blob-metadata)) to batch re-wrap all blobs under a new key. For AWS KMS → AWS KMS rotations the plaintext DEK never leaves KMS (`ReEncrypt` API). Cross-provider rotations (e.g. `EnvProvider` → `AwsKmsProvider`) briefly hold the plaintext DEK in process memory and zero it immediately after.

**Dry-run mode** — validate headers without uploading:

```ruby
ActiveCipherStorage::KeyRotation.rotate(
  old_provider: old_kms,
  new_provider: new_kms,
  service:      svc,
  dry_run:      true
) do |blob, result|
  puts "#{blob.key}: #{result[:status]}"   # :validated or :failed
end
```

### Low-level DEK re-wrapping

```ruby
# AWS KMS → AWS KMS (ReEncrypt, no plaintext in memory)
old_provider = ActiveCipherStorage::Providers::AwsKmsProvider.new(key_id: "arn:...old")
new_provider = ActiveCipherStorage::Providers::AwsKmsProvider.new(key_id: "arn:...new")
new_dek = old_provider.rotate_data_key(encrypted_dek, destination_key_id: new_provider.key_id)

# EnvProvider → EnvProvider
old_provider = ActiveCipherStorage::Providers::EnvProvider.new(env_var: "OLD_KEY")
new_provider = ActiveCipherStorage::Providers::EnvProvider.new(env_var: "NEW_KEY")
new_dek = new_provider.rotate_data_key(encrypted_dek, old_provider: old_provider)
```

## Configuration reference

```ruby
ActiveCipherStorage.configure do |config|
  # Required.  A Providers::Base instance or :env / :aws_kms shorthand.
  config.provider   = :env

  # Encryption algorithm.  Currently only "aes-256-gcm" is supported.
  config.algorithm  = "aes-256-gcm"

  # Plaintext bytes per chunk in StreamCipher mode.
  # Must be >= 5 MiB for S3 multipart uploads (except the last part).
  config.chunk_size = 5 * 1024 * 1024

  # Controls new Active Storage uploads only. Downloads always auto-detect
  # encrypted vs. plaintext payloads by the ACS header.
  config.encrypt_uploads = true

  # Logger instance.  Defaults to STDOUT at WARN level.
  config.logger     = Rails.logger
end
```

## Encryption format

Every encrypted payload is a self-describing binary blob:

```
HEADER
  [4]  Magic bytes   "ACS\x01"
  [1]  Format version  (0x01)
  [1]  Algorithm ID    (0x01 = AES-256-GCM)
  [1]  Flags           (bit 0: chunked mode)
  [4]  Chunk-size hint (uint32 BE; 0 if non-chunked)
  [2]  Provider-ID length (uint16 BE)
  [N]  Provider ID  (UTF-8, e.g. "env" or "aws_kms")
  [2]  Encrypted DEK length (uint16 BE)
  [M]  Encrypted DEK bytes

NON-CHUNKED PAYLOAD
  [12] IV (random, unique per operation)
  [K]  AES-256-GCM ciphertext
  [16] Auth tag

CHUNKED PAYLOAD (repeated until final frame)
  [4]  Sequence number (1, 2, …  or 0xFFFFFFFF = final)
  [12] Chunk IV (random, unique per chunk)
  [4]  Ciphertext length (uint32 BE)
  [K]  Chunk ciphertext
  [16] Chunk auth tag
```

**Security properties:**
- Each file uses a fresh DEK, so compromising one file does not affect others.
- Each chunk (and each non-chunked payload) uses a fresh random IV.
- The chunk sequence number is AAD, preventing chunk reordering/splicing attacks.
- Auth tag failure raises `DecryptionError` immediately — no partial plaintext is returned.
- Unsupported format versions, algorithms, and header flags raise `InvalidFormat` instead of being parsed permissively.

## Security notes

| Risk | Mitigation |
|------|-----------|
| IV reuse | `SecureRandom.random_bytes` for every encrypt call; the probability of collision is negligible at any realistic scale. |
| Plaintext DEK in memory | DEK bytes are zeroed with `setbyte(i, 0)` in `ensure` blocks. Ruby GC may retain copies; use locked memory (e.g. via a C extension) for stricter requirements. |
| Direct uploads | `url_for_direct_upload` raises `UnsupportedOperation` — it is not possible to encrypt client-side with this gem. Use server-side uploads only. |
| Partial-read oracle | `DecryptionError` is always raised from `cipher.final`; no partial plaintext is ever returned. |
| Accidental plaintext upload | All upload paths go through the cipher layer; there is no bypass. |

## Testing

```bash
# All tests
bundle exec rake spec

# Unit tests only
bundle exec rake spec:unit

# Integration tests only
bundle exec rake spec:integration
```

Integration tests use in-memory fakes for both Active Storage and S3 — no real AWS credentials or S3 bucket required.

## Contributing

Contributions are welcome. Please read `CONTRIBUTING.md` before opening a pull request.

For changes that affect encryption, streaming, providers, key rotation, or storage behavior, include focused specs that prove both the success path and the failure/tamper path. Run the full suite before submitting:

```bash
bundle exec rspec
```

Do not commit secrets, credentials, `.env` files, local coverage output, or generated gems.

## Security reports

Please do not open public GitHub issues for vulnerabilities. Follow `SECURITY.md` and use GitHub private vulnerability reporting if it is available for the repository:

https://github.com/codebyjass/active-cipher-storage/security/advisories/new

## License

The gem is available as open source under the terms of the MIT License. See `LICENSE`.

## Ruby and Rails compatibility

| | Version |
|--|---------|
| Ruby | >= 3.2 |
| Rails / Active Storage | >= 7.0 |
| aws-sdk-kms | ~> 1.0 (optional) |
| aws-sdk-s3 | ~> 1.0 (optional) |
