require "spec_helper"

# These tests exercise ActiveCipherStorage::Adapters::ActiveStorageService
# by swapping the wrapped service for a lightweight in-memory fake that
# mirrors the ActiveStorage::Service interface.
#
# No Rails app boot or real S3 bucket is required.

class MemoryStorageService
  def initialize
    @store = {}
  end

  def upload(key, io, **_opts)
    @store[key] = io.read.b
  end

  def download(key, &block)
    raise "Object not found: #{key}" unless @store.key?(key)
    data = @store[key].dup
    block ? yield(data) : data
  end

  def download_chunk(key, range)
    @store.fetch(key)[range]
  end

  def delete(key)
    @store.delete(key)
  end

  def exist?(key)
    @store.key?(key)
  end

  def delete_prefixed(pfx)
    @store.delete_if { |k, _| k.start_with?(pfx) }
  end
end

RSpec.describe ActiveCipherStorage::Adapters::ActiveStorageService do
  before { configure_env_provider }

  let(:inner)   { MemoryStorageService.new }
  subject(:svc) { described_class.new(wrapped_service: inner) }

  let(:plaintext) { "Confidential document contents.\n" * 200 }
  let(:key)       { "users/42/document.pdf" }

  describe "#upload / #download round-trip" do
    it "stores encrypted bytes and returns the original plaintext" do
      svc.upload(key, StringIO.new(plaintext))
      result = svc.download(key)
      expect(result).to eq(plaintext)
    end

    it "stores ciphertext (not plaintext) in the backing service" do
      svc.upload(key, StringIO.new(plaintext))
      raw = inner.download(key)
      expect(raw).not_to include(plaintext[0..20])
      expect(raw.byteslice(0, 4)).to eq("ACS\x01".b)
    end

    it "handles binary content (e.g. PNG header bytes)" do
      binary = "\x89PNG\r\n\x1a\n".b + SecureRandom.random_bytes(512)
      svc.upload(key, StringIO.new(binary))
      expect(svc.download(key)).to eq(binary)
    end

    it "stores plaintext for new uploads when encryption is disabled" do
      ActiveCipherStorage.configure { |c| c.encrypt_uploads = false }

      svc.upload(key, StringIO.new(plaintext))

      expect(inner.download(key)).to eq(plaintext)
      expect(svc.download(key)).to eq(plaintext)
    end

    it "still decrypts existing encrypted blobs when encryption is disabled" do
      svc.upload(key, StringIO.new(plaintext))
      ActiveCipherStorage.configure { |c| c.encrypt_uploads = false }

      expect(svc.download(key)).to eq(plaintext)
    end
  end

  describe "#download with block" do
    it "yields the plaintext" do
      svc.upload(key, StringIO.new(plaintext))
      received = nil
      svc.download(key) { |chunk| received = chunk }
      expect(received).to eq(plaintext)
    end
  end

  describe "#download_chunk" do
    it "returns the correct byte range" do
      svc.upload(key, StringIO.new(plaintext))
      range_data = svc.download_chunk(key, 10..29)
      expect(range_data).to eq(plaintext.b[10..29])
    end
  end

  describe "#exist?" do
    it "returns false before upload" do
      expect(svc.exist?(key)).to be false
    end

    it "returns true after upload" do
      svc.upload(key, StringIO.new("data"))
      expect(svc.exist?(key)).to be true
    end
  end

  describe "#delete" do
    it "removes the object" do
      svc.upload(key, StringIO.new("data"))
      svc.delete(key)
      expect(svc.exist?(key)).to be false
    end
  end

  describe "#url_for_direct_upload" do
    it "raises UnsupportedOperation" do
      expect { svc.url_for_direct_upload }
        .to raise_error(ActiveCipherStorage::Errors::UnsupportedOperation)
    end
  end

  describe "large file (stream cipher path)" do
    before { ActiveCipherStorage.configure { |c| c.chunk_size = 1024 } }

    it "round-trips a file larger than chunk_size" do
      big = SecureRandom.random_bytes(4096)
      svc.upload(key, StringIO.new(big))
      expect(svc.download(key)).to eq(big)
    end
  end

  describe "backward compatibility — legacy plaintext blobs" do
    it "returns raw bytes when the blob has no ACS magic header" do
      # Simulate a blob uploaded before encryption was enabled.
      inner.upload(key, StringIO.new(plaintext))
      expect(svc.download(key)).to eq(plaintext)
    end

    it "handles binary plaintext blobs" do
      binary = SecureRandom.random_bytes(256)
      inner.upload(key, StringIO.new(binary))
      expect(svc.download(key)).to eq(binary)
    end
  end

  describe "#download_raw / #upload_raw" do
    it "download_raw returns raw ciphertext bytes" do
      svc.upload(key, StringIO.new(plaintext))
      raw = svc.download_raw(key)
      expect(raw.b[0, 4]).to eq("ACS\x01".b)
    end

    it "upload_raw stores bytes that download_raw returns unchanged" do
      svc.upload(key, StringIO.new(plaintext))
      original_raw = svc.download_raw(key)

      svc.upload_raw(key, StringIO.new(original_raw))
      expect(svc.download_raw(key)).to eq(original_raw)
    end
  end

  describe "#rekey" do
    let(:var_b) { "REKEY_KEY_B_#{SecureRandom.hex(4).upcase}" }
    let(:provider_b) do
      random_master_key_env(var_b)
      ActiveCipherStorage::Providers::EnvProvider.new(env_var: var_b)
    end

    after { ENV.delete(var_b) }

    it "re-wraps the DEK so the blob is decryptable under the new provider" do
      svc.upload(key, StringIO.new(plaintext))
      old_provider = ActiveCipherStorage.configuration.provider

      result = svc.rekey(key, old_provider: old_provider, new_provider: provider_b)
      expect(result[:status]).to eq(:rotated)

      # The blob is no longer decryptable under the old provider.
      expect {
        ActiveCipherStorage::Cipher.new.decrypt(svc.download_raw(key))
      }.to raise_error(ActiveCipherStorage::Errors::KeyManagementError)

      # But decrypts cleanly under the new provider.
      cfg = ActiveCipherStorage::Configuration.new
      cfg.provider = provider_b
      decrypted = ActiveCipherStorage::Cipher.new(cfg).decrypt(svc.download_raw(key))
      expect(decrypted).to eq(plaintext)
    end
  end
end
