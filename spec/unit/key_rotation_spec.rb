require "spec_helper"

RSpec.describe ActiveCipherStorage::KeyRotation do
  before { configure_env_provider }

  let(:var_a) { "ROTATION_KEY_A_#{SecureRandom.hex(4).upcase}" }
  let(:var_b) { "ROTATION_KEY_B_#{SecureRandom.hex(4).upcase}" }

  let(:provider_a) do
    random_master_key_env(var_a)
    ActiveCipherStorage::Providers::EnvProvider.new(env_var: var_a)
  end

  let(:provider_b) do
    random_master_key_env(var_b)
    ActiveCipherStorage::Providers::EnvProvider.new(env_var: var_b)
  end

  after do
    ENV.delete(var_a)
    ENV.delete(var_b)
  end

  let(:plaintext) { "Sensitive payload " * 50 }

  # Minimal service stub that wraps a hash store.
  let(:service) do
    store = {}
    double("Service").tap do |s|
      allow(s).to receive(:download_raw) { |k| store[k] }
      allow(s).to receive(:upload_raw) { |k, io| store[k] = io.read.b }

      # Pre-populate with a blob encrypted under provider_a
      cipher = ActiveCipherStorage::Cipher.new(
        build_config(provider_a)
      )
      store["blob/abc"] = cipher.encrypt(StringIO.new(plaintext))
    end
  end

  def build_config(provider)
    cfg = ActiveCipherStorage::Configuration.new
    cfg.provider = provider
    cfg
  end

  describe ".rewrite_dek" do
    it "produces a payload that decrypts correctly under new_provider" do
      original = ActiveCipherStorage::Cipher.new(build_config(provider_a)).encrypt(StringIO.new(plaintext))

      rotated = described_class.rewrite_dek(original,
        old_provider: provider_a, new_provider: provider_b)

      decrypted = ActiveCipherStorage::Cipher.new(build_config(provider_b)).decrypt(rotated)
      expect(decrypted).to eq(plaintext)
    end

    it "does not alter the ciphertext body — only the header changes" do
      original = ActiveCipherStorage::Cipher.new(build_config(provider_a)).encrypt(StringIO.new(plaintext))

      rotated = described_class.rewrite_dek(original,
        old_provider: provider_a, new_provider: provider_b)

      orig_body_start = StringIO.new(original).then do |io|
        ActiveCipherStorage::Format.read_header(io)
        io.pos
      end
      rotated_body_start = StringIO.new(rotated).then do |io|
        ActiveCipherStorage::Format.read_header(io)
        io.pos
      end

      expect(original[orig_body_start..]).to eq(rotated[rotated_body_start..])
    end

    it "updates the provider_id in the new header" do
      original = ActiveCipherStorage::Cipher.new(build_config(provider_a)).encrypt(StringIO.new(plaintext))
      rotated  = described_class.rewrite_dek(original,
        old_provider: provider_a, new_provider: provider_b)

      header = ActiveCipherStorage::Format.read_header(StringIO.new(rotated))
      expect(header.provider_id).to eq(provider_b.provider_id)
    end

    it "works with chunked (StreamCipher) payloads" do
      cfg = build_config(provider_a)
      cfg.chunk_size = 32
      encrypted = ActiveCipherStorage::StreamCipher.new(cfg).encrypt_to_io(StringIO.new(plaintext)).read

      rotated   = described_class.rewrite_dek(encrypted,
        old_provider: provider_a, new_provider: provider_b)

      cfg_b = build_config(provider_b)
      cfg_b.chunk_size = 32
      decrypted = ActiveCipherStorage::StreamCipher.new(cfg_b).decrypt_to_io(StringIO.new(rotated)).read
      expect(decrypted).to eq(plaintext)
    end

    it "raises InvalidFormat for non-encrypted data" do
      expect {
        described_class.rewrite_dek("not encrypted", old_provider: provider_a, new_provider: provider_b)
      }.to raise_error(ActiveCipherStorage::Errors::InvalidFormat)
    end
  end

  describe ".rotate_blob" do
    let(:blob) { OpenStruct.new(key: "blob/abc") }

    it "returns status :rotated and leaves blob decryptable under new provider" do
      result = described_class.rotate_blob(blob,
        old_provider: provider_a, new_provider: provider_b, service: service)

      expect(result[:status]).to eq(:rotated)
      rotated_raw = service.download_raw("blob/abc")
      decrypted   = ActiveCipherStorage::Cipher.new(build_config(provider_b)).decrypt(rotated_raw)
      expect(decrypted).to eq(plaintext)
    end

    it "returns status :skipped for a non-encrypted blob" do
      allow(service).to receive(:download_raw).and_return("plaintext data")
      result = described_class.rotate_blob(blob,
        old_provider: provider_a, new_provider: provider_b, service: service)
      expect(result[:status]).to eq(:skipped)
    end

    it "returns status :failed when decryption fails (wrong old_provider)" do
      wrong_provider_var = "WRONG_#{SecureRandom.hex(4).upcase}"
      random_master_key_env(wrong_provider_var)
      wrong = ActiveCipherStorage::Providers::EnvProvider.new(env_var: wrong_provider_var)

      result = described_class.rotate_blob(blob,
        old_provider: wrong, new_provider: provider_b, service: service)

      expect(result[:status]).to eq(:failed)
      ENV.delete(wrong_provider_var)
    end

    it "does not upload when dry_run: true" do
      expect(service).not_to receive(:upload_raw)
      described_class.rotate_blob(blob,
        old_provider: provider_a, new_provider: provider_b, service: service, dry_run: true)
    end

    it "returns status :validated on a dry run" do
      result = described_class.rotate_blob(blob,
        old_provider: provider_a, new_provider: provider_b, service: service, dry_run: true)
      expect(result[:status]).to eq(:validated)
    end
  end

  describe ".rotate" do
    it "yields results for each blob found by BlobMetadata" do
      blob = OpenStruct.new(key: "blob/abc")
      allow(ActiveCipherStorage::BlobMetadata).to receive(:blobs_for)
        .with(provider_a).and_yield(blob)

      yielded = []
      described_class.rotate(old_provider: provider_a, new_provider: provider_b,
                              service: service) { |b, r| yielded << [b, r] }

      expect(yielded.length).to eq(1)
      expect(yielded.first[1][:status]).to eq(:rotated)
    end
  end
end
