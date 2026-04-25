require "spec_helper"

RSpec.describe ActiveCipherStorage::BlobMetadata do
  before { configure_env_provider }

  # Minimal ActiveStorage::Blob stand-in.
  let(:blob_metadata) { {} }
  let(:fake_blob) do
    double("Blob",
      metadata:         blob_metadata,
      update_columns:   nil
    ).tap do |b|
      allow(b).to receive(:update_columns) do |h|
        blob_metadata.replace(h[:metadata] || h)
      end
    end
  end

  before do
    stub_const("ActiveStorage::Blob", Class.new do
      def self.find_by(*) = nil
      def self.table_exists? = true
      def self.find_each(&block) = nil
    end)
    allow(ActiveStorage::Blob).to receive(:find_by).and_return(fake_blob)
  end

  describe ".write" do
    let(:provider) { ActiveCipherStorage.configuration.provider }

    it "sets encrypted: true on the blob metadata" do
      described_class.write("key/abc", provider)
      expect(blob_metadata["encrypted"]).to be true
    end

    it "records cipher_version" do
      described_class.write("key/abc", provider)
      expect(blob_metadata["cipher_version"]).to eq(ActiveCipherStorage::Format::VERSION)
    end

    it "records provider_id" do
      described_class.write("key/abc", provider)
      expect(blob_metadata["provider_id"]).to eq("env")
    end

    it "records kms_key_id (env var name for EnvProvider)" do
      described_class.write("key/abc", provider)
      expect(blob_metadata["kms_key_id"]).to include("ACTIVE_CIPHER_MASTER_KEY")
    end

    it "does not raise when the blob is not found" do
      allow(ActiveStorage::Blob).to receive(:find_by).and_return(nil)
      expect { described_class.write("missing/key", provider) }.not_to raise_error
    end

    it "logs a warning and does not raise when update_columns fails" do
      allow(fake_blob).to receive(:update_columns).and_raise(RuntimeError, "DB unavailable")
      logger = double("Logger")
      allow(logger).to receive(:warn)
      allow(ActiveCipherStorage.configuration).to receive(:logger).and_return(logger)

      expect { described_class.write("key/abc", provider) }.not_to raise_error
      expect(logger).to have_received(:warn).with(/DB unavailable/)
    end
  end

  describe ".write_plaintext" do
    it "sets encrypted: false on the blob metadata" do
      described_class.write_plaintext("key/abc")
      expect(blob_metadata["encrypted"]).to be false
    end

    it "removes stale encryption metadata" do
      blob_metadata.merge!(
        "encrypted" => true,
        "cipher_version" => ActiveCipherStorage::Format::VERSION,
        "provider_id" => "env",
        "kms_key_id" => "ACTIVE_CIPHER_MASTER_KEY"
      )

      described_class.write_plaintext("key/abc")

      expect(blob_metadata).to eq("encrypted" => false)
    end
  end

  describe ".update_after_rotation" do
    let(:provider) { ActiveCipherStorage.configuration.provider }

    it "updates provider_id and kms_key_id" do
      described_class.update_after_rotation("key/abc", provider)
      expect(blob_metadata["provider_id"]).to eq("env")
    end
  end

  describe ".blobs_for" do
    let(:blob1) do
      double("Blob1", metadata: { "encrypted" => true, "provider_id" => "env",
                                  "kms_key_id" => "ACTIVE_CIPHER_MASTER_KEY" })
    end
    let(:blob2) do
      double("Blob2", metadata: { "encrypted" => true, "provider_id" => "aws_kms",
                                  "kms_key_id" => "arn:..." })
    end
    let(:blob3) do
      double("Blob3", metadata: { "encrypted" => false })
    end

    before do
      allow(ActiveStorage::Blob).to receive(:find_each).and_yield(blob1).and_yield(blob2).and_yield(blob3)
    end

    it "yields only blobs matching the provider" do
      provider = ActiveCipherStorage.configuration.provider
      results  = []
      described_class.blobs_for(provider) { |b| results << b }
      expect(results).to eq([blob1])
    end

    it "returns an enumerator when no block is given" do
      provider = ActiveCipherStorage.configuration.provider
      expect(described_class.blobs_for(provider)).to be_a(Enumerator)
    end
  end
end
