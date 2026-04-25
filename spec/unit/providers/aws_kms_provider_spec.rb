require "spec_helper"

RSpec.describe ActiveCipherStorage::Providers::AwsKmsProvider do
  # All tests use a fake KMS client so no real AWS credentials are needed.
  let(:plaintext_dek)  { SecureRandom.random_bytes(32) }
  let(:encrypted_dek)  { SecureRandom.random_bytes(60) }

  let(:fake_generate_resp) do
    double("GenerateDataKeyResponse",
      plaintext:       plaintext_dek.dup,
      ciphertext_blob: encrypted_dek.dup)
  end

  let(:fake_decrypt_resp) do
    double("DecryptResponse", plaintext: plaintext_dek.dup)
  end

  let(:fake_reencrypt_resp) do
    double("ReEncryptResponse", ciphertext_blob: SecureRandom.random_bytes(60))
  end

  # Stateful fake: decrypt returns whatever plaintext was last generated,
  # simulating real KMS envelope-key round-trip without a real AWS call.
  let(:kms_client) do
    last_pt = nil
    double("Aws::KMS::Client").tap do |c|
      allow(c).to receive(:generate_data_key) do
        pt = SecureRandom.random_bytes(32)
        last_pt = pt
        double("GenerateDataKeyResponse",
          plaintext:       pt.dup,
          ciphertext_blob: SecureRandom.random_bytes(60))
      end
      allow(c).to receive(:decrypt) do
        double("DecryptResponse", plaintext: last_pt&.dup || plaintext_dek.dup)
      end
      allow(c).to receive(:re_encrypt).and_return(fake_reencrypt_resp)
    end
  end

  subject(:provider) do
    described_class.new(key_id: "arn:aws:kms:us-east-1:123:key/test", client: kms_client)
  end

  include_examples "a kms provider"

  describe "#generate_data_key" do
    it "calls KMS with AES_256 key spec" do
      expect(kms_client).to receive(:generate_data_key)
        .with(hash_including(key_spec: "AES_256"))
        .and_return(fake_generate_resp)
      provider.generate_data_key
    end

    it "passes encryption_context when configured" do
      ctx      = { "resource" => "user/42" }
      provider = described_class.new(
        key_id:             "arn:...",
        encryption_context: ctx,
        client:             kms_client
      )
      expect(kms_client).to receive(:generate_data_key)
        .with(hash_including(encryption_context: ctx))
        .and_return(double("resp", plaintext: SecureRandom.random_bytes(32),
                                   ciphertext_blob: SecureRandom.random_bytes(60)))
      provider.generate_data_key
    end

    it "raises KeyManagementError on KMS service errors" do
      allow(kms_client).to receive(:generate_data_key)
        .and_raise(Aws::KMS::Errors::ServiceError.new(nil, "throttled"))
      expect { provider.generate_data_key }
        .to raise_error(ActiveCipherStorage::Errors::KeyManagementError, /throttled/)
    end
  end

  describe "#decrypt_data_key" do
    it "calls KMS Decrypt with the stored blob" do
      expect(kms_client).to receive(:decrypt)
        .with(hash_including(ciphertext_blob: encrypted_dek))
        .and_return(fake_decrypt_resp)
      provider.decrypt_data_key(encrypted_dek)
    end

    it "raises KeyManagementError on invalid ciphertext" do
      allow(kms_client).to receive(:decrypt)
        .and_raise(Aws::KMS::Errors::InvalidCiphertextException.new(nil, "bad ciphertext"))
      expect { provider.decrypt_data_key(encrypted_dek) }
        .to raise_error(ActiveCipherStorage::Errors::KeyManagementError, /tampered/)
    end
  end

  describe "#rotate_data_key" do
    it "calls KMS ReEncrypt" do
      expect(kms_client).to receive(:re_encrypt)
        .with(hash_including(ciphertext_blob: encrypted_dek))
        .and_return(fake_reencrypt_resp)
      provider.rotate_data_key(encrypted_dek)
    end

    it "accepts a destination_key_id override" do
      new_key = "arn:aws:kms:us-east-1:123:key/new"
      expect(kms_client).to receive(:re_encrypt)
        .with(hash_including(destination_key_id: new_key))
        .and_return(fake_reencrypt_resp)
      provider.rotate_data_key(encrypted_dek, destination_key_id: new_key)
    end
  end

  describe "#provider_id" do
    it "returns 'aws_kms'" do
      expect(provider.provider_id).to eq("aws_kms")
    end
  end
end
