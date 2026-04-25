require "spec_helper"

RSpec.describe ActiveCipherStorage::Providers::EnvProvider do
  let(:var) { "TEST_CIPHER_KEY_#{SecureRandom.hex(4).upcase}" }

  before { random_master_key_env(var) }
  after  { ENV.delete(var) }

  subject(:provider) { described_class.new(env_var: var) }

  include_examples "a kms provider"

  describe "#generate_data_key" do
    it "uses the correct DEK size (32 bytes)" do
      expect(provider.generate_data_key[:plaintext_key].bytesize).to eq(32)
    end

    it "raises ProviderError when the env var is absent" do
      ENV.delete(var)
      expect { provider.generate_data_key }
        .to raise_error(ActiveCipherStorage::Errors::ProviderError, /not set/)
    end

    it "raises ProviderError when the key is not valid Base64" do
      ENV[var] = "not!@#base64"
      expect { provider.generate_data_key }
        .to raise_error(ActiveCipherStorage::Errors::ProviderError, /Base64/)
    end

    it "raises ProviderError when the decoded key is the wrong length" do
      ENV[var] = Base64.strict_encode64("short")
      expect { provider.generate_data_key }
        .to raise_error(ActiveCipherStorage::Errors::ProviderError, /32 bytes/)
    end
  end

  describe "#decrypt_data_key" do
    it "raises KeyManagementError with a different master key" do
      bundle      = provider.generate_data_key
      new_var     = "#{var}_NEW"
      random_master_key_env(new_var)
      new_provider = described_class.new(env_var: new_var)

      expect { new_provider.decrypt_data_key(bundle[:encrypted_key]) }
        .to raise_error(ActiveCipherStorage::Errors::KeyManagementError)

      ENV.delete(new_var)
    end
  end

  describe "#rotate_data_key" do
    it "re-wraps the DEK under a new master key and round-trips" do
      old_bundle = provider.generate_data_key

      new_var = "#{var}_ROTATED"
      random_master_key_env(new_var)
      new_provider = described_class.new(env_var: new_var)

      rotated_enc_dek = new_provider.rotate_data_key(
        old_bundle[:encrypted_key],
        old_provider: provider
      )

      recovered = new_provider.decrypt_data_key(rotated_enc_dek)
      expect(recovered).to eq(old_bundle[:plaintext_key])

      ENV.delete(new_var)
    end

    it "raises UnsupportedOperation when no old_env_var or old_provider is given" do
      bundle = provider.generate_data_key
      expect { provider.rotate_data_key(bundle[:encrypted_key]) }
        .to raise_error(ActiveCipherStorage::Errors::UnsupportedOperation)
    end
  end

  describe "#provider_id" do
    it "returns 'env'" do
      expect(provider.provider_id).to eq("env")
    end
  end
end
