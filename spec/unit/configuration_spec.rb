require "spec_helper"

RSpec.describe ActiveCipherStorage::Configuration do
  subject(:configuration) { described_class.new }

  describe "#config" do
    it "backs regular settings with an ActiveSupport config object" do
      configuration.config.algorithm = "aes-256-gcm"

      expect(configuration.algorithm).to eq("aes-256-gcm")
    end
  end

  describe "#encrypt_uploads" do
    it "defaults to true" do
      expect(configuration.encrypt_uploads).to be true
    end

    it "rejects non-boolean values" do
      configure_env_provider
      ActiveCipherStorage.configure { |config| config.encrypt_uploads = "yes" }

      expect { ActiveCipherStorage.configuration.validate! }
        .to raise_error(ArgumentError, /encrypt_uploads/)
    end
  end
end
