require "spec_helper"

RSpec.describe ActiveCipherStorage::Cipher do
  include_examples "a symmetric cipher", described_class

  describe "#encrypt" do
    before { configure_env_provider }
    subject(:cipher) { described_class.new }

    it "produces output that starts with the format magic bytes" do
      result = cipher.encrypt(StringIO.new("hello"))
      expect(result.byteslice(0, 4)).to eq("ACS\x01".b)
    end

    it "encodes chunked=false in the header" do
      result = cipher.encrypt(StringIO.new("hello"))
      header = ActiveCipherStorage::Format.read_header(StringIO.new(result))
      expect(header.chunked).to be false
    end

    it "embeds the provider_id in the header" do
      result = cipher.encrypt(StringIO.new("hello"))
      header = ActiveCipherStorage::Format.read_header(StringIO.new(result))
      expect(header.provider_id).to eq("env")
    end
  end

  describe "#decrypt" do
    before { configure_env_provider }
    subject(:cipher) { described_class.new }

    it "raises InvalidFormat for completely invalid input" do
      expect { cipher.decrypt("not-encrypted-data") }
        .to raise_error(ActiveCipherStorage::Errors::InvalidFormat)
    end

    it "raises InvalidFormat when given a chunked payload" do
      stream_io = ActiveCipherStorage::StreamCipher.new.encrypt_to_io(StringIO.new("hello"))
      expect { cipher.decrypt(stream_io) }
        .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /chunked/)
    end

    it "accepts both String and IO input" do
      encrypted_str = cipher.encrypt(StringIO.new("test"))
      encrypted_io  = StringIO.new(encrypted_str)

      expect(cipher.decrypt(encrypted_str)).to eq("test")
      expect(cipher.decrypt(encrypted_io)).to eq("test")
    end
  end

  describe "thread safety" do
    before { configure_env_provider }

    it "encrypts/decrypts concurrently without data corruption" do
      cipher   = described_class.new
      messages = (1..20).map { |i| "message-#{i}-" * 50 }

      results = messages.map { |m| Thread.new { cipher.encrypt(StringIO.new(m)) } }.map(&:value)

      decrypted = results.map { |enc| Thread.new { cipher.decrypt(enc) } }.map(&:value)

      expect(decrypted).to match_array(messages)
    end
  end
end
