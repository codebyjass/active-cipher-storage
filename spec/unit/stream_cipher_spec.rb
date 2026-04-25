require "spec_helper"

RSpec.describe ActiveCipherStorage::StreamCipher do
  include_examples "a symmetric cipher", described_class

  let(:chunk_size) { 64 }  # tiny for testing chunk boundaries

  before do
    configure_env_provider
    ActiveCipherStorage.configure { |c| c.chunk_size = chunk_size }
  end

  subject(:cipher) { described_class.new }

  describe "#encrypt" do
    it "sets chunked=true in the header" do
      out = cipher.encrypt_to_io(StringIO.new("hello"))
      header = ActiveCipherStorage::Format.read_header(out)
      expect(header.chunked).to be true
    end

    it "embeds chunk_size in the header" do
      out = cipher.encrypt_to_io(StringIO.new("data"))
      header = ActiveCipherStorage::Format.read_header(out)
      expect(header.chunk_size).to eq(chunk_size)
    end

    it "returns the number of chunks written" do
      plaintext = "x" * (chunk_size * 3 + 10)
      count = cipher.encrypt(StringIO.new(plaintext), StringIO.new("".b))
      # 3 full chunks + 1 final (partial) chunk = 4
      expect(count).to eq(4)
    end

    it "handles empty input" do
      expect { cipher.encrypt_to_io(StringIO.new("")) }.not_to raise_error
    end
  end

  describe "#decrypt" do
    it "raises InvalidFormat when given a non-chunked payload" do
      non_chunked = ActiveCipherStorage::Cipher.new.encrypt(StringIO.new("hello"))
      expect { cipher.decrypt_to_io(StringIO.new(non_chunked)) }
        .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /not chunked/)
    end

    it "raises DecryptionError when a chunk is individually tampered" do
      enc = cipher.encrypt_to_io(StringIO.new("sensitive data " * 10))
      raw = enc.read

      # Flip a byte deep in the ciphertext (past the header).
      target = raw.bytesize / 2
      raw.setbyte(target, raw.getbyte(target) ^ 0xFF)

      expect { cipher.decrypt_to_io(StringIO.new(raw)) }
        .to raise_error(ActiveCipherStorage::Errors::DecryptionError)
    end
  end

  describe "large file scenario" do
    it "round-trips a 1 MiB file in chunks of 64 KiB" do
      ActiveCipherStorage.configure { |c| c.chunk_size = 64 * 1024 }
      plaintext = SecureRandom.random_bytes(1 * 1024 * 1024)
      enc = described_class.new.encrypt_to_io(StringIO.new(plaintext))
      dec = described_class.new.decrypt_to_io(enc)
      expect(dec.read).to eq(plaintext)
    end
  end

  describe "exact chunk boundary" do
    it "round-trips when plaintext is an exact multiple of chunk_size" do
      plaintext = "A" * (chunk_size * 4)
      enc = cipher.encrypt_to_io(StringIO.new(plaintext))
      dec = cipher.decrypt_to_io(enc)
      expect(dec.read).to eq(plaintext)
    end
  end
end
