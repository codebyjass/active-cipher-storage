require "base64"
require "securerandom"

# ─────────────────────────────────────────────────────────────────
# Test helpers
# ─────────────────────────────────────────────────────────────────

def random_master_key_env(var = "ACTIVE_CIPHER_MASTER_KEY")
  key_b64 = Base64.strict_encode64(SecureRandom.random_bytes(32))
  ENV[var] = key_b64
  key_b64
end

def configure_env_provider(var = "ACTIVE_CIPHER_MASTER_KEY")
  random_master_key_env(var)
  ActiveCipherStorage.configure do |c|
    c.provider = ActiveCipherStorage::Providers::EnvProvider.new(env_var: var)
  end
end

# ─────────────────────────────────────────────────────────────────
# Shared example: any cipher class (Cipher or StreamCipher)
# ─────────────────────────────────────────────────────────────────

RSpec.shared_examples "a symmetric cipher" do |cipher_class|
  let(:plaintext) { "The quick brown fox jumps over the lazy dog.\n" * 100 }
  let(:io)        { StringIO.new(plaintext) }
  let(:shared_cipher) { cipher_class.new }

  before { configure_env_provider }

  it "round-trips plaintext" do
    if cipher_class == ActiveCipherStorage::Cipher
      encrypted  = shared_cipher.encrypt(io)
      decrypted  = shared_cipher.decrypt(encrypted)
    else
      enc_io = shared_cipher.encrypt_to_io(io)
      dec_io = shared_cipher.decrypt_to_io(enc_io)
      decrypted = dec_io.read
    end
    expect(decrypted).to eq(plaintext)
  end

  it "produces different ciphertext for identical plaintext (random IV)" do
    io2 = StringIO.new(plaintext)
    if cipher_class == ActiveCipherStorage::Cipher
      a = shared_cipher.encrypt(io)
      b = shared_cipher.encrypt(io2)
    else
      a = shared_cipher.encrypt_to_io(io).read
      b = shared_cipher.encrypt_to_io(io2).read
    end
    expect(a).not_to eq(b)
  end

  it "raises DecryptionError on tampered ciphertext" do
    if cipher_class == ActiveCipherStorage::Cipher
      encrypted = shared_cipher.encrypt(io)
      encrypted.setbyte(encrypted.bytesize - 20, encrypted.getbyte(encrypted.bytesize - 20) ^ 0xFF)
      expect { shared_cipher.decrypt(encrypted) }.to raise_error(ActiveCipherStorage::Errors::DecryptionError)
    else
      enc_io = shared_cipher.encrypt_to_io(io)
      raw    = enc_io.read
      raw.setbyte(raw.bytesize - 20, raw.getbyte(raw.bytesize - 20) ^ 0xFF)
      expect { shared_cipher.decrypt_to_io(StringIO.new(raw)) }
        .to raise_error(ActiveCipherStorage::Errors::DecryptionError)
    end
  end
end

# ─────────────────────────────────────────────────────────────────
# Shared example: any KMS provider
# ─────────────────────────────────────────────────────────────────

RSpec.shared_examples "a kms provider" do
  it "returns a 32-byte plaintext DEK" do
    bundle = subject.generate_data_key
    expect(bundle[:plaintext_key].bytesize).to eq(32)
  end

  it "returns a non-empty encrypted DEK" do
    bundle = subject.generate_data_key
    expect(bundle[:encrypted_key]).not_to be_empty
  end

  it "round-trips the data key" do
    bundle    = subject.generate_data_key
    recovered = subject.decrypt_data_key(bundle[:encrypted_key])
    expect(recovered).to eq(bundle[:plaintext_key])
  end

  it "produces a different encrypted DEK on each call (random IV)" do
    a = subject.generate_data_key[:encrypted_key]
    b = subject.generate_data_key[:encrypted_key]
    expect(a).not_to eq(b)
  end

  it "exposes a non-empty provider_id" do
    expect(subject.provider_id).to be_a(String).and(satisfy { |s| !s.empty? })
  end
end
