require "spec_helper"

# These tests exercise S3Adapter end-to-end using a fake Aws::S3::Client.
# No real AWS credentials or bucket are required.

Response = Struct.new(:upload_id, :body, :etag, keyword_init: true)

class FakeS3Client
  attr_reader :store, :multipart_parts

  def initialize
    @store           = {}
    @multipart_parts = {}
    @upload_id_seq   = 0
  end

  def put_object(bucket:, key:, body:, **_opts)
    @store[key] = body.respond_to?(:read) ? body.read.b : body.b
    Response.new
  end

  def get_object(bucket:, key:)
    raise Aws::S3::Errors::NoSuchKey.new(nil, "NoSuchKey") unless @store.key?(key)
    Response.new(body: StringIO.new(@store[key]))
  end

  def head_object(bucket:, key:)
    raise Aws::S3::Errors::NotFound.new(nil, "NotFound") unless @store.key?(key)
    Response.new
  end

  def delete_object(bucket:, key:)
    @store.delete(key)
    Response.new
  end

  def create_multipart_upload(bucket:, key:, **_opts)
    @upload_id_seq += 1
    id = "upload-#{@upload_id_seq}"
    @multipart_parts[id] = []
    Response.new(upload_id: id)
  end

  def upload_part(bucket:, key:, upload_id:, part_number:, body:, **_opts)
    @multipart_parts[upload_id] << {
      part_number: part_number,
      data: body.respond_to?(:read) ? body.read.b : body.b
    }
    Response.new(etag: "etag-#{part_number}")
  end

  def complete_multipart_upload(bucket:, key:, upload_id:, multipart_upload:, **_opts)
    parts = @multipart_parts[upload_id].sort_by { |p| p[:part_number] }
    @store[key] = parts.map { |p| p[:data] }.join.b
    Response.new
  end

  def abort_multipart_upload(bucket:, key:, upload_id:)
    @multipart_parts.delete(upload_id)
    Response.new
  end
end

RSpec.describe ActiveCipherStorage::Adapters::S3Adapter do
  before { configure_env_provider }

  let(:fake_s3)  { FakeS3Client.new }
  let(:bucket)   { "test-bucket" }

  subject(:adapter) do
    described_class.new(bucket: bucket, s3_client: fake_s3,
                        multipart_threshold: 500)  # low threshold for tests
  end

  describe "#put_encrypted / #get_decrypted" do
    let(:plaintext) { "Top secret payload.\n" * 100 }

    it "stores ciphertext and returns original plaintext" do
      adapter.put_encrypted("docs/secret.txt", StringIO.new(plaintext))
      result = adapter.get_decrypted("docs/secret.txt")
      expect(result.read).to eq(plaintext)
    end

    it "stores encrypted bytes (not plaintext)" do
      adapter.put_encrypted("docs/secret.txt", StringIO.new(plaintext))
      raw = fake_s3.store["docs/secret.txt"]
      expect(raw).not_to include(plaintext[0..20])
      expect(raw.byteslice(0, 4)).to eq("ACS\x01".b)
    end

    it "handles binary payloads" do
      binary = SecureRandom.random_bytes(256)
      adapter.put_encrypted("bin/data", StringIO.new(binary))
      expect(adapter.get_decrypted("bin/data").read).to eq(binary)
    end
  end

  describe "multipart upload (large file)" do
    before do
      ActiveCipherStorage.configure { |c| c.chunk_size = 128 }
    end

    let(:big_plaintext) { SecureRandom.random_bytes(600) }  # > multipart_threshold

    it "uses multiple parts for large files" do
      io = StringIO.new(big_plaintext)
      allow(io).to receive(:size).and_return(big_plaintext.bytesize)
      adapter.put_encrypted("large/file.bin", io)
      expect(fake_s3.store).to have_key("large/file.bin")
    end

    it "round-trips a large file through multipart upload" do
      io = StringIO.new(big_plaintext)
      allow(io).to receive(:size).and_return(big_plaintext.bytesize)
      adapter.put_encrypted("large/file.bin", io)

      result = adapter.get_decrypted("large/file.bin")
      expect(result.read).to eq(big_plaintext)
    end

    it "does not mask create_multipart_upload failures with abort cleanup errors" do
      original_error = RuntimeError.new("create failed")
      allow(fake_s3).to receive(:create_multipart_upload).and_raise(original_error)
      allow(fake_s3).to receive(:abort_multipart_upload).and_raise("abort should not happen")

      io = StringIO.new(big_plaintext)
      allow(io).to receive(:size).and_return(big_plaintext.bytesize)

      expect { adapter.put_encrypted("large/file.bin", io) }
        .to raise_error(original_error)
    end
  end

  describe "#exist?" do
    it "returns false for a missing key" do
      expect(adapter.exist?("no/such/key")).to be false
    end

    it "returns true after upload" do
      adapter.put_encrypted("present", StringIO.new("data"))
      expect(adapter.exist?("present")).to be true
    end
  end

  describe "#delete" do
    it "removes the object" do
      adapter.put_encrypted("to/delete", StringIO.new("bye"))
      adapter.delete("to/delete")
      expect(adapter.exist?("to/delete")).to be false
    end
  end

  describe "error handling" do
    it "re-raises provider errors as KeyManagementError" do
      allow(ActiveCipherStorage.configuration.provider)
        .to receive(:generate_data_key)
        .and_raise(ActiveCipherStorage::Errors::KeyManagementError, "KMS down")

      expect { adapter.put_encrypted("k", StringIO.new("x")) }
        .to raise_error(ActiveCipherStorage::Errors::KeyManagementError, "KMS down")
    end
  end
end
