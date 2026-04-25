require "spec_helper"

# In-memory S3 with multipart upload support.
class FakeS3Multipart
  def initialize
    @objects = {}
    @uploads = {}
  end

  def create_multipart_upload(bucket:, key:, **)
    id = SecureRandom.hex(8)
    @uploads[id] = { key: key, parts: {} }
    Struct.new(:upload_id).new(id)
  end

  def upload_part(bucket:, key:, upload_id:, part_number:, body:)
    @uploads[upload_id][:parts][part_number] =
      body.respond_to?(:read) ? body.read.b : body.dup.b
    Struct.new(:etag).new("etag-#{part_number}")
  end

  def complete_multipart_upload(bucket:, key:, upload_id:, multipart_upload:)
    ordered = multipart_upload[:parts].sort_by { |p| p[:part_number] }
    @objects[key] = ordered.map { |p| @uploads[upload_id][:parts][p[:part_number]] }.join.b
    @uploads.delete(upload_id)
  end

  def abort_multipart_upload(bucket:, key:, upload_id:)
    @uploads.delete(upload_id)
  end

  # Yields object bytes in configurable chunk sizes (default: all at once).
  def get_object(bucket:, key:, yield_size: nil, &block)
    data = @objects.fetch(key) { raise "Object not found: #{key}" }
    if block
      if yield_size
        pos = 0
        while pos < data.bytesize
          block.call(data.byteslice(pos, yield_size))
          pos += yield_size
        end
      else
        block.call(data)
      end
      nil
    else
      Struct.new(:body).new(StringIO.new(data))
    end
  end
end

RSpec.describe "Multipart upload + streaming download round-trip" do
  before { configure_env_provider }

  let(:config)     { ActiveCipherStorage.configuration }
  let(:chunk_size) { config.chunk_size }
  let(:bucket)     { "test-bucket" }
  let(:key)        { "uploads/test-#{SecureRandom.hex(4)}.bin" }
  let(:s3)         { FakeS3Multipart.new }

  let(:uploader) { ActiveCipherStorage::EncryptedMultipartUpload.new(s3_client: s3, bucket: bucket) }
  let(:adapter)  { ActiveCipherStorage::Adapters::S3Adapter.new(bucket: bucket, s3_client: s3) }

  def upload_in_parts(plaintext, part_size:)
    session_id = uploader.initiate(key: key)
    pos = 0
    while pos < plaintext.bytesize
      uploader.upload_part(session_id: session_id,
                           chunk_io: StringIO.new(plaintext.byteslice(pos, part_size)))
      pos += part_size
    end
    uploader.complete(session_id: session_id)
  end

  shared_examples "correct round-trip" do |label|
    context label do
      it "stream_decrypted yields the original plaintext" do
        upload_in_parts(plaintext, part_size: upload_part_size)
        collected = "".b
        adapter.stream_decrypted(key) { |c| collected += c }
        expect(collected).to eq(plaintext)
      end

      it "get_decrypted returns the original plaintext" do
        upload_in_parts(plaintext, part_size: upload_part_size)
        expect(adapter.get_decrypted(key).read).to eq(plaintext)
      end
    end
  end

  context "with chunks larger than chunk_size" do
    let(:plaintext)        { SecureRandom.random_bytes(3 * chunk_size + 37) }
    let(:upload_part_size) { chunk_size + 1024 }

    include_examples "correct round-trip", "FE sends chunks larger than ACS chunk_size"
  end

  context "with chunks smaller than chunk_size (heavy buffering)" do
    let(:plaintext)        { SecureRandom.random_bytes(chunk_size + 500) }
    let(:upload_part_size) { 256 * 1024 }  # 256 KiB

    include_examples "correct round-trip", "FE sends small 256 KiB chunks"
  end

  context "with a single chunk (entire file at once)" do
    let(:plaintext)        { SecureRandom.random_bytes(chunk_size - 1) }
    let(:upload_part_size) { plaintext.bytesize }

    include_examples "correct round-trip", "FE sends the whole file as one chunk"
  end

  context "with an exact chunk_size boundary" do
    let(:plaintext)        { SecureRandom.random_bytes(chunk_size) }
    let(:upload_part_size) { chunk_size }

    include_examples "correct round-trip", "plaintext is exactly chunk_size bytes"
  end

  describe "stream_decrypted with S3 delivering data in tiny pieces" do
    it "correctly decrypts when S3 yields 512-byte network packets" do
      plaintext = SecureRandom.random_bytes(2 * chunk_size + 77)
      upload_in_parts(plaintext, part_size: chunk_size)

      # Override get_object to yield in 512-byte pieces.
      raw = s3.instance_variable_get(:@objects)[key]
      allow(s3).to receive(:get_object) do |_args, &blk|
        pos = 0
        while pos < raw.bytesize
          blk.call(raw.byteslice(pos, 512))
          pos += 512
        end
      end

      collected = "".b
      adapter.stream_decrypted(key) { |c| collected += c }
      expect(collected).to eq(plaintext)
    end
  end

  describe "tampered data detection" do
    it "raises DecryptionError if a byte in the ciphertext body is flipped" do
      plaintext = SecureRandom.random_bytes(chunk_size + 100)
      upload_in_parts(plaintext, part_size: chunk_size)

      # Flip a byte deep in the ciphertext (past the header).
      raw = s3.instance_variable_get(:@objects)[key]
      raw.setbyte(raw.bytesize / 2, raw.getbyte(raw.bytesize / 2) ^ 0xFF)

      expect {
        adapter.stream_decrypted(key) { |_| }
      }.to raise_error(ActiveCipherStorage::Errors::DecryptionError)
    end
  end

  describe "invalid streaming inputs" do
    it "rejects non-chunked encrypted objects with a clear error" do
      encrypted = ActiveCipherStorage::Cipher.new.encrypt(StringIO.new("small secret".b))
      s3.instance_variable_get(:@objects)[key] = encrypted

      expect {
        adapter.stream_decrypted(key) { |_| }
      }.to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /not chunked/)
    end

    it "rejects non-ACS objects without waiting for the header buffer limit" do
      s3.instance_variable_get(:@objects)[key] = "plaintext object".b

      expect {
        adapter.stream_decrypted(key) { |_| }
      }.to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /Invalid magic bytes/)
    end
  end
end
