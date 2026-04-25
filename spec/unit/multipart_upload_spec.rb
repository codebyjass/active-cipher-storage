require "spec_helper"

RSpec.describe ActiveCipherStorage::EncryptedMultipartUpload do
  before { configure_env_provider }

  let(:bucket)    { "test-bucket" }
  let(:upload_id) { "s3-mpu-#{SecureRandom.hex(4)}" }
  let(:parts_log) { [] }

  let(:s3) do
    double("S3Client").tap do |s3|
      allow(s3).to receive(:create_multipart_upload) do
        double("Response", upload_id: upload_id)
      end
      allow(s3).to receive(:upload_part) do |args|
        parts_log << { part_number: args[:part_number], size: args[:body].bytesize }
        double("Response", etag: "etag-#{args[:part_number]}")
      end
      allow(s3).to receive(:complete_multipart_upload)
      allow(s3).to receive(:abort_multipart_upload)
    end
  end

  subject(:uploader) { described_class.new(s3_client: s3, bucket: bucket) }

  let(:chunk_size) { ActiveCipherStorage.configuration.chunk_size }

  describe "#initiate" do
    it "returns an opaque session_id string" do
      session_id = uploader.initiate(key: "uploads/doc.pdf")
      expect(session_id).to be_a(String)
      expect(session_id.length).to be > 10
    end

    it "creates an S3 multipart upload" do
      uploader.initiate(key: "uploads/doc.pdf")
      expect(s3).to have_received(:create_multipart_upload)
        .with(hash_including(bucket: bucket, key: "uploads/doc.pdf"))
    end
  end

  describe "#upload_part / #complete" do
    it "completes a single-chunk upload" do
      session_id = uploader.initiate(key: "uploads/doc.pdf")
      uploader.upload_part(session_id: session_id, chunk_io: StringIO.new("hello world"))
      result = uploader.complete(session_id: session_id)

      expect(result[:status]).to eq(:completed)
      expect(result[:key]).to eq("uploads/doc.pdf")
      expect(s3).to have_received(:complete_multipart_upload)
    end

    it "flushes a part to S3 once the buffer exceeds chunk_size" do
      session_id = uploader.initiate(key: "uploads/big.bin")

      # One full chunk_size chunk: header + frame > chunk_size → should flush one part.
      uploader.upload_part(
        session_id: session_id,
        chunk_io: StringIO.new(SecureRandom.random_bytes(chunk_size))
      )
      expect(parts_log.length).to be >= 1

      uploader.complete(session_id: session_id)
    end

    it "returns :ok status from upload_part" do
      session_id = uploader.initiate(key: "uploads/doc.pdf")
      result = uploader.upload_part(session_id: session_id,
                                    chunk_io: StringIO.new("small chunk"))
      expect(result[:status]).to eq(:ok)
    end

    it "accumulates small chunks without flushing until buffer is large enough" do
      session_id = uploader.initiate(key: "uploads/small.txt")
      5.times { uploader.upload_part(session_id: session_id, chunk_io: StringIO.new("x" * 100)) }

      # Buffer is tiny (< chunk_size) so no parts should have been flushed yet.
      expect(parts_log).to be_empty

      uploader.complete(session_id: session_id)
      # After complete, everything is flushed as the final part.
      expect(parts_log.length).to eq(1)
    end

    it "raises for an unknown session_id" do
      expect { uploader.upload_part(session_id: "bogus", chunk_io: StringIO.new("")) }
        .to raise_error(ActiveCipherStorage::Errors::Error, /not found/)
    end
  end

  describe "#abort" do
    it "aborts the S3 multipart upload" do
      session_id = uploader.initiate(key: "uploads/cancelled.pdf")
      uploader.abort(session_id: session_id)
      expect(s3).to have_received(:abort_multipart_upload)
    end

    it "is a no-op for an unknown session_id" do
      expect { uploader.abort(session_id: "unknown") }.not_to raise_error
    end
  end

  describe "error handling in #complete" do
    it "aborts the S3 upload and re-raises if complete_multipart_upload fails" do
      allow(s3).to receive(:complete_multipart_upload).and_raise(RuntimeError, "S3 down")
      session_id = uploader.initiate(key: "uploads/fail.pdf")
      uploader.upload_part(session_id: session_id, chunk_io: StringIO.new("data"))
      expect { uploader.complete(session_id: session_id) }
        .to raise_error(RuntimeError, "S3 down")
      expect(s3).to have_received(:abort_multipart_upload)
    end
  end
end
