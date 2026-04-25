require "spec_helper"

RSpec.describe ActiveCipherStorage::Format do
  let(:header) do
    described_class::Header.new(
      version: described_class::VERSION,
      algorithm: described_class::ALGO_AES256GCM,
      chunked: false,
      chunk_size: 0,
      provider_id: "env",
      encrypted_dek: "wrapped-key".b
    )
  end

  it "round-trips headers" do
    io = StringIO.new("".b)

    described_class.write_header(io, header)
    io.rewind

    parsed = described_class.read_header(io)
    expect(parsed.version).to eq(described_class::VERSION)
    expect(parsed.algorithm).to eq(described_class::ALGO_AES256GCM)
    expect(parsed.chunked).to be false
    expect(parsed.chunk_size).to eq(0)
    expect(parsed.provider_id).to eq("env")
    expect(parsed.encrypted_dek).to eq("wrapped-key")
  end

  it "rejects unsupported versions" do
    io = StringIO.new("".b)
    described_class.write_header(io, header)
    io.string.setbyte(4, 0x02)
    io.rewind

    expect { described_class.read_header(io) }
      .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /Unsupported version/)
  end

  it "rejects unsupported algorithms" do
    io = StringIO.new("".b)
    described_class.write_header(io, header)
    io.string.setbyte(5, 0x02)
    io.rewind

    expect { described_class.read_header(io) }
      .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /Unsupported algorithm/)
  end

  it "rejects unknown header flags" do
    io = StringIO.new("".b)
    described_class.write_header(io, header)
    io.string.setbyte(6, 0x80)
    io.rewind

    expect { described_class.read_header(io) }
      .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /Unsupported flags/)
  end

  it "rejects truncated chunks" do
    io = StringIO.new([1].pack("N") + "short")

    expect { described_class.read_chunk(io) }
      .to raise_error(ActiveCipherStorage::Errors::InvalidFormat, /Unexpected end of stream/)
  end
end
