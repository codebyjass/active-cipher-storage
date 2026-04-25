module ActiveCipherStorage
  # Binary format v1:
  #
  # Header
  #   [4]  Magic "ACS\x01"
  #   [1]  Version (0x01)
  #   [1]  Algorithm (0x01 = AES-256-GCM)
  #   [1]  Flags    (bit 0 = chunked)
  #   [4]  Chunk-size hint (uint32 BE; 0 if non-chunked)
  #   [2]  Provider-ID length (uint16 BE)
  #   [N]  Provider ID (UTF-8)
  #   [2]  Encrypted DEK length (uint16 BE)
  #   [M]  Encrypted DEK bytes
  #
  # Non-chunked payload:  [12 IV] [K ciphertext] [16 auth-tag]
  #
  # Chunked payload (repeat until seq == FINAL_SEQ):
  #   [4]  Sequence number (1-based; FINAL_SEQ = 0xFFFFFFFF marks last frame)
  #   [12] Chunk IV
  #   [4]  Ciphertext length (uint32 BE)
  #   [K]  Ciphertext
  #   [16] Auth tag
  #
  # The final frame may carry zero-length ciphertext when the plaintext length
  # is an exact multiple of chunk_size.
  module Format
    MAGIC          = "ACS\x01".b.freeze
    VERSION        = 0x01
    ALGO_AES256GCM = 0x01
    FLAG_CHUNKED   = 0x01
    IV_SIZE        = 12
    AUTH_TAG_SIZE  = 16
    FINAL_SEQ      = 0xFFFF_FFFF

    Header = Struct.new(
      :version, :algorithm, :chunked, :chunk_size, :provider_id, :encrypted_dek,
      keyword_init: true
    )

    def self.write_header(io, header)
      provider_bytes = header.provider_id.encode("UTF-8").b
      flags = header.chunked ? FLAG_CHUNKED : 0x00

      io.write(MAGIC)
      io.write([VERSION].pack("C"))
      io.write([ALGO_AES256GCM].pack("C"))
      io.write([flags].pack("C"))
      io.write([header.chunk_size.to_i].pack("N"))
      io.write([provider_bytes.bytesize].pack("n"))
      io.write(provider_bytes)
      io.write([header.encrypted_dek.bytesize].pack("n"))
      io.write(header.encrypted_dek)
    end

    def self.read_header(io)
      magic = safe_read(io, 4)
      raise Errors::InvalidFormat, "Invalid magic bytes" unless magic == MAGIC

      version   = safe_read(io, 1).unpack1("C")
      algorithm = safe_read(io, 1).unpack1("C")
      flags     = safe_read(io, 1).unpack1("C")
      chunk_sz  = safe_read(io, 4).unpack1("N")

      validate_header_fields!(version, algorithm, flags)

      provider_len  = safe_read(io, 2).unpack1("n")
      provider_id   = safe_read(io, provider_len).force_encoding("UTF-8")

      dek_len       = safe_read(io, 2).unpack1("n")
      encrypted_dek = safe_read(io, dek_len)

      Header.new(
        version:       version,
        algorithm:     algorithm,
        chunked:       (flags & FLAG_CHUNKED) != 0,
        chunk_size:    chunk_sz,
        provider_id:   provider_id,
        encrypted_dek: encrypted_dek
      )
    end

    def self.write_chunk(io, seq:, iv:, ciphertext:, auth_tag:)
      io.write([seq].pack("N"))
      io.write(iv)
      io.write([ciphertext.bytesize].pack("N"))
      io.write(ciphertext)
      io.write(auth_tag)
    end

    # Returns { seq:, iv:, ciphertext:, auth_tag: } or nil on clean EOF.
    def self.read_chunk(io)
      seq_bytes = io.read(4)
      return nil if seq_bytes.nil? || seq_bytes.empty?

      seq        = seq_bytes.unpack1("N")
      iv         = safe_read(io, IV_SIZE)
      ct_len     = safe_read(io, 4).unpack1("N")
      ciphertext = ct_len.positive? ? safe_read(io, ct_len) : "".b
      auth_tag   = safe_read(io, AUTH_TAG_SIZE)

      { seq: seq, iv: iv, ciphertext: ciphertext, auth_tag: auth_tag }
    end

    private_class_method def self.safe_read(io, n)
      data = io.read(n)
      unless data && data.bytesize == n
        raise Errors::InvalidFormat,
              "Unexpected end of stream: expected #{n} bytes, got #{data&.bytesize || 0}"
      end
      data
    end

    private_class_method def self.validate_header_fields!(version, algorithm, flags)
      raise Errors::InvalidFormat, "Unsupported version: #{version}" unless version == VERSION

      unless algorithm == ALGO_AES256GCM
        raise Errors::InvalidFormat, "Unsupported algorithm: #{algorithm}"
      end

      unknown_flags = flags & ~FLAG_CHUNKED
      return if unknown_flags.zero?

      raise Errors::InvalidFormat, "Unsupported flags: 0x#{unknown_flags.to_s(16)}"
    end
  end
end
