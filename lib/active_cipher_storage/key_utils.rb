module ActiveCipherStorage
  module KeyUtils
    private

    # Best-effort in-place zeroing. Ruby GC may retain copies, but this
    # reduces the window during which a key sits in heap memory.
    def zero_bytes!(str)
      return unless str.is_a?(String)
      str.bytesize.times { |i| str.setbyte(i, 0) }
    end
  end
end
