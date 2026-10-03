module IPAddress
  #
  # =Name
  #
  # IPAddress::RFC6052 - IPv6 Addressing of IPv4/IPv6 Translators
  #
  # =Description
  #
  # RFC 6052 defines how IPv4 addresses are embedded into IPv6
  # addresses for stateless IPv4/IPv6 translation (NAT64 and
  # friends). The IPv4 address is split around a reserved
  # "u" octet (bits 64..71, which must be zero) and the
  # embedding is defined for the following IPv6 prefix lengths
  # only: 32, 40, 48, 56, 64 and 96.
  #
  # This module holds the bit-level layout and the pure
  # address-computation functions. It never creates sockets
  # nor performs any network operation.
  #
  module RFC6052

    #
    # IPv6 prefix lengths for which RFC 6052 defines the
    # IPv4 embedding.
    #
    PREFIX_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

    #
    # Number of IPv4 bits embedded before the reserved
    # "u" octet (bits 64..71), indexed by prefix length.
    # The remaining 32 - n bits are embedded right after
    # the "u" octet (or at bit 96 for a /96 prefix).
    #
    HIGH_BITS = {32 => 32, 40 => 24, 48 => 16, 56 => 8, 64 => 0, 96 => 0}.freeze

    #
    # True if the given prefix length is allowed by RFC 6052.
    #
    def self.valid_prefix_length?(prefix)
      PREFIX_LENGTHS.include?(prefix)
    end

    #
    # Raises ArgumentError unless the prefix length is
    # allowed by RFC 6052.
    #
    def self.validate_prefix_length!(prefix)
      unless valid_prefix_length?(prefix)
        raise ArgumentError,
          "Invalid RFC6052 prefix length #{prefix.inspect}, " +          "must be one of #{PREFIX_LENGTHS.join(', ')}"
      end
    end

    #
    # Coerces the argument into an IPAddress::IPv6 object and
    # checks that its prefix length is a valid RFC 6052 one.
    # Accepts an IPAddress::IPv6 or anything that can be
    # parsed into one (e.g. "64:ff9b::/96").
    #
    def self.network(obj)
      net = obj.is_a?(IPAddress::IPv6) ? obj : IPAddress::IPv6.new(obj.to_s)
      validate_prefix_length!(net.prefix.to_i)
      net
    end

    #
    # Embeds an IPv4 address (as an unsigned 32 bit integer)
    # into an IPv6 prefix (as an unsigned 128 bit integer),
    # following the RFC 6052 Section 2.2 layout, and returns
    # the resulting unsigned 128 bit integer.
    #
    #   IPAddress::RFC6052.encode_u128(0xc0000221, 0x64ff9b000000000000000000000000, 96)
    #     #=> 0x64ff9b000000000000000000c0000221
    #
    def self.encode_u128(u32, prefix_u128, prefix_len)
      validate_prefix_length!(prefix_len)
      high = HIGH_BITS[prefix_len]
      low = 32 - high
      hi = high.zero? ? 0 : u32 >> low
      lo = low.zero? ? 0 : u32 & ((1 << low) - 1)
      prefix_u128 | (hi << 64) | (lo << low_shift(prefix_len, low))
    end

    #
    # Extracts the embedded IPv4 address from an IPv6 address
    # (both as unsigned integers) according to the RFC 6052
    # layout for the given prefix length. No validation is
    # performed here besides the prefix length: use
    # IPAddress::IPv6#rfc6052_status to validate an address.
    #
    def self.decode_u32(u128, prefix_len)
      validate_prefix_length!(prefix_len)
      high = HIGH_BITS[prefix_len]
      low = 32 - high
      hi = high.zero? ? 0 : (u128 >> 64) & ((1 << high) - 1)
      lo = low.zero? ? 0 : (u128 >> low_shift(prefix_len, low)) & ((1 << low) - 1)
      (hi << low) | lo
    end

    #
    # Returns the value of the reserved "u" octet
    # (bits 64..71) of the given IPv6 address. RFC 6052
    # requires it to be zero.
    #
    def self.reserved_bits(u128)
      (u128 >> 56) & 0xff
    end

    #
    # Bit shift of the IPv4 chunk embedded after the
    # reserved octet.
    #
    def self.low_shift(prefix_len, low) # :nodoc:
      prefix_len == 96 ? 0 : 56 - low
    end

  end # module RFC6052
end # module IPAddress
