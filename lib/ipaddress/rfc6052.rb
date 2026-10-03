require 'ipaddress/ipv4'
require 'ipaddress/ipv6'

module IPAddress
  #
  # =Name
  #
  # IPAddress::RFC6052 - IPv6 addressing of IPv4/IPv6 translators
  #
  # =Synopsis
  #
  #    require 'ipaddress'
  #
  # =Description
  #
  # Class IPAddress::RFC6052 implements the address mapping defined
  # by RFC 6052 ("IPv6 Addressing of IPv4/IPv6 Translators"), commonly
  # used by NAT64 gateways to embed IPv4 addresses into IPv6 ones.
  #
  # An IPv4-embedded IPv6 address is composed of a variable length
  # prefix, the embedded IPv4 address, a reserved "u" octet (bits
  # 64-71, which must be zero) and a suffix:
  #
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |PL| 0-------------72--64--56--48--40--32--24--16--8--------------0|
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |32|     prefix    |v4(32)         | u | suffix                    |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |40|     prefix        |v4(24)     | u |(8)| suffix                |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |48|     prefix            |v4(16)  | u | (16)  | suffix            |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |56|     prefix                |(8)| u |  v4(24)   | suffix        |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |64|     prefix                    | u |   v4(32)      | suffix    |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #   |96|     prefix                                    | v4(32)        |
  #   +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  #
  # The only prefix lengths allowed by the RFC are 32, 40, 48, 56, 64
  # and 96. The Well-Known Prefix 64:ff9b::/96 is used by default:
  #
  #   nat64 = IPAddress::RFC6052.new
  #   nat64.encode("192.0.2.33").to_s
  #     #=> "64:ff9b::c000:221"
  #
  # A Network-Specific Prefix with any of the allowed lengths can be
  # used instead:
  #
  #   nsp = IPAddress::RFC6052.new "2001:db8:100::/40"
  #   nsp.encode("192.0.2.33").to_s
  #     #=> "2001:db8:1c0:2:21::"
  #
  # The class only performs address calculations: it never creates
  # sockets nor queries the network.
  #
  class RFC6052

    #
    # Prefix lengths allowed by RFC 6052 for the IPv4/IPv6
    # translator prefix.
    #
    PREFIX_LENGTHS = [32, 40, 48, 56, 64, 96].freeze

    #
    # The Well-Known Prefix (WKP) reserved by RFC 6052 for the
    # algorithmic mapping of IPv4 addresses, 64:ff9b::/96.
    #
    WELL_KNOWN_PREFIX = "64:ff9b::/96"

    #
    # Status codes returned by RFC6052#decode_status
    #
    STATUS_VALID                 = :valid
    STATUS_NOT_IN_NETWORK        = :not_in_network
    STATUS_INVALID_RESERVED_BITS = :invalid_reserved_bits
    STATUS_IPV4_MAPPED           = :ipv4_mapped

    #
    # The IPv6 network used as translator prefix, as an
    # IPAddress::IPv6 object with the host bits zeroed.
    #
    attr_reader :prefix

    #
    # Creates a new RFC6052 translator mapper.
    #
    # With no arguments, the Well-Known Prefix 64:ff9b::/96 is used:
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.prefix.to_string
    #     #=> "64:ff9b::/96"
    #
    # A Network-Specific Prefix can be supplied as a string or as an
    # IPAddress::IPv6 object. Its prefix length must be one of those
    # allowed by RFC 6052: 32, 40, 48, 56, 64 or 96.
    #
    #   nsp = IPAddress::RFC6052.new "2001:db8::/32"
    #   nsp.prefix.to_string
    #     #=> "2001:db8::/32"
    #
    # Any host bit set in the given address is zeroed, so that the
    # prefix is always stored as a network:
    #
    #   nsp = IPAddress::RFC6052.new "2001:db8::1/32"
    #   nsp.prefix.to_string
    #     #=> "2001:db8::/32"
    #
    def initialize(prefix = WELL_KNOWN_PREFIX)
      prefix = IPAddress::IPv6.new(prefix) if prefix.is_a? String
      unless prefix.is_a? IPAddress::IPv6
        raise ArgumentError, "Invalid IPv6 prefix #{prefix.inspect}"
      end
      unless PREFIX_LENGTHS.include? prefix.prefix.to_i
        raise ArgumentError, "Prefix length must be one of #{PREFIX_LENGTHS.join(", ")}, got: #{prefix.prefix}"
      end
      @prefix = prefix.network
    end

    #
    # Returns the length of the translator prefix
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.prefix_length
    #     #=> 96
    #
    def prefix_length
      @prefix.prefix.to_i
    end

    #
    # Encodes an IPv4 address into its IPv4-embedded IPv6 address,
    # as defined by RFC 6052. The argument can be an IPAddress::IPv4
    # object or a string. The suffix bits are set to zero.
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.encode("192.0.2.33").to_s
    #     #=> "64:ff9b::c000:221"
    #
    #   nsp = IPAddress::RFC6052.new "2001:db8::/32"
    #   nsp.encode("192.0.2.33").to_s
    #     #=> "2001:db8:c000:221::"
    #
    def encode(ipv4)
      ipv4 = IPAddress::IPv4.new(ipv4) if ipv4.is_a? String
      unless ipv4.is_a? IPAddress::IPv4
        raise ArgumentError, "Invalid IPv4 address #{ipv4.inspect}"
      end
      IPAddress::IPv6.parse_u128(network_u128 | embed(ipv4.to_u32))
    end

    #
    # Decodes an IPv4-embedded IPv6 address back to its IPv4 address.
    # Returns an IPAddress::IPv4 object if the address is a valid
    # RFC 6052 mapping for this translator prefix, nil otherwise.
    # Use RFC6052#decode_status to know why an address was rejected.
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.decode("64:ff9b::c000:221").to_s
    #     #=> "192.0.2.33"
    #
    #   nat64.decode("2001:db8::1")
    #     #=> nil
    #
    def decode(ipv6)
      return nil unless decode_status(ipv6) == STATUS_VALID
      IPAddress::IPv4.parse_u32(extract(to_ipv6(ipv6).to_u128))
    end

    #
    # Checks whether an IPv6 address is a valid RFC 6052 mapping for
    # this translator prefix, and why not. Returns one of the
    # following symbols:
    #
    # * +:valid+: the address belongs to the translator prefix, its
    #   reserved bits are zero and it can be decoded to an IPv4
    #   address
    # * +:not_in_network+: the address does not belong to the
    #   translator prefix
    # * +:invalid_reserved_bits+: the "u" octet (bits 64-71), which
    #   RFC 6052 requires to be zero, has some bit set
    # * +:ipv4_mapped+: the address is an IPv4-mapped IPv6 address
    #   (::ffff:a.b.c.d), which is a different transition mechanism
    #   and must not be confused with an RFC 6052 mapping
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.decode_status "64:ff9b::c000:221"
    #     #=> :valid
    #   nat64.decode_status "2001:db8::1"
    #     #=> :not_in_network
    #   nat64.decode_status "::ffff:192.0.2.33"
    #     #=> :ipv4_mapped
    #
    def decode_status(ipv6)
      ipv6 = to_ipv6(ipv6)
      return STATUS_IPV4_MAPPED if ipv6.mapped?
      return STATUS_NOT_IN_NETWORK unless include? ipv6
      if prefix_length != 96 && (ipv6.to_u128 >> 56) & 0xff != 0
        return STATUS_INVALID_RESERVED_BITS
      end
      STATUS_VALID
    end

    #
    # True if the IPv6 address belongs to the translator prefix,
    # regardless of the reserved bits:
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.include? "64:ff9b::c000:221"
    #     #=> true
    #   nat64.include? "2001:db8::1"
    #     #=> false
    #
    def include?(ipv6)
      ipv6 = to_ipv6(ipv6)
      shift = 128 - prefix_length
      (ipv6.to_u128 >> shift) == (network_u128 >> shift)
    end

    #
    # True if the IPv6 address is a valid RFC 6052 mapping for this
    # translator prefix:
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.valid? "64:ff9b::c000:221"
    #     #=> true
    #
    def valid?(ipv6)
      decode_status(ipv6) == STATUS_VALID
    end

    #
    # Maps a whole IPv4 network to the compact set of IPv6 prefixes
    # that represent it through this translator prefix.
    #
    # The result is the minimal set of IPv6 networks such that every
    # IPv6 address decoding to an IPv4 address of the given network
    # belongs to exactly one of them. Each returned network carries
    # the translator prefix, the zeroed "u" octet and the embedded
    # bits of the IPv4 network in its fixed bits, so the IPv4 network
    # can be recovered by decoding any address of each network.
    #
    # With the Well-Known Prefix (or any /96) the embedded IPv4 bits
    # are contiguous, so any IPv4 network maps to a single IPv6
    # network:
    #
    #   nat64 = IPAddress::RFC6052.new
    #   nat64.encode_network("192.0.2.0/24").map{|i| i.to_string}
    #     #=> ["64:ff9b::c000:200/120"]
    #
    # With shorter prefixes the IPv4 bits straddle the reserved "u"
    # octet. When the host part of the IPv4 network crosses that
    # boundary, the mapped addresses do not form a contiguous IPv6
    # network, and the result is the exact set of IPv6 networks
    # covering them, without aggregating them into a larger network
    # that would include invalid or unrelated addresses:
    #
    #   nsp = IPAddress::RFC6052.new "2001:db8:100:200::/56"
    #   nsp.encode_network("192.0.0.0/6").map{|i| i.to_string}
    #     #=> ["2001:db8:100:2c0::/72",
    #     #    "2001:db8:100:2c1::/72",
    #     #    "2001:db8:100:2c2::/72",
    #     #    "2001:db8:100:2c3::/72"]
    #
    def encode_network(ipv4)
      ipv4 = IPAddress::IPv4.new(ipv4) if ipv4.is_a? String
      unless ipv4.is_a? IPAddress::IPv4
        raise ArgumentError, "Invalid IPv4 network #{ipv4.inspect}"
      end
      ipv4 = ipv4.network
      plen = prefix_length
      if plen == 96
        # The embedded IPv4 bits are the low 32 bits: the mapping of
        # any IPv4 network is a single IPv6 network.
        return [to_ipv6_network(network_u128 | ipv4.to_u32, plen + ipv4.prefix.to_i)]
      end
      # Width of the IPv4 high bits field, placed just below the
      # reserved "u" octet.
      hi_width = 64 - plen
      if ipv4.prefix.to_i >= hi_width
        # All the variable IPv4 bits lie past the "u" octet, so the
        # mapping is a single IPv6 network.
        return [to_ipv6_network(network_u128 | embed(ipv4.to_u32), plen + 8 + ipv4.prefix.to_i)]
      end
      # The IPv4 network boundary falls inside the high bits field:
      # the mapped addresses are split by the "u" octet into one IPv6
      # network per value of the variable high bits.
      hi_first = ipv4.to_u32 >> (32 - hi_width)
      (hi_first...(hi_first + (1 << (hi_width - ipv4.prefix.to_i)))).map do |hi|
        to_ipv6_network(network_u128 | (hi << 64), 72)
      end
    end

    private

    def network_u128
      @prefix.network_u128
    end

    def to_ipv6(ipv6)
      ipv6 = IPAddress::parse(ipv6) if ipv6.is_a? String
      unless ipv6.is_a? IPAddress::IPv6
        raise ArgumentError, "Invalid IPv6 address #{ipv6.inspect}"
      end
      ipv6
    end

    def to_ipv6_network(u128, prefix_length)
      IPAddress::IPv6.parse_u128(u128, prefix_length)
    end

    #
    # Places the 32 bits of an IPv4 address around the reserved "u"
    # octet, as per the RFC 6052 bit layout. The translator prefix
    # itself is not included.
    #
    def embed(u32)
      plen = prefix_length
      case plen
      when 96
        u32
      when 32
        u32 << 64
      else
        hi = u32 >> (plen - 32)
        lo = u32 & ((1 << (plen - 32)) - 1)
        (hi << 64) | (lo << (88 - plen))
      end
    end

    #
    # Extracts the 32 bits of the embedded IPv4 address from an IPv6
    # address belonging to the translator prefix.
    #
    def extract(u128)
      plen = prefix_length
      case plen
      when 96
        u128 & 0xffffffff
      when 32
        (u128 >> 64) & 0xffffffff
      else
        hi = (u128 >> 64) & ((1 << (64 - plen)) - 1)
        lo = (u128 >> (88 - plen)) & ((1 << (plen - 32)) - 1)
        (hi << (plen - 32)) | lo
      end
    end

  end # class RFC6052
end # module IPAddress

