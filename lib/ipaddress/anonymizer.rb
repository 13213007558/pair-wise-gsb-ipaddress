require 'openssl'

module IPAddress

  # Reversible, prefix-preserving IP address anonymization.
  class Anonymizer

    SALT = "IPAddress/Anonymizer/v1/HKDF-SHA256"
    private_constant :SALT

    IPV4_TAG = "IPAddress/Anonymizer/v1/IPv4"
    IPV6_TAG = "IPAddress/Anonymizer/v1/IPv6"
    private_constant :IPV4_TAG, :IPV6_TAG

    # Internal binary-tree permutation. It is used by Anonymizer and by the
    # exhaustive small-width property tests.
    class PrefixPermutation

      def initialize(prf_key, width, domain_tag)
        unless prf_key.is_a?(String) && prf_key.bytesize == 32
          raise ArgumentError, "prf_key must be a 32 byte binary String"
        end
        unless width.is_a?(Integer) && width > 0
          raise ArgumentError, "width must be a positive Integer"
        end
        unless domain_tag.is_a?(String) && !domain_tag.empty?
          raise ArgumentError, "domain_tag must be a non-empty String"
        end

        @prf_key = prf_key.dup.freeze
        @width = width
        @domain_tag = domain_tag.dup.freeze
        @width_bytes = (width / 8.0).ceil
      end

      def forward(value)
        validate_value!(value)

        input_prefix = 0
        output = 0

        @width.times do |depth|
          input_bit = bit_at(value, depth)
          output_bit = input_bit ^ permutation_bit(input_prefix, depth)
          input_prefix = (input_prefix << 1) | input_bit
          output = (output << 1) | output_bit
        end

        output
      end

      def inverse(value)
        validate_value!(value)

        input_prefix = 0
        result = 0

        @width.times do |depth|
          output_bit = bit_at(value, depth)
          input_bit = output_bit ^ permutation_bit(input_prefix, depth)
          input_prefix = (input_prefix << 1) | input_bit
          result = (result << 1) | input_bit
        end

        result
      end

      private

      def bit_at(value, depth)
        (value >> (@width - depth - 1)) & 1
      end

      def permutation_bit(prefix, depth)
        prefix_bytes = Array.new(@width_bytes) do |index|
          (prefix >> (8 * (@width_bytes - index - 1))) & 0xff
        end.pack("C*")
        message = [@domain_tag, depth, @width_bytes, prefix_bytes].pack("a*CQ>a*")
        OpenSSL::HMAC.digest("SHA256", @prf_key, message).getbyte(0) >> 7
      end

      def validate_value!(value)
        unless value.is_a?(Integer) && value >= 0 && value < (1 << @width)
          raise ArgumentError, "value must be an unsigned #{@width}-bit Integer"
        end
      end

    end # class PrefixPermutation

    # Creates an anonymizer. +key+ must be 32 bytes of cryptographically
    # secure random key material, shared out of band by the systems that are
    # allowed to reverse mappings.
    def initialize(key)
      unless key.is_a?(String) && key.bytesize == 32
        raise ArgumentError, "key must be a 32 byte binary String"
      end

      binary_key = key.dup.force_encoding(Encoding::BINARY).freeze
      permutations = {}
      [IPV4_TAG, IPV6_TAG].each do |tag|
        family_key = hkdf_sha256(binary_key, tag)
        width = tag == IPV4_TAG ? 32 : 128
        permutations[tag] = PrefixPermutation.new(family_key, width, tag)
      end
      @permutations = permutations
    end

    # Anonymizes a host or interface address while preserving its prefix.
    def forward(value)
      ip = coerce(value)
      tag, width, integer, parser = family(ip)
      anonymized = @permutations[tag].forward(integer)
      parser.call(anonymized, ip.prefix.to_i)
    end
    alias_method :anonymize, :forward

    # Reverses a host or interface address produced by #forward.
    def inverse(value)
      ip = coerce(value)
      tag, width, integer, parser = family(ip)
      original = @permutations[tag].inverse(integer)
      parser.call(original, ip.prefix.to_i)
    end
    alias_method :deanonymize, :inverse

    # Anonymizes a network prefix. Host bits are ignored and the returned
    # object has the same prefix length as the input network.
    def forward_network(value)
      map_network(value, :forward)
    end
    alias_method :anonymize_network, :forward_network

    # Reverses a network prefix produced by #forward_network.
    def inverse_network(value)
      map_network(value, :inverse)
    end
    alias_method :deanonymize_network, :inverse_network

    def self.forward(key, value)
      new(key).forward(value)
    end

    def self.inverse(key, value)
      new(key).inverse(value)
    end

    def self.forward_network(key, value)
      new(key).forward_network(value)
    end

    def self.inverse_network(key, value)
      new(key).inverse_network(value)
    end

    private

    def map_network(value, direction)
      ip = coerce(value).network
      tag, width, integer, parser = family(ip)
      prefix_length = ip.prefix.to_i
      mapped = @permutations[tag].public_send(direction, integer)
      host_bits = width - prefix_length
      network_integer = (mapped >> host_bits) << host_bits
      parser.call(network_integer, prefix_length)
    end

    def coerce(value)
      case value
      when IPv4, IPv6
        value
      when String
        IPAddress.parse(value)
      else
        raise ArgumentError, "expected an IPAddress::IPv4, IPAddress::IPv6 or String"
      end
    end

    def family(ip)
      case ip
      when IPv4
        [IPV4_TAG, 32, ip.to_u32, lambda { |integer, prefix| IPv4.parse_u32(integer, prefix) }]
      when IPv6
        [IPV6_TAG, 128, ip.to_u128, lambda { |integer, prefix| IPv6.parse_u128(integer, prefix) }]
      end
    end

    def hkdf_sha256(key, info)
      pseudorandom_key = OpenSSL::HMAC.digest("SHA256", SALT, key)
      OpenSSL::HMAC.digest("SHA256", pseudorandom_key, info + "\x01")
    end

  end # class Anonymizer
end # module IPAddress
