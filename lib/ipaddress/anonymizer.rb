require 'openssl'
require 'securerandom'

module IPAddress
  # Keyed, reversible anonymization for IPv4 and IPv6 addresses.
  #
  # The cipher is stateless and uses one HMAC-SHA256 pseudorandom function
  # evaluation per address bit. It is a bijection on each complete address
  # space and preserves every pair's longest common prefix.
  class PrefixPreservingAnonymizer
    SALT = "IPAddress prefix-preserving anonymizer v1"
    private_constant :SALT

    def self.generate_key
      SecureRandom.random_bytes(32)
    end

    def initialize(key)
      unless key.is_a?(String) && key.encoding == Encoding::BINARY
        raise ArgumentError, "key must be a binary String"
      end

      unless key.bytesize == 32
        raise ArgumentError, "key must be 32 bytes (256 bits)"
      end

      @ipv4 = Permutation.new(key, "IPv4", 32)
      @ipv6 = Permutation.new(key, "IPv6", 128)
    end

    def forward(value)
      ip = coerce(value)
      transform(ip, :forward)
    end
    alias_method :anonymize, :forward

    def reverse(value)
      ip = coerce(value)
      transform(ip, :reverse)
    end
    alias_method :deanonymize, :reverse

    def forward_network(value)
      transform_network(coerce(value), :forward)
    end
    alias_method :anonymize_network, :forward_network

    def reverse_network(value)
      transform_network(coerce(value), :reverse)
    end
    alias_method :deanonymize_network, :reverse_network

    private

    def coerce(value)
      case value
      when IPAddress::IPv4, IPAddress::IPv6
        value
      when String
        IPAddress.parse(value)
      else
        raise ArgumentError, "expected an IPAddress object or String"
      end
    end

    def transform(ip, direction)
      case ip
      when IPAddress::IPv4
        integer = @ipv4.public_send(direction, ip.to_u32)
        IPAddress::IPv4.parse_u32(integer, ip.prefix.to_i)
      when IPAddress::IPv6
        integer = @ipv6.public_send(direction, ip.to_u128)
        IPAddress::IPv6.parse_u128(integer, ip.prefix.to_i)
      end
    end

    def transform_network(ip, direction)
      network = ip.network
      transform(network, direction).network
    end

    # Prefix-tree pseudorandom permutation.
    #
    # At depth d, output bit y[d] is x[d] XOR PRF(x[0...d]). The inverse
    # reconstructs x from left to right and applies the same XOR.
    class Permutation
      def initialize(master_key, domain, width)
        @width = width
        @subkey = hkdf(master_key, domain)
      end

      def forward(integer)
        input_prefix = 0
        output_prefix = 0

        width.times do |depth|
          input_bit = bit_at(integer, depth)
          next_bit = input_bit ^ prf_bit(depth, input_prefix)
          output_prefix = append_bit(
            output_prefix,
            next_bit
          )
          input_prefix = append_bit(input_prefix, input_bit)
        end

        output_prefix
      end

      def reverse(integer)
        input_prefix = 0
        output_prefix = 0

        width.times do |depth|
          output_bit = bit_at(integer, depth)
          input_bit = output_bit ^ prf_bit(depth, input_prefix)
          input_prefix = append_bit(
            input_prefix,
            input_bit
          )
          output_prefix = append_bit(output_prefix, output_bit)
        end

        input_prefix
      end

      private

      attr_reader :subkey
      attr_reader :width

      def hkdf(master_key, domain)
        info = "IPAddress-prefix-preserving-anonymizer-v1|#{domain}"
        pseudorandom_key = OpenSSL::HMAC.digest("SHA256", SALT, master_key)
        OpenSSL::HMAC.digest("SHA256", pseudorandom_key, info + "\x01")
      end

      def bit_at(integer, depth)
        (integer >> (width - depth - 1)) & 1
      end

      def append_bit(prefix, bit)
        (prefix << 1) | bit
      end

      def prf_bit(depth, prefix)
        message = [width, depth].pack("CC") + encode_prefix(prefix, depth)
        digest = OpenSSL::HMAC.digest("SHA256", subkey, message)
        digest.getbyte(0) & 1
      end

      def encode_prefix(prefix, depth)
        return String.new.force_encoding(Encoding::BINARY) if depth.zero?

        bits = format("%0#{depth}b", prefix)
        [bits].pack("B*")
      end
    end
    private_constant :Permutation
  end
end
