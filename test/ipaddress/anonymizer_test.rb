require 'test_helper'
require 'rbconfig'

class IPAddressAnonymizerTest < Minitest::Test
  KEY = ('0123456789abcdef' * 2).b
  OTHER_KEY = ('fedcba9876543210' * 2).b

  VECTORS = [
    ['198.51.100.10', '80.120.42.98/32'],
    ['198.51.100.20', '80.120.42.113/32'],
    ['198.51.100.0/24', '80.120.42.110/24'],
    ['0.0.0.0/0', '217.89.248.57/0'],
    ['2001:db8::1', '7717:3342:28a4:fca9:5bfa:3335:8bf3:fe0a/128'],
    ['2001:db8::2', '7717:3342:28a4:fca9:5bfa:3335:8bf3:fe08/128'],
    ['2001:db8::/64', '7717:3342:28a4:fca9:5bfa:3335:8bf3:fe0b/64'],
    ['::/0', '546f:1cb9:2755:1173:d3b1:3939:ca89:d44e/0'],
  ].freeze

  NETWORK_VECTORS = [
    ['198.51.100.5/24', '80.120.42.0/24'],
    ['198.51.100.0/24', '80.120.42.0/24'],
    ['0.0.0.0/0', '0.0.0.0/0'],
    ['2001:db8:1234:5678::1/64', '7717:3342:360d:e152::/64'],
    ['2001:db8::/64', '7717:3342:28a4:fca9::/64'],
    ['::/0', '::/0'],
  ].freeze

  def setup
    @anonymizer = IPAddress::PrefixPreservingAnonymizer.new(KEY)
  end

  def test_requires_exactly_32_binary_bytes
    assert_raises(ArgumentError) { IPAddress::PrefixPreservingAnonymizer.new('short'.b) }
    assert_raises(ArgumentError) { IPAddress::PrefixPreservingAnonymizer.new(KEY * 2) }
    assert_raises(ArgumentError) { IPAddress::PrefixPreservingAnonymizer.new('0123456789abcdef0123456789abcdef') }
  end

  def test_fixed_forward_vectors
    VECTORS.each do |input, output|
      assert_equal output, @anonymizer.forward(input).to_string
      assert_equal output, @anonymizer.anonymize(input).to_string
    end
  end

  def test_fixed_network_vectors
    NETWORK_VECTORS.each do |input, output|
      assert_equal output, @anonymizer.forward_network(input).to_string
      assert_equal IPAddress.parse(input).network.to_string,
                   @anonymizer.reverse_network(output).to_string
    end
  end

  def test_address_forward_is_reversible
    VECTORS.each do |input, _|
      original = IPAddress.parse(input)
      anonymized = @anonymizer.forward(original)

      assert_equal original.to_string, @anonymizer.reverse(anonymized).to_string
    end
  end

  def test_network_conversion_matches_address_prefix
    address = IPAddress.parse('198.51.100.7/24')
    transformed_address = @anonymizer.forward(address)
    transformed_network = @anonymizer.forward_network(address)

    assert_equal transformed_network.network_u32,
                 transformed_address.network_u32

    address6 = IPAddress.parse('2001:db8:abcd:1234::beef/64')
    transformed6 = @anonymizer.forward(address6)
    network6 = @anonymizer.forward_network(address6)

    assert_equal network6.network_u128,
                 transformed6.network_u128
  end

  def test_ipv4_and_ipv6_use_separated_keys
    refute_equal @anonymizer.forward('0.0.0.0').to_u32,
                 (@anonymizer.forward('::').to_u128 >> 96)
  end

  def test_different_key_does_not_preserve_vector
    other = IPAddress::PrefixPreservingAnonymizer.new(OTHER_KEY)

    VECTORS.first(4).each do |input, output|
      refute_equal output, other.forward(input).to_string
      refute_equal IPAddress.parse(input).to_string,
                   other.reverse(output).to_string
    end
  end

  def test_same_key_is_stable_across_processes
    script = <<-RUBY
      require 'ipaddress'
      key = ('0123456789abcdef' * 2).b
      anonymizer = IPAddress::PrefixPreservingAnonymizer.new(key)
      puts anonymizer.forward('198.51.100.10').to_string
      puts anonymizer.forward('2001:db8::1').to_string
    RUBY

    output = IO.popen(
      [RbConfig.ruby, '-I', File.expand_path('../../lib', __dir__), '-e', script],
      &:read
    )

    expected = [
      @anonymizer.forward('198.51.100.10').to_string,
      @anonymizer.forward('2001:db8::1').to_string
    ].join("\n") + "\n"

    assert_equal expected,
      output
  end

  def test_small_width_permutations_are_bijective_and_prefix_preserving
    permutation_class = IPAddress::PrefixPreservingAnonymizer.const_get(:Permutation)

    (1..8).each do |width|
      permutation = permutation_class.new(KEY, 'test', width)
      values = (0...2**width).map { |value| permutation.forward(value) }

      assert_equal (0...2**width).to_a, values.sort

      values.each_with_index do |output, input|
        assert_equal input, permutation.reverse(output)
      end

      (0...2**width).each do |left|
        ((left + 1)...2**width).each do |right|
          original_prefix = common_prefix(left, right, width)
          output_prefix = common_prefix(values[left], values[right], width)

          assert_equal original_prefix, output_prefix
        end
      end
    end
  end

  private

  def common_prefix(left, right, width)
    width.times do |position|
      bit = width - position - 1
      return position if ((left >> bit) & 1) != ((right >> bit) & 1)
    end

    width
  end
end
