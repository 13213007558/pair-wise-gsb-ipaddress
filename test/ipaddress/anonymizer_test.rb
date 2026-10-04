require 'test_helper'
require 'rbconfig'

class AnonymizerTest < Minitest::Test

  def setup
    @key = '0123456789ABCDEF0123456789ABCDEF'
    @anonymizer = IPAddress::Anonymizer.new(@key)

    @address_vectors = {
      '192.0.2.10/32' => '6.88.30.204/32',
      '2001:db8::1/128' => '4f76:5f59:1b14:b02f:9ae:406b:3a62:98d2/128'
    }

    @network_vectors = {
      '0.0.0.0/0' => '0.0.0.0/0',
      '192.0.2.0/24' => '6.88.30.0/24',
      '::/0' => '::/0',
      '2001:db8::/32' => '4f76:5f59::/32'
    }
  end

  def test_fixed_address_vectors
    @address_vectors.each do |input, output|
      ip = IPAddress.parse(input)

      assert_equal output, @anonymizer.forward(ip).to_string
      assert_equal input, @anonymizer.inverse(IPAddress.parse(output)).to_string
    end
  end

  def test_fixed_network_vectors
    @network_vectors.each do |input, output|
      network = IPAddress.parse(input)

      assert_equal output, @anonymizer.forward_network(network).to_string
      assert_equal input, @anonymizer.inverse_network(IPAddress.parse(output)).to_string
    end
  end

  def test_string_and_object_inputs_match
    ip = IPAddress.parse('198.51.100.42/255.255.255.0')

    assert_equal @anonymizer.forward(ip).to_s,
                 @anonymizer.forward(ip.address).to_s
  end

  def test_address_and_network_prefix_transformations_are_consistent
    address = IPAddress.parse('192.0.2.10')
    network = IPAddress.parse('192.0.2.0/24')

    transformed_address = @anonymizer.forward(address)
    transformed_network = @anonymizer.forward_network(network)

    assert transformed_network.include?(transformed_address)
    assert_equal transformed_network.to_string,
                 @anonymizer.forward(network).network.to_string
  end

  def test_ipv4_and_ipv6_use_separate_key_domains
    mapped_ipv4 = IPAddress.parse('::ffff:192.0.2.10')
    ipv4_output = @anonymizer.forward(IPAddress.parse('192.0.2.10')).to_i
    mapped_output_low_32 = @anonymizer.forward(mapped_ipv4).to_i & 0xffffffff

    refute_equal ipv4_output, mapped_output_low_32
  end

  def test_key_must_be_exactly_32_bytes
    assert_raises(ArgumentError) { IPAddress::Anonymizer.new('short') }
    assert_raises(ArgumentError) { IPAddress::Anonymizer.new('x' * 31) }
    assert_raises(ArgumentError) { IPAddress::Anonymizer.new('x' * 33) }
  end

  def test_same_key_is_deterministic_without_shared_state
    first = IPAddress::Anonymizer.new(@key)
    second = IPAddress::Anonymizer.new(@key)

    assert_equal first.forward('192.0.2.10').to_string,
                 second.forward('192.0.2.10').to_string
  end

  def test_a_different_key_changes_the_mapping
    other = IPAddress::Anonymizer.new('FEDCBA9876543210FEDCBA9876543210')
    original = '192.0.2.10'

    refute_equal @anonymizer.forward(original).to_s, other.forward(original).to_s
    refute_equal original, @anonymizer.inverse(other.forward(original)).to_s
  end

  def test_same_key_produces_the_same_result_in_another_process
    code = 'require "ipaddress"; ' \
           'key = "0123456789ABCDEF0123456789ABCDEF"; ' \
           'print IPAddress::Anonymizer.new(key).forward("192.0.2.10").to_s'
    output = IO.popen([RbConfig.ruby, '-Ilib', '-e', code], &:read)

    assert_equal @anonymizer.forward('192.0.2.10').to_s, output
  end

  def test_longest_common_prefix_is_preserved_for_ipv4_and_ipv6
    examples = {
      IPAddress::IPv4 => ['10.1.2.3', '10.1.2.9'],
      IPAddress::IPv6 => ['2001:db8:1::1', '2001:db8:1::9']
    }

    examples.each do |klass, strings|
      inputs = strings.map { |string| klass.new(string) }
      outputs = inputs.map { |ip| @anonymizer.forward(ip) }

      assert_equal longest_common_prefix(inputs.map(&:bits)),
                   longest_common_prefix(outputs.map(&:bits))
    end
  end

  def test_small_width_permutation_is_bijective_and_prefix_preserving
    width = 5
    values = (0...(1 << width)).to_a
    input_bits = values.map { |value| '%0*b' % [width, value] }

    8.times do |index|
      key = [0x11 * (index + 1)].pack('C') * 32
      permutation = IPAddress::Anonymizer::PrefixPermutation.new(key, width, "test/small-width/#{index}")
      transformed = values.map { |value| permutation.forward(value) }
      restored = transformed.map { |value| permutation.inverse(value) }

      assert_equal values, transformed.sort
      assert_equal values, restored
      values.product(values) do |left, right|
        input_prefix = longest_common_prefix([input_bits[left], input_bits[right]])
        output_prefix = longest_common_prefix([input_bits[transformed[left]],
                                               input_bits[transformed[right]]])
        assert_equal input_prefix, output_prefix
      end
    end
  end

  private

  def longest_common_prefix(bits)
    first = bits.first
    (0...first.length).find do |index|
      bits.any? { |other| other[index] != first[index] }
    end || first.length
  end

end
