require 'test_helper'

class RFC6052Test < Minitest::Test

  # Test vectors computed from the bit layout of RFC 6052
  # Section 2.2, embedding 192.0.2.33 (0xc0000221).
  VECTORS = {
    "2001:db8::/32"         => "2001:db8:c000:221::",
    "2001:db8:100::/40"     => "2001:db8:1c0:2:21::",
    "2001:db8:1234::/48"    => "2001:db8:1234:c000:2:2100::",
    "2001:db8:1234:ab00::/56" => "2001:db8:1234:abc0:0:221::",
    "2001:db8::/64"         => "2001:db8::c0:2:2100:0",
    "64:ff9b::/96"          => "64:ff9b::c000:221",
  }.freeze

  def setup
    @ipv4 = IPAddress("192.0.2.33")
    @klass = IPAddress::IPv6
  end

  def test_valid_prefix_lengths
    [32, 40, 48, 56, 64, 96].each do |len|
      assert IPAddress::RFC6052.valid_prefix_length?(len), "#{len} should be valid"
    end
    [0, 8, 24, 31, 33, 63, 65, 95, 97, 128].each do |len|
      refute IPAddress::RFC6052.valid_prefix_length?(len), "#{len} should be invalid"
    end
  end

  def test_encode_bit_layout
    VECTORS.each do |network, expected|
      ip6 = @ipv4.to_ipv6_rfc6052(network)
      assert_instance_of @klass, ip6
      assert_equal expected, ip6.to_s, "wrong encoding for #{network}"
    end
  end

  def test_encode_accepts_ipv6_object
    ip6 = @ipv4.to_ipv6_rfc6052(IPAddress("64:ff9b::/96"))
    assert_equal "64:ff9b::c000:221", ip6.to_s
  end

  def test_encode_uses_network_portion
    ip6 = @ipv4.to_ipv6_rfc6052("64:ff9b::dead:beef/96")
    assert_equal "64:ff9b::c000:221", ip6.to_s
  end

  def test_encode_rejects_invalid_prefix_length
    assert_raises(ArgumentError) { @ipv4.to_ipv6_rfc6052("64:ff9b::/95") }
    assert_raises(ArgumentError) { @ipv4.to_ipv6_rfc6052("2001:db8::/24") }
    assert_raises(ArgumentError) { @ipv4.to_ipv6_rfc6052("2001:db8::/128") }
  end

  def test_decode_bit_layout
    VECTORS.each do |network, address|
      ip4 = IPAddress(address).to_ipv4_rfc6052(network)
      assert_instance_of IPAddress::IPv4, ip4
      assert_equal "192.0.2.33", ip4.to_s, "wrong decoding for #{network}"
    end
  end

  def test_roundtrip_all_prefix_lengths
    ["0.0.0.0", "10.20.30.40", "192.0.2.33", "203.0.113.200", "255.255.255.255"].each do |addr|
      VECTORS.each_key do |network|
        encoded = IPAddress(addr).to_ipv6_rfc6052(network)
        assert encoded.rfc6052?(network), "#{encoded} should be valid for #{network}"
        assert_equal addr, encoded.to_ipv4_rfc6052(network).to_s
      end
    end
  end

  def test_status_valid
    assert_equal :valid, IPAddress("64:ff9b::c000:221").rfc6052_status("64:ff9b::/96")
    assert_equal :valid, IPAddress("2001:db8::c0:2:2100:0").rfc6052_status("2001:db8::/64")
  end

  def test_status_not_in_network
    assert_equal :not_in_network,
      IPAddress("2001:db9::1").rfc6052_status("2001:db8::/32")
    assert_equal :not_in_network,
      IPAddress("64:ff9c::c000:221").rfc6052_status("64:ff9b::/96")
    refute IPAddress("64:ff9c::c000:221").rfc6052?("64:ff9b::/96")
    assert_nil IPAddress("64:ff9c::c000:221").to_ipv4_rfc6052("64:ff9b::/96")
  end

  def test_status_invalid_reserved_bits
    # bits 64..71 (the "u" octet) must be zero
    assert_equal :invalid_reserved_bits,
      IPAddress("2001:db8::100:0:0:0").rfc6052_status("2001:db8::/64")
    assert_equal :invalid_reserved_bits,
      IPAddress("2001:db8:c000:221:ff00::").rfc6052_status("2001:db8::/32")
    refute IPAddress("2001:db8::100:0:0:0").rfc6052?("2001:db8::/64")
    assert_nil IPAddress("2001:db8::100:0:0:0").to_ipv4_rfc6052("2001:db8::/64")
  end

  def test_status_ignores_suffix_bits
    # bits below the embedded IPv4 address are a suffix and
    # do not affect decoding
    ip6 = IPAddress("2001:db8::c0:2:2100:ffff")
    assert_equal :valid, ip6.rfc6052_status("2001:db8::/64")
    assert_equal "192.0.2.33", ip6.to_ipv4_rfc6052("2001:db8::/64").to_s
  end

  def test_status_ipv4_mapped_not_confused
    mapped = IPAddress("::ffff:192.0.2.33")
    assert_equal :ipv4_mapped, mapped.rfc6052_status("::ffff:0:0/96")
    refute mapped.rfc6052?("::ffff:0:0/96")
    assert_nil mapped.to_ipv4_rfc6052("::ffff:0:0/96")
    # same for the plain hex form of an IPv4-mapped address
    hex = IPAddress("::ffff:c000:221")
    assert_equal :ipv4_mapped, hex.rfc6052_status("::ffff:0:0/96")
  end

  def test_status_rejects_invalid_prefix_length
    assert_raises(ArgumentError) do
      IPAddress("64:ff9b::c000:221").rfc6052_status("64:ff9b::/95")
    end
  end

  def test_networks_single_prefix
    nets = IPAddress("192.0.2.0/24").to_ipv6_rfc6052_networks("64:ff9b::/96")
    assert_equal ["64:ff9b::c000:200/120"], nets.map(&:to_string)

    nets = IPAddress("192.0.2.0/24").to_ipv6_rfc6052_networks("2001:db8::/64")
    assert_equal ["2001:db8::c0:2:0:0/96"], nets.map(&:to_string)

    nets = IPAddress("192.0.2.0/24").to_ipv6_rfc6052_networks("2001:db8:1234::/48")
    assert_equal ["2001:db8:1234:c000:2::/80"], nets.map(&:to_string)

    nets = IPAddress("192.0.2.33/32").to_ipv6_rfc6052_networks("64:ff9b::/96")
    assert_equal ["64:ff9b::c000:221/128"], nets.map(&:to_string)

    nets = IPAddress("192.0.2.33/32").to_ipv6_rfc6052_networks("2001:db8::/32")
    assert_equal ["2001:db8:c000:221::/72"], nets.map(&:to_string)
  end

  def test_networks_slash32_fans_out
    # with a /32 translator prefix the whole IPv4 address is
    # embedded before the reserved octet, so any host bit
    # straddles it: 192.0.2.0/24 maps to 256 /72 prefixes,
    # one per value of the last IPv4 octet
    nets = IPAddress("192.0.2.0/24").to_ipv6_rfc6052_networks("2001:db8::/32")
    expected = (0..255).map { |i| "2001:db8:c000:2#{'%02x' % i}::/72" }
    assert_equal expected, nets.map(&:to_string)
  end

  def test_networks_ignores_host_bits_of_ipv4
    nets = IPAddress("192.0.2.33/24").to_ipv6_rfc6052_networks("64:ff9b::/96")
    assert_equal ["64:ff9b::c000:200/120"], nets.map(&:to_string)
  end

  def test_networks_split_across_reserved_octet
    # 192.0.0.0/12 with a /48 prefix: 4 variable IPv4 bits
    # are embedded before the reserved octet, so the result
    # is 16 /72 prefixes, not one larger network.
    nets = IPAddress("192.0.0.0/12").to_ipv6_rfc6052_networks("2001:db8:1234::/48")
    expected = (0..15).map { |i| "2001:db8:1234:c#{'%03x' % i}::/72" }
    assert_equal expected, nets.map(&:to_string)
    assert nets.all? { |n| n.prefix.to_i == 72 }
  end

  def test_networks_split_does_not_overcover
    nets = IPAddress("192.0.0.0/12").to_ipv6_rfc6052_networks("2001:db8:1234::/48")
    # an address with a non-zero reserved octet lies inside
    # the naive 2001:db8:1234:c000::/60 block but must not
    # be covered by any returned prefix
    intruder = IPAddress("2001:db8:1234:c000:100::")
    assert_equal :invalid_reserved_bits, intruder.rfc6052_status("2001:db8:1234::/48")
    refute nets.any? { |n| n.network_u128 <= intruder.to_u128 && intruder.to_u128 <= n.broadcast_u128 },
      "no prefix should cover addresses with non-zero reserved bits"
  end

  def test_networks_rejects_invalid_prefix_length
    assert_raises(ArgumentError) do
      IPAddress("192.0.2.0/24").to_ipv6_rfc6052_networks("64:ff9b::/95")
    end
  end

  def test_exhaustive_small_network
    # verify the batch result address by address against a
    # small restricted network, for every allowed prefix
    # length
    ipv4_net = IPAddress("198.51.100.0/29")
    addrs = ipv4_net.map { |ip| ip }
    assert_equal 8, addrs.size

    VECTORS.each_key do |network|
      prefixes = ipv4_net.to_ipv6_rfc6052_networks(network)

      addrs.each do |ip|
        encoded = ip.to_ipv6_rfc6052(network)
        # every encoded address decodes back to itself
        assert_equal :valid, encoded.rfc6052_status(network)
        assert_equal ip.to_u32, encoded.to_ipv4_rfc6052(network).to_u32
        # and is covered by exactly one of the batch prefixes
        covering = prefixes.select do |p|
          p.network_u128 <= encoded.to_u128 && encoded.to_u128 <= p.broadcast_u128
        end
        assert_equal 1, covering.size,
          "#{encoded} should be covered by exactly one prefix for #{network}"
      end

      # the edges of every returned prefix decode back into
      # the original IPv4 network
      prefixes.each do |p|
        [p.network_u128, p.broadcast_u128].each do |edge|
          decoded = IPAddress::IPv6.parse_u128(edge).to_ipv4_rfc6052(network)
          assert decoded, "edge #{IPAddress::IPv6.parse_u128(edge)} should decode"
          assert ipv4_net.include?(decoded),
            "#{decoded} should be inside #{ipv4_net}"
        end
      end
    end
  end

  def test_exhaustive_decode_of_small_ipv6_prefix
    # with a /96 translator prefix the mapped result of
    # 198.51.100.0/29 is a single /125: decode every single
    # address in it and check we get exactly the original
    # eight IPv4 addresses
    ipv4_net = IPAddress("198.51.100.0/29")
    prefixes = ipv4_net.to_ipv6_rfc6052_networks("64:ff9b::/96")
    assert_equal 1, prefixes.size
    decoded = []
    prefixes.first.each do |ip6|
      decoded << ip6.to_ipv4_rfc6052("64:ff9b::/96")
    end
    assert_equal ipv4_net.map(&:to_u32).sort, decoded.map(&:to_u32).sort
  end

end
