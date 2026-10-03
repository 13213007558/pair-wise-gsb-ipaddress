require 'test_helper'

class RFC6052Test < Minitest::Test

  def setup
    @klass = IPAddress::RFC6052
    @wkp = @klass.new # Well-Known Prefix 64:ff9b::/96
    # RFC 6052, Figure 2: bit layout of the IPv4-embedded IPv6
    # address for each allowed prefix length. The IPv4 address
    # 192.0.2.33 is 0xC0000221.
    @ipv4 = "192.0.2.33"
    @layout = {
      "64:ff9b::/96"          => [0x0064, 0xff9b, 0x0000, 0x0000, 0x0000, 0x0000, 0xc000, 0x0221],
      "2001:db8::/32"         => [0x2001, 0x0db8, 0xc000, 0x0221, 0x0000, 0x0000, 0x0000, 0x0000],
      "2001:db8:100::/40"     => [0x2001, 0x0db8, 0x01c0, 0x0002, 0x0021, 0x0000, 0x0000, 0x0000],
      "2001:db8:100::/48"     => [0x2001, 0x0db8, 0x0100, 0xc000, 0x0002, 0x2100, 0x0000, 0x0000],
      "2001:db8:100:200::/56" => [0x2001, 0x0db8, 0x0100, 0x02c0, 0x0000, 0x0221, 0x0000, 0x0000],
      "2001:db8:100:200::/64" => [0x2001, 0x0db8, 0x0100, 0x0200, 0x00c0, 0x0002, 0x2100, 0x0000]}
    @compressed = {
      "64:ff9b::/96"          => "64:ff9b::c000:221",
      "2001:db8::/32"         => "2001:db8:c000:221::",
      "2001:db8:100::/40"     => "2001:db8:1c0:2:21::",
      "2001:db8:100::/48"     => "2001:db8:100:c000:2:2100::",
      "2001:db8:100:200::/56" => "2001:db8:100:2c0:0:221::",
      "2001:db8:100:200::/64" => "2001:db8:100:200:c0:2:2100:0"}
  end

  def test_default_prefix_is_well_known
    assert_equal "64:ff9b::/96", @wkp.prefix.to_string
    assert_equal 96, @wkp.prefix_length
  end

  def test_constructor_accepts_all_rfc6052_prefix_lengths
    [32, 40, 48, 56, 64, 96].each do |plen|
      assert_equal plen, @klass.new("2001:db8::/#{plen}").prefix_length
    end
  end

  def test_constructor_accepts_ipv6_object_and_normalizes_network
    nsp = @klass.new IPAddress::IPv6.new("2001:db8:100:200:300::1/56")
    assert_equal "2001:db8:100:200::/56", nsp.prefix.to_string
  end

  def test_constructor_rejects_invalid_prefix_lengths
    [0, 8, 24, 33, 72, 104, 128].each do |plen|
      assert_raises(ArgumentError) { @klass.new "2001:db8::/#{plen}" }
    end
  end

  def test_constructor_rejects_non_ipv6_arguments
    assert_raises(ArgumentError) { @klass.new IPAddress::IPv4.new("10.0.0.0/8") }
    assert_raises(ArgumentError) { @klass.new "not-an-ip-address" }
  end

  def test_encode_matches_rfc6052_bit_layout
    @layout.each do |prefix, groups|
      encoded = @klass.new(prefix).encode(@ipv4)
      assert_equal groups, encoded.groups, "wrong bit layout for #{prefix}"
      assert_equal @compressed[prefix], encoded.to_s
    end
  end

  def test_encode_zeroes_reserved_u_octet
    @layout.keys.each do |prefix|
      encoded = @klass.new(prefix).encode(@ipv4)
      u_octet = (encoded.to_u128 >> 56) & 0xff
      if prefix.end_with?("/96")
        # with a /96 prefix bits 64-71 are prefix bits, not the u octet
        assert_equal 0, u_octet
      else
        assert_equal 0, u_octet, "u octet not zero for #{prefix}"
      end
    end
  end

  def test_encode_boundary_addresses
    assert_equal "64:ff9b::", @wkp.encode("0.0.0.0").to_s
    assert_equal "64:ff9b::ffff:ffff", @wkp.encode("255.255.255.255").to_s
    assert_equal "2001:db8:ffff:ffff::", @klass.new("2001:db8::/32").encode("255.255.255.255").to_s
    assert_equal "2001:db8::ff:ffff:ff00:0", @klass.new("2001:db8::/64").encode("255.255.255.255").to_s
  end

  def test_encode_accepts_ipv4_objects
    assert_equal @wkp.encode(@ipv4).to_u128, @wkp.encode(IPAddress::IPv4.new(@ipv4)).to_u128
  end

  def test_round_trip_for_all_prefix_lengths
    addresses = ["0.0.0.0", "1.2.3.4", "10.20.30.40", "192.0.2.33", "223.255.254.1", "255.255.255.255"]
    @layout.keys.each do |prefix|
      nsp = @klass.new(prefix)
      addresses.each do |addr|
        encoded = nsp.encode(addr)
        assert_equal :valid, nsp.decode_status(encoded)
        assert nsp.valid?(encoded)
        assert_equal addr, nsp.decode(encoded).address, "round trip failed for #{addr} with #{prefix}"
      end
    end
  end

  def test_decode_ignores_suffix_bits
    nsp = @klass.new("2001:db8::/32")
    assert_equal @ipv4, nsp.decode("2001:db8:c000:221::1").address
    assert_equal @ipv4, @wkp.decode("64:ff9b::c000:221").address
  end

  def test_decode_status_valid
    assert_equal :valid, @wkp.decode_status("64:ff9b::c000:221")
    assert_equal @ipv4, @wkp.decode("64:ff9b::c000:221").address
  end

  def test_decode_status_not_in_network
    assert_equal :not_in_network, @wkp.decode_status("2001:db8::1")
    assert_equal :not_in_network, @wkp.decode_status("64:ff9c::c000:221")
    assert_nil @wkp.decode("2001:db8::1")
    refute @wkp.valid?("2001:db8::1")
    refute @wkp.include?("2001:db8::1")
  end

  def test_decode_status_invalid_reserved_bits
    {
      "2001:db8::/32"         => "2001:db8:c000:221:ff00::",
      "2001:db8:100::/40"     => "2001:db8:1c0:2:2100::",
      "2001:db8:100::/48"     => "2001:db8:100:c000:200::",
      "2001:db8:100:200::/56" => "2001:db8:100:2c0:ff00::",
      "2001:db8:100:200::/64" => "2001:db8:100:200:ff00::"}.each do |prefix, addr|
      nsp = @klass.new(prefix)
      assert nsp.include?(addr), "#{addr} should be in #{prefix}"
      assert_equal :invalid_reserved_bits, nsp.decode_status(addr)
      assert_nil nsp.decode(addr)
      refute nsp.valid?(addr)
    end
  end

  def test_decode_status_never_invalid_reserved_bits_with_96_prefix
    # with a /96 translator prefix bits 64-71 belong to the prefix
    # itself, so any in-network address is a valid mapping
    assert_equal :valid, @wkp.decode_status("64:ff9b::c000:221")
    assert_equal :valid, @wkp.decode_status("64:ff9b::")
  end

  def test_decode_status_ipv4_mapped
    assert_equal :ipv4_mapped, @wkp.decode_status("::ffff:192.0.2.33")
    assert_equal :ipv4_mapped, @wkp.decode_status("::ffff:c000:221")
    assert_equal :ipv4_mapped, @wkp.decode_status(IPAddress::IPv6::Mapped.new("::ffff:192.0.2.33"))
    assert_nil @wkp.decode("::ffff:192.0.2.33")
    refute @wkp.valid?("::ffff:192.0.2.33")
  end

  def test_ipv4_mapped_not_confused_even_inside_translator_prefix
    # ::ffff:a.b.c.d belongs to the ::/32 translator prefix, but it is
    # an IPv4-mapped address, not an RFC 6052 mapping of 0.0.255.255
    nsp = @klass.new("::/32")
    assert nsp.include?("::ffff:192.0.2.33")
    assert_equal :ipv4_mapped, nsp.decode_status("::ffff:192.0.2.33")
    assert_nil nsp.decode("::ffff:192.0.2.33")
    # a genuine RFC 6052 mapping under the same prefix still decodes
    assert_equal :valid, nsp.decode_status("0:0:c000:221::")
    assert_equal @ipv4, nsp.decode("0:0:c000:221::").address
  end

  def test_encode_network_well_known_prefix
    assert_equal ["64:ff9b::c000:200/120"], @wkp.encode_network("192.0.2.0/24").map(&:to_string)
    assert_equal ["64:ff9b::c000:280/121"], @wkp.encode_network("192.0.2.128/25").map(&:to_string)
    assert_equal ["64:ff9b::c000:221/128"], @wkp.encode_network("192.0.2.33/32").map(&:to_string)
    assert_equal ["64:ff9b::/96"], @wkp.encode_network("0.0.0.0/0").map(&:to_string)
  end

  def test_encode_network_normalizes_ipv4_network
    assert_equal @wkp.encode_network("192.0.2.0/24").map(&:to_string),
                 @wkp.encode_network("192.0.2.33/24").map(&:to_string)
    assert_equal @wkp.encode_network("192.0.2.0/24").map(&:to_string),
                 @wkp.encode_network(IPAddress::IPv4.new("192.0.2.0/24")).map(&:to_string)
  end

  def test_encode_network_contiguous_single_prefix
    nsp64 = @klass.new("2001:db8::/64")
    assert_equal ["2001:db8::c0:2:0:0/96"], nsp64.encode_network("192.0.2.0/24").map(&:to_string)
    nsp40 = @klass.new("2001:db8:100::/40")
    assert_equal ["2001:db8:1c0:2::/72"], nsp40.encode_network("192.0.2.0/24").map(&:to_string)
    assert_equal ["2001:db8:1c0:2:80::/73"], nsp40.encode_network("192.0.2.128/25").map(&:to_string)
    nsp48 = @klass.new("2001:db8:100::/48")
    assert_equal ["2001:db8:100:c000:2::/80"], nsp48.encode_network("192.0.2.0/24").map(&:to_string)
  end

  def test_encode_network_split_across_u_octet
    # the IPv4 network boundary falls inside the high bits field, so
    # the reserved u octet splits the mapping into one IPv6 network
    # per value of the variable high bits
    nsp56 = @klass.new("2001:db8:100:200::/56")
    assert_equal ["2001:db8:100:2c0::/72",
                  "2001:db8:100:2c1::/72",
                  "2001:db8:100:2c2::/72",
                  "2001:db8:100:2c3::/72"],
                 nsp56.encode_network("192.0.0.0/6").map(&:to_string)
  end

  def test_encode_network_split_does_not_over_aggregate
    # 192.0.2.0/24 through a /32 prefix maps to 256 distinct /72
    # networks: they must not be forced into a larger network such as
    # 2001:db8:c000:200::/56, which would include invalid mappings
    nsp32 = @klass.new("2001:db8::/32")
    result = nsp32.encode_network("192.0.2.0/24")
    assert_equal 256, result.size
    assert result.all? {|net| net.prefix.to_i == 72}
    assert result.all? {|net| net.network?}
    assert_equal "2001:db8:c000:200::/72", result.first.to_string
    assert_equal "2001:db8:c000:2ff::/72", result.last.to_string
    assert_equal result.sort.map(&:to_string), result.map(&:to_string)
  end

  def test_encode_network_result_decodes_back_into_ipv4_network
    v4net = IPAddress::IPv4.new("192.0.0.0/6")
    @klass.new("2001:db8:100:200::/56").encode_network(v4net).each do |net|
      assert v4net.include?(@klass.new("2001:db8:100:200::/56").decode(net.network))
    end
  end

  def test_encode_network_per_address_verification
    # restricted small subnet: check the batch result address by
    # address against the single address encoding
    v4net = IPAddress::IPv4.new("192.0.2.240/28")
    result = @wkp.encode_network(v4net)
    assert_equal ["64:ff9b::c000:2f0/124"], result.map(&:to_string)
    # every IPv4 address of the subnet encodes inside the result
    v4net.each do |v4|
      encoded = @wkp.encode(v4)
      assert result.any? {|net| net.include? encoded}, "#{encoded} not covered"
    end
    # every IPv6 address of the result decodes back into the subnet
    decoded = []
    result.each do |net|
      net.each do |addr|
        assert_equal :valid, @wkp.decode_status(addr)
        decoded << @wkp.decode(addr)
      end
    end
    assert_equal v4net.size, decoded.size
    assert decoded.all? {|v4| v4net.include? v4}
    assert_equal v4net.map(&:to_u32).sort, decoded.map(&:to_u32).sort
  end

  def test_encode_network_per_address_verification_shorter_prefix
    v4net = IPAddress::IPv4.new("10.1.2.4/30")
    nsp = @klass.new("2001:db8::/64")
    result = nsp.encode_network(v4net)
    assert_equal 1, result.size
    v4net.each do |v4|
      encoded = nsp.encode(v4)
      assert result.first.include?(encoded), "#{encoded} not covered"
      assert_equal v4.to_u32, nsp.decode(encoded).to_u32
    end
    assert v4net.include?(nsp.decode(result.first.network))
  end

  def test_encode_network_rejects_invalid_arguments
    assert_raises(ArgumentError) { @wkp.encode_network "not-a-network" }
    assert_raises(ArgumentError) { @wkp.encode_network IPAddress::IPv6.new("2001:db8::/64") }
  end

end

