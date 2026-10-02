require 'test_helper'

class ReverseDNSTest < Minitest::Test

  def plan(parent, delegations, options = {})
    IPAddress::ReverseDNS.plan(parent, delegations, options)
  end

  def test_ipv4_rfc2317_delegation
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/27",
       nameservers: ["ns1.example.com", "ns2.example.com"]},
    ])
    assert_equal "2.0.192.in-addr.arpa", p.parent_zone
    assert_equal ["0/27.2.0.192.in-addr.arpa"], p.zones.map(&:name)
    assert p.valid?

    ns = p.ns_records
    assert_equal 2, ns.size
    assert_equal "0/27.2.0.192.in-addr.arpa", ns.first.name
    assert_equal "NS", ns.first.type
    assert_equal "192.0.2.0..192.0.2.31", ns.first.range

    cnames = p.cname_records
    assert_equal 32, cnames.size
    first = cnames.find { |r| r.name == "0.2.0.192.in-addr.arpa" }
    assert_equal "0.0/27.2.0.192.in-addr.arpa", first.value
    assert_equal "192.0.2.0", first.range
    last = cnames.find { |r| r.name == "31.2.0.192.in-addr.arpa" }
    assert_equal "31.0/27.2.0.192.in-addr.arpa", last.value
  end

  def test_ipv4_ptr_mapping
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]},
    ])
    zone = p.zones.first
    assert_equal "5.0/27.2.0.192.in-addr.arpa", zone.ptr_name("192.0.2.5")
    mapping = zone.ptr_mapping
    assert_equal 32, mapping.size
    assert_equal "0.0/27.2.0.192.in-addr.arpa", mapping["192.0.2.0"]
    assert_equal "31.0/27.2.0.192.in-addr.arpa", mapping["192.0.2.31"]
    assert_raises(IPAddress::ReverseDNS::Error) do
      zone.ptr_name("192.0.2.32")
    end
  end

  def test_ipv4_octet_boundary_direct_delegation
    p = plan("192.0.0.0/16", [
      {prefix: "192.0.2.0/24", nameservers: ["ns1.example.com"]},
    ])
    assert_equal ["2.0.192.in-addr.arpa"], p.zones.map(&:name)
    assert_equal 0, p.cname_records.size
    assert_equal 1, p.ns_records.size
    assert_equal "7.2.0.192.in-addr.arpa", p.zones.first.ptr_name("192.0.2.7")
    chain = p.delegation_chain("192.0.2.7")
    assert_equal ["0.192.in-addr.arpa", "2.0.192.in-addr.arpa"],
                 chain.map(&:zone)
  end

  def test_ipv4_non_octet_parent
    p = plan("192.0.2.0/27", [
      {prefix: "192.0.2.0/29", nameservers: ["ns1.example.com"]},
    ])
    assert_equal "0/27.2.0.192.in-addr.arpa", p.parent_zone
    assert_equal ["0/29.2.0.192.in-addr.arpa"], p.zones.map(&:name)
    cname = p.cname_records.find { |r| r.name == "0.0/27.2.0.192.in-addr.arpa" }
    assert_equal "0.0/29.2.0.192.in-addr.arpa", cname.value
    chain = p.delegation_chain("192.0.2.1")
    assert_equal ["0/27.2.0.192.in-addr.arpa", "0/29.2.0.192.in-addr.arpa"],
                 chain.map(&:zone)
  end

  #
  # Two non-adjacent small blocks sharing the same /24: every address
  # inside the blocks must have exactly one delegation chain, and no
  # address outside the blocks may be captured by a delegation.
  #
  def test_two_non_adjacent_blocks_in_same_slash24
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/28", nameservers: ["ns1.a.example"]},
      {prefix: "192.0.2.64/26", nameservers: ["ns1.b.example"]},
    ])
    assert p.valid?
    assert_equal ["0/28.2.0.192.in-addr.arpa", "64/26.2.0.192.in-addr.arpa"],
                 p.zones.map(&:name)

    0.upto(255) do |i|
      addr = "192.0.2.#{i}"
      chain = p.delegation_chain(addr)
      if (0..15).cover?(i)
        assert_equal ["2.0.192.in-addr.arpa", "0/28.2.0.192.in-addr.arpa"],
                     chain.map(&:zone), "wrong chain for #{addr}"
        assert_equal "CNAME", chain.first.record.type
        assert_equal p.zones[0].ptr_name(addr), chain.last.name
      elsif (64..127).cover?(i)
        assert_equal ["2.0.192.in-addr.arpa", "64/26.2.0.192.in-addr.arpa"],
                     chain.map(&:zone), "wrong chain for #{addr}"
        assert_equal "CNAME", chain.first.record.type
        assert_equal p.zones[1].ptr_name(addr), chain.last.name
      else
        assert_equal ["2.0.192.in-addr.arpa"], chain.map(&:zone),
                     "#{addr} was captured by a delegation"
        assert_nil chain.last.record
        assert_nil p.zone_for(addr)
      end
    end

    # every address inside the blocks resolves to exactly one zone
    owners = p.cname_records.map(&:name)
    assert_equal owners.uniq.size, owners.size
    assert_equal 16 + 64, owners.size
  end

  def test_ipv6_nibble_split_is_exact
    p = plan("2001:db8::/48", [
      {prefix: "2001:db8:0:1::/65", nameservers: ["ns1.example.com"]},
    ])
    assert p.valid?
    assert_equal 8, p.zones.size
    p.zones.each { |zone| assert_equal 68, zone.prefix }

    # the /68 blocks cover exactly the /65, nothing more
    covered = p.zones.map { |z| z.network.network_u128 }.min
    covered_last = p.zones.map { |z| z.network.broadcast_u128 }.max
    child = IPAddress::IPv6.new("2001:db8:0:1::/65").network
    assert_equal child.network_u128, covered
    assert_equal child.broadcast_u128, covered_last

    # no overlap between the generated zones
    p.zones.combination(2) do |a, b|
      refute IPAddress::ReverseDNS.ranges_overlap?(a.network, b.network)
    end

    # the adjacent /65 is not captured
    adjacent = "2001:db8:0:1:8000::"
    assert_nil p.zone_for(adjacent)
    assert_equal [p.parent_zone], p.delegation_chain(adjacent).map(&:zone)

    # an address inside is delegated to exactly one zone
    inside = "2001:db8:0:1::5"
    zone = p.zone_for(inside)
    assert_equal "0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", zone.name
    assert_equal [p.parent_zone, zone.name],
                 p.delegation_chain(inside).map(&:zone)
    assert zone.ptr_name(inside).end_with?(zone.name)
  end

  def test_ipv6_nibble_aligned_child_single_zone
    p = plan("2001:db8::/32", [
      {prefix: "2001:db8:1::/64", nameservers: ["ns1.example.com"]},
    ])
    assert_equal 1, p.zones.size
    assert_equal 64, p.zones.first.prefix
    assert_equal 1, p.ns_records.size
  end

  def test_ipv6_non_nibble_parent_rejected
    assert_raises(IPAddress::ReverseDNS::Error) do
      plan("2001:db8::/47", [])
    end
  end

  def test_overlap_between_delegations_reported
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]},
      {prefix: "192.0.2.16/28", nameservers: ["ns2.example.com"]},
    ])
    refute p.valid?
    assert p.conflicts.any? { |c| c.type == :overlap }
  end

  def test_existing_delegation_overlap_reported
    p = plan("192.0.2.0/24",
             [{prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]}],
             existing: [{prefix: "192.0.2.16/28",
                         nameservers: ["ns.other.example"]}])
    refute p.valid?
    conflict = p.conflicts.find { |c| c.type == :overlap }
    assert conflict
    assert_match(/192\.0\.2\.16\/28/, conflict.message)
  end

  def test_existing_record_cname_conflict_reported
    p = plan("192.0.2.0/24",
             [{prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]}],
             existing: [{name: "0.2.0.192.in-addr.arpa",
                         type: "PTR", value: "host.example.com."}])
    refute p.valid?
    conflict = p.conflicts.find { |c| c.type == :cname_conflict }
    assert conflict
    assert_match(/0.2.0.192.in-addr.arpa/, conflict.message)
  end

  def test_existing_identical_cname_is_not_a_conflict
    p = plan("192.0.2.0/24",
             [{prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]}],
             existing: [{name: "0.2.0.192.in-addr.arpa", type: "CNAME",
                         value: "0.0/27.2.0.192.in-addr.arpa"}])
    assert p.valid?
  end

  def test_delegation_outside_parent_rejected
    assert_raises(IPAddress::ReverseDNS::Error) do
      plan("192.0.2.0/24", [
        {prefix: "192.0.3.0/27", nameservers: ["ns1.example.com"]},
      ])
    end
  end

  def test_mixed_families_rejected
    assert_raises(IPAddress::ReverseDNS::Error) do
      plan("192.0.2.0/24", [
        {prefix: "2001:db8::/64", nameservers: ["ns1.example.com"]},
      ])
    end
  end

  def test_record_ranges
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]},
    ])
    ns = p.ns_records.first
    assert_equal "192.0.2.0", ns.first
    assert_equal "192.0.2.31", ns.last
    cname = p.cname_records.find { |r| r.name == "5.2.0.192.in-addr.arpa" }
    assert_equal "192.0.2.5", cname.range
  end

  def test_to_s_renders_zone_records
    p = plan("192.0.2.0/24", [
      {prefix: "192.0.2.0/28", nameservers: ["ns1.example.com"]},
    ])
    output = p.to_s
    assert_match(/0\/28\.2\.0\.192\.in-addr\.arpa\.\s+NS\s+ns1\.example\.com\./,
                 output)
    assert_match(/192.0.2.0..192.0.2.15/, output)
  end
end
