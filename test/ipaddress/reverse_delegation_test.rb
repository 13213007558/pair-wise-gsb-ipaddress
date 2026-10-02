require 'test_helper'

class ReverseDelegationTest < Minitest::Test
  def test_ipv4_rfc2317_delegates_nonadjacent_blocks_exactly
    parent = IPAddress('192.0.2.0/24')
    first = IPAddress('192.0.2.32/27')
    second = IPAddress('192.0.2.96/27')

    plan = parent.plan_reverse_delegation(
      [
        { :subnet => first, :nameservers => ['ns1.example.com'] },
        { :subnet => second, :nameservers => ['ns2.example.com'] }
      ]
    )

    assert_equal '2.0.192.in-addr.arpa', plan.parent_origin
    assert_equal [first, second], plan.zones.map(&:range)
    assert_equal ['32-27.2.0.192.in-addr.arpa',
                  '96-27.2.0.192.in-addr.arpa'], plan.zones.map(&:origin)

    ns_records = plan.parent_records.select { |record| record.type == 'NS' }
    cname_records = plan.parent_records.select { |record| record.type == 'CNAME' }

    assert_equal 2, ns_records.size
    assert_equal 64, cname_records.size
    assert_equal 64, cname_records.map(&:name).uniq.size
    assert_equal((32..63).to_a + (96..127).to_a,
                 cname_records.map { |record| record.range.octets.last }.sort)
    assert cname_records.all? { |record| record.range.prefix.to_i == 32 }
    assert cname_records.all? { |record| [first, second].include?(record.source_range) }

    [first, second].each do |subnet|
      subnet.each do |address|
        assert plan.covers?(address)
        ptr_name = plan.ptr_name_for(address)
        assert_equal address.reverse.sub('.2.0.192.in-addr.arpa', ''),
                     ptr_name.split('.').first
        assert ptr_name.end_with?('.2.0.192.in-addr.arpa')

        cname = cname_records.find { |record| record.name == address.reverse }
        assert_equal ptr_name, cname.value
        assert_equal IPAddress::IPv4.parse_u32(address.to_u32, 32), cname.range
      end
    end

    (0..255).each do |host|
      address = IPAddress('192.0.2.%d' % host)
      delegated = (32..63).cover?(host) || (96..127).cover?(host)

      assert_equal delegated, plan.covers?(address)
      next if delegated

      assert_raises(ArgumentError) { plan.ptr_name_for(address) }
      refute plan.parent_records.any? { |record| record.range.include?(address) }
    end

    assert_empty plan.conflicts
  end

  def test_ipv4_octet_boundary_uses_ns_without_cnames
    plan = IPAddress.plan_reverse_delegation(
      '10.0.0.0/8',
      [[ '10.0.1.0/24', ['ns.example.com'] ]]
    )

    record = plan.parent_records.first

    assert_equal 'NS', record.type
    assert_equal '1.0.10.in-addr.arpa', record.name
    assert_equal 'ns.example.com', record.value
    assert_equal IPAddress('10.0.1.0/24'), record.range
    refute plan.parent_records.any? { |item| item.type == 'CNAME' }
    assert_equal 256, plan.zones.first.ptr_mapping.size
    assert_equal IPAddress('10.0.1.4').reverse,
                 plan.zones.first.ptr_mapping['10.0.1.4']
  end

  def test_ipv6_non_nibble_delegation_splits_to_exact_nibble_zones
    parent = IPAddress('2001:db8::/64')
    subnet = IPAddress('2001:db8::/66')

    plan = parent.plan_reverse_delegation(
      [[subnet, ['ns6.example.com']]]
    )

    expected_ranges = [
      IPAddress('2001:db8::/68'),
      IPAddress('2001:db8:0:0:1000::/68'),
      IPAddress('2001:db8:0:0:2000::/68'),
      IPAddress('2001:db8:0:0:3000::/68')
    ]

    assert_equal expected_ranges, plan.zones.map(&:range)
    assert plan.zones.all? { |zone| zone.source_range == subnet }
    assert_equal expected_ranges, plan.parent_records.map(&:range)
    assert plan.parent_records.all? { |record| record.source_range == subnet }
    assert plan.parent_records.all? { |record| record.type == 'NS' }

    assert plan.covers?('2001:db8::1')
    assert plan.covers?('2001:db8:0:0:3fff:ffff:ffff:ffff')
    refute plan.covers?('2001:db8:0:0:4000::1')
    refute plan.parent_records.any? { |record| record.range.include?(IPAddress('2001:db8:0:0:4000::1')) }

    assert_equal IPAddress('2001:db8::1').reverse,
                 plan.ptr_name_for('2001:db8::1')
    assert_empty plan.conflicts
  end

  def test_ipv6_odd_non_nibble_delegation_splits_to_two_nibble_zones
    plan = IPAddress.plan_reverse_delegation(
      '2001:db8::/64',
      [['2001:db8:0:0:2000::/67', ['ns6.example.com']]]
    )

    assert_equal [
      IPAddress('2001:db8:0:0:2000::/68'),
      IPAddress('2001:db8:0:0:3000::/68')
    ], plan.zones.map(&:range)
    refute plan.covers?('2001:db8:0:0:1fff:ffff:ffff:ffff')
    refute plan.covers?('2001:db8:0:0:4000::')
  end

  def test_reports_existing_overlap_and_cname_conflicts
    parent = IPAddress('192.0.2.0/24')
    existing = [
      { :type => 'CNAME',
        :name => '48.2.0.192.in-addr.arpa',
        :value => '48.old.2.0.192.in-addr.arpa',
        :range => '192.0.2.48/32' },
      { :type => 'NS',
        :name => '64-26.2.0.192.in-addr.arpa',
        :value => 'old.example.com',
        :range => '192.0.2.64/26' }
    ]

    plan = parent.plan_reverse_delegation(
      [['192.0.2.32/27', ['ns1.example.com']],
       ['192.0.2.96/27', ['ns2.example.com']]],
      :existing_records => existing
    )

    types = plan.conflicts.map { |conflict| conflict[:type] }.sort

    assert_equal ['cname_conflict', 'overlap'], types
    assert_includes plan.conflicts.flat_map { |conflict| conflict[:ranges] },
                    '192.0.2.48/32'
    assert_includes plan.conflicts.flat_map { |conflict| conflict[:ranges] },
                    '192.0.2.64/26'
  end

  def test_identical_existing_records_do_not_conflict
    plan = IPAddress.plan_reverse_delegation(
      '192.0.2.0/24',
      [['192.0.2.32/27', ['ns1.example.com']]],
      :existing_records => [
        { :type => 'NS',
          :name => '32-27.2.0.192.in-addr.arpa',
          :value => 'ns1.example.com',
          :range => '192.0.2.32/27' },
        { :type => 'CNAME',
          :name => '33.2.0.192.in-addr.arpa',
          :value => '33.32-27.2.0.192.in-addr.arpa',
          :range => '192.0.2.33/32' }
      ]
    )

    assert_empty plan.conflicts
  end

  def test_accepts_existing_delegations_and_unscoped_records
    plan = IPAddress.plan_reverse_delegation(
      '192.0.2.0/24',
      [['192.0.2.32/27', ['ns1.example.com']]],
      :existing_records => [
        { :subnet => '192.0.2.32/27',
          :nameservers => ['ns1.example.com'] },
        { :type => 'PTR', :name => 'outside.2.0.192.in-addr.arpa', :value => 'host.example.com' }
      ]
    )

    assert_equal 'NS', plan.existing_records.first.type
    assert_equal IPAddress('192.0.2.32/27'), plan.existing_records.first.range
    assert_nil plan.existing_records.last.range
    assert_empty plan.conflicts
  end

  def test_rejects_non_nibble_ipv6_parent
    assert_raises(ArgumentError) do
      IPAddress.plan_reverse_delegation('2001:db8::/65', [])
    end
  end

  def test_supports_arpa_roots
    assert_equal 'in-addr.arpa',
                 IPAddress.plan_reverse_delegation('0.0.0.0/0', []).parent_origin
    assert_equal 'ip6.arpa',
                 IPAddress.plan_reverse_delegation('::/0', []).parent_origin
  end
end
