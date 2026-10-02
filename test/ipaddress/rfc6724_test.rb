require 'test_helper'

class RFC6724Test < Minitest::Test

  def setup
    @mod = IPAddress::RFC6724
  end

  def src(address, **opts)
    @mod::SourceAddress.new(address: address, **opts)
  end

  def select(destinations, sources, **opts)
    @mod.sort(destinations, sources: sources, **opts)
  end

  def one_source(destination, sources, **opts)
    results = select([destination], sources, **opts)
    assert_equal 1, results.size
    results.first.source
  end

  #
  # Scope, label and precedence helpers
  #

  def test_scope_values
    assert_equal @mod::SCOPE_INTERFACE_LOCAL, @mod.scope("127.0.0.1")
    assert_equal @mod::SCOPE_INTERFACE_LOCAL, @mod.scope("::1")
    assert_equal @mod::SCOPE_LINK_LOCAL, @mod.scope("169.254.0.1")
    assert_equal @mod::SCOPE_LINK_LOCAL, @mod.scope("fe80::1")
    assert_equal @mod::SCOPE_SITE_LOCAL, @mod.scope("fec0::1")
    assert_equal @mod::SCOPE_GLOBAL, @mod.scope("192.0.2.1")
    assert_equal @mod::SCOPE_GLOBAL, @mod.scope("2001:db8::1")
    assert_equal @mod::SCOPE_GLOBAL, @mod.scope("fc00::1")
    assert_equal 14, @mod.scope("ff0e::1")
    assert_equal @mod::SCOPE_INTERFACE_LOCAL, @mod.scope("::ffff:127.0.0.1")
  end

  def test_default_policy_table_labels_and_precedence
    assert_equal 0, @mod.label("::1")
    assert_equal 50, @mod.precedence("::1")
    assert_equal 1, @mod.label("2001:db8::1")
    assert_equal 40, @mod.precedence("2001:db8::1")
    assert_equal 4, @mod.label("192.0.2.1")
    assert_equal 35, @mod.precedence("192.0.2.1")
    assert_equal 13, @mod.label("fc00::1")
  end

  def test_user_policy_table_longest_prefix_match_wins
    table = [
      {prefix: "::/0", precedence: 40, label: 1},
      {prefix: "2001:db8::/32", precedence: 10, label: 9},
    ]
    assert_equal 10, @mod.precedence("2001:db8::1", table)
    assert_equal 9, @mod.label("2001:db8::1", table)
    assert_equal 40, @mod.precedence("2001:db9::1", table)
    assert_equal 1, @mod.label("2001:db9::1", table)
  end

  def test_user_policy_table_accepts_ipv4_prefixes
    table = [
      {prefix: "10.0.0.0/8", precedence: 30, label: 3},
      {prefix: "::/0", precedence: 40, label: 1},
    ]
    assert_equal 30, @mod.precedence("10.1.2.3", table)
    assert_equal 3, @mod.label("10.1.2.3", table)
    assert_equal 40, @mod.precedence("192.0.2.1", table)
  end

  def test_common_prefix_length
    assert_equal 126, @mod.common_prefix_length("2001:db8::1", "2001:db8::2")
    assert_equal 30, @mod.common_prefix_length("10.0.0.1", "10.0.0.2")
    assert_equal 128, @mod.common_prefix_length("2001:db8::1", "2001:db8::1")
  end

  #
  # Source address selection (RFC 6724 section 5)
  #

  def test_source_rule1_prefer_same_address
    source = one_source("2001:db8::1",
                        [src("2001:db8::2"), src("2001:db8::1")])
    assert_equal "2001:db8::1", source.address
  end

  def test_source_rule2_prefer_appropriate_scope
    source = one_source("fe80::5",
                        [src("2001:db8::1"), src("fe80::1")])
    assert_equal "fe80::1", source.address

    source = one_source("2001:db8::5",
                        [src("fe80::1"), src("2001:db8::1")])
    assert_equal "2001:db8::1", source.address
  end

  def test_source_rule2_link_local_zone_must_match
    source = one_source("fe80::5%eth0",
                        [src("fe80::1", interface: "eth1"),
                         src("fe80::2", interface: "eth0")])
    assert_equal "fe80::2", source.address
  end

  def test_source_rule3_avoid_deprecated
    source = one_source("2001:db8::9",
                        [src("2001:db8::1", deprecated: true),
                         src("2001:db8::2")])
    assert_equal "2001:db8::2", source.address
  end

  def test_source_rule4_prefer_home_address
    source = one_source("2001:db8::9",
                        [src("2001:db8::1"),
                         src("2001:db8::2", home: true)])
    assert_equal "2001:db8::2", source.address
  end

  def test_source_rule5_prefer_outgoing_interface
    source = one_source("2001:db8::9",
                        [src("2001:db8::1", interface: "eth0"),
                         src("2001:db8::2", interface: "eth1")],
                        interfaces: {"2001:db8::9" => "eth1"})
    assert_equal "2001:db8::2", source.address
  end

  def test_source_rule6_prefer_matching_label
    table = [
      {prefix: "::/0", precedence: 40, label: 1},
      {prefix: "2001:db8::/64", precedence: 40, label: 5},
      {prefix: "2001:db8::2/128", precedence: 40, label: 9},
    ]
    source = one_source("2001:db8::9",
                        [src("2001:db8::2"), src("2001:db8::1")],
                        policy_table: table)
    assert_equal "2001:db8::1", source.address
  end

  def test_source_rule7_prefer_temporary_address
    source = one_source("2001:db8::9",
                        [src("2001:db8::1"),
                         src("2001:db8::2", temporary: true)])
    assert_equal "2001:db8::2", source.address

    source = one_source("2001:db8::9",
                        [src("2001:db8::1"),
                         src("2001:db8::2", temporary: true)],
                        prefer_temporary: false)
    assert_equal "2001:db8::1", source.address
  end

  def test_source_rule8_longest_matching_prefix
    source = one_source("2001:db8:1::9",
                        [src("2001:db8:2::1"), src("2001:db8:1::1")])
    assert_equal "2001:db8:1::1", source.address
  end

  def test_source_tie_keeps_input_order
    source = one_source("2001:db8::9",
                        [src("2001:db8::1"), src("2001:db8::2")])
    assert_equal "2001:db8::1", source.address
  end

  def test_no_suitable_source
    result = select(["2001:db8::1"], [src("192.0.2.1")]).first
    assert_nil result.source
    refute result.usable?

    result = select(["2001:db8::1"], []).first
    assert_nil result.source
    refute result.usable?
  end

  #
  # Destination address selection (RFC 6724 section 6)
  #

  def test_destination_rule1_unreachable_is_unusable
    results = select(["2001:db8::1", "2001:db8::2"],
                     [src("2001:db8::5")],
                     reachable: {"2001:db8::1" => false})
    assert_equal ["2001:db8::2", "2001:db8::1"], results.map(&:destination)
    assert results.first.usable?
    refute results.last.usable?
    assert_equal "2001:db8::5", results.last.source.address
  end

  def test_destination_rule1_callable_reachability
    results = select(["2001:db8::1", "2001:db8::2"],
                     [src("2001:db8::5")],
                     reachable: ->(dst) { dst != "2001:db8::1" })
    assert_equal ["2001:db8::2", "2001:db8::1"], results.map(&:destination)
  end

  def test_destination_rule1_no_source_is_unusable
    results = select(["2001:db8::1", "192.0.2.1"], [src("192.0.2.5")])
    assert_equal ["192.0.2.1", "2001:db8::1"], results.map(&:destination)
    assert results.first.usable?
    refute results.last.usable?
    assert_nil results.last.source
  end

  def test_destination_rule2_prefer_matching_scope
    results = select(["2001:db8::1", "fe80::2"], [src("fe80::1")])
    assert_equal ["fe80::2", "2001:db8::1"], results.map(&:destination)
  end

  def test_destination_rule3_avoid_deprecated
    results = select(["2001:db8:1::1", "2001:db8:2::1"],
                     [src("2001:db8:1::2", deprecated: true),
                      src("2001:db8:2::2")])
    assert_equal ["2001:db8:2::1", "2001:db8:1::1"], results.map(&:destination)
  end

  def test_destination_rule4_prefer_home_address
    results = select(["2001:db8:1::1", "2001:db8:2::1"],
                     [src("2001:db8:1::2"),
                      src("2001:db8:2::2", home: true)])
    assert_equal ["2001:db8:2::1", "2001:db8:1::1"], results.map(&:destination)
  end

  def test_destination_rule5_prefer_matching_label
    table = [
      {prefix: "::/0", precedence: 40, label: 1},
      {prefix: "2001:db8:1::/64", precedence: 40, label: 1},
      {prefix: "2001:db8:2::/64", precedence: 40, label: 2},
      {prefix: "2001:db8:2::1/128", precedence: 40, label: 5},
    ]
    results = select(["2001:db8:2::1", "2001:db8:1::1"],
                     [src("2001:db8:1::2"), src("2001:db8:2::2")],
                     policy_table: table)
    assert_equal ["2001:db8:1::1", "2001:db8:2::1"], results.map(&:destination)
  end

  def test_destination_rule6_prefer_higher_precedence
    table = [
      {prefix: "::/0", precedence: 40, label: 1},
      {prefix: "2001:db8:1::/64", precedence: 10, label: 1},
      {prefix: "2001:db8:2::/64", precedence: 20, label: 1},
    ]
    results = select(["2001:db8:1::1", "2001:db8:2::1"],
                     [src("2001:db8:1::2"), src("2001:db8:2::2")],
                     policy_table: table)
    assert_equal ["2001:db8:2::1", "2001:db8:1::1"], results.map(&:destination)
  end

  def test_destination_rule8_prefer_smaller_scope
    results = select(["2001:db8::5", "fe80::5"],
                     [src("fe80::1"), src("2001:db8::1")])
    assert_equal ["fe80::5", "2001:db8::5"], results.map(&:destination)
  end

  def test_destination_rule9_longest_matching_prefix
    results = select(["2001:db8:2::1", "2001:db8:1::1"],
                     [src("2001:db8:1::2"), src("2001:db8::3")])
    assert_equal ["2001:db8:1::1", "2001:db8:2::1"], results.map(&:destination)
  end

  def test_destination_rule10_ties_keep_input_order
    results = select(["2001:db8::1", "2001:db8::2", "2001:db8::3"],
                     [src("2001:db8::5")])
    assert_equal ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
                 results.map(&:destination)
  end

  #
  # Combinations
  #

  def test_cross_family_default_policy
    results = select(["192.0.2.1", "2001:db8::1"],
                     [src("192.0.2.5"), src("2001:db8::5")])
    assert_equal ["2001:db8::1", "192.0.2.1"], results.map(&:destination)
    assert_equal "2001:db8::5", results[0].source.address
    assert_equal "192.0.2.5", results[1].source.address
    assert results.all?(&:usable?)
  end

  def test_link_local_zones_select_matching_sources
    results = select(["fe80::1%eth0", "fe80::2%eth1"],
                     [src("fe80::5", interface: "eth0"),
                      src("fe80::6", interface: "eth1")])
    assert_equal ["fe80::1%eth0", "fe80::2%eth1"], results.map(&:destination)
    assert_equal "fe80::5", results[0].source.address
    assert_equal "fe80::6", results[1].source.address
  end

  def test_link_local_zone_mismatch_breaks_scope_match
    results = select(["fe80::1%eth0", "2001:db8::1"],
                     [src("fe80::5", interface: "eth1"),
                      src("2001:db8::5")])
    assert_equal ["2001:db8::1", "fe80::1%eth0"], results.map(&:destination)
  end

  def test_multiple_sources_single_destination_rule_cascade
    source = one_source("2001:db8:1::9",
                        [src("2001:db8:1::1", deprecated: true),
                         src("2001:db8:1::2", temporary: true),
                         src("2001:db8:1::3")])
    assert_equal "2001:db8:1::2", source.address
  end

  def test_sources_accept_hashes_and_strings
    results = select(["2001:db8::9"],
                     [{address: "2001:db8::1", temporary: true},
                      "2001:db8::2"])
    assert_equal "2001:db8::1", results.first.source.address
    assert results.first.source.temporary?
  end
end
