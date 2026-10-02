require 'test_helper'

class RFC6724Test < Minitest::Test

  RFC = IPAddress::RFC6724

  # Scopes used across the tests (explicit input, RFC 4291 numbering)
  IL = RFC::SCOPE_INTERFACE_LOCAL
  LL = RFC::SCOPE_LINK_LOCAL
  SL = RFC::SCOPE_SITE_LOCAL
  G  = RFC::SCOPE_GLOBAL

  def src(address, scope: G, **opts)
    RFC::Source.new(address, scope: scope, **opts)
  end

  def dst(address, scope: G, **opts)
    RFC::Destination.new(address, scope: scope, **opts)
  end

  def select(destination, sources, **opts)
    RFC::Selector.new(sources: sources, **opts).select_source(destination)
  end

  def sort(destinations, sources, **opts)
    RFC::Selector.new(sources: sources, **opts).sort(destinations)
  end

  def sorted_addresses(results)
    results.map { |result| result.destination.address.to_s }
  end

  #
  # RFC 6724 section 5: source address selection. One minimal
  # example per rule; the losing candidate is always listed first,
  # so each test only passes if the rule actually flips the outcome.
  #

  def test_source_rule1_prefer_same_address
    destination = dst("2001:db8::5")
    sources = [src("2001:db8::6"), src("2001:db8::5")]
    assert_equal "2001:db8::5", select(destination, sources).address.to_s
  end

  def test_source_rule2_prefer_sufficient_scope
    # The link-local source shares a longer prefix with the
    # destination (which rule 8 would prefer), but only the global
    # source has a sufficient scope.
    destination = dst("2001:db8:1::9", scope: G)
    sources = [src("2001:db8:1::1", scope: LL), src("2001:db8:2::1", scope: G)]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule2_prefer_smallest_sufficient_scope
    destination = dst("2001:db8::9", scope: LL)
    sources = [src("2001:db8:1::1", scope: G), src("2001:db8:2::1", scope: SL)]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule2_prefer_largest_insufficient_scope
    destination = dst("2001:db8::9", scope: G)
    sources = [src("2001:db8:1::1", scope: IL), src("2001:db8:2::1", scope: LL)]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule3_avoid_deprecated
    destination = dst("2001:db8::9")
    sources = [src("2001:db8:1::1", deprecated: true), src("2001:db8:2::1")]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule4_prefer_home_over_care_of
    destination = dst("2001:db8::9")
    sources = [src("2001:db8:1::1", care_of: true), src("2001:db8:2::1")]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule4_prefer_home_and_care_of
    destination = dst("2001:db8::9")
    sources = [src("2001:db8:1::1", home: true),
               src("2001:db8:2::1", home: true, care_of: true)]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule5_prefer_outgoing_interface
    destination = dst("2001:db8::9", interface: "eth0")
    sources = [src("2001:db8:1::1", interface: "eth1"),
               src("2001:db8:2::1", interface: "eth0")]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule5_5_prefer_next_hop_advertised_prefix
    # The first source shares a longer prefix with the destination
    # (which rule 8 would prefer), but only the second one sits
    # inside a prefix advertised by the next-hop.
    destination = dst("2001:db8:1::9", advertised_prefixes: ["2001:db8:2::/48"])
    sources = [src("2001:db8:1:1::1"), src("2001:db8:2::7")]
    assert_equal "2001:db8:2::7", select(destination, sources).address.to_s
  end

  def test_source_rule6_prefer_matching_label
    # Custom policy table: the first source shares a longer prefix
    # with the destination (which rule 8 would prefer), but only the
    # second source has a matching label.
    table = RFC::PolicyTable.new(defaults: false)
    table.add("::/0", precedence: 40, label: 1)
    table.add("2001:db8:1:1::/64", precedence: 40, label: 9)
    destination = dst("2001:db8:1:2::9")
    sources = [src("2001:db8:1:1::1"), src("2001:db8:2::1")]
    selected = select(destination, sources, policy_table: table)
    assert_equal "2001:db8:2::1", selected.address.to_s
  end

  def test_source_rule7_prefer_temporary
    destination = dst("2001:db8::9")
    sources = [src("2001:db8:1::1"), src("2001:db8:2::1", temporary: true)]
    assert_equal "2001:db8:2::1", select(destination, sources).address.to_s
  end

  def test_source_rule7_temporary_preference_can_be_reversed
    destination = dst("2001:db8::9")
    sources = [src("2001:db8:1::1"), src("2001:db8:2::1", temporary: true)]
    selected = select(destination, sources, prefer_temporary: false)
    assert_equal "2001:db8:1::1", selected.address.to_s
  end

  def test_source_rule8_longest_matching_prefix
    destination = dst("2001:db8:1:2::9")
    sources = [src("2001:db8:9::1"), src("2001:db8:1:2::7")]
    assert_equal "2001:db8:1:2::7", select(destination, sources).address.to_s
  end

  def test_source_tie_keeps_input_order
    destination = dst("2001:db8:1::9")
    first = src("2001:db8:2::1")
    second = src("2001:db8:3::1")
    assert_equal first, select(destination, [first, second])
    assert_equal second, select(destination, [second, first])
  end

  def test_select_source_returns_nil_without_eligible_source
    destination = dst("2001:db8::1")
    assert_nil select(destination, [src("192.0.2.1")])
    assert_nil select(destination, [])
  end

  #
  # RFC 6724 section 6: destination address selection. One minimal
  # example per rule; the losing destination is always listed first.
  #

  def test_destination_rule1_avoid_unreachable
    unreachable = dst("2001:db8::1", reachable: false)
    usable = dst("2001:db8::2")
    results = sort([unreachable, usable], [src("2001:db8::9")])
    assert_equal ["2001:db8::2", "2001:db8::1"], sorted_addresses(results)
    refute results.last.usable?
    # Source selection itself is independent of reachability
    assert_equal "2001:db8::9", results.last.source.address.to_s
  end

  def test_destination_without_suitable_source_sinks
    no_source = dst("2001:db8::1")
    with_source = dst("10.0.0.1")
    results = sort([no_source, with_source], [src("192.0.2.1")])
    assert_equal ["10.0.0.1", "2001:db8::1"], sorted_addresses(results)
    assert results.first.usable?
    refute results.last.usable?
    assert_nil results.last.source
  end

  def test_destination_rule2_prefer_matching_scope
    # The only source has global scope, so the link-local
    # destination ends up with a scope mismatch. Rule 2 beats rule 8
    # (which would prefer the smaller link-local scope).
    mismatched = dst("2001:db8::a", scope: LL)
    matched = dst("2001:db8::b", scope: G)
    results = sort([mismatched, matched], [src("2001:db8::1", scope: G)])
    assert_equal ["2001:db8::b", "2001:db8::a"], sorted_addresses(results)
  end

  def test_destination_rule3_avoid_deprecated_source
    # 2001:db8::1 selects the deprecated source (same address,
    # source rule 1), 2001:db8::9 selects the fresh one.
    deprecated_source = src("2001:db8::1", deprecated: true)
    fresh_source = src("2001:db8::2")
    results = sort([dst("2001:db8::1"), dst("2001:db8::9")],
                   [deprecated_source, fresh_source])
    assert_equal ["2001:db8::9", "2001:db8::1"], sorted_addresses(results)
    assert_equal "2001:db8::2", results.first.source.address.to_s
    assert_equal "2001:db8::1", results.last.source.address.to_s
  end

  def test_destination_rule4_prefer_home_source
    care_of_source = src("2001:db8::1", care_of: true)
    plain_source = src("2001:db8::2")
    results = sort([dst("2001:db8::1"), dst("2001:db8::9")],
                   [care_of_source, plain_source])
    assert_equal ["2001:db8::9", "2001:db8::1"], sorted_addresses(results)
  end

  def test_destination_rule5_prefer_matching_label
    # ::1 has a higher precedence (50) than 2001:db8::9 (40), but
    # rule 5 fires before rule 6 and only 2001:db8::9 has a source
    # with a matching label.
    source = src("2001:db8::1")
    results = sort([dst("::1"), dst("2001:db8::9")], [source])
    assert_equal ["2001:db8::9", "::1"], sorted_addresses(results)
  end

  def test_destination_rule6_prefer_higher_precedence
    sources = [src("192.0.2.1"), src("2001:db8::1")]
    results = sort([dst("8.8.8.8"), dst("2001:db8::9")], sources)
    assert_equal ["2001:db8::9", "8.8.8.8"], sorted_addresses(results)
  end

  def test_destination_rule8_prefer_smaller_scope
    sources = [src("2001:db8::1", scope: G), src("fe80::1", scope: LL)]
    results = sort([dst("2001:db8::9", scope: G), dst("fe80::9", scope: LL)],
                   sources)
    assert_equal ["fe80::9", "2001:db8::9"], sorted_addresses(results)
  end

  def test_destination_rule9_longest_matching_prefix
    # Each destination selects its longest-prefix source (rule 8 of
    # source selection); the pair sharing 112 bits beats the pair
    # sharing 48 bits.
    sources = [src("2001:db8:1:1::1"), src("2001:db8:2:8::1")]
    results = sort([dst("2001:db8:2::9"), dst("2001:db8:1:1::9")], sources)
    assert_equal ["2001:db8:1:1::9", "2001:db8:2::9"], sorted_addresses(results)
  end

  def test_destination_rule10_keeps_input_order
    sources = [src("2001:db8::9")]
    destinations = [dst("2001:db8::1"), dst("2001:db8::2"), dst("2001:db8::3")]
    assert_equal ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
                 sorted_addresses(sort(destinations, sources))
    assert_equal ["2001:db8::3", "2001:db8::2", "2001:db8::1"],
                 sorted_addresses(sort(destinations.reverse, sources))
  end

  #
  # Policy table
  #

  def test_policy_table_default_entries
    table = RFC::PolicyTable.new
    assert_equal [50, 0], table.lookup("::1").to_a
    assert_equal [40, 1], table.lookup("2001:db8::1").to_a
    assert_equal [35, 4], table.lookup("8.8.8.8").to_a
    assert_equal [30, 2], table.lookup("2002::1").to_a
    assert_equal [5, 5],  table.lookup("2001:0::1").to_a
    assert_equal [3, 13], table.lookup("fc00::1").to_a
  end

  def test_policy_table_user_entries_use_longest_match
    table = RFC::PolicyTable.new
    table.add("2001:db8::/32", precedence: 45, label: 7)
    assert_equal [45, 7], table.lookup("2001:db8::1").to_a
    assert_equal [40, 1], table.lookup("2001:db9::1").to_a
    table.add("2001:db8:1::/48", precedence: 46, label: 8)
    assert_equal [46, 8], table.lookup("2001:db8:1::1").to_a
    assert_equal [45, 7], table.lookup("2001:db8:2::1").to_a
  end

  def test_policy_table_user_entry_overrides_default_with_same_prefix
    table = RFC::PolicyTable.new
    table.add("::/0", precedence: 99, label: 9)
    assert_equal [99, 9], table.lookup("2001:db8::1").to_a
    assert_equal [50, 0], table.lookup("::1").to_a
  end

  def test_policy_table_ipv4_entries
    table = RFC::PolicyTable.new
    table.add("10.0.0.0/8", precedence: 60, label: 9)
    assert_equal [60, 9], table.lookup("10.1.2.3").to_a
    assert_equal [35, 4], table.lookup("11.0.0.1").to_a
  end

  def test_policy_table_without_defaults
    table = RFC::PolicyTable.new(defaults: false)
    assert_nil table.lookup("2001:db8::1")
    # The selector falls back to a zero precedence/label entry and
    # still sorts, keeping the input order for otherwise tied pairs.
    sources = [src("2001:db8::9")]
    destinations = [dst("2001:db8::1"), dst("2001:db8::2")]
    results = sort(destinations, sources, policy_table: table)
    assert_equal ["2001:db8::1", "2001:db8::2"], sorted_addresses(results)
  end

  #
  # Combinations
  #

  def test_cross_family_combination
    sources = [src("192.0.2.1"), src("2001:db8::1")]
    destinations = [dst("8.8.8.8"), dst("2001:db8::9"), dst("10.0.0.1")]

    # Default policy: native IPv6 (precedence 40) beats IPv4 (35);
    # the two IPv4 destinations tie and keep their input order.
    results = sort(destinations, sources)
    assert_equal ["2001:db8::9", "8.8.8.8", "10.0.0.1"],
                 sorted_addresses(results)
    assert_equal "2001:db8::1", results[0].source.address.to_s
    assert_equal "192.0.2.1", results[1].source.address.to_s
    assert_equal "192.0.2.1", results[2].source.address.to_s

    # A user policy entry can flip the preference towards IPv4.
    table = RFC::PolicyTable.new
    table.add("8.8.8.0/24", precedence: 100, label: 4)
    results = sort(destinations, sources, policy_table: table)
    assert_equal ["8.8.8.8", "2001:db8::9", "10.0.0.1"],
                 sorted_addresses(results)
  end

  def test_link_local_with_zone
    sources = [src("fe80::5", scope: LL, interface: "eth0"),
               src("fe80::6", scope: LL, interface: "eth1"),
               src("2001:db8::5", scope: G, interface: "eth0")]

    # Only sources on the zone's interface are eligible.
    on_eth0 = dst("fe80::1%eth0", scope: LL)
    assert_equal "eth0", on_eth0.zone
    assert_equal "eth0", on_eth0.interface
    assert_equal "fe80::5", select(on_eth0, sources).address.to_s

    # The zone can also be passed explicitly.
    explicit = dst("fe80::3", scope: LL, zone: "eth0")
    assert_equal "fe80::5", select(explicit, sources).address.to_s

    # A zone without any source on its interface has no suitable
    # source and sinks to the bottom.
    on_eth3 = dst("fe80::2%eth3", scope: LL)
    results = sort([on_eth3, on_eth0], sources)
    assert_equal ["fe80::1", "fe80::2"], sorted_addresses(results)
    assert results.first.usable?
    refute results.last.usable?
    assert_nil results.last.source
  end

  def test_multiple_sources_for_one_destination
    destination = dst("2001:db8:1::9")
    sources = [
      src("192.0.2.1"),                          # wrong family
      src("fc00::1"),                            # label mismatch
      src("2001:db8:1::5", deprecated: true),    # deprecated
      src("2001:db8:1::7", temporary: true),     # best candidate
    ]
    assert_equal "2001:db8:1::7", select(destination, sources).address.to_s
  end

  def test_combined_sort
    sources = [src("192.0.2.1", interface: "eth0"),
               src("2001:db8::1", interface: "eth0"),
               src("fe80::5", scope: LL, interface: "eth0")]
    global_v6 = dst("2001:db8::9")
    global_v4 = dst("8.8.8.8")
    link_local = dst("fe80::1%eth0", scope: LL)
    unreachable = dst("2001:db8::dead", reachable: false)
    no_source = dst("fe80::2%eth9", scope: LL)

    results = sort([global_v4, no_source, link_local, unreachable, global_v6],
                   sources)
    # Link-local wins on smaller scope (rule 8) after tying on
    # precedence; unusable destinations sink, keeping input order.
    assert_equal ["fe80::1", "2001:db8::9", "8.8.8.8",
                  "fe80::2", "2001:db8::dead"],
                 sorted_addresses(results)
    assert_equal "fe80::5", results[0].source.address.to_s
    assert_equal "2001:db8::1", results[1].source.address.to_s
    assert_equal "192.0.2.1", results[2].source.address.to_s
    assert results[0].usable?
    assert results[1].usable?
    assert results[2].usable?
    refute results[3].usable?
    refute results[4].usable?
    assert_nil results[3].source
    assert_equal "2001:db8::1", results[4].source.address.to_s
  end

  #
  # Input validation
  #

  def test_selector_rejects_raw_addresses
    assert_raises(ArgumentError) { RFC::Selector.new(sources: ["1.2.3.4"]) }
    assert_raises(ArgumentError) do
      RFC::Selector.new(sources: []).sort(["2001:db8::1"])
    end
  end
end
