require 'test_helper'
require 'timeout'

class PlannerTest < Minitest::Test

  def subnets_of(result)
    result.subnets.map(&:to_string)
  end

  def free_of(result)
    result.free.map(&:to_string)
  end

  # Minimal CIDR block count of the [lo, hi] interval,
  # implemented independently for cross-checking.
  def cover_count(lo, hi)
    count = 0
    while lo <= hi
      align = lo & -lo
      size = 1 << ((hi - lo + 1).bit_length - 1)
      lo += (align == 0 || align > size) ? size : align
      count += 1
    end
    count
  end

  # Enumerates every possible layout of the requested block sizes
  # inside [base, base + span - 1] avoiding the reserved intervals,
  # and returns [best_count, best_positions] where best_positions is
  # the lexicographically smallest placement (in request order)
  # among those achieving the minimal free CIDR block count.
  # Returns nil when no layout exists.
  def brute_force_best(base, span, sizes, reserved)
    best = nil
    place = lambda do |idx, taken, positions|
      if idx == sizes.size
        free = subtract([[base, base + span - 1]], reserved + taken)
        count = free.inject(0) { |sum, (lo, hi)| sum + cover_count(lo, hi) }
        if best.nil? || count < best[0] || (count == best[0] && (positions <=> best[1]) < 0)
          best = [count, positions.dup]
        end
        next
      end
      size = sizes[idx]
      x = base + ((-base) & (size - 1))
      while x + size <= base + span
        unless (reserved + taken).any? { |lo, hi| x <= hi && x + size - 1 >= lo }
          place.call(idx + 1, taken + [[x, x + size - 1]], positions + [x])
        end
        x += size
      end
    end
    place.call(0, [], [])
    best
  end

  def subtract(intervals, blocks)
    blocks.inject(intervals) do |current, (blo, bhi)|
      current.flat_map do |lo, hi|
        if bhi < lo || blo > hi
          [[lo, hi]]
        else
          parts = []
          parts << [lo, blo - 1] if blo > lo
          parts << [bhi + 1, hi] if bhi < hi
          parts
        end
      end
    end
  end

  def int_of(ip)
    ip.ipv4? ? ip.network_u32 : ip.network_u128
  end

  def assert_valid_layout(result, parent, reserved)
    taken = result.subnets.map { |s| [int_of(s), int_of(s) + s.size - 1] }
    (taken + reserved).combination(2) do |(alo, ahi), (blo, bhi)|
      assert alo > bhi || blo > ahi, "overlapping intervals [#{alo},#{ahi}] [#{blo},#{bhi}]"
    end
    plo = int_of(parent)
    phi = plo + parent.size - 1
    taken.each do |lo, hi|
      assert lo >= plo && hi <= phi, "subnet outside parent"
    end
    result.subnets.each { |s| assert s.network?, "#{s.to_string} is not aligned" }
    # free space plus allocations plus reserved must tile the parent
    free = result.free.map { |s| [int_of(s), int_of(s) + s.size - 1] }
    all = (taken + reserved + free).sort
    assert_equal plo, all.first[0]
    assert_equal phi, all.last[1]
    all.each_cons(2) do |(_, ahi), (blo, _)|
      assert_equal ahi + 1, blo, "layout does not tile the parent network"
    end
  end

  # -- basic layout --------------------------------------------------

  def test_plans_simple_ipv4_layout
    result = IPAddress::Planner.plan(IPAddress("10.0.0.0/24"), [26, 26])
    assert_equal ["10.0.0.0/26", "10.0.0.64/26"], subnets_of(result)
    assert_equal ["10.0.0.128/25"], free_of(result)
    assert_equal 1, result.free_count
  end

  def test_returns_ip_objects_with_requested_prefixes
    result = IPAddress::Planner.plan("10.0.0.0/24", [28])
    assert_instance_of IPAddress::IPv4, result.subnets.first
    assert_equal 28, result.subnets.first.prefix.to_i
    assert_equal "10.0.0.0", result.subnets.first.address
  end

  def test_respects_reserved_segments
    result = IPAddress::Planner.plan("10.0.0.0/24", [26, 26],
                                     reserved: [IPAddress("10.0.0.240/28")])
    assert_equal ["10.0.0.0/26", "10.0.0.64/26"], subnets_of(result)
    assert_equal ["10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/28"], free_of(result)
  end

  def test_respects_fixed_allocations
    result = IPAddress::Planner.plan("10.0.0.0/24", [26],
                                     fixed: ["10.0.0.0/26"])
    assert_equal ["10.0.0.64/26"], subnets_of(result)
  end

  def test_backtracks_when_greedy_first_fit_would_fail
    # A greedy first-fit in request order places the /26 at 10.0.0.0/26,
    # after which no aligned /25 remains free. That local dead end must
    # not be mistaken for global infeasibility.
    result = IPAddress::Planner.plan("10.0.0.0/24", [26, 25],
                                     reserved: ["10.0.0.128/26"])
    assert_equal ["10.0.0.192/26", "10.0.0.0/25"], subnets_of(result)
    assert_equal 0, result.free_count
  end

  def test_minimizes_free_cidr_blocks
    # Placing the /26 at .64 leaves a single /25 free; every other
    # position fragments the remaining space into two blocks.
    result = IPAddress::Planner.plan("10.0.0.0/24", [26],
                                     reserved: ["10.0.0.0/26"])
    assert_equal ["10.0.0.64/26"], subnets_of(result)
    assert_equal ["10.0.0.128/25"], free_of(result)
  end

  # -- infeasible vs budget exhausted ---------------------------------

  def test_raises_infeasible_when_requests_do_not_fit
    assert_raises(IPAddress::Planner::Infeasible) do
      IPAddress::Planner.plan("10.0.0.0/24", [24, 25])
    end
  end

  def test_raises_infeasible_when_request_is_bigger_than_parent
    assert_raises(IPAddress::Planner::Infeasible) do
      IPAddress::Planner.plan("10.0.0.0/24", [23])
    end
  end

  def test_raises_infeasible_when_reserved_blocks_everything
    assert_raises(IPAddress::Planner::Infeasible) do
      IPAddress::Planner.plan("10.0.0.0/24", [25], reserved: ["10.0.0.0/24"])
    end
  end

  def test_infeasible_is_proven_not_a_budget_problem
    error = assert_raises(IPAddress::Planner::Infeasible) do
      IPAddress::Planner.plan("10.0.0.0/24", [24, 25], budget: nil)
    end
    refute_kind_of IPAddress::Planner::BudgetExceeded, error
  end

  def test_budget_exceeded_is_distinct_from_infeasible
    error = assert_raises(IPAddress::Planner::BudgetExceeded) do
      IPAddress::Planner.plan("10.0.0.0/24", [26, 26], budget: 1)
    end
    assert_kind_of IPAddress::Planner::Error, error
    refute_kind_of IPAddress::Planner::Infeasible, error
    assert_nil error.best
  end

  def test_budget_exceeded_carries_best_effort_layout
    error = assert_raises(IPAddress::Planner::BudgetExceeded) do
      IPAddress::Planner.plan("2001:db8::/64", [126, 126, 125],
                              reserved: ["2001:db8::ffff/128"], budget: 1_000)
    end
    refute_nil error.best
    assert_equal 3, error.best.subnets.size
  end

  def test_unlimited_budget_with_nil
    result = IPAddress::Planner.plan("10.0.0.0/24", [26, 26], budget: nil)
    assert_equal 2, result.size
  end

  # -- input validation ------------------------------------------------

  def test_rejects_reserved_outside_parent
    assert_raises(ArgumentError) do
      IPAddress::Planner.plan("10.0.0.0/24", [26], reserved: ["10.0.1.0/26"])
    end
  end

  def test_rejects_mismatched_address_family
    assert_raises(ArgumentError) do
      IPAddress::Planner.plan("10.0.0.0/24", [26], reserved: ["2001:db8::/64"])
    end
  end

  def test_rejects_out_of_range_prefix
    assert_raises(ArgumentError) do
      IPAddress::Planner.plan("10.0.0.0/24", [33])
    end
  end

  def test_rejects_invalid_request
    assert_raises(ArgumentError) do
      IPAddress::Planner.plan("10.0.0.0/24", ["26"])
    end
  end

  # -- inputs are never modified ----------------------------------------

  def test_does_not_modify_inputs
    parent = IPAddress("10.0.0.0/24")
    requests = [26, 27]
    fixed = [IPAddress("10.0.0.192/26")]
    reserved = [IPAddress("10.0.0.128/26")]
    IPAddress::Planner.plan(parent, requests, fixed: fixed, reserved: reserved)
    assert_equal "10.0.0.0/24", parent.to_string
    assert_equal [26, 27], requests
    assert_equal ["10.0.0.192/26"], fixed.map(&:to_string)
    assert_equal ["10.0.0.128/26"], reserved.map(&:to_string)
  end

  # -- IPv6 ------------------------------------------------------------

  def test_plans_simple_ipv6_layout
    result = IPAddress::Planner.plan("2001:db8::/64", [66, 66])
    assert_equal ["2001:db8::/66", "2001:db8:0:0:4000::/66"], subnets_of(result)
    assert_equal ["2001:db8:0:0:8000::/65"], free_of(result)
    assert result.subnets.all? { |s| s.is_a?(IPAddress::IPv6) }
  end

  def test_ipv6_fixed_and_reserved
    result = IPAddress::Planner.plan("2001:db8::/64", [66],
                                     fixed: ["2001:db8::/66"],
                                     reserved: ["2001:db8:0:0:8000::/65"])
    assert_equal ["2001:db8:0:0:4000::/66"], subnets_of(result)
    assert_equal [], result.free
  end

  def test_ipv6_infeasible
    assert_raises(IPAddress::Planner::Infeasible) do
      IPAddress::Planner.plan("2001:db8::/126", [125, 125, 125])
    end
  end

  def test_large_ipv6_parent_does_not_expand_hosts
    # A /48 spans 2^80 addresses; enumerating hosts would never finish.
    result = nil
    Timeout.timeout(30) do
      result = IPAddress::Planner.plan("2001:db8::/48", [64, 64, 64])
    end
    assert_equal ["2001:db8::/64", "2001:db8:0:1::/64", "2001:db8:0:2::/64"],
                 subnets_of(result)
    assert_valid_layout(result, IPAddress("2001:db8::/48"), [])
  end

  def test_large_ipv6_parent_with_small_request_prefixes
    # Requesting /126 and /125 subnets from a /64 must not enumerate
    # the 2^64 host addresses either.
    result = nil
    Timeout.timeout(30) do
      result = IPAddress::Planner.plan("2001:db8::/64", [126, 126, 125])
    end
    assert_equal ["2001:db8::/126", "2001:db8::4/126", "2001:db8::8/125"],
                 subnets_of(result)
    assert_valid_layout(result, IPAddress("2001:db8::/64"), [])
  end

  # -- exhaustive verification on small parents -------------------------

  def verify_against_brute_force(parent, prefixes, reserved)
    bits = parent.ipv4? ? 32 : 128
    base = int_of(parent)
    span = parent.size
    sizes = prefixes.map { |p| 1 << (bits - p) }
    reserved_intervals = reserved.map { |r| [int_of(r), int_of(r) + r.size - 1] }
    best = brute_force_best(base, span, sizes, reserved_intervals)
    if best.nil?
      assert_raises(IPAddress::Planner::Infeasible) do
        IPAddress::Planner.plan(parent, prefixes, reserved: reserved)
      end
    else
      count, positions = best
      result = IPAddress::Planner.plan(parent, prefixes, reserved: reserved)
      assert_equal positions, result.subnets.map { |s| int_of(s) },
        "layout for #{parent.to_string} requests=#{prefixes.inspect} " +
        "reserved=#{reserved.map(&:to_string).inspect} is not the optimal one"
      assert_equal count, result.free_count
      assert_valid_layout(result, parent, reserved_intervals)
    end
  end

  def test_matches_brute_force_on_small_ipv4_parent
    parent = IPAddress("10.0.0.0/26")
    reserved_sets = [
      [],
      [IPAddress("10.0.0.16/28")],
      [IPAddress("10.0.0.0/28"), IPAddress("10.0.0.56/29")],
    ]
    request_sets = [[28, 28], [29, 28, 30], [27, 28], [30, 30, 30, 30], [26], [27, 27]]
    reserved_sets.each do |reserved|
      request_sets.each do |prefixes|
        verify_against_brute_force(parent, prefixes, reserved)
      end
    end
  end

  def test_matches_brute_force_on_small_ipv6_parent
    parent = IPAddress("2001:db8::/124")
    reserved_sets = [
      [],
      [IPAddress("2001:db8::4/126")],
      [IPAddress("2001:db8::/125"), IPAddress("2001:db8::e/127")],
    ]
    request_sets = [[126, 126], [127, 126, 128], [125], [126, 127]]
    reserved_sets.each do |reserved|
      request_sets.each do |prefixes|
        verify_against_brute_force(parent, prefixes, reserved)
      end
    end
  end

  def test_matches_brute_force_with_tight_space
    parent = IPAddress("10.0.0.0/27")
    reserved = [IPAddress("10.0.0.8/29")]
    [[29, 29, 29], [28, 28], [26]].each do |prefixes|
      verify_against_brute_force(parent, prefixes, reserved)
    end
  end
end

  def test_prefers_lexicographically_smallest_addresses_on_ties
    result = IPAddress::Planner.plan("10.0.0.0/24", [25])
    assert_equal ["10.0.0.0/25"], subnets_of(result)
  end

  def test_supports_named_requests_as_hash
    result = IPAddress::Planner.plan("10.0.0.0/24", {dmz: 26, web: 27})
    assert_equal "10.0.0.0/26", result.named[:dmz].to_string
    assert_equal "10.0.0.64/27", result.named[:web].to_string
    assert_equal ["10.0.0.0/26", "10.0.0.64/27"], subnets_of(result)
  end

  def test_supports_named_requests_as_hashes
    result = IPAddress::Planner.plan("10.0.0.0/24", [{name: "dmz", prefix: 26}])
    assert_equal "10.0.0.0/26", result.named["dmz"].to_string
  end

  def test_empty_request_list
    result = IPAddress::Planner.plan("10.0.0.0/24", [], reserved: ["10.0.0.0/25"])
    assert_equal [], result.subnets
    assert_equal ["10.0.0.128/25"], free_of(result)
  end
