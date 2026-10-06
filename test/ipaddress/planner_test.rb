require 'test_helper'

class PlannerTest < Minitest::Test

  def plan(**opts)
    IPAddress.plan(**opts)
  end

  def intervals_of(assignments)
    assignments.values.map do |cidr|
      ip = IPAddress.parse(cidr)
      [ip.network_u32, ip.broadcast_u32]
    end
  end

  def assert_no_overlap(assignments, occupied)
    blocks = intervals_of(assignments)
    blocks.combination(2) do |a, b|
      assert a[1] < b[0] || b[1] < a[0],
             "assigned blocks overlap: #{a.inspect} #{b.inspect}"
    end
    occupied.each do |cidr|
      ip = IPAddress.parse(cidr)
      blocks.each do |lo, hi|
        assert hi < ip.network_u32 || lo > ip.broadcast_u32,
               "assigned block #{lo}-#{hi} overlaps #{cidr}"
      end
    end
  end

  def test_basic_allocation_avoids_occupied_space
    res = plan(pools: ["10.0.0.0/24"],
               allocations: ["10.0.0.0/26"],
               reserved: ["10.0.0.64/26"],
               forbidden: ["10.0.0.192/26"],
               requests: [{name: "t", prefix: 26}])
    assert_equal :optimal, res.status
    assert_equal({"t" => "10.0.0.128/26"}, res.assignments)
    assert res.complete?
    assert res.proven?
  end

  def test_request_can_restrict_candidate_pools
    res = plan(pools: ["10.0.0.0/24", "10.1.0.0/24"],
               requests: [{name: "t", prefix: 26, pools: ["10.1.0.0/24"]}])
    assert_equal :optimal, res.status
    assert_equal "10.1.0.0/26", res.assignments["t"]
    assert_equal ["10.1.0.0/24"], res.pools_used
  end

  def test_prefix_range_prefers_smallest_block
    res = plan(pools: ["10.0.0.0/24"],
               requests: [{name: "t", prefix: 26..28}])
    assert_equal "10.0.0.0/28", res.assignments["t"]
  end

  def test_minimizes_number_of_pools_used
    res = plan(pools: ["10.0.0.0/24", "10.1.0.0/24"],
               requests: [{name: "a", prefix: 26}, {name: "b", prefix: 26}])
    assert_equal :optimal, res.status
    assert_equal 1, res.pools_used.size
    assert_equal({"a" => "10.0.0.0/26", "b" => "10.0.0.64/26"},
                 res.assignments)
  end

  def test_minimizes_free_fragments
    # Placing the new /26 at 10.0.0.0 leaves a single free fragment,
    # placing it anywhere past 10.0.0.64/26 would leave two.
    res = plan(pools: ["10.0.0.0/24"],
               allocations: ["10.0.0.64/26"],
               requests: [{name: "t", prefix: 26}])
    assert_equal :optimal, res.status
    assert_equal "10.0.0.0/26", res.assignments["t"]
    assert_equal 1, res.fragments
  end

  def test_alignment_pushes_block_to_boundary
    res = plan(pools: ["10.0.0.0/23"],
               allocations: ["10.0.0.0/26"],
               requests: [{name: "t", prefix: 26, align: 24}])
    assert_equal :optimal, res.status
    assert_equal "10.0.1.0/26", res.assignments["t"]
  end

  def test_alignment_blocker_diagnostics
    # Two /26 allocations leave 128 free addresses, but no aligned
    # /25 slot: the request cannot be placed because of alignment.
    res = plan(pools: ["10.0.0.0/24"],
               allocations: ["10.0.0.64/26", "10.0.0.192/26"],
               requests: [{name: "big", prefix: 25, align: 24}])
    assert_equal :infeasible, res.status
    assert_equal ["big"], res.unplaced
    diag = res.diagnostics["big"]
    assert_equal :no_aligned_space, diag[:reason]
    report = diag[:pools].find { |p| p[:pool] == "10.0.0.0/24" }
    refute_nil report
    ranges = report[:blockers].map { |b| b[:range] }
    assert_includes ranges, "10.0.0.64/26"
    assert_includes ranges, "10.0.0.192/26"
    assert report[:blockers].all? { |b| b[:kind] == :allocation }
  end

  def test_infeasible_when_not_enough_space
    res = plan(pools: ["10.0.0.0/24"],
               allocations: ["10.0.0.0/24"],
               requests: [{name: "t", prefix: 25}])
    assert_equal :infeasible, res.status
    assert_equal :insufficient_space, res.diagnostics["t"][:reason]
    blockers = res.diagnostics["t"][:pools].first[:blockers]
    assert_equal "10.0.0.0/24", blockers.first[:range]
  end

  def test_budget_exhaustion_never_reports_infeasible
    requests = (1..8).map { |i| {name: "t#{i}", prefix: 24} }
    res = plan(pools: ["10.0.0.0/16"], requests: requests, max_nodes: 1)
    assert_equal :unknown, res.status
    refute res.proven?

    res = plan(pools: ["10.0.0.0/16"], requests: requests, max_nodes: 60)
    assert_equal :feasible, res.status
    assert res.complete?
    refute res.proven?
    assert_no_overlap(res.assignments, [])
  end

  def test_deterministic_across_runs
    args = {pools: ["10.0.0.0/24", "10.1.0.0/24"],
            allocations: ["10.0.0.128/25"],
            requests: [{name: "a", prefix: 26..27},
                       {name: "b", prefix: 25..26, align: 25}]}
    first = plan(**args)
    3.times do
      again = plan(**args)
      assert_equal first.status, again.status
      assert_equal first.assignments, again.assignments
      assert_equal first.fragments, again.fragments
    end
  end

  def test_ipv6_pools
    res = plan(pools: ["2001:db8::/60"],
               allocations: ["2001:db8::/64"],
               requests: [{name: "t", prefix: 64}])
    assert_equal :optimal, res.status
    assert_equal "2001:db8:0:1::/64", res.assignments["t"]
  end

  def test_overlapping_pools_rejected
    assert_raises(ArgumentError) do
      plan(pools: ["10.0.0.0/24", "10.0.0.0/25"], requests: [])
    end
  end

  def test_unknown_pool_rejected
    assert_raises(ArgumentError) do
      plan(pools: ["10.0.0.0/24"],
           requests: [{name: "t", prefix: 26, pools: ["10.9.0.0/24"]}])
    end
  end

  def test_impossible_prefix_rejected
    assert_raises(ArgumentError) do
      plan(pools: ["10.0.0.0/24"],
           requests: [{name: "t", prefix: 40}])
    end
  end

  #
  # Cross-check the planner against an independent brute-force
  # enumeration of the whole search space on a small address space.
  #
  def test_enumeration_cross_check
    pools = [[0, 127], [128, 255]] # two /25 blocks of 10.0.0.0/24
    occupied = [[64, 95]]          # 10.0.0.64/27 reserved
    requests = [
      {name: "a", prefixes: [27, 26], align: 26, pools: [0, 1]},
      {name: "b", prefixes: [27], align: nil, pools: [1]},
    ]
    best = brute_force(pools, occupied, requests)
    refute_nil best

    res = plan(pools: ["10.0.0.0/25", "10.0.0.128/25"],
               reserved: ["10.0.0.64/27"],
               requests: [
                 {name: "a", prefix: 26..27, align: 26},
                 {name: "b", prefix: 27, pools: ["10.0.0.128/25"]},
               ])
    assert_equal :optimal, res.status
    expected = {}
    requests.each_with_index do |req, i|
      cand = best[:assignment][i]
      next if cand.nil?
      expected[req[:name]] = "10.0.0.#{cand[2]}/#{cand[1]}"
    end
    assert_equal expected, res.assignments
    assert_equal best[:fragments], res.fragments
    assert_equal best[:pools_used], res.pools_used.size
  end

  # Independent enumerator: tries every placement of every request
  # (skipping only when no candidate exists) and keeps the best
  # solution under the same lexicographic objective as the planner.
  def brute_force(pools, occupied, requests)
    free = pools.map { |lo, hi| [[lo, hi]] }
    occupied.each do |lo, hi|
      free.each_with_index do |intervals, pi|
        next unless pools[pi][1] >= lo && pools[pi][0] <= hi
        free[pi] = subtract(intervals, lo, hi)
      end
    end
    best = nil
    assignment = Array.new(requests.size)
    search = lambda do |i, used, fragments, satisfied|
      if i == requests.size
        key = [-satisfied, used.count(true), fragments] +
              assignment.flat_map { |c| c ? [0, c[0], c[2], -c[1]] : [1, 0, 0, 0] }
        if best.nil? || (key <=> best[:key]) < 0
          best = {key: key, assignment: assignment.dup,
                  fragments: fragments, pools_used: used.count(true)}
        end
        next
      end
      req = requests[i]
      placed = false
      req[:pools].each do |pi|
        req[:prefixes].each do |pfx|
          size = 1 << (32 - pfx)
          gran_prefix = req[:align] && req[:align] < pfx ? req[:align] : pfx
          gran = 1 << (32 - gran_prefix)
          free[pi].each do |lo, hi|
            start = (lo + gran - 1) & ~(gran - 1)
            while start + size - 1 <= hi
              was_used = used[pi]
              before = was_used ? free[pi].size : 0
              removed = free[pi]
              free[pi] = subtract(free[pi], start, start + size - 1)
              used[pi] = true
              assignment[i] = [pi, pfx, start]
              search.call(i + 1, used,
                          fragments + free[pi].size - before,
                          satisfied + 1)
              assignment[i] = nil
              used[pi] = was_used
              free[pi] = removed
              placed = true
              start += gran
            end
          end
        end
      end
      search.call(i + 1, used, fragments, satisfied) unless placed
    end
    search.call(0, Array.new(pools.size, false), 0, 0)
    best
  end

  def subtract(intervals, lo, hi)
    out = []
    intervals.each do |a, b|
      if b < lo || a > hi
        out << [a, b]
      else
        out << [a, lo - 1] if a < lo
        out << [hi + 1, b] if b > hi
      end
    end
    out
  end
end
