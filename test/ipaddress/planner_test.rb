begin
  require 'test_helper'
rescue LoadError
  require 'minitest/autorun'
  require 'ipaddress'
end

class IPAddressPlannerTest < Minitest::Test
  def test_allocates_variable_prefixes_from_minimum_pool
    result = IPAddress.plan(
      pools: ['10.0.0.0/29', '10.0.0.8/30'],
      requests: [
        { id: :a, prefix: 30 },
        { id: :b, prefix: 31 }
      ]
    )

    assert_equal :optimal, result.status
    assert_equal [0], result.enabled_pools
    assert_equal ['10.0.0.0/30', '10.0.0.4/31'], result.allocations.map { |item| item[:cidr] }
    assert_equal 1, result.remaining_fragments
    assert_equal 2, result.remaining_addresses
  end

  def test_reserved_existing_and_forbidden_ranges_are_excluded
    result = IPAddress.plan(
      pools: ['10.0.0.0/29'],
      reserved: ['10.0.0.0/32'],
      existing: ['10.0.0.1/32'],
      forbidden: ['10.0.0.6..10.0.0.7'],
      requests: [{ id: :small, prefix: 31 }]
    )

    assert_equal :optimal, result.status
    assert_equal '10.0.0.2/31', result.allocations.dig(0, :cidr)
    cidrs = [
      '10.0.0.0/32', '10.0.0.1/32',
      '10.0.0.6/32', '10.0.0.7/32'
    ]
    refute_includes cidrs, result.allocations.dig(0, :cidr)
  end

  def test_prefix_range_pool_filter_and_non_natural_alignment
    result = IPAddress.plan(
      pools: [
        { id: :a, cidr: '10.0.0.0/29' },
        { id: :b, cidr: '10.0.0.8/29' }
      ],
      requests: [
        { id: :first, pools: [:b], min_prefix: 31, max_prefix: 31 },
        { id: :aligned, pools: [:a], prefix: 31, alignment: 8 }
      ]
    )

    assert_equal :optimal, result.status
    allocations = result.allocations.to_h { |item| [item[:request_id], item[:cidr]] }
    assert_equal '10.0.0.0/31', allocations[:aligned]
    assert_equal '10.0.0.8/31', allocations[:first]
  end

  def test_small_space_enumeration_matches_independent_brute_force
    pools = ['10.0.0.0/30']
    requests = [
      { id: :a, min_prefix: 31, max_prefix: 32 },
      { id: :b, prefix: 32 }
    ]
    result = IPAddress.plan(pools: pools, requests: requests, budget: 10_000)
    brute_requests = requests.map do |request|
      minimum = request[:min_prefix] || request[:prefix]
      maximum = request[:max_prefix] || request[:prefix]
      request.merge(prefixes: [31, 32].select { |prefix| prefix >= minimum && prefix <= maximum })
    end
    brute_force = enumerate(pools, brute_requests)

    assert result.optimal?
    assert_equal brute_force.fetch(:allocations), result.allocations.map { |item| item[:cidr] }
    assert_equal brute_force.fetch(:fragments), result.remaining_fragments
  end

  def test_repeated_runs_are_deterministic
    options = {
      pools: ['10.0.0.0/28', '10.0.0.16/28', '10.0.0.32/28'],
      requests: [
        { id: 1, min_prefix: 29, max_prefix: 31 },
        { id: 2, min_prefix: 30, max_prefix: 32 },
        { id: 3, prefix: 30 }
      ],
      budget: 200
    }
    first = IPAddress.plan(options).allocations.map { |item| item.slice(:request_id, :pool_id, :cidr) }
    second = IPAddress.plan(options).allocations.map { |item| item.slice(:request_id, :pool_id, :cidr) }

    assert_equal first, second
  end

  def test_budget_exceeded_returns_best_effort_without_claiming_infeasible
    result = IPAddress.plan(
      pools: ['10.0.0.0/30', '10.0.0.4/30'],
      requests: [{ id: :a, prefix: 31 }, { id: :b, prefix: 31 }],
      budget: 4
    )

    assert_equal :best_effort, result.status
    assert result.feasible?
    refute result.optimal?
    refute result.search_exhausted
    assert_equal 2, result.allocations.size
  end

  def test_budget_exceeded_before_leaf_keeps_partial_state
    result = IPAddress.plan(
      pools: ['10.0.0.0/30', '10.0.0.4/30'],
      requests: [{ id: :a, prefix: 31 }, { id: :b, prefix: 31 }],
      budget: 1
    )

    assert_equal :budget_exceeded, result.status
    refute result.feasible?
    refute result.search_exhausted
    assert_equal [:a, :b], result.unallocated_requests
    assert_empty result.blockers
  end

  def test_ipv6_allocation_and_address_formatted_blocker
    result = IPAddress.plan(
      pools: ['2001:db8::/64'],
      requests: [{ prefix: 80 }, { prefix: 80 }]
    )

    assert_equal :optimal, result.status
    assert_equal ['2001:db8::/80', '2001:db8:0:0:ffff::/80'], result.allocations.map { |item| item[:cidr] }

    blocked = IPAddress.plan(
      pools: ['2001:db8::/124'],
      existing: ['2001:db8::/125'],
      requests: [{ prefix: 124 }]
    )

    assert_equal :infeasible, blocked.status
    blocker = blocked.blockers.first[:blockers].first
    assert_equal '2001:db8::/125', blocker[:blocking_intervals].first[:cidr_or_range]
    assert_equal '2001:db8::8', blocker[:gap][:start_address]
  end

  def test_alignment_failure_names_blocking_existing_interval
    result = IPAddress.plan(
      pools: ['10.0.0.0/28'],
      existing: ['10.0.0.0/31'],
      requests: [{ id: :blocked, prefix: 28 }]
    )

    assert_equal :infeasible, result.status
    blocker = result.blockers.first[:blockers].first
    assert_equal 14, result.blockers.first[:total_available_addresses]
    assert_equal '10.0.0.0/31', blocker[:blocking_intervals].first[:cidr_or_range]
    assert_equal '10.0.0.0', blocker[:blocking_intervals].first[:start_address]
    assert_equal '10.0.0.1', blocker[:blocking_intervals].first[:finish_address]
  end

  private

  def enumerate(pool_strings, requests)
    pools = pool_strings.map { |cidr| IPAddress.parse(cidr).network }
    choices = requests.map do |request|
      request[:prefixes].flat_map do |prefix|
        pools.flat_map do |pool|
          pool.subnet(prefix).map do |subnet|
            {
              request_id: request[:id],
              pool: pool.to_string,
              subnet: subnet
            }
          end
        end
      end
    end

    best = nil
    choices[0].product(*choices[1..]) do |selection|
      subnets = selection.map { |item| item[:subnet] }
      next if subnets.combination(2).any? { |left, right| overlaps?(left, right) }

      used_pools = selection.map { |item| item[:pool] }.uniq.sort
      pool_networks = used_pools.map { |cidr| IPAddress.parse(cidr).network }
      fragments = pool_networks.sum do |pool|
        used_subnets = subnets.select { |subnet| subnet.network_u32 >= pool.network_u32 && subnet.broadcast_u32 <= pool.broadcast_u32 }
        subtract(pool, used_subnets).count { |start, finish| start <= finish }
      end
      score = [
        used_pools.size,
        fragments,
        selection.map { |item| item[:pool] }.uniq.sort,
        selection.map { |item| [item[:subnet].network_u32, -item[:subnet].size, item[:subnet].prefix.to_i] }
      ]
      next unless best.nil? || better_brute_force_score?(score, best[:score])
      best = { pools: used_pools, allocations: subnets.map(&:to_string), score: score }
    end

    best.merge(fragments: best[:score][1])
  end

  def overlaps?(left, right)
    left_finish = left.network_u32 + left.size - 1
    right_finish = right.network_u32 + right.size - 1
    left.network_u32 <= right_finish && right.network_u32 <= left_finish
  end

  def subtract(pool, used)
    gaps = []
      cursor = pool.network_u32
      used.sort_by(&:network_u32).each do |subnet|
        next if subnet.network_u32 < cursor
        subnet_finish = subnet.network_u32 + (2**(32 - subnet.prefix.to_i)) - 1
        gaps << [cursor, subnet.network_u32 - 1] if cursor < subnet.network_u32
        cursor = subnet_finish + 1
      end
    gaps << [cursor, pool.broadcast_u32] if cursor <= pool.broadcast_u32
    gaps
  end

  def better_brute_force_score?(left, right)
    return true if left[0] < right[0]
    return false if left[0] > right[0]
    return true if left[1] < right[1]
    return false if left[1] > right[1]
    lexicographic_less?(left, right)
  end

  def lexicographic_less?(left, right)
    left.each_with_index do |value, index|
      other = right[index]
      if value.is_a?(Array)
        next if value == other
        return lexicographic_less?(value, other)
      end
      next if value == other
      return value < other
    end
    false
  end
end
