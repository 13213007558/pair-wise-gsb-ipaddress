require 'test_helper'

class IPAddressLayoutTest < Minitest::Test
  def test_plans_aligned_non_overlapping_ipv4_subnets
    parent = IPAddress('10.0.0.0/24')
    result = parent.plan_layout([26, 27, 28])

    assert_equal(
      ['10.0.0.0/26', '10.0.0.64/27', '10.0.0.96/28'],
      result.map(&:to_string)
    )
    assert_equal(['10.0.0.112/28', '10.0.0.128/25'], result.remaining.map(&:to_string))
    assert_non_overlapping(parent, result + result.remaining)
  end

  def test_respects_fixed_allocations_and_reservations
    parent = IPAddress('10.0.0.0/27')
    fixed = [IPAddress('10.0.0.8/30')]
    reserved = ['10.0.0.12/31']

    result = parent.plan_layout([29, 30], fixed: fixed, reserved: reserved)

    assert_equal(['10.0.0.0/29', '10.0.0.16/30'], result.map(&:to_string))
    assert_equal(['10.0.0.8/30'], result.fixed_allocations.map(&:to_string))
    assert_equal(['10.0.0.12/31'], result.reserved.map(&:to_string))
    assert_equal(
      ['10.0.0.14/31', '10.0.0.20/30', '10.0.0.24/29'],
      result.remaining.map(&:to_string)
    )
    assert_non_overlapping(parent, result + result.fixed_allocations + result.reserved + result.remaining)
  end

  def test_does_not_mistake_sequential_greedy_failure_for_no_solution
    parent = IPAddress('10.0.0.0/24')
    reserved = ['10.0.0.128/28']

    result = parent.plan_layout([30, 25], reserved: reserved)

    assert_equal(['10.0.0.144/30', '10.0.0.0/25'], result.map(&:to_string))
    assert_non_overlapping(parent, result + result.reserved + result.remaining)
  end

  def test_chooses_lexicographically_smallest_optimal_layout_by_enumeration
    parent = IPAddress('10.0.0.0/29')
    reserved = ['10.0.0.4/32']
    requests = [31, 32, 32]
    result = parent.plan_layout(requests, reserved: reserved)

    optimal = optimal_layouts(parent, result.reserved, requests).first

    assert_equal(optimal[:addresses], result.map(&:to_string))
    assert_equal(optimal[:remaining_blocks], result.remaining.size)
    assert_non_overlapping(parent, result + result.reserved + result.remaining)
  end

  def test_distinguishes_impossible_layout_from_budget_exhaustion
    parent = IPAddress('10.0.0.0/30')

    assert_raises(IPAddress::Layout::Impossible) do
      parent.plan_layout([32, 32, 32, 32, 32])
    end

    assert_raises(IPAddress::Layout::BudgetExhausted) do
      parent.plan_layout([32, 32, 32, 32], search_budget: 0)
    end

    assert_raises(IPAddress::Layout::Impossible) do
      parent.plan_layout([32, 32, 32, 32, 32], search_budget: 0)
    end
  end

  def test_budget_allows_explicit_search_until_optimum_is_found
    parent = IPAddress('10.0.0.0/24')
    options = { reserved: ['10.0.0.128/28'] }

    assert_raises(IPAddress::Layout::BudgetExhausted) do
      parent.plan_layout([30, 25], options.merge(search_budget: 1))
    end

    result = parent.plan_layout([30, 25], options.merge(search_budget: 3))
    assert_equal(['10.0.0.144/30', '10.0.0.0/25'], result.map(&:to_string))
  end

  def test_plans_large_ipv6_parent_without_host_expansion
    parent = IPAddress('::/0')
    def parent.each
      flunk 'IPv6 planning must not enumerate addresses'
    end

    def parent.each_host
      flunk 'IPv6 planning must not enumerate hosts'
    end

    elapsed = Time.now.to_f
    result = parent.plan_layout([48, 64])
    elapsed = Time.now.to_f - elapsed

    assert(elapsed < 1)
    assert_equal(48, result.first.prefix.to_i)
    assert_equal(64, result.last.prefix.to_i)
    assert(result.remaining.size < 256)
    assert_non_overlapping(parent, result + result.remaining)
  end

  def test_does_not_mutate_inputs
    parent = IPAddress('10.0.0.1/24')
    requests = [30, 31]
    fixed = [IPAddress('10.0.0.8/30')]
    reserved = ['10.0.0.12/32']

    result = parent.plan_layout(requests, fixed: fixed, reserved: reserved)

    assert_equal('10.0.0.1/24', parent.to_string)
    assert_equal([30, 31], requests)
    assert_equal(['10.0.0.8/30'], fixed.map(&:to_string))
    assert_equal(['10.0.0.12/32'], reserved)
    assert_instance_of(IPAddress::Layout::Result, result)
    assert_kind_of(Array, result)
  end

  private

  def assert_non_overlapping(parent, subnets)
    subnets.each do |subnet|
      assert(parent.include?(subnet), "#{subnet} is outside #{parent}")
      assert_equal(0, subnet.to_i % subnet.size, "#{subnet} is not aligned")
    end

    subnets.combination(2) do |left, right|
      refute(overlap?(left, right), "#{left} overlaps #{right}")
    end
  end

  def overlap?(left, right)
    left_start = left.ipv4? ? left.network_u32 : left.network_u128
    right_start = right.ipv4? ? right.network_u32 : right.network_u128
    left_start < right_start + right.size && right_start < left_start + left.size
  end

  def optimal_layouts(parent, blocked, prefixes)
    blocked_intervals = blocked.map { |subnet| interval(subnet) }
    sizes = prefixes.map { |prefix| 2 ** (32 - prefix) }
    occupied = search_optimal(parent, blocked_intervals, sizes, [], prefixes)
    occupied.map do |layout|
      {
        addresses: layout[:selected].each_with_index.map do |(start, _size), index|
          IPAddress::IPv4.parse_u32(start, layout[:prefixes][index]).to_string
        end,
        remaining_blocks: free_block_count(parent.network_u32, parent.size, layout[:occupied])
      }
    end
  end

  def search_optimal(parent, blocked, sizes, selected, prefixes)
    if sizes.empty?
      return [{ selected: selected, occupied: blocked.dup, prefixes: prefixes }]
    end

    size = sizes.first
    candidates = (0...(parent.size / size)).map { |index| [parent.network_u32 + index * size, size] }
    candidates.reject! do |candidate|
      blocked.any? { |blocked_start, blocked_size| intervals_overlap?(candidate, [blocked_start, blocked_size]) }
    end

    layouts = candidates.flat_map do |candidate|
      search_optimal(parent, blocked + [candidate], sizes[1..-1], selected + [candidate], prefixes)
    end
    minimum = layouts.map { |layout| free_block_count(parent.network_u32, parent.size, layout[:occupied]) }.min
    layouts.select { |layout| free_block_count(parent.network_u32, parent.size, layout[:occupied]) == minimum }
           .sort_by { |layout| layout[:selected].map(&:first) }
  end

  def interval(subnet)
    [subnet.network_u32, subnet.size]
  end

  def intervals_overlap?(left, right)
    left.first < right.first + right.last && right.first < left.first + left.last
  end

  def free_block_count(start, size, occupied)
    return 0 if occupied.include?([start, size])

    inside = occupied.select do |occupied_start, occupied_size|
      occupied_start >= start && occupied_start + occupied_size <= start + size
    end
    return 1 if inside.empty?

    half = size / 2
    free_block_count(start, half, inside) + free_block_count(start + half, half, inside)
  end
end
