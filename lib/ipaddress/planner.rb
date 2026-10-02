#
# = IPAddress::Planner
#
# Batch subnet layout planner: given a parent network, a list of
# subnet requests (by prefix length), optional fixed allocations and
# reserved segments, compute a non-overlapping, properly aligned
# layout for all requests.
#
# Package::     IPAddress
# Author::      Marco Ceresa <ceresa@ieee.org>
# License::     Ruby License
#

require 'ipaddress/ipv4'
require 'ipaddress/ipv6'

module IPAddress

  #
  # IPAddress::Planner performs batch layout planning of a parent
  # network. It takes a set of subnet requests (each identified by the
  # desired prefix length), optional fixed allocations that must be
  # left untouched, and optional reserved segments that cannot be
  # used, and returns a layout of aligned, non-overlapping subnets
  # that satisfies every request.
  #
  # The planner works on both IPv4 and IPv6 networks and operates
  # purely on integer range arithmetic, so even huge IPv6 parent
  # networks are handled without enumerating individual addresses.
  #
  # The layout is chosen according to the following criteria, in
  # order:
  #
  # 1. every request must be satisfied (otherwise the planner reports
  #    the layout as infeasible),
  # 2. the remaining free space must be coverable by as few CIDR
  #    blocks as possible,
  # 3. among equally good layouts, the one with the lexicographically
  #    smallest subnet addresses (in request order) wins.
  #
  # The search is a complete backtracking search: a greedy
  # allocation order that gets stuck is never mistaken for global
  # infeasibility. An explicit search budget can be supplied; running
  # out of budget is reported separately from proven infeasibility.
  #
  # Example:
  #
  #   result = IPAddress::Planner.plan(IPAddress("10.0.0.0/24"),
  #                                    [26, 26],
  #                                    reserved: [IPAddress("10.0.0.240/28")])
  #
  #   result.subnets.map(&:to_string)
  #     #=> ["10.0.0.0/26", "10.0.0.64/26"]
  #
  #   result.free.map(&:to_string)
  #     #=> ["10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/28"]
  #
  module Planner

    # Default maximum number of candidate placements explored by
    # +plan+. Pass an explicit +:budget+ to override, or +nil+ for no
    # limit.
    DEFAULT_BUDGET = 1_000_000

    #
    # Base class for all planner errors.
    #
    class Error < StandardError; end

    #
    # Raised when the whole search space has been explored and no
    # layout can satisfy all the requests. This is a proven negative
    # answer, as opposed to BudgetExceeded, which means the answer is
    # unknown because the search was cut short.
    #
    class Infeasible < Error; end

    #
    # Raised when the search budget is exhausted before the search
    # space has been fully explored. The best layout found so far (if
    # any) is available through #best, but it is not guaranteed to be
    # optimal.
    #
    class BudgetExceeded < Error
      # The best layout found before the budget ran out, or nil if no
      # feasible layout was found at all. Not guaranteed to be optimal.
      attr_reader :best

      def initialize(message = nil, best = nil)
        @best = best
        super(message || "search budget exhausted before the layout could be proven optimal")
      end
    end
    #
    # The outcome of a successful Planner::plan call.
    #
    #   result = IPAddress::Planner.plan(IPAddress("10.0.0.0/24"), [26, 27])
    #
    #   result.subnets.map(&:to_string)
    #     #=> ["10.0.0.0/26", "10.0.0.64/27"]
    #
    class Result
      # The subnets allocated to the requests, in request order.
      # Each element is an IPv4 or IPv6 object carrying the requested
      # prefix length.
      attr_reader :subnets

      # The minimal CIDR decomposition of the space that remains free
      # inside the parent network, as an array of network objects.
      attr_reader :free

      # The normalized requests the layout answers, as an array of
      # hashes with +:prefix+ and +:name+ keys.
      attr_reader :requests

      def initialize(subnets, free, requests) # :nodoc:
        @subnets = subnets.freeze
        @free = free.freeze
        @requests = requests.map(&:dup).freeze
      end

      # The subnet allocated to the +index+-th request.
      def [](index)
        @subnets[index]
      end

      # The number of allocated subnets.
      def size
        @subnets.size
      end

      # The number of CIDR blocks needed to cover the remaining free
      # space. This is the quantity the planner minimizes after all
      # requests have been satisfied.
      def free_count
        @free.size
      end

      # A hash mapping each named request to its allocated subnet.
      #
      #   result = IPAddress::Planner.plan(IPAddress("10.0.0.0/24"),
      #                                    [{name: "dmz", prefix: 26}])
      #   result.named["dmz"].to_string
      #     #=> "10.0.0.0/26"
      #
      def named
        @named ||= begin
          mapping = {}
          @requests.each_with_index do |req, index|
            mapping[req[:name]] = @subnets[index] if req[:name]
          end
          mapping
        end
      end
    end

    #
    # Plans a batch subnet layout for +parent+.
    #
    # * +parent+: the network to carve up, as an IPv4/IPv6 object or a
    #   string such as "10.0.0.0/24" or "2001:db8::/48".
    # * +requests+: an array of requested prefix lengths. Each entry
    #   may be an Integer (e.g. +26+), or a hash with a +:prefix+ key
    #   and an optional +:name+ key. A hash of +name => prefix+ is
    #   also accepted.
    # * +fixed+: allocations that already exist inside the parent and
    #   must be left untouched (strings or IP objects).
    # * +reserved+: segments that cannot be used for new allocations
    #   (strings or IP objects).
    # * +budget+: maximum number of candidate placements to explore.
    #   Defaults to DEFAULT_BUDGET; pass +nil+ for an unlimited
    #   search.
    #
    # Returns a Planner::Result. Raises Planner::Infeasible when no
    # layout can satisfy all requests, and Planner::BudgetExceeded
    # when the budget runs out before the search completes.
    #
    # The inputs are never modified and no network configuration is
    # touched: the method only computes and returns new objects.
    #
    def self.plan(parent, requests, fixed: [], reserved: [], budget: DEFAULT_BUDGET)
      parent = IPAddress.parse(parent) if parent.is_a?(String)
      bits = case parent
             when IPAddress::IPv4 then 32
             when IPAddress::IPv6 then 128
             else
               raise ArgumentError, "parent must be an IPv4 or IPv6 network: #{parent.inspect}"
             end

      parent_lo = bits == 32 ? parent.network_u32 : parent.network_u128
      parent_size = 1 << (bits - parent.prefix.to_i)
      parent_hi = parent_lo + parent_size - 1

      occupied = (fixed + reserved).map do |item|
        normalize_network(item, bits)
      end
      occupied.each do |lo, hi|
        if lo < parent_lo || hi > parent_hi
          raise ArgumentError, "fixed or reserved network lies outside the parent network"
        end
      end
      occupied = merge_intervals(occupied.sort)

      reqs = normalize_requests(requests)
      reqs.each do |req|
        if req[:prefix] < 0 || req[:prefix] > bits
          raise ArgumentError, "request prefix #{req[:prefix]} out of range 0..#{bits}"
        end
      end
      block_sizes = reqs.map { |req| 1 << (bits - req[:prefix]) }

      initial_free = subtract_intervals([[parent_lo, parent_hi]], occupied)
      initial_count = initial_free.inject(0) { |sum, (lo, hi)| sum + cidr_count(lo, hi) }

      remaining_size = parent_size -
                       occupied.inject(0) { |sum, (lo, hi)| sum + hi - lo + 1 } -
                       block_sizes.inject(0, :+)
      # The free space always totals remaining_size addresses, and any
      # set of CIDR blocks covering N addresses needs at least
      # popcount(N) blocks, so no layout can do better than this.
      min_possible = remaining_size.to_s(2).count("1")

      from_int = lambda do |int, prefix|
        if bits == 32
          IPAddress::IPv4.parse_u32(int, prefix)
        else
          IPAddress::IPv6.parse_u128(int, prefix)
        end
      end

      build_result = lambda do |placement|
        subnets = placement_subnets(placement, reqs, from_int)
        taken = occupied + placement.each_with_index.map do |x, i|
          [x, x + block_sizes[i] - 1]
        end
        free_intervals = subtract_intervals([[parent_lo, parent_hi]],
                                            merge_intervals(taken.sort))
        free_nets = free_intervals.flat_map { |lo, hi| cidr_cover(lo, hi) }.map do |start, size|
          from_int.call(start, bits + 1 - size.bit_length)
        end
        Result.new(subnets, free_nets, reqs)
      end

      best = nil
      best_count = nil
      budget_left = budget
      placement = []

      spend = lambda do
        unless budget_left.nil?
          budget_left -= 1
          raise BudgetExceeded if budget_left < 0
        end
      end

      search = lambda do |idx, intervals, count|
        spend.call
        if idx == reqs.size
          if best_count.nil? || count < best_count
            best = placement.dup
            best_count = count
            throw :optimal if count <= min_possible
          end
          next
        end
        # Each remaining request can lower the free block count by at
        # most one, so this branch cannot improve on the best layout
        # already known.
        if best_count && count - (reqs.size - idx) >= best_count
          next
        end
        size = block_sizes[idx]
        intervals.each_with_index do |(lo, hi), i|
          next if hi - lo + 1 < size
          interval_cost = cidr_count(lo, hi)
          last = hi - size + 1
          x = lo + ((-lo) & (size - 1))
          while x <= last
            # Every candidate placement counts against the budget, so
            # that even a single huge free interval cannot keep the
            # search running past it.
            spend.call
            new_count = count - interval_cost
            new_count += cidr_count(lo, x - 1) if x > lo
            new_count += cidr_count(x + size, hi) if x + size <= hi
            # Skip candidates that cannot improve on the best layout
            # already known, without paying for a recursive call.
            if best_count.nil? || new_count - (reqs.size - idx - 1) < best_count
              new_intervals = intervals[0...i]
              new_intervals += [[lo, x - 1]] if x > lo
              new_intervals += [[x + size, hi]] if x + size <= hi
              new_intervals += intervals[(i + 1)..-1]
              placement[idx] = x
              search.call(idx + 1, new_intervals, new_count)
            end
            x += size
          end
        end
      end

      begin
        catch(:optimal) do
          search.call(0, initial_free, initial_count)
        end
      rescue BudgetExceeded
        raise BudgetExceeded.new(nil, best && build_result.call(best))
      end

      if best.nil?
        raise Infeasible, "no layout can satisfy all #{reqs.size} requests inside the parent network"
      end
      build_result.call(best)
    end

    #
    # Normalizes the request list into an array of
    # {prefix:, name:} hashes. Accepts Integers, hashes with
    # +:prefix+/+:name+ keys, or a single hash of +name => prefix+.
    #
    def self.normalize_requests(requests) # :nodoc:
      if requests.is_a?(Hash)
        requests = requests.map { |name, prefix| {name: name, prefix: prefix} }
      end
      requests.map do |req|
        case req
        when Integer
          {prefix: req, name: nil}
        when Hash
          prefix = req[:prefix]
          unless prefix.is_a?(Integer)
            raise ArgumentError, "request prefix must be an Integer: #{req.inspect}"
          end
          {prefix: prefix, name: req[:name]}
        else
          raise ArgumentError, "invalid request: #{req.inspect}"
        end
      end
    end

    #
    # Normalizes a fixed/reserved entry into a [lo, hi] integer
    # interval, checking that the address family matches the parent.
    #
    def self.normalize_network(item, bits) # :nodoc:
      item = IPAddress.parse(item) if item.is_a?(String)
      case bits
      when 32
        unless item.is_a?(IPAddress::IPv4)
          raise ArgumentError, "expected an IPv4 network: #{item.inspect}"
        end
        [item.network_u32, item.broadcast_u32]
      else
        unless item.is_a?(IPAddress::IPv6)
          raise ArgumentError, "expected an IPv6 network: #{item.inspect}"
        end
        [item.network_u128, item.broadcast_u128]
      end
    end

    #
    # Merges a sorted list of [lo, hi] intervals, joining overlapping
    # or adjacent ones.
    #
    def self.merge_intervals(sorted) # :nodoc:
      sorted.each_with_object([]) do |(lo, hi), merged|
        if merged.empty? || lo > merged[-1][1] + 1
          merged << [lo, hi]
        elsif hi > merged[-1][1]
          merged[-1][1] = hi
        end
      end
    end

    #
    # Removes the +blocks+ intervals from the +intervals+ list.
    #
    def self.subtract_intervals(intervals, blocks) # :nodoc:
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

    #
    # The number of CIDR blocks in the minimal decomposition of the
    # [lo, hi] interval.
    #
    def self.cidr_count(lo, hi) # :nodoc:
      count = 0
      while lo <= hi
        lo += largest_block(lo, hi - lo + 1)
        count += 1
      end
      count
    end

    #
    # The minimal CIDR decomposition of the [lo, hi] interval, as a
    # list of [start, size] pairs.
    #
    def self.cidr_cover(lo, hi) # :nodoc:
      blocks = []
      while lo <= hi
        size = largest_block(lo, hi - lo + 1)
        blocks << [lo, size]
        lo += size
      end
      blocks
    end

    #
    # The largest aligned CIDR block starting at +start+ that fits in
    # +span+ addresses.
    #
    def self.largest_block(start, span) # :nodoc:
      align = start & -start
      size = 1 << (span.bit_length - 1)
      if align == 0 || align > size
        size
      else
        align
      end
    end

    #
    # Builds the subnet objects for a placement, in request order.
    #
    def self.placement_subnets(placement, reqs, from_int) # :nodoc:
      placement.each_with_index.map do |x, i|
        from_int.call(x, reqs[i][:prefix])
      end
    end

  end # module Planner
end # module IPAddress
