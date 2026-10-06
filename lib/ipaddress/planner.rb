#
# = IPAddress::Planner
#
# Plans CIDR allocations across a set of address pools. Planning is
# done purely in memory: no network device is ever touched.
#
# Given a set of address pools, the space already taken (reserved
# ranges, existing allocations and forbidden ranges) and a list of
# tenant requests, the planner searches for a valid assignment of
# CIDR blocks. The objectives, in decreasing priority, are:
#
# 1. satisfy every request
# 2. enable as few pools as possible
# 3. leave as few free fragments as possible
#
# Remaining ties are broken with a deterministic ordering, so
# running the planner twice on the same input always yields the
# same plan.
#
#   result = IPAddress.plan(
#     pools:       ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
#     allocations: ["10.1.0.0/16"],
#     reserved:    ["10.2.0.0/16"],
#     forbidden:   ["192.168.0.0/24"],
#     requests:    [
#       {name: "tenant-a", prefix: 20..24, align: 20},
#       {name: "tenant-b", prefix: 24, pools: ["192.168.0.0/16"]},
#     ])
#
#   result.status       #=> :optimal
#   result.assignments  #=> {"tenant-a" => "10.4.0.0/24", ...}
#
# When the search space is too large for the configured budget the
# planner returns the best plan found so far with a status that
# makes clear optimality (or feasibility) has not been proven; it
# never reports a problem as infeasible unless the whole search
# space has been exhausted.
#
module IPAddress

  #
  # Plans CIDR allocations for a set of requests over the given
  # pools. See IPAddress::Planner for the available options.
  #
  def IPAddress::plan(pools:, requests:, reserved: [], allocations: [],
                      forbidden: [], max_nodes: Planner::DEFAULT_MAX_NODES)
    Planner.new(pools: pools, requests: requests, reserved: reserved,
                allocations: allocations, forbidden: forbidden,
                max_nodes: max_nodes).plan
  end

  class Planner

    DEFAULT_MAX_NODES = 50_000

    #
    # A single tenant request.
    #
    # * +name+   - identifier used as key in the result
    # * +prefix+ - an Integer or a Range of acceptable prefix lengths
    # * +pools+  - nil (every pool) or an Array of pool CIDRs/indices
    #              restricting the candidate pools
    # * +align+  - optional prefix length whose boundary the allocated
    #              block must be aligned to
    #
    class Request
      attr_reader :name, :prefix_range, :pools, :align

      def initialize(name:, prefix:, pools: nil, align: nil)
        @name = name
        @prefix_range =
          case prefix
          when Range then prefix
          when Integer then prefix..prefix
          else
            raise ArgumentError, "invalid prefix #{prefix.inspect}"
          end
        @pools = pools
        @align = align
      end

      def min_prefix
        @prefix_range.begin
      end

      def max_prefix
        @prefix_range.end
      end
    end

    #
    # The outcome of a planning run.
    #
    # +status+ is one of:
    #
    # * +:optimal+    - every request placed, search space exhausted
    # * +:feasible+   - every request placed, but the budget ran out
    #                   before optimality could be proven
    # * +:infeasible+ - proven impossible to satisfy every request
    # * +:unknown+    - budget exhausted before a complete plan was
    #                   found; feasibility is undetermined
    #
    class Result
      attr_reader :status, :assignments, :unplaced, :pools_used,
                  :fragments, :nodes, :diagnostics

      def initialize(status:, assignments:, unplaced:, pools_used:,
                     fragments:, nodes:, diagnostics:)
        @status = status
        @assignments = assignments
        @unplaced = unplaced
        @pools_used = pools_used
        @fragments = fragments
        @nodes = nodes
        @diagnostics = diagnostics
      end

      def optimal?
        @status == :optimal
      end

      # True when the status has been proven by an exhaustive search.
      def proven?
        optimal? || @status == :infeasible
      end

      # True when every request has been placed.
      def complete?
        @unplaced.empty?
      end
    end

    Occupied = Struct.new(:first, :last, :kind, :cidr, :owner)
    Candidate = Struct.new(:pool, :prefix, :start, :size)

    class Pool
      attr_reader :index, :cidr, :first, :last, :bits, :occupied
      attr_accessor :free

      def initialize(index, ip)
        @index = index
        @bits = ip.ipv4? ? 32 : 128
        network = ip.network
        @first = ip.ipv4? ? network.network_u32 : network.network_u128
        @last = @first + ip.size - 1
        @cidr = network.to_string
        @occupied = []
        @free = [[@first, @last]]
      end

      def address_string(num, prefix)
        if @bits == 32
          IPAddress::IPv4.parse_u32(num, prefix).to_string
        else
          IPAddress::IPv6.parse_u128(num, prefix).to_string
        end
      end
    end

    def initialize(pools:, requests:, reserved: [], allocations: [],
                   forbidden: [], max_nodes: DEFAULT_MAX_NODES)
      raise ArgumentError, "pools must not be empty" if pools.empty?
      @max_nodes = max_nodes
      @pools = pools.each_with_index.map { |p, i| Pool.new(i, parse_ip(p)) }
      check_pools_disjoint!
      @requests = requests.each_with_index.map do |r, i|
        normalize_request(r, i)
      end
      add_occupied(reserved, :reserved)
      add_occupied(allocations, :allocation)
      add_occupied(forbidden, :forbidden)
      @pools.each { |pool| recompute_free(pool) }
      @request_pools = @requests.map { |r| resolve_request_pools(r) }
      @requests.each_with_index do |req, i|
        if @request_pools[i].none? { |pi| req.min_prefix <= @pools[pi].bits }
          raise ArgumentError,
                "no pool can host prefix range of request #{req.name}"
        end
      end
    end

    def plan
      n = @requests.size
      @assignment = Array.new(n)
      @pool_used = Array.new(@pools.size, false)
      @pools_used_count = 0
      @fragments = 0
      @satisfied = 0
      @nodes = 0
      @budget_exceeded = false
      @best_key = nil
      @best_assignment = nil
      @best_satisfied = nil
      @best_pools = nil
      @best_fragments = nil

      search(0, n)

      build_result
    end

    private

    def parse_ip(obj)
      if obj.is_a?(IPAddress::IPv4) || obj.is_a?(IPAddress::IPv6)
        obj
      else
        IPAddress.parse(obj)
      end
    end

    def check_pools_disjoint!
      sorted = @pools.sort_by { |p| [p.bits, p.first] }
      sorted.each_cons(2) do |a, b|
        if a.bits == b.bits && b.first <= a.last
          raise ArgumentError, "pools overlap: #{a.cidr} and #{b.cidr}"
        end
      end
    end

    def normalize_request(raw, index)
      req =
        case raw
        when Request then raw
        when Hash
          h = {}
          raw.each { |k, v| h[k.to_sym] = v }
          Request.new(name: h[:name] || "request-#{index}",
                      prefix: h[:prefix],
                      pools: h[:pools],
                      align: h[:align])
        else
          raise ArgumentError, "invalid request #{raw.inspect}"
        end
      if req.min_prefix > req.max_prefix
        raise ArgumentError, "invalid prefix range for #{req.name}"
      end
      req
    end

    def add_occupied(list, kind)
      list.each do |entry|
        ip = parse_ip(entry)
        network = ip.network
        first = ip.ipv4? ? network.network_u32 : network.network_u128
        last = first + ip.size - 1
        cidr = network.to_string
        bits = ip.ipv4? ? 32 : 128
        @pools.each do |pool|
          next unless pool.bits == bits
          lo = [first, pool.first].max
          hi = [last, pool.last].min
          next if lo > hi
          pool.occupied << Occupied.new(lo, hi, kind, cidr, nil)
        end
      end
    end

    def recompute_free(pool)
      taken = pool.occupied.map { |o| [o.first, o.last] }.sort_by(&:first)
      free = []
      cursor = pool.first
      taken.each do |lo, hi|
        free << [cursor, lo - 1] if lo > cursor
        cursor = hi + 1 if hi + 1 > cursor
      end
      free << [cursor, pool.last] if cursor <= pool.last
      pool.free = free
    end

    def resolve_request_pools(req)
      return (0...@pools.size).to_a if req.pools.nil?
      req.pools.map do |ref|
        case ref
        when Integer
          if ref < 0 || ref >= @pools.size
            raise ArgumentError, "unknown pool index #{ref} for #{req.name}"
          end
          ref
        else
          cidr = parse_ip(ref).network.to_string
          index = @pools.index { |p| p.cidr == cidr }
          raise ArgumentError, "unknown pool #{ref} for #{req.name}" if index.nil?
          index
        end
      end.uniq.sort
    end

    #
    # Depth-first branch and bound over the requests, taken in input
    # order. A request is only left unplaced when no candidate block
    # exists, because placing it always dominates skipping it.
    #
    def search(i, n)
      @nodes += 1
      if @nodes > @max_nodes
        @budget_exceeded = true
        return
      end
      if i == n
        record_best
        return
      end
      return if pruned?(i, n)

      placed = false
      each_candidate(i) do |cand|
        @nodes += 1
        if @nodes > @max_nodes
          @budget_exceeded = true
          break
        end
        place(i, cand)
        search(i + 1, n)
        unplace(i, cand)
        placed = true
        break if @budget_exceeded
      end
      search(i + 1, n) unless placed || @budget_exceeded
    end

    def pruned?(i, n)
      return false if @best_key.nil?
      remaining = n - i
      potential = @satisfied + remaining
      return true if potential < @best_satisfied
      if potential == @best_satisfied
        return true if @pools_used_count > @best_pools
        if @pools_used_count == @best_pools
          frag_lb = @fragments - remaining
          frag_lb = 0 if frag_lb < 0
          return true if frag_lb > @best_fragments
        end
      end
      false
    end

    #
    # Yields candidate blocks for request +i+, most promising first:
    # pools already in use before fresh pools, smaller blocks before
    # larger ones, lower addresses before higher ones. The ordering
    # depends only on the search state, so it is deterministic.
    #
    def each_candidate(i)
      req = @requests[i]
      order = @request_pools[i].sort_by { |pi| @pool_used[pi] ? [0, pi] : [1, pi] }
      order.each do |pi|
        pool = @pools[pi]
        req.max_prefix.downto(req.min_prefix) do |pfx|
          next if pfx > pool.bits
          size = 1 << (pool.bits - pfx)
          gran_prefix = req.align && req.align < pfx ? req.align : pfx
          gran = 1 << (pool.bits - gran_prefix)
          # Iterate over a snapshot: placing a candidate rewrites
          # pool.free while we are iterating it.
          pool.free.dup.each do |lo, hi|
            start = (lo + gran - 1) & ~(gran - 1)
            while start + size - 1 <= hi
              yield Candidate.new(pi, pfx, start, size)
              start += gran
            end
          end
        end
      end
    end

    def place(i, cand)
      pool = @pools[cand.pool]
      before = @pool_used[cand.pool] ? pool.free.size : 0
      split_free(pool, cand.start, cand.start + cand.size - 1)
      @pools_used_count += 1 unless @pool_used[cand.pool]
      @pool_used[cand.pool] = true
      @satisfied += 1
      @assignment[i] = cand
      @fragments += pool.free.size - before
    end

    def unplace(i, cand)
      pool = @pools[cand.pool]
      before = pool.free.size
      merge_free(pool, cand.start, cand.start + cand.size - 1)
      @satisfied -= 1
      @assignment[i] = nil
      still_used = @assignment.any? { |a| a && a.pool == cand.pool }
      unless still_used
        @pool_used[cand.pool] = false
        @pools_used_count -= 1
      end
      @fragments += (still_used ? pool.free.size : 0) - before
    end

    def split_free(pool, s, e)
      idx = pool.free.index { |lo, hi| lo <= s && e <= hi }
      lo, hi = pool.free[idx]
      replacement = []
      replacement << [lo, s - 1] if s > lo
      replacement << [e + 1, hi] if e < hi
      pool.free[idx..idx] = replacement
    end

    def merge_free(pool, s, e)
      lo, hi = s, e
      kept = []
      pool.free.each do |a, b|
        if b == lo - 1
          lo = a
        elsif a == hi + 1
          hi = b
        else
          kept << [a, b]
        end
      end
      kept << [lo, hi]
      pool.free = kept.sort_by(&:first)
    end

    #
    # Solutions are compared lexicographically: more requests
    # satisfied, fewer pools used, fewer free fragments, then a
    # deterministic tie-break over the assignment vector.
    #
    def record_best
      key = [-@satisfied, @pools_used_count, @fragments] + tie_vector
      if @best_key.nil? || (key <=> @best_key) < 0
        @best_key = key
        @best_assignment = @assignment.dup
        @best_satisfied = @satisfied
        @best_pools = @pools_used_count
        @best_fragments = @fragments
      end
    end

    def tie_vector
      vector = []
      @assignment.each do |cand|
        if cand
          vector.concat([0, cand.pool, cand.start, -cand.prefix])
        else
          vector.concat([1, 0, 0, 0])
        end
      end
      vector
    end

    def build_result
      diagnostics = build_diagnostics
      if @best_assignment.nil?
        return Result.new(status: :unknown,
                          assignments: {},
                          unplaced: @requests.map(&:name),
                          pools_used: [],
                          fragments: 0,
                          nodes: @nodes,
                          diagnostics: diagnostics)
      end
      complete = @best_satisfied == @requests.size
      status =
        if complete
          @budget_exceeded ? :feasible : :optimal
        else
          @budget_exceeded ? :unknown : :infeasible
        end
      assignments = {}
      unplaced = []
      @requests.each_with_index do |req, i|
        cand = @best_assignment[i]
        if cand
          assignments[req.name] =
            @pools[cand.pool].address_string(cand.start, cand.prefix)
        else
          unplaced << req.name
        end
      end
      pools_used = @pools.select do |pool|
        @best_assignment.any? { |c| c && c.pool == pool.index }
      end.map(&:cidr)
      Result.new(status: status,
                 assignments: assignments,
                 unplaced: unplaced,
                 pools_used: pools_used,
                 fragments: @best_fragments,
                 nodes: @nodes,
                 diagnostics: diagnostics)
    end

    #
    # For every request that could not be placed, explain why: for
    # each candidate pool report the free space and the existing
    # intervals (reserved ranges, allocations, forbidden ranges and
    # other assignments) that block every aligned slot.
    #
    def build_diagnostics
      diag = {}
      @requests.each_with_index do |req, i|
        next if @best_assignment && @best_assignment[i]
        diag[req.name] = request_diagnostic(req, i)
      end
      diag
    end

    def request_diagnostic(req, req_index)
      pools_report = []
      any_fit = false
      any_room = false
      @request_pools[req_index].each do |pi|
        pool = @pools[pi]
        next if req.min_prefix > pool.bits
        pfx = [req.max_prefix, pool.bits].min
        size = 1 << (pool.bits - pfx)
        gran_prefix = req.align && req.align < pfx ? req.align : pfx
        gran = 1 << (pool.bits - gran_prefix)
        occupied = pool.occupied.dup
        (@best_assignment || []).each_with_index do |cand, j|
          next if cand.nil? || cand.pool != pi || j == req_index
          occupied << Occupied.new(cand.start, cand.start + cand.size - 1,
                                   :assigned,
                                   pool.address_string(cand.start, cand.prefix),
                                   @requests[j].name)
        end
        free = free_intervals(pool, occupied)
        total_free = free.inject(0) { |sum, (lo, hi)| sum + hi - lo + 1 }
        any_room = true if total_free >= size
        if free.any? { |lo, hi| aligned_slot_fits?(lo, hi, gran, size) }
          any_fit = true
          next
        end
        pools_report << {
          pool: pool.cidr,
          free_addresses: total_free,
          required_addresses: size,
          blockers: blockers_for(free, occupied),
        }
      end
      reason =
        if any_fit
          :undetermined
        elsif any_room
          :no_aligned_space
        else
          :insufficient_space
        end
      {reason: reason, pools: pools_report}
    end

    def free_intervals(pool, occupied)
      taken = occupied.map { |o| [o.first, o.last] }.sort_by(&:first)
      free = []
      cursor = pool.first
      taken.each do |lo, hi|
        free << [cursor, lo - 1] if lo > cursor
        cursor = hi + 1 if hi + 1 > cursor
      end
      free << [cursor, pool.last] if cursor <= pool.last
      free
    end

    def aligned_slot_fits?(lo, hi, gran, size)
      start = (lo + gran - 1) & ~(gran - 1)
      start + size - 1 <= hi
    end

    #
    # The intervals blocking a free range are the occupied ranges
    # touching its edges; every aligned slot inside the range is
    # either too small or cut off by one of them.
    #
    def blockers_for(free, occupied)
      blockers = []
      if free.empty?
        occupied.each do |entry|
          blocker = {range: entry.cidr, kind: entry.kind}
          blocker[:owner] = entry.owner if entry.owner
          blockers << blocker
        end
        return blockers.sort_by { |b| [b[:kind].to_s, b[:range]] }
      end
      free.each do |lo, hi|
        occupied.each do |entry|
          touches_left = entry.first <= lo - 1 && lo - 1 <= entry.last
          touches_right = entry.first <= hi + 1 && hi + 1 <= entry.last
          next unless touches_left || touches_right
          blocker = {range: entry.cidr, kind: entry.kind}
          blocker[:owner] = entry.owner if entry.owner
          blockers << blocker unless blockers.include?(blocker)
        end
      end
      blockers.sort_by { |b| [b[:kind].to_s, b[:range]] }
    end
  end
end
