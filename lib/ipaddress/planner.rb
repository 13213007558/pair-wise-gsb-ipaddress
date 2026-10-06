# frozen_string_literal: true

require 'set'

module IPAddress
  PlanResult = Struct.new(
    :status, :feasible, :optimal, :complete,
    :allocations, :partial_allocations, :enabled_pools,
    :remaining_fragments, :remaining_addresses,
    :unallocated_requests, :blockers,
    :nodes_visited, :budget, :search_exhausted,
    keyword_init: true
  ) do
    def feasible?
      feasible
    end

    def optimal?
      optimal
    end

    def complete?
      complete
    end

    def to_h
      members.each_with_object({}) { |key, hash| hash[key] = self[key] }
    end
  end

  module Planner
    Block = Struct.new(:start, :finish, :kind, :reference, keyword_init: true) do
      def size
        finish - start + 1
      end

      def overlaps?(other)
        start <= other.finish && other.start <= finish
      end
    end

    Pool = Struct.new(:id, :index, :family, :start, :finish, :source, keyword_init: true)

    Request = Struct.new(
      :id, :index, :family, :min_prefix, :max_prefix, :prefixes,
      :alignment, :pool_ids, :required_start, keyword_init: true
    )

    Candidate = Struct.new(
      :request_index, :pool_index, :start, :finish, :prefix,
      :family, :gap, :blockers_for_window, keyword_init: true
    ) do
      def size
        finish - start + 1
      end

      def subnet
        family == 4 ? IPv4.parse_u32(start, prefix) : IPv6.parse_u128(start, prefix)
      end

      def overlaps?(other)
        start <= other.finish && other.start <= finish
      end
    end

    class SearchBudget
      attr_reader :nodes

      def initialize(nodes, deadline)
        @nodes = nodes
        @remaining = nodes
        @deadline = deadline
      end

      def self.deadline(seconds)
        return nil if seconds.nil?
        if Process.respond_to?(:clock_gettime)
          Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
        else
          Time.now.to_f + seconds
        end
      end

      def tick!
        @remaining -= 1
        remaining?
      end

      def remaining?
        @remaining.positive? && (@deadline.nil? || current_time < @deadline)
      end

      def used
        nodes - @remaining
      end

      private

      def current_time
        if Process.respond_to?(:clock_gettime)
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        else
          Time.now.to_f
        end
      end
    end

    EXHAUSTIVE_POSITIONS = 1024

    module_function

    def plan(options)
      Builder.new(options).plan
    end

    class Builder
      DEFAULT_BUDGET = 10_000

      def initialize(options)
        @options = options || {}
        nodes = Integer(@options.fetch(:budget, @options.fetch(:node_budget, DEFAULT_BUDGET)))
        raise ArgumentError, "budget must be positive" if nodes <= 0
        seconds = @options.key?(:time_budget) ? Float(@options[:time_budget]) : nil
        deadline = SearchBudget.deadline(seconds)
        @budget = SearchBudget.new(nodes, deadline)
        @candidate_complete = true
      end

      def plan
        normalize!
        infer_request_families!
        @static_candidates = build_static_candidates

        static = static_blockers
        return infeasible_result(static, complete: true) if static.any?
        return optimal_empty if @requests.empty?

        feasible = feasible_solution
        unless feasible
          return infeasible_result(collective_blockers, complete: @budget.remaining? && @candidate_complete)
        end

        maximum_count = feasible[:enabled_pool_ids].size
        best = feasible
        best_search_exhausted = false

        (1..maximum_count).each do |count|
          break unless @budget.remaining?
          found_at_count = false

          pool_combinations(count).each do |pool_indices|
            break unless @budget.remaining?
            result = depth_first_search(pool_indices)
            next unless result

            found_at_count = true
            best = result
            best_search_exhausted = false
          end

          if found_at_count
            best_search_exhausted = @budget.remaining? && @candidate_complete
            break
          end
        end

        if best
          status = best_search_exhausted ? :optimal : :best_effort
          result_from_solution(best, status: status, complete: best_search_exhausted)
        elsif @budget.remaining? && @candidate_complete
          infeasible_result(collective_blockers, complete: true)
        else
          infeasible_result(collective_blockers, complete: false)
        end
      end

      private

      def normalize!
        @pools = Array(@options[:pools]).each_with_index.map { |pool, index| normalize_pool(pool, index) }
        raise ArgumentError, "at least one address pool is required" if @pools.empty?
        pool_ids = @pools.map(&:id)
        raise ArgumentError, "pool ids must be unique" if pool_ids.uniq.size != pool_ids.size
        @pool_by_id = @pools.each_with_object({}) { |pool, hash| hash[pool.id] = pool }

        @blocked = normalize_blocks(@options[:reserved], :reserved) +
                   normalize_blocks(@options[:forbidden], :forbidden) +
                   normalize_blocks(@options[:banned], :forbidden) +
                   normalize_blocks(@options[:prohibited], :forbidden) +
                   normalize_blocks(@options[:existing], :existing) +
                   normalize_blocks(@options[:allocations], :existing)
        @requests = Array(@options[:requests]).each_with_index.map { |request, index| normalize_request(request, index) }
        request_ids = @requests.map(&:id)
        raise ArgumentError, "request ids must be unique" if request_ids.uniq.size != request_ids.size
      end

      def normalize_pool(pool, index)
        value, options = if pool.is_a?(Hash)
          [pool[:cidr] || pool[:network] || pool[:range] || pool, pool]
        else
          [pool, {}]
        end
        family, start, finish, source = range_from(value)
        id = options.key?(:id) ? options[:id] : (options.key?(:name) ? options[:name] : index)
        Pool.new(
          id: id, index: index, family: family,
          start: start, finish: finish, source: source
        )
      end

      def normalize_request(request, index)
        min_prefix = prefix_value(request, :min_prefix, :prefix_min, :min)
        max_prefix = prefix_value(request, :max_prefix, :prefix_max, :max)
        prefixes = Array(request[:prefixes] || request[:prefix_lengths]).map { |value| Integer(value) }
        prefix = request.key?(:prefix) ? Integer(request[:prefix]) : nil
        if prefix
          min_prefix ||= prefix
          max_prefix ||= prefix
          prefixes |= [prefix]
        end

        alignment = request[:align] || request[:alignment] || 1
        alignment = Integer(alignment)
        raise ArgumentError, "alignment must be a positive power of two" unless alignment.positive? && (alignment & (alignment - 1)).zero?

        family = request[:family] && request[:family].to_i
        pool_ids = request[:pools] || request[:pool_ids] || request[:candidate_pools]
        pool_ids = Array(pool_ids).map(&method(:pool_identifier)) unless pool_ids.nil?
        required = required_start_from(request[:cidr] || request[:required_cidr] || request[:start])

        Request.new(
          id: request.key?(:id) ? request[:id] : index,
          index: index, family: family,
          min_prefix: min_prefix, max_prefix: max_prefix,
          prefixes: prefixes, alignment: alignment,
          pool_ids: pool_ids, required_start: required
        )
      end

      def normalize_blocks(values, kind)
        Array(values).map { |value| block_from(value, kind) }
      end

      def block_from(value, kind, reference = nil)
        family, start, finish, source = range_from(value)
        Block.new(start: start, finish: finish, kind: kind, reference: reference || source)
      end

      def infer_request_families!
        @requests.each do |request|
          pools = allowed_pools(request)
          families = pools.map(&:family).uniq
          next unless request.family.nil?
          raise ArgumentError, "request #{request.id.inspect} must specify family when no candidate pools exist" if families.empty?
          raise ArgumentError, "request #{request.id.inspect} must specify :family across IPv4 and IPv6 pools" if families.size > 1
          request.family = families.first
        end
        @eligible_pools = @pools
      end

      def build_static_candidates
        @requests.each_with_object([]).with_index do |(request, list), _index|
          allowed_pools(request).select { |pool| pool.family == request.family }.each do |pool|
            free_gaps(pool).each do |gap|
              prefix_range(request, pool).each do |prefix|
                candidates_in_gap(request, pool, gap, prefix).each do |candidate|
                  list << candidate
                end
              end
            end
          end
        end.group_by(&:request_index)
      end

      def static_blockers
        @requests.each_with_object([]) do |request, blockers|
          candidates = @static_candidates[request.index] || []
          next if candidates.any?

          request_blockers = alignment_blockers(request)
          reason = request_blockers.any? { |blocker| blocker[:reason] == :alignment } ? :alignment : :insufficient_free_space
          blockers << {
            request_id: request.id,
            reason: request_blockers.empty? ? :no_candidate_pool : reason,
            total_available_addresses: available_addresses(request),
            blockers: request_blockers
          }
        end
      end

      def feasible_solution
        depth_first_search(@pools.map(&:index), greedy: true)
      end

      def pool_combinations(count)
        @pools.combination(count).lazy.map { |pools| pools.map(&:index) }
      end

      def depth_first_search(pool_indices, greedy: false)
        initial_gaps = pool_indices.each_with_object({}) do |pool_index, gaps|
          gaps[pool_index] = free_gaps(@pools[pool_index])
        end
        search_requests = ordered_request_indices(pool_indices)
        best_partial = { placements: [], depth: 0 } if @options[:track_partial] != false
        best_solution = nil

        search = lambda do |depth, placements, gaps|
          return nil unless @budget.tick!
          if best_partial && depth > best_partial[:depth]
            best_partial = { placements: placements.dup, depth: depth }
          end
          if depth == search_requests.size
            solution = score_solution(placements, pool_indices, gaps)
            if best_solution.nil? || better_score?(solution[:score], best_solution[:score])
              best_solution = solution
            end
            return best_solution
          end

          request_index = search_requests[depth]
          candidates = dynamic_candidates(request_index, pool_indices, gaps)
          return nil if candidates.empty?
          lower_bound = optimistic_fragment_count(gaps, candidates, search_requests[depth..])
          return nil if prune_by_bound?(lower_bound, placements, pool_indices, depth)

          candidates.each do |candidate|
            next unless candidate_fits?(gaps, candidate)
            updated = place_candidate(gaps, candidate)
            search.call(depth + 1, placements + [candidate], updated)
            return best_solution if greedy && best_solution
            return nil unless @budget.remaining?
          end
          best_solution
        end

        solution = search.call(0, [], initial_gaps)
        unless solution
          @best_partial = best_partial
        end
        solution
      end

      def collective_blockers
        @requests.each_with_object([]) do |request, blockers|
          next if @static_candidates[request.index] && @static_candidates[request.index].any?
          blockers << {
            request_id: request.id,
            reason: :no_candidate_pool,
            total_available_addresses: available_addresses(request),
            blockers: []
          }
        end
      end

      def result_from_solution(solution, status:, complete:)
        allocations = solution[:placements].sort_by(&:request_index).map do |candidate|
          {
            request_id: @requests[candidate.request_index].id,
            pool_id: @pools[candidate.pool_index].id,
            cidr: candidate.subnet.to_string,
            prefix: candidate.prefix,
            subnet: candidate.subnet
          }
        end
        PlanResult.new(
          status: status, feasible: true, optimal: status == :optimal,
          complete: complete, allocations: allocations,
          partial_allocations: allocations, enabled_pools: solution[:enabled_pool_ids],
          remaining_fragments: solution[:fragments],
          remaining_addresses: solution[:remaining_addresses],
          unallocated_requests: [], blockers: [],
          nodes_visited: @budget.used, budget: @budget.nodes,
          search_exhausted: complete
        )
      end

      def infeasible_result(blockers, complete:)
        status = complete ? :infeasible : :budget_exceeded
        partial = (@best_partial && @best_partial[:placements]) || []
        partial_allocations = partial.map do |candidate|
          {
            request_id: @requests[candidate.request_index].id,
            pool_id: @pools[candidate.pool_index].id,
            cidr: candidate.subnet.to_string,
            prefix: candidate.prefix,
            subnet: candidate.subnet
          }
        end
        allocated = partial_allocations.map { |item| item[:request_id] }
        PlanResult.new(
          status: status, feasible: false, optimal: false,
          complete: complete, allocations: [],
          partial_allocations: partial_allocations,
          enabled_pools: partial.map { |candidate| @pools[candidate.pool_index].id }.uniq,
          remaining_fragments: nil, remaining_addresses: nil,
          unallocated_requests: @requests.map(&:id) - allocated,
          blockers: blockers, nodes_visited: @budget.used, budget: @budget.nodes,
          search_exhausted: complete
        )
      end

      def optimal_empty
        PlanResult.new(
          status: :optimal, feasible: true, optimal: true, complete: true,
          allocations: [], partial_allocations: [], enabled_pools: [],
          remaining_fragments: 0, remaining_addresses: 0,
          unallocated_requests: [], blockers: [],
          nodes_visited: 0, budget: @budget.nodes, search_exhausted: true
        )
      end

      def prefix_value(request, *keys)
        key = keys.find { |candidate| request.key?(candidate) }
        key && Integer(request[key])
      end

      def pool_identifier(value)
        value.is_a?(Pool) ? value.id : value
      end

      def required_start_from(value)
        return nil if value.nil?
        return value if value.is_a?(Integer)
        return address_to_i(value, nil) unless value.is_a?(String)
        block = range_from(value)
        block[1]
      end

      def range_from(value)
        case value
        when Hash
          cidr = value[:cidr] || value[:network]
          return range_from(cidr) if cidr
          return range_from(value[:range]) if value[:range]
          family = value[:family]&.to_i
          start = address_to_i(value[:start] || value[:from], family)
          finish = address_to_i(value[:finish] || value[:to] || value[:end], family)
          family ||= family_of_integer(start)
          [family, start, finish, range_source(family, start, finish)]
        when IPv4
          network = value.network
          [4, network.to_i, network.broadcast_u32, network.to_string]
        when IPv6
          network = value.network
          [6, network.to_i, network.broadcast_u128, network.to_string]
        when String
          if value.include?('/')
            subnet = IPAddress.parse(value).network
            family = subnet.is_a?(IPv4) ? 4 : 6
            [family, subnet.to_i, family == 4 ? subnet.broadcast_u32 : subnet.broadcast_u128, subnet.to_string]
          elsif value.include?('..') || value.include?('-')
            left, right = value.split(/\.\.|-/, 2)
            family = left.include?(':') ? 6 : 4
            [family, address_to_i(left, family), address_to_i(right, family), value]
          else
            family = value.include?(':') ? 6 : 4
            address = address_to_i(value, family)
            [family, address, address, value]
          end
        else
          raise ArgumentError, "unsupported address block #{value.inspect}"
        end
      end

      def family_of_integer(value)
        value > 0xffffffff ? 6 : 4
      end

      def address_to_i(value, family)
        return Integer(value) if value.is_a?(Integer)
        return IPAddress.parse(value).to_i if family.nil?
        family == 4 ? IPv4.new(value).to_i : IPv6.new(value).to_i
      end

      def range_source(family, start, finish)
        if family == 4
          "#{IPv4.parse_u32(start)}..#{IPv4.parse_u32(finish)}"
        else
          "#{IPv6.parse_u128(start)}..#{IPv6.parse_u128(finish)}"
        end
      end

      def allowed_pools(request)
        return @pools if request.pool_ids.nil?
        request.pool_ids.map do |id|
          @pool_by_id.fetch(id) { raise ArgumentError, "unknown address pool #{id.inspect}" }
        end
      end

      def free_gaps(pool)
        blocks = @blocked.select do |block|
          block.start <= pool.finish && pool.start <= block.finish
        end.sort_by { |block| [block.start, block.finish] }

        gaps = []
        cursor = pool.start
        blocks.each do |block|
          start = [block.start, pool.start].max
          finish = [block.finish, pool.finish].min
          gaps << [cursor, start - 1] if cursor < start
          cursor = [cursor, finish + 1].max
        end
        gaps << [cursor, pool.finish] if cursor <= pool.finish
        gaps
      end

      def prefix_range(request, pool)
        family_bits = request.family == 4 ? 32 : 128
        minimum = request.min_prefix || pool_prefix(pool)
        maximum = request.max_prefix || family_bits
        unless minimum.is_a?(Integer) && maximum.is_a?(Integer) && minimum >= 0 && maximum <= family_bits && minimum <= maximum
          raise ArgumentError, "invalid prefix range for request #{request.id.inspect}"
        end
        prefixes = request.prefixes.empty? ? (minimum..maximum).to_a : request.prefixes.select { |prefix| prefix >= minimum && prefix <= maximum }
        prefixes.uniq.sort.reverse
      end

      def pool_prefix(pool)
        pool.family == 4 ? 32 - Math.log2(pool.size).to_i : 128 - Math.log2(pool.size).to_i
      end

      def candidates_in_gap(request, pool, gap, prefix)
        gap_start, gap_finish = gap
        block_size = 1 << (family_bits(request.family) - prefix)
        alignment = [request.alignment, block_size].max
        positions = aligned_positions(gap_start, gap_finish, alignment, block_size, request.required_start)
        enumerable_positions = if positions.size > EXHAUSTIVE_POSITIONS && request.alignment <= block_size
          boundary_positions(positions)
        else
          positions
        end

        enumerable_positions.map do |start|
          Candidate.new(
            request_index: request.index,
            pool_index: pool.index,
            start: start,
            finish: start + block_size - 1,
            prefix: prefix,
            family: request.family,
            gap: [gap_start, gap_finish]
          )
        end
      end

      def aligned_positions(start, finish, alignment, block_size, required_start)
        if required_start
          return [] unless required_start.modulo(alignment).zero? && required_start >= start && required_start + block_size - 1 <= finish
          return [required_start]
        end

        first = (start + alignment - 1) / alignment * alignment
        last = ((finish - block_size + 1) / alignment) * alignment
        return [] if first > last
        positions = []
        cursor = first
        while cursor <= last
          positions << cursor
          cursor += alignment
        end
        positions
      end

      def boundary_positions(positions)
        [positions.first, positions.last].uniq
      end

      def family_bits(family)
        family == 4 ? 32 : 128
      end

      def available_addresses(request)
        allowed_pools(request).select { |pool| pool.family == request.family }.sum do |pool|
          free_gaps(pool).sum { |start, finish| finish - start + 1 }
        end
      end

      def alignment_blockers(request)
        allowed_pools(request).select { |pool| pool.family == request.family }.flat_map do |pool|
          prefix_range(request, pool).flat_map do |prefix|
            block_size = 1 << (family_bits(request.family) - prefix)
            alignment = [request.alignment, block_size].max
            free_gaps(pool).map do |gap_start, gap_finish|
              build_alignment_blocker(request, pool, gap_start, gap_finish, prefix, block_size, alignment)
            end
          end
        end.compact
      end

      def build_alignment_blocker(request, pool, gap_start, gap_finish, prefix, block_size, alignment)
        aligned_start = (gap_start + alignment - 1) / alignment * alignment
        natural_window_finish = aligned_start + block_size - 1
        gap_size = gap_finish - gap_start + 1
        candidate_end = gap_finish - block_size + 1
        candidate_window_finish = candidate_end + block_size - 1
        return nil if gap_size >= block_size && natural_window_finish <= gap_finish && request.required_start.nil?

        window_start = [aligned_start - block_size + 1, pool.start].max
        window_finish = [candidate_window_finish, pool.finish].min
        blockers = @blocked.select do |block|
          clipped_start = [block.start, pool.start].max
          clipped_finish = [block.finish, pool.finish].min
          clipped_start <= window_finish && window_start <= clipped_finish
        end.map do |block|
          {
            kind: block.kind,
            cidr_or_range: block.reference,
            start: block.start,
            finish: block.finish,
            start_address: format_integer(request.family, block.start),
            finish_address: format_integer(request.family, block.finish)
          }
        end
        reason = blockers.empty? ? (gap_size < block_size ? :insufficient_free_space : :insufficient_pool_space) : :alignment
        {
          pool_id: pool.id,
          prefix: prefix,
          size: block_size,
          alignment: alignment,
          gap: {
            start: gap_start,
            finish: gap_finish,
            start_address: format_integer(request.family, gap_start),
            finish_address: format_integer(request.family, gap_finish)
          },
          aligned_start: aligned_start,
          aligned_start_address: format_integer(request.family, aligned_start),
          window: {
            start: window_start,
            finish: window_finish,
            start_address: format_integer(request.family, window_start),
            finish_address: format_integer(request.family, window_finish)
          },
          reason: reason,
          blocking_intervals: blockers
        }
      end

      def ordered_request_indices(pool_indices)
        pool_set = pool_indices.to_set
        @requests.sort_by do |request|
          count = (@static_candidates[request.index] || []).count { |candidate| pool_set.include?(candidate.pool_index) }
          largest = 1 << (family_bits(request.family) - (request.min_prefix || 0))
          [count, -largest, request.index]
        end.map(&:index)
      end

      def dynamic_candidates(request_index, pool_indices, gaps)
        (@static_candidates[request_index] || []).select do |candidate|
          pool_indices.include?(candidate.pool_index) && candidate_fits?(gaps, candidate)
        end.sort_by do |candidate|
          [-candidate.prefix, candidate.pool_index, candidate.start, candidate.request_index]
        end
      end

      def candidate_fits?(gaps, candidate)
        gaps[candidate.pool_index].any? do |start, finish|
          start <= candidate.start && candidate.finish <= finish
        end
      end

      def place_candidate(gaps, candidate)
        updated = gaps.transform_values(&:dup)
        updated[candidate.pool_index] = updated[candidate.pool_index].flat_map do |start, finish|
          next [[start, finish]] unless start <= candidate.start && candidate.finish <= finish
          pieces = []
          pieces << [start, candidate.start - 1] if start < candidate.start
          pieces << [candidate.finish + 1, finish] if candidate.finish < finish
          pieces
        end
        updated
      end

      def optimistic_fragment_count(gaps, _candidates, _remaining_requests)
        gaps.values.sum { |pool_gaps| pool_gaps.count { |start, finish| start <= finish } }
      end

      def prune_by_bound?(_lower_bound, _placements, _pool_indices, _depth)
        false
      end

      def score_solution(placements, pool_indices, _gaps)
        enabled_indices = placements.map(&:pool_index).uniq.sort
        pool_ids = enabled_indices.map { |index| @pools[index].id }
        occupied = placements.map(&method(:candidate_block)) + @blocked
        free = enabled_indices.flat_map do |pool_index|
          pool = @pools[pool_index]
          subtract_union([[pool.start, pool.finish]], occupied.select do |block|
            block[0] <= pool.finish && pool.start <= block[1]
          end)
        end
        allocation_key = placements.sort_by(&:request_index).map do |candidate|
          [candidate.pool_index, candidate.start, -candidate.size, candidate.prefix]
        end
        {
          placements: placements,
          enabled_pool_ids: pool_ids,
          fragments: free.size,
          remaining_addresses: free.sum { |start, finish| finish - start + 1 },
          score: [free.size, enabled_indices, allocation_key]
        }
      end

      def candidate_block(candidate)
        Block.new(start: candidate.start, finish: candidate.finish, kind: :allocation, reference: candidate.subnet.to_string)
      end

      def better_score?(left, right)
        lexicographic_less?(left, right)
      end

      def lexicographic_less?(left, right)
        left.each_with_index do |value, index|
          other = right[index]
          next if value == other
          if value.is_a?(Array)
            return value_less?(value, other)
          else
            return value < other
          end
        end
        false
      end

      def value_less?(left, right)
        return left < right unless left.is_a?(Array)
        left.each_with_index do |value, index|
          other = right[index]
          next if value == other
          return value_less?(value, other)
        end
        false
      end

      def subtract_union(union, occupied)
        gaps = []
        ordered = occupied.sort_by { |block| block.is_a?(Block) ? block.start : block[0] }
        union.each do |start, finish|
          cursor = start
          ordered.each do |block|
            block_start, block_finish = block.is_a?(Block) ? [block.start, block.finish] : [block[0], block[1]]
            next if block_finish < cursor || block_start > finish || block_finish < start
            clipped_start = [block_start, start].max
            gaps << [cursor, clipped_start - 1] if cursor < clipped_start
            cursor = [cursor, [block_finish, finish].min + 1].max
          end
          gaps << [cursor, finish] if cursor <= finish
        end
        gaps
      end

      def format_integer(_family, value)
        case _family
        when 4 then IPv4.parse_u32(value).to_s
        when 6 then IPv6.parse_u128(value).to_s
        else value
        end
      end
    end
  end

  private_constant :Planner
end
