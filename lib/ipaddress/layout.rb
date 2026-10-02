module IPAddress
  module Layout
    class Error < StandardError; end
    class Impossible < Error; end
    BudgetExhausted = Class.new(Error)
    NoSolution = Impossible
    SearchBudgetExhausted = BudgetExhausted

    class Result < Array
      attr_reader :parent, :requests, :allocations, :fixed_allocations,
                  :reserved, :remaining

      def initialize(parent, requests, allocations, fixed_allocations,
                     reserved, remaining)
        super(allocations)
        @parent = parent
        @requests = requests
        @allocations = allocations
        @fixed_allocations = fixed_allocations
        @reserved = reserved
        @remaining = remaining
      end

      def available
        remaining
      end

      def subnets
        allocations
      end

      def to_h
        {
          parent: parent,
          requests: requests,
          allocations: allocations,
          fixed_allocations: fixed_allocations,
          reserved: reserved,
          remaining: remaining
        }
      end
    end

    def self.plan(parent, requests, options = {})
      Planner.new(parent, requests, options).plan
    end

    def self.layout(parent, requests, options = {})
      plan(parent, requests, options)
    end

    def self.allocate(parent, requests, options = {})
      plan(parent, requests, options)
    end

    def plan_layout(requests, options = {})
      IPAddress::Layout.plan(self, requests, options)
    end
    alias_method :plan_subnets, :plan_layout
    alias_method :allocate_subnets, :plan_layout
    alias_method :batch_allocate, :plan_layout
    alias_method :allocate_layout, :plan_layout
    alias_method :layout, :plan_layout

    class Planner
      def initialize(parent, requests, options)
        @parent = parent.network
        @requests = Array(requests).dup
        @fixed_allocations = Array(options[:fixed_allocations] || options[:fixed]).dup
        @reserved = Array(options[:reserved] || options[:reservations]).dup
        @budget = options.key?(:search_budget) ? options[:search_budget] : options[:budget]

        @bits = @parent.ipv4? ? 32 : 128
        @request_prefixes = @requests.map { |request| prefix_from_request(request) }
        validate_budget
      end

      def plan
        fixed = normalize_subnets(@fixed_allocations)
        reserved = normalize_subnets(@reserved)
        blocked = (fixed + reserved).map { |subnet| interval(subnet) }.sort

        validate_intervals(blocked)

        free_gaps = maximal_free_gaps(parent_start, parent_size, blocked.uniq)
        request_sizes = @request_prefixes.map { |prefix| 1 << (@bits - prefix) }

        unless can_pack?(free_gaps, request_sizes)
          raise IPAddress::Layout::Impossible,
                "requested subnets cannot fit without overlapping a fixed allocation or reservation"
        end

        selected, remaining_gaps = choose_requests(free_gaps, request_sizes)

        allocations = selected.each_with_index.map do |(start, _, _), index|
          parse_subnet(start, @request_prefixes[index])
        end
        remaining = remaining_gaps.map { |start, size| parse_subnet(start, prefix_for_size(size)) }

        IPAddress::Layout::Result.new(
          @parent,
          @requests,
          allocations,
          fixed,
          reserved,
          remaining
        )
      end

      private

      def validate_budget
        return if @budget.nil?
        unless @budget.is_a?(Integer) && @budget >= 0
          raise ArgumentError, "search_budget must be a non-negative Integer"
        end
      end

      def prefix_from_request(request)
        prefix = case request
                 when Integer
                   request
                 when String
                   request =~ /\A\d+\z/ ? request.to_i : nil
                 else
                   if request.respond_to?(:prefix) && request.class == @parent.class
                     request.prefix.to_i
                   end
                 end

        unless prefix.is_a?(Integer) && prefix >= @parent.prefix.to_i && prefix <= @bits
          raise ArgumentError,
                "request prefix must be between #{@parent.prefix} and #{@bits}: #{request.inspect}"
        end
        prefix
      end

      def normalize_subnets(subnets)
        subnets.map { |subnet| normalize_subnet(subnet) }.sort
      end

      def normalize_subnet(subnet)
        subnet = @parent.class.new(subnet) if subnet.is_a?(String)
        unless subnet.class == @parent.class && @parent.include?(subnet.network)
          raise ArgumentError, "#{subnet.to_string} is not contained in #{@parent.to_string}"
        end
        subnet.network
      rescue ArgumentError => error
        raise error if error.message =~ /not contained/
        raise ArgumentError, "invalid subnet #{subnet.inspect}"
      end

      def validate_intervals(blocked)
        blocked.each_cons(2) do |first, second|
          next if first.first + first.last <= second.first
          raise ArgumentError, "fixed allocations and reservations must not overlap"
        end
      end

      def interval(subnet)
        if @parent.ipv4?
          [subnet.network_u32, subnet.size]
        else
          [subnet.network_u128, subnet.size]
        end
      end

      def parent_start
        @parent_start ||= @parent.ipv4? ? @parent.network_u32 : @parent.network_u128
      end

      def parent_size
        @parent_size ||= 1 << (@bits - @parent.prefix.to_i)
      end

      def maximal_free_gaps(start, size, blocked)
        return [] if blocked.include?([start, size])

        contained = blocked.select do |blocked_start, blocked_size|
          blocked_start >= start && blocked_start + blocked_size <= start + size
        end
        return [[start, size]] if contained.empty?

        half = size / 2
        maximal_free_gaps(start, half, contained) +
          maximal_free_gaps(start + half, half, contained)
      end

      def choose_requests(initial_gaps, request_sizes)
        gaps = initial_gaps
        selected = []
        budget = @budget

        index = 0

        while index < request_sizes.size
          size = request_sizes[index]
          run_length = consecutive_equal_count(request_sizes, index)
          target = minimum_free_blocks(gaps, request_sizes[index..-1])
          chosen_gap = nil
          candidate_gaps = nil

          if run_length > 1
            run_gap = gaps.find { |gap| gap.last >= size }
            if run_gap && run_gap.last >= size * run_length
              run_candidate_gaps = place_run(gaps, run_gap, size, run_length)
              if minimum_free_blocks(run_candidate_gaps, request_sizes[(index + run_length)..-1]) == target
                chosen_gap = run_gap
                candidate_gaps = run_candidate_gaps
                unless budget.nil?
                  raise IPAddress::Layout::BudgetExhausted,
                        "search budget exhausted before an optimal layout was completed" if budget <= 0
                  budget -= 1
                end
              end
            end
          end

          unless chosen_gap
            remaining_sizes = request_sizes[(index + 1)..-1] || []

            gaps.each do |gap|
              next unless gap.last >= size

              unless budget.nil?
                raise IPAddress::Layout::BudgetExhausted,
                      "search budget exhausted before an optimal layout was completed" if budget <= 0
                budget -= 1
              end

              candidate_gaps = place_in_gap(gaps, gap, size)
              candidate_blocks = minimum_free_blocks(candidate_gaps, remaining_sizes)

              if candidate_blocks == target
                chosen_gap = gap
                run_length = 1
                break
              end
            end
          end

          if chosen_gap.nil?
            raise IPAddress::Layout::Impossible,
                  "requested subnets cannot fit without overlapping a fixed allocation or reservation"
          end

          if run_length > 1
            run_length.times do |offset|
              selected << [chosen_gap.first + (offset * size), size, size]
            end
          else
            selected << [chosen_gap.first, chosen_gap.last, size]
          end
          gaps = candidate_gaps
          index += run_length
        end

        [selected, gaps]
      end

      def consecutive_equal_count(sizes, index)
        count = 1
        while index + count < sizes.size && sizes[index + count] == sizes[index]
          count += 1
        end
        count
      end

      def can_pack?(gaps, sizes)
        !minimum_free_blocks(gaps, sizes).nil?
      end

      def minimum_free_blocks(gaps, sizes)
        free_blocks_from_counts(capacity_counts(gaps), item_counts(sizes))
      end

      def free_blocks_from_counts(counts, requests)
        counts = counts.dup

        (0..host_prefix).each do |exponent|
          demand = requests[exponent].to_i
          exact = [demand, counts[exponent]].min
          demand -= exact
          counts[exponent] -= exact

          while demand > 0
            gap_exponent = (exponent + 1..host_prefix).find do |candidate|
              counts[candidate] > 0
            end
            return nil if gap_exponent.nil?

            units_per_gap = 1 << (gap_exponent - exponent)
            full_gaps = [demand / units_per_gap, counts[gap_exponent]].min
            counts[gap_exponent] -= full_gaps
            demand -= full_gaps * units_per_gap

            next if demand >= units_per_gap || counts[gap_exponent].zero?

            if demand > 0 && counts[gap_exponent] > 0
              counts[gap_exponent] -= 1
              remaining = units_per_gap - demand
              free_exponent = exponent
              while remaining > 0
                counts[free_exponent] += 1 if remaining.odd?
                remaining >>= 1
                free_exponent += 1
              end
              demand = 0
            end
          end
        end

        counts.reduce(0, :+)
      end

      def capacity_counts(gaps)
        Array.new(host_prefix + 1, 0).tap do |counts|
          gaps.each { |_start, size| counts[exponent_for_size(size)] += 1 }
        end
      end

      def item_counts(sizes)
        Array.new(host_prefix + 1, 0).tap do |counts|
          sizes.each { |size| counts[exponent_for_size(size)] += 1 }
        end
      end

      def exponent_for_size(size)
        exponent = 0
        block_size = 1
        while block_size < size
          block_size <<= 1
          exponent += 1
        end
        exponent
      end

      def host_prefix
        @bits - @parent.prefix.to_i
      end

      def place_in_gap(gaps, gap, size)
        remaining = gaps.dup
        remaining.delete(gap)

        start, capacity = gap
        while capacity > size
          capacity /= 2
          remaining << [start + capacity, capacity]
        end

        remaining.sort
      end

      def place_run(gaps, gap, size, count)
        remaining = gaps.dup
        remaining.delete(gap)

        start, capacity = gap
        used = size * count
        leftover = capacity - used
        offset = used

        while leftover > 0
          block_size = capacity
          while block_size > leftover || ((offset & (block_size - 1)) != 0)
            block_size /= 2
          end
          remaining << [start + offset, block_size]
          offset += block_size
          leftover -= block_size
        end

        remaining.sort
      end

      def prefix_for_size(size)
        prefix = @bits
        block_size = 1
        while block_size < size
          block_size <<= 1
          prefix -= 1
        end
        prefix
      end

      def parse_subnet(start, prefix)
        if @parent.ipv4?
          IPAddress::IPv4.parse_u32(start, prefix)
        else
          IPAddress::IPv6.parse_u128(start, prefix)
        end
      end
    end
  end
end
