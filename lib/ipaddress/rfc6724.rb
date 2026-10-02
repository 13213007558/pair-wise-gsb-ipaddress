#
# = IPAddress::RFC6724
#
# Pure-computation RFC 6724 (Default Address Selection for IPv6)
# source and destination address selection.
#
# Given a set of destination addresses (as returned by a DNS lookup),
# the source addresses assigned to the local interfaces together with
# their state, a policy table and route reachability information, the
# selector sorts the destinations in the order the stack should try to
# connect to them and reports which source address would be used for
# each of them.
#
# Everything is computed from explicit input: no interface is
# enumerated, no packet is sent, no address property (scope,
# deprecated/home/temporary flags, reachability, outgoing interface)
# is derived from the host. Address scopes and flags are supplied by
# the caller, and label/precedence lookups are performed against the
# RFC 6724 default policy table plus any caller supplied entries
# (longest prefix match wins).
#
#   sources = [
#     IPAddress::RFC6724::Source.new("192.0.2.10", scope: 14),
#     IPAddress::RFC6724::Source.new("2001:db8::10", scope: 14),
#   ]
#   destinations = [
#     IPAddress::RFC6724::Destination.new("93.184.216.34", scope: 14),
#     IPAddress::RFC6724::Destination.new("2001:db8::1", scope: 14),
#   ]
#   selector = IPAddress::RFC6724::Selector.new(sources: sources)
#   selector.sort(destinations).each do |result|
#     puts "#{result.destination.address} via #{result.source&.address}"
#   end
#
module IPAddress
  module RFC6724

    #
    # Address scope values, using the RFC 4291 scope numbering. They
    # are only conventions: any integer may be supplied as a scope,
    # comparisons are purely numeric.
    #
    SCOPE_INTERFACE_LOCAL     = 1
    SCOPE_LINK_LOCAL          = 2
    SCOPE_ADMIN_LOCAL         = 4
    SCOPE_SITE_LOCAL          = 5
    SCOPE_ORGANIZATION_LOCAL  = 8
    SCOPE_GLOBAL              = 14

    # Base value of the IPv4-mapped IPv6 space ::ffff:0:0/96
    MAPPED_BASE = 0xffff << 32

    #
    # A candidate source address assigned to a local interface, with
    # the state flags RFC 6724 source address selection cares about.
    # All attributes are explicit input.
    #
    #   IPAddress::RFC6724::Source.new("2001:db8::10",
    #     scope: IPAddress::RFC6724::SCOPE_GLOBAL,
    #     interface: "eth0",
    #     deprecated: false,
    #     temporary: true)
    #
    class Source
      attr_reader :address, :scope, :interface

      def initialize(address, scope:, interface: nil, deprecated: false,
                     home: false, care_of: false, temporary: false)
        @address   = RFC6724.coerce_address(address)
        @scope     = scope
        @interface = interface
        @deprecated = deprecated
        @home      = home
        @care_of   = care_of
        @temporary = temporary
      end

      def deprecated?
        @deprecated
      end

      def home?
        @home
      end

      def care_of?
        @care_of
      end

      def temporary?
        @temporary
      end

      #
      # Ranking used by RFC 6724 section 5 rule 4 ("prefer home
      # addresses"): an address that is both a home and a care-of
      # address is best, a plain care-of address is worst, anything
      # else ranks in between.
      #
      def home_rank
        return 2 if home? && care_of?
        return 0 if care_of? && !home?
        1
      end
    end

    #
    # A destination address to connect to, with the route information
    # RFC 6724 destination and source selection care about. All
    # attributes are explicit input.
    #
    # A zone may be attached to the address string in the usual
    # "fe80::1%eth0" notation (or passed via the +zone+ keyword): only
    # sources on that interface are eligible for such a destination.
    #
    #   IPAddress::RFC6724::Destination.new("fe80::1%eth0",
    #     scope: IPAddress::RFC6724::SCOPE_LINK_LOCAL)
    #
    class Destination
      attr_reader :address, :scope, :interface, :zone, :advertised_prefixes

      def initialize(address, scope:, reachable: true, interface: nil,
                     zone: nil, advertised_prefixes: [])
        if address.is_a?(String) && address.include?("%")
          address, parsed_zone = address.split("%", 2)
          zone ||= parsed_zone
        end
        @address   = RFC6724.coerce_address(address)
        @scope     = scope
        @reachable = reachable
        @zone      = zone
        @interface = interface || zone
        @advertised_prefixes = advertised_prefixes.map do |prefix|
          RFC6724.normalize_prefix(prefix)
        end
      end

      def reachable?
        @reachable
      end
    end

    #
    # The outcome of destination address selection for a single
    # destination: the destination itself and the source address that
    # would be used to reach it (nil when no suitable source address
    # exists).
    #
    class Result
      attr_reader :destination, :source

      def initialize(destination, source)
        @destination = destination
        @source      = source
      end

      #
      # A destination is usable when the route to it is known to be
      # reachable and a suitable source address was found.
      #
      def usable?
        @destination.reachable? && !@source.nil?
      end
    end

    #
    # The RFC 6724 policy table: a list of prefix => {precedence,
    # label} entries. Lookups use longest prefix match; entries added
    # later win over entries with the same prefix length, so user
    # supplied entries override the defaults.
    #
    #   table = IPAddress::RFC6724::PolicyTable.new
    #   table.add("2001:db8::/32", precedence: 45, label: 7)
    #   table.lookup("2001:db8::1").precedence  #=> 45
    #
    class PolicyTable

      Entry = Struct.new(:precedence, :label)

      # RFC 6724 section 2.1 default policy table
      DEFAULT_ENTRIES = [
        ["::1/128",       50, 0],
        ["::/0",          40, 1],
        ["::ffff:0:0/96", 35, 4],
        ["2002::/16",     30, 2],
        ["2001::/32",      5, 5],
        ["fc00::/7",       3, 13],
        ["::/96",          1, 3],
        ["fec0::/10",      1, 11],
        ["3ffe::/16",      1, 12],
      ].freeze

      def initialize(defaults: true)
        @entries = []
        return unless defaults
        DEFAULT_ENTRIES.each do |prefix, precedence, label|
          add(prefix, precedence: precedence, label: label)
        end
      end

      def add(prefix, precedence:, label:)
        network, length = RFC6724.normalize_prefix(prefix)
        @entries << [network, length, Entry.new(precedence, label)]
        self
      end

      #
      # Longest prefix match lookup. Returns an Entry, or nil when
      # the table holds no matching entry (only possible with
      # defaults: false).
      #
      def lookup(address)
        value, = RFC6724.mapped_bits(RFC6724.coerce_address(address))
        best = nil
        @entries.each do |network, length, entry|
          next unless RFC6724.prefix_match?(value, network, length)
          best = [length, entry] if best.nil? || length >= best[0]
        end
        best && best[1]
      end
    end

    #
    # The address selector. Holds the candidate source addresses, the
    # policy table and the temporary-address preference, and applies
    # the RFC 6724 source (section 5) and destination (section 6)
    # selection rules to them.
    #
    class Selector

      # Used when the policy table has no matching entry at all
      FALLBACK_ENTRY = PolicyTable::Entry.new(0, 0)

      attr_reader :sources, :policy_table

      def initialize(sources: [], policy_table: PolicyTable.new,
                     prefer_temporary: true)
        sources.each do |source|
          next if source.is_a?(Source)
          raise ArgumentError,
                "sources must be IPAddress::RFC6724::Source objects"
        end
        @sources = sources
        @policy_table = policy_table
        @prefer_temporary = prefer_temporary
      end

      #
      # RFC 6724 section 5: pick the best source address for a
      # destination. Returns nil when no source address is eligible
      # (different address family, or zone mismatch).
      #
      def select_source(destination)
        candidates = @sources.each_with_index.select do |source, _|
          eligible?(source, destination)
        end
        return nil if candidates.empty?
        candidates.min_by do |source, index|
          source_key(source, destination, index)
        end.first
      end

      #
      # RFC 6724 section 6: sort destinations in the order they
      # should be tried, selecting a source address for each of them.
      # Returns an array of Result objects. Unusable destinations
      # (unreachable, or without a suitable source address) sink to the
      # bottom; destinations that compare equal on every rule keep
      # their input order.
      #
      def sort(destinations)
        destinations.each do |destination|
          next if destination.is_a?(Destination)
          raise ArgumentError,
                "destinations must be IPAddress::RFC6724::Destination objects"
        end
        destinations.each_with_index.map do |destination, index|
          [Result.new(destination, select_source(destination)), index]
        end.sort_by do |result, index|
          destination_key(result, index)
        end.map(&:first)
      end

      private

      def policy(address)
        @policy_table.lookup(address) || FALLBACK_ENTRY
      end

      def eligible?(source, destination)
        return false unless RFC6724.family(source.address) ==
                          RFC6724.family(destination.address)
        destination.zone.nil? || source.interface == destination.zone
      end

      #
      # RFC 6724 section 5 rules 1-8 as a lexicographic sort key
      # (lower is better). The candidate index is appended so that
      # fully tied candidates keep their input order.
      #
      def source_key(source, destination, index)
        source_policy = policy(source.address)
        destination_policy = policy(destination.address)
        sufficient = source.scope >= destination.scope
        [
          # Rule 1: prefer same address
          same_address?(source.address, destination.address) ? 0 : 1,
          # Rule 2: prefer appropriate scope
          sufficient ? 0 : 1,
          sufficient ? source.scope : -source.scope,
          # Rule 3: avoid deprecated addresses
          source.deprecated? ? 1 : 0,
          # Rule 4: prefer home addresses
          -source.home_rank,
          # Rule 5: prefer outgoing interface
          interface_match?(source, destination) ? 0 : 1,
          # Rule 5.5: prefer addresses in a prefix advertised by the next-hop
          advertised_match?(source, destination) ? 0 : 1,
          # Rule 6: prefer matching label
          source_policy.label == destination_policy.label ? 0 : 1,
          # Rule 7: prefer temporary addresses
          temporary_rank(source),
          # Rule 8: use longest matching prefix
          -RFC6724.common_prefix_length(source.address, destination.address),
          index,
        ]
      end

      #
      # RFC 6724 section 6 rules 1-10 as a lexicographic sort key
      # (lower sorts first). Rule 7 of the RFC ("prefer native
      # transport") is not computable from addresses alone and is
      # left out. The input index implements rule 10 ("otherwise,
      # leave the order unchanged").
      #
      def destination_key(result, index)
        return [1, 0, 0, 0, 0, 0, 0, 0, index] unless result.usable?
        source = result.source
        destination = result.destination
        source_policy = policy(source.address)
        destination_policy = policy(destination.address)
        [
          # Rule 1: avoid unusable destinations
          0,
          # Rule 2: prefer matching scope
          source.scope == destination.scope ? 0 : 1,
          # Rule 3: avoid deprecated addresses
          source.deprecated? ? 1 : 0,
          # Rule 4: prefer home addresses
          -source.home_rank,
          # Rule 5: prefer matching label
          source_policy.label == destination_policy.label ? 0 : 1,
          # Rule 6: prefer higher precedence
          -destination_policy.precedence,
          # Rule 8: prefer smaller scope
          destination.scope,
          # Rule 9: use longest matching prefix
          -RFC6724.common_prefix_length(source.address, destination.address),
          # Rule 10: otherwise, leave the order unchanged
          index,
        ]
      end

      def same_address?(first, second)
        RFC6724.family(first) == RFC6724.family(second) &&
          RFC6724.native_bits(first) == RFC6724.native_bits(second)
      end

      def interface_match?(source, destination)
        destination.interface.nil? || source.interface == destination.interface
      end

      def advertised_match?(source, destination)
        return true if destination.advertised_prefixes.empty?
        value, = RFC6724.mapped_bits(source.address)
        destination.advertised_prefixes.any? do |network, length|
          RFC6724.prefix_match?(value, network, length)
        end
      end

      def temporary_rank(source)
        if @prefer_temporary
          source.temporary? ? 0 : 1
        else
          source.temporary? ? 1 : 0
        end
      end
    end

    #
    # Convenience wrapper around Selector#sort.
    #
    def self.sort(destinations, sources:, policy_table: PolicyTable.new,
                  prefer_temporary: true)
      Selector.new(sources: sources, policy_table: policy_table,
                   prefer_temporary: prefer_temporary).sort(destinations)
    end

    #
    # Convenience wrapper around Selector#select_source.
    #
    def self.select_source(destination, sources:,
                           policy_table: PolicyTable.new,
                           prefer_temporary: true)
      Selector.new(sources: sources, policy_table: policy_table,
                   prefer_temporary: prefer_temporary).select_source(destination)
    end

    #
    # Coerces a string into an IPAddress::IPv4 or IPAddress::IPv6
    # object; address objects pass through untouched.
    #
    def self.coerce_address(address)
      return address if address.is_a?(IPAddress::IPv4) ||
                        address.is_a?(IPAddress::IPv6)
      IPAddress.parse(address.to_s)
    end

    def self.family(address)
      address.is_a?(IPAddress::IPv4) ? :ipv4 : :ipv6
    end

    #
    # The address as an integer in its native width: 32 bits for
    # IPv4, 128 bits for IPv6.
    #
    def self.native_bits(address)
      if address.is_a?(IPAddress::IPv4)
        [address.to_u32, 32]
      else
        [address.to_u128, 128]
      end
    end

    #
    # The address as a 128 bit integer, mapping IPv4 addresses into
    # the ::ffff:0:0/96 space so that a single policy table covers
    # both address families.
    #
    def self.mapped_bits(address)
      if address.is_a?(IPAddress::IPv4)
        [MAPPED_BASE + address.to_u32, 128]
      else
        [address.to_u128, 128]
      end
    end

    #
    # Normalizes a prefix ("10.0.0.0/8", "2001:db8::/32" or an
    # IPAddress object carrying a prefix) to a [network, length] pair
    # in the 128 bit mapped space.
    #
    def self.normalize_prefix(prefix)
      prefix = coerce_address(prefix)
      if prefix.is_a?(IPAddress::IPv4)
        [MAPPED_BASE + prefix.network_u32, 96 + prefix.prefix.to_i]
      else
        [prefix.network_u128, prefix.prefix.to_i]
      end
    end

    def self.prefix_match?(value, network, length)
      length.zero? || (value ^ network) >> (128 - length) == 0
    end

    #
    # Length of the longest common prefix of two addresses of the
    # same family, computed over their native width (32 bits for
    # IPv4, 128 bits for IPv6).
    #
    def self.common_prefix_length(first, second)
      first_value, width = native_bits(first)
      second_value, = native_bits(second)
      width - (first_value ^ second_value).bit_length
    end
  end
end
