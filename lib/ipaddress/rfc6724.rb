#
# = IPAddress::RFC6724
#
# Pure-computation RFC 6724 destination and source address selection.
#
require 'ipaddress/ipv4'
require 'ipaddress/ipv6'

module IPAddress

  #
  # =Name
  #
  # IPAddress::RFC6724 - RFC 6724 "Default Address Selection for IPv6"
  #
  # =Description
  #
  # A pure calculator implementing the RFC 6724 destination address
  # selection (section 6) and source address selection (section 5)
  # algorithms. It never reads local network interfaces and never
  # opens connections: scopes, address states (deprecated, home,
  # temporary), the policy table, route reachability and outgoing
  # interfaces all come from explicit input.
  #
  # =Synopsis
  #
  #   require 'ipaddress'
  #
  #   sources = [
  #     IPAddress::RFC6724::SourceAddress.new(address: "2001:db8::1"),
  #     IPAddress::RFC6724::SourceAddress.new(address: "192.0.2.5"),
  #   ]
  #   results = IPAddress::RFC6724.sort(["2001:db8::9", "192.0.2.9"],
  #                                     sources: sources)
  #   results.map(&:destination) #=> ["2001:db8::9", "192.0.2.9"]
  #   results.first.usable?      #=> true
  #
  module RFC6724

    # Scope values, ordered by size (numbering follows RFC 4007).
    SCOPE_INTERFACE_LOCAL = 1
    SCOPE_LINK_LOCAL      = 2
    SCOPE_SITE_LOCAL      = 5
    SCOPE_GLOBAL          = 14

    # RFC 6724 section 2.1 default policy table.
    DEFAULT_POLICY_TABLE = [
      {prefix: "::1/128",       precedence: 50, label: 0},
      {prefix: "::/0",          precedence: 40, label: 1},
      {prefix: "::ffff:0:0/96", precedence: 35, label: 4},
      {prefix: "2002::/16",     precedence: 30, label: 2},
      {prefix: "2001::/32",     precedence: 5,  label: 5},
      {prefix: "fc00::/7",      precedence: 3,  label: 13},
      {prefix: "::/96",         precedence: 1,  label: 3},
      {prefix: "fec0::/10",     precedence: 1,  label: 11},
      {prefix: "3ffe::/16",     precedence: 1,  label: 12},
    ].freeze

    # Used when no entry of the policy table matches an address.
    FALLBACK_POLICY = {precedence: 0, label: 0}.freeze

    #
    # A source address candidate together with its state. All state
    # flags are explicit input; nothing is probed.
    #
    class SourceAddress
      attr_reader :address, :interface

      def initialize(address:, interface: nil, deprecated: false,
                     home: false, temporary: false)
        @address    = address
        @interface  = interface
        @deprecated = deprecated
        @home       = home
        @temporary  = temporary
      end

      def deprecated?
        @deprecated
      end

      def home?
        @home
      end

      def temporary?
        @temporary
      end
    end

    #
    # One element of the sorted result: the destination string as it
    # was passed in, the selected SourceAddress (nil when no suitable
    # source exists) and whether the destination is usable.
    #
    class Result
      attr_reader :destination, :source

      def initialize(destination:, source:, reachable:)
        @destination = destination
        @source      = source
        @reachable   = reachable
      end

      # False when the destination is unreachable or has no suitable
      # source address (RFC 6724 section 6, rule 1).
      def usable?
        @reachable && !@source.nil?
      end
    end

    #
    # Sorts +destinations+ according to the RFC 6724 destination
    # address selection rules and returns an array of Result objects,
    # each carrying the source address selected by the RFC 6724
    # source address selection rules.
    #
    # Options:
    #
    # sources::          array of SourceAddress, Hash or address String
    # policy_table::     array of {prefix:, precedence:, label:} hashes;
    #                    longest prefix match wins
    # reachable::        true/false, Hash of destination => boolean, or
    #                    a callable receiving the destination string
    # interfaces::       Hash of destination => outgoing interface name,
    #                    or a callable (source selection rule 5)
    # prefer_temporary:: when false, source rule 7 prefers public
    #                    addresses over temporary ones
    #
    # Destinations that compare equal keep their input order.
    #
    def self.sort(destinations, sources:, policy_table: DEFAULT_POLICY_TABLE,
                  reachable: true, interfaces: nil, prefer_temporary: true)
      ctx = Context.new(policy_table, reachable, interfaces, prefer_temporary)
      candidates = sources.map { |s| Candidate.new(coerce_source(s)) }
      rows = destinations.each_with_index.map do |destination, index|
        endpoint = Endpoint.new(destination)
        candidate = select_source(endpoint, candidates, ctx)
        Row.new(destination, endpoint, candidate,
                ctx.reachable?(destination), index)
      end
      rows.sort { |a, b| compare_rows(a, b, ctx) }.map do |row|
        Result.new(destination: row.destination,
                   source: row.candidate && row.candidate.source,
                   reachable: row.reachable)
      end
    end

    #
    # The precedence the policy table assigns to an address.
    #
    def self.precedence(address, policy_table = DEFAULT_POLICY_TABLE)
      lookup_policy(compile_policy_table(policy_table),
                    Endpoint.new(address).to_u128)[:precedence]
    end

    #
    # The label the policy table assigns to an address.
    #
    def self.label(address, policy_table = DEFAULT_POLICY_TABLE)
      lookup_policy(compile_policy_table(policy_table),
                    Endpoint.new(address).to_u128)[:label]
    end

    #
    # The scope of an address: SCOPE_INTERFACE_LOCAL, SCOPE_LINK_LOCAL,
    # SCOPE_SITE_LOCAL, SCOPE_GLOBAL or, for multicast addresses, the
    # scope nibble. IPv4-mapped IPv6 addresses get IPv4 scopes.
    #
    def self.scope(address)
      endpoint = address.is_a?(Endpoint) ? address : Endpoint.new(address)
      u128 = endpoint.to_u128
      if endpoint.ipv4? || (u128 >> 32) == 0xffff
        u32 = u128 & 0xffffffff
        return SCOPE_INTERFACE_LOCAL if (u32 >> 24) == 127
        return SCOPE_LINK_LOCAL if (u32 >> 16) == 0xa9fe
        return SCOPE_GLOBAL
      end
      return SCOPE_INTERFACE_LOCAL if u128 == 1
      return SCOPE_LINK_LOCAL if (u128 >> 118) == 0x3fa # fe80::/10
      return SCOPE_SITE_LOCAL if (u128 >> 118) == 0x3fb # fec0::/10
      return (u128 >> 112) & 0xf if (u128 >> 120) == 0xff # multicast
      SCOPE_GLOBAL
    end

    #
    # Length of the longest common leading bit prefix of two addresses.
    #
    def self.common_prefix_length(a, b)
      ea = a.is_a?(Endpoint) ? a : Endpoint.new(a)
      eb = b.is_a?(Endpoint) ? b : Endpoint.new(b)
      if ea.ipv4? && eb.ipv4?
        32 - (ea.to_u32 ^ eb.to_u32).bit_length
      else
        128 - (ea.to_u128 ^ eb.to_u128).bit_length
      end
    end

    # An IP address plus its optional zone ("fe80::1%eth0").
    class Endpoint
      attr_reader :ip, :zone, :original

      def initialize(str)
        @original = str.to_s
        address, separator, zone = @original.partition('%')
        @zone = separator.empty? ? nil : zone
        @ip = IPAddress.parse(address)
      end

      def ipv4?
        @ip.is_a?(IPAddress::IPv4)
      end

      def family
        ipv4? ? :ipv4 : :ipv6
      end

      def to_u32
        @ip.u32
      end

      # IPv4 addresses are mapped to ::ffff:a.b.c.d so that policy
      # table lookups work uniformly in 128-bit space.
      def to_u128
        ipv4? ? (0xffff << 32) + @ip.u32 : @ip.to_u128
      end
    end

    # A SourceAddress wrapped with its parsed endpoint.
    class Candidate
      attr_reader :source, :endpoint

      def initialize(source)
        @source   = source
        @endpoint = Endpoint.new(source.address)
      end

      # Explicit zone from the address string, else the interface.
      def zone
        @endpoint.zone || @source.interface
      end
    end

    # Internal: one destination plus its selection state.
    Row = Struct.new(:destination, :endpoint, :candidate, :reachable, :index) do
      def usable?
        reachable && !candidate.nil?
      end
    end

    # Internal: resolved options shared by all comparisons.
    class Context
      attr_reader :prefer_temporary

      def initialize(policy_table, reachable, interfaces, prefer_temporary)
        @policy = RFC6724.compile_policy_table(policy_table)
        @reachable = reachable
        @interfaces = interfaces
        @prefer_temporary = prefer_temporary
        @policy_cache = {}
      end

      def reachable?(destination)
        resolve(@reachable, destination, true)
      end

      def outgoing_interface(destination)
        resolve(@interfaces, destination, nil)
      end

      def label(endpoint)
        policy(endpoint)[:label]
      end

      def precedence(endpoint)
        policy(endpoint)[:precedence]
      end

      private

      def policy(endpoint)
        @policy_cache[endpoint.to_u128] ||=
          RFC6724.lookup_policy(@policy, endpoint.to_u128)
      end

      def resolve(option, key, default)
        case option
        when nil then default
        when Hash then option.fetch(key, default)
        else option.respond_to?(:call) ? option.call(key) : option
        end
      end
    end

    def self.coerce_source(source)
      case source
      when SourceAddress then source
      when Hash
        SourceAddress.new(**source.each_with_object({}) { |(k, v), h| h[k.to_sym] = v })
      else SourceAddress.new(address: source.to_s)
      end
    end

    def self.compile_policy_table(table)
      table.map do |entry|
        ip = IPAddress.parse(entry[:prefix].to_s)
        if ip.is_a?(IPAddress::IPv4)
          {value: (0xffff << 32) + ip.u32, bits: 96 + ip.prefix.to_i,
           precedence: entry[:precedence], label: entry[:label]}
        else
          {value: ip.to_u128, bits: ip.prefix.to_i,
           precedence: entry[:precedence], label: entry[:label]}
        end
      end
    end

    # Longest prefix match; ties keep the earlier table entry.
    def self.lookup_policy(compiled, u128)
      best = nil
      compiled.each do |entry|
        next unless prefix_match?(u128, entry[:value], entry[:bits])
        best = entry if best.nil? || entry[:bits] > best[:bits]
      end
      best || FALLBACK_POLICY
    end

    def self.prefix_match?(u128, value, bits)
      return true if bits.zero?
      shift = 128 - bits
      (u128 >> shift) == (value >> shift)
    end

    # True when a link-local candidate and destination share a zone.
    # Non link-local pairs are always zone compatible.
    def self.zone_compatible?(candidate, dest_endpoint)
      return true unless scope(candidate.endpoint) == SCOPE_LINK_LOCAL &&
                         scope(dest_endpoint) == SCOPE_LINK_LOCAL
      candidate.zone == dest_endpoint.zone
    end

    # RFC 6724 section 5: pick the best source for a destination.
    # Only same-family sources are candidates; ties keep input order.
    def self.select_source(dest_endpoint, candidates, ctx)
      pool = candidates.select { |c| c.endpoint.family == dest_endpoint.family }
      pool.reduce do |current, challenger|
        prefer_source?(challenger, current, dest_endpoint, ctx) ? challenger : current
      end
    end

    # RFC 6724 section 5, rules 1-8: true when +sa+ is strictly
    # preferred over +sb+ as source for destination +d+.
    def self.prefer_source?(sa, sb, d, ctx)
      # Rule 1: prefer same address
      a_same = sa.endpoint.family == d.family && sa.endpoint.to_u128 == d.to_u128
      b_same = sb.endpoint.family == d.family && sb.endpoint.to_u128 == d.to_u128
      return a_same if a_same != b_same

      # Rule 2: prefer appropriate scope. A link-local source in a
      # different zone than a link-local destination is inappropriate.
      a_zone = zone_compatible?(sa, d)
      b_zone = zone_compatible?(sb, d)
      return a_zone if a_zone != b_zone
      a_scope = scope(sa.endpoint)
      b_scope = scope(sb.endpoint)
      d_scope = scope(d)
      if a_scope < b_scope
        return a_scope >= d_scope
      elsif b_scope < a_scope
        return b_scope < d_scope
      end

      # Rule 3: avoid deprecated addresses
      return !sa.source.deprecated? if sa.source.deprecated? != sb.source.deprecated?

      # Rule 4: prefer home addresses
      return sa.source.home? if sa.source.home? != sb.source.home?

      # Rule 5: prefer an address on the outgoing interface
      outgoing = ctx.outgoing_interface(d.original)
      if outgoing
        a_on = sa.source.interface == outgoing
        b_on = sb.source.interface == outgoing
        return a_on if a_on != b_on
      end

      # Rule 6: prefer matching label
      d_label = ctx.label(d)
      a_match = ctx.label(sa.endpoint) == d_label
      b_match = ctx.label(sb.endpoint) == d_label
      return a_match if a_match != b_match

      # Rule 7: prefer temporary addresses (unless disabled)
      if sa.source.temporary? != sb.source.temporary?
        return ctx.prefer_temporary ? sa.source.temporary? : !sa.source.temporary?
      end

      # Rule 8: use longest matching prefix
      a_len = common_prefix_length(sa.endpoint, d)
      b_len = common_prefix_length(sb.endpoint, d)
      a_len > b_len
    end

    # RFC 6724 section 6, rules 1-10: -1/0/1 comparison of two
    # destination rows. Rule 7 (prefer native transport) is not
    # implemented: no transport information is available to a pure
    # calculator. Rule 10 falls back to input order.
    def self.compare_rows(a, b, ctx)
      # Rule 1: avoid unusable destinations
      return -1 if a.usable? && !b.usable?
      return 1 if b.usable? && !a.usable?
      return a.index <=> b.index unless a.usable? && b.usable?

      sa = a.candidate
      sb = b.candidate

      # Rule 2: prefer matching scope
      a_match = scope_match?(sa, a.endpoint)
      b_match = scope_match?(sb, b.endpoint)
      return -1 if a_match && !b_match
      return 1 if b_match && !a_match

      # Rule 3: avoid deprecated addresses
      a_dep = sa.source.deprecated?
      b_dep = sb.source.deprecated?
      return -1 if !a_dep && b_dep
      return 1 if !b_dep && a_dep

      # Rule 4: prefer home addresses
      a_home = sa.source.home?
      b_home = sb.source.home?
      return -1 if a_home && !b_home
      return 1 if b_home && !a_home

      # Rule 5: prefer matching label
      a_label = ctx.label(sa.endpoint) == ctx.label(a.endpoint)
      b_label = ctx.label(sb.endpoint) == ctx.label(b.endpoint)
      return -1 if a_label && !b_label
      return 1 if b_label && !a_label

      # Rule 6: prefer higher precedence
      a_prec = ctx.precedence(a.endpoint)
      b_prec = ctx.precedence(b.endpoint)
      return -1 if a_prec > b_prec
      return 1 if b_prec > a_prec

      # Rule 8: prefer smaller scope
      a_scope = scope(a.endpoint)
      b_scope = scope(b.endpoint)
      return -1 if a_scope < b_scope
      return 1 if b_scope < a_scope

      # Rule 9: use longest matching prefix
      a_len = common_prefix_length(sa.endpoint, a.endpoint)
      b_len = common_prefix_length(sb.endpoint, b.endpoint)
      return -1 if a_len > b_len
      return 1 if b_len > a_len

      # Rule 10: otherwise, leave the order unchanged
      a.index <=> b.index
    end

    def self.scope_match?(candidate, endpoint)
      return false unless scope(candidate.endpoint) == scope(endpoint)
      zone_compatible?(candidate, endpoint)
    end

    private_class_method :coerce_source, :zone_compatible?, :select_source,
                         :prefer_source?, :compare_rows, :scope_match?
  end
end

