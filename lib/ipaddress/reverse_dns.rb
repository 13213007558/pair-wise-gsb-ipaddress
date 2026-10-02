#
# = IPAddress::ReverseDNS
#
# Planning of reverse DNS delegations.
#
# Given a parent prefix you control and a set of child prefixes with
# their name servers, this module computes the records that have to be
# published in the parent zone and the PTR name mapping of every child
# zone. It never talks to a DNS server: it only computes the plan.
#
# For IPv4, children falling on non-octet boundaries are delegated
# classlessly as described by RFC 2317 (a sub zone plus one CNAME per
# address in the parent zone). For IPv6, children are split exactly on
# nibble boundaries so that no adjacent address space is covered.
#
#   plan = IPAddress::ReverseDNS.plan("192.0.2.0/24", [
#     {prefix: "192.0.2.0/27", nameservers: ["ns1.example.com"]},
#   ])
#
#   plan.parent_zone
#     #=> "2.0.192.in-addr.arpa"
#   plan.zones.first.name
#     #=> "0/27.2.0.192.in-addr.arpa"
#   plan.zones.first.ptr_name("192.0.2.5")
#     #=> "5.0/27.2.0.192.in-addr.arpa"
#
module IPAddress
  module ReverseDNS

    #
    # Raised when the plan input is invalid
    #
    class Error < StandardError; end

    # Maximum number of addresses Zone#ptr_mapping will enumerate
    DEFAULT_ENUMERATION_LIMIT = 4096

    # Maximum number of CNAME records generated for a single
    # RFC 2317 delegation
    DEFAULT_CNAME_LIMIT = 65536

    #
    # A single record to publish in the parent zone, annotated with
    # the original address range it was generated for.
    #
    class Record
      attr_reader :name, :type, :value, :first, :last

      def initialize(name, type, value, first, last)
        @name  = name
        @type  = type
        @value = value
        @first = first
        @last  = last
      end

      #
      # The original address range this record covers
      #
      #   record.range
      #     #=> "192.0.2.0..192.0.2.31"
      #
      def range
        first == last ? first : "#{first}..#{last}"
      end

      def to_s
        "#{name}. #{type} #{value}."
      end
    end

    #
    # A conflict detected between the generated plan and either the
    # requested delegations themselves or user supplied existing
    # delegations and records.
    #
    class Conflict
      attr_reader :type, :message

      def initialize(type, message)
        @type    = type
        @message = message
      end

      def to_s
        message
      end
    end

    #
    # A child zone produced by the plan. Knows how to map any address
    # of its prefix to the PTR record name living inside the zone.
    #
    class Zone
      attr_reader :name, :nameservers, :network

      def initialize(name, nameservers, network)
        @name        = name
        @nameservers = nameservers
        @network     = network
      end

      def prefix
        @network.prefix.to_i
      end

      def size
        @network.size
      end

      def first_address
        ReverseDNS.address_string(@network)
      end

      def last_address
        ReverseDNS.address_string(ReverseDNS.last_of(@network))
      end

      #
      # Checks whether the given address belongs to this zone
      #
      def include?(address)
        addr = ReverseDNS.coerce_address(address)
        addr.class == @network.class && @network.include?(addr)
      end

      #
      # The name of the PTR record for an address of this zone
      #
      #   zone.ptr_name("192.0.2.5")
      #     #=> "5.0/27.2.0.192.in-addr.arpa"
      #
      def ptr_name(address)
        addr = ReverseDNS.coerce_address(address)
        unless include?(addr)
          raise Error, "#{address} is not inside #{@network.to_string}"
        end
        ReverseDNS.owner_name(addr, @network, @name)
      end

      #
      # A hash mapping every address of the zone to its PTR record
      # name. Raises if the zone holds more than +limit+ addresses.
      #
      def ptr_mapping(limit = DEFAULT_ENUMERATION_LIMIT)
        if size > limit
          raise Error, "zone #{name} covers #{size} addresses, " +                       "refusing to enumerate more than #{limit}; " +                       "use ptr_name for single addresses"
        end
        mapping = {}
        @network.each do |addr|
          mapping[ReverseDNS.address_string(addr)] =
            ReverseDNS.owner_name(addr, @network, @name)
        end
        mapping
      end
    end

    #
    # One hop of a delegation chain, as returned by
    # Plan#delegation_chain. +record+ is the record causing the hop
    # (a CNAME or an NS), nil on the terminal hop.
    #
    Hop = Struct.new(:zone, :name, :record)

    #
    # The result of ReverseDNS.plan
    #
    class Plan
      attr_reader :parent, :parent_zone, :records, :zones, :conflicts

      def initialize(parent, delegations, options = {})
        existing   = options[:existing] || []
        max_cnames = options[:max_cnames] || DEFAULT_CNAME_LIMIT

        @parent = ReverseDNS.parse_network(parent)
        if @parent.is_a?(IPAddress::IPv6) && @parent.prefix.to_i % 4 != 0
          raise Error, "IPv6 parent prefix #{@parent.prefix} is not on " \
                       "a nibble boundary (multiple of 4)"
        end
        @parent_zone = ReverseDNS.zone_name(@parent)
        @records     = []
        @zones       = []
        @conflicts   = []

        delegations.each do |delegation|
          child, nameservers = ReverseDNS.normalize_delegation(delegation)
          unless child.class == @parent.class
            raise Error, "delegation #{child.to_string} does not match " \
                         "the address family of #{@parent.to_string}"
          end
          unless @parent.include?(child)
            raise Error, "delegation #{child.to_string} is not contained " \
                         "in parent #{@parent.to_string}"
          end
          build_delegation(child, nameservers, max_cnames)
        end

        build_indexes
        check_internal_conflicts
        check_existing(existing)
      end

      #
      # True when no conflict was detected
      #
      def valid?
        @conflicts.empty?
      end

      def ns_records
        @records.select { |record| record.type == "NS" }
      end

      def cname_records
        @records.select { |record| record.type == "CNAME" }
      end

      #
      # The child zone covering the given address, or nil when the
      # address is not delegated away from the parent zone.
      #
      def zone_for(address)
        addr = ReverseDNS.coerce_address(address)
        @zones.find { |zone| zone.include?(addr) }
      end

      #
      # Simulates the delegation chain for an address, hopping from
      # the parent zone through CNAMEs and NS delegations down to the
      # zone holding the PTR record. Returns nil when the address is
      # outside the parent prefix.
      #
      #   plan.delegation_chain("192.0.2.5").map(&:zone)
      #     #=> ["2.0.192.in-addr.arpa", "0/27.2.0.192.in-addr.arpa"]
      #
      def delegation_chain(address)
        addr = ReverseDNS.coerce_address(address)
        return nil unless addr.class == @parent.class && @parent.include?(addr)

        hops         = []
        current_zone = @parent_zone
        current_name = ReverseDNS.owner_name(addr, @parent, @parent_zone)
        loop do
          if (cname = @cname_index[current_name.downcase])
            hops << Hop.new(current_zone, current_name, cname)
            current_name = cname.value
            current_zone = zone_name_for(current_name) || current_zone
          elsif (zone = delegation_for(current_name, current_zone))
            hops << Hop.new(current_zone, zone.name, ns_record_for(zone))
            current_zone = zone.name
          else
            hops << Hop.new(current_zone, current_name, nil)
            return hops
          end
        end
      end

      #
      # Renders the parent zone records, each annotated with the
      # address range it was generated for.
      #
      def to_s
        lines = ["; Parent zone: #{@parent_zone}"]
        @records.each do |record|
          lines << format("%-40s %-6s %s ; %s",
                          "#{record.name}.", record.type,
                          "#{record.value}.", record.range)
        end
        lines.join("\n")
      end

      private

      def build_delegation(child, nameservers, max_cnames)
        if same_network?(child, @parent)
          add_ns(@parent_zone, nameservers, child)
          return
        end
        case child
        when IPAddress::IPv4
          if child.prefix.to_i % 8 == 0
            add_zone(ReverseDNS.zone_name(child), nameservers, child)
          else
            build_rfc2317(child, nameservers, max_cnames)
          end
        when IPAddress::IPv6
          ReverseDNS.nibble_blocks(child).each do |block|
            add_zone(ReverseDNS.zone_name(block), nameservers, block)
          end
        end
      end

      def build_rfc2317(child, nameservers, max_cnames)
        if child.size > max_cnames
          raise Error, "delegation #{child.to_string} would need " \
                       "#{child.size} CNAME records (limit #{max_cnames})"
        end
        zone = add_zone(ReverseDNS.zone_name(child), nameservers, child)
        child.each do |addr|
          owner  = ReverseDNS.owner_name(addr, @parent, @parent_zone)
          target = ReverseDNS.owner_name(addr, child, zone.name)
          add_record(owner, "CNAME", target, addr, addr)
        end
      end

      def add_zone(name, nameservers, network)
        add_ns(name, nameservers, network)
        zone = Zone.new(name, nameservers, network)
        @zones << zone
        zone
      end

      def add_ns(name, nameservers, network)
        nameservers.each do |ns|
          add_record(name, "NS", ns, network, ReverseDNS.last_of(network))
        end
      end

      def add_record(name, type, value, first, last)
        @records << Record.new(name, type, value,
                               ReverseDNS.address_string(first),
                               ReverseDNS.address_string(last))
      end

      def same_network?(a, b)
        a.prefix.to_i == b.prefix.to_i &&
          ReverseDNS.first_u(a) == ReverseDNS.first_u(b)
      end

      def build_indexes
        @cname_index = {}
        @records.each do |record|
          next unless record.type == "CNAME"
          @cname_index[record.name.downcase] = record
        end
      end

      def check_internal_conflicts
        @zones.map(&:network).combination(2) do |a, b|
          next unless ReverseDNS.ranges_overlap?(a, b)
          @conflicts << Conflict.new(
            :overlap,
            "delegations #{a.to_string} and #{b.to_string} overlap")
        end
        grouped = @records.group_by { |record| record.name.downcase }
        grouped.each do |name, records|
          cnames = records.select { |record| record.type == "CNAME" }
          others = records - cnames
          if cnames.map { |record| record.value.downcase }.uniq.size > 1
            @conflicts << Conflict.new(
              :cname_conflict,
              "multiple CNAME records with different targets at #{name}")
          end
          if !cnames.empty? && !others.empty?
            @conflicts << Conflict.new(
              :cname_conflict,
              "CNAME at #{name} coexists with other records")
          end
        end
      end

      def check_existing(existing)
        existing.each do |entry|
          normalized = ReverseDNS.symbolize_keys(entry)
          if normalized[:prefix]
            check_existing_delegation(normalized)
          elsif normalized[:name]
            check_existing_record(normalized)
          else
            raise Error, "existing entries need a :prefix or a :name key"
          end
        end
      end

      def check_existing_delegation(entry)
        network = ReverseDNS.parse_network(entry[:prefix])
        return unless network.class == @parent.class
        label = entry[:zone] || network.to_string
        @zones.map(&:network).each do |zone_network|
          next unless ReverseDNS.ranges_overlap?(zone_network, network)
          @conflicts << Conflict.new(
            :overlap,
            "delegation #{zone_network.to_string} overlaps existing " \
            "delegation #{label} (#{network.to_string})")
        end
      end

      def check_existing_record(entry)
        name  = entry[:name].to_s.downcase
        type  = entry[:type].to_s.upcase
        value = entry[:value].to_s
        @records.each do |record|
          next unless record.name.downcase == name
          if record.type == "CNAME"
            next if type == "CNAME" && record.value.downcase == value.downcase
            @conflicts << Conflict.new(
              :cname_conflict,
              "generated CNAME at #{record.name} conflicts with existing " \
              "#{type} record")
          elsif type == "CNAME"
            @conflicts << Conflict.new(
              :cname_conflict,
              "existing CNAME at #{record.name} conflicts with generated " \
              "#{record.type} record")
          end
        end
      end

      def zone_name_for(name)
        zone = @zones.select { |z| ReverseDNS.name_within?(name, z.name) }
                     .max_by { |z| z.name.length }
        zone && zone.name
      end

      def delegation_for(name, current_zone)
        @zones.select { |z| z.name != current_zone &&
                            ReverseDNS.name_within?(name, z.name) }
              .max_by { |z| z.name.length }
      end

      def ns_record_for(zone)
        @records.find { |record| record.type == "NS" && record.name == zone.name }
      end
    end

    #
    # Builds a reverse DNS plan.
    #
    # +parent+ is the prefix you control (a String or an IPAddress
    # object), +delegations+ an array of hashes with a :prefix and a
    # :nameservers key. The :existing option takes already published
    # delegations ({prefix:, nameservers:}) or records
    # ({name:, type:, value:}) so the plan can report overlaps and
    # CNAME conflicts instead of clobbering them.
    #
    #   plan = IPAddress::ReverseDNS.plan("2001:db8::/48", [
    #     {prefix: "2001:db8:1::/65", nameservers: ["ns1.example.com"]},
    #   ])
    #   plan.zones.size
    #     #=> 8
    #
    def self.plan(parent, delegations, options = {})
      Plan.new(parent, delegations, options)
    end

    #
    # Parses a prefix, normalizing it to its network address
    #
    def self.parse_network(obj)
      ip = obj.is_a?(String) || obj.is_a?(Integer) ? IPAddress.parse(obj) : obj
      if ip.is_a?(IPAddress::IPv6::Mapped)
        raise Error, "IPv4-mapped IPv6 addresses cannot be used for " \
                     "reverse DNS planning"
      end
      unless ip.is_a?(IPAddress::IPv4) || ip.is_a?(IPAddress::IPv6)
        raise Error, "cannot parse network #{obj.inspect}"
      end
      ip.network
    end

    #
    # Parses a single IP address
    #
    def self.coerce_address(obj)
      ip = obj.is_a?(String) || obj.is_a?(Integer) ? IPAddress.parse(obj) : obj
      unless ip.is_a?(IPAddress::IPv4) || ip.is_a?(IPAddress::IPv6)
        raise Error, "cannot parse address #{obj.inspect}"
      end
      ip
    end

    def self.normalize_delegation(delegation)
      entry = symbolize_keys(delegation)
      unless entry[:prefix]
        raise Error, "delegations need a :prefix key"
      end
      nameservers = Array(entry[:nameservers] || entry[:ns])
      if nameservers.empty? || nameservers.any? { |ns| ns.to_s.empty? }
        raise Error, "delegation #{entry[:prefix]} has no name servers"
      end
      [parse_network(entry[:prefix]), nameservers.map(&:to_s)]
    end

    def self.symbolize_keys(hash)
      unless hash.respond_to?(:each_pair)
        raise Error, "expected a Hash, got #{hash.inspect}"
      end
      hash.each_pair.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
    end

    #
    # The reverse zone name for a prefix. Non-octet IPv4 prefixes get
    # an RFC 2317 style name, IPv6 prefixes must be nibble aligned.
    #
    #   IPAddress::ReverseDNS.zone_name(IPAddress("192.0.2.0/27"))
    #     #=> "0/27.2.0.192.in-addr.arpa"
    #
    def self.zone_name(network)
      case network
      when IPAddress::IPv4
        prefix = network.prefix.to_i
        labels = network.octets[0, (prefix + 7) / 8].reverse.map(&:to_s)
        if prefix % 8 != 0 && !labels.empty?
          labels[0] = "#{labels[0]}/#{prefix}"
        end
        (labels + %w[in-addr arpa]).join(".")
      when IPAddress::IPv6
        nibbles = network.to_hex[0, network.prefix.to_i / 4].chars
        (nibbles.reverse + %w[ip6 arpa]).join(".")
      end
    end

    #
    # The owner name of the PTR record for +addr+ inside the zone
    # +zone_name+ authoritative for +zone_network+.
    #
    def self.owner_name(addr, zone_network, zone_name)
      case addr
      when IPAddress::IPv4
        rest = addr.octets[zone_network.prefix.to_i / 8..-1] || []
        (rest.reverse.map(&:to_s) + [zone_name]).join(".")
      when IPAddress::IPv6
        rest = addr.to_hex[zone_network.prefix.to_i / 4..-1].chars
        (rest.reverse + [zone_name]).join(".")
      end
    end

    #
    # Splits a prefix into the minimal set of nibble aligned blocks
    # covering exactly the same addresses.
    #
    def self.nibble_blocks(network)
      prefix = network.prefix.to_i
      nibble = (prefix + 3) / 4 * 4
      step   = 1 << (128 - nibble)
      base   = network.network_u128
      (0...(1 << (nibble - prefix))).map do |i|
        IPAddress::IPv6.parse_u128(base + i * step, nibble)
      end
    end

    def self.address_string(ip)
      ip.is_a?(IPAddress::IPv4) ? ip.address : ip.compressed
    end

    def self.first_u(network)
      network.is_a?(IPAddress::IPv4) ? network.network_u32 : network.network_u128
    end

    def self.last_u(network)
      network.is_a?(IPAddress::IPv4) ? network.broadcast_u32 : network.broadcast_u128
    end

    def self.last_of(network)
      if network.is_a?(IPAddress::IPv4)
        IPAddress::IPv4.parse_u32(network.broadcast_u32, network.prefix.to_i)
      else
        IPAddress::IPv6.parse_u128(network.broadcast_u128, network.prefix.to_i)
      end
    end

    def self.ranges_overlap?(a, b)
      first_u(a) <= last_u(b) && first_u(b) <= last_u(a)
    end

    #
    # DNS name suffix match on label boundaries
    #
    def self.name_within?(name, zone)
      name = name.downcase
      zone = zone.downcase
      name == zone || name.end_with?(".#{zone}")
    end
  end
end
