module IPAddress

  # Represents one NS, CNAME or PTR record considered by a reverse DNS plan.
  class ReverseRecord < Struct.new(:type, :name, :value, :range, :source_range)
    def to_h
      {
        :type => type.to_s.upcase,
        :name => name,
        :value => value,
        :range => range ? range.to_string : nil,
        :source_range => source_range ? source_range.to_string : nil
      }
    end
  end

  # Represents a reverse zone which can receive PTR records.
  class ReverseZone < Struct.new(:origin, :range, :source_range, :label,
                                 :ptr_mapping, :nameservers)
    def ptr_name_for(address)
      ip = IPAddress.parse(address.to_s)
      unless range.include?(ip)
        raise ArgumentError, "#{ip} is outside #{range.to_string}"
      end

      if ip.is_a?(IPv4) && label
        "#{ip.octets.last}.#{origin}"
      else
        ip.reverse
      end
    end

    def to_h
      {
        :origin => origin,
        :range => range.to_string,
        :source_range => source_range.to_string,
        :label => label,
        :ptr_mapping => ptr_mapping,
        :nameservers => nameservers
      }
    end
  end

  # Offline reverse DNS delegation plan. No DNS server is contacted.
  class ReverseDelegationPlan
    PTR_MAPPING_LIMIT = 1024

    attr_reader :parent, :parent_origin, :parent_records, :zones,
                :existing_records, :conflicts

    def initialize(parent, delegations, existing_records = [])
      @parent = parent.network
      validate_parent!
      @parent_origin = reverse_origin(@parent)

      @delegations = delegations.map { |item| normalize_delegation(item) }
      @existing_records = existing_records.flat_map { |record| normalize_record(record) }
      @parent_records = []
      @zones = []
      @conflicts = []

      build_plan
      detect_delegation_overlaps
      detect_existing_conflicts
      sort_results
    end

    def records
      parent_records
    end

    def ptr_mapping
      zones.each_with_object({}) do |zone, mapping|
        mapping.merge!(zone.ptr_mapping)
      end
    end

    def ptr_name_for(address)
      ip = IPAddress.parse(address.to_s)
      zone = zones.find { |candidate| candidate.range.include?(ip) }
      unless zone
        raise ArgumentError, "#{ip} is not covered by a delegated reverse zone"
      end
      zone.ptr_name_for(ip)
    end

    def covers?(address)
      ip = IPAddress.parse(address.to_s)
      zones.any? { |zone| zone.range.include?(ip) }
    end

    def to_h
      {
        :parent => parent.to_string,
        :parent_origin => parent_origin,
        :parent_records => parent_records.map(&:to_h),
        :zones => zones.map(&:to_h),
        :existing_records => existing_records.map(&:to_h),
        :conflicts => conflicts
      }
    end

    private

    def validate_parent!
      case parent
      when IPv4
        unless [0, 8, 16, 24].include?(parent.prefix.to_i)
          raise ArgumentError, "IPv4 reverse parent must be on an octet boundary"
        end
      when IPv6
        unless parent.prefix.to_i % 4 == 0 && parent.prefix.to_i < 128
          raise ArgumentError, "IPv6 reverse parent must be on a nibble boundary"
        end
      else
        raise ArgumentError, "parent must be an IPv4 or IPv6 subnet"
      end
    end

    def normalize_delegation(item)
      if item.is_a?(Hash)
        subnet = option_value(item, :subnet, :network, :range)
        nameservers = option_value(item, :nameservers, :ns) || []
        label = option_value(item, :label, :tag)
      else
        subnet, nameservers = item
        label = nil
      end

      subnet = subnet.is_a?(String) ? IPAddress.parse(subnet).network : subnet.network
      nameservers = Array(nameservers).map(&:to_s)
      unless parent.include?(subnet)
        raise ArgumentError, "#{subnet.to_string} is outside #{parent.to_string}"
      end
      unless subnet.prefix.to_i > parent.prefix.to_i
        raise ArgumentError, "delegated prefix must be more specific than the parent"
      end
      unless nameservers.all? { |server| server =~ /\A[\w.-]+\.?\z/ }
        raise ArgumentError, "invalid nameserver"
      end

      { :subnet => subnet, :nameservers => nameservers, :label => label }
    end

    def normalize_record(record)
      if record.is_a?(ReverseRecord)
        record.dup
      elsif delegation_record?(record)
        delegation = normalize_delegation(record)
        subnet = delegation[:subnet]
        label = delegation[:label]
        if subnet.is_a?(IPv4) && parent.prefix.to_i == 24 && subnet.prefix.to_i >= 25
          label ||= "#{subnet.octets.last}-#{subnet.prefix}"
        end
        origin = label ? "#{label}.#{parent_origin}" : reverse_origin(subnet)
        delegation[:nameservers].map do |server|
          ReverseRecord.new('NS', origin, server, subnet, subnet)
        end
      else
        type = option_value(record, :type).to_s.upcase
        name = option_value(record, :name).to_s
        value = option_value(record, :value).to_s
        range = option_value(record, :range)
        normalized_range = range ? IPAddress.parse(range.to_s).network : nil
        ReverseRecord.new(type, name, value, normalized_range, normalized_range)
      end
    rescue NoMethodError
      raise ArgumentError, "invalid reverse record: #{record.inspect}"
    end

    def delegation_record?(record)
      record.is_a?(Hash) &&
        [:subnet, :network, :range, 'subnet', 'network', 'range'].any? { |key| record.key?(key) } &&
        ![:type, 'type'].any? { |key| record.key?(key) }
    end

    def option_value(hash, *keys)
      keys.each do |key|
        return hash[key] if hash.key?(key)
        return hash[key.to_s] if hash.key?(key.to_s)
      end
      nil
    end

    def build_plan
      @delegations.each do |delegation|
        if parent.is_a?(IPv4)
          build_ipv4_delegation(delegation)
        else
          build_ipv6_delegation(delegation)
        end
      end
    end

    def build_ipv4_delegation(delegation)
      subnet = delegation[:subnet]
      prefix = subnet.prefix.to_i
      nameservers = delegation[:nameservers]

      if parent.prefix.to_i == 24 && prefix >= 25
        label = delegation[:label] || "#{subnet.octets.last}-#{prefix}"
        validate_label!(label)
        origin = "#{label}.#{parent_origin}"
        add_zone(origin, subnet, subnet, label, nameservers)

        subnet.each do |ip|
          name = ip.reverse
          target = "#{ip.octets.last}.#{origin}"
          add_record("CNAME", name, target, IPv4.parse_u32(ip.to_u32, 32), subnet)
        end

        nameservers.each do |server|
          add_record("NS", origin, server, subnet)
        end
      else
        unless prefix % 8 == 0
          raise ArgumentError,
                "RFC 2317 delegation from #{parent.to_string} is only supported on a /24 parent"
        end

        origin = reverse_origin(subnet)
        add_zone(origin, subnet, subnet, nil, nameservers)
        nameservers.each do |server|
          add_record("NS", origin, server, subnet)
        end
      end
    end

    def build_ipv6_delegation(delegation)
      subnet = delegation[:subnet]
      prefix = subnet.prefix.to_i
      nameservers = delegation[:nameservers]

      if prefix % 4 != 0
        aligned_prefix = (prefix + 3) & ~3
        unless aligned_prefix < 128
          raise ArgumentError, "IPv6 delegation cannot be split beyond /124"
        end

        block_network = parent.network_u128 +
                        ((subnet.network_u128 - parent.network_u128) / (2 ** (128 - aligned_prefix))) *
                        (2 ** (128 - aligned_prefix))

        count = 2 ** (aligned_prefix - prefix)
        count.times do |index|
          piece = IPv6.parse_u128(block_network + index * (2 ** (128 - aligned_prefix)), aligned_prefix)
          unless subnet.include?(piece)
            raise ArgumentError, "invalid IPv6 nibble split"
          end
          add_ipv6_zone(piece, subnet, nameservers)
        end
      else
        unless prefix < 128
          raise ArgumentError, "IPv6 reverse zones cannot be delegated at /128"
        end
        add_ipv6_zone(subnet, subnet, nameservers)
      end
    end

    def add_ipv6_zone(subnet, source_subnet, nameservers)
      origin = reverse_origin(subnet)
      add_zone(origin, subnet, source_subnet, nil, nameservers)
      nameservers.each do |server|
        add_record("NS", origin, server, subnet, source_subnet)
      end
    end

    def add_zone(origin, range, source_range, label, nameservers)
      mapping = if range.size <= PTR_MAPPING_LIMIT
                  range.each_with_object({}) do |ip, result|
                    result[ip.to_s] = reverse_ptr_name(ip, origin, label)
                  end
                else
                  {}
                end

      zones << ReverseZone.new(origin, range, source_range, label, mapping, nameservers)
    end

    def reverse_ptr_name(ip, origin, label)
      if ip.is_a?(IPv4) && label
        "#{ip.octets.last}.#{origin}"
      else
        ip.reverse
      end
    end

    def reverse_origin(subnet)
      if subnet.is_a?(IPv4)
        octets = subnet.octets[0...(subnet.prefix.to_i / 8)].reverse
        prefix = octets.empty? ? '' : octets.join('.') + '.'
        "#{prefix}in-addr.arpa"
      else
        nibbles = subnet.to_hex[0...(subnet.prefix.to_i / 4)].reverse.chars
        prefix = nibbles.empty? ? '' : nibbles.join('.') + '.'
        "#{prefix}ip6.arpa"
      end
    end

    def add_record(type, name, value, range, source_range = nil)
      range = range.network
      source_range = (source_range || range).network
      parent_records << ReverseRecord.new(type, name, value, range, source_range)
    end

    def validate_label!(label)
      unless label =~ /\A[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\z/
        raise ArgumentError, "invalid RFC2317 label: #{label}"
      end
    end

    def detect_delegation_overlaps
      zones.to_a.combination(2) do |left, right|
        next unless ranges_overlap?(left.range, right.range)

        add_conflict("overlap", left.range, right.range,
                     "delegated zones overlap")
      end
    end

    def detect_existing_conflicts
      zones.each do |zone|
        @existing_records.each do |record|
          next unless record.range && ranges_overlap?(zone.range, record.range)
          next if compatible_existing_record?(zone, record)

          add_conflict(conflict_type(zone, record), zone.range, record.range,
                       "#{record.type} #{record.name} conflicts with delegation")
        end
      end
    end

    def compatible_existing_record?(zone, record)
      case record.type
      when "NS"
        record.name == zone.origin && zone.nameservers.include?(record.value)
      when "CNAME"
        parent_records.any? do |planned|
          planned.type == "CNAME" &&
            planned.name == record.name &&
            planned.value == record.value
        end
      else
        false
      end
    end

    def conflict_type(zone, record)
      return "cname_conflict" if record.type == "CNAME"
      "overlap"
    end

    def add_conflict(type, left, right, message)
      conflicts << {
        :type => type,
        :ranges => [left.to_string, right.to_string],
        :message => message
      }
    end

    def ranges_overlap?(left, right)
      return false unless (left.is_a?(IPv4) && right.is_a?(IPv4)) ||
                          (left.is_a?(IPv6) && right.is_a?(IPv6))

      left.network_u128 <= right.broadcast_u128 &&
        right.network_u128 <= left.broadcast_u128
    rescue NoMethodError
      left.network_u32 <= right.broadcast_u32 &&
        right.network_u32 <= left.broadcast_u32
    end

    def sort_results
      parent_records.sort_by! { |record| [record.name, record.type, record.value] }
      parent_records.uniq! { |record| [record.type, record.name, record.value] }
      zones.sort_by! { |zone| [zone.range.to_i, zone.origin] }
      conflicts.uniq!
    end
  end

  def self.plan_reverse_delegation(parent, delegations = [], options = {})
    parent_subnet = parent.is_a?(String) ? parse(parent) : parent
    existing = options[:existing_records] || options[:existing] || []
    ReverseDelegationPlan.new(parent_subnet, delegations, Array(existing))
  end

end

class IPAddress::IPv4
  def plan_reverse_delegation(delegations = [], options = {})
    IPAddress.plan_reverse_delegation(self, delegations, options)
  end
end

class IPAddress::IPv6
  def plan_reverse_delegation(delegations = [], options = {})
    IPAddress.plan_reverse_delegation(self, delegations, options)
  end
end
