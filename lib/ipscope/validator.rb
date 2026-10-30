# frozen_string_literal: true

require "ipaddr"
require "resolv"

module IpScope
  # Zero-DNS client-side validator for IPv4/IPv6 addresses, CIDR prefixes, and API keys.
  module Validator
    MAX_BATCH_SIZE = 100

    module_function

    def validate_api_key(api_key)
      trimmed = api_key.to_s.strip
      if trimmed.empty? || trimmed.length < 8
        raise IpScopeValidationError.new(
          'A valid IPScope API key ("<public>:<private>") is required.',
          field: "api_key"
        )
      end
      trimmed
    end

    # Validates and canonicalizes an IPv4 or IPv6 literal without performing DNS resolution.
    def validate_ip_address(ip, field_name = "ip")
      unless ip.is_a?(String)
        raise IpScopeValidationError.new("IP address must be a non-empty string.", field: field_name)
      end

      trimmed = ip.strip
      if trimmed.empty?
        raise IpScopeValidationError.new("IP address must be a non-empty string.", field: field_name)
      end

      # Strip optional IPv6 zone identifier (%eth0)
      clean = trimmed.split("%", 2).first.to_s
      if clean.include?("/") || !(Resolv::IPv4::Regex.match?(clean) || Resolv::IPv6::Regex.match?(clean))
        raise IpScopeValidationError.new(
          format('Invalid IPv4 or IPv6 address: "%s".', trimmed),
          field: field_name
        )
      end

      begin
        parsed = IPAddr.new(clean)
        parsed.to_s
      rescue IPAddr::Error
        raise IpScopeValidationError.new(
          format('Invalid IPv4 or IPv6 address: "%s".', trimmed),
          field: field_name
        )
      end
    end

    # Validates and normalizes a CIDR prefix (`8.8.8.0/24` or `2001:4860::/32`).
    # Returns `{ address: String, prefix_length: Integer, canonical_cidr: String }`.
    def validate_cidr_prefix(cidr)
      trimmed = cidr.to_s.strip
      parts = trimmed.split("/", -1)
      if parts.length != 2
        raise IpScopeValidationError.new(
          format('Invalid CIDR notation "%s". Expected "<ip>/<prefixLength>" (e.g. "8.8.8.0/24").', cidr),
          field: "cidr"
        )
      end

      raw_address = parts[0].strip
      raw_prefix = parts[1].strip

      if raw_prefix.empty? || !/\A\d+\z/.match?(raw_prefix)
        raise IpScopeValidationError.new(
          format('Invalid prefix length in CIDR "%s".', cidr),
          field: "cidr"
        )
      end

      unless Resolv::IPv4::Regex.match?(raw_address) || Resolv::IPv6::Regex.match?(raw_address)
        raise IpScopeValidationError.new(
          format('Invalid network IP address in CIDR "%s".', cidr),
          field: "cidr"
        )
      end

      begin
        base_ip = IPAddr.new(raw_address)
      rescue IPAddr::Error
        raise IpScopeValidationError.new(
          format('Invalid network IP address in CIDR "%s".', cidr),
          field: "cidr"
        )
      end

      prefix_len = raw_prefix.to_i
      max_bits = base_ip.ipv4? ? 32 : 128
      if prefix_len.negative? || prefix_len > max_bits
        raise IpScopeValidationError.new(
          format('Prefix length %d is out of range (0..%d) for "%s".', prefix_len, max_bits, cidr),
          field: "cidr"
        )
      end

      masked_ip = base_ip.mask(prefix_len)
      network_addr = masked_ip.to_s
      {
        address: network_addr,
        prefix_length: prefix_len,
        canonical_cidr: "#{network_addr}/#{prefix_len}"
      }
    end

    # Validates and deduplicates a batch of IP addresses (`1..100` items by default).
    def validate_and_deduplicate_batch_ips(ips, max_size = MAX_BATCH_SIZE)
      unless ips.is_a?(Array) && !ips.empty?
        raise IpScopeValidationError.new(
          "Batch IP list must contain at least 1 IP address.",
          field: "ips"
        )
      end

      unique = []
      seen = {}

      ips.each_with_index do |raw, idx|
        unless raw.is_a?(String)
          raise IpScopeValidationError.new(
            format("Expected String at ips[%d].", idx),
            field: format("ips[%d]", idx)
          )
        end

        canonical = validate_ip_address(raw, format("ips[%d]", idx))
        next if seen.key?(canonical)

        seen[canonical] = true
        unique << canonical
      end

      if unique.length > max_size
        raise IpScopeValidationError.new(
          format(
            "Batch IP list exceeds maximum of %d unique IPs (%d provided). Use lookup_batch_chunked or lookup_batch_stream for larger lists.",
            max_size,
            unique.length
          ),
          field: "ips"
        )
      end

      unique
    end
  end
end
