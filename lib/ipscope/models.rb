# frozen_string_literal: true

module IpScope
  # Geographic location intelligence block.
  class GeoBlock
    attr_reader :country_code, :country_name, :region_code, :region_name,
                :city, :postal_code, :latitude, :longitude, :timezone,
                :accuracy_radius_km

    def initialize(
      country_code: nil,
      country_name: nil,
      region_code: nil,
      region_name: nil,
      city: nil,
      postal_code: nil,
      latitude: nil,
      longitude: nil,
      timezone: nil,
      accuracy_radius_km: nil
    )
      @country_code = country_code&.to_s&.freeze
      @country_name = country_name&.to_s&.freeze
      @region_code = region_code&.to_s&.freeze
      @region_name = region_name&.to_s&.freeze
      @city = city&.to_s&.freeze
      @postal_code = postal_code&.to_s&.freeze
      @latitude = latitude.nil? ? nil : latitude.to_f
      @longitude = longitude.nil? ? nil : longitude.to_f
      @timezone = timezone&.to_s&.freeze
      @accuracy_radius_km = accuracy_radius_km.nil? ? nil : accuracy_radius_km.to_i
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        country_code: h["country_code"],
        country_name: h["country_name"],
        region_code: h["region_code"],
        region_name: h["region_name"],
        city: h["city"],
        postal_code: h["postal_code"],
        latitude: h["latitude"],
        longitude: h["longitude"],
        timezone: h["timezone"],
        accuracy_radius_km: h["accuracy_radius_km"]
      )
    end
  end

  # Autonomous System (ASN) and BGP prefix block.
  class NetworkBlock
    attr_reader :asn, :asn_name, :org, :isp, :connection_type, :bgp_prefix, :rir

    def initialize(
      asn: nil,
      asn_name: nil,
      org: nil,
      isp: nil,
      connection_type: nil,
      bgp_prefix: nil,
      rir: nil
    )
      @asn = asn.nil? ? nil : asn.to_i
      @asn_name = asn_name&.to_s&.freeze
      @org = org&.to_s&.freeze
      @isp = isp&.to_s&.freeze
      @connection_type = connection_type&.to_s&.freeze
      @bgp_prefix = bgp_prefix&.to_s&.freeze
      @rir = rir&.to_s&.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        asn: h["asn"],
        asn_name: h["asn_name"],
        org: h["org"],
        isp: h["isp"],
        connection_type: h["connection_type"],
        bgp_prefix: h["bgp_prefix"],
        rir: h["rir"]
      )
    end
  end

  # Anonymity, proxy, VPN, Tor, and threat intelligence block.
  class SecurityBlock
    attr_reader :is_vpn, :is_proxy, :is_tor, :is_datacenter, :is_relay,
                :threat_level, :threat_types

    def initialize(
      is_vpn: false,
      is_proxy: false,
      is_tor: false,
      is_datacenter: false,
      is_relay: false,
      threat_level: "low",
      threat_types: []
    )
      @is_vpn = !!is_vpn
      @is_proxy = !!is_proxy
      @is_tor = !!is_tor
      @is_datacenter = !!is_datacenter
      @is_relay = !!is_relay
      @threat_level = (threat_level || "low").to_s.freeze
      @threat_types = Array(threat_types).map { |t| t.to_s.freeze }.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        is_vpn: h["is_vpn"],
        is_proxy: h["is_proxy"],
        is_tor: h["is_tor"],
        is_datacenter: h["is_datacenter"],
        is_relay: h["is_relay"],
        threat_level: h["threat_level"] || "low",
        threat_types: h["threat_types"].is_a?(Array) ? h["threat_types"] : []
      )
    end
  end

  # Detailed connection and carrier classification block.
  class ConnectionBlock
    attr_reader :usage_type, :company_type, :carrier_name, :mcc, :mnc,
                :domain, :route, :allocated_date, :registry_status

    def initialize(
      usage_type: nil,
      company_type: nil,
      carrier_name: nil,
      mcc: nil,
      mnc: nil,
      domain: nil,
      route: nil,
      allocated_date: nil,
      registry_status: nil
    )
      @usage_type = usage_type&.to_s&.freeze
      @company_type = company_type&.to_s&.freeze
      @carrier_name = carrier_name&.to_s&.freeze
      @mcc = mcc&.to_s&.freeze
      @mnc = mnc&.to_s&.freeze
      @domain = domain&.to_s&.freeze
      @route = route&.to_s&.freeze
      @allocated_date = allocated_date&.to_s&.freeze
      @registry_status = registry_status&.to_s&.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        usage_type: h["usage_type"],
        company_type: h["company_type"],
        carrier_name: h["carrier_name"],
        mcc: h["mcc"],
        mnc: h["mnc"],
        domain: h["domain"],
        route: h["route"],
        allocated_date: h["allocated_date"],
        registry_status: h["registry_status"]
      )
    end
  end

  # Extended threat scoring and provider attribution block.
  class SecurityExtensionsBlock
    attr_reader :vpn_provider, :proxy_type, :threat_score, :is_abuser, :is_bot, :is_bogon

    def initialize(
      vpn_provider: nil,
      proxy_type: nil,
      threat_score: nil,
      is_abuser: false,
      is_bot: false,
      is_bogon: false
    )
      @vpn_provider = vpn_provider&.to_s&.freeze
      @proxy_type = proxy_type&.to_s&.freeze
      @threat_score = threat_score.nil? ? nil : threat_score.to_i
      @is_abuser = !!is_abuser
      @is_bot = !!is_bot
      @is_bogon = !!is_bogon
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        vpn_provider: h["vpn_provider"],
        proxy_type: h["proxy_type"],
        threat_score: h["threat_score"],
        is_abuser: h["is_abuser"],
        is_bot: h["is_bot"],
        is_bogon: h["is_bogon"]
      )
    end
  end

  # Canonical IP intelligence response returned by `/v1/ip` and `/v1/ip/{ip}`.
  class IpLookupResponse
    attr_reader :ip, :version, :is_bogon, :bogon_type, :geo, :network,
                :security, :connection, :security_extensions, :updated_at

    def initialize(
      ip:,
      version:,
      is_bogon:,
      bogon_type:,
      geo:,
      network:,
      security:,
      connection: nil,
      security_extensions: nil,
      updated_at: ""
    )
      @ip = ip.to_s.freeze
      @version = version.to_i
      @is_bogon = !!is_bogon
      @bogon_type = bogon_type&.to_s&.freeze
      @geo = geo
      @network = network
      @security = security
      @connection = connection
      @security_extensions = security_extensions
      @updated_at = updated_at.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        ip: h["ip"] || "",
        version: h["version"] || 4,
        is_bogon: h["is_bogon"] || false,
        bogon_type: h["bogon_type"],
        geo: GeoBlock.from_h(h["geo"]),
        network: NetworkBlock.from_h(h["network"]),
        security: SecurityBlock.from_h(h["security"]),
        connection: h["connection"].is_a?(Hash) ? ConnectionBlock.from_h(h["connection"]) : nil,
        security_extensions: h["security_extensions"].is_a?(Hash) ? SecurityExtensionsBlock.from_h(h["security_extensions"]) : nil,
        updated_at: h["updated_at"] || ""
      )
    end
  end

  # Batch IP lookup response returned by `POST /v1/ip/batch`.
  class BatchLookupResponse
    attr_reader :count, :results

    def initialize(count:, results:)
      @results = Array(results).freeze
      @count = count ? count.to_i : @results.length
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      raw_list = h["results"].is_a?(Array) ? h["results"] : []
      records = raw_list.select { |item| item.is_a?(Hash) }.map { |item| IpLookupResponse.from_h(item) }
      new(
        count: h["count"] || records.length,
        results: records
      )
    end
  end

  # Canonical BGP/CIDR prefix intelligence record.
  class CanonicalNetworkPrefixRecord
    attr_reader :network_cidr, :ip_version, :geo, :network, :security,
                :connection, :security_extensions, :updated_at

    def initialize(
      network_cidr:,
      ip_version:,
      geo:,
      network:,
      security:,
      connection: nil,
      security_extensions: nil,
      updated_at: ""
    )
      @network_cidr = network_cidr.to_s.freeze
      @ip_version = ip_version.to_i
      @geo = geo
      @network = network
      @security = security
      @connection = connection
      @security_extensions = security_extensions
      @updated_at = updated_at.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        network_cidr: h["network_cidr"] || "",
        ip_version: h["ip_version"] || 4,
        geo: GeoBlock.from_h(h["geo"]),
        network: NetworkBlock.from_h(h["network"]),
        security: SecurityBlock.from_h(h["security"]),
        connection: h["connection"].is_a?(Hash) ? ConnectionBlock.from_h(h["connection"]) : nil,
        security_extensions: h["security_extensions"].is_a?(Hash) ? SecurityExtensionsBlock.from_h(h["security_extensions"]) : nil,
        updated_at: h["updated_at"] || ""
      )
    end
  end

  # Network CIDR lookup response returned by `GET /v1/network/{address}/{prefixLength}`.
  class NetworkPrefixLookupResponse
    attr_reader :requested_cidr, :exact_match, :enclosing_prefix,
                :overlapping_prefixes, :total_matches

    def initialize(
      requested_cidr:,
      exact_match:,
      enclosing_prefix:,
      overlapping_prefixes:,
      total_matches:
    )
      @requested_cidr = requested_cidr.to_s.freeze
      @exact_match = exact_match
      @enclosing_prefix = enclosing_prefix
      @overlapping_prefixes = Array(overlapping_prefixes).freeze
      @total_matches = total_matches.to_i
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      overlaps = (h["overlapping_prefixes"].is_a?(Array) ? h["overlapping_prefixes"] : [])
                 .select { |item| item.is_a?(Hash) }
                 .map { |item| CanonicalNetworkPrefixRecord.from_h(item) }
      new(
        requested_cidr: h["requested_cidr"] || "",
        exact_match: h["exact_match"].is_a?(Hash) ? CanonicalNetworkPrefixRecord.from_h(h["exact_match"]) : nil,
        enclosing_prefix: h["enclosing_prefix"].is_a?(Hash) ? CanonicalNetworkPrefixRecord.from_h(h["enclosing_prefix"]) : nil,
        overlapping_prefixes: overlaps,
        total_matches: h["total_matches"] || overlaps.length
      )
    end
  end

  # Snapshot metadata for a single IP intelligence dataset source.
  class DatasetSnapshotSummary
    attr_reader :source, :version_tag, :checksum_sha256, :record_count,
                :activated_at, :created_at

    def initialize(
      source:,
      version_tag:,
      checksum_sha256:,
      record_count:,
      activated_at:,
      created_at:
    )
      @source = source.to_s.freeze
      @version_tag = version_tag.to_s.freeze
      @checksum_sha256 = checksum_sha256.to_s.freeze
      @record_count = record_count.to_i
      @activated_at = activated_at&.to_s&.freeze
      @created_at = created_at.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        source: h["source"] || "",
        version_tag: h["version_tag"] || "",
        checksum_sha256: h["checksum_sha256"] || "",
        record_count: h["record_count"] || 0,
        activated_at: h["activated_at"],
        created_at: h["created_at"] || ""
      )
    end
  end

  # Active dataset snapshots metadata returned by `GET /v1/datasets/metadata`.
  class DatasetsMetadataResponse
    attr_reader :count, :active_datasets

    def initialize(count:, active_datasets:)
      @active_datasets = Array(active_datasets).freeze
      @count = count ? count.to_i : @active_datasets.length
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      datasets = (h["active_datasets"].is_a?(Array) ? h["active_datasets"] : [])
                 .select { |item| item.is_a?(Hash) }
                 .map { |item| DatasetSnapshotSummary.from_h(item) }
      new(
        count: h["count"] || datasets.length,
        active_datasets: datasets
      )
    end
  end

  # Payload for submitting an IP geolocation or anonymity correction (`POST /v1/feedback`).
  class FeedbackSubmissionInput
    attr_reader :ip_or_cidr, :suggested_country_code, :suggested_region_name,
                :suggested_city, :suggested_is_vpn, :notes, :contact_email

    def initialize(
      ip_or_cidr:,
      suggested_country_code: nil,
      suggested_region_name: nil,
      suggested_city: nil,
      suggested_is_vpn: nil,
      notes: nil,
      contact_email: nil
    )
      @ip_or_cidr = ip_or_cidr.to_s.freeze
      @suggested_country_code = suggested_country_code&.to_s&.freeze
      @suggested_region_name = suggested_region_name&.to_s&.freeze
      @suggested_city = suggested_city&.to_s&.freeze
      @suggested_is_vpn = suggested_is_vpn.nil? ? nil : !!suggested_is_vpn
      @notes = notes&.to_s&.freeze
      @contact_email = contact_email&.to_s&.freeze
      freeze
    end

    def to_h
      payload = { "ip_or_cidr" => @ip_or_cidr }
      payload["suggested_country_code"] = @suggested_country_code unless @suggested_country_code.nil?
      payload["suggested_region_name"] = @suggested_region_name unless @suggested_region_name.nil?
      payload["suggested_city"] = @suggested_city unless @suggested_city.nil?
      payload["suggested_is_vpn"] = @suggested_is_vpn unless @suggested_is_vpn.nil?
      payload["notes"] = @notes unless @notes.nil?
      payload["contact_email"] = @contact_email unless @contact_email.nil?
      payload
    end
  end

  # Feedback submission acknowledgment returned by `POST /v1/feedback`.
  class FeedbackSubmissionResponse
    attr_reader :id, :ip_or_cidr, :status, :created_at

    def initialize(id:, ip_or_cidr:, status:, created_at:)
      @id = id.to_s.freeze
      @ip_or_cidr = ip_or_cidr.to_s.freeze
      @status = status.to_s.freeze
      @created_at = created_at.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        id: h["id"] || "",
        ip_or_cidr: h["ip_or_cidr"] || "",
        status: h["status"] || "",
        created_at: h["created_at"] || ""
      )
    end
  end

  # Service health status returned by `GET /v1/status`.
  class ServiceStatusResponse
    attr_reader :status, :service, :version, :uptime_seconds, :timestamp

    def initialize(status:, service:, version:, uptime_seconds:, timestamp:)
      @status = status.to_s.freeze
      @service = service.to_s.freeze
      @version = version.to_s.freeze
      @uptime_seconds = uptime_seconds.to_f
      @timestamp = timestamp.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = raw.is_a?(Hash) ? raw : {}
      new(
        status: h["status"] || "",
        service: h["service"] || "",
        version: h["version"] || "",
        uptime_seconds: h["uptime_seconds"] || 0.0,
        timestamp: h["timestamp"] || ""
      )
    end
  end

  # Rate-limit and quota metadata extracted from `x-ratelimit-*` HTTP response headers.
  class RateLimitMetadata
    attr_reader :limit, :remaining, :reset_epoch_seconds, :credits_remaining, :plan_tier

    def initialize(
      limit: nil,
      remaining: nil,
      reset_epoch_seconds: nil,
      credits_remaining: nil,
      plan_tier: nil
    )
      @limit = limit.nil? ? nil : limit.to_i
      @remaining = remaining.nil? ? nil : remaining.to_i
      @reset_epoch_seconds = reset_epoch_seconds.nil? ? nil : reset_epoch_seconds.to_i
      @credits_remaining = credits_remaining.nil? ? nil : credits_remaining.to_i
      @plan_tier = plan_tier&.to_s&.freeze
      freeze
    end
  end

  # Wrapper pairing a response payload with rate-limit metadata and cache hit status.
  class IpScopeResultWithMeta
    attr_reader :data, :rate_limit, :from_cache

    def initialize(data:, rate_limit:, from_cache:)
      @data = data
      @rate_limit = rate_limit
      @from_cache = !!from_cache
      freeze
    end
  end

  # Snapshot of in-memory LRU cache statistics.
  class CacheStats
    attr_reader :enabled, :size, :max_entries, :hits, :misses, :evictions

    def initialize(enabled:, size:, max_entries:, hits:, misses:, evictions:)
      @enabled = !!enabled
      @size = size.to_i
      @max_entries = max_entries.to_i
      @hits = hits.to_i
      @misses = misses.to_i
      @evictions = evictions.to_i
      freeze
    end
  end

  # Retry configuration for transient HTTP errors (`429`, `502`, `503`, `504`).
  class RetryOptions
    attr_reader :max_retries, :initial_delay_seconds, :max_delay_seconds

    def initialize(max_retries: 2, initial_delay_seconds: 0.25, max_delay_seconds: 4.0)
      @max_retries = max_retries.to_i
      @initial_delay_seconds = initial_delay_seconds.to_f
      @max_delay_seconds = max_delay_seconds.to_f
      freeze
    end
  end

  # Bounded LRU + TTL cache configuration (`max_entries: 512` default `< 400 KB`).
  class CacheOptions
    attr_reader :enabled, :max_entries, :ttl_seconds

    def initialize(enabled: true, max_entries: 512, ttl_seconds: 60.0)
      @enabled = !!enabled
      @max_entries = max_entries.to_i
      @ttl_seconds = ttl_seconds.to_f
      freeze
    end
  end

  # Per-request options.
  class RequestOptions
    attr_reader :bypass_cache, :timeout_seconds, :headers

    def initialize(bypass_cache: false, timeout_seconds: nil, headers: {})
      @bypass_cache = !!bypass_cache
      @timeout_seconds = timeout_seconds.nil? ? nil : timeout_seconds.to_f
      @headers = (headers || {}).each_with_object({}) { |(k, v), acc| acc[k.to_s] = v.to_s }.freeze
      freeze
    end
  end
end
