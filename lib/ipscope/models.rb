# frozen_string_literal: true

module IpScope
  # Lenient JSON value casting shared by the response models.
  # @api private
  module ModelCast
    module_function

    def as_hash(raw)
      raw.is_a?(Hash) ? raw : {}
    end

    def obj(raw, key)
      v = raw[key]
      v.is_a?(Hash) ? v : nil
    end

    def str(raw, key)
      v = raw[key]
      return nil if v.nil? || v.is_a?(Hash) || v.is_a?(Array)

      v.to_s.freeze
    end

    def int(raw, key)
      v = raw[key]
      v.is_a?(Numeric) ? v.to_i : nil
    end

    def float(raw, key)
      v = raw[key]
      v.is_a?(Numeric) ? v.to_f : nil
    end

    # Numeric value kept as sent: an Integer stays Integer, a fraction stays Float.
    def number(raw, key)
      v = raw[key]
      v.is_a?(Numeric) ? v : nil
    end

    # Tri-state boolean: true, false, or nil when the API abstains or omits the field.
    def bool(raw, key)
      v = raw[key]
      v == true || v == false ? v : nil
    end

    def str_list(raw, key)
      v = raw[key]
      return [].freeze unless v.is_a?(Array)

      v.reject { |item| item.is_a?(Hash) || item.is_a?(Array) || item.nil? }.map { |item| item.to_s.freeze }.freeze
    end

    # Prints a deprecation warning pointing at the caller (silenced by `ruby -W0`, i.e. `$VERBOSE = nil`).
    def deprecated(klass, old, new_name)
      return if $VERBOSE.nil?

      warn("[ipscope] #{klass}##{old} is deprecated since 1.1.0; use ##{new_name}.", uplevel: 2)
    end
  end

  # Geographic block (`geo`) of a lookup response.
  class GeoBlock
    attr_reader :country_code, :subdivision, :city, :postal_code, :latitude, :longitude,
                :timezone, :location_type, :confidence, :accuracy_radius_km,
                :declared_country_code, :physical_country_code, :is_virtual_location

    def initialize(
      country_code: nil,
      subdivision: nil,
      city: nil,
      postal_code: nil,
      latitude: nil,
      longitude: nil,
      timezone: nil,
      location_type: "unknown",
      confidence: 0.0,
      accuracy_radius_km: nil,
      declared_country_code: nil,
      physical_country_code: nil,
      is_virtual_location: nil
    )
      @country_code = country_code
      @subdivision = subdivision
      @city = city
      @postal_code = postal_code
      @latitude = latitude
      @longitude = longitude
      @timezone = timezone
      @location_type = location_type
      @confidence = confidence
      @accuracy_radius_km = accuracy_radius_km
      @declared_country_code = declared_country_code
      @physical_country_code = physical_country_code
      @is_virtual_location = is_virtual_location
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        country_code: ModelCast.str(h, "country_code"),
        subdivision: ModelCast.str(h, "subdivision"),
        city: ModelCast.str(h, "city"),
        postal_code: ModelCast.str(h, "postal_code"),
        latitude: ModelCast.float(h, "latitude"),
        longitude: ModelCast.float(h, "longitude"),
        timezone: ModelCast.str(h, "timezone"),
        location_type: ModelCast.str(h, "location_type") || "unknown",
        confidence: ModelCast.float(h, "confidence") || 0.0,
        accuracy_radius_km: ModelCast.float(h, "accuracy_radius_km"),
        declared_country_code: ModelCast.str(h, "declared_country_code"),
        physical_country_code: ModelCast.str(h, "physical_country_code"),
        is_virtual_location: ModelCast.bool(h, "is_virtual_location")
      )
    end
  end

  # Autonomous System block (`network`) of a lookup response.
  class NetworkBlock
    attr_reader :asn, :organization

    def initialize(asn: nil, organization: nil)
      @asn = asn
      @organization = organization
      freeze
    end

    # @deprecated since 1.1.0; use {#organization}.
    def org
      ModelCast.deprecated(self.class, "org", "organization")
      @organization
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(asn: ModelCast.int(h, "asn"), organization: ModelCast.str(h, "organization"))
    end
  end

  # Security and anonymity block (`security`) of a lookup response.
  # Booleans are nil when the API has insufficient evidence (never a silent false).
  class SecurityBlock
    attr_reader :is_vpn, :is_hosting, :is_tor_exit, :is_proxy, :is_relay,
                :anonymizer_type, :confidence, :reason_codes

    def initialize(
      is_vpn: nil,
      is_hosting: nil,
      is_tor_exit: nil,
      is_proxy: nil,
      is_relay: nil,
      anonymizer_type: "unknown",
      confidence: 0.0,
      reason_codes: []
    )
      @is_vpn = is_vpn
      @is_hosting = is_hosting
      @is_tor_exit = is_tor_exit
      @is_proxy = is_proxy
      @is_relay = is_relay
      @anonymizer_type = anonymizer_type
      @confidence = confidence
      @reason_codes = Array(reason_codes).freeze
      freeze
    end

    # @deprecated since 1.1.0; use {#is_tor_exit}.
    def is_tor
      ModelCast.deprecated(self.class, "is_tor", "is_tor_exit")
      @is_tor_exit
    end

    # @deprecated since 1.1.0; use {#is_hosting}.
    def is_datacenter
      ModelCast.deprecated(self.class, "is_datacenter", "is_hosting")
      @is_hosting
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        is_vpn: ModelCast.bool(h, "is_vpn"),
        is_hosting: ModelCast.bool(h, "is_hosting"),
        is_tor_exit: ModelCast.bool(h, "is_tor_exit"),
        is_proxy: ModelCast.bool(h, "is_proxy"),
        is_relay: ModelCast.bool(h, "is_relay"),
        anonymizer_type: ModelCast.str(h, "anonymizer_type") || "unknown",
        confidence: ModelCast.float(h, "confidence") || 0.0,
        reason_codes: ModelCast.str_list(h, "reason_codes")
      )
    end
  end

  # Connection context block (`connection`), present only when the `connection` field family is licensed.
  class ConnectionBlock
    attr_reader :connection_type, :is_residential, :is_mobile, :is_business, :is_hosting

    def initialize(connection_type: "unknown", is_residential: nil, is_mobile: nil, is_business: nil, is_hosting: nil)
      @connection_type = connection_type
      @is_residential = is_residential
      @is_mobile = is_mobile
      @is_business = is_business
      @is_hosting = is_hosting
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        connection_type: ModelCast.str(h, "connection_type") || "unknown",
        is_residential: ModelCast.bool(h, "is_residential"),
        is_mobile: ModelCast.bool(h, "is_mobile"),
        is_business: ModelCast.bool(h, "is_business"),
        is_hosting: ModelCast.bool(h, "is_hosting")
      )
    end
  end

  # Security extensions block (`security_extensions`), present only when that field family is licensed.
  class SecurityExtensionsBlock
    # Abuse reputation / velocity score, or nil. The API contract defines an Integer 0..100
    # (higher is worse); API releases before that change serve a Float in 0.0..1.0. The value
    # is passed through unchanged, so check which form you got.
    attr_reader :abuse_velocity_score
    attr_reader :is_known_scanner, :observation_recency_hours

    def initialize(abuse_velocity_score: nil, is_known_scanner: nil, observation_recency_hours: nil)
      @abuse_velocity_score = abuse_velocity_score
      @is_known_scanner = is_known_scanner
      @observation_recency_hours = observation_recency_hours
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        abuse_velocity_score: ModelCast.number(h, "abuse_velocity_score"),
        is_known_scanner: ModelCast.bool(h, "is_known_scanner"),
        observation_recency_hours: ModelCast.float(h, "observation_recency_hours")
      )
    end
  end

  # Canonical IP lookup response (`GET /v1/ip/{ip}`, `GET /v1/ip/me`).
  class IpLookupResponse
    attr_reader :ip, :ip_version, :matched_network, :geo, :network, :security,
                :connection, :security_extensions, :dataset_version, :updated_at

    def initialize(
      ip:,
      ip_version:,
      geo:,
      network:,
      security:,
      matched_network: nil,
      connection: nil,
      security_extensions: nil,
      dataset_version: "",
      updated_at: nil
    )
      @ip = ip.to_s.freeze
      @ip_version = ip_version.to_i
      @matched_network = matched_network
      @geo = geo
      @network = network
      @security = security
      @connection = connection
      @security_extensions = security_extensions
      @dataset_version = dataset_version.to_s.freeze
      @updated_at = updated_at
      freeze
    end

    # @deprecated since 1.1.0; use {#ip_version}.
    def version
      ModelCast.deprecated(self.class, "version", "ip_version")
      @ip_version
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      ip = ModelCast.str(h, "ip") || ""
      connection = ModelCast.obj(h, "connection")
      extensions = ModelCast.obj(h, "security_extensions")
      new(
        ip: ip,
        ip_version: ModelCast.int(h, "ip_version") || (ip.include?(":") ? 6 : 4),
        matched_network: ModelCast.str(h, "matched_network"),
        geo: GeoBlock.from_h(h["geo"]),
        network: NetworkBlock.from_h(h["network"]),
        security: SecurityBlock.from_h(h["security"]),
        connection: connection ? ConnectionBlock.from_h(connection) : nil,
        security_extensions: extensions ? SecurityExtensionsBlock.from_h(extensions) : nil,
        dataset_version: ModelCast.str(h, "dataset_version") || "",
        updated_at: ModelCast.str(h, "updated_at")
      )
    end
  end

  # Batch IP lookup response (`POST /v1/ip/batch`).
  class BatchLookupResponse
    attr_reader :count, :results, :dataset_version

    def initialize(count:, results:, dataset_version: "")
      @results = Array(results).freeze
      @count = count ? count.to_i : @results.length
      @dataset_version = dataset_version.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      raw_list = h["results"].is_a?(Array) ? h["results"] : []
      records = raw_list.select { |item| item.is_a?(Hash) }.map { |item| IpLookupResponse.from_h(item) }
      new(
        count: ModelCast.int(h, "count") || records.length,
        results: records,
        dataset_version: ModelCast.str(h, "dataset_version") || ""
      )
    end
  end

  # A structured geographic assertion inside a canonical network record (camelCase on the wire).
  class LocationAssertion
    attr_reader :country_code, :country_name, :subdivision, :city, :latitude, :longitude,
                :accuracy_radius_km, :timezone

    def initialize(country_code: nil, country_name: nil, subdivision: nil, city: nil, latitude: nil,
                   longitude: nil, accuracy_radius_km: nil, timezone: nil)
      @country_code = country_code
      @country_name = country_name
      @subdivision = subdivision
      @city = city
      @latitude = latitude
      @longitude = longitude
      @accuracy_radius_km = accuracy_radius_km
      @timezone = timezone
      freeze
    end

    def self.from_h(raw)
      return nil unless raw.is_a?(Hash)

      new(
        country_code: ModelCast.str(raw, "countryCode"),
        country_name: ModelCast.str(raw, "countryName"),
        subdivision: ModelCast.str(raw, "subdivision"),
        city: ModelCast.str(raw, "city"),
        latitude: ModelCast.float(raw, "latitude"),
        longitude: ModelCast.float(raw, "longitude"),
        accuracy_radius_km: ModelCast.float(raw, "accuracyRadiusKm"),
        timezone: ModelCast.str(raw, "timezone")
      )
    end
  end

  # Declared, inferred-physical, and client locations kept separate in a canonical record.
  class SeparatedLocations
    attr_reader :declared_location, :inferred_physical_location, :client_location

    def initialize(declared_location: nil, inferred_physical_location: nil, client_location: nil)
      @declared_location = declared_location
      @inferred_physical_location = inferred_physical_location
      @client_location = client_location
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        declared_location: LocationAssertion.from_h(h["declaredLocation"]),
        inferred_physical_location: LocationAssertion.from_h(h["inferredPhysicalLocation"]),
        client_location: LocationAssertion.from_h(h["clientLocation"])
      )
    end
  end

  # Canonical network record stored in the serving snapshot (`record` of a network lookup).
  # The API serves this object with camelCase keys; attributes here are snake_case.
  class CanonicalNetworkPrefixRecord
    FIELDS = {
      family: ["family", :int],
      prefix: ["prefix", :str],
      asn: ["asn", :int],
      organization: ["organization", :str],
      country_code: ["countryCode", :str],
      subdivision: ["subdivision", :str],
      city: ["city", :str],
      postal_code: ["postalCode", :str],
      latitude: ["latitude", :float],
      longitude: ["longitude", :float],
      timezone: ["timezone", :str],
      location_type: ["locationType", :str],
      geo_confidence: ["geoConfidence", :float],
      accuracy_radius_km: ["accuracyRadiusKm", :float],
      is_virtual_location: ["isVirtualLocation", :bool],
      connection_type: ["connectionType", :str],
      is_hosting: ["isHosting", :bool],
      is_vpn: ["isVpn", :bool],
      is_tor_exit: ["isTorExit", :bool],
      is_proxy: ["isProxy", :bool],
      anonymizer_type: ["anonymizerType", :str],
      security_confidence: ["securityConfidence", :float],
      abuse_velocity_score: ["abuseVelocityScore", :number],
      is_known_scanner: ["isKnownScanner", :bool],
      reason_codes: ["reasonCodes", :str_list],
      source_ids: ["sourceIds", :str_list],
      license_policy_ids: ["licensePolicyIds", :str_list],
      updated_at: ["updatedAt", :str]
    }.freeze

    attr_reader(*FIELDS.keys)
    attr_reader :locations

    def initialize(locations: SeparatedLocations.new, **attrs)
      unknown = attrs.keys - FIELDS.keys
      raise ArgumentError, "unknown keywords: #{unknown.join(', ')}" unless unknown.empty?

      FIELDS.each_key { |name| instance_variable_set("@#{name}", attrs[name]) }
      @prefix ||= ""
      @family ||= @prefix.include?(":") ? 6 : 4
      @location_type ||= "unknown"
      @anonymizer_type ||= "unknown"
      @geo_confidence ||= 0.0
      @security_confidence ||= 0.0
      @reason_codes ||= [].freeze
      @source_ids ||= [].freeze
      @license_policy_ids ||= [].freeze
      @locations = locations
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      attrs = FIELDS.each_with_object({}) do |(name, (key, type)), acc|
        acc[name] = ModelCast.public_send(type, h, key)
      end
      new(locations: SeparatedLocations.from_h(h["locations"]), **attrs)
    end
  end

  # Network CIDR lookup response (`GET /v1/networks/{address}/{prefixLength}`).
  class NetworkPrefixLookupResponse
    attr_reader :queried_cidr, :matched_network, :family, :bgp_prefix_length,
                :dataset_version, :record, :lookup

    def initialize(queried_cidr:, matched_network:, family:, bgp_prefix_length:, dataset_version:,
                   record: nil, lookup: nil)
      @queried_cidr = queried_cidr.to_s.freeze
      @matched_network = matched_network.to_s.freeze
      @family = family.to_i
      @bgp_prefix_length = bgp_prefix_length.to_i
      @dataset_version = dataset_version.to_s.freeze
      @record = record
      @lookup = lookup
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      queried = ModelCast.str(h, "queried_cidr") || ""
      matched = ModelCast.str(h, "matched_network") || queried
      record = ModelCast.obj(h, "record")
      lookup = ModelCast.obj(h, "lookup")
      new(
        queried_cidr: queried,
        matched_network: matched,
        family: ModelCast.int(h, "family") || (queried.include?(":") ? 6 : 4),
        bgp_prefix_length: ModelCast.int(h, "bgp_prefix_length") || matched.split("/")[1].to_i,
        dataset_version: ModelCast.str(h, "dataset_version") || "",
        record: record ? CanonicalNetworkPrefixRecord.from_h(record) : nil,
        lookup: lookup ? IpLookupResponse.from_h(lookup) : nil
      )
    end
  end

  # Summary of one loaded dataset snapshot.
  class DatasetSnapshotSummary
    attr_reader :snapshot_version, :digest, :ruleset_version, :published_at,
                :ipv4_prefix_count, :ipv6_prefix_count

    def initialize(snapshot_version:, digest:, ruleset_version:, published_at:,
                   ipv4_prefix_count:, ipv6_prefix_count:)
      @snapshot_version = snapshot_version.to_s.freeze
      @digest = digest.to_s.freeze
      @ruleset_version = ruleset_version.to_s.freeze
      @published_at = published_at.to_s.freeze
      @ipv4_prefix_count = ipv4_prefix_count.to_i
      @ipv6_prefix_count = ipv6_prefix_count.to_i
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        snapshot_version: ModelCast.str(h, "snapshot_version") || "",
        digest: ModelCast.str(h, "digest") || "",
        ruleset_version: ModelCast.str(h, "ruleset_version") || "",
        published_at: ModelCast.str(h, "published_at") || "",
        ipv4_prefix_count: ModelCast.int(h, "ipv4_prefix_count") || 0,
        ipv6_prefix_count: ModelCast.int(h, "ipv6_prefix_count") || 0
      )
    end
  end

  # Dataset snapshots metadata (`GET /v1/metadata/datasets`).
  class DatasetsMetadataResponse
    attr_reader :active_version, :previous_version, :snapshots

    def initialize(active_version:, previous_version:, snapshots:)
      @active_version = active_version.to_s.freeze
      @previous_version = previous_version
      @snapshots = Array(snapshots).freeze
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      snapshots = (h["snapshots"].is_a?(Array) ? h["snapshots"] : [])
                  .select { |item| item.is_a?(Hash) }
                  .map { |item| DatasetSnapshotSummary.from_h(item) }
      new(
        active_version: ModelCast.str(h, "active_version") || "",
        previous_version: ModelCast.str(h, "previous_version"),
        snapshots: snapshots
      )
    end
  end

  # Correction report for `POST /v1/feedback`.
  class FeedbackSubmissionInput
    ROLES = %w[network_owner user researcher].freeze
    ISSUE_TYPES = %w[
      wrong_country
      wrong_city
      false_positive_vpn
      false_positive_hosting
      false_positive_tor
      virtual_location_mismatch
      other
    ].freeze

    attr_reader :prefix_or_ip, :role, :issue_type, :requested_correction,
                :evidence_url, :contact_consent, :contact_email

    # @param prefix_or_ip [String] target IP address or CIDR prefix
    # @param role [String] one of {ROLES}
    # @param issue_type [String] one of {ISSUE_TYPES}
    # @param requested_correction [Hash] requested corrected attributes, e.g. `{ "country_code" => "DE" }`
    # @param evidence_url [String, nil] public URL to geofeed / RDAP / traceroute evidence
    def initialize(prefix_or_ip:, role:, issue_type:, requested_correction: {}, evidence_url: nil,
                   contact_consent: false, contact_email: nil)
      @prefix_or_ip = prefix_or_ip.to_s.freeze
      @role = role.to_s.freeze
      @issue_type = issue_type.to_s.freeze
      @requested_correction = (requested_correction || {}).each_with_object({}) { |(k, v), acc| acc[k.to_s] = v }.freeze
      @evidence_url = evidence_url&.to_s&.freeze
      @contact_consent = contact_consent ? true : false
      @contact_email = contact_email&.to_s&.freeze
      freeze
    end

    def to_h
      payload = {
        "prefix_or_ip" => @prefix_or_ip,
        "role" => @role,
        "issue_type" => @issue_type,
        "requested_correction" => @requested_correction,
        "contact_consent" => @contact_consent
      }
      payload["evidence_url"] = @evidence_url unless @evidence_url.nil?
      payload["contact_email"] = @contact_email unless @contact_email.nil?
      payload
    end
  end

  # Feedback acknowledgment returned by `POST /v1/feedback`.
  class FeedbackSubmissionResponse
    attr_reader :id, :prefix_or_ip, :role, :issue_type, :requested_correction,
                :evidence_url, :contact_consent, :contact_email, :status, :created_at

    def initialize(id:, status:, created_at:, prefix_or_ip: "", role: "", issue_type: "",
                   requested_correction: {}, evidence_url: nil, contact_consent: nil, contact_email: nil)
      @id = id.to_s.freeze
      @prefix_or_ip = prefix_or_ip.to_s.freeze
      @role = role.to_s.freeze
      @issue_type = issue_type.to_s.freeze
      @requested_correction = requested_correction.freeze
      @evidence_url = evidence_url
      @contact_consent = contact_consent
      @contact_email = contact_email
      @status = status.to_s.freeze
      @created_at = created_at.to_s.freeze
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        id: ModelCast.str(h, "id") || "",
        prefix_or_ip: ModelCast.str(h, "prefix_or_ip") || "",
        role: ModelCast.str(h, "role") || "",
        issue_type: ModelCast.str(h, "issue_type") || "",
        requested_correction: ModelCast.obj(h, "requested_correction") || {},
        evidence_url: ModelCast.str(h, "evidence_url"),
        contact_consent: ModelCast.bool(h, "contact_consent"),
        contact_email: ModelCast.str(h, "contact_email"),
        status: ModelCast.str(h, "status") || "",
        # The API returns camelCase `createdAt`; accept snake_case too.
        created_at: ModelCast.str(h, "createdAt") || ModelCast.str(h, "created_at") || ""
      )
    end
  end

  # Serving and previous dataset versions reported by `GET /v1/status`.
  class ServiceSnapshotInfo
    attr_reader :current_version, :previous_version

    def initialize(current_version: nil, previous_version: nil)
      @current_version = current_version
      @previous_version = previous_version
      freeze
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      new(
        current_version: ModelCast.str(h, "currentVersion"),
        previous_version: ModelCast.str(h, "previousVersion")
      )
    end
  end

  # Service health returned by `GET /v1/status`.
  class ServiceStatusResponse
    attr_reader :status, :snapshot

    def initialize(status:, snapshot: nil)
      @status = status.to_s.freeze
      @snapshot = snapshot
      freeze
    end

    # Dataset version currently served (the `dataset_version` lookups return).
    def current_version
      @snapshot&.current_version
    end

    def previous_version
      @snapshot&.previous_version
    end

    def self.from_h(raw)
      h = ModelCast.as_hash(raw)
      snapshot = ModelCast.obj(h, "snapshot")
      new(
        status: ModelCast.str(h, "status") || "",
        snapshot: snapshot ? ServiceSnapshotInfo.from_h(snapshot) : nil
      )
    end
  end

  # Rate-limit metadata from the `X-RateLimit-*` response headers. Limits apply per user, not per key.
  class RateLimitMetadata
    # limit: requests allowed per window; remaining: left in this window;
    # reset_after_seconds: seconds until the window resets; scope: e.g. "user".
    attr_reader :limit, :remaining, :reset_after_seconds, :scope

    # `reset_epoch_seconds:` is accepted as a deprecated 1.0 alias of `reset_after_seconds:`.
    def initialize(limit: nil, remaining: nil, reset_after_seconds: nil, scope: nil,
                   reset_epoch_seconds: nil, credits_remaining: nil, plan_tier: nil)
      reset = reset_after_seconds.nil? ? reset_epoch_seconds : reset_after_seconds
      @limit = limit.nil? ? nil : limit.to_i
      @remaining = remaining.nil? ? nil : remaining.to_i
      @reset_after_seconds = reset.nil? ? nil : reset.to_i
      @scope = scope&.to_s&.freeze
      freeze
    end

    # @deprecated since 1.1.0. Misnamed in 1.0: the API sends seconds until the window
    #   resets, not an epoch timestamp. Returns the same value as {#reset_after_seconds}.
    def reset_epoch_seconds
      @reset_after_seconds
    end

    # @deprecated since 1.1.0. The API never sends a credits header; always nil.
    def credits_remaining
      nil
    end

    # @deprecated since 1.1.0. The API never sends a tier header; always nil.
    def plan_tier
      nil
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
