# frozen_string_literal: true

module IpScope
  # Official Server-Side Ruby Client for the IPScope IP Intelligence Platform.
  #
  # Scoped strictly to IP intelligence operations (single IP lookup, caller IP lookup,
  # batch lookup, chunked/streaming batch lookup, CIDR network prefix lookup, dataset metadata,
  # geolocation/anonymity feedback submission, and service health status).
  class Client
    MAX_BATCH_SIZE = Validator::MAX_BATCH_SIZE
    MAX_RESPONSE_BYTES = HttpTransport::MAX_RESPONSE_BYTES

    def initialize(
      api_key:,
      base_url: HttpTransport::DEFAULT_BASE_URL,
      timeout_seconds: HttpTransport::DEFAULT_TIMEOUT_SECONDS,
      retry_options: nil,
      cache_options: nil,
      user_agent: nil,
      custom_transport: nil
    )
      @transport = HttpTransport.new(
        api_key: api_key,
        base_url: base_url,
        timeout_seconds: timeout_seconds,
        retry_options: retry_options,
        user_agent: user_agent,
        custom_transport: custom_transport
      )
      @cache = LruTtlCache.new(cache_options)
      @inflight_mutex = Mutex.new
      @inflight = {}
    end

    # Closes persistent keep-alive connections and clears cached state.
    def close
      @cache.clear
      @transport.close
    end

    # Looks up full IP intelligence for a single IPv4 or IPv6 address (`GET /v1/ip/{ip}`).
    def lookup_ip(ip, options = nil)
      lookup_ip_with_meta(ip, options).data
    end

    # Looks up full IP intelligence for a single IPv4 or IPv6 address along with
    # rate-limit headers and cache hit metadata. Coalesces concurrent identical lookups
    # across threads via singleflight.
    def lookup_ip_with_meta(ip, options = nil)
      canonical_ip = Validator.validate_ip_address(ip)
      bypass_cache = options&.bypass_cache || false

      unless bypass_cache
        cached = @cache.get(canonical_ip)
        unless cached.nil?
          return IpScopeResultWithMeta.new(
            data: cached,
            rate_limit: @transport.last_rate_limit,
            from_cache: true
          )
        end
      end

      return fetch_and_cache_single_ip(canonical_ip, bypass_cache, options) if bypass_cache

      execute_singleflight(canonical_ip) do
        fetch_and_cache_single_ip(canonical_ip, false, options)
      end
    end

    # Resolves IP intelligence for the caller's own public IP address (`GET /v1/ip/me`).
    def lookup_caller_ip(options = nil)
      raw = @transport.request_json("GET", "/v1/ip/me", options: options)
      record = IpLookupResponse.from_h(raw[:data])
      @cache.set(record.ip, record) if !(options&.bypass_cache) && !record.ip.empty?
      record
    end

    # Performs a batch IP lookup (`POST /v1/ip/batch`) for up to 100 IP addresses.
    # Automatically deduplicates input IPs, reuses cached entries from the LRU cache,
    # and backfills newly fetched records into the cache.
    def lookup_batch(ips, options = nil)
      unique_ips = Validator.validate_and_deduplicate_batch_ips(ips, MAX_BATCH_SIZE)
      bypass_cache = options&.bypass_cache || false

      resolved_map = {}
      missing_ips = []
      dataset_version = ""

      if !bypass_cache && @cache.enabled?
        unique_ips.each do |ip|
          cached = @cache.get(ip)
          if cached
            resolved_map[ip] = cached
          else
            missing_ips << ip
          end
        end
      else
        missing_ips = unique_ips
      end

      unless missing_ips.empty?
        raw = @transport.request_json(
          "POST",
          "/v1/ip/batch",
          json_body: { "ips" => missing_ips },
          options: options
        )
        batch_resp = BatchLookupResponse.from_h(raw[:data])
        dataset_version = batch_resp.dataset_version

        batch_resp.results.each_with_index do |record, idx|
          requested_key = missing_ips[idx] || record.ip
          resolved_map[requested_key] = record
          resolved_map[record.ip] = record unless record.ip.empty?
          unless bypass_cache
            @cache.set(requested_key, record)
            @cache.set(record.ip, record) if !record.ip.empty? && record.ip != requested_key
          end
        end
      end

      ordered_results = unique_ips.each_with_object([]) do |ip, acc|
        acc << resolved_map[ip] if resolved_map.key?(ip)
      end

      BatchLookupResponse.new(
        count: ordered_results.length,
        results: ordered_results,
        dataset_version: dataset_version.empty? ? first_dataset_version(ordered_results) : dataset_version
      )
    end

    # Splits an arbitrarily large list of IP addresses into chunks of up to 100 unique IPs
    # and merges the results into a single `BatchLookupResponse`.
    def lookup_batch_chunked(ips, options = nil)
      merged = []
      lookup_batch_stream(ips, options) do |chunk_resp|
        merged.concat(chunk_resp.results)
      end
      BatchLookupResponse.new(
        count: merged.length,
        results: merged,
        dataset_version: first_dataset_version(merged)
      )
    end

    # Memory-bounded streaming enumerator that yields `BatchLookupResponse` chunks of up to
    # 100 unique IP addresses at a time with constant `O(chunk)` RAM usage.
    # Returns an `Enumerator` if no block is given.
    def lookup_batch_stream(ips, options = nil)
      return enum_for(:lookup_batch_stream, ips, options) unless block_given?

      unless ips.respond_to?(:each)
        raise IpScopeValidationError.new("Batch IP stream must be an Enumerable.", field: "ips")
      end

      chunk = []
      seen_in_chunk = {}
      yielded_any = false

      ips.each do |raw_ip|
        unless raw_ip.is_a?(String)
          raise IpScopeValidationError.new("Expected String IP address in lookup_batch_stream.", field: "ips")
        end

        canonical = Validator.validate_ip_address(raw_ip, "ips")
        next if seen_in_chunk.key?(canonical)

        seen_in_chunk[canonical] = true
        chunk << canonical

        if chunk.length >= MAX_BATCH_SIZE
          yielded_any = true
          yield lookup_batch(chunk, options)
          chunk = []
          seen_in_chunk = {}
        end
      end

      if !chunk.empty?
        yield lookup_batch(chunk, options)
      elsif !yielded_any
        raise IpScopeValidationError.new("Batch IP stream must contain at least 1 IP address.", field: "ips")
      end
    end

    # Looks up BGP/CIDR network prefix intelligence (`GET /v1/networks/{address}/{prefixLength}`).
    def lookup_network(cidr, options = nil)
      parsed = Validator.validate_cidr_prefix(cidr)
      encoded_addr = URI.encode_www_form_component(parsed[:address])
      path = "/v1/networks/#{encoded_addr}/#{parsed[:prefix_length]}"
      raw = @transport.request_json("GET", path, options: options)
      NetworkPrefixLookupResponse.from_h(raw[:data])
    end

    # Retrieves active and historical dataset snapshot metadata (`GET /v1/metadata/datasets`).
    def get_datasets_metadata(options = nil)
      raw = @transport.request_json("GET", "/v1/metadata/datasets", options: options)
      DatasetsMetadataResponse.from_h(raw[:data])
    end

    # Submits an IP geolocation or anonymity correction (`POST /v1/feedback`).
    def submit_feedback(feedback, options = nil)
      unless feedback.is_a?(FeedbackSubmissionInput)
        raise IpScopeValidationError.new("Expected FeedbackSubmissionInput instance.", field: "feedback")
      end

      trimmed = feedback.prefix_or_ip.strip
      if trimmed.empty?
        raise IpScopeValidationError.new("prefix_or_ip must not be empty.", field: "prefix_or_ip")
      end

      normalized = if trimmed.include?("/")
                     Validator.validate_cidr_prefix(trimmed)[:canonical_cidr]
                   else
                     Validator.validate_ip_address(trimmed, "prefix_or_ip")
                   end
      validate_feedback_fields(feedback)

      payload = feedback.to_h
      payload["prefix_or_ip"] = normalized

      raw = @transport.request_json("POST", "/v1/feedback", json_body: payload, options: options)
      FeedbackSubmissionResponse.from_h(raw[:data])
    end

    # Queries the IPScope API health status (`GET /v1/status`).
    def get_status(options = nil)
      raw = @transport.request_json("GET", "/v1/status", options: options)
      ServiceStatusResponse.from_h(raw[:data])
    end

    # Returns the most recent rate-limit metadata observed from `X-RateLimit-*` headers.
    def last_rate_limit
      @transport.last_rate_limit
    end

    # Returns current bounded LRU cache statistics.
    def cache_stats
      @cache.stats
    end

    # Clears all entries and resets statistics in the in-memory LRU cache.
    def clear_cache
      @cache.clear
    end

    private

    def first_dataset_version(records)
      found = records.find { |r| !r.dataset_version.empty? }
      found ? found.dataset_version : ""
    end

    def validate_feedback_fields(feedback)
      unless FeedbackSubmissionInput::ROLES.include?(feedback.role)
        raise IpScopeValidationError.new(
          "role must be one of: #{FeedbackSubmissionInput::ROLES.join(', ')}.", field: "role"
        )
      end
      unless FeedbackSubmissionInput::ISSUE_TYPES.include?(feedback.issue_type)
        raise IpScopeValidationError.new(
          "issue_type must be one of: #{FeedbackSubmissionInput::ISSUE_TYPES.join(', ')}.", field: "issue_type"
        )
      end
      if feedback.evidence_url && !%r{\Ahttps?://[^\s/]+\S*\z}i.match?(feedback.evidence_url)
        raise IpScopeValidationError.new("evidence_url must be an absolute http(s) URL.", field: "evidence_url")
      end
      if feedback.contact_email && !/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/.match?(feedback.contact_email)
        raise IpScopeValidationError.new("contact_email must be a valid email address.", field: "contact_email")
      end
    end

    def fetch_and_cache_single_ip(canonical_ip, bypass_cache, options)
      encoded = URI.encode_www_form_component(canonical_ip)
      raw = @transport.request_json("GET", "/v1/ip/#{encoded}", options: options)
      record = IpLookupResponse.from_h(raw[:data])

      unless bypass_cache
        @cache.set(canonical_ip, record)
        @cache.set(record.ip, record) if !record.ip.empty? && record.ip != canonical_ip
      end

      IpScopeResultWithMeta.new(
        data: record,
        rate_limit: raw[:rate_limit],
        from_cache: false
      )
    end

    def execute_singleflight(key)
      leader = false
      state = nil

      @inflight_mutex.synchronize do
        if @inflight.key?(key)
          state = @inflight[key]
        else
          leader = true
          state = { done: false, result: nil, error: nil, cond: ConditionVariable.new }
          @inflight[key] = state
        end
      end

      if leader
        begin
          res = yield
          @inflight_mutex.synchronize do
            state[:result] = res
            state[:done] = true
            @inflight.delete(key)
            state[:cond].broadcast
          end
          res
        rescue StandardError => e
          @inflight_mutex.synchronize do
            state[:error] = e
            state[:done] = true
            @inflight.delete(key)
            state[:cond].broadcast
          end
          raise e
        end
      else
        @inflight_mutex.synchronize do
          state[:cond].wait(@inflight_mutex) until state[:done]
        end
        raise state[:error] if state[:error]

        state[:result]
      end
    end
  end

  # Alias for consistency with other IPScope SDKs (`IpScopeClient`).
  IpScopeClient = Client
end
