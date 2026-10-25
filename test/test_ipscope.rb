# frozen_string_literal: true

require_relative "../lib/ipscope"

$passed = 0
$failed = 0

def assert_true(condition, message)
  if condition
    $passed += 1
  else
    $failed += 1
    warn "FAIL: #{message}"
  end
end

def assert_equal(expected, actual, message)
  assert_true(
    expected == actual,
    "#{message} (expected #{expected.inspect}, got #{actual.inspect})"
  )
end

def sample_ip_payload(ip = "8.8.8.8")
  {
    "ip" => ip,
    "version" => ip.include?(":") ? 6 : 4,
    "is_bogon" => false,
    "bogon_type" => nil,
    "geo" => {
      "country_code" => "US",
      "country_name" => "United States",
      "region_code" => "CA",
      "region_name" => "California",
      "city" => "Mountain View",
      "postal_code" => "94043",
      "latitude" => 37.4056,
      "longitude" => -122.0775,
      "timezone" => "America/Los_Angeles",
      "accuracy_radius_km" => 20
    },
    "network" => {
      "asn" => 15169,
      "asn_name" => "GOOGLE",
      "org" => "Google LLC",
      "isp" => "Google LLC",
      "connection_type" => "datacenter",
      "bgp_prefix" => "8.8.8.0/24",
      "rir" => "ARIN"
    },
    "security" => {
      "is_vpn" => false,
      "is_proxy" => false,
      "is_tor" => false,
      "is_datacenter" => true,
      "is_relay" => false,
      "threat_level" => "low",
      "threat_types" => []
    },
    "connection" => {
      "usage_type" => "hosting",
      "company_type" => "technology",
      "carrier_name" => nil,
      "mcc" => nil,
      "mnc" => nil,
      "domain" => "google.com",
      "route" => "8.8.8.0/24",
      "allocated_date" => "2014-03-14",
      "registry_status" => "assigned"
    },
    "security_extensions" => {
      "vpn_provider" => nil,
      "proxy_type" => nil,
      "threat_score" => 5,
      "is_abuser" => false,
      "is_bot" => false,
      "is_bogon" => false
    },
    "updated_at" => "2026-10-25T00:00:00Z"
  }
end

# ---------------------------------------------------------------------------
# 1. Zero-DNS Validator Tests
# ---------------------------------------------------------------------------
assert_equal("8.8.8.8", IpScope::Validator.validate_ip_address("  8.8.8.8  "), "IPv4 canonicalized")
assert_equal(
  "2001:db8::1",
  IpScope::Validator.validate_ip_address("2001:0db8:0000:0000:0000:0000:0000:0001%eth0"),
  "IPv6 compressed & zone stripped"
)

hostname_rejected = false
begin
  IpScope::Validator.validate_ip_address("dns.google.com")
rescue IpScope::IpScopeValidationError
  hostname_rejected = true
end
assert_true(hostname_rejected, "Hostnames rejected without DNS lookup")

cidr4 = IpScope::Validator.validate_cidr_prefix("8.8.8.42/24")
assert_equal("8.8.8.0/24", cidr4[:canonical_cidr], "IPv4 CIDR host bits masked")

cidr6 = IpScope::Validator.validate_cidr_prefix("2001:4860:4860::8888/32")
assert_equal("2001:4860::/32", cidr6[:canonical_cidr], "IPv6 CIDR host bits masked")

deduped = IpScope::Validator.validate_and_deduplicate_batch_ips(["8.8.8.8", "1.1.1.1", "8.8.8.8"])
assert_equal(["8.8.8.8", "1.1.1.1"], deduped, "Batch deduplicates while preserving order")

# ---------------------------------------------------------------------------
# 2. Bounded O(1) LRU + TTL Cache Tests
# ---------------------------------------------------------------------------
cache = IpScope::LruTtlCache.new(IpScope::CacheOptions.new(enabled: true, max_entries: 2, ttl_seconds: 10.0))
rec1 = IpScope::IpLookupResponse.from_h(sample_ip_payload("1.1.1.1"))
rec2 = IpScope::IpLookupResponse.from_h(sample_ip_payload("8.8.8.8"))
rec3 = IpScope::IpLookupResponse.from_h(sample_ip_payload("9.9.9.9"))

cache.set("1.1.1.1", rec1, 100.0)
cache.set("8.8.8.8", rec2, 100.0)
assert_equal("1.1.1.1", cache.get("1.1.1.1", 101.0)&.ip, "Cache hit promotes 1.1.1.1")
cache.set("9.9.9.9", rec3, 102.0)

assert_equal(nil, cache.get("8.8.8.8", 103.0), "LRU entry 8.8.8.8 evicted")
assert_equal("1.1.1.1", cache.get("1.1.1.1", 103.0)&.ip, "Promoted entry 1.1.1.1 retained")
assert_equal(nil, cache.get("1.1.1.1", 115.0), "TTL expired entry evicted on access")
assert_equal(1, cache.stats.evictions, "Cache eviction counter incremented")

# ---------------------------------------------------------------------------
# 3. Client Operations, Batch Cache Reuse, Singleflight & Streaming Tests
# ---------------------------------------------------------------------------
requests = []
req_mutex = Mutex.new

client = IpScope::IpScopeClient.new(
  api_key: "ips_live_ruby_test_key_12345",
  custom_transport: lambda do |method, url, _headers, body, _timeout|
    req_mutex.synchronize { requests << { method: method, url: url, body: body } }
    path = URI.parse(url).path

    if method == "GET" && path == "/v1/ip/8.8.8.8"
      return {
        status: 200,
        headers: {
          "x-ratelimit-limit" => "1000",
          "x-ratelimit-remaining" => "997",
          "x-ratelimit-reset" => "1760000000",
          "x-ratelimit-credits-remaining" => "49980",
          "x-ratelimit-tier" => "pro"
        },
        body: JSON.generate(sample_ip_payload("8.8.8.8"))
      }
    end

    if method == "GET" && path == "/v1/ip/8.8.4.4"
      sleep(0.02)
      return {
        status: 200,
        headers: {},
        body: JSON.generate(sample_ip_payload("8.8.4.4"))
      }
    end

    if method == "GET" && path == "/v1/ip"
      return {
        status: 200,
        headers: {},
        body: JSON.generate(sample_ip_payload("203.0.113.25"))
      }
    end

    if method == "POST" && path == "/v1/ip/batch"
      decoded = JSON.parse(body)
      results = decoded["ips"].map { |ip| sample_ip_payload(ip) }
      return {
        status: 200,
        headers: {},
        body: JSON.generate({ "count" => results.length, "results" => results })
      }
    end

    if method == "GET" && path == "/v1/network/8.8.8.0/24"
      return {
        status: 200,
        headers: {},
        body: JSON.generate({
          "requested_cidr" => "8.8.8.0/24",
          "exact_match" => {
            "network_cidr" => "8.8.8.0/24",
            "ip_version" => 4,
            "geo" => sample_ip_payload["geo"],
            "network" => sample_ip_payload["network"],
            "security" => sample_ip_payload["security"],
            "updated_at" => "2026-10-25T00:00:00Z"
          },
          "enclosing_prefix" => nil,
          "overlapping_prefixes" => [],
          "total_matches" => 1
        })
      }
    end

    if method == "GET" && path == "/v1/datasets/metadata"
      return {
        status: 200,
        headers: {},
        body: JSON.generate({
          "count" => 1,
          "active_datasets" => [{
            "source" => "ipscope-core",
            "version_tag" => "2026.10.25",
            "checksum_sha256" => "abc123",
            "record_count" => 1_250_000,
            "activated_at" => "2026-10-25T00:00:00Z",
            "created_at" => "2026-10-25T00:00:00Z"
          }]
        })
      }
    end

    if method == "POST" && path == "/v1/feedback"
      return {
        status: 201,
        headers: {},
        body: JSON.generate({
          "id" => "fb_ruby_01",
          "ip_or_cidr" => "8.8.8.8",
          "status" => "pending_review",
          "created_at" => "2026-10-25T00:00:00Z"
        })
      }
    end

    if method == "GET" && path == "/v1/status"
      return {
        status: 200,
        headers: {},
        body: JSON.generate({
          "status" => "ok",
          "service" => "ipscope-api",
          "version" => "2.0.0",
          "uptime_seconds" => 86_400.5,
          "timestamp" => "2026-10-25T00:00:00Z"
        })
      }
    end

    { status: 404, headers: {}, body: '{"message":"Not Found"}' }
  end
)

meta1 = client.lookup_ip_with_meta("8.8.8.8")
assert_equal(false, meta1.from_cache, "First lookup_ip fetched from API")
assert_equal("US", meta1.data.geo.country_code, "Country code mapped")
assert_equal(15169, meta1.data.network.asn, "ASN mapped")
assert_equal(997, meta1.rate_limit.remaining, "RateLimit remaining parsed")
assert_equal("pro", client.last_rate_limit.plan_tier, "Plan tier stored on client")

meta2 = client.lookup_ip_with_meta("8.8.8.8")
assert_equal(true, meta2.from_cache, "Second lookup_ip served from LRU cache")
assert_equal(1, requests.length, "No extra HTTP request on cache hit")

# Multi-threaded singleflight coalescing test
threads = Array.new(8) do
  Thread.new { client.lookup_ip("8.8.4.4") }
end
results_sf = threads.map(&:value)
assert_equal(8, results_sf.length, "All 8 threads resolved")
sf_requests = requests.count { |r| r[:url].end_with?("/v1/ip/8.8.4.4") }
assert_equal(1, sf_requests, "8 concurrent lookups coalesced into 1 HTTP request")

# Batch lookup reuses cached 8.8.8.8 and only sends 1.1.1.1
batch = client.lookup_batch(["8.8.8.8", "1.1.1.1", "8.8.8.8"])
assert_equal(2, batch.count, "Batch returns 2 unique records")
assert_equal("8.8.8.8", batch.results[0].ip, "First batch item is 8.8.8.8")
assert_equal("1.1.1.1", batch.results[1].ip, "Second batch item is 1.1.1.1")
batch_req = requests.find { |r| r[:url].end_with?("/v1/ip/batch") }
assert_equal('{"ips":["1.1.1.1"]}', batch_req[:body], "Batch POST only sent uncached 1.1.1.1")

# Streaming batch lookup over 140 IPs (100 + 40 chunks)
stream_ips = (1..140).map { |i| "198.51.100.#{i}" }
chunk_counts = client.lookup_batch_stream(stream_ips).map(&:count)
assert_equal([100, 40], chunk_counts, "lookup_batch_stream yields 100 and 40 IP chunks")

caller_info = client.lookup_caller_ip
assert_equal("203.0.113.25", caller_info.ip, "Caller IP resolved")

net = client.lookup_network("8.8.8.42/24")
assert_equal("8.8.8.0/24", net.requested_cidr, "CIDR lookup normalizes host bits")
assert_equal(1, net.total_matches, "CIDR total_matches parsed")

datasets = client.get_datasets_metadata
assert_equal("ipscope-core", datasets.active_datasets.first.source, "Dataset source parsed")

fb = client.submit_feedback(
  IpScope::FeedbackSubmissionInput.new(
    ip_or_cidr: "8.8.8.8",
    suggested_country_code: "US",
    notes: "Anycast node"
  )
)
assert_equal("fb_ruby_01", fb.id, "Feedback ID parsed")

status = client.get_status
assert_equal("ok", status.status, "Service status parsed")

# ---------------------------------------------------------------------------
# 4. Retry on 429 and Deep JSON Nesting Protection
# ---------------------------------------------------------------------------
attempts = 0
retry_client = IpScope::Client.new(
  api_key: "ips_live_retry_key_12345",
  retry_options: IpScope::RetryOptions.new(max_retries: 2, initial_delay_seconds: 0.005, max_delay_seconds: 0.02),
  custom_transport: lambda do |_m, _u, _h, _b, _t|
    attempts += 1
    if attempts == 1
      { status: 429, headers: { "retry-after" => "0.005" }, body: '{"message":"Rate limit exceeded"}' }
    else
      { status: 200, headers: {}, body: JSON.generate(sample_ip_payload("9.9.9.9")) }
    end
  end
)
retried = retry_client.lookup_ip("9.9.9.9")
assert_equal("9.9.9.9", retried.ip, "Client automatically retries on HTTP 429")
assert_equal(2, attempts, "Exactly 2 attempts performed")

deep_client = IpScope::Client.new(
  api_key: "ips_live_deep_key_12345",
  retry_options: IpScope::RetryOptions.new(max_retries: 0),
  custom_transport: lambda do |_m, _u, _h, _b, _t|
    nested = ('{"a":' * 25) + "1" + ("}" * 25)
    { status: 200, headers: {}, body: nested }
  end
)
deep_rejected = false
begin
  deep_client.lookup_ip("8.8.8.8")
rescue IpScope::IpScopeApiError => e
  deep_rejected = (e.error_code == "IPSCOPE_INVALID_JSON")
end
assert_true(deep_rejected, "Deeply nested JSON (>16 depth) rejected")

client.close
assert_equal(0, client.cache_stats.size, "close clears cache")

if $failed.positive?
  warn "\nFAILED: #{$failed} failed, #{$passed} passed."
  exit(1)
end

puts "ALL #{$passed} RUBY SDK TESTS PASSED (Ruby #{RUBY_VERSION})"
