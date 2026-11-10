# frozen_string_literal: true

require "stringio"
require_relative "../lib/ipscope"

$passed = 0
$failed = 0

# Example key in the real token format: <uuid>:<43-char base64url secret>. Not a real key.
TEST_API_KEY = "3f6b2a91-7c4d-4e8a-9b1f-2d5c8e0a4b7c:Zm9vYmFyYmF6cXV4Y29yZ2VncmF1bHRnYXJwbHl3YWw"
FIXTURES = File.join(__dir__, "fixtures")

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
    expected == actual && expected.class == actual.class,
    "#{message} (expected #{expected.inspect}, got #{actual.inspect})"
  )
end

# Raw JSON of a captured (api.ipscope.io) or contract-built API response.
def fixture_json(name)
  File.read(File.join(FIXTURES, "#{name}.json"))
end

def fixture(name)
  JSON.parse(fixture_json(name))
end

# The live 1.1.1.1 / 2606:4700:4700::1111 lookup body with the address swapped.
def lookup_payload_for(ip)
  payload = fixture(ip.include?(":") ? "lookup_2606_4700_4700__1111" : "lookup_1.1.1.1")
  payload["ip"] = ip
  payload
end

def capture_stderr
  old = $stderr
  $stderr = StringIO.new
  yield
  $stderr.string
ensure
  $stderr = old
end

# ---------------------------------------------------------------------------
# 1. Zero-DNS validator
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
# 2. Models parse real API JSON (captured from api.ipscope.io)
# ---------------------------------------------------------------------------
v4 = IpScope::IpLookupResponse.from_h(fixture("lookup_1.1.1.1"))
assert_equal("1.1.1.1", v4.ip, "ip parsed")
assert_equal(4, v4.ip_version, "ip_version parsed")
assert_equal("1.1.1.0/24", v4.matched_network, "matched_network parsed")
assert_equal("2026-11-10", v4.dataset_version, "dataset_version parsed")
assert_equal("2026-11-04T21:07:15.284Z", v4.updated_at, "updated_at parsed")
assert_equal("AU", v4.geo.country_code, "geo.country_code parsed")
assert_equal("New South Wales", v4.geo.subdivision, "geo.subdivision parsed")
assert_equal("Sydney", v4.geo.city, "geo.city parsed")
assert_equal(nil, v4.geo.postal_code, "absent geo.postal_code is nil")
assert_equal(-33.8688, v4.geo.latitude, "geo.latitude parsed")
assert_equal(151.209, v4.geo.longitude, "geo.longitude parsed")
assert_equal("Australia/Sydney", v4.geo.timezone, "geo.timezone parsed")
assert_equal("declared", v4.geo.location_type, "geo.location_type parsed")
assert_equal(0.85, v4.geo.confidence, "geo.confidence parsed")
assert_equal(300.0, v4.geo.accuracy_radius_km, "geo.accuracy_radius_km parsed")
assert_equal("AU", v4.geo.declared_country_code, "geo.declared_country_code parsed")
assert_equal(nil, v4.geo.physical_country_code, "null geo.physical_country_code stays nil")
assert_equal(nil, v4.geo.is_virtual_location, "null geo.is_virtual_location stays nil (not false)")
assert_equal(13335, v4.network.asn, "network.asn parsed")
assert_equal("CLOUDFLARENET - Cloudflare, Inc.", v4.network.organization, "network.organization parsed")
assert_equal(false, v4.security.is_vpn, "security.is_vpn parsed")
assert_equal(true, v4.security.is_hosting, "security.is_hosting parsed")
assert_equal(false, v4.security.is_tor_exit, "security.is_tor_exit parsed")
assert_equal(false, v4.security.is_proxy, "security.is_proxy parsed")
assert_equal(false, v4.security.is_relay, "security.is_relay parsed")
assert_equal("none", v4.security.anonymizer_type, "security.anonymizer_type parsed")
assert_equal(0.85, v4.security.confidence, "security.confidence parsed")
assert_equal(4, v4.security.reason_codes.length, "security.reason_codes parsed")
assert_equal("BGP_ORIGIN_ASN_MATCHED", v4.security.reason_codes.first, "first reason code parsed")
assert_equal("hosting", v4.connection.connection_type, "connection.connection_type parsed")
assert_equal(false, v4.connection.is_residential, "connection.is_residential parsed")
assert_equal(true, v4.connection.is_hosting, "connection.is_hosting parsed")
assert_equal(0.14, v4.security_extensions.abuse_velocity_score, "pre-0-100 fractional abuse_velocity_score passed through")
assert_equal(false, v4.security_extensions.is_known_scanner, "security_extensions.is_known_scanner parsed")
assert_equal(0.0, v4.security_extensions.observation_recency_hours, "security_extensions.observation_recency_hours parsed")

v6 = IpScope::IpLookupResponse.from_h(fixture("lookup_2606_4700_4700__1111"))
assert_equal(6, v6.ip_version, "IPv6 ip_version is 6")
assert_equal("2606:4700:4700::/48", v6.matched_network, "IPv6 matched_network parsed")
assert_equal("physical", v6.geo.location_type, "IPv6 location_type parsed")
assert_equal(false, v6.geo.is_virtual_location, "false is_virtual_location stays false")

# 8.8.8.8 omits security.is_relay entirely.
google = IpScope::IpLookupResponse.from_h(fixture("lookup_8.8.8.8"))
assert_equal(nil, google.security.is_relay, "absent security.is_relay is nil")
assert_equal("Google LLC", google.network.organization, "8.8.8.8 organization parsed")

# Unlicensed field families are omitted by the API.
unlicensed = fixture("lookup_1.1.1.1")
unlicensed.delete("connection")
unlicensed.delete("security_extensions")
u = IpScope::IpLookupResponse.from_h(unlicensed)
assert_equal(nil, u.connection, "omitted connection block is nil")
assert_equal(nil, u.security_extensions, "omitted security_extensions block is nil")

# Abstaining booleans are nil, not false.
abstain = fixture("lookup_1.1.1.1")
abstain["security"]["is_vpn"] = nil
abstain["connection"]["is_mobile"] = nil
abstain["security_extensions"]["abuse_velocity_score"] = nil
a = IpScope::IpLookupResponse.from_h(abstain)
assert_equal(nil, a.security.is_vpn, "null security.is_vpn stays nil")
assert_equal(nil, a.connection.is_mobile, "null connection.is_mobile stays nil")
assert_equal(nil, a.security_extensions.abuse_velocity_score, "null abuse_velocity_score stays nil")

# Deprecated 1.0 accessors still read the right values, and warn.
warnings = capture_stderr do
  assert_equal("CLOUDFLARENET - Cloudflare, Inc.", v4.network.org, "deprecated network.org aliases organization")
  assert_equal(true, v4.security.is_datacenter, "deprecated security.is_datacenter aliases is_hosting")
  assert_equal(false, v4.security.is_tor, "deprecated security.is_tor aliases is_tor_exit")
  assert_equal(6, v6.version, "deprecated version aliases ip_version")
end
assert_equal(4, warnings.scan("is deprecated since 1.1.0").length, "each deprecated accessor warns")

# ---------------------------------------------------------------------------
# 3. Bounded O(1) LRU + TTL cache
# ---------------------------------------------------------------------------
cache = IpScope::LruTtlCache.new(IpScope::CacheOptions.new(enabled: true, max_entries: 2, ttl_seconds: 10.0))
rec1 = IpScope::IpLookupResponse.from_h(lookup_payload_for("1.1.1.1"))
rec2 = IpScope::IpLookupResponse.from_h(lookup_payload_for("8.8.8.8"))
rec3 = IpScope::IpLookupResponse.from_h(lookup_payload_for("9.9.9.9"))

cache.set("1.1.1.1", rec1, 100.0)
cache.set("8.8.8.8", rec2, 100.0)
assert_equal("1.1.1.1", cache.get("1.1.1.1", 101.0)&.ip, "Cache hit promotes 1.1.1.1")
cache.set("9.9.9.9", rec3, 102.0)

assert_equal(nil, cache.get("8.8.8.8", 103.0), "LRU entry 8.8.8.8 evicted")
assert_equal("1.1.1.1", cache.get("1.1.1.1", 103.0)&.ip, "Promoted entry 1.1.1.1 retained")
assert_equal(nil, cache.get("1.1.1.1", 115.0), "TTL expired entry evicted on access")
assert_equal(1, cache.stats.evictions, "Cache eviction counter incremented")

# ---------------------------------------------------------------------------
# 4. Client operations against the real API paths and bodies
# ---------------------------------------------------------------------------
requests = []
req_mutex = Mutex.new
RATE_HEADERS = {
  "X-RateLimit-Scope" => "user",
  "X-RateLimit-Limit" => "600",
  "X-RateLimit-Remaining" => "598",
  "X-RateLimit-Reset" => "42"
}.freeze

client = IpScope::IpScopeClient.new(
  api_key: TEST_API_KEY,
  custom_transport: lambda do |method, url, headers, body, _timeout|
    req_mutex.synchronize { requests << { method: method, url: url, body: body, headers: headers } }
    path = URI.decode_www_form_component(URI.parse(url).path)

    case [method, path]
    when ["GET", "/v1/ip/1.1.1.1"]
      { status: 200, headers: RATE_HEADERS, body: fixture_json("lookup_1.1.1.1") }
    when ["GET", "/v1/ip/2606:4700:4700::1111"]
      { status: 200, headers: RATE_HEADERS, body: fixture_json("lookup_2606_4700_4700__1111") }
    when ["GET", "/v1/ip/8.8.4.4"]
      sleep(0.02)
      { status: 200, headers: {}, body: JSON.generate(lookup_payload_for("8.8.4.4")) }
    when ["GET", "/v1/ip/me"]
      { status: 200, headers: {}, body: JSON.generate(lookup_payload_for("203.0.113.25")) }
    when ["POST", "/v1/ip/batch"]
      results = JSON.parse(body)["ips"].map { |ip| lookup_payload_for(ip) }
      { status: 200, headers: RATE_HEADERS,
        body: JSON.generate("dataset_version" => "2026-11-10", "count" => results.length, "results" => results) }
    when ["GET", "/v1/networks/1.1.1.0/24"]
      { status: 200, headers: RATE_HEADERS, body: fixture_json("network_1.1.1.0_24") }
    when ["GET", "/v1/metadata/datasets"]
      { status: 200, headers: RATE_HEADERS, body: fixture_json("datasets") }
    when ["POST", "/v1/feedback"]
      { status: 201, headers: RATE_HEADERS, body: fixture_json("feedback_response") }
    when ["GET", "/v1/status"]
      { status: 200, headers: {}, body: fixture_json("status") }
    else
      { status: 404, headers: {}, body: JSON.generate("message" => "Cannot #{method} #{path}", "error" => "Not Found", "statusCode" => 404) }
    end
  end
)

assert_equal("1.1.0", IpScope::VERSION, "VERSION is 1.1.0")
meta1 = client.lookup_ip_with_meta("1.1.1.1")
assert_equal(false, meta1.from_cache, "First lookup_ip fetched from API")
assert_equal("ipscope-sdk-ruby/1.1.0 (Ruby/#{RUBY_VERSION})", requests[0][:headers]["User-Agent"], "User-Agent carries SDK version")
assert_equal(TEST_API_KEY, requests[0][:headers]["X-API-Key"], "API key sent in X-API-Key")
assert_equal("CLOUDFLARENET - Cloudflare, Inc.", meta1.data.network.organization, "lookup_ip organization")
assert_equal(600, meta1.rate_limit.limit, "X-RateLimit-Limit parsed")
assert_equal(598, meta1.rate_limit.remaining, "X-RateLimit-Remaining parsed")
assert_equal(42, meta1.rate_limit.reset_after_seconds, "X-RateLimit-Reset parsed as seconds until reset")
assert_equal("user", meta1.rate_limit.scope, "X-RateLimit-Scope parsed")
assert_equal(42, client.last_rate_limit.reset_epoch_seconds, "deprecated reset_epoch_seconds returns the same seconds value")
assert_equal(nil, client.last_rate_limit.credits_remaining, "deprecated credits_remaining is always nil")
assert_equal(nil, client.last_rate_limit.plan_tier, "deprecated plan_tier is always nil")
assert_equal(
  7,
  IpScope::RateLimitMetadata.new(reset_epoch_seconds: 7).reset_after_seconds,
  "1.0 keyword reset_epoch_seconds: still accepted"
)

meta2 = client.lookup_ip_with_meta("1.1.1.1")
assert_equal(true, meta2.from_cache, "Second lookup_ip served from LRU cache")
assert_equal(1, requests.length, "No extra HTTP request on cache hit")

v6_live = client.lookup_ip("2606:4700:4700:0000:0000:0000:0000:1111")
assert_equal(6, v6_live.ip_version, "IPv6 lookup via canonicalized path")

# Multi-threaded singleflight coalescing
threads = Array.new(8) { Thread.new { client.lookup_ip("8.8.4.4") } }
results_sf = threads.map(&:value)
assert_equal(8, results_sf.length, "All 8 threads resolved")
sf_requests = requests.count { |r| r[:url].end_with?("/v1/ip/8.8.4.4") }
assert_equal(1, sf_requests, "8 concurrent lookups coalesced into 1 HTTP request")

# Batch lookup reuses cached 1.1.1.1 and only sends 8.8.8.8
batch = client.lookup_batch(["1.1.1.1", "8.8.8.8", "1.1.1.1"])
assert_equal(2, batch.count, "Batch returns 2 unique records")
assert_equal("1.1.1.1", batch.results[0].ip, "First batch item is 1.1.1.1")
assert_equal("8.8.8.8", batch.results[1].ip, "Second batch item is 8.8.8.8")
assert_equal("2026-11-10", batch.dataset_version, "Batch dataset_version parsed")
batch_req = requests.find { |r| r[:url].end_with?("/v1/ip/batch") }
assert_equal('{"ips":["8.8.8.8"]}', batch_req[:body], "Batch POST only sent uncached 8.8.8.8")

cached_only = client.lookup_batch(["1.1.1.1"])
assert_equal("2026-11-10", cached_only.dataset_version, "All-cached batch carries dataset_version from records")

stream_ips = (1..140).map { |i| "198.51.100.#{i}" }
chunk_counts = client.lookup_batch_stream(stream_ips).map(&:count)
assert_equal([100, 40], chunk_counts, "lookup_batch_stream yields 100 and 40 IP chunks")

caller_info = client.lookup_caller_ip
assert_equal("203.0.113.25", caller_info.ip, "Caller IP resolved via /v1/ip/me")

net = client.lookup_network("1.1.1.42/24")
assert_equal("1.1.1.0/24", net.queried_cidr, "network queried_cidr parsed (host bits masked)")
assert_equal("1.1.1.0/24", net.matched_network, "network matched_network parsed")
assert_equal(4, net.family, "network family parsed")
assert_equal(24, net.bgp_prefix_length, "network bgp_prefix_length parsed")
assert_equal("2026-11-10", net.dataset_version, "network dataset_version parsed")
assert_equal("1.1.1.0/24", net.record.prefix, "network record.prefix parsed")
assert_equal("CLOUDFLARENET - Cloudflare, Inc.", net.record.organization, "network record.organization parsed")
assert_equal(true, net.record.is_hosting, "network record.is_hosting parsed")
assert_equal(nil, net.record.is_virtual_location, "network record.is_virtual_location nil")
assert_equal("hosting", net.record.connection_type, "network record.connection_type parsed")
assert_equal(0.85, net.record.geo_confidence, "network record.geo_confidence parsed")
assert_equal("Australia", net.record.locations.declared_location.country_name, "network record declared location parsed")
assert_equal(nil, net.record.locations.client_location, "network record client_location nil")
assert_equal(%w[policy-routing-rdap-permitted policy-rfc8805-public], net.record.license_policy_ids, "network record license_policy_ids parsed")
assert_equal(14, net.record.abuse_velocity_score, "network record integer abuse_velocity_score stays Integer")
assert_equal(14, net.lookup.security_extensions.abuse_velocity_score, "integer 0-100 abuse_velocity_score stays Integer")
assert_equal("1.1.1.0", net.lookup.ip, "network lookup parsed as IpLookupResponse")
assert_equal(true, net.lookup.security.is_hosting, "network lookup security parsed")

null_record = fixture("network_1.1.1.0_24")
null_record["record"] = nil
assert_equal(nil, IpScope::NetworkPrefixLookupResponse.from_h(null_record).record, "null network record stays nil")

datasets = client.get_datasets_metadata
assert_equal("2026-11-10", datasets.active_version, "datasets active_version parsed")
assert_equal("2026-11-09", datasets.previous_version, "datasets previous_version parsed")
assert_equal(2, datasets.snapshots.length, "datasets snapshots parsed")
assert_equal("ruleset-2026.11.1", datasets.snapshots.first.ruleset_version, "snapshot ruleset_version parsed")
assert_equal(1_043_211, datasets.snapshots.first.ipv4_prefix_count, "snapshot ipv4_prefix_count parsed")

fb = client.submit_feedback(
  IpScope::FeedbackSubmissionInput.new(
    prefix_or_ip: "8.8.8.42/24",
    role: "network_owner",
    issue_type: "wrong_city",
    requested_correction: { city: "Mountain View", country_code: "US" },
    evidence_url: "https://example.net/geofeed.csv"
  )
)
fb_req = requests.reverse.find { |r| r[:url].end_with?("/v1/feedback") }
assert_equal(
  {
    "prefix_or_ip" => "8.8.8.0/24",
    "role" => "network_owner",
    "issue_type" => "wrong_city",
    "requested_correction" => { "city" => "Mountain View", "country_code" => "US" },
    "contact_consent" => false,
    "evidence_url" => "https://example.net/geofeed.csv"
  },
  JSON.parse(fb_req[:body]),
  "Feedback body matches the API schema"
)
assert_equal("fb_3f9a2c71-b4e", fb.id, "Feedback id parsed")
assert_equal("2026-11-10T09:15:42.118Z", fb.created_at, "Feedback camelCase createdAt parsed")
assert_equal("pending_review", fb.status, "Feedback status parsed")
assert_equal("wrong_city", fb.issue_type, "Feedback issue_type parsed")
assert_equal(
  "2026-11-10T00:00:00Z",
  IpScope::FeedbackSubmissionResponse.from_h("created_at" => "2026-11-10T00:00:00Z").created_at,
  "Feedback snake_case created_at also accepted"
)

client.submit_feedback(IpScope::FeedbackSubmissionInput.new(prefix_or_ip: "8.8.8.8", role: "user", issue_type: "other"))
assert_equal(
  '{"prefix_or_ip":"8.8.8.8","role":"user","issue_type":"other","requested_correction":{},"contact_consent":false}',
  requests.last[:body],
  "Empty requested_correction encodes as JSON object"
)

requests_before = requests.length
[
  ["role", { role: "admin", issue_type: "other" }],
  ["issue_type", { role: "user", issue_type: "wrong_asn" }],
  ["evidence_url", { role: "user", issue_type: "other", evidence_url: "not a url" }],
  ["contact_email", { role: "user", issue_type: "other", contact_email: "nobody" }]
].each do |field, attrs|
  rejected_field = nil
  begin
    client.submit_feedback(IpScope::FeedbackSubmissionInput.new(prefix_or_ip: "8.8.8.8", **attrs))
  rescue IpScope::IpScopeValidationError => e
    rejected_field = e.field
  end
  assert_equal(field, rejected_field, "Invalid feedback #{field} rejected client-side")
end
assert_equal(requests_before, requests.length, "Invalid feedback never reaches the API")

status = client.get_status
assert_equal("healthy", status.status, "Service status parsed")
assert_equal("2026-11-10", status.current_version, "Status snapshot.currentVersion parsed")
assert_equal("2026-11-09", status.snapshot.previous_version, "Status snapshot.previousVersion parsed")

# ---------------------------------------------------------------------------
# 5. Retry on 429 and deep JSON nesting protection
# ---------------------------------------------------------------------------
attempts = 0
retry_client = IpScope::Client.new(
  api_key: TEST_API_KEY,
  retry_options: IpScope::RetryOptions.new(max_retries: 2, initial_delay_seconds: 0.005, max_delay_seconds: 0.02),
  custom_transport: lambda do |_m, _u, _h, _b, _t|
    attempts += 1
    if attempts == 1
      { status: 429, headers: { "Retry-After" => "0.005", "X-RateLimit-Remaining" => "0", "X-RateLimit-Reset" => "1" },
        body: '{"statusCode":429,"message":"Rate limit exceeded for user"}' }
    else
      { status: 200, headers: {}, body: JSON.generate(lookup_payload_for("9.9.9.9")) }
    end
  end
)
retried = retry_client.lookup_ip("9.9.9.9")
assert_equal("9.9.9.9", retried.ip, "Client automatically retries on HTTP 429")
assert_equal(2, attempts, "Exactly 2 attempts performed")

deep_client = IpScope::Client.new(
  api_key: TEST_API_KEY,
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
