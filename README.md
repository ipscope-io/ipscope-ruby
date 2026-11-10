# IPScope Official Ruby Server-Side SDK (`ipscope`)

Zero-dependency, thread-safe, memory-bounded Ruby Server-Side SDK for the **IPScope IP Intelligence Platform**.

Scoped strictly to **IP intelligence operations** (single IP lookup, caller IP lookup, batch lookup, chunked/streaming batch lookup, network CIDR prefix lookup, dataset metadata, geolocation/anonymity feedback submission, and service health status) with zero account, wallet, or billing dependencies.

---

## Key Features

- **Zero External Runtime Dependencies**: Built entirely on Ruby's standard library (`net/http`, `json`, `ipaddr`, `resolv`, `uri`).
- **Bounded `O(1)` LRU + TTL Cache**: Default `max_entries: 512` (`< 400 KB` memory footprint) using Ruby's ordered `Hash` protected by a `Mutex` and `Process::CLOCK_MONOTONIC`.
- **Singleflight Request Coalescing**: Concurrent threads looking up the same IP address simultaneously share a single in-flight HTTP request.
- **Hard `2 MiB` Streaming Response Ceiling & Bounded JSON Depth (`16`)**: Protects Ruby workers (Puma, Sidekiq, Unicorn, Pitchfork) against oversized upstream payloads and deeply nested JSON memory bombs.
- **Zero-DNS IPv4/IPv6 & CIDR Validation**: Validates and canonicalizes IP addresses and CIDR prefixes locally without triggering DNS queries.

---

## Installation

Add to your `Gemfile`:

```ruby
gem "ipscope"
```

---

## Quick Start

```ruby
require "ipscope"

# API keys have the form "<public>:<private>" (a UUID, a colon, then a 43-character secret).
client = IpScope::Client.new(api_key: "<public>:<private>")

# 1. Single IPv4 or IPv6 lookup (GET /v1/ip/{ip}; cached in a bounded LRU cache)
ip_info = client.lookup_ip("8.8.8.8")
puts "#{ip_info.ip} IPv#{ip_info.ip_version} #{ip_info.geo.country_code} " \
     "AS#{ip_info.network.asn} #{ip_info.network.organization}"
# Security booleans are true, false, or nil (nil = not enough evidence).
puts "VPN: #{ip_info.security.is_vpn.inspect} Hosting: #{ip_info.security.is_hosting.inspect} " \
     "Tor exit: #{ip_info.security.is_tor_exit.inspect} Anonymizer: #{ip_info.security.anonymizer_type}"
# `connection` and `security_extensions` are nil unless your plan licenses them.
puts "Connection: #{ip_info.connection&.connection_type || 'n/a'} Dataset: #{ip_info.dataset_version}"

# 2. Your own public IP (GET /v1/ip/me)
me = client.lookup_caller_ip

# 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
batch = client.lookup_batch(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
batch.results.each do |record|
  puts "#{record.ip} -> #{record.network.organization}"
end

# 4. Memory-bounded streaming batch lookup for 10,000+ IPs (constant O(chunk) RAM)
client.lookup_batch_stream(large_ip_list) do |chunk|
  chunk.results.each do |record|
    # Process each record with < 400 KB steady-state memory overhead
  end
end

# 5. Network CIDR prefix lookup (GET /v1/networks/{address}/{length})
prefix = client.lookup_network("8.8.8.0/24")
puts "#{prefix.queried_cidr} matched #{prefix.matched_network} org: #{prefix.record&.organization || 'n/a'}"

# 6. Rate limits (per user): seconds until the window resets
limits = client.last_rate_limit
puts "#{limits&.remaining}/#{limits&.limit}, resets in #{limits&.reset_after_seconds}s"

# 7. Report a wrong answer (POST /v1/feedback)
client.submit_feedback(
  IpScope::FeedbackSubmissionInput.new(
    prefix_or_ip: "8.8.8.0/24",
    role: "network_owner",   # network_owner | user | researcher
    issue_type: "wrong_city", # see IpScope::FeedbackSubmissionInput::ISSUE_TYPES
    requested_correction: { "city" => "Mountain View" },
    evidence_url: "https://example.net/geofeed.csv"
  )
)

# 8. Service health and dataset versions
puts client.get_status.current_version
puts client.get_datasets_metadata.active_version
```

Upgrading from 1.0? See [CHANGELOG.md](CHANGELOG.md).
