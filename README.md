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

client = IpScope::Client.new(api_key: "ips_live_your_api_key_here")

# 1. Single IPv4 or IPv6 lookup (cached automatically in bounded LRU cache)
ip_info = client.lookup_ip("8.8.8.8")
puts "#{ip_info.ip} #{ip_info.geo.country_code} AS#{ip_info.network.asn}"
puts "VPN: #{ip_info.security.is_vpn} Threat: #{ip_info.security.threat_level}"

# 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
batch = client.lookup_batch(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
batch.results.each do |record|
  puts "#{record.ip} -> #{record.network.org}"
end

# 3. Memory-bounded streaming batch lookup for 10,000+ IPs (constant O(chunk) RAM)
client.lookup_batch_stream(large_ip_list) do |chunk|
  chunk.results.each do |record|
    # Process each record with < 400 KB steady-state memory overhead
  end
end

# 4. Network CIDR prefix lookup
prefix = client.lookup_network("8.8.8.0/24")
puts "#{prefix.requested_cidr} matches: #{prefix.total_matches}"
```
