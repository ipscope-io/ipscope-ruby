<div align="center">
  <br />
  <a href="https://ipscope.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" />
      <img alt="ipscope" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" height="32" />
    </picture>
  </a>
  <h1>ipscope for Ruby</h1>
  <p><strong>Official zero-dependency Ruby server SDK for ipscope — IP geolocation, BGP ASN, and VPN/proxy detection</strong></p>
  <p>
    <a href="https://rubygems.org/gems/ipscope"><img src="https://img.shields.io/gem/v/ipscope.svg?style=flat-square&label=gem&color=0f172a" alt="RubyGems version" /></a>
    <img src="https://img.shields.io/badge/ruby-%3E%3D2.6-0f172a?style=flat-square" alt="Ruby >= 2.6" />
    <img src="https://img.shields.io/badge/dependencies-zero-0f172a?style=flat-square" alt="Zero dependencies" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-0f172a?style=flat-square" alt="MIT licence" /></a>
    <a href="https://ipscope.io/docs/sdks/ruby"><img src="https://img.shields.io/badge/docs-ipscope.io-0f172a?style=flat-square" alt="Documentation" /></a>
  </p>
  <br />
  <a href="https://ipscope.io">
    <img alt="ipscope Ruby SDK" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/banner.webp" width="100%" />
  </a>
</div>

<br />

## What is this

`ipscope` is the official, zero-external-dependency, thread-safe Ruby server SDK for [ipscope](https://ipscope.io). Built entirely on Ruby's standard library (`net/http`, `json`, `ipaddr`, `resolv`, `uri`), it queries the [ipscope REST API](https://ipscope.io/products/api) for physical and declared [IP geolocation](https://ipscope.io/products/geolocation), [BGP origin ASN and prefix routing](https://ipscope.io/products/network), and [VPN, residential proxy, Tor exit, and relay detection](https://ipscope.io/products/privacy).

Every `IpScope::Client` includes a `Mutex`-synchronized `O(1)` LRU + TTL cache (`max_entries: 512` default, `< 400 KB` memory footprint), singleflight request coalescing across threads, a hard `2 MiB` streaming response ceiling with bounded JSON depth (`16`) to protect Puma and Sidekiq workers, and constant-RAM batch streaming for 10,000+ IPs. For offline lookups in Ruby, see our [downloadable MMDB and CSV.gz databases](https://ipscope.io/docs/databases/mmdb).

---

## Getting started

### 1. Get an API key

Create a free account at [dashboard.ipscope.io](https://dashboard.ipscope.io/auth/login) and copy your server API key (`<public>:<private>`).

### 2. Install the gem

Add to your `Gemfile`:

```ruby
gem "ipscope"
```

Or install directly:

```bash
gem install ipscope
```

### 3. Look up an IP address

```ruby
require "ipscope"

client = IpScope::Client.new(api_key: ENV.fetch("IPSCOPE_API_KEY"))

info = client.lookup_ip("8.8.8.8")
puts "#{info.ip} #{info.geo.country_code} AS#{info.network.asn} #{info.network.organization}"
```

---

## Contents

- [Lookups](#lookups)
- [Streaming large IP lists](#streaming-large-ip-lists)
- [Network CIDR prefix lookups](#network-cidr-prefix-lookups)
- [Rate-limit metadata](#rate-limit-metadata)
- [Submitting feedback](#submitting-feedback)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Help](#help)
- [Licence](#licence)

---

## Lookups

```ruby
require "ipscope"

client = IpScope::Client.new(api_key: "<public>:<private>")

# 1. Single IPv4 or IPv6 lookup (cached in bounded LRU & singleflight-coalesced)
ip_info = client.lookup_ip("8.8.8.8")
puts "#{ip_info.ip} IPv#{ip_info.ip_version} #{ip_info.geo.country_code} " \
     "AS#{ip_info.network.asn} #{ip_info.network.organization}"
# Security booleans are true, false, or nil (nil = not enough evidence)
puts "VPN: #{ip_info.security.is_vpn.inspect} Hosting: #{ip_info.security.is_hosting.inspect} " \
     "Tor exit: #{ip_info.security.is_tor_exit.inspect} Anonymizer: #{ip_info.security.anonymizer_type}"
puts "Connection: #{ip_info.connection&.connection_type || 'n/a'} Dataset: #{ip_info.dataset_version}"

# 2. Caller IP lookup (GET /v1/ip/me)
me = client.lookup_caller_ip

# 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
batch = client.lookup_batch(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
batch.results.each do |record|
  puts "#{record.ip} -> #{record.network.organization}"
end
```

---

## Streaming large IP lists

Enrich 10,000+ IP addresses with `< 400 KB` steady-state memory overhead using `lookup_batch_stream`:

```ruby
client.lookup_batch_stream(large_ip_list) do |chunk|
  chunk.results.each do |record|
    puts "#{record.ip} #{record.geo.country_code}"
  end
end
```

---

## Network CIDR prefix lookups

Inspect the longest-matching routed BGP prefix and its base address intelligence via `lookup_network`:

```ruby
prefix = client.lookup_network("8.8.8.0/24")
puts "#{prefix.queried_cidr} matched #{prefix.matched_network} org: #{prefix.record&.organization || 'n/a'}"
```

---

## Rate-limit metadata

Inspect the parsed `X-RateLimit-*` headers from the last request or inspect service health and dataset versions:

```ruby
limits = client.last_rate_limit
puts "#{limits&.remaining}/#{limits&.limit}, resets in #{limits&.reset_after_seconds}s"

puts client.get_status.current_version
puts client.get_datasets_metadata.active_version
```

---

## Submitting feedback

Report outdated geolocation or anonymity classifications directly via `submit_feedback`:

```ruby
client.submit_feedback(
  IpScope::FeedbackSubmissionInput.new(
    prefix_or_ip: "8.8.8.0/24",
    role: "network_owner",    # network_owner | user | researcher
    issue_type: "wrong_city", # see IpScope::FeedbackSubmissionInput::ISSUE_TYPES
    requested_correction: { "city" => "Mountain View" },
    evidence_url: "https://example.net/geofeed.csv"
  )
)
```

---

## Requirements

- Ruby 2.6 or later (zero external runtime gem dependencies).

---

## Documentation

| Topic | Link |
| :--- | :--- |
| Ruby SDK guide | [ipscope.io/docs/sdks/ruby](https://ipscope.io/docs/sdks/ruby) |
| REST API overview | [ipscope.io/docs/api/overview](https://ipscope.io/docs/api/overview) |
| Single & batch IP lookups | [ipscope.io/docs/api/single-ip](https://ipscope.io/docs/api/single-ip) |
| Network CIDR prefix lookups | [ipscope.io/docs/api/network-prefix](https://ipscope.io/docs/api/network-prefix) |
| Errors & rate limits | [ipscope.io/docs/api/errors](https://ipscope.io/docs/api/errors) |
| Downloadable MMDB databases | [ipscope.io/docs/databases/mmdb](https://ipscope.io/docs/databases/mmdb) |

---

## Help

- Bugs and feature requests: [open an issue](https://github.com/ipscope-io/ipscope-ruby/issues)
- Account, billing and integration questions: [contact@ipscope.io](mailto:contact@ipscope.io)
- Security vulnerabilities: see the [security policy](https://github.com/ipscope-io/.github/blob/main/SECURITY.md)

---

## Licence

[MIT](LICENSE). Made by [ipscope](https://ipscope.io).
