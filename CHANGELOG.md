# Changelog

All notable changes to the `ipscope` gem are documented here.
The project follows [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-10

1.0.0 did not match the live IPScope API. Several methods called URLs that do not
exist, and the response models were built around field names the API never sends,
so most fields came back as `nil`/`false` even when the request worked. 1.1.0 fixes
the gem against the real API at `https://api.ipscope.io`.

### Fixed

- **Endpoint paths** (each returned HTTP 404 in 1.0.0):
  - `lookup_caller_ip` now calls `GET /v1/ip/me` (was `GET /v1/ip`).
  - `lookup_network` now calls `GET /v1/networks/{address}/{length}` (was `/v1/network/...`).
  - `get_datasets_metadata` now calls `GET /v1/metadata/datasets` (was `/v1/datasets/metadata`).
- **Response models rebuilt from the API's response contract.**
  - `IpLookupResponse`: `ip_version`, `matched_network`, `dataset_version`, and `updated_at` (may be `nil`).
  - `GeoBlock`: `country_code`, `subdivision`, `city`, `postal_code`, `latitude`, `longitude`,
    `timezone`, `location_type`, `confidence`, `accuracy_radius_km`, `declared_country_code`,
    `physical_country_code`, `is_virtual_location`.
  - `NetworkBlock`: `asn`, `organization`.
  - `SecurityBlock`: `is_vpn`, `is_hosting`, `is_tor_exit`, `is_proxy`, `is_relay`,
    `anonymizer_type`, `confidence`, `reason_codes`. The booleans can now be `nil`: `nil` means
    the API did not have enough evidence, which is different from `false`.
  - `ConnectionBlock`: `connection_type`, `is_residential`, `is_mobile`, `is_business`, `is_hosting`.
  - `SecurityExtensionsBlock`: `abuse_velocity_score`, `is_known_scanner`, `observation_recency_hours`.
    `abuse_velocity_score` is passed through unchanged. The API contract defines it as an
    Integer 0–100 (higher is worse). API releases from before that change serve a Float in
    0.0–1.0, so code written against both should check which form it got.
  - `connection` and `security_extensions` are `nil` when your plan does not license those
    field families (the API leaves those blocks out).
  - `BatchLookupResponse` gains `dataset_version`.
  - `NetworkPrefixLookupResponse` is now `queried_cidr`, `matched_network`, `family`,
    `bgp_prefix_length`, `dataset_version`, `record` (a `CanonicalNetworkPrefixRecord` with the
    snapshot's own fields in snake_case, or `nil`), and `lookup` (a full `IpLookupResponse`).
    New supporting classes: `SeparatedLocations`, `LocationAssertion`.
  - `DatasetsMetadataResponse` is now `active_version`, `previous_version`, `snapshots`
    (`snapshot_version`, `digest`, `ruleset_version`, `published_at`, `ipv4_prefix_count`, `ipv6_prefix_count`).
  - `ServiceStatusResponse` is now `status` plus `snapshot` (`ServiceSnapshotInfo` with
    `current_version`/`previous_version`), with `current_version`/`previous_version` helpers.
- **`submit_feedback` sends the body the API accepts:** `prefix_or_ip`, `role`
  (`network_owner`|`user`|`researcher`), `issue_type` (`wrong_country`|`wrong_city`|
  `false_positive_vpn`|`false_positive_hosting`|`false_positive_tor`|`virtual_location_mismatch`|`other`),
  `requested_correction` (Hash), and optionally `evidence_url`, `contact_consent`, `contact_email`.
  The gem checks role, issue type, URL, and email before sending the request.
  `FeedbackSubmissionResponse` reads the API's `createdAt` (and still accepts `created_at`).
- **Rate-limit headers:** the gem now parses `X-RateLimit-Limit`, `-Remaining`, `-Reset`, and `-Scope`.
  `X-RateLimit-Reset` is the number of **seconds until the window resets**, exposed as
  `RateLimitMetadata#reset_after_seconds`; `#scope` is new (e.g. `"user"`). The gem no longer
  parses `X-RateLimit-Credits-Remaining` or `X-RateLimit-Tier`, which the API never sends.
- The README examples now use the real API fields.

### Deprecated

These still work in 1.1.x and will be removed in 2.0. The model accessors print a deprecation
warning (silenced by `ruby -W0`).

- `RateLimitMetadata#reset_epoch_seconds` (and the `reset_epoch_seconds:` constructor keyword):
  the name was wrong. It returns the **same seconds-until-reset value** as `#reset_after_seconds`,
  not an epoch timestamp. Use `#reset_after_seconds`.
- `RateLimitMetadata#credits_remaining`, `RateLimitMetadata#plan_tier`: always `nil` (no such headers).
- `NetworkBlock#org` → `#organization`.
- `SecurityBlock#is_tor` → `#is_tor_exit`; `SecurityBlock#is_datacenter` → `#is_hosting`.
- `IpLookupResponse#version` → `#ip_version`.

### Breaking changes

- `FeedbackSubmissionInput` now takes the API's fields (`prefix_or_ip:`, `role:`, `issue_type:`,
  `requested_correction:`, `evidence_url:`, `contact_consent:`, `contact_email:`). The 1.0
  keywords (`ip_or_cidr:`, `suggested_*:`, `notes:`) are gone. The API rejected every 1.0
  submission, so no working code depended on them.
- 1.0 model readers for fields the API never sends have been removed: for example `threat_level`,
  `threat_types`, `asn_name`, `isp`, `bgp_prefix`, `rir`, `is_bogon`, `country_name`, `region_code`,
  the old `ConnectionBlock`/`SecurityExtensionsBlock` readers, and the old network, datasets,
  and status response readers. In 1.0 they were always `nil`/`false`/empty. Calling one now
  raises `NoMethodError`.
- The network, datasets, and caller-IP response models changed shape. In 1.0 those methods
  always failed with HTTP 404.

### Notes

- The minimum Ruby version is unchanged (`>= 2.6.0`). The test suite passes on 2.6, 3.2, and 3.3.
