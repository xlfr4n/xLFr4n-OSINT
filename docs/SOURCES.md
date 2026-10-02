# 📡 xLFr4n-OSINT // Sources

## Public code forges

### GitHub

The GitHub provider reads public user-profile data from the GitHub REST API.

### GitLab

The GitLab provider uses the public Users API username lookup endpoint.

### Gitea

The Gitea provider uses the public user endpoint on gitea.com.

## Domain registration

### IANA RDAP bootstrap

The RDAP provider first reads IANA's DNS bootstrap registry to discover the authoritative RDAP service for the queried TLD.

It then requests the domain object from the discovered RDAP service.

## Data boundary

The project normalizes public-source metadata and deliberately omits contact details and other fields that are not required for the initial research workflow.

Source behavior, limits and provenance should be documented before a provider is enabled.

> **🔎 Public source ≠ automatically complete or verified.**


### DNS resolution

The DNS provider queries Cloudflare's public DNS-over-HTTPS JSON endpoint for A, AAAA, CNAME, MX, NS, SOA and TXT records.

The provider stores normalized record data and resolver response codes, while keeping the source endpoint in provenance.


### Certificate Transparency

The CT provider queries the public ctlogs.dev hosts endpoint to collect certificate-observed hostnames and their first/last seen metadata.

The free public API documents anonymous access with rate limits; the provider does not use an API key.


### TLS

The TLS provider opens a verified TLS connection to port 443 using Python's standard `ssl.create_default_context()`.

It records certificate subject/issuer, SANs, validity dates, negotiated TLS version and cipher metadata. It does not disable certificate verification.


### HTTPS metadata

The HTTP provider performs a lightweight HTTPS HEAD request and keeps only response status, final URL and selected security/transport headers.

Response bodies and cookies are intentionally not retained.


### IP and ASN registration

The number-resource provider uses IANA RDAP bootstrap registries for IPv4, IPv6 and AS Number space, then queries the discovered authoritative RDAP service.

IANA publishes separate bootstrap registries for IPv4 and AS Number space, with corresponding IPv6 coverage. citeturn934555search0turn934555search1turn934555search5


### Planned exposure sources

- **LeakCheck Public** — free public API for breach-source/category exposure. It does not return passwords or full records. urlLeakCheck API docshttps://docs.leakcheck.io/overview
- **HIBP Pwned Passwords** — free password exposure check using k-anonymity; only a five-character SHA-1 prefix is sent. urlHIBP API docshttps://haveibeenpwned.com/API/V3
- **HIBP breach email search** — authenticated API; will remain an optional connector requiring the user's own API key. urlHIBP API docshttps://haveibeenpwned.com/API/V3


### Exposure / breach intelligence

The exposure layer intentionally separates breach metadata from credential material. `LeakCheck Public` can report exposure-source metadata without returning full records; `HIBP BreachedAccount` returns breach metadata for an email when an authenticated key is available; HIBP also exposes paste and stealer-log lookups subject to subscription and domain requirements. xLFr4n stores metadata and provenance, not recovered passwords, cookies, session tokens or raw credential values. [HIBP API documentation](https://haveibeenpwned.com/API/V3)

A complete global breach corpus does not exist behind one public endpoint. `ALL SOURCES` therefore means every registered provider applicable to the target type and currently available in the local configuration, with every skipped, empty, errored or credential-gated provider shown in the execution ledger.

### Direct Certificate Transparency

`crt.sh` is available as a separate opt-in provider in addition to the existing CT aggregator. The direct provider queries `q=%.<domain>` with expired certificates excluded and deduplication enabled.


### External account-presence tools

Holehe is an opt-in external adapter. Its upstream project documents checks using forgotten-password mechanisms and can return partially masked recovery contact information; xLFr4n intentionally discards those recovery fields and retains account-presence metadata only.
