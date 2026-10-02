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
