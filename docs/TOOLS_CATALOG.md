# 🧭 xLFr4n-OSINT // Master Tool Catalog

El objetivo no es reescribir herramientas maduras. El objetivo es reunir su cobertura detrás de una capa común de findings, provenance, correlación y reporting.

## Coverage already connected

| Family | Upstream | xLFr4n mode | Status |
|---|---|---|---|
| Username | GitHub / GitLab / Gitea | native public APIs | ✅ |
| Username | Maigret | external CLI | ✅ opt-in |
| Username | Sherlock | external CLI | ✅ opt-in |
| Email account presence | Holehe | external CLI | ✅ opt-in |
| Multi-source OSINT | SpiderFoot | external CLI, passive use case | ✅ opt-in |
| Domain discovery | theHarvester | external CLI, P0 sources | ✅ opt-in |
| Passive subdomains | Subfinder | external CLI | ✅ opt-in |
| Passive subdomains | Amass | external CLI, passive mode | ✅ opt-in |
| Certificate Transparency | crt.sh | native public endpoint | ✅ opt-in |
| Certificate Transparency | ctlogs.dev | native public endpoint | ✅ |
| Domain registration | IANA RDAP | native | ✅ |
| DNS | Cloudflare DoH | native | ✅ |
| TLS | Python ssl | native | ✅ |
| HTTPS metadata | Python urllib | native | ✅ |
| IP / ASN registration | IANA RDAP | native | ✅ |
| Breach exposure metadata | LeakCheck Public | native public API | ✅ opt-in |
| Password exposure | HIBP Pwned Passwords | k-anonymity | ✅ |
| Breach metadata | HIBP Breach API | user's API key | ✅ opt-in |
| Historical web scans | URLScan | authenticated API | ✅ opt-in |
| Threat / host intelligence | VirusTotal | authenticated API | ✅ opt-in |
| Host intelligence | Censys | authenticated API | ✅ opt-in |
| Host/service intelligence | Shodan | authenticated API | ✅ opt-in |
| DNS / infrastructure history | SecurityTrails | authenticated API | ✅ opt-in |
| Email discovery / verification | Hunter | authenticated API | ✅ opt-in |
| Infostealer exposure metadata | Hudson Rock | authenticated API, sanitized | ✅ opt-in |
| Indexed exposure metadata | Intelligence X | authenticated API, sanitized | ✅ opt-in |
| Local file metadata | ExifTool | local CLI | ✅ opt-in |
| Web archives | Wayback | public CDX API | ✅ opt-in |
| Web archives | Common Crawl | public CDXJ index | ✅ opt-in |

## Coverage through upstream aggregators

theHarvester currently catalogues a broad set of discovery sources, including certificate transparency, Common Crawl, public DNS datasets, search engines, code repositories and optional API-backed providers.

SpiderFoot provides a separate broad module ecosystem and correlation layer. xLFr4n treats it as an external enrichment engine rather than copying its module tree.

## Still catalog-only / not yet bridged

| Tool / service | Role | xLFr4n position |
|---|---|---|
| Intelligence X | indexed exposure / document intelligence | optional authenticated connector |
| Hudson Rock | infostealer intelligence | optional authenticated connector |
| Snusbase | breach / combolist intelligence | optional authenticated connector; metadata boundary |
| DeHashed | breach search | optional authenticated connector; metadata boundary |
| urlscan.io | historical web scans / URLs / hosts | optional authenticated connector |
| VirusTotal | threat / domain / IP intelligence | optional authenticated connector |
| Censys | internet-facing infrastructure intelligence | optional authenticated connector |
| SecurityTrails | DNS / infrastructure history | optional authenticated connector |
| Shodan | host/service intelligence | optional authenticated connector |
| Hunter | email discovery | optional authenticated connector |

## Other established open-source families to evaluate

- `Recon-ng` — modular reconnaissance framework.
- `GHunt` — Google-account/public Google-service investigation; requires operator authentication and is therefore not part of the default public-source core.
- `WhatsMyName` datasets — useful source data for username discovery; use through an adapter/dataset contract rather than copying arbitrary site-checking logic.
- `ExifTool` — document/image metadata extraction layer.
- `dnsrecon`, `massdns`, `dnsx` — DNS resolution/enumeration building blocks; active behavior must remain explicitly scoped.
- `Photon` — website crawler/content discovery; separate from the passive-first default.
- `Metagoofil` and document-focused collectors — candidate sources for the document metadata phase.

## Integration rules

1. Prefer maintained upstream tools over duplicated databases.
2. Keep external tools installed independently from the xLFr4n package.
3. Capture tool version and invocation in provenance when available.
4. Keep high-volume or high-interaction tools opt-in.
5. Never infer ownership or identity solely from a shared identifier.
6. Never persist secrets, API keys or raw credential material in source control.
7. Preserve provider errors, partial results and rate limits.

## Architecture

```text
mature upstream ecosystem
        ↓
source/tool adapter
        ↓
normalized Finding
        ↓
correlation + evidence ledger
        ↓
JSON / Markdown / future PDF
```

> ⚡ xLFr4n rule: reuse what is already maintained; own the normalization and evidence layer.
