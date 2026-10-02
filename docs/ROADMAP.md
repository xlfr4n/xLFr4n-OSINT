# 🗺️ xLFr4n-OSINT // Roadmap

## Phase 01 — Foundation ✅

- [x] Bilingual project documentation
- [x] xLFr4n repository identity
- [x] Security and contribution standards
- [x] Initial architecture
- [x] MIT license

## Phase 02 — Core 🟢

- [x] Python package
- [x] CLI
- [x] Provider registry
- [x] Username scanner
- [x] Normalized findings
- [x] Stable report schema
- [x] Provenance metadata
- [x] Deterministic provider tests
- [x] GitHub Actions validation

### Remaining Core work

- [ ] Central logging policy
- [ ] Structured retry/backoff policy

## Phase 03 — Providers

Initial provider:

- [x] GitHub public profile

Planned provider families:

- [ ] URL / domain metadata
- [x] DNS resolution
- [x] Certificate Transparency hosts
- [x] TLS certificate inspection
- [x] HTTPS metadata
- [x] IP registration / RDAP
- [x] ASN registration / RDAP
- [x] IP / ASN registration
- [ ] DNS / certificate intelligence
- [x] public code-platform profiles
  - [x] GitHub
  - [x] GitLab
  - [x] Gitea
- [ ] mature external username-tool adapters
  - [ ] Maigret
  - [ ] Sherlock
  - [ ] SpiderFoot bridge
- [ ] exposure-source adapters
  - [ ] LeakCheck Public
  - [ ] HIBP Pwned Passwords
  - [ ] optional authenticated HIBP breach metadata
- [ ] passive subdomain tool adapters
  - [ ] Subfinder
  - [ ] Amass
- [ ] public social-source adapters
- [ ] web archives
- [ ] public document metadata
- [ ] image / hash intelligence

A provider enters the project only after its source, limits, provenance and tests are documented.

## Phase 04 — Correlation

- [x] entity model
- [ ] relationship model
- [x] deterministic correlation rules
- [ ] evidence graph
- [ ] duplicate handling

## Phase 05 — Evidence & Reporting

- [x] evidence bundles
- [x] payload fingerprints
- [x] JSON export
- [x] Markdown reports
- [ ] investigation summaries
- [x] reproducibility metadata

## Phase 06 — Automation

- [ ] batch jobs
- [ ] scheduled scans
- [ ] CI integrations
- [ ] optional notification adapters

## Project rule

Planned items are not features until implemented and tested.

> **⚡ Build the core. Verify the source. Then scale.**
