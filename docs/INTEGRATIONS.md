# 🔌 xLFr4n-OSINT // Integration Matrix

El proyecto no necesita copiar las bases de datos ni el código de otros proyectos para aprovecharlos.

## Direct public APIs

| Integration | Capability | Cost / access | Default | Data boundary |
|---|---|---|---|---|
| LeakCheck Public | email / username / phone | public free endpoint | opt-in | exposure metadata only |
| crt.sh | certificate hosts | public CT JSON endpoint | opt-in | normalized certificate hostnames |
| HIBP Pwned Passwords | password | free, no API key | default | k-anonymity prevalence only |

## External local tools

| Integration | Capability | Execution | Default | License / distribution note |
|---|---|---|---|---|
| Maigret | username | local CLI | opt-in | use installed upstream; do not copy its database |
| Sherlock | username | local CLI | opt-in | use installed upstream; do not copy its site database |
| Subfinder | passive subdomains | local CLI | opt-in | use installed upstream; respect source restrictions |
| Amass | passive subdomains | local CLI | opt-in | use installed upstream; review subcomponent licenses |
| SpiderFoot | multi-source OSINT | local service/CLI, passive use case | opt-in | bridge only; keep upstream installation independent |
| theHarvester | multi-source domain discovery | local CLI, P0 sources | opt-in | bridge only; preserve source attribution |
| Holehe | email/account enumeration | local CLI | opt-in | recovery fields discarded; bridge only |

## Optional authenticated connectors

| Integration | Purpose | Requirement | Default |
|---|---|---|---|
| HIBP Breach API | email breach metadata | user's own HIBP API key / subscription | opt-in |
| Intelligence X | indexed exposure/document search | user's own API access | opt-in |
| Hudson Rock | infostealer intelligence | user's own API access | opt-in |
| Censys | host/certificate infrastructure intelligence | user's own API access | opt-in |
| Shodan | host/service intelligence | user's own API key | opt-in |
| SecurityTrails | DNS/infrastructure history | user's own API key | opt-in |
| VirusTotal | domain/IP/hash intelligence | user's own API key | opt-in |
| Hunter | email verification/discovery | user's own API key | opt-in |
| URLScan | historical web scans | user's own API key | opt-in |
| Snusbase | breach/combolist search | authenticated service access | not bridged |
| DeHashed | breach search | authenticated service access | not bridged |

Authenticated connectors are intentionally separate from the free core. Credentials, API keys and private datasets are never committed.

| Wayback | historical web archive | public CDX API | opt-in |
| Common Crawl | historical web archive | public CDXJ index | opt-in |
| ExifTool | local document/image metadata | local CLI | opt-in |

## Exposure transparency

For email investigations, the exposure layer can combine `hibp-breaches`, `hibp-pastes`, `hibp-stealerlogs`, `leakcheck`, `intelligence-x`, and other applicable registered providers. Authenticated sources use the operator's own credentials and remain opt-in. HIBP's account, paste and stealer-log searches require authorization/subscription according to the endpoint, while its breach catalogue and Pwned Passwords APIs have separate public/free access characteristics. citeturn400940search1turn709078search2

Results are never presented as a single undifferentiated truth set. Each finding keeps provider provenance, observation time, source URL, and an evidence fingerprint; each provider also records whether it returned findings, returned no findings, timed out, or errored.

## External-tool contract

External integrations run through `run_external_command()` with `shell=False`, explicit timeouts, captured stdout/stderr and typed execution errors.

Each adapter is responsible for:

- translating upstream output into `Finding` objects;
- preserving the upstream tool name and command provenance;
- filtering output to the requested scope;
- never assuming that an upstream positive result is an identity assertion;
- remaining opt-in when the tool may perform many remote checks.

## Why this architecture

Established tools already maintain large, changing source databases. Reimplementing them would create duplicate maintenance and lower coverage.

Therefore:

```text
upstream specialist tool
        ↓
     adapter
        ↓
normalized Finding
        ↓
xLFr4n correlation / evidence / reporting
```

> ⚡ Reuse the ecosystem. Own the normalization, evidence and correlation layer.
