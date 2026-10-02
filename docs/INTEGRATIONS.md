# 🔌 xLFr4n-OSINT // Integration Matrix

El proyecto no necesita copiar las bases de datos ni el código de otros proyectos para aprovecharlos.

## Direct public APIs

| Integration | Capability | Cost / access | Default | Data boundary |
|---|---|---|---|---|
| LeakCheck Public | email / username / phone | public free endpoint | opt-in | exposure metadata only |
| HIBP Pwned Passwords | password | free, no API key | default | k-anonymity prevalence only |

## External local tools

| Integration | Capability | Execution | Default | License / distribution note |
|---|---|---|---|---|
| Maigret | username | local CLI | opt-in | use installed upstream; do not copy its database |
| Sherlock | username | local CLI | opt-in | use installed upstream; do not copy its site database |
| Subfinder | passive subdomains | local CLI | opt-in | use installed upstream; respect source restrictions |
| Amass | passive subdomains | local CLI | opt-in | use installed upstream; review subcomponent licenses |
| SpiderFoot | multi-source OSINT | local service/CLI | planned | bridge only; keep upstream installation independent |
| Holehe | email/account enumeration | local CLI | planned / high-interaction | bridge only; review exact upstream terms before distribution |

## Optional authenticated connectors

| Integration | Purpose | Requirement | Default |
|---|---|---|---|
| HIBP Breach API | email breach metadata | user's own HIBP API key / subscription | opt-in |
| Intelligence X | indexed exposure/document search | user's own API access | opt-in |
| Hudson Rock | infostealer intelligence | user's own API access | opt-in |
| Snusbase | breach/combolist search | authenticated service access | opt-in / metadata only |
| DeHashed | breach search | authenticated service access | opt-in / metadata only |

Authenticated connectors are intentionally separate from the free core. Credentials, API keys and private datasets are never committed.

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
