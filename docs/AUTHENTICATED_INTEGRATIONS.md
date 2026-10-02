# 🔐 xLFr4n-OSINT // Authenticated Integrations

These connectors are deliberately separate from the public core. They use the operator's own API credentials and stay opt-in.

## Candidate matrix

| Provider | Main value | Credentials | Initial mode |
|---|---|---|---|
| Censys | certificate / host / internet intelligence | API ID + secret | authenticated, opt-in |
| Shodan | host / service intelligence | API key | authenticated, opt-in |
| SecurityTrails | DNS / infrastructure history | API key | authenticated, opt-in |
| VirusTotal | domain / IP / URL threat intelligence | API key | authenticated, opt-in |
| Hunter | email discovery / verification | API key | authenticated, opt-in |
| Intelligence X | indexed exposure / document intelligence | API key | authenticated, opt-in |
| Hudson Rock | infostealer exposure intelligence | API key | authenticated, opt-in |
| Snusbase | breach / combolist intelligence | account/API access | authenticated, opt-in, metadata boundary |
| DeHashed | breach search | account/API access | authenticated, opt-in, metadata boundary |

## Connector rules

- credentials come only from environment variables or user-local configuration;
- no credential is written to `Finding`, evidence, logs or report files;
- requests are bounded by the shared timeout and source-specific limits;
- responses are normalized to metadata and provenance;
- provider-specific raw records are not silently treated as ground truth;
- premium connectors never become default providers;
- every connector gets deterministic mock-based tests before activation.

## Suggested environment namespace

```text
XLFR4N_OSINT_CENSYS_API_ID
XLFR4N_OSINT_CENSYS_API_SECRET
XLFR4N_OSINT_SHODAN_API_KEY
XLFR4N_OSINT_SECURITYTRAILS_API_KEY
XLFR4N_OSINT_VIRUSTOTAL_API_KEY
XLFR4N_OSINT_HUNTER_API_KEY
XLFR4N_OSINT_INTELX_API_KEY
XLFR4N_OSINT_HUDSONROCK_API_KEY
```

> Credentials stay with the operator. The repository contains only connector contracts and tests.
