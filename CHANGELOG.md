# 📝 Changelog

All notable changes to **xLFr4n-OSINT** are documented here.

## 2026-10-02 — Transparent orchestration / Exposure intelligence

### Added

- ⚡ Bounded concurrent provider execution for investigations and batch items.
- 🧾 Per-provider execution ledger with status, duration, finding count, errors and skip reasons.
- 🔐 Accurate authenticated-provider readiness reporting in `doctor`.
- 🕷️ Kali SpiderFoot executable detection now defaults to `spiderfoot`.
- 🧩 HIBP paste and stealer-log metadata adapters.
- 🌐 HIBP verified-domain breach and stealer-log metadata adapters.
- 🔗 Exact public-selector correlation across distinct providers without identity assertions.
- ⚙️ Configurable provider concurrency via TOML/environment.
- 🖥️ GUI collection ledger and explicit skipped-provider state.

### Documentation

- 📚 Expanded breach/exposure coverage and provenance boundaries.
- 🧭 Updated provider catalog and CLI contract.

## 2026-10-02

- Added provider readiness doctor and Kali external-tool bootstrap.
- GUI provider registry now exposes dependency/credential readiness.
- Added real Markdown report export from the local GUI.


### Added

- 🔎 Repository foundation and bilingual README.
- 🧭 Initial OSINT architecture and roadmap.
- 🧾 Provenance-first documentation rules.
- 🔐 Security, contribution and code-of-conduct standards.
- ⚡ xLFr4n project identity.

> This entry documents the initial repository foundation; it does not imply that planned OSINT collectors are already implemented.

## 2026-10-02 — Core / Providers

### Added

- 🧩 Extensible provider registry with explicit capabilities.
- 👤 GitHub, GitLab and Gitea public username providers.
- 🌐 Domain capability routing.
- 📋 IANA-bootstrap RDAP provider.
- 🌐 Public DNS-over-HTTPS provider.
- 📜 Certificate Transparency host provider.
- 🧾 First-class provenance and stable scan metadata.
- 🧪 Deterministic provider and orchestration tests.
- ✅ GitHub Actions validation for the complete test suite.

### Core

- 🌍 Added public IP and ASN RDAP research through IANA bootstrap registries.

- 🔐 Verified TLS certificate inspection on TCP/443.
- 🌐 Domain CLI routing through explicit provider capabilities.

### Documentation

- 🧱 Architecture and source inventory.
- 🧾 Provenance contract.
- 🗺️ Phased roadmap.
- ⚡ xLFr4n repository standards.

> The project intentionally exposes only capabilities backed by implementation and tests.


## 2026-10-02 — Local GUI

### Added — Local GUI

- 🖥️ Local graphical investigation console backed by the existing Python engine.
- 🎛️ Target-type, provider-mode and timeout controls.
- 📊 Dashboard, findings, metrics and deterministic correlation graph.
- 🧾 Local report history and JSON export.
- ◈ Live provider registry and capability view.
- 🔐 Password redaction preserved through GUI scans and saved reports.
- 🧪 Dedicated GUI service tests.
- 📦 GUI static assets packaged with the Python distribution.
