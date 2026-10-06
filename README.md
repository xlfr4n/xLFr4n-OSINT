# 🔎 xLFr4n // OSINT

> **Public-source intelligence tooling with provenance, normalization and reproducible output.**

<p align="center">
[![CI](https://img.shields.io/github/actions/workflow/status/xlfr4n/xLFr4n-OSINT/ci.yml?branch=main&label=CI&logo=githubactions&style=for-the-badge)](https://github.com/xlfr4n/xLFr4n-OSINT/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-111827?style=for-the-badge)](https://github.com/xlfr4n/xLFr4n-OSINT/blob/main/LICENSE)
</p>

## 🇪🇸 Español

### 🎯 Qué es

xLFr4n-OSINT es un toolkit de investigación sobre **fuentes públicamente accesibles**. El proyecto separa proveedores por capacidad, normaliza sus resultados, conserva provenance y construye reporting reproducible.

El principio operativo es:

> **fuente → observación → evidencia → interpretación**

Lo público no equivale automáticamente a verificado, completo o actual.

### 🧭 Capacidades

| Target | Ejemplo |
|---|---|
| Username | `python -m xlfr4n_osint username xLFr4n` |
| Domain | `python -m xlfr4n_osint domain example.com` |
| Email | public exposure / account-presence research |
| Phone | public exposure research |
| URL | historical/public URL research |
| Person | public name/person queries |
| IP / ASN | registration and optional host intelligence |
| Hash | hash intelligence through enabled providers |
| File | local metadata and hashes |
| Password | privacy-preserving exposure check |
| Batch | bounded JSONL scans |

### 📦 Estado

🟢 **Functional toolkit + local GUI**

El árbol actual incluye CLI Python, registry de providers, providers públicos, adaptadores externos opt-in, correlación determinista, evidence ledger, reporting JSON/Markdown y una consola gráfica local.

### 🇺🇸 English

xLFr4n-OSINT is a research toolkit for **publicly accessible sources**. It separates providers by capability, normalizes results, preserves provenance and produces reproducible reports.

The operating principle is:

> **source → observation → evidence → interpretation**

Publicly accessible data is not automatically verified, complete or current.

---

# 🚀 Quick start

~~~bash
python -m xlfr4n_osint username xLFr4n
python -m xlfr4n_osint username xLFr4n --json
python -m xlfr4n_osint domain example.com --source rdap --source dns
~~~

### Report

~~~bash
python -m xlfr4n_osint domain example.com --output report.json --format json
python -m xlfr4n_osint domain example.com --output report.md --format markdown
~~~

### Batch

~~~json
{"type":"username","value":"octocat","sources":["github"]}
{"type":"domain","value":"example.com","sources":["rdap","dns","ctlogs"]}
~~~

Batch execution is bounded and sequential by default.

---

# 🧠 Provider model

Providers are capability-based and explicitly track readiness.

~~~bash
xlfr4n-osint sources
xlfr4n-osint doctor
xlfr4n-osint doctor --json
xlfr4n-osint doctor --json --strict
~~~

`ready` means a provider can be constructed with the current environment. External tools and authenticated providers can remain opt-in.

Use exact sources with `--source`. Use `--all-sources` only when you deliberately want every opt-in provider for the capability.

---

# 🖥️ Local GUI

~~~bash
xlfr4n-osint gui
~~~

Default address: `http://127.0.0.1:8787/`.

The local console exposes dashboard metrics, target selection, provider registry state, findings, deterministic correlations, error information, normalized reports, history and JSON export.

Non-loopback binding is blocked unless `--allow-remote` is explicitly supplied.

---

# 🧾 Evidence & provenance

Every normalized finding should retain enough context to answer:

- where did this come from?
- when was it retrieved?
- what transformation was applied?
- what is known versus inferred?
- what limitations remain?

Generated reports include source provenance, correlation entities, duplicate groups, evidence fingerprints, summaries and typed provider errors.

---

# 🔐 Security & responsible use

The project is intended for lawful public-source research, defensive security work and authorized environments.

Never commit API keys, cookies, webhook secrets, private keys, passwords or private datasets.

Password checks are privacy-preserving; password values are not written to reports.

---

# 🧪 Verification

~~~bash
python -m pytest
~~~

The project keeps provider behavior and frontend syntax under automated verification.

---

# 📚 Documentation

- `docs/CLI.md` — command and output contract
- `docs/GUI.md` — local GUI
- `docs/SOURCES.md` — source inventory
- `docs/PROVENANCE.md` — provenance contract
- `docs/INTEGRATIONS.md` — provider and external-tool boundaries
- `docs/KALI-SETUP.md` — Kali provider setup
- `docs/TOOLS_CATALOG.md` — tool coverage catalog
- `BRAND.md` — xLFr4n project identity

---

# ⚡ xLFr4n standard

<div align="center"><strong>INVESTIGATE → VERIFY → DOCUMENT</strong><br><sub>Evidence first · Provenance always</sub></div>