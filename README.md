# 🔎 xLFr4n // OSINT

> 🧠 **Open-source intelligence toolkit and research laboratory by xLFr4n.**  
> 🧠 **Laboratorio de inteligencia sobre fuentes abiertas y toolkit de investigación de xLFr4n.**

<p align="center">

[![CI](https://img.shields.io/github/actions/workflow/status/xlfr4n/xLFr4n-OSINT/ci.yml?branch=main&label=CI&logo=githubactions&style=for-the-badge)](https://github.com/xlfr4n/xLFr4n-OSINT/actions)
![Status](https://img.shields.io/badge/status-active-2ea043?style=for-the-badge)
![Scope](https://img.shields.io/badge/scope-public%20sources-111827?style=for-the-badge)
![Docs](https://img.shields.io/badge/docs-ES%20%2B%20EN-4b5563?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)

</p>

---

## 🇪🇸 Español

### 🎯 Qué es

**xLFr4n-OSINT** es el laboratorio destinado a investigar, normalizar y automatizar trabajo de **OSINT (Open-Source Intelligence)** usando información disponible públicamente.

La base funcional ya está establecida y el proyecto está entrando en la fase de expansión controlada de fuentes. La arquitectura, provenance, correlación, evidencia y reporting se mantienen como contratos estables mientras se añaden nuevos collectors.

### 🧭 Objetivo

La dirección del proyecto es reunir en un flujo coherente:

- 🔎 descubrimiento de fuentes públicas;
- 👤 búsqueda por identificadores públicos;
- 🌐 dominios, URLs e infraestructura pública;
- 📚 consulta y normalización de resultados;
- 🔗 correlación entre evidencias;
- 🧾 provenance y referencias de cada hallazgo;
- 📊 exportación de resultados y reporting;
- ⚙️ automatización reproducible.

**Nada de esto se presenta como implementado mientras no exista en el código.**

### 🧱 Principios

```text
SOURCE
  ↓
COLLECT
  ↓
NORMALIZE
  ↓
CORRELATE
  ↓
VERIFY
  ↓
REPORT
```

El proyecto prioriza:

    01  evidencia sobre suposiciones
    02  provenance sobre resultados opacos
    03  fuentes públicas sobre acceso privilegiado
    04  reproducibilidad sobre magia
    05  límites y rate limits desde el diseño
    06  documentación junto al código
    07  datos mínimos necesarios

### 🗺️ Roadmap

```text
FOUNDATION ✅
   ↓
CORE ✅
   ├─ CLI / config
   ├─ normalized findings
   ├─ evidence / fingerprints
   └─ reporting
   ↓
PUBLIC PROVIDERS ✅
   ├─ username: GitHub / GitLab / Gitea
   ├─ domain: RDAP / DNS / CT / TLS / HTTPS
   └─ infrastructure: IP / ASN RDAP
   ↓
EXTERNAL TOOL LAYER 🟢
   ├─ Maigret / Sherlock
   └─ Subfinder / Amass
   ↓
EXPOSURE LAYER 🟢
   ├─ LeakCheck Public
   └─ HIBP Pwned Passwords
   ↓
CORRELATION / EVIDENCE 🟢
   └─ deterministic entity grouping
   ↓
NEXT
   ├─ SpiderFoot / Holehe bridges
   ├─ authenticated breach connectors
   ├─ archives / documents / image intelligence
   └─ batch / scheduled automation
```

### 🚧 Estado actual

🟢 **Core + public-source infrastructure / Núcleo + infraestructura de fuentes**

La base funcional actual incluye:

- 🐍 paquete Python;
- 🧩 provider registry con capabilities explícitas;
- 👤 GitHub, GitLab y Gitea;
- 🌐 RDAP, DNS, Certificate Transparency, TLS y HTTPS metadata;
- 🌍 IP y ASN mediante RDAP;
- 🧾 findings normalizados con provenance;
- 🧠 correlación determinista;
- 🧪 evidence ledger con fingerprints;
- 📊 JSON + Markdown reporting;
- ⚙️ configuración TOML / entorno / CLI;
- ✅ CI con tests deterministas.

Ejemplo:

```bash
python -m xlfr4n_osint username xlfr4n
python -m xlfr4n_osint username xlfr4n --json
```

Los providers públicos forman el núcleo; encima ya existen adapters de exposición, herramientas externas, archives, infraestructura, hashes, archivos locales y APIs autenticadas.

---


## 🧪 Usage

### Username research

```bash
python -m xlfr4n_osint username xLFr4n
python -m xlfr4n_osint username xLFr4n --source github --source gitlab --source gitea
python -m xlfr4n_osint username xLFr4n --json
python -m xlfr4n_osint email user@example.com --all-sources
python -m xlfr4n_osint url https://example.com/ --source urlscan
python -m xlfr4n_osint domain example.com --source wayback --source commoncrawl
python -m xlfr4n_osint ip 192.0.2.10 --source rdap-number --source shodan --source censys
```

### Domain research

```bash
python -m xlfr4n_osint domain example.com
python -m xlfr4n_osint domain example.com --source rdap --source dns --source ctlogs --source tls
python -m xlfr4n_osint domain example.com --json
python -m xlfr4n_osint ip 192.0.2.10
python -m xlfr4n_osint asn AS64500 --json

# Save a report
python -m xlfr4n_osint domain example.com --output reports/example.json --format json
python -m xlfr4n_osint domain example.com --output reports/example.md --format markdown
```


### Batch

Create a JSONL input from the safe example at `examples/batch.jsonl`.

```bash
python -m xlfr4n_osint batch examples/batch.jsonl --output reports/batch.jsonl --format jsonl
python -m xlfr4n_osint batch examples/batch.jsonl --all-sources --json
```

`--all-sources` is explicit and may execute opt-in external tools. Use it only when that broader source set is intended.
### Configuration

The CLI can load an optional TOML file from:

```text
~/.config/xlfr4n-osint/config.toml
```

Start from `config.example.toml`.

Environment overrides:

```bash
export XLFR4N_OSINT_TIMEOUT=5
export XLFR4N_OSINT_USER_AGENT="xLFr4n-Lab/1.0"
```

Explicit CLI values take precedence over file and environment configuration.
### Enabled sources

```bash
python -m xlfr4n_osint sources
python -m xlfr4n_osint sources --json
```

Provider failures are kept inside the report rather than silently discarded.

---

## 🧠 Correlation

The scanner can correlate returned findings using exact, normalized matches only.

It does **not** claim that two public accounts belong to the same person. A shared username is represented as a deterministic correlation between source findings, while different categories remain separate.

JSON reports include a `correlation` object with the grouped entities.

---

## 🇬🇧 English

### 🎯 What it is

**xLFr4n-OSINT** is the laboratory for researching, normalizing and automating **OSINT (Open-Source Intelligence)** workflows using publicly available information.

The repository has moved beyond the initial docs-first stage: collectors, external-tool adapters, correlation, evidence, batch execution and scheduled automation are now implemented and tested.

### 🧭 Direction

The project is designed around a coherent pipeline for:

- 🔎 discovering public sources;
- 👤 searching public identifiers;
- 🌐 domains, URLs and public infrastructure;
- 📚 collecting and normalizing results;
- 🔗 correlating evidence;
- 🧾 preserving provenance for every finding;
- 📊 exporting and reporting results;
- ⚙️ reproducible automation.

**Nothing is described as implemented until it exists in the codebase.**

### 🧱 Principles

Evidence, provenance, public sources, reproducibility, rate-limit awareness, data minimization and documentation are treated as first-class project requirements.

### 🚧 Current status

🟢 **Core v0.1**

The first functional foundation is now available:

- 🐍 dependency-free Python package;
- 🧩 interchangeable provider architecture;
- 👤 public GitHub, GitLab and Gitea username lookup;
- 🌐 RDAP, DNS, Certificate Transparency, TLS and HTTPS metadata;
- 🌍 RDAP IP and ASN registration data;
- 📜 LeakCheck public exposure metadata;
- 🔐 HIBP Pwned Passwords k-anonymity check;
- 🧾 normalized findings with timestamps and provenance;
- 📦 JSON output for automation;
- 🧪 initial tests;
- ⚙️ reproducible CLI.

Example:

```bash
python -m xlfr4n_osint username xlfr4n
python -m xlfr4n_osint username xlfr4n --json
```

The direct provider layer now covers **GitHub, GitLab, Gitea, RDAP, DNS, Certificate Transparency, TLS, HTTPS, IP and ASN registration**, with external-tool and exposure integrations layered on top.

---

## 🔐 Security & responsible use

This project is intended for lawful research, defensive security, investigation of public information and authorized environments.

Do not expose credentials, private keys, session tokens, private datasets or other secrets in issues, commits, generated reports or examples.

See [`SECURITY.md`](./SECURITY.md) for reporting guidance and data boundaries.

---

## 📚 Documentation

- [`BRAND.md`](./BRAND.md) — identity, visual language and writing rules.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — contribution and verification workflow.
- [`SECURITY.md`](./SECURITY.md) — secrets, reporting and data boundaries.
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — collaboration baseline.
- [`CHANGELOG.md`](./CHANGELOG.md) — documented project evolution.
- [`docs/SOURCES.md`](./docs/SOURCES.md) — public source inventory and data boundaries.
- [`docs/PROVENANCE.md`](./docs/PROVENANCE.md) — provenance contract for findings.
- [`docs/CLI.md`](./docs/CLI.md) — command, output and exit-code contract.
- [`docs/INTEGRATIONS.md`](./docs/INTEGRATIONS.md) — upstream tools, APIs and distribution boundaries.
- [`docs/TOOLS_CATALOG.md`](./docs/TOOLS_CATALOG.md) — master catalog of existing OSINT tools and coverage.

---

## ⚡ xLFr4n repository standard

**Display signature:** ⚡ xLFr4n  
**GitHub handle:** `xlfr4n`

Common ecosystem rules:

> 🔎 **Evidence first.**  
> 🔁 **Reproducible by design.**  
> 🧾 **Every important result needs provenance.**  
> 📚 **Documentation stays close to implementation.**

> **⚡ xLFr4n · Investigate → Verify → Document**

<p align="center">
  <strong>⚡ xLFr4n</strong><br>
  <sub>One signature. Different laboratories.</sub>
</p>

### Automation

The repository includes `.github/workflows/scheduled-osint.yml` for manual or explicitly enabled weekly scans. Scheduled execution requires the repository variable `XLFR4N_OSINT_SCHEDULE_ENABLED=true`; manual runs can optionally enable `--all-sources`.
