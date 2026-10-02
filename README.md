# 🔎 xLFr4n // OSINT

> 🧠 **Open-source intelligence toolkit and research laboratory by xLFr4n.**  
> 🧠 **Laboratorio de inteligencia sobre fuentes abiertas y toolkit de investigación de xLFr4n.**

<p align="center">

![Status](https://img.shields.io/badge/status-foundation-ff3344?style=for-the-badge)
![Scope](https://img.shields.io/badge/scope-public%20sources-111827?style=for-the-badge)
![Docs](https://img.shields.io/badge/docs-ES%20%2B%20EN-4b5563?style=for-the-badge)

</p>

---

## 🇪🇸 Español

### 🎯 Qué es

**xLFr4n-OSINT** es el laboratorio destinado a investigar, normalizar y automatizar trabajo de **OSINT (Open-Source Intelligence)** usando información disponible públicamente.

El repositorio acaba de establecerse y esta primera etapa es deliberadamente **docs-first**: antes de añadir collectors, correlación o automatización, se fija una arquitectura clara, trazabilidad de fuentes y límites operativos.

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
PHASE 01  Foundation
          ├─ project standards
          ├─ source model
          ├─ evidence model
          └─ documentation

PHASE 02  Core
          ├─ CLI
          ├─ configuration
          ├─ logging
          └─ normalized output

PHASE 03  Providers
          ├─ source adapters
          ├─ retries / rate limits
          └─ provenance

PHASE 04  Correlation
          ├─ entity resolution
          ├─ relationships
          └─ evidence graph

PHASE 05  Reporting
          ├─ JSON
          ├─ Markdown
          └─ investigation reports

PHASE 06  Automation
          ├─ scheduled jobs
          ├─ integrations
          └─ CI validation
```

### 🚧 Estado actual

🟢 **Core v0.1 / Núcleo v0.1**

La primera base funcional ya está disponible:

- 🐍 paquete Python sin dependencias externas;
- 🧩 arquitectura de providers intercambiables;
- 🔎 búsqueda inicial de username mediante GitHub, GitLab y Gitea;
- 🧾 modelo normalizado de findings con timestamp y provenance;
- 📦 salida JSON para automatización;
- 🧪 tests iniciales;
- ⚙️ CLI reproducible.

Ejemplo:

```bash
python -m xlfr4n_osint username xlfr4n
python -m xlfr4n_osint username xlfr4n --json
```

La búsqueda de GitHub es solo el **primer provider**. Las siguientes fases ampliarán fuentes y tipos de investigación sin convertir el proyecto en una colección opaca de scrapers.

---

## 🇬🇧 English

### 🎯 What it is

**xLFr4n-OSINT** is the laboratory for researching, normalizing and automating **OSINT (Open-Source Intelligence)** workflows using publicly available information.

The repository has just been established and this first stage is intentionally **docs-first**: architecture, source provenance and operational boundaries come before collectors, correlation and automation.

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
- 🔎 initial public GitHub username lookup;
- 🧾 normalized findings with timestamps and provenance;
- 📦 JSON output for automation;
- 🧪 initial tests;
- ⚙️ reproducible CLI.

Example:

```bash
python -m xlfr4n_osint username xlfr4n
python -m xlfr4n_osint username xlfr4n --json
```

The first provider family now covers **GitHub, GitLab and Gitea**. Future phases will expand into domain, DNS, certificate, archive and other public-source families while keeping evidence, provenance and reproducibility explicit.

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