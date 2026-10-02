# 🧾 xLFr4n-OSINT // Provenance

## 🇪🇸 Español

La provenance responde a una pregunta sencilla:

> **¿De dónde salió este dato y qué ocurrió entre la fuente y el resultado?**

Cada finding debe conservar, cuando la fuente lo permita:

| Campo | Significado |
|---|---|
| `source` | proveedor que produjo el resultado |
| `provenance.source_url` | endpoint o documento consultado |
| `provenance.retrieval_method` | mecanismo utilizado para obtenerlo |
| `observed_at` | instante en que xLFr4n observó el resultado |
| `url` | recurso público relacionado con el hallazgo |
| `confidence` | nivel de confianza declarado por el provider |
| `data` | datos normalizados obtenidos de la fuente |

### Reglas

- No convertir ausencia de datos en una afirmación.
- No presentar inferencias como observaciones.
- Mantener timestamps en UTC.
- Conservar la URL pública relevante.
- Documentar transformaciones importantes.
- Separar errores de findings válidos.

## 🇬🇧 English

Provenance answers a simple question:

> **Where did this data come from, and what happened between the source and the result?**

The same fields and rules apply in English.

## Confidence

Confidence is a documented property of the provider result, not a guarantee of truth.

A future provider may define a more precise confidence model, but it must document its semantics before using new levels.

## Data minimization

Collect only the public information required for the research operation. Do not turn provenance into a reason to retain unnecessary personal data.

> **🔎 Observe. 🧾 Attribute. 🔁 Reproduce.**


## Evidence ledger

The evidence bundle records provenance and a SHA-256 fingerprint of each finding payload. It is an audit aid: it can show which normalized payload was observed without duplicating the complete payload in a separate evidence record.
