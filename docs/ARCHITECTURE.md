# 🧱 xLFr4n-OSINT // Architecture

## 🇪🇸 Español

El proyecto separa la investigación en capas pequeñas para que cada fuente pueda cambiar sin romper el núcleo.

```text
CLI
 ↓
Scan orchestration
 ↓
provider interface
 ↓
 ├─ username providers
 │   ├─ GitHub
 │   ├─ GitLab
 │   └─ Gitea
 └─ domain providers
     └─ RDAP
 ↓
Normalized Finding
 ↓
Report / JSON
```

### Core rules

- **Provider:** conoce una fuente, no el resto del sistema.
- **Finding:** formato común para resultados de fuentes distintas.
- **ScanReport:** agrupa resultados y errores sin ocultarlos.
- **CLI:** coordina la ejecución, no contiene lógica específica de cada fuente.
- **Tests:** validan transformaciones y contratos antes de ampliar providers.

La provenance forma parte del resultado desde el principio: fuente, URL, identificador y timestamp de observación.

## 🇬🇧 English

The project separates investigation into small layers so individual sources can evolve without breaking the core.

```text
CLI
 ↓
Scan orchestration
 ↓
provider interface
 ├─ username providers
 │   ├─ GitHub
 │   ├─ GitLab
 │   └─ Gitea
 └─ domain providers
     └─ RDAP
 ↓
Normalized Finding
 ↓
Report / JSON
```

The same architecture rules apply in English: providers stay isolated, findings stay normalized, errors remain visible and provenance is preserved.

## 🛡️ Operational boundary

The initial implementation is intentionally limited to public-source lookups. Future providers should document their source, access method, rate limits and data boundaries before being enabled.

