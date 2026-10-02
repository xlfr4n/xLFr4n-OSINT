# ⚡ xLFr4n OSINT GUI

## 🇪🇸 Español

La GUI de **xLFr4n-OSINT** es una consola web local servida por el mismo paquete Python que ejecuta el CLI.

### Arranque

```bash
python -m pip install -e .
xlfr4n-osint gui
```

Por defecto:

```text
http://127.0.0.1:8787/
```

Opciones:

```bash
xlfr4n-osint gui --port 9000
xlfr4n-osint gui --no-browser
xlfr4n-osint gui --host 127.0.0.1 --timeout 30
```

### Qué incluye

**Dashboard** muestra el historial reciente y métricas agregadas.

**New investigation** permite seleccionar:

```text
username · domain · email · phone · url · ip · asn
hash · file · person · password
```

La selección de fuentes tiene tres modos:

- **Default sources** — providers marcados como activos por defecto.
- **Custom selection** — selección explícita por provider.
- **All registered sources** — incluye providers opt-in y requiere activación explícita.

**Results** muestra findings normalizados, fuentes, métricas, entidades correlacionadas, grafo de relaciones deterministas, errores de providers y el reporte JSON completo.

**History** conserva los informes de las investigaciones locales.

**Sources** expone el registry real del motor y sus capabilities.

### Arquitectura

La GUI no duplica los collectors. El flujo es:

```text
Browser
   ↓
Local HTTP service
   ↓
InvestigationService
   ↓
BatchItem + run_item()
   ↓
ProviderRegistry
   ↓
Providers
   ↓
Finding / Correlation / Evidence / Summary
   ↓
JSON report
```

Esto hace que una mejora del motor CLI también esté disponible para la GUI.

### API local

```text
GET  /api/health
GET  /api/sources?type=username
POST /api/scan
GET  /api/reports
GET  /api/reports/<scan_id>
```

`POST /api/scan` acepta:

```json
{
  "type": "username",
  "value": "xLFr4n",
  "sources": ["github"],
  "all_sources": false,
  "timeout": 10
}
```

### Historial

Por defecto:

```text
~/.local/share/xlfr4n-osint/reports/
```

Puedes cambiarlo:

```bash
export XLFR4N_OSINT_REPORT_DIR="/ruta/a/reportes"
```

También funciona en Windows porque la ruta se resuelve con `Path.home()`.

### Seguridad

El servidor escucha en `127.0.0.1` por defecto.

No expongas la interfaz a una red pública sin añadir autenticación, autorización, controles de acceso y una política de transporte adecuada.

Las comprobaciones de contraseña mantienen el contrato de privacidad del CLI: el informe utiliza `<redacted-password>` y la GUI sustituye cualquier aparición del secreto antes de persistir el reporte.

---

## 🇬🇧 English

The **xLFr4n-OSINT GUI** is a local web console served by the same Python package that powers the CLI.

### Start

```bash
python -m pip install -e .
xlfr4n-osint gui
```

Default:

```text
http://127.0.0.1:8787/
```

You can override the bind address, port, browser behavior and provider timeout from the CLI.

### Features

The console provides a dashboard, target selection, source selection, result inspection, deterministic relationship graph, provider error ledger, local report history and JSON export.

Supported engine target types:

```text
username · domain · email · phone · url · ip · asn
hash · file · person · password
```

The GUI reuses the same provider registry, batch execution path, normalized findings, deterministic correlation, evidence ledger and reporting layer as the CLI.

### Security

The service binds to `127.0.0.1` by default.

Password checks remain privacy-preserving and saved reports use `<redacted-password>` rather than the submitted password.

> ⚡ xLFr4n · Investigate → Verify → Document