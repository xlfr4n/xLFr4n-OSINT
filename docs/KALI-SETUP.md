# 🛠️ xLFr4n-OSINT // Kali setup

## 🇪🇸 Español

El núcleo Python no instala automáticamente bases de datos de herramientas externas. Los adapters de Maigret, Sherlock, Holehe, SpiderFoot, Subfinder, Amass, theHarvester y ExifTool usan instalaciones locales independientes.

### Diagnóstico

Desde el repositorio:

```bash
xlfr4n-osint doctor
```

Para automatización:

```bash
xlfr4n-osint doctor --json
```

El diagnóstico distingue:

- `ready`: el provider puede ejecutarse con el entorno actual;
- `missing-dependency`: falta el ejecutable local requerido;
- `missing-credentials`: falta una credencial configurada;
- `default` / `opt-in`: indica si forma parte del conjunto predeterminado.

### Instalación asistida de herramientas externas

En Kali:

```bash
cd ~/Downloads/xLFr4n-OSINT
bash scripts/install-kali-tools.sh
```

El script intenta utilizar paquetes APT disponibles para Kali/Debian y `pipx` para las herramientas Python. Los fallos individuales se reportan como advertencias; el estado definitivo debe comprobarse con:

```bash
xlfr4n-osint doctor
```

### GUI

```bash
xlfr4n-osint gui
```

Por defecto:

```text
http://127.0.0.1:8787/
```

La GUI es local por defecto. No habilites `--allow-remote` salvo que tengas tus propios controles de acceso delante del servicio.

## 🇬🇧 English

The Python core intentionally does not vendor third-party OSINT databases. Maigret, Sherlock, Holehe, SpiderFoot, Subfinder, Amass, theHarvester and ExifTool remain independently installed upstream tools accessed through adapters.

Use `xlfr4n-osint doctor` to inspect readiness and `bash scripts/install-kali-tools.sh` for assisted Kali setup.

The GUI listens on `127.0.0.1:8787` by default and exposes the same provider registry and normalized reporting engine used by the CLI.
