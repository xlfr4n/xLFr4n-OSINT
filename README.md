<div align="center">

# ⚡ xLFr4n / OSINT

**Investigar con fuentes públicas, conservar la procedencia y poder revisar cada hallazgo.**

<p>
  <a href="https://github.com/xlfr4n/xLFr4n-OSINT/actions"><img src="https://img.shields.io/github/actions/workflow/status/xlfr4n/xLFr4n-OSINT/ci.yml?branch=main&label=CI&logo=githubactions&style=for-the-badge&color=FF3344&labelColor=111318" alt="Estado de CI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-FF3344?style=for-the-badge&logo=python&logoColor=white&labelColor=111318" alt="Python 3.11 o superior"></a>
  <a href="https://github.com/xlfr4n/xLFr4n-OSINT/blob/main/LICENSE"><img src="https://img.shields.io/badge/Licencia-MIT-252A34?style=for-the-badge&labelColor=111318" alt="Licencia MIT"></a>
</p>

<sub>Fuentes públicas · Evidencia trazable · Investigación reproducible</sub>

</div>

---

<p align="center">
  <a href="#qué-es">Qué es</a> ·
  <a href="#tipos-de-objetivo">Objetivos</a> ·
  <a href="#inicio-rápido">Inicio rápido</a> ·
  <a href="#consola-local">Consola</a> ·
  <a href="#evidencia-y-procedencia">Procedencia</a> ·
  <a href="#uso-responsable">Uso responsable</a>
</p>

## Qué es

**xLFr4n-OSINT** es un entorno para organizar investigaciones basadas en fuentes públicas. Separa los proveedores por capacidades, normaliza los resultados y conserva información de procedencia para revisar de dónde salió cada hallazgo y cuándo se obtuvo.

El criterio de trabajo es sencillo:

> **Fuente → Observación → Evidencia → Interpretación**

Que un dato esté disponible públicamente no significa que sea correcto, completo o reciente. Los resultados son pistas que conviene contrastar antes de sacar conclusiones.

## Tipos de objetivo

| Objetivo | Uso previsto |
| --- | --- |
| **Usuario** | Buscar presencia pública con los proveedores habilitados. |
| **Dominio** | Consultar registro, DNS, certificados y fuentes seleccionadas. |
| **Correo / teléfono** | Investigar exposición o presencia pública, respetando la legislación aplicable. |
| **URL** | Consultar fuentes históricas y otras fuentes de URL habilitadas. |
| **Persona** | Realizar consultas basadas en nombres públicos. |
| **IP / ASN** | Consultar datos de registro y, si se habilita, inteligencia de host. |
| **Hash / archivo** | Consultar inteligencia de hashes y metadatos locales. |
| **Lotes** | Procesar entradas JSONL de forma acotada. |

La cobertura real depende de los proveedores configurados y de la disponibilidad de las fuentes externas.

## Inicio rápido

Ejecuta los comandos desde la raíz del repositorio.

**Buscar un nombre de usuario**

~~~bash
python -m xlfr4n_osint username xLFr4n
~~~

**Obtener salida JSON**

~~~bash
python -m xlfr4n_osint username xLFr4n --json
~~~

**Consultar un dominio con fuentes concretas**

~~~bash
python -m xlfr4n_osint domain example.com --source rdap --source dns
~~~

Selecciona las fuentes que necesitas para cada objetivo. No actives todos los proveedores por defecto si una consulta más acotada puede responder a la pregunta.

## Generar informes

Informe JSON:

~~~bash
python -m xlfr4n_osint domain example.com --output report.json --format json
~~~

Informe Markdown:

~~~bash
python -m xlfr4n_osint domain example.com --output report.md --format markdown
~~~

## Procesamiento por lotes

Un lote utiliza una entrada JSONL: un objeto JSON por línea.

~~~json
{"type":"username","value":"octocat","sources":["github"]}
{"type":"domain","value":"example.com","sources":["rdap","dns","ctlogs"]}
~~~

La ejecución por lotes es acotada y secuencial de forma predeterminada. Selecciona solo los tipos de objetivo y las fuentes que necesitas.

## Proveedores y diagnóstico

Los proveedores se registran por capacidad y muestran si están preparados para usarse en el entorno actual.

~~~bash
xlfr4n-osint sources
xlfr4n-osint doctor
xlfr4n-osint doctor --json
xlfr4n-osint doctor --json --strict
~~~

Un proveedor marcado como **ready** puede construirse con la configuración actual. Eso no significa que la fuente externa esté disponible en ese instante ni que vaya a devolver resultados.

Utiliza **--source** para seleccionar fuentes concretas. Emplea **--all-sources** solo cuando quieras activar deliberadamente todos los proveedores opcionales para esa capacidad.

## Consola local

Inicia la interfaz con:

~~~bash
xlfr4n-osint gui
~~~

La dirección predeterminada es http://127.0.0.1:8787/.

La consola reúne métricas de sesión, selección de objetivos, estado del registro de proveedores, hallazgos, correlaciones deterministas, errores, informes normalizados, historial y exportación JSON. La escucha fuera de localhost está bloqueada salvo que se pase explícitamente **--allow-remote**.

Si habilitas el acceso remoto, revisa primero el entorno de ejecución y los controles de red. No expongas una consola de investigación a una red no confiable por comodidad.

## Evidencia y procedencia

Un hallazgo útil debe permitir responder:

- ¿Qué fuente lo proporcionó?
- ¿Cuándo se obtuvo?
- ¿Qué transformación se aplicó?
- ¿Qué parte es un dato y qué parte es una inferencia?
- ¿Qué limitaciones siguen pendientes?

Los informes pueden incluir procedencia de fuentes, entidades correlacionadas, grupos de duplicados, huellas de evidencia, resúmenes y errores tipados de los proveedores.

## Comprobaciones

~~~bash
python -m pytest
~~~

Las pruebas cubren el comportamiento de proveedores y comprobaciones de sintaxis de la interfaz. Antes de publicar cambios, ejecuta la suite y revisa el efecto de las modificaciones sobre el origen y la interpretación de los datos.

## Uso responsable

El proyecto está orientado a investigación lícita con fuentes públicas, seguridad defensiva y entornos autorizados. Respeta la legislación aplicable, las condiciones de las fuentes y la privacidad de las personas.

- No incluyas API keys, cookies, tokens, claves privadas, contraseñas ni conjuntos de datos privados en Git.
- Trata los resultados como pistas que requieren contexto, no como conclusiones automáticas.
- Las comprobaciones de exposición de contraseñas están diseñadas para no escribir los valores de contraseña en los informes.
- No utilices los resultados para acceder a cuentas, acosar a personas o eludir controles de acceso.

## Documentación

- **docs/CLI.md** — comandos y formatos de salida.
- **docs/GUI.md** — consola local.
- **docs/SOURCES.md** — inventario de fuentes.
- **docs/PROVENANCE.md** — criterios de procedencia.
- **docs/INTEGRATIONS.md** — proveedores y herramientas externas.
- **docs/KALI-SETUP.md** — configuración en Kali.
- **docs/TOOLS_CATALOG.md** — catálogo de herramientas.
- **BRAND.md** — identidad del proyecto.

<div align="center">

**Investigar → Verificar → Documentar**  
<sub>⚡ xLFr4n · Primero la evidencia · Procedencia siempre</sub>

</div>

<details>
<summary><strong>English</strong></summary>

## Overview

xLFr4n-OSINT is a toolkit for research based on publicly accessible sources. It separates providers by capability, normalizes their output and preserves provenance so findings can be reviewed and traced back to their source.

**Source → Observation → Evidence → Interpretation**

Public data is not automatically accurate, complete or current. Treat results as leads and verify them before drawing conclusions.

## Quick start

~~~bash
python -m xlfr4n_osint username xLFr4n
python -m xlfr4n_osint username xLFr4n --json
python -m xlfr4n_osint domain example.com --source rdap --source dns
~~~

Write reports as JSON or Markdown:

~~~bash
python -m xlfr4n_osint domain example.com --output report.json --format json
python -m xlfr4n_osint domain example.com --output report.md --format markdown
~~~

Start the local GUI with the command **xlfr4n-osint gui**. By default it listens at http://127.0.0.1:8787/; remote binding requires the explicit **--allow-remote** option.

## Providers and verification

~~~bash
xlfr4n-osint sources
xlfr4n-osint doctor --json
python -m pytest
~~~

A provider marked ready can be constructed with the current environment; this does not guarantee that an external source is reachable or will return data. Select providers explicitly with **--source**, and use **--all-sources** only when you intentionally want every optional provider for the selected capability.

## Responsible use

The project is intended for lawful public-source research, defensive security work and authorized environments. Never commit API keys, cookies, credentials, private datasets or other secrets. Password-exposure checks do not write password values into reports.

</details>