# 🖥️ xLFr4n-OSINT // CLI Contract

## Commands

| Command | Purpose |
|---|---|
| `username <value>` | public username research |
| `domain <value>` | public domain / infrastructure research |
| `email <value>` | public email exposure / account-presence research |
| `phone <value>` | public phone exposure research |
| `url <value>` | historical/public URL research |
| `person <value>` | public name/person query |
| `ip <value>` | public IP registration and optional host intelligence |
| `asn <value>` | public ASN registration research |
| `hash <value>` | file-hash intelligence through enabled hash providers |
| `file <path>` | local file metadata and hashes |
| `password` | privacy-preserving password exposure check |
| `batch <JSONL>` | bounded multi-target scans |
| `notify <JSON>` | send report summary to optional webhook |
| `gui` | launch the local graphical investigation console |
| `doctor` | inspect provider dependencies, credentials and readiness |
| `sources` | list all registered providers, readiness and capabilities |

## Provider readiness

`doctor` distinguishes installed native/public providers from external tools and authenticated providers that still need local setup:

```bash
xlfr4n-osint doctor
xlfr4n-osint doctor --json
xlfr4n-osint doctor --json --strict
```

`ready` means the provider has its local dependency available and, for authenticated providers, the required credential is configured. `skipped` in a report means the provider was registered but not executable for the current environment; the reason remains visible in the provider execution ledger. `missing-dependency` means its external executable is not installed. `missing-credentials` means an authenticated provider has no configured credential. The command is informational by default; `--strict` returns exit code 1 when any registered provider is not ready.

On Kali, optional external tools can be provisioned with:

```bash
bash scripts/install-kali-tools.sh
```

## Provider selection

By default, only providers marked `default_enabled=true` are selected.

Use `--source NAME` repeatedly to select exact providers:

```bash
python -m xlfr4n_osint domain example.com --source rdap --source dns
```

Use `--all-sources` explicitly to include opt-in providers for that capability:

```bash
python -m xlfr4n_osint username xLFr4n --all-sources
python -m xlfr4n_osint email user@example.com --all-sources
python -m xlfr4n_osint domain example.com --all-sources
python -m xlfr4n_osint batch examples/batch.jsonl --all-sources
```

`--all-sources` cannot be combined with `--source`.

## Output

`--json` writes the normalized machine-readable report to stdout.

`--output PATH --format json` writes the report structure to a file.

`--output PATH --format markdown` writes a human-readable investigation report.

Reports contain:

- normalized findings;
- source provenance;
- deterministic correlation entities;
- exact shared-selector relationships;
- duplicate groups;
- evidence fingerprints;
- investigation summary;
- typed provider errors.

## Batch

Each input line is a JSON object:

```json
{"type":"username","value":"octocat","sources":["github"]}
{"type":"domain","value":"example.com","sources":["rdap","dns","ctlogs"]}
{"type":"email","value":"user@example.com","sources":["leakcheck"]}
```

Supported target types:

```text
username
domain
email
phone
url
person
ip
asn
hash
file
password
```

Batch execution is sequential by default (`--workers 1`). Higher worker counts are bounded by `--workers` and preserve input order in the resulting reports.

Password values are never used as report query identifiers; reports store `<redacted-password>`.

## Password privacy

The HIBP Pwned Passwords provider uses a k-anonymity range request and only returns prevalence metadata.

The password itself is not written to `ScanReport`, findings or generated reports.

## External tools

External tools are invoked with `shell=False`, explicit execution timeouts and captured stdout/stderr.

Tool adapters are opt-in because they may perform a large number of remote checks.

## Notifications

`notify <JSON>` sends only scan-level summary metadata to `XLFR4N_OSINT_WEBHOOK_URL` or the explicit `--webhook` argument.

The notification does not include findings, evidence payloads, credentials or API keys.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | execution completed without provider errors |
| `2` | configuration, input, registry or provider error |

A scan returning zero findings is still a successful execution; absence of results is data, not an error.

Provider failures remain visible in the report with their source and typed error name.

## Configuration precedence

Explicit CLI options override environment variables, which override the optional TOML configuration.

```text
CLI
 ↓
environment
 ↓
config.toml
 ↓
built-in defaults
```

> **⚡ xLFr4n · Stable inputs → Stable outputs**


## GUI

Launch the local graphical console:

```bash
xlfr4n-osint gui
```

The default bind address is `127.0.0.1:8787`. Use `--no-browser` to keep the command headless. Non-loopback binding is rejected unless `--allow-remote` is explicitly supplied.
