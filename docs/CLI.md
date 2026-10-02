# 🖥️ xLFr4n-OSINT // CLI Contract

## Commands

| Command | Purpose |
|---|---|
| `username <value>` | public username research |
| `domain <value>` | public domain research |
| `sources` | list enabled providers |

## Output

`--json` writes the normalized machine-readable report to stdout.

`--output PATH --format json` writes the same report structure to a file.

`--output PATH --format markdown` writes a human-readable investigation report.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | scan completed without provider errors |
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
