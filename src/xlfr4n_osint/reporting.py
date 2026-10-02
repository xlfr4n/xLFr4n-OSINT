from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from xlfr4n_osint.correlation import CorrelationEngine
from xlfr4n_osint.evidence import EvidenceBundle
from xlfr4n_osint.models import ScanReport


def build_json_report(report: ScanReport) -> dict[str, Any]:
    payload = report.to_dict()
    payload["correlation"] = CorrelationEngine().build(report).to_dict()
    payload["evidence"] = EvidenceBundle.from_report(report).to_dict()
    return payload


def render_markdown_report(report: ScanReport) -> str:
    payload = build_json_report(report)
    correlation = payload["correlation"]["entities"]
    evidence = payload["evidence"]["records"]

    lines = [
        "# ⚡ xLFr4n-OSINT Investigation Report",
        "",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Query:** `{report.query}`",
        f"- **Started:** `{report.started_at}`",
        f"- **Findings:** {len(report.findings)}",
        f"- **Correlated entities:** {len(correlation)}",
        f"- **Evidence records:** {len(evidence)}",
        "",
        "## Findings",
        "",
    ]

    if report.findings:
        for finding in report.findings:
            lines.extend([
                f"### [{finding.source}] {finding.title}",
                "",
                f"- **Category:** `{finding.category}`",
                f"- **Identifier:** `{finding.identifier}`",
                f"- **URL:** {finding.url}",
                f"- **Observed:** `{finding.observed_at}`",
                f"- **Confidence:** `{finding.confidence}`",
                "",
                "```json",
                json.dumps(finding.data, ensure_ascii=False, indent=2, sort_keys=True),
                "```",
                "",
            ])
    else:
        lines.extend(["No findings returned.", ""])

    if report.errors:
        lines.extend(["## Provider errors", ""])
        for error in report.errors:
            lines.append(
                f"- `{error.get('source', 'unknown')}`: {error.get('error', 'unknown error')}"
            )
        lines.append("")

    lines.extend([
        "## Correlation",
        "",
        "Correlation is deterministic and based on normalized exact matches. It is not an identity assertion.",
        "",
        "```json",
        json.dumps(correlation, ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Evidence ledger",
        "",
        "Each evidence record preserves provenance and a SHA-256 fingerprint of the normalized payload.",
        "",
        "```json",
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "> ⚡ xLFr4n · Observe → Correlate → Preserve → Report",
        "",
    ])
    return "\n".join(lines)


def write_json(report: ScanReport, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_json_report(report), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def write_markdown(report: ScanReport, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown_report(report), encoding="utf-8")
    return path
