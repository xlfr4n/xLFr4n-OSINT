from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from xlfr4n_osint.correlation import CorrelationEngine
from xlfr4n_osint.evidence import EvidenceBundle
from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.summary import build_summary


def build_json_report(report: ScanReport) -> dict[str, Any]:
    payload = report.to_dict()
    payload["correlation"] = CorrelationEngine().build(report).to_dict()
    payload["evidence"] = EvidenceBundle.from_report(report).to_dict()
    payload["summary"] = build_summary(report).to_dict()
    return payload


def render_markdown_report(report: ScanReport) -> str:
    payload = build_json_report(report)
    correlation = payload["correlation"]["entities"]
    relationships = payload["correlation"]["relationships"]
    duplicates = payload["correlation"]["duplicates"]
    evidence = payload["evidence"]["records"]
    summary = payload["summary"]

    lines = [
        "# ⚡ xLFr4n-OSINT Investigation Report",
        "",
        f"- **Scan ID:** `{report.scan_id}`",
        f"- **Query:** `{report.query}`",
        f"- **Started:** `{report.started_at}`",
        f"- **Findings:** {len(report.findings)}",
        f"- **Exact-selector entities:** {len(correlation)}",
        f"- **Exact relationships:** {len(relationships)}",
        f"- **Duplicate groups:** {len(duplicates)}",
        f"- **Evidence records:** {len(evidence)}",
        f"- **Sources:** {summary['source_count']}",
        f"- **Categories:** {summary['category_count']}",
        "",
        "## Provider execution",
        "",
        ]

    if report.provider_runs:
        for execution in report.provider_runs:
            status = execution.get("status", "unknown")
            detail = str(execution.get("finding_count", 0)) + " findings"
            if status == "no-findings":
                detail = "no findings"
            elif execution.get("error"):
                detail = str(execution.get("error"))
            lines.append(
                "- **" + str(execution.get("provider", "unknown")) + "** — `" +
                str(status) + "` — " + detail + " — `" +
                str(execution.get("duration_seconds", 0)) + "s`"
            )
        lines.append("")
    else:
        lines.extend(["No provider execution records.", ""])

    lines.extend(["## Findings", ""])
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
                *([f"- **Verification:** `{finding.data['verification']}`"] if finding.data.get("verification") else []),
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
        "## Exact-selector correlation",
        "",
        "Relationships are deterministic links created from normalized exact selectors. They are not identity assertions and do not establish that accounts belong to the same person.",
        "",
        "```json",
        json.dumps(
            {
                "entities": correlation,
                "relationships": relationships,
                "duplicates": duplicates,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
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


def build_batch_json(reports: list[ScanReport]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "report_count": len(reports),
        "reports": [build_json_report(report) for report in reports],
    }


def write_batch_json(reports: list[ScanReport], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(build_batch_json(reports), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def write_batch_jsonl(reports: list[ScanReport], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for report in reports:
            handle.write(
                json.dumps(build_json_report(report), ensure_ascii=False)
                + "\n"
            )
    return path
