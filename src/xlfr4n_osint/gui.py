from __future__ import annotations

import json
import mimetypes
import os
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files as resource_files
from pathlib import Path
from uuid import uuid4
from typing import Any
from urllib.parse import parse_qs, urlparse

from xlfr4n_osint.batch import BatchItem, run_item
from xlfr4n_osint.models import Finding, ScanReport
from xlfr4n_osint.logging_utils import get_logger
from xlfr4n_osint.reporting import build_json_report, render_markdown_report
from xlfr4n_osint.registry import ProviderRegistry
from xlfr4n_osint.source_status import inspect_registry

logger = get_logger(__name__)

SUPPORTED_TYPES = frozenset({
    "username", "domain", "email", "phone", "password",
    "ip", "asn", "url", "person", "hash", "file",
})


def _history_dir() -> Path:
    default = Path.home() / ".local" / "share" / "xlfr4n-osint" / "reports"
    configured = Path(os.environ.get("XLFR4N_OSINT_REPORT_DIR", str(default)))
    configured.mkdir(parents=True, exist_ok=True)
    return configured


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def _safe_scan_id(value: str) -> str:
    candidate = value.strip()
    if not candidate or len(candidate) > 96:
        raise ValueError("invalid scan id")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    if any(char not in allowed for char in candidate):
        raise ValueError("invalid scan id")
    return candidate


def _redact_secret(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "<redacted-password>")
    if isinstance(value, list):
        return [_redact_secret(item, secret) for item in value]
    if isinstance(value, dict):
        return {key: _redact_secret(item, secret) for key, item in value.items()}
    return value


class InvestigationService:
    """HTTP-facing service that reuses the native xLFr4n OSINT engine."""

    def __init__(
        self,
        registry: ProviderRegistry | None = None,
        *,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT-GUI/1.0",
    ) -> None:
        if registry is None:
            from xlfr4n_osint.cli import build_registry

            registry = build_registry()
        self.registry = registry
        self.timeout = timeout
        self.user_agent = user_agent
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        from concurrent.futures import ThreadPoolExecutor
        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="xlfr4n-osint-job",
        )

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)

    def submit_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid4().hex
        now = time.time()
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "stage": "queued",
                "created_at": now,
                "started_at": None,
                "finished_at": None,
                "report": None,
                "error": None,
            }
        self._executor.submit(self._run_job, job_id, payload)
        return self.get_job(job_id)

    def _run_job(self, job_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["status"] = "running"
            job["stage"] = "collecting"
            job["started_at"] = time.time()
        try:
            report = self.scan(payload)
        except Exception as exc:
            with self._lock:
                job = self._jobs.get(job_id)
                if job is not None:
                    job["status"] = "failed"
                    job["stage"] = "failed"
                    job["error"] = str(exc)
                    job["finished_at"] = time.time()
            return

        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job["status"] = "completed"
                job["stage"] = "completed"
                job["report"] = report
                job["finished_at"] = time.time()

    def get_job(self, job_id: str) -> dict[str, Any]:
        key = _safe_scan_id(job_id)
        with self._lock:
            job = self._jobs.get(key)
            if job is None:
                raise FileNotFoundError(job_id)
            result = dict(job)
        if result["status"] == "completed" and result.get("report"):
            result["summary"] = result["report"].get("summary", {})
        result["elapsed_seconds"] = (
            (result["finished_at"] or time.time()) - result["created_at"]
        )
        return result


    def source_snapshot(self, capability: str | None = None) -> list[dict[str, Any]]:
        if capability:
            capability = capability.strip().lower()
        providers = {
            item["name"]: item
            for item in inspect_registry(self.registry)
        }
        return [
            {
                **providers[name],
                "capabilities": list(self.registry.capabilities(name)),
            }
            for name in self.registry.names(capability)
        ]

    def scan(self, payload: dict[str, Any]) -> dict[str, Any]:
        item_type = str(payload.get("type", "")).strip().lower()
        value = str(payload.get("value", "")).strip()

        if item_type not in SUPPORTED_TYPES:
            raise ValueError(f"unsupported target type: {item_type or '<empty>'}")
        if not value:
            raise ValueError("target value cannot be empty")
        if len(value) > 4096:
            raise ValueError("target value is too long")

        raw_sources = payload.get("sources", [])
        if raw_sources is None:
            raw_sources = []
        if not isinstance(raw_sources, list) or not all(
            isinstance(source, str) for source in raw_sources
        ):
            raise ValueError("sources must be a string list")

        try:
            timeout = float(payload.get("timeout", self.timeout))
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout must be numeric") from exc
        timeout = min(max(timeout, 1.0), 120.0)

        item = BatchItem.from_dict(
            {"type": item_type, "value": value, "sources": raw_sources}
        )
        report = run_item(
            item,
            self.registry,
            timeout=timeout,
            user_agent=self.user_agent,
            all_sources=bool(payload.get("all_sources", False)),
        )
        result = build_json_report(report)

        if item_type == "password":
            result = _redact_secret(result, value)
            result["query"] = "<redacted-password>"

        path = _history_dir() / f"{report.scan_id}.json"
        with self._lock:
            path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        return result

    def history(self, limit: int = 40) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 200))
        records = []
        paths = sorted(
            _history_dir().glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in paths[:limit]:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            summary = payload.get("summary", {})
            records.append(
                {
                    "scan_id": payload.get("scan_id", path.stem),
                    "query": payload.get("query", ""),
                    "started_at": payload.get("started_at", ""),
                    "finding_count": summary.get(
                        "finding_count", len(payload.get("findings", []))
                    ),
                    "source_count": summary.get("source_count", 0),
                    "entity_count": summary.get("entity_count", 0),
                    "error_count": summary.get(
                        "error_count", len(payload.get("errors", []))
                    ),
                }
            )
        return records

    def get_report(self, scan_id: str) -> dict[str, Any]:
        path = _history_dir() / f"{_safe_scan_id(scan_id)}.json"
        if not path.exists():
            raise FileNotFoundError(scan_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def get_markdown(self, scan_id: str) -> str:
        payload = self.get_report(scan_id)
        report = ScanReport(
            query=str(payload.get("query", "")),
            findings=[
                Finding(
                    source=str(item.get("source", "")),
                    category=str(item.get("category", "")),
                    identifier=str(item.get("identifier", "")),
                    title=str(item.get("title", "")),
                    url=str(item.get("url", "")),
                    observed_at=str(item.get("observed_at", "")),
                    confidence=str(item.get("confidence", "unknown")),
                    data=dict(item.get("data") or {}),
                    provenance=dict(item.get("provenance") or {}),
                )
                for item in payload.get("findings", [])
                if isinstance(item, dict)
            ],
            errors=list(payload.get("errors") or []),
            scan_id=str(payload.get("scan_id", scan_id)),
            started_at=str(payload.get("started_at", "")),
        )
        return render_markdown_report(report)

    @staticmethod
    def asset(name: str) -> tuple[bytes, str]:
        safe_name = Path(name).name
        if safe_name not in {"index.html", "app.js", "styles.css", "favicon.svg"}:
            raise FileNotFoundError(name)
        body = resource_files("xlfr4n_osint").joinpath("web", safe_name).read_bytes()
        content_type, _ = mimetypes.guess_type(safe_name)
        return body, content_type or "application/octet-stream"


class _Handler(BaseHTTPRequestHandler):
    service: InvestigationService
    server_version = "xLFr4n-OSINT-GUI/1.0"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Any) -> None:
        self._send(status, _json_bytes(payload), "application/json")

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length < 0 or length > 2_000_000:
            raise ValueError("request body is too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def do_GET(self) -> None:
        request = urlparse(self.path)
        path = request.path
        try:
            if path == "/api/health":
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "ok", "name": "xLFr4n-OSINT", "version": "1.0"},
                )
                return

            if path == "/api/sources":
                capability = parse_qs(request.query).get("type", [None])[0]
                self._send_json(
                    HTTPStatus.OK,
                    {"sources": self.service.source_snapshot(capability)},
                )
                return

            if path == "/api/reports":
                self._send_json(HTTPStatus.OK, {"reports": self.service.history()})
                return

            if path.startswith("/api/jobs/"):
                job_id = path.removeprefix("/api/jobs/").strip("/")
                self._send_json(HTTPStatus.OK, self.service.get_job(job_id))
                return

            if path.startswith("/api/reports/") and path.endswith("/markdown"):
                scan_id = path.removeprefix("/api/reports/").removesuffix("/markdown").strip("/")
                body = self.service.get_markdown(scan_id).encode("utf-8")
                self._send(HTTPStatus.OK, body, "text/markdown")
                return

            if path.startswith("/api/reports/"):
                scan_id = path.removeprefix("/api/reports/").strip("/")
                self._send_json(HTTPStatus.OK, self.service.get_report(scan_id))
                return

            asset_name = "index.html" if path in {"/", "/index.html"} else path.removeprefix("/")
            body, content_type = self.service.asset(asset_name)
            self._send(HTTPStatus.OK, body, content_type)
        except FileNotFoundError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except Exception as exc:
            logger.exception("GUI GET failed")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_POST(self) -> None:
        if self.path == "/api/jobs":
            try:
                job = self.service.submit_scan(self._read_json())
                self._send_json(HTTPStatus.ACCEPTED, job)
            except (ValueError, FileNotFoundError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:
                logger.exception("GUI job submission failed")
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
            return

        if self.path != "/api/scan":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            self._send_json(HTTPStatus.OK, self.service.scan(self._read_json()))
        except (ValueError, FileNotFoundError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            logger.exception("GUI scan failed")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        logger.info("GUI %s", format % args)


def run_gui(
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser: bool = True,
    timeout: float = 10.0,
    user_agent: str = "xLFr4n-OSINT-GUI/1.0",
    allow_remote: bool = False,
) -> None:
    loopback_hosts = {"127.0.0.1", "localhost"}
    if host not in loopback_hosts and not allow_remote:
        raise ValueError(
            "refusing non-loopback GUI binding; pass allow_remote=True only when remote access is intentionally secured"
        )

    service = InvestigationService(timeout=timeout, user_agent=user_agent)

    class Handler(_Handler):
        pass

    Handler.service = service
    server = ThreadingHTTPServer((host, port), Handler)
    address = f"http://{host}:{port}/"

    print("⚡ xLFr4n // OSINT GUI")
    print(f"   Local interface: {address}")
    if host not in loopback_hosts:
        print("   WARNING: remote binding enabled; the GUI has no built-in authentication.")
    print("   API: /api/health · /api/sources · /api/scan · /api/reports")
    print("   Press Ctrl+C to stop.")

    if open_browser:
        try:
            webbrowser.open(address)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nStopping GUI...")
    finally:
        server.server_close()
        service.close()
