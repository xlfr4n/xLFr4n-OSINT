from __future__ import annotations

import hashlib
import json
from pathlib import Path

from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import ProviderError
from xlfr4n_osint.tooling import run_external_command


class ExifToolProvider:
    name = "exiftool"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def inspect_file(self, path: str) -> list[Finding]:
        file_path = Path(path).expanduser()
        if not file_path.exists():
            raise FileNotFoundError(file_path)
        if not file_path.is_file():
            raise ValueError("file target must be a regular file")

        command = [
            "exiftool",
            "-j",
            "-G1",
            "-a",
            "-s",
            str(file_path),
        ]
        result = run_external_command(
            command,
            timeout=max(10.0, self.timeout),
        )
        if result.returncode != 0:
            raise ProviderError(
                f"exiftool exited with code {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProviderError("exiftool returned invalid JSON") from exc

        metadata = payload[0] if isinstance(payload, list) and payload else {}
        if not isinstance(metadata, dict):
            raise ProviderError("exiftool returned an unexpected metadata object")

        file_bytes = file_path.read_bytes()
        hashes = {
            "md5": hashlib.md5(file_bytes, usedforsecurity=False).hexdigest(),
            "sha1": hashlib.sha1(file_bytes, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest(),
        }

        safe_metadata = {
            str(key): value
            for key, value in metadata.items()
            if not str(key).casefold().endswith(
                ("password", "token", "secret", "credential")
            )
        }

        return [
            Finding.now(
                source=self.name,
                category="file-metadata",
                identifier=f"sha256:{hashes['sha256']}",
                title=f"File metadata — {file_path.name}",
                url=file_path.resolve().as_uri(),
                confidence="high",
                provenance={
                    "source_url": file_path.resolve().as_uri(),
                    "retrieval_method": "local ExifTool JSON metadata extraction",
                    "provider": self.name,
                    "local_only": "true",
                },
                data={
                    "filename": file_path.name,
                    "size_bytes": file_path.stat().st_size,
                    "hashes": hashes,
                    "metadata": safe_metadata,
                },
            )
        ]
