"""Nmap wrapper for the recon agent.

Runs a real Nmap scan (via python-nmap or a subprocess) when the binary is
available, and falls back to bundled sample recon output otherwise.

Corresponds to the `run_port_scan` tool schema in the spec.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ..config import Settings

_SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "nmap_recon.json"

# Rough service -> risk heuristic for the raw recon findings.
_SERVICE_RISK = {
    "mysql": "medium",
    "postgresql": "medium",
    "mongodb": "medium",
    "redis": "high",
    "ftp": "medium",
    "telnet": "high",
    "ssh": "low",
    "http": "informational",
    "https": "informational",
}


class NmapClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.used_mock = False

    def recon(self, host: str, scan_type: str = "quick") -> list[dict]:
        if not self.settings.mock and shutil.which(self.settings.nmap_binary):
            try:
                return self._live_scan(host, scan_type)
            except Exception:
                pass
        self.used_mock = True
        return self._load_sample()

    # ------------------------------------------------------------------ live
    def _live_scan(self, host: str, scan_type: str) -> list[dict]:
        args = ["-sV", "-T4"]
        if scan_type == "quick":
            args += ["-F"]  # fast: top 100 ports
        else:
            args += ["-p-"]  # full port range
        cmd = [self.settings.nmap_binary, *args, "-oX", "-", host]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return self._parse_xml(out.stdout, host)

    @staticmethod
    def _parse_xml(xml_text: str, host: str) -> list[dict]:
        findings: list[dict] = []
        root = ET.fromstring(xml_text)
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            service = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(p for p in [product, version] if p).strip()
            findings.append(
                {
                    "endpoint": f"{host}:{portid}",
                    "name": f"Open port {portid}/{proto} - {service}",
                    "param": f"{portid}/{proto}",
                    "risk": _SERVICE_RISK.get(service, "low"),
                    "confidence": "high",
                    "evidence": f"{portid}/{proto} open {service} {banner}".strip(),
                    "description": (
                        f"{service} service"
                        + (f" ({banner})" if banner else "")
                        + " is exposed on this host."
                    ),
                    "solution": "Restrict exposure of non-essential services and keep them patched.",
                    "service": service,
                    "product": product,
                    "version": version,
                }
            )
        return findings

    # ---------------------------------------------------------------- sample
    @staticmethod
    def _load_sample() -> list[dict]:
        override = os.getenv("SENTINEL_NMAP_SAMPLE")
        path = Path(override) if override else _SAMPLE
        return json.loads(path.read_text(encoding="utf-8"))
