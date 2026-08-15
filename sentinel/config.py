"""Central configuration and scope/authorization enforcement.

Settings are read from the environment (optionally via a .env file). The most
important responsibility here is Section 9 of the spec: refuse to scan anything
that is not localhost or an explicitly approved target.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:  # optional: load a .env if present, but never required
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover - dotenv is optional
    pass


# Hostnames that are always considered in-scope (local practice labs).
_ALWAYS_ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "host.docker.internal",
    "dvwa",
    "juice-shop",
    "juiceshop",
}


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


@dataclass
class Settings:
    """Runtime settings for a scan session."""

    # --- LLM ---
    # Which backend to use: "auto" | "claude" | "hf" | "ollama" | "groq" | "heuristic".
    # "auto" prefers Claude, then Hugging Face, then Groq, then the offline heuristic.
    llm_provider: str = field(
        default_factory=lambda: os.getenv("SENTINEL_LLM_PROVIDER", "auto").strip().lower()
    )
    # Cost/model routing (spec Section 8): route the cheap "parse raw output" step
    # and the "reason/confirm + report" step to different providers. Empty = use
    # llm_provider for both. E.g. SENTINEL_PARSE_PROVIDER=groq, SENTINEL_REASON_PROVIDER=claude.
    parse_provider: str = field(
        default_factory=lambda: os.getenv("SENTINEL_PARSE_PROVIDER", "").strip().lower()
    )
    reason_provider: str = field(
        default_factory=lambda: os.getenv("SENTINEL_REASON_PROVIDER", "").strip().lower()
    )

    anthropic_api_key: str | None = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY")
    )
    # claude-opus-5 is the current flagship; adaptive thinking is used at call sites.
    claude_model: str = field(
        default_factory=lambda: os.getenv("SENTINEL_CLAUDE_MODEL", "claude-opus-5")
    )

    # --- Hugging Face (OpenAI-compatible router / Inference Providers) ---
    hf_api_key: str | None = field(
        default_factory=lambda: (
            os.getenv("HF_API_KEY")
            or os.getenv("HF_TOKEN")
            or os.getenv("HUGGINGFACEHUB_API_TOKEN")
        )
    )
    hf_model: str = field(
        default_factory=lambda: os.getenv(
            "HF_MODEL", "meta-llama/Llama-3.3-70B-Instruct"
        )
    )
    hf_base_url: str = field(
        default_factory=lambda: os.getenv(
            "HF_BASE_URL", "https://router.huggingface.co/v1"
        )
    )

    # --- Ollama (local, free, OpenAI-compatible at /v1) ---
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    )
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv(
            "OLLAMA_BASE_URL", "http://localhost:11434/v1"
        )
    )

    # --- Groq (fast, cheap open models, OpenAI-compatible) ---
    groq_api_key: str | None = field(default_factory=lambda: os.getenv("GROQ_API_KEY"))
    groq_model: str = field(
        default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    )
    groq_base_url: str = field(
        default_factory=lambda: os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    )

    # --- OWASP ZAP ---
    zap_api_url: str = field(
        default_factory=lambda: os.getenv("ZAP_API_URL", "http://localhost:8080")
    )
    zap_api_key: str = field(default_factory=lambda: os.getenv("ZAP_API_KEY", ""))

    # --- Nmap ---
    nmap_binary: str = field(default_factory=lambda: os.getenv("NMAP_BINARY", "nmap"))

    # --- Operating mode ---
    # When True, tools return bundled sample data instead of hitting real ZAP/Nmap.
    # Also auto-enabled when the real tools are unreachable.
    mock: bool = field(default_factory=lambda: _env_bool("SENTINEL_MOCK", False))

    # Escape hatch to scan non-local targets you own. Off by default (see ethics).
    allow_any_target: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_ALLOW_ANY", False)
    )
    # Extra explicitly-approved hosts (comma separated).
    approved_hosts: list[str] = field(default_factory=lambda: _env_list("SENTINEL_APPROVED_HOSTS"))

    # --- Output ---
    reports_dir: str = field(
        default_factory=lambda: os.getenv("SENTINEL_REPORTS_DIR", "reports")
    )

    def has_llm(self) -> bool:
        """True if any real LLM backend (Claude, Hugging Face, or Groq) is configured."""
        return bool(self.anthropic_api_key or self.hf_api_key or self.groq_api_key)


class ScopeError(PermissionError):
    """Raised when a target is outside the approved testing scope."""


def _extract_host(target: str) -> str:
    """Pull a bare hostname/IP out of a URL or host:port string."""
    candidate = target.strip()
    if "://" not in candidate:
        candidate = "//" + candidate  # let urlparse treat it as netloc
    host = urlparse(candidate).hostname or ""
    return host.lower()


def _is_private_or_loopback(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def assert_in_scope(target: str, settings: Settings) -> str:
    """Validate a target against the approved scope. Returns the extracted host.

    Raises ScopeError with actionable guidance if the target is out of scope.
    Only local practice apps (DVWA / Juice Shop) or explicitly-approved hosts are
    permitted unless SENTINEL_ALLOW_ANY is set.
    """
    host = _extract_host(target)
    if not host:
        raise ScopeError(f"Could not determine a host from target {target!r}.")

    if settings.allow_any_target:
        return host
    if host in _ALWAYS_ALLOWED_HOSTS:
        return host
    if host in set(settings.approved_hosts):
        return host
    if _is_private_or_loopback(host):
        return host

    raise ScopeError(
        f"Target host {host!r} is not in the approved scope.\n"
        "SentinelAgent only scans local practice apps (DVWA / OWASP Juice Shop) or\n"
        "hosts you have explicit written authorization to test.\n"
        "To allow it, add the host to SENTINEL_APPROVED_HOSTS, or set "
        "SENTINEL_ALLOW_ANY=1 if you own it."
    )
