"""Tool wrappers that produce the raw scan output agents reason over."""

from .zap import ZapClient
from .nmap_tool import NmapClient

__all__ = ["ZapClient", "NmapClient"]
