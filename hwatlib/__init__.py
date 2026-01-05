"""hwatlib

Practical pentesting helper library.

Recommended imports:

    from hwatlib import recon, web, exploit, privesc

This package intentionally exposes a small, stable surface (submodules).
"""

from . import async_http, cli, config, dns, exploit, findings, fingerprint, http, plugins, postex, privesc, recon, report, secrets, session, web, workflows, workflows_async
from .utils import setup_logger as _setup_logger

_setup_logger()

__all__ = [
    "recon",
    "web",
    "exploit",
    "postex",
    "privesc",
    "cli",
    "config",
    "async_http",
    "findings",
    "session",
    "http",
    "report",
    "plugins",
    "dns",
    "fingerprint",
    "secrets",
    "workflows",
    "workflows_async",
    "__version__",
]

__version__ = "0.1.0"
__author__ = "HwatSauce"
