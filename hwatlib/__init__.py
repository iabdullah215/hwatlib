"""hwatlib

Practical pentesting helper library.

Recommended imports:

    from hwatlib import recon, web, exploit, privesc

This package intentionally exposes a small, stable surface (submodules).
"""

import logging

from . import (
    async_http,
    cli,
    config,
    dns,
    exploit,
    findings,
    fingerprint,
    http,
    plugins,
    postex,
    privesc,
    recon,
    report,
    secrets,
    session,
    web,
    workflows,
    workflows_async,
)

# Follow the stdlib recommendation for libraries: attach a NullHandler so that
# importing hwatlib never configures handlers or emits output on its own. The
# host application (or the bundled CLIs via setup_logger()) decides on output.
logging.getLogger("hwatlib").addHandler(logging.NullHandler())

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

__version__ = "0.3.0"
__author__ = "HwatSauce"
