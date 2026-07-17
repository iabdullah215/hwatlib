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
    exceptions,
    exploit,
    findings,
    fingerprint,
    http,
    logging_ext,
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
from .exceptions import (
    ConfigError,
    DependencyError,
    HwatlibError,
    NetworkError,
    PluginError,
    RequestError,
    ScanError,
    TargetUnreachable,
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
    "exceptions",
    "logging_ext",
    # Exception hierarchy (re-exported for convenience)
    "HwatlibError",
    "ConfigError",
    "PluginError",
    "DependencyError",
    "ScanError",
    "NetworkError",
    "TargetUnreachable",
    "RequestError",
    "__version__",
]

__version__ = "0.3.0"
__author__ = "HwatSauce"
