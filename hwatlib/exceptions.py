"""Typed exception hierarchy for hwatlib.

All library-raised errors derive from :class:`HwatlibError`, so callers can
catch everything hwatlib throws with a single ``except HwatlibError``. More
specific subclasses let callers react precisely (retry a network error, prompt
for a fixed config, install a missing extra, etc.) instead of catching broad
built-ins.

Several subclasses *also* inherit from the built-in they historically replaced
(``ConfigError`` is a ``ValueError``, ``DependencyError`` is a ``RuntimeError``,
and so on). That keeps older ``except ValueError``/``except RuntimeError`` code
working while new code can catch the precise hwatlib type.

Hierarchy::

    HwatlibError
    ├── ConfigError        (also ValueError)
    ├── PluginError        (also ValueError)
    ├── DependencyError    (also RuntimeError)
    ├── ScanError          (also RuntimeError)
    └── NetworkError
        ├── TargetUnreachable
        └── RequestError   (also RuntimeError)
"""

from __future__ import annotations


class HwatlibError(Exception):
    """Base class for every error raised by hwatlib."""


class ConfigError(HwatlibError, ValueError):
    """Invalid or out-of-range configuration.

    Subclasses ``ValueError`` for backwards compatibility with callers (and the
    strict-mode config path) that historically caught ``ValueError``.
    """


class PluginError(HwatlibError, ValueError):
    """A plugin could not be registered, loaded, or resolved.

    Subclasses ``ValueError`` for backwards compatibility.
    """


class DependencyError(HwatlibError, RuntimeError):
    """A required optional dependency (extra) is missing.

    For example, using the async client without ``pip install hwatlib[async]``.
    Subclasses ``RuntimeError`` for backwards compatibility.
    """


class ScanError(HwatlibError, RuntimeError):
    """A scan/recon helper was invoked incorrectly or could not run.

    Subclasses ``RuntimeError`` for backwards compatibility.
    """


class NetworkError(HwatlibError):
    """Base class for network-related failures (DNS, TCP, HTTP)."""


class TargetUnreachable(NetworkError):
    """A target host could not be resolved or connected to."""


class RequestError(NetworkError, RuntimeError):
    """An HTTP(S) request failed (e.g. exhausted retries).

    Subclasses ``RuntimeError`` for backwards compatibility with the previous
    behaviour of the async client.
    """


__all__ = [
    "HwatlibError",
    "ConfigError",
    "PluginError",
    "DependencyError",
    "ScanError",
    "NetworkError",
    "TargetUnreachable",
    "RequestError",
]
