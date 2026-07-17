"""Structured logging helpers: JSON output and run/correlation IDs.

hwatlib follows the stdlib guidance for libraries — importing it never
configures handlers (see ``__init__``'s ``NullHandler``). These helpers are
opt-in and used by the bundled CLIs (and available to host applications) to get
machine-parseable logs that carry a stable *run id*, so every log line and every
report emitted by a single invocation can be correlated end-to-end.

Typical use::

    from hwatlib import logging_ext
    run_id = logging_ext.new_run_id()          # generate + bind for this run
    logging_ext.setup_json_logging()           # JSON lines to stderr
    # ... work ...  every record now carries {"run_id": run_id, ...}

The run id lives in a :class:`contextvars.ContextVar`, so it is safe across
threads and asyncio tasks.
"""

from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import uuid

# The current run/correlation id. Empty string means "unset".
_run_id: contextvars.ContextVar[str] = contextvars.ContextVar("hwatlib_run_id", default="")


def new_run_id(prefix: str = "") -> str:
    """Generate a fresh run id, bind it to the current context, and return it."""
    rid = (f"{prefix}-" if prefix else "") + uuid.uuid4().hex[:16]
    _run_id.set(rid)
    return rid


def set_run_id(run_id: str) -> None:
    """Bind an explicit run id to the current context."""
    _run_id.set(run_id or "")


def get_run_id() -> str:
    """Return the current run id, or an empty string if none is bound."""
    return _run_id.get()


class RunIdFilter(logging.Filter):
    """Attach the current run id to every record as ``record.run_id``."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Only set if not already provided via `extra={"run_id": ...}`.
        if not getattr(record, "run_id", ""):
            record.run_id = get_run_id() or "-"
        return True


# LogRecord attributes that are structural, not user-supplied "extra" fields.
_RESERVED = set(
    logging.makeLogRecord({}).__dict__.keys()
) | {"message", "asctime", "run_id", "taskName"}


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects.

    Emits ``timestamp`` (UTC ISO-8601), ``level``, ``logger``, ``message`` and
    ``run_id``, plus any ``extra=`` fields passed to the logging call and a
    ``exc_info`` string when an exception is being logged.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "run_id": getattr(record, "run_id", "-"),
        }

        # Merge user-supplied extras (anything not a reserved LogRecord field).
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(payload, default=str)


def setup_json_logging(name: str = "hwatlib", level: int = logging.INFO) -> logging.Logger:
    """Attach a JSON StreamHandler (+ run-id filter) to the named logger.

    Idempotent: it will not add a second hwatlib JSON handler if one exists.
    """
    logger = logging.getLogger(name)
    for h in logger.handlers:
        if getattr(h, "_hwat_json", False):
            return logger

    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RunIdFilter())
    handler._hwat_json = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger
