from __future__ import annotations

import json
import logging

import pytest

from hwatlib import logging_ext
from hwatlib.logging_ext import (
    JsonFormatter,
    RunIdFilter,
    get_run_id,
    new_run_id,
    set_run_id,
)


@pytest.fixture(autouse=True)
def _reset_run_id():
    set_run_id("")
    yield
    set_run_id("")


def test_new_run_id_binds_and_returns():
    rid = new_run_id()
    assert rid == get_run_id()
    assert len(rid) == 16


def test_new_run_id_prefix():
    rid = new_run_id("report")
    assert rid.startswith("report-")
    assert get_run_id() == rid


def test_set_get_run_id():
    set_run_id("abc123")
    assert get_run_id() == "abc123"
    set_run_id("")
    assert get_run_id() == ""


def _record(msg="hello", **extra):
    record = logging.LogRecord("hwatlib", logging.INFO, __file__, 1, msg, None, None)
    for k, v in extra.items():
        setattr(record, k, v)
    return record


def test_run_id_filter_injects_current_id():
    set_run_id("run-xyz")
    record = _record()
    assert RunIdFilter().filter(record) is True
    assert record.run_id == "run-xyz"


def test_run_id_filter_defaults_to_dash_when_unset():
    record = _record()
    RunIdFilter().filter(record)
    assert record.run_id == "-"


def test_run_id_filter_preserves_explicit_extra():
    record = _record(run_id="explicit")
    RunIdFilter().filter(record)
    assert record.run_id == "explicit"


def test_json_formatter_shape():
    set_run_id("run-1")
    record = _record("scanning %s", args=("host",))
    record.args = ("host",)
    record.run_id = "run-1"
    out = JsonFormatter().format(record)
    payload = json.loads(out)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "hwatlib"
    assert payload["message"] == "scanning host"
    assert payload["run_id"] == "run-1"
    assert "timestamp" in payload


def test_json_formatter_includes_extra_fields():
    record = _record()
    record.run_id = "-"
    record.target = "example.test"
    record.port = 443
    payload = json.loads(JsonFormatter().format(record))
    assert payload["target"] == "example.test"
    assert payload["port"] == 443


def test_json_formatter_includes_exception():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord(
            "hwatlib", logging.ERROR, __file__, 1, "failed", None, sys.exc_info()
        )
        record.run_id = "-"
    payload = json.loads(JsonFormatter().format(record))
    assert "exc_info" in payload
    assert "ValueError" in payload["exc_info"]


def test_setup_json_logging_is_idempotent():
    logger = logging.getLogger("hwatlib.test.json")
    logger.handlers.clear()
    logging_ext.setup_json_logging("hwatlib.test.json")
    logging_ext.setup_json_logging("hwatlib.test.json")
    json_handlers = [h for h in logger.handlers if getattr(h, "_hwat_json", False)]
    assert len(json_handlers) == 1


def test_setup_json_logging_emits_json(capsys):
    logger = logging.getLogger("hwatlib.test.emit")
    logger.handlers.clear()
    logger.propagate = False
    new_run_id("emit")
    logging_ext.setup_json_logging("hwatlib.test.emit")
    logger.info("hello world")
    err = capsys.readouterr().err
    payload = json.loads(err.strip().splitlines()[-1])
    assert payload["message"] == "hello world"
    assert payload["run_id"].startswith("emit-")


def test_setup_logger_json_via_env(monkeypatch):
    from hwatlib.utils import setup_logger

    monkeypatch.setenv("HWAT_LOG_FORMAT", "json")
    logger = logging.getLogger("hwatlib.test.env")
    logger.handlers.clear()
    setup_logger("hwatlib.test.env")
    assert any(getattr(h, "_hwat_json", False) for h in logger.handlers)
