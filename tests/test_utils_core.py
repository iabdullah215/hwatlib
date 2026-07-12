from __future__ import annotations

import logging
import socket

import pytest

import hwatlib.utils as utils


def _raise_gaierror(_target):
    raise socket.gaierror("unresolvable")


# --- resolve_host ---------------------------------------------------------


def test_resolve_host_ipv4_passthrough():
    assert utils.resolve_host("10.0.0.1") == "10.0.0.1"


def test_resolve_host_empty_returns_none():
    assert utils.resolve_host("") is None


def test_resolve_host_uses_stdlib(monkeypatch):
    monkeypatch.setattr(utils.socket, "gethostbyname", lambda _t: "1.2.3.4")
    assert utils.resolve_host("example.com") == "1.2.3.4"


def test_resolve_host_prefers_dnspython_over_nslookup(monkeypatch):
    monkeypatch.setattr(utils.socket, "gethostbyname", _raise_gaierror)
    monkeypatch.setattr(utils, "_resolve_with_dnspython", lambda _t: "9.9.9.9")

    def _no_nslookup(*_a, **_k):
        raise AssertionError("nslookup must not run when dnspython resolves")

    monkeypatch.setattr(utils.subprocess, "check_output", _no_nslookup)
    assert utils.resolve_host("example.com") == "9.9.9.9"


def test_resolve_host_falls_back_to_nslookup(monkeypatch):
    monkeypatch.setattr(utils.socket, "gethostbyname", _raise_gaierror)
    monkeypatch.setattr(utils, "_resolve_with_dnspython", lambda _t: None)
    monkeypatch.setattr(
        utils.subprocess, "check_output", lambda *_a, **_k: b"Name: x\nAddress: 5.6.7.8\n"
    )
    assert utils.resolve_host("example.com") == "5.6.7.8"


def test_resolve_host_all_fail_returns_none(monkeypatch):
    monkeypatch.setattr(utils.socket, "gethostbyname", _raise_gaierror)
    monkeypatch.setattr(utils, "_resolve_with_dnspython", lambda _t: None)

    def _raise_fnf(*_a, **_k):
        raise FileNotFoundError

    monkeypatch.setattr(utils.subprocess, "check_output", _raise_fnf)
    assert utils.resolve_host("nope.invalid") is None


def test_resolve_domain_is_alias(monkeypatch):
    monkeypatch.setattr(utils, "resolve_host", lambda _t: "1.1.1.1")
    assert utils.resolve_domain("x") == "1.1.1.1"


# --- _resolve_with_dnspython ---------------------------------------------


def test_resolve_with_dnspython_success(monkeypatch):
    resolver = pytest.importorskip("dns.resolver")
    monkeypatch.setattr(resolver, "resolve", lambda _t, _rtype: ["1.2.3.4"])
    assert utils._resolve_with_dnspython("example.com") == "1.2.3.4"


def test_resolve_with_dnspython_failure_returns_none(monkeypatch):
    resolver = pytest.importorskip("dns.resolver")

    def _boom(*_a, **_k):
        raise RuntimeError("dns down")

    monkeypatch.setattr(resolver, "resolve", _boom)
    assert utils._resolve_with_dnspython("example.com") is None


# --- misc pure helpers ----------------------------------------------------


def test_extract_links():
    html = '<a href="http://a/x">x</a> <a href=/y>y</a>'
    links = utils.extract_links(html)
    assert "http://a/x" in links
    assert "/y" in links


def test_timestamp_format():
    assert len(utils.timestamp()) == len("2020-01-01 00:00:00")


def test_run_command_list():
    assert utils.run_command(["echo", "hello"]) == "hello"


def test_run_command_string_is_shlex_split():
    assert utils.run_command("echo hi there") == "hi there"


def test_run_command_missing_binary_returns_none():
    assert utils.run_command(["definitely-not-a-real-binary-xyz"]) is None


def test_run_command_unsafe_shell_delegates():
    assert utils.run_command_unsafe_shell("echo z") == "z"


def test_save_to_file_appends(tmp_path):
    path = tmp_path / "out.txt"
    utils.save_to_file(str(path), "line1")
    utils.save_to_file(str(path), "line2")
    assert path.read_text().splitlines() == ["line1", "line2"]


# --- logging helpers ------------------------------------------------------


def test_get_logger_adds_no_handlers():
    lg = utils.get_logger("hwatlib.test.child")
    assert isinstance(lg, logging.Logger)
    assert not any(type(h) is logging.StreamHandler for h in lg.handlers)


def test_setup_logger_adds_stream_handler():
    lg = utils.setup_logger("hwatlib.test.setup")
    assert any(type(h) is logging.StreamHandler for h in lg.handlers)


# --- authorized-use banner ------------------------------------------------


def test_banner_prints_to_stderr_only(capsys, monkeypatch):
    monkeypatch.delenv("HWAT_NO_BANNER", raising=False)
    utils._banner_shown = False
    utils.authorized_use_banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "authorized use only" in captured.err.lower()


def test_banner_shown_only_once(capsys, monkeypatch):
    monkeypatch.delenv("HWAT_NO_BANNER", raising=False)
    utils._banner_shown = False
    utils.authorized_use_banner()
    capsys.readouterr()  # discard first
    utils.authorized_use_banner()
    assert capsys.readouterr().err == ""


def test_banner_suppressed_by_env(capsys, monkeypatch):
    monkeypatch.setenv("HWAT_NO_BANNER", "1")
    utils._banner_shown = False
    utils.authorized_use_banner()
    assert capsys.readouterr().err == ""
