from __future__ import annotations

import hwatlib.utils as utils


def test_fetch_url_success(monkeypatch):
    class _R:
        text = "hello"

    monkeypatch.setattr(utils.requests, "get", lambda url, timeout=5.0, verify=True: _R())
    assert utils.fetch_url("http://x") == "hello"


def test_fetch_url_error_returns_none(monkeypatch):
    def boom(*a, **k):
        raise utils.requests.RequestException("dead")

    monkeypatch.setattr(utils.requests, "get", boom)
    assert utils.fetch_url("http://x") is None


def test_fetch_url_insecure_suppresses_warning(monkeypatch):
    class _R:
        text = "ok"

    monkeypatch.setattr(utils.requests, "get", lambda url, timeout=5.0, verify=True: _R())
    # verify=False + suppress flag exercises the warnings-suppression branch.
    assert utils.fetch_url("http://x", verify=False, suppress_insecure_warning=True) == "ok"


def test_check_sudo_true(monkeypatch):
    class _Res:
        returncode = 0

    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: _Res())
    assert utils.check_sudo() is True


def test_check_sudo_false_on_error(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(utils.subprocess, "run", boom)
    assert utils.check_sudo() is False


def test_grab_banner_success(monkeypatch):
    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def sendall(self, data):
            pass

        def recv(self, n):
            return b"SSH-2.0-OpenSSH\r\n"

    monkeypatch.setattr(utils.socket, "create_connection", lambda *a, **k: _Sock())
    assert utils.grab_banner("h", 22) == "SSH-2.0-OpenSSH"


def test_grab_banner_failure(monkeypatch):
    def boom(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(utils.socket, "create_connection", boom)
    assert "failed" in utils.grab_banner("h", 22).lower()


def test_save_to_file_error(monkeypatch, caplog):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("builtins.open", boom)
    # Should log and swallow the error, not raise.
    utils.save_to_file("/nope/x", "data")


def test_run_command_unsafe_shell_delegates(monkeypatch):
    monkeypatch.setattr(utils, "run_command", lambda cmd: "OUT")
    assert utils.run_command_unsafe_shell("echo hi") == "OUT"


def test_run_command_passes_timeout(monkeypatch):
    seen = {}

    class _Res:
        stdout = "ok"
        stderr = ""

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return _Res()

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    utils.run_command(["echo", "hi"], timeout=3.0)
    assert seen["timeout"] == 3.0


def test_run_command_timeout_returns_none(monkeypatch):
    def boom(*a, **k):
        raise utils.subprocess.TimeoutExpired(cmd="x", timeout=1.0)

    monkeypatch.setattr(utils.subprocess, "run", boom)
    assert utils.run_command(["sleep", "999"], timeout=1.0) is None
