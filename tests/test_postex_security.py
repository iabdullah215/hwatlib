from __future__ import annotations

import hwatlib.postex as postex


def test_add_cronjob_confirmed_rejects_non_allowlisted_command():
    out = postex.add_cronjob_confirmed("rm -rf /", schedule="* * * * *", confirm=True)
    assert "allowlist" in out.lower()


def test_add_cronjob_confirmed_rejects_invalid_schedule():
    out = postex.add_cronjob_confirmed("python3 /tmp/task.py", schedule="bad schedule", confirm=True)
    assert "invalid cron schedule" in out.lower()


def test_add_schtask_confirmed_rejects_invalid_schedule():
    out = postex.add_schtask_confirmed("python3 C:\\tmp\\task.py", schedule="YEARLY", confirm=True)
    assert "invalid schedule" in out.lower()


def test_run_fallback_returns_first_success_output(monkeypatch):
    calls = []

    def fake_run(argv, input_text=None):
        calls.append(tuple(argv))
        if argv[0] == "netstat":
            return 1, "netstat missing"
        return 0, "ss output"

    monkeypatch.setattr(postex, "_run_argv", fake_run)

    out = postex._run_fallback((
        ["netstat", "-tunlp"],
        ["ss", "-tunlp"],
    ))

    assert out == "ss output"
    assert calls == [("netstat", "-tunlp"), ("ss", "-tunlp")]


def test_get_network_info_unix_uses_fallback_non_shell(monkeypatch):
    calls = []

    def fake_run(argv, input_text=None):
        calls.append(tuple(argv))
        if argv[0] == "netstat":
            return 1, "not available"
        return 0, "socket stats"

    monkeypatch.setattr(postex, "_run_argv", fake_run)

    out = postex.get_network_info_unix()

    assert out == "socket stats"
    assert calls[0] == ("netstat", "-tunlp")
    assert calls[1] == ("ss", "-tunlp")
