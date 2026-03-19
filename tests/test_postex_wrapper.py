from __future__ import annotations

import hwatlib.postex as postex


def test_run_cmd_splits_string_to_argv(monkeypatch):
    calls = []

    def fake_run_argv(argv, input_text=None):
        calls.append((list(argv), input_text))
        return 0, "ok"

    monkeypatch.setattr(postex, "_run_argv", fake_run_argv)

    out = postex.run_cmd("python3 /tmp/demo.py")

    assert out == "ok"
    assert calls[0][0] == ["python3", "/tmp/demo.py"]


def test_add_cronjob_confirmed_success_writes_via_crontab_dash(monkeypatch):
    calls = []

    def fake_run_argv(argv, input_text=None):
        calls.append((list(argv), input_text))
        if argv == ["crontab", "-l"]:
            return 0, "# existing"
        if argv == ["crontab", "-"]:
            assert input_text is not None
            assert "*/5 * * * * python3 /tmp/task.py" in input_text
            return 0, ""
        return 1, "unexpected"

    monkeypatch.setattr(postex, "_run_argv", fake_run_argv)

    out = postex.add_cronjob_confirmed("python3 /tmp/task.py", schedule="*/5 * * * *", confirm=True)

    assert out == "[+] Cronjob added."
    assert calls[0][0] == ["crontab", "-l"]
    assert calls[1][0] == ["crontab", "-"]


def test_add_schtask_confirmed_calls_safe_wrapper(monkeypatch):
    captured = {}

    def fake_run_cmd(cmd):
        captured["cmd"] = cmd
        return "created"

    monkeypatch.setattr(postex, "run_cmd", fake_run_cmd)

    out = postex.add_schtask_confirmed("python3 C:\\tmp\\task.py", schedule="DAILY", confirm=True)

    assert out == "created"
    assert captured["cmd"][0] == "schtasks"
    assert "/Create" in captured["cmd"]


def test_allowlist_parser_rejects_broken_command():
    assert postex._is_allowed_state_change_command('"unterminated') is False
