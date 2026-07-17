from __future__ import annotations

import hwatlib.postex as postex


def _force_unix(monkeypatch):
    monkeypatch.setattr(postex, "is_windows", lambda: False)


def test_run_argv_real_echo():
    rc, out = postex._run_argv(["echo", "hello"])
    assert rc == 0
    assert "hello" in out


def test_run_argv_handles_missing_binary():
    rc, out = postex._run_argv(["hwat_nonexistent_binary_xyz"])
    assert rc == 1
    assert isinstance(out, str)


def test_run_argv_timeout(monkeypatch):
    def boom(*a, **k):
        raise postex.subprocess.TimeoutExpired(cmd="sleep", timeout=1.0)

    monkeypatch.setattr(postex.subprocess, "run", boom)
    rc, out = postex._run_argv(["sleep", "999"], timeout=1.0)
    assert rc == 1
    assert "timed out" in out


def test_default_cmd_timeout_env(monkeypatch):
    monkeypatch.setenv("HWAT_CMD_TIMEOUT", "7.5")
    assert postex._default_cmd_timeout() == 7.5
    monkeypatch.setenv("HWAT_CMD_TIMEOUT", "not-a-number")
    assert postex._default_cmd_timeout() == 120.0
    monkeypatch.delenv("HWAT_CMD_TIMEOUT", raising=False)
    assert postex._default_cmd_timeout() == 120.0


def test_run_cmd_exception_returns_str(monkeypatch):
    def boom(cmd):
        raise ValueError("bad")

    monkeypatch.setattr(postex.shlex, "split", boom)
    assert "bad" in postex.run_cmd("something")


def test_unix_recon_wrappers(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda *a, **k: "OUT")
    assert postex.get_users() == "OUT"
    assert postex.get_processes() == "OUT"
    assert postex.check_kernel_exploits() == "OUT"
    assert postex.search_config_files() == "OUT"
    assert postex.dump_passwd_shadow() == "OUT"


def test_get_network_info_unix_fallback(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "_run_fallback", lambda cmds: "netstat-out")
    assert postex.get_network_info() == "netstat-out"


def test_search_ssh_keys_scoped_first(monkeypatch):
    _force_unix(monkeypatch)
    outputs = iter(["/home/u/.ssh/id_rsa", ""])
    monkeypatch.setattr(postex, "run_cmd", lambda *a, **k: next(outputs))
    assert postex.search_ssh_keys() == "/home/u/.ssh/id_rsa"


def test_search_ssh_keys_falls_back_to_root(monkeypatch):
    _force_unix(monkeypatch)
    outputs = iter(["", "/root/.ssh/id_rsa"])
    monkeypatch.setattr(postex, "run_cmd", lambda *a, **k: next(outputs))
    assert postex.search_ssh_keys() == "/root/.ssh/id_rsa"


def test_find_network_shares_unix(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "_run_fallback", lambda cmds: "shares")
    assert postex.find_network_shares() == "shares"


def test_search_history_reads_files(monkeypatch, tmp_path):
    _force_unix(monkeypatch)
    home = tmp_path / "home"
    (home / "user").mkdir(parents=True)
    (home / "user" / ".bash_history").write_text("ls\ncat /etc/passwd\n")

    # Point the /home glob at our fake home dir; keep Path.home() working.
    real_path = postex.Path

    def fake_path(arg):
        if arg == "/home":
            return real_path(str(home))
        return real_path(arg)

    fake_path.home = lambda: tmp_path / "nobody"
    monkeypatch.setattr(postex, "Path", fake_path)
    out = postex.search_history()
    assert "cat /etc/passwd" in out


def test_list_scheduled_tasks_unix(monkeypatch, tmp_path):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda argv, **k: "* * * * * job")

    cron_d = tmp_path / "cron.d"
    cron_d.mkdir()
    (cron_d / "myjob").write_text("0 0 * * * root backup")

    real_path = postex.Path

    def fake_path(arg):
        if arg == "/etc/cron.d":
            return real_path(str(cron_d))
        return real_path(arg)

    monkeypatch.setattr(postex, "Path", fake_path)
    out = postex.list_scheduled_tasks()
    assert "user crontab" in out
    assert "backup" in out


def test_add_schtask_confirmed_success(monkeypatch):
    monkeypatch.setattr(postex, "run_cmd", lambda argv, **k: "SUCCESS: task created")
    out = postex.add_schtask_confirmed("python3 -c 'x'", confirm=True)
    assert "SUCCESS" in out


def test_add_schtask_confirmed_bad_schedule():
    out = postex.add_schtask_confirmed("bash -i", schedule="NOPE", confirm=True)
    assert "invalid schedule" in out


def test_add_cronjob_delegates_on_unix(monkeypatch):
    _force_unix(monkeypatch)
    # add_cronjob wraps the confirmed variant with confirm=False -> refusal.
    assert postex.add_cronjob("bash -i").startswith("[-]")
