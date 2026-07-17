from __future__ import annotations

import hwatlib.privesc as privesc


def test_delegators_call_postex(monkeypatch):
    monkeypatch.setattr(privesc.postex, "full_recon", lambda: {"ok": True})
    monkeypatch.setattr(privesc.postex, "check_sudo_rights", lambda: "sudo")
    monkeypatch.setattr(privesc.postex, "list_scheduled_tasks", lambda: "cron")
    monkeypatch.setattr(privesc.postex, "check_kernel_exploits", lambda: "kernel")

    assert privesc.run_checks() == {"ok": True}
    assert privesc.enumerate_sudo() == "sudo"
    assert privesc.enumerate_cron() == "cron"
    assert privesc.kernel_exploits() == "kernel"


def test_risk_score_dict():
    d = privesc.risk_score_dict({"sudo_rights": "(ALL) NOPASSWD"})
    assert d["score"] >= 35
    assert d["level"] in {"low", "medium", "high"}
    assert "reasons" in d


def test_risk_score_history_and_shares():
    report = {
        "bash_history": "export TOKEN=secret",
        "network_shares": "//server/share",
        "ssh_keys": "/home/u/.ssh/id_rsa",
    }
    result = privesc.risk_score(report)
    assert "history_may_contain_secrets" in result.reasons
    assert "network_shares_detected" in result.reasons
    assert "ssh_private_keys_may_exist" in result.reasons


def test_risk_score_exact_contributions():
    # Pin the exact weight of each rule so arithmetic mutations are caught.
    assert privesc.risk_score({"sudo_rights": "(ALL) NOPASSWD"}).score == 35
    assert privesc.risk_score({"suid_bins": "/usr/bin/foo"}).score == 20
    assert privesc.risk_score({"bash_history": "password=1"}).score == 10
    assert privesc.risk_score({"ssh_keys": "/home/u/.ssh/id_rsa"}).score == 10
    assert privesc.risk_score({"network_shares": "//srv/share"}).score == 5


def test_risk_score_exact_level_boundaries():
    # score 60 -> high, 30 -> medium, just below -> lower band.
    high = privesc.risk_score({"sudo_rights": "NOPASSWD", "suid_bins": "/x", "network_shares": "//s"})
    assert high.score == 60 and high.level == "high"
    medium = privesc.risk_score({"suid_bins": "/x", "bash_history": "token"})
    assert medium.score == 30 and medium.level == "medium"
    low = privesc.risk_score({"network_shares": "//s"})
    assert low.score == 5 and low.level == "low"


def test_risk_score_ignores_not_applicable():
    report = {"suid_bins": "not applicable", "ssh_keys": "search failed"}
    result = privesc.risk_score(report)
    assert "suid_binaries_found" not in result.reasons
    assert "ssh_private_keys_may_exist" not in result.reasons


def test_main_read_only_command(monkeypatch, capsys):
    monkeypatch.setenv("HWAT_NO_BANNER", "1")
    monkeypatch.setattr(privesc.postex, "check_kernel_exploits", lambda: "5.15.0")
    rc = privesc.main(["kernel"])
    assert rc == 0
    assert "5.15.0" in capsys.readouterr().out


def test_main_checks_default(monkeypatch, capsys):
    monkeypatch.setenv("HWAT_NO_BANNER", "1")
    monkeypatch.setattr(privesc.postex, "full_recon", lambda: {"system_info": {}})
    monkeypatch.setattr(privesc.postex, "pretty_report", lambda r: "REPORT")
    rc = privesc.main([])
    assert rc == 0
    assert "REPORT" in capsys.readouterr().out


def test_main_mutator_without_confirm_returns_2(monkeypatch, capsys):
    monkeypatch.setenv("HWAT_NO_BANNER", "1")
    monkeypatch.setattr(privesc.postex, "add_cronjob_confirmed", lambda *a, **k: "[-] refused")
    rc = privesc.main(["add-cronjob", "bash -i"])
    assert rc == 2


def test_main_mutator_with_confirm_returns_0(monkeypatch, capsys):
    monkeypatch.setenv("HWAT_NO_BANNER", "1")
    monkeypatch.setattr(privesc.postex, "backdoor_ssh_confirmed", lambda *a, **k: "[+] added")
    rc = privesc.main(["backdoor-ssh", "ssh-ed25519 AAAA", "--confirm"])
    assert rc == 0
