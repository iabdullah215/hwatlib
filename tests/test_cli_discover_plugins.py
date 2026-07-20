from __future__ import annotations

import hwatlib.plugins as plugins


class _FakeEP:
    def __init__(self, name, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


def test_cli_discover_plugins_then_list(monkeypatch, capsys):
    import hwatlib.cli as cli

    saved = dict(plugins._registry)
    plugins._registry.clear()
    try:
        def ep_check(session):
            return None

        monkeypatch.setattr(plugins, "_iter_entry_points", lambda group: [_FakeEP("third_party", ep_check)])
        monkeypatch.setenv("HWAT_NO_BANNER", "1")

        code = cli.main(["report", "example.com", "--discover-plugins", "--list-plugins"])
        assert code == 0
        out = capsys.readouterr()
        # Discovery notice on stderr; plugin listed on stdout.
        assert "Discovered 1 plugin" in out.err
        assert "third_party" in out.out
    finally:
        plugins._registry.clear()
        plugins._registry.update(saved)
