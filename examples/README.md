# hwatlib examples

Small, runnable snippets showing the `hwatlib` Python API.

> ⚠️ **Authorized use only.** The recon/web examples make real network requests.
> Run them **only** against systems you own or are explicitly authorized to test
> (the examples default to `example.com`/`localhost` placeholders — change them
> deliberately). See [`../SECURITY.md`](../SECURITY.md). Payload-generation
> examples are offline and safe to run anywhere.

## Running

```bash
pip install -e ".[async,dns]"
python examples/reverse_shell_payloads.py     # offline, safe
python examples/recon_report.py example.com   # network: use an authorized target
python examples/web_enum.py http://localhost:8000
python examples/config_profile.py
```

| Example | What it shows | Network |
| ------- | ------------- | ------- |
| `reverse_shell_payloads.py` | Generating/encoding reverse-shell payloads | No |
| `recon_report.py` | Building a safe-by-default `HwatReport` (JSON/Markdown) | Yes |
| `web_enum.py` | Fetching headers/forms/JS and crawling | Yes |
| `config_profile.py` | Loading validated config profiles | No |
