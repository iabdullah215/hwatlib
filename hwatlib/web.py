import requests
from bs4 import BeautifulSoup
import urllib.parse
import re

class WebScanner:
    def __init__(self, target, wordlist=None):
        self.target = target if target.startswith("http") else "http://" + target
        self.wordlist = wordlist
        self.visited = set()
        self.found_links = []
        self.session = requests.Session()

    # ---------------- CRAWLER ----------------
    def crawl(self, depth=2):
        print(f"[+] Crawling {self.target} (depth={depth})")
        self._crawl(self.target, depth)

    def _crawl(self, url, depth):
        if depth == 0 or url in self.visited:
            return
        try:
            resp = self.session.get(url, timeout=5)
            self.visited.add(url)
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                abs_url = urllib.parse.urljoin(url, link["href"])
                if self.target in abs_url and abs_url not in self.visited:
                    self.found_links.append(abs_url)
                    print(f"  [link] {abs_url}")
                    self._crawl(abs_url, depth - 1)
        except Exception as e:
            print(f"  [!] Crawl error: {e}")

    # ---------------- DIRECTORY BRUTEFORCE ----------------
    def dir_bruteforce(self):
        if not self.wordlist:
            print("[!] No wordlist provided for directory brute force")
            return
        print(f"[+] Directory brute force on {self.target}")
        with open(self.wordlist, "r") as f:
            for line in f:
                path = line.strip()
                url = urllib.parse.urljoin(self.target, path)
                try:
                    r = self.session.get(url, timeout=3)
                    if r.status_code == 200:
                        print(f"  [dir] {url} ({r.status_code})")
                except:
                    pass

    # ---------------- PARAMETER DISCOVERY ----------------
    def param_discovery(self, params=["id", "page", "q", "file"]):
        print(f"[+] Parameter discovery on {self.target}")
        for p in params:
            url = f"{self.target}?{p}=test"
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    print(f"  [param] {url} -> {len(r.text)} bytes")
            except:
                pass

    # ---------------- HEADER ANALYSIS ----------------
    def analyze_headers(self):
        print(f"[+] Analyzing headers for {self.target}")
        try:
            r = self.session.get(self.target, timeout=5)
            for h, v in r.headers.items():
                print(f"  {h}: {v}")
            missing = []
            for sec in ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]:
                if sec not in r.headers:
                    missing.append(sec)
            if missing:
                print(f"  [!] Missing security headers: {', '.join(missing)}")
        except Exception as e:
            print(f"  [!] Header analysis failed: {e}")

    # ---------------- BASIC VULN CHECKS ----------------
    def check_xss(self, param="q"):
        print(f"[+] Testing for XSS on param {param}")
        payload = "<script>alert(1)</script>"
        url = f"{self.target}?{param}={payload}"
        try:
            r = self.session.get(url, timeout=5)
            if payload in r.text:
                print(f"  [VULN] Reflected XSS at {url}")
        except:
            pass

    def check_sqli(self, param="id"):
        print(f"[+] Testing for SQLi on param {param}")
        payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1"]
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if re.search(r"(SQL|syntax|database|mysql|odbc)", r.text, re.I):
                    print(f"  [VULN] Possible SQLi at {url}")
            except:
                pass

    def check_lfi(self, param="file"):
        print(f"[+] Testing for LFI on param {param}")
        payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
        for p in payloads:
            url = f"{self.target}?{param}={p}"
            try:
                r = self.session.get(url, timeout=5)
                if "root:" in r.text or "[extensions]" in r.text:
                    print(f"  [VULN] LFI at {url}")
            except:
                pass
