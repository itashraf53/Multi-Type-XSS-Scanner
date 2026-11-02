# Multi-Type-XSS-Scanner
This tool is provided strictly for educational purposes and authorized security testing. MAY use this tool against: Applications you own Lab environments (DVWA, Juice Shop, local VMs) Targets for which you have explicit written authorization to test .
Common Commands
Task	Command
Full scan (all phases, no browser)	`python3 xss_scanner.py http://target.lab/ --insecure`
Full scan with browser DOM confirmation	`python3 xss_scanner.py http://target.lab/ --browser --insecure`
Reflected + Stored only	`python3 xss_scanner.py http://target.lab/ --skip-dom --force --insecure`
Reflected only (safe, no writes)	`python3 xss_scanner.py http://target.lab/ --skip-stored --skip-dom --insecure`
Output JSON for CI/CD	`python3 xss_scanner.py http://target.lab/ --output json --skip-stored --insecure > findings.json`
Authenticated scan	`python3 xss_scanner.py http://target.lab/ --cookies "session=abc123" --insecure`
Scan slower (polite mode)	`python3 xss_scanner.py http://target.lab/ --delay 2 --max-pages 15 --insecure`
---
All Command-Line Flags
```bash
python3 xss_scanner.py --help
```
```
usage: xss_scanner.py [-h] [--max-pages N] [--timeout N] [--delay S]
                      [--browser] [--force]
                      [--skip-reflected] [--skip-stored] [--skip-dom]
                      [--insecure] [--ignore-robots]
                      [--cookies COOKIES] [--header HEADER]
                      [--output {text,json}]
                      url
```
Flag	Default	Description
`url` (positional)	—	Target URL (must include `http://` or `https://`)
`--max-pages`	`10`	Max pages to crawl
`--timeout`	`10`	Per-request HTTP timeout (seconds)
`--delay`	`0.5`	Delay between requests (seconds)
`--browser`	off	Use Playwright to confirm DOM-based XSS
`--force`	off	Skip confirmation prompt for stored XSS scan
`--skip-reflected`	off	Skip Reflected XSS phase
`--skip-stored`	off	Skip Stored XSS phase (recommended for non-owned targets)
`--skip-dom`	off	Skip both DOM XSS phases
`--insecure`	off	Disable TLS cert verification (for self-signed labs)
`--ignore-robots`	off	Do not respect `robots.txt` (use only on your own infra)
`--cookies`	—	Cookie header string, e.g. `"session=abc; role=user"`
`--header`	—	Extra header (repeatable), e.g. `--header "X-Api-Key: 123"`
`--output`	`text`	Output format: `text` or `json`
---
What the Scanner Detects
XSS Type	Detection Method	False Positive Rate
Reflected	Injects payloads into form fields; checks for raw reflection in HTTP response	Low (exact string match)
Stored	Submits uniquely marked payloads; re-fetches pages to detect persistence	Low (uses `uuid4` markers)
DOM-based (static)	Static regex analysis of JS sources and sinks	Medium (heuristic)
DOM-based (browser-confirmed)	Real Chromium via Playwright; listens for `alert()` dialogs	Very Low (executed)
---
Project Structure
```
xss-scanner/
├── xss_scanner.py        # Main scanner script
├── README.md             # This file (GitHub README)
├── README.md             # Detailed technical README
└── linkedin_blog.md      # Educational blog post
```
---
Troubleshooting
Issue	Solution
`ModuleNotFoundError: requests`	`pip3 install requests beautifulsoup4`
`--browser requires Playwright`	`pip3 install playwright && playwright install chromium`
`SSLError: certificate verify failed`	Add `--insecure` flag
Hangs / slow	Lower `--max-pages`, raise `--delay`, or raise `--timeout`
Stored phase does nothing	POST forms rejected (CSRF). Add `--skip-stored` or test against a lab
No findings on vulnerable page	Likely a SPA. Add `--browser` flag
`[-] Skipping (robots.txt)`	Add `--ignore-robots` (only on your own infra)
---
Ethical Use Checklist
Before running the scanner, confirm:
[ ] I own the target, OR
[ ] I have written authorization from the asset owner
[ ] The target is a lab/development environment, not production
[ ] I have configured `--delay` to avoid disrupting the target
[ ] I am NOT scanning `.gov`, `.mil`, banking, healthcare, or any system covered by laws like CFAA (US), CMA (UK), or IT Act (India) without authorization
[ ] If I find a real vulnerability, I will report it through responsible disclosure — not exploit it
---
License
MIT License — see LICENSE file for details.
You are free to use, modify, and distribute this tool, provided you do so ethically and legally.
---
Contributing
Pull requests are welcome. Especially welcome:
Additional XSS payloads (especially WAF-evading variants)
Improved static DOM analysis with path-sensitive taint tracking
Test cases against common vulnerable apps
Documentation improvements
Please do not contribute payloads or features whose primary purpose is unauthorized access.
---
Acknowledgments
OWASP — for the XSS prevention cheat sheet that informed the payload list
PortSwigger Web Security Academy — for the conceptual breakdown of DOM-based XSS
The authors of `requests`, `beautifulsoup4`, and `playwright`
---
Contact / Responsible Disclosure
Found a bug in the tool itself? Open an issue.
Found a vulnerability in someone else's system using this tool? Do not contact the tool author — report it to the system owner through their responsible disclosure channel.
---
> **Final reminder**: This tool does not give you permission to scan anything. **Authorization is your responsibility.** Ignorance of the law is not a defense.
