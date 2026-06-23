# CyberGuard // Website Security Analyzer & Exploit Sandbox

A lightweight, high-performance, learning-focused web security scanner and interactive playground. Built using **Python's standard library modules, Flask, and SQLite**, this application performs active audits across network protocols, certificate configurations, DNS entries, directory indexes, and host platforms. 

It also features a sandboxed **HTTP Headers Exploitation Playground** that visually simulates client-side attacks (Clickjacking and Cross-Site Scripting) based on dynamic server header configurations.

---

## 🚀 Key Security Scanner Modules

The analyzer executes ten separate security evaluations divided into dedicated domains:

| Category | Scan Module | Networking / System Logic | Cybersecurity & Compliance Audited |
| :--- | :--- | :--- | :--- |
| **Headers** | HTTP Headers Auditor | `urllib.request` | Validates clickjacking (XFO/CSP), MIME-sniffing (nosniff), and downgrade protection (HSTS). |
| **Cryptography** | TLS Handshake Prober | `ssl` socket wrapper | Verifies issuer trust chains, expiration dates, and probes support for legacy versions (`TLSv1.0`, `TLSv1.1`). |
| **DNS** | Nameserver Resolver | Safe `subprocess` with `shell=False` | Resolves A, AAAA, MX, and validates SPF/DMARC anti-spoofing policies without command injection risk. |
| **Registry** | Recursive WHOIS client | Raw sockets on TCP Port 43 | Queries IANA first, resolves authoritative TLD registry, and audits transfer locks (`clientTransferProhibited`). |
| **Ports** | C-Style Port Prober | C-style `socket.connect_ex` | Scans key ports (SSH, FTP, DB, web) quickly with a 1.0s timeout to bypass socket exception overheads. |
| **Host Info** | Technology Detector | Regular expressions & cookie grids | Scrapes response banners (`Server`, `X-Powered-By`) and cookies (`PHPSESSID`, `JSESSIONID`) to flag version leaks. |
| **Discovery** | Subdomain Mapper | Concurrent Thread Resolution | Performs multi-threaded queries for sub-platforms (e.g. `dev`, `vpn`, `admin`) to map the attack surface. |
| **Verbs** | HTTP Method Auditor | Custom verb request loops | Audits supported methods (`PUT`, `DELETE`, `TRACE`) to flag verb tampering and Cross-Site Tracking (XST) risks. |
| **Threat Intel** | robots/security.txt Crawler | Document parsing regex | Parses `robots.txt` for sensitive directory exposures and validates presence of `security.txt` contacts. |

---

## 🎮 The Interactive Exploit Playground

The playground provides a split-screen educational sandbox displaying how browser client protections behave under different header states:

1. **Clickjacking Simulation:** Students adjust `X-Frame-Options` (`None`, `SAMEORIGIN`, `DENY`), load the vulnerable banking portal, and deploy a transparent overlay. They can observe how clicks are hijacked when protection is missing versus how the browser blocks rendering when headers are active.
2. **CSP Bypass Simulation:** Injects script payloads into reflected query parameters. Students observe how strict Content-Security-Policies (`default-src 'self'`) block inline code execution versus how legacy or missing configurations allow cookies to be extracted.

---

## 🛡️ Vulnerability Mitigation Matrix

We implement defensive programming best practices directly in code to avoid standard web vulnerabilities:

- **Server-Side Request Forgery (SSRF) Prevention:** Inputs are validated using `urllib.parse`. Loopback subnets (`127.0.0.1`, `localhost`, `169.254.*.*`) and internal network IPs are strictly blocked to prevent the server from scanning internal assets.
- **SQL Injection (SQLi) Prevention:** SQLite interactions use parameterized queries (`?` placeholders) and enforce strict key casting (e.g. `int(history_id)`), ensuring user inputs are treated as literal strings, not query instructions.
- **Command Injection Prevention:** DNS queries invoke system utilities using `subprocess.Popen` with `shell=False`. Arguments are passed as structured lists, neutralizing shell command separators (like `;` or `&&`).
- **Denial of Service (DoS) Prevention:** The scan ledger caps records at exactly 50 items. Every scan triggers a deterministic SQLite pruning query to delete records older than the 50th item, protecting server disk space from exhaustion.
- **Cross-Site Scripting (XSS) Prevention:** Output rendering uses Jinja2 auto-escaping to convert HTML characters into safe codes, neutralizing payload injections.

---

## 🔍 Phase-by-Phase Summary

- **Phase 1: Flask Web Framework & SSRF Prevention** — Setup routing, templates, and strict URL protocol normalization. (See [education_phase1_flask.md](education_phase1_flask.md))
- **Phase 2: SQLite Ledger & SQLi Mitigation** — Created the history system, query parameterization, and automated table pruning. (See [education_phase2_db.md](education_phase2_db.md))
- **Phase 3: HTTP Security Headers Auditor** — Probed browser safety tags (Clickjacking, MIME, SSL strip protection). (See [education_phase3_headers.md](education_phase3_headers.md))
- **Phase 4: SSL/TLS Certificate Analyzer** — Extracted cert parameters (expiry, CA issuer) using native socket contexts. (See [education_phase4_ssl.md](education_phase4_ssl.md))
- **Phase 5: DNS Records & Safe Shell Probes** — Safe multi-record system resolutions to evaluate SPF/DMARC spoofing protections. (See [education_phase5_dns.md](education_phase5_dns.md))
- **Phase 6: Recursive WHOIS Registry Scanner** — Raw TCP Port 43 client traversing TLD referrers to audit registrar locks. (See [education_phase6_whois.md](education_phase6_whois.md))
- **Phase 7: C-Style TCP Port Scanner** — Rapid connect checks targeting admin/DB ports using error code returns. (See [education_phase7_portscan.md](education_phase7_portscan.md))
- **Phase 8: Tech Stack Fingerprinter & Version Leaks** — Scraped server signatures and session cookie names for CVE vulnerability matching. (See [education_phase8_techdetect.md](education_phase8_techdetect.md))
- **Phase 9: Advanced Cryptography, Scanners & Exploit Playground** — Added TLS protocol support audits, subdomain mapping, verb tampering checks, threat intel crawler, and the HTML/JS exploit simulation playground. (See [education_phase9_advanced.md](education_phase9_advanced.md))

---

## 📂 Project Directory Structure

```
Website Security Scanner/
│
├── app.py                      # Main Flask router, controllers, and database caps
├── modules/                    # Security scanning modules
│   ├── __init__.py
│   ├── header_scanner.py       # Audits response safety headers
│   ├── ssl_checker.py          # Cryptographic handshake, TLS & cipher checker
│   ├── dns_checker.py          # Command-injection safe DNS lookup tool
│   ├── whois_checker.py        # Recursive WHOIS parser querying registrar sockets
│   ├── port_scanner.py         # C-style connect_ex port scanner
│   ├── tech_detector.py        # Banner scraping and cookie analyzer
│   ├── subdomain_scanner.py    # Multi-threaded subdomain DNS brute-forcer
│   ├── verb_auditor.py         # HTTP verb tampering & TRACE/XST check module
│   └── threat_intelligence.py  # Robots.txt / security.txt parser
│
├── database/
│   └── scan_history.db         # SQLite database file
│
├── templates/
│   ├── index.html              # Main security audit console layout
│   ├── playground.html         # Exploit playground parent configuration panel
│   └── playground_target.html  # Vulnerable target bank application layout
│
├── static/
│   └── style.css               # Dark cyberpunk theme stylesheets
│
├── .gitignore                  # Git exclusions configuration
└── README.md                   # Full deployment & documentation manual
```

---

## 🚀 Installation & Local Deployment

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/Parvanshu12/website-security-analyzer.git
   cd website-security-analyzer
   ```

2. **Verify Python Installation:**
   ```powershell
   python --version
   ```

3. **Install Dependencies:**
   Ensure Flask is installed in your python environment:
   ```powershell
   pip install Flask
   ```

4. **Launch the Application:**
   ```powershell
   python app.py
   ```

5. **Interact via Browser:**
   - **Main Security Scanner:** Navigate to **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.
   - **Exploit Playground:** Navigate to **[http://127.0.0.1:5000/playground](http://127.0.0.1:5000/playground)**.

---

## 🌐 Push Updates to GitHub

To commit these new Phase 9 feature upgrades and push them to your repository on GitHub:

1. **Verify Git Status:**
   ```powershell
   git status
   ```

2. **Stage New Files:**
   ```powershell
   git add .
   ```

3. **Commit Upgrades:**
   ```powershell
   git commit -m "Implement Phase 9: Active TLS protocol auditing, subdomain brute-forcing, HTTP verb checking, threat crawler, and Exploit Playground"
   ```

4. **Push to Remote:**
   ```powershell
   git push origin main
   ```
