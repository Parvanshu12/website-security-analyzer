# Website Security Analyzer

A comprehensive, learning-oriented, production-ready Website Security Analyzer built with Python standard library modules, Flask, and SQLite. The application executes active audits across network layers, HTTP headers, cryptographic certificates, DNS systems, registry databases, TCP ports, and infrastructure platforms.

---

## 🏗️ Architecture & Core Philosophy

This project was built strictly without heavy third-party libraries (such as `requests` or `dnspython`). Instead, it relies entirely on native Python packages (`socket`, `ssl`, `urllib.request`, `subprocess`, `sqlite3`). 

By enforcing this constraint:
- **Low-Level Protocol Understanding:** We interact directly with TCP ports, parse SSL certificates from raw sockets, and query WHOIS registries via Port 43 TCP streams.
- **Minimal Dependencies:** The system is lightweight, easy to run, and highly portable for production hosting on Linux or Windows.
- **Defensive Design:** We implement core security principles directly in code to guard against common web vulnerabilities (SSRF, SQLi, Command Injection, DoS).

---

## 🔍 Phase-by-Phase Implementation Details

Here is a breakdown of what was built during each phase, why we did it, and the security or network concepts applied:

### Phase 1: Flask Web Framework & SSRF Prevention
* **What We Did:** Created the web application interface using Flask, CSS, and Jinja2 templates, processing target URLs via `POST` requests.
* **Why We Did It:** Separated the client interface from the backend scanning engine. We validated inputs using `urllib.parse` to extract clean domain hosts.
* **Security Control (SSRF Prevention):** An attacker might supply loopback addresses (like `http://127.0.0.1:8080/admin` or `http://169.254.169.254/`) to scan internal ports or cloud metadata. We block loopback subnets and non-web protocols (enforcing `http` or `https` only) to eliminate **Server-Side Request Forgery (SSRF)**.
* **Security Control (XSS Prevention):** Used Jinja2 auto-escaping (`{{ value }}`) to neutralize HTML tags in user-supplied strings, preventing **Cross-Site Scripting (XSS)**.

### Phase 2: SQLite Ledger & SQLi Mitigation
* **What We Did:** Implemented a persistent scan history ledger using SQLite, capped at exactly 50 records.
* **Why We Did It:** Allowed users to view past scan results and reload them instantly without re-running socket scans.
* **Security Control (SQL Injection Prevention):** Standard string concatenation in SQL queries (e.g. `SELECT * FROM scans WHERE id = ` + user_id) allows attackers to inject database commands. We use **parameterized queries** (`?` placeholders) and cast keys to integers to ensure the database engine treats input strictly as literal values.
* **Security Control (DoS & Disk Exhaustion Prevention):** To prevent malicious bots from filling the server's hard drive by scanning millions of pages, we created an automated database pruning system. Every new scan triggers a query that locates the ID of the 50th newest record and deletes all records older than it.

### Phase 3: HTTP Security Headers Auditor
* **What We Did:** Built `modules/header_scanner.py` to fetch headers from target domains and audit modern security configuration tags.
* **Why We Did It:** Web browsers use headers to apply security rules. Missing headers leave users exposed to client-side attacks.
* **Audited Protections:**
  - **`X-Frame-Options` & `CSP (frame-ancestors)`:** Prevents **Clickjacking** by stopping external domains from rendering this site in an invisible iframe.
  - **`X-Content-Type-Options: nosniff`:** Prevents **MIME-Sniffing** attacks where browsers interpret assets (like stylesheets or images) as executable JavaScript.
  - **`Strict-Transport-Security` (HSTS):** Mitigates **SSL Strip/HTTP Downgrade** attacks by forcing browsers to connect only via HTTPS.
  - **`Content-Security-Policy` (CSP):** Restricts script sources to protect users from XSS payloads.

### Phase 4: SSL/TLS Certificate Analyzer
* **What We Did:** Programmed `modules/ssl_checker.py` using Python's native `ssl` and `socket` modules to perform cryptographic handshakes.
* **Why We Did It:** Validating certificate configurations ensures that data transmitted between clients and the server is encrypted securely and trusted.
* **Audited Protections:**
  - **Trust Chain Integrity:** Validates that the certificate common name (CN) matches the target domain, and checks whether the issuing Certificate Authority (CA) is recognized.
  - **Expiration Check:** Extracts and parses date strings to notify administrators of expired or expiring certificates.
  - **Man-in-the-Middle (MitM) Defense:** Detects self-signed or invalid certificates that could allow attackers to intercept and read sensitive traffic.

### Phase 5: DNS Records & Command Injection Safety
* **What We Did:** Built `modules/dns_checker.py` to resolve network routing and security records (`A`, `AAAA`, `MX`, `TXT`/SPF/DMARC) using native system commands.
* **Why We Did It:** Auditing DNS settings exposes network routing configurations and validates domain anti-spoofing policies.
* **Security Control (Command Injection Prevention):** Running system commands like `nslookup` using Python's `subprocess.Popen(..., shell=True)` with unescaped string concatenations allows attackers to append arbitrary command strings (e.g., `; rm -rf /`). We set `shell=False` and pass arguments as a structured array list, which prompts the Operating System to execute the command directly, neutralizing all shell command separators.
* **Spoofing Defense Validation:** Inspects SPF and DMARC TXT records to ensure the domain is hardened against email phishing and spoofing.

### Phase 6: Recursive WHOIS Registry Scanner
* **What We Did:** Built a raw TCP Port 43 client in `modules/whois_checker.py` that queries domain registries to find registration details.
* **Why We Did It:** Domain ownership, registry locks, and expiration dates are key markers for evaluating domain trust.
* **Networking Concept (Recursive Querying):** Different top-level domains (TLDs) have different registries. The analyzer queries `whois.iana.org` first, parses the response to find the authoritative registrar WHOIS server for that TLD, opens a second TCP socket connection to that registrar, and extracts domain creation, update, and registry lock statuses.
* **Domain Hijacking Check:** Verifies if flags like `clientTransferProhibited` are active, ensuring the domain is locked against unauthorized transfer attempts.

### Phase 7: C-Style TCP Port Scanner
* **What We Did:** Programmed `modules/port_scanner.py` using sockets to scan common administrative, database, and web ports.
* **Why We Did It:** Open administrative ports (like SSH, Telnet, or FTP) are primary targets for brute-force attacks.
* **Networking Concept (connect_ex):** Traditional socket connections throw exceptions when a port is closed, adding severe CPU overhead. We use C-style `socket.connect_ex` which returns status codes directly (0 for open, non-zero for closed/filtered), bypassing exception handling and increasing scan speeds.
* **Resource Starvation Prevention:** Enforces a strict 1.0-second timeout per port to prevent threads from locking up on firewalled ports.

### Phase 8: Production Tech Stack Detector & Version Leaks
* **What We Did:** Coded `modules/tech_detector.py` to identify backend web servers, programming frameworks, and CMS deployments.
* **Why We Did It:** Exposing names and versions of backend software allows attackers to query CVE databases for known public exploits.
* **Audit Mechanics:**
  - **Banner Grabbing:** Uses regular expressions to extract `Server` and `X-Powered-By` headers. Version disclosures (e.g., `nginx/1.24.0`) are flagged as vulnerability warnings.
  - **Cookie Signatures:** Audits cookies like `PHPSESSID` (PHP), `JSESSIONID` (Java), and `ASP.NET_SessionId` (Microsoft IIS) to identify the framework even when headers are stripped.
  - **HTML Meta Tag Scraping:** Scrapes raw HTML for `<meta name="generator" content="...">` to identify WordPress, Drupal, or other CMS version layers.

---

## 📂 Project Directory Structure

```
Website Security Scanner/
│
├── app.py                     # Main Flask router & Secure controller
├── modules/                   # Active security scanning engines
│   ├── __init__.py
│   ├── header_scanner.py      # HTTP response header checks
│   ├── ssl_checker.py         # Cryptographic trust chain validator
│   ├── dns_checker.py         # Command-injection safe DNS resolver
│   ├── whois_checker.py       # Recursive TCP Port 43 WHOIS parser
│   ├── port_scanner.py        # C-style connect_ex TCP port scanner
│   └── tech_detector.py       # Banner grabbing & Cookie fingerprinter
│
├── database/
│   └── scan_history.db        # SQLite database (capped at 50 records)
│
├── templates/
│   └── index.html             # Premium glassmorphism dark UI dashboard
│
├── static/
│   └── style.css              # Cyberpunk UI stylesheet
│
├── .gitignore                 # Configured git exclusions (db, logs, cache)
└── README.md                  # Comprehensive project documentation
```

---

## 🚀 How to Run the App

1. **Verify Python is installed:**
   ```powershell
   python --version
   ```

2. **Run the Flask application:**
   ```powershell
   python app.py
   ```

3. **Navigate to the web dashboard:**
   Open your browser and go to **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

4. **Verify educational files:**
   Review the `education_phase*.md` files in the project root. These files provide deep dive guides into the systems, cryptography, and protocols driving each security module.
