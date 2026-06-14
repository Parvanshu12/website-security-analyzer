# Study Guide: HTTP Security Headers & Defensive Networking (Phase 3)

This study guide explains the web security controls and defensive programming principles implemented in **Phase 3** of the Website Security Analyzer.

---

## 1. HTTP Security Headers

Security headers are HTTP response key-value metadata pairs sent by a server to a client browser. They instruct the browser to restrict permissions and enable security sandboxes.

### A. Strict-Transport-Security (HSTS)
Instructs the browser to communicate with the host strictly using encrypted HTTPS connections, even if the user clicks an HTTP link.
* **Format:** `max-age=31536000; includeSubDomains; preload`
* **Vulnerability Mitigated:** **SSL Stripping / Protocol Downgrade** attacks. Attackers intercepting local network traffic cannot force the browser to drop encryption down to cleartext HTTP.

### B. Content-Security-Policy (CSP)
Declares trusted source domains from which the browser is allowed to load resources (scripts, styles, frames, images).
* **Format:** `default-src 'self'; script-src 'self' https://apis.google.com`
* **Vulnerability Mitigated:** **Cross-Site Scripting (XSS)**. Even if an attacker injects a malicious script tag (e.g. `<script src="http://attacker.com/mal.js">`), the browser rejects loading it because the source domain is not listed in the CSP policy whitelist.

### C. X-Frame-Options (XFO)
Specifies whether the browser is allowed to render the site's pages inside `<iframe>` tags on other websites.
* **Format:** `DENY` or `SAMEORIGIN`
* **Vulnerability Mitigated:** **Clickjacking**. Attackers embed your site inside an invisible iframe overlaying a malicious page, tricking users into clicking hidden buttons (e.g. "Delete Account").

### D. X-Content-Type-Options
Instructs the browser to strictly follow the declared MIME content types sent by the server rather than guessing the file type (sniffing).
* **Format:** `nosniff`
* **Vulnerability Mitigated:** **MIME-Sniffing Exploits**. Prevents users from uploading text or image files containing hidden executable HTML or JavaScript that the browser might run as a script.

### E. Referrer-Policy
Controls how much referral path information (the source page URL) is sent to external sites in the `Referer` header when users click outbound links.
* **Format:** `no-referrer`, `same-origin`, `strict-origin-when-cross-origin`
* **Vulnerability Mitigated:** **Sensitive Information Leakage**. Prevents exposing private URL parameters (e.g., reset tokens, private IDs) in external web logs.

---

## 2. Defensive Network Programming

### A. User-Agent Spoofing
Outbound queries from standard scripting environments identify themselves via headers like `User-Agent: Python-urllib/3.x`.
* **The Problem:** Modern Web Application Firewalls (WAFs) and CDNs block bot scraping signatures.
* **Solution:** We set standard browser strings (User-Agent spoofing) to ensure our security scans are not rejected by target network filters.

### B. Socket Connection Timeouts (DoS Mitigation)
When requesting remote web servers, we are communicating with external, untrusted environments.
* **The Threat:** If we send a request without a timeout, a slow or malicious remote server can keep the connection socket open indefinitely. This blocks our Flask server threads, exhausting resources and causing a Denial of Service.
* **Defense:** Enforce a strict `timeout=5.0` socket limit on all outbound network queries.

### C. Exception Handling and Error Trapping
Outbound network requests are highly prone to failures. We handle:
1. **HTTPError:** Spun when the server responds with a failure code (e.g., `404` or `403`). We catch this and still audit the headers, since error templates must also be securely configured.
2. **URLError:** Caught when host DNS lookup fails or connections are refused, returning a clean alert warning to the dashboard instead of throwing tracebacks.
3. **socket.timeout:** Caught when connections hang.
