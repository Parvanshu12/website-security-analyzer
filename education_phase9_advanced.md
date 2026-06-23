# Study Guide: Advanced Security Audits & Exploit Sandboxes (Phase 9)

This study guide explains the systems engineering, network protocols, defensive configurations, and exploit theory implemented in **Phase 9** of the Website Security Analyzer.

---

## 1. Active TLS Protocol & Cipher Suite Auditing

### Legacy Protocols & Downgrade Risks
Secure communication on the web depends on the Transport Layer Security (TLS) protocol. Over time, cryptographic vulnerabilities have deprecated older versions of the protocol:
* **TLS 1.0 & TLS 1.1:** Vulnerable to cryptographic attacks like BEAST (Browser Exploit Against SSL/TLS), POODLE (Padding Oracle On Downgraded Legacy Encryption), and RC4 cipher flaws.
* **TLS 1.2 & TLS 1.3:** Modern, secure protocols. TLS 1.3 simplifies the handshake process and removes obsolete, insecure cryptographic algorithms.

If a server accepts connections using TLS 1.0 or 1.1, attackers can force a client's connection to downgrade (a **downgrade attack**) to intercept or modify encrypted traffic.

### Active Handshake Probing Mechanics
To audit TLS support without relying on external libraries, we establish direct socket connections to the target server's HTTPS port (443) and force the client context to negotiate only one specific protocol version.
In Python, this is achieved by creating an `ssl.SSLContext` and setting protocol exclusion flags:

```python
# To isolate and test TLS 1.0 support:
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
context.load_default_certs()

# Disable all versions except TLS 1.0
context.options |= ssl.OP_NO_TLSv1_1
context.options |= ssl.OP_NO_TLSv1_2
context.options |= ssl.OP_NO_TLSv1_3
```

By wrapping a raw TCP socket connection with this specific context and calling `wrap_socket()`, we can determine if the handshake succeeds (indicating the server supports TLS 1.0) or throws a handshake exception (indicating it does not).

### Defensive Hardening: Disabling Legacy TLS
To disable legacy TLS protocols, configure web servers or reverse proxies to enforce minimum TLS versions.

**Nginx Configuration:**
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3; # Disable TLSv1.0 and TLSv1.1
    ssl_ciphers HIGH:!aNULL:!MD5;
}
```

**Apache Configuration:**
```apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL:!MD5
```

---

## 2. Attack Surface Mapping via Subdomain Discovery

### The Threat Model of Subdomain Exposure
Organizations often launch pre-production environments, administrative portals, or back-office integrations on subdomains that are not linked from their primary website (e.g., `dev.example.com`, `admin.example.com`, `vpn.example.com`, `db.example.com`).
* **Information Exposure:** Staging or dev servers may contain verbose error messages, debugging tools, or unauthenticated databases.
* **Forgotten Assets:** Deprecated software might remain active on old subdomains, providing a target for known exploits.
* **Subdomain Takeover:** If a subdomain points to a third-party service (e.g., GitHub Pages, AWS S3) that has been decommissioned, an attacker can register that third-party name and take control of the subdomain.

### Thread Pool Parallelism
Scanning subdomains serially is highly inefficient due to network timeouts. We use a thread pool (`concurrent.futures.ThreadPoolExecutor`) to dispatch DNS queries concurrently.

```
       +------------------------------------+
       |       ThreadPoolExecutor           |
       |  (Dispatches queries in parallel)  |
       +------------------------------------+
          /          |          |          \
         /           |          |           \
     [Worker 1]  [Worker 2]  [Worker 3]  [Worker 4]
        |            |          |            |
     dev.host     vpn.host    api.host    db.host
        |            |          |            |
     (Resolve)   (Timeout)   (Resolve)   (Resolve)
```

Each worker calls `socket.gethostbyname()`, which triggers the operating system's resolver to query DNS nameservers for an IPv4 address. If the subdomain does not exist, the resolver throws a `socket.gaierror` (getaddrinfo error), which is caught and filtered out.

---

## 3. HTTP Verb Tampering & Cross-Site Tracking (XST)

### Unsafe HTTP Methods
While `GET` and `POST` are standard for web traffic, HTTP defines several other verbs:
* **`PUT` / `DELETE`:** Used in REST APIs to create or delete resources. If exposed on static directories or administrative routes without authentication, they can allow unauthorized file uploads or deletion.
* **`TRACE`:** A diagnostic method that echoes the exact received request back to the client.

### Cross-Site Tracking (XST) Vulnerability
Modern browsers protect session security using the `HttpOnly` flag on cookies, preventing JavaScript (XSS) from reading them. However, if the `TRACE` method is enabled on the server:
1. An attacker injects a malicious script via an XSS vulnerability.
2. The script sends an asynchronous `TRACE` request to the server.
3. The server echoes the request headers—**including the client's HttpOnly session cookies**—back in the HTTP response body.
4. The script parses the response body, extracts the cookies, and sends them to the attacker's server, completely bypassing the `HttpOnly` defense.

### Defensive Hardening: Disabling TRACE
Disable the `TRACE` method in web server configurations.

**Nginx Configuration:**
```nginx
if ($request_method !~ ^(GET|POST)$ ) {
    return 405; # Block all methods except GET and POST
}
```

**Apache Configuration:**
```apache
TraceEnable off
```

---

## 4. Information Disclosure via robots.txt and security.txt

### The Double-Edged Sword of robots.txt
The Robots Exclusion Protocol (`robots.txt`) resides at the website root and instructs web crawlers (like Googlebot) which folders they should not scan.
```http
User-agent: *
Disallow: /admin/
Disallow: /db_backup/
Disallow: /config/
```
While search engines respect these rules, attackers read `robots.txt` specifically to find sensitive folders. This represents a form of **Information Disclosure**. Folder structures that need protection should be secured by authentication and authorization, not just "hidden" in `robots.txt`.

### security.txt Standard (RFC 9116)
The `security.txt` file (typically located at `/.well-known/security.txt`) provides a standardized way for security researchers to report vulnerabilities responsibly. It defines:
* **Contact:** Email addresses, phone numbers, or pgp keys.
* **Expires:** The date when the file is no longer valid.
* **Policy:** A link to the organization's responsible disclosure policy.

Ensuring a valid `security.txt` exists helps prevent researchers from disclosing flaws publicly before developers can patch them.

---

## 5. Exploit Playground Theory

### Clickjacking & Frame Sandboxing
Clickjacking (User Interface Redress Attack) occurs when an attacker overlays a transparent, invisible iframe containing a target application (like a bank portal) over a seemingly harmless website. A user attempting to click on the harmless overlay button actually clicks on the hidden target's button (e.g., "Confirm Transfer").

#### Defending Against Clickjacking:
1. **`X-Frame-Options` Header:**
   * `DENY`: Modern browsers will completely refuse to render the page inside a frame.
   * `SAMEORIGIN`: The page can only be framed by pages running on the same domain/origin.
2. **Content-Security-Policy (CSP) `frame-ancestors`:**
   * `frame-ancestors 'none'`: Replaces `X-Frame-Options: DENY`.
   * `frame-ancestors 'self'`: Replaces `X-Frame-Options: SAMEORIGIN`.

### Content Security Policy (CSP) & XSS Mitigation
Content Security Policy is an HTTP response header that lets server administrators restrict the resources (JavaScript, CSS, Images) that the browser is allowed to load.

#### CSP Directives:
* **`default-src 'self'`:** Restricts all assets to only load from the domain origin.
* **`script-src 'self'`:** Disallows inline script tags (`<script>alert(1)</script>`) and code evaluation (`eval()`), which are the primary vectors for Cross-Site Scripting (XSS).
* **`script-src 'unsafe-inline'`:** Explicitly permits inline scripts, weakening XSS protections.
* **`script-src 'nonce-...'`:** Only executes scripts containing a matching cryptographic token (nonce) generated per request.

### Same-Origin Policy (SOP) Limits in Testing
The browser's Same-Origin Policy permits frames to access their parent page's DOM (and vice versa) only if they share the exact protocol, port, and domain. In our sandbox environment, because both the controller and the target bank page are hosted on the same Flask instance (e.g., `127.0.0.1:5000`), they share the same origin.
* This allows our demonstration script in `playground.html` to programmatically detect when the iframe has loaded successfully or blocked rendering, illustrating how browsers respond to various safety configurations.
