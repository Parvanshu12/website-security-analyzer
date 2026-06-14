# Study Guide: Domain Name System (DNS) & Anti-Phishing Security (Phase 5)

This study guide explains the networking records and email validation architectures implemented in **Phase 5** of the Website Security Analyzer.

---

## 1. Domain Name System (DNS) Fundamentals

DNS is the phonebook of the Internet, translating human-readable hostnames (e.g. `google.com`) into machine-readable IP addresses (e.g. `142.250.190.46`).
* **Name Resolution Hierarchy:** When a query is made, it travels from your local stub resolver to a recursive DNS server, then queries Root Servers (`.`), Top-Level Domain (TLD) servers (like `.com`), and finally the domain's Authoritative Name Server.

---

## 2. Common DNS Record Classes

* **A (Address) Records:** Maps a domain host name to its 32-bit IPv4 address.
* **AAAA (IPv6 Address) Records:** Maps a domain to its 128-bit IPv6 address.
* **MX (Mail Exchanger) Records:** Directs mail delivery traffic. Defines mail servers authorized to receive incoming emails for the domain, sorted by preference levels (lower numbers have higher priority).
* **NS (Name Server) Records:** Identifies the authoritative DNS servers responsible for the domain's records.
* **TXT (Text) Records:** Holds arbitrary human-readable or machine-readable text annotations. Critical for hosting security configuration frameworks.

---

## 3. Email Spoofing & Phishing Vulnerabilities

The standard email protocol, **SMTP (Simple Mail Transfer Protocol)**, was created in 1982 and lacks built-in identity verification. 
* **The Vulnerability:** An attacker can easily connect to an SMTP server and craft an email header claiming to be `ceo@yourcompany.com`, sending it to employees.
* **Defense:** Domains deploy SPF and DMARC TXT records to specify who is authorized to send emails on their behalf, allowing receiving servers to detect and block spoofed mail.

---

## 4. SPF: Sender Policy Framework

An SPF record is a TXT record containing a list of authorized IP addresses, subnets, and include scopes allowed to send emails from the domain.
* **Example:** `v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all`
* **Directives:**
  * `v=spf1`: Identifies the record version.
  * `ip4:` / `ip6:` / `include:`: Declares authorized sources.
  * `~all` (SoftFail): Receivers should accept but flag unauthorized mail.
  * `-all` (Fail): Receivers should strictly reject unauthorized mail.

---

## 5. DMARC: Domain-based Message Authentication

DMARC builds upon SPF and DKIM validation. It defines policies telling receiving servers how to handle messages that fail validation.
* **Example:** `v=DMARC1; p=reject; pct=100`
* **Directives:**
  * `p=none`: Monitor mail traffic; do not block (reporting mode).
  * `p=quarantine`: Send failed emails to the spam/junk folder.
  * `p=reject`: Drop/block failed emails entirely (strict enforcement).
  * `pct=100`: Apply the policy to 100% of outbound messages.

---

## 6. Secure Scripting: Mitigating OS Command Injection

To fetch MX/TXT records without external modules (like `dnspython`), we query the operating system's native command-line DNS resolver utility **`nslookup`** using Python's `subprocess` module.
* Spawning shell commands exposes web servers to **Command Injection** if inputs are concatenated directly.
* **Defense:**
  1. We strictly validate the domain format in validation routines.
  2. We call `subprocess.run()` with `shell=False`.
  3. We pass parameters as a clean list of strings: `["nslookup", "-type=TXT", domain]`.
  The operating system runs the executable directly and treats the entire domain parameter as a literal string argument, preventing control characters (like `;`, `&`, `|`) from spawning new shell sub-processes.
