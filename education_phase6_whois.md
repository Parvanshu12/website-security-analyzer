# Study Guide: WHOIS Domain Registries & Sockets (Phase 6)

This study guide explains the directory query architectures, socket-level networking protocols, and parsing designs implemented in **Phase 6** of the Website Security Analyzer.

---

## 1. The WHOIS Protocol (RFC 3912)

### A. What is WHOIS?
WHOIS is a transaction-oriented query and response protocol used to query databases storing information about registered domain names, IP address blocks, nameservers, and administrative contacts.

### B. Protocol Characteristics
WHOIS is one of the simplest protocols on the Internet:
* **Transport Protocol:** Runs on top of **TCP (Transmission Control Protocol)**.
* **Network Port:** Standardized on **Port 43**.
* **Transaction Loop:**
  1. The client establishes a TCP connection to the WHOIS server.
  2. The client sends a query payload string (the domain name, e.g. `google.com`) followed by a carriage return and line feed (`\r\n`).
  3. The server receives the query, processes it against its registration database, and returns matching text records.
  4. The server **automatically closes** the TCP socket connection once it finishes transmitting the data.

Unlike HTTP, there are no headers, status codes (like 200 OK), or request methods. It is pure text transmission.

---

## 2. Passive Reconnaissance & Security Scanning

In cybersecurity auditing, reconnaissance is split into two phases:
* **Active Reconnaissance:** Directly interacting with the target system's network boundaries (e.g., port scanning, vulnerability scanning). This activity is logged by target firewalls and IDS.
* **Passive Reconnaissance:** Gathering intelligence about the target *without* interacting with the target's servers. 
  * *Use Case:* Querying public WHOIS databases is a **passive** technique. The target website has no knowledge that we looked up their registration details, as our scanner connects directly to third-party registrar databases.

---

## 3. Recursive WHOIS Lookups (Root Referral Routing)

### A. Decentralization of Domain Data
There is no single centralized database for domain registration records. Different Top-Level Domains (TLDs like `.com`, `.org`, `.in`) are managed by separate registries:
* Verisign manages `.com` and `.net`.
* Public Interest Registry (PIR) manages `.org`.

### B. The Recursive Query Loop
To build a modular client that queries *any* domain extension natively without hardcoding registry IP maps, we implement a **recursive routing query loop**:
1. **Query Root Registry:** We open a TCP connection to **`whois.iana.org`** (the Internet Assigned Numbers Authority root server) and query the domain.
2. **Extract Referral Server:** We parse IANA's output for the line matching `whois:` or `refer:` (e.g. `whois: whois.verisign-grs.com`). This tells us the authoritative WHOIS server for that TLD.
3. **Query Authoritative Server:** We open a second socket connection directly to the referral registry server, re-query the domain, and fetch the full registration record.

---

## 4. Regular Expressions for Raw Data Parsing

Once the text record is fetched, we use Python's built-in **`re` (Regular Expressions)** library to extract key metrics. WHOIS outputs are free-text formats and differ between registrars, so our regex filters must be robust:
* **Registrar Name:** Look for strings like `Registrar:` or `Sponsoring Registrar:`.
* **Dates (Creation / Expiration):** Look for `Creation Date:`, `Created On:`, `Expiration Date:`, or `Registry Expiry Date:`.
* **Nameservers:** Loop and extract all records matching `Name Server:`.
* **Domain Lock Status:** Extract ICANN lock codes (e.g., `clientTransferProhibited`) which protect domains from unauthorized hijacking transfers.
* **Privacy Shield Detection:** We verify if contact details are hidden (e.g., matching strings like `REDACTED FOR PRIVACY` or `GDPR Masked`).
