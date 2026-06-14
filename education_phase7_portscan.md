# Study Guide: Network Port Scanning & Surface Auditing (Phase 7)

This study guide explains the networking concepts, system socket protocols, and security evaluation rules implemented in **Phase 7** of the Website Security Analyzer.

---

## 1. Network Ports & Protocols

### A. What is a Network Port?
An IP address identifies a unique device on a network. A **port** is a 16-bit unsigned integer (ranging from 0 to 65535) that identifies a specific application process or daemon running on that device.
* **Well-Known Ports (0-1023):** Standard system services (e.g. HTTP on Port 80, HTTPS on Port 443, SSH on Port 22).
* **Registered Ports (1024-49151):** Vendor-specific applications (e.g., MySQL on Port 3306).
* **Dynamic/Private Ports (49152-65535):** Temporary ports assigned by client operating systems for outgoing traffic.

---

## 2. TCP Port States

When our port scanner probes a target TCP port, it attempts a standard TCP connection. The state is determined by the target's response:
1. **Open:** The target server completed the TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`). A service is actively listening on this port.
2. **Closed:** The target server responded with a `RST` (Reset) packet. The host is online, but no application process is listening on that port.
3. **Filtered:** The scanner received no response (request timed out). This indicates that an intermediate firewall or host-based security policy is dropping the probe packets without sending a response.

---

## 3. C-Style Sockets: `connect_ex` vs. `connect`

In standard socket programming, we use the `connect((ip, port))` function.
* **The Problem:** If a port is closed or filtered, `connect()` raises a system exception (like `ConnectionRefusedError` or `TimeoutError`). In a scanning loop checking multiple ports, handling multiple try-except exception paths generates significant system overhead and slows execution speed.
* **The Solution:** We use the C-style socket method `connect_ex((ip, port))`.
  * Instead of raising exceptions, it returns an **integer error code** (errno) directly.
  * If the connection is successful, it returns `0` (port is **Open**).
  * If it fails, it returns a non-zero system error code (e.g., `10061` on Windows or `111` on Linux for connection refused, indicating the port is **Closed**).
  * This enables a lightweight, high-performance scanning loop.

---

## 4. Attack Surface Security Audits

Exposing unnecessary ports directly to the public Internet increases the target's attack surface. We scan five standard ports to audit compliance:

| Port | Service | Default Encryption | Security Evaluation |
|---|---|---|---|
| **Port 21** | FTP | None (Cleartext) | **High Risk.** Transmits credentials and files in cleartext. Vulnerable to sniffing. Must be closed or replaced by SFTP (Port 22). |
| **Port 22** | SSH | Strong (Asymmetric/Symmetric) | **Standard.** Secure remote console. Must be monitored to block password brute-forcing. |
| **Port 23** | Telnet | None (Cleartext) | **Critical Risk.** Transmits command sessions and credentials in cleartext. Must be strictly closed. |
| **Port 80** | HTTP | None (Cleartext) | **Normal.** Web service. Should redirect all traffic to Port 443. |
| **Port 443** | HTTPS | Strong (SSL/TLS) | **Secure.** Standard encrypted web traffic. |

---

## 5. Port Scan Performance and Timeouts

Web scanners must balance accuracy and speed:
* If a port is **Filtered**, the socket will wait for a response until it hits the system timeout (usually 60 seconds).
* To prevent checking 5 ports from taking 5 minutes, we enforce a strict **`timeout = 1.0` second** limit on each connection. This guarantees that even if all ports are filtered, the scan completes in exactly 5 seconds.
