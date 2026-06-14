# Study Guide: SSL/TLS Cryptography & Trust Chains (Phase 4)

This study guide explains the cryptographic operations and socket-level verification principles implemented in **Phase 4** of the Website Security Analyzer.

---

## 1. Network Sockets & Port Operations

### A. Sockets
A **socket** is the software abstraction representing a terminal node for transmitting and receiving data across a network (bound to an IP address and Port).
* **Port 443:** The standard port for HTTPS (Hypertext Transfer Protocol Secure).

### B. TCP Sockets (`SOCK_STREAM`)
Our scanner opens a **TCP (Transmission Control Protocol)** socket. TCP is a **connection-oriented** protocol, which means a 3-way handshake must occur to establish a reliable connection before data transmits:
1. Client sends a `SYN` (Synchronize) packet.
2. Server responds with `SYN-ACK` (Synchronize-Acknowledge).
3. Client sends `ACK` (Acknowledge) to establish the circuit.

---

## 2. The SSL/TLS Cryptographic Handshake

Once the standard TCP connection is established, the application initiates the **TLS (Transport Layer Security)** cryptographic handshake to negotiate encryption keys.

```
       Client                                                    Server
         |                                                         |
         |  ClientHello (TLS versions, ciphers, random)            |
         |-------------------------------------------------------->|
         |                                                         |
         |  ServerHello (selected TLS version, cipher, random)     |
         |<--------------------------------------------------------|
         |  Server Certificate (Public Key & Identity signatures)  |
         |<--------------------------------------------------------|
         |                                                         |
         |  Key Exchange & Verification                            |
         |-------------------------------------------------------->|
         |                                                         |
         |  ChangeCipherSpec (Symmetric Session Key Encrypted)     |
         |-------------------------------------------------------->|
         |                                                         |
         |  ChangeCipherSpec (Symmetric Session Key Decrypted)     |
         |<--------------------------------------------------------|
         |                                                         |
         v                                                         v
                       Encrypted Session Active (HTTPS)
```

### Handshake Stages:
1. **ClientHello:** The client announces its capabilities (supported TLS versions, cipher suites like AES, ChaCha20, and a random number `ClientRandom`).
2. **ServerHello:** The server selects the highest common secure TLS protocol version (e.g., TLSv1.3) and cipher suite, and sends its `ServerRandom`.
3. **Server Certificate:** The server sends its certificate containing its **Public Key** and identity signatures.
4. **Verification:** The client verifies the certificate.
5. **Key Exchange:** The client generates a `Pre-Master Secret`, encrypts it with the server's public key (using RSA/DH), and sends it. Both parties derive the symmetric session keys.
6. **Symmetric Encryption:** Both parties activate symmetric encryption using the derived session key.

---

## 3. Public Key Infrastructure (PKI) & Trust Chains

### A. Asymmetric vs. Symmetric Cryptography
* **Asymmetric (Public-Key) Cryptography:** Uses a key pair (public key shared with everyone, private key kept secret).
  * *Purpose:* Used during the handshake for **identity verification** (authentication) and **key exchange**.
  * *Algorithms:* **RSA** (legacy math) and **ECC** (modern elliptic curves, offering stronger security with smaller keys).
* **Symmetric Cryptography:** Uses a single shared key for both encryption and decryption.
  * *Purpose:* Used to encrypt the actual web traffic because it is computationally faster than asymmetric math.

### B. Certificate Authorities (CAs) & Trust Stores
An SSL certificate binds a public key to a domain name. To prevent spoofing, a trusted third party must sign this binding:
1. **Certificate Authority (CA):** Entities like *Let's Encrypt* or *DigiCert* verify ownership and sign certificates.
2. **Root Trust Store:** Operating systems and browsers come pre-installed with root certificates of trusted CAs.
3. **Certificate Chain:** A domain's certificate is signed by an intermediate CA, which is signed by a Root CA. The browser traces this chain back to a root certificate in its trust store.

---

## 4. Handshake Verification Fallbacks

If a domain presents an expired, self-signed, or untrusted certificate, standard verified context connections throw validation errors.
* **The Problem:** We want to show certificate details even if the handshake fails verification, rather than crashing the scan.
* **Solution:** We wrap connections in standard try-except blocks. If verification fails, the scanner catches the verification error, flags `valid = False`, and automatically retries using an unverified context (`ssl._create_unverified_context()`) to retrieve cipher suites and protocol versions safely.
