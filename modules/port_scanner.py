# modules/port_scanner.py
# ------------------------------------------------------------------------------
# This module implements active network-level TCP port scanning on target systems.
#
# CYBERSECURITY CONCEPT - Active Reconnaissance:
# A port scanner queries network ports to find out which system services (daemons) are listening.
# Attackers look for open ports running legacy or vulnerable services to exploit.
# Defenders audit open ports to minimize the host's attack surface.
#
# NETWORKING CONCEPT - TCP/IP Sockets:
# We resolve the domain name to an IP address and attempt connections across standard ports.
# ------------------------------------------------------------------------------

import socket  # Low-level networking socket interface library
from urllib.parse import urlparse  # Utility for parsing URL string segments

def scan_ports(url):
    """
    Performs active TCP port scans targeting a list of standard network services.
    
    PYTHON CONCEPT - socket.connect_ex():
    Attempts TCP connections. Instead of raising exceptions on connection failures,
    it returns an integer error code (errno) directly (0 for success, non-zero for error),
    enabling a clean, high-performance scanning loop.
    
    ARGUMENTS:
        url (str): The target website URL (e.g., https://example.com)
        
    RETURNS:
        dict: A checklist of probed ports and their active states.
    """
    
    # 1. Parse target domain hostname
    parsed_url = urlparse(url)
    
    # Strip port details if present (e.g., 'example.com:443' -> 'example.com')
    hostname = parsed_url.netloc.split(':')[0]
    
    # 2. Resolve Host name to IP Address
    # CYBERSECURITY RELEVANCE - Direct IP Targeting:
    # Connecting directly to IP addresses prevents recursive DNS query lookups on every port,
    # making the scanning sequence much faster.
    try:
        # gethostbyname queries DNS recursive servers for the host's A (IPv4) record
        target_ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        # Fallback details list structure on host resolution errors.
        # This prevents UndefinedError crashes in templates by supplying default mock list objects.
        return {
            "status": "completed",
            "score_impact": 0,
            "ports": [
                {"port": 21, "service": "FTP", "state": "Unknown", "secure": True, "notes": f"Host IP lookup failed: {str(e)}"},
                {"port": 22, "service": "SSH", "state": "Unknown", "secure": True, "notes": f"Host IP lookup failed: {str(e)}"},
                {"port": 23, "service": "Telnet", "state": "Unknown", "secure": True, "notes": f"Host IP lookup failed: {str(e)}"},
                {"port": 80, "service": "HTTP", "state": "Unknown", "secure": True, "notes": f"Host IP lookup failed: {str(e)}"},
                {"port": 443, "service": "HTTPS", "state": "Unknown", "secure": True, "notes": f"Host IP lookup failed: {str(e)}"}
            ]
        }

    # 3. Define Checklist of Target Network Ports to Audit
    # We audit legacy cleartext protocols (21 FTP, 23 Telnet) alongside standard web services.
    target_ports = [
        {"port": 21, "service": "FTP", "notes": "File Transfer Protocol (Cleartext)"},
        {"port": 22, "service": "SSH", "notes": "Secure Shell Remote Console"},
        {"port": 23, "service": "Telnet", "notes": "Legacy Cleartext Terminal Console"},
        {"port": 80, "service": "HTTP", "notes": "Unencrypted Web Traffic Service"},
        {"port": 443, "service": "HTTPS", "notes": "Encrypted Web Traffic Service"}
    ]

    scan_results = []
    points_deducted = 0

    # 4. Execute Scanning Loop
    for item in target_ports:
        port_num = item["port"]
        service_name = item["service"]
        service_desc = item["notes"]
        
        # Instantiate raw TCP socket descriptor
        # AF_INET indicates IPv4 addressing, SOCK_STREAM indicates TCP connection-oriented protocol.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Enforce strict timeout parameter (1.0 second) to prevent hanging on filtered ports
        s.settimeout(1.0)
        
        # Execute C-style connection check
        # Returns 0 if connection completes successfully (Completed TCP Handshake)
        result = s.connect_ex((target_ip, port_num))
        
        # Initialize default security audit metrics
        port_open = False
        port_secure = True
        status_text = "Closed"
        audit_note = ""

        # 5. Evaluate Probed Port State & Security Risks
        if result == 0:
            port_open = True
            status_text = "Open"
            
            # CYBERSECURITY CONCEPT - Cleartext Protocol Vulnerabilities:
            # Exposing unencrypted interfaces (FTP on 21 or Telnet on 23) represents a critical security risk.
            # Credentials transmitted across these channels are visible to sniffing attacks (MitM).
            if port_num == 21:
                port_secure = False
                audit_note = "VULNERABILITY: Insecure cleartext FTP service is exposed! Disable or replace with SFTP."
                points_deducted += 10  # Deduct points in app.py grading engine for open FTP
            elif port_num == 23:
                port_secure = False
                audit_note = "CRITICAL VULNERABILITY: Highly insecure cleartext Telnet exposed! Close this port immediately."
                points_deducted += 10  # Deduct points for open Telnet
            elif port_num == 22:
                port_secure = True
                audit_note = "Secure administration service exposed. Ensure password brute-force protections are active."
            elif port_num == 80:
                port_secure = True
                audit_note = "HTTP web port is open. Ensure it automatically redirects users to secure HTTPS Port 443."
            elif port_num == 443:
                port_secure = True
                audit_note = "HTTPS secure web service is open and accepting encrypted connections."
        else:
            # Port is closed or filtered (blocked by host firewalls)
            port_open = False
            status_text = "Closed"
            port_secure = True
            audit_note = f"Service is closed or filtered. Attack surface is safely minimized."

        # Always close sockets to release network descriptors
        s.close()

        # Save audited parameters to results list
        scan_results.append({
            "port": port_num,
            "service": service_name,
            "state": status_text,
            "secure": port_secure,
            "notes": audit_note
        })

    # Return structured compliance summary
    return {
        "status": "completed",
        "score_impact": points_deducted,
        "ports": scan_results
    }
