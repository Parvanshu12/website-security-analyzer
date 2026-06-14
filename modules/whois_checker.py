# modules/whois_checker.py
# ------------------------------------------------------------------------------
# This module implements raw TCP socket connections to query WHOIS registration registries.
#
# CYBERSECURITY CONCEPT - Passive Reconnaissance:
# Querying public WHOIS databases gathers domain registrar name servers, registration dates,
# and lock statuses without interacting directly with the target host.
#
# NETWORKING CONCEPT - TCP Sockets (Port 43):
# WHOIS queries are simple text exchanges executed over TCP Port 43 (RFC 3912).
# ------------------------------------------------------------------------------

import socket  # Low-level networking socket interface library
import re      # Built-in regular expression string parsing library
from urllib.parse import urlparse  # Utility for parsing URL segments

def clean_to_base_domain(hostname):
    """
    Strips subdomains (like 'www.') to isolate the second-level domain name (e.g. google.com).
    
    WHY THIS APPROACH:
    WHOIS servers query at the base domain level. Querying 'www.google.com' on Port 43
    returns failures or missing records. Stripping subdomains ensures lookup compatibility.
    """
    # Split domain name by dot dividers
    parts = hostname.split('.')
    
    # If the domain is a subdomain structure (more than 2 parts, e.g. www.google.com)
    if len(parts) > 2:
        # Check if the domain is a second-level country code TLD (e.g., google.co.uk or amazon.co.in)
        # If the second to last part is a standard second-level extension (co, org, net, ac, etc.)
        if parts[-2] in ["co", "com", "org", "net", "gov", "ac", "res", "edu", "in", "uk"]:
            # Combine the last three parts (e.g. 'google.co.uk')
            return ".".join(parts[-3:])
        else:
            # Combine the last two parts (e.g. 'google.com')
            return ".".join(parts[-2:])
            
    # Return original host name if it already has only two parts
    return hostname

def query_socket_whois(server, domain):
    """
    Establishes a raw TCP socket connection on Port 43 and transmits the WHOIS query.
    
    NETWORKING CONCEPT - Raw TCP Sockets:
    We initiate a direct TCP stream connection, transmit the payload query, read the
    returned buffer block stream, and capture it into a text variable.
    """
    # Create raw TCP socket descriptor
    # AF_INET indicates IPv4 addressing, SOCK_STREAM indicates TCP connection-oriented protocol.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set strict connection timeout to prevent process hangs
    s.settimeout(5.0)
    
    try:
        # Connect socket to the target WHOIS server on Port 43
        s.connect((server, 43))
        
        # Format the query payload adding standard Carriage Return + Line Feed (CRLF) endings
        payload = f"{domain}\r\n"
        
        # Send raw query bytes to the socket stream
        s.sendall(payload.encode("utf-8"))
        
        # Initialize byte buffer assembly registry
        response = b""
        
        # Read the returned server streams in 4096-byte buffers
        while True:
            data = s.recv(4096)
            # If the socket returns empty, the server has closed connection (standard WHOIS loop exit)
            if not data:
                break
            response += data
            
        # Decode bytes back to UTF-8 text ignoring non-standard encoding parameters
        return response.decode("utf-8", errors="ignore")
        
    except Exception as e:
        # Propagate error warnings
        return f"Socket error connecting to {server}: {str(e)}"
    finally:
        # Always close sockets to release network descriptors
        s.close()

def parse_whois_field(patterns, text, is_multi=False):
    """
    Helper function using regular expressions to match fields in free-text records.
    
    PYTHON CONCEPT - Regex Matching:
    WHOIS responses are free-text structures, and keys vary between registrars.
    We pass lists of alternative patterns to find matching fields.
    """
    # If we are looking for multiple matches (like name servers or domain locks)
    if is_multi:
        results = []
        for pattern in patterns:
            # Find all matching tokens in text
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                clean_val = m.strip().strip('.')
                if clean_val and clean_val not in results:
                    results.append(clean_val)
        return results

    # If we are searching for a single record match (like dates or registrar)
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            # Clean and return the matching text capture group
            return match.group(1).strip()
            
    return None

def check_whois(url):
    """
    Performs active recursive WHOIS queries on Port 43 and parses registration fields.
    """
    
    # 1. Parse target domain hostname
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    
    # 2. Clean subdomain prefixes to isolate base domain
    cleaned_domain = clean_to_base_domain(hostname)
    
    # 3. Recursive WHOIS lookup
    # Step A: Query global IANA root database on Port 43
    iana_output = query_socket_whois("whois.iana.org", cleaned_domain)
    
    # Step B: Parse response to extract authoritative TLD registry referral server
    tld_server = None
    if iana_output and "socket error" not in iana_output.lower():
        for line in iana_output.splitlines():
            # IANA referral server labels typically start with 'whois:' or 'refer:'
            if line.strip().lower().startswith("whois:"):
                # Isolate domain server text after colon
                tld_server = line.split(":", 1)[1].strip()
                break
                
    # Step C: Query TLD registry server if referenced
    if tld_server:
        whois_raw_text = query_socket_whois(tld_server, cleaned_domain)
    else:
        whois_raw_text = iana_output

    # Check for query failures (e.g. timeout, connection reset, host offline)
    if not whois_raw_text or "socket error" in whois_raw_text.lower() or "connection error" in whois_raw_text.lower() or "timeout" in whois_raw_text.lower():
        # Fallback details structure on network connection errors.
        # This prevents UndefinedError crashes in Jinja templates by supplying defaults.
        return {
            "status": "completed",
            "score_impact": 0,
            "details": {
                "domain_name": cleaned_domain,
                "registrar": "Query Connection Failed",
                "creation_date": "N/A",
                "expiration_date": "N/A",
                "name_servers": ["Lookup Time Out / Refused"],
                "privacy_enabled": False,
                "status": whois_raw_text if whois_raw_text else "Connection refused on TCP Port 43"
            }
        }

    # 4. Extract registration parameters using robust regex patterns
    # Registrar search alternatives
    registrar_patterns = [
        r'Registrar:\s*(.*)',
        r'Sponsoring Registrar:\s*(.*)',
        r'registrar name:\s*(.*)'
    ]
    
    # Expiration date search alternatives
    expiry_patterns = [
        r'Registry Expiry Date:\s*(.*)',
        r'Expiration Date:\s*(.*)',
        r'Expiry Date:\s*(.*)',
        r'registry expiry date:\s*(.*)'
    ]
    
    # Creation date search alternatives
    creation_patterns = [
        r'Creation Date:\s*(.*)',
        r'Created On:\s*(.*)',
        r'creation date:\s*(.*)',
        r'Registration Date:\s*(.*)'
    ]
    
    # Nameserver list search alternatives
    ns_patterns = [
        r'Name Server:\s*(\S+)',
        r'nameserver:\s*(\S+)'
    ]
    
    # Registry Lock Status search alternatives
    status_patterns = [
        r'Domain Status:\s*(\S+)',
        r'status:\s*(\S+)'
    ]

    # Process parses
    registrar = parse_whois_field(registrar_patterns, whois_raw_text)
    expiry_raw = parse_whois_field(expiry_patterns, whois_raw_text)
    creation_raw = parse_whois_field(creation_patterns, whois_raw_text)
    name_servers = parse_whois_field(ns_patterns, whois_raw_text, is_multi=True)
    statuses = parse_whois_field(status_patterns, whois_raw_text, is_multi=True)

    # 5. Normalize dates to ISO formats (YYYY-MM-DD)
    # Exponent: '1997-09-15T04:00:00Z' -> splits on 'T' -> '1997-09-15'
    creation_date = creation_raw.split('T')[0].strip() if creation_raw else "Unknown"
    expiration_date = expiry_raw.split('T')[0].strip() if expiry_raw else "Unknown"

    # 6. Audit Privacy Shields
    # We scan the raw text database block for indicators of redacted ownership details (GDPR compliance)
    privacy_shield = False
    privacy_keywords = [
        "redacted for privacy", 
        "gdpr masked", 
        "privacy protection", 
        "whoisproxy", 
        "contact privacy",
        "withheld for privacy"
    ]
    for key in privacy_keywords:
        if key in whois_raw_text.lower():
            privacy_shield = True
            break

    # Structure statuses list formatting
    lock_status = ", ".join(statuses) if statuses else "Unknown"

    # Package output values
    return {
        "status": "completed",
        "score_impact": 0,  # Registry lookup acts as intelligence gathering, does not impact base grades
        "details": {
            "domain_name": cleaned_domain,
            "registrar": registrar if registrar else "Unknown Registrar",
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": name_servers if name_servers else ["None Found"],
            "privacy_enabled": privacy_shield,
            "status": lock_status
        }
    }
