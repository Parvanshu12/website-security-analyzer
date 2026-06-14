# modules/dns_checker.py
# ------------------------------------------------------------------------------
# This module implements active querying of Domain Name System (DNS) records.
#
# CYBERSECURITY CONCEPT - Passive & Active Reconnaissance:
# DNS lookup queries authoritative name servers for security-related policy records (SPF, DMARC).
# Since Python's built-in socket API only handles host-to-IP resolutions (A records),
# we wrap the host's native 'nslookup' system command securely to fetch MX and TXT records.
#
# CYBERSECURITY CRITICAL - Parameterized Execution (Shell-less Execution):
# Executing system commands with user parameters can expose apps to Command Injection.
# We bypass the OS shell (shell=False) and pass commands as a discrete list of string tokens,
# preventing command chaining characters (like ';', '&', '|') from executing.
# ------------------------------------------------------------------------------

import socket      # Built-in low-level socket networking library
import subprocess  # Built-in library to spawn OS system command processes
import re          # Python standard regular expression parsing engine
import platform    # Utility to identify host operating system details
from urllib.parse import urlparse  # Segment extractor for web URLs

def query_nslookup(record_type, hostname):
    """
    Executes a shell-less nslookup command targeting a specific record type.
    
    PYTHON CONCEPT - subprocess.run():
    Spawns a child process and reads its stdout/stderr streams cleanly.
    We enforce a 5.0 second execution timeout to prevent zombie process hangs.
    """
    try:
        # Command token parameters sequence.
        # Enforcing shell=False treats the entire hostname as a literal argument,
        # completely mitigating OS command injection.
        cmd = ["nslookup", f"-type={record_type}", hostname]
        
        # Spawn execution process safely
        res = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            timeout=5.0
        )
        # Return standard output logs
        return res.stdout
    except Exception as e:
        # Return empty log block on failure
        return ""

def parse_txt_records(output):
    """
    Extracts text strings from raw nslookup command response outputs.
    
    PYTHON CONCEPT - Regular Expressions (re):
    TXT records in nslookup outputs are usually wrapped in double quotes.
    We use re.findall to extract all matches of quoted strings.
    """
    # Pattern explanation: matching any sequence inside quotation marks
    matches = re.findall(r'"([^"]*)"', output)
    
    # Process matches
    records = []
    for m in matches:
        clean_record = m.strip()
        if clean_record:
            records.append(clean_record)
            
    # Fallback parser if no quotes are matched (different OS formatting)
    if not records:
        for line in output.splitlines():
            # If the output line references a text description assignment
            if "text =" in line.lower() or "txt =" in line.lower():
                parts = line.split("=")
                if len(parts) > 1:
                    # Clean trailing double-quote indicators
                    records.append(parts[1].strip().strip('"'))
                    
    return records

def check_dns(url):
    """
    Performs active DNS security evaluations targeting the target domain.
    Queries IPv4 IP maps, MX mail handlers, SPF validations, and DMARC rules.
    """
    
    # 1. Parse target domain hostname
    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    
    # Define registry structures
    a_records = []
    mx_records = []
    txt_records = []
    dmarc_txt = []
    
    # Default DMARC status parameters
    dmarc_status = "Missing"
    dmarc_policy = None
    dmarc_secure = False
    dmarc_desc = "Domain lacks email authentication policy records (DMARC), exposing it to phishing spoofing."
    
    # 2. Fetch A Records (IPv4) natively
    try:
        # getaddrinfo resolves host addresses to IP tuples
        addr_info = socket.getaddrinfo(hostname, None)
        ips = set()
        for res in addr_info:
            # Extract IPv4 address string from tuple
            ips.add(res[4][0])
        a_records = list(ips)
    except Exception:
        a_records = ["Resolution failed"]

    # 3. Query MX Records (Mail Gateways)
    # Why this approach:
    # Outputs differ between systems (Windows 'MX preference = 10, mail exchanger = server' 
    # has two equal signs, while Unix/standard outputs have one). 
    # We check parts count to extract preference and host domain safely.
    mx_output = query_nslookup("MX", hostname)
    for line in mx_output.splitlines():
        if "mail exchanger" in line.lower():
            parts = line.split("=")
            if len(parts) > 1:
                if len(parts) == 3:  # Windows format with two equal signs
                    preference = parts[1].split(",")[0].strip()  # Extracts priority number (e.g. 10)
                    mail_server = parts[2].strip().strip('.')    # Extracts mail server domain (e.g. smtp.google.com)
                    mx_records.append(f"{preference} {mail_server}")
                else:  # Standard format with one equal sign (Unix / typical format)
                    mx_records.append(parts[1].strip().strip('.'))

    # 4. Query TXT Records (SPF and verification tokens)
    txt_output = query_nslookup("TXT", hostname)
    txt_records = parse_txt_records(txt_output)

    # 5. Query DMARC Records (Anti-Spoofing checks)
    # DMARC records must sit strictly at the subdomain: _dmarc.yourdomain.com
    dmarc_host = f"_dmarc.{hostname}"
    dmarc_output = query_nslookup("TXT", dmarc_host)
    dmarc_txt = parse_txt_records(dmarc_output)

    # 6. Audit DMARC configuration policy compliance
    for record in dmarc_txt:
        # DMARC policy definitions must start with the version statement (V=DMARC1)
        if record.strip().upper().startswith("V=DMARC1"):
            dmarc_status = "Present"
            dmarc_policy = record
            
            # Use Regex boundary boundaries to isolate policy parameters (p=reject/quarantine/none)
            match = re.search(r'\bp=([^;]+)', record, re.IGNORECASE)
            if match:
                policy_val = match.group(1).strip().lower()
                # Check for active enforcement states
                if policy_val in ["reject", "quarantine"]:
                    dmarc_secure = True
                    dmarc_desc = f"DMARC alignment policy is set to secure enforcement '{policy_val}'."
                else:
                    dmarc_secure = False
                    dmarc_desc = f"DMARC record exists but policy is set to unsafe monitoring state '{policy_val}'."
            break

    # Determine compliance score impact
    score_impact = 0
    if not dmarc_secure:
        # Subtract 10 points in app.py for lacking anti-spoofing enforcement
        score_impact = 10

    # Package output values
    return {
        "status": "completed",
        "score_impact": score_impact,
        "records": {
            "A": a_records if a_records else ["None Found"],
            "MX": mx_records if mx_records else ["None Found"],
            "TXT": txt_records if txt_records else ["None Found"],
            "DMARC": {
                "status": dmarc_status,
                "policy": dmarc_policy,
                "secure": dmarc_secure,
                "description": dmarc_desc
            }
        }
    }
