# modules/threat_intelligence.py
# ------------------------------------------------------------------------------
# This module implements a Threat Intelligence Crawler targeting robots.txt and security.txt.
#
# CYBERSECURITY CONCEPT - Directory Leakage & Responsible Disclosure:
# - robots.txt: Used to tell search engines which paths they should not index.
#   However, attackers read robots.txt to discover sensitive directory structures
#   (e.g., '/backup/', '/admin/', '/private/') that the owner wants hidden.
# - security.txt: A standard (.well-known/security.txt) defining how security researchers
#   can report vulnerabilities. Its absence indicates a lack of clear disclosure channels.
#
# NETWORKING CONCEPT - File Fetching & Line Parsing:
# We resolve URLs dynamically, issue HTTP requests using urllib.request,
# and parse plaintext response lines using regex/string operations.
# ------------------------------------------------------------------------------

import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urljoin
import re

# Sensitive folder names commonly found in robots.txt that represent a security concern
SENSITIVE_DIRECTIVES_REGEX = re.compile(
    r'(admin|backup|config|db|database|private|secret|vpn|login|wp-admin|sql|git|user|api)', 
    re.IGNORECASE
)

def fetch_and_parse_file(base_url, path):
    """
    Fetches a text asset and parses its lines.
    """
    target_url = urljoin(base_url, path)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Website Security Scanner"
    }
    
    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, timeout=3.0) as response:
            if response.status == 200:
                raw_content = response.read().decode('utf-8', errors='ignore')
                lines = [line.strip() for line in raw_content.splitlines() if line.strip()]
                return {
                    "found": True,
                    "url": target_url,
                    "raw": raw_content[:2000],  # Truncate raw dump to prevent database bloating
                    "lines": lines
                }
    except Exception:
        pass
        
    return {"found": False, "url": target_url, "raw": "", "lines": []}

def scan_threat_intel(url):
    """
    Crawls and analyzes robots.txt and security.txt.
    """
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme if parsed_url.scheme in ["http", "https"] else "http"
    hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
    
    base_url = f"{scheme}://{hostname}"
    
    # 1. Fetch robots.txt
    robots_data = fetch_and_parse_file(base_url, "/robots.txt")
    # 2. Fetch security.txt (RFC 9116 specifies .well-known/security.txt)
    security_data = fetch_and_parse_file(base_url, "/.well-known/security.txt")
    # Fallback to root level security.txt if .well-known is missing
    if not security_data["found"]:
        security_data = fetch_and_parse_file(base_url, "/security.txt")
        
    warnings = []
    disallowed_paths = []
    contacts = []
    sensitive_leaks = []
    
    # Analyze robots.txt directives
    if robots_data["found"]:
        for line in robots_data["lines"]:
            # Parse 'Disallow: /path'
            match = re.match(r'^\s*Disallow:\s*(\S+)', line, re.IGNORECASE)
            if match:
                path = match.group(1)
                disallowed_paths.append(path)
                # Check if the disallowed directory leaks sensitive terms
                if SENSITIVE_DIRECTIVES_REGEX.search(path):
                    sensitive_leaks.append(path)
                    
        if sensitive_leaks:
            warnings.append(f"robots.txt exposes sensitive paths to crawlers: {', '.join(sensitive_leaks)}")
    else:
        # Note: missing robots.txt is not a vulnerability, but worth reporting
        pass
        
    # Analyze security.txt directives
    if security_data["found"]:
        for line in security_data["lines"]:
            match = re.match(r'^\s*Contact:\s*(\S+)', line, re.IGNORECASE)
            if match:
                contacts.append(match.group(1))
    else:
        warnings.append("security.txt not found (Domain lacks a standardized security contact channel)")
        
    # Calculate score impact:
    # 5 points deduction if sensitive paths are leaked in robots.txt
    # 2 points deduction if security.txt is missing (Standard best-practice audit)
    score_impact = 0
    if sensitive_leaks:
        score_impact += 5
    if not security_data["found"]:
        score_impact += 2
        
    return {
        "status": "completed",
        "score_impact": score_impact,
        "details": {
            "robots": {
                "found": robots_data["found"],
                "url": robots_data["url"],
                "disallowed_count": len(disallowed_paths),
                "disallowed_paths": disallowed_paths[:15],  # Capped limit
                "sensitive_leaks": sensitive_leaks
            },
            "security": {
                "found": security_data["found"],
                "url": security_data["url"],
                "contacts": contacts
            },
            "warnings": warnings
        }
    }
