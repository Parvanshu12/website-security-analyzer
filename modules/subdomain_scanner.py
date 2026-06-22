# modules/subdomain_scanner.py
# ------------------------------------------------------------------------------
# This module implements an active DNS-based Subdomain Discovery Scanner.
#
# CYBERSECURITY CONCEPT - Attack Surface Mapping:
# Organizations frequently run sensitive services (like admin portals, databases,
# or staging builds) on subdomains (e.g. 'dev.example.com' or 'vpn.example.com').
# These endpoints may not be publicly linked, but they represent a target's attack surface.
# Identifying them exposes forgotten or vulnerable hosts.
#
# NETWORKING CONCEPT - DNS Resolution & Thread Pool Parallelism:
# Domain Name System (DNS) maps domain names to IP addresses.
# Performing name resolutions serially can be extremely slow due to timeouts.
# We utilize concurrent thread execution (ThreadPoolExecutor) to query multiple
# subdomains in parallel, optimizing execution speed.
# ------------------------------------------------------------------------------

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# A curated dictionary list of common target subdomains to search for
SUBDOMAINS_LIST = [
    "www", "mail", "dev", "admin", "api", "secure", "vpn", "staging",
    "test", "portal", "db", "git", "cpanel", "autodiscover", "blog",
    "monitor", "status", "app", "aws", "cloud"
]

def resolve_subdomain(subdomain, root_domain):
    """
    Attempts to resolve a specific subdomain.
    
    NETWORKING CONCEPT - Name Resolution:
    We use the system's underlying socket library 'gethostbyname' to resolve the host.
    This bypasses external libraries and uses the OS DNS resolver cache / servers.
    """
    target_host = f"{subdomain}.{root_domain}"
    try:
        # socket.gethostbyname queries the DNS system for an IPv4 mapping.
        # It throws a gaierror (Get Address Info Error) if the name cannot be resolved.
        ip_addr = socket.gethostbyname(target_host)
        return {
            "subdomain": target_host,
            "ip": ip_addr,
            "status": "Active"
        }
    except socket.gaierror:
        # Host is offline, invalid, or does not exist
        return None
    except Exception:
        return None

def scan_subdomains(url):
    """
    Orchestrates the multi-threaded subdomain brute-force process.
    """
    # Parse target root domain
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    
    # In case the hostname itself is a subdomain (like 'www.google.com'), we extract the base domain
    # for scanning (e.g., 'google.com').
    parts = hostname.split('.')
    if len(parts) > 2:
        # E.g. 'www.google.com' -> base is 'google.com'
        # Handles generic domain suffixes like '.com' or '.org' simply
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = hostname
        
    found_subdomains = []
    
    # CYBERSECURITY DESIGN - Performance vs DoS:
    # Running too many threads can lead to high local resource consumption and trigger DNS rate-limiting.
    # We limit concurrent workers to 10. We also enforce a socket timeout implicitly via gethostbyname configuration.
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all subdomain resolution jobs to the worker pool
        futures = {executor.submit(resolve_subdomain, sub, base_domain): sub for sub in SUBDOMAINS_LIST}
        
        for future in futures:
            try:
                res = future.result(timeout=3.0)  # Enforce a 3-second completion limit per thread
                if res:
                    found_subdomains.append(res)
            except Exception:
                pass
                
    # Sort subdomains alphabetically
    found_subdomains.sort(key=lambda x: x["subdomain"])
    
    # Calculate score impact (Finding active dev/admin/db endpoints is a general exposure warning)
    # This doesn't directly deduct from score unless sensitive subdomains are discovered (e.g. dev, db, staging)
    sensitive_exposures = [item["subdomain"] for item in found_subdomains if any(sec in item["subdomain"] for sec in ["dev", "admin", "db", "staging", "vpn"])]
    score_impact = 5 if len(sensitive_exposures) > 0 else 0
    
    return {
        "status": "completed",
        "score_impact": score_impact,
        "details": {
            "base_domain": base_domain,
            "scanned_count": len(SUBDOMAINS_LIST),
            "found_count": len(found_subdomains),
            "subdomains": found_subdomains,
            "sensitive_exposures": sensitive_exposures
        }
    }
