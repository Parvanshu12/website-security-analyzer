# modules/verb_auditor.py
# ------------------------------------------------------------------------------
# This module implements an active HTTP Method / Verb Tampering Auditor.
#
# CYBERSECURITY CONCEPT - HTTP Verb Tampering & Cross-Site Tracking (XST):
# Web applications should only expose the HTTP methods necessary for their function (usually GET and POST).
# Exposing administrative or debugging verbs represents a vulnerability:
# - PUT/DELETE: May allow unauthorized creation, modification, or deletion of files.
# - TRACE: Echoes the client's request headers back, including HttpOnly session cookies.
#   Attackers exploit this via Cross-Site Scripting (XSS) to grab cookies via XST.
#
# NETWORKING CONCEPT - HTTP Requests & Error Handling:
# We build custom request structures using urllib.request.Request, set specific
# HTTP methods, and handle status response codes (200 OK, 405 Method Not Allowed).
# ------------------------------------------------------------------------------

import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

def audit_verbs(url):
    """
    Probes the target web host with various HTTP verbs and evaluates server policies.
    """
    # Normalize the target URL structure
    parsed_url = urlparse(url)
    # Ensure we scan http/https and have a scheme. Force HTTP if none exists.
    scheme = parsed_url.scheme if parsed_url.scheme in ["http", "https"] else "http"
    hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
    
    # Construct base URL for verb probes
    target_url = f"{scheme}://{hostname}/"
    
    verbs = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    results = {}
    score_impact = 0
    warning_list = []
    
    # Enforce standard browser headers to bypass simple bot filters
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Website Security Scanner",
        "Accept": "*/*"
    }
    
    for verb in verbs:
        try:
            # Create request object with the current verb override
            req = urllib.request.Request(target_url, headers=headers, method=verb)
            
            # Execute HTTP request. We set a low timeout of 3.0s to avoid hanging.
            with urllib.request.urlopen(req, timeout=3.0) as response:
                status_code = response.status
                reason = response.reason
                allowed = True
                
                # Check for specific risks
                if verb == "TRACE" and status_code == 200:
                    warning_list.append("TRACE Method Enabled (Vulnerable to Cross-Site Tracking / XST)")
                    score_impact += 10
                elif verb in ["PUT", "DELETE"] and status_code in [200, 201, 204]:
                    warning_list.append(f"Dangerous HTTP method {verb} returned successful code {status_code}")
                    score_impact += 15
                    
                results[verb] = {
                    "allowed": True,
                    "status_code": status_code,
                    "reason": reason
                }
                
        except HTTPError as e:
            # Server responded but returned an HTTP error code (e.g. 405 Method Not Allowed or 403 Forbidden)
            results[verb] = {
                "allowed": (e.code not in [403, 405, 501]),
                "status_code": e.code,
                "reason": e.reason
            }
            # Although the server returns an error, we check if it is technically "allowed"
            # (non-405, non-403 means it was handled or routed, which is still a potential exposure)
            if verb == "TRACE" and e.code not in [403, 405, 501]:
                # In some configurations, TRACE might return 500 or 400, but it's still enabled
                pass
                
        except (URLError, Exception) as e:
            # Connection failed or timed out
            results[verb] = {
                "allowed": False,
                "status_code": None,
                "reason": f"Connection Failed: {str(e)}"
            }
            
    return {
        "status": "completed",
        "score_impact": score_impact,
        "details": {
            "target_url": target_url,
            "verb_matrix": results,
            "warnings": warning_list,
            "trace_enabled": "TRACE" in results and results["TRACE"]["allowed"] and results["TRACE"]["status_code"] == 200
        }
    }
