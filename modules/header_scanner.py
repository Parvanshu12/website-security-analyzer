# modules/header_scanner.py
# -------------------------
# This module is responsible for scanning and auditing a target website's live HTTP response headers.
#
# NETWORKING CONCEPT - HTTP Response Headers:
# When a client sends an HTTP request, the web server responds with the requested content
# along with "Response Headers." These are key-value string metadata pairs (e.g., "Server: Nginx").
#
# CYBERSECURITY CONCEPT - Security Header Auditing:
# Certain headers instruct the browser to activate security sandboxing features.
# If these headers are missing or misconfigured, the client browser will run in a less-secure default state,
# exposing the website's visitors to client-side attacks.
# We will actively query the host and audit the presence and values of these key headers.
# -------------------------

import urllib.request
import urllib.error
import socket
import ssl

def scan_headers(url):
    """
    Actively requests the target URL and audits its HTTP security headers.
    
    PYTHON CONCEPT - urllib.request:
    This is Python's built-in module for fetching URLs. We use it to make standard HTTP requests
    without requiring third-party libraries (like 'requests'), keeping our footprint small.
    
    ARGUMENTS:
        url (str): The validated target URL (e.g., https://example.com)
        
    RETURNS:
        dict: Audited headers configuration results or a network failure dictionary.
    """
    
    # CYBER SECURITY CRITICAL - User-Agent Spoofing:
    # By default, Python's urllib sends a user-agent containing "Python-urllib/3.x".
    # Many modern Web Application Firewalls (WAFs) and CDNs (like Cloudflare) block requests with default
    # scripting headers to prevent scraping and automated DDoS attacks.
    # To bypass this filter, we spoof a standard, legitimate browser User-Agent.
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    )

    headers_obj = None
    connection_error = None

    try:
        # CYBER SECURITY CRITICAL - Outbound Request Timeout:
        # We enforce a strict timeout of 5.0 seconds. Without this limit, if a remote host is malicious
        # or down, our Flask thread will hang indefinitely waiting for a response.
        # This causes resource exhaustion and can easily crash our scanner application (Denial of Service).
        with urllib.request.urlopen(req, timeout=5.0) as response:
            # Info returns case-insensitive HTTPMessage headers dictionary
            headers_obj = response.info()
            
    # CYBERSECURITY RELEVANCE - Error Audits:
    # HTTPError is raised when the server responds with a failure code (e.g. 403 Forbidden, 401 Unauthorized, 500 Server Error).
    # Even if a server responds with an error, it STILL returns HTTP response headers!
    # Cyber defenders must configure security headers on error templates too, so we catch this exception
    # and audit whatever headers the server provided.
    except urllib.error.HTTPError as e:
        headers_obj = e.headers
        
    # URLError is raised for network-level failures (DNS resolution failure, connection refused, host down).
    except urllib.error.URLError as e:
        # Check if the error was a certificate verification failure
        if isinstance(e.reason, ssl.SSLError):
            connection_error = "SSL/TLS handshake failure. Target certificate is invalid or untrusted."
        else:
            connection_error = f"Unreachable host domain name or connection refused: {e.reason}"
            
    # Socket timeout handles cases where the host connection handshake is accepted but doesn't return data.
    except socket.timeout:
        connection_error = "Target host connection timed out (server did not respond in 5 seconds)."
        
    # General safety check to prevent unhandled database or system crashes
    except Exception as e:
        connection_error = f"Unexpected connection error occurred during network probe: {str(e)}"

    # If the network connection failed, we return a failure status structure
    if connection_error:
        return {
            "status": "failed",
            "error": connection_error
        }

    # --------------------------------------------------------------------------
    # Auditing Phase: Evaluate Target Headers
    # --------------------------------------------------------------------------
    # We query the HTTPMessage object using case-insensitive lookup get().
    hsts_val = headers_obj.get("Strict-Transport-Security")
    csp_val = headers_obj.get("Content-Security-Policy")
    xfo_val = headers_obj.get("X-Frame-Options")
    xcto_val = headers_obj.get("X-Content-Type-Options")
    ref_val = headers_obj.get("Referrer-Policy")

    # We build our results registry dictionary.
    # We audit not only if headers are present, but also if they conform to security specifications.
    results = {
        "Strict-Transport-Security": {
            "status": "Present" if hsts_val else "Missing",
            "value": hsts_val,
            "secure": True if hsts_val else False,
            "description": "Enforces HTTPS encryption, protecting against SSL stripping / protocol downgrade."
        },
        "Content-Security-Policy": {
            "status": "Present" if csp_val else "Missing",
            "value": csp_val,
            "secure": True if csp_val else False,
            "description": "Specifies trusted source domains for loaded assets. Crucial for mitigating Cross-Site Scripting (XSS)."
        },
        "X-Frame-Options": {
            "status": "Present" if xfo_val else "Missing",
            "value": xfo_val,
            # X-Frame-Options is secure if configured as 'DENY' or 'SAMEORIGIN'
            "secure": True if xfo_val and xfo_val.strip().upper() in ["DENY", "SAMEORIGIN"] else False,
            "description": "Controls iframe embedding permissions, blocking Clickjacking attacks."
        },
        "X-Content-Type-Options": {
            "status": "Present" if xcto_val else "Missing",
            "value": xcto_val,
            # Must be set strictly to 'nosniff' to neutralize MIME sniffing sniffing exploits
            "secure": True if xcto_val and "nosniff" in xcto_val.lower() else False,
            "description": "Prevents the browser from MIME-sniffing content types. Mitigates drive-by executable uploads."
        },
        "Referrer-Policy": {
            "status": "Present" if ref_val else "Missing",
            "value": ref_val,
            "secure": True if ref_val else False,
            "description": "Controls what referrer headers are sent when clicking links navigating to other sites."
        }
    }

    # Count how many points are deducted (missing/insecure headers subtract 5 points each in app.py)
    score_impact = sum(5 for header_data in results.values() if not header_data["secure"])

    return {
        "status": "completed",
        "score_impact": score_impact,
        "headers": results
    }
