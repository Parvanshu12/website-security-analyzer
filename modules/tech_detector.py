# modules/tech_detector.py
# ------------------------------------------------------------------------------
# This module implements active web fingerprinting and infrastructure banner auditing.
#
# CYBERSECURITY CONCEPT - Banner Grabbing:
# We query the target URL, retrieve HTTP response headers, session cookies,
# and page source code to identify servers (Nginx/Apache), backend languages (PHP/Python),
# or CMS frameworks (WordPress/Drupal) deployed on the target host.
#
# CYBERSECURITY CONCEPT - Information Disclosure:
# Exposing detailed software names and patch version numbers helps attackers target exploits.
# We audit if software version signatures are leaked in headers or template structures.
# ------------------------------------------------------------------------------

import urllib.request  # Python standard library for web requests
import urllib.error    # HTTP error catcher subclasses
import re              # Built-in regular expression parsing library
import socket          # Socket exceptions registry
from urllib.parse import urlparse  # Utility for parsing URL segments

def detect_tech(url):
    """
    Fingerprints target servers by auditing banners, cookie formats, and HTML code.
    
    PYTHON CONCEPT - urllib.request:
    Natively sends HTTP requests. We spoof browser headers and enforce timeouts.
    
    ARGUMENTS:
        url (str): Target web URL (e.g., https://example.com)
        
    RETURNS:
        dict: A dictionary checklist of detected technologies and info leaks.
    """
    
    # 1. Parse target domain hostname
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    
    # Initialize default technology database details
    web_server = "Hidden/Proxy"
    web_server_ver = "Protected"
    web_server_secure = True
    web_server_notes = "Web server headers are stripped or hidden. Good security profile."
    
    backend_lang = "Undetected"
    backend_lang_ver = "Protected"
    backend_lang_secure = True
    backend_lang_notes = "Language headers are hidden or suppressed."
    
    framework = "Custom / Non-CMS"
    framework_ver = "Hidden"
    framework_secure = True
    framework_notes = "No common CMS generator meta tags were detected in the source template."

    # Define User-Agent headers to bypass WAF bot block filters
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    )

    headers_obj = None
    html_content = ""

    # 2. Execute Web Request with Timeouts
    try:
        # Enforce strict 5.0 second connection timeout to prevent process exhaustion
        with urllib.request.urlopen(req, timeout=5.0) as response:
            # Info extracts case-insensitive headers metadata dictionary
            headers_obj = response.info()
            # Read response body and decode characters safely
            html_content = response.read().decode('utf-8', errors='ignore')
            
    except urllib.error.HTTPError as e:
        # HTTPError is raised for server errors (403, 500, etc.), but we can still grab headers!
        headers_obj = e.headers
    except (urllib.error.URLError, socket.timeout, Exception):
        # Fallback on connection failures to prevent Flask rendering crashes
        pass

    # Process audits if headers were retrieved
    if headers_obj:
        
        # 3. Audit HTTP Server Banners
        server_header = headers_obj.get("Server")
        if server_header:
            # Server header is exposed (e.g. 'nginx/1.24.0' or 'Apache')
            web_server = server_header.split('/')[0].strip()
            
            # CYBERSECURITY CONCEPT - Version Disclosures:
            # We use regular expressions to check if version digits (e.g. 1.24 or 2.4.41) are exposed.
            # If numbers exist, it is an insecure information disclosure.
            version_match = re.search(r'\/([0-9\.]+)', server_header)
            if version_match:
                web_server_ver = version_match.group(1)
                web_server_secure = False
                web_server_notes = f"VULNERABILITY: Web server version ({web_server_ver}) is exposed! Disable server tokens."
            else:
                web_server_ver = "Exposed (No Version)"
                web_server_secure = True
                web_server_notes = "Web server name is exposed, but exact patch version is securely hidden."

        # 4. Audit Backend Language (X-Powered-By header)
        powered_by = headers_obj.get("X-Powered-By")
        if powered_by:
            # Extract language (e.g. 'PHP/7.4.3' -> PHP)
            backend_lang = powered_by.split('/')[0].strip()
            version_match_lang = re.search(r'\/([0-9\.]+)', powered_by)
            if version_match_lang:
                backend_lang_ver = version_match_lang.group(1)
                backend_lang_secure = False
                backend_lang_notes = f"VULNERABILITY: Language engine version ({backend_lang_ver}) is exposed via X-Powered-By! Suppress expose_php."
            else:
                backend_lang_ver = "Exposed (No Version)"
                backend_lang_secure = True
                backend_lang_notes = "Language engine name is exposed, but version is hidden."

        # 5. Audit Session Cookies Signatures
        # We query all Set-Cookie response strings to identify default language cookie names.
        cookies = headers_obj.get_all("Set-Cookie")
        if cookies:
            for cookie in cookies:
                # PHP default session cookie signature
                if "PHPSESSID" in cookie:
                    backend_lang = "PHP (Cookie Signature)"
                    backend_lang_notes = "Determined PHP backend language via PHPSESSID cookie signature."
                # Java servlet default session cookie signature
                elif "JSESSIONID" in cookie:
                    backend_lang = "Java (Cookie Signature)"
                    backend_lang_notes = "Determined Java servlet engine backend via JSESSIONID cookie signature."
                # Microsoft ASP.NET default session cookie signature
                elif "ASPSESSIONID" in cookie or "ASP.NET_SessionId" in cookie:
                    backend_lang = "ASP.NET (Cookie Signature)"
                    backend_lang_notes = "Determined Microsoft ASP.NET backend via session cookie signatures."

    # 6. Audit HTML Generator Meta Tags (CMS Fingerprinting)
    if html_content:
        # Search HTML body for meta name="generator" content="..." structures using regular expressions.
        # Captures content value in group(1).
        generator_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', 
            html_content, 
            re.IGNORECASE
        )
        if generator_match:
            generator_val = generator_match.group(1).strip()
            # Match WordPress profiles (e.g. 'WordPress 6.4.2')
            if "wordpress" in generator_val.lower():
                framework = "WordPress CMS"
                version_match_fw = re.search(r'WordPress\s*([0-9\.]+)', generator_val, re.IGNORECASE)
                if version_match_fw:
                    framework_ver = version_match_fw.group(1)
                    framework_secure = False
                    framework_notes = f"VULNERABILITY: WordPress generator version ({framework_ver}) is leaked! Remove generator tags."
                else:
                    framework_ver = "Exposed (No Version)"
                    framework_secure = True
                    framework_notes = "WordPress CMS detected, but version is securely hidden."
            else:
                # General CMS generator values
                framework = generator_val.split()[0]
                framework_ver = "Exposed"
                framework_secure = True
                framework_notes = f"CMS framework exposed via generator tag: {generator_val}"

    # Calculate grading penalties (version exposures deduct 5 points each in app.py)
    deductions = 0
    if not web_server_secure:
        deductions += 5
    if not backend_lang_secure:
        deductions += 5
    if not framework_secure:
        deductions += 5

    # Package output values
    return {
        "status": "completed",
        "score_impact": deductions,
        "technologies": {
            "Web Server": {
                "name": web_server,
                "version": web_server_ver,
                "secure": web_server_secure,
                "notes": web_server_notes
            },
            "Programming Language": {
                "name": backend_lang,
                "version": backend_lang_ver,
                "secure": backend_lang_secure,
                "notes": backend_lang_notes
            },
            "Security Framework": {
                "name": framework,
                "version": framework_ver,
                "secure": framework_secure,
                "notes": framework_notes
            }
        }
    }
