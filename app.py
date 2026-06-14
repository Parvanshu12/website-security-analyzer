# ==============================================================================
# app.py - Main Entry Point for Website Security Analyzer
# ==============================================================================
# Welcome to the backbone of your Python web application! This file is the primary server
# code that orchestrates the data flow, HTTP requests, input validation, database integration,
# and rendering logic.
#
# FLASK CONCEPT - Routing and Server Execution:
# Flask is a micro-framework that maps URLs (like "/") to specific Python functions.
# These decorated functions are called "view functions" or "controllers."
#
# CYBERSECURITY CONCEPT - Input Validation & Defensive Coding:
# Web scanners are powerful tools, but if left open to arbitrary input, they can be weaponized.
# We address this with strict URL normalization and validation using 'urllib.parse'.
#
# CYBERSECURITY CONCEPT - SQL Injection (SQLi) Prevention:
# Databases in web applications are primary targets for SQLi attacks. We prevent this by:
# 1. Parameterized Queries: We never concatenate strings in SQL. Instead, we use placeholders (?)
#    so the database engine treats input strictly as literal values.
# 2. Strict Input Sanitization: Query parameters like ID fields are explicitly cast to integers
#    (e.g., int(history_id)), neutralizing any injected characters (like quotes or statements).
# ==============================================================================

# PYTHON CONCEPT - Imports:
# We import the required modules. Built-in modules are imported first,
# followed by external dependencies, and finally our custom modules.
import re
import os
import time
import sqlite3
import json
import contextlib  # Helps manage connection closing context managers
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for

# Importing our custom security analyzer modules from the 'modules' directory.
from modules.header_scanner import scan_headers
from modules.ssl_checker import check_ssl
from modules.dns_checker import check_dns
from modules.whois_checker import check_whois
from modules.port_scanner import scan_ports
from modules.tech_detector import detect_tech

# FLASK CONCEPT - Application Instance:
# We instantiate the Flask class. The '__name__' variable is a special built-in Python variable
# that evaluates to the name of the current module. Flask uses it to locate our static files
# (CSS/JS) and templates (HTML).
app = Flask(__name__)

# FLASK CONCEPT - Application Secret Key:
# Flask uses a secret key to cryptographically sign session cookies and securely handle user messages.
app.secret_key = "cybersecurity_academy_secret_key_change_me_in_production"

# ==============================================================================
# Database Configuration & Paths (Hosting-Ready)
# ==============================================================================
# HOSTING CONCEPT - Portable Path Resolution:
# Avoid hardcoding local absolute paths (like 'C:\Users\...').
# We dynamically locate the app directory and build database paths relative to it.
# This ensures the database initializes correctly on both local Windows machines and Linux cloud servers.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "scan_history.db")


def init_db():
    """
    Initializes the SQLite database and creates the scans table and search indexes.
    
    WHY THIS APPROACH:
    Running this function on app startup guarantees that the application self-configures
    and creates its database structure immediately upon deployment, removing manual configuration.
    """
    # Ensure the database directory exists
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)

    # Connect to SQLite file with a timeout parameter.
    # The timeout (10 seconds) instructs SQLite to wait for locked write operations to complete
    # instead of crashing immediately under concurrent cloud requests.
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        cursor = conn.cursor()
        
        # SQL TABLE SCHEMA:
        # We store general metadata for sorting/filtering (url, grade, score, scan_time, scan_date)
        # alongside a complete serialized JSON string representation of the detailed scan results.
        # This keeps the database simple and highly adaptable for changing modules.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                grade TEXT NOT NULL,
                score INTEGER NOT NULL,
                scan_time REAL NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                results_json TEXT NOT NULL
            )
        """)
        
        # DATABASE OPTIMIZATION - Indexing:
        # We create a database index on the 'scan_date' column. When queries sort or filter by dates
        # (e.g. ORDER BY scan_date DESC LIMIT 10), an index avoids full-table scans, keeping lookups
        # incredibly fast as the database size grows over time.
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_date 
            ON scans (scan_date DESC)
        """)
        
        conn.commit()
    finally:
        conn.close()


def get_db_connection():
    """
    Establishes a connection to the SQLite database.

    WHY THIS APPROACH:
    We open a connection on-demand per request and close it when finished.
    This prevents memory leak errors and handles database access across multiple HTTP requests safely.

    RETURNS:
        sqlite3.Connection: Database connection object configured to access columns by names.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    
    # Configure rows to behave like Python dictionaries.
    # This allows us to access database columns by name (e.g. row['grade']) instead of index (e.g. row[3]).
    conn.row_factory = sqlite3.Row
    return conn


def prune_database(conn):
    """
    Checks the scan ledger count and prunes the database to keep only the 50 most recent records.

    WHY THIS APPROACH:
    In a hosted production setting (like free cloud databases or small local VMs),
    unbounded database growth will eventually fill up the server's storage quota.
    Pruning the oldest items keeps our memory footprint stable and safe.
    
    ARGUMENTS:
        conn (sqlite3.Connection): An active database connection object inside a transaction.
    """
    try:
        cursor = conn.cursor()
        # Query the ID of the 51st newest record (offset 50).
        # We sort by scan_date DESC and id DESC to ensure a deterministic order
        # even if multiple scans share the exact same timestamp.
        cursor.execute("""
            SELECT id FROM scans 
            ORDER BY scan_date DESC, id DESC 
            LIMIT 1 OFFSET 50
        """)
        row = cursor.fetchone()
        
        if row:
            boundary_id = row['id']
            # Delete any record older than or equal to the 50th record ID
            cursor.execute("""
                DELETE FROM scans 
                WHERE id <= ?
            """, (boundary_id,))
            conn.commit()
    except Exception as e:
        # We print database pruning warnings to the console but do not crash the request flow,
        # ensuring minor maintenance issues do not disrupt the user's scanning service.
        print(f"[DATABASE MAINTENANCE] Warning: Auto-pruning failed: {str(e)}")


# Initialize the database immediately upon module execution
init_db()


# ==============================================================================
# Helper Function: URL Validation and Normalization
# ==============================================================================
def validate_and_normalize_url(url_input):
    """
    Validates the structure of a URL input and normalizes it.
    If a user inputs 'google.com', we normalize it to 'https://google.com'.
    If the input is malicious or malformed, we reject it.

    CYBERSECURITY CRITICAL:
    This prevents SSRF and standard input injection by ensuring the string strictly conforms
    to a valid domain name and standard web protocols (HTTP/HTTPS) and does not refer
    to local or loopback addresses (localhost, 127.0.0.1, 0.0.0.0, etc.).
    """
    # Remove leading/trailing whitespaces
    url = url_input.strip()

    if not url:
        return None, "URL input cannot be empty."

    # If the user did not specify a protocol scheme (e.g. they typed 'example.com'),
    # we default to 'https://' because modern web communication relies on SSL/TLS encryption.
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    try:
        # urllib.parse.urlparse splits a URL string into components: scheme, netloc, path, etc.
        parsed = urlparse(url)
        
        # Extract the netloc (network location / domain name, e.g. 'google.com' or 'www.google.com')
        netloc = parsed.netloc

        if not netloc:
            return None, "Could not extract a valid host domain name from input."

        # Let's enforce that the scheme must be either HTTP or HTTPS.
        # This blocks attempts to load local files via 'file:///' or query database connections.
        if parsed.scheme not in ["http", "https"]:
            return None, "Only HTTP and HTTPS protocols are allowed."

        # SSRF PREVENTATIVE CHECK:
        # We block requests to local networks (localhost, 127.x.x.x, 192.168.x.x, 10.x.x.x, 172.16.x.x-172.31.x.x)
        # to ensure the scanner cannot be used to probe the host server's local environment.
        local_host_patterns = [
            r'^localhost$',
            r'^127\.\d+\.\d+\.\d+$',
            r'^10\.\d+\.\d+\.\d+$',
            r'^192\.168\.\d+\.\d+$',
            r'^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$',
            r'^0\.0\.0\.0$'
        ]
        
        # We strip out optional port numbers (e.g. 'localhost:5000' -> 'localhost') for validation checks.
        host_only = netloc.split(':')[0]
        
        for pattern in local_host_patterns:
            if re.match(pattern, host_only, re.IGNORECASE):
                return None, "Scanning internal local network addresses is blocked for security reasons (SSRF Protection)."

        # Basic domain format validation using a Regular Expression (Regex).
        # A valid domain must contain alphanumeric characters, hyphens, and a valid TLD (Top Level Domain, e.g. .com, .org, .edu).
        domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_regex, host_only, re.IGNORECASE):
            return None, "Invalid domain structure. Please enter a valid web domain (e.g. google.com)."

        # Return the normalized URL and None (no error)
        return url, None

    except Exception as e:
        return None, f"An error occurred during URL parsing: {str(e)}"


# ==============================================================================
# Helper Function: Cyber Security Grading Algorithm
# ==============================================================================
def calculate_security_grade(header_res, ssl_res, dns_res, tech_res):
    """
    Computes an aggregated numerical score (0-100) and letter grade (A-F) based
    on security scanner findings.
    """
    score = 100  # Start with a perfect score and deduct points for vulnerabilities found.

    # 1. Headers Check Deductions (Missing CSP or Referrer-Policy are security risks)
    for header, data in header_res.get("headers", {}).items():
        if not data.get("secure"):
            score -= 5

    # 2. SSL Cert Check Deductions
    ssl_details = ssl_res.get("details", {})
    if not ssl_details.get("enabled"):
        score -= 30  # No SSL is a massive security failure.
    elif ssl_details.get("expired"):
        score -= 20  # Expired certificates generate browser warnings.
    elif ssl_details.get("days_remaining", 0) < 30:
        score -= 5   # Warning state if it is expiring soon.

    # 3. DNS Security Checklist Deductions
    dns_records = dns_res.get("records", {})
    dmarc = dns_records.get("DMARC", {})
    if dmarc.get("status") == "Missing":
        score -= 10  # Lacking email spoofing protection.

    # 4. Tech Exposed Check Deductions
    tech_list = tech_res.get("technologies", {})
    for tech, data in tech_list.items():
        if not data.get("secure") and "exposed" in data.get("notes", "").lower():
            score -= 5  # minor warning for software banner disclosure.

    # Keep the score within bounds [0, 100]
    score = max(0, min(score, 100))

    # Convert the numerical score to a standard letter grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


# ==============================================================================
# Primary Route: The Controller for Website Scanning & History
# ==============================================================================
@app.route("/", methods=["GET", "POST"])
def home():
    """
    Serves as the primary controller for the security scanner.
    Handles rendering the static form, scanning URLs, writing data to SQLite,
    and retrieving historical scan entries.
    """
    error_message = None
    results = None

    # PYTHON CONCEPT - contextlib.closing():
    # Wrap database connections in contextlib.closing() to ensure that even if
    # database transactions or template rendering crash, the socket handlers
    # are strictly closed, avoiding database locking errors.
    with contextlib.closing(get_db_connection()) as conn:
        
        # --------------------------------------------------------------------------
        # GET REQUEST: Fetch Recent History & View Past Reports
        # --------------------------------------------------------------------------
        if request.method == "GET":
            # Check if the user is requesting to view a specific past report
            history_id = request.args.get("history_id")
            
            if history_id:
                try:
                    # CYBERSECURITY CRITICAL - Type Casting:
                    # We cast the query parameter to an integer. If the user tries to inject malicious
                    # strings (e.g. "1 OR 1=1"), int() throws a ValueError, neutralizing SQLi.
                    history_id = int(history_id)
                    
                    # Fetch the record safely using a parameterized SQL query
                    row = conn.execute(
                        "SELECT * FROM scans WHERE id = ?", 
                        (history_id,)
                    ).fetchone()

                    if row:
                        # Deserialize the stringified JSON findings back into a Python dict
                        results = json.loads(row["results_json"])
                        # Attach SQL meta parameters so the HTML knows which row is selected
                        results["id"] = row["id"]
                        results["scan_date"] = row["scan_date"]
                    else:
                        error_message = "Requested security report ID was not found in database records."
                except ValueError:
                    error_message = "Invalid report ID parameter entered (SQL Injection attempt rejected)."

        # --------------------------------------------------------------------------
        # POST REQUEST: Execute New Scan & Write to DB
        # --------------------------------------------------------------------------
        elif request.method == "POST":
            # Extract the input URL from the POST form request body
            input_url = request.form.get("url")

            # Perform our sanitization routine
            validated_url, error = validate_and_normalize_url(input_url)

            if error:
                error_message = error
            else:
                scanned_url = validated_url
                
                # Measure scan execution latency
                start_time = time.time()

                # Execute active network scanners.
                # In Phase 3, this is a real-world audit targeting the website's headers.
                headers_results = scan_headers(scanned_url)

                # CYBERSECURITY CRITICAL - Error Audits & Connection Check:
                # If active header retrieval fails (e.g., DNS resolution fails or socket timeouts),
                # we abort the scan sequence immediately and pass the network failure logs back to the user interface.
                if headers_results.get("status") == "failed":
                    error_message = headers_results.get("error")
                else:
                    # Run other mock modules (SSL, DNS, Ports, Tech stack)
                    ssl_results = check_ssl(scanned_url)
                    dns_results = check_dns(scanned_url)
                    whois_results = check_whois(scanned_url)
                    ports_results = scan_ports(scanned_url)
                    tech_results = detect_tech(scanned_url)

                    scan_duration = round(time.time() - start_time, 2)

                    # Compute aggregated compliance grade
                    score, grade = calculate_security_grade(
                        headers_results, 
                        ssl_results, 
                        dns_results, 
                        tech_results
                    )

                    # Package findings together
                    results_payload = {
                        "url": scanned_url,
                        "domain": urlparse(scanned_url).netloc,
                        "grade": grade,
                        "score": score,
                        "scan_time": scan_duration,
                        "headers": headers_results,
                        "ssl": ssl_results,
                        "dns": dns_results,
                        "whois": whois_results,
                        "ports": ports_results,
                        "tech": tech_results
                    }

                    results_json = json.dumps(results_payload)

                    try:
                        cursor = conn.cursor()
                        cursor.execute(
                            """
                            INSERT INTO scans (url, domain, grade, score, scan_time, results_json)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (scanned_url, results_payload["domain"], grade, score, scan_duration, results_json)
                        )
                        conn.commit()
                        new_id = cursor.lastrowid
                        
                        # Trigger automated database maintenance to cap table storage size at 50 items
                        prune_database(conn)

                        # WEB ENGINEERING BEST PRACTICE - Post/Redirect/Get (PRG) Pattern:
                        # Redirect to GET endpoint to prevent double scan execution on reload
                        return redirect(url_for("home", history_id=new_id))

                    except Exception as e:
                        error_message = f"Database write failure occurred: {str(e)}"

        # Fetch the 10 most recent scans for the history ledger table
        # Using index (idx_scan_date) guarantees this runs in logarithmic O(log N) complexity instead of O(N) linear time.
        recent_scans = conn.execute(
            "SELECT id, url, domain, grade, score, scan_date FROM scans ORDER BY scan_date DESC LIMIT 10"
        ).fetchall()

    # Render template injecting results, error alerts, input text, and recent scans history list
    return render_template(
        "index.html",
        results=results,
        error_message=error_message,
        url_input=request.form.get("url", ""),
        recent_scans=recent_scans
    )


# ==============================================================================
# Development Server Startup
# ==============================================================================
if __name__ == "__main__":
    # HOSTING READINESS:
    # Online hosting providers (like Render or Heroku) dynamically assign a PORT environment variable.
    # We query this using os.environ, falling back to 5000 for local development.
    # We bind host to "0.0.0.0" so the server accepts traffic routed from outside the container.
    port = int(os.environ.get("PORT", 5000))
    is_prod = "PORT" in os.environ
    app.run(host="0.0.0.0", port=port, debug=not is_prod)
