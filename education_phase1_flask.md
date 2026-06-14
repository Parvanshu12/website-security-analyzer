# Study Guide: Flask Framework & Web Architecture (Phase 1)

This study guide explains the architectural and coding principles implemented in **Phase 1** of the Website Security Analyzer.

---

## 1. The Client-Server Model & Web Protocols

All web communications operate on the **Client-Server Architecture**.
* **Client (Front-end):** The user's browser (Chrome, Safari, Firefox). It requests resources and renders HTML/CSS/JS.
* **Server (Back-end):** The hosting machine running our Python code. It listens on a socket port, processes inputs, and sends back formatted data responses.

```
+------------------+                   HTTP Request (GET /)                 +------------------+
|                  | -----------------------------------------------------> |                  |
|  Client Browser  |                                                        |   Python Flask   |
|                  | <----------------------------------------------------- |      Server      |
+------------------+                   HTTP Response (HTML)                 +------------------+
```

### HTTP (Hypertext Transfer Protocol)
HTTP is an application-layer protocol for transmitting hypermedia documents. It is **stateless**, meaning each request is executed independently without the server remembering past requests (solved later with cookies/sessions).

---

## 2. HTTP Request Methods: GET vs. POST

HTTP defines actions (methods) to indicate the desired operations:
* **`GET`:** Used to retrieve data. Typing a URL in a browser makes a `GET` request. 
  * *Security Note:* `GET` parameters are appended to the URL (e.g. `/?search=test`). They are logged in browser history, proxy servers, and server access logs. Never use `GET` to submit sensitive data (like passwords).
* **`POST`:** Used to send data to the server to modify state or trigger actions. Form inputs are packed inside the **Request Body**, leaving the URL clean.
  * *Use Case:* In our security scanner, the URL to scan is submitted via `POST` because it triggers socket network scans (a processing action).

---

## 3. Web Framework Architectures & Flask

### A. What is Flask?
Flask is a **micro-framework** written in Python. It does not enforce a specific database, form validator, or directory structure. 
* **WSGI (Web Server Gateway Interface):** A standard defining how Python web apps communicate with web servers (like Nginx or Apache). Flask wraps a WSGI utility library called *Werkzeug*.
* **Routing:** Mapping URLs to Python functions using Python **decorators** (annotations starting with `@`).
  * *Example:* `@app.route("/")` tells Flask to run the decorated function whenever a client requests the root index URL.

### B. Directory Convention
Flask expects a strict workspace structure:
* `/templates`: Houses HTML files. Flask uses the **Jinja2** template engine to parse these files.
* `/static`: Houses assets served directly without processing (CSS stylesheets, JavaScript files, images).

---

## 4. Jinja2 Templating Engine

Jinja2 is a templating language for Python that dynamically generates HTML.
* **Variables (`{{ value }}`):** Replaced by Flask with active Python variables passed during rendering:
  `render_template("index.html", url_input="google.com")`
* **Statement Blocks (`{% ... %}`):** Used for loops (`{% for %}`) and conditionals (`{% if %}`).
* **Context Escaping (XSS Mitigation):** Jinja automatically converts tags (like `<script>` to `&lt;script&gt;`) before printing. This is a critical built-in security control that blocks attackers from running unauthorized client-side scripts.

---

## 5. Input Validation and URL Sanitization

### A. The SSRF Attack Vector
**Server-Side Request Forgery (SSRF)** occurs when an attacker forces a server-side application to make HTTP requests to an arbitrary domain.
* If our scanner allows inputs like `http://127.0.0.1:8080/admin` or `http://192.168.1.1/router`, our server will actively probe internal network devices or cloud metadata points (`http://169.254.169.254/`).
* **Defense:** We validate domains using regular expressions and block loopback subnets.

### B. Python `urllib.parse`
We use `urlparse(url)` to split inputs:
* `scheme`: Enforces `http` or `https` (blocks `file://` or `ftp://` traversal).
* `netloc`: Extracts the host domain name, allowing us to perform regex domain checks.
