# Study Guide: Database Design & SQL Injection Prevention (Phase 2)

This study guide explains the database engineering and defensive query design principles implemented in **Phase 2** of the Website Security Analyzer.

---

## 1. Databases in Web Applications: SQLite

### A. What is SQLite?
SQLite is a database engine implemented as a serverless, self-contained library.
* **Serverless:** Unlike MySQL, PostgreSQL, or Oracle, which run as independent background service processes, SQLite reads and writes directly to a single file on the host disk (`database/scan_history.db`).
* **Use Cases:** Perfect for local desktop software, mobile applications, edge deployments, and development environments.
* **Concurrencies:** Since it relies on a single file, write operations lock the file. To handle parallel web request traffic, we set a `timeout=10.0` connection parameter to wait for lock releases.

---

## 2. Connection Lifecycle & Context Managers

### A. Threading Constraints
In Python, database connection objects cannot be shared across multiple web request threads simultaneously.
* **Bad Practice:** Opening a single database connection when the app starts and leaving it open globally. This results in file access conflicts and application crashes.
* **Best Practice:** Open a connection on-demand when an HTTP request is received, execute queries, and close the connection immediately when finished.

### B. Python Context Managers & `contextlib.closing`
In Python, the `with` statement manages setup and cleanup logic:
```python
with contextlib.closing(get_db_connection()) as conn:
    # SQL operations here
```
* **Auto-Teardown:** `contextlib.closing` wraps the connection. When the code exits the `with` block (even if an error occurs), it automatically invokes `conn.close()`. This prevents memory leaks and lock hang-ups.

---

## 3. SQL Injection (SQLi) - The Vulnerability

SQL Injection occurs when user-supplied input is concatenated directly into an SQL statement string instead of processed as a variable. This allows attackers to manipulate the database query's logic.

```
                  Unsafe Query Concatenation:
                  SELECT * FROM scans WHERE id = ' + user_input + '
                                       |
                                       v
                  If user_input is:  1' OR '1'='1
                                       |
                                       v
                  Manipulated Query:
                  SELECT * FROM scans WHERE id = '1' OR '1'='1'
```
Because `'1'='1'` is always true, the database returns all records, bypassing authentication checks or exposure limitations. Attackers can also append command separators to delete tables (`1'; DROP TABLE scans; --`).

---

## 4. Parameterized Queries (Prepared Statements)

We mitigate SQL Injection using **Parameterized Queries** (also called prepared statements):
```python
conn.execute("SELECT * FROM scans WHERE id = ?", (history_id,))
```
* **Placeholders (`?`):** Instead of executing a single raw string, the query structure is pre-compiled by the database engine.
* **Separation of Code & Data:** The input parameter `(history_id,)` is sent separately. The database treats it strictly as a literal text or integer value, never executing it as code. Even if it contains quotes or SQL keywords, it is harmless data.

---

## 5. Database Optimization: Indexing

As database tables grow, scanning rows linearly (an $O(N)$ table scan) becomes slow. We optimize queries using **Database Indexes**:
```sql
CREATE INDEX IF NOT EXISTS idx_scan_date ON scans (scan_date DESC);
```
* **B-Trees:** An index builds a separate, balanced search tree structure pointing to rows.
* **Performance:** When running queries with sorting filters (`ORDER BY scan_date DESC LIMIT 10`), the index allows the database to retrieve rows in logarithmic $O(\log N)$ time, preventing performance degradation.

---

## 6. Disk Quota Management (Data Pruning)

On hosted cloud environments (especially free tiers), storage space is strictly capped. Unbounded database growth eventually crashes the hosting environment.
* **Pruning Logic:** We implement a routine that counts records, finds the ID boundary at `OFFSET 50`, and deletes older records (`DELETE FROM scans WHERE id <= boundary_id`).
* **Deterministic Sort:** We sort by `scan_date DESC, id DESC` to handle ties if multiple scans execute simultaneously, ensuring only the oldest records are deleted.
