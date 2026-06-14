# modules/__init__.py
# ------------------
# This file is a special Python file that marks the 'modules' directory as a Python package.
#
# WHY IT EXISTS:
# In Python, directories containing an '__init__.py' file are treated as packages. This allows
# us to import our custom scanners into our main app.py using syntax like:
#     from modules.header_scanner import scan_headers
#
# CYBERSECURITY RELEVANCE:
# Organizing code into isolated, modular units is a key principle of Secure Software Development (SSD).
# By separating scanning duties into isolated files, we ensure that:
# 1. We keep our codebase clean and maintainable.
# 2. We can audit, test, and secure individual modules independently without risking the entire system.
# 3. We adhere to the "Principle of Least Privilege" inside code architecture, making sure components
#    only have access to what they need.
