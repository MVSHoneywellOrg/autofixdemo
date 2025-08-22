# Security Vulnerability Validator

A Python script for basic security vulnerability validation in Python code.

## Features

This validator detects common security vulnerabilities in Python code:

- **Hardcoded Secrets**: Detects hardcoded secret keys, passwords, API keys, and tokens
- **SQL Injection**: Identifies potential SQL injection vulnerabilities in database queries
- **Remote Code Execution (RCE)**: Finds unsafe command execution with user input
- **Cross-Site Scripting (XSS)**: Detects XSS vulnerabilities in template rendering and HTML output

## Usage

```bash
python3 security_validator.py <python_file>
```

### Example

```bash
# Scan mvs.py for vulnerabilities
python3 security_validator.py mvs.py
```

## Output

The validator provides a detailed report including:
- Summary of vulnerabilities by severity (Critical, High, Medium)
- Line numbers where vulnerabilities are found
- Description of each vulnerability
- Code snippets showing the problematic code
- Severity levels with color-coded emojis

### Example Output

```
🚨 SECURITY VULNERABILITY REPORT
==================================================

SUMMARY:
  Total vulnerabilities: 5
  Critical: 2
  High: 3
  Medium: 0

📋 HARDCODED SECRETS
------------------------------
🟠 Line 9: Hardcoded Secret Key found: 'mySuperSecretKey123'
   Code: app.secret_key = "mySuperSecretKey123"
   Severity: HIGH
```

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected

## Vulnerability Types

### Hardcoded Secrets (HIGH)
- Detects hardcoded credentials in source code
- Looks for patterns like `secret_key=`, `password=`, `api_key=`, etc.

### SQL Injection (CRITICAL)
- Identifies unsafe SQL query construction
- Detects f-strings and string concatenation in SQL queries

### Remote Code Execution (CRITICAL)
- Finds command execution functions with user input
- Detects `os.popen()`, `os.system()`, `subprocess` calls with request data

### Cross-Site Scripting (HIGH)
- Identifies unsafe template rendering
- Detects unsanitized user input in HTML output