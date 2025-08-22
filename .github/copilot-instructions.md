# Vulnerable Flask Application (autofixdemo)

This repository contains a simple Python Flask web application (`mvs.py`) with intentional security vulnerabilities designed for security demonstration and testing purposes. The application includes SQL injection, remote code execution (RCE), and cross-site scripting (XSS) vulnerabilities.

**ALWAYS reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.**

## Working Effectively

### Bootstrap and Setup
Run these commands in sequence to set up the application:

1. **Install Flask** (takes ~3 seconds, NEVER CANCEL):
   ```bash
   pip3 install flask
   ```

2. **Create test database** (takes <1 second):
   ```bash
   sqlite3 users.db "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT); INSERT INTO users (username) VALUES ('testuser'), ('admin'), ('demo');"
   ```

3. **Start the application**:
   ```bash
   python3 mvs.py
   ```
   - Application starts in ~2 seconds
   - Runs on http://127.0.0.1:5000 in debug mode
   - **NEVER CANCEL** - Application runs continuously until stopped with Ctrl+C

### Application Structure
- **Single file**: `mvs.py` - Complete Flask application
- **Database**: SQLite database (`users.db`) created when testing
- **No build process** - Direct Python execution
- **No package management files** - Uses system/user-installed packages

## Validation

### **CRITICAL**: Manual Validation Requirements
**ALWAYS test actual functionality after making ANY changes to the code.** Run through these complete scenarios:

#### End-to-End Validation Scenarios
After starting the application with `python3 mvs.py`, test these scenarios:

1. **XSS Endpoint Test**:
   ```bash
   curl "http://127.0.0.1:5000/xss?name=TestUser"
   # Expected: <h1>Welcome TestUser</h1>
   ```

2. **Search Endpoint Test** (requires database):
   ```bash
   curl "http://127.0.0.1:5000/search?username=testuser"
   # Expected: [(1, 'testuser')]
   ```

3. **RCE Endpoint Test** (safe command):
   ```bash
   curl "http://127.0.0.1:5000/rce?cmd=echo%20hello"
   # Expected: <pre>hello</pre>
   ```

4. **SQL Injection Demonstration**:
   ```bash
   curl "http://127.0.0.1:5000/search?username=admin'%20OR%20'1'='1"
   # Expected: Shows all users due to SQL injection vulnerability
   ```

### Timing Expectations
- **Flask installation**: ~3 seconds (set timeout: 5+ minutes for safety)
- **Database creation**: <1 second  
- **Application startup**: ~2 seconds
- **Endpoint responses**: ~10ms each
- **NEVER CANCEL** any pip install operations - they may take up to 5 minutes on slow networks

### Database Requirements
The application **requires** a SQLite database with a `users` table for the `/search` endpoint to work. Without this database:
- `/search` endpoint will throw `sqlite3.OperationalError: no such table: users`
- `/xss` and `/rce` endpoints work without database
- Always create the test database using the provided SQL command

## Common Tasks

### Starting Fresh
```bash
# Clean previous artifacts
rm -f users.db __pycache__/*

# Install dependencies  
pip3 install flask

# Create database
sqlite3 users.db "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT); INSERT INTO users (username) VALUES ('testuser'), ('admin'), ('demo');"

# Run application
python3 mvs.py
```

### Code Validation
```bash
# Python syntax check (always run before committing)
python3 -m py_compile mvs.py

# No additional linters available in base environment
# Application has no test suite - manual testing required
```

### Security Testing Scenarios
This application is designed for security testing. Test these vulnerability scenarios:

1. **SQL Injection**: Try malicious usernames in search parameter
2. **Remote Code Execution**: Test safe commands via RCE endpoint  
3. **Cross-Site Scripting**: Test HTML/JavaScript injection in name parameter

**WARNING**: This application has intentional security vulnerabilities. Only use in isolated testing environments.

## File Structure Reference
```
autofixdemo/
├── .git/                    # Git repository data
├── .gitignore              # Git ignore patterns  
├── mvs.py                  # Main Flask application (1,157 bytes)
├── users.db                # SQLite database (created during testing)
└── __pycache__/            # Python cache (auto-generated)
```

### Key Application Code
The application contains these vulnerable endpoints:
- **GET /search?username=X** - SQL injection vulnerability
- **GET /rce?cmd=X** - Remote code execution vulnerability  
- **GET /xss?name=X** - Cross-site scripting vulnerability

### Environment Information
- **Python**: 3.12.3 available at `/usr/bin/python3`
- **pip**: 24.0 available at `/usr/bin/pip3`
- **SQLite**: Available via `sqlite3` command
- **No testing framework**: Use manual curl commands for validation
- **No linting tools**: Only basic syntax checking available

## Integration Notes

### GitHub Actions
- **Copilot workflow**: Active for automated code assistance
- **CodeQL workflow**: Active for security scanning
- No build/test workflows - manual testing required

### Troubleshooting
- **"ModuleNotFoundError: No module named 'flask'"**: Run `pip3 install flask`
- **"sqlite3.OperationalError: no such table: users"**: Create database using provided SQL
- **"Address already in use"**: Stop previous Flask instance with Ctrl+C
- **Application not responding**: Wait 3-5 seconds for startup, check port 5000

Always validate your changes by running the complete validation scenarios above.