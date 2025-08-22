#!/usr/bin/env python3
"""
Security Vulnerability Validator
A basic Python script to scan for common security vulnerabilities in Python code.
"""

import re
import os
import sys
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability."""
    type: str
    line: int
    description: str
    severity: str
    code_snippet: str


class SecurityValidator:
    """Main class for validating security vulnerabilities in Python code."""
    
    def __init__(self):
        self.vulnerabilities = []
        
    def scan_file(self, filepath: str) -> List[Vulnerability]:
        """Scan a Python file for security vulnerabilities."""
        if not os.path.exists(filepath):
            print(f"Error: File {filepath} not found")
            return []
            
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                
            self.vulnerabilities = []
            self._check_hardcoded_secrets(lines)
            self._check_sql_injection(lines)
            self._check_command_execution(lines)
            self._check_xss_vulnerabilities(lines)
            
            return self.vulnerabilities
            
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return []
    
    def _check_hardcoded_secrets(self, lines: List[str]) -> None:
        """Check for hardcoded secrets and credentials."""
        secret_patterns = [
            (r'secret_key\s*=\s*["\']([^"\']+)["\']', 'Hardcoded Secret Key'),
            (r'password\s*=\s*["\']([^"\']+)["\']', 'Hardcoded Password'),
            (r'api_key\s*=\s*["\']([^"\']+)["\']', 'Hardcoded API Key'),
            (r'token\s*=\s*["\']([^"\']+)["\']', 'Hardcoded Token'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, vuln_type in secret_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    self.vulnerabilities.append(Vulnerability(
                        type="Hardcoded Secrets",
                        line=line_num,
                        description=f"{vuln_type} found: '{match.group(1)}'",
                        severity="HIGH",
                        code_snippet=line.strip()
                    ))
    
    def _check_sql_injection(self, lines: List[str]) -> None:
        """Check for SQL injection vulnerabilities."""
        sql_patterns = [
            r'f["\'].*SELECT.*\{.*\}.*["\']',  # f-string with SELECT
            r'["\'].*SELECT.*["\'].*\+.*',      # String concatenation with SELECT
            r'["\'].*SELECT.*["\'].*%.*',       # String formatting with SELECT
            r'cursor\.execute\s*\(\s*f["\'].*\{.*\}.*["\']',  # Direct f-string in execute
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(Vulnerability(
                        type="SQL Injection",
                        line=line_num,
                        description="Potential SQL injection vulnerability detected",
                        severity="CRITICAL",
                        code_snippet=line.strip()
                    ))
    
    def _check_command_execution(self, lines: List[str]) -> None:
        """Check for command execution vulnerabilities."""
        cmd_patterns = [
            r'os\.popen\s*\(',
            r'os\.system\s*\(',
            r'subprocess\.call\s*\(',
            r'subprocess\.run\s*\(',
            r'subprocess\.Popen\s*\(',
            r'eval\s*\(',
            r'exec\s*\(',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in cmd_patterns:
                if re.search(pattern, line):
                    # Check if user input is involved by looking at surrounding context
                    context_lines = lines[max(0, line_num-3):line_num+2]
                    context_text = ' '.join([l.strip() for l in context_lines])
                    
                    if re.search(r'request\.args|request\.form|request\.json|input\(', context_text):
                        self.vulnerabilities.append(Vulnerability(
                            type="Remote Code Execution",
                            line=line_num,
                            description="Command execution with user input detected",
                            severity="CRITICAL",
                            code_snippet=line.strip()
                        ))
                    else:
                        self.vulnerabilities.append(Vulnerability(
                            type="Command Execution",
                            line=line_num,
                            description="Potentially unsafe command execution",
                            severity="MEDIUM",
                            code_snippet=line.strip()
                        ))
                    break  # Only report one pattern per line
    
    def _check_xss_vulnerabilities(self, lines: List[str]) -> None:
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        for line_num, line in enumerate(lines, 1):
            # Check for render_template_string with f-strings
            if re.search(r'render_template_string\s*\(\s*f["\'].*\{.*\}.*["\']', line):
                # Look for user input in context
                context_lines = lines[max(0, line_num-5):line_num+2]
                context_text = ' '.join([l.strip() for l in context_lines])
                if re.search(r'request\.args|request\.form|request\.json|request\.get|input\(', context_text):
                    self.vulnerabilities.append(Vulnerability(
                        type="Cross-Site Scripting (XSS)",
                        line=line_num,
                        description="XSS vulnerability - unsanitized user input in render_template_string",
                        severity="HIGH",
                        code_snippet=line.strip()
                    ))
            
            # Check for f-strings with HTML tags that include user input
            elif re.search(r'return.*f["\'].*<.*\{.*\}.*>.*["\']', line):
                # Look for user input variables
                context_lines = lines[max(0, line_num-5):line_num+2]
                context_text = ' '.join([l.strip() for l in context_lines])
                if re.search(r'request\.args|request\.form|request\.json|request\.get|input\(', context_text):
                    self.vulnerabilities.append(Vulnerability(
                        type="Cross-Site Scripting (XSS)",
                        line=line_num,
                        description="XSS vulnerability - unsanitized user input in HTML output",
                        severity="HIGH",
                        code_snippet=line.strip()
                    ))
    
    def generate_report(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate a formatted report of vulnerabilities."""
        if not vulnerabilities:
            return "✅ No security vulnerabilities detected!"
        
        report = f"\n🚨 SECURITY VULNERABILITY REPORT\n"
        report += "=" * 50 + "\n\n"
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            if vuln.type not in vuln_by_type:
                vuln_by_type[vuln.type] = []
            vuln_by_type[vuln.type].append(vuln)
        
        total_count = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if v.severity == "CRITICAL"])
        high_count = len([v for v in vulnerabilities if v.severity == "HIGH"])
        medium_count = len([v for v in vulnerabilities if v.severity == "MEDIUM"])
        
        report += f"SUMMARY:\n"
        report += f"  Total vulnerabilities: {total_count}\n"
        report += f"  Critical: {critical_count}\n"
        report += f"  High: {high_count}\n"
        report += f"  Medium: {medium_count}\n\n"
        
        for vuln_type, vulns in vuln_by_type.items():
            report += f"📋 {vuln_type.upper()}\n"
            report += "-" * 30 + "\n"
            
            for vuln in vulns:
                severity_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠", 
                    "MEDIUM": "🟡"
                }.get(vuln.severity, "⚪")
                
                report += f"{severity_emoji} Line {vuln.line}: {vuln.description}\n"
                report += f"   Code: {vuln.code_snippet}\n"
                report += f"   Severity: {vuln.severity}\n\n"
        
        return report


def main():
    """Main function to run the security validator."""
    if len(sys.argv) != 2:
        print("Usage: python security_validator.py <python_file>")
        print("Example: python security_validator.py mvs.py")
        sys.exit(1)
    
    filepath = sys.argv[1]
    validator = SecurityValidator()
    vulnerabilities = validator.scan_file(filepath)
    report = validator.generate_report(vulnerabilities)
    
    print(report)
    
    # Exit with error code if vulnerabilities found
    if vulnerabilities:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()