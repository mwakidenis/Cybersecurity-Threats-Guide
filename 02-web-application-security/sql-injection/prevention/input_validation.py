#!/usr/bin/env python3
"""
Input Validation and Sanitization for SQL Injection Prevention
Location: 02-web-application-security/sql-injection/prevention/input_validation.py

This script demonstrates various input validation and sanitization techniques
to prevent SQL injection and other injection attacks.
"""

import re
import html
import json
from typing import Any, Dict, List, Optional, Union
import ipaddress
from datetime import datetime
import unicodedata

class InputValidator:
    """
    Comprehensive input validation and sanitization class
    """
    
    def __init__(self):
        # Common patterns
        self.email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        self.username_pattern = r'^[a-zA-Z0-9_]{3,20}$'
        self.password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$'
        self.phone_pattern = r'^\+?1?\d{9,15}$'
        self.ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        # SQL injection blacklist patterns
        self.sql_patterns = [
            r'(\bSELECT\b.*\bFROM\b)',
            r'(\bINSERT\b.*\bINTO\b)',
            r'(\bUPDATE\b.*\bSET\b)',
            r'(\bDELETE\b.*\bFROM\b)',
            r'(\bDROP\b.*\bTABLE\b)',
            r'(\bUNION\b.*\bSELECT\b)',
            r'--',
            r';',
            r'/\*.*\*/',
            r'(\bOR\b.*\b=\b)',
            r'(\bAND\b.*\b=\b)',
            r'\bSLEEP\s*\(',
            r'\bWAITFOR\s+DELAY',
            r'\bBENCHMARK\s*\(',
            r'\bEXEC\s*\(',
            r'\bEXECUTE\s*\(',
            r'\bCAST\s*\(',
            r'\bCONVERT\s*\(',
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'onclick=',
            r'onmouseover=',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\(',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>',
            r'<svg.*?>',
            r'eval\s*\(',
            r'document\.cookie',
            r'window\.location',
        ]
        
    # ==================== VALIDATION METHODS ====================
    
    def validate_email(self, email: str) -> bool:
        """Validate email address format"""
        if not email or not isinstance(email, str):
            return False
        return bool(re.match(self.email_pattern, email, re.IGNORECASE))
    
    def validate_username(self, username: str) -> bool:
        """Validate username (alphanumeric + underscore, 3-20 chars)"""
        if not username or not isinstance(username, str):
            return False
        return bool(re.match(self.username_pattern, username))
    
    def validate_password(self, password: str) -> tuple:
        """
        Validate password strength
        Returns: (is_valid, message)
        """
        if not password or not isinstance(password, str):
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[@$!%*#?&]', password):
            return False, "Password must contain at least one special character (@$!%*#?&)"
        
        return True, "Password is strong"
    
    def validate_phone(self, phone: str) -> bool:
        """Validate phone number (E.164 format)"""
        if not phone or not isinstance(phone, str):
            return False
        # Remove common separators
        cleaned = re.sub(r'[\s\-\(\)]', '', phone)
        return bool(re.match(self.phone_pattern, cleaned))
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format"""
        if not url or not isinstance(url, str):
            return False
        url_pattern = r'^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$'
        return bool(re.match(url_pattern, url))
    
    def validate_date(self, date_str: str, format: str = '%Y-%m-%d') -> bool:
        """Validate date string"""
        try:
            datetime.strptime(date_str, format)
            return True
        except ValueError:
            return False
    
    def validate_integer(self, value: Any, min_val: int = None, max_val: int = None) -> bool:
        """Validate integer with optional range"""
        try:
            val = int(value)
            if min_val is not None and val < min_val:
                return False
            if max_val is not None and val > max_val:
                return False
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_float(self, value: Any, min_val: float = None, max_val: float = None) -> bool:
        """Validate float with optional range"""
        try:
            val = float(value)
            if min_val is not None and val < min_val:
                return False
            if max_val is not None and val > max_val:
                return False
            return True
        except (ValueError, TypeError):
            return False
    
    def validate_boolean(self, value: Any) -> bool:
        """Validate boolean value"""
        if isinstance(value, bool):
            return True
        if isinstance(value, str):
            return value.lower() in ['true', 'false', '1', '0', 'yes', 'no']
        if isinstance(value, (int, float)):
            return value in [0, 1]
        return False
    
    def validate_enum(self, value: Any, allowed_values: List) -> bool:
        """Validate value against list of allowed values"""
        return value in allowed_values
    
    # ==================== SANITIZATION METHODS ====================
    
    def sanitize_string(self, value: str, max_length: int = None, allow_html: bool = False) -> str:
        """
        Sanitize string input
        - Remove control characters
        - Normalize Unicode
        - Strip whitespace
        - Optionally escape HTML
        - Truncate to max_length
        """
        if not isinstance(value, str):
            value = str(value) if value is not None else ''
        
        # Normalize Unicode
        value = unicodedata.normalize('NFKD', value)
        
        # Remove control characters
        value = ''.join(char for char in value if ord(char) >= 32 or char == '\n' or char == '\r' or char == '\t')
        
        # Strip leading/trailing whitespace
        value = value.strip()
        
        # Escape HTML if not allowed
        if not allow_html:
            value = html.escape(value)
        
        # Truncate if max_length specified
        if max_length and len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    def sanitize_email(self, email: str) -> str:
        """Sanitize email address"""
        email = self.sanitize_string(email.lower())
        # Remove any potentially dangerous characters
        email = re.sub(r'[^\w\.@\+\-]', '', email)
        return email
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove path separators
        filename = filename.replace('/', '_').replace('\\', '_')
        # Remove any directory traversal attempts
        filename = filename.replace('..', '_')
        # Keep only safe characters
        filename = re.sub(r'[^\w\-\.]', '_', filename)
        # Prevent empty filename
        if not filename or filename in ['.', '..']:
            filename = 'file'
        return filename
    
    def sanitize_sql(self, value: str) -> str:
        """Basic SQL sanitization (use parameterized queries instead!)"""
        # This is just a backup - always use parameterized queries!
        if not isinstance(value, str):
            return str(value) if value is not None else ''
        
        # Escape single quotes
        value = value.replace("'", "''")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        return value
    
    def sanitize_html(self, value: str) -> str:
        """Sanitize HTML content"""
        if not isinstance(value, str):
            value = str(value) if value is not None else ''
        
        # Escape HTML special characters
        return html.escape(value)
    
    def sanitize_json(self, data: Any) -> str:
        """Convert to JSON safely"""
        try:
            return json.dumps(data, ensure_ascii=False)
        except:
            return json.dumps({})
    
    # ==================== INJECTION DETECTION ====================
    
    def detect_sql_injection(self, value: str) -> tuple:
        """
        Detect potential SQL injection attempts
        Returns: (is_suspicious, matched_pattern)
        """
        if not isinstance(value, str):
            return False, None
        
        value_upper = value.upper()
        
        for pattern in self.sql_patterns:
            if re.search(pattern, value_upper, re.IGNORECASE):
                return True, pattern
        
        return False, None
    
    def detect_xss(self, value: str) -> tuple:
        """
        Detect potential XSS attempts
        Returns: (is_suspicious, matched_pattern)
        """
        if not isinstance(value, str):
            return False, None
        
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True, pattern
        
        return False, None
    
    def detect_command_injection(self, value: str) -> tuple:
        """
        Detect potential command injection attempts
        """
        cmd_patterns = [
            r'[;&|`]',
            r'\$\(.*\)',
            r'`.*`',
            r'\|\|',
            r'&&',
            r'>.*&',
            r'<.*&',
            r'\/etc\/passwd',
            r'\/bin\/sh',
            r'\/bin\/bash',
            r'wget',
            r'curl',
            r'nmap',
            r'ping.*-c',
        ]
        
        if not isinstance(value, str):
            return False, None
        
        for pattern in cmd_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True, pattern
        
        return False, None
    
    # ==================== COMPREHENSIVE VALIDATION ====================
    
    def validate_and_sanitize_input(self, data: Dict, rules: Dict) -> Dict:
        """
        Comprehensive input validation and sanitization based on rules
        
        Args:
            data: Dictionary of input data
            rules: Dictionary of validation rules
                  Example:
                  {
                      'username': {'type': 'username', 'required': True, 'max_length': 20},
                      'email': {'type': 'email', 'required': True},
                      'age': {'type': 'integer', 'min': 18, 'max': 120},
                      'bio': {'type': 'string', 'required': False, 'max_length': 500, 'allow_html': False}
                  }
        
        Returns:
            Dictionary with validated/sanitized data and errors
        """
        result = {
            'validated_data': {},
            'errors': {},
            'warnings': []
        }
        
        for field, rule in rules.items():
            value = data.get(field)
            
            # Check required
            if rule.get('required', False) and value is None:
                result['errors'][field] = f"{field} is required"
                continue
            
            # Skip if value is None and not required
            if value is None:
                continue
            
            # Type validation and sanitization
            field_type = rule.get('type', 'string')
            
            try:
                if field_type == 'email':
                    if not self.validate_email(value):
                        result['errors'][field] = f"Invalid email format"
                    else:
                        result['validated_data'][field] = self.sanitize_email(value)
                
                elif field_type == 'username':
                    if not self.validate_username(value):
                        result['errors'][field] = f"Username must be 3-20 alphanumeric characters or underscore"
                    else:
                        result['validated_data'][field] = self.sanitize_string(value, rule.get('max_length'))
                
                elif field_type == 'password':
                    is_valid, message = self.validate_password(value)
                    if not is_valid:
                        result['errors'][field] = message
                    else:
                        result['validated_data'][field] = value  # Don't sanitize password, hash it instead!
                
                elif field_type == 'integer':
                    if not self.validate_integer(value, rule.get('min'), rule.get('max')):
                        result['errors'][field] = f"Must be an integer"
                        if rule.get('min') and rule.get('max'):
                            result['errors'][field] += f" between {rule['min']} and {rule['max']}"
                    else:
                        result['validated_data'][field] = int(value)
                
                elif field_type == 'float':
                    if not self.validate_float(value, rule.get('min'), rule.get('max')):
                        result['errors'][field] = f"Must be a number"
                    else:
                        result['validated_data'][field] = float(value)
                
                elif field_type == 'boolean':
                    if not self.validate_boolean(value):
                        result['errors'][field] = f"Must be a boolean"
                    else:
                        if isinstance(value, str):
                            result['validated_data'][field] = value.lower() in ['true', '1', 'yes']
                        else:
                            result['validated_data'][field] = bool(value)
                
                elif field_type == 'string':
                    sanitized = self.sanitize_string(
                        value,
                        max_length=rule.get('max_length'),
                        allow_html=rule.get('allow_html', False)
                    )
                    
                    # Check for injections
                    is_sql, sql_pattern = self.detect_sql_injection(value)
                    if is_sql:
                        result['warnings'].append(f"Potential SQL injection in {field}: {sql_pattern}")
                    
                    is_xss, xss_pattern = self.detect_xss(value)
                    if is_xss:
                        result['warnings'].append(f"Potential XSS in {field}: {xss_pattern}")
                    
                    is_cmd, cmd_pattern = self.detect_command_injection(value)
                    if is_cmd:
                        result['warnings'].append(f"Potential command injection in {field}: {cmd_pattern}")
                    
                    result['validated_data'][field] = sanitized
                
                elif field_type == 'ip':
                    if not self.validate_ip(value):
                        result['errors'][field] = f"Invalid IP address"
                    else:
                        result['validated_data'][field] = value
                
                elif field_type == 'phone':
                    if not self.validate_phone(value):
                        result['errors'][field] = f"Invalid phone number"
                    else:
                        result['validated_data'][field] = self.sanitize_string(value)
                
                elif field_type == 'url':
                    if not self.validate_url(value):
                        result['errors'][field] = f"Invalid URL"
                    else:
                        result['validated_data'][field] = value
                
                elif field_type == 'enum':
                    allowed = rule.get('allowed', [])
                    if not self.validate_enum(value, allowed):
                        result['errors'][field] = f"Must be one of: {', '.join(allowed)}"
                    else:
                        result['validated_data'][field] = value
                
            except Exception as e:
                result['errors'][field] = f"Validation error: {str(e)}"
        
        return result

class SecureForm:
    """Example secure form handling class"""
    
    def __init__(self):
        self.validator = InputValidator()
        
    def process_registration_form(self, form_data):
        """Process user registration form securely"""
        
        rules = {
            'username': {
                'type': 'username',
                'required': True,
                'max_length': 20
            },
            'email': {
                'type': 'email',
                'required': True
            },
            'password': {
                'type': 'password',
                'required': True
            },
            'age': {
                'type': 'integer',
                'required': True,
                'min': 18,
                'max': 120
            },
            'phone': {
                'type': 'phone',
                'required': False
            },
            'bio': {
                'type': 'string',
                'required': False,
                'max_length': 500,
                'allow_html': False
            },
            'newsletter': {
                'type': 'boolean',
                'required': False
            }
        }
        
        return self.validator.validate_and_sanitize_input(form_data, rules)
    
    def process_comment_form(self, form_data):
        """Process comment form securely with XSS prevention"""
        
        rules = {
            'name': {
                'type': 'string',
                'required': True,
                'max_length': 50,
                'allow_html': False
            },
            'email': {
                'type': 'email',
                'required': True
            },
            'comment': {
                'type': 'string',
                'required': True,
                'max_length': 1000,
                'allow_html': False
            },
            'rating': {
                'type': 'enum',
                'required': True,
                'allowed': [1, 2, 3, 4, 5]
            }
        }
        
        return self.validator.validate_and_sanitize_input(form_data, rules)
    
    def process_search_form(self, form_data):
        """Process search form with injection detection"""
        
        rules = {
            'query': {
                'type': 'string',
                'required': True,
                'max_length': 100,
                'allow_html': False
            },
            'page': {
                'type': 'integer',
                'required': False,
                'min': 1,
                'max': 1000
            },
            'sort': {
                'type': 'enum',
                'required': False,
                'allowed': ['relevance', 'date', 'rating']
            }
        }
        
        return self.validator.validate_and_sanitize_input(form_data, rules)

def demonstrate_validation():
    """Demonstrate input validation and sanitization"""
    
    print("="*60)
    print("INPUT VALIDATION AND SANITIZATION DEMO")
    print("="*60)
    
    validator = InputValidator()
    secure_form = SecureForm()
    
    # Test 1: Email validation
    print("\n📧 Email Validation:")
    test_emails = [
        "user@example.com",
        "invalid.email",
        "user+tag@example.co.uk",
        "user@.com",
    ]
    
    for email in test_emails:
        is_valid = validator.validate_email(email)
        sanitized = validator.sanitize_email(email) if is_valid else "INVALID"
        status = "✅" if is_valid else "❌"
        print(f"  {status} {email} -> {sanitized}")
    
    # Test 2: Password strength
    print("\n🔐 Password Strength:")
    test_passwords = [
        "weak",
        "StrongPass123!",
        "NoNumbers!",
        "12345678",
        "Str0ng!Pass",
    ]
    
    for pwd in test_passwords:
        is_valid, message = validator.validate_password(pwd)
        status = "✅" if is_valid else "❌"
        print(f"  {status} {pwd:15} - {message}")
    
    # Test 3: SQL injection detection
    print("\n💉 SQL Injection Detection:")
    test_sql = [
        "normal input",
        "Robert'; DROP TABLE users--",
        "admin' OR '1'='1",
        "SELECT * FROM users",
        "1; SLEEP(5)--",
    ]
    
    for input_str in test_sql:
        is_suspicious, pattern = validator.detect_sql_injection(input_str)
        status = "⚠️" if is_suspicious else "✅"
        print(f"  {status} {input_str:30} - {pattern if pattern else 'Clean'}")
    
    # Test 4: XSS detection
    print("\n🌐 XSS Detection:")
    test_xss = [
        "normal comment",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert('XSS')",
        "normal <b>bold</b> text",
    ]
    
    for input_str in test_xss:
        is_suspicious, pattern = validator.detect_xss(input_str)
        sanitized = validator.sanitize_html(input_str)
        status = "⚠️" if is_suspicious else "✅"
        print(f"  {status} Original: {input_str[:30]}")
        print(f"      Sanitized: {sanitized[:30]}")
    
    # Test 5: Registration form
    print("\n📝 Registration Form Validation:")
    test_registration = {
        'username': 'john_doe',
        'email': 'john@example.com',
        'password': 'Test123!',
        'age': '25',
        'phone': '+1234567890',
        'bio': 'Hello <script>alert(1)</script> world!',
        'newsletter': 'yes'
    }
    
    result = secure_form.process_registration_form(test_registration)
    
    print(f"  Validated Data: {json.dumps(result['validated_data'], indent=4)}")
    if result['errors']:
        print(f"  Errors: {result['errors']}")
    if result['warnings']:
        print(f"  Warnings: {result['warnings']}")
    
    # Test 6: Comment form with malicious input
    print("\n💬 Comment Form with Malicious Input:")
    test_comment = {
        'name': '<script>alert(1)</script>',
        'email': 'attacker@example.com',
        'comment': "Nice post!'; DROP TABLE users; --",
        'rating': '5'
    }
    
    result = secure_form.process_comment_form(test_comment)
    
    print(f"  Validated Data: {json.dumps(result['validated_data'], indent=4)}")
    if result['warnings']:
        print(f"  Warnings: {result['warnings']}")

def main():
    print("""
    ╔═══════════════════════════════════════╗
    ║   Input Validation & Sanitization     ║
    ║     SQL Injection Prevention Demo     ║
    ╚═══════════════════════════════════════╝
    """)
    
    demonstrate_validation()
    
    print("\n" + "="*60)
    print("KEY TAKEAWAYS:")
    print("1. Always validate input on both client and server side")
    print("2. Use parameterized queries - validation is additional defense")
    print("3. Sanitize output based on context (HTML, SQL, etc.)")
    print("4. Don't rely on blacklists - use whitelists when possible")
    print("5. Combine multiple validation techniques")
    print("="*60)

if __name__ == "__main__":
    main()
