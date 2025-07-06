import requests
from urllib.parse import urlparse

class HeaderAnalyzer:
    def __init__(self, session, timeout):
        self.session = session
        self.timeout = timeout
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'severity': 'high'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and data injection attacks',
                'severity': 'high'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'medium'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'medium'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS protection',
                'severity': 'medium'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'severity': 'low'
            },
            'Permissions-Policy': {
                'description': 'Controls browser feature permissions',
                'severity': 'low'
            }
        }
    
    def analyze(self, target_url):
        """Analyze HTTP headers for security and configuration issues"""
        findings = []
        
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            headers = response.headers
            
            # Check for server information disclosure
            if 'Server' in headers:
                findings.append({
                    'title': 'Server Information Disclosure',
                    'description': 'Server header reveals server software and version',
                    'severity': 'low',
                    'details': f"Server: {headers['Server']}"
                })
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                findings.append({
                    'title': 'Technology Stack Disclosure',
                    'description': 'X-Powered-By header reveals technology stack',
                    'severity': 'low',
                    'details': f"X-Powered-By: {headers['X-Powered-By']}"
                })
            
            # Check for custom headers that might leak information
            suspicious_headers = ['X-Debug', 'X-Version', 'X-Application']
            for header in suspicious_headers:
                if header in headers:
                    findings.append({
                        'title': 'Information Disclosure in Headers',
                        'description': f'Custom header {header} may leak sensitive information',
                        'severity': 'medium',
                        'details': f"{header}: {headers[header]}"
                    })
            
            # Check cache headers
            cache_headers = ['Cache-Control', 'Pragma', 'Expires']
            cache_issues = []
            for header in cache_headers:
                if header in headers:
                    cache_issues.append(f"{header}: {headers[header]}")
            
            if cache_issues:
                findings.append({
                    'title': 'Cache Headers Analysis',
                    'description': 'Cache headers configuration detected',
                    'severity': 'info',
                    'details': ', '.join(cache_issues)
                })
            
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'Header Analysis Failed',
                'description': f'Unable to retrieve headers: {str(e)}',
                'severity': 'info',
                'details': str(e)
            })
        
        return findings
    
    def check_security_headers(self, target_url):
        """Check for presence and configuration of security headers"""
        findings = []
        
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            headers = response.headers
            
            # Check for missing security headers
            for header, info in self.security_headers.items():
                if header not in headers:
                    findings.append({
                        'title': f'Missing Security Header: {header}',
                        'description': f'Missing {header} header - {info["description"]}',
                        'severity': info['severity'],
                        'details': f'The {header} header is not present in the response'
                    })
                else:
                    # Header is present, check its configuration
                    header_value = headers[header]
                    config_issues = self._analyze_header_config(header, header_value)
                    if config_issues:
                        findings.extend(config_issues)
            
            # Check for insecure cookies
            if 'Set-Cookie' in headers:
                cookie_issues = self._analyze_cookies(headers['Set-Cookie'])
                findings.extend(cookie_issues)
            
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'Security Header Check Failed',
                'description': f'Unable to check security headers: {str(e)}',
                'severity': 'info',
                'details': str(e)
            })
        
        return findings
    
    def _analyze_header_config(self, header_name, header_value):
        """Analyze specific security header configurations"""
        issues = []
        
        if header_name == 'Strict-Transport-Security':
            if 'max-age' not in header_value.lower():
                issues.append({
                    'title': 'HSTS Configuration Issue',
                    'description': 'HSTS header missing max-age directive',
                    'severity': 'medium',
                    'details': f'HSTS value: {header_value}'
                })
            elif 'includesubdomains' not in header_value.lower():
                issues.append({
                    'title': 'HSTS Incomplete Configuration',
                    'description': 'HSTS header missing includeSubDomains directive',
                    'severity': 'low',
                    'details': f'HSTS value: {header_value}'
                })
        
        elif header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in header_value.lower():
                issues.append({
                    'title': 'CSP Unsafe Configuration',
                    'description': 'CSP allows unsafe-inline which reduces security',
                    'severity': 'medium',
                    'details': f'CSP value: {header_value}'
                })
            
            if 'unsafe-eval' in header_value.lower():
                issues.append({
                    'title': 'CSP Unsafe Eval',
                    'description': 'CSP allows unsafe-eval which enables code execution',
                    'severity': 'high',
                    'details': f'CSP value: {header_value}'
                })
        
        elif header_name == 'X-Frame-Options':
            if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                issues.append({
                    'title': 'X-Frame-Options Weak Configuration',
                    'description': 'X-Frame-Options should be DENY or SAMEORIGIN',
                    'severity': 'medium',
                    'details': f'X-Frame-Options value: {header_value}'
                })
        
        return issues
    
    def _analyze_cookies(self, cookie_header):
        """Analyze cookie security attributes"""
        issues = []
        
        if 'secure' not in cookie_header.lower():
            issues.append({
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookies missing Secure flag',
                'severity': 'medium',
                'details': 'Cookies should include the Secure flag when transmitted over HTTPS'
            })
        
        if 'httponly' not in cookie_header.lower():
            issues.append({
                'title': 'Cookie XSS Vulnerability',
                'description': 'Cookies missing HttpOnly flag',
                'severity': 'medium',
                'details': 'Cookies should include the HttpOnly flag to prevent XSS attacks'
            })
        
        if 'samesite' not in cookie_header.lower():
            issues.append({
                'title': 'Cookie CSRF Vulnerability',
                'description': 'Cookies missing SameSite attribute',
                'severity': 'low',
                'details': 'Cookies should include SameSite attribute to prevent CSRF attacks'
            })
        
        return issues
