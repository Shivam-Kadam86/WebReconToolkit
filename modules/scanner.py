import requests
import urllib.parse
import socket
import time
import concurrent.futures
from bs4 import BeautifulSoup
from modules.header_analyzer import HeaderAnalyzer
from modules.directory_scanner import DirectoryScanner
from modules.xss_scanner import XSSScanner
from modules.sql_scanner import SQLScanner

class WebScanner:
    def __init__(self, target_url, timeout=10, threads=5):
        self.target_url = target_url
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebRecon Security Scanner v1.0'
        })
        
        # Initialize specialized scanners
        self.header_analyzer = HeaderAnalyzer(self.session, timeout)
        self.directory_scanner = DirectoryScanner(self.session, timeout, threads)
        self.xss_scanner = XSSScanner(self.session, timeout)
        self.sql_scanner = SQLScanner(self.session, timeout)
    
    def analyze_headers(self):
        """Analyze HTTP headers for security issues"""
        return self.header_analyzer.analyze(self.target_url)
    
    def check_security_headers(self):
        """Check for presence and configuration of security headers"""
        return self.header_analyzer.check_security_headers(self.target_url)
    
    def enumerate_directories(self):
        """Enumerate common directories and files"""
        return self.directory_scanner.scan(self.target_url)
    
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        return self.xss_scanner.scan(self.target_url)
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        return self.sql_scanner.scan(self.target_url)
    
    def get_page_content(self, url):
        """Fetch and parse page content"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            return None
    
    def is_target_reachable(self):
        """Check if target is reachable"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            return response.status_code < 400
        except:
            return False
