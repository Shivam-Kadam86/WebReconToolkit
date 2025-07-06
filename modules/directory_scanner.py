import requests
import concurrent.futures
from urllib.parse import urljoin
import os

class DirectoryScanner:
    def __init__(self, session, timeout, threads):
        self.session = session
        self.timeout = timeout
        self.threads = threads
        self.wordlist = self._load_wordlist()
    
    def _load_wordlist(self):
        """Load directory wordlist from file"""
        try:
            with open('data/common_directories.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Return a basic wordlist if file doesn't exist
            return [
                'admin', 'administrator', 'login', 'test', 'tmp', 'temp',
                'backup', 'backups', 'config', 'conf', 'data', 'db',
                'files', 'images', 'uploads', 'download', 'downloads',
                'docs', 'documentation', 'api', 'v1', 'v2', 'private',
                'internal', 'dev', 'development', 'staging', 'phpmyadmin',
                'mysql', 'sql', 'database', 'wp-admin', 'wp-content',
                'wp-includes', 'wordpress', 'joomla', 'drupal', 'magento',
                'shop', 'store', 'cart', 'checkout', 'payment', 'secure',
                'ssl', 'tls', 'cert', 'certificates', 'keys', 'logs',
                'log', 'error', 'debug', 'trace', 'status', 'health',
                'info', 'version', 'readme', 'changelog', 'license',
                'robots.txt', 'sitemap.xml', '.htaccess', 'web.config'
            ]
    
    def scan(self, target_url):
        """Scan for common directories and files"""
        findings = []
        
        # Ensure target URL ends with /
        if not target_url.endswith('/'):
            target_url += '/'
        
        # Test for directory listing
        dir_listing = self._check_directory_listing(target_url)
        if dir_listing:
            findings.extend(dir_listing)
        
        # Scan for common paths
        discovered_paths = self._scan_paths(target_url)
        findings.extend(discovered_paths)
        
        return findings
    
    def _check_directory_listing(self, target_url):
        """Check if directory listing is enabled"""
        findings = []
        
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            
            # Check for directory listing indicators
            content = response.text.lower()
            listing_indicators = [
                'index of',
                'directory listing',
                'parent directory',
                '[dir]',
                '[file]',
                'last modified',
                'apache server at'
            ]
            
            if any(indicator in content for indicator in listing_indicators):
                findings.append({
                    'title': 'Directory Listing Enabled',
                    'description': 'Web server allows directory browsing',
                    'severity': 'medium',
                    'details': f'Directory listing detected at {target_url}'
                })
        
        except requests.exceptions.RequestException:
            pass
        
        return findings
    
    def _scan_paths(self, target_url):
        """Scan for common paths using multithreading"""
        findings = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all requests
            future_to_path = {
                executor.submit(self._check_path, target_url, path): path
                for path in self.wordlist
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                except Exception as e:
                    # Skip failed requests
                    continue
        
        return findings
    
    def _check_path(self, target_url, path):
        """Check if a specific path exists"""
        try:
            full_url = urljoin(target_url, path)
            response = self.session.get(full_url, timeout=self.timeout, allow_redirects=False)
            
            # Consider 200, 403, and 401 as existing paths
            if response.status_code in [200, 403, 401]:
                severity = 'low'
                
                # Higher severity for sensitive paths
                sensitive_paths = [
                    'admin', 'administrator', 'login', 'config', 'conf',
                    'backup', 'backups', 'database', 'db', 'phpmyadmin',
                    'mysql', 'private', 'internal', 'dev', 'development',
                    'staging', 'test', 'debug', 'trace', 'logs', 'log',
                    'error', 'keys', 'cert', 'certificates', '.htaccess',
                    'web.config', 'robots.txt'
                ]
                
                if any(sensitive in path.lower() for sensitive in sensitive_paths):
                    severity = 'medium'
                
                return {
                    'title': f'Discovered Path: {path}',
                    'description': f'Found accessible path at {full_url}',
                    'severity': severity,
                    'details': f'Status: {response.status_code}, URL: {full_url}'
                }
        
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def _is_interesting_response(self, response):
        """Determine if a response is interesting"""
        # Check for interesting status codes
        if response.status_code in [200, 403, 401, 500]:
            return True
        
        # Check for redirects to login pages
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            login_indicators = ['login', 'auth', 'signin', 'sign-in']
            if any(indicator in location.lower() for indicator in login_indicators):
                return True
        
        return False
