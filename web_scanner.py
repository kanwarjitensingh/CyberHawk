#!/usr/bin/env python3
"""
Web Application Scanner
Handles web vulnerability scanning
"""

import requests
import ssl
import socket
import datetime
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberHawk-Scanner/2.1.0'
        })
        
        # Common paths to check for sensitive information
        self.common_paths = [
            '/robots.txt', '/.htaccess', '/admin', '/login', '/wp-admin',
            '/phpMyAdmin', '/manager', '/backup', '/config', '/test',
            '/debug', '/info.php', '/phpinfo.php', '/.git', '/.env',
            '/sitemap.xml', '/crossdomain.xml'
        ]
        
        # Security headers to check
        self.security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Permitted-Cross-Domain-Policies', 'Referrer-Policy'
        ]
        
        self.vulnerabilities = []
        
    def validate_url(self, url):
        """Validate URL format and add protocol if missing"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def check_connectivity(self, url):
        """Check if website is accessible"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            return response.status_code < 400
        except Exception:
            return False
    
    def scan_common_paths(self, base_url, verbose=False):
        """Scan for common sensitive files and directories"""
        findings = []
        
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Scanning for sensitive files and directories...")
        
        for path in self.common_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    severity = "Medium" if response.status_code == 200 else "Low"
                    finding = {
                        "type": "Sensitive Path",
                        "url": url,
                        "status_code": response.status_code,
                        "severity": severity
                    }
                    findings.append(finding)
                    
                    if verbose:
                        color = Fore.YELLOW if response.status_code == 200 else Fore.BLUE
                        print(f"  {color}[{response.status_code}]{Style.RESET_ALL} {path}")
                        
            except requests.RequestException:
                continue
            
            # Small delay to be respectful
            time.sleep(0.1)
        
        return findings
    
    def check_security_headers(self, url, verbose=False):
        """Check for missing security headers"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Analyzing security headers...")
            
            missing_headers = []
            for header in self.security_headers:
                if header not in headers:
                    missing_headers.append(header)
                    if verbose:
                        print(f"  {Fore.RED}[-]{Style.RESET_ALL} Missing: {header}")
                elif verbose:
                    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Present: {header}")
            
            if missing_headers:
                findings.append({
                    "type": "Missing Security Headers",
                    "missing_headers": missing_headers,
                    "severity": "Medium" if len(missing_headers) > 3 else "Low"
                })
                
        except Exception as e:
            if verbose:
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} Error checking headers: {str(e)}")
        
        return findings
    
    def check_ssl_configuration(self, url, verbose=False):
        """Check SSL/TLS configuration"""
        findings = []
        
        if not url.startswith('https://'):
            findings.append({
                "type": "Insecure Protocol",
                "description": "Website not using HTTPS",
                "severity": "High"
            })
            return findings
        
        try:
            hostname = urlparse(url).hostname
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Analyzing SSL/TLS configuration...")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate info
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    if verbose:
                        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} SSL/TLS Version: {ssock.version()}")
                        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Cipher: {cipher[0]}")
                        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Key Size: {cipher[2]} bits")
                    
                    # Check cipher strength
                    if cipher[2] < 128:
                        findings.append({
                            "type": "Weak SSL Cipher",
                            "cipher": cipher[0],
                            "key_size": cipher[2],
                            "severity": "High"
                        })
                    
                    # Check certificate expiry
                    from datetime import datetime
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        severity = "High" if days_until_expiry < 0 else "Medium"
                        findings.append({
                            "type": "Certificate Expiry Warning",
                            "days_remaining": days_until_expiry,
                            "severity": severity
                        })
                        
                        if verbose:
                            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Certificate expires in {days_until_expiry} days")
                    
        except Exception as e:
            findings.append({
                "type": "SSL Configuration Error",
                "error": str(e),
                "severity": "Medium"
            })
            if verbose:
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} SSL check failed: {str(e)}")
        
        return findings
    
    def check_server_information(self, url, verbose=False):
        """Check for information disclosure in server headers"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Analyzing server information disclosure...")
            
            # Check for server version disclosure
            if 'Server' in headers:
                server_info = headers['Server']
                if any(version_indicator in server_info.lower() 
                       for version_indicator in ['/', 'v', 'version']):
                    findings.append({
                        "type": "Server Version Disclosure",
                        "server_header": server_info,
                        "severity": "Low"
                    })
                    if verbose:
                        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Server: {server_info}")
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                findings.append({
                    "type": "Technology Disclosure",
                    "header": "X-Powered-By",
                    "value": headers['X-Powered-By'],
                    "severity": "Low"
                })
                if verbose:
                    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} X-Powered-By: {headers['X-Powered-By']}")
            
        except Exception as e:
            if verbose:
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} Error analyzing server info: {str(e)}")
        
        return findings
    
    def scan(self, target, verbose=False):
        """Main web scanning function"""
        # Validate and prepare URL
        if not target.startswith(('http://', 'https://')):
            # Try HTTPS first, fallback to HTTP
            https_url = 'https://' + target
            http_url = 'http://' + target
            
            if self.check_connectivity(https_url):
                target = https_url
            elif self.check_connectivity(http_url):
                target = http_url
            else:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Unable to connect to {target}")
                return None
        
        if not self.validate_url(target):
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Invalid URL: {target}")
            return None
        
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Validating target: {target}")
        
        # Check connectivity
        if not self.check_connectivity(target):
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Unable to connect to {target}")
            return None
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Target is accessible")
        
        # Start scanning
        start_time = time.time()
        all_findings = []
        
        # Scan common paths
        path_findings = self.scan_common_paths(target, verbose)
        all_findings.extend(path_findings)
        
        # Check security headers
        header_findings = self.check_security_headers(target, verbose)
        all_findings.extend(header_findings)
        
        # Check SSL configuration
        ssl_findings = self.check_ssl_configuration(target, verbose)
        all_findings.extend(ssl_findings)
        
        # Check server information disclosure
        server_findings = self.check_server_information(target, verbose)
        all_findings.extend(server_findings)
        
        scan_duration = time.time() - start_time
        
        # Display results
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Web scan completed in {scan_duration:.2f}s")
        
        if all_findings:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Found {len(all_findings)} potential issues")
            
            # Display findings by severity
            critical_findings = [f for f in all_findings if f.get('severity') == 'Critical']
            high_findings = [f for f in all_findings if f.get('severity') == 'High']
            medium_findings = [f for f in all_findings if f.get('severity') == 'Medium']
            low_findings = [f for f in all_findings if f.get('severity') == 'Low']
            
            if critical_findings or high_findings or medium_findings:
                print(f"\n{Fore.RED}WEB VULNERABILITY FINDINGS{Style.RESET_ALL}")
                print("=" * 35)
                
                for finding in critical_findings + high_findings + medium_findings:
                    severity_color = {
                        'Critical': Fore.RED,
                        'High': Fore.MAGENTA,
                        'Medium': Fore.YELLOW,
                        'Low': Fore.GREEN
                    }.get(finding.get('severity', 'Low'), Fore.WHITE)
                    
                    print(f"{severity_color}[{finding.get('severity', 'Low')}]{Style.RESET_ALL} {finding['type']}")
                    
                    # Show additional details based on finding type
                    if finding['type'] == 'Sensitive Path':
                        print(f"    URL: {finding['url']} (Status: {finding['status_code']})")
                    elif finding['type'] == 'Missing Security Headers':
                        print(f"    Missing: {', '.join(finding['missing_headers'][:3])}{'...' if len(finding['missing_headers']) > 3 else ''}")
                    elif finding['type'] == 'Weak SSL Cipher':
                        print(f"    Cipher: {finding['cipher']} ({finding['key_size']} bits)")
                    elif finding['type'] == 'Server Version Disclosure':
                        print(f"    Server: {finding['server_header']}")
        else:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No obvious vulnerabilities detected")
        
        # Prepare results
        results = {
            "scan_type": "web",
            "target": target,
            "scan_time": datetime.datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "findings": all_findings,
            "risk_level": self.calculate_risk_level(all_findings)
        }
        
        return results
    
    def calculate_risk_level(self, findings):
        """Calculate overall risk level based on findings"""
        if not findings:
            return "Low"
        
        severities = [f.get("severity", "Low") for f in findings]
        
        if "Critical" in severities:
            return "Critical"
        elif "High" in severities:
            return "High"
        elif "Medium" in severities:
            return "Medium"
        else:
            return "Low"