#!/usr/bin/env python3
"""
Network Scanner Engine
Handles port scanning and network reconnaissance
"""

import socket
import threading
import time
import datetime
from colorama import Fore, Style

class NetworkScanner:
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900]
        self.port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 
            5432: "PostgreSQL", 5900: "VNC"
        }
        
        # Vulnerability database - simplified for interview explanation
        self.vulnerabilities = {
            21: {"service": "FTP", "risks": ["Anonymous login", "Weak credentials", "Unencrypted data"]},
            22: {"service": "SSH", "risks": ["Brute force attacks", "Weak passwords", "Key-based attacks"]},
            23: {"service": "Telnet", "risks": ["Unencrypted protocol", "Credential sniffing", "Man-in-the-middle"]},
            80: {"service": "HTTP", "risks": ["Web vulnerabilities", "Information disclosure", "XSS/SQLi"]},
            443: {"service": "HTTPS", "risks": ["SSL/TLS issues", "Certificate problems", "Weak ciphers"]},
            3389: {"service": "RDP", "risks": ["BlueKeep vulnerability", "Brute force", "Session hijacking"]},
            3306: {"service": "MySQL", "risks": ["Weak root password", "SQL injection", "Remote access"]},
            1433: {"service": "MSSQL", "risks": ["SA account attacks", "SQL injection", "xp_cmdshell abuse"]}
        }
        
        self.results = {}
        self.open_ports = []
        
    def validate_target(self, target):
        """Validate if target is reachable"""
        try:
            socket.inet_aton(target)  # Check if valid IP
            return True
        except socket.error:
            try:
                socket.gethostbyname(target)  # Try to resolve hostname
                return True
            except socket.gaierror:
                return False
    
    def scan_port(self, target, port, timeout=3):
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                return result == 0  # 0 means connection successful
        except Exception:
            return False
    
    def threaded_scan(self, target, ports, verbose=False):
        """Multi-threaded port scanning"""
        open_ports = []
        threads = []
        lock = threading.Lock()
        
        def scan_worker(port):
            if self.scan_port(target, port):
                with lock:
                    open_ports.append(port)
                    service = self.port_services.get(port, "Unknown")
                    if verbose:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Port {port}/tcp open - {service}")
        
        # Create and start threads
        for port in ports:
            thread = threading.Thread(target=scan_worker, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        return sorted(open_ports)
    
    def get_port_list(self, port_range):
        """Get list of ports to scan"""
        if port_range == "common":
            return self.common_ports
        elif port_range == "all":
            return list(range(1, 65536))
        elif "-" in port_range:
            start, end = map(int, port_range.split("-"))
            return list(range(start, end + 1))
        elif "," in port_range:
            return [int(p.strip()) for p in port_range.split(",")]
        else:
            return [int(port_range)]
    
    def assess_vulnerabilities(self, open_ports):
        """Assess potential vulnerabilities for open ports"""
        vulnerabilities = []
        
        for port in open_ports:
            if port in self.vulnerabilities:
                vuln_info = self.vulnerabilities[port]
                for risk in vuln_info["risks"]:
                    severity = self.determine_severity(port, risk)
                    vulnerabilities.append({
                        "port": port,
                        "service": vuln_info["service"],
                        "vulnerability": risk,
                        "severity": severity
                    })
        
        return vulnerabilities
    
    def determine_severity(self, port, risk):
        """Determine vulnerability severity"""
        # High-risk conditions
        if port in [23, 21] or "unencrypted" in risk.lower():
            return "High"
        elif "brute force" in risk.lower() or "weak password" in risk.lower():
            return "Medium"
        elif "bluekeep" in risk.lower() or "injection" in risk.lower():
            return "Critical"
        else:
            return "Low"
    
    def scan(self, target, port_range="common", verbose=False):
        """Main scanning function"""
        # Validate target
        if not self.validate_target(target):
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Invalid target: {target}")
            return None
        
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Validating target: {target}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Target is reachable")
        
        # Get ports to scan
        ports = self.get_port_list(port_range)
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Scanning {len(ports)} ports...")
        
        # Show scanning animation
        def animate():
            chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            for char in chars:
                print(f"\r{Fore.CYAN}[{char}]{Style.RESET_ALL} Scanning in progress... ", end="", flush=True)
                time.sleep(0.1)
        
        # Start scanning
        start_time = time.time()
        open_ports = self.threaded_scan(target, ports, verbose)
        scan_duration = time.time() - start_time
        
        print(f"\r{' ' * 50}\r", end="")  # Clear animation line
        
        # Process results
        if open_ports:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Scan completed in {scan_duration:.2f}s")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {len(open_ports)} open ports")
            
            # Display results
            print(f"\n{Fore.YELLOW}{'Port':<8} {'State':<10} {'Service':<15}{Style.RESET_ALL}")
            print("=" * 40)
            
            for port in open_ports:
                service = self.port_services.get(port, "Unknown")
                # Color code based on risk
                if port in [21, 23, 3389]:  # High risk
                    color = Fore.RED
                elif port in [22, 80, 443]:  # Medium risk
                    color = Fore.YELLOW
                else:  # Low risk
                    color = Fore.GREEN
                
                print(f"{color}{port:<8} {'open':<10} {service:<15}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No open ports found")
        
        # Vulnerability assessment
        vulnerabilities = self.assess_vulnerabilities(open_ports)
        
        if vulnerabilities:
            print(f"\n{Fore.RED}VULNERABILITY ASSESSMENT{Style.RESET_ALL}")
            print("=" * 30)
            
            for vuln in vulnerabilities:
                severity_color = {
                    'Critical': Fore.RED,
                    'High': Fore.MAGENTA,
                    'Medium': Fore.YELLOW,
                    'Low': Fore.GREEN
                }.get(vuln['severity'], Fore.WHITE)
                
                print(f"{severity_color}[{vuln['severity']}]{Style.RESET_ALL} "
                      f"Port {vuln['port']} ({vuln['service']}): {vuln['vulnerability']}")
        
        # Prepare results
        results = {
            "scan_type": "network",
            "target": target,
            "scan_time": datetime.datetime.now().isoformat(),
            "scan_duration": scan_duration,
            "ports_scanned": len(ports),
            "open_ports": [
                {
                    "port": port,
                    "service": self.port_services.get(port, "Unknown"),
                    "state": "open"
                } for port in open_ports
            ],
            "vulnerabilities": vulnerabilities,
            "risk_level": self.calculate_risk_level(vulnerabilities)
        }
        
        return results
    
    def calculate_risk_level(self, vulnerabilities):
        """Calculate overall risk level"""
        if not vulnerabilities:
            return "Low"
        
        severities = [v["severity"] for v in vulnerabilities]
        
        if "Critical" in severities:
            return "Critical"
        elif "High" in severities:
            return "High"
        elif "Medium" in severities:
            return "Medium"
        else:
            return "Low"