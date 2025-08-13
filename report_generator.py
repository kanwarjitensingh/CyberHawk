#!/usr/bin/env python3
"""
Report Generator
Handles result reporting and summary display
"""

import json
import datetime
from colorama import Fore, Style

class ReportGenerator:
    def __init__(self):
        pass
    
    def print_summary(self, results):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'╔' * 60}")
        print(f"                    SCAN SUMMARY")
        print(f"{'╚' * 60}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Target: {results['target']}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Scan Type: {results['scan_type'].upper()}")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Duration: {results['scan_duration']:.2f}s")
        
        if results['scan_type'] == 'network':
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Ports Scanned: {results['ports_scanned']}")
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Open Ports: {len(results['open_ports'])}")
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Vulnerabilities: {len(results.get('vulnerabilities', []))}")
            
            if results['open_ports']:
                print(f"\n{Fore.YELLOW}OPEN PORTS:{Style.RESET_ALL}")
                for port_info in results['open_ports']:
                    print(f"  • Port {port_info['port']}: {port_info['service']}")
        
        elif results['scan_type'] == 'web':
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Issues Found: {len(results.get('findings', []))}")
            
            if results.get('findings'):
                # Group findings by severity
                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                for finding in results['findings']:
                    severity = finding.get('severity', 'Low')
                    severity_counts[severity] += 1
                
                print(f"\n{Fore.YELLOW}FINDINGS BREAKDOWN:{Style.RESET_ALL}")
                if severity_counts['Critical']:
                    print(f"  {Fore.RED}• Critical: {severity_counts['Critical']}{Style.RESET_ALL}")
                if severity_counts['High']:
                    print(f"  {Fore.MAGENTA}• High: {severity_counts['High']}{Style.RESET_ALL}")
                if severity_counts['Medium']:
                    print(f"  {Fore.YELLOW}• Medium: {severity_counts['Medium']}{Style.RESET_ALL}")
                if severity_counts['Low']:
                    print(f"  {Fore.GREEN}• Low: {severity_counts['Low']}{Style.RESET_ALL}")
        
        # Risk assessment
        risk_level = results.get('risk_level', 'Low')
        risk_color = {
            'Critical': Fore.RED,
            'High': Fore.MAGENTA,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN
        }.get(risk_level, Fore.GREEN)
        
        print(f"\n{risk_color}[RISK LEVEL]{Style.RESET_ALL} Overall Risk: {risk_color}{risk_level}{Style.RESET_ALL}")
        
        # Recommendations
        self.print_recommendations(results)
        
        print(f"{Fore.CYAN}{'╚' * 60}{Style.RESET_ALL}")
    
    def print_recommendations(self, results):
        """Print security recommendations"""
        print(f"\n{Fore.BLUE}SECURITY RECOMMENDATIONS:{Style.RESET_ALL}")
        
        if results['scan_type'] == 'network':
            recommendations = [
                "Close unnecessary ports and services",
                "Implement strong authentication mechanisms",
                "Keep services updated with latest patches",
                "Configure proper firewall rules",
                "Monitor network traffic regularly"
            ]
            
            # Add specific recommendations based on findings
            if any(port['port'] == 23 for port in results.get('open_ports', [])):
                recommendations.insert(0, "⚠️  URGENT: Disable Telnet service (unencrypted)")
            if any(port['port'] == 21 for port in results.get('open_ports', [])):
                recommendations.insert(0, "⚠️  Consider using SFTP instead of FTP")
            if any(port['port'] == 3389 for port in results.get('open_ports', [])):
                recommendations.insert(0, "⚠️  Secure RDP with strong passwords and NLA")
        
        elif results['scan_type'] == 'web':
            recommendations = [
                "Implement all missing security headers",
                "Remove sensitive files from web root",
                "Hide server version information",
                "Use HTTPS with strong SSL/TLS configuration",
                "Regular security audits and updates"
            ]
            
            # Add specific recommendations based on findings
            findings = results.get('findings', [])
            if any(f['type'] == 'Insecure Protocol' for f in findings):
                recommendations.insert(0, "🔒 URGENT: Implement HTTPS encryption")
            if any(f['type'] == 'Weak SSL Cipher' for f in findings):
                recommendations.insert(0, "🔒 Update SSL/TLS configuration")
        
        for i, rec in enumerate(recommendations[:5], 1):  # Show top 5
            print(f"  {i}. {rec}")
    
    def generate_json_report(self, results, filename):
        """Generate JSON report"""
        try:
            # Add metadata
            report_data = {
                "report_metadata": {
                    "generated_by": "CyberHawk v2.1.0",
                    "generated_at": datetime.datetime.now().isoformat(),
                    "report_format": "JSON"
                },
                "scan_results": results
            }
            
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Error generating report: {str(e)}")
            return False