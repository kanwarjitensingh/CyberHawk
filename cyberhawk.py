#!/usr/bin/env python3
"""
CyberHawk - Network Security Scanner
Simple and effective network reconnaissance tool
"""

import argparse
import sys
import time
from colorama import Fore, Back, Style, init
from scanner_engine import NetworkScanner
from web_scanner import WebScanner
from report_generator import ReportGenerator

# Initialize colorama
init(autoreset=True)

class CyberHawk:
    def __init__(self):
        self.version = "2.1.0"
        self.author = "kanwarjitensingh"
        self.network_scanner = NetworkScanner()
        self.web_scanner = WebScanner()
        self.report_gen = ReportGenerator()
    
    def print_banner(self):
        """Display the tool banner"""
        banner = f"""
{Fore.CYAN}
    ▒███████╗▒██╗   ██╗████████╗ ███████╗██████╗ ██╗  ██╗ █████╗  ██╗      ██╗██╗  ██╗
    ██╔══███╗╚██╗ ██╔╝██╔═══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗ ██║  ██╗  ██║██║ ██╔╝
    ██║  ╚═╝ ╚████╔╝ ██████╦╝█████╗  ██████╔╝███████║███████║ ╚██╗ ████╗██╔╝████╝
    ██║  ██╗  ╚██╔╝  ██╔══██╗██╔══╝  ██╔═══██╗██╔══██║██╔═══██║  ██████╔╝ ████║  ██╔══██╗
    ╚███████║   ██║   ██████╦╝███████╗██║   ██║██║  ██║██║   ██║   ╚██╔╝ ╚██╔╝ ██║ ╚██╗
     ╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝    ╚═╝   ╚═╝  ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.RED}    ╔═════════════════════════════════════════════════════════════════════════════════╗
    ║           Advanced Network Security Scanner & Vulnerability Assessment            ║
    ╚═════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}    Version: {self.version}                    Author: {self.author}
    GitHub: https://github.com/cybersec/cyberhawk
    
    {Fore.GREEN}[+]{Style.RESET_ALL} Professional Network Reconnaissance Tool
    {Fore.GREEN}[+]{Style.RESET_ALL} Web Application Security Scanner  
    {Fore.GREEN}[+]{Style.RESET_ALL} Multi-threaded Scanning Engine
    {Fore.GREEN}[+]{Style.RESET_ALL} Comprehensive Reporting System
{Style.RESET_ALL}
"""
        print(banner)
    
    def print_help(self):
        """Display help information"""
        help_text = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗
                                CYBERHAWK USAGE GUIDE
╚═══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}NETWORK SCANNING:{Style.RESET_ALL}
    python cyberhawk.py --network -t <IP_ADDRESS> [options]
    
{Fore.YELLOW}WEB SCANNING:{Style.RESET_ALL}
    python cyberhawk.py --web -t <WEBSITE_URL> [options]

{Fore.YELLOW}TARGET SPECIFICATION:{Style.RESET_ALL}
    -t, --target        Target IP address or website URL
                        Network: 192.168.1.1, 10.0.0.1
                        Web: https://example.com, http://test.com

{Fore.YELLOW}SCANNING MODE:{Style.RESET_ALL}
    --network          Scan network/IP address for open ports
    --web              Scan website for web vulnerabilities
    
{Fore.YELLOW}OPTIONS:{Style.RESET_ALL}
    -p, --ports         Port range for network scan (default: common ports)
    -v, --verbose       Show detailed output
    -o, --output        Save results to file (JSON format)
    -h, --help          Show this help message

{Fore.YELLOW}EXAMPLES:{Style.RESET_ALL}
    {Fore.GREEN}# Scan network target{Style.RESET_ALL}
    python cyberhawk.py --network -t 192.168.1.1
    
    {Fore.GREEN}# Scan website{Style.RESET_ALL}
    python cyberhawk.py --web -t https://example.com
    
    {Fore.GREEN}# Network scan with custom ports{Style.RESET_ALL}
    python cyberhawk.py --network -t 10.0.0.1 -p 1-1000 -v
    
    {Fore.GREEN}# Web scan with output{Style.RESET_ALL}
    python cyberhawk.py --web -t https://testsite.com -o results.json

{Fore.RED}DISCLAIMER:{Style.RESET_ALL}
    This tool is for educational and authorized security testing purposes only.
    Users are responsible for complying with applicable laws and regulations.

{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}
"""
        print(help_text)
    
    def print_status(self, message):
        """Print status message"""
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

def main():
    parser = argparse.ArgumentParser(
        description="CyberHawk - Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    # Scanning mode (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--network", action="store_true",
                           help="Network/IP scanning mode")
    mode_group.add_argument("--web", action="store_true",
                           help="Web application scanning mode")
    
    # Target specification
    parser.add_argument("-t", "--target", required=True,
                       help="Target IP address or website URL")
    
    # Options
    parser.add_argument("-p", "--ports", default="common",
                       help="Port range for network scan (default: common)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Show detailed output")
    parser.add_argument("-o", "--output",
                       help="Save results to JSON file")
    parser.add_argument("-h", "--help", action="store_true",
                       help="Show help message")
    
    # Parse arguments
    if len(sys.argv) == 1:
        scanner = CyberHawk()
        scanner.print_banner()
        scanner.print_help()
        return
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = CyberHawk()
    
    # Show help if requested
    if args.help:
        scanner.print_banner()
        scanner.print_help()
        return
    
    # Show banner
    scanner.print_banner()
    
    # Show disclaimer
    print(f"\n{Fore.RED}[DISCLAIMER]{Style.RESET_ALL} This tool is for authorized security testing only.")
    print(f"{Fore.RED}[DISCLAIMER]{Style.RESET_ALL} Users must comply with applicable laws and regulations.")
    
    # Countdown
    for i in range(3, 0, -1):
        print(f"\r{Fore.YELLOW}[*]{Style.RESET_ALL} Starting scan in {i}...", end="", flush=True)
        time.sleep(1)
    print(f"\r{' ' * 30}\r", end="")
    
    try:
        results = None
        
        if args.network:
            # Network scanning
            scanner.print_status(f"Starting network scan on {args.target}")
            results = scanner.network_scanner.scan(args.target, args.ports, args.verbose)
            
        elif args.web:
            # Web scanning
            scanner.print_status(f"Starting web scan on {args.target}")
            results = scanner.web_scanner.scan(args.target, args.verbose)
        
        # Generate report if output specified
        if args.output and results:
            scanner.report_gen.generate_json_report(results, args.output)
            scanner.print_success(f"Report saved to: {args.output}")
        
        # Print summary
        if results:
            scanner.report_gen.print_summary(results)
            
    except KeyboardInterrupt:
        scanner.print_warning("Scan interrupted by user")
    except Exception as e:
        scanner.print_error(f"Scan error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
