# 🦅 CyberHawk - Network Security Scanner

**Professional Network Reconnaissance & Web Vulnerability Assessment Tool**

CyberHawk is a Python-based network security scanner designed for penetration testers, security researchers, and cybersecurity professionals. It provides separate scanning modes for network infrastructure and web applications, making it perfect for comprehensive security assessments.

## ✨ Features

- **🔍 Network Port Scanning** - Fast and reliable port discovery
- **🌐 Web Application Scanning** - Basic web vulnerability detection  
- **🛡️ Vulnerability Assessment** - Risk-based vulnerability analysis
- **📊 Professional Reporting** - JSON format reports
- **🎨 Modern CLI Interface** - Colorful, user-friendly command-line
- **⚡ Multi-threading** - High-performance concurrent scanning
- **🔒 SSL/TLS Analysis** - Certificate and security configuration checks

## 🚀 Installation

### Prerequisites

**Kali Linux 2024.x/2025.x** (Recommended):
```bash
# Python 3 is pre-installed on Kali Linux
# Create virtual environment (required for Kali 2024+)
python3 -m venv cyberhawk-env
source cyberhawk-env/bin/activate

# Verify Python version (should be 3.9+)
python3 --version
```

**Ubuntu 22.04/24.04**:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**Windows 11**:
1. Install Python 3.9+ from [python.org](https://python.org)
2. Add Python to system PATH during installation
3. Open Command Prompt or PowerShell as Administrator

### Install CyberHawk

**For Kali Linux (2024/2025)**:
```bash
# Clone the repository
git clone https://github.com/kanwarjitensingh/cyberhawk.git
cd cyberhawk

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python cyberhawk.py -h
```

**For Other Linux Distributions**:
```bash
# Clone repository
git clone https://github.com/kanwarjitensingh/cyberhawk.git
cd cyberhawk

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x cyberhawk.py

# Test installation
python3 cyberhawk.py -h
```

**For Windows**:
```cmd
# Clone repository
git clone https://github.com/kanwarjitensingh/cyberhawk.git
cd cyberhawk

# Install dependencies
pip install -r requirements.txt

# Test installation
python cyberhawk.py -h
```

## 🎯 Usage Examples

### Network Scanning (IP Addresses)
```bash
# Activate virtual environment first (Kali 2024+)
source venv/bin/activate

# Basic network scan
python cyberhawk.py --network -t 192.168.1.1

# Scan with verbose output
python cyberhawk.py --network -t 10.0.0.1 -v

# Custom port range scan
python cyberhawk.py --network -t 192.168.1.100 -p 1-1000 -v

# Save results to file
python cyberhawk.py --network -t 172.16.0.1 -v -o network_scan.json
```

### Web Application Scanning (Websites)
```bash
# Basic web scan
python cyberhawk.py --web -t https://example.com

# Scan with detailed output
python cyberhawk.py --web -t https://testsite.com -v

# Web scan with report generation
python cyberhawk.py --web -t http://vulnerable-site.com -v -o web_scan.json

# Scan website without HTTPS
python cyberhawk.py --web -t example.com -v
```

## 📋 Command-Line Options

```
SCANNING MODES (choose one):
  --network             Scan network/IP address for open ports
  --web                 Scan website for web vulnerabilities

REQUIRED:
  -t, --target          Target IP address (network) or URL (web)

OPTIONS:
  -p, --ports           Port range for network scan (default: common)
                        Examples: common, 1-1000, 80,443,8080
  -v, --verbose         Show detailed scanning output
  -o, --output          Save results to JSON file
  -h, --help            Show help message

EXAMPLES:
  Network Scanning:
    python cyberhawk.py --network -t 192.168.1.1
    python cyberhawk.py --network -t 10.0.0.1 -p 1-5000 -v -o results.json
    
  Web Scanning:
    python cyberhawk.py --web -t https://example.com
    python cyberhawk.py --web -t testsite.com -v -o web_report.json
```

## 📁 Project Structure

```
cyberhawk/
├── cyberhawk.py          # Main application entry point
├── scanner_engine.py     # Network port scanning module
├── web_scanner.py        # Web application scanning module
├── report_generator.py   # Report generation and display
├── requirements.txt      # Python dependencies
├── README.md            # This file
└── venv/               # Virtual environment (created during setup)
```

## 🔧 How It Works (Interview Explanation)

### Network Scanner (`scanner_engine.py`)
1. **Target Validation**: Checks if IP is valid and reachable
2. **Port Selection**: Uses common ports or custom range
3. **Multi-threaded Scanning**: Creates threads for concurrent port checking
4. **Socket Connection**: Attempts TCP connection to each port
5. **Vulnerability Mapping**: Maps open ports to known vulnerabilities
6. **Risk Assessment**: Categorizes findings by severity level

### Web Scanner (`web_scanner.py`)
1. **URL Validation**: Ensures proper URL format and connectivity
2. **Path Discovery**: Checks for sensitive files/directories
3. **Header Analysis**: Examines security headers and server info
4. **SSL/TLS Testing**: Validates certificate and cipher strength
5. **Finding Classification**: Categorizes issues by security impact

### Key Interview Points:
- **Separation of Concerns**: Each module handles specific functionality
- **Error Handling**: Graceful handling of network timeouts and errors
- **Threading**: Efficient concurrent scanning without overwhelming targets
- **Practical Security**: Real-world vulnerability detection and reporting

## 📊 Sample Output

### Network Scan Results:
```
[*] Validating target: 192.168.1.1
[+] Target is reachable
[*] Scanning 16 ports...
[+] Scan completed in 2.45s
[+] Found 3 open ports

Port     State      Service        
========================================
22       open       SSH            
80       open       HTTP           
443      open       HTTPS          

VULNERABILITY ASSESSMENT
==============================
[Medium] Port 22 (SSH): Brute force attacks
[Medium] Port 80 (HTTP): Web vulnerabilities
[Low] Port 443 (HTTPS): SSL/TLS issues
```

### Web Scan Results:
```
[*] Validating target: https://example.com
[+] Target is accessible
[*] Scanning for sensitive files and directories...
[*] Analyzing security headers...
[*] Analyzing SSL/TLS configuration...
[+] Web scan completed in 8.32s

WEB VULNERABILITY FINDINGS
===================================
[Medium] Missing Security Headers
    Missing: X-Frame-Options, X-XSS-Protection, CSP
[Low] Server Version Disclosure
    Server: Apache/2.4.41 (Ubuntu)
```

## ⚠️ Important Notes for Kali Linux 2024+

**Virtual Environment Requirement**:
```bash
# Always activate virtual environment before running
source venv/bin/activate

# To deactivate when done
deactivate
```

**Why Virtual Environment?**:
- Kali Linux 2024+ enforces PEP 668 (externally managed environments)
- Prevents conflicts with system Python packages
- Required for pip installations outside system package manager

## 🛡️ Legal Disclaimer

**⚠️ CRITICAL: Use this tool only on networks and systems you own or have explicit written permission to test.**

- This tool is designed for **authorized security testing** and **educational purposes** only
- Unauthorized scanning may violate computer crime laws in your jurisdiction
- Users are solely responsible for complying with all applicable laws and regulations
- The authors assume **no liability** for misuse of this tool

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add NewFeature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **GitHub Repository**: https://github.com/kanwarjitensingh/cyberhawk
- **Bug Reports**: https://github.com/kanwarjitensingh/cyberhawk/issues


*"Professional security testing made simple."*
