🔍 ReconMaster
<div align="center">
https://img.shields.io/badge/version-1.2.0-blue.svg
https://img.shields.io/badge/python-3.7+-brightgreen.svg
https://img.shields.io/badge/license-MIT-orange.svg
https://img.shields.io/badge/platform-Kali%2520%257C%2520Termux-red.svg
https://img.shields.io/badge/status-beta-yellow.svg

Professional Bug Bounty Reconnaissance Tool

Created by Abdulbasid Yakubu | cy30rt

Multi-API intelligence gathering with Advanced Vulnerability Scanning for security researchers and bug bounty hunters

Features • Installation • Usage • Vulnerability Scanning • Examples

</div>
📋 Table of Contents
Overview

✨ Enhanced Features

Requirements

Installation

Configuration

Usage

Vulnerability Scanning

Risk Assessment

API Integration

Examples

Output

Troubleshooting

Contributing

Legal Disclaimer

Author

License

🎯 Overview
ReconMaster v1.2.0 is a powerful, professional-grade reconnaissance tool designed for bug bounty hunters and security researchers. It aggregates data from multiple threat intelligence and reconnaissance APIs to provide comprehensive information about targets in a single, streamlined workflow, now with Advanced Vulnerability Scanning.

NEW IN v1.2.0: Vulnerability Scanner Edition
This major update introduces a comprehensive vulnerability scanning module that performs automated security checks on discovered subdomains, providing risk assessment and prioritization.

✨ Enhanced Features
🔍 Intelligence Gathering Capabilities (Enhanced)
Network Intelligence

Open port discovery and service detection

Banner grabbing and service fingerprinting

Historical host data analysis

Vulnerability detection

Domain Intelligence

Comprehensive subdomain enumeration from 5+ sources

DNS history tracking and analysis

WHOIS information retrieval

Certificate transparency log searching (crt.sh)

Multi-source passive discovery

Geolocation Intelligence

Precise IP geolocation data

ASN and network information

Organization and ISP details

Network infrastructure mapping

Security Intelligence

Malware and threat analysis

Domain/IP reputation scoring

Security vendor consensus

Threat actor attribution

🛡️ NEW: Advanced Vulnerability Scanner Module
SSL/TLS Security Analysis
✅ Certificate validity and expiry checks

✅ Self-signed certificate detection

✅ Certificate chain validation

✅ Expiry date tracking with alerts

✅ Issuer and subject verification

Security Headers Analysis
✅ HSTS (Strict-Transport-Security) enforcement

✅ Clickjacking protection (X-Frame-Options)

✅ MIME sniffing prevention (X-Content-Type-Options)

✅ Content Security Policy (CSP) implementation

✅ XSS Protection header validation

✅ CORS configuration security analysis

Common Vulnerability Detection
✅ Clickjacking vulnerability scanning

✅ CORS misconfiguration detection

✅ Directory listing exposure checks

✅ Server information disclosure analysis

✅ Backup and configuration file exposure

✅ Default page and error disclosure

Sensitive File Exposure Detection
✅ Exposed .git directories and repositories

✅ Exposed .env configuration files with credentials

✅ Backup files (.zip, .sql, .bak, .tar.gz)

✅ Log files and debugging endpoints

✅ Admin panel and login page discovery

Subdomain Takeover Detection (9+ Services)
✅ GitHub Pages: "There isn't a GitHub Pages site here"

✅ Heroku: "No such app", "herokucdn.com"

✅ AWS S3: "NoSuchBucket", "The specified bucket does not exist"

✅ Azure: "404 Web Site not found", "azurewebsites.net"

✅ CloudFront: "Bad request", "ERROR: The request could not be satisfied"

✅ Shopify: "Sorry, this shop is currently unavailable"

✅ Tumblr: "Whatever you were looking for doesn't currently exist"

✅ WordPress: "Do you want to register"

✅ Fastly: "Fastly error: unknown domain"

📊 NEW: Professional Risk Assessment System
Automated Risk Scoring (0-100+ points)
🔴 CRITICAL (50+ points): Immediate action required

🟠 HIGH (30-49 points): High priority remediation

🟡 MEDIUM (15-29 points): Moderate risk

🟢 LOW (1-14 points): Low priority issues

✅ SECURE (0 points): No significant security issues found

Risk Weighting Algorithm
+50 points: Subdomain takeover possible

+35 points: Exposed .env file with credentials

+30 points: Exposed .git directory

+25 points: No HTTPS available

+25 points: Exposed backup files

+20 points: Invalid SSL certificate

+15 points: Expired SSL certificate

+15 points: CORS misconfiguration

+10 points: Self-signed SSL certificate

+10 points: Clickjacking vulnerability

+5 points: Missing security headers (each)

+5 points: Server information disclosure

🎨 Enhanced User Experience
Professional ASCII banner with author credits

Color-coded risk level indicators (🟢🟡🟠🔴)

Real-time vulnerability scanning progress

Emoji-based risk visualization

Interactive setup wizard

Auto-generated timestamped reports

Structured JSON vulnerability reports

Detailed scan summaries with statistics

🚀 Performance Enhancements
Multi-threaded DNS brute force (10 threads)

Concurrent vulnerability scanning

Intelligent rate limiting across all APIs

Configurable timeouts and retries

Session reuse for HTTP requests

Connection pooling optimization

Caching for repeated requests

📁 Enhanced Reporting & Export
Terminal output with color-coded risk levels

JSON export with comprehensive vulnerability data

Risk score calculation for each subdomain

Vulnerability categorization and prioritization

Remediation recommendations

Scan duration and statistics

📦 Requirements
System Requirements
Python: Version 3.7 or higher

Operating System: Linux (Kali, Ubuntu, Debian) or Termux (Android)

Internet: Active internet connection

Terminal: Terminal with ANSI color support

Memory: 2GB RAM recommended for large scans

Python Dependencies
requests >= 2.31.0

urllib3 >= 2.0.0

colorama >= 0.4.6 (optional, for enhanced colors)

API Requirements
You'll need API keys from the following services (all offer free tiers):

Shodan - Network intelligence and port scanning

SecurityTrails - Domain and DNS intelligence

IPInfo - Geolocation and network data

VirusTotal - Security and malware analysis

🚀 Installation
Quick Install (Linux/Termux)
bash
# Clone the repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip3 install requests urllib
# Run setup wizard for API keys
python3 recon_master.py --setup
Manual Installation
On Kali Linux / Ubuntu / Debian
bash
# Update system packages
sudo apt-get update

# Install Python and pip
sudo apt-get install python3 python3-pip git -y

# Clone repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip3 install -r requirements.txt

# Make script executable
chmod +x recon_master.py
On Termux (Android)
bash
# Update Termux packages
pkg update -y && pkg upgrade -y

# Install required packages
pkg install python git openssl-tool -y

# Clone repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip install requests urllib3

# Make script executable
chmod +x recon_master.py

# Optional: Add to PATH for easy access
cp recon_master.py $PREFIX/bin/reconmaster
chmod +x $PREFIX/bin/reconmaster

# Grant storage permissions
termux-setup-storage
⚙️ Configuration
Interactive Setup (Recommended)
Run the built-in setup wizard to configure your API keys:

bash
python3 recon_master.py --setup
Manual Configuration
Create or edit config.json in the tool directory:

json
{
    "shodan": "YOUR_SHODAN_API_KEY",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "ipinfo": "YOUR_IPINFO_API_KEY"
}
Getting API Keys (Free Tier)
Shodan: https://account.shodan.io/register

SecurityTrails: https://securitytrails.com/app/signup

IPInfo: https://ipinfo.io/signup

VirusTotal: https://www.virustotal.com/gui/join-us

📖 Usage
Basic Usage
bash
# Basic domain scan
python3 recon_master.py -t example.com

# Basic IP scan
python3 recon_master.py -t 8.8.8.8
Advanced Usage with New Features
bash
# Subdomain enumeration with vulnerability scanning
python3 recon_master.py -t example.com --enum-subs --scan-vulns

# Subdomain enumeration only (no API calls)
python3 recon_master.py --enum-only example.com

# Subdomain enumeration + vulnerability scan
python3 recon_master.py --enum-only example.com --scan-vulns

# Force specific scan type
python3 recon_master.py -t example.com --type domain
Command Line Options
Options:
  -h, --help            Show help message and exit
  -t TARGET, --target TARGET
                        Target domain or IP address
  --type {auto,ip,domain}
                        Target type (default: auto-detect)
  --setup               Run interactive setup wizard
  -o OUTPUT, --output OUTPUT
                        Custom output filename (optional)
  --enum-subs           Enable comprehensive subdomain enumeration
  --scan-vulns          Enable vulnerability scanning on discovered subdomains
  --enum-only DOMAIN    Run subdomain enumeration only (no other recon)
  -v, --version         Show version information
🛡️ Vulnerability Scanning
Scan Methodology
ReconMaster performs comprehensive security checks in multiple phases:

Phase 1: Service Discovery
HTTP/HTTPS accessibility verification

Port 80/443 availability checking

Redirect chain analysis

Server header and technology detection

Phase 2: SSL/TLS Analysis
Certificate validity and chain verification

Expiry date calculation and warnings

Self-signed certificate detection

Issuer and subject validation

Phase 3: Security Headers Check
Complete OWASP-recommended header validation

CSP policy analysis and recommendations

HSTS configuration verification

CORS security settings analysis

Phase 4: Content Security Analysis
Directory traversal and listing checks

Backup and configuration file detection

Source code and repository exposure

Admin interface and login page discovery

Phase 5: Takeover Vulnerability Analysis
Service-specific fingerprint matching

Error page content analysis

DNS record verification

Wildcard and CNAME record analysis

Scan Coverage
Vulnerability Type	Checks Performed	Risk Weight
SSL/TLS Issues	5 different checks	10-20 points
Security Headers	6 header validations	5 points each
File Exposure	8 file type detections	25-35 points
Configuration	5 config checks	5-15 points
Takeover	9 service fingerprints	50 points
📊 Risk Assessment
Risk Level Definitions
🔴 CRITICAL (50+ points)
Immediate attention required. Examples:

Subdomain takeover vulnerabilities

Exposed .env files with API keys/credentials

Critical SSL misconfigurations

Multiple high-risk vulnerabilities combined

🟠 HIGH (30-49 points)
High priority for remediation. Examples:

Exposed .git repositories

Multiple security headers missing

Expired SSL certificates

Self-signed certificates in production

🟡 MEDIUM (15-29 points)
Moderate risk requiring attention. Examples:

Clickjacking vulnerabilities

CORS misconfigurations

Server information disclosure

Mixed content issues

🟢 LOW (1-14 points)
Low priority security improvements. Examples:

Missing individual security headers

Minor configuration issues

Informational findings

✅ SECURE (0 points)
No significant security issues detected.

Scoring Examples
Subdomain with takeover vulnerability: 50+ points (CRITICAL)

Subdomain with exposed .env file: 35+ points (HIGH)

Subdomain with expired SSL + missing headers: 20+ points (MEDIUM)

Subdomain with only minor issues: 5-10 points (LOW)

Properly secured subdomain: 0 points (SECURE)

🔧 API Integration
Enhanced API Capabilities
API	Free Tier	Rate Limit	Enhanced Capabilities
Shodan	✅ Yes	Varies	Port scanning, service detection, vulnerabilities
SecurityTrails	✅ Yes	50/month	Subdomains, DNS records, WHOIS, historical data
IPInfo	✅ Yes	50k/month	Geolocation, ASN, organization, network data
VirusTotal	✅ Yes	4/minute	Enhanced security analysis with risk assessment
Passive Intelligence Sources (New)
crt.sh: Certificate transparency log searching

HackerTarget: Subdomain enumeration API

ThreatCrowd: Threat intelligence and subdomains

AlienVault OTX: Passive DNS data

URLScan.io: Recent scan results and subdomains

API Workflow
Target Analysis: Automatically detects IP vs Domain

API Selection: Chooses appropriate APIs based on target

Sequential Queries: Rate-limited API calls with delays

Data Aggregation: Combines results from all sources

Vulnerability Scanning: Security checks on discovered assets

Risk Assessment: Automated scoring and prioritization

Report Generation: Structured output and JSON export

💡 Examples
Example 1: Basic Domain Reconnaissance
bash
python3 recon_master.py -t example.com
Enhanced Output includes:

Domain information from SecurityTrails

Enhanced VirusTotal security analysis with risk assessment

Resolved IP information from Shodan

Geolocation data from IPInfo

Basic vulnerability assessment

Example 2: Comprehensive Subdomain Discovery
bash
python3 recon_master.py -t example.com --enum-subs
New Workflow:
Phase 1: Passive Discovery (5 sources)
  → crt.sh certificate transparency logs
  → HackerTarget API enumeration
  → ThreatCrowd threat intelligence
  → AlienVault OTX passive DNS
  → URLScan.io recent scans
  
Phase 2: Active DNS Brute Force
  → 100+ common subdomains wordlist
  → Multi-threaded DNS resolution (10 threads)
  → Active service and port detection
  
Phase 3: Results Aggregation
  → Deduplication across all sources
  → Source attribution tracking
  → Statistics and summary generation
Example 3: Full Security Assessment
bash
python3 recon_master.py -t example.com --enum-subs --scan-vulns
Complete Scan Process:

Intelligence Gathering: Multi-API reconnaissance

Asset Discovery: Comprehensive subdomain enumeration

Vulnerability Scanning: 25+ security checks per subdomain

Risk Assessment: Automated scoring and prioritization

Reporting: JSON export with detailed findings

Example 4: Focused Vulnerability Assessment
bash
python3 recon_master.py --enum-only example.com --scan-vulns
Perfect for:

Continuous security monitoring

Asset inventory and management

Quick security posture assessment

Pre-deployment security checks

Compliance and audit requirements

Example Output
═══════════════════════════════════════════════
  VULNERABILITY SCAN SUMMARY
═══════════════════════════════════════════════
🔴 Critical Risk: 2
🟠 High Risk: 3  
🟡 Medium Risk: 5
🟢 Low Risk: 8
✅ Secure: 22
═══════════════════════════════════════════════

Sample Findings:
  🔴 admin.example.com - Risk: CRITICAL (65 points)
      • Exposed .env File (+35)
      • Missing 3 Security Headers (+15)
      • Self-Signed SSL Certificate (+10)
      • Server Information Disclosure (+5)
  
  🟢 www.example.com - Risk: SECURE (0 points)
      • All security headers present
      • Valid SSL certificate
      • No vulnerabilities detected
📊 Output
Enhanced JSON Report Structure
json
{
  "target": "example.com",
  "timestamp": "2024-01-15T14:30:22.123456",
  "scan_type": "full",
  "subdomain_enum": {
    "total_found": 42,
    "sources": {
      "crtsh": ["sub1.example.com", "sub2.example.com"],
      "hackertarget": ["www.example.com"],
      "threatcrowd": ["api.example.com"],
      "alienvault": ["dev.example.com"],
      "urlscan": ["test.example.com"],
      "dns_brute_force": ["admin.example.com", "mail.example.com"]
    },
    "vulnerability_scans": [
      {
        "subdomain": "admin.example.com",
        "accessible": true,
        "risk_level": "CRITICAL",
        "risk_score": 65,
        "issues_found": [
          "Exposed .env File",
          "Missing 3 Security Headers",
          "Self-Signed SSL Certificate",
          "Server Information Disclosure"
        ],
        "http_info": {
          "http": true,
          "https": true,
          "http_status": 200,
          "redirects_to_https": true
        },
        "ssl_info": {
          "valid": false,
          "expired": false,
          "self_signed": true,
          "issuer": "Self-Signed",
          "subject": "admin.example.com",
          "expiry_date": "2024-12-31T23:59:59",
          "days_until_expiry": 350
        },
        "vulnerabilities": {
          "missing_security_headers": ["HSTS", "CSP", "X-Frame-Options"],
          "clickjacking_vulnerable": true,
          "cors_misconfiguration": false,
          "directory_listing": false,
          "exposed_git": false,
          "exposed_env": true,
          "exposed_backup": false,
          "server_info_disclosure": true,
          "server_header": "Apache/2.4.41"
        },
        "takeover_check": {
          "vulnerable": false,
          "service": null,
          "fingerprint": null
        }
      }
    ]
  },
  "apis_used": 4,
  "scan_duration_seconds": 215.7,
  "total_vulnerabilities_found": 18,
  "risk_distribution": {
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 8,
    "secure": 24
  }
}
File Naming Convention
recon_TARGET_TIMESTAMP.json
Example: recon_example_com_20240115_143022.json

subdomains_DOMAIN_TIMESTAMP.json  
Example: subdomains_example_com_20240115_143022.json
Termux Output Location
Default: /storage/emulated/0/recon_*.json

Home directory: ~/recon_*.json

Current directory: ./recon_*.json

🐛 Troubleshooting
Common Issues & Solutions
Issue: "Module not found" errors
bash
# Solution: Install dependencies
pip3 install requests urllib3
# or for Termux
pip install requests urllib3
Issue: API key errors
bash
# Run setup wizard
python3 recon_master.py --setup

# Or manually configure
nano config.json
Issue: SSL certificate errors (Termux)
bash
pkg install openssl-tool
Issue: Permission denied
bash
chmod +x recon_master.py
Issue: Rate limit exceeded
Wait for rate limit reset

Use fewer simultaneous scans

Consider API plan upgrades

Implement custom delays

Issue: Vulnerability scan timeouts
Reduce concurrent scans

Increase timeout values

Check network connectivity

Verify target accessibility

Debug Mode
For detailed troubleshooting:

bash
# Check Python version
python3 --version

# Verify dependencies
pip3 list | grep -E "requests|urllib3"

# Test basic connectivity
curl -I https://google.com

# Check config file
cat config.json

# Test with verbose output
python3 -c "import requests; print('Requests version:', requests.__version__)"
🤝 Contributing
How to Contribute
Fork the repository

Create a feature branch: git checkout -b feature/AmazingFeature

Commit your changes: git commit -m 'Add some AmazingFeature'

Push to the branch: git push origin feature/AmazingFeature

Open a Pull Request

Development Guidelines
Follow PEP 8 Python style guidelines

Add comprehensive comments for complex logic

Update documentation for new features

Test on both Kali Linux and Termux

Ensure backward compatibility

Add error handling for new features

Areas for Contribution
Additional vulnerability checks

Performance optimizations

New API integrations

GUI implementation

Docker containerization

Additional reconnaissance modules

Enhanced reporting formats

⚖️ Legal Disclaimer
IMPORTANT: READ CAREFULLY BEFORE USING THIS TOOL
Terms of Use
This tool is provided for educational and authorized security testing purposes only.

✅ Permitted Uses
Testing systems you own or have explicit written permission to test

Authorized penetration testing engagements

Bug bounty programs with explicit scope permission

Educational and research purposes

Security awareness training

❌ Prohibited Uses
Unauthorized access to computer systems

Violating laws or regulations

Disrupting services or networks

Malicious activities

Privacy violations

Legal Compliance
By using this tool, you agree to:

Obtain proper authorization before scanning

Comply with all applicable laws

Respect API terms of service and rate limits

Follow responsible disclosure practices

Accept full responsibility for your actions

No Warranty
This software is provided "as is" without warranty of any kind. The author assumes no liability for damages resulting from use of this tool.

Responsible Disclosure
If you discover vulnerabilities using this tool:

Do not exploit or share them publicly

Report them to the appropriate security team

Follow the organization's disclosure policy

Allow reasonable time for remediation

Respect bug bounty program rules

👤 Author
Abdulbasid Yakubu | cy30rt

Professional Bug Bounty Hunter & Security Researcher

This tool was created to streamline the reconnaissance phase of bug bounty hunting and security assessments. Version 1.2.0 introduces comprehensive vulnerability scanning capabilities to provide end-to-end security assessment.

Connect
GitHub: @abdulcybort

Twitter: @cy30rt

Professional: Bug Bounty platforms and security communities

Acknowledgments
Special thanks to:

The bug bounty community for inspiration and feedback

API providers (Shodan, SecurityTrails, IPInfo, VirusTotal) for their excellent services

Beta testers who helped refine the vulnerability scanning features

Open source contributors and maintainers

Security researchers sharing knowledge and techniques

📄 License
This project is licensed under the MIT License.
MIT License

Copyright (c) 2024 Abdulbasid Yakubu | cy30rt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
📞 Support & Contact
Getting Help
GitHub Issues: Report bugs or request features

Documentation: This README serves as comprehensive documentation

Community: Security forums and bug bounty communities

Reporting Bugs
When reporting bugs, please include:

Python Version: python3 --version or python --version

Operating System: Kali Linux, Termux (Android), Ubuntu, etc.

Complete Error Message: Copy-paste the full error traceback

Steps to Reproduce: Exact commands and inputs used

Expected vs Actual Behavior: What you expected vs what happened

Feature Requests
When requesting features, please:

Describe the use case and benefits

Suggest implementation approach

Reference similar tools if applicable

Consider backward compatibility

📈 Roadmap
🚀 Planned Features (v1.3.0+)
Additional Vulnerability Checks

SQL injection detection

XSS vulnerability scanning

Open redirect detection

SSRF vulnerability checks

Enhanced API Integrations

Censys integration

Hunter.io email enumeration

BuiltWith technology detection

BinaryEdge threat intelligence

Performance Improvements

Parallel scanning optimization

Result caching system

Distributed scanning capabilities

Reporting Enhancements

HTML report generation

PDF executive summaries

Dashboard visualization

Trend analysis

Usability Features

Web interface

API endpoint for automation

Scheduled scanning

Team collaboration features

📋 Version History
v1.0.0: Initial release with core API integration

v1.1.0: Enhanced error handling and performance

v1.2.0: Vulnerability Scanner Edition (Current)

Advanced vulnerability scanning module

Risk assessment and scoring system

Multiple passive intelligence sources

Comprehensive security checks

v1.3.0 (Planned): Additional vulnerability checks and performance

v2.0.0 (Future): Major rewrite with advanced features

<div align="center">
Made with ❤️ by Abdulbasid Yakubu | cy30rt

For Bug Bounty Hunters, By a Bug Bounty Hunter

Version 1.2.0 - Vulnerability Scanner Edition

⭐ If you find this tool useful, please give it a star on GitHub! ⭐

Happy Hunting & Stay Secure! 🎯🔒

</div>
