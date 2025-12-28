ReconMaster 🎯
https://img.shields.io/badge/python-3.7+-blue.svg
https://img.shields.io/badge/license-MIT-green.svg
https://img.shields.io/github/v/release/cy30rt/ReconMaster?include_prereleases
https://img.shields.io/badge/status-beta-yellow
https://img.shields.io/github/stars/cy30rt/ReconMaster.svg
https://img.shields.io/github/issues/cy30rt/ReconMaster.svg
https://img.shields.io/badge/PRs-welcome-brightgreen.svg

Professional Bug Bounty Reconnaissance Tool with Advanced Vulnerability Scanning - Currently in Beta Testing Phase 🔧

<div align="center">
Created by Abdulbasid Yakubu | cy30rt

https://img.shields.io/badge/Kali_Linux-557C94?logo=kali-linux&logoColor=white
https://img.shields.io/badge/Termux-000000?logo=android&logoColor=white

Multi-API Intelligence Gathering + Vulnerability Scanning for Security Researchers

Features • Installation • Quick Start • Vulnerability Scanning • Examples

</div>
⚠️ BETA RELEASE NOTICE
ReconMaster v1.2.0-beta is currently in testing phase. Some features are experimental and may contain bugs. Please report any issues here.

📋 Table of Contents
Overview

✨ Features

📦 Installation

🚀 Quick Start

⚙️ Configuration

🛡️ Vulnerability Scanning

📊 Risk Assessment

📁 Output & Reporting

💡 Usage Examples

🎯 Command Line Reference

🔧 API Integration

🧪 Beta Testing Guidelines

🐛 Troubleshooting

🤝 Contributing

⚖️ Legal Disclaimer

👤 Author

📄 License

📞 Support

🎯 Overview
ReconMaster is a powerful, professional-grade reconnaissance tool designed for bug bounty hunters and security researchers. It combines multi-source intelligence gathering with advanced vulnerability scanning to provide comprehensive security assessments in a single, streamlined workflow.

Why Choose ReconMaster?
🔍 All-in-One Solution: Combines reconnaissance + vulnerability scanning

🌐 Multi-Source Intelligence: 9+ data sources and APIs

🛡️ Automated Security Checks: 25+ vulnerability detection modules

📊 Professional Risk Assessment: Color-coded scoring and prioritization

🚀 Cross-Platform: Works on Kali Linux and Termux (Android)

📁 Structured Reporting: JSON exports for further analysis

⚡ Performance Optimized: Multi-threading and rate limiting

🔧 Extensible Architecture: Modular design for easy expansion

✨ Features
🔍 Intelligence Gathering Suite
Category	Features	Data Sources
Network Intelligence	Port scanning, Service detection, Banner grabbing, Historical data	Shodan, Censys (planned)
Domain Intelligence	Subdomain enumeration, DNS records, WHOIS data, Certificate transparency	SecurityTrails, crt.sh, HackerTarget
Security Intelligence	Threat analysis, Reputation scoring, Malware detection, Vendor consensus	VirusTotal, ThreatCrowd, AlienVault
Geolocation Intelligence	IP geolocation, ASN data, Organization mapping, Network infrastructure	IPInfo, URLScan
🛡️ Advanced Vulnerability Scanner (New in v1.2.0)
SSL/TLS Security
✅ Certificate validity and expiry checks

✅ Self-signed certificate detection

✅ Certificate chain validation

✅ Expiry date tracking with alerts

✅ Issuer and subject verification

Security Headers Analysis
✅ HSTS (Strict-Transport-Security)

✅ Clickjacking protection (X-Frame-Options)

✅ MIME sniffing prevention (X-Content-Type-Options)

✅ Content Security Policy (CSP)

✅ XSS Protection header

✅ CORS configuration analysis

Common Vulnerabilities
✅ Clickjacking vulnerability detection

✅ CORS misconfiguration scanning

✅ Directory listing exposure

✅ Server information disclosure

✅ Backup and config file exposure

✅ Default credential checks (planned)

Sensitive File Detection
✅ Exposed .git directories

✅ Exposed .env configuration files

✅ Backup files (.zip, .sql, .bak)

✅ Log files and debugging endpoints

✅ Admin panel and login pages

Subdomain Takeover Detection
✅ GitHub Pages: There isn't a GitHub Pages site here

✅ Heroku: No such app, herokucdn.com

✅ AWS S3: NoSuchBucket, The specified bucket does not exist

✅ Azure: 404 Web Site not found, azurewebsites.net

✅ CloudFront: Bad request, ERROR: The request could not be satisfied

✅ Shopify: Sorry, this shop is currently unavailable

✅ Tumblr: Whatever you were looking for doesn't currently exist

✅ WordPress: Do you want to register

✅ Fastly: Fastly error: unknown domain

📊 Professional Risk Assessment System
Risk Scoring (0-100+)
Critical (50+): Immediate action required

High (30-49): High priority remediation

Medium (15-29): Moderate risk

Low (1-14): Low priority issues

Secure (0): No significant issues found

Risk Weighting
+50 points: Subdomain takeover possible

+35 points: Exposed .env file

+30 points: Exposed .git directory

+25 points: No HTTPS available

+25 points: Exposed backup files

+20 points: Invalid SSL certificate

+15 points: Expired SSL certificate

+15 points: CORS misconfiguration

+10 points: Self-signed SSL certificate

+10 points: Clickjacking vulnerable

+5 points: Missing security headers (each)

+5 points: Server information disclosure

🎨 User Experience Features
Visual Interface
Professional ASCII banner with author credits

Color-coded terminal output (GREEN/YELLOW/RED)

Real-time progress indicators

Emoji-based risk level indicators

Multi-phase scan visualization

Detailed summary statistics

Interactive Features
Setup wizard for API configuration

Interactive command line interface

Progress bars for long operations

Error handling with recovery options

Keyboard interrupt handling

Performance Features
Multi-threaded DNS brute force (10 threads)

Concurrent API requests with rate limiting

Intelligent caching where possible

Configurable timeouts

Graceful degradation on API failures

📁 Reporting & Export
Output Formats
Terminal Output: Color-coded, human-readable

JSON Export: Structured data for automation

Timestamped Files: Automatic organization

Summary Reports: Executive overview

Report Contents
Complete scan configuration

All discovered subdomains with sources

Vulnerability scan results per subdomain

Risk scores and levels

Recommendations and remediation steps

Raw API responses (where applicable)

🔧 Technical Architecture
Core Modules
Config Manager: API key management and persistence

Vulnerability Scanner: Multi-layer security checks

Subdomain Enumerator: Hybrid passive/active discovery

API Handlers: Modular integration with external services

Risk Calculator: Automated scoring and prioritization

Performance Optimizations
Thread pool for DNS resolution

Session reuse for HTTP requests

Intelligent rate limiting

Connection pooling

Timeout management

Error recovery and retry logic

📦 Installation
Quick Installation (Linux/Termux)
bash
# Clone the repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install dependencies
pip3 install -r requirements.txt

# Run setup wizard
python3 recon_master.py --setup
Detailed Installation
On Kali Linux / Ubuntu / Debian
bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip git -y

# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip3 install requests urllib3

# Make script executable
chmod +x recon_master.py

# Verify installation
python3 recon_master.py --version
On Termux (Android)
bash
# Update Termux
pkg update && pkg upgrade -y

# Install required packages
pkg install python git openssl-tool -y

# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
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
Requirements File
requirements.txt:

txt
requests>=2.31.0
urllib3>=2.0.0
🚀 Quick Start
Basic Usage Examples
bash
# Scan a domain with subdomain enumeration
python3 recon_master.py -t example.com --enum-subs

# Full scan with vulnerability detection
python3 recon_master.py -t example.com --enum-subs --scan-vulns

# Scan an IP address
python3 recon_master.py -t 8.8.8.8

# Subdomain enumeration only
python3 recon_master.py --enum-only example.com

# Subdomain enumeration + vulnerability scan only
python3 recon_master.py --enum-only example.com --scan-vulns
Beta Testing Recommendations
bash
# Test with authorized targets
python3 recon_master.py -t testphp.vulnweb.com

# Test vulnerability scanner features
python3 recon_master.py -t example.com --scan-vulns

# Start with basic features, then expand
python3 recon_master.py -t example.com
python3 recon_master.py -t example.com --enum-subs
python3 recon_master.py -t example.com --enum-subs --scan-vulns
⚙️ Configuration
API Keys Setup
Run the interactive setup wizard:

bash
python3 recon_master.py --setup
Supported APIs (All with Free Tiers)
API	Free Tier	Key Source	Purpose
Shodan	✅ Limited	shodan.io	Network intelligence
SecurityTrails	✅ 50/month	securitytrails.com	Domain intelligence
VirusTotal	✅ 4/minute	virustotal.com	Security analysis
IPInfo	✅ 50k/month	ipinfo.io	Geolocation data
Manual Configuration
Edit config.json:

json
{
    "shodan": "YOUR_SHODAN_API_KEY",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "ipinfo": "YOUR_IPINFO_API_KEY"
}
🛡️ Vulnerability Scanning
Scan Coverage Matrix
Category	Checks Performed	Risk Weight
SSL/TLS	Validity, Expiry, Self-signed, Chain	10-20 points
Security Headers	HSTS, CSP, X-Frame, X-Content, X-XSS	5 points each
Sensitive Files	.git, .env, backups, configs	25-35 points
Configuration	CORS, Directory listing, Server info	5-15 points
Takeover	9+ service fingerprints	50 points
Scan Methodology
Phase 1: Service Discovery
python
1. HTTP/HTTPS accessibility check
2. Port 80/443 availability
3. Redirect chain analysis
4. Server header collection
Phase 2: SSL Analysis
python
1. Certificate validity check
2. Expiry date calculation
3. Issuer validation
4. Self-signed detection
Phase 3: Security Headers
python
1. Check all OWASP-recommended headers
2. Analyze CSP policies
3. Verify HSTS configuration
4. Check CORS settings
Phase 4: Content Analysis
python
1. Directory traversal attempts
2. Backup file detection
3. Source code exposure
4. Admin interface discovery
Phase 5: Takeover Analysis
python
1. Service-specific fingerprint matching
2. Error page content analysis
3. DNS record verification
4. Wildcard detection
📊 Risk Assessment
Risk Level Definitions
🔴 CRITICAL (50+ points)
Immediate action required. Examples:

Subdomain takeover possible

Exposed .env files with credentials

Critical SSL misconfigurations

🟠 HIGH (30-49 points)
High priority remediation. Examples:

Exposed .git repositories

Multiple security headers missing

Expired SSL certificates

🟡 MEDIUM (15-29 points)
Moderate risk. Examples:

Self-signed SSL certificates

Clickjacking vulnerabilities

CORS misconfigurations

🟢 LOW (1-14 points)
Low priority issues. Examples:

Missing individual security headers

Server information disclosure

Minor configuration issues

✅ SECURE (0 points)
No significant security issues found.

Scoring Algorithm
python
def calculate_risk_score(issues):
    score = 0
    
    if takeover_possible: score += 50
    if exposed_env: score += 35
    if exposed_git: score += 30
    if no_https: score += 25
    if exposed_backups: score += 25
    if invalid_ssl: score += 20
    if expired_ssl: score += 15
    if cors_misconfig: score += 15
    if self_signed_ssl: score += 10
    if clickjacking: score += 10
    if server_info_disclosure: score += 5
    score += len(missing_headers) * 5
    
    return score
ReconMaster 🎯
https://img.shields.io/badge/python-3.7+-blue.svg
https://img.shields.io/badge/license-MIT-green.svg
https://img.shields.io/github/v/release/cy30rt/ReconMaster?include_prereleases
https://img.shields.io/badge/status-beta-yellow
https://img.shields.io/github/stars/cy30rt/ReconMaster.svg
https://img.shields.io/github/issues/cy30rt/ReconMaster.svg
https://img.shields.io/badge/PRs-welcome-brightgreen.svg

Professional Bug Bounty Reconnaissance Tool with Advanced Vulnerability Scanning - Currently in Beta Testing Phase 🔧

<div align="center">
Created by Abdulbasid Yakubu | cy30rt

https://img.shields.io/badge/Kali_Linux-557C94?logo=kali-linux&logoColor=white
https://img.shields.io/badge/Termux-000000?logo=android&logoColor=white

Multi-API Intelligence Gathering + Vulnerability Scanning for Security Researchers

Features • Installation • Quick Start • Vulnerability Scanning • Examples

</div>
⚠️ BETA RELEASE NOTICE
ReconMaster v1.2.0-beta is currently in testing phase. Some features are experimental and may contain bugs. Please report any issues here.

📋 Table of Contents
Overview

✨ Features

📦 Installation

🚀 Quick Start

⚙️ Configuration

🛡️ Vulnerability Scanning

📊 Risk Assessment

📁 Output & Reporting

💡 Usage Examples

🎯 Command Line Reference

🔧 API Integration

🧪 Beta Testing Guidelines

🐛 Troubleshooting

🤝 Contributing

⚖️ Legal Disclaimer

👤 Author

📄 License

📞 Support

🎯 Overview
ReconMaster is a powerful, professional-grade reconnaissance tool designed for bug bounty hunters and security researchers. It combines multi-source intelligence gathering with advanced vulnerability scanning to provide comprehensive security assessments in a single, streamlined workflow.

Why Choose ReconMaster?
🔍 All-in-One Solution: Combines reconnaissance + vulnerability scanning

🌐 Multi-Source Intelligence: 9+ data sources and APIs

🛡️ Automated Security Checks: 25+ vulnerability detection modules

📊 Professional Risk Assessment: Color-coded scoring and prioritization

🚀 Cross-Platform: Works on Kali Linux and Termux (Android)

📁 Structured Reporting: JSON exports for further analysis

⚡ Performance Optimized: Multi-threading and rate limiting

🔧 Extensible Architecture: Modular design for easy expansion

✨ Features
🔍 Intelligence Gathering Suite
Category	Features	Data Sources
Network Intelligence	Port scanning, Service detection, Banner grabbing, Historical data	Shodan, Censys (planned)
Domain Intelligence	Subdomain enumeration, DNS records, WHOIS data, Certificate transparency	SecurityTrails, crt.sh, HackerTarget
Security Intelligence	Threat analysis, Reputation scoring, Malware detection, Vendor consensus	VirusTotal, ThreatCrowd, AlienVault
Geolocation Intelligence	IP geolocation, ASN data, Organization mapping, Network infrastructure	IPInfo, URLScan
🛡️ Advanced Vulnerability Scanner (New in v1.2.0)
SSL/TLS Security
✅ Certificate validity and expiry checks

✅ Self-signed certificate detection

✅ Certificate chain validation

✅ Expiry date tracking with alerts

✅ Issuer and subject verification

Security Headers Analysis
✅ HSTS (Strict-Transport-Security)

✅ Clickjacking protection (X-Frame-Options)

✅ MIME sniffing prevention (X-Content-Type-Options)

✅ Content Security Policy (CSP)

✅ XSS Protection header

✅ CORS configuration analysis

Common Vulnerabilities
✅ Clickjacking vulnerability detection

✅ CORS misconfiguration scanning

✅ Directory listing exposure

✅ Server information disclosure

✅ Backup and config file exposure

✅ Default credential checks (planned)

Sensitive File Detection
✅ Exposed .git directories

✅ Exposed .env configuration files

✅ Backup files (.zip, .sql, .bak)

✅ Log files and debugging endpoints

✅ Admin panel and login pages

Subdomain Takeover Detection
✅ GitHub Pages: There isn't a GitHub Pages site here

✅ Heroku: No such app, herokucdn.com

✅ AWS S3: NoSuchBucket, The specified bucket does not exist

✅ Azure: 404 Web Site not found, azurewebsites.net

✅ CloudFront: Bad request, ERROR: The request could not be satisfied

✅ Shopify: Sorry, this shop is currently unavailable

✅ Tumblr: Whatever you were looking for doesn't currently exist

✅ WordPress: Do you want to register

✅ Fastly: Fastly error: unknown domain

📊 Professional Risk Assessment System
Risk Scoring (0-100+)
Critical (50+): Immediate action required

High (30-49): High priority remediation

Medium (15-29): Moderate risk

Low (1-14): Low priority issues

Secure (0): No significant issues found

Risk Weighting
+50 points: Subdomain takeover possible

+35 points: Exposed .env file

+30 points: Exposed .git directory

+25 points: No HTTPS available

+25 points: Exposed backup files

+20 points: Invalid SSL certificate

+15 points: Expired SSL certificate

+15 points: CORS misconfiguration

+10 points: Self-signed SSL certificate

+10 points: Clickjacking vulnerable

+5 points: Missing security headers (each)

+5 points: Server information disclosure

🎨 User Experience Features
Visual Interface
Professional ASCII banner with author credits

Color-coded terminal output (GREEN/YELLOW/RED)

Real-time progress indicators

Emoji-based risk level indicators

Multi-phase scan visualization

Detailed summary statistics

Interactive Features
Setup wizard for API configuration

Interactive command line interface

Progress bars for long operations

Error handling with recovery options

Keyboard interrupt handling

Performance Features
Multi-threaded DNS brute force (10 threads)

Concurrent API requests with rate limiting

Intelligent caching where possible

Configurable timeouts

Graceful degradation on API failures

📁 Reporting & Export
Output Formats
Terminal Output: Color-coded, human-readable

JSON Export: Structured data for automation

Timestamped Files: Automatic organization

Summary Reports: Executive overview

Report Contents
Complete scan configuration

All discovered subdomains with sources

Vulnerability scan results per subdomain

Risk scores and levels

Recommendations and remediation steps

Raw API responses (where applicable)

🔧 Technical Architecture
Core Modules
Config Manager: API key management and persistence

Vulnerability Scanner: Multi-layer security checks

Subdomain Enumerator: Hybrid passive/active discovery

API Handlers: Modular integration with external services

Risk Calculator: Automated scoring and prioritization

Performance Optimizations
Thread pool for DNS resolution

Session reuse for HTTP requests

Intelligent rate limiting

Connection pooling

Timeout management

Error recovery and retry logic

📦 Installation
Quick Installation (Linux/Termux)
bash
# Clone the repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install dependencies
pip3 install -r requirements.txt

# Run setup wizard
python3 recon_master.py --setup
Detailed Installation
On Kali Linux / Ubuntu / Debian
bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip git -y

# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip3 install requests urllib3

# Make script executable
chmod +x recon_master.py

# Verify installation
python3 recon_master.py --version
On Termux (Android)
bash
# Update Termux
pkg update && pkg upgrade -y

# Install required packages
pkg install python git openssl-tool -y

# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
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
Requirements File
requirements.txt:

txt
requests>=2.31.0
urllib3>=2.0.0
🚀 Quick Start
Basic Usage Examples
bash
# Scan a domain with subdomain enumeration
python3 recon_master.py -t example.com --enum-subs

# Full scan with vulnerability detection
python3 recon_master.py -t example.com --enum-subs --scan-vulns

# Scan an IP address
python3 recon_master.py -t 8.8.8.8

# Subdomain enumeration only
python3 recon_master.py --enum-only example.com

# Subdomain enumeration + vulnerability scan only
python3 recon_master.py --enum-only example.com --scan-vulns
Beta Testing Recommendations
bash
# Test with authorized targets
python3 recon_master.py -t testphp.vulnweb.com

# Test vulnerability scanner features
python3 recon_master.py -t example.com --scan-vulns

# Start with basic features, then expand
python3 recon_master.py -t example.com
python3 recon_master.py -t example.com --enum-subs
python3 recon_master.py -t example.com --enum-subs --scan-vulns
⚙️ Configuration
API Keys Setup
Run the interactive setup wizard:

bash
python3 recon_master.py --setup
Supported APIs (All with Free Tiers)
API	Free Tier	Key Source	Purpose
Shodan	✅ Limited	shodan.io	Network intelligence
SecurityTrails	✅ 50/month	securitytrails.com	Domain intelligence
VirusTotal	✅ 4/minute	virustotal.com	Security analysis
IPInfo	✅ 50k/month	ipinfo.io	Geolocation data
Manual Configuration
Edit config.json:

json
{
    "shodan": "YOUR_SHODAN_API_KEY",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "ipinfo": "YOUR_IPINFO_API_KEY"
}
🛡️ Vulnerability Scanning
Scan Coverage Matrix
Category	Checks Performed	Risk Weight
SSL/TLS	Validity, Expiry, Self-signed, Chain	10-20 points
Security Headers	HSTS, CSP, X-Frame, X-Content, X-XSS	5 points each
Sensitive Files	.git, .env, backups, configs	25-35 points
Configuration	CORS, Directory listing, Server info	5-15 points
Takeover	9+ service fingerprints	50 points
Scan Methodology
Phase 1: Service Discovery
python
1. HTTP/HTTPS accessibility check
2. Port 80/443 availability
3. Redirect chain analysis
4. Server header collection
Phase 2: SSL Analysis
python
1. Certificate validity check
2. Expiry date calculation
3. Issuer validation
4. Self-signed detection
Phase 3: Security Headers
python
1. Check all OWASP-recommended headers
2. Analyze CSP policies
3. Verify HSTS configuration
4. Check CORS settings
Phase 4: Content Analysis
python
1. Directory traversal attempts
2. Backup file detection
3. Source code exposure
4. Admin interface discovery
Phase 5: Takeover Analysis
python
1. Service-specific fingerprint matching
2. Error page content analysis
3. DNS record verification
4. Wildcard detection
📊 Risk Assessment
Risk Level Definitions
🔴 CRITICAL (50+ points)
Immediate action required. Examples:

Subdomain takeover possible

Exposed .env files with credentials

Critical SSL misconfigurations

🟠 HIGH (30-49 points)
High priority remediation. Examples:

Exposed .git repositories

Multiple security headers missing

Expired SSL certificates

🟡 MEDIUM (15-29 points)
Moderate risk. Examples:

Self-signed SSL certificates

Clickjacking vulnerabilities

CORS misconfigurations

🟢 LOW (1-14 points)
Low priority issues. Examples:

Missing individual security headers

Server information disclosure

Minor configuration issues

✅ SECURE (0 points)
No significant security issues found.

Scoring Algorithm
python
def calculate_risk_score(issues):
    score = 0
    
    if takeover_possible: score += 50
    if exposed_env: score += 35
    if exposed_git: score += 30
    if no_https: score += 25
    if exposed_backups: score += 25
    if invalid_ssl: score += 20
    if expired_ssl: score += 15
    if cors_misconfig: score += 15
    if self_signed_ssl: score += 10
    if clickjacking: score += 10
    if server_info_disclosure: score += 5
    score += len(missing_headers) * 5
    
    return score
    📁 Output & Reporting
Terminal Output Example
═══════════════════════════════════════════════
  SUBDOMAIN ENUMERATION ENGINE
═══════════════════════════════════════════════
  Target: example.com
═══════════════════════════════════════════════

[*] Phase 1: Passive Subdomain Discovery
[+] crt.sh: Found 15 subdomains
[+] HackerTarget: Found 8 subdomains
[+] ThreatCrowd: Found 5 subdomains

[*] Phase 2: Active DNS Brute Force
[+] DNS Brute Force: Found 12 active subdomains

═══════════════════════════════════════════════
  VULNERABILITY SCAN SUMMARY
═══════════════════════════════════════════════
  Critical Risk: 1
  High Risk: 2
  Medium Risk: 3
  Low Risk: 5
  Secure: 15
═══════════════════════════════════════════════
JSON Report Structure
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
      "dns_brute_force": ["admin.example.com"]
    },
    "vulnerability_scans": [
      {
        "subdomain": "admin.example.com",
        "accessible": true,
        "risk_level": "CRITICAL",
        "risk_score": 65,
        "issues_found": [
          "Exposed .env File",
          "Missing Security Headers (3)",
          "Self-Signed SSL Certificate"
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
          "days_until_expiry": 365
        },
        "vulnerabilities": {
          "missing_security_headers": ["HSTS", "CSP", "X-Frame-Options"],
          "clickjacking_vulnerable": true,
          "exposed_env": true,
          "server_info_disclosure": true
        }
      }
    ]
  },
  "apis_used": 4,
  "scan_duration_seconds": 185.5
}
File Naming Convention
Format: recon_TARGET_TIMESTAMP.json
Example: recon_example_com_20240115_143022.json

Format: subdomains_DOMAIN_TIMESTAMP.json  
Example: subdomains_example_com_20240115_143022.json
💡 Usage Examples
Example 1: Basic Domain Reconnaissance
bash
python3 recon_master.py -t example.com
Output includes:

Domain information from SecurityTrails

VirusTotal security analysis

Resolved IP information

Basic API intelligence

Example 2: Comprehensive Subdomain Discovery
bash
python3 recon_master.py -t example.com --enum-subs
Workflow:
Phase 1: Passive Discovery (5 sources)
  → crt.sh certificate transparency
  → HackerTarget API
  → ThreatCrowd API  
  → AlienVault OTX
  → URLScan.io
  
Phase 2: Active DNS Brute Force
  → 100+ common subdomains
  → Multi-threaded resolution
  → Active service detection
Example 3: Full Security Assessment
bash
python3 recon_master.py -t example.com --enum-subs --scan-vulns
Full Scan Phases:

Reconnaissance: Gather intelligence from all APIs

Enumeration: Discover all subdomains

Scanning: Vulnerability checks on each subdomain

Assessment: Risk scoring and prioritization

Reporting: JSON export and terminal summary

Example 4: IP Address Intelligence
bash
python3 recon_master.py -t 8.8.8.8
IP-Specific Features:

Shodan port and service scan

IPInfo geolocation data

VirusTotal reputation check

Historical data analysis

Example 5: Subdomain-Only Mode
bash
python3 recon_master.py --enum-only example.com --scan-vulns
Perfect for:

Focused subdomain discovery

Continuous monitoring

Asset inventory management

Quick vulnerability assessment

🎯 Command Line Reference
Full Command Line Options
usage: recon_master.py [-h] [-t TARGET] [--type {auto,ip,domain}] [--setup]
                      [--output OUTPUT] [--enum-subs] [--scan-vulns]
                      [--enum-only DOMAIN] [-v]

ReconMaster - Professional Bug Bounty Reconnaissance Tool by Abdulbasid Yakubu | cy30rt

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain or IP address (required for full recon)
  --type {auto,ip,domain}
                        Target type (default: auto-detect)
  --setup               Run interactive setup wizard for API keys
  -o OUTPUT, --output OUTPUT
                        Custom output filename (optional)
  --enum-subs           Enable comprehensive subdomain enumeration
  --scan-vulns          Enable vulnerability scanning on discovered subdomains
  --enum-only DOMAIN    Run subdomain enumeration only (no other recon)
  -v, --version         show program's version number and exit
Flag Combinations
Command	Description	Use Case
-t target	Basic reconnaissance	Quick intelligence gathering
-t target --enum-subs	With subdomain discovery	Asset enumeration
-t target --enum-subs --scan-vulns	Full assessment	Security audit
--enum-only domain	Subdomain-only mode	Asset inventory
--enum-only domain --scan-vulns	Subdomain + vuln scan	Focused testing
--setup	Configuration wizard	Initial setup
🔧 API Integration
API Capabilities Matrix
API	Free Tier	Rate Limit	Key Features	Integration Status
Shodan	✅ Limited	Varies	Port scanning, Vuln detection	✅ Fully Integrated
SecurityTrails	✅ 50/month	1/sec	Subdomains, DNS, WHOIS	✅ Fully Integrated
VirusTotal	✅ 4/min	500/day	Malware analysis, Reputation	✅ Enhanced Integration
IPInfo	✅ 50k/month	None	Geolocation, ASN, Org	✅ Fully Integrated
crt.sh	✅ Unlimited	None	Certificate transparency	✅ Passive Source
HackerTarget	✅ Unlimited	None	Subdomain enumeration	✅ Passive Source
ThreatCrowd	✅ Unlimited	None	Threat intelligence	✅ Passive Source
AlienVault OTX	✅ Unlimited	None	Passive DNS	✅ Passive Source
URLScan.io	✅ Unlimited	None	Recent scans	✅ Passive Source
API Workflow
python
1. Target Analysis → Determine IP vs Domain
2. API Selection → Choose appropriate APIs
3. Sequential Query → Rate-limited API calls  
4. Data Aggregation → Combine all results
5. Error Handling → Graceful degradation
6. Result Export → Structured JSON output
🧪 Beta Testing Guidelines
Testing Recommendations
Safe Test Targets
bash
# Authorized test domains
python3 recon_master.py -t testphp.vulnweb.com
python3 recon_master.py -t scanme.nmap.org
python3 recon_master.py -t example.com  # Your own domain
Progressive Testing
bash
# 1. Basic functionality
python3 recon_master.py -t example.com

# 2. Add subdomain enumeration  
python3 recon_master.py -t example.com --enum-subs

# 3. Add vulnerability scanning
python3 recon_master.py -t example.com --enum-subs --scan-vulns

# 4. Test specific features
python3 recon_master.py --enum-only example.com --scan-vulns
Reporting Beta Issues
When reporting issues, please include:

Command Used: Exact command line

Target: What you scanned (if allowed)

Python Version: python3 --version

OS Details: Kali/Termux version

Full Error: Copy-paste complete error

Expected Behavior: What you expected

Config Status: API keys configured?

Network Status: Any proxy/VPN?

Beta Limitations
SSL certificate parsing may have edge cases

Some APIs may timeout under load

Vulnerability scanner is experimental

Rate limiting may affect large scans

Output formatting may vary by terminal

🐛 Troubleshooting
Common Issues & Solutions
Issue: "Module not found" errors
bash
# Solution: Install dependencies
pip3 install -r requirements.txt
# or
pip install requests urllib3
Issue: API key errors
bash
# Solution: Run setup wizard
python3 recon_master.py --setup

# Or manually edit config.json
nano config.json
Issue: Permission denied
bash
# Solution: Make executable
chmod +x recon_master.py
Issue: SSL certificate errors
bash
# Termux specific
pkg install openssl-tool

# Or run with Python directly
python3 recon_master.py -t example.com
Issue: Rate limit exceeded
Wait for rate limit reset

Use fewer simultaneous scans

Consider API plan upgrades

Implement delays between scans

Issue: DNS resolution failures
Check internet connection

Verify DNS settings

Try with VPN

Test with ping google.com

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

# Run with verbose output
python3 -c "import requests; print(requests.__version__)"
🤝 Contributing
How to Contribute
Fork the repository

Create a feature branch: git checkout -b feature/AmazingFeature

Commit your changes: git commit -m 'Add AmazingFeature'

Push to the branch: git push origin feature/AmazingFeature

Open a Pull Request

Areas for Contribution
High Priority
Additional vulnerability checks

Performance optimizations

More API integrations

Better error handling

Medium Priority
Export formats (CSV, HTML, PDF)

GUI interface

Docker containerization

Documentation improvements

Low Priority
Plugin system

Scheduled scans

Advanced reporting

Integration with other tools

Development Guidelines
Follow PEP 8 Python style guide

Add comprehensive comments

Include error handling

Test on Kali and Termux

Update documentation

Maintain backward compatibility

⚖️ Legal Disclaimer
IMPORTANT: READ BEFORE USE
This tool is for educational and authorized security testing purposes only.

✅ Permitted Uses
Testing systems you own or manage

Authorized penetration testing

Bug bounty programs with explicit permission

Educational and research purposes

Security awareness training

❌ Prohibited Uses
Unauthorized access to systems

Violating laws or regulations

Disrupting services or networks

Malicious activities

Privacy violations

Legal Compliance
By using this tool, you agree to:

Obtain proper authorization before scanning

Comply with all applicable laws

Respect API terms of service

Follow responsible disclosure practices

Accept full responsibility for your actions

No Warranty
This software is provided "as is" without warranty of any kind. The author assumes no liability for damages resulting from use of this tool.

👤 Author
Abdulbasid Yakubu | cy30rt

Professional Bug Bounty Hunter & Security Researcher

Connect
GitHub: @cy30rt

Twitter: @cy30rt

LinkedIn: Abdulbasid Yakubu

Acknowledgments
Special thanks to:

The bug bounty community for inspiration

API providers for their excellent services

Beta testers who helped refine the tool

Open source contributors worldwide

Security researchers sharing knowledge

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
📞 Support
Getting Help
GitHub Issues: Report bugs

Documentation: This README serves as primary documentation

Community: Share experiences with other users

Feature Requests
When requesting features, please:

Describe the use case

Explain the benefits

Suggest implementation approach

Reference similar tools if applicable

Bug Reports
When reporting bugs, include:

Environment: OS, Python version

Command: Exact command used

Error: Complete error message

Expected: What should happen

Actual: What actually happened

Steps: Steps to reproduce

📈 Roadmap
v1.3.0 (Next Release)
Additional vulnerability checks

Performance improvements

More API integrations

Enhanced error handling

Better documentation

v2.0.0 (Future)
Web interface

Plugin system

Advanced reporting

Scheduled scans

Team collaboration features

Long Term Vision
Comprehensive security assessment platform

Integration with major bug bounty platforms

Machine learning for vulnerability prediction

Real-time monitoring capabilities

Professional reporting suite

<div align="center">
Made with ❤️ by Abdulbasid Yakubu | cy30rt

For Bug Bounty Hunters, By a Bug Bounty Hunter

⭐ If you find this tool useful, please give it a star on GitHub! ⭐

Happy Hunting! 🎯

</div>
