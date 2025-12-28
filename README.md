# 🔍 ReconMaster

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Termux-red.svg)

**Professional Bug Bounty Reconnaissance Tool**

*Created by Abdulbasid Yakubu | cy30rt*

Multi-API intelligence gathering for security researchers and bug bounty hunters

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Configuration](#-configuration) • [Examples](#-examples)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Integration](#-api-integration)
- [Examples](#-examples)
- [Output](#-output)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Legal Disclaimer](#-legal-disclaimer)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Overview

**ReconMaster** is a powerful, professional-grade reconnaissance tool designed for bug bounty hunters and security researchers. It aggregates data from multiple threat intelligence and reconnaissance APIs to provide comprehensive information about targets in a single, streamlined workflow.

### Why ReconMaster?

- **Multi-Source Intelligence**: Combines data from four major reconnaissance APIs
- **Cross-Platform**: Works seamlessly on both Kali Linux and Termux (Android)
- **Professional Output**: Clean, color-coded CLI interface with structured JSON export
- **Fully Functional**: 100% working tool with comprehensive error handling
- **Modular Design**: Easy to extend and customize for your needs
- **Rate Limiting Aware**: Built-in delays to respect API rate limits
- **Production Ready**: Battle-tested for real-world bug bounty hunting

---

## ✨ Features

### 🔍 Intelligence Gathering Capabilities

- **Network Intelligence**
  - Open port discovery and service detection
  - Banner grabbing and service fingerprinting
  - Historical host data analysis
  - Vulnerability detection

- **Domain Intelligence**
  - Comprehensive subdomain enumeration
  - DNS history tracking and analysis
  - WHOIS information retrieval
  - Domain relationship mapping

- **Geolocation Intelligence**
  - Precise IP geolocation data
  - ASN and network information
  - Organization and ISP details
  - Network infrastructure mapping

- **Security Intelligence**
  - Malware and threat analysis
  - Domain/IP reputation scoring
  - Security vendor consensus
  - Threat actor attribution

### 🎨 User Experience

- Professional ASCII banner with author credits
- Color-coded output (success, warning, error, info)
- Real-time progress indicators
- Interactive setup wizard
- Auto-generated timestamped reports
- Structured JSON export for further analysis
- Detailed scan summaries

### 🛠️ Technical Features

- Full cross-platform compatibility (Kali Linux & Termux)
- Intelligent target type detection (IP vs Domain)
- Automatic domain-to-IP resolution
- Robust session management with custom user agents
- Configurable timeouts for all API calls
- Graceful error handling and recovery
- SSL verification bypass option for testing environments
- Modular API handler architecture

---

## 📦 Requirements

### System Requirements

- **Python**: Version 3.7 or higher
- **Operating System**: Linux (Kali, Ubuntu, Debian) or Termux (Android)
- **Internet**: Active internet connection
- **Terminal**: Terminal with ANSI color support

### Python Dependencies

- `requests` >= 2.31.0
- `urllib3` >= 2.0.0
- `colorama` >= 0.4.6

### API Requirements

You'll need API keys from the following services (all offer free tiers):

1. **Shodan** - Network intelligence and port scanning
2. **SecurityTrails** - Domain and DNS intelligence
3. **IPInfo** - Geolocation and network data
4. **VirusTotal** - Security and malware analysis

---

## 🚀 Installation

### Quick Install (Linux/Termux)

bash
#Clone the repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Run automated installer (Linux only)
chmod +x install.sh
./install.sh
Manual Installation
On Kali Linux / Ubuntu / Debian
bash
# Clone repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Update system packages
sudo apt-get update

# Install Python and pip
sudo apt-get install python3 python3-pip -y

# Install Python dependencies
pip3 install -r requirements.txt

# Make script executable
chmod +x recon_master.py
On Termux (Android)
bash
# Update Termux packages
pkg update -y && pkg upgrade -y

# Install required packages
pkg install python git -y

# Clone repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip install -r requirements.txt

# Make script executable
chmod +x recon_master.py

# Optional: Add to PATH for easy access
cp recon_master.py $PREFIX/bin/reconmaster
chmod +x $PREFIX/bin/reconmaster
Termux Notes:

Works on Android 7.0+

Install Termux from F-Droid for best compatibility

Grant storage permissions: termux-setup-storage

Fix SSL errors: pkg install openssl-tool

⚙️ Configuration
Interactive Setup (Recommended)
Run the built-in setup wizard to configure your API keys:

bash
python3 recon_master.py --setup
The wizard will guide you through entering each API key. You can skip any API by pressing Enter if you don't have that particular key.

Manual Configuration
Create or edit config.json in the tool directory:

json
{
    "shodan": "YOUR_SHODAN_API_KEY",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "ipinfo": "YOUR_IPINFO_API_KEY"
}
Termux-specific Configuration:

Grant storage permissions:

bash
termux-setup-storage
If you get SSL errors, install:

bash
pkg install openssl-tool
For better performance, install:

bash
pkg install python-numpy
Getting API Keys (Free Tier)
Shodan

Visit: https://account.shodan.io/register

Sign up for a free account

Navigate to: https://account.shodan.io/

Copy your API key

SecurityTrails

Visit: https://securitytrails.com/app/signup

Create a free account

Go to: https://securitytrails.com/app/account/credentials

Copy your API key

IPInfo

Visit: https://ipinfo.io/signup

Register for free access

Navigate to: https://ipinfo.io/account/token

Copy your access token

VirusTotal

Visit: https://www.virustotal.com/gui/join-us

Create a free account

Go to: https://www.virustotal.com/gui/my-apikey

Copy your API key

📖 Usage
Basic Usage
bash
python3 recon_master.py -t TARGET
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
  -v, --version         Show version information
Target Types
auto (default): Automatically detects whether target is IP or domain

ip: Forces IP-based reconnaissance workflow

domain: Forces domain-based reconnaissance workflow

Termux Usage Note: Use python instead of python3:
python recon_master.py -t example.com
 API Integration
API Capabilities
API	Free Tier	Rate Limit	Capabilities
Shodan	✅ Yes	Varies	Port scanning, service detection, vulnerabilities
SecurityTrails	✅ Yes	50/month	Subdomains, DNS records, WHOIS
IPInfo	✅ Yes	50k/month	Geolocation, ASN, organization
VirusTotal	✅ Yes	4/minute	Security analysis, reputation
How It Works
Target Analysis: Tool automatically detects if target is IP or domain

API Selection: Chooses appropriate APIs based on target type

Sequential Queries: Queries each API with built-in rate limiting

Data Aggregation: Combines all results into unified report

Export: Saves structured JSON for further analysis

💡 Examples
Scan a Domain
bash
python3 recon_master.py -t example.com
Output includes:

Subdomain enumeration

DNS records

Security reputation

Associated IP addresses

Geolocation data

Open ports and services

Scan an IP Address
bash
python3 recon_master.py -t 8.8.8.8
Output includes:

Open ports and services

Geolocation information

Organization details

Security reputation

Historical data

Force Specific Scan Type
bash
# Force domain scan
python3 recon_master.py -t example.com --type domain

# Force IP scan
python3 recon_master.py -t 192.168.1.1 --type ip
Run Setup Wizard
bash
python3 recon_master.py --setup
Example Output
   ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
    ╠╦╝║╣ ║  ║ ║║║║  ║║║╠═╣╚═╗ ║ ║╣ ╠╦╝
    ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╩ ╩╩ ╩╚═╝ ╩ ╚═╝╩╚═

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Professional Bug Bounty Reconnaissance Tool
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Version: 1.0.0
    Author:  Abdulbasid Yakubu | cy30rt

    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Multi-Source Intelligence Gathering
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

═══════════════════════════════════════════════
  INITIATING RECONNAISSANCE
═══════════════════════════════════════════════
  Target: example.com
  Type: auto
  Time: 2024-01-15 14:30:22
═══════════════════════════════════════════════

[*] Detected domain target - running domain-based reconnaissance

[*] Querying SecurityTrails database...
[+] SecurityTrails: Domain data retrieved
    Subdomains discovered: 15
    Sample subdomains: www, mail, ftp, blog, shop

[*] Querying VirusTotal database...
[+] VirusTotal: Security analysis completed
    Malicious detections: 0
    Suspicious detections: 0
    Clean detections: 85
    ✓ Target appears clean

[*] Resolving domain to IP address...
[+] Resolved IP: 93.184.216.34

[*] Querying Shodan database...
[+] Shodan: Data retrieved successfully
    IP: 93.184.216.34
    Organization: EDGECAST
    Country: United States
    OS: N/A
    Open Ports: 80, 443

[*] Querying IPInfo database...
[+] IPInfo: Geolocation data retrieved
    Location: Los Angeles, California, US
    Organization: AS15133 Edgecast Inc.
    Timezone: America/Los_Angeles
    Coordinates: 34.0522,-118.2437

═══════════════════════════════════════════════
  RECONNAISSANCE COMPLETED
═══════════════════════════════════════════════
  APIs queried: 4/4
  Data points collected: 2847
  Report: recon_example_com_20240115_143022.json
═══════════════════════════════════════════════
📊 Output
JSON Report Structure
Results are automatically saved in timestamped JSON files:

json
{
    "target": "example.com",
    "timestamp": "2024-01-15T14:30:22.123456",
    "scan_type": "auto",
    "resolved_ip": "93.184.216.34",
    "shodan": {
        "ip_str": "93.184.216.34",
        "org": "EDGECAST",
        "country_name": "United States",
        "ports": [80, 443],
        "vulns": []
    },
    "securitytrails": {
        "subdomains": ["www", "mail", "ftp"],
        "dns_records": {},
        "whois": {}
    },
    "ipinfo": {
        "ip": "93.184.216.34",
        "city": "Los Angeles",
        "region": "California",
        "country": "US",
        "loc": "34.0522,-118.2437",
        "org": "AS15133 Edgecast Inc."
    },
    "virustotal": {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 85
                }
            }
        }
    }
}
File Naming Convention
Format: recon_TARGET_TIMESTAMP.json

Example: recon_example_com_20240115_143022.json

Location: Current working directory

Termux Output Location:

bash
# Default location
/storage/emulated/0/recon_*.json

# Or in home directory
~/recon_*.json
🔧 Troubleshooting
Common Issues and Solutions
Issue: "No module named 'requests'"

bash
# Solution
pip3 install -r requirements.txt  # Linux
pip install -r requirements.txt   # Termux
Issue: "API key not found" or "API key not configured"

bash
# Solution: Run setup wizard
python3 recon_master.py --setup
Issue: "Permission denied" when running script

bash
# Solution: Make script executable
chmod +x recon_master.py
chmod +x install.sh
Issue: "Invalid API key" errors

Verify your API keys are correct

Check that keys are properly saved in config.json

Ensure keys have not expired

Visit the respective API provider's dashboard

Issue: "Request timeout" errors

Check your internet connection

Some APIs may be temporarily down

Try increasing timeout values in the code

Use a VPN if APIs are blocked in your region

Issue: API rate limit exceeded

Wait for the rate limit window to reset

Consider upgrading to paid API plans

Reduce scan frequency

Use fewer simultaneous scans

Issue: "Could not resolve domain"

Verify the domain name is correct

Check DNS settings

Try using a public DNS server (8.8.8.8)

Termux-Specific Issues
Issue: "Command not found" or "python3 not found"

bash
# Use python instead of python3
python recon_master.py -t example.com
Issue: SSL certificate errors

bash
pkg install openssl-tool
Issue: No storage permission

bash
termux-setup-storage
Issue: Can't save output files

bash
# Save to home directory
cd ~
python recon_master.py -t example.com
Debug Mode
For detailed error information, Python will display full tracebacks. If you encounter persistent issues:

Check Python version: python3 --version or python --version

Verify all dependencies: pip3 list or pip list

Test internet connectivity: ping google.com

Validate API keys in config.json

Check file permissions: ls -la

🤝 Contributing
Contributions are welcome and appreciated! Here's how you can help:

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
Additional API integrations

Performance optimizations

New output formats (CSV, HTML)

GUI implementation

Docker containerization

Additional reconnaissance modules

⚖️ Legal Disclaimer
IMPORTANT: READ CAREFULLY BEFORE USING THIS TOOL

Terms of Use
This tool is provided for educational and authorized security testing purposes only.

✅ DO: Use on systems you own or have explicit written permission to test

✅ DO: Follow responsible disclosure practices

✅ DO: Respect all applicable laws and regulations

✅ DO: Honor API terms of service and rate limits

❌ DO NOT: Use for unauthorized access or malicious purposes

❌ DO NOT: Violate any laws or regulations

❌ DO NOT: Harm or disrupt systems or networks

Legal Notice
Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA)

Users are solely responsible for ensuring their use complies with all applicable laws

The author assumes NO LIABILITY for misuse of this software

This tool should only be used in accordance with bug bounty program rules and with proper authorization

Responsible Disclosure
If you discover vulnerabilities using this tool:

Do not exploit or share them publicly

Report them to the appropriate security team

Follow the organization's disclosure policy

Allow reasonable time for remediation

Respect bug bounty program rules

By using this tool, you agree to use it responsibly and ethically.

👤 Author
Abdulbasid Yakubu | cy30rt

Professional Bug Bounty Hunter & Security Researcher

This tool was created to streamline the reconnaissance phase of bug bounty hunting and security assessments. It represents hundreds of hours of development, testing, and refinement to provide the security community with a reliable, professional-grade tool.

Connect
GitHub: Check my other security projects

Bug Bounty: Active on major platforms

Security Research: Focused on web application security

Acknowledgments
Special thanks to:

The bug bounty community for inspiration and feedback

API providers (Shodan, SecurityTrails, IPInfo, VirusTotal) for their excellent services

Beta testers who helped refine this tool

Open source contributors and maintainers

📄 License
This project is licensed under the MIT License.
MIT License

## 📄 License

This project is licensed under the **MIT License**.

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

GitHub Discussions: Join the community discussion

Documentation: This README serves as comprehensive documentation

Reporting Bugs
When reporting bugs, please include the following information:

Python Version: python3 --version or python --version

Operating System: Kali Linux, Termux (Android), Ubuntu, etc.

Complete Error Message: Copy-paste the full error traceback

Steps to Reproduce: Exact commands and inputs used

Expected vs Actual Behavior: What you expected vs what happened

📈 Roadmap
🚀 Planned Features
Additional API Integrations: Censys, Hunter.io, BuiltWith, etc.

Parallel Execution: Multi-threaded API queries for faster results

Export Formats: CSV, HTML, PDF reports with templates

Web Interface: Browser-based GUI for easier usage

Automated Reporting: Generate professional PDF reports

Result Caching: Local database to avoid duplicate API calls

Proxy Support: Rotating proxies and Tor integration

Custom Modules: Plugin system for user-created modules

Scheduled Scans: Automated periodic reconnaissance

Tool Integration: Export to Burp Suite, Nmap, etc.

📋 Version History
v1.0.0 (Current) - Initial release with core functionality

v1.1.0 (Planned) - Performance improvements and bug fixes

v1.2.0 (Planned) - Additional API integrations

v2.0.0 (Future) - Major rewrite with advanced features

🌟 Support the Project
If you find ReconMaster useful for your bug bounty hunting or security research:

⭐ Star the Repository
Give the project a star on GitHub to show your support and help others discover it.

🐛 Report Issues
Found a bug? Have a feature request? Open an issue on GitHub.

🤝 Contribute
Submit pull requests with improvements

Add new API integrations

Improve documentation

Share your use cases

📢 Spread the Word
Share on social media (Twitter, LinkedIn, Reddit)

Mention in bug bounty communities

Write blog posts or tutorials

Include in your security toolkit lists

☕ Support the Developer
Follow on GitHub for updates

Connect on professional networks

Share feedback and suggestions

<div align="center">
Made with ❤️ by Abdulbasid Yakubu | cy30rt

For Bug Bounty Hunters, By a Bug Bounty Hunter

If you find this tool useful, please give it a ⭐ on GitHub!

Report Bug ·
Request Feature ·
View Documentation

📢 Join the Community

Share your success stories

Submit your improvements

Help others learn reconnaissance

🔐 Stay Ethical

Always get proper authorization

Respect rate limits and ToS

Follow responsible disclosure

🚀 Keep Learning

Continuous improvement is key

Share knowledge with others

Build a safer internet together

</div> 
