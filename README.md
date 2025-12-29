# 🔍 ReconMaster - Advanced Reconnaissance Tool

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Termux%20%7C%20Windows%20%7C%20macOS-purple)
![Downloads](https://img.shields.io/badge/downloads-500+-brightgreen)
![Maintenance](https://img.shields.io/badge/maintenance-active-success)

**Professional Bug Bounty & Penetration Testing Reconnaissance Tool**  
*Automated subdomain enumeration, port scanning, technology detection, and threat intelligence gathering*

---

## ✨ Features

### 🚀 **Core Capabilities**
- **Subdomain Enumeration** - 12+ sources with SSL fixes
- **Port Scanning** - Intelligent port discovery
- **IP Intelligence** - Threat reputation scoring  
- **Technology Detection** - Stack fingerprinting
- **Risk Assessment** - Automated security scoring
- **Comprehensive Reporting** - JSON, TXT outputs

### 🔧 **Advanced Features**
- **SSL Certificate Fixes** - Auto-handles problematic APIs
- **Rate Limiting Protection** - Exponential backoff retry
- **Parallel Processing** - Fast DNS brute forcing
- **Error Resilience** - Graceful degradation on API failures
- **Smart Caching** - Reduce API calls for repeated targets

### 🌐 **API Integration**
| Service | Status | Purpose |
|---------|--------|---------|
| **Shodan** | ✅ | Port scanning & service detection |
| **SecurityTrails** | ✅ | Historical DNS data |
| **VirusTotal** | ✅ | Threat intelligence |
| **AbuseIPDB** | ✅ | IP reputation scoring |
| **GreyNoise** | ✅ | Background noise filtering |
| **AnubisDB** | ✅ | Reliable subdomain discovery |
| **BufferOver.run** | ✅ | Fast DNS database |
| **Certificate Transparency** | ✅ | crt.sh, CertSpotter, Facebook CT |
| **IPInfo** | ✅ | Geolocation data |
| **BuiltWith/Wappalyzer** | ✅ | Technology stack analysis |

## 📦 Installation

### Kali Linux / Ubuntu / Debian
bash
# Clone repository
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x recon_master.py

# Or use installer script
chmod +x install-kali.sh
./install-kali.sh
Termux (Android)
bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster
pip install requests urllib3 dnspython colorama
chmod +x recon_master.py
Windows / macOS
bash
# Install Python 3.8+ from python.org
# Then run:
git clone https://github.com/abdulcybort/ReconMaster.git
cd ReconMaster
pip install -r requirements.txt
⚡ Quick Start
1. Configure API Keys (Optional but Recommended)
bash
# Interactive setup wizard
python recon_master.py --setup

# Or edit config.json manually
nano config.json
2. Basic Usage Examples
bash
# Subdomain enumeration
python recon_master.py -t example.com --enum-subs

# Full advanced scan (recommended)
python recon_master.py -t example.com --advanced --full-scan

# IP intelligence
python recon_master.py -t 8.8.8.8 --advanced --risk-assessment

# Technology detection
python recon_master.py -t example.com --advanced --tech-detect

# Quick scan (basic functionality)
python recon_master.py -t example.com --quick
🎯 Usage Examples
Subdomain Discovery
bash
python recon_master.py -t bugcrowd.com --enum-subs
*Expected output: 200-500+ subdomains*

Complete Reconnaissance
bash
python recon_master.py -t target.com --advanced --full-scan
Includes: Subdomains, ports, technologies, risk assessment

IP Analysis
bash
python recon_master.py -t 1.1.1.1 --advanced --risk-assessment
Checks: Abuse score, threat intelligence, open ports

Batch Processing

# Create targets.txt with list of domains
for domain in $(cat targets.txt); do
    python recon_master.py -t $domain --enum-subs -o results/$domain.json
done
📊 Sample Output
Terminal Display
text
===============================================
  ENHANCED SUBDOMAIN ENUMERATION ENGINE
===============================================
  Target: example.com
  Sources: 12+ APIs available
===============================================

[*] Phase 1: Passive Enumeration
[+] crt.sh: Found 127 subdomains
[+] AnubisDB: Found 89 subdomains  
[+] BufferOver.run: Found 45 subdomains
[+] RapidDNS: Found 32 subdomains

[*] Phase 2: Active DNS Brute Force
[+] DNS Brute Force: Found 18 active subdomains

[*] Phase 3: Technology Detection
[+] Web Server: nginx/1.18.0
[+] Framework: React 18.2.0
[+] CMS: WordPress 6.2

[*] Phase 4: Risk Assessment
[!] Risk Level: MEDIUM (45/100)
- Open port 445 detected
- Moderate abuse confidence score

===============================================
           ENUMERATION COMPLETE
===============================================
Total Subdomains Found: 245
Successful Sources: 9
Failed Sources: 3
Total Open Ports Found: 18
JSON Report Structure
json
{
  "target": "example.com",
  "timestamp": "2024-01-15T10:30:00",
  "subdomain_enum": {
    "total_found": 245,
    "subdomains": [
      {
        "subdomain": "mail.example.com",
        "ip": "192.168.1.10",
        "source": "crt.sh,anubisdb",
        "ports": [25, 443, 993]
      }
    ]
  },
  "risk_assessment": {
    "score": 65,
    "level": "HIGH",
    "factors": ["Open port 445", "High abuse score"]
  }
}
🛠️ Command Line Options

Basic Options:
  -t, --target TARGET    Target domain or IP address
  --type {auto,ip,domain} Target type (default: auto)
  --enum-subs            Enable subdomain enumeration
  --scan-ports           Enable port scanning
  --setup                Run basic API setup wizard

Advanced Options:
  --advanced             Enable advanced scanning features
  --full-scan            Run all available scans
  --tech-detect          Enable technology detection
  --risk-assessment      Generate risk assessment report
  --quick                Quick scan only (skip intensive checks)

Output Options:
  -o, --output FILE      Output file for results
  --format {json,txt}    Output format (default: json)

Performance Options:
  --threads THREADS      Threads for parallel scanning (default: 10)
  --timeout TIMEOUT      Timeout per request in seconds (default: 30)

Info Options:
  -h, --help            Show this help message
  -v, --version         Show version information
📁 Project Structure

ReconMaster/
├── recon_master.py          # Main tool
├── config.json              # API configuration
├── requirements.txt         # Python dependencies
├── install-kali.sh         # Kali Linux installer
├── README.md               # This file
└── examples/               # Usage examples
    ├── basic_scan.sh       # Basic scan script
    ├── batch_scan.py       # Batch scanning
    └── sample_report.json  # Sample output
🔧 Technical Details
Subdomain Sources (13 Total)
crt.sh - Certificate Transparency logs

AnubisDB - Highly reliable, no rate limits

BufferOver.run - Fast DNS database

RapidDNS - Recent subdomains

CertSpotter - Certificate transparency

Facebook CT - Facebook certificate logs

HackerTarget - With rate limiting protection

ThreatCrowd - With SSL fix

AlienVault OTX - With SSL fix

URLScan.io - Live scanning data

VirusTotal - Threat intelligence

SecurityTrails - Historical DNS

DNS Brute Force - Active enumeration

Error Handling
SSL Issues → Auto HTTP fallback

Rate Limits → Exponential backoff (2ⁿ seconds)

API Failures → Continue with remaining sources

Network Issues → Retry with timeout

🤝 Contributing
We welcome contributions! Here's how:

Fork the repository

Create a feature branch: git checkout -b feature/AmazingFeature

Commit your changes: git commit -m 'Add AmazingFeature'

Push to the branch: git push origin feature/AmazingFeature

Open a Pull Request

Areas for Contribution
Additional API integrations

Improved error handling

Performance optimizations

Documentation improvements

Bug fixes and testing

📄 License
Distributed under the MIT License. See LICENSE for more information.

Attribution
If you use ReconMaster in your work, please credit:

ReconMaster by Abdulbasid Yakubu
https://github.com/abdulcybort/ReconMaster
👨‍💻 Author
Abdulbasid Yakubu

GitHub: @abdulcybort

Twitter: @cy30rt

Portfolio: cy30rt.me

Support the Project
If you find this tool useful:

Give it a ⭐ on GitHub

Share with your security friends

Report issues or suggest features

Consider supporting API providers

⚠️ Legal & Ethical Use
This tool is for authorized security testing only.

Responsible Usage Guidelines:
Only scan targets you own or have explicit permission to test

Respect rate limits of free APIs to avoid bans

Comply with target website's robots.txt

Follow rules of bug bounty programs

Never use for illegal or malicious purposes

Users are responsible for:
Obtaining proper authorization before scanning

Complying with local laws and regulations

Respecting privacy and data protection laws

🐛 Troubleshooting
Common Issues & Solutions:
SSL Certificate Errors

text
The tool automatically handles SSL issues, but if you see:
"certificate verify failed: Hostname mismatch"
This is normal - the tool will retry with HTTP
Rate Limiting


[!] HackerTarget: Rate limited or no data
Wait a few minutes or use --quick mode
DNS Resolution Failures


# Install dnspython
pip install dnspython
API Key Issues


# Reset configuration
rm config.json
python recon_master.py --setup
Getting Help:
Check Issues

Create a new issue with detailed error

Join security communities for support

🔗 Related Projects
Amass - In-depth attack surface mapping

Subfinder - Subdomain discovery

Nmap - Network discovery and security auditing

Shodan - Shodan API client

🌟 Star History
https://api.star-history.com/svg?repos=abdulcybort/ReconMaster&type=Date

Happy Reconnaissance! Stay Ethical, Stay Safe. 🔐

📝 Copyright & Attribution
Copyright
© 2024 Abdulbasid Yakubu. All rights reserved.

License Terms
This project is licensed under the MIT License - see the LICENSE file for details.

Usage Terms
When using ReconMaster, you agree to:

Use it only for authorized security testing

Respect all applicable laws and regulations

Give proper attribution when sharing results

Not hold the author liable for any misuse

Citation
If you use ReconMaster in research or publications:

bibtex
@software{ReconMaster2024,
  author = {Yakubu, Abdulbasid},
  title = {ReconMaster: Advanced Reconnaissance Tool},
  year = {2024},
  publisher = {GitHub},
  url = {https://github.com/abdulcybort/ReconMaster}
}
Contact
For questions, support, or collaboration:

Email: contact@cy30rt.me

GitHub Issues: https://github.com/abdulcybort/ReconMaster/issues

Twitter: @cy30rt

Last Updated: January 2024 | Version: 3.0.0

**Key additions at the end:**

1. **📝 Copyright Section** - Clear copyright notice
2. **📄 License Terms** - MIT License reference
3. **⚖️ Usage Terms** - Legal agreement for users
4. **📚 Citation Format** - Proper academic citation
5. **📧 Contact Information** - Multiple contact methods
6. **🔄 Version/Date Stamp** - Clear documentation of updates

This gives you:
- ✅ **Legal protection** with clear copyright
- ✅ **Professional appearance** for GitHub
- ✅ **Proper attribution** for academic/research use
- ✅ **Contact options** for collaboration
- ✅ **Version control** for tracking updates

Perfect for a professional open-source project! 🚀
