# 🔍 ProRecon - Professional Reconnaissance Tool

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20termux-lightgrey.svg)

**A Professional Bug Bounty Reconnaissance Tool for Security Researchers**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## 📋 Overview

ProRecon is a comprehensive reconnaissance tool designed for bug bounty hunters, penetration testers, and security researchers. It combines multiple reconnaissance techniques into a single, efficient tool with professional output and detailed reporting.

### 🎯 Core Capabilities

- **IP Resolution** - Automatic domain-to-IP address resolution
- **TCP Port Scanning** - Fast, multi-threaded TCP port discovery with service detection
- **UDP Port Scanning** - UDP protocol scanning for hidden services
- **SSL/TLS Analysis** - Certificate validation, expiry checking, and security assessment
- **Subdomain Enumeration** - Multiple sources (crt.sh, HackerTarget, AlienVault, DNS brute force)
- **Professional Reporting** - JSON export with comprehensive scan data

---

## ✨ Features

### 🔌 Port Scanning
- **Multi-threaded scanning** for optimal performance (50 TCP threads, 20 UDP threads)
- **Service detection** with banner grabbing
- **Custom port ranges** support
- **Protocol support** for both TCP and UDP
- **Smart filtering** of open, closed, and filtered ports

### 🌐 Subdomain Discovery
- **Certificate Transparency** logs (crt.sh)
- **HackerTarget API** integration
- **AlienVault OTX** threat intelligence
- **DNS brute force** with customizable wordlists
- **Automatic deduplication** and validation

### 🔒 SSL/TLS Analysis
- **Certificate validation** and chain verification
- **Expiry date monitoring** with warnings
- **Self-signed certificate detection**
- **Subject Alternative Names (SANs)** extraction
- **Issuer information** gathering

### 📊 Reporting
- **JSON export** for integration with other tools
- **Color-coded terminal output** for easy reading
- **Timestamped results** for tracking
- **Comprehensive data** including all findings

---

## 🚀 Installation

### Kali Linux / Debian / Ubuntu

```bash
# Clone the repository
git clone https://github.com/cy30rt/prorecon.git
cd prorecon

# Run the installation script
chmod +x install-kali.sh
sudo ./install-kali.sh

# Or install manually
pip3 install -r requirements.txt
chmod +x prorecon.py
```

### Termux (Android)

```bash
# Update Termux
pkg update && pkg upgrade

# Clone the repository
pkg install git
git clone https://github.com/cy30rt/prorecon.git
cd prorecon

# Run Termux installer
chmod +x install-termux.sh
./install-termux.sh

# Grant storage permissions
termux-setup-storage
```

### Manual Installation

```bash
# Install Python dependencies
pip3 install requests urllib3 dnspython

# Make executable
chmod +x prorecon.py

# Run
python3 prorecon.py --help
```

---

## 💻 Usage

### Basic Syntax

```bash
python3 prorecon.py -t <target> [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target domain or IP address (required) |
| `--tcp` | Enable TCP port scanning (enabled by default) |
| `--udp` | Enable UDP port scanning |
| `--subs` | Enable subdomain enumeration |
| `-p, --ports` | Custom port list (e.g., 80,443,8080) |
| `-v, --version` | Show version information |
| `-h, --help` | Show help message |

---

## 📖 Examples

### Basic Domain Scan
```bash
python3 prorecon.py -t example.com
```
Performs TCP port scan and SSL analysis on example.com

### Full Reconnaissance Scan
```bash
python3 prorecon.py -t example.com --tcp --udp --subs
```
Complete scan including TCP, UDP, SSL, and subdomain enumeration

### IP Address Scan
```bash
python3 prorecon.py -t 8.8.8.8 --tcp
```
Scan specific IP address for open TCP ports

### Custom Port Scan
```bash
python3 prorecon.py -t example.com -p 80,443,8080,3306,5432
```
Scan only specified ports

### Subdomain Discovery Only
```bash
python3 prorecon.py -t example.com --subs
```
Focus on subdomain enumeration without port scanning

### Quick Web Server Check
```bash
python3 prorecon.py -t example.com -p 80,443,8080,8443
```
Check common web server ports

### Bug Bounty Recon
```bash
python3 prorecon.py -t target.com --tcp --subs
```
Perfect for initial bug bounty reconnaissance

### Network Infrastructure Audit
```bash
python3 prorecon.py -t company.com --tcp --udp -p 1-1000
```
Comprehensive network service discovery

---

## 📊 Output Format

### Terminal Output
ProRecon provides color-coded, structured output:
- 🔵 **Blue** - Information and progress
- 🟢 **Green** - Success and findings
- 🟡 **Yellow** - Warnings
- 🔴 **Red** - Errors and critical issues

### Sample Output
```
╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗   ║
║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗ ║
║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ██║     ██║   ██║ ║
║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║ ║
║   ██║     ██║  ██║╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝ ║
╚═══════════════════════════════════════════════════════════╝

[*] Resolving example.com...
[+] Resolved: 93.184.216.34

============================================================
TCP PORT SCAN
============================================================
[*] Scanning 23 TCP ports...
[+] 3 open TCP ports

PORT    STATE     SERVICE         BANNER
----------------------------------------------------------------------
80      OPEN      HTTP            Server: nginx/1.18.0
443     OPEN      HTTPS           Server: nginx/1.18.0
8080    OPEN      HTTP-Alt        

============================================================
SSL CERTIFICATE ANALYSIS
============================================================
[+] SSL Certificate Found
  Subject: example.com
  Issuer: Let's Encrypt
  Valid Until: Mar 15 23:59:59 2025 GMT
  Days Until Expiry: 75

============================================================
SUBDOMAIN ENUMERATION
============================================================
[*] Querying crt.sh...
[+] crt.sh: 12 subdomains
[*] Querying HackerTarget...
[+] HackerTarget: 8 subdomains
[*] DNS brute force (22 words)...
[+] DNS Brute: 5 subdomains

Total: 25 subdomains

Subdomains:
   1. www.example.com
   2. mail.example.com
   3. api.example.com
   4. blog.example.com
   ... and 21 more

[+] Saved: prorecon_example_com_20240129_154530.json
```

### JSON Report
Results are automatically saved to timestamped JSON files:
```
prorecon_example_com_20240129_154530.json
```

#### JSON Structure
```json
{
    "target": "example.com",
    "timestamp": "2024-01-29T15:45:30.123456",
    "ip": "93.184.216.34",
    "tcp": {
        "ports": [
            {
                "port": 80,
                "state": "open",
                "service": "HTTP",
                "banner": "Server: nginx/1.18.0"
            },
            {
                "port": 443,
                "state": "open",
                "service": "HTTPS",
                "banner": "Server: nginx/1.18.0"
            }
        ],
        "total": 2
    },
    "udp": {
        "ports": [],
        "total": 0
    },
    "ssl": {
        "hostname": "example.com",
        "port": 443,
        "ssl_enabled": true,
        "certificate": {
            "subject": {
                "commonName": "example.com"
            },
            "issuer": {
                "organizationName": "Let's Encrypt"
            },
            "notBefore": "Dec 15 00:00:00 2024 GMT",
            "notAfter": "Mar 15 23:59:59 2025 GMT",
            "days_until_expiry": 75,
            "subjectAltName": [
                "example.com",
                "www.example.com"
            ]
        },
        "issues": []
    },
    "subdomains": {
        "domain": "example.com",
        "timestamp": "2024-01-29T15:45:30.123456",
        "sources": {
            "crtsh": ["www.example.com", "mail.example.com"],
            "hackertarget": ["api.example.com"],
            "alienvault": ["blog.example.com"],
            "dns_brute": ["dev.example.com"]
        },
        "all_subdomains": [
            "api.example.com",
            "blog.example.com",
            "dev.example.com",
            "mail.example.com",
            "www.example.com"
        ],
        "total": 5
    }
}
```

---

## 🛠️ Technical Details

### Architecture
- **Multi-threaded scanning** for optimal performance
- **Concurrent operations** for parallel requests
- **Thread-safe operations** with proper locking mechanisms
- **Timeout management** to prevent hanging connections
- **Comprehensive error handling** for robust operation

### Performance Metrics
- **TCP Scan Speed**: ~50 ports/second (50 threads)
- **UDP Scan Speed**: ~20 ports/second (20 threads)
- **Subdomain Discovery**: 4 sources queried in parallel
- **Memory Usage**: < 100MB typical usage
- **Network Efficiency**: Smart rate limiting to avoid bans

### Compatibility
- **Python Version**: 3.7+
- **Operating Systems**: 
  - ✅ Kali Linux
  - ✅ Ubuntu/Debian
  - ✅ Termux (Android)
  - ✅ Windows (WSL)
  - ✅ macOS
  - ✅ Parrot OS
  - ✅ BlackArch

### Dependencies
- **requests** - HTTP library for API calls
- **urllib3** - HTTP client with SSL support
- **dnspython** - DNS toolkit for Python

---

## 🔧 Configuration

Edit `config.json` to customize default settings:

```json
{
    "version": "2.0.0",
    "settings": {
        "tcp_timeout": 1.0,
        "udp_timeout": 2.0,
        "max_tcp_threads": 50,
        "max_udp_threads": 20,
        "enable_banner_grab": true,
        "save_results": true
    },
    "tcp_ports": [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        3306, 3389, 5900, 8080, 8443
    ],
    "udp_ports": [
        53, 67, 68, 123, 161, 162, 500, 1900, 5353
    ],
    "subdomain_wordlist": [
        "www", "mail", "api", "dev", "staging", "admin"
    ]
}
```

### Customization Options
- Adjust timeout values for slower networks
- Modify thread counts based on your system
- Add custom ports to default scan lists
- Expand subdomain wordlist for deeper discovery

---

## 🔒 Legal Disclaimer

**⚠️ IMPORTANT: This tool is designed for AUTHORIZED security testing ONLY.**

### Acceptable Use
✅ Authorized penetration testing with written permission  
✅ Bug bounty programs within their scope  
✅ Your own systems and networks  
✅ Educational purposes in controlled environments  
✅ Security research with proper authorization  

### Prohibited Use
❌ Unauthorized network scanning  
❌ Attacking systems without explicit permission  
❌ Violating computer crime laws  
❌ Any illegal activities  
❌ Scanning without proper authorization  

### Your Responsibilities
- **Obtain written permission** before scanning any target
- **Respect rate limits** and terms of service
- **Follow responsible disclosure** practices
- **Comply with local laws** and regulations
- **Use ethically** and professionally

**Unauthorized scanning and hacking is ILLEGAL and may result in criminal prosecution. The author is NOT responsible for any misuse of this tool.**

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Permission Denied Error
```bash
chmod +x prorecon.py
# Or run with python3
python3 prorecon.py -t example.com
```

#### Module Not Found Error
```bash
# Install dependencies
pip3 install -r requirements.txt

# Or install individually
pip3 install requests urllib3 dnspython
```

#### DNS Resolution Fails
- Check your internet connection
- Verify the domain name spelling
- Try using IP address directly
- Check DNS server configuration: `cat /etc/resolv.conf`

#### Slow Scanning
- Reduce thread count in config.json
- Increase timeout values
- Check network connection speed
- Scan specific ports instead of all

#### No Results Found
- Target may have firewall blocking scans
- Services might be on non-standard ports
- Try with different scan options
- Verify target is accessible: `ping target.com`

#### Termux: Results Not Saving
```bash
# Grant storage permissions
termux-setup-storage

# Change to downloads directory
cd ~/storage/downloads

# Run scan from there
python prorecon.py -t example.com
```

#### Termux: Installation Fails
```bash
# Update packages first
pkg update && pkg upgrade -y

# Install dependencies manually
pkg install python git openssl libffi
pip install requests urllib3 dnspython
```

#### Rate Limiting Issues
- Add delays between scans: `time.sleep(5)`
- Reduce concurrent threads
- Use VPN or proxy if necessary
- Respect API rate limits

---

## 📚 Documentation

### Subdomain Enumeration Sources

#### 1. crt.sh - Certificate Transparency Logs
- **Description**: Searches SSL/TLS certificate databases
- **Advantages**: Historical data, no API key required
- **Data Type**: Certificates issued for domain
- **Rate Limit**: Generous, usually no issues
- **Coverage**: Excellent for HTTPS-enabled subdomains

#### 2. HackerTarget - Reconnaissance API
- **Description**: Free security scanning API
- **Advantages**: Multiple data sources, easy to use
- **Data Type**: DNS records, IP data
- **Rate Limit**: 500 requests/day (free tier)
- **Coverage**: Good for common subdomains

#### 3. AlienVault OTX - Threat Intelligence
- **Description**: Open threat exchange platform
- **Advantages**: Passive DNS records, threat data
- **Data Type**: Historical DNS, malware indicators
- **Rate Limit**: Moderate, no key required
- **Coverage**: Excellent for security research

#### 4. DNS Brute Force - Active Discovery
- **Description**: Direct DNS queries with wordlist
- **Advantages**: Finds current, active subdomains
- **Data Type**: Live DNS resolution
- **Rate Limit**: Based on DNS server
- **Coverage**: Limited to wordlist quality

### Port Scanning Methodology

#### TCP Scanning
1. **SYN Connection** - Establishes TCP handshake
2. **Service Detection** - Identifies running service
3. **Banner Grabbing** - Retrieves service version
4. **State Classification** - Open, closed, or filtered

#### UDP Scanning
1. **Packet Transmission** - Sends UDP probe
2. **Response Analysis** - Checks for replies
3. **ICMP Interpretation** - Handles error messages
4. **State Determination** - Open, filtered, or closed

### SSL/TLS Analysis Process

1. **Connection Establishment** - TLS handshake
2. **Certificate Retrieval** - Downloads cert chain
3. **Validation Checks** - Expiry, issuer, subject
4. **Security Assessment** - Self-signed, weak crypto
5. **Alternative Names** - SANs extraction


## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- ⭐ Star the repository
- 📢 Share with the community

### Development Setup

# Fork and clone
git clone https://github.com/YOUR_USERNAME/prorecon.git
cd prorecon

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
python3 prorecon.py -t example.com

# Commit and push
git add .
git commit -m "Add your feature"
git push origin feature/your-feature-name

### Code Style Guidelines
- Follow **PEP 8** Python style guide
- Add **docstrings** to all functions
- Include **error handling** for edge cases
- Write **clear comments** for complex logic
- Update **documentation** for new features
- Add **examples** for new functionality

### Pull Request Process
1. Update README.md with changes
2. Ensure all tests pass
3. Add description of changes
4. Reference any related issues
5. Wait for review and feedback


## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ⚠️ No warranty provided
- ⚠️ No liability accepted


## 👤 Author

**Abdulbasid Yakubu | cy30rt**

- 🐙 GitHub: [@cy30rt](https://github.com/abdlcybort)
- 🐦 Twitter: [@cy30rt](https://twitter.com/cy30rt)
- 📧 Email: contact@abdulcybort.com
- 🌐 Website: [cy30rt.com](https://cy30rt.com)

### About the Author
Cybersecurity researcher and bug bounty hunter passionate about building tools for the security community. Specializing in reconnaissance, vulnerability assessment, and automation.


## 🌟 Support the Project

If you find ProRecon useful, please consider:

- ⭐ **Star the repository** - Shows appreciation
- 🐛 **Report bugs** - Helps improve quality
- 💡 **Request features** - Guides development
- 🤝 **Contribute code** - Makes it better
- 📢 **Share with others** - Grows the community
- ☕ **Buy me a coffee** - Supports development

### Star History
[![Star History Chart](https://api.star-history.com/svg?repos=cy30rt/prorecon&type=Date)](https://star-history.com/#cy30rt/prorecon&Date)


## 📝 Changelog

### Version 2.0.0 (2024-01-29) - Current Release
- ✨ Complete rewrite for production readiness
- 🚀 Multi-threaded scanning engine (50x faster)
- 🔒 SSL/TLS certificate analysis
- 🌐 Enhanced subdomain enumeration (4 sources)
- 📱 Full Termux/Android compatibility
- 📊 Professional JSON reporting
- 🎨 Color-coded terminal output
- 🔧 Configurable settings via JSON
- 🐛 Comprehensive error handling
- 📚 Professional documentation

### Version 1.0.0 (2023-12-01)
- 🎉 Initial release
- 🔌 Basic TCP port scanning
- 🌐 Simple subdomain enumeration
- 📄 Basic text output

## 🎯 Roadmap

### Planned Features
- [ ] API key support for enhanced enumeration
- [ ] Shodan integration
- [ ] VirusTotal scanning
- [ ] Screenshot capture
- [ ] Technology detection
- [ ] WHOIS lookup
- [ ] Reverse IP lookup
- [ ] Email harvesting
- [ ] Export to multiple formats (CSV, XML, HTML)
- [ ] GUI interface
- [ ] Web dashboard
- [ ] Scheduled scans
- [ ] Notification system
- [ ] Custom plugins support

### Future Improvements
- [ ] Faster scanning algorithms
- [ ] Better error recovery
- [ ] Enhanced reporting
- [ ] Machine learning integration
- [ ] Cloud deployment options

---

## 🙏 Acknowledgments

Special thanks to:

- **Certificate Transparency Project** - crt.sh database
- **HackerTarget** - Free reconnaissance API
- **AlienVault** - Open Threat Exchange platform
- **Python Community** - Excellent libraries and support
- **Bug Bounty Community** - Feedback and testing
- **Security Researchers** - Inspiration and guidance

### Tools That Inspired ProRecon
- Subfinder
- Amass
- Nmap
- Masscan
- DNSRecon

---

## 📖 Additional Resources

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [HackerOne Resources](https://www.hackerone.com/ethical-hacker)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

### Related Tools
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain discovery
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [naabu](https://github.com/projectdiscovery/naabu) - Port scanner

### Bug Bounty Platforms
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)

---

## 💬 Community

Join the ProRecon community:

- 💬 [Discord Server](https://discord.gg/prorecon)
- 📱 [Telegram Group](https://t.me/prorecon)
- 🐦 [Twitter Updates](https://twitter.com/cy30rt)
- 📧 [Mailing List](mailto:subscribe@prorecon.com)

---

## ❓ FAQ

### Is ProRecon free to use?
Yes, ProRecon is completely free and open-source under the MIT license.

### Do I need API keys?
No, ProRecon works without any API keys. All enumeration sources used are free and public.

### Can I use this for bug bounties?
Yes, ProRecon is designed specifically for bug bounty reconnaissance and authorized security testing.

### Is it legal to use this tool?
Yes, when used on systems you own or have explicit permission to test. Always get written authorization first.

### Does it work on Android?
Yes, ProRecon has full Termux support for Android devices.

### How fast is the scanning?
TCP scanning averages 50 ports/second. Full domain recon typically takes 2-5 minutes.

### Can I customize the wordlist?
Yes, edit the `subdomain_wordlist` array in `config.json`.

### Does it support proxies?
Not currently, but proxy support is planned for future releases.

### How do I report bugs?
Open an issue on GitHub with details about the problem and your environment.

### Can I contribute?
Absolutely! Pull requests are welcome. See the Contributing section above.



<div align="center">

**Made with ❤️ for the Security Community**

*Remember: Always obtain proper authorization before testing!*

**ProRecon v2.0.0** | **© 2024 Abdulbasid Yakubu | cy30rt**

[⬆ Back to Top](#-prorecon---professional-reconnaissance-tool)

</div>
