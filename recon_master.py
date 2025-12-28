#!/usr/bin/env python3

"""
ReconMaster - Professional Bug Bounty Reconnaissance Tool
Author: Abdulbasid Yakubu | cy30rt
Version: 1.1.0 - Enhanced with Advanced Subdomain Discovery
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Optional
import urllib3
import concurrent.futures
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Config:
    """Configuration manager for API keys"""
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), 'config.json')
        self.apis = self.load_config()
    
    def load_config(self) -> Dict:
        """Load API keys from config file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{Colors.RED}[!] Error loading config: {e}{Colors.END}")
                return {}
        return {}
    
    def save_config(self, apis: Dict):
        """Save API keys to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(apis, f, indent=4)
            print(f"{Colors.GREEN}[+] Configuration saved successfully!{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving config: {e}{Colors.END}")

class SubdomainEnumerator:
    """Advanced subdomain enumeration engine"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Common subdomain wordlist
        self.common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
            'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
            'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
            'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
            'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login',
            'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage',
            'ldap', 'tv', 'ssl', 'web1', 'tracker', 'web2', 'finance', 'upload', 'billing',
            'video1', 'registration', 'jobs', 'jenkins', 'jira', 'confluence', 'gitlab', 'github'
        ]
    
    def crtsh_search(self) -> List[str]:
        """Search crt.sh certificate transparency logs"""
        print(f"{Colors.BLUE}[*] Searching Certificate Transparency logs (crt.sh)...{Colors.END}")
        found = []
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and multiple names
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().lower()
                            if n.endswith(self.domain) and n != self.domain:
                                n = n.replace('*.', '')
                                found.append(n)
                
                found = list(set(found))
                print(f"{Colors.GREEN}[+] crt.sh: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] crt.sh: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] crt.sh error: {str(e)}{Colors.END}")
            return []
    
    def hackertarget_search(self) -> List[str]:
        """Search HackerTarget API"""
        print(f"{Colors.BLUE}[*] Querying HackerTarget API...{Colors.END}")
        found = []
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(self.domain):
                            found.append(subdomain)
                
                found = list(set(found))
                print(f"{Colors.GREEN}[+] HackerTarget: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] HackerTarget: Rate limited or no data{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] HackerTarget error: {str(e)}{Colors.END}")
            return []
    
    def threatcrowd_search(self) -> List[str]:
        """Search ThreatCrowd API"""
        print(f"{Colors.BLUE}[*] Querying ThreatCrowd API...{Colors.END}")
        found = []
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                found = [s for s in subdomains if s.endswith(self.domain)]
                
                print(f"{Colors.GREEN}[+] ThreatCrowd: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] ThreatCrowd: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] ThreatCrowd error: {str(e)}{Colors.END}")
            return []
    
    def alienvault_search(self) -> List[str]:
        """Search AlienVault OTX API"""
        print(f"{Colors.BLUE}[*] Querying AlienVault OTX...{Colors.END}")
        found = []
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(self.domain) and hostname != self.domain:
                        found.append(hostname)
                
                found = list(set(found))
                print(f"{Colors.GREEN}[+] AlienVault: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] AlienVault: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] AlienVault error: {str(e)}{Colors.END}")
            return []
    
    def urlscan_search(self) -> List[str]:
        """Search URLScan.io API"""
        print(f"{Colors.BLUE}[*] Querying URLScan.io...{Colors.END}")
        found = []
        
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.session.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain and page_domain.endswith(self.domain) and page_domain != self.domain:
                        found.append(page_domain)
                
                found = list(set(found))
                print(f"{Colors.GREEN}[+] URLScan: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] URLScan: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] URLScan error: {str(e)}{Colors.END}")
            return []
    
    def brute_force(self, wordlist: List[str] = None, threads: int = 10) -> List[str]:
        """Brute force subdomain discovery using DNS resolution"""
        print(f"{Colors.BLUE}[*] Starting DNS brute force attack...{Colors.END}")
        
        if wordlist is None:
            wordlist = self.common_subs
        
        found = []
        
        def check_subdomain(sub):
            try:
                import socket
                hostname = f"{sub}.{self.domain}"
                socket.gethostbyname(hostname)
                return hostname
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        print(f"{Colors.GREEN}[+] DNS Brute Force: Found {len(found)} active subdomains{Colors.END}")
        return found
    
    def enumerate_all(self, brute_force: bool = True) -> Dict:
        """Run all enumeration methods"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}  SUBDOMAIN ENUMERATION ENGINE{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{self.domain}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
        
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'all_subdomains': [],
            'active_subdomains': []
        }
        
        # Passive enumeration
        print(f"{Colors.YELLOW}[*] Phase 1: Passive Subdomain Discovery{Colors.END}\n")
        
        sources = [
            ('crtsh', self.crtsh_search),
            ('hackertarget', self.hackertarget_search),
            ('threatcrowd', self.threatcrowd_search),
            ('alienvault', self.alienvault_search),
            ('urlscan', self.urlscan_search)
        ]
        
        for source_name, source_func in sources:
            try:
                found = source_func()
                results['sources'][source_name] = found
                self.subdomains.update(found)
                time.sleep(1)  # Rate limiting
            except Exception as e:
                print(f"{Colors.RED}[!] {source_name} failed: {str(e)}{Colors.END}")
                results['sources'][source_name] = []
        
        # Active enumeration
        if brute_force:
            print(f"\n{Colors.YELLOW}[*] Phase 2: Active DNS Brute Force{Colors.END}\n")
            try:
                found = self.brute_force()
                results['sources']['dns_brute_force'] = found
                self.subdomains.update(found)
            except Exception as e:
                print(f"{Colors.RED}[!] DNS brute force failed: {str(e)}{Colors.END}")
                results['sources']['dns_brute_force'] = []
        
        # Compile results
        results['all_subdomains'] = sorted(list(self.subdomains))
        results['total_found'] = len(self.subdomains)
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  SUBDOMAIN ENUMERATION COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Total Subdomains Found: {Colors.BOLD}{len(self.subdomains)}{Colors.END}")
        print(f"{Colors.CYAN}  Sources Used: {len([s for s in results['sources'] if results['sources'][s]])}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
        
        # Display top subdomains
        if self.subdomains:
            print(f"{Colors.YELLOW}Sample Subdomains:{Colors.END}")
            for i, sub in enumerate(sorted(list(self.subdomains))[:20], 1):
                print(f"  {i}. {sub}")
            if len(self.subdomains) > 20:
                print(f"  ... and {len(self.subdomains) - 20} more\n")
        
        return results

class ReconMaster:
    """Main reconnaissance tool class"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.results = {}
    
    def banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
    ╠╦╝║╣ ║  ║ ║║║║  ║║║╠═╣╚═╗ ║ ║╣ ╠╦╝
    ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╩ ╩╩ ╩╚═╝ ╩ ╚═╝╩╚═
{Colors.END}
{Colors.YELLOW}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Professional Bug Bounty Reconnaissance Tool
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
{Colors.GREEN}    Version: 1.1.0 (Enhanced Edition)
    Author:  Abdulbasid Yakubu | cy30rt
{Colors.END}
{Colors.CYAN}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Multi-Source Intelligence Gathering
    + Advanced Subdomain Enumeration
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
        """
        print(banner)
    
    def save_results(self, target: str):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"recon_{target.replace('.', '_')}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"\n{Colors.GREEN}[+] Results saved to: {filename}{Colors.END}")
            return filename
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}")
            return None
    
    def shodan_lookup(self, target: str) -> Dict:
        """Query Shodan API for host information"""
        print(f"\n{Colors.BLUE}[*] Querying Shodan database...{Colors.END}")
        
        api_key = self.config.apis.get('shodan')
        if not api_key or api_key == "YOUR_SHODAN_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] Shodan API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] Shodan: Data retrieved successfully{Colors.END}")
                print(f"    IP: {data.get('ip_str', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    Country: {data.get('country_name', 'N/A')}")
                print(f"    OS: {data.get('os', 'N/A')}")
                print(f"    Open Ports: {', '.join(map(str, data.get('ports', []))) if data.get('ports') else 'None'}")
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] Shodan: Invalid API key{Colors.END}")
                return {}
            elif response.status_code == 404:
                print(f"{Colors.YELLOW}[!] Shodan: No information found for this host{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] Shodan API error: {response.status_code}{Colors.END}")
                return {}
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] Shodan: Request timeout{Colors.END}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Shodan error: {str(e)}{Colors.END}")
            return {}
        except Exception as e:
            print(f"{Colors.RED}[!] Shodan unexpected error: {str(e)}{Colors.END}")
            return {}
    
    def securitytrails_lookup(self, domain: str) -> Dict:
        """Query SecurityTrails API for domain information"""
        print(f"\n{Colors.BLUE}[*] Querying SecurityTrails database...{Colors.END}")
        
        api_key = self.config.apis.get('securitytrails')
        if not api_key or api_key == "YOUR_SECURITYTRAILS_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] SecurityTrails API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}"
            headers = {'APIKEY': api_key}
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] SecurityTrails: Domain data retrieved{Colors.END}")
                
                # Get subdomains
                subdomain_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                sub_response = self.session.get(subdomain_url, headers=headers, timeout=15)
                
                if sub_response.status_code == 200:
                    subdomains = sub_response.json().get('subdomains', [])
                    print(f"    Subdomains discovered: {len(subdomains)}")
                    if subdomains:
                        print(f"    Sample subdomains: {', '.join(subdomains[:5])}")
                    data['subdomains'] = subdomains[:50]  # Limit to first 50
                
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] SecurityTrails: Invalid API key{Colors.END}")
                return {}
            elif response.status_code == 404:
                print(f"{Colors.YELLOW}[!] SecurityTrails: Domain not found{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] SecurityTrails API error: {response.status_code}{Colors.END}")
                return {}
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] SecurityTrails: Request timeout{Colors.END}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] SecurityTrails error: {str(e)}{Colors.END}")
            return {}
        except Exception as e:
            print(f"{Colors.RED}[!] SecurityTrails unexpected error: {str(e)}{Colors.END}")
            return {}
    
    def ipinfo_lookup(self, ip: str) -> Dict:
        """Query IPInfo API for IP geolocation"""
        print(f"\n{Colors.BLUE}[*] Querying IPInfo database...{Colors.END}")
        
        api_key = self.config.apis.get('ipinfo')
        if not api_key or api_key == "YOUR_IPINFO_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] IPInfo API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://ipinfo.io/{ip}?token={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] IPInfo: Geolocation data retrieved{Colors.END}")
                print(f"    Location: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    Timezone: {data.get('timezone', 'N/A')}")
                print(f"    Coordinates: {data.get('loc', 'N/A')}")
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] IPInfo: Invalid API key{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] IPInfo API error: {response.status_code}{Colors.END}")
                return {}
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] IPInfo: Request timeout{Colors.END}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] IPInfo error: {str(e)}{Colors.END}")
            return {}
        except Exception as e:
            print(f"{Colors.RED}[!] IPInfo unexpected error: {str(e)}{Colors.END}")
            return {}
    
    def virustotal_lookup(self, target: str, scan_type: str = 'domain') -> Dict:
        """Query VirusTotal API for security analysis"""
        print(f"\n{Colors.BLUE}[*] Querying VirusTotal database...{Colors.END}")
        
        api_key = self.config.apis.get('virustotal')
        if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] VirusTotal API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            headers = {'x-apikey': api_key}
            
            if scan_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] VirusTotal: Security analysis completed{Colors.END}")
                
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                clean = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                
                print(f"    Malicious detections: {malicious}")
                print(f"    Suspicious detections: {suspicious}")
                print(f"    Clean detections: {clean}")
                print(f"    Undetected: {undetected}")
                
                if malicious > 0:
                    print(f"{Colors.RED}    ⚠️  WARNING: Target flagged as malicious by {malicious} vendors{Colors.END}")
                elif suspicious > 0:
                    print(f"{Colors.YELLOW}    ⚠️  CAUTION: Target flagged as suspicious by {suspicious} vendors{Colors.END}")
                else:
                    print(f"{Colors.GREEN}    ✓ Target appears clean{Colors.END}")
                
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] VirusTotal: Invalid API key{Colors.END}")
                return {}
            elif response.status_code == 404:
                print(f"{Colors.YELLOW}[!] VirusTotal: No data found for this target{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] VirusTotal API error: {response.status_code}{Colors.END}")
                return {}
        except requests.exceptions.Timeout:
            print(f"{Colors.RED}[!] VirusTotal: Request timeout{Colors.END}")
            return {}
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] VirusTotal error: {str(e)}{Colors.END}")
            return {}
        except Exception as e:
            print(f"{Colors.RED}[!] VirusTotal unexpected error: {str(e)}{Colors.END}")
            return {}
    
    def full_recon(self, target: str, target_type: str = 'auto', enum_subdomains: bool = False):
        """Perform full reconnaissance on target"""
        print(f"\n{Colors.YELLOW}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}  INITIATING RECONNAISSANCE{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{target}{Colors.END}")
        print(f"{Colors.CYAN}  Type: {target_type}{Colors.END}")
        print(f"{Colors.CYAN}  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': target_type,
            'shodan': {},
            'securitytrails': {},
            'ipinfo': {},
            'virustotal': {},
            'subdomain_enum': {}
        }
        
        # Determine if target is IP or domain
        is_ip = all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.')) if target.count('.') == 3 else False
        
        if is_ip or target_type == 'ip':
            # IP-based reconnaissance
            print(f"\n{Colors.CYAN}[*] Detected IP address target - running IP-based reconnaissance{Colors.END}")
            
            self.results['shodan'] = self.shodan_lookup(target)
            time.sleep(2)
            
            self.results['ipinfo'] = self.ipinfo_lookup(target)
            time.sleep(2)
            
            self.results['virustotal'] = self.virustotal_lookup(target, 'ip')
            
        else:
            # Domain-based reconnaissance
            print(f"\n{Colors.CYAN}[*] Detected domain target - running domain-based reconnaissance{Colors.END}")
            
            # Subdomain enumeration (if enabled)
            if enum_subdomains:
                enumerator = SubdomainEnumerator(target)
                self.results['subdomain_enum'] = enumerator.enumerate_all(brute_force=True)
                time.sleep(2)
            
            self.results['securitytrails'] = self.securitytrails_lookup(target)
            time.sleep(2)
            
            self.results['virustotal'] = self.virustotal_lookup(target, 'domain')
            time.sleep(2)
            
            # Try to resolve domain to IP
            try:
                import socket
                print(f"\n{Colors.BLUE}[*] Resolving domain to IP address...{Colors.END}")
                ip = socket.gethostbyname(target)
                print(f"{Colors.GREEN}[+] Resolved IP: {ip}{Colors.END}")
                self.results['resolved_ip'] = ip
                
                # Run IP-based checks
                time.sleep(2)
                self.results['shodan'] = self.shodan_lookup(ip)
                time.sleep(2)
                self.results['ipinfo'] = self.ipinfo_lookup(ip)
                
            except socket.gaierror:
                print(f"{Colors.RED}[!] Could not resolve domain to IP address{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error resolving domain: {str(e)}{Colors.END}")
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  RECONNAISSANCE COMPLETED{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        
        # Summary
        apis_used = sum(1 for v in [self.results['shodan'], self.results['securitytrails'], 
                                     self.results['ipinfo'], self.results['virustotal']] if v)
        print(f"{Colors.CYAN}  APIs queried: {apis_used}/4{Colors.END}")
        print(f"{Colors.CYAN}  Data points collected: {len(str(self.results))}{Colors.END}")
        
        if enum_subdomains and self.results.get('subdomain_enum'):
            subdomain_count = self.results['subdomain_enum'].get('total_found', 0)
            print(f"{Colors.CYAN}  Subdomains discovered: {subdomain_count}{Colors.END}")
        
        filename = self.save_results(target)
        if filename:
            print(f"{Colors.GREEN}  Report: {filename}{Colors.END}")
        
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")

def setup_wizard():
    """Interactive setup wizard for API keys"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  RECONMASTER SETUP WIZARD{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
    
    print(f"{Colors.YELLOW}Configure your API keys for enhanced reconnaissance.{Colors.END}")
    print(f"{Colors.YELLOW}Press Enter to skip any API you don't have.{Colors.END}\n")
    
    apis = {}
    
    print(f"{Colors.CYAN}[1/4] Shodan API Configuration{Colors.END}")
    print(f"      Get your key at: https://account.shodan.io/")
    apis['shodan'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[2/4] SecurityTrails API Configuration{Colors.END}")
    print(f"      Get your key at: https://securitytrails.com/")
    apis['securitytrails'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[3/4] IPInfo API Configuration{Colors.END}")
    print(f"      Get your key at: https://ipinfo.io/")
    apis['ipinfo'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[4/4] VirusTotal API Configuration{Colors.END}")
    print(f"      Get your key at: https://www.virustotal.com/")
    apis['virustotal'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    # Remove empty keys
    apis = {k: v for k, v in apis.items() if v}
    
    if apis:
        config = Config()
        config.save_config(apis)
        print(f"\n{Colors.GREEN}[+] Configuration saved! {len(apis)}/4 APIs configured.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[!] No API keys provided. You can run setup again anytime.{Colors.END}")
    
    print(f"{Colors.CYAN}\nYou're ready to start reconnaissance!{Colors.END}")
    print(f"{Colors.CYAN}Example: python3 recon_master.py -t example.com{Colors.END}")
    print(f"{Colors.CYAN}Example with subdomain enum: python3 recon_master.py -t example.com --enum-subs{Colors.END}\n")

def main():
    parser = argparse.ArgumentParser(
        description='ReconMaster - Professional Bug Bounty Reconnaissance Tool by Abdulbasid Yakubu | cy30rt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.END}
  python3 recon_master.py -t example.com          Scan a domain
  python3 recon_master.py -t example.com --enum-subs    Scan with subdomain enumeration
  python3 recon_master.py -t 8.8.8.8              Scan an IP address
  python3 recon_master.py -t target.com --type domain
  python3 recon_master.py --setup                 Configure API keys
  python3 recon_master.py --enum-only example.com Subdomain enumeration only

{Colors.YELLOW}Author: Abdulbasid Yakubu | cy30rt{Colors.END}
        """
    )
    
    parser.add_argument('-t', '--target', help='Target domain or IP address')
    parser.add_argument('--type', choices=['auto', 'ip', 'domain'], default='auto',
                       help='Target type (default: auto)')
    parser.add_argument('--setup', action='store_true', help='Run setup wizard to configure API keys')
    parser.add_argument('-o', '--output', help='Custom output filename (optional)')
    parser.add_argument('--enum-subs', action='store_true', help='Enable comprehensive subdomain enumeration')
    parser.add_argument('--enum-only', metavar='DOMAIN', help='Run subdomain enumeration only (no other recon)')
    parser.add_argument('-v', '--version', action='version', version='ReconMaster v1.1.0 by Abdulbasid Yakubu | cy30rt')
    
    args = parser.parse_args()
    
    config = Config()
    recon = ReconMaster(config)
    
    recon.banner()
    
    if args.setup:
        setup_wizard()
        return
    
    # Subdomain enumeration only mode
    if args.enum_only:
        print(f"{Colors.YELLOW}[*] Running subdomain enumeration only mode{Colors.END}")
        enumerator = SubdomainEnumerator(args.enum_only)
        results = enumerator.enumerate_all(brute_force=True)
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"subdomains_{args.enum_only.replace('.', '_')}_{timestamp}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"{Colors.GREEN}[+] Results saved to: {filename}{Colors.END}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}\n")
        return
    
    if not args.target:
        print(f"{Colors.RED}[!] Error: Target required. Use -h for help.{Colors.END}\n")
        parser.print_help()
        return
    
    if not config.apis and not args.enum_only:
        print(f"{Colors.YELLOW}[!] No API keys configured.{Colors.END}")
        print(f"{Colors.YELLOW}[!] Run 'python3 recon_master.py --setup' to configure APIs.{Colors.END}")
        print(f"{Colors.YELLOW}[!] Subdomain enumeration will still work without API keys.{Colors.END}")
        print(f"{Colors.YELLOW}[!] Continuing with limited functionality...\n{Colors.END}")
    
    try:
        recon.full_recon(args.target, args.type, enum_subdomains=args.enum_subs)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        print(f"{Colors.YELLOW}[!] Partial results may have been saved{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        print(f"{Colors.RED}[!] Please report this issue if it persists{Colors.END}\n")

if __name__ == "__main__":
    main()
