#!/usr/bin/env python3

"""
ReconMaster IP - IP & Subdomain Reconnaissance Tool
Author: Abdulbasid Yakubu | cy30rt
Version: 2.0.0 - IP & Subdomain Focused
"""

import os
import sys
import json
import time
import argparse
import requests
import asyncio
import aiohttp
import random
import socket
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
import urllib3
import concurrent.futures
import dns.resolver
import re

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

class IPTools:
    """IP address utility tools"""
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if IP is private/RFC1918"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False
    
    @staticmethod
    def get_ip_range(start_ip: str, end_ip: str) -> List[str]:
        """Generate list of IPs in a range"""
        try:
            start = int(ipaddress.ip_address(start_ip))
            end = int(ipaddress.ip_address(end_ip))
            return [str(ipaddress.ip_address(ip)) for ip in range(start, end + 1)]
        except:
            return []
    
    @staticmethod
    def cidr_to_ips(cidr: str) -> List[str]:
        """Convert CIDR notation to list of IPs"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return []

class SubdomainEnumerator:
    """Fast subdomain enumeration engine"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        # Common subdomain wordlist
        self.common_subs = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
            'admin', 'administrator', 'dashboard', 'control', 'cp',
            'api', 'api1', 'api2', 'api3', 'rest', 'graphql',
            'dev', 'development', 'staging', 'test', 'testing', 'qa',
            'blog', 'news', 'forum', 'forums', 'community',
            'shop', 'store', 'cart', 'checkout', 'payment',
            'cdn', 'static', 'assets', 'media', 'images', 'img',
            'app', 'apps', 'mobile', 'm', 'wap',
            'secure', 'ssl', 'vpn', 'remote', 'ssh',
            'db', 'database', 'sql', 'mysql', 'postgres',
            'git', 'gitlab', 'github', 'bitbucket',
            'jenkins', 'ci', 'cd', 'deploy',
            'monitor', 'monitoring', 'stats', 'analytics',
            'old', 'new', 'temp', 'tmp', 'backup',
            'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
            'mx1', 'mx2', 'mx3', 'mail1', 'mail2',
            'vpn1', 'vpn2', 'proxy', 'gateway',
            'beta', 'alpha', 'gamma', 'demo', 'stage',
            'internal', 'intranet', 'portal', 'extranet',
            'partner', 'partners', 'client', 'clients',
            'support', 'help', 'contact', 'info',
            'status', 'uptime', 'health', 'ping',
            'search', 'find', 'discover',
            'auth', 'authentication', 'login', 'signin',
            'register', 'signup', 'account', 'profile',
            'download', 'uploads', 'files', 'docs',
            'wiki', 'documentation', 'helpdesk',
            'cms', 'content', 'blog', 'news',
            'events', 'calendar', 'schedule',
            'jobs', 'careers', 'recruitment',
            'legal', 'terms', 'privacy', 'policy'
        ]
        
        # Add number permutations
        for num in range(1, 10):
            self.common_subs.extend([f'web{num}', f'app{num}', f'api{num}', f'srv{num}', f'prod{num}'])
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    def reverse_dns(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup"""
        try:
            answers = self.resolver.resolve_address(ip)
            return [str(rdata) for rdata in answers]
        except:
            return []
    
    def crtsh_search(self) -> List[str]:
        """Search crt.sh certificate transparency logs"""
        print(f"{Colors.BLUE}[*] Searching Certificate Transparency logs (crt.sh)...{Colors.END}")
        found = []
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().lower()
                            if n.endswith(self.domain) and n != self.domain:
                                n = n.replace('*.', '').replace('www.', '')
                                if n not in found:
                                    found.append(n)
                
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
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(self.domain) and subdomain != self.domain:
                            if subdomain not in found:
                                found.append(subdomain)
                
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
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                for s in subdomains:
                    if s.endswith(self.domain) and s != self.domain and s not in found:
                        found.append(s)
                
                print(f"{Colors.GREEN}[+] ThreatCrowd: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] ThreatCrowd: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] ThreatCrowd error: {str(e)}{Colors.END}")
            return []
    
    def brute_force(self, threads: int = 50) -> List[str]:
        """Brute force subdomain discovery using DNS resolution"""
        print(f"{Colors.BLUE}[*] Starting DNS brute force attack...{Colors.END}")
        found = []
        
        def check_subdomain(sub: str) -> Optional[str]:
            try:
                hostname = f"{sub}.{self.domain}"
                answers = self.resolver.resolve(hostname, 'A')
                if answers:
                    return hostname
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.common_subs}
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                result = future.result()
                if result:
                    found.append(result)
                
                # Progress indicator
                if (i + 1) % 50 == 0:
                    print(f"{Colors.CYAN}[*] Checked {i+1}/{len(self.common_subs)} subdomains{Colors.END}")
        
        print(f"{Colors.GREEN}[+] DNS Brute Force: Found {len(found)} active subdomains{Colors.END}")
        return found
    
    def enumerate_all(self) -> Dict:
        """Run all enumeration methods"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}  SUBDOMAIN ENUMERATION{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{self.domain}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
        
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'all_subdomains': [],
            'ip_addresses': {},
            'statistics': {}
        }
        
        # Passive enumeration
        print(f"{Colors.YELLOW}[*] Phase 1: Passive Discovery{Colors.END}")
        
        sources = [
            ('crtsh', self.crtsh_search),
            ('hackertarget', self.hackertarget_search),
            ('threatcrowd', self.threatcrowd_search)
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
        print(f"\n{Colors.YELLOW}[*] Phase 2: DNS Brute Force{Colors.END}")
        try:
            found = self.brute_force(threads=50)
            results['sources']['dns_brute_force'] = found
            self.subdomains.update(found)
        except Exception as e:
            print(f"{Colors.RED}[!] DNS brute force failed: {str(e)}{Colors.END}")
            results['sources']['dns_brute_force'] = []
        
        # Resolve IP addresses for each subdomain
        print(f"\n{Colors.YELLOW}[*] Phase 3: IP Resolution{Colors.END}")
        ip_map = {}
        for subdomain in sorted(self.subdomains):
            ips = self.resolve_domain(subdomain)
            if ips:
                ip_map[subdomain] = ips
                print(f"  {subdomain} -> {', '.join(ips)}")
        
        results['ip_addresses'] = ip_map
        results['all_subdomains'] = sorted(list(self.subdomains))
        results['total_found'] = len(self.subdomains)
        
        # Statistics
        all_ips = set()
        for ips in ip_map.values():
            all_ips.update(ips)
        
        stats = {
            'total_subdomains': len(self.subdomains),
            'total_unique_ips': len(all_ips),
            'sources_used': len([s for s in results['sources'] if results['sources'][s]]),
            'subdomains_with_ips': len(ip_map)
        }
        results['statistics'] = stats
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  ENUMERATION COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"\n{Colors.CYAN}📊 Statistics:{Colors.END}")
        print(f"  Total Subdomains: {stats['total_subdomains']}")
        print(f"  Unique IP Addresses: {stats['total_unique_ips']}")
        print(f"  Subdomains with IPs: {stats['subdomains_with_ips']}")
        
        if self.subdomains:
            print(f"\n{Colors.YELLOW}Top Subdomains:{Colors.END}")
            for i, sub in enumerate(sorted(list(self.subdomains))[:10], 1):
                print(f"  {i}. {sub}")
            if len(self.subdomains) > 10:
                print(f"  ... and {len(self.subdomains) - 10} more")
        
        if all_ips:
            print(f"\n{Colors.YELLOW}Unique IP Addresses:{Colors.END}")
            for i, ip in enumerate(sorted(list(all_ips))[:10], 1):
                print(f"  {i}. {ip}")
            if len(all_ips) > 10:
                print(f"  ... and {len(all_ips) - 10} more")
        
        print()
        return results

class IPReconnaissance:
    """IP address reconnaissance engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
    ╠╦╝║╣ ║  ║ ║║║║  ║║║╠═╣╚═╗ ║ ║╣ ╠╦╝
    ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╩ ╩╩ ╩╚═╝ ╩ ╚═╝╩╚═
    
    ╔═╗╔═╗     ╔═╗╔╦╗╔═╗╔═╗╔═╗╔═╗
    ║ ╦║╣      ╠═╣ ║║╠═╣║  ║ ║╚═╗
    ╚═╝╚═╝     ╩ ╩═╩╝╩ ╩╚═╝╚═╝╚═╝
{Colors.END}
{Colors.YELLOW}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    IP & Subdomain Reconnaissance Tool
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
{Colors.GREEN}    Version: 2.0.0 (IP & Subdomain Focused)
    Author:  Abdulbasid Yakubu | cy30rt
{Colors.END}
{Colors.CYAN}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    + IP Address Intelligence
    + Subdomain Enumeration
    + Port Scanning (Basic)
    + Reverse DNS Lookup
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
        """
        print(banner)
    
    def shodan_lookup(self, ip: str) -> Dict:
        """Query Shodan API for IP information"""
        print(f"{Colors.BLUE}[*] Querying Shodan database...{Colors.END}")
        
        api_key = self.config.apis.get('shodan')
        if not api_key or api_key == "YOUR_SHODAN_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] Shodan API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] Shodan: Data retrieved successfully{Colors.END}")
                
                print(f"    IP: {data.get('ip_str', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    ISP: {data.get('isp', 'N/A')}")
                print(f"    Country: {data.get('country_name', 'N/A')}")
                print(f"    City: {data.get('city', 'N/A')}")
                print(f"    OS: {data.get('os', 'N/A')}")
                
                # Ports and services
                ports = data.get('ports', [])
                if ports:
                    print(f"    Open Ports: {', '.join(map(str, ports))}")
                    
                    # Show services on common ports
                    common_ports = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 53: 'DNS'}
                    for port in ports[:10]:  # Show first 10
                        service = common_ports.get(port, 'Unknown')
                        print(f"      Port {port}: {service}")
                
                # Vulnerabilities
                vulns = data.get('vulns', [])
                if vulns:
                    print(f"    Vulnerabilities: {len(vulns)} found")
                    for vuln in list(vulns.keys())[:5]:
                        print(f"      • {vuln}")
                
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] Shodan: Invalid API key{Colors.END}")
                return {}
            elif response.status_code == 404:
                print(f"{Colors.YELLOW}[!] Shodan: No information found for this IP{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] Shodan API error: {response.status_code}{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] Shodan error: {str(e)}{Colors.END}")
            return {}
    
    def ipinfo_lookup(self, ip: str) -> Dict:
        """Query IPInfo API for geolocation"""
        print(f"{Colors.BLUE}[*] Querying IPInfo database...{Colors.END}")
        
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
                
                print(f"    IP: {data.get('ip', 'N/A')}")
                print(f"    Hostname: {data.get('hostname', 'N/A')}")
                print(f"    City: {data.get('city', 'N/A')}")
                print(f"    Region: {data.get('region', 'N/A')}")
                print(f"    Country: {data.get('country', 'N/A')}")
                print(f"    Location: {data.get('loc', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    Timezone: {data.get('timezone', 'N/A')}")
                
                # Check if it's a hosting provider
                org = data.get('org', '').lower()
                hosting_keywords = ['host', 'server', 'cloud', 'vps', 'dedicated', 'datacenter']
                if any(keyword in org for keyword in hosting_keywords):
                    print(f"    {Colors.YELLOW}⚠️  This appears to be a hosting provider IP{Colors.END}")
                
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] IPInfo: Invalid API key{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] IPInfo API error: {response.status_code}{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] IPInfo error: {str(e)}{Colors.END}")
            return {}
    
    def virustotal_lookup(self, ip: str) -> Dict:
        """Query VirusTotal API for security analysis"""
        print(f"{Colors.BLUE}[*] Querying VirusTotal database...{Colors.END}")
        
        api_key = self.config.apis.get('virustotal')
        if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] VirusTotal API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            headers = {'x-apikey': api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] VirusTotal: Security analysis completed{Colors.END}")
                
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                reputation = attributes.get('reputation', 0)
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                
                total = malicious + suspicious + harmless + undetected
                
                print(f"    Reputation Score: {reputation}")
                print(f"    Total Scanners: {total}")
                print(f"    Malicious: {malicious}")
                print(f"    Suspicious: {suspicious}")
                print(f"    Harmless: {harmless}")
                print(f"    Undetected: {undetected}")
                
                # Risk assessment
                if malicious > 0:
                    print(f"    {Colors.RED}🔴 HIGH RISK: IP flagged as malicious by {malicious} scanners{Colors.END}")
                elif suspicious > 0:
                    print(f"    {Colors.YELLOW}🟠 MEDIUM RISK: IP flagged as suspicious by {suspicious} scanners{Colors.END}")
                elif harmless > 0:
                    print(f"    {Colors.GREEN}🟢 LOW RISK: IP appears clean{Colors.END}")
                else:
                    print(f"    {Colors.BLUE}⚪ UNKNOWN: No scan data available{Colors.END}")
                
                return data
            elif response.status_code == 401:
                print(f"{Colors.RED}[!] VirusTotal: Invalid API key{Colors.END}")
                return {}
            elif response.status_code == 404:
                print(f"{Colors.YELLOW}[!] VirusTotal: No data found for this IP{Colors.END}")
                return {}
            else:
                print(f"{Colors.RED}[!] VirusTotal API error: {response.status_code}{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] VirusTotal error: {str(e)}{Colors.END}")
            return {}
    
    def basic_port_scan(self, ip: str, ports: List[int] = None) -> Dict:
        """Perform basic port scan"""
        print(f"{Colors.BLUE}[*] Performing basic port scan...{Colors.END}")
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        open_ports = []
        
        def check_port(port: int) -> Tuple[int, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return (port, result == 0)
            except:
                return (port, False)
        
        # Scan ports in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
        
        # Map ports to services
        port_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        
        print(f"{Colors.GREEN}[+] Port scan complete: {len(open_ports)}/{len(ports)} ports open{Colors.END}")
        
        if open_ports:
            print(f"    Open Ports:")
            for port in sorted(open_ports):
                service = port_services.get(port, 'Unknown')
                print(f"      {port}/tcp - {service}")
        
        return {
            'target': ip,
            'ports_scanned': ports,
            'open_ports': open_ports,
            'port_services': {port: port_services.get(port, 'Unknown') for port in open_ports}
        }
    
    def reverse_dns_scan(self, ip: str) -> Dict:
        """Perform reverse DNS lookup and find related domains"""
        print(f"{Colors.BLUE}[*] Performing reverse DNS lookup...{Colors.END}")
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Try to get PTR record
            try:
                answers = resolver.resolve_address(ip)
                ptr_records = [str(rdata) for rdata in answers]
            except:
                ptr_records = []
            
            # Use SecurityTrails for more reverse DNS (if API available)
            domains = set(ptr_records)
            
            print(f"{Colors.GREEN}[+] Reverse DNS found {len(domains)} domains{Colors.END}")
            if domains:
                for domain in sorted(domains):
                    print(f"    • {domain}")
            
            return {
                'ip': ip,
                'ptr_records': ptr_records,
                'domains_found': list(domains)
            }
        except Exception as e:
            print(f"{Colors.RED}[!] Reverse DNS error: {str(e)}{Colors.END}")
            return {'ip': ip, 'ptr_records': [], 'domains_found': []}
    
    def scan_ip(self, ip: str, port_scan: bool = False) -> Dict:
        """Comprehensive IP address scan"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}  IP RECONNAISSANCE REPORT{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{ip}{Colors.END}")
        print(f"{Colors.CYAN}  Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
        
        results = {
            'target': ip,
            'timestamp': datetime.now().isoformat(),
            'is_valid': IPTools.is_valid_ip(ip),
            'is_private': IPTools.is_private_ip(ip),
            'shodan': {},
            'ipinfo': {},
            'virustotal': {},
            'port_scan': {},
            'reverse_dns': {}
        }
        
        # Check if IP is valid
        if not results['is_valid']:
            print(f"{Colors.RED}[!] Invalid IP address: {ip}{Colors.END}")
            return results
        
        # Check if IP is private
        if results['is_private']:
            print(f"{Colors.YELLOW}[!] Private IP address detected (RFC1918){Colors.END}")
            print(f"{Colors.YELLOW}[!] Some scans may not work for private IPs{Colors.END}\n")
        
        # Run all scans
        results['shodan'] = self.shodan_lookup(ip)
        time.sleep(1)
        
        results['ipinfo'] = self.ipinfo_lookup(ip)
        time.sleep(1)
        
        results['virustotal'] = self.virustotal_lookup(ip)
        time.sleep(1)
        
        if port_scan:
            results['port_scan'] = self.basic_port_scan(ip)
        
        results['reverse_dns'] = self.reverse_dns_scan(ip)
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  SCAN COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        
        # Calculate risk score
        risk_score = 0
        risk_factors = []
        
        # Check VirusTotal results
        vt_data = results.get('virustotal', {})
        if 'data' in vt_data:
            stats = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            if malicious > 0:
                risk_score += 50
                risk_factors.append(f"Malicious detection by {malicious} scanners")
            elif suspicious > 0:
                risk_score += 30
                risk_factors.append(f"Suspicious detection by {suspicious} scanners")
        
        # Check open ports
        if 'port_scan' in results and results['port_scan'].get('open_ports'):
            open_ports = results['port_scan']['open_ports']
            risky_ports = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, RPC, NetBIOS, SMB, RDP
            risky_open = [p for p in open_ports if p in risky_ports]
            
            if risky_open:
                risk_score += len(risky_open) * 10
                risk_factors.append(f"Risky ports open: {', '.join(map(str, risky_open))}")
        
        # Display risk assessment
        if risk_score >= 50:
            risk_level = f"{Colors.RED}🔴 HIGH RISK{Colors.END}"
        elif risk_score >= 30:
            risk_level = f"{Colors.YELLOW}🟠 MEDIUM RISK{Colors.END}"
        elif risk_score > 0:
            risk_level = f"{Colors.YELLOW}🟡 LOW RISK{Colors.END}"
        else:
            risk_level = f"{Colors.GREEN}🟢 LOW RISK{Colors.END}"
        
        print(f"\n{Colors.CYAN}📊 Risk Assessment:{Colors.END}")
        print(f"  Risk Level: {risk_level}")
        print(f"  Risk Score: {risk_score}")
        
        if risk_factors:
            print(f"  Risk Factors:")
            for factor in risk_factors:
                print(f"    • {factor}")
        
        print()
        return results

def setup_wizard():
    """Interactive setup wizard for API keys"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  RECONMASTER IP SETUP WIZARD{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}\n")
    
    print(f"{Colors.YELLOW}Configure your API keys for enhanced reconnaissance.{Colors.END}")
    print(f"{Colors.YELLOW}Press Enter to skip any API you don't have.{Colors.END}\n")
    
    apis = {}
    
    print(f"{Colors.CYAN}[1/3] Shodan API Configuration{Colors.END}")
    print(f"      Get your key at: https://account.shodan.io/")
    apis['shodan'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[2/3] IPInfo API Configuration{Colors.END}")
    print(f"      Get your key at: https://ipinfo.io/")
    apis['ipinfo'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[3/3] VirusTotal API Configuration{Colors.END}")
    print(f"      Get your key at: https://www.virustotal.com/")
    apis['virustotal'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    # Remove empty keys
    apis = {k: v for k, v in apis.items() if v}
    
    if apis:
        config = Config()
        config.save_config(apis)
        print(f"\n{Colors.GREEN}[+] Configuration saved! {len(apis)}/3 APIs configured.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[!] No API keys provided. You can run setup again anytime.{Colors.END}")
    
    print(f"{Colors.CYAN}\nYou're ready to start reconnaissance!{Colors.END}")
    print(f"{Colors.CYAN}Example: python3 recon_master.py --ip 8.8.8.8{Colors.END}")
    print(f"{Colors.CYAN}Example with port scan: python3 recon_master.py --ip 8.8.8.8 --port-scan{Colors.END}")
    print(f"{Colors.CYAN}Example for subdomains: python3 recon_master.py --domain example.com{Colors.END}\n")

def save_results(filename: str, results: Dict):
    """Save results to JSON file"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        print(f"{Colors.GREEN}[+] Results saved to: {filename}{Colors.END}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='ReconMaster IP - IP & Subdomain Reconnaissance Tool by Abdulbasid Yakubu | cy30rt',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Examples:{Colors.END}
  # IP Address Reconnaissance
  python3 recon_master.py --ip 8.8.8.8
  python3 recon_master.py --ip 8.8.8.8 --port-scan
  python3 recon_master.py --ip-range 192.168.1.1-192.168.1.10
  python3 recon_master.py --cidr 192.168.1.0/24
  
  # Subdomain Enumeration
  python3 recon_master.py --domain example.com
  
  # Setup
  python3 recon_master.py --setup

{Colors.YELLOW}Features:{Colors.END}
  • IP Address Intelligence (Shodan, IPInfo, VirusTotal)
  • Basic Port Scanning
  • Reverse DNS Lookup
  • Subdomain Enumeration
  • DNS Resolution

{Colors.YELLOW}Author: Abdulbasid Yakubu | cy30rt{Colors.END}
        """
    )
    
    # IP scanning options
    ip_group = parser.add_argument_group('IP Address Scanning')
    ip_group.add_argument('--ip', help='Single IP address to scan')
    ip_group.add_argument('--ip-range', help='IP range to scan (e.g., 192.168.1.1-192.168.1.10)')
    ip_group.add_argument('--cidr', help='CIDR notation to scan (e.g., 192.168.1.0/24)')
    ip_group.add_argument('--port-scan', action='store_true', help='Enable port scanning')
    ip_group.add_argument('--threads', type=int, default=50, help='Threads for port scanning (default: 50)')
    
    # Subdomain options
    subdomain_group = parser.add_argument_group('Subdomain Enumeration')
    subdomain_group.add_argument('--domain', help='Domain for subdomain enumeration')
    
    # General options
    parser.add_argument('--setup', action='store_true', help='Run setup wizard to configure API keys')
    parser.add_argument('-o', '--output', help='Custom output filename (optional)')
    parser.add_argument('-v', '--version', action='version', version='ReconMaster IP v2.0.0 by Abdulbasid Yakubu | cy30rt')
    
    args = parser.parse_args()
    
    config = Config()
    
    if args.setup:
        setup_wizard()
        return
    
    recon = IPReconnaissance(config)
    recon.banner()
    
    # Check if any target is specified
    if not any([args.ip, args.ip_range, args.cidr, args.domain]):
        print(f"{Colors.RED}[!] Error: No target specified. Use --ip, --domain, --ip-range, or --cidr{Colors.END}\n")
        parser.print_help()
        return
    
    # Subdomain enumeration
    if args.domain:
        print(f"{Colors.YELLOW}[*] Starting subdomain enumeration for: {args.domain}{Colors.END}")
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', args.domain):
            print(f"{Colors.RED}[!] Invalid domain format: {args.domain}{Colors.END}")
            return
        
        enumerator = SubdomainEnumerator(args.domain)
        results = enumerator.enumerate_all()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = args.output or f"subdomains_{args.domain.replace('.', '_')}_{timestamp}.json"
        save_results(filename, results)
        
        return
    
    # IP address scanning
    ip_list = []
    
    # Single IP
    if args.ip:
        if IPTools.is_valid_ip(args.ip):
            ip_list.append(args.ip)
        else:
            print(f"{Colors.RED}[!] Invalid IP address: {args.ip}{Colors.END}")
            return
    
    # IP range
    if args.ip_range:
        if '-' in args.ip_range:
            start_ip, end_ip = args.ip_range.split('-')
            if IPTools.is_valid_ip(start_ip) and IPTools.is_valid_ip(end_ip):
                ip_list.extend(IPTools.get_ip_range(start_ip, end_ip))
            else:
                print(f"{Colors.RED}[!] Invalid IP range: {args.ip_range}{Colors.END}")
                return
        else:
            print(f"{Colors.RED}[!] Invalid range format. Use: START-IP-END-IP{Colors.END}")
            return
    
    # CIDR notation
    if args.cidr:
        cidr_ips = IPTools.cidr_to_ips(args.cidr)
        if cidr_ips:
            ip_list.extend(cidr_ips)
        else:
            print(f"{Colors.RED}[!] Invalid CIDR notation: {args.cidr}{Colors.END}")
            return
    
    # Remove duplicates and limit to reasonable number
    ip_list = list(set(ip_list))
    
    if len(ip_list) > 100:
        print(f"{Colors.YELLOW}[!] Warning: {len(ip_list)} IPs to scan. Limiting to first 100.{Colors.END}")
        ip_list = ip_list[:100]
    
    if not ip_list:
        print(f"{Colors.RED}[!] No valid IP addresses to scan{Colors.END}")
        return
    
    print(f"{Colors.YELLOW}[*] Starting IP reconnaissance for {len(ip_list)} IP address(es){Colors.END}")
    
    all_results = []
    
    for i, ip in enumerate(ip_list):
        print(f"\n{Colors.CYAN}[{i+1}/{len(ip_list)}] Scanning IP: {ip}{Colors.END}")
        
        if IPTools.is_private_ip(ip) and len(ip_list) > 1:
            print(f"{Colors.YELLOW}[!] Skipping private IP: {ip}{Colors.END}")
            continue
        
        try:
            results = recon.scan_ip(ip, port_scan=args.port_scan)
            all_results.append(results)
            
            # Small delay between scans to avoid rate limiting
            if i < len(ip_list) - 1:
                time.sleep(2)
                
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {ip}: {str(e)}{Colors.END}")
    
    # Save combined results
    if all_results:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if len(ip_list) == 1:
            filename = args.output or f"ip_scan_{ip_list[0].replace('.', '_')}_{timestamp}.json"
        else:
            filename = args.output or f"ip_scan_batch_{timestamp}.json"
        
        save_results(filename, {
            'scan_type': 'ip_reconnaissance',
            'timestamp': datetime.now().isoformat(),
            'targets': ip_list,
            'results': all_results,
            'summary': {
                'total_scanned': len(all_results),
                'private_ips': sum(1 for r in all_results if r.get('is_private')),
                'valid_ips': sum(1 for r in all_results if r.get('is_valid'))
            }
        })
        
        # Display quick summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  BATCH SCAN COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.CYAN}  Total IPs Scanned: {len(all_results)}{Colors.END}")
        print(f"{Colors.CYAN}  Results Saved To: {filename}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}═══════════════════════════════════════════════{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        print(f"{Colors.YELLOW}[!] Partial results may have been saved{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        print(f"{Colors.RED}[!] Please report this issue if it persists{Colors.END}\n")
