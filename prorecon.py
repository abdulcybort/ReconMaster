#!/usr/bin/env python3

"""
ProRecon - Professional Reconnaissance Tool
Author: Abdulbasid Yakubu | cy30rt
Version: 2.0.0 - Production Ready
Features: IP Resolution, Port Scanning (TCP/UDP), Subdomain Enumeration, SSL Analysis
"""

import os
import sys
import json
import time
import socket
import argparse
import requests
import threading
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class PortScanner:
    """Professional TCP and UDP port scanner"""
    
    COMMON_TCP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090
    ]
    
    COMMON_UDP_PORTS = [
        53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 1900, 4500, 5353
    ]
    
    SERVICE_BANNERS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
        110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9090: 'HTTP-Proxy'
    }
    
    def __init__(self, target_ip: str, timeout: float = 1.0):
        self.target_ip = target_ip
        self.timeout = timeout
        self.open_tcp_ports = []
        self.open_udp_ports = []
        self.lock = threading.Lock()
    
    def scan_tcp_port(self, port: int) -> Optional[Dict]:
        """Scan single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': self.SERVICE_BANNERS.get(port, 'unknown'),
                    'banner': None
                }
                
                # Try banner grab
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        port_info['banner'] = banner[:200]
                except:
                    pass
                
                sock.close()
                return port_info
            
            sock.close()
        except:
            pass
        return None
    
    def scan_udp_port(self, port: int) -> Optional[Dict]:
        """Scan single UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout * 2)
            sock.sendto(b'', (self.target_ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return {
                    'port': port,
                    'state': 'open',
                    'service': self.SERVICE_BANNERS.get(port, 'unknown')
                }
            except socket.timeout:
                sock.close()
                return {
                    'port': port,
                    'state': 'open|filtered',
                    'service': self.SERVICE_BANNERS.get(port, 'unknown')
                }
        except:
            pass
        return None
    
    def scan_tcp_ports(self, ports: List[int] = None, threads: int = 50) -> List[Dict]:
        """Scan multiple TCP ports"""
        if ports is None:
            ports = self.COMMON_TCP_PORTS
        
        print(f"{Colors.BLUE}[*] Scanning {len(ports)} TCP ports...{Colors.END}")
        results = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_tcp_port, port): port for port in ports}
            completed = 0
            
            for future in as_completed(futures):
                completed += 1
                print(f"{Colors.CYAN}[*] Progress: {completed}/{len(ports)}{Colors.END}", end='\r')
                result = future.result()
                if result:
                    results.append(result)
        
        print()
        return sorted(results, key=lambda x: x['port'])
    
    def scan_udp_ports(self, ports: List[int] = None, threads: int = 20) -> List[Dict]:
        """Scan multiple UDP ports"""
        if ports is None:
            ports = self.COMMON_UDP_PORTS
        
        print(f"{Colors.BLUE}[*] Scanning {len(ports)} UDP ports (slower)...{Colors.END}")
        results = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_udp_port, port): port for port in ports}
            completed = 0
            
            for future in as_completed(futures):
                completed += 1
                print(f"{Colors.CYAN}[*] Progress: {completed}/{len(ports)}{Colors.END}", end='\r')
                result = future.result()
                if result:
                    results.append(result)
        
        print()
        return sorted(results, key=lambda x: x['port'])

class SSLAnalyzer:
    """SSL/TLS certificate analyzer"""
    
    def analyze(self, hostname: str, port: int = 443) -> Dict:
        """Analyze SSL certificate"""
        result = {
            'hostname': hostname,
            'port': port,
            'ssl_enabled': False,
            'certificate': {},
            'issues': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['ssl_enabled'] = True
                    result['certificate'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': [ext[1] for ext in cert.get('subjectAltName', []) if ext[0] == 'DNS']
                    }
                    
                    # Check expiry
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.now()).days
                        result['certificate']['days_until_expiry'] = days_left
                        
                        if days_left < 0:
                            result['issues'].append('CRITICAL: Certificate expired')
                        elif days_left < 30:
                            result['issues'].append(f'WARNING: Expires in {days_left} days')
                    
                    # Self-signed check
                    if result['certificate']['issuer'] == result['certificate']['subject']:
                        result['issues'].append('WARNING: Self-signed certificate')
        
        except ssl.SSLError as e:
            result['issues'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            result['issues'].append(f'Error: {str(e)}')
        
        return result

class SubdomainEnumerator:
    """Professional subdomain enumeration"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0'}
    
    def crtsh_search(self) -> Set[str]:
        """Search crt.sh Certificate Transparency"""
        print(f"{Colors.BLUE}[*] Querying crt.sh...{Colors.END}")
        found = set()
        
        try:
            response = self.session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    names = entry.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lower().replace('*.', '')
                        if name.endswith(self.domain) and name != self.domain and self._is_valid(name):
                            found.add(name)
                
                print(f"{Colors.GREEN}[+] crt.sh: {len(found)} subdomains{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] crt.sh error: {str(e)}{Colors.END}")
        
        return found
    
    def hackertarget_search(self) -> Set[str]:
        """Search HackerTarget"""
        print(f"{Colors.BLUE}[*] Querying HackerTarget...{Colors.END}")
        found = set()
        
        try:
            response = self.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                timeout=20
            )
            
            if response.status_code == 200 and 'error' not in response.text.lower():
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(self.domain) and self._is_valid(sub):
                            found.add(sub)
                
                print(f"{Colors.GREEN}[+] HackerTarget: {len(found)} subdomains{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] HackerTarget error: {str(e)}{Colors.END}")
        
        return found
    
    def alienvault_search(self) -> Set[str]:
        """Search AlienVault"""
        print(f"{Colors.BLUE}[*] Querying AlienVault...{Colors.END}")
        found = set()
        
        try:
            response = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns",
                timeout=20
            )
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    host = entry.get('hostname', '').lower()
                    if host.endswith(self.domain) and host != self.domain and self._is_valid(host):
                        found.add(host)
                
                print(f"{Colors.GREEN}[+] AlienVault: {len(found)} subdomains{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] AlienVault error: {str(e)}{Colors.END}")
        
        return found
    
    def dns_brute(self, wordlist: List[str] = None, threads: int = 50) -> Set[str]:
        """DNS brute force"""
        if not wordlist:
            wordlist = ['www', 'mail', 'webmail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2',
                       'admin', 'blog', 'dev', 'staging', 'test', 'api', 'cdn', 'vpn',
                       'portal', 'app', 'secure', 'remote', 'support', 'shop']
        
        print(f"{Colors.BLUE}[*] DNS brute force ({len(wordlist)} words)...{Colors.END}")
        found = set()
        
        def check(sub):
            try:
                socket.gethostbyname(f"{sub}.{self.domain}")
                return f"{sub}.{self.domain}"
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for result in executor.map(check, wordlist):
                if result:
                    found.add(result)
        
        print(f"{Colors.GREEN}[+] DNS Brute: {len(found)} subdomains{Colors.END}")
        return found
    
    def _is_valid(self, sub: str) -> bool:
        """Validate subdomain"""
        return sub and sub != self.domain and '*' not in sub and ' ' not in sub
    
    def enumerate(self, brute: bool = True) -> Dict:
        """Run all methods"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}SUBDOMAIN ENUMERATION{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}\n")
        
        results = {'domain': self.domain, 'timestamp': datetime.now().isoformat(), 'sources': {}}
        
        # Passive
        for name, func in [('crtsh', self.crtsh_search),
                          ('hackertarget', self.hackertarget_search),
                          ('alienvault', self.alienvault_search)]:
            try:
                found = func()
                results['sources'][name] = list(found)
                self.subdomains.update(found)
                time.sleep(1)
            except Exception as e:
                results['sources'][name] = []
        
        # Active
        if brute:
            try:
                found = self.dns_brute()
                results['sources']['dns_brute'] = list(found)
                self.subdomains.update(found)
            except:
                results['sources']['dns_brute'] = []
        
        results['all_subdomains'] = sorted(list(self.subdomains))
        results['total'] = len(self.subdomains)
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.GREEN}Total: {len(self.subdomains)} subdomains{Colors.END}")
        
        if self.subdomains:
            print(f"\n{Colors.YELLOW}Subdomains:{Colors.END}")
            for i, sub in enumerate(sorted(list(self.subdomains))[:25], 1):
                print(f"  {i:2}. {sub}")
            if len(self.subdomains) > 25:
                print(f"  ... and {len(self.subdomains) - 25} more")
        
        print(f"{Colors.GREEN}{Colors.BOLD}{'=' * 60}{Colors.END}\n")
        return results

class ProRecon:
    """Main tool"""
    
    def banner(self):
        print(f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ██████╗  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗   ║
║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗ ║
║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ██║     ██║   ██║ ║
║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║ ║
║   ██║     ██║  ██║╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝ ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}{Colors.YELLOW}        Professional Reconnaissance Tool v2.0{Colors.END}
{Colors.GREEN}        Author: Abdulbasid Yakubu | cy30rt{Colors.END}
{Colors.CYAN}{'=' * 60}{Colors.END}
        """)
    
    def resolve(self, domain: str) -> Optional[str]:
        """Resolve domain to IP"""
        print(f"{Colors.BLUE}[*] Resolving {domain}...{Colors.END}")
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.GREEN}[+] Resolved: {ip}{Colors.END}")
            return ip
        except:
            print(f"{Colors.RED}[!] Failed to resolve{Colors.END}")
            return None
    
    def save(self, target: str, data: Dict):
        """Save results"""
        filename = f"prorecon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"{Colors.GREEN}[+] Saved: {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Save error: {e}{Colors.END}")
    
    def scan(self, target: str, tcp: bool = True, udp: bool = False, 
             subs: bool = False, ports: List[int] = None):
        """Full scan"""
        print(f"\n{Colors.YELLOW}{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}RECONNAISSANCE START{Colors.END}")
        print(f"{Colors.CYAN}Target: {target}{Colors.END}")
        print(f"{Colors.CYAN}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}{'=' * 60}{Colors.END}")
        
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'ip': None,
            'tcp': {},
            'udp': {},
            'ssl': {},
            'subdomains': {}
        }
        
        # Check if IP or domain
        try:
            socket.inet_aton(target)
            ip = target
            is_ip = True
        except:
            ip = self.resolve(target)
            is_ip = False
            if not ip:
                return
        
        results['ip'] = ip
        
        # TCP scan
        if tcp:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}TCP PORT SCAN{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
            
            scanner = PortScanner(ip)
            tcp_results = scanner.scan_tcp_ports(ports)
            results['tcp'] = {'ports': tcp_results, 'total': len(tcp_results)}
            
            if tcp_results:
                print(f"\n{Colors.GREEN}[+] {len(tcp_results)} open TCP ports{Colors.END}\n")
                print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<15}{'BANNER'}")
                print('-' * 70)
                for p in tcp_results:
                    banner = (p.get('banner') or '')[:35]
                    print(f"{p['port']:<8}{'OPEN':<10}{p['service']:<15}{banner}")
            else:
                print(f"\n{Colors.YELLOW}[!] No open TCP ports{Colors.END}")
        
        # UDP scan
        if udp:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}UDP PORT SCAN{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
            
            scanner = PortScanner(ip, timeout=2.0)
            udp_results = scanner.scan_udp_ports()
            results['udp'] = {'ports': udp_results, 'total': len(udp_results)}
            
            if udp_results:
                print(f"\n{Colors.GREEN}[+] {len(udp_results)} open/filtered UDP ports{Colors.END}\n")
                print(f"{'PORT':<8}{'STATE':<15}{'SERVICE'}")
                print('-' * 40)
                for p in udp_results:
                    print(f"{p['port']:<8}{p['state']:<15}{p['service']}")
            else:
                print(f"\n{Colors.YELLOW}[!] No open UDP ports{Colors.END}")
        
        # SSL check
        if not is_ip and tcp:
            has_https = any(p['port'] in [443, 8443] for p in results['tcp'].get('ports', []))
            if has_https:
                print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
                print(f"{Colors.CYAN}{Colors.BOLD}SSL CERTIFICATE ANALYSIS{Colors.END}")
                print(f"{Colors.CYAN}{Colors.BOLD}{'=' * 60}{Colors.END}")
                
                analyzer = SSLAnalyzer()
                ssl_result = analyzer.analyze(target)
                results['ssl'] = ssl_result
                
                if ssl_result['ssl_enabled']:
                    cert = ssl_result['certificate']
                    print(f"\n{Colors.GREEN}[+] SSL Certificate Found{Colors.END}")
                    print(f"  Subject: {cert.get('subject', {}).get('commonName', 'N/A')}")
                    print(f"  Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}")
                    print(f"  Valid Until: {cert.get('notAfter', 'N/A')}")
                    if 'days_until_expiry' in cert:
                        days = cert['days_until_expiry']
                        color = Colors.GREEN if days > 30 else Colors.YELLOW if days > 0 else Colors.RED
                        print(f"  Days Until Expiry: {color}{days}{Colors.END}")
                    
                    if ssl_result['issues']:
                        print(f"\n{Colors.YELLOW}Issues:{Colors.END}")
                        for issue in ssl_result['issues']:
                            print(f"  • {issue}")
        
        # Subdomain enum
        if subs and not is_ip:
            enum = SubdomainEnumerator(target)
            results['subdomains'] = enum.enumerate(brute=True)
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}SCAN COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}{'=' * 60}{Colors.END}")
        print(f"{Colors.GREEN}Target: {target}{Colors.END}")
        print(f"{Colors.GREEN}IP: {ip}{Colors.END}")
        if tcp:
            print(f"{Colors.GREEN}TCP Ports: {results['tcp']['total']}{Colors.END}")
        if udp:
            print(f"{Colors.GREEN}UDP Ports: {results['udp']['total']}{Colors.END}")
        if subs:
            print(f"{Colors.GREEN}Subdomains: {results['subdomains'].get('total', 0)}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}{'=' * 60}{Colors.END}\n")
        
        self.save(target, results)

def main():
    parser = argparse.ArgumentParser(
        description='ProRecon - Professional Reconnaissance Tool',
        epilog=f'''{Colors.CYAN}Examples:{Colors.END}
  python3 prorecon.py -t example.com
  python3 prorecon.py -t example.com --tcp --udp
  python3 prorecon.py -t example.com --subs
  python3 prorecon.py -t example.com --tcp --subs
  python3 prorecon.py -t 8.8.8.8 --tcp
  python3 prorecon.py -t example.com -p 80,443,8080

{Colors.YELLOW}Author: Abdulbasid Yakubu | cy30rt{Colors.END}''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP')
    parser.add_argument('--tcp', action='store_true', default=True, help='TCP port scan (default)')
    parser.add_argument('--udp', action='store_true', help='UDP port scan')
    parser.add_argument('--subs', action='store_true', help='Subdomain enumeration')
    parser.add_argument('-p', '--ports', help='Custom ports (e.g., 80,443,8080)')
    parser.add_argument('-v', '--version', action='version', version='ProRecon v2.0')
    
    args = parser.parse_args()
    
    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(',')]
        except:
            print(f"{Colors.RED}[!] Invalid port format{Colors.END}")
            return
    
    tool = ProRecon()
    tool.banner()
    
    try:
        tool.scan(args.target, tcp=args.tcp, udp=args.udp, 
                 subs=args.subs, ports=custom_ports)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.END}\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}\n")

if __name__ == "__main__":
    main()
