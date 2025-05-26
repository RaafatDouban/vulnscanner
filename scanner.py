import nmap
import json
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def scan(self, target, scan_type='quick'):
        """
        Perform vulnerability scan on the target
        scan_type can be 'quick' or 'full'
        """
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': scan_type,
            'open_ports': [],
            'vulnerabilities': [],
            'services': []
        }
        
        try:
            # Basic port scan
            if scan_type == 'quick':
                self.nm.scan(target, arguments='-sS -sV -F -T4')
            else:
                self.nm.scan(target, arguments='-sS -sV -p- -T4 --script vuln')
            
            # Process scan results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        port_info = {
                            'port': port,
                            'state': service['state'],
                            'name': service['name'],
                            'product': service.get('product', ''),
                            'version': service.get('version', '')
                        }
                        results['open_ports'].append(port_info)
                        
                        # Check for common vulnerabilities
                        if scan_type == 'full':
                            vuln_info = self._check_vulnerabilities(host, port, service)
                            if vuln_info:
                                results['vulnerabilities'].append(vuln_info)
            
            return results
            
        except Exception as e:
            return {
                'error': str(e),
                'target': target,
                'timestamp': datetime.now().isoformat()
            }
    
    def _check_vulnerabilities(self, host, port, service):
        """
        Check for common vulnerabilities based on service information
        """
        vuln_info = {
            'port': port,
            'service': service['name'],
            'severity': 'medium',
            'description': '',
            'recommendation': ''
        }
        
        # Example vulnerability checks (you can expand these)
        if service['name'] == 'http' or service['name'] == 'https':
            if service.get('version', '').startswith('1.1'):
                vuln_info.update({
                    'severity': 'high',
                    'description': 'Outdated HTTP version detected',
                    'recommendation': 'Upgrade to HTTP/2 or HTTP/3'
                })
                return vuln_info
                
        elif service['name'] == 'ssh':
            if service.get('version', '').startswith('7'):
                vuln_info.update({
                    'severity': 'medium',
                    'description': 'Older SSH version detected',
                    'recommendation': 'Upgrade to latest SSH version'
                })
                return vuln_info
                
        return None 