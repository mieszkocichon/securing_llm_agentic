/**
 * Domain Threat Intelligence Database
 *
 * This represents what would be fed by AbuseIPDB or similar threat intelligence.
 * In production, this would be dynamically updated from various feeds.
 * Here we include ~100 known domains associated with malware, phishing, and data exfiltration.
 */

export interface DomainThreat {
  domain: string;
  reason: string;
  severity: 'low' | 'medium' | 'high';
  category: 'exfiltration' | 'malware' | 'phishing' | 'command_control' | 'suspicious_service';
}

export const DEFAULT_DOMAIN_BLOCKLIST: DomainThreat[] = [
  // Paste services (common exfiltration targets)
  { domain: 'pastebin.com', reason: 'Common exfiltration target', severity: 'high', category: 'exfiltration' },
  { domain: 'paste.ee', reason: 'Exfiltration service', severity: 'high', category: 'exfiltration' },
  { domain: 'hastebin.com', reason: 'Code sharing for exfiltration', severity: 'medium', category: 'exfiltration' },
  { domain: 'gist.github.com', reason: 'GitHub gists for data exfiltration', severity: 'high', category: 'exfiltration' },
  { domain: 'raw.githubusercontent.com', reason: 'GitHub raw for malware hosting', severity: 'high', category: 'malware' },
  { domain: 'github.io', reason: 'Potential malware/phishing hosting', severity: 'medium', category: 'suspicious_service' },

  // Webhook and request inspection services
  { domain: 'webhook.site', reason: 'Webhook exfiltration target', severity: 'high', category: 'exfiltration' },
  { domain: 'requestbin.net', reason: 'Request inspection for data exfiltration', severity: 'high', category: 'exfiltration' },
  { domain: 'pipedream.com', reason: 'Workflow automation for exfiltration', severity: 'medium', category: 'exfiltration' },
  { domain: 'hookbin.com', reason: 'Hook inspection service', severity: 'medium', category: 'exfiltration' },
  { domain: 'beeceptor.com', reason: 'API mocking and inspection', severity: 'medium', category: 'exfiltration' },

  // Shortening and URL services
  { domain: 'tinyurl.com', reason: 'URL obfuscation', severity: 'low', category: 'suspicious_service' },
  { domain: 'bit.ly', reason: 'URL shortening for phishing', severity: 'low', category: 'phishing' },
  { domain: 'ow.ly', reason: 'URL shortening service', severity: 'low', category: 'suspicious_service' },

  // Known botnet/C2 domains (simulated - these change frequently)
  { domain: 'darkenet.io', reason: 'Known C2 server', severity: 'high', category: 'command_control' },
  { domain: 'botnet.malware.net', reason: 'Botnet command and control', severity: 'high', category: 'command_control' },
  { domain: 'c2.example.malicious', reason: 'Command and control infrastructure', severity: 'high', category: 'command_control' },

  // File sharing (potential malware distribution)
  { domain: 'uploadfiles.io', reason: 'Malware distribution', severity: 'medium', category: 'malware' },
  { domain: 'megaupload.fake', reason: 'Illegal file sharing', severity: 'medium', category: 'malware' },
  { domain: 'dropmefiles.com', reason: 'File exfiltration service', severity: 'high', category: 'exfiltration' },

  // Phishing-as-a-service domains
  { domain: 'phishing.example.net', reason: 'Phishing infrastructure', severity: 'high', category: 'phishing' },
  { domain: 'cloning.malware.io', reason: 'Website cloning for phishing', severity: 'high', category: 'phishing' },
  { domain: 'stolen-creds.dark.net', reason: 'Credential marketplace', severity: 'high', category: 'phishing' },

  // Cryptocurrency mixers (money laundering, often malware-related)
  { domain: 'bitcoinmixer.io', reason: 'Crypto mixer - ransomware payment', severity: 'medium', category: 'suspicious_service' },
  { domain: 'coinjoin.site', reason: 'Currency anonymization', severity: 'medium', category: 'suspicious_service' },

  // Known malware sites
  { domain: 'malware.example.com', reason: 'Malware distribution', severity: 'high', category: 'malware' },
  { domain: 'virus-download.net', reason: 'Malware hosting', severity: 'high', category: 'malware' },
  { domain: 'exploit-kit.malicious.io', reason: 'Exploit kit hosting', severity: 'high', category: 'malware' },

  // Suspicious localhost alternatives
  { domain: 'localhost.malware.net', reason: 'Localhost masquerading', severity: 'medium', category: 'suspicious_service' },
  { domain: '127.0.0.1.malware.io', reason: 'IP spoofing domain', severity: 'low', category: 'suspicious_service' },

  // Typosquatting domains (simulated)
  { domain: 'googl3.com', reason: 'Typosquatting phishing', severity: 'medium', category: 'phishing' },
  { domain: 'amazno.com', reason: 'Typosquatting phishing', severity: 'medium', category: 'phishing' },
  { domain: 'paypa1.net', reason: 'Typosquatting phishing', severity: 'high', category: 'phishing' },

  // Data broker / stolen data sites
  { domain: 'stolen-database.dark', reason: 'Stolen data marketplace', severity: 'high', category: 'suspicious_service' },
  { domain: 'breached-info.io', reason: 'Breach data trading', severity: 'high', category: 'suspicious_service' },

  // Ransomware payment/negotiation sites
  { domain: 'ransomware-payments.onion', reason: 'Ransomware C2', severity: 'high', category: 'command_control' },
  { domain: 'recovery-key-service.malware.net', reason: 'Fake recovery service', severity: 'high', category: 'phishing' },

  // DDoS services
  { domain: 'ddos-for-hire.io', reason: 'DDoS-as-a-service', severity: 'high', category: 'malware' },
  { domain: 'botnet-rental.dark.net', reason: 'Botnet rental marketplace', severity: 'high', category: 'command_control' },

  // SQL Injection / Web attack tools
  { domain: 'sqlmap-shell-hosting.net', reason: 'Web shell hosting', severity: 'high', category: 'malware' },
  { domain: 'web-shell-repository.io', reason: 'Web shell distribution', severity: 'high', category: 'malware' },

  // Cryptolocker and variants
  { domain: 'cryptolocker.payment', reason: 'Ransomware payment site', severity: 'high', category: 'malware' },
  { domain: 'wanacry-recovery.io', reason: 'Ransomware negotiation', severity: 'high', category: 'malware' },

  // Spyware / Stalkerware services
  { domain: 'spyware-control.panel', reason: 'Spyware command center', severity: 'high', category: 'command_control' },
  { domain: 'location-tracker-service.io', reason: 'Stalkerware service', severity: 'high', category: 'suspicious_service' },

  // Network reconnaissance tools
  { domain: 'port-scanner-results.io', reason: 'Reconnaissance data exfil', severity: 'medium', category: 'exfiltration' },
  { domain: 'network-scan-results.malware.net', reason: 'Scan result aggregation', severity: 'medium', category: 'exfiltration' },

  // Additional infrastructure (realistic padding)
  { domain: 'malware-control.ru', reason: 'Russian malware C2', severity: 'high', category: 'command_control' },
  { domain: 'phishing-farm.cn', reason: 'Phishing infrastructure', severity: 'high', category: 'phishing' },
  { domain: 'botnet-herder.net', reason: 'Botnet management', severity: 'high', category: 'command_control' },
  { domain: 'exploit-delivery.io', reason: 'Exploit distribution', severity: 'high', category: 'malware' },
  { domain: 'loader-service.malware.io', reason: 'Malware loader', severity: 'high', category: 'malware' },
  { domain: 'trojan-panel.net', reason: 'Trojan command center', severity: 'high', category: 'command_control' },
  { domain: 'worm-propagation.io', reason: 'Worm distribution', severity: 'high', category: 'malware' },
  { domain: 'rootkit-hosting.net', reason: 'Rootkit distribution', severity: 'high', category: 'malware' },
  { domain: 'keylogger-results.io', reason: 'Keylogger data exfil', severity: 'high', category: 'exfiltration' },
  { domain: 'credential-stealer.net', reason: 'Credential harvesting', severity: 'high', category: 'exfiltration' },
  { domain: 'session-hijacking.malware.io', reason: 'Session theft', severity: 'high', category: 'phishing' },
  { domain: 'clipboard-logger.net', reason: 'Clipboard data theft', severity: 'high', category: 'exfiltration' },
  { domain: 'browser-history-stealer.io', reason: 'History theft', severity: 'medium', category: 'exfiltration' },
  { domain: 'password-vault-breaker.net', reason: 'Password manager targeting', severity: 'high', category: 'phishing' },
  { domain: 'cookie-exfil.io', reason: 'Cookie and session theft', severity: 'high', category: 'exfiltration' },
  { domain: 'dns-exfil.malware.net', reason: 'DNS tunneling exfil', severity: 'high', category: 'exfiltration' },
  { domain: 'icmp-tunnel.io', reason: 'ICMP tunneling C2', severity: 'high', category: 'command_control' },
  { domain: 'http-tunnel.net', reason: 'HTTP tunneling C2', severity: 'high', category: 'command_control' },
  { domain: 'smtp-relay-exploit.io', reason: 'SMTP abuse for spam', severity: 'medium', category: 'suspicious_service' },
  { domain: 'ftp-backdoor.net', reason: 'FTP backdoor access', severity: 'high', category: 'malware' },
  { domain: 'ssh-weak-keys.malware.io', reason: 'SSH compromise', severity: 'high', category: 'command_control' },
  { domain: 'rdp-bruteforce.net', reason: 'RDP attack staging', severity: 'high', category: 'malware' },
  { domain: 'vnc-exploit-delivery.io', reason: 'VNC vulnerability exploit', severity: 'high', category: 'malware' },
  { domain: 'telnet-protocol-abuse.net', reason: 'Legacy protocol abuse', severity: 'medium', category: 'suspicious_service' },
  { domain: 'snmp-walk-results.malware.io', reason: 'SNMP reconnaissance', severity: 'medium', category: 'exfiltration' },
  { domain: 'ldap-injection-exploits.net', reason: 'LDAP attack framework', severity: 'high', category: 'malware' },
  { domain: 'xml-bomb-service.io', reason: 'DoS attack service', severity: 'high', category: 'suspicious_service' },
  { domain: 'path-traversal-toolkit.net', reason: 'Path traversal tools', severity: 'high', category: 'malware' },
  { domain: 'prototype-pollution.io', reason: 'JS prototype pollution', severity: 'medium', category: 'malware' },
  { domain: 'deserialization-gadget.malware.net', reason: 'Deserialization exploit', severity: 'high', category: 'malware' },
  { domain: 'race-condition-simulator.net', reason: 'Race condition exploit', severity: 'medium', category: 'malware' },
  { domain: 'timing-attack-tools.io', reason: 'Timing attack framework', severity: 'medium', category: 'suspicious_service' },
  { domain: 'side-channel-leaks.net', reason: 'Side-channel attack tools', severity: 'medium', category: 'suspicious_service' },
  { domain: 'spectre-exploit.io', reason: 'Spectre/Meltdown exploit', severity: 'high', category: 'malware' },
  { domain: 'rowhammer-attack.malware.net', reason: 'Rowhammer exploit', severity: 'high', category: 'malware' },
  { domain: 'firmware-backdoor.net', reason: 'Firmware compromise', severity: 'high', category: 'command_control' },
  { domain: 'bootkit-delivery.io', reason: 'Bootkit distribution', severity: 'high', category: 'malware' },
  { domain: 'uefi-rootkit.net', reason: 'UEFI/BIOS infection', severity: 'high', category: 'malware' },
  { domain: 'hypervisor-escape.malware.io', reason: 'VM escape exploit', severity: 'high', category: 'malware' },
  { domain: 'container-breakout.net', reason: 'Container escape exploit', severity: 'high', category: 'malware' },
  { domain: 'kubernetes-attack.io', reason: 'K8s exploitation', severity: 'high', category: 'malware' },
  { domain: 'cloud-credential-theft.net', reason: 'Cloud credential harvesting', severity: 'high', category: 'phishing' },
  { domain: 'lambda-injection.malware.io', reason: 'Serverless code injection', severity: 'high', category: 'malware' },
  { domain: 'api-gateway-abuse.net', reason: 'API gateway exploitation', severity: 'high', category: 'suspicious_service' }
];

/**
 * Get domain threat info
 */
export function getDomainThreat(domain: string): DomainThreat | undefined {
  const normalized = domain.toLowerCase().trim();

  // Exact match
  let threat = DEFAULT_DOMAIN_BLOCKLIST.find((t) => t.domain.toLowerCase() === normalized);
  if (threat) return threat;

  // Subdomain match (e.g., evil.pastebin.com matches pastebin.com)
  threat = DEFAULT_DOMAIN_BLOCKLIST.find((t) => normalized.endsWith('.' + t.domain.toLowerCase()));
  if (threat) return threat;

  return undefined;
}

/**
 * Check if domain is blocklisted
 */
export function isBlocklistedDomain(domain: string): boolean {
  return getDomainThreat(domain) !== undefined;
}
