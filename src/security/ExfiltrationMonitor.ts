import { DataClassifier } from './DataClassifier';
import { ThreatDetection, ToolCall, SecurityPolicy, SensitivityLabel } from '../types';
import { isBlocklistedDomain, getDomainThreat } from './domainBlocklist';
import { getSensitivityRiskLevel } from './validators';

export class ExfiltrationMonitor {
  private classifier: DataClassifier;
  private policy: SecurityPolicy;
  private baselineVolume: number = 10000; // bytes

  constructor(policy: SecurityPolicy) {
    this.classifier = new DataClassifier();
    this.policy = policy;
  }

  monitor(toolCall: ToolCall): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    // Monitor HTTP requests for data exfiltration
    if (toolCall.toolName === 'http') {
      const httpThreats = this.monitorHTTP(toolCall);
      threats.push(...httpThreats);
    }

    // Monitor file access for sensitive data
    if (toolCall.toolName === 'filesystem') {
      const fsThreats = this.monitorFileSystem(toolCall);
      threats.push(...fsThreats);
    }

    return threats;
  }

  private monitorHTTP(toolCall: ToolCall): ThreatDetection[] {
    const threats: ThreatDetection[] = [];
    const { params } = toolCall;
    const url = params.url as string;
    const body = params.body;

    // Check destination domain against blocklist
    const domainThreat = this.checkBlocklistedDomain(url);
    if (domainThreat) {
      threats.push(domainThreat);
    }

    // Check request body for sensitive data
    if (body) {
      const bodyStr = JSON.stringify(body);
      const classification = this.classifier.getClassificationResult(bodyStr);

      if (classification.isSensitive) {
        const sensitivityThreat = this.checkSensitivityLevel(classification.sensitivityLabel, classification.types);
        if (sensitivityThreat) {
          threats.push(sensitivityThreat);
        }
      }
    }

    // Check transfer volume
    if (params.size && (params.size as number) > this.baselineVolume * 5) {
      threats.push({
        type: 'data_exfiltration',
        severity: 'medium',
        message: `Unusually large HTTP request: ${params.size} bytes`,
        evidence: `Size: ${params.size} bytes`,
        timestamp: new Date()
      });
    }

    return threats;
  }

  private monitorFileSystem(toolCall: ToolCall): ThreatDetection[] {
    const threats: ThreatDetection[] = [];
    const { params } = toolCall;
    const { action, content, path } = params;

    // Monitor file writes for sensitive data
    if (action === 'write' && content) {
      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
      const classification = this.classifier.getClassificationResult(contentStr);

      if (classification.isSensitive) {
        // Block writes of CRITICAL data to any location
        if (classification.sensitivityLabel === 'CRITICAL') {
          threats.push({
            type: 'data_exfiltration',
            severity: 'critical',
            message: `Attempt to write CRITICAL data to file: ${classification.types.join(', ')}`,
            evidence: `File: ${path}, Data types: ${classification.types.join(', ')}`,
            timestamp: new Date()
          });
        }
        // Warn on HIGH sensitivity data
        else if (classification.sensitivityLabel === 'HIGH') {
          threats.push({
            type: 'data_exfiltration',
            severity: 'high',
            message: `Attempt to write HIGH sensitivity data to file: ${classification.types.join(', ')}`,
            evidence: `File: ${path}, Data types: ${classification.types.join(', ')}`,
            timestamp: new Date()
          });
        }
      }
    }

    return threats;
  }

  /**
   * Check if domain is blocklisted
   * Returns threat if domain matches blocklist
   */
  private checkBlocklistedDomain(url: string): ThreatDetection | null {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;

      // Check against domain blocklist (AbuseIPDB simulation)
      if (isBlocklistedDomain(hostname)) {
        const threat = getDomainThreat(hostname);
        if (threat) {
          return {
            type: 'data_exfiltration',
            severity: threat.severity === 'high' ? 'high' : 'medium',
            message: `Blocked request to known ${threat.category} domain: ${hostname}`,
            evidence: `${threat.category}: ${threat.reason}`,
            timestamp: new Date()
          };
        }
      }

      // Additional heuristics: IP-based access (bypass domain filtering)
      if (this.isIPAddress(hostname)) {
        return {
          type: 'data_exfiltration',
          severity: 'medium',
          message: `HTTP request using IP address (domain bypass attempt): ${hostname}`,
          evidence: `Direct IP access: ${hostname}`,
          timestamp: new Date()
        };
      }

      return null;
    } catch {
      // Invalid URL is suspicious
      return {
        type: 'data_exfiltration',
        severity: 'medium',
        message: `Invalid URL detected`,
        evidence: `URL: ${url}`,
        timestamp: new Date()
      };
    }
  }

  /**
   * Check if sensitivity level warrants blocking/warning
   */
  private checkSensitivityLevel(label: SensitivityLabel, types: string[]): ThreatDetection | null {
    const riskLevel = getSensitivityRiskLevel(label);

    if (label === 'CRITICAL') {
      return {
        type: 'data_exfiltration',
        severity: 'critical',
        message: `Attempt to exfiltrate CRITICAL sensitivity data: ${types.join(', ')}`,
        evidence: `Data types: ${types.join(', ')}`,
        timestamp: new Date()
      };
    }

    if (label === 'HIGH') {
      return {
        type: 'data_exfiltration',
        severity: 'high',
        message: `Attempt to exfiltrate HIGH sensitivity data: ${types.join(', ')}`,
        evidence: `Data types: ${types.join(', ')}`,
        timestamp: new Date()
      };
    }

    // MEDIUM and LOW are allowed but logged
    return null;
  }

  /**
   * Check if hostname is an IP address
   */
  private isIPAddress(hostname: string): boolean {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  }

  checkVolumeAnomaly(bytesTransferred: number): boolean {
    // Detect if transfer volume is abnormally high
    return bytesTransferred > this.baselineVolume * 10;
  }

  setBaseline(bytes: number): void {
    this.baselineVolume = bytes;
  }
}
