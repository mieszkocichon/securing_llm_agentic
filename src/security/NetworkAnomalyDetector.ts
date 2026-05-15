import { NetworkFlow, AnomalyScore, ThreatDetection } from '../types';

/**
 * NetworkAnomalyDetector
 *
 * Detects suspicious network behavior using deterministic heuristics.
 * This layer is designed to flag behavioral anomalies (port scanning, beaconing,
 * volume spikes, brute force) from VPC Flow Log abstractions.
 *
 * Design: Heuristic-based (fixed thresholds) rather than statistical (Mahalanobis
 * or other distance metrics). This trades adaptive detection for transparency:
 * each flagged flow can be audited and the detection logic is immediately clear.
 *
 * Limitations:
 * - Thresholds (20+ ports, CV < 0.2, etc.) are heuristic and may not fit all
 *   operational contexts. Recalibrate for your own traffic baselines.
 * - Legitimate high-volume operations (bulk S3 downloads, API bursts) may trigger
 *   false positives.
 * - No adaptive learning; detection rules are static unless manually updated.
 */
export class NetworkAnomalyDetector {
  private flows: NetworkFlow[] = [];
  private volumeBaseline: number = 10000; // bytes (configurable baseline for exfiltration detection)

  addFlow(flow: NetworkFlow): void {
    this.flows.push(flow);
  }

  addFlows(flows: NetworkFlow[]): void {
    this.flows.push(...flows);
  }

  /**
   * Detect all four classes of network anomalies
   */
  detect(): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    threats.push(...this.detectPortScanning());
    threats.push(...this.detectBeaconing());
    threats.push(...this.detectExfiltrationByVolume());
    threats.push(...this.detectBruteForce());

    return threats;
  }

  /**
   * Detect port scanning: single source probing many destination ports
   * Heuristic: >20 unique ports, >50 flows, <100 bytes/flow average
   */
  private detectPortScanning(): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    // Group flows by source IP
    const flowsBySource = new Map<string, NetworkFlow[]>();
    for (const flow of this.flows) {
      const key = flow.srcIp;
      if (!flowsBySource.has(key)) {
        flowsBySource.set(key, []);
      }
      flowsBySource.get(key)!.push(flow);
    }

    // Analyze each source
    for (const [srcIp, sourceFlows] of flowsBySource) {
      const uniquePorts = new Set(sourceFlows.map((f) => f.dstPort)).size;
      const totalFlows = sourceFlows.length;

      if (uniquePorts > 20 && totalFlows > 50) {
        const avgBytes = sourceFlows.reduce((sum, f) => sum + f.bytes, 0) / totalFlows;

        if (avgBytes < 100) {
          threats.push({
            type: 'network_anomaly',
            severity: 'high',
            message: `Port scanning detected from ${srcIp}: ${uniquePorts} unique ports`,
            evidence: `${totalFlows} flows to ${uniquePorts} unique ports, avg ${avgBytes.toFixed(0)} bytes`,
            timestamp: new Date()
          });
        }
      }
    }

    return threats;
  }

  /**
   * Detect beaconing: regular periodic outbound traffic (C2 communication)
   * Heuristic: coefficient of variation (stddev/mean) < 0.2 for inter-arrival times
   */
  private detectBeaconing(): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    // Group flows by source-destination pair
    const flowsByPair = new Map<string, NetworkFlow[]>();
    for (const flow of this.flows) {
      const key = `${flow.srcIp}->${flow.dstIp}:${flow.dstPort}`;
      if (!flowsByPair.has(key)) {
        flowsByPair.set(key, []);
      }
      flowsByPair.get(key)!.push(flow);
    }

    // Detect regular intervals (beaconing)
    for (const [pair, pairFlows] of flowsByPair) {
      if (pairFlows.length < 5) continue;

      const timestamps = pairFlows.map((f) => f.timestamp.getTime());
      const intervals = [];

      for (let i = 1; i < timestamps.length; i++) {
        intervals.push(timestamps[i] - timestamps[i - 1]);
      }

      // Check for low variance in intervals
      if (intervals.length > 0) {
        const mean = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = intervals.reduce((sum, i) => sum + Math.pow(i - mean, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);
        const coefficient = stdDev / mean;

        // CV < 0.2 indicates highly regular intervals (suspicious)
        if (coefficient < 0.2 && mean > 0) {
          threats.push({
            type: 'network_anomaly',
            severity: 'medium',
            message: `Beaconing detected: ${pair}`,
            evidence: `Regular intervals of ~${Math.round(mean / 1000)}s, CV=${coefficient.toFixed(2)}`,
            timestamp: new Date()
          });
        }
      }
    }

    return threats;
  }

  /**
   * Detect data exfiltration by volume
   * Heuristic: outbound volume to single destination > 5x baseline
   */
  private detectExfiltrationByVolume(): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    const outboundByDest = new Map<string, number>();
    for (const flow of this.flows) {
      const key = flow.dstIp;
      outboundByDest.set(key, (outboundByDest.get(key) || 0) + flow.bytes);
    }

    for (const [dstIp, totalBytes] of outboundByDest) {
      if (totalBytes > this.volumeBaseline * 5) {
        threats.push({
          type: 'data_exfiltration',
          severity: 'high',
          message: `Large outbound volume to ${dstIp}: ${(totalBytes / 1024 / 1024).toFixed(2)} MB`,
          evidence: `Exceeds baseline (${this.volumeBaseline} bytes) by ${(totalBytes / this.volumeBaseline).toFixed(1)}x`,
          timestamp: new Date()
        });
      }
    }

    return threats;
  }

  /**
   * Detect brute force: many connection attempts from single source
   * Heuristic: >100 flows from single source IP
   */
  private detectBruteForce(): ThreatDetection[] {
    const threats: ThreatDetection[] = [];

    const connectionsBySource = new Map<string, number>();
    for (const flow of this.flows) {
      connectionsBySource.set(flow.srcIp, (connectionsBySource.get(flow.srcIp) || 0) + 1);
    }

    for (const [srcIp, count] of connectionsBySource) {
      if (count > 100) {
        threats.push({
          type: 'network_anomaly',
          severity: 'medium',
          message: `Brute force attempt from ${srcIp}: ${count} connection attempts`,
          evidence: `${count} flows detected from single source`,
          timestamp: new Date()
        });
      }
    }

    return threats;
  }

  getAnomalyScore(flow: NetworkFlow): AnomalyScore {
    // Simple scoring: how anomalous is this single flow?
    let score = 0;
    const indicators: string[] = [];

    // Unusual port?
    if (this.isUnusualPort(flow.dstPort)) {
      score += 0.2;
      indicators.push('unusual_port');
    }

    // Large data transfer?
    if (flow.bytes > 1000000) {
      score += 0.15;
      indicators.push('large_transfer');
    }

    // Many packets?
    if (flow.packets > 10000) {
      score += 0.1;
      indicators.push('many_packets');
    }

    return {
      isAnomaly: score > 0.5,
      score,
      threshold: 0.5,
      indicators
    };
  }

  private isUnusualPort(port: number): boolean {
    const commonPorts = [80, 443, 22, 21, 25, 53, 110, 143, 3306, 5432, 5984, 6379, 27017];
    return !commonPorts.includes(port);
  }

  setVolumeBaseline(bytes: number): void {
    this.volumeBaseline = bytes;
  }

  getFlowStats() {
    return {
      totalFlows: this.flows.length,
      totalBytes: this.flows.reduce((sum, f) => sum + f.bytes, 0),
      uniqueSourceIPs: new Set(this.flows.map((f) => f.srcIp)).size,
      uniqueDestIPs: new Set(this.flows.map((f) => f.dstIp)).size,
      uniquePorts: new Set(this.flows.map((f) => f.dstPort)).size
    };
  }
}
