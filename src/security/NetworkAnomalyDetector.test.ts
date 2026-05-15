import { NetworkAnomalyDetector } from './NetworkAnomalyDetector';
import { NetworkFlow } from '../types';

describe('NetworkAnomalyDetector', () => {
  let detector: NetworkAnomalyDetector;

  beforeEach(() => {
    detector = new NetworkAnomalyDetector();
  });

  describe('Port Scanning Detection', () => {
    it('should detect port scanning', () => {
      const flows: NetworkFlow[] = [];
      for (let port = 1; port <= 100; port++) {
        flows.push({
          id: `flow_${port}`,
          srcIp: '192.168.1.100',
          dstIp: '10.0.0.1',
          srcPort: 54000 + port,
          dstPort: port,
          bytes: 50,
          packets: 1,
          timestamp: new Date(Date.now() - (100 - port) * 1000),
          protocol: 'tcp'
        });
      }

      detector.addFlows(flows);
      const threats = detector.detect();

      const scanThreat = threats.find((t) => t.message.toLowerCase().includes('port scanning'));
      expect(scanThreat).toBeDefined();
      expect(scanThreat?.severity).toBe('high');
    });

    it('should not flag normal traffic as port scanning', () => {
      const flows: NetworkFlow[] = [
        {
          id: 'flow_1',
          srcIp: '192.168.1.100',
          dstIp: '10.0.0.1',
          srcPort: 54000,
          dstPort: 443,
          bytes: 1024,
          packets: 10,
          timestamp: new Date(),
          protocol: 'tcp'
        },
        {
          id: 'flow_2',
          srcIp: '192.168.1.100',
          dstIp: '10.0.0.1',
          srcPort: 54001,
          dstPort: 443,
          bytes: 2048,
          packets: 20,
          timestamp: new Date(),
          protocol: 'tcp'
        }
      ];

      detector.addFlows(flows);
      const threats = detector.detect();

      const scanThreat = threats.find((t) => t.message.toLowerCase().includes('port scanning'));
      expect(scanThreat).toBeUndefined();
    });
  });

  describe('Beaconing Detection', () => {
    it('should detect regular beaconing patterns', () => {
      const flows: NetworkFlow[] = [];
      const now = Date.now();

      // Create 10 flows at regular 60-second intervals
      for (let i = 0; i < 10; i++) {
        flows.push({
          id: `beacon_${i}`,
          srcIp: '192.168.1.100',
          dstIp: '1.2.3.4',
          srcPort: 50000 + i,
          dstPort: 443,
          bytes: 1024,
          packets: 10,
          timestamp: new Date(now + i * 60000),
          protocol: 'tcp'
        });
      }

      detector.addFlows(flows);
      const threats = detector.detect();

      const beaconThreat = threats.find((t) => t.message.toLowerCase().includes('beaconing'));
      expect(beaconThreat).toBeDefined();
      expect(beaconThreat?.severity).toBe('medium');
    });
  });

  describe('Data Exfiltration Detection', () => {
    it('should detect high-volume transfers', () => {
      detector.setVolumeBaseline(10000);

      const flows: NetworkFlow[] = [
        {
          id: 'exfil_1',
          srcIp: '192.168.1.50',
          dstIp: '203.0.113.45',
          srcPort: 54321,
          dstPort: 443,
          bytes: 500000000, // 500MB
          packets: 100000,
          timestamp: new Date(),
          protocol: 'tcp'
        }
      ];

      detector.addFlows(flows);
      const threats = detector.detect();

      const exfilThreat = threats.find((t) => t.type === 'data_exfiltration');
      expect(exfilThreat).toBeDefined();
      expect(exfilThreat?.severity).toBe('high');
    });
  });

  describe('Brute Force Detection', () => {
    it('should detect many connections from same source', () => {
      const flows: NetworkFlow[] = [];

      // Create 150 flows from same source IP
      for (let i = 0; i < 150; i++) {
        flows.push({
          id: `brute_${i}`,
          srcIp: '203.0.113.50',
          dstIp: '10.0.0.5',
          srcPort: 54000 + i,
          dstPort: 22, // SSH
          bytes: 100,
          packets: 5,
          timestamp: new Date(),
          protocol: 'tcp'
        });
      }

      detector.addFlows(flows);
      const threats = detector.detect();

      const bruteForceThreat = threats.find((t) => t.message.toLowerCase().includes('brute force'));
      expect(bruteForceThreat).toBeDefined();
    });
  });

  describe('Flow Statistics', () => {
    it('should correctly calculate flow stats', () => {
      const flows: NetworkFlow[] = [
        {
          id: 'flow_1',
          srcIp: '192.168.1.100',
          dstIp: '10.0.0.1',
          srcPort: 54000,
          dstPort: 443,
          bytes: 1000,
          packets: 10,
          timestamp: new Date(),
          protocol: 'tcp'
        },
        {
          id: 'flow_2',
          srcIp: '192.168.1.101',
          dstIp: '10.0.0.2',
          srcPort: 54001,
          dstPort: 80,
          bytes: 2000,
          packets: 20,
          timestamp: new Date(),
          protocol: 'tcp'
        }
      ];

      detector.addFlows(flows);
      const stats = detector.getFlowStats();

      expect(stats.totalFlows).toBe(2);
      expect(stats.totalBytes).toBe(3000);
      expect(stats.uniqueSourceIPs).toBe(2);
      expect(stats.uniqueDestIPs).toBe(2);
      expect(stats.uniquePorts).toBe(2);
    });
  });

  describe('Anomaly Scoring', () => {
    it('should score unusual ports higher', () => {
      const unusualFlow: NetworkFlow = {
        id: 'unusual',
        srcIp: '192.168.1.1',
        dstIp: '10.0.0.1',
        srcPort: 54321,
        dstPort: 12345, // Unusual port
        bytes: 1000,
        packets: 10,
        timestamp: new Date(),
        protocol: 'tcp'
      };

      const score = detector.getAnomalyScore(unusualFlow);
      expect(score.indicators).toContain('unusual_port');
      expect(score.score).toBeGreaterThan(0);
    });

    it('should score large transfers higher', () => {
      const largeFlow: NetworkFlow = {
        id: 'large',
        srcIp: '192.168.1.1',
        dstIp: '10.0.0.1',
        srcPort: 54321,
        dstPort: 443,
        bytes: 10000000, // 10MB
        packets: 10,
        timestamp: new Date(),
        protocol: 'tcp'
      };

      const score = detector.getAnomalyScore(largeFlow);
      expect(score.indicators).toContain('large_transfer');
    });
  });
});
