import { Tool, NetworkFlow } from '../types';

export class HTTPTool implements Tool {
  name = 'http';
  description = 'Make HTTP requests to external APIs';
  private networkFlows: NetworkFlow[] = [];

  async execute(params: Record<string, unknown>): Promise<unknown> {
    const { method = 'GET', url, headers, body } = params;

    if (typeof url !== 'string') {
      throw new Error('URL must be string');
    }

    // Validate URL to prevent SSRF
    this.validateURL(url);

    // Log network flow for anomaly detection
    this.logNetworkFlow(url, method as string, body);

    // In production, use real fetch. For MVP, we mock it.
    return this.mockHTTPCall(url, method as string);
  }

  private validateURL(url: string): void {
    try {
      const parsed = new URL(url);
      // Block private/internal networks
      const blockedHosts = ['localhost', '127.0.0.1', '192.168.', '10.0.', '172.16.'];
      if (blockedHosts.some((host) => parsed.hostname.includes(host))) {
        throw new Error(`Blocked: Cannot access internal network ${url}`);
      }
    } catch (e) {
      throw new Error(`Invalid URL: ${url}`);
    }
  }

  private logNetworkFlow(url: string, method: string, body?: unknown): void {
    const urlObj = new URL(url);
    const flow: NetworkFlow = {
      id: `flow_${Date.now()}`,
      srcIp: '127.0.0.1',
      dstIp: '0.0.0.0', // Would be resolved in production
      srcPort: Math.floor(Math.random() * 65535),
      dstPort: urlObj.protocol === 'https:' ? 443 : 80,
      bytes: JSON.stringify(body).length || 0,
      packets: 1,
      timestamp: new Date(),
      protocol: urlObj.protocol
    };
    this.networkFlows.push(flow);
  }

  private mockHTTPCall(url: string, method: string): { status: number; body: string } {
    // Mock response based on URL pattern
    return {
      status: 200,
      body: JSON.stringify({
        message: `Mock response from ${url}`,
        method,
        timestamp: new Date().toISOString()
      })
    };
  }

  getNetworkFlows(): NetworkFlow[] {
    return this.networkFlows;
  }

  clearNetworkFlows(): void {
    this.networkFlows = [];
  }
}
