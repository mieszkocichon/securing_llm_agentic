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
    // Parse URL first — throw immediately on invalid URL, before any other checks.
    // IMPORTANT: do NOT wrap the blocked-host check inside this try/catch, or
    // the intentional "Blocked" error gets swallowed and relabelled as "Invalid URL".
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`Invalid URL: ${url}`);
    }

    // Block private/internal networks (SSRF prevention)
    // Uses proper RFC 1918 / loopback range checks rather than fragile string-prefix matching.
    if (this.isBlockedHost(parsed.hostname)) {
      throw new Error(`Blocked: Cannot access internal network ${url}`);
    }
  }

  /**
   * Returns true if the hostname resolves to a private, loopback, or link-local address.
   *
   * Covers:
   *   - Named hosts: localhost, ::1, 0.0.0.0
   *   - RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
   *   - Loopback: 127.0.0.0/8
   *   - Link-local: 169.254.0.0/16 (AWS metadata service is on 169.254.169.254)
   *
   * Previous implementation used string-prefix matching ('10.0.', '172.16.')
   * which only blocked 10.0.x.x and 172.16.x.x — missing the full RFC 1918 ranges
   * (10.1–255.x.x and 172.17–31.x.x).
   */
  private isBlockedHost(hostname: string): boolean {
    // Named loopback / special hosts
    if (['localhost', '::1', '0.0.0.0'].includes(hostname)) return true;

    // IPv4 range checks
    const parts = hostname.split('.').map(Number);
    if (parts.length === 4 && parts.every((n) => !isNaN(n) && n >= 0 && n <= 255)) {
      if (parts[0] === 127) return true;                                      // 127.0.0.0/8  loopback
      if (parts[0] === 10) return true;                                       // 10.0.0.0/8   RFC 1918
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12 RFC 1918
      if (parts[0] === 192 && parts[1] === 168) return true;                 // 192.168.0.0/16 RFC 1918
      if (parts[0] === 169 && parts[1] === 254) return true;                 // 169.254.0.0/16 link-local
    }

    return false;
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
