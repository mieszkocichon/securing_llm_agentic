import { ExecutionTrace } from '../types';
import * as fs from 'fs';
import * as path from 'path';

export class ExecutionLogger {
  private logDir: string;

  constructor(logDir: string = './logs') {
    this.logDir = logDir;
    this.ensureLogDir();
  }

  private ensureLogDir(): void {
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }
  }

  logTrace(trace: ExecutionTrace): void {
    const logEntry = {
      ...trace,
      timestamp: trace.timestamp.toISOString()
    };

    const logPath = path.join(this.logDir, `trace_${trace.id}.json`);
    fs.writeFileSync(logPath, JSON.stringify(logEntry, null, 2), 'utf-8');
  }

  logThreats(traces: ExecutionTrace[]): void {
    const allThreats = traces
      .flatMap((t) =>
        t.threats.map((threat) => ({
          ...threat,
          traceId: t.id,
          timestamp: threat.timestamp.toISOString()
        }))
      )
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const logPath = path.join(this.logDir, 'threats.json');
    fs.writeFileSync(logPath, JSON.stringify(allThreats, null, 2), 'utf-8');
  }

  logSecurityReport(traces: ExecutionTrace[]): void {
    const allThreats = traces.flatMap((t) => t.threats);
    const allViolations = traces.flatMap((t) => t.securityViolations);

    const report = {
      generatedAt: new Date().toISOString(),
      summary: {
        totalExecutions: traces.length,
        totalThreatsDetected: allThreats.length,
        totalViolations: allViolations.length,
        executionsBlocked: traces.filter((t) => t.securityViolations.some((v) => v.blocked)).length
      },
      threatsBreakdown: {
        byType: this.groupBy(allThreats, (t) => t.type),
        bySeverity: this.groupBy(allThreats, (t) => t.severity)
      },
      violations: allViolations,
      detailedThreats: allThreats
    };

    const logPath = path.join(this.logDir, 'security_report.json');
    fs.writeFileSync(logPath, JSON.stringify(report, null, 2), 'utf-8');
  }

  exportCSV(traces: ExecutionTrace[]): void {
    const allThreats = traces.flatMap((t) =>
      t.threats.map((threat) => ({
        traceId: t.id,
        timestamp: threat.timestamp.toISOString(),
        type: threat.type,
        severity: threat.severity,
        message: threat.message
      }))
    );

    const headers = ['traceId', 'timestamp', 'type', 'severity', 'message'];
    const rows = allThreats.map((t) => [t.traceId, t.timestamp, t.type, t.severity, t.message]);

    const csv = [headers, ...rows].map((row) => row.join(',')).join('\n');

    const logPath = path.join(this.logDir, 'threats.csv');
    fs.writeFileSync(logPath, csv, 'utf-8');
  }

  private groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, number> {
    const result: Record<string, number> = {};
    for (const item of items) {
      const key = keyFn(item);
      result[key] = (result[key] || 0) + 1;
    }
    return result;
  }
}
