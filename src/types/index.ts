export interface LLMMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface LLMResponse {
  content: string;
  model: string;
  tokensUsed?: {
    input: number;
    output: number;
  };
}

export interface Tool {
  name: string;
  description: string;
  execute(params: Record<string, unknown>): Promise<unknown>;
}

export interface ToolCall {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  timestamp: Date;
}

export interface ExecutionTrace {
  id: string;
  timestamp: Date;
  userInput: string;
  llmResponse: LLMResponse;
  toolCalls: ToolCall[];
  threats: ThreatDetection[];
  securityViolations: SecurityViolation[];
}

export interface ThreatDetection {
  type: 'prompt_injection' | 'data_exfiltration' | 'network_anomaly';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  evidence: string;
  timestamp: Date;
}

export interface SecurityViolation {
  type: string;
  message: string;
  blocked: boolean;
  timestamp: Date;
}

export interface SecurityPolicy {
  maxTokensPerRequest: number;
  maxToolsPerExecution: number;
  allowedTools: string[];
  blockedPatterns: RegExp[];
  dataClassificationLevel: 'public' | 'internal' | 'confidential' | 'restricted';
}

export interface NetworkFlow {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  bytes: number;
  packets: number;
  timestamp: Date;
  protocol: string;
}

export interface AnomalyScore {
  isAnomaly: boolean;
  score: number;
  threshold: number;
  indicators: string[];
}

export type SensitivityLabel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface DataClassificationResult {
  isSensitive: boolean;
  types: string[];
  confidence: number;
  sensitivityLabel: SensitivityLabel;
}

export interface RiskScore {
  overallScore: number;
  applicationScore: number;
  infrastructureScore: number;
  recommendation: 'allow' | 'review' | 'block';
}
