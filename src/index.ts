// Core exports
export { AgentExecutor, AgentConfig } from './agent/AgentExecutor';
export { LLMAdapter, LLMConfig, MockLLMAdapter } from './llm/LLMAdapter';
export { ClaudeAdapter } from './llm/ClaudeAdapter';
export { OpenAIAdapter } from './llm/OpenAIAdapter';
export { ToolRegistry } from './tools/ToolRegistry';
export { FileSystemTool } from './tools/FileSystemTool';
export { HTTPTool } from './tools/HTTPTool';

// Security exports
export { PromptInjectionDetector } from './security/PromptInjectionDetector';
export { DataClassifier } from './security/DataClassifier';
export { ExfiltrationMonitor } from './security/ExfiltrationMonitor';
export { NetworkAnomalyDetector } from './security/NetworkAnomalyDetector';
export { RiskAggregator } from './security/RiskAggregator';

// Config exports
export { createSecurityPolicy, STRICT_POLICY, PERMISSIVE_POLICY } from './config/SecurityPolicy';

// Logging exports
export { ExecutionLogger } from './logger/ExecutionLogger';

// Evaluation framework exports
export { EvaluationMetrics } from './evaluation/EvaluationMetrics';
export {
  INJECTION_ATTACKS,
  BENIGN_SAMPLES,
  getDatasetSplit,
  createEvaluationDataset,
  datasetStats
} from './evaluation/JailbreakBenchDataset';

// Type exports
export type {
  LLMMessage,
  LLMResponse,
  Tool,
  ToolCall,
  ExecutionTrace,
  ThreatDetection,
  SecurityViolation,
  SecurityPolicy,
  NetworkFlow,
  AnomalyScore,
  DataClassificationResult,
  RiskScore,
  SensitivityLabel
} from './types';

export type {
  EvaluationResult,
  ThresholdAnalysis
} from './evaluation/EvaluationMetrics';

export type {
  AttackSample,
  BenignSample
} from './evaluation/JailbreakBenchDataset';
