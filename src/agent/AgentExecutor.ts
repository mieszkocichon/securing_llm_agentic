import { LLMAdapter } from '../llm/LLMAdapter';
import { ToolRegistry } from '../tools/ToolRegistry';
import { PromptInjectionDetector } from '../security/PromptInjectionDetector';
import { ExfiltrationMonitor } from '../security/ExfiltrationMonitor';
import { NetworkAnomalyDetector } from '../security/NetworkAnomalyDetector';
import { RiskAggregator } from '../security/RiskAggregator';
import { ExecutionTrace, LLMMessage, SecurityPolicy, ToolCall, ThreatDetection, NetworkFlow } from '../types';
import { HTTPTool } from '../tools/HTTPTool';

export interface AgentConfig {
  llm: LLMAdapter;
  tools: ToolRegistry;
  policy: SecurityPolicy;
  systemPrompt?: string;
}

export class AgentExecutor {
  private llm: LLMAdapter;
  private toolRegistry: ToolRegistry;
  private policy: SecurityPolicy;
  private systemPrompt: string;
  private injectionDetector: PromptInjectionDetector;
  private exfiltrationMonitor: ExfiltrationMonitor;
  private networkDetector: NetworkAnomalyDetector;
  private riskAggregator: RiskAggregator;
  private traces: ExecutionTrace[] = [];

  constructor(config: AgentConfig) {
    this.llm = config.llm;
    this.toolRegistry = config.tools;
    this.policy = config.policy;
    this.systemPrompt =
      config.systemPrompt ||
      'You are a helpful AI assistant. You have access to specific tools. Always be honest and helpful.';

    this.injectionDetector = new PromptInjectionDetector(this.policy);
    this.exfiltrationMonitor = new ExfiltrationMonitor(this.policy);
    this.networkDetector = new NetworkAnomalyDetector();
    this.riskAggregator = new RiskAggregator();
  }

  async execute(userInput: string): Promise<ExecutionTrace> {
    const trace: ExecutionTrace = {
      id: this.generateId(),
      timestamp: new Date(),
      userInput,
      llmResponse: { content: '', model: this.llm.getModelId() },
      toolCalls: [],
      threats: [],
      securityViolations: []
    };

    // Phase 1: Input validation & threat detection
    const inputThreats = this.injectionDetector.detect(userInput);
    trace.threats.push(...inputThreats);

    // Block if critical threats
    const criticalThreats = inputThreats.filter((t) => t.severity === 'critical' || t.severity === 'high');
    if (criticalThreats.length > 0) {
      trace.securityViolations.push({
        type: 'prompt_injection_detected',
        message: `Blocked execution due to detected injection: ${criticalThreats.map((t) => t.message).join('; ')}`,
        blocked: true,
        timestamp: new Date()
      });

      this.traces.push(trace);
      return trace;
    }

    // Phase 2: Get LLM response
    const messages: LLMMessage[] = [
      { role: 'system', content: this.systemPrompt },
      { role: 'user', content: userInput }
    ];

    try {
      const llmResponse = await this.llm.generateResponse(messages, this.toolRegistry.getToolDescriptions());
      trace.llmResponse = llmResponse;
    } catch (error) {
      trace.securityViolations.push({
        type: 'llm_error',
        message: `LLM execution failed: ${error instanceof Error ? error.message : String(error)}`,
        blocked: true,
        timestamp: new Date()
      });

      this.traces.push(trace);
      return trace;
    }

    // Phase 3: Tool execution with pre-execution exfiltration screening
    // ExfiltrationMonitor runs BEFORE each tool executes so blocked calls are prevented.
    trace.toolCalls = await this.executeTools(trace, userInput);

    // Phase 4: Collect application-layer threats (injection + exfiltration)
    // These were already gathered during Phases 1 and 3 into trace.threats.

    // Phase 5: Network anomaly detection (infrastructure layer)
    // Collect network flows from HTTPTool and analyze.
    // After consuming flows we clear BOTH the HTTPTool buffer and the detector's
    // internal state so that flows from this execution do not pollute subsequent ones.
    // Without clearing, accumulated flows across many executions would falsely trigger
    // port-scan (>50 flows), beaconing, or brute-force alerts due to benign aggregate counts.
    const httpTool = this.toolRegistry.get('http') as HTTPTool | undefined;
    if (httpTool) {
      const networkFlows = httpTool.getNetworkFlows();
      if (networkFlows.length > 0) {
        this.networkDetector.addFlows(networkFlows);
      }
      httpTool.clearNetworkFlows(); // prevent cross-execution accumulation
    }
    const networkThreats = this.networkDetector.detect();
    this.networkDetector.clearFlows(); // reset detector state for next execution
    trace.threats.push(...networkThreats);

    // Phase 6: Risk aggregation — combine application and infrastructure signals
    // using the product-of-complements formula R = 1 - (1 - r_A)(1 - d·r_I)
    // Separate by source (not by type) to avoid double-counting:
    // networkThreats may include type='data_exfiltration' (from detectExfiltrationByVolume)
    // which would otherwise appear in both lists if filtered by type.
    const infrastructureThreats = networkThreats; // ALL threats from networkDetector
    const applicationThreats = trace.threats.filter((t) => !networkThreats.includes(t));
    const riskScore = this.riskAggregator.aggregate(applicationThreats, infrastructureThreats);

    if (riskScore.recommendation === 'block') {
      trace.securityViolations.push({
        type: 'risk_threshold_exceeded',
        message: `Blocked by risk aggregator: overall risk score ${riskScore.overallScore} ≥ τ_B (0.85)`,
        blocked: true,
        timestamp: new Date()
      });
    } else if (riskScore.recommendation === 'review') {
      // Route to human review; execution already completed but response should be flagged
      trace.securityViolations.push({
        type: 'risk_review_required',
        message: `Flagged for human review: overall risk score ${riskScore.overallScore} in REVIEW band [0.65, 0.85)`,
        blocked: false,
        timestamp: new Date()
      });
    }

    this.traces.push(trace);
    return trace;
  }

  private async executeTools(trace: ExecutionTrace, context: string): Promise<ToolCall[]> {
    const toolCalls: ToolCall[] = [];
    const toolsUsed = new Set<string>();

    // Simulate tool execution based on LLM response
    const availableTools = this.toolRegistry.getAllNames();

    for (const toolName of availableTools) {
      // Check policy limits
      if (toolsUsed.size >= this.policy.maxToolsPerExecution) {
        trace.securityViolations.push({
          type: 'max_tools_exceeded',
          message: `Max tools limit exceeded: ${this.policy.maxToolsPerExecution}`,
          blocked: true,
          timestamp: new Date()
        });
        break;
      }

      // Check if tool is allowed
      if (!this.policy.allowedTools.includes(toolName)) {
        trace.securityViolations.push({
          type: 'tool_not_allowed',
          message: `Tool ${toolName} is not in allowed list`,
          blocked: true,
          timestamp: new Date()
        });
        continue;
      }

      // Mock tool execution
      const mockParams = this.getMockToolParams(toolName);
      const toolCall: ToolCall = {
        toolName,
        params: mockParams,
        timestamp: new Date()
      };

      // PRE-EXECUTION: ExfiltrationMonitor screens the call BEFORE the tool runs.
      // This is the correct order — paper §4: "a call is blocked if..."
      const exfilThreats = this.exfiltrationMonitor.monitor(toolCall);
      trace.threats.push(...exfilThreats);

      const criticalExfil = exfilThreats.filter(
        (t) => t.severity === 'critical' || t.severity === 'high'
      );
      if (criticalExfil.length > 0) {
        trace.securityViolations.push({
          type: 'exfiltration_blocked',
          message: `Tool call '${toolName}' blocked before execution: ${criticalExfil.map((t) => t.message).join('; ')}`,
          blocked: true,
          timestamp: new Date()
        });
        // Skip tool execution — call is blocked
        toolCalls.push(toolCall);
        continue;
      }

      try {
        const result = await this.toolRegistry.executeTool(toolName, mockParams);
        toolCall.result = result;

        if (!result.success) {
          toolCall.error = result.error;
        }
      } catch (error) {
        toolCall.error = error instanceof Error ? error.message : String(error);
      }

      toolsUsed.add(toolName);
      toolCalls.push(toolCall);
    }

    return toolCalls;
  }

  private getMockToolParams(toolName: string): Record<string, unknown> {
    switch (toolName) {
      case 'filesystem':
        return {
          action: 'read',
          path: 'example.txt'
        };
      case 'http':
        return {
          method: 'GET',
          url: 'https://api.example.com/data'
        };
      default:
        return {};
    }
  }

  private generateId(): string {
    return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getTraces(): ExecutionTrace[] {
    return this.traces;
  }

  getTrace(id: string): ExecutionTrace | undefined {
    return this.traces.find((t) => t.id === id);
  }

  clearTraces(): void {
    this.traces = [];
  }

  getSecurityStats() {
    const allThreats = this.traces.flatMap((t) => t.threats);
    const allViolations = this.traces.flatMap((t) => t.securityViolations);

    return {
      totalExecutions: this.traces.length,
      totalThreatsDetected: allThreats.length,
      threatsByType: this.groupBy(allThreats, (t) => t.type),
      threatsBySeverity: this.groupBy(allThreats, (t) => t.severity),
      totalViolations: allViolations.length,
      blockedExecutions: this.traces.filter((t) => t.securityViolations.some((v) => v.blocked)).length
    };
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
