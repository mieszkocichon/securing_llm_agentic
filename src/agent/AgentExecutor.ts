import { LLMAdapter } from '../llm/LLMAdapter';
import { ToolRegistry } from '../tools/ToolRegistry';
import { PromptInjectionDetector } from '../security/PromptInjectionDetector';
import { ExfiltrationMonitor } from '../security/ExfiltrationMonitor';
import { NetworkAnomalyDetector } from '../security/NetworkAnomalyDetector';
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

    // Phase 3: Tool execution with security monitoring
    trace.toolCalls = await this.executeTools(trace, userInput);

    // Phase 4: Collect all threats from tool calls
    for (const toolCall of trace.toolCalls) {
      const toolThreats = this.exfiltrationMonitor.monitor(toolCall);
      trace.threats.push(...toolThreats);
    }

    // Phase 5: Network anomaly detection
    // Collect network flows from HTTPTool and analyze
    const httpTool = this.toolRegistry.get('http') as HTTPTool | undefined;
    if (httpTool) {
      const networkFlows = httpTool.getNetworkFlows();
      if (networkFlows.length > 0) {
        this.networkDetector.addFlows(networkFlows);
      }
    }
    const networkThreats = this.networkDetector.detect();
    trace.threats.push(...networkThreats);

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
