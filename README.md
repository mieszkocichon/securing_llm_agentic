# Secure Agentic LLM Framework

A production-ready TypeScript framework for securing autonomous LLM agents against prompt injection, data exfiltration, and network-based attacks.

## Overview

This framework provides a comprehensive security architecture for agentic LLM systems that extends traditional language models with autonomous decision-making and tool execution capabilities. It addresses three critical threat vectors:

1. **Prompt Injection Detection** - Identifies and blocks malicious instructions embedded in user input
2. **Data Exfiltration Prevention** - Monitors and blocks attempts to steal sensitive data
3. **Network Anomaly Detection** - Detects suspicious network behavior patterns

## Key Features

- **Multi-Provider LLM Support** - Abstract adapter pattern for Claude, GPT-4, and local models (Ollama)
- **Multi-Layer Security** - Defense-in-depth across input, processing, and output stages
- **Comprehensive Threat Detection**:
  - Pattern-based prompt injection detection
  - Semantic analysis and entropy checking
  - Sensitive data classification (PII, API keys, credentials)
  - Network traffic anomaly detection (port scanning, beaconing, data exfiltration)
- **Sandboxed Tool Execution** - Restricted file and HTTP operations
- **Audit Trail** - Complete execution logging and threat reporting
- **Extensible Architecture** - Easy to add new tools, detectors, and LLM providers

## Architecture

```
┌──────────────────────────────────────┐
│     LLM Provider (Multi-tenant)       │
│  Claude | OpenAI | Ollama | Custom    │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│   Input Security Layer               │
│  • Prompt Injection Detection        │
│  • Pattern Analysis                  │
│  • Entropy Analysis                  │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│     Agent Executor                    │
│  • Tool Registry & Dispatch           │
│  • Policy Enforcement                 │
│  • Execution Tracing                  │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│   Output Security Layer              │
│  • Data Exfiltration Monitor         │
│  • Network Anomaly Detection         │
│  • Sensitive Data Classification     │
└──────────────────────────────────────┘
           ↓
┌──────────────────────────────────────┐
│    Logging & Reporting               │
│  • Execution Traces                  │
│  • Threat Reports                    │
│  • Metrics & Analytics               │
└──────────────────────────────────────┘
```

## Installation

```bash
npm install
```

### Dependencies

- `@anthropic-ai/sdk` - Anthropic Claude API
- `openai` - OpenAI GPT API
- `zod` - Schema validation
- `typescript` - Type safety
- `jest` - Testing framework

## Quick Start

### Basic Agent Setup

```typescript
import {
  AgentExecutor,
  MockLLMAdapter,
  ToolRegistry,
  FileSystemTool,
  HTTPTool,
  createSecurityPolicy,
} from './src/index';

// Initialize components
const llm = new MockLLMAdapter({ modelId: 'mock-v1' });
const tools = new ToolRegistry();

tools.register(new FileSystemTool('./sandbox'));
tools.register(new HTTPTool());

const policy = createSecurityPolicy();
const executor = new AgentExecutor({ llm, tools, policy });

// Execute with security
const trace = await executor.execute('What is 2+2?');
console.log('Threats detected:', trace.threats);
console.log('Blocked:', trace.securityViolations);
```

### Using Claude

```typescript
import { ClaudeAdapter } from './src/index';

const llm = new ClaudeAdapter({
  modelId: 'claude-3-sonnet',
  apiKey: process.env.ANTHROPIC_API_KEY
});

const executor = new AgentExecutor({ llm, tools, policy });
```

### Security Policies

```typescript
import { STRICT_POLICY, PERMISSIVE_POLICY, createSecurityPolicy } from './src/index';

// Predefined policies
const executor = new AgentExecutor({ llm, tools, policy: STRICT_POLICY });

// Custom policy
const customPolicy = createSecurityPolicy({
  maxToolsPerExecution: 3,
  allowedTools: ['filesystem', 'http'],
  dataClassificationLevel: 'confidential'
});
```

## Examples

### Run Basic Demo

```bash
npm run example:basic
```

Output includes:
- Normal operation test
- Prompt injection attempt
- Sensitive data detection

### Run Attack Scenarios

```bash
npm run example:attacks
```

Demonstrates:
- Various prompt injection techniques
- Data exfiltration attempts
- Network anomaly patterns

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Coverage

- **PromptInjectionDetector**: Pattern detection, entropy analysis, structural anomalies
- **DataClassifier**: Email, API keys, credit cards, SSN, passwords, database URLs
- **NetworkAnomalyDetector**: Port scanning, beaconing, volume-based exfiltration, brute force
- **ExfiltrationMonitor**: Data classification, suspicious destinations
- **AgentExecutor**: End-to-end execution with security checks

## Threat Detection Details

### Prompt Injection

Detects multiple attack vectors:

```
1. Direct Patterns
   "Ignore all previous instructions"
   "System prompt override"
   "You are now in developer mode"

2. Entropy Analysis
   High entropy input suggests encoded/obfuscated commands

3. Structural Anomalies
   Unusual character density
   Excessive Unicode
   Short command-like lines

4. Injection Markers
   HTML comments: <!-- -->
   System tags: [SYSTEM], {SYSTEM}
```

### Data Exfiltration

Identifies sensitive data types:

```
- PII: Email addresses, SSN, phone numbers
- Credentials: API keys, passwords, database URLs
- Financial: Credit cards, account numbers
- Security: Private keys, certificates
```

Monitors outbound channels:
- HTTP requests with sensitive data
- File writes containing PII
- Destination validation

### Network Anomalies

```
1. Port Scanning
   - Many unique destination ports
   - Low data volume per connection
   - Short duration flows

2. Beaconing
   - Regular time intervals
   - Same destination
   - Consistent data patterns

3. Data Exfiltration
   - High outbound volume
   - Unusual destinations
   - Regular intervals

4. Brute Force
   - Many connection attempts
   - Same source IP
   - Repeated failures
```

## Security Policy Configuration

```typescript
interface SecurityPolicy {
  maxTokensPerRequest: number;      // Limit tokens per LLM call
  maxToolsPerExecution: number;     // Max tools per execution
  allowedTools: string[];            // Whitelist of allowed tools
  blockedPatterns: RegExp[];         // Prompt injection patterns
  dataClassificationLevel: string;   // 'public' | 'internal' | 'confidential' | 'restricted'
}
```

## Logging & Reporting

### Execution Traces

Each execution produces a comprehensive trace:

```typescript
{
  id: "trace_1234567890",
  timestamp: "2024-01-15T10:30:00Z",
  userInput: "What is the weather?",
  llmResponse: { content: "...", model: "claude-3" },
  toolCalls: [
    { toolName: "http", params: {...}, result: {...} }
  ],
  threats: [...],
  securityViolations: [...]
}
```

### Generate Reports

```typescript
import { ExecutionLogger } from './src/index';

const logger = new ExecutionLogger('./logs');
logger.logTrace(trace);
logger.logSecurityReport(allTraces);
logger.exportCSV(allTraces);
```

## Performance

- **Prompt Injection Detection**: < 10ms per request
- **Data Classification**: < 5ms per classification
- **Network Analysis**: < 50ms per 1000 flows
- **Overall Security Overhead**: < 100ms per execution

## Integration with Real Systems

### For Production Deployment

1. **Replace Mock LLM** with actual Claude/OpenAI adapter
2. **Connect Real Tools** (databases, APIs, file systems)
3. **Enable Network Monitoring** with real VPC Flow Logs
4. **Setup Persistent Logging** (CloudWatch, DataDog, etc.)
5. **Configure Alerting** for high-severity threats

### Network Flow Integration

```typescript
import { NetworkAnomalyDetector } from './src/index';

const detector = new NetworkAnomalyDetector();

// Feed real VPC Flow Logs
vpcFlows.forEach(flow => detector.addFlow(flow));

// Detect anomalies
const threats = detector.detect();
```

## Research Paper Integration

This framework serves as the practical implementation component for the paper "Securing Agentic LLM Systems: Mitigating Prompt Injection and Data Exfiltration Risks".

### Sections Addressed

- **Introduction**: System architecture and threat model
- **Related Work**: Network traffic analysis and anomaly detection
- **Implementation**: Framework components and design decisions
- **Evaluation**: Attack scenarios and detection results
- **Results**: Threat detection rates and performance metrics

## File Structure

```
src/
├── agent/
│   └── AgentExecutor.ts          # Main orchestrator
├── llm/
│   ├── LLMAdapter.ts              # Base class
│   ├── ClaudeAdapter.ts           # Claude implementation
│   └── OpenAIAdapter.ts           # GPT-4 implementation
├── security/
│   ├── PromptInjectionDetector.ts # Pattern & semantic analysis
│   ├── DataClassifier.ts          # Sensitive data detection
│   ├── ExfiltrationMonitor.ts     # Outbound data monitoring
│   └── NetworkAnomalyDetector.ts  # Network pattern analysis
├── tools/
│   ├── FileSystemTool.ts          # Sandboxed file ops
│   ├── HTTPTool.ts                # Monitored HTTP requests
│   └── ToolRegistry.ts            # Tool management
├── config/
│   └── SecurityPolicy.ts          # Policy definitions
├── logger/
│   └── ExecutionLogger.ts         # Audit trail & reporting
├── types/
│   └── index.ts                   # Type definitions
└── index.ts                       # Public API

examples/
├── basic_agent.ts                 # Simple demo
└── attack_scenarios.ts            # Threat demonstrations

tests/
└── security/
    ├── *.test.ts                  # Unit tests
```

## Contributing

This is a research implementation. Contributions for:
- Additional LLM provider adapters
- New detection mechanisms
- Performance optimizations
- Real-world integrations

are welcome.

## License

MIT

## Authors

- Andrzej Mycek (Cracow University of Technology)
- Mieszko Cichoń (Cracow University of Technology)

## Citation

```bibtex
@paper{mycek2024securing,
  title={Securing Agentic LLM Systems: Mitigating Prompt Injection and Data Exfiltration Risks},
  authors={Mycek, Andrzej and Cichoń, Mieszko},
  institution={Cracow University of Technology},
  year={2024}
}
```
