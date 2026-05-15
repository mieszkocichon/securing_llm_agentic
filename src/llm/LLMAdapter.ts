import { LLMMessage, LLMResponse } from '../types';

export interface LLMConfig {
  modelId: string;
  apiKey?: string;
  baseUrl?: string;
  temperature?: number;
  maxTokens?: number;
}

export abstract class LLMAdapter {
  protected modelId: string;
  protected temperature: number;
  protected maxTokens: number;

  constructor(config: LLMConfig) {
    this.modelId = config.modelId;
    this.temperature = config.temperature ?? 0.7;
    this.maxTokens = config.maxTokens ?? 2048;
  }

  abstract generateResponse(
    messages: LLMMessage[],
    tools?: Array<{ name: string; description: string }>
  ): Promise<LLMResponse>;

  abstract parseToolCall(response: string): { toolName: string; params: Record<string, unknown> } | null;

  getModelId(): string {
    return this.modelId;
  }
}

export class MockLLMAdapter extends LLMAdapter {
  async generateResponse(messages: LLMMessage[]): Promise<LLMResponse> {
    const lastMessage = messages[messages.length - 1];

    // Simple mock: echo back the user input with a prefix
    const content = `I understand you want to: ${lastMessage.content}`;

    return {
      content,
      model: this.modelId,
      tokensUsed: {
        input: lastMessage.content.split(' ').length,
        output: content.split(' ').length
      }
    };
  }

  parseToolCall(response: string) {
    // Mock implementation: look for tool call patterns
    const match = response.match(/\{tool:\s*(\w+),\s*params:\s*({.*?})\}/);
    if (match) {
      try {
        return {
          toolName: match[1],
          params: JSON.parse(match[2])
        };
      } catch {
        return null;
      }
    }
    return null;
  }
}
