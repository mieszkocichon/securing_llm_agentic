import Anthropic from '@anthropic-ai/sdk';
import { LLMAdapter, LLMConfig } from './LLMAdapter';
import { LLMMessage, LLMResponse } from '../types';

export class ClaudeAdapter extends LLMAdapter {
  private client: Anthropic;

  constructor(config: LLMConfig) {
    super(config);
    if (!config.apiKey) {
      throw new Error('Claude adapter requires apiKey');
    }
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  async generateResponse(
    messages: LLMMessage[],
    tools?: Array<{ name: string; description: string }>
  ): Promise<LLMResponse> {
    const anthropicMessages = messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({
        role: m.role as 'user' | 'assistant',
        content: m.content
      }));

    const systemPrompt = messages.find((m) => m.role === 'system')?.content || '';

    const response = await this.client.messages.create({
      model: this.modelId,
      max_tokens: this.maxTokens,
      temperature: this.temperature,
      system: systemPrompt || undefined,
      messages: anthropicMessages
    });

    const content = response.content
      .filter((block) => block.type === 'text')
      .map((block) => (block.type === 'text' ? block.text : ''))
      .join('');

    return {
      content,
      model: this.modelId,
      tokensUsed: {
        input: response.usage.input_tokens,
        output: response.usage.output_tokens
      }
    };
  }

  parseToolCall(response: string) {
    // Simple pattern matching for tool calls in response
    const match = response.match(/use_tool\s*\(\s*"(\w+)"\s*,\s*({[\s\S]*?})\s*\)/);
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
