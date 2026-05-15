import OpenAI from 'openai';
import { LLMAdapter, LLMConfig } from './LLMAdapter';
import { LLMMessage, LLMResponse } from '../types';

export class OpenAIAdapter extends LLMAdapter {
  private client: OpenAI;

  constructor(config: LLMConfig) {
    super(config);
    if (!config.apiKey) {
      throw new Error('OpenAI adapter requires apiKey');
    }
    this.client = new OpenAI({ apiKey: config.apiKey });
  }

  async generateResponse(messages: LLMMessage[]): Promise<LLMResponse> {
    const openaiMessages = messages.map((m) => ({
      role: m.role as 'user' | 'assistant' | 'system',
      content: m.content
    }));

    const response = await this.client.chat.completions.create({
      model: this.modelId,
      max_tokens: this.maxTokens,
      temperature: this.temperature,
      messages: openaiMessages
    });

    const content = response.choices[0]?.message?.content || '';

    return {
      content,
      model: this.modelId,
      tokensUsed: {
        input: response.usage?.prompt_tokens || 0,
        output: response.usage?.completion_tokens || 0
      }
    };
  }

  parseToolCall(response: string) {
    const match = response.match(/\{tool:\s*"(\w+)",\s*params:\s*({[\s\S]*?})\}/);
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
