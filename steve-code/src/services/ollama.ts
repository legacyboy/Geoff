import { spawn } from 'child_process';
import { Readable } from 'stream';

export interface OllamaMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface OllamaOptions {
  model: string;
  messages: OllamaMessage[];
  stream?: boolean;
  temperature?: number;
  maxTokens?: number;
}

export interface OllamaResponse {
  message: {
    role: string;
    content: string;
  };
  done: boolean;
}

export class OllamaService {
  constructor(public baseUrl: string = 'http://localhost:11434') {
  }

  async *chat(options: OllamaOptions): AsyncGenerator<string, void, unknown> {
    const { model, messages, stream = true, temperature = 0.7 } = options;

    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream,
        options: {
          temperature,
          num_predict: options.maxTokens || 8192,
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
    }

    if (!response.body) {
      throw new Error('No response body');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.trim()) {
          try {
            const data: OllamaResponse = JSON.parse(line);
            if (data.message?.content) {
              yield data.message.content;
            }
          } catch {
            // Skip invalid JSON lines
          }
        }
      }
    }
  }

  async listModels(): Promise<string[]> {
    const response = await fetch(`${this.baseUrl}/api/tags`);
    if (!response.ok) {
      throw new Error('Failed to fetch models');
    }
    const data = await response.json() as { models: Array<{ name: string }> };
    return data.models.map(m => m.name);
  }

  async pullModel(model: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn('ollama', ['pull', model], {
        stdio: ['ignore', 'inherit', 'inherit'],
      });

      process.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Failed to pull model ${model}`));
      });
    });
  }

  async checkConnection(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`, { 
        signal: AbortSignal.timeout(5000) 
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}