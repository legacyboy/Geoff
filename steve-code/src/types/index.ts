export interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface Conversation {
  id: string;
  messages: Message[];
  model: string;
  timestamp: number;
}

export interface ToolResult {
  success: boolean;
  [key: string]: any;
}

export interface ToolCall {
  name: string;
  input: Record<string, any>;
}

export interface Command {
  name: string;
  description: string;
  handler: (args: string[]) => Promise<void>;
}
