import { z } from 'zod';
export const ConfigSchema = z.object({
    defaultModel: z.string().default('qwen2.5-coder:14b'),
    fallbackModel: z.string().default('llama3.1:8b'),
    maxTokens: z.number().default(8192),
    temperature: z.number().default(0.7),
    ollamaUrl: z.string().default('http://localhost:11434'),
    tools: z.object({
        BashTool: z.boolean().default(true),
        FileReadTool: z.boolean().default(true),
        FileWriteTool: z.boolean().default(true),
        FileEditTool: z.boolean().default(true),
        GlobTool: z.boolean().default(true),
        GrepTool: z.boolean().default(true),
        LSPTool: z.boolean().default(false),
    }).default({}),
});
export const DEFAULT_MODELS = [
    { name: 'qwen2.5-coder:14b', description: 'Primary coding model', size: '9.0 GB' },
    { name: 'deepseek-coder:33b', description: 'Heavy lifting', size: '18 GB' },
    { name: 'llama3.1:8b', description: 'Fast responses', size: '4.9 GB' },
    { name: 'mistral:latest', description: 'Balanced', size: '4.4 GB' },
    { name: 'qwen3-coder:latest', description: 'Alternative coding', size: '18 GB' },
];
export const SYSTEM_PROMPT = `You are Steve Code 🦊, a helpful coding assistant powered by Ollama.
You have access to tools that let you read files, edit code, run commands, and search the codebase.

Always:
1. Think step by step
2. Use tools when needed (don't just describe what you would do)
3. Be concise but thorough
4. Ask for clarification if the request is ambiguous

When editing files:
- Use precise string matching with FileEditTool
- Verify changes by reading the file back
- Prefer small, focused edits over large replacements

When running commands:
- Explain what you're doing
- Show important output
- Handle errors gracefully

You are running entirely locally via Ollama. No data leaves this machine.`;
//# sourceMappingURL=config.js.map