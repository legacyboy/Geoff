import { z } from 'zod';
export declare const ConfigSchema: z.ZodObject<{
    defaultModel: z.ZodDefault<z.ZodString>;
    fallbackModel: z.ZodDefault<z.ZodString>;
    maxTokens: z.ZodDefault<z.ZodNumber>;
    temperature: z.ZodDefault<z.ZodNumber>;
    ollamaUrl: z.ZodDefault<z.ZodString>;
    tools: z.ZodDefault<z.ZodObject<{
        BashTool: z.ZodDefault<z.ZodBoolean>;
        FileReadTool: z.ZodDefault<z.ZodBoolean>;
        FileWriteTool: z.ZodDefault<z.ZodBoolean>;
        FileEditTool: z.ZodDefault<z.ZodBoolean>;
        GlobTool: z.ZodDefault<z.ZodBoolean>;
        GrepTool: z.ZodDefault<z.ZodBoolean>;
        LSPTool: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        BashTool: boolean;
        FileReadTool: boolean;
        FileWriteTool: boolean;
        FileEditTool: boolean;
        GlobTool: boolean;
        GrepTool: boolean;
        LSPTool: boolean;
    }, {
        BashTool?: boolean | undefined;
        FileReadTool?: boolean | undefined;
        FileWriteTool?: boolean | undefined;
        FileEditTool?: boolean | undefined;
        GlobTool?: boolean | undefined;
        GrepTool?: boolean | undefined;
        LSPTool?: boolean | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    defaultModel: string;
    fallbackModel: string;
    maxTokens: number;
    temperature: number;
    ollamaUrl: string;
    tools: {
        BashTool: boolean;
        FileReadTool: boolean;
        FileWriteTool: boolean;
        FileEditTool: boolean;
        GlobTool: boolean;
        GrepTool: boolean;
        LSPTool: boolean;
    };
}, {
    defaultModel?: string | undefined;
    fallbackModel?: string | undefined;
    maxTokens?: number | undefined;
    temperature?: number | undefined;
    ollamaUrl?: string | undefined;
    tools?: {
        BashTool?: boolean | undefined;
        FileReadTool?: boolean | undefined;
        FileWriteTool?: boolean | undefined;
        FileEditTool?: boolean | undefined;
        GlobTool?: boolean | undefined;
        GrepTool?: boolean | undefined;
        LSPTool?: boolean | undefined;
    } | undefined;
}>;
export type Config = z.infer<typeof ConfigSchema>;
export declare const DEFAULT_MODELS: readonly [{
    readonly name: "qwen2.5-coder:14b";
    readonly description: "Primary coding model";
    readonly size: "9.0 GB";
}, {
    readonly name: "deepseek-coder:33b";
    readonly description: "Heavy lifting";
    readonly size: "18 GB";
}, {
    readonly name: "llama3.1:8b";
    readonly description: "Fast responses";
    readonly size: "4.9 GB";
}, {
    readonly name: "mistral:latest";
    readonly description: "Balanced";
    readonly size: "4.4 GB";
}, {
    readonly name: "qwen3-coder:latest";
    readonly description: "Alternative coding";
    readonly size: "18 GB";
}];
export declare const SYSTEM_PROMPT = "You are Steve Code \uD83E\uDD8A, a helpful coding assistant powered by Ollama.\nYou have access to tools that let you read files, edit code, run commands, and search the codebase.\n\nAlways:\n1. Think step by step\n2. Use tools when needed (don't just describe what you would do)\n3. Be concise but thorough\n4. Ask for clarification if the request is ambiguous\n\nWhen editing files:\n- Use precise string matching with FileEditTool\n- Verify changes by reading the file back\n- Prefer small, focused edits over large replacements\n\nWhen running commands:\n- Explain what you're doing\n- Show important output\n- Handle errors gracefully\n\nYou are running entirely locally via Ollama. No data leaves this machine.";
//# sourceMappingURL=config.d.ts.map