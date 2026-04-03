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
export declare class OllamaService {
    private baseUrl;
    constructor(baseUrl?: string);
    chat(options: OllamaOptions): AsyncGenerator<string, void, unknown>;
    listModels(): Promise<string[]>;
    pullModel(model: string): Promise<void>;
    checkConnection(): Promise<boolean>;
}
//# sourceMappingURL=ollama.d.ts.map