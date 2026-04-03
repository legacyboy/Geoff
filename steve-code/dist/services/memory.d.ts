import type { Message } from '../types/index.js';
export interface Conversation {
    id: string;
    messages: Message[];
    model: string;
    timestamp: number;
}
export declare class Memory {
    private db;
    private dbPath;
    constructor(dbPath?: string);
    private init;
    ensureDir(): Promise<void>;
    saveConversation(conversation: Conversation): void;
    getConversation(id: string): Conversation | null;
    getRecentConversations(limit?: number): Conversation[];
    close(): void;
}
//# sourceMappingURL=memory.d.ts.map