export interface Tool {
    name: string;
    description: string;
    inputSchema: unknown;
    execute: (input: any) => Promise<any>;
}
export declare const tools: Tool[];
export declare function getTool(name: string): Tool | undefined;
export declare function getAllTools(): Tool[];
//# sourceMappingURL=tools.d.ts.map