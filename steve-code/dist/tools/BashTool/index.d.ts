import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    command: z.ZodString;
    description: z.ZodString;
    timeout: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    command: string;
    description: string;
    timeout?: number | undefined;
}, {
    command: string;
    description: string;
    timeout?: number | undefined;
}>;
export declare const BashTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        command: z.ZodString;
        description: z.ZodString;
        timeout: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        command: string;
        description: string;
        timeout?: number | undefined;
    }, {
        command: string;
        description: string;
        timeout?: number | undefined;
    }>;
    execute(input: z.infer<typeof inputSchema>): Promise<{
        success: boolean;
        stdout: any;
        stderr: any;
        exitCode: any;
    }>;
};
export {};
//# sourceMappingURL=index.d.ts.map