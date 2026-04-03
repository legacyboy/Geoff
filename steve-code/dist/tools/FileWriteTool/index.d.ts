import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    file_path: z.ZodString;
    content: z.ZodString;
}, "strip", z.ZodTypeAny, {
    file_path: string;
    content: string;
}, {
    file_path: string;
    content: string;
}>;
export declare const FileWriteTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        file_path: z.ZodString;
        content: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        file_path: string;
        content: string;
    }, {
        file_path: string;
        content: string;
    }>;
    execute(input: z.infer<typeof inputSchema>): Promise<{
        success: boolean;
        message: string;
        error?: undefined;
    } | {
        success: boolean;
        error: any;
        message?: undefined;
    }>;
};
export {};
//# sourceMappingURL=index.d.ts.map