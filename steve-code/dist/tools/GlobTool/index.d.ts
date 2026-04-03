import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    pattern: z.ZodString;
    cwd: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    pattern: string;
    cwd?: string | undefined;
}, {
    pattern: string;
    cwd?: string | undefined;
}>;
export declare const GlobTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        pattern: z.ZodString;
        cwd: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pattern: string;
        cwd?: string | undefined;
    }, {
        pattern: string;
        cwd?: string | undefined;
    }>;
    execute(input: z.infer<typeof inputSchema>): Promise<{
        success: boolean;
        files: string[];
        count: number;
        error?: undefined;
    } | {
        success: boolean;
        error: any;
        files?: undefined;
        count?: undefined;
    }>;
};
export {};
//# sourceMappingURL=index.d.ts.map