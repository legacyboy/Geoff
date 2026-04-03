import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    file_path: z.ZodString;
    offset: z.ZodOptional<z.ZodNumber>;
    limit: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    file_path: string;
    offset?: number | undefined;
    limit?: number | undefined;
}, {
    file_path: string;
    offset?: number | undefined;
    limit?: number | undefined;
}>;
export declare const FileReadTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        file_path: z.ZodString;
        offset: z.ZodOptional<z.ZodNumber>;
        limit: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        file_path: string;
        offset?: number | undefined;
        limit?: number | undefined;
    }, {
        file_path: string;
        offset?: number | undefined;
        limit?: number | undefined;
    }>;
    execute(input: z.infer<typeof inputSchema>): Promise<{
        success: boolean;
        content: string;
        totalLines: number;
        readLines: number;
        error?: undefined;
    } | {
        success: boolean;
        error: any;
        content?: undefined;
        totalLines?: undefined;
        readLines?: undefined;
    }>;
};
export {};
//# sourceMappingURL=index.d.ts.map