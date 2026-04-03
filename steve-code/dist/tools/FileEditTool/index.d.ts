import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    file_path: z.ZodString;
    old_string: z.ZodString;
    new_string: z.ZodString;
}, "strip", z.ZodTypeAny, {
    file_path: string;
    old_string: string;
    new_string: string;
}, {
    file_path: string;
    old_string: string;
    new_string: string;
}>;
export declare const FileEditTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        file_path: z.ZodString;
        old_string: z.ZodString;
        new_string: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        file_path: string;
        old_string: string;
        new_string: string;
    }, {
        file_path: string;
        old_string: string;
        new_string: string;
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