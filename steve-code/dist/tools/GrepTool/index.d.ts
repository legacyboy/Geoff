import { z } from 'zod';
declare const inputSchema: z.ZodObject<{
    pattern: z.ZodString;
    path: z.ZodOptional<z.ZodString>;
    include: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    pattern: string;
    path?: string | undefined;
    include?: string | undefined;
}, {
    pattern: string;
    path?: string | undefined;
    include?: string | undefined;
}>;
export declare const GrepTool: {
    name: string;
    description: string;
    inputSchema: z.ZodObject<{
        pattern: z.ZodString;
        path: z.ZodOptional<z.ZodString>;
        include: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        pattern: string;
        path?: string | undefined;
        include?: string | undefined;
    }, {
        pattern: string;
        path?: string | undefined;
        include?: string | undefined;
    }>;
    execute(input: z.infer<typeof inputSchema>): Promise<{
        success: boolean;
        matches: {
            file: string;
            line: number;
            content: string;
        }[];
        count: number;
        error?: undefined;
    } | {
        success: boolean;
        error: any;
        matches?: undefined;
        count?: undefined;
    }>;
};
export {};
//# sourceMappingURL=index.d.ts.map