import { z } from 'zod';

const inputSchema = z.object({
  pattern: z.string().describe('Glob pattern to match files'),
  cwd: z.string().optional().describe('Working directory for the search'),
});

export const GlobTool = {
  name: 'GlobTool',
  description: 'Find files matching a glob pattern. Use for finding files by name or extension.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { pattern, cwd = process.cwd() } = input;
    
    try {
      const { glob } = await import('glob');
      const files = await glob(pattern, { cwd, absolute: true });
      
      return {
        success: true,
        files,
        count: files.length,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  },
};