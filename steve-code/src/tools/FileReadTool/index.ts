import { readFile } from 'fs/promises';
import { z } from 'zod';

const inputSchema = z.object({
  file_path: z.string().describe('The path to the file to read'),
  offset: z.number().optional().describe('Line number to start reading from'),
  limit: z.number().optional().describe('Maximum number of lines to read'),
});

export const FileReadTool = {
  name: 'FileReadTool',
  description: 'Read the contents of a file. Supports text files and code files.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { file_path, offset = 1, limit } = input;
    
    try {
      const content = await readFile(file_path, 'utf-8');
      const lines = content.split('\n');
      
      let start = Math.max(0, offset - 1);
      let end = limit ? start + limit : lines.length;
      
      const selectedLines = lines.slice(start, end);
      const result = selectedLines.join('\n');
      
      return {
        success: true,
        content: result,
        totalLines: lines.length,
        readLines: selectedLines.length,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  },
};