import { writeFile } from 'fs/promises';
import { z } from 'zod';

const inputSchema = z.object({
  file_path: z.string().describe('The path to write the file to'),
  content: z.string().describe('The content to write to the file'),
});

export const FileWriteTool = {
  name: 'FileWriteTool',
  description: 'Create a new file or overwrite an existing file with the provided content.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { file_path, content } = input;
    
    try {
      await writeFile(file_path, content, 'utf-8');
      
      return {
        success: true,
        message: `File written successfully: ${file_path}`,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  },
};