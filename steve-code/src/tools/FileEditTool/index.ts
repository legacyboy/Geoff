import { readFile, writeFile } from 'fs/promises';
import { z } from 'zod';

const inputSchema = z.object({
  file_path: z.string().describe('The path to the file to edit'),
  old_string: z.string().describe('The exact text to find and replace'),
  new_string: z.string().describe('The replacement text'),
});

export const FileEditTool = {
  name: 'FileEditTool',
  description: 'Make precise edits to a file by replacing a specific string with new content.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { file_path, old_string, new_string } = input;
    
    try {
      const content = await readFile(file_path, 'utf-8');
      
      if (!content.includes(old_string)) {
        return {
          success: false,
          error: 'old_string not found in file',
        };
      }
      
      const newContent = content.replace(old_string, new_string);
      await writeFile(file_path, newContent, 'utf-8');
      
      return {
        success: true,
        message: `File edited successfully: ${file_path}`,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
      };
    }
  },
};