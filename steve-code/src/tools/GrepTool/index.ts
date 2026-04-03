import { exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';

const execAsync = promisify(exec);

const inputSchema = z.object({
  pattern: z.string().describe('The regex pattern to search for'),
  path: z.string().optional().describe('The directory or file to search in'),
  include: z.string().optional().describe('File pattern to include (e.g., "*.ts")'),
});

export const GrepTool = {
  name: 'GrepTool',
  description: 'Search for patterns in files using regex. Fast code search across your project.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { pattern, path = '.', include } = input;
    
    try {
      let command = `grep -r -n -I --color=never`;
      if (include) {
        command += ` --include="${include}"`;
      }
      command += ` "${pattern}" "${path}"`;
      
      const { stdout } = await execAsync(command, {
        maxBuffer: 1024 * 1024 * 5,
      });
      
      const lines = stdout.trim().split('\n').filter(Boolean);
      
      return {
        success: true,
        matches: lines.map(line => {
          const [file, lineNum, ...contentParts] = line.split(':');
          return {
            file,
            line: parseInt(lineNum, 10),
            content: contentParts.join(':'),
          };
        }),
        count: lines.length,
      };
    } catch (error: any) {
      // grep returns exit code 1 when no matches found
      if (error.code === 1 && !error.stdout) {
        return {
          success: true,
          matches: [],
          count: 0,
        };
      }
      
      return {
        success: false,
        error: error.message,
      };
    }
  },
};