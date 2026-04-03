import { exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';

const execAsync = promisify(exec);

const inputSchema = z.object({
  command: z.string().describe('The shell command to execute'),
  description: z.string().describe('A brief description of what the command does'),
  timeout: z.number().optional().describe('Timeout in milliseconds'),
});

export const BashTool = {
  name: 'BashTool',
  description: 'Execute shell commands. Use for file operations, running scripts, git commands, etc.',
  inputSchema,
  
  async execute(input: z.infer<typeof inputSchema>) {
    const { command, description, timeout = 60000 } = input;
    
    console.log(`🦊 Running: ${description || command}`);
    
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout,
        maxBuffer: 1024 * 1024 * 10, // 10MB buffer
      });
      
      return {
        success: true,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: 0,
      };
    } catch (error: any) {
      return {
        success: false,
        stdout: error.stdout?.trim() || '',
        stderr: error.stderr?.trim() || error.message,
        exitCode: error.code || 1,
      };
    }
  },
};