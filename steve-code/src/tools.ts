import { BashTool } from './tools/BashTool/index.js';
import { FileReadTool } from './tools/FileReadTool/index.js';
import { FileWriteTool } from './tools/FileWriteTool/index.js';
import { FileEditTool } from './tools/FileEditTool/index.js';
import { GlobTool } from './tools/GlobTool/index.js';
import { GrepTool } from './tools/GrepTool/index.js';

export interface Tool {
  name: string;
  description: string;
  inputSchema: unknown;
  execute: (input: any) => Promise<any>;
}

export const tools: Tool[] = [
  BashTool,
  FileReadTool,
  FileWriteTool,
  FileEditTool,
  GlobTool,
  GrepTool,
];

export function getTool(name: string): Tool | undefined {
  return tools.find(t => t.name === name);
}

export function getAllTools(): Tool[] {
  return tools;
}
