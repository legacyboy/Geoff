import { BashTool } from './tools/BashTool/index.js';
import { FileReadTool } from './tools/FileReadTool/index.js';
import { FileWriteTool } from './tools/FileWriteTool/index.js';
import { FileEditTool } from './tools/FileEditTool/index.js';
import { GlobTool } from './tools/GlobTool/index.js';
import { GrepTool } from './tools/GrepTool/index.js';
export const tools = [
    BashTool,
    FileReadTool,
    FileWriteTool,
    FileEditTool,
    GlobTool,
    GrepTool,
];
export function getTool(name) {
    return tools.find(t => t.name === name);
}
export function getAllTools() {
    return tools;
}
//# sourceMappingURL=tools.js.map