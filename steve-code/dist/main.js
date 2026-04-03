import { OllamaService } from './services/ollama.js';
import { ConfigSchema, SYSTEM_PROMPT } from './config.js';
import { getAllTools } from './tools.js';
import { join } from 'path';
import { homedir } from 'os';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { createInterface } from 'readline';
class SteveCode {
    ollama;
    config;
    conversation;
    tools;
    constructor() {
        this.config = this.loadConfig();
        this.ollama = new OllamaService(this.config.ollamaUrl);
        this.tools = getAllTools();
        this.conversation = {
            messages: [{ role: 'system', content: SYSTEM_PROMPT }],
            model: this.config.defaultModel,
        };
    }
    loadConfig() {
        const configPath = join(homedir(), '.steve-code', 'config.json');
        if (existsSync(configPath)) {
            try {
                const config = JSON.parse(readFileSync(configPath, 'utf-8'));
                return ConfigSchema.parse(config);
            }
            catch {
                console.log('⚠️ Invalid config, using defaults');
            }
        }
        return ConfigSchema.parse({});
    }
    saveConfig() {
        const configDir = join(homedir(), '.steve-code');
        if (!existsSync(configDir)) {
            mkdirSync(configDir, { recursive: true });
        }
        const configPath = join(configDir, 'config.json');
        writeFileSync(configPath, JSON.stringify(this.config, null, 2));
    }
    async checkOllama() {
        const connected = await this.ollama.checkConnection();
        if (!connected) {
            console.error('❌ Cannot connect to Ollama. Is it running?');
            console.error('   Start with: ollama serve');
            return false;
        }
        return true;
    }
    async listModels() {
        try {
            return await this.ollama.listModels();
        }
        catch {
            return [];
        }
    }
    setModel(model) {
        this.conversation.model = model;
        this.config.defaultModel = model;
        this.saveConfig();
        console.log(`🦊 Model set to: ${model}`);
    }
    async executeTool(toolCall) {
        const tool = this.tools.find(t => t.name === toolCall.name);
        if (!tool) {
            return { success: false, error: `Tool ${toolCall.name} not found` };
        }
        console.log(`🔧 Using ${toolCall.name}...`);
        return await tool.execute(toolCall.input);
    }
    parseToolCalls(content) {
        const toolCalls = [];
        // Parse <tool> tags from LLM output
        const toolRegex = /<tool>\s*\{[\s\S]*?\}\s*<\/tool>/g;
        const matches = content.match(toolRegex);
        if (!matches)
            return null;
        for (const match of matches) {
            try {
                const json = match.replace(/<tool>/, '').replace(/<\/tool>/, '').trim();
                const parsed = JSON.parse(json);
                if (parsed.name && parsed.input) {
                    toolCalls.push(parsed);
                }
            }
            catch {
                // Skip invalid JSON
            }
        }
        return toolCalls.length > 0 ? toolCalls : null;
    }
    async chat(userInput) {
        this.conversation.messages.push({ role: 'user', content: userInput });
        // Build system prompt with tool definitions
        const toolDescriptions = this.tools
            .filter(t => this.config.tools[t.name] !== false)
            .map(t => `${t.name}: ${t.description}`)
            .join('\n');
        const toolInstructions = `\n\nYou have access to these tools:\n${toolDescriptions}\n\nWhen you need to use a tool, output:\n<tool>{"name": "ToolName", "input": {"param": "value"}}</tool>\n\nThe user will see the tool result, then you can respond naturally.`;
        const systemMessage = SYSTEM_PROMPT + toolInstructions;
        const messages = [
            { role: 'system', content: systemMessage },
            ...this.conversation.messages.slice(1), // Skip default system, use enhanced
        ];
        process.stdout.write('🦊 ');
        let fullResponse = '';
        try {
            const stream = this.ollama.chat({
                model: this.conversation.model,
                messages,
                temperature: this.config.temperature,
                maxTokens: this.config.maxTokens,
            });
            for await (const chunk of stream) {
                process.stdout.write(chunk);
                fullResponse += chunk;
            }
            process.stdout.write('\n');
            // Check for tool calls
            const toolCalls = this.parseToolCalls(fullResponse);
            if (toolCalls) {
                for (const toolCall of toolCalls) {
                    const result = await this.executeTool(toolCall);
                    const resultMsg = `\n[Tool ${toolCall.name} result]: ${JSON.stringify(result, null, 2)}`;
                    console.log(resultMsg);
                    // Add to conversation
                    this.conversation.messages.push({
                        role: 'assistant',
                        content: fullResponse,
                    });
                    this.conversation.messages.push({
                        role: 'user',
                        content: `[Tool result for ${toolCall.name}]: ${JSON.stringify(result)}`,
                    });
                    // Get follow-up response
                    await this.continueChat();
                    return;
                }
            }
            this.conversation.messages.push({
                role: 'assistant',
                content: fullResponse,
            });
        }
        catch (error) {
            console.error(`\n❌ Error: ${error.message}`);
            if (error.message.includes('model')) {
                console.error(`   Model "${this.conversation.model}" not found.`);
                console.error(`   Run: ollama pull ${this.conversation.model}`);
            }
        }
    }
    async continueChat() {
        const toolDescriptions = this.tools
            .filter(t => this.config.tools[t.name] !== false)
            .map(t => `${t.name}: ${t.description}`)
            .join('\n');
        const systemMessage = SYSTEM_PROMPT + `\n\nAvailable tools:\n${toolDescriptions}`;
        const messages = [{ role: 'system', content: systemMessage }, ...this.conversation.messages.slice(1)];
        process.stdout.write('🦊 ');
        let fullResponse = '';
        const stream = this.ollama.chat({
            model: this.conversation.model,
            messages,
            temperature: this.config.temperature,
            maxTokens: this.config.maxTokens,
        });
        for await (const chunk of stream) {
            process.stdout.write(chunk);
            fullResponse += chunk;
        }
        process.stdout.write('\n');
        this.conversation.messages.push({
            role: 'assistant',
            content: fullResponse,
        });
    }
    showHelp() {
        console.log(`
🦊 Steve Code - Local AI Coding Assistant

Commands:
  /models              List available models
  /model <name>       Switch to a different model
  /clear               Clear conversation history
  /settings            Show current settings
  /tools               List available tools
  /help                Show this help
  exit                 Quit Steve Code

Usage:
  Type natural language to chat with the AI
  It can read files, run commands, search code, and more
`);
    }
    showSettings() {
        console.log(`\n🦊 Current Settings:`);
        console.log(`  Default Model: ${this.config.defaultModel}`);
        console.log(`  Fallback Model: ${this.config.fallbackModel}`);
        console.log(`  Temperature: ${this.config.temperature}`);
        console.log(`  Max Tokens: ${this.config.maxTokens}`);
        console.log(`  Ollama URL: ${this.config.ollamaUrl}`);
        console.log(`\n  Enabled Tools:`);
        Object.entries(this.config.tools)
            .filter(([_, enabled]) => enabled)
            .forEach(([name]) => console.log(`    ✓ ${name}`));
    }
    clearConversation() {
        this.conversation.messages = [{ role: 'system', content: SYSTEM_PROMPT }];
        console.log('🦊 Conversation cleared');
    }
}
async function main() {
    const steve = new SteveCode();
    console.log(`
╔══════════════════════════════════════════╗
║                                          ║
║           🦊 Steve Code                  ║
║                                          ║
║   Local AI Coding Assistant              ║
║   Powered by Ollama                      ║
║                                          ║
╚══════════════════════════════════════════╝
`);
    if (!await steve.checkOllama()) {
        process.exit(1);
    }
    const models = await steve.listModels();
    console.log(`✓ Connected to Ollama`);
    console.log(`✓ ${models.length} models available`);
    console.log(`\nType /help for commands, or just start chatting!\n`);
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: '\n❯ ',
    });
    rl.prompt();
    rl.on('line', async (input) => {
        const trimmed = input.trim();
        if (!trimmed) {
            rl.prompt();
            return;
        }
        if (trimmed === 'exit' || trimmed === 'quit') {
            console.log('\n🦊 Goodbye!');
            rl.close();
            return;
        }
        if (trimmed === '/help') {
            steve.showHelp();
        }
        else if (trimmed === '/models') {
            const models = await steve.listModels();
            console.log('\n🦊 Available Models:');
            models.forEach(m => console.log(`  • ${m}`));
        }
        else if (trimmed.startsWith('/model ')) {
            const model = trimmed.slice(7).trim();
            steve.setModel(model);
        }
        else if (trimmed === '/clear') {
            steve.clearConversation();
        }
        else if (trimmed === '/settings') {
            steve.showSettings();
        }
        else if (trimmed === '/tools') {
            const tools = getAllTools();
            console.log('\n🦊 Available Tools:');
            tools.forEach(t => console.log(`  • ${t.name}: ${t.description}`));
        }
        else {
            await steve.chat(trimmed);
        }
        rl.prompt();
    });
    rl.on('close', () => {
        console.log('\n🦊 Session saved. See you next time!');
        process.exit(0);
    });
}
main().catch(console.error);
//# sourceMappingURL=main.js.map