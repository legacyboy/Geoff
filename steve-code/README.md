# Steve Code 🦊

A fully local, open-source alternative to Claude Code powered by Ollama.

## Architecture

- **Frontend:** React + Ink (terminal UI, like Claude Code)
- **Backend:** Bun runtime with TypeScript
- **LLM:** Ollama (local models only - no Claude API)
- **Tools:** Bash, file operations, grep, glob, edit tools
- **Memory:** Local SQLite for conversation history
- **Config:** JSON-based user settings

## Models Supported

### Recommended Models (pulled automatically):
- `qwen2.5-coder:14b` - Primary coding model (9GB)
- `deepseek-coder:33b` - Heavy lifting (18GB)
- `llama3.1:8b` - Fast responses (4.9GB)
- `mistral:latest` - Balanced (4.4GB)
- `qwen3-coder:latest` - Alternative coding (18GB)

### Embedding Models:
- `nomic-embed-text:latest` - For RAG (274MB)
- `mxbai-embed-large:latest` - Better quality (669MB)

## Key Differences from Claude Code

1. **Fully Local** - No cloud dependencies, no API keys, no telemetry
2. **Model Flexibility** - Switch between local models on the fly
3. **No Claude** - Uses only Ollama-hosted models
4. **Simpler** - Streamlined codebase, fewer feature flags
5. **Open Source** - Modify, extend, self-host

## Installation

```bash
# Clone and install
cd steve-code
bun install

# Pull recommended models
bun run setup:models

# Start Steve Code
bun run start
```

## Configuration

Edit `~/.steve-code/config.json`:

```json
{
  "defaultModel": "qwen2.5-coder:14b",
  "fallbackModel": "llama3.1:8b",
  "maxTokens": 8192,
  "temperature": 0.7,
  "tools": {
    "BashTool": true,
    "FileEditTool": true,
    "FileReadTool": true,
    "GlobTool": true,
    "GrepTool": true
  }
}
```

## Commands

- `/models` - List and switch models
- `/settings` - Edit configuration
- `/clear` - Clear conversation history
- `/cost` - Show token usage stats
- `exit` - Quit Steve Code

## Project Structure

```
steve-code/
├── src/
│   ├── main.tsx           # Entry point
│   ├── commands/          # CLI commands
│   ├── tools/            # Tool implementations
│   ├── services/         # Ollama integration
│   └── utils/            # Helpers
├── models/               # Model configs
├── config/               # User settings
└── memory/               # Conversation history
```

---

*Built with ❤️ by Steve for Dan*