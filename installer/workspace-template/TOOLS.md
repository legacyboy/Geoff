# TOOLS.md - Geoff's Tool Notes

Skills define _how_ tools work. This file is for _Geoff's_ specifics.

## Multi-Agent Models

### Local Models (via Ollama)

| Alias | Model | Size | Role | Trigger |
|-------|-------|------|------|---------|
| `geoff` | gemma4:31b-cloud | 4GB | Main coordinator | Default |
| `fastcoder` | qwen2.5-coder:7b | 4.7GB | Quick fixes | "quick", "fix" |
| `critic` | qwen2.5-coder:14b | 9GB | Code review | "review", "audit" |
| `architect` | gemma4:31b-cloud | 8GB | UI/Frontend | "UI", "design" |
| `deepseek` | deepseek-coder:33b | 18GB | Complex dev | "build", "architecture" |

### Cloud Models (via Ollama Cloud)

| Alias | Model | Role |
|-------|-------|------|
| `deepseek-v3` | ollama/deepseek-v3.2:cloud | Complex reasoning, coding |
| `gemma4` | ollama/gemma4:31b-cloud | General purpose, fast |
| `qwen-large` | ollama/qwen2.5:32b:cloud | Large context tasks |

## Environment

- **OS:** Ubuntu 24.04
- **Node:** v22
- **OpenClaw:** Installed via npm
- **Ollama:** ~/.local/bin/ollama
- **Port:** 11434

## Geoff-Specific Config

### Test Machine (192.168.1.94)
- User: claw
- SSH Key: ~/.ssh/id_ed25519
- Geoff UI: http://localhost:8080
- Gateway: ws://127.0.0.1:18789
- Token: geoff-default

### Model Routing

```javascript
// Auto-detect which agent to use
function routeTask(task) {
  const lower = task.toLowerCase();
  
  if (lower.includes('review') || lower.includes('audit'))
    return 'critic';
  if (lower.includes('ui') || lower.includes('design'))
    return 'architect';
  if (lower.includes('build') || lower.includes('architecture'))
    return 'deepseek';
  if (lower.includes('quick') || lower.includes('fix'))
    return 'fastcoder';
  
  return 'geoff'; // Default
}
```

## Evidence Storage

Default evidence location: `~/.geoff/evidence/`

Each upload gets:
- Original file
- Metadata JSON
- Processing log
- Hash verification

## API Keys

- Ollama (local): Not required
- Ollama Cloud: Set via `OLLAMA_API_KEY`
- Other services: Stored in `~/.openclaw/agents/main/agent/auth-profiles.json`

---

Add tool-specific configurations here as needed.
