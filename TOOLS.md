# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

## Search Module (Standard Tool)

**Location:** `/home/claw/.openclaw/workspace/search_module.py`

**All future projects use this for web search.**

**Usage:**
```python
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import web_search, search_workspace

# Web search via SerpAPI (100 free/month)
results = web_search('your query', num_results=5)

# Search local workspace files
local_results = search_workspace('your query')
```

**Currently Used By:**
- Trading Bot (geopolitical monitoring)
- Business Ideas Bot (market validation)
- iOS Games Bot (trend research)

---

Add whatever helps you do your job. This is your cheat sheet.

## LLM Models

### Local Models (via Ollama)

| Alias | Model | Size | Best For |
|-------|-------|------|----------|
| `phi-mini` | phi3:mini | 2.2 GB | Fast, lightweight tasks |
| `qwen-coder` | qwen2.5-coder:14b | 9.0 GB | Code generation |
| `deepseek-coder` | deepseek-coder:33b | 18 GB | Complex coding |
| `fast-coder` | qwen2.5-coder:7b | 4.7 GB | Quick coding tasks |
| `gemma` | gemma3:12b | 8.1 GB | General purpose |
| `mistral` | mistral:latest | 4.4 GB | Balanced performance |
| `llama` | llama3.1:8b | 4.9 GB | General purpose |

### Cloud Models (via Ollama)

| Alias | Model | Best For |
|-------|-------|----------|
| `deepseek-v3` | ollama/deepseek-v3.2:cloud | Complex reasoning, coding, analysis |
| `deepseek-v3.2` | ollama/deepseek-v3.2:cloud | Same as above (alternate alias) |
| `gemma4` | ollama/gemma3.4:cloud | Advanced reasoning, multilingual, coding |

**Usage:**
```bash
ollama run deepseek-v3.2:cloud
ollama run gemma3.4:cloud
```

Or via OpenClaw: specify `model=ollama/deepseek-v3.2:cloud` or `model=ollama/gemma3.4:cloud` in your request.

**Usage:**
```bash
ollama run phi3:mini
ollama run qwen2.5-coder:14b
```

Or via OpenClaw: specify `model=ollama/phi3:mini` in your request.




## Email (Dedicated Account)
- Account: danoclawnor@gmail.com 
- Password: vcya wmru jlcx gqgo 
- Purpose: Check/read/send for Dan, registrations, automated tasks

---

## OpenClaw Configuration

Config location: `~/.openclaw/config.yaml`

### Available Models

#### Cloud Models
- `gemma4` - ollama/gemma3.4:cloud - Advanced reasoning, multilingual, coding
- `deepseek-v3` - ollama/deepseek-v3.2:cloud - Complex reasoning, analysis

#### Local Models
See LLM Models section above

### Usage
\`\`\`yaml
# OpenClaw Configuration

models:
  # Local Models
  phi-mini:
    provider: ollama
    model: phi3:mini
    description: "Fast, lightweight tasks (2.2GB)"
    
  qwen-coder:
    provider: ollama
    model: qwen2.5-coder:14b
    description: "Code generation (9GB)"
    
  deepseek-coder:
    provider: ollama
    model: deepseek-coder:33b
    description: "Complex coding (18GB)"
    
  fast-coder:
    provider: ollama
    model: qwen2.5-coder:7b
    description: "Quick coding tasks (4.7GB)"
    
  gemma:
    provider: ollama
    model: gemma3:12b
    description: "General purpose (8.1GB)"
    
  mistral:
    provider: ollama
    model: mistral:latest
    description: "Balanced performance (4.4GB)"
    
  llama:
    provider: ollama
    model: llama3.1:8b
    description: "General purpose (4.9GB)"
  
  # Cloud Models
  deepseek-v3:
    provider: ollama
    model: ollama/deepseek-v3.2:cloud
    description: "Complex reasoning, coding, analysis (cloud)"
    
  gemma4:
    provider: ollama
    model: ollama/gemma3.4:cloud
    description: "Advanced reasoning, multilingual, coding (cloud)"
    
  gemma4-coder:
    provider: ollama
    model: ollama/gemma3.4:cloud
    description: "Advanced coding tasks (cloud, same as gemma4)"

default_model: gemma4

# Model aliases
aliases:
  ChatCoder: qwen-coder
  ClaudeCoder: deepseek-coder
  FastCoder: fast-coder
  PrimaryCoder: deepseek-coder
  sonnet: deepseek-coder
  deepseek-v3.2: deepseek-v3
\`\`\`
