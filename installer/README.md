# Geoff AI Assistant

A self-hosted AI assistant with a custom web UI, powered by Ollama and OpenClaw.

## Quick Start

```bash
# One-command install
curl -fsSL https://raw.githubusercontent.com/legacyboy/Geoff/main/installer/install.sh | bash

# Or download and run
git clone https://github.com/yourusername/geoff.git
cd geoff
bash install.sh
```

## Features

- **Web UI** - Clean, responsive interface for chatting and managing evidence
- **Local AI** - Runs entirely on your machine using Ollama
- **Evidence Management** - Upload and organize files for AI context
- **Easy Install** - One command to install everything
- **Systemd Integration** - Auto-start on boot

## Usage

```bash
# Start all services
geoff start

# Open web UI (http://localhost:8080)
geoff ui

# Chat in terminal
geoff chat

# Check status
geoff status

# Stop services
geoff stop

# View logs
geoff logs
```

## Requirements

- Linux (Ubuntu/Debian recommended)
- 8GB+ RAM recommended
- curl, jq

## Web UI Features

- **Chat Tab** - Real-time messaging with WebSocket
- **Evidence Tab** - Drag-and-drop file uploads
- **Config Tab** - Model settings, evidence paths, gateway config

## Configuration

- `~/.openclaw/config.yaml` - OpenClaw settings
- `~/.geoff/ui-config.json` - Web UI settings
- `~/.geoff/evidence/` - Evidence storage

## Architecture

```
[Browser] ←→ [Geoff UI Server :8080] ←→ [OpenClaw Gateway :18789] ←→ [Ollama :11434]
                                              ↓
                                    [Geoff AI (gemma3:4b)]
```

## License

MIT

## Contributing

Fork, branch, PR. Issues welcome.
