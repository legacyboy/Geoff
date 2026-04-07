# Geoff - Digital Forensics Investigator

**Geoff** is an autonomous digital forensics investigation platform with a web-based interface for managing evidence, running investigations, and reviewing findings.

## Features

- **Web Chat Interface**: Interact with Geoff through a clean, dark-themed web UI
- **Evidence Upload**: Drag-and-drop file uploads with automatic case creation
- **Configuration Panel**: Manage Ollama settings (local or cloud)
- **Case Management**: Track investigation progress with visual indicators
- **Findings Viewer**: Browse and view investigation results
- **One-Command Install**: Complete setup including Ollama and models

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/yourrepo/geoff/main/install.sh | bash
```

Or manually:

```bash
git clone https://github.com/yourrepo/geoff
cd geoff
./install.sh
```

## Usage

### Start Geoff

```bash
# Foreground (see logs)
geoff start

# Background (daemon mode)
geoff start -d
```

### Web Interface

Open your browser to `http://localhost:5000`

1. **Upload Evidence**: Drag files to the upload area or click to browse
2. **Configure**: Set Ollama host (local or cloud) and preferred models
3. **Chat**: Interact with Geoff to start the investigation
4. **Monitor**: Track progress in real-time with the status panel

### Commands

```bash
geoff start          # Start Geoff
geoff start -d       # Start in background
geoff stop           # Stop Geoff
geoff status         # Check status
geoff logs           # View logs
geoff config         # Show configuration
```

## Project Structure

```
geoff/
├── install.sh           # One-command installer
├── setup.sh            # Dev environment setup
├── spawn_geoff.py     # Investigation runner
├── check_geoff.py     # Status checker
├── investigation_planner.py  # State management
├── PROJECT.md          # Architecture docs
├── webui/
│   ├── app.py          # Flask web application
│   ├── requirements.txt # Python dependencies
│   └── templates/
│       └── index.html  # Main UI
├── cases/              # Investigation data
├── uploads/            # Evidence storage
└── findings/           # Investigation results
```

## Configuration

Geoff stores configuration in `~/.geoff/geoff/config.json`:

```json
{
  "ollama_host": "http://localhost:11434",
  "cloud_ollama": "https://ollama.yourdomain.com",
  "default_model": "deepseek-v3.2:cloud",
  "evidence_path": "./uploads"
}
```

## Requirements

- Linux (Ubuntu/Debian/Kali recommended)
- Python 3.8+
- curl
- ~2GB disk space (for models)

## Development

```bash
# Setup dev environment
./setup.sh

# Activate virtual environment
source venv/bin/activate

# Run web UI
python webui/app.py

# Run tests
python -m pytest tests/
```

## Architecture

Geoff consists of:

1. **Web UI** (Flask): User interface for uploads, chat, and case management
2. **Investigation Planner**: Manages case state and step execution
3. **Agent (ACP)**: Geoff investigator spawned as isolated sessions
4. **Ollama**: LLM inference for the investigation agent

## License

MIT