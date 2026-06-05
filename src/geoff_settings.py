#!/usr/bin/env python3
"""Geoff DFIR — Settings manager: model selection and API key persistence."""

import json
import os
import stat
from pathlib import Path

SETTINGS_FILE = Path.home() / '.geoff_settings.json'

_MODEL_OPTIONS = [
    "deepseek-v3.2:cloud",
    "deepseek-v4-pro",
    "gpt-4o",
    "claude-sonnet-4",
    "qwen3-coder-next:cloud",
    "qwen3.5:cloud",
    "deepseek-r1:32b",
    "qwen2.5-coder:14b",
    "qwen2.5:14b",
]


class SettingsManager:
    def __init__(self, settings_file: Path = SETTINGS_FILE):
        self._path = settings_file
        self._data = {
            "models": {
                "manager": "deepseek-v3.2:cloud",
                "forensicator": "qwen3-coder-next:cloud",
                "critic": "qwen3.5:cloud",
            },
            "keys": {
                "openai_key": "",
                "claude_key": "",
                "ollama_key": "",
                "deepseek_key": "",
            },
        }
        self._load()

    def _load(self):
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                loaded = json.load(f)
            if "models" in loaded and isinstance(loaded["models"], dict):
                self._data["models"].update(loaded["models"])
            if "keys" in loaded and isinstance(loaded["keys"], dict):
                self._data["keys"].update(loaded["keys"])
        except (json.JSONDecodeError, OSError):
            pass

    def _save(self):
        """Write settings atomically with 0600 permissions."""
        tmp = self._path.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            json.dump(self._data, f, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self._path)

    @staticmethod
    def _mask(value: str) -> str:
        if not value:
            return ""
        return "••••" + value[-4:] if len(value) >= 4 else "••••"

    def get_settings(self) -> dict:
        """Return current settings; API keys are masked to last 4 chars."""
        masked_keys = {k: self._mask(v) for k, v in self._data["keys"].items()}
        return {
            "models": dict(self._data["models"]),
            "keys": masked_keys,
            "model_options": _MODEL_OPTIONS,
        }

    def update_models(self, manager: str = None, forensicator: str = None, critic: str = None):
        if manager is not None:
            self._data["models"]["manager"] = manager
        if forensicator is not None:
            self._data["models"]["forensicator"] = forensicator
        if critic is not None:
            self._data["models"]["critic"] = critic
        self._save()

    def update_keys(self, openai_key: str = None, claude_key: str = None,
                    ollama_key: str = None, deepseek_key: str = None):
        if openai_key is not None:
            self._data["keys"]["openai_key"] = openai_key
        if claude_key is not None:
            self._data["keys"]["claude_key"] = claude_key
        if ollama_key is not None:
            self._data["keys"]["ollama_key"] = ollama_key
        if deepseek_key is not None:
            self._data["keys"]["deepseek_key"] = deepseek_key
        self._save()

    def apply_to_config(self):
        """Apply loaded settings to geoff_config at runtime (call on startup)."""
        import geoff_config
        models = self._data["models"]
        for role in ("manager", "forensicator", "critic"):
            if models.get(role):
                geoff_config.AGENT_MODELS[role] = models[role]
        geoff_config.LLM_MODEL = geoff_config.AGENT_MODELS["manager"]

        keys = self._data["keys"]
        if keys.get("openai_key"):
            os.environ["OPENAI_API_KEY"] = keys["openai_key"]
        if keys.get("claude_key"):
            os.environ["ANTHROPIC_API_KEY"] = keys["claude_key"]
        if keys.get("ollama_key"):
            os.environ["OLLAMA_API_KEY"] = keys["ollama_key"]
            geoff_config.OLLAMA_API_KEY = keys["ollama_key"]
        if keys.get("deepseek_key"):
            os.environ["DEEPSEEK_API_KEY"] = keys["deepseek_key"]

    @property
    def models(self) -> dict:
        return dict(self._data["models"])
