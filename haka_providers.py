#!/usr/bin/env python3
"""
HAKA Providers — Unified LLM backend for HAKA tools.
Supports: local (ollama), Anthropic, DeepSeek, OpenAI, OpenRouter.

Usage:
  from haka_providers import HakaLLM
  llm = HakaLLM()
  response = llm.generate("Write a report...", model="claude")
"""

import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from typing import Optional, Dict, List

# ── API key loading ──────────────────────────────────────────────────────────

def _load_key(env_var: str, file_paths: list = None) -> Optional[str]:
    """Load an API key from env var or known .env files."""
    key = os.environ.get(env_var)
    if key:
        return key
    paths = file_paths or [
        os.path.expanduser("~/kewani-bot/.env"),
        os.path.expanduser("~/my-dev-project/apex-real/.env"),
        os.path.expanduser("~/.deepseek.env"),
        os.path.expanduser("~/HAKA-AI/.env"),
    ]
    for path in paths:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            try:
                with open(expanded) as f:
                    for line in f:
                        line = line.strip()
                        # Handle both FOO=bar and export FOO=bar
                        if line.startswith("export "):
                            line = line[7:]
                        if line.startswith(f"{env_var}="):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val and val != "your-key-here":
                                return val
            except Exception:
                pass
    return None


# ── Model shortcuts ──────────────────────────────────────────────────────────

MODEL_SHORTCUTS: Dict[str, str] = {
    # --- Cloud: Anthropic ---
    "claude":           "anthropic:claude-sonnet-4-20250514",
    "claude-sonnet":    "anthropic:claude-sonnet-4-20250514",
    "claude-sonnet-4":  "anthropic:claude-sonnet-4-20250514",
    "claude-opus":      "anthropic:claude-opus-4-20250514",
    "claude-haiku":     "anthropic:claude-haiku-4-5-20250514",
    # --- Cloud: DeepSeek ---
    "deepseek":         "deepseek:deepseek-chat",
    "deepseek-v4":      "deepseek:deepseek-chat",
    "deepseek-r1":      "deepseek:deepseek-reasoner",
    # --- Cloud: OpenAI ---
    "gpt5":             "openai:gpt-5",
    "gpt-5":            "openai:gpt-5",
    "gpt4":             "openai:gpt-4o",
    "gpt4-mini":        "openai:gpt-4o-mini",
    # --- Local: Ollama ---
    "qwen":             "ollama:qwen3:32b",
    "qwen32":           "ollama:qwen3:32b",
    "qwen-coder":       "ollama:qwen2.5-coder:7b",
    "gemma":            "ollama:gemma3:12b",
    "gemma12":          "ollama:gemma3:12b",
    "gemma27":          "ollama:gemma3:27b",
    "gemma4b":          "ollama:gemma3:4b",
    "r1":               "ollama:deepseek-r1:7b",
    "coder":            "ollama:qwen2.5-coder:7b",
    "llama":            "ollama:llama3.2:latest",
    # --- OpenClaw Gateway (openai-compatible local endpoint) ---
    "openclaw":         "openclaw:openclaw/default",
    "oc":               "openclaw:openclaw/default",
}


# ── Base Provider ────────────────────────────────────────────────────────────

class _LLMProvider:
    """Base class for LLM providers."""
    name = "base"

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        raise NotImplementedError


# ── Ollama Provider ──────────────────────────────────────────────────────────

class OllamaProvider(_LLMProvider):
    """Local inference via ollama REST API."""
    name = "ollama"
    API_URL = "http://localhost:11434/api/generate"

    def __init__(self):
        self.available_models = self._list_models()

    def _list_models(self) -> List[str]:
        try:
            result = subprocess.run(
                ["ollama", "list"], capture_output=True, text=True, timeout=10
            )
            models = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if parts:
                    models.append(parts[0])
            return models
        except Exception:
            return []

    def is_available(self, model: str) -> bool:
        base = model.split(":")[0]
        return any(m.startswith(base) for m in self.available_models)

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        body = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }
        if system:
            body["system"] = system

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r.get("response", "").strip() or "[Empty ollama response]"
        except urllib.error.URLError as e:
            raise RuntimeError(f"ollama unreachable: {e}\nRun: ollama serve")


# ── Anthropic Provider ───────────────────────────────────────────────────────

class AnthropicProvider(_LLMProvider):
    """Direct Anthropic API (Claude models)."""
    name = "anthropic"
    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or _load_key("ANTHROPIC_API_KEY")
        self._available = self.api_key is not None

    @property
    def available(self) -> bool:
        return self._available

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        if not self.api_key:
            raise RuntimeError("No ANTHROPIC_API_KEY found. Set in env or .env file.")

        body = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            # Anthropic system is a top-level param for Claude 4
            body["system"] = [{"type": "text", "text": system}]

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r["content"][0]["text"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Anthropic HTTP {e.code}: {body}")


# ── DeepSeek Provider ────────────────────────────────────────────────────────

class DeepSeekProvider(_LLMProvider):
    """Direct DeepSeek API (OpenAI-compatible)."""
    name = "deepseek"
    API_URL = "https://api.deepseek.com/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or _load_key("DEEPSEEK_API_KEY")
        self._available = self.api_key is not None

    @property
    def available(self) -> bool:
        return self._available

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        if not self.api_key:
            raise RuntimeError("No DEEPSEEK_API_KEY found. Set in env or .env file.")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = json.dumps({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"DeepSeek HTTP {e.code}: {body}")


# ── OpenAI Provider ──────────────────────────────────────────────────────────

class OpenAIProvider(_LLMProvider):
    """Direct OpenAI API (GPT models)."""
    name = "openai"
    API_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or _load_key("OPENAI_API_KEY")
        self._available = self.api_key is not None

    @property
    def available(self) -> bool:
        return self._available

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        if not self.api_key:
            raise RuntimeError("No OPENAI_API_KEY found. Set in env or .env file.")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = json.dumps({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"OpenAI HTTP {e.code}: {body}")


# ── OpenClaw Provider ─────────────────────────────────────────────────────

class OpenClawProvider(_LLMProvider):
    """OpenClaw Gateway OpenAI-compatible endpoint (local, same as this assistant)."""
    name = "openclaw"
    API_URL = "http://127.0.0.1:18789/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or _load_key("OPENCLAW_GATEWAY_TOKEN")
        # Auto-discover token from openclaw.json
        if not self.api_key:
            try:
                config_path = os.path.expanduser("~/.openclaw/openclaw.json")
                if os.path.exists(config_path):
                    with open(config_path) as f:
                        cfg = json.load(f)
                    self.api_key = cfg.get("gateway", {}).get("auth", {}).get("token")
            except Exception:
                pass
        self._available = self.api_key is not None

    @property
    def available(self) -> bool:
        return self._available

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        if not self.api_key:
            raise RuntimeError("No OpenClaw gateway token found.")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        # Map model to OpenClaw agent: openclaw:openclaw/default
        agent = "openclaw/default"
        if ":" in model:
            agent = model.split(":", 1)[1]

        data = json.dumps({
            "model": agent,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"OpenClaw HTTP {e.code}: {body}")


# ── OpenRouter Provider ──────────────────────────────────────────────────────

class OpenRouterProvider(_LLMProvider):
    """OpenRouter API (aggregator for 200+ models)."""
    name = "openrouter"
    API_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or _load_key("OPENROUTER_API_KEY")
        self._available = self.api_key is not None

    @property
    def available(self) -> bool:
        return self._available

    def generate(self, prompt: str, model: str, system: Optional[str] = None,
                 max_tokens: int = 2048, temperature: float = 0.3) -> str:
        if not self.api_key:
            raise RuntimeError("No OPENROUTER_API_KEY found.")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        data = json.dumps({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode("utf-8")

        req = urllib.request.Request(
            self.API_URL, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://haka.ai",
                "X-Title": "HAKA Security",
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                r = json.loads(resp.read().decode("utf-8"))
                return r["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"OpenRouter HTTP {e.code}: {body}")


# ── Unified LLM Interface ────────────────────────────────────────────────────


class HakaLLM:
    """Route requests to the appropriate provider based on model prefix.

    Model formats:
      ollama:qwen3:32b        → local ollama
      anthropic:claude-...    → Anthropic API
      deepseek:deepseek-chat  → DeepSeek API
      openai:gpt-5            → OpenAI API
      openrouter:deepseek/... → OpenRouter

    Shortcuts (auto-resolve):
      qwen, claude, deepseek, gpt5, gemma, r1, coder
    """

    def __init__(self):
        self._ollama = OllamaProvider()
        # Lazy-init cloud providers (only if keys exist)
        self._anthropic: Optional[AnthropicProvider] = None
        self._deepseek: Optional[DeepSeekProvider] = None
        self._openai: Optional[OpenAIProvider] = None
        self._openrouter: Optional[OpenRouterProvider] = None
        self._openclaw: Optional[OpenClawProvider] = None

    # Provider properties (lazy)
    @property
    def anthropic(self):
        if self._anthropic is None:
            self._anthropic = AnthropicProvider()
        return self._anthropic

    @property
    def deepseek_api(self):
        if self._deepseek is None:
            self._deepseek = DeepSeekProvider()
        return self._deepseek

    @property
    def openai(self):
        if self._openai is None:
            self._openai = OpenAIProvider()
        return self._openai

    @property
    def openrouter(self):
        if self._openrouter is None:
            self._openrouter = OpenRouterProvider()
        return self._openrouter

    @property
    def openclaw_gw(self):
        if self._openclaw is None:
            self._openclaw = None  # initialized in __init__ if needed
        if self._openclaw is None:
            self._openclaw = OpenClawProvider()
        return self._openclaw

    def resolve_model(self, model: str) -> tuple:
        """Resolve model name to (provider_name, actual_model_name)."""
        # Check shortcuts
        if model.lower() in MODEL_SHORTCUTS:
            model = MODEL_SHORTCUTS[model.lower()]

        # Explicit provider prefix
        for prefix in ["ollama:", "anthropic:", "deepseek:", "openai:", "openrouter:", "openclaw:"]:
            if model.startswith(prefix):
                return (prefix[:-1], model[len(prefix):])

        # Auto-detect: check ollama first
        if self._ollama.is_available(model):
            return ("ollama", model)

        # If it has a /, treat as OpenRouter path
        if "/" in model:
            return ("openrouter", model)

        # Default to ollama (will error clearly if model not found)
        return ("ollama", model)

    def _get_provider(self, provider_name: str):
        providers = {
            "ollama": self._ollama,
            "anthropic": self.anthropic,
            "deepseek": self.deepseek_api,
            "openai": self.openai,
            "openrouter": self.openrouter,
            "openclaw": self.openclaw_gw,
        }
        return providers.get(provider_name)

    def generate(self, prompt: str, model: str = "qwen",
                 system: Optional[str] = None, max_tokens: int = 2048,
                 temperature: float = 0.3) -> str:
        """Generate text using the appropriate provider."""
        provider_name, actual_model = self.resolve_model(model)
        provider = self._get_provider(provider_name)
        if provider is None:
            raise RuntimeError(f"Unknown provider: {provider_name}")

        # Check availability for cloud providers
        if hasattr(provider, 'available') and not provider.available:
            alt_models = {
                "anthropic": "No ANTHROPIC_API_KEY. Use --model qwen for local.",
                "deepseek": "No DEEPSEEK_API_KEY. Use --model qwen for local.",
                "openai": "No OPENAI_API_KEY. Use --model qwen for local.",
                "openrouter": "No OPENROUTER_API_KEY. Use --model qwen for local.",
            }
            hint = alt_models.get(provider_name, "Use --model qwen for local inference.")
            raise RuntimeError(f"{provider_name} not available: {hint}")

        return provider.generate(
            prompt, actual_model, system, max_tokens, temperature
        )

    def status(self) -> dict:
        """Return provider availability status."""
        return {
            "ollama": {
                "available": True,
                "models": self._ollama.available_models,
            },
            "anthropic": {
                "available": self.anthropic.available,
            },
            "deepseek": {
                "available": self.deepseek_api.available,
            },
            "openai": {
                "available": self.openai.available,
            },
            "openrouter": {
                "available": self.openrouter.available,
            },
            "shortcuts": list(MODEL_SHORTCUTS.keys()),
        }


# ── Quick test / status ──────────────────────────────────────────────────────

if __name__ == "__main__":
    llm = HakaLLM()
    status = llm.status()
    print("=== HAKA Providers ===")
    for name, info in status.items():
        if name == "shortcuts":
            continue
        avail = "✅" if info["available"] else "❌"
        print(f"  {avail} {name}: {'available' if info['available'] else 'missing API key'}")
        if name == "ollama" and info.get("models"):
            print(f"       models: {', '.join(info['models'][:8])}")

    print(f"\n  Shortcuts: {', '.join(status['shortcuts'][:10])}...")
    print("\nResolve tests:")
    for name in ["claude", "qwen", "deepseek", "gpt5", "gemma", "r1"]:
        try:
            provider, actual = llm.resolve_model(name)
            avail = status.get(provider, {}).get("available", False)
            symbol = "✅" if avail else "⚠️ "
            print(f"  {symbol} {name:15s} → {provider:12s} {actual}")
        except Exception as e:
            print(f"  ❌ {name:15s} → ERROR: {e}")
