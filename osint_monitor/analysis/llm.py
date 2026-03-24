"""Multi-provider LLM abstraction. Default: OpenAI. Optional: Anthropic, Ollama, Gemini."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Optional, Type

from pydantic import BaseModel

from osint_monitor.core.config import get_settings

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract LLM provider."""

    @abstractmethod
    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        """Generate text completion."""
        ...

    def generate_json(self, prompt: str, system: str = "", model_class: Type[BaseModel] | None = None) -> dict | BaseModel:
        """Generate and parse JSON response."""
        if system:
            system += "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no code fences."
        else:
            system = "Respond ONLY with valid JSON. No markdown, no code fences."

        raw = self.generate(prompt, system=system, temperature=0.1)

        # Strip markdown code fences if present
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        data = json.loads(text)
        if model_class:
            return model_class(**data)
        return data


class OpenAIProvider(LLMProvider):
    """OpenAI API provider (default)."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        settings = get_settings()
        import os
        from dotenv import load_dotenv
        load_dotenv()
        self.api_key = api_key or settings.openai_api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model or settings.openai_model

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. Set OPENAI_API_KEY env var or OSINT_OPENAI_API_KEY."
            )

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        from openai import OpenAI
        client = OpenAI(api_key=self.api_key)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
        )
        return response.choices[0].message.content or ""


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514"):
        settings = get_settings()
        self.api_key = api_key or settings.anthropic_api_key
        if not self.api_key:
            import os
            self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.model = model

        if not self.api_key:
            raise ValueError("Anthropic API key not found. Set ANTHROPIC_API_KEY env var.")

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)

        response = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system or "You are a geopolitical intelligence analyst.",
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
        )
        return response.content[0].text


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, base_url: str | None = None, model: str = "llama3.1"):
        settings = get_settings()
        self.base_url = base_url or settings.ollama_base_url
        self.model = model

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        import requests

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system or "You are a geopolitical intelligence analyst.",
            "stream": False,
            "options": {"temperature": temperature},
        }

        resp = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


class GeminiProvider(LLMProvider):
    """Google Gemini provider."""

    def __init__(self, model: str = "gemini-2.0-flash"):
        import os
        self.api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        self.model = model

        if not self.api_key:
            raise ValueError("Google API key not found. Set GOOGLE_API_KEY env var.")

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        from google import genai
        client = genai.Client(api_key=self.api_key)

        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        response = client.models.generate_content(
            model=self.model,
            contents=full_prompt,
        )
        return response.text or ""


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    "gemini": GeminiProvider,
}


def get_llm(provider: str | None = None, **kwargs) -> LLMProvider:
    """Get an LLM provider instance.

    Args:
        provider: "openai", "anthropic", "ollama", "gemini". Defaults to settings.
        **kwargs: Passed to provider constructor.
    """
    settings = get_settings()
    provider = provider or settings.default_llm_provider

    cls = _PROVIDERS.get(provider)
    if cls is None:
        raise ValueError(f"Unknown LLM provider: {provider}. Options: {list(_PROVIDERS.keys())}")

    return cls(**kwargs)
