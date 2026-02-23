"""
AI client abstraction layer supporting multiple LLM providers.
"""

import logging
import json
from typing import Optional, Dict, Any
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...models.llm_config import LLMConfig, LLMProvider
from ...db.database import async_session_maker

logger = logging.getLogger(__name__)


class AIClient:
    """Unified AI client that routes requests to configured LLM provider."""

    def __init__(self):
        self._config: Optional[LLMConfig] = None

    async def _get_active_config(self) -> Optional[LLMConfig]:
        """Get the active LLM configuration."""
        if self._config:
            return self._config

        async with async_session_maker() as session:
            result = await session.execute(
                select(LLMConfig).where(LLMConfig.is_active == True).limit(1)
            )
            self._config = result.scalar_one_or_none()
            return self._config

    async def is_configured(self) -> bool:
        """Check if AI is configured."""
        config = await self._get_active_config()
        return config is not None

    async def complete(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Send a completion request to the configured LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            Generated text response
        """
        config = await self._get_active_config()
        if not config:
            raise ValueError("No active LLM configuration found. Please configure AI in Admin settings.")

        try:
            if config.provider == LLMProvider.CLAUDE:
                return await self._claude_complete(config, prompt, system_prompt)
            elif config.provider == LLMProvider.OPENAI:
                return await self._openai_complete(config, prompt, system_prompt)
            elif config.provider == LLMProvider.OLLAMA:
                return await self._ollama_complete(config, prompt, system_prompt)
            elif config.provider == LLMProvider.GEMINI:
                return await self._gemini_complete(config, prompt, system_prompt)
            elif config.provider == LLMProvider.AZURE_OPENAI:
                return await self._azure_openai_complete(config, prompt, system_prompt)
            else:
                raise ValueError(f"Unsupported provider: {config.provider}")
        except Exception as e:
            logger.error(f"AI completion failed: {e}", exc_info=True)
            raise

    async def _claude_complete(
        self, config: LLMConfig, prompt: str, system_prompt: Optional[str]
    ) -> str:
        """Call Anthropic Claude API."""
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        payload = {
            "model": config.model_name,
            "max_tokens": config.max_tokens,
            "temperature": config.temperature / 100.0,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    async def _openai_complete(
        self, config: LLMConfig, prompt: str, system_prompt: Optional[str]
    ) -> str:
        """Call OpenAI API."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": config.model_name,
            "messages": messages,
            "max_tokens": config.max_tokens,
            "temperature": config.temperature / 100.0,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def _ollama_complete(
        self, config: LLMConfig, prompt: str, system_prompt: Optional[str]
    ) -> str:
        """Call Ollama local API."""
        url = f"{config.api_base_url or 'http://localhost:11434'}/api/generate"

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        payload = {
            "model": config.model_name,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": config.temperature / 100.0,
                "num_predict": config.max_tokens,
            }
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["response"]

    async def _gemini_complete(
        self, config: LLMConfig, prompt: str, system_prompt: Optional[str]
    ) -> str:
        """Call Google Gemini API."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.model_name}:generateContent?key={config.api_key}"

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature": config.temperature / 100.0,
                "maxOutputTokens": config.max_tokens,
            }
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]

    async def _azure_openai_complete(
        self, config: LLMConfig, prompt: str, system_prompt: Optional[str]
    ) -> str:
        """Call Azure OpenAI API."""
        # Azure OpenAI URL format: https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version=2024-02-01
        if not config.api_base_url:
            raise ValueError("Azure OpenAI requires api_base_url to be set")

        headers = {
            "api-key": config.api_key,
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "messages": messages,
            "max_tokens": config.max_tokens,
            "temperature": config.temperature / 100.0,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(config.api_base_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]


# Global singleton
ai_client = AIClient()
