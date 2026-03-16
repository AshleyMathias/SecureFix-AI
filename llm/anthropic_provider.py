from __future__ import annotations

from typing import List, Optional

import anthropic

from utils.config import get_settings
from utils.logger import get_logger
from .llm_interface import BaseLLMProvider, LLMMessage, LLMResponse

logger = get_logger("securefix.llm.anthropic")


class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic Claude provider.

    Activated by setting LLM_PROVIDER=anthropic in the environment.
    Defaults to claude-3-5-sonnet-20241022. Override via ANTHROPIC_MODEL.
    Supports claude-3-5-sonnet, claude-3-opus, claude-3-haiku.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        if not self._settings.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is required when using the Anthropic provider. "
                "Set it in .env or as an environment variable."
            )
        self._client = anthropic.AsyncAnthropic(api_key=self._settings.anthropic_api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self._settings.anthropic_model

    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        messages = [{"role": "user", "content": prompt}]
        return await self._call(
            messages=messages,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def generate_response_with_history(
        self,
        messages: List[LLMMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        system_prompt: Optional[str] = None
        raw_messages: list[dict] = []

        for msg in messages:
            if msg.role == "system":
                system_prompt = msg.content
            else:
                raw_messages.append({"role": msg.role, "content": msg.content})

        return await self._call(
            messages=raw_messages,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def _call(
        self,
        messages: list[dict],
        system_prompt: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int],
    ) -> LLMResponse:
        effective_temp = temperature if temperature is not None else self._settings.anthropic_temperature
        effective_max = max_tokens if max_tokens is not None else self._settings.anthropic_max_tokens

        logger.debug(
            "anthropic_request",
            model=self.model_name,
            messages_count=len(messages),
            temperature=effective_temp,
        )

        kwargs: dict = dict(
            model=self.model_name,
            messages=messages,
            temperature=effective_temp,
            max_tokens=effective_max,
        )
        if system_prompt:
            kwargs["system"] = system_prompt

        try:
            response = await self._client.messages.create(**kwargs)
        except anthropic.RateLimitError as exc:
            logger.error("anthropic_rate_limit", error=str(exc))
            raise
        except anthropic.APIConnectionError as exc:
            logger.error("anthropic_connection_error", error=str(exc))
            raise
        except anthropic.APIStatusError as exc:
            logger.error("anthropic_api_error", status=exc.status_code, error=str(exc))
            raise

        content = response.content[0].text if response.content else ""

        logger.debug(
            "anthropic_response",
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason,
        )

        return LLMResponse(
            content=content,
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            finish_reason=response.stop_reason,
            metadata={"message_id": response.id},
        )
