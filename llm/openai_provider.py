from __future__ import annotations

from typing import List, Optional

import openai
from openai import AsyncOpenAI

from utils.config import get_settings
from utils.logger import get_logger
from .llm_interface import BaseLLMProvider, LLMMessage, LLMResponse

logger = get_logger("securefix.llm.openai")


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI ChatCompletion provider.

    Defaults to gpt-4o. Override via OPENAI_MODEL env var.
    Supports gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-4.1.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        if not self._settings.openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY is required when using the OpenAI provider. "
                "Set it in .env or as an environment variable."
            )
        self._client = AsyncOpenAI(api_key=self._settings.openai_api_key)

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._settings.openai_model

    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        messages: list[dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        return await self._call(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def generate_response_with_history(
        self,
        messages: List[LLMMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        raw_messages = [{"role": m.role, "content": m.content} for m in messages]
        return await self._call(
            messages=raw_messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def _call(
        self,
        messages: list[dict],
        temperature: Optional[float],
        max_tokens: Optional[int],
    ) -> LLMResponse:
        effective_temp = temperature if temperature is not None else self._settings.openai_temperature
        effective_max = max_tokens if max_tokens is not None else self._settings.openai_max_tokens

        logger.debug(
            "openai_request",
            model=self.model_name,
            messages_count=len(messages),
            temperature=effective_temp,
        )

        try:
            response = await self._client.chat.completions.create(
                model=self.model_name,
                messages=messages,  # type: ignore[arg-type]
                temperature=effective_temp,
                max_tokens=effective_max,
            )
        except openai.RateLimitError as exc:
            logger.error("openai_rate_limit", error=str(exc))
            raise
        except openai.APIConnectionError as exc:
            logger.error("openai_connection_error", error=str(exc))
            raise
        except openai.APIStatusError as exc:
            logger.error("openai_api_error", status=exc.status_code, error=str(exc))
            raise

        choice = response.choices[0]
        content = choice.message.content or ""

        logger.debug(
            "openai_response",
            model=response.model,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            finish_reason=choice.finish_reason,
        )

        return LLMResponse(
            content=content,
            model=response.model,
            provider=self.provider_name,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            finish_reason=choice.finish_reason,
            metadata={"response_id": response.id},
        )
