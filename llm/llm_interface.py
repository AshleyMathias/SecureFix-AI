from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class BaseLLMProvider(ABC):
    """
    Provider-agnostic interface for all LLM interactions in SecureFix AI.

    Concrete implementations must override generate_response and
    generate_response_with_history. All other helpers are built on top
    of those two primitives so switching providers requires zero changes
    to callers.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Active model identifier."""

    @abstractmethod
    async def generate_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send a single-turn prompt and return the LLM response.

        Args:
            prompt:        User turn message.
            system_prompt: Optional system / context message prepended.
            temperature:   Override default temperature.
            max_tokens:    Override default max output tokens.
        """

    @abstractmethod
    async def generate_response_with_history(
        self,
        messages: List[LLMMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """
        Send a multi-turn conversation and return the next assistant turn.

        Args:
            messages:    Full conversation history (system + user + assistant).
            temperature: Override default temperature.
            max_tokens:  Override default max output tokens.
        """

    async def analyze_vulnerability(self, prompt: str) -> str:
        """Thin wrapper: call generate_response and return plain text."""
        resp = await self.generate_response(prompt)
        return resp.content

    async def reason_about_patch(self, prompt: str) -> str:
        resp = await self.generate_response(prompt)
        return resp.content

    async def generate_pr_description(self, prompt: str) -> str:
        resp = await self.generate_response(prompt)
        return resp.content

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.model_name!r})"
