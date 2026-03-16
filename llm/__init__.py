from .llm_interface import BaseLLMProvider, LLMResponse
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .prompts import PromptLibrary

__all__ = [
    "BaseLLMProvider",
    "LLMResponse",
    "OpenAIProvider",
    "AnthropicProvider",
    "PromptLibrary",
]


def get_llm_provider(provider: str = "openai") -> BaseLLMProvider:
    """
    Factory function. Switch providers purely via the LLM_PROVIDER env var.
    No code changes required.
    """
    provider = provider.lower()
    if provider == "openai":
        return OpenAIProvider()
    elif provider == "anthropic":
        return AnthropicProvider()
    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. "
            "Supported providers: openai, anthropic"
        )
