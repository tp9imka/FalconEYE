"""Unit tests for Ollama embedding retry behavior."""

from unittest.mock import MagicMock

import ollama
import pytest

from falconeye.infrastructure.llm_providers.ollama_adapter import OllamaLLMAdapter


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_embedding_retries_with_smaller_prompt_on_context_error():
    adapter = OllamaLLMAdapter()
    adapter.logger = MagicMock()

    attempted_lengths: list[int] = []

    def fake_embeddings(*, model: str, prompt: str):
        attempted_lengths.append(len(prompt))
        if len(prompt) > 2000:
            raise ollama.ResponseError("the input length exceeds the context length", 500)
        return {"embedding": [0.1, 0.2, 0.3]}

    adapter.client = MagicMock()
    adapter.client.embeddings.side_effect = fake_embeddings

    embedding = await adapter.generate_embedding("x" * 7000)

    assert embedding == [0.1, 0.2, 0.3]
    assert attempted_lengths == [7000, 3500, 1750]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_embedding_reraises_non_context_errors():
    adapter = OllamaLLMAdapter()
    adapter.logger = MagicMock()
    adapter.client = MagicMock()
    adapter.client.embeddings.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await adapter.generate_embedding("hello")
