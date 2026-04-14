"""Unit tests for large-file handling: adaptive chunking + prompt truncation.

These tests exercise the size-adaptive behavior added for multi-thousand-line
files so regressions are caught without needing a real LLM or vector store.
"""

from __future__ import annotations

import pytest

from falconeye.domain.models.prompt import PromptContext


# ---------------------------------------------------------------------------
# PromptContext._add_line_numbers / format_for_ai
# ---------------------------------------------------------------------------


def _make_context(code: str) -> PromptContext:
    return PromptContext(file_path="big.py", code_snippet=code, language="python")


def test_small_file_is_not_truncated():
    ctx = _make_context("a\nb\nc\n")
    out = ctx.format_for_ai()
    assert "Truncated" not in out
    assert "   1 | a" in out
    assert "   3 | c" in out


def test_exact_max_lines_is_not_truncated():
    max_lines = 100
    code = "\n".join(f"line_{i}" for i in range(max_lines))
    numbered = _make_context(code)._add_line_numbers(code, max_lines=max_lines)
    assert "Truncated" not in numbered
    # All lines present
    assert numbered.count("\n") == max_lines - 1


def test_large_file_keeps_head_and_tail():
    max_lines = 100
    total = 500
    code = "\n".join(f"line_{i}" for i in range(total))
    numbered = _make_context(code)._add_line_numbers(code, max_lines=max_lines)

    # Head: first line present with line number 1
    assert "   1 | line_0" in numbered
    # Tail: the very last line of the source is present with its original number
    assert f" {total:4d} | line_{total - 1}".strip() in numbered.replace("  ", " ")
    # Truncation marker
    assert "Truncated 400 lines" in numbered
    # Middle content is gone
    assert "line_250" not in numbered


def test_truncation_preserves_original_line_numbers_for_tail():
    """Line numbers in the tail must reflect positions in the original file,
    otherwise LLM findings would reference wrong line numbers."""
    max_lines = 10
    total = 1000
    code = "\n".join(f"L{i}" for i in range(total))
    numbered = _make_context(code)._add_line_numbers(code, max_lines=max_lines)

    lines = numbered.splitlines()
    # Last rendered source line should carry the original line number = total
    last_numbered = [ln for ln in lines if "|" in ln][-1]
    assert last_numbered.lstrip().startswith(f"{total} |")


def test_enrichment_analysis_type_bypasses_formatting():
    ctx = PromptContext(
        file_path="ignored",
        code_snippet="RAW_PAYLOAD",
        language="python",
        analysis_type="enrichment",
    )
    assert ctx.format_for_ai() == "RAW_PAYLOAD"


# ---------------------------------------------------------------------------
# Adaptive chunking in IndexCodebaseHandler._chunk_content
# ---------------------------------------------------------------------------


class _StubLLMService:
    """Minimal stand-in for LLMService used only by _chunk_content."""

    def count_tokens(self, text: str) -> int:  # pragma: no cover - trivial
        return len(text)


@pytest.fixture
def chunk_content():
    """Return a bound reference to the _chunk_content method on a minimal
    handler instance without invoking the full __init__."""
    from falconeye.application.commands.index_codebase import IndexCodebaseHandler
    import logging

    handler = IndexCodebaseHandler.__new__(IndexCodebaseHandler)
    handler.llm_service = _StubLLMService()
    handler.logger = logging.getLogger("test.index_codebase")
    return handler._chunk_content


def _make_source(n_lines: int) -> str:
    return "\n".join(f"line {i}" for i in range(n_lines)) + "\n"


def test_small_file_uses_default_chunking(chunk_content):
    content = _make_source(200)
    chunks = chunk_content(content, "small.py", "python", chunk_size=50, overlap=10)
    # Step = 40, 200 lines -> ceil(200/40) = 5 chunks
    assert len(chunks) == 5
    assert chunks[0].metadata.start_line == 1
    # No chunk should span more than the configured size
    for c in chunks:
        assert c.metadata.end_line - c.metadata.start_line + 1 <= 50


def test_adaptive_chunking_triggers_above_threshold(chunk_content):
    content = _make_source(5000)
    chunks = chunk_content(content, "big.py", "python", chunk_size=50, overlap=10)
    # At 5000 lines: chunk_size becomes 100, overlap becomes 20, step=80
    # -> ceil(5000/80) = 63 chunks. Importantly, far fewer than default (~125).
    assert len(chunks) < 100
    # Chunks should now be larger than the default 50-line size
    sizes = [c.metadata.end_line - c.metadata.start_line + 1 for c in chunks]
    assert max(sizes) > 50


def test_adaptive_chunking_caps_chunk_size(chunk_content):
    content = _make_source(50_000)
    chunks = chunk_content(content, "huge.py", "python", chunk_size=50, overlap=10)
    # Chunk size is capped at MAX_ADAPTIVE_CHUNK_SIZE (200)
    sizes = [c.metadata.end_line - c.metadata.start_line + 1 for c in chunks]
    assert max(sizes) <= 200


def test_adaptive_overlap_scales_up_not_down(chunk_content):
    """Regression: the prior formula min(overlap, acs//5) could only shrink
    overlap. Verify overlap grows with chunk size for large files."""
    content = _make_source(5000)
    chunks = chunk_content(content, "big.py", "python", chunk_size=50, overlap=10)
    # With chunk_size=100 and overlap=20, consecutive chunks overlap by 20 lines.
    # Check that adjacent chunks actually overlap.
    for a, b in zip(chunks, chunks[1:]):
        assert b.metadata.start_line <= a.metadata.end_line


def test_adaptive_chunking_preserves_total_chunks_metadata(chunk_content):
    content = _make_source(3000)
    chunks = chunk_content(content, "big.py", "python", chunk_size=50, overlap=10)
    assert all(c.metadata.total_chunks == len(chunks) for c in chunks)
