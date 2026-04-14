"""Unit tests for SAGE hooks in ReviewFileHandler."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

from falconeye.domain.models.security import (
    SecurityFinding,
    SecurityReview,
    Severity,
    FindingConfidence,
)
from falconeye.domain.models.prompt import PromptContext
from falconeye.application.commands.review_file import (
    ReviewFileCommand,
    ReviewFileHandler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_command(tmp_path: Path) -> ReviewFileCommand:
    """Create a ReviewFileCommand pointing at a temp file."""
    test_file = tmp_path / "vuln.py"
    test_file.write_text('import os\nos.system(input("cmd: "))\n', encoding="utf-8")
    return ReviewFileCommand(
        file_path=test_file,
        language="python",
        system_prompt="You are a security expert.",
        validate_findings=False,
        top_k_context=3,
    )


def _make_context(file_path: str = "vuln.py") -> PromptContext:
    """Create a minimal PromptContext."""
    return PromptContext(
        file_path=file_path,
        code_snippet='import os\nos.system(input("cmd: "))\n',
        language="python",
        related_docs=None,
    )


def _make_finding() -> SecurityFinding:
    """Create a test SecurityFinding."""
    return SecurityFinding.create(
        issue="Command injection",
        reasoning="User input passed to os.system",
        mitigation="Use subprocess with shell=False",
        severity=Severity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        file_path="vuln.py",
        code_snippet='os.system(input("cmd: "))',
        cwe_id="CWE-78",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestReviewWithoutSAGE:
    """Verify default behavior is unchanged when memory_service=None."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_review_without_sage(self, mock_logger_cls, tmp_path):
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=None,  # No SAGE
        )

        command = _make_command(tmp_path)
        review = await handler.handle(command)

        assert len(review.findings) == 1
        assert review.findings[0].issue == "Command injection"
        assert review.files_analyzed == 1
        assert review.completed_at is not None

        # Assembler and analyzer should be called normally
        mock_assembler.assemble_context.assert_awaited_once()
        mock_analyzer.analyze_code.assert_awaited_once()


@pytest.mark.unit
class TestPreAnalysisRecall:
    """Test SAGE recall before analysis."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_pre_analysis_recall(self, mock_logger_cls, tmp_path):
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        # Mock memory service returning historical findings
        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = [
            {"content": '{"issue": "Previous injection"}', "confidence": 0.88, "domain": "falconeye-findings"},
            {"content": '{"issue": "Old XSS"}', "confidence": 0.75, "domain": "falconeye-findings"},
        ]
        mock_memory.store_review.return_value = None
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        review = await handler.handle(command)

        # recall_findings should have been called
        mock_memory.recall_findings.assert_awaited_once()
        recall_kwargs = mock_memory.recall_findings.call_args.kwargs
        assert recall_kwargs["language"] == "python"

        # The context passed to analyze_code should have historical findings injected
        analyze_call = mock_analyzer.analyze_code.call_args
        ctx_used = analyze_call.kwargs["context"]
        assert ctx_used.related_docs is not None
        assert "HISTORICAL FINDINGS" in ctx_used.related_docs
        assert "88%" in ctx_used.related_docs  # 0.88 formatted as percentage

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_pre_analysis_recall_appends_to_existing_docs(self, mock_logger_cls, tmp_path):
        """If context already has related_docs, history should be appended."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        context.related_docs = "[Documentation 1] Security policy..."

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = []

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = [
            {"content": "old finding", "confidence": 0.7, "domain": "falconeye-findings"},
        ]
        mock_memory.store_review.return_value = None
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        await handler.handle(command)

        ctx_used = mock_analyzer.analyze_code.call_args.kwargs["context"]
        assert "Security policy..." in ctx_used.related_docs
        assert "HISTORICAL FINDINGS" in ctx_used.related_docs

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_pre_analysis_recall_empty_results(self, mock_logger_cls, tmp_path):
        """Empty recall results should not modify related_docs."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = []

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.store_review.return_value = None
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        await handler.handle(command)

        ctx_used = mock_analyzer.analyze_code.call_args.kwargs["context"]
        assert ctx_used.related_docs is None


@pytest.mark.unit
class TestPreAnalysisRecallFailure:
    """Test graceful degradation when SAGE recall fails."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_pre_analysis_recall_failure(self, mock_logger_cls, tmp_path):
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.side_effect = ConnectionError("SAGE unreachable")
        mock_memory.store_review.return_value = None
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        # Should not raise - analysis continues normally
        review = await handler.handle(command)

        assert len(review.findings) == 1
        mock_analyzer.analyze_code.assert_awaited_once()


@pytest.mark.unit
class TestPostAnalysisStore:
    """Test SAGE storage after analysis."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_post_analysis_store(self, mock_logger_cls, tmp_path):
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.store_review.return_value = None
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        review = await handler.handle(command)

        # store_review should have been called with the completed review
        mock_memory.store_review.assert_awaited_once()
        store_call = mock_memory.store_review.call_args
        stored_review = store_call.kwargs["review"]
        assert len(stored_review.findings) == 1
        assert stored_review.completed_at is not None

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_post_analysis_store_failure(self, mock_logger_cls, tmp_path):
        """If store_review raises, the review should still be returned."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.store_review.side_effect = RuntimeError("SAGE write failed")
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        # Should not raise
        review = await handler.handle(command)

        # Review should still be valid and returned
        assert len(review.findings) == 1
        assert review.completed_at is not None
        assert review.files_analyzed == 1
