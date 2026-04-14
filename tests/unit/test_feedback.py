"""Unit tests for severity calibration feedback via SAGE."""

import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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


def _patch_sage_sdk():
    """Create mock sage_sdk modules and return them for further setup."""
    mock_async_client_cls = MagicMock()
    mock_identity_cls = MagicMock()
    mock_memory_type = SimpleNamespace(observation="observation", fact="fact")

    patches = {
        "sage_sdk": MagicMock(),
        "sage_sdk.async_client": MagicMock(AsyncSageClient=mock_async_client_cls),
        "sage_sdk.auth": MagicMock(AgentIdentity=mock_identity_cls),
        "sage_sdk.models": MagicMock(MemoryType=mock_memory_type),
    }
    return patches, mock_async_client_cls, mock_identity_cls, mock_memory_type


def _build_adapter(patches, mock_async_client_cls, mock_identity_cls):
    """Import SAGEMemoryAdapter under mocked sage_sdk and return an instance."""
    import sys
    import importlib

    originals = {}
    for mod_name, mod_mock in patches.items():
        originals[mod_name] = sys.modules.get(mod_name)
        sys.modules[mod_name] = mod_mock

    mod_path = "falconeye.infrastructure.memory.sage_adapter"
    if mod_path in sys.modules:
        importlib.reload(sys.modules[mod_path])
    else:
        importlib.import_module(mod_path)

    from falconeye.infrastructure.memory.sage_adapter import SAGEMemoryAdapter

    mock_identity_cls.default.return_value = MagicMock(name="default_identity")

    mock_client = AsyncMock()
    mock_async_client_cls.return_value = mock_client

    with patch("falconeye.infrastructure.memory.sage_adapter.FalconEyeLogger") as mock_logger_cls:
        mock_logger_cls.get_instance.return_value = MagicMock()
        adapter = SAGEMemoryAdapter(base_url="http://test:8080")

    adapter._client = mock_client
    adapter.logger = MagicMock()

    for mod_name, orig in originals.items():
        if orig is None:
            sys.modules.pop(mod_name, None)
        else:
            sys.modules[mod_name] = orig

    return adapter, mock_client


@pytest.fixture
def sage_env():
    """Provide a SAGEMemoryAdapter with a mocked AsyncSageClient."""
    patches, mock_cls, mock_id, mock_mt = _patch_sage_sdk()
    adapter, mock_client = _build_adapter(patches, mock_cls, mock_id)
    return adapter, mock_client, mock_mt


# ---------------------------------------------------------------------------
# feedback_command tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFeedbackCommandValid:
    """Test feedback_command marks findings as true positive."""

    def test_feedback_command_valid(self, sage_env):
        """Mock memory_service.record_feedback, verify called with is_valid=True."""
        from unittest.mock import patch as mock_patch
        from rich.console import Console

        mock_memory = AsyncMock()
        mock_memory.record_feedback.return_value = None

        mock_container = MagicMock()
        mock_container.memory_service = mock_memory

        console = Console(quiet=True)

        with mock_patch("falconeye.adapters.cli.commands.DIContainer") as mock_di:
            mock_di.create.return_value = mock_container
            from falconeye.adapters.cli.commands import feedback_command

            feedback_command(
                finding_id="abc-123",
                valid=True,
                severity=None,
                reason="Confirmed manually",
                config_path=None,
                sage_url=None,
                console=console,
            )

        mock_memory.record_feedback.assert_awaited_once()
        call_kwargs = mock_memory.record_feedback.call_args.kwargs
        assert call_kwargs["finding_id"] == "abc-123"
        assert call_kwargs["is_valid"] is True
        assert "Confirmed manually" in call_kwargs["reason"]


@pytest.mark.unit
class TestFeedbackCommandInvalid:
    """Test feedback_command marks findings as false positive."""

    def test_feedback_command_invalid(self, sage_env):
        """Verify called with is_valid=False."""
        from unittest.mock import patch as mock_patch
        from rich.console import Console

        mock_memory = AsyncMock()
        mock_memory.record_feedback.return_value = None

        mock_container = MagicMock()
        mock_container.memory_service = mock_memory

        console = Console(quiet=True)

        with mock_patch("falconeye.adapters.cli.commands.DIContainer") as mock_di:
            mock_di.create.return_value = mock_container
            from falconeye.adapters.cli.commands import feedback_command

            feedback_command(
                finding_id="def-456",
                valid=False,
                severity=None,
                reason="Not exploitable in this context",
                config_path=None,
                sage_url=None,
                console=console,
            )

        mock_memory.record_feedback.assert_awaited_once()
        call_kwargs = mock_memory.record_feedback.call_args.kwargs
        assert call_kwargs["finding_id"] == "def-456"
        assert call_kwargs["is_valid"] is False
        assert "Not exploitable" in call_kwargs["reason"]


@pytest.mark.unit
class TestFeedbackWithSeverityCorrection:
    """Test feedback with severity correction."""

    def test_feedback_with_severity_correction(self, sage_env):
        """Verify reason includes severity correction."""
        from unittest.mock import patch as mock_patch
        from rich.console import Console

        mock_memory = AsyncMock()
        mock_memory.record_feedback.return_value = None

        mock_container = MagicMock()
        mock_container.memory_service = mock_memory

        console = Console(quiet=True)

        with mock_patch("falconeye.adapters.cli.commands.DIContainer") as mock_di:
            mock_di.create.return_value = mock_container
            from falconeye.adapters.cli.commands import feedback_command

            feedback_command(
                finding_id="ghi-789",
                valid=True,
                severity="low",
                reason="Impact is minimal",
                config_path=None,
                sage_url=None,
                console=console,
            )

        call_kwargs = mock_memory.record_feedback.call_args.kwargs
        assert "Severity correction: -> low." in call_kwargs["reason"]
        assert "Impact is minimal" in call_kwargs["reason"]


# ---------------------------------------------------------------------------
# recall_feedback adapter tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRecallFeedback:

    async def test_recall_feedback_returns_results(self, sage_env):
        """Mock query, verify formatted output."""
        adapter, mock_client, _ = sage_env

        mock_client.embed.return_value = [0.1, 0.2, 0.3]
        mock_record = SimpleNamespace(
            content="Finding abc-123: FALSE POSITIVE. Not exploitable.",
            confidence_score=0.95,
        )
        mock_client.query.return_value = SimpleNamespace(results=[mock_record])

        results = await adapter.recall_feedback(
            file_path="src/app.py",
            top_k=3,
        )

        assert len(results) == 1
        assert results[0]["content"] == "Finding abc-123: FALSE POSITIVE. Not exploitable."
        assert results[0]["confidence"] == 0.95

        # Verify embed called with meaningful query
        embed_arg = mock_client.embed.call_args[0][0]
        assert "feedback" in embed_arg
        assert "src/app.py" in embed_arg

        # Verify query called with correct domain
        mock_client.query.assert_awaited_once()
        query_kwargs = mock_client.query.call_args.kwargs
        assert query_kwargs["domain_tag"] == "falconeye-feedback"
        assert query_kwargs["top_k"] == 3

    async def test_recall_feedback_empty(self, sage_env):
        """Mock query returning empty, verify empty list."""
        adapter, mock_client, _ = sage_env

        mock_client.embed.return_value = [0.0, 0.0]
        mock_client.query.return_value = SimpleNamespace(results=[])

        results = await adapter.recall_feedback(
            file_path="src/app.py",
        )
        assert results == []

    async def test_recall_feedback_error(self, sage_env):
        """Mock raising exception, verify empty list returned."""
        adapter, mock_client, _ = sage_env

        mock_client.embed.side_effect = ConnectionError("SAGE unavailable")

        results = await adapter.recall_feedback(
            file_path="src/app.py",
        )
        assert results == []
        adapter.logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# Feedback injected into context during review
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestFeedbackInjectedIntoContext:
    """Test that feedback is recalled and injected into analysis context."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_feedback_injected_into_context(self, mock_logger_cls, tmp_path):
        """Mock review handler, verify context.related_docs updated with feedback."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        # Mock memory service with recall_feedback returning results
        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = [
            {"content": "Finding xyz-1: FALSE POSITIVE. Not exploitable in test env.", "confidence": 0.95},
            {"content": "Finding xyz-2: TRUE POSITIVE. Severity correction: -> low.", "confidence": 0.90},
        ]
        mock_memory.store_review.return_value = None
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        review = await handler.handle(command)

        # recall_feedback should have been called
        mock_memory.recall_feedback.assert_awaited_once()

        # The context passed to analyze_code should have feedback injected
        analyze_call = mock_analyzer.analyze_code.call_args
        ctx_used = analyze_call.kwargs["context"]
        assert ctx_used.related_docs is not None
        assert "BEGIN USER FEEDBACK" in ctx_used.related_docs
        assert "END USER FEEDBACK" in ctx_used.related_docs
        assert "FALSE POSITIVE" in ctx_used.related_docs

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_feedback_recall_empty_no_modification(self, mock_logger_cls, tmp_path):
        """Empty feedback results should not add a feedback section."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = []

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_review.return_value = None
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

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_feedback_recall_failure_graceful(self, mock_logger_cls, tmp_path):
        """If recall_feedback raises, analysis should continue normally."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.side_effect = ConnectionError("SAGE unreachable")
        mock_memory.store_review.return_value = None
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

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_feedback_appends_to_existing_docs(self, mock_logger_cls, tmp_path):
        """If context already has related_docs, feedback should be appended."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        context.related_docs = "[Documentation] Security policy..."

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = []

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.return_value = []
        mock_memory.recall_feedback.return_value = [
            {"content": "Finding xyz: FALSE POSITIVE.", "confidence": 0.90},
        ]
        mock_memory.store_review.return_value = None
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
        assert "BEGIN USER FEEDBACK" in ctx_used.related_docs
        assert "END USER FEEDBACK" in ctx_used.related_docs
