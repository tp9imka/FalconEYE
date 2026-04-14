"""Unit tests for cross-project learning and dynamic prompt enrichment via SAGE."""

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
from falconeye.domain.services.memory_service import MemoryService
from falconeye.application.commands.review_file import (
    ReviewFileCommand,
    ReviewFileHandler,
)


# ---------------------------------------------------------------------------
# sage_sdk patching helpers (same pattern as test_sage_adapter.py)
# ---------------------------------------------------------------------------

def _patch_sage_sdk():
    """Create mock sage_sdk modules and return them for further setup."""
    mock_async_client_cls = MagicMock()
    mock_identity_cls = MagicMock()
    mock_memory_type = SimpleNamespace(
        observation="observation", fact="fact", inference="inference"
    )

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

    with patch(
        "falconeye.infrastructure.memory.sage_adapter.FalconEyeLogger"
    ) as mock_logger_cls:
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sage_env():
    """Provide a SAGEMemoryAdapter with a mocked AsyncSageClient."""
    patches, mock_cls, mock_id, mock_mt = _patch_sage_sdk()
    adapter, mock_client = _build_adapter(patches, mock_cls, mock_id)
    return adapter, mock_client, mock_mt


def _make_review_with_findings() -> SecurityReview:
    """Create a review with diverse findings for profile/reflection tests."""
    review = SecurityReview.create(codebase_path="/tmp/test-proj", language="python")
    review.add_finding(
        SecurityFinding.create(
            issue="SQL Injection in query handler",
            reasoning="User input concatenated into SQL.",
            mitigation="Use parameterized queries.",
            severity=Severity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            file_path="src/db.py",
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
            cwe_id="CWE-89",
        )
    )
    review.add_finding(
        SecurityFinding.create(
            issue="SQL Injection in search endpoint",
            reasoning="Search term unsanitized.",
            mitigation="Use parameterized queries.",
            severity=Severity.HIGH,
            confidence=FindingConfidence.HIGH,
            file_path="src/search.py",
            code_snippet='cursor.execute(f"SELECT * FROM items WHERE name LIKE {term}")',
            cwe_id="CWE-89",
        )
    )
    review.add_finding(
        SecurityFinding.create(
            issue="Hardcoded secret in config",
            reasoning="API key stored as literal.",
            mitigation="Use environment variables.",
            severity=Severity.MEDIUM,
            confidence=FindingConfidence.MEDIUM,
            file_path="src/config.py",
            code_snippet='API_KEY = "sk-abc123"',
            cwe_id="CWE-798",
        )
    )
    review.add_finding(
        SecurityFinding.create(
            issue="Debug mode enabled",
            reasoning="Debug flag is set to True in production config.",
            mitigation="Disable debug mode for production.",
            severity=Severity.LOW,
            confidence=FindingConfidence.LOW,
            file_path="src/settings.py",
            code_snippet='DEBUG = True',
        )
    )
    review.files_analyzed = 4
    review.complete()
    return review


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
# _store_project_profile tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStoreProjectProfile:

    async def test_store_project_profile(self, sage_env):
        """Verify _store_project_profile proposes to falconeye-projects domain."""
        adapter, mock_client, mock_mt = sage_env
        mock_client.embed.return_value = [0.1, 0.2]
        review = _make_review_with_findings()

        await adapter._store_project_profile(review, "my-project", "python")

        # embed called for the profile text, then propose called once
        mock_client.embed.assert_awaited_once()
        mock_client.propose.assert_awaited_once()
        call_kwargs = mock_client.propose.call_args.kwargs
        assert call_kwargs["domain_tag"] == "falconeye-projects"
        assert call_kwargs["memory_type"] == mock_mt.observation
        assert call_kwargs["confidence"] == 0.85
        # Embedding should be passed through
        assert call_kwargs["embedding"] == [0.1, 0.2]

    async def test_store_project_profile_includes_severity_counts(self, sage_env):
        """Profile content should contain severity distribution."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1]
        review = _make_review_with_findings()

        await adapter._store_project_profile(review, "my-project", "python")

        content = mock_client.propose.call_args.kwargs["content"]
        assert "my-project" in content
        assert "python" in content
        assert "4 findings" in content
        # 1 critical, 1 high, 1 medium, 1 low
        assert "critical=1" in content
        assert "high=1" in content
        assert "medium=1" in content
        assert "low=1" in content

    async def test_store_project_profile_includes_vuln_types(self, sage_env):
        """Profile content should list unique vulnerability types."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1]
        review = _make_review_with_findings()

        await adapter._store_project_profile(review, "proj", "python")

        content = mock_client.propose.call_args.kwargs["content"]
        # "SQL Injection" appears as a type (extracted from "SQL Injection in ...")
        assert "SQL Injection" in content
        # "Hardcoded secret" extracted from "Hardcoded secret in config"
        assert "Hardcoded secret" in content

    async def test_store_project_profile_empty_findings(self, sage_env):
        """No findings -> propose should not be called."""
        adapter, mock_client, _ = sage_env
        review = SecurityReview.create("/tmp/empty", "python")
        review.complete()

        await adapter._store_project_profile(review, "proj", "python")

        mock_client.propose.assert_not_awaited()

    async def test_store_project_profile_handles_error(self, sage_env):
        """If embed or propose fails, should log warning and not propagate."""
        adapter, mock_client, _ = sage_env
        review = _make_review_with_findings()
        mock_client.embed.side_effect = RuntimeError("network error")

        # Should not raise
        await adapter._store_project_profile(review, "proj", "python")

        adapter.logger.warning.assert_called_once()
        assert "project profile" in adapter.logger.warning.call_args[0][0].lower()


# ---------------------------------------------------------------------------
# recall_cross_project_patterns tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRecallCrossProjectPatterns:

    async def test_recall_cross_project_patterns(self, sage_env):
        """Verify embed + query with falconeye-projects domain."""
        adapter, mock_client, _ = sage_env
        mock_client.reset_mock()

        mock_client.embed.return_value = [0.1, 0.2, 0.3]
        mock_record = SimpleNamespace(
            content="Project X (python) scan profile: 12 findings...",
            confidence_score=0.87,
        )
        mock_client.query.return_value = SimpleNamespace(results=[mock_record])

        results = await adapter.recall_cross_project_patterns(
            language="python", vuln_type="sql-injection", top_k=3
        )

        adapter.logger.warning.assert_not_called()
        assert len(results) == 1
        assert results[0]["content"] == mock_record.content
        assert results[0]["confidence"] == 0.87

        # Verify embed was called with a meaningful query
        embed_arg = mock_client.embed.call_args[0][0]
        assert "python" in embed_arg
        assert "sql-injection" in embed_arg

        # Verify query used the falconeye-projects domain
        query_kwargs = mock_client.query.call_args.kwargs
        assert query_kwargs["domain_tag"] == "falconeye-projects"
        assert query_kwargs["top_k"] == 3

    async def test_recall_cross_project_patterns_empty(self, sage_env):
        """Empty results from SAGE should return empty list."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1, 0.2, 0.3]
        mock_client.query.return_value = SimpleNamespace(results=[])

        results = await adapter.recall_cross_project_patterns(
            language="go", vuln_type="buffer-overflow"
        )
        assert results == []

    async def test_recall_cross_project_patterns_error(self, sage_env):
        """If embed fails, return empty list without propagating."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.side_effect = ConnectionError("SAGE unreachable")

        results = await adapter.recall_cross_project_patterns(
            language="python", vuln_type="xss"
        )
        assert results == []
        adapter.logger.warning.assert_called_once()

    async def test_recall_cross_project_patterns_query_error(self, sage_env):
        """If query fails after successful embed, return empty list."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1, 0.2]
        mock_client.query.side_effect = RuntimeError("query timeout")

        results = await adapter.recall_cross_project_patterns(
            language="rust", vuln_type="memory-safety"
        )
        assert results == []

    async def test_recall_cross_project_patterns_multiple_results(self, sage_env):
        """Multiple results should all be returned."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1, 0.2, 0.3]
        mock_records = [
            SimpleNamespace(content=f"Project-{i} scan profile", confidence_score=0.9 - i * 0.1)
            for i in range(3)
        ]
        mock_client.query.return_value = SimpleNamespace(results=mock_records)

        results = await adapter.recall_cross_project_patterns(
            language="python", vuln_type="injection", top_k=3
        )
        assert len(results) == 3
        assert results[0]["content"] == "Project-0 scan profile"
        assert results[2]["confidence"] == pytest.approx(0.7)


# ---------------------------------------------------------------------------
# store_scan_reflection tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStoreScanReflection:

    async def test_store_scan_reflection(self, sage_env):
        """Verify reflection uses falconeye-reflections domain and inference type."""
        adapter, mock_client, mock_mt = sage_env
        mock_client.embed.return_value = [0.5, 0.6]
        review = _make_review_with_findings()

        await adapter.store_scan_reflection(review, "proj-abc", "python")

        mock_client.embed.assert_awaited_once()
        mock_client.propose.assert_awaited_once()
        call_kwargs = mock_client.propose.call_args.kwargs
        assert call_kwargs["domain_tag"] == "falconeye-reflections"
        assert call_kwargs["memory_type"] == mock_mt.inference
        assert call_kwargs["confidence"] == 0.80
        assert call_kwargs["embedding"] == [0.5, 0.6]

    async def test_store_scan_reflection_content(self, sage_env):
        """Reflection content should include top vuln patterns and totals."""
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1]
        review = _make_review_with_findings()

        await adapter.store_scan_reflection(review, "proj-abc", "python")

        content = mock_client.propose.call_args.kwargs["content"]
        assert "proj-abc" in content
        assert "python" in content
        # SQL Injection appears twice -> should show (2x)
        assert "SQL Injection" in content
        assert "2x" in content
        # Total findings
        assert "4 findings" in content
        # Files analyzed
        assert "4 files" in content

    async def test_store_scan_reflection_empty_findings(self, sage_env):
        """No findings -> propose should not be called."""
        adapter, mock_client, _ = sage_env
        review = SecurityReview.create("/tmp/empty", "python")
        review.complete()

        await adapter.store_scan_reflection(review, "proj", "python")

        mock_client.propose.assert_not_awaited()

    async def test_store_scan_reflection_handles_error(self, sage_env):
        """If embed or propose fails, should log warning and not propagate."""
        adapter, mock_client, _ = sage_env
        review = _make_review_with_findings()
        mock_client.embed.side_effect = RuntimeError("SAGE down")

        # Should not raise
        await adapter.store_scan_reflection(review, "proj", "python")

        adapter.logger.warning.assert_called_once()
        assert "scan reflection" in adapter.logger.warning.call_args[0][0].lower()


# ---------------------------------------------------------------------------
# Cross-project context injection in ReviewFileHandler
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCrossProjectContextInjection:
    """Verify cross-project patterns are injected into prompt context."""

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_cross_project_context_injected_into_review(
        self, mock_logger_cls, tmp_path
    ):
        """Cross-project patterns should appear in related_docs."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.return_value = [
            {
                "content": "Project X (python): SQL injection dominant (5x)",
                "confidence": 0.85,
            },
            {
                "content": "Project Y (python): XSS in templates (3x)",
                "confidence": 0.78,
            },
        ]
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

        # Verify the context passed to analyzer includes cross-project patterns
        ctx_used = mock_analyzer.analyze_code.call_args.kwargs["context"]
        assert ctx_used.related_docs is not None
        assert "CROSS-PROJECT PATTERNS" in ctx_used.related_docs
        assert "SQL injection dominant" in ctx_used.related_docs
        assert "85%" in ctx_used.related_docs

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_cross_project_appends_to_existing_docs(
        self, mock_logger_cls, tmp_path
    ):
        """Cross-project patterns should be appended to existing related_docs."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        # Simulate that historical recall already set related_docs
        context.related_docs = "[Historical Security Findings]\n- [90%] old finding"

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = []

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []  # empty so no overwrite
        mock_memory.recall_cross_project_patterns.return_value = [
            {"content": "Cross-project pattern ABC", "confidence": 0.82},
        ]
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
        # Original docs preserved
        assert "old finding" in ctx_used.related_docs
        # Cross-project appended
        assert "CROSS-PROJECT PATTERNS" in ctx_used.related_docs
        assert "Cross-project pattern ABC" in ctx_used.related_docs

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_cross_project_empty_patterns_no_change(
        self, mock_logger_cls, tmp_path
    ):
        """Empty cross-project patterns should not modify related_docs."""
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
    async def test_cross_project_recall_failure_graceful(
        self, mock_logger_cls, tmp_path
    ):
        """If cross-project recall fails, analysis should still proceed."""
        mock_logger_cls.get_instance.return_value = MagicMock()

        context = _make_context(str(tmp_path / "vuln.py"))
        finding = _make_finding()

        mock_analyzer = AsyncMock()
        mock_analyzer.analyze_code.return_value = [finding]

        mock_assembler = AsyncMock()
        mock_assembler.assemble_context.return_value = context

        mock_memory = AsyncMock()
        mock_memory.recall_findings.return_value = []
        mock_memory.recall_cross_project_patterns.side_effect = ConnectionError(
            "SAGE down"
        )
        mock_memory.recall_feedback.return_value = []
        mock_memory.store_review.return_value = None
        mock_memory.store_scan_reflection.return_value = None

        handler = ReviewFileHandler(
            security_analyzer=mock_analyzer,
            context_assembler=mock_assembler,
            memory_service=mock_memory,
        )

        command = _make_command(tmp_path)
        review = await handler.handle(command)

        # Analysis should still complete normally
        assert len(review.findings) == 1
        mock_analyzer.analyze_code.assert_awaited_once()

    @patch("falconeye.application.commands.review_file.FalconEyeLogger")
    async def test_scan_reflection_called_after_store(
        self, mock_logger_cls, tmp_path
    ):
        """store_scan_reflection should be called after store_review."""
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

        # Both store methods should have been called
        mock_memory.store_review.assert_awaited_once()
        mock_memory.store_scan_reflection.assert_awaited_once()

        # store_scan_reflection should receive language
        reflect_kwargs = mock_memory.store_scan_reflection.call_args.kwargs
        assert reflect_kwargs["language"] == "python"


# ---------------------------------------------------------------------------
# Abstract port completeness
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestAbstractPortCompleteness:
    """Verify all new methods are defined in the abstract MemoryService port."""

    def test_all_new_methods_in_abstract_port(self):
        """recall_cross_project_patterns and store_scan_reflection must be abstract."""
        assert hasattr(MemoryService, "recall_cross_project_patterns")
        assert getattr(
            MemoryService.recall_cross_project_patterns, "__isabstractmethod__", False
        )

        assert hasattr(MemoryService, "store_scan_reflection")
        assert getattr(
            MemoryService.store_scan_reflection, "__isabstractmethod__", False
        )

    def test_incomplete_subclass_without_new_methods_fails(self):
        """A subclass missing the new methods cannot be instantiated."""

        class PartialImpl(MemoryService):
            async def store_review(self, review, project_id):
                pass

            async def recall_findings(self, file_path, language, project_id, top_k=5):
                return []

            async def record_feedback(self, finding_id, is_valid, reason=""):
                pass

            async def recall_feedback(self, file_path, top_k=3):
                return []

            async def health_check(self):
                return True

            # Deliberately omit recall_cross_project_patterns and
            # store_scan_reflection

        with pytest.raises(TypeError):
            PartialImpl()

    def test_complete_subclass_with_new_methods_works(self):
        """A subclass implementing all methods (including new ones) instantiates."""

        class FullImpl(MemoryService):
            async def store_review(self, review, project_id):
                pass

            async def recall_findings(self, file_path, language, project_id, top_k=5):
                return []

            async def record_feedback(self, finding_id, is_valid, reason=""):
                pass

            async def recall_feedback(self, file_path, top_k=3):
                return []

            async def recall_cross_project_patterns(
                self, language, vuln_type, top_k=3
            ):
                return []

            async def store_scan_reflection(self, review, project_id, language):
                pass

            async def health_check(self):
                return True

            def reconfigure(self, base_url):
                pass

        impl = FullImpl()
        assert isinstance(impl, MemoryService)
