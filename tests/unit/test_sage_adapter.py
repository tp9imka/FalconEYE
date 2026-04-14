"""Unit tests for SAGEMemoryAdapter."""

import json
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from falconeye.domain.models.security import (
    SecurityFinding,
    SecurityReview,
    Severity,
    FindingConfidence,
)


# ---------------------------------------------------------------------------
# We can't import SAGEMemoryAdapter at module level because it tries to
# import sage_sdk which may not be installed.  Instead, every test patches
# the sage_sdk modules and then imports the adapter inside the test body.
# ---------------------------------------------------------------------------

def _patch_sage_sdk():
    """Create mock sage_sdk modules and return them for further setup."""
    mock_async_client_cls = MagicMock()
    mock_identity_cls = MagicMock()
    mock_memory_type = SimpleNamespace(observation="observation", fact="fact", inference="inference")

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

    # Inject mocked modules
    originals = {}
    for mod_name, mod_mock in patches.items():
        originals[mod_name] = sys.modules.get(mod_name)
        sys.modules[mod_name] = mod_mock

    # Force re-import to pick up mocked modules
    import importlib
    mod_path = "falconeye.infrastructure.memory.sage_adapter"
    if mod_path in sys.modules:
        importlib.reload(sys.modules[mod_path])
    else:
        importlib.import_module(mod_path)

    from falconeye.infrastructure.memory.sage_adapter import SAGEMemoryAdapter

    # Make identity default() return a sentinel
    mock_identity_cls.default.return_value = MagicMock(name="default_identity")

    # Build mock client instance
    mock_client = AsyncMock()
    mock_async_client_cls.return_value = mock_client

    # Create adapter with mocked logger
    with patch("falconeye.infrastructure.memory.sage_adapter.FalconEyeLogger") as mock_logger_cls:
        mock_logger_cls.get_instance.return_value = MagicMock()
        adapter = SAGEMemoryAdapter(base_url="http://test:8080")

    # Swap the internal client to our mock
    adapter._client = mock_client
    adapter.logger = MagicMock()

    # Restore original modules
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


# ---------------------------------------------------------------------------
# Health check tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestHealthCheck:

    async def test_health_check_success(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.health.return_value = {"status": "ok"}
        result = await adapter.health_check()
        assert result is True
        mock_client.health.assert_awaited_once()

    async def test_health_check_failure(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.health.side_effect = ConnectionError("connection refused")
        result = await adapter.health_check()
        assert result is False

    async def test_health_check_missing_status_key(self, sage_env):
        """health() returns a dict without 'status' -> should return False."""
        adapter, mock_client, _ = sage_env
        mock_client.health.return_value = {"version": "1.0"}
        result = await adapter.health_check()
        assert result is False


# ---------------------------------------------------------------------------
# store_review tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestStoreReview:

    async def test_store_review(self, sage_env, sample_review):
        adapter, mock_client, mock_mt = sage_env
        await adapter.store_review(sample_review, project_id="test-project")

        # Called once per finding + once for project profile
        assert mock_client.propose.await_count == 3

        # Verify first call (finding storage)
        first_call = mock_client.propose.call_args_list[0]
        assert first_call.kwargs["domain_tag"] == "falconeye-findings"
        assert first_call.kwargs["memory_type"] == mock_mt.observation
        assert "embedding" in first_call.kwargs  # Must include embedding for vector search

        # Content should be natural language containing the issue
        content = first_call.kwargs["content"]
        assert "SQL Injection" in content
        assert "test-project" in content

        # Verify last call is the project profile
        last_call = mock_client.propose.call_args_list[-1]
        assert last_call.kwargs["domain_tag"] == "falconeye-projects"

    async def test_store_review_uses_flat_confidence(self, sage_env, sample_review):
        """All findings use the same default confidence (0.85) regardless of severity."""
        adapter, mock_client, _ = sage_env
        await adapter.store_review(sample_review, project_id="proj")

        calls = mock_client.propose.call_args_list
        # Both findings should use the flat default confidence
        assert calls[0].kwargs["confidence"] == 0.85
        assert calls[1].kwargs["confidence"] == 0.85

    async def test_store_review_empty_findings(self, sage_env, empty_review):
        """No findings -> propose() should not be called."""
        adapter, mock_client, _ = sage_env
        await adapter.store_review(empty_review, project_id="proj")
        mock_client.propose.assert_not_awaited()

    async def test_store_review_handles_error(self, sage_env, sample_review):
        """If propose() raises, it should log warning and not propagate."""
        adapter, mock_client, _ = sage_env
        mock_client.propose.side_effect = RuntimeError("network error")

        # Should not raise
        await adapter.store_review(sample_review, project_id="proj")

        # Should have logged warnings (2 findings + 1 project profile = 3)
        assert adapter.logger.warning.call_count == 3

    async def test_store_review_partial_failure(self, sage_env, sample_review):
        """If one propose() fails and another succeeds, continue storing."""
        adapter, mock_client, _ = sage_env
        mock_client.propose.side_effect = [
            RuntimeError("first fails"),
            AsyncMock(return_value=None)(),  # second succeeds
            AsyncMock(return_value=None)(),  # project profile succeeds
        ]
        await adapter.store_review(sample_review, project_id="proj")
        assert mock_client.propose.await_count == 3


# ---------------------------------------------------------------------------
# recall_findings tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRecallFindings:

    async def test_recall_findings(self, sage_env):
        adapter, mock_client, _ = sage_env

        # Mock embed() returning a vector
        mock_client.embed.return_value = [0.1, 0.2, 0.3]

        # Mock query() returning results
        mock_record = SimpleNamespace(
            content='{"issue": "SQL Injection"}',
            confidence_score=0.92,
            domain_tag="falconeye-findings",
        )
        mock_response = SimpleNamespace(results=[mock_record])
        mock_client.query.return_value = mock_response

        results = await adapter.recall_findings(
            file_path="src/db.py",
            language="python",
            project_id="proj",
            top_k=5,
        )

        assert len(results) == 1
        assert results[0]["content"] == '{"issue": "SQL Injection"}'
        assert results[0]["confidence"] == 0.92
        assert results[0]["domain"] == "falconeye-findings"

        # Verify embed was called with a meaningful query
        embed_arg = mock_client.embed.call_args[0][0]
        assert "python" in embed_arg
        assert "src/db.py" in embed_arg

        # Verify query was called with correct params
        mock_client.query.assert_awaited_once()
        query_kwargs = mock_client.query.call_args.kwargs
        assert query_kwargs["domain_tag"] == "falconeye-findings"
        assert query_kwargs["top_k"] == 5

    async def test_recall_findings_empty(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.0, 0.0]
        mock_client.query.return_value = SimpleNamespace(results=[])

        results = await adapter.recall_findings(
            file_path="src/app.py",
            language="python",
            project_id="proj",
        )
        assert results == []

    async def test_recall_findings_handles_embed_error(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.embed.side_effect = ConnectionError("SAGE unavailable")

        results = await adapter.recall_findings(
            file_path="src/app.py",
            language="python",
            project_id="proj",
        )
        assert results == []
        adapter.logger.warning.assert_called_once()

    async def test_recall_findings_handles_query_error(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1]
        mock_client.query.side_effect = RuntimeError("query failed")

        results = await adapter.recall_findings(
            file_path="src/app.py",
            language="python",
            project_id="proj",
        )
        assert results == []

    async def test_recall_findings_multiple_results(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.embed.return_value = [0.1]

        records = [
            SimpleNamespace(content=f"finding-{i}", confidence_score=0.9 - i * 0.1, domain_tag="falconeye-findings")
            for i in range(3)
        ]
        mock_client.query.return_value = SimpleNamespace(results=records)

        results = await adapter.recall_findings(
            file_path="src/app.py",
            language="python",
            project_id="proj",
            top_k=3,
        )
        assert len(results) == 3
        assert results[0]["content"] == "finding-0"
        assert results[2]["content"] == "finding-2"


# ---------------------------------------------------------------------------
# record_feedback tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRecordFeedback:

    async def test_record_feedback_true_positive(self, sage_env):
        adapter, mock_client, mock_mt = sage_env
        await adapter.record_feedback(
            finding_id="abc-123",
            is_valid=True,
            reason="Confirmed by manual review",
        )

        mock_client.propose.assert_awaited_once()
        call_kwargs = mock_client.propose.call_args.kwargs
        assert "TRUE POSITIVE" in call_kwargs["content"]
        assert "abc-123" in call_kwargs["content"]
        assert "Confirmed by manual review" in call_kwargs["content"]
        assert call_kwargs["domain_tag"] == "falconeye-feedback"
        assert call_kwargs["memory_type"] == mock_mt.fact
        assert call_kwargs["confidence"] == 0.95

    async def test_record_feedback_false_positive(self, sage_env):
        adapter, mock_client, mock_mt = sage_env
        await adapter.record_feedback(
            finding_id="def-456",
            is_valid=False,
            reason="Not exploitable in this context",
        )

        call_kwargs = mock_client.propose.call_args.kwargs
        assert "FALSE POSITIVE" in call_kwargs["content"]
        assert "def-456" in call_kwargs["content"]
        assert "Not exploitable" in call_kwargs["content"]

    async def test_record_feedback_no_reason(self, sage_env):
        adapter, mock_client, _ = sage_env
        await adapter.record_feedback(finding_id="ghi-789", is_valid=True)

        call_kwargs = mock_client.propose.call_args.kwargs
        assert "TRUE POSITIVE" in call_kwargs["content"]
        # Content should end cleanly without trailing space from empty reason
        assert call_kwargs["content"].endswith("TRUE POSITIVE.")

    async def test_record_feedback_handles_error(self, sage_env):
        adapter, mock_client, _ = sage_env
        mock_client.propose.side_effect = RuntimeError("SAGE down")

        # Should not raise
        await adapter.record_feedback(finding_id="err-1", is_valid=True)
        adapter.logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# Default confidence constant tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestDefaultFindingConfidence:

    def test_default_confidence_is_085(self, sage_env):
        """Verify the flat default confidence constant."""
        import sys
        import importlib

        patches, mock_cls, mock_id, mock_mt = _patch_sage_sdk()
        originals = {}
        for mod_name, mod_mock in patches.items():
            originals[mod_name] = sys.modules.get(mod_name)
            sys.modules[mod_name] = mod_mock

        mod_path = "falconeye.infrastructure.memory.sage_adapter"
        if mod_path in sys.modules:
            importlib.reload(sys.modules[mod_path])
        from falconeye.infrastructure.memory.sage_adapter import _DEFAULT_FINDING_CONFIDENCE

        for mod_name, orig in originals.items():
            if orig is None:
                sys.modules.pop(mod_name, None)
            else:
                sys.modules[mod_name] = orig

        assert _DEFAULT_FINDING_CONFIDENCE == 0.85
