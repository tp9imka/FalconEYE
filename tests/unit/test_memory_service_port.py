"""Unit tests for the MemoryService abstract port."""

import pytest
from abc import ABC

from falconeye.domain.services.memory_service import MemoryService
from falconeye.domain.models.security import SecurityReview


@pytest.mark.unit
class TestMemoryServiceAbstract:
    """Test that MemoryService enforces abstract contract."""

    def test_cannot_instantiate_directly(self):
        """MemoryService is abstract and cannot be instantiated."""
        with pytest.raises(TypeError) as exc_info:
            MemoryService()
        assert "abstract" in str(exc_info.value).lower() or "instantiate" in str(exc_info.value).lower()

    def test_is_subclass_of_abc(self):
        """MemoryService should inherit from ABC."""
        assert issubclass(MemoryService, ABC)

    def test_has_store_review_method(self):
        """MemoryService must define store_review."""
        assert hasattr(MemoryService, "store_review")
        assert getattr(MemoryService.store_review, "__isabstractmethod__", False)

    def test_has_recall_findings_method(self):
        """MemoryService must define recall_findings."""
        assert hasattr(MemoryService, "recall_findings")
        assert getattr(MemoryService.recall_findings, "__isabstractmethod__", False)

    def test_has_record_feedback_method(self):
        """MemoryService must define record_feedback."""
        assert hasattr(MemoryService, "record_feedback")
        assert getattr(MemoryService.record_feedback, "__isabstractmethod__", False)

    def test_has_recall_feedback_method(self):
        """MemoryService must define recall_feedback."""
        assert hasattr(MemoryService, "recall_feedback")
        assert getattr(MemoryService.recall_feedback, "__isabstractmethod__", False)

    def test_has_recall_cross_project_patterns_method(self):
        """MemoryService must define recall_cross_project_patterns."""
        assert hasattr(MemoryService, "recall_cross_project_patterns")
        assert getattr(MemoryService.recall_cross_project_patterns, "__isabstractmethod__", False)

    def test_has_store_scan_reflection_method(self):
        """MemoryService must define store_scan_reflection."""
        assert hasattr(MemoryService, "store_scan_reflection")
        assert getattr(MemoryService.store_scan_reflection, "__isabstractmethod__", False)

    def test_has_health_check_method(self):
        """MemoryService must define health_check."""
        assert hasattr(MemoryService, "health_check")
        assert getattr(MemoryService.health_check, "__isabstractmethod__", False)


@pytest.mark.unit
class TestMemoryServiceIncompleteSubclass:
    """Test that partial implementations are rejected."""

    def test_missing_all_methods_raises(self):
        """A subclass implementing none of the methods cannot be instantiated."""
        class EmptyImpl(MemoryService):
            pass

        with pytest.raises(TypeError):
            EmptyImpl()

    def test_missing_one_method_raises(self):
        """A subclass missing even one method cannot be instantiated."""
        class PartialImpl(MemoryService):
            async def store_review(self, review, project_id):
                pass

            async def recall_findings(self, file_path, language, project_id, top_k=5):
                return []

            async def record_feedback(self, finding_id, is_valid, reason=""):
                pass

            # health_check deliberately omitted

        with pytest.raises(TypeError):
            PartialImpl()


@pytest.mark.unit
class TestMemoryServiceCompleteSubclass:
    """Test that a fully implemented subclass works."""

    def test_complete_subclass_instantiates(self):
        """A subclass implementing all abstract methods should instantiate."""
        class FullImpl(MemoryService):
            async def store_review(self, review, project_id):
                pass

            async def recall_findings(self, file_path, language, project_id, top_k=5):
                return []

            async def record_feedback(self, finding_id, is_valid, reason=""):
                pass

            async def recall_feedback(self, file_path, top_k=3):
                return []

            async def recall_cross_project_patterns(self, language, vuln_type, top_k=3):
                return []

            async def store_scan_reflection(self, review, project_id, language):
                pass

            async def health_check(self):
                return True

            def reconfigure(self, base_url):
                pass

        impl = FullImpl()
        assert isinstance(impl, MemoryService)

    async def test_complete_subclass_methods_callable(self):
        """A complete subclass's methods should be callable."""
        class FullImpl(MemoryService):
            async def store_review(self, review, project_id):
                self._stored = True

            async def recall_findings(self, file_path, language, project_id, top_k=5):
                return [{"content": "test", "confidence": 0.9}]

            async def record_feedback(self, finding_id, is_valid, reason=""):
                self._feedback = (finding_id, is_valid)

            async def recall_feedback(self, file_path, top_k=3):
                return [{"content": "FALSE POSITIVE", "confidence": 0.95}]

            async def recall_cross_project_patterns(self, language, vuln_type, top_k=3):
                return [{"content": "pattern", "confidence": 0.85}]

            async def store_scan_reflection(self, review, project_id, language):
                self._reflected = True

            async def health_check(self):
                return True

            def reconfigure(self, base_url):
                pass

        impl = FullImpl()

        # health_check
        assert await impl.health_check() is True

        # recall_findings
        results = await impl.recall_findings("f.py", "python", "proj")
        assert len(results) == 1

        # store_review
        review = SecurityReview.create("/tmp", "python")
        await impl.store_review(review, "proj")
        assert impl._stored is True

        # record_feedback
        await impl.record_feedback("id-1", True, "confirmed")
        assert impl._feedback == ("id-1", True)

        # recall_feedback
        fb = await impl.recall_feedback("f.py")
        assert len(fb) == 1

        # recall_cross_project_patterns
        patterns = await impl.recall_cross_project_patterns("python", "security")
        assert len(patterns) == 1

        # store_scan_reflection
        await impl.store_scan_reflection(review, "proj", "python")
        assert impl._reflected is True
