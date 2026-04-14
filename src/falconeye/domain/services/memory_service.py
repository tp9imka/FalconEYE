"""Memory service port for persistent security knowledge."""

from abc import ABC, abstractmethod
from typing import Optional

from falconeye.domain.models.security import SecurityFinding, SecurityReview


class MemoryService(ABC):
    """Port for external memory/knowledge services.

    Provides persistent storage and retrieval of security findings
    across scans, enabling learning from historical analysis.
    """

    @abstractmethod
    async def store_review(self, review: SecurityReview, project_id: str) -> None:
        """Store a completed security review's findings."""

    @abstractmethod
    async def recall_findings(
        self,
        file_path: str,
        language: str,
        project_id: str,
        top_k: int = 5,
    ) -> list[dict]:
        """Recall historical findings relevant to a file."""

    @abstractmethod
    async def record_feedback(
        self,
        finding_id: str,
        is_valid: bool,
        reason: str = "",
    ) -> None:
        """Record user feedback on a finding (true/false positive)."""

    @abstractmethod
    async def recall_feedback(
        self,
        file_path: str,
        top_k: int = 3,
    ) -> list[dict]:
        """Recall user feedback for similar code patterns."""

    @abstractmethod
    async def recall_cross_project_patterns(
        self,
        language: str,
        vuln_type: str,
        top_k: int = 3,
    ) -> list[dict]:
        """Recall patterns from other projects for the same language/vuln type."""

    @abstractmethod
    async def store_scan_reflection(
        self,
        review: SecurityReview,
        project_id: str,
        language: str,
    ) -> None:
        """Store a post-scan reflection for continuous improvement."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the memory service is available."""

    @abstractmethod
    def reconfigure(self, base_url: str) -> None:
        """Reconfigure the service with a new base URL.

        Subclasses must override to reset internal clients.
        """
