"""SAGE persistent memory adapter for FalconEYE."""

import asyncio
import json
from pathlib import Path
from typing import Optional

from sage_sdk.async_client import AsyncSageClient
from sage_sdk.auth import AgentIdentity
from sage_sdk.models import MemoryType

from ...domain.models.security import SecurityReview, Severity
from ...domain.services.memory_service import MemoryService
from ..logging import FalconEyeLogger


# Severity → confidence mapping
_SEVERITY_CONFIDENCE = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.90,
    Severity.MEDIUM: 0.80,
    Severity.LOW: 0.70,
    Severity.INFO: 0.60,
}


class SAGEMemoryAdapter(MemoryService):
    """
    SAGE memory adapter for persistent security knowledge.

    Stores and recalls security findings across scans via the SAGE
    consensus-validated memory network, enabling learning from
    historical analysis and reducing false positives over time.

    Uses the sage-agent-sdk for all API interactions.
    The client is lazily created on first use to avoid event-loop
    lifetime issues (the DI container may health-check in a separate
    loop from the one used during analysis).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        identity_path: Optional[str] = None,
        timeout: float = 15.0,
    ):
        """
        Initialize SAGE memory adapter.

        Args:
            base_url: SAGE API base URL
            identity_path: Path to SAGE agent key file (defaults to ~/.sage/agent.key)
            timeout: API request timeout in seconds
        """
        self.logger = FalconEyeLogger.get_instance()
        self._base_url = base_url
        self._timeout = timeout

        # Load or create agent identity
        if identity_path and Path(identity_path).exists():
            self._identity = AgentIdentity.from_file(identity_path)
        else:
            self._identity = AgentIdentity.default()

        # Client is created lazily per event-loop
        self._client: Optional[AsyncSageClient] = None

        self.logger.info(
            "SAGE memory adapter initialized",
            extra={"base_url": base_url},
        )

    def _get_client(self) -> AsyncSageClient:
        """Get or create an AsyncSageClient bound to the current event loop."""
        if self._client is None:
            self._client = AsyncSageClient(
                base_url=self._base_url,
                identity=self._identity,
                timeout=self._timeout,
            )
        return self._client

    async def store_review(self, review: SecurityReview, project_id: str) -> None:
        """
        Store a completed security review's findings in SAGE.

        Each finding is proposed as an observation memory in the
        'falconeye-findings' domain.

        Args:
            review: Completed security review with findings
            project_id: Project identifier for scoping
        """
        if not review.findings:
            return

        # Wake up CometBFT consensus by submitting a lightweight query first.
        # Single-node SAGE uses create_empty_blocks=false, so the consensus
        # loop may be idle after long analysis pauses.
        try:
            await self._get_client().embed("wake")
        except Exception:
            pass

        stored = 0
        for finding in review.findings:
            try:
                # Store as natural language so semantic recall works.
                # SAGE generates embeddings from this content — JSON won't
                # match natural-language recall queries.
                snippet = finding.code_snippet[:200] if finding.code_snippet else ""
                summary = (
                    f"[{finding.severity.value.upper()}] {finding.issue} "
                    f"in {finding.file_path} "
                    f"(project: {project_id}). "
                    f"Mitigation: {finding.mitigation} "
                    f"Code: {snippet}"
                )

                confidence = _SEVERITY_CONFIDENCE.get(finding.severity, 0.70)

                # Generate embedding so vector search works on recall
                embedding = await self._get_client().embed(summary)
                await self._get_client().propose(
                    content=summary,
                    memory_type=MemoryType.observation,
                    domain_tag="falconeye-findings",
                    confidence=confidence,
                    embedding=embedding,
                )
                stored += 1
                # Small delay between proposals to avoid overwhelming
                # single-node BFT consensus
                await asyncio.sleep(0.5)
            except Exception as e:
                self.logger.warning(
                    f"Failed to store finding in SAGE: {e}",
                    extra={
                        "finding_id": str(finding.id),
                        "file_path": finding.file_path,
                    },
                )

        if stored > 0:
            self.logger.info(
                f"Stored {stored}/{len(review.findings)} findings in SAGE",
                extra={"project_id": project_id},
            )

        # Store a project-level profile summary for cross-project learning
        await self._store_project_profile(review, project_id, review.language)

    async def recall_findings(
        self,
        file_path: str,
        language: str,
        project_id: str,
        top_k: int = 5,
    ) -> list[dict]:
        """
        Recall historical findings relevant to a file from SAGE.

        Generates an embedding from the file context and queries the
        'falconeye-findings' domain for similar historical findings.

        Args:
            file_path: Path of the file being analyzed
            language: Programming language
            project_id: Project identifier
            top_k: Maximum number of results to return

        Returns:
            List of dicts with content, confidence, and domain keys
        """
        try:
            query_text = f"security findings for {language} file {file_path} in project {project_id}"
            embedding = await self._get_client().embed(query_text)

            response = await self._get_client().query(
                embedding=embedding,
                domain_tag="falconeye-findings",
                top_k=top_k,
            )

            results = []
            for record in response.results:
                results.append({
                    "content": record.content,
                    "confidence": record.confidence_score,
                    "domain": record.domain_tag,
                })

            if results:
                self.logger.info(
                    f"Recalled {len(results)} historical findings from SAGE",
                    extra={"file_path": file_path, "language": language},
                )

            return results

        except Exception as e:
            self.logger.warning(
                f"Failed to recall findings from SAGE: {e}",
                extra={"file_path": file_path},
            )
            return []

    async def record_feedback(
        self,
        finding_id: str,
        is_valid: bool,
        reason: str = "",
    ) -> None:
        """
        Record user feedback on a finding in SAGE.

        Validated feedback is stored as a fact memory in the
        'falconeye-feedback' domain.

        Args:
            finding_id: UUID of the finding
            is_valid: Whether the finding is a true positive
            reason: Optional explanation
        """
        try:
            verdict = "TRUE POSITIVE" if is_valid else "FALSE POSITIVE"
            content = f"Finding {finding_id}: {verdict}. {reason}".strip()

            embedding = await self._get_client().embed(content)
            await self._get_client().propose(
                content=content,
                memory_type=MemoryType.fact,
                domain_tag="falconeye-feedback",
                confidence=0.95,
                embedding=embedding,
            )

            self.logger.info(
                f"Recorded feedback for finding {finding_id}: {verdict}",
            )
        except Exception as e:
            self.logger.warning(
                f"Failed to record feedback in SAGE: {e}",
                extra={"finding_id": finding_id},
            )

    async def recall_feedback(self, file_path: str, top_k: int = 3) -> list[dict]:
        """
        Recall user feedback for similar code patterns from SAGE.

        Queries the 'falconeye-feedback' domain for feedback on findings
        related to the given file path.

        Args:
            file_path: Path of the file being analyzed
            top_k: Maximum number of results to return

        Returns:
            List of dicts with content and confidence keys
        """
        try:
            query = f"false positive feedback for security findings in {file_path}"
            embedding = await self._get_client().embed(query)
            response = await self._get_client().query(
                embedding=embedding,
                domain_tag="falconeye-feedback",
                top_k=top_k,
            )
            return [
                {"content": r.content, "confidence": r.confidence_score}
                for r in response.results
            ]
        except Exception as e:
            self.logger.warning(
                f"Failed to recall feedback from SAGE: {e}",
                extra={"file_path": file_path},
            )
            return []

    async def _store_project_profile(
        self, review: SecurityReview, project_id: str, language: str
    ) -> None:
        """Store a project-level learning summary after each scan."""
        if not review.findings:
            return
        try:
            severity_dist = {
                "critical": review.get_critical_count(),
                "high": review.get_high_count(),
                "medium": review.get_medium_count(),
                "low": review.get_low_count(),
            }
            # Collect unique vulnerability types found
            vuln_types = list(
                set(
                    f.issue.split(" in ")[0] if " in " in f.issue else f.issue
                    for f in review.findings
                )
            )

            profile = (
                f"Project {project_id} ({language}) scan profile: "
                f"{len(review.findings)} findings "
                f"(critical={severity_dist['critical']}, high={severity_dist['high']}, "
                f"medium={severity_dist['medium']}, low={severity_dist['low']}). "
                f"Vulnerability types: {', '.join(vuln_types[:10])}. "
            )

            embedding = await self._get_client().embed(profile)
            await self._get_client().propose(
                content=profile,
                memory_type=MemoryType.observation,
                domain_tag="falconeye-projects",
                confidence=0.85,
                embedding=embedding,
            )
        except Exception as e:
            self.logger.warning(f"Failed to store project profile: {e}")

    async def recall_cross_project_patterns(
        self, language: str, vuln_type: str, top_k: int = 3
    ) -> list[dict]:
        """Recall cross-project patterns from SAGE."""
        try:
            query = f"{language} {vuln_type} vulnerability patterns across projects"
            embedding = await self._get_client().embed(query)
            response = await self._get_client().query(
                embedding=embedding,
                domain_tag="falconeye-projects",
                top_k=top_k,
            )
            return [
                {"content": r.content, "confidence": r.confidence_score}
                for r in response.results
            ]
        except Exception as e:
            self.logger.warning(f"Failed to recall cross-project patterns: {e}")
            return []

    async def store_scan_reflection(
        self, review: SecurityReview, project_id: str, language: str
    ) -> None:
        """Store a post-scan reflection for continuous improvement."""
        if not review.findings:
            return
        try:
            # Find which vulnerability types dominated
            vuln_counts: dict[str, int] = {}
            for f in review.findings:
                vtype = f.issue.split(" in ")[0] if " in " in f.issue else f.issue
                vuln_counts[vtype] = vuln_counts.get(vtype, 0) + 1

            top_vulns = sorted(vuln_counts.items(), key=lambda x: -x[1])[:5]
            reflection = (
                f"Scan reflection for {language} project {project_id}: "
                f"Top vulnerability patterns: "
                f"{', '.join(f'{v[0]} ({v[1]}x)' for v in top_vulns)}. "
                f"Total: {len(review.findings)} findings across "
                f"{review.files_analyzed} files."
            )

            embedding = await self._get_client().embed(reflection)
            await self._get_client().propose(
                content=reflection,
                memory_type=MemoryType.inference,
                domain_tag="falconeye-reflections",
                confidence=0.80,
                embedding=embedding,
            )
        except Exception as e:
            self.logger.warning(f"Failed to store scan reflection: {e}")

    async def health_check(self) -> bool:
        """
        Check if the SAGE memory service is available.

        Returns:
            True if SAGE is reachable and healthy, False otherwise
        """
        try:
            result = await self._get_client().health()
            return "status" in result
        except Exception as e:
            self.logger.warning(f"SAGE health check failed: {e}")
            return False
