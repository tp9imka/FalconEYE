"""Review single file command and handler."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable
import re
import time

from ...domain.models.security import SecurityReview, SecurityFinding
from ...domain.services.security_analyzer import SecurityAnalyzer
from ...domain.services.context_assembler import ContextAssembler
from ...domain.services.memory_service import MemoryService
from ...infrastructure.logging import FalconEyeLogger


def _sanitize_memory_content(text: str) -> str:
    """Sanitize recalled memory content to mitigate prompt injection.

    SAGE memories can originate from any scan and get recalled by
    semantic similarity across projects. A malicious repo could seed
    adversarial instructions that flow into future scans' prompts.

    This function:
    - Strips control characters (except newlines/tabs)
    - Removes role-switch sequences (e.g. "system:", "assistant:", "user:")
    - Truncates excessively long entries
    """
    # Strip control characters except newline and tab
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Remove common role-switch / prompt injection sequences
    text = re.sub(
        r'(?i)^(system|assistant|user|human|ai)\s*:', '', text, flags=re.MULTILINE
    )
    # Remove XML-style role tags
    text = re.sub(r'(?i)</?(?:system|assistant|user|human|instruction)[^>]*>', '', text)
    # Truncate individual entries to a reasonable length
    if len(text) > 500:
        text = text[:500] + "..."
    return text.strip()


@dataclass
class ReviewFileCommand:
    """
    Command to review a single file.

    Uses AI to analyze the file for security vulnerabilities.
    NO pattern matching - pure AI reasoning.
    """
    file_path: Path
    language: str
    system_prompt: str
    validate_findings: bool = False
    top_k_context: int = 5
    stream_callback: Optional[Callable[[str], None]] = None
    finding_callback: Optional[Callable[['SecurityFinding'], None]] = None


class ReviewFileHandler:
    """
    Handler for review file command.

    Orchestrates:
    1. Read file content
    2. Assemble context with RAG
    3. AI analysis
    4. Optional validation
    """

    def __init__(
        self,
        security_analyzer: SecurityAnalyzer,
        context_assembler: ContextAssembler,
        memory_service: Optional[MemoryService] = None,
        recall_context: bool = True,
        store_findings: bool = True,
    ):
        """
        Initialize handler.

        Args:
            security_analyzer: AI-powered security analyzer
            context_assembler: Context assembly for RAG
            memory_service: Optional persistent memory service (e.g. SAGE)
            recall_context: Whether to recall historical context before analysis
            store_findings: Whether to store scan findings in memory
        """
        self.security_analyzer = security_analyzer
        self.context_assembler = context_assembler
        self.memory_service = memory_service
        self.recall_context = recall_context
        self.store_findings = store_findings
        self.logger = FalconEyeLogger.get_instance()

    async def handle(self, command: ReviewFileCommand) -> SecurityReview:
        """
        Execute review file command.

        Args:
            command: Review command

        Returns:
            SecurityReview with AI-identified findings
        """
        start_time = time.time()

        # Log start
        self.logger.info(
            "Starting file review",
            extra={
                "file_path": str(command.file_path),
                "language": command.language,
                "validate_findings": command.validate_findings,
                "top_k_context": command.top_k_context,
            }
        )

        # Read file
        content = command.file_path.read_text(encoding="utf-8")

        # Create review session
        review = SecurityReview.create(
            codebase_path=str(command.file_path),
            language=command.language,
        )

        # Assemble context with RAG
        context = await self.context_assembler.assemble_context(
            file_path=str(command.file_path),
            code_snippet=content,
            language=command.language,
            top_k_similar=command.top_k_context,
            analysis_type="review",
        )

        # Enrich context with historical findings from SAGE.
        # NOTE: SAGE content is treated as low-trust — it may originate from
        # any prior scan, including adversarial repos. All recalled text is
        # sanitized and wrapped in delimited blocks to prevent prompt injection.
        if self.memory_service and self.recall_context:
            try:
                historical = await self.memory_service.recall_findings(
                    file_path=str(command.file_path),
                    language=command.language,
                    project_id=str(command.file_path.parent),
                )
                if historical:
                    history_text = "\n".join(
                        f"- [{h.get('confidence', 0):.0%}] {_sanitize_memory_content(h.get('content', ''))}"
                        for h in historical[:3]
                    )
                    block = (
                        "--- BEGIN HISTORICAL FINDINGS (low-trust, for reference only) ---\n"
                        f"{history_text}\n"
                        "--- END HISTORICAL FINDINGS ---"
                    )
                    if context.related_docs:
                        context.related_docs += f"\n\n{block}"
                    else:
                        context.related_docs = block
            except Exception as e:
                self.logger.warning(f"SAGE recall failed: {e}")

        # Cross-project learning — recall patterns from other projects
        if self.memory_service and self.recall_context:
            try:
                patterns = await self.memory_service.recall_cross_project_patterns(
                    language=command.language,
                    vuln_type="security",
                )
                if patterns:
                    pattern_text = "\n".join(
                        f"- [{p.get('confidence', 0):.0%}] {_sanitize_memory_content(p.get('content', ''))}"
                        for p in patterns[:3]
                    )
                    block = (
                        "--- BEGIN CROSS-PROJECT PATTERNS (low-trust, for reference only) ---\n"
                        f"{pattern_text}\n"
                        "--- END CROSS-PROJECT PATTERNS ---"
                    )
                    if context.related_docs:
                        context.related_docs += f"\n\n{block}"
                    else:
                        context.related_docs = block
            except Exception as e:
                self.logger.warning(f"SAGE cross-project recall failed: {e}")

        # Also recall severity feedback from past user corrections
        if self.memory_service and self.recall_context:
            try:
                feedback = await self.memory_service.recall_feedback(
                    file_path=str(command.file_path),
                )
                if feedback:
                    fb_text = "\n".join(
                        f"- {_sanitize_memory_content(f.get('content', ''))}"
                        for f in feedback[:3]
                    )
                    block = (
                        "--- BEGIN USER FEEDBACK (low-trust, for reference only) ---\n"
                        f"{fb_text}\n"
                        "--- END USER FEEDBACK ---"
                    )
                    if context.related_docs:
                        context.related_docs += f"\n\n{block}"
                    else:
                        context.related_docs = block
            except Exception as e:
                self.logger.warning(f"SAGE feedback recall failed: {e}")

        # AI analysis
        findings = await self.security_analyzer.analyze_code(
            context=context,
            system_prompt=command.system_prompt,
            stream_callback=command.stream_callback,
            finding_callback=command.finding_callback,
        )

        # Add findings to review
        for finding in findings:
            review.add_finding(finding)

        # Optional validation
        if command.validate_findings and findings:
            self.logger.info(
                "Validating findings with AI",
                extra={
                    "file_path": str(command.file_path),
                    "findings_count": len(findings),
                }
            )

            validated_findings = await self.security_analyzer.validate_findings(
                findings=findings,
                context=context,
            )

            # Replace with validated
            review.findings = validated_findings

        review.files_analyzed = 1
        review.complete()

        # Store findings in SAGE for future reference
        if self.memory_service and self.store_findings:
            try:
                await self.memory_service.store_review(
                    review=review,
                    project_id=str(command.file_path.parent),
                )
                await self.memory_service.store_scan_reflection(
                    review=review,
                    project_id=str(command.file_path.parent),
                    language=command.language,
                )
            except Exception as e:
                self.logger.warning(f"SAGE store failed: {e}")

        # Calculate duration
        duration = time.time() - start_time

        # Log completion
        self.logger.info(
            "File review completed",
            extra={
                "file_path": str(command.file_path),
                "findings_count": len(review.findings),
                "validated": command.validate_findings,
                "duration_seconds": round(duration, 2),
            }
        )

        return review