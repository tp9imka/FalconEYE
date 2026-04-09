"""Shared fixtures for FalconEYE tests."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from falconeye.domain.models.security import (
    SecurityFinding,
    SecurityReview,
    Severity,
    FindingConfidence,
)


@pytest.fixture
def sample_finding_critical():
    """Create a sample CRITICAL security finding."""
    return SecurityFinding.create(
        issue="SQL Injection via unsanitized user input",
        reasoning="The query parameter is concatenated directly into the SQL string.",
        mitigation="Use parameterized queries or an ORM.",
        severity=Severity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        file_path="src/app/db.py",
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        line_start=42,
        line_end=42,
        cwe_id="CWE-89",
        tags=["sql-injection", "user-input"],
    )


@pytest.fixture
def sample_finding_medium():
    """Create a sample MEDIUM security finding."""
    return SecurityFinding.create(
        issue="Hardcoded secret in source code",
        reasoning="An API key is stored as a string literal.",
        mitigation="Use environment variables or a secrets manager.",
        severity=Severity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        file_path="src/app/config.py",
        code_snippet='API_KEY = "sk-1234567890abcdef"',
        line_start=10,
        line_end=10,
        cwe_id="CWE-798",
        tags=["hardcoded-secret"],
    )


@pytest.fixture
def sample_review(sample_finding_critical, sample_finding_medium):
    """Create a sample SecurityReview with two findings."""
    review = SecurityReview.create(
        codebase_path="/tmp/test-project",
        language="python",
    )
    review.add_finding(sample_finding_critical)
    review.add_finding(sample_finding_medium)
    review.files_analyzed = 1
    review.complete()
    return review


@pytest.fixture
def empty_review():
    """Create a SecurityReview with no findings."""
    review = SecurityReview.create(
        codebase_path="/tmp/test-project",
        language="python",
    )
    review.complete()
    return review
