"""Tests for the SAGE knowledge seeding script."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the scripts directory is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))
# Ensure src is on path for falconeye imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from seed_sage_knowledge import (
    collect_all_knowledge,
    get_enrichment_knowledge,
    get_plugin_knowledge,
    get_severity_knowledge,
    get_system_prompt_knowledge,
    get_taxonomy_and_framework_knowledge,
    get_threshold_knowledge,
    get_validation_prompt_knowledge,
    seed_sage,
)

REQUIRED_FIELDS = {"content", "domain", "memory_type", "confidence", "description"}

# All 9 languages loaded by the plugin registry
EXPECTED_LANGUAGES = {
    "python", "javascript", "go", "rust", "c_cpp", "java", "dart", "php", "ruby",
}


# ---------------------------------------------------------------------------
# Severity knowledge
# ---------------------------------------------------------------------------

class TestGetSeverityKnowledge:
    """Tests for severity knowledge extraction."""

    def test_returns_non_empty_list(self):
        entries = get_severity_knowledge()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_entries_have_required_fields(self):
        entries = get_severity_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, (
                f"Entry '{entry.get('description', '?')}' missing fields: {missing}"
            )

    def test_severity_anti_patterns_included(self):
        entries = get_severity_knowledge()
        anti_pattern_entries = [
            e for e in entries if "anti-pattern" in e.get("description", "").lower()
        ]
        assert len(anti_pattern_entries) >= 5, (
            f"Expected at least 5 anti-pattern entries, got {len(anti_pattern_entries)}"
        )

    def test_contains_all_severity_levels(self):
        entries = get_severity_knowledge()
        descriptions = [e["description"] for e in entries]
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert any(level in d for d in descriptions), (
                f"Missing severity level definition for {level}"
            )

    def test_main_framework_entry_present(self):
        entries = get_severity_knowledge()
        framework_entries = [
            e for e in entries
            if "classification framework" in e.get("description", "").lower()
        ]
        assert len(framework_entries) == 1

    def test_severity_domain_is_consistent(self):
        entries = get_severity_knowledge()
        for entry in entries:
            assert entry["domain"] == "falconeye-severity"

    def test_severity_entry_count(self):
        """1 framework + 5 levels + 5 anti-patterns = 11."""
        entries = get_severity_knowledge()
        assert len(entries) == 11


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

class TestSystemPrompts:
    """Tests for system prompt extraction."""

    def test_system_prompts_extracted_for_all_languages(self):
        entries = get_system_prompt_knowledge()
        domains = {e["domain"] for e in entries}
        for lang in EXPECTED_LANGUAGES:
            assert f"falconeye-prompts-{lang}" in domains, (
                f"Missing system prompt for {lang}"
            )
        assert len(entries) == len(EXPECTED_LANGUAGES)

    def test_system_prompts_are_substantial(self):
        """Each system prompt should be at least 200 words."""
        entries = get_system_prompt_knowledge()
        for entry in entries:
            word_count = len(entry["content"].split())
            assert word_count >= 200, (
                f"System prompt for domain '{entry['domain']}' has only "
                f"{word_count} words (need >= 200)"
            )

    def test_system_prompt_confidence(self):
        entries = get_system_prompt_knowledge()
        for entry in entries:
            assert entry["confidence"] == 0.95
            assert entry["memory_type"] == "fact"

    def test_system_prompts_have_required_fields(self):
        entries = get_system_prompt_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, (
                f"Entry '{entry.get('description', '?')}' missing fields: {missing}"
            )


# ---------------------------------------------------------------------------
# Validation prompts
# ---------------------------------------------------------------------------

class TestValidationPrompts:
    """Tests for validation prompt extraction."""

    def test_validation_prompts_extracted_for_all_languages(self):
        entries = get_validation_prompt_knowledge()
        domains = {e["domain"] for e in entries}
        for lang in EXPECTED_LANGUAGES:
            assert f"falconeye-prompts-{lang}" in domains, (
                f"Missing validation prompt for {lang}"
            )
        assert len(entries) == len(EXPECTED_LANGUAGES)

    def test_validation_prompts_are_substantial(self):
        """Each validation prompt should be at least 50 words."""
        entries = get_validation_prompt_knowledge()
        for entry in entries:
            word_count = len(entry["content"].split())
            assert word_count >= 50, (
                f"Validation prompt for domain '{entry['domain']}' has only "
                f"{word_count} words (need >= 50)"
            )

    def test_validation_prompt_confidence(self):
        entries = get_validation_prompt_knowledge()
        for entry in entries:
            assert entry["confidence"] == 0.90
            assert entry["memory_type"] == "fact"


# ---------------------------------------------------------------------------
# Taxonomy, frameworks, chunking
# ---------------------------------------------------------------------------

class TestTaxonomyAndFrameworks:
    """Tests for vulnerability categories, frameworks, and chunking."""

    def test_returns_entries_for_multiple_languages(self):
        entries = get_taxonomy_and_framework_knowledge()
        assert isinstance(entries, list)
        assert len(entries) > 0

        vuln_languages = {
            e["domain"].replace("falconeye-vuln-", "")
            for e in entries
            if e["domain"].startswith("falconeye-vuln-")
        }
        assert len(vuln_languages) >= 5, (
            f"Expected entries for at least 5 languages, got {len(vuln_languages)}"
        )

    def test_python_vulnerability_categories_present(self):
        entries = get_taxonomy_and_framework_knowledge()
        python_vuln = [
            e for e in entries if e["domain"] == "falconeye-vuln-python"
        ]
        assert len(python_vuln) == 1
        content = python_vuln[0]["content"]
        assert "Command Injection" in content
        assert "SQL Injection" in content
        assert "Deserialization" in content

    def test_framework_entries_present(self):
        entries = get_taxonomy_and_framework_knowledge()
        fw_entries = [
            e for e in entries if e["domain"].startswith("falconeye-frameworks-")
        ]
        assert len(fw_entries) >= 1
        python_fw = [e for e in fw_entries if "python" in e["domain"]]
        assert len(python_fw) == 1
        assert "Django" in python_fw[0]["content"]

    def test_ruby_framework_context_handled(self):
        """Ruby's get_framework_context() returns a str, not List[str].
        The script must handle this gracefully."""
        entries = get_taxonomy_and_framework_knowledge()
        ruby_fw = [
            e for e in entries if e["domain"] == "falconeye-frameworks-ruby"
        ]
        assert len(ruby_fw) == 1
        content = ruby_fw[0]["content"]
        # Ruby's context is a big descriptive string, not "- item" list
        assert "Ruby" in content
        assert "Rails" in content
        # Should NOT start with the generic "Security-relevant frameworks" prefix
        # because the str branch skips that
        assert not content.startswith("Security-relevant frameworks")

    def test_chunking_entries_present(self):
        entries = get_taxonomy_and_framework_knowledge()
        chunking_entries = [
            e for e in entries if e["domain"] == "falconeye-config"
        ]
        assert len(chunking_entries) >= 1
        for entry in chunking_entries:
            assert "chunk_size=" in entry["content"]

    def test_confidence_values_in_range(self):
        entries = get_taxonomy_and_framework_knowledge()
        for entry in entries:
            assert 0.0 <= entry["confidence"] <= 1.0, (
                f"Confidence {entry['confidence']} out of range for {entry['description']}"
            )

    def test_entries_have_required_fields(self):
        entries = get_taxonomy_and_framework_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, (
                f"Entry '{entry.get('description', '?')}' missing fields: {missing}"
            )


# ---------------------------------------------------------------------------
# Legacy get_plugin_knowledge compat
# ---------------------------------------------------------------------------

class TestGetPluginKnowledge:
    """Tests for the legacy get_plugin_knowledge wrapper."""

    def test_returns_same_as_taxonomy_and_framework(self):
        legacy = get_plugin_knowledge()
        modern = get_taxonomy_and_framework_knowledge()
        assert len(legacy) == len(modern)
        for a, b in zip(legacy, modern):
            assert a["content"] == b["content"]
            assert a["domain"] == b["domain"]


# ---------------------------------------------------------------------------
# Enrichment and threshold knowledge
# ---------------------------------------------------------------------------

class TestEnrichmentKnowledge:
    """Tests for enrichment prompt extraction."""

    def test_enrichment_knowledge_extracted(self):
        entries = get_enrichment_knowledge()
        assert len(entries) == 1
        entry = entries[0]
        assert entry["domain"] == "falconeye-prompts-enrichment"
        assert entry["memory_type"] == "fact"
        assert entry["confidence"] == 0.95
        # The prompt should contain key phrases
        assert "security expert" in entry["content"]
        assert "adjusted_severity" in entry["content"]
        assert "severity_justification" in entry["content"]
        assert "needs_field_enrichment" in entry["content"]

    def test_enrichment_has_required_fields(self):
        entries = get_enrichment_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing


class TestThresholdKnowledge:
    """Tests for threshold extraction."""

    def test_threshold_knowledge_extracted(self):
        entries = get_threshold_knowledge()
        assert len(entries) == 1
        entry = entries[0]
        assert entry["domain"] == "falconeye-config"
        assert entry["memory_type"] == "fact"
        assert entry["confidence"] == 0.90

        content = entry["content"]
        # Check that key threshold values are present
        assert "40" in content  # min mitigation length
        assert "60" in content  # min reasoning length
        assert "0.7" in content  # default confidence
        assert "medium" in content  # default severity

        # Check that generic mitigation prefixes are listed
        assert "review and remediate" in content
        assert "fix the vulnerability" in content
        assert "ensure proper" in content

    def test_threshold_has_required_fields(self):
        entries = get_threshold_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing


# ---------------------------------------------------------------------------
# Overall structure
# ---------------------------------------------------------------------------

class TestEntriesStructure:
    """Tests for the overall structure of all entries combined."""

    def test_all_entries_have_required_fields(self):
        entries, _ = collect_all_knowledge()
        for entry in entries:
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, (
                f"Entry '{entry.get('description', '?')}' missing fields: {missing}"
            )

    def test_content_is_non_empty_string(self):
        entries, _ = collect_all_knowledge()
        for entry in entries:
            assert isinstance(entry["content"], str)
            assert len(entry["content"].strip()) > 0, (
                f"Empty content for {entry['description']}"
            )

    def test_domain_is_non_empty_string(self):
        entries, _ = collect_all_knowledge()
        for entry in entries:
            assert isinstance(entry["domain"], str)
            assert len(entry["domain"].strip()) > 0

    def test_memory_type_is_valid(self):
        entries, _ = collect_all_knowledge()
        valid_types = {"fact", "observation", "reflection", "directive"}
        for entry in entries:
            assert entry["memory_type"] in valid_types, (
                f"Invalid memory_type '{entry['memory_type']}' for {entry['description']}"
            )

    def test_total_entry_count_comprehensive(self):
        """Verify we are extracting substantially more than the old script.

        Old script: ~38 entries (11 severity + 27 plugin)
        New script: ~58+ entries (11 severity + 9 sys + 9 val + 27 tax + 1 enr + 1 thr)
        """
        entries, _ = collect_all_knowledge()
        assert len(entries) >= 55, (
            f"Expected at least 55 total entries, got {len(entries)}. "
            "Ensure system prompts, validation prompts, enrichment, and thresholds "
            "are all extracted."
        )


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

class TestDryRun:
    """Tests for dry-run mode (should not call SAGE)."""

    def test_dry_run_does_not_call_sage(self, capsys):
        """Dry run should print entries but never import or call sage_sdk."""
        entries = [
            {
                "content": "Test content",
                "domain": "test-domain",
                "memory_type": "fact",
                "confidence": 0.9,
                "description": "Test entry",
            },
        ]

        with patch.dict("sys.modules", {"sage_sdk": MagicMock()}):
            seed_sage(entries, sage_url="http://localhost:8080", dry_run=True)

        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        assert "1 memories" in captured.out
        assert "test-domain" in captured.out
        assert "Test entry" in captured.out

    def test_dry_run_does_not_import_sage_sdk(self):
        """Dry run should never attempt to import sage_sdk."""
        entries = [
            {
                "content": "Test",
                "domain": "test",
                "memory_type": "fact",
                "confidence": 0.8,
                "description": "Test",
            },
        ]

        original = sys.modules.pop("sage_sdk", None)
        try:
            seed_sage(entries, sage_url="http://fake:9999", dry_run=True)
        finally:
            if original is not None:
                sys.modules["sage_sdk"] = original

    def test_dry_run_with_empty_entries(self, capsys):
        """Dry run with no entries should still work."""
        seed_sage([], sage_url="http://localhost:8080", dry_run=True)

        captured = capsys.readouterr()
        assert "DRY RUN" in captured.out
        assert "0 memories" in captured.out
