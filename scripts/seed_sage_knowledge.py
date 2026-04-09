#!/usr/bin/env python3
"""Seed FalconEYE's hardcoded security knowledge into SAGE.

This transfers FalconEYE's static vulnerability knowledge, framework context,
severity guidelines, system prompts, validation prompts, enrichment prompts,
and validation thresholds into SAGE's persistent memory, enabling the
knowledge to evolve and improve over time.

Usage:
    python scripts/seed_sage_knowledge.py [--sage-url http://localhost:8080] [--dry-run]
"""

import argparse
import sys
from pathlib import Path

# Add src to path so we can import falconeye
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ---------------------------------------------------------------------------
# 1. Severity classification knowledge
# ---------------------------------------------------------------------------

def get_severity_guidelines() -> str:
    """Extract severity classification guidelines from base plugin."""
    from falconeye.infrastructure.plugins.base_plugin import LanguagePlugin

    return LanguagePlugin.get_severity_guidelines()


def get_severity_knowledge() -> list[dict]:
    """Extract severity classification knowledge.

    Returns structured entries for:
    - The full severity classification framework
    - Individual severity level definitions
    - Common severity anti-patterns (over-rating mistakes)
    """
    guidelines = get_severity_guidelines()

    entries: list[dict] = []

    # Main severity framework
    entries.append({
        "content": guidelines.strip(),
        "domain": "falconeye-severity",
        "memory_type": "fact",
        "confidence": 0.95,
        "description": "Multi-factor severity classification framework for security findings",
    })

    # Individual severity level definitions
    severity_defs = {
        "CRITICAL": (
            "Direct RCE, full database access, or complete authentication bypass "
            "achievable with minimal effort and no prerequisites. Attacker can "
            "directly achieve maximum impact."
        ),
        "HIGH": (
            "Arbitrary file read/write, internal service access (SSRF), privilege "
            "escalation, or significant data exposure. Requires some conditions "
            "but highly impactful."
        ),
        "MEDIUM": (
            "Security posture weakened but requires chaining with other "
            "vulnerabilities for significant impact. Limited direct impact on its own."
        ),
        "LOW": (
            "Hard to exploit in practice, minimal real-world consequence. "
            "Theoretical risk or requires unlikely conditions."
        ),
        "INFO": (
            "Security observation or recommendation. Not directly exploitable "
            "but worth noting for defense-in-depth."
        ),
    }

    for sev, definition in severity_defs.items():
        entries.append({
            "content": f"Severity {sev}: {definition}",
            "domain": "falconeye-severity",
            "memory_type": "fact",
            "confidence": 0.95,
            "description": f"{sev} severity level definition",
        })

    # Anti-patterns (what NOT to mark as critical)
    anti_patterns = [
        (
            "Weak hash algorithms (MD5/SHA1) weaken cryptographic security but "
            "do not directly grant system access -- typically MEDIUM, not CRITICAL."
        ),
        (
            "Weak TLS configuration enables potential MITM but requires network "
            "position -- typically MEDIUM, not CRITICAL."
        ),
        (
            "Weak PRNG (pseudo-random number generator) produces predictable "
            "values but rarely gives direct system access -- typically MEDIUM "
            "unless used for auth tokens."
        ),
        (
            "Integer overflow is concerning but only CRITICAL if it leads to "
            "memory corruption or authentication bypass -- otherwise MEDIUM."
        ),
        (
            "Not every finding should be CRITICAL -- realistic security scans "
            "produce a mix of severities. Over-rating erodes trust in the tool."
        ),
    ]

    for ap in anti_patterns:
        entries.append({
            "content": f"Severity anti-pattern: {ap}",
            "domain": "falconeye-severity",
            "memory_type": "fact",
            "confidence": 0.90,
            "description": "Severity classification anti-pattern -- common over-rating mistake",
        })

    return entries


# ---------------------------------------------------------------------------
# 2 / 3 / 4. Language plugin knowledge (prompts, categories, frameworks,
#             chunking)
# ---------------------------------------------------------------------------

def _load_plugins():
    """Load and return all registered plugins."""
    from falconeye.infrastructure.plugins.plugin_registry import PluginRegistry

    registry = PluginRegistry()
    registry.load_all_plugins()
    return registry.get_all_plugins()


def get_system_prompt_knowledge() -> list[dict]:
    """Extract system prompts from every language plugin.

    System prompts are the most valuable knowledge -- 400-1000+ words of
    language-specific security reasoning instructions per language.
    """
    entries: list[dict] = []

    for plugin in _load_plugins():
        lang = plugin.language_name
        prompt = plugin.get_system_prompt()
        if prompt and prompt.strip():
            entries.append({
                "content": prompt.strip(),
                "domain": f"falconeye-prompts-{lang.lower()}",
                "memory_type": "fact",
                "confidence": 0.95,
                "description": f"{lang} security analysis system prompt",
            })

    return entries


def get_validation_prompt_knowledge() -> list[dict]:
    """Extract validation prompts from every language plugin.

    Validation prompts encode false-positive filtering logic.
    """
    entries: list[dict] = []

    for plugin in _load_plugins():
        lang = plugin.language_name
        prompt = plugin.get_validation_prompt()
        if prompt and prompt.strip():
            entries.append({
                "content": prompt.strip(),
                "domain": f"falconeye-prompts-{lang.lower()}",
                "memory_type": "fact",
                "confidence": 0.90,
                "description": f"{lang} validation prompt for false-positive filtering",
            })

    return entries


def get_taxonomy_and_framework_knowledge() -> list[dict]:
    """Extract vulnerability categories, framework context, and chunking
    strategy from every language plugin.

    Returns separate entries for:
    - Vulnerability categories (List[str] per plugin)
    - Framework context (List[str] OR str per plugin -- Ruby returns str)
    - Chunking strategy (Dict[str, int] per plugin)
    """
    entries: list[dict] = []

    for plugin in _load_plugins():
        lang = plugin.language_name

        # Vulnerability categories -- List[str]
        categories = plugin.get_vulnerability_categories()
        if categories:
            cat_text = f"Vulnerability categories for {lang}:\n"
            for cat in categories:
                cat_text += f"- {cat}\n"

            entries.append({
                "content": cat_text.strip(),
                "domain": f"falconeye-vuln-{lang.lower()}",
                "memory_type": "fact",
                "confidence": 0.95,
                "description": f"{lang} vulnerability taxonomy",
            })

        # Framework context -- List[str] OR str (Ruby returns a big string)
        frameworks = plugin.get_framework_context()
        if frameworks:
            if isinstance(frameworks, str):
                fw_text = frameworks  # Ruby returns a full string
            elif isinstance(frameworks, list):
                fw_text = f"Security-relevant frameworks for {lang}:\n" + "\n".join(
                    f"- {fw}" for fw in frameworks
                )
            else:
                fw_text = str(frameworks)

            entries.append({
                "content": fw_text.strip(),
                "domain": f"falconeye-frameworks-{lang.lower()}",
                "memory_type": "fact",
                "confidence": 0.90,
                "description": f"{lang} framework security context",
            })

        # Chunking strategy -- Dict[str, int]
        chunking = plugin.get_chunking_strategy()
        if chunking:
            entries.append({
                "content": (
                    f"{lang} optimal chunking: "
                    f"chunk_size={chunking.get('chunk_size', 50)}, "
                    f"overlap={chunking.get('chunk_overlap', 10)}. "
                    f"Tuned for {lang} code structure patterns."
                ),
                "domain": "falconeye-config",
                "memory_type": "observation",
                "confidence": 0.80,
                "description": f"{lang} code chunking parameters",
            })

    return entries


# ---------------------------------------------------------------------------
# 5. Enrichment prompts and validation thresholds (security_analyzer.py)
# ---------------------------------------------------------------------------

def get_enrichment_knowledge() -> list[dict]:
    """Extract the hardcoded enrichment system prompt from SecurityAnalyzer.

    This is the prompt that guides the LLM when enriching incomplete findings
    with detailed reasoning, mitigations, snippets, and severity adjustments.
    """
    # The enrichment system prompt is constructed inline inside
    # SecurityAnalyzer._enrich_incomplete_findings.  We reproduce it here
    # verbatim so the seed script does not depend on instantiating the full
    # analyzer stack (which requires an LLM service).
    enrichment_prompt = (
        "You are a security expert reviewing and enriching vulnerability findings.\n"
        "You are given the SOURCE CODE with line numbers and a list of findings.\n\n"
        "Each finding has a 'needs_field_enrichment' flag:\n"
        "- If TRUE: provide ALL fields below (reasoning, mitigation, code_snippet, lines, adjusted_severity)\n"
        "- If FALSE: the finding already has good fields, but you MUST still review the severity "
        "and provide adjusted_severity\n\n"
        "For EACH finding, provide:\n"
        "1. reasoning: Detailed description (2-3+ sentences) - what the vuln is, how to exploit it, what the impact is\n"
        "2. mitigation: Specific fix referencing actual function/variable names from the code\n"
        "3. code_snippet: The exact vulnerable lines from the source\n"
        "4. line_start / line_end: Exact line numbers from the source code\n"
        "5. adjusted_severity: Your assessed severity after reasoning about exploitability and impact\n"
        "6. severity_justification: Brief explanation of WHY you chose this severity level\n\n"
        "SEVERITY ASSESSMENT - reason through these for each finding:\n"
        "- Can a remote unauthenticated attacker exploit this directly? (if yes, likely critical/high)\n"
        "- Does exploitation give code execution or full data access? (if yes, critical)\n"
        "- Does it only weaken security posture without direct compromise? (if yes, medium or lower)\n"
        "- Does it require chaining with other flaws or special conditions? (lower the severity)\n"
        "- A realistic codebase has a MIX of severities - not everything is critical\n\n"
        "Respond ONLY with a JSON object:\n"
        '{"enriched": [\n'
        "  {\n"
        '    "index": <original index>,\n'
        '    "reasoning": "<detailed vulnerability description>",\n'
        '    "mitigation": "<specific actionable recommendation>",\n'
        '    "code_snippet": "<exact vulnerable lines from source>",\n'
        '    "line_start": <integer line number>,\n'
        '    "line_end": <integer line number>,\n'
        '    "adjusted_severity": "critical|high|medium|low|info",\n'
        '    "severity_justification": "<why this severity level>"\n'
        "  }\n"
        "]}\n\n"
        "CRITICAL RULES:\n"
        "- line_start and line_end are MANDATORY integers\n"
        "- code_snippet must be the EXACT lines from the source (max 10 lines)\n"
        "- mitigation must reference specific identifiers from THIS code\n"
        "- adjusted_severity is MANDATORY for every finding - think carefully about real-world impact"
    )

    return [{
        "content": enrichment_prompt.strip(),
        "domain": "falconeye-prompts-enrichment",
        "memory_type": "fact",
        "confidence": 0.95,
        "description": "Enrichment system prompt for vulnerability finding enhancement",
    }]


def get_threshold_knowledge() -> list[dict]:
    """Extract validation thresholds and generic-mitigation patterns from
    SecurityAnalyzer.

    These are the hardcoded constants the analyzer uses to decide whether a
    finding is "complete" and whether its mitigation text is too generic.
    """
    generic_mitigation_prefixes = [
        "review and remediate",
        "review this finding",
        "fix the vulnerability",
        "fix this issue",
        "fix this vulnerability",
        "remediate this",
        "address this issue",
        "ensure proper",
        "implement proper",
        "add proper",
        "use proper",
    ]

    content = (
        "FalconEYE validation thresholds and quality gates:\n\n"
        "Finding completeness rules:\n"
        "- Minimum mitigation length: 40 characters\n"
        "- Minimum reasoning length: 60 characters\n"
        "- Default confidence when missing: 0.7\n"
        "- Default severity when missing: medium\n"
        "- Code snippet must not be empty or 'N/A'\n"
        "- Reasoning must not be 'No detailed description provided.'\n"
        "- line_start must be present\n\n"
        "Generic mitigation prefixes (auto-rejected as too vague):\n"
        + "\n".join(f"- \"{p}\"" for p in generic_mitigation_prefixes)
    )

    return [{
        "content": content.strip(),
        "domain": "falconeye-config",
        "memory_type": "fact",
        "confidence": 0.90,
        "description": "Validation thresholds and generic-mitigation rejection patterns",
    }]


# ---------------------------------------------------------------------------
# Legacy aliases (keep backward compat for callers that import the old names)
# ---------------------------------------------------------------------------

def get_plugin_knowledge() -> list[dict]:
    """Legacy wrapper: returns taxonomy + framework + chunking knowledge.

    New code should call get_taxonomy_and_framework_knowledge(),
    get_system_prompt_knowledge(), and get_validation_prompt_knowledge()
    directly.
    """
    return get_taxonomy_and_framework_knowledge()


# ---------------------------------------------------------------------------
# SAGE seeding
# ---------------------------------------------------------------------------

def seed_sage(entries: list[dict], sage_url: str, dry_run: bool = False) -> None:
    """Seed knowledge entries into SAGE.

    In dry-run mode, prints what would be seeded without connecting.
    Otherwise, registers an agent and proposes each entry as a memory.
    """
    import asyncio

    if dry_run:
        print(f"\n[DRY RUN] Would seed {len(entries)} memories into SAGE at {sage_url}\n")
        for i, entry in enumerate(entries, 1):
            print(
                f"  {i:3d}. [{entry['domain']}] "
                f"({entry['memory_type']}, {entry['confidence']:.0%}) "
                f"{entry['description']}"
            )
        print(f"\nTotal: {len(entries)} memories")
        return

    from sage_sdk import AgentIdentity, AsyncSageClient

    identity = AgentIdentity.default()

    async def _seed() -> None:
        async with AsyncSageClient(sage_url, identity) as client:
            # Health check
            try:
                health = await client.health()
                print(f"SAGE connected: {health.get('status', 'unknown')}")
            except Exception as e:
                print(f"ERROR: Cannot reach SAGE at {sage_url}: {e}")
                sys.exit(1)

            # Register agent if needed
            try:
                await client.register_agent(
                    name="falconeye-seed",
                    role="member",
                    boot_bio="FalconEYE knowledge seeding agent",
                    provider="falconeye",
                )
                print("Agent registered: falconeye-seed")
            except Exception:
                pass  # Already registered

            # Seed memories
            success = 0
            failed = 0
            for i, entry in enumerate(entries, 1):
                try:
                    result = await client.propose(
                        content=entry["content"],
                        memory_type=entry["memory_type"],
                        domain_tag=entry["domain"],
                        confidence=entry["confidence"],
                    )
                    print(
                        f"  [{i}/{len(entries)}] OK  "
                        f"{entry['description']} -> {result.memory_id[:12]}..."
                    )
                    success += 1
                    # Small delay to avoid overwhelming consensus
                    await asyncio.sleep(0.1)
                except Exception as e:
                    print(f"  [{i}/{len(entries)}] ERR {entry['description']}: {e}")
                    failed += 1

            print(
                f"\nSeeding complete: {success} succeeded, "
                f"{failed} failed, {len(entries)} total"
            )

    asyncio.run(_seed())


# ---------------------------------------------------------------------------
# Collect everything
# ---------------------------------------------------------------------------

def collect_all_knowledge() -> tuple[list[dict], dict[str, int]]:
    """Collect all FalconEYE knowledge with progress output.

    Returns:
        (all_entries, section_counts) where section_counts maps section name
        to entry count for reporting.
    """
    entries: list[dict] = []
    section_counts: dict[str, int] = {}

    # [1/6] Severity classification framework
    print("  [1/6] Severity classification framework...")
    severity = get_severity_knowledge()
    entries.extend(severity)
    section_counts["severity"] = len(severity)
    print(f"    -> {len(severity)} memories (guidelines, 5 levels, 5 anti-patterns)")

    # [2/6] Language system prompts
    print("  [2/6] Language system prompts (9 languages)...")
    sys_prompts = get_system_prompt_knowledge()
    entries.extend(sys_prompts)
    section_counts["system_prompts"] = len(sys_prompts)
    print(f"    -> {len(sys_prompts)} memories")

    # [3/6] Language validation prompts
    print("  [3/6] Language validation prompts (9 languages)...")
    val_prompts = get_validation_prompt_knowledge()
    entries.extend(val_prompts)
    section_counts["validation_prompts"] = len(val_prompts)
    print(f"    -> {len(val_prompts)} memories")

    # [4/6] Vulnerability taxonomies & frameworks
    print("  [4/6] Vulnerability taxonomies & frameworks (9 languages)...")
    taxonomy = get_taxonomy_and_framework_knowledge()
    entries.extend(taxonomy)
    section_counts["taxonomy_frameworks"] = len(taxonomy)
    # Count subcategories for display
    n_cats = sum(1 for e in taxonomy if e["domain"].startswith("falconeye-vuln-"))
    n_fws = sum(1 for e in taxonomy if e["domain"].startswith("falconeye-frameworks-"))
    n_chunk = sum(
        1 for e in taxonomy
        if e["domain"] == "falconeye-config" and "chunking" in e["description"]
    )
    print(f"    -> {len(taxonomy)} memories ({n_cats} categories + {n_fws} frameworks + {n_chunk} chunking)")

    # [5/6] Enrichment prompts & thresholds
    print("  [5/6] Enrichment prompts & thresholds...")
    enrichment = get_enrichment_knowledge()
    thresholds = get_threshold_knowledge()
    entries.extend(enrichment)
    entries.extend(thresholds)
    section_counts["enrichment"] = len(enrichment)
    section_counts["thresholds"] = len(thresholds)
    print(f"    -> {len(enrichment) + len(thresholds)} memories")

    # [6/6] Summary
    print(f"  [6/6] Summary...")
    print(f"\nTotal: {len(entries)} memories ready to seed")

    return entries, section_counts


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed FalconEYE's security knowledge into SAGE persistent memory",
    )
    parser.add_argument(
        "--sage-url",
        default="http://localhost:8080",
        help="SAGE API URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be seeded without actually connecting to SAGE",
    )
    args = parser.parse_args()

    print("Extracting FalconEYE security knowledge...\n")

    entries, _ = collect_all_knowledge()

    # Seed into SAGE
    seed_sage(entries, args.sage_url, args.dry_run)


if __name__ == "__main__":
    main()
