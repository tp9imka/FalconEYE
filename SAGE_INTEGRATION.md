# FalconEYE + SAGE Integration
**Persistent Security Memory for AI-Powered Code Analysis**

---

## What is SAGE?

SAGE (Sovereign Agent Governed Experience) is a consensus-validated persistent memory system for AI agents. It stores knowledge as memories that go through BFT consensus, have confidence scores, and decay over time.

When integrated with FalconEYE, SAGE enables:

- **Cross-scan memory**: Findings from previous scans inform future analysis
- **False positive learning**: Mark findings as FP and SAGE learns the pattern
- **Security posture tracking**: Historical timeline of findings per project
- **Cross-project intelligence**: Patterns learned in one project apply to others

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     FalconEYE CLI (Host)                        │
│  falconeye scan /path/to/project --sage                        │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Code Index   │  │ AI Analysis  │  │ SAGE Memory Service  │  │
│  │ (ChromaDB)   │  │ (Ollama LLM) │  │ (sage-agent-sdk)     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
└─────────┼─────────────────┼──────────────────────┼──────────────┘
          │                 │                      │
          │     ┌───────────▼───────────┐    ┌─────▼─────┐
          │     │   Ollama Container    │    │   SAGE    │
          │     │   localhost:11434     │    │ Container │
          │     │                       │    │ :8080     │
          │     │ • qwen3-coder:30b    │    │           │
          │     │ • embeddinggemma:300m│    │ Embeddings│
          │     │ • nomic-embed-text    │◄───┤ via       │
          │     │                       │    │ Ollama    │
          │     └───────────────────────┘    └───────────┘
          │           Docker Compose
          └─── Local ChromaDB (no container needed)
```

---

## Quick Start

```bash
# 1. Start SAGE + Ollama containers
docker compose -f docker-compose.sage.yml up -d

# 2. Install FalconEYE with SAGE support
pip install -e ".[sage]"

# 3. Run your first memory-enabled scan
falconeye scan /path/to/project --sage

# 4. Subsequent scans automatically recall past findings
falconeye scan /path/to/project --sage
```

---

## Configuration

Add the following to `~/.falconeye/config.yaml`:

```yaml
sage:
  enabled: true
  base_url: http://localhost:8080
  identity_path: ~/.sage/agent.key    # Auto-generated on first use
  timeout: 15
  store_findings: true                # Store scan results in SAGE
  recall_context: true                # Recall historical context
```

Alternatively, enable via CLI flag:

```bash
falconeye scan /path/to/project --sage
```

---

## How It Works

### During Analysis (Pre-scan)

Before analyzing each file, FalconEYE queries SAGE for historical findings related to that file. These are injected into the LLM's context alongside RAG results, giving the AI awareness of:

- Previously confirmed vulnerabilities in this code
- Known false positive patterns to avoid
- Severity calibration from past validated findings

### After Analysis (Post-scan)

After each scan completes, findings are stored in SAGE as consensus-validated memories:

- Each finding becomes a memory with confidence based on severity
- Memories go through BFT consensus and decay over time
- Findings corroborated across multiple scans gain higher confidence

### Feedback Loop

*(Future feature)* Users can mark findings as true/false positives, which SAGE stores as high-confidence facts. This feedback trains the system to reduce noise on future scans.

---

## Docker Compose Details

The `docker-compose.sage.yml` file defines three services:

1. **ollama** -- Shared LLM server that serves both FalconEYE (analysis + embeddings) and SAGE (embeddings). Runs on `localhost:11434`.

2. **ollama-init** -- One-shot model puller that downloads required models on first start. Exits after pulling is complete.

3. **sage** -- SAGE memory server providing persistent consensus-validated storage. Runs on `localhost:8080`.

FalconEYE itself runs on the host (not in a container) because it needs local filesystem access to scan your code.

---

## Data Persistence

| Data | Location |
|------|----------|
| SAGE data | Docker volume `sage_data` (persists across container restarts) |
| Ollama models | Docker volume `ollama_data` |
| FalconEYE config | `~/.falconeye/config.yaml` |
| Agent identity | `~/.sage/agent.key` (Ed25519 keypair, auto-generated) |

---

## Domains Used

- `falconeye-findings` -- Security findings from scans
- `falconeye-feedback` -- User feedback on finding validity

---

## Security

- SAGE uses **Ed25519 request signing** (not API keys) -- each FalconEYE instance gets its own cryptographic identity
- All communication stays local (`localhost`) -- no cloud services
- Code never leaves your machine

---

## Troubleshooting

**"SAGE memory service unavailable"**
Check if the SAGE container is running:
```bash
docker compose -f docker-compose.sage.yml ps
```

**"Connection refused on port 8080"**
SAGE may still be starting. Wait for the healthcheck to pass:
```bash
docker compose -f docker-compose.sage.yml logs sage
```

**"No historical context found"**
Expected on the first scan. Memories build up over time as you run more scans.

**Reset SAGE data**
Remove all volumes and start fresh:
```bash
docker compose -f docker-compose.sage.yml down -v
```

---

## Links

- **SAGE**: [github.com/l33tdawg/sage](https://github.com/l33tdawg/sage)
- **FalconEYE**: [github.com/FalconEYE-ai/FalconEYE](https://github.com/FalconEYE-ai/FalconEYE)
- **SAGE Python SDK**: `pip install sage-agent-sdk`
