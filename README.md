# SecureFix AI

**Autonomous DevSecOps agent that monitors GitHub repositories for dependency vulnerabilities and automatically generates secure patches.**

SecureFix AI operates entirely through GitHub workflows and backend services — no frontend UI. It detects vulnerabilities, reasons about safe fixes using an LLM, upgrades dependencies, runs tests, and creates pull requests with detailed explanations.

---

## Architecture Diagram

```
GitHub Event (push / schedule / vulnerability_alert)
         │
         ▼
┌─────────────────────────────┐
│  Webhook Listener (FastAPI) │  POST /github/webhook
│  triggers.webhook_listener  │  POST /scan (manual)
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│         SecureFix Orchestrator (LangGraph)              │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────────────┐   │
│  │Initialize│──▶│ Detect   │──▶│   AI Reasoning   │   │
│  │          │   │Vulns     │   │  (LLM Analysis)  │   │
│  └──────────┘   └──────────┘   └────────┬─────────┘   │
│                                          │              │
│  ┌──────────┐   ┌──────────┐   ┌────────▼─────────┐   │
│  │Create PR │◀──│Run Tests │◀──│ Apply Patch      │   │
│  │(GitHub)  │   │(npm/pytest│   │ (Git branch+commit│  │
│  └──────────┘   └──────────┘   └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
              │
              ▼
    GitHub Pull Request
    with full vulnerability
    explanation + test results
```

---

## LangGraph Workflow

```
[initialize]
    │
    ▼
[detect_vulnerabilities]
    │ vulnerabilities found         │ none found / all unpatchable
    ▼                               ▼
[ai_reasoning]                  [complete]
    │
    ▼
[update_dependencies]
    │
    ▼
[apply_patch]
    │ success                   │ failure
    ▼                           ▼
[run_tests]                  [abort]
    │ passed                    │ failed + abort_on_failure=true
    ▼                           ▼
[create_pull_request]        [abort]
    │
    ▼
[complete]
```

---

## Repository Structure

```
securefix-ai/
│
├── agent/
│   ├── orchestrator.py        # LangGraph node implementations
│   ├── securefix_agent.py     # High-level agent entry point
│   ├── graph_builder.py       # LangGraph graph construction + routing
│   └── state.py               # SecureFixState TypedDict
│
├── llm/
│   ├── llm_interface.py       # BaseLLMProvider ABC
│   ├── openai_provider.py     # OpenAI ChatCompletion implementation
│   ├── anthropic_provider.py  # Anthropic Claude implementation
│   └── prompts.py             # Prompt library (vulnerability, patch, PR)
│
├── services/
│   ├── github_service.py      # PyGithub wrapper (PR, labels, comments)
│   ├── vulnerability_service.py  # Scanner orchestration + deduplication
│   ├── dependency_service.py  # Dependency file read/write
│   ├── patch_service.py       # Git branch + commit + push
│   ├── test_service.py        # npm test / pytest execution
│   └── repository_service.py  # Clone, branch, commit, push, cleanup
│
├── scanners/
│   ├── npm_scanner.py         # npm audit (v6 + v7 output formats)
│   ├── python_scanner.py      # pip-audit + safety
│   └── osv_scanner.py         # OSV API (google.github.io/osv.dev)
│
├── workflows/
│   └── vulnerability_fix_flow.py  # High-level flow facade + batch support
│
├── triggers/
│   └── webhook_listener.py    # FastAPI server (webhook + manual scan endpoints)
│
├── models/
│   ├── vulnerability.py       # Vulnerability Pydantic model
│   ├── dependency.py          # Dependency Pydantic model
│   ├── patch_result.py        # PatchResult + TestResult models
│   └── workflow_state.py      # WorkflowState Pydantic model
│
├── utils/
│   ├── config.py              # Pydantic Settings (all env vars)
│   ├── logger.py              # structlog + EventLogger
│   └── shell.py               # Sandboxed subprocess with allow-list
│
├── scripts/
│   └── run_local_demo.py      # Offline demo (no GitHub token required)
│
├── docker/
│   ├── Dockerfile             # Multi-stage Python 3.11 image
│   └── docker-compose.yml
│
├── tests/
│   ├── test_scanners.py
│   ├── test_services.py
│   └── test_agent.py
│
├── .github/workflows/
│   └── securefix.yml          # GitHub Actions CI/CD workflow
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Core Technology Stack

| Category | Technology |
|---|---|
| Language | Python 3.11+ |
| AI Orchestration | LangGraph + LangChain Core |
| LLM Providers | OpenAI GPT-4o / Anthropic Claude |
| Web Framework | FastAPI + Uvicorn |
| GitHub Integration | PyGithub + GitPython |
| Security Scanners | npm audit, pip-audit, safety, OSV API |
| Async HTTP | httpx + asyncio |
| Configuration | Pydantic Settings |
| Logging | structlog (JSON) |
| Infrastructure | Docker + GitHub Actions |

---

## Local Setup

### Prerequisites

- Python 3.11+
- Node.js 20+ (for npm audit)
- Git

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/securefix-ai.git
cd securefix-ai

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install security scanners
pip install pip-audit safety

# 5. Configure environment
cp .env.example .env
# Edit .env with your GITHUB_TOKEN, OPENAI_API_KEY, etc.
```

### Run the webhook server

```bash
python -m uvicorn triggers.webhook_listener:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:
- `http://localhost:8000/health` — health check
- `http://localhost:8000/docs` — Swagger UI (development only)
- `POST http://localhost:8000/github/webhook` — GitHub webhook receiver
- `POST http://localhost:8000/scan` — manual scan trigger

### Run tests

```bash
pytest tests/ -v
```

---

## Local Demo (No GitHub Token Required)

Run the offline demo to see SecureFix AI in action with simulated vulnerabilities:

```bash
# With LLM calls (requires OPENAI_API_KEY)
python scripts/run_local_demo.py

# Without LLM calls (fully offline)
DEMO_SKIP_LLM=1 python scripts/run_local_demo.py
```

**Demo scenario:**
- Creates a temporary repo with `lodash 4.17.15`, `axios 0.21.1`, `Pillow 8.2.0`
- Detects 3 vulnerabilities (CVE-2021-23337, CVE-2021-3749, CVE-2022-22815)
- Calls LLM to reason about safe upgrade versions
- Applies patches to `package.json` and `requirements.txt`
- Prints a full PR description preview

**Expected output:**
```
══════════════════════════════════════════════════════════════════════
  SecureFix AI — Local Demo
══════════════════════════════════════════════════════════════════════

  SCAN RESULTS
  ────────────────────────────────────────────────────────────
  [HIGH    ] lodash          4.17.15    — GHSA-35jh-r3h4-6jhm
             CVE-2021-23337  CVSS: 7.2
             Fix:  4.17.21

  [MODERATE] axios           0.21.1     — GHSA-cph5-m8f7-6c5x
             CVE-2021-3749   CVSS: 5.9
             Fix:  1.6.0

  [HIGH    ] Pillow          8.2.0      — GHSA-xvch-5gv4-984h
             CVE-2022-22815  CVSS: 7.5
             Fix:  9.0.0
```

---

## GitHub Webhook Configuration

1. Go to your repository **Settings → Webhooks → Add webhook**
2. Set **Payload URL** to `https://your-domain.com/github/webhook`
3. Set **Content type** to `application/json`
4. Set **Secret** to the value of `GITHUB_WEBHOOK_SECRET` in your `.env`
5. Select events:
   - `Push`
   - `Pull requests`
   - `Repository vulnerability alerts`
   - `Workflow runs`

---

## Docker Deployment

```bash
# Build and run with Docker Compose
cd docker
docker-compose up -d

# Or build manually
docker build -f docker/Dockerfile -t securefix-ai:latest .
docker run -d \
  -p 8000:8000 \
  -e GITHUB_TOKEN=ghp_... \
  -e OPENAI_API_KEY=sk-... \
  securefix-ai:latest
```

---

## GitHub Actions Integration

The included `.github/workflows/securefix.yml` workflow:
- Runs unit tests on every push and pull request
- Executes a full vulnerability scan on pushes to `main`
- Supports manual dispatch with a custom `repo_url`
- Runs on a daily schedule (02:00 UTC)
- Builds and verifies the Docker image on main branch pushes

Required secrets in your GitHub repository:
- `GITHUB_TOKEN` — automatically provided by GitHub Actions
- `OPENAI_API_KEY` — your OpenAI API key
- `ANTHROPIC_API_KEY` — optional, for Claude provider
- `GITHUB_WEBHOOK_SECRET` — optional, for webhook validation

---

## Switching LLM Providers

No code changes required. Set a single environment variable:

```bash
# Use OpenAI (default)
LLM_PROVIDER=openai

# Switch to Anthropic Claude
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

The `get_llm_provider()` factory in `llm/__init__.py` handles routing automatically.

---

## Example Pull Request Output

```
Title: Security Patch: Fix vulnerability in lodash (GHSA-35jh-r3h4-6jhm)
Branch: securefix/lodash-high-20240116-a1b2c3d4
Labels: security, automated, securefix-ai

## Security Patch — Generated by SecureFix AI

### Executive Summary
This PR resolves a **High severity** prototype pollution vulnerability
(CVE-2021-23337) in `lodash`. Versions prior to 4.17.21 allow command
injection via crafted template strings.

### Vulnerabilities Fixed

| ID                   | Package | Severity | Before   | After    | CVSS |
|----------------------|---------|----------|----------|----------|------|
| GHSA-35jh-r3h4-6jhm  | lodash  | HIGH     | 4.17.15  | 4.17.21  | 7.2  |

### Changes Applied
- `package.json`: `lodash` 4.17.15 → 4.17.21

### Breaking Change Assessment
This is a **patch-level upgrade** (4.17.x → 4.17.21). No breaking API
changes. Breaking change risk: **low** (confirmed by AI analysis).

### Test Results
| Test Suite  | Outcome  | Duration |
|-------------|----------|----------|
| npm test    | ✅ passed | 3.2s     |

### AI Reasoning
Lodash 4.17.21 is the minimal safe version that patches CVE-2021-23337
without introducing any breaking changes. The lodash project follows
strict semver, making this upgrade safe for automated application.

---
*Automated by [SecureFix AI](https://github.com/securefix-ai)*
```

---

## Security Considerations

- **Command injection prevention**: All subprocess calls go through `utils/shell.py` which validates against an executable allow-list and rejects shell metacharacters.
- **Path traversal prevention**: All repository paths are resolved and validated to remain within the configured base directory.
- **SSRF prevention**: Only `https://github.com` URLs are permitted for repository cloning.
- **Webhook authentication**: HMAC-SHA256 signature verification via `X-Hub-Signature-256`.
- **Secrets management**: All credentials via environment variables / `.env`; never hardcoded.
- **Non-root Docker**: The container runs as a dedicated `securefix` user.

---

## Configuration Reference

All configuration is managed via Pydantic Settings. See `.env.example` for the full list with descriptions. Key settings:

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `openai` | Active LLM provider |
| `OPENAI_MODEL` | `gpt-4o` | OpenAI model |
| `GITHUB_TOKEN` | — | **Required.** PAT with repo + PR scopes |
| `PATCH_BRANCH_PREFIX` | `securefix/` | Branch name prefix |
| `ABORT_ON_TEST_FAILURE` | `true` | Cancel PR if tests fail |
| `SKIP_BREAKING_CHANGES` | `false` | Skip high-risk upgrades |
| `MAX_VULNERABILITIES_PER_RUN` | `20` | Cap per workflow run |
| `CLEANUP_AFTER_RUN` | `true` | Delete local clone after run |

---

## License

MIT License — see `LICENSE` for details.
