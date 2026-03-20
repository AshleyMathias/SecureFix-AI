<p align="center">
  <h1 align="center">SecureFix AI</h1>
  <p align="center">
    <strong>Autonomous DevSecOps agent that detects dependency vulnerabilities and ships secure patches — automatically.</strong>
  </p>
  <p align="center">
    <a href="https://ashleymathias.github.io/SecureFix-AI/dashboard.html">Live Dashboard</a> &nbsp;·&nbsp;
    <a href="https://securefix-ai-production.up.railway.app/docs">API Docs</a> &nbsp;·&nbsp;
    <a href="https://securefix-ai-production.up.railway.app/health">Health Check</a>
  </p>
</p>

---

## What is SecureFix AI?

SecureFix AI is an **end-to-end autonomous security agent** that plugs into your GitHub workflow. When you push code or open an issue, it:

1. **Detects** known vulnerabilities in your dependencies (Python & Node.js)
2. **Reasons** about safe upgrade paths using an LLM (GPT-4o / Claude)
3. **Patches** dependency files on a dedicated branch
4. **Tests** the patched code automatically
5. **Opens a Pull Request** with a full vulnerability report, AI reasoning, and test results

No human intervention needed between push and PR. The entire pipeline — clone, scan, reason, patch, test, PR — runs in under 60 seconds.

---

## Key Features

| Feature | Description |
|---|---|
| **Multi-Scanner Engine** | pip-audit, safety, npm audit, and OSV API run in parallel to maximize coverage |
| **LLM-Powered Reasoning** | GPT-4o or Claude analyzes vulnerabilities, evaluates breaking-change risk, and picks the minimal safe version |
| **LangGraph Orchestrator** | Stateful, node-based workflow graph with conditional routing (abort on failure, skip if no vulns) |
| **Webhook-Driven** | Listens for GitHub `push` and `issues` (opened) events — zero polling |
| **Auto Pull Requests** | Creates labeled, detailed PRs with severity tables, AI reasoning, and test results |
| **Live Dashboard** | Real-time activity feed and run summary, deployed on GitHub Pages |
| **Dual Deployment** | Backend on Railway, frontend on GitHub Pages — fully separated concerns |
| **Security Hardened** | HMAC webhook verification, subprocess sandboxing, SSRF protection, non-root Docker |

---

## Live Demo

| Component | URL |
|---|---|
| **Dashboard** | [ashleymathias.github.io/SecureFix-AI](https://ashleymathias.github.io/SecureFix-AI/dashboard.html) |
| **Backend API** | [securefix-ai-production.up.railway.app](https://securefix-ai-production.up.railway.app/) |
| **Swagger Docs** | [/docs](https://securefix-ai-production.up.railway.app/docs) |
| **Source Code** | [github.com/AshleyMathias/SecureFix-AI](https://github.com/AshleyMathias/SecureFix-AI) |

---

## How It Works

```
 ┌──────────────────────────────────────────────────────────────────┐
 │                        TRIGGER                                   │
 │   GitHub Push  ───┐                                              │
 │   Issue Opened ───┤──▶  POST /github/webhook                    │
 │   Manual /scan ───┘     (HMAC-SHA256 verified)                   │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │              SECUREFIX ORCHESTRATOR (LangGraph)                  │
 │                                                                  │
 │   ┌────────────┐    ┌─────────────────┐    ┌────────────────┐   │
 │   │ Initialize │───▶│ Detect Vulns    │───▶│ AI Reasoning   │   │
 │   │ Clone repo │    │ pip-audit       │    │ GPT-4o/Claude  │   │
 │   │ Create ID  │    │ safety + npm    │    │ safe versions  │   │
 │   └────────────┘    │ OSV API         │    │ risk analysis  │   │
 │                     └─────────────────┘    └───────┬────────┘   │
 │                                                    │             │
 │   ┌────────────┐    ┌─────────────────┐    ┌───────▼────────┐   │
 │   │ Create PR  │◀───│ Run Tests       │◀───│ Apply Patch    │   │
 │   │ Labels +   │    │ pytest / npm    │    │ Branch, commit │   │
 │   │ AI summary │    │ test validation │    │ push to remote │   │
 │   └────────────┘    └─────────────────┘    └────────────────┘   │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                                ▼
                   GitHub Pull Request
                   ┌─────────────────────────────┐
                   │ Severity table               │
                   │ AI reasoning + risk analysis │
                   │ Test results                 │
                   │ Labels: security, automated  │
                   └─────────────────────────────┘
```

### LangGraph State Machine

```
[initialize] ──▶ [detect_vulnerabilities]
                        │
            ┌───────────┴───────────┐
            │ vulns found           │ none / unpatchable
            ▼                       ▼
      [ai_reasoning]           [complete] ✓
            │
            ▼
   [update_dependencies]
            │
            ▼
      [apply_patch]
            │
      ┌─────┴──────┐
      │ success     │ failure
      ▼             ▼
   [run_tests]   [abort] ✗
      │
   ┌──┴───┐
   │pass  │fail + abort_on_failure
   ▼      ▼
[create_pr] [abort] ✗
   │
   ▼
[complete] ✓
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Orchestration** | LangGraph + LangChain Core | Stateful multi-step workflow with conditional routing |
| **LLM** | OpenAI GPT-4o / Anthropic Claude | Vulnerability reasoning, safe version selection, PR descriptions |
| **Web Framework** | FastAPI + Uvicorn | Async webhook receiver, REST API, health checks |
| **GitHub** | PyGithub + GitPython | Clone, branch, commit, push, PR creation, labels |
| **Scanners** | pip-audit, safety, npm audit, OSV API | Multi-source vulnerability detection |
| **Frontend** | Vanilla HTML/CSS/JS | Live dashboard polling backend API |
| **Logging** | structlog (JSON) | Structured events with in-memory ring buffer for dashboard |
| **Config** | Pydantic Settings + python-dotenv | Type-safe env var management |
| **Deployment** | Railway (backend) + GitHub Pages (frontend) | Production hosting with auto-deploy |
| **CI/CD** | GitHub Actions | Tests, scans, Docker build, Pages deployment |
| **Security** | HMAC-SHA256, subprocess sandbox, SSRF checks | Defense in depth |

---

## Project Structure

```
securefix-ai/
│
├── agent/                          # LangGraph orchestration layer
│   ├── orchestrator.py             #   Node implementations (8 nodes)
│   ├── securefix_agent.py          #   High-level agent entry point
│   ├── graph_builder.py            #   Graph construction + routing logic
│   └── state.py                    #   SecureFixState TypedDict
│
├── llm/                            # LLM provider abstraction
│   ├── llm_interface.py            #   BaseLLMProvider ABC
│   ├── openai_provider.py          #   OpenAI GPT-4o implementation
│   ├── anthropic_provider.py       #   Anthropic Claude implementation
│   └── prompts.py                  #   Prompt templates (vuln analysis, PR)
│
├── services/                       # Domain services
│   ├── vulnerability_service.py    #   Scanner orchestration + dedup
│   ├── github_service.py           #   PyGithub wrapper (PR, labels)
│   ├── dependency_service.py       #   Dependency file read/write
│   ├── patch_service.py            #   Git branch + commit + push
│   ├── test_service.py             #   Test runner (npm/pytest)
│   └── repository_service.py       #   Clone, validate, cleanup
│
├── scanners/                       # Vulnerability scanners
│   ├── python_scanner.py           #   pip-audit + safety
│   ├── npm_scanner.py              #   npm audit (v6 + v7 formats)
│   └── osv_scanner.py              #   OSV API enrichment
│
├── models/                         # Pydantic data models
│   ├── vulnerability.py            #   Vulnerability, Severity, Source
│   ├── dependency.py               #   Dependency, Ecosystem, File
│   ├── patch_result.py             #   PatchResult, TestResult, Status
│   └── workflow_state.py           #   WorkflowState, WorkflowStatus
│
├── triggers/                       # API layer
│   └── webhook_listener.py         #   FastAPI app (webhook, scan, logs)
│
├── workflows/                      # Flow facades
│   └── vulnerability_fix_flow.py   #   VulnerabilityFixFlow + batch
│
├── utils/                          # Cross-cutting concerns
│   ├── config.py                   #   Pydantic Settings (all env vars)
│   ├── logger.py                   #   structlog + EventLogger + templates
│   ├── log_buffer.py               #   In-memory ring buffer for dashboard
│   └── shell.py                    #   Sandboxed subprocess (allow-list)
│
├── frontend/                       # Dashboard (GitHub Pages)
│   ├── dashboard.html              #   Live activity feed + run summary
│   └── index.html                  #   Redirect to dashboard
│
├── scripts/                        # Developer tools
│   ├── run_local_demo.py           #   Offline demo (no GitHub needed)
│   ├── serve_frontend.py           #   Local static server (port 3000)
│   ├── test_example_repo.py        #   Trigger scan on example repo
│   └── test_issue_webhook.py       #   Simulate issues webhook
│
├── docker/                         # Container deployment
│   ├── Dockerfile                  #   Multi-stage Python 3.11 image
│   └── docker-compose.yml
│
├── tests/                          # Test suite
│   ├── test_agent.py
│   ├── test_scanners.py
│   └── test_services.py
│
├── .github/workflows/
│   ├── securefix.yml               #   CI: tests + vuln scan + Docker
│   └── deploy-pages.yml            #   CD: deploy frontend to Pages
│
├── Procfile                        # Railway start command
├── railway.toml                    # Railway build + deploy config
├── runtime.txt                     # Python 3.11.9
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
└── LICENSE
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Git
- A GitHub Personal Access Token (with `repo` + `pull_requests` scopes)
- An OpenAI API key (or Anthropic key)

### Installation

```bash
# Clone
git clone https://github.com/AshleyMathias/SecureFix-AI.git
cd SecureFix-AI

# Virtual environment
python -m venv .venv
.venv\Scripts\activate           # Windows
# source .venv/bin/activate      # Linux/macOS

# Dependencies
pip install -r requirements.txt

# Configuration
cp .env.example .env
# Edit .env → add GITHUB_TOKEN, OPENAI_API_KEY, GITHUB_WEBHOOK_SECRET
```

### Run the Backend

```bash
uvicorn triggers.webhook_listener:app --host 0.0.0.0 --port 8000 --reload
```

**Endpoints:**

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/docs` | GET | Swagger UI (dev only) |
| `/github/webhook` | POST | GitHub webhook receiver |
| `/scan` | POST | Manual scan trigger |
| `/api/recent-logs` | GET | Dashboard log feed |

### Run the Frontend (Local)

```bash
python scripts/serve_frontend.py
# Open http://localhost:3000/dashboard.html
```

### Run Tests

```bash
pytest tests/ -v
```

---

## Deployment

### Backend → Railway

The backend auto-deploys to [Railway](https://railway.app) on every push to `main`.

| File | Purpose |
|---|---|
| `Procfile` | `web: uvicorn triggers.webhook_listener:app --host 0.0.0.0 --port $PORT` |
| `railway.toml` | Build config, health check path, restart policy |
| `runtime.txt` | Python version pinning |

**Required Railway environment variables:**

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | PAT with repo + PR scopes |
| `GITHUB_WEBHOOK_SECRET` | Webhook HMAC secret |
| `OPENAI_API_KEY` | OpenAI API key |
| `LLM_PROVIDER` | `openai` or `anthropic` |
| `ENVIRONMENT` | `development` or `production` |

### Frontend → GitHub Pages

The `frontend/` directory deploys automatically via `.github/workflows/deploy-pages.yml` whenever files in `frontend/` change on `main`.

**Dashboard URL:** [ashleymathias.github.io/SecureFix-AI](https://ashleymathias.github.io/SecureFix-AI/dashboard.html)

---

## Webhook Setup

To connect a repository to SecureFix AI:

1. Go to **repo → Settings → Webhooks → Add webhook**
2. **Payload URL:** `https://securefix-ai-production.up.railway.app/github/webhook`
3. **Content type:** `application/json`
4. **Secret:** same as `GITHUB_WEBHOOK_SECRET`
5. **Events:** select `Pushes` and `Issues`

Now every push triggers a vulnerability scan, and every new issue triggers an analysis.

---

## Example PR Output

When SecureFix AI detects a vulnerability, it opens a PR like this:

```
┌─────────────────────────────────────────────────────────────┐
│  Security Patch: Fix vulnerability in lodash                 │
│  Branch: securefix/lodash-high-20240116-a1b2c3d4            │
│  Labels: security, automated, securefix-ai                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ## Executive Summary                                        │
│  Resolves a HIGH severity prototype pollution vulnerability  │
│  (CVE-2021-23337) in lodash.                                 │
│                                                              │
│  ## Vulnerabilities Fixed                                    │
│  ┌──────────────────┬─────────┬──────┬────────┬────────┐    │
│  │ ID               │ Package │ Sev  │ Before │ After  │    │
│  ├──────────────────┼─────────┼──────┼────────┼────────┤    │
│  │ GHSA-35jh-r3h4   │ lodash  │ HIGH │ 4.17.15│ 4.17.21│    │
│  └──────────────────┴─────────┴──────┴────────┴────────┘    │
│                                                              │
│  ## AI Reasoning                                             │
│  4.17.21 is the minimal safe version. Patch-level upgrade,   │
│  no breaking changes. lodash follows strict semver.          │
│                                                              │
│  ## Test Results                                             │
│  ✅ npm test — passed (3.2s)                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Local Demo (No GitHub Token Required)

Try SecureFix AI without any external services:

```bash
# With LLM calls
python scripts/run_local_demo.py

# Fully offline (simulated LLM)
DEMO_SKIP_LLM=1 python scripts/run_local_demo.py
```

Creates a temp repo with vulnerable `lodash 4.17.15`, `axios 0.21.1`, and `Pillow 8.2.0`, then runs the full scan → reason → patch pipeline.

---

## Security Design

| Layer | Protection |
|---|---|
| **Webhook Auth** | HMAC-SHA256 signature verification (`X-Hub-Signature-256`) |
| **Subprocess** | Allow-list of permitted executables; shell metacharacter rejection (`utils/shell.py`) |
| **SSRF** | Only `https://github.com` URLs allowed for cloning |
| **Path Traversal** | Repository paths resolved and validated within configured base directory |
| **Secrets** | All credentials via environment variables; `.env` gitignored |
| **Docker** | Non-root `securefix` user; multi-stage build |
| **CORS** | Explicit origin allow-list (GitHub Pages + localhost) |

---

## Configuration Reference

All settings managed via Pydantic Settings. See `.env.example` for the full list.

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `openai` | `openai` or `anthropic` |
| `OPENAI_MODEL` | `gpt-4o` | Model for vulnerability reasoning |
| `GITHUB_TOKEN` | — | **Required.** PAT with repo + PR scopes |
| `GITHUB_WEBHOOK_SECRET` | — | HMAC secret for webhook verification |
| `PATCH_BRANCH_PREFIX` | `securefix/` | Branch name prefix for patches |
| `ABORT_ON_TEST_FAILURE` | `true` | Cancel PR if tests fail |
| `SKIP_BREAKING_CHANGES` | `false` | Skip major version upgrades |
| `MAX_VULNERABILITIES_PER_RUN` | `20` | Cap per workflow run |
| `CLEANUP_AFTER_RUN` | `true` | Delete local clone after run |

---

## Switching LLM Providers

No code changes needed — just set the environment variable:

```bash
# OpenAI (default)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Anthropic Claude
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
