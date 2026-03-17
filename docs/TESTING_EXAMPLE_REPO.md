# Testing SecureFix AI with Exmaple-SecureFix

This guide walks through end-to-end testing of webhook, scan, and PR using the [Exmaple-SecureFix](https://github.com/AshleyMathias/Exmaple-SecureFix) repo.

## 1. Example repo contents (already prepared)

The folder `_example_securefix_repo/` in this project contains:

- **requirements.txt** – Old versions of `requests==2.20.0` and `urllib3==1.24.3` (known CVEs) so the scanner can find vulnerabilities.
- **main.py** – Simple script that uses `requests`.
- **README.md** – Short description.

These files are **committed locally**. You need to **push** them to GitHub (see below).

## 2. Push the example repo to GitHub

Push was not done automatically (403: token may not have write access to the repo). Do one of the following:

**Option A – Push from this machine (recommended)**

```powershell
cd "c:\Users\AshleyMathias\Documents\SecureFix AI\_example_securefix_repo"
# Ensure your GitHub token has repo scope and push access to AshleyMathias/Exmaple-SecureFix
git push origin main
```

If you use HTTPS and a Personal Access Token, when prompted use your token as the password. Or set the remote once:

```powershell
git remote set-url origin https://YOUR_GITHUB_USERNAME@github.com/AshleyMathias/Exmaple-SecureFix.git
git push origin main
# When prompted for password, paste your Personal Access Token (not your GitHub password).
```

**Option B – Create repo on GitHub and push**

If the repo is empty or you prefer a fresh start: create `Exmaple-SecureFix` on GitHub (if needed), then add it as remote and push from `_example_securefix_repo` as above.

After the push, the repo should contain at least: `LICENSE`, `README.md`, `main.py`, `requirements.txt`.

## 3. Ensure SecureFix app and tunnel are running

- **App:** `uvicorn triggers.webhook_listener:app --host 0.0.0.0 --port 8000 --reload`
- **Tunnel (for webhook):** e.g. `ngrok http 8000`  
  Your webhook URL will be: `https://<your-ngrok-host>/github/webhook`

## 4. Configure GitHub webhook (for webhook-driven runs)

1. Open **https://github.com/AshleyMathias/Exmaple-SecureFix** → **Settings** → **Webhooks** → **Add webhook**.
2. **Payload URL:** `https://<your-ngrok-host>/github/webhook`
3. **Content type:** `application/json`
4. **Secret:** Same value as `GITHUB_WEBHOOK_SECRET` in your `.env`.
5. **Events:** e.g. “Just the push event” or “Let me select individual events” and choose **Pushes** and **Issues** (and optionally **Repository vulnerability alerts**).
6. Save. Send a test “ping” and confirm you get a green check (202 response).

## 5. Trigger a scan and verify

**Manual trigger (no webhook needed)**

```powershell
cd "c:\Users\AshleyMathias\Documents\SecureFix AI"
.\.venv\Scripts\python.exe scripts\test_example_repo.py --base-url http://localhost:8000
```

Or with curl:

```powershell
curl -X POST http://localhost:8000/scan -H "Content-Type: application/json" -d "{\"repo_url\": \"https://github.com/AshleyMathias/Exmaple-SecureFix\", \"base_branch\": \"main\"}"
```

**Webhook trigger (push)**

- Push a commit to `Exmaple-SecureFix` (e.g. from another clone or from GitHub UI).  
- The webhook should hit your app; check **Recent Deliveries** in the webhook settings (expect 202).

**Webhook trigger (issue opened)**

- Open a new issue on **https://github.com/AshleyMathias/Exmaple-SecureFix** (any title, e.g. "Run security scan").
- SecureFix treats **issues** with `action: opened` like a trigger: it runs the same clone → scan → patch → PR workflow for that repo.
- In logs you should see: `Webhook: issues for AshleyMathias/Exmaple-SecureFix`, then `Dispatching workflow for ... (issue #N: title)`.

**Local test (issue payload, no GitHub)**

- Run: `python scripts/test_issue_webhook.py` (app must be running on port 8000).
- This POSTs a fake `issues` (opened) payload to `/github/webhook`. Use `--base-url` if the app is behind a tunnel; use `--title "..."` to set the issue title in the payload.

## 6. What to verify (technically)

| Check | Where | What to look for |
|-------|--------|-------------------|
| **Scan accepted** | API response | `"status": "accepted"`, `run_id` returned. |
| **Clone** | App logs | `clone_complete`, `path` = clone directory. |
| **Detection** | App logs | `scan_all_starting`, `pip_audit_starting`, `scan_all_complete`, `total` ≥ 0. |
| **Vulns found** | App logs | `detection_complete` with `patchable` > 0; then `node_ai_reasoning`, `node_apply_patch`, etc. |
| **Patch / PR** | App logs | `pull_request_created`, `pr_url` in `workflow_completed`. |
| **PR on GitHub** | Repo → Pull requests | New PR from branch like `securefix/requests-high-...` with security fixes. |
| **Webhook delivery** | GitHub → Webhooks → Recent Deliveries | 202 response for `ping`, `push`, and `issues` (if you triggered by push or opening an issue). |

If the **remote** repo does not yet have `requirements.txt` (because push failed), the scan will complete with **0 vulnerabilities** and no PR. Push the example files first, then run the scan again.

## 7. Run the test script via tunnel (optional)

If your app is exposed via ngrok:

```powershell
.\.venv\Scripts\python.exe scripts\test_example_repo.py --base-url https://<your-ngrok-host>
```

This only triggers the scan; it does not simulate the webhook. Webhook behavior is tested by pushing to the repo and checking Recent Deliveries and app logs.

## 8. Cleanup

- To stop the app and tunnel, press Ctrl+C in each terminal.
- The local clone `_example_securefix_repo` can be kept for future edits and pushes, or deleted if you no longer need it.
