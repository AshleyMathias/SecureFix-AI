#!/usr/bin/env python3
"""
Send a fake GitHub 'issues' (opened) webhook to SecureFix for testing.
Use when the app is running (and optionally behind a tunnel).

Usage:
  python scripts/test_issue_webhook.py
  python scripts/test_issue_webhook.py --base-url https://your-ngrok-host
  python scripts/test_issue_webhook.py --title "Security: check dependencies"
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(_env_path)
except ImportError:
    pass

# Minimal payload matching GitHub's issues webhook (action=opened)
REPO_FULL_NAME = "AshleyMathias/Exmaple-SecureFix"
REPO_CLONE_URL = "https://github.com/AshleyMathias/Exmaple-SecureFix.git"
DEFAULT_BASE = "http://localhost:8000"


def build_issues_payload(issue_number: int = 1, title: str = "Test security scan request") -> dict:
    return {
        "action": "opened",
        "issue": {
            "number": issue_number,
            "title": title,
            "body": "Please run a vulnerability scan (triggered by test script).",
            "state": "open",
        },
        "repository": {
            "full_name": REPO_FULL_NAME,
            "clone_url": REPO_CLONE_URL,
            "html_url": f"https://github.com/{REPO_FULL_NAME}",
            "default_branch": "main",
        },
    }


def send_webhook(base_url: str, payload: dict, secret: str | None = None) -> dict:
    url = f"{base_url.rstrip('/')}/github/webhook"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "issues",
        "X-GitHub-Delivery": "test-delivery-issue-001",
    }
    if secret:
        headers["X-Hub-Signature-256"] = (
            "sha256=" + hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
        )
    req = Request(url, data=data, method="POST", headers=headers)
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        body = e.read().decode() if e.fp else ""
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        raise
    except URLError as e:
        print(f"Request failed: {e.reason}", file=sys.stderr)
        raise


def main() -> None:
    ap = argparse.ArgumentParser(description="Send a fake GitHub issues (opened) webhook to SecureFix")
    ap.add_argument("--base-url", default=DEFAULT_BASE, help="SecureFix API base URL")
    ap.add_argument("--title", default="Test security scan request", help="Issue title in payload")
    ap.add_argument("--number", type=int, default=1, help="Issue number in payload")
    ap.add_argument("--secret", default=os.getenv("GITHUB_WEBHOOK_SECRET"), help="Webhook secret (default: from .env)")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    print(f"Base URL: {base}")
    payload = build_issues_payload(issue_number=args.number, title=args.title)
    secret = args.secret
    if not secret:
        print("Warning: no GITHUB_WEBHOOK_SECRET (set in .env or --secret); server may return 401.", file=sys.stderr)
    print(f"Sending issues webhook (action=opened, repo={REPO_FULL_NAME}, issue #{args.number})...")
    result = send_webhook(base, payload, secret=secret)
    print("Response:", json.dumps(result, indent=2))
    if result.get("status") == "accepted":
        print(f"\nRun ID: {result.get('run_id')}")
        print("Check app logs for: workflow_dispatched (issue), agent_run_starting, clone_complete / clone_failed, etc.")


if __name__ == "__main__":
    main()
