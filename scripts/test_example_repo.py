#!/usr/bin/env python3
"""
Test script for Exmaple-SecureFix repo: trigger scan and optionally verify webhook/PR.
Run after: (1) Pushing example repo to GitHub, (2) SecureFix app + tunnel running.

Usage:
  python scripts/test_example_repo.py                    # trigger scan only
  python scripts/test_example_repo.py --wait            # trigger and wait for run (poll)
  python scripts/test_example_repo.py --base-url URL    # use custom base URL (default http://localhost:8000)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

REPO_URL = "https://github.com/AshleyMathias/Exmaple-SecureFix"
DEFAULT_BASE = "http://localhost:8000"


def trigger_scan(base_url: str) -> dict:
    """POST /scan with repo URL. Returns JSON response."""
    url = f"{base_url.rstrip('/')}/scan"
    data = json.dumps({"repo_url": REPO_URL, "base_branch": "main"}).encode("utf-8")
    req = Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
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


def health(base_url: str) -> bool:
    """GET /health. Returns True if healthy."""
    try:
        with urlopen(f"{base_url.rstrip('/')}/health", timeout=5) as resp:
            return resp.getcode() == 200
    except Exception:
        return False


def main() -> None:
    ap = argparse.ArgumentParser(description="Trigger SecureFix scan for Exmaple-SecureFix repo")
    ap.add_argument("--base-url", default=DEFAULT_BASE, help="SecureFix API base URL")
    ap.add_argument("--wait", action="store_true", help="After triggering, print reminder to check logs/PR (no polling)")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    print(f"Base URL: {base}")
    if not health(base):
        print("Warning: /health failed. Is the app running?", file=sys.stderr)
    print(f"Triggering scan for {REPO_URL} ...")
    result = trigger_scan(base)
    print("Response:", json.dumps(result, indent=2))
    run_id = result.get("run_id")
    if run_id:
        print(f"\nRun ID: {run_id}")
        print("Check app logs for: agent_run_complete, workflow_completed, pull_request_created (if vulns found).")
        print("If vulnerabilities were found, a PR should appear on the repo.")
    if args.wait:
        print("\n(Use --wait only to remind; no automatic polling.)")


if __name__ == "__main__":
    main()
