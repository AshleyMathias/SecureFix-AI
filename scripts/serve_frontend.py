#!/usr/bin/env python3
"""
Standalone static server for the SecureFix AI dashboard (frontend).
Serves the frontend/ directory so the UI runs separately from the API backend.

Usage:
  python scripts/serve_frontend.py
  # Open http://localhost:3000/dashboard.html?api=http://localhost:8000

Or with custom port:
  python scripts/serve_frontend.py 8080
"""
from __future__ import annotations

import argparse
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    frontend_dir = root / "frontend"
    if not frontend_dir.is_dir():
        print(f"Frontend directory not found: {frontend_dir}", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Serve SecureFix AI frontend (dashboard)")
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=3000,
        help="Port to bind (default: 3000)",
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Address to bind (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    os.chdir(frontend_dir)
    server = HTTPServer((args.bind, args.port), SimpleHTTPRequestHandler)
    host = args.bind if args.bind != "0.0.0.0" else "localhost"
    print(f"Serving frontend at http://{host}:{args.port}/")
    print(f"  Dashboard: http://{host}:{args.port}/dashboard.html?api=http://localhost:8000")
    print("  (Ensure the API backend is running on port 8000.)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
