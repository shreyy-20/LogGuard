#!/usr/bin/env python3
"""Helper to list Render services and their IDs for a given account.

Usage:
  export RENDER_API_KEY=... && python scripts/get_render_service_ids.py

This script prints JSON array of services. It requires no third-party deps.
"""
import os
import sys
import json
import urllib.request
import urllib.error

API_URL = "https://api.render.com/v1/services"


def get_services(api_key):
    req = urllib.request.Request(API_URL)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        print("HTTP error:", e.code, file=sys.stderr)
        print(e.read().decode(), file=sys.stderr)
        raise
    except Exception:
        raise


def main():
    api_key = os.environ.get("RENDER_API_KEY")
    if not api_key:
        print("Please set RENDER_API_KEY environment variable.", file=sys.stderr)
        sys.exit(2)

    services = get_services(api_key)
    # Pretty print name/id pairs
    pairs = [{"name": s.get("name"), "id": s.get("id"), "serviceType": s.get("serviceDetails", {}).get("serviceType")} for s in services]
    print(json.dumps(pairs, indent=2))


if __name__ == "__main__":
    main()
