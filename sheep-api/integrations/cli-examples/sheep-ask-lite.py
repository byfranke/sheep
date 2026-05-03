#!/usr/bin/env python3
# Usage: python3 sheep-ask.py <token> <question>

import sys
import json
import urllib.request
import urllib.error

API_URL = "https://sheep.byfranke.com/api/ai/ask"

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <token> <question>", file=sys.stderr)
        sys.exit(1)

    token = sys.argv[1]
    question = " ".join(sys.argv[2:])

    payload = json.dumps({"question": question}).encode("utf-8")

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Sheep-Token": token,
            "User-Agent": "sheep-ask/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))

        if data.get("success"):
            print(data["response"])
        else:
            print(f"Error: {data.get('error', 'Unknown error')}", file=sys.stderr)
            sys.exit(1)

    except urllib.error.HTTPError as e:
        print(f"Error: HTTP {e.code} - {e.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
