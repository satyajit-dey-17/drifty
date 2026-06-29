"""
Smoke test for the Drifty MCP server over raw stdio JSON-RPC.
Usage: python examples/mcp_client_test.py /path/to/terraform/workspace
"""

import json
import subprocess
import sys


def send(proc, method, params=None):
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    proc.stdin.write(json.dumps(req).encode() + b"\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def main():
    working_dir = sys.argv[1] if len(sys.argv) > 1 else "."

    proc = subprocess.Popen(
        ["drifty-mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    # List tools
    resp = send(proc, "tools/list")
    print("Available tools:")
    for tool in resp.get("result", {}).get("tools", []):
        print(f"  - {tool['name']}: {tool['description'][:70]}...")

    # Call detect_drift
    print(f"\nCalling detect_drift on: {working_dir}\n")
    result = send(
        proc,
        "tools/call",
        {
            "name": "detect_drift",
            "arguments": {"working_dir": working_dir},
        },
    )
    print(json.dumps(result.get("result"), indent=2))
    proc.terminate()


if __name__ == "__main__":
    main()
