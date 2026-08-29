"""Block until Elasticsearch answers an authenticated health request.

    python scripts/wait_for_es.py [--timeout 180]

Reads DETECTION_LAB_ES_URL (default http://127.0.0.1:9200) and, if set,
DETECTION_LAB_ES_PASSWORD for the `elastic` user. A fresh 8.x node accepts TCP
connections and returns 401 for a few seconds while it bootstraps its security
index, so "port open" is not "ready"; this waits for HTTP 200 and a non-red cluster.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for Elasticsearch readiness")
    parser.add_argument("--timeout", type=float, default=180.0, help="seconds to wait")
    args = parser.parse_args()

    url = os.environ.get("DETECTION_LAB_ES_URL", "http://127.0.0.1:9200").rstrip("/")
    password = os.environ.get("DETECTION_LAB_ES_PASSWORD")
    headers = {}
    if password:
        token = base64.b64encode(f"elastic:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {token}"

    deadline = time.monotonic() + args.timeout
    last = "no response yet"
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            f"{url}/_cluster/health?wait_for_status=yellow&timeout=5s", headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if payload.get("status") in {"yellow", "green"}:
                    print(f"Elasticsearch ready: status={payload['status']} at {url}")
                    return 0
                last = f"status={payload.get('status')}"
        except urllib.error.HTTPError as error:
            last = f"HTTP {error.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last = f"{type(error).__name__}: {error}"
        time.sleep(3)
    print(f"Elasticsearch not ready after {args.timeout:.0f}s ({last})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
