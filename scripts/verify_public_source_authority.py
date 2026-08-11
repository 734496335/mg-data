#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REQUIRED = {
    "sources.enc.json": (
        "https://raw.githubusercontent.com/734496335/mg-data/main/sources.enc.json",
        "https://magnetgoogo.com/sources.enc.json",
        "https://api.naoshiquan.com/sources.enc.json",
    ),
}
OPTIONAL = {
    "sources.enc.json": (
        "https://cdn.jsdelivr.net/gh/734496335/mg-data@main/sources.enc.json",
        "https://maggoogo-gateway.734496335lp.workers.dev/sources.enc.json",
    ),
}


def fetch_sha(url: str, attempt: int) -> tuple[str | None, str]:
    separator = "&" if "?" in url else "?"
    request = urllib.request.Request(
        f"{url}{separator}verify={int(time.time())}-{attempt}",
        headers={"User-Agent": "MagnetGoogo-SourceAuthority-CI/1.0", "Cache-Control": "no-cache"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read()
            if response.status != 200:
                return None, f"HTTP {response.status}"
            return hashlib.sha256(body).hexdigest(), f"HTTP {response.status} bytes={len(body)}"
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def main() -> int:
    expected = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in REQUIRED}
    failures: list[str] = []
    for name, urls in REQUIRED.items():
        for url in urls:
            matched = False
            detail = "not attempted"
            actual = None
            for attempt in range(1, 7):
                actual, detail = fetch_sha(url, attempt)
                if actual == expected[name]:
                    matched = True
                    break
                if attempt < 6:
                    time.sleep(5)
            print(f"required file={name} matched={matched} expected={expected[name]} actual={actual} url={url} detail={detail}")
            if not matched:
                failures.append(url)
    for name, urls in OPTIONAL.items():
        for url in urls:
            actual, detail = fetch_sha(url, 1)
            matched = actual == expected[name]
            print(f"optional file={name} matched={matched} expected={expected[name]} actual={actual} url={url} detail={detail}")
    if failures:
        print(f"required source authority convergence failed: {failures}", file=sys.stderr)
        return 1
    print("SOURCE_AUTHORITY_CONVERGENCE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
