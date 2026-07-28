#!/usr/bin/env python3
"""Refresh encrypted source-pack envelopes without changing their payloads."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

DEFAULT_FILES = (Path("sources.enc.json"), Path("sources-green.enc.json"))


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("empty padded plaintext")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS7 padding")
    return data[:-padding]


def canonical_payload_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {field}")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_key() -> bytes:
    key_hex = os.environ.get("SOURCE_ENCRYPTION_KEY_HEX", "").strip()
    if len(key_hex) != 64:
        raise RuntimeError("SOURCE_ENCRYPTION_KEY_HEX must be a 64-character hex value")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise RuntimeError("SOURCE_ENCRYPTION_KEY_HEX is not valid hexadecimal") from exc
    if len(key) != 32:
        raise RuntimeError("SOURCE_ENCRYPTION_KEY_HEX must decode to 32 bytes")
    return key


def decrypt_wrapper(wrapper: dict[str, Any], key: bytes) -> dict[str, Any]:
    required = {"iv", "ct", "sig", "gz"}
    if set(wrapper) != required:
        raise ValueError(f"wrapper fields mismatch: {sorted(wrapper)}")
    if wrapper.get("gz") is not True:
        raise ValueError("source pack must use gzip")

    iv = bytes.fromhex(str(wrapper["iv"]))
    if len(iv) != 16:
        raise ValueError("AES IV must be 16 bytes")
    ciphertext_b64 = str(wrapper["ct"])
    expected = hmac.new(key, ciphertext_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(wrapper["sig"])):
        raise ValueError("HMAC verification failed")

    ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    plaintext = pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))
    plaintext = gzip.decompress(plaintext)
    envelope = json.loads(plaintext.decode("utf-8"))
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise ValueError("encrypted document is not a source envelope")
    if envelope.get("schema_version") != 1:
        raise ValueError(f"unsupported schema_version: {envelope.get('schema_version')!r}")
    if not isinstance(envelope.get("min_app_version"), str):
        raise ValueError("missing min_app_version")
    parse_timestamp(envelope.get("issued_at"), "issued_at")
    parse_timestamp(envelope.get("expires_at"), "expires_at")
    return envelope


def encrypt_envelope(envelope: dict[str, Any], key: bytes) -> dict[str, Any]:
    plaintext = json.dumps(
        envelope,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    compressed = gzip.compress(plaintext, compresslevel=9)
    iv = os.urandom(16)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(compressed))
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    signature = hmac.new(key, ciphertext_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "iv": iv.hex(),
        "ct": ciphertext_b64,
        "sig": signature,
        "gz": True,
    }


def write_github_output(changed: bool, files: list[str]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"changed={'true' if changed else 'false'}\n")
        output.write(f"files={','.join(files)}\n")


def refresh_file(
    path: Path,
    key: bytes,
    now: datetime,
    expiry_hours: int,
    refresh_before_hours: int,
    force: bool,
    dry_run: bool,
    verify_only: bool,
) -> tuple[bool, dict[str, Any]]:
    wrapper = json.loads(path.read_text("utf-8"))
    envelope = decrypt_wrapper(wrapper, key)
    payload_hash = canonical_payload_hash(envelope["payload"])
    issued_at = parse_timestamp(envelope["issued_at"], "issued_at")
    expires_at = parse_timestamp(envelope["expires_at"], "expires_at")
    remaining_hours = (expires_at - now).total_seconds() / 3600

    details = {
        "path": str(path),
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "remaining_hours": round(remaining_hours, 3),
        "payload_sha256": payload_hash,
        "refreshed": False,
    }

    if verify_only:
        if remaining_hours <= 0:
            raise ValueError(f"{path} is expired")
        return False, details

    should_refresh = force or remaining_hours <= refresh_before_hours
    if not should_refresh:
        return False, details

    refreshed = dict(envelope)
    refreshed["issued_at"] = now.isoformat()
    refreshed["expires_at"] = (now + timedelta(hours=expiry_hours)).isoformat()
    refreshed_wrapper = encrypt_envelope(refreshed, key)

    roundtrip = decrypt_wrapper(refreshed_wrapper, key)
    if canonical_payload_hash(roundtrip["payload"]) != payload_hash:
        raise ValueError(f"{path} payload changed during refresh")
    if roundtrip.get("schema_version") != envelope.get("schema_version"):
        raise ValueError(f"{path} schema changed during refresh")
    if roundtrip.get("min_app_version") != envelope.get("min_app_version"):
        raise ValueError(f"{path} minimum app version changed during refresh")

    refreshed_expiry = parse_timestamp(roundtrip["expires_at"], "expires_at")
    if (refreshed_expiry - now).total_seconds() < (expiry_hours - 0.01) * 3600:
        raise ValueError(f"{path} refreshed expiry is shorter than requested")

    if not dry_run:
        path.write_text(
            json.dumps(refreshed_wrapper, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    details.update(
        {
            "issued_at": roundtrip["issued_at"],
            "expires_at": roundtrip["expires_at"],
            "remaining_hours": round((refreshed_expiry - now).total_seconds() / 3600, 3),
            "refreshed": True,
            "dry_run": dry_run,
        }
    )
    return True, details


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", dest="files", type=Path)
    parser.add_argument("--expiry-hours", type=int, default=72)
    parser.add_argument("--refresh-before-hours", type=int, default=24)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.expiry_hours < 24:
        raise ValueError("expiry-hours must be at least 24")
    if args.refresh_before_hours < 1 or args.refresh_before_hours >= args.expiry_hours:
        raise ValueError("refresh-before-hours must be between 1 and expiry-hours - 1")
    if args.verify_only and (args.force or args.dry_run):
        raise ValueError("verify-only cannot be combined with force or dry-run")

    key = load_key()
    now = datetime.now(timezone.utc)
    files = args.files or list(DEFAULT_FILES)
    changed_files: list[str] = []
    results: list[dict[str, Any]] = []

    for path in files:
        if not path.is_file():
            raise FileNotFoundError(path)
        changed, details = refresh_file(
            path=path,
            key=key,
            now=now,
            expiry_hours=args.expiry_hours,
            refresh_before_hours=args.refresh_before_hours,
            force=args.force,
            dry_run=args.dry_run,
            verify_only=args.verify_only,
        )
        if changed and not args.dry_run:
            changed_files.append(str(path))
        results.append(details)

    write_github_output(bool(changed_files), changed_files)
    print(
        json.dumps(
            {
                "checked_at": now.isoformat(),
                "changed": bool(changed_files),
                "changed_files": changed_files,
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"refresh-source-envelopes: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
