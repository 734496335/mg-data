from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import refresh_source_envelopes as refresh


KEY = bytes.fromhex("22" * 32)


def _envelope(*, now: datetime, expires_in_hours: float, payload_marker: str) -> dict:
    return {
        "schema_version": 1,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=expires_in_hours)).isoformat(),
        "min_app_version": "0.1.10",
        "payload": {"marker": payload_marker, "rulesets": [{"rules": []}]},
    }


def _write(path: Path, envelope: dict) -> None:
    path.write_text(json.dumps(refresh.encrypt_envelope(envelope, KEY), ensure_ascii=False), encoding="utf-8")


def _read(path: Path) -> dict:
    return refresh.decrypt_wrapper(json.loads(path.read_text(encoding="utf-8")), KEY)


def test_coherent_fresh_pair_is_not_rewritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    full = tmp_path / "sources.enc.json"
    green = tmp_path / "sources-green.enc.json"
    _write(full, _envelope(now=now, expires_in_hours=72, payload_marker="full"))
    _write(green, _envelope(now=now, expires_in_hours=72, payload_marker="green"))
    before = (full.read_bytes(), green.read_bytes())
    monkeypatch.setenv("SOURCE_ENCRYPTION_KEY_HEX", KEY.hex())
    monkeypatch.setattr(refresh, "DEFAULT_FILES", (full, green))
    monkeypatch.setattr(refresh, "parse_args", lambda: type("Args", (), {
        "files": None,
        "expiry_hours": 72,
        "refresh_before_hours": 24,
        "force": False,
        "dry_run": False,
        "verify_only": False,
    })())

    assert refresh.main() == 0
    assert (full.read_bytes(), green.read_bytes()) == before


def test_one_near_expiry_member_refreshes_entire_cohort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    full = tmp_path / "sources.enc.json"
    green = tmp_path / "sources-green.enc.json"
    _write(full, _envelope(now=now - timedelta(hours=60), expires_in_hours=72, payload_marker="full"))
    _write(green, _envelope(now=now, expires_in_hours=72, payload_marker="green"))
    full_payload = refresh.canonical_payload_hash(_read(full)["payload"])
    green_payload = refresh.canonical_payload_hash(_read(green)["payload"])
    monkeypatch.setenv("SOURCE_ENCRYPTION_KEY_HEX", KEY.hex())
    monkeypatch.setattr(refresh, "DEFAULT_FILES", (full, green))
    monkeypatch.setattr(refresh, "parse_args", lambda: type("Args", (), {
        "files": None,
        "expiry_hours": 72,
        "refresh_before_hours": 24,
        "force": False,
        "dry_run": False,
        "verify_only": False,
    })())

    assert refresh.main() == 0
    full_after = _read(full)
    green_after = _read(green)
    assert full_after["issued_at"] == green_after["issued_at"]
    assert full_after["expires_at"] == green_after["expires_at"]
    assert refresh.canonical_payload_hash(full_after["payload"]) == full_payload
    assert refresh.canonical_payload_hash(green_after["payload"]) == green_payload


def test_verify_only_rejects_cohort_metadata_skew(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    full = tmp_path / "sources.enc.json"
    green = tmp_path / "sources-green.enc.json"
    _write(full, _envelope(now=now, expires_in_hours=72, payload_marker="full"))
    _write(green, _envelope(now=now + timedelta(minutes=1), expires_in_hours=72, payload_marker="green"))
    monkeypatch.setenv("SOURCE_ENCRYPTION_KEY_HEX", KEY.hex())
    monkeypatch.setattr(refresh, "DEFAULT_FILES", (full, green))
    monkeypatch.setattr(refresh, "parse_args", lambda: type("Args", (), {
        "files": None,
        "expiry_hours": 72,
        "refresh_before_hours": 24,
        "force": False,
        "dry_run": False,
        "verify_only": True,
    })())

    with pytest.raises(ValueError, match="cohort metadata is inconsistent"):
        refresh.main()


def test_tampered_member_fails_before_any_rewrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    full = tmp_path / "sources.enc.json"
    green = tmp_path / "sources-green.enc.json"
    _write(full, _envelope(now=now - timedelta(hours=60), expires_in_hours=72, payload_marker="full"))
    _write(green, _envelope(now=now - timedelta(hours=60), expires_in_hours=72, payload_marker="green"))
    wrapper = json.loads(green.read_text(encoding="utf-8"))
    wrapper["sig"] = "0" * 64
    green.write_text(json.dumps(wrapper), encoding="utf-8")
    before = (full.read_bytes(), green.read_bytes())
    monkeypatch.setenv("SOURCE_ENCRYPTION_KEY_HEX", KEY.hex())
    monkeypatch.setattr(refresh, "DEFAULT_FILES", (full, green))
    monkeypatch.setattr(refresh, "parse_args", lambda: type("Args", (), {
        "files": None,
        "expiry_hours": 72,
        "refresh_before_hours": 24,
        "force": False,
        "dry_run": False,
        "verify_only": False,
    })())

    with pytest.raises(ValueError, match="HMAC verification failed"):
        refresh.main()
    assert (full.read_bytes(), green.read_bytes()) == before


def test_production_workflow_refreshes_only_full_source_pack() -> None:
    workflow = Path(".github/workflows/refresh-source-envelopes.yml").read_text(encoding="utf-8")
    assert "--file sources.enc.json" in workflow
    assert "push:" in workflow
    assert "- '.github/workflows/refresh-source-envelopes.yml'" in workflow
    assert "- 'scripts/refresh_source_envelopes.py'" in workflow
    assert "- 'tests/test_refresh_source_envelopes.py'" in workflow
    assert "      - 'sources.enc.json'" not in workflow
    assert "--expiry-hours 72 --refresh-before-hours 32" in workflow
    assert "Refresh threshold: 32 hours remaining" in workflow
    assert "git diff --check -- sources.enc.json" in workflow
    assert "git add sources.enc.json" in workflow
    assert "purge.jsdelivr.net/gh/734496335/mg-data@main/sources-green.enc.json" not in workflow
