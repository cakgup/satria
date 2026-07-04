from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal
from .models import ScanAllowlistEntry

settings = get_settings()


def _dedupe_rules(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    rules: list[str] = []
    for value in values:
        rule = (value or '').strip()
        if not rule:
            continue
        key = rule.lower()
        if key in seen:
            continue
        seen.add(key)
        rules.append(rule)
    return rules


def configured_allowlist_rules() -> list[str]:
    return _dedupe_rules(settings.allowlist())


def database_allowlist_entries(db: Session) -> list[ScanAllowlistEntry]:
    return (
        db.query(ScanAllowlistEntry)
        .filter(ScanAllowlistEntry.is_active == True)  # noqa: E712
        .order_by(ScanAllowlistEntry.rule.asc())
        .all()
    )


def database_allowlist_rules(db: Session) -> list[str]:
    return _dedupe_rules(entry.rule for entry in database_allowlist_entries(db))


def effective_allowlist_rules() -> list[str]:
    db = SessionLocal()
    try:
        return _dedupe_rules([
            *configured_allowlist_rules(),
            *database_allowlist_rules(db),
        ])
    finally:
        db.close()
