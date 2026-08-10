"""Engagement checkpoint store (M4) — makes `heretic scan --save x.db` resumable.

A scan writes its config + every CONFIRMED primitive finding to a SQLite file as it
goes, and marks each bug-class done as its phase completes. If the run is interrupted
(Ctrl-C, crash, network drop), `heretic resume --engagement x.db` reloads the saved
findings and re-runs only the classes that had not finished — then re-chains over the
merged set. A finished engagement simply reproduces its findings + report.

Chains are NOT persisted (they are derived): resume recomputes them from the full,
merged primitive set so no chain is ever double-counted.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .models import Finding, Severity

_META_KEYS = ("url", "mode", "model", "roe", "accounts", "chain", "classes", "completed")


def finding_to_dict(f: Finding) -> dict[str, Any]:
    d = asdict(f)
    d["severity"] = f.severity.value          # enum -> plain string for JSON
    return d


def finding_from_dict(d: dict[str, Any]) -> Finding:
    d = dict(d)
    d["severity"] = Severity(d["severity"])
    return Finding(**d)


class EngagementStore:
    """SQLite-backed, commit-per-write so partial progress survives an interrupt."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.executescript(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, bug_class TEXT, data TEXT);"
            "CREATE TABLE IF NOT EXISTS done (bug_class TEXT PRIMARY KEY);"
        )
        self.db.commit()

    # ---- write side (called by the orchestrator / scan) ----------------
    def start(self, cfg: Any, roe: str, accounts: str) -> None:
        meta = {
            "url": cfg.url, "mode": cfg.mode, "model": cfg.model,
            "roe": str(roe), "accounts": str(accounts),
            "chain": "1" if cfg.chain else "0",
            "classes": json.dumps(list(cfg.classes)),
            "completed": "0",
        }
        self.db.executemany("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", meta.items())
        self.db.commit()

    def save_finding(self, f: Finding) -> None:
        if f.bug_class == "chain":
            return                                # chains are derived, never persisted
        self.db.execute(
            "INSERT INTO findings(bug_class, data) VALUES (?, ?)",
            (f.bug_class, json.dumps(finding_to_dict(f), default=str)),
        )
        self.db.commit()

    def mark_done(self, bug_class: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO done(bug_class) VALUES (?)", (bug_class,))
        self.db.commit()

    def mark_complete(self) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('completed', '1')")
        self.db.commit()

    # ---- read side (called by `heretic resume`) ------------------------
    def load(self) -> tuple[dict[str, Any], list[Finding], set[str]]:
        meta_rows = dict(self.db.execute("SELECT key, value FROM meta").fetchall())
        meta = {
            "url": meta_rows.get("url", ""),
            "mode": meta_rows.get("mode", "dry-run"),
            "model": meta_rows.get("model", "nemotron-super"),
            "roe": meta_rows.get("roe", ""),
            "accounts": meta_rows.get("accounts", ""),
            "chain": meta_rows.get("chain", "0") == "1",
            "classes": json.loads(meta_rows.get("classes", "[]")),
            "completed": meta_rows.get("completed", "0") == "1",
        }
        findings = [finding_from_dict(json.loads(row[0]))
                    for row in self.db.execute("SELECT data FROM findings").fetchall()]
        done = {row[0] for row in self.db.execute("SELECT bug_class FROM done").fetchall()}
        return meta, findings, done

    def close(self) -> None:
        self.db.close()
