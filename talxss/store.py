"""Persistent storage for TalXSS — keeps every scan and all findings in SQLite.

A single file (``talxss.db`` by default, next to the project) holds a history
of scans so an operator can review, compare, and re-report past assessments.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "talxss.db"


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB):
        self.path = str(path)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target      TEXT NOT NULL,
                    scope       TEXT NOT NULL,
                    attack_types TEXT NOT NULL,
                    started     REAL,
                    finished    REAL,
                    pages       INTEGER,
                    params      INTEGER,
                    requests    INTEGER,
                    findings    INTEGER,
                    summary     TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    url         TEXT,
                    method      TEXT,
                    parameter   TEXT,
                    context     TEXT,
                    attack_type TEXT,
                    payload_name TEXT,
                    payload     TEXT,
                    severity    TEXT,
                    evidence    TEXT,
                    note        TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
                """
            )

    # -- writes ----------------------------------------------------------- #
    def save_scan(self, result, scope: list[str], attack_types: list[str]) -> int:
        d = result.as_dict()
        with self._conn() as c:
            cur = c.execute(
                """INSERT INTO scans
                   (target, scope, attack_types, started, finished, pages, params,
                    requests, findings, summary)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (result.config_url, ",".join(scope), ",".join(attack_types),
                 result.started, result.finished, result.pages_crawled,
                 result.params_tested, result.requests_made, len(result.findings),
                 json.dumps(d)),
            )
            scan_id = int(cur.lastrowid)
            for f in result.findings:
                c.execute(
                    """INSERT INTO findings
                       (scan_id, url, method, parameter, context, attack_type,
                        payload_name, payload, severity, evidence, note)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, f.url, f.method, f.parameter, f.context,
                     getattr(f, "attack_type", ""), f.payload_name, f.payload,
                     f.severity, f.evidence, f.note),
                )
        return scan_id

    # -- reads ------------------------------------------------------------ #
    def list_scans(self, limit: int = 100) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id,target,scope,attack_types,started,finished,pages,"
                "params,requests,findings FROM scans ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            scan = dict(row)
            fr = c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id",
                           (scan_id,)).fetchall()
            scan["findings"] = [dict(x) for x in fr]
        return scan

    def all_findings(self, limit: int = 1000) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT f.*, s.target FROM findings f JOIN scans s ON s.id=f.scan_id "
                "ORDER BY f.id DESC LIMIT ?", (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
