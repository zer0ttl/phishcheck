"""SQLite persistence for completed email processing runs."""

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import ParseReport


@dataclass(frozen=True)
class SavedRun:
    run_id: int
    action: str
    created_at: str
    sha256: str | None
    status: str
    classifications: tuple[str, ...]
    filename: str | None
    original_available: bool
    snapshot: dict[str, Any] | None


def record_run(
    path: str | Path,
    action: str,
    status: str,
    *,
    sha256: str | None = None,
    filename: str | None = None,
    original: bytes | None = None,
    parsed: ParseReport | None = None,
    triage: dict[str, Any] | None = None,
    detection: dict[str, Any] | None = None,
    diagnostics: tuple[str, ...] = (),
    classifications: tuple[str, ...] = (),
) -> int:
    """Save a snapshot and the original upload in one run transaction."""
    snapshot = json.dumps(
        {
            "version": 3,
            "parsed": parsed.model_dump(mode="json") if parsed is not None else None,
            "triage": triage,
            "diagnostics": diagnostics,
            **({"detection": detection} if detection is not None else {}),
        }
    )
    db = Path(path).expanduser()
    db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db, timeout=5)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS triage_attempts (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                sha256 TEXT,
                status TEXT NOT NULL,
                classifications TEXT,
                action TEXT NOT NULL DEFAULT 'triage',
                snapshot TEXT,
                filename TEXT,
                original BLOB
            )
            """)
        columns = _columns(connection)
        for name, definition in (
            ("action", "TEXT NOT NULL DEFAULT 'triage'"),
            ("snapshot", "TEXT"),
            ("filename", "TEXT"),
            ("original", "BLOB"),
        ):
            if name not in columns:
                connection.execute(
                    f"ALTER TABLE triage_attempts ADD COLUMN {name} {definition}"
                )
        row = connection.execute(
            """
            INSERT INTO triage_attempts(
                action, created_at, sha256, status, classifications, snapshot,
                filename, original
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                action,
                datetime.now(UTC).isoformat(),
                sha256,
                status,
                ",".join(classifications) or None,
                snapshot,
                filename,
                original,
            ),
        ).fetchone()
        assert row is not None
        return int(row[0])


def _columns(connection: sqlite3.Connection) -> set[str]:
    return {row[1] for row in connection.execute("PRAGMA table_info(triage_attempts)")}


def _open_reader(path: str | Path) -> sqlite3.Connection:
    db = Path(path).expanduser().absolute()
    connection = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def read_run(path: str | Path, run_id: int) -> SavedRun | None:
    """Load run metadata and the versioned snapshot from a fresh connection."""
    if not Path(path).expanduser().exists():
        return None
    with closing(_open_reader(path)) as connection:
        columns = _columns(connection)
        if not columns:
            return None
        fields = [
            column if column in columns else f"{fallback} AS {column}"
            for column, fallback in (
                ("action", "'triage'"),
                ("snapshot", "NULL"),
                ("filename", "NULL"),
            )
        ]
        original = "original IS NOT NULL" if "original" in columns else "0"
        row = connection.execute(
            f"""
            SELECT id, created_at, sha256, status, classifications,
                   {", ".join(fields)}, {original} AS original_available
            FROM triage_attempts WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
    if row is None:
        return None
    snapshot = json.loads(row["snapshot"]) if row["snapshot"] is not None else None
    if snapshot is not None and snapshot.get("version") not in (1, 2, 3):
        raise ValueError(f"Unsupported saved report version for run {run_id}")
    return SavedRun(
        run_id=row["id"],
        action=row["action"],
        created_at=row["created_at"],
        sha256=row["sha256"],
        status=row["status"],
        classifications=tuple(row["classifications"].split(","))
        if row["classifications"]
        else (),
        filename=row["filename"],
        original_available=bool(row["original_available"]),
        snapshot=snapshot,
    )


def read_original(path: str | Path, run_id: int) -> tuple[str, bytes] | None:
    """Load the original filename and exact bytes when the complete upload exists."""
    if not Path(path).expanduser().exists():
        return None
    with closing(_open_reader(path)) as connection:
        if "original" not in _columns(connection):
            return None
        row = connection.execute(
            "SELECT filename, original FROM triage_attempts WHERE id = ?",
            (run_id,),
        ).fetchone()
    if row is None or row["original"] is None:
        return None
    return row["filename"], row["original"]
