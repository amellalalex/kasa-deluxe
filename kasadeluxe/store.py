"""SQLite storage for power samples and an activity log."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SAMPLE_COLS = (
    "on_state", "power_w", "voltage_v", "current_a", "energy_wh",
    "today_wh", "month_wh", "rssi",
)  # fmt: skip

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    device TEXT NOT NULL, ts REAL NOT NULL,
    on_state INTEGER, power_w REAL, voltage_v REAL, current_a REAL,
    energy_wh REAL, today_wh REAL, month_wh REAL, rssi INTEGER
);
CREATE INDEX IF NOT EXISTS samples_dev_ts ON samples(device, ts);
CREATE TABLE IF NOT EXISTS events (
    device TEXT NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, detail TEXT
);
CREATE INDEX IF NOT EXISTS events_dev_ts ON events(device, ts);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    def add_sample(self, device: str, s: dict[str, Any]) -> None:
        row = (
            device, s["ts"], None if s.get("on") is None else int(s["on"]),
            s.get("power_w"), s.get("voltage_v"), s.get("current_a"), s.get("energy_wh"),
            s.get("today_wh"), s.get("month_wh"), s.get("rssi"),
        )  # fmt: skip
        with self._lock:
            self._db.execute(f"INSERT INTO samples VALUES ({','.join('?' * len(row))})", row)
            self._db.commit()

    def add_event(self, device: str, kind: str, detail: str = "") -> None:
        with self._lock:
            self._db.execute("INSERT INTO events VALUES (?,?,?,?)", (device, time.time(), kind, detail))
            self._db.commit()

    def events(self, device: str, limit: int = 100) -> list[dict]:
        with self._lock:
            cur = self._db.execute(
                "SELECT ts, kind, detail FROM events WHERE device=? ORDER BY ts DESC LIMIT ?",
                (device, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def history(self, device: str, since: float, until: float, bucket: float) -> list[dict]:
        """Bucketed averages (and peak power) between since and until."""
        bucket = max(1.0, bucket)
        with self._lock:
            cur = self._db.execute(
                """
                SELECT CAST(ts / :b AS INTEGER) * :b AS t,
                       AVG(power_w) AS power_w, MAX(power_w) AS power_max_w,
                       AVG(voltage_v) AS voltage_v, AVG(current_a) AS current_a,
                       MAX(on_state) AS on_state, COUNT(*) AS n
                FROM samples WHERE device=:d AND ts BETWEEN :s AND :u
                GROUP BY t ORDER BY t
                """,
                {"b": bucket, "d": device, "s": since, "u": until},
            )
            return [dict(r) for r in cur.fetchall()]

    def raw(self, device: str, since: float, until: float):
        with self._lock:
            cur = self._db.execute(
                f"SELECT ts, {','.join(SAMPLE_COLS)} FROM samples "
                "WHERE device=? AND ts BETWEEN ? AND ? ORDER BY ts",
                (device, since, until),
            )
            return [tuple(r) for r in cur.fetchall()]

    def energy_between(self, device: str, since: float, until: float) -> float:
        """Integrate power over time (Wh) from stored samples; gaps > 5 min are skipped."""
        rows = self.raw(device, since, until)
        wh = 0.0
        for (t0, _, p0, *_), (t1, _, p1, *_) in zip(rows, rows[1:]):
            dt = t1 - t0
            if p0 is not None and p1 is not None and 0 < dt <= 300:
                wh += (p0 + p1) / 2 * dt / 3600
        return wh

    def prune(self, keep_days: float) -> int:
        cutoff = time.time() - keep_days * 86400
        with self._lock:
            n = self._db.execute("DELETE FROM samples WHERE ts < ?", (cutoff,)).rowcount
            self._db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._db.commit()
        return n
