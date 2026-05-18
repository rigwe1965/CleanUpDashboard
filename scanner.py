"""
scanner.py — Disk scanner using os.walk + classifier.
Writes results to SQLite in real time. Runs in a background thread.
Emits progress events to a queue for SSE streaming.
"""

import hashlib
import json
import os
import queue
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from classifier import classify, PROTECTED_PATHS, is_protected

# ---------------------------------------------------------------------------
# Scan targets: (root_path, max_depth or None)
# We always add the current user's profile as primary target.
# ---------------------------------------------------------------------------

BATCH_SIZE = 500           # SQLite batch insert size
PROGRESS_EVERY = 200       # emit SSE event every N files
DUPLICATE_MIN_SIZE = 512 * 1024         # 512 KB minimum for duplicate check
LARGE_FILE_MIN = 100 * 1024 * 1024     # 100 MB


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _partial_hash(path: str, chunk: int = 65536) -> str | None:
    """Hash first+last chunk of a file for fast duplicate pre-check."""
    try:
        size = os.path.getsize(path)
        h = hashlib.md5()
        with open(path, "rb") as f:
            h.update(f.read(chunk))
            if size > chunk:
                f.seek(max(0, size - chunk))
                h.update(f.read(chunk))
        return h.hexdigest()
    except Exception:
        return None


def _full_hash(path: str) -> str | None:
    """Full MD5 hash of a file."""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                buf = f.read(131072)
                if not buf:
                    break
                h.update(buf)
        return h.hexdigest()
    except Exception:
        return None


def _emit(q: queue.Queue, data: dict):
    try:
        q.put_nowait(data)
    except queue.Full:
        pass


def _get_scan_targets() -> list[str]:
    """Determine which drives/paths to scan."""
    targets = []

    # Primary: user profile
    user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
    if os.path.isdir(user_profile):
        targets.append(user_profile)

    # Windows Temp (outside protected zone, useful to scan)
    win_temp = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Temp")
    if os.path.isdir(win_temp):
        targets.append(win_temp)

    # H:\ — Google Drive mount if present
    if os.path.isdir("H:\\"):
        targets.append("H:\\")

    return targets


def _init_db(conn: sqlite3.Connection):
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id              TEXT PRIMARY KEY,
            scan_id         TEXT NOT NULL,
            path            TEXT NOT NULL UNIQUE,
            drive           TEXT NOT NULL,
            size            INTEGER NOT NULL DEFAULT 0,
            risk            TEXT NOT NULL DEFAULT 'HIGH',
            risk_reason     TEXT NOT NULL DEFAULT '',
            type            TEXT NOT NULL DEFAULT 'unknown',
            category        TEXT NOT NULL DEFAULT 'Unknown',
            last_accessed   TEXT,
            last_modified   TEXT,
            is_duplicate    INTEGER DEFAULT 0,
            duplicate_group TEXT,
            protected       INTEGER DEFAULT 0,
            in_trash        INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_meta (
            scan_id         TEXT PRIMARY KEY,
            started_at      TEXT,
            finished_at     TEXT,
            status          TEXT,
            drives          TEXT,
            total_files     INTEGER DEFAULT 0,
            total_size      INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trash_log (
            id              TEXT PRIMARY KEY,
            file_id         TEXT,
            original_path   TEXT NOT NULL,
            size            INTEGER DEFAULT 0,
            risk            TEXT,
            trashed_at      TEXT NOT NULL,
            method          TEXT,
            restored        INTEGER DEFAULT 0,
            restored_at     TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_category  ON files(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_risk       ON files(risk)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_size       ON files(size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_scan_id    ON files(scan_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_duplicate  ON files(is_duplicate, duplicate_group)")
    # Compound covering indexes for dashboard filter + sort queries
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_size ON files(in_trash, protected, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_risk ON files(in_trash, protected, risk, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_cat  ON files(in_trash, protected, category, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_dup  ON files(in_trash, protected, is_duplicate, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_path ON files(in_trash, protected, path)")
    conn.commit()


INSERT_SQL = (
    "INSERT OR REPLACE INTO files "
    "(id,scan_id,path,drive,size,risk,risk_reason,type,category,"
    "last_accessed,last_modified,protected,is_duplicate,in_trash) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def scan(db_path: str, progress_q: queue.Queue, cancel_flag) -> None:
    """
    Main scan function. Runs in a background thread.
    Writes results to SQLite. Emits SSE events via progress_q.
    """
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    targets = _get_scan_targets()

    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    _init_db(conn)

    # Clear previous scan data
    conn.execute("DELETE FROM files")
    conn.commit()

    conn.execute(
        "INSERT OR REPLACE INTO scan_meta (scan_id,started_at,status,drives,total_files,total_size) "
        "VALUES (?,?,?,?,?,?)",
        (scan_id, started_at, "scanning", json.dumps(targets), 0, 0),
    )
    conn.commit()

    total_files = 0
    total_size = 0
    batch = []
    drives_done = []

    # -----------------------------------------------------------------------
    # Phase 1: Walk file system
    # -----------------------------------------------------------------------
    for target_idx, root in enumerate(targets):
        drive = os.path.splitdrive(root)[0].upper().rstrip(":\\") or "C"
        phase_label = f"Scanning {root}"
        _files_at_target_start = total_files

        n_targets = max(len(targets), 1)
        band_start = int((target_idx / n_targets) * 70)
        _emit(progress_q, {
            "phase": phase_label,
            "drive": drive,
            "pct": band_start,
            "files_found": total_files,
            "current_path": root,
            "status": "scanning",
        })

        try:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=None):
                if cancel_flag.is_set():
                    break

                # Prune protected directories (modifies in place)
                dirnames[:] = [
                    d for d in dirnames
                    if not is_protected(os.path.join(dirpath, d))
                ]

                for fname in filenames:
                    if cancel_flag.is_set():
                        break

                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.stat(fpath)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue

                    size = st.st_size
                    last_accessed = datetime.fromtimestamp(st.st_atime, tz=timezone.utc).isoformat()
                    last_modified = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()

                    cls = classify(fpath, size, st)

                    batch.append((
                        str(uuid.uuid4()), scan_id, fpath, drive, size,
                        cls["risk"], cls["risk_reason"], cls["type"], cls["category"],
                        last_accessed, last_modified,
                        1 if cls["protected"] else 0,
                        0,   # is_duplicate (set in phase 2)
                        1 if cls["category"] == "Trash" else 0,  # in_trash
                    ))

                    total_files += 1
                    total_size += size

                    if len(batch) >= BATCH_SIZE:
                        conn.executemany(INSERT_SQL, batch)
                        conn.commit()
                        batch.clear()

                    if total_files % PROGRESS_EVERY == 0:
                        n_targets = max(len(targets), 1)
                        band_start = int((target_idx / n_targets) * 70)
                        band_size = int((1 / n_targets) * 70)
                        # Linear: advance 1 step per 10 k files, never saturates early
                        files_in_target = total_files - _files_at_target_start
                        within = min(band_size - 1, files_in_target // 10_000)
                        pct = band_start + within
                        _emit(progress_q, {
                            "phase": phase_label,
                            "drive": drive,
                            "pct": pct,
                            "files_found": total_files,
                            "current_path": dirpath,
                            "status": "scanning",
                        })

        except Exception:
            pass

        drives_done.append(drive)

    if batch:
        conn.executemany(INSERT_SQL, batch)
        conn.commit()
        batch.clear()

    if cancel_flag.is_set():
        conn.execute(
            "UPDATE scan_meta SET status=?, finished_at=?, total_files=?, total_size=? WHERE scan_id=?",
            ("cancelled", datetime.now(timezone.utc).isoformat(), total_files, total_size, scan_id),
        )
        conn.commit()
        conn.close()
        _emit(progress_q, {"phase": "Cancelled", "pct": 0, "files_found": total_files, "status": "cancelled"})
        return

    # -----------------------------------------------------------------------
    # Phase 2: Duplicate detection (size → partial hash → full hash)
    # -----------------------------------------------------------------------
    _emit(progress_q, {
        "phase": "Detecting duplicates",
        "pct": 72,
        "files_found": total_files,
        "status": "scanning",
    })

    # Find size candidates
    rows = conn.execute(
        "SELECT size, COUNT(*) as cnt FROM files WHERE size >= ? AND protected=0 "
        "GROUP BY size HAVING cnt > 1",
        (DUPLICATE_MIN_SIZE,),
    ).fetchall()

    MAX_CANDIDATES_PER_SIZE = 2000   # skip degenerate groups (e.g. 50K files of same size)
    dup_count = 0
    for (size, _) in rows:
        if cancel_flag.is_set():
            break
        candidates = conn.execute(
            "SELECT id, path FROM files WHERE size=? AND protected=0 LIMIT ?",
            (size, MAX_CANDIDATES_PER_SIZE + 1),
        ).fetchall()
        if len(candidates) > MAX_CANDIDATES_PER_SIZE:
            continue  # common size — not real duplicates, skip to avoid hashing thousands of files

        # Partial hash grouping
        partial_groups: dict[str, list] = {}
        for (fid, fpath) in candidates:
            ph = _partial_hash(fpath)
            if ph:
                partial_groups.setdefault(ph, []).append((fid, fpath))

        # Full hash on partial hash collisions
        for partial, group in partial_groups.items():
            if len(group) < 2:
                continue
            full_groups: dict[str, list] = {}
            for (fid, fpath) in group:
                fh = _full_hash(fpath)
                if fh:
                    full_groups.setdefault(fh, []).append((fid, fpath))

            for fh, dupes in full_groups.items():
                if len(dupes) < 2:
                    continue
                group_id = fh[:12]
                for (fid, _) in dupes:
                    conn.execute(
                        "UPDATE files SET is_duplicate=1, duplicate_group=?, category='Duplicates' WHERE id=?",
                        (group_id, fid),
                    )
                    dup_count += 1
        conn.commit()

    # -----------------------------------------------------------------------
    # Phase 3: Update Large Files category where size >= threshold
    # -----------------------------------------------------------------------
    _emit(progress_q, {
        "phase": "Categorising large files",
        "pct": 88,
        "files_found": total_files,
        "status": "scanning",
    })
    conn.execute(
        "UPDATE files SET category='Large Files' WHERE size >= ? AND risk IN ('LOW','MEDIUM') "
        "AND is_duplicate=0 AND category NOT IN ('Cache & Junk','Duplicates')",
        (LARGE_FILE_MIN,),
    )
    conn.commit()

    # -----------------------------------------------------------------------
    # Finalise
    # -----------------------------------------------------------------------
    finished_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE scan_meta SET status=?, finished_at=?, total_files=?, total_size=? WHERE scan_id=?",
        ("complete", finished_at, total_files, total_size, scan_id),
    )
    conn.commit()
    conn.close()

    _emit(progress_q, {
        "phase": "Complete",
        "pct": 100,
        "files_found": total_files,
        "duplicates_found": dup_count,
        "total_size": total_size,
        "status": "complete",
    })
