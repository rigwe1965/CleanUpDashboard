"""
server.py — Local HTTP server for the disk cleanup dashboard.
Python 3 stdlib only. No pip required.

Run:
    python server.py
Opens http://localhost:8765 automatically.
"""

import json
import os
import queue
import shutil
import sqlite3
import sys
import threading
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

import recycle as rc
from classifier import is_protected

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("CLEANUP_PORT", "8765"))
DB_PATH = os.environ.get("CLEANUP_DB") or os.path.join(os.path.dirname(__file__), "scan_results.db")
DASHBOARD_HTML = os.path.join(os.path.dirname(__file__), "dashboard.html")
PAGE_SIZE = 100
LARGE_FILE_MIN = 100 * 1024 * 1024   # 100 MB — must match scanner.py
RECONCILE_TTL = float(os.environ.get("CLEANUP_RECONCILE_TTL", "15"))   # seconds between trash-list syncs with the Recycle Bin


# ---------------------------------------------------------------------------
# Application State (module-level singleton)
# ---------------------------------------------------------------------------
class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.scan_thread: threading.Thread | None = None
        self.scan_status = "idle"          # idle | scanning | complete | error | cancelled
        self.scan_pct = 0
        self.scan_files_found = 0
        self.scan_phase = ""
        self.scan_id = ""
        self.progress_queue: queue.Queue = queue.Queue(maxsize=200)
        self.cancel_flag = threading.Event()
        self.db_path = DB_PATH
        self.sse_clients: list[queue.Queue] = []
        self.sse_lock = threading.Lock()
        self.reclaim_job: dict = {"status": "idle", "succeeded": 0, "total": 0, "failed_count": 0}
        self.reclaim_job_lock = threading.Lock()
        # Summary cache — avoids re-running 8 DB queries on every 3-second poll
        self._summary_cache: dict = {}
        self._summary_cache_ts: float = 0.0
        self._summary_cache_lock = threading.Lock()
        self.last_reconcile: float = 0.0

    def is_scanning(self):
        with self.lock:
            return self.scan_status == "scanning"

    def add_sse_client(self, q):
        with self.sse_lock:
            self.sse_clients.append(q)

    def remove_sse_client(self, q):
        with self.sse_lock:
            try:
                self.sse_clients.remove(q)
            except ValueError:
                pass

    def broadcast(self, data: dict):
        with self.sse_lock:
            dead = []
            for cq in self.sse_clients:
                try:
                    cq.put_nowait(data)
                except queue.Full:
                    dead.append(cq)
            for cq in dead:
                try:
                    self.sse_clients.remove(cq)
                except ValueError:
                    pass


STATE = AppState()

# HTML cached at startup — avoids sync file I/O on every request thread.
# Restart server after editing dashboard.html to pick up changes.
_HTML_BYTES: bytes = b""

MAX_SSE_CLIENTS = 10


# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA cache_size=-65536")    # 64 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")    # temp tables in RAM
    conn.execute("PRAGMA mmap_size=536870912")  # 512 MB memory-mapped I/O
    conn.execute("PRAGMA read_uncommitted=1")   # safe in WAL: readers don't block writers
    return conn


def init_db():
    """Ensure tables exist (scanner creates them, but we need them ready for status checks)."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY, scan_id TEXT, path TEXT, drive TEXT,
            size INTEGER DEFAULT 0, risk TEXT DEFAULT 'HIGH',
            risk_reason TEXT DEFAULT '', type TEXT DEFAULT 'unknown',
            category TEXT DEFAULT 'Unknown',
            last_accessed TEXT, last_modified TEXT,
            is_duplicate INTEGER DEFAULT 0, duplicate_group TEXT,
            protected INTEGER DEFAULT 0, in_trash INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_meta (
            scan_id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT,
            status TEXT, drives TEXT, total_files INTEGER DEFAULT 0, total_size INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trash_log (
            id TEXT PRIMARY KEY, file_id TEXT, original_path TEXT NOT NULL,
            size INTEGER DEFAULT 0, risk TEXT, trashed_at TEXT NOT NULL,
            method TEXT, restored INTEGER DEFAULT 0, restored_at TEXT
        )
    """)
    # Compound covering indexes — make every filtered/sorted query fast
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_size ON files(in_trash, protected, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_risk ON files(in_trash, protected, risk, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_cat  ON files(in_trash, protected, category, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_dup  ON files(in_trash, protected, is_duplicate, size DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_active_path ON files(in_trash, protected, path)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_path        ON files(path)")
    conn.commit()
    conn.close()


def _invalidate_summary_cache():
    """Call after any write that changes summary data."""
    with STATE._summary_cache_lock:
        STATE._summary_cache_ts = 0.0


def db_summary() -> dict:
    # Return cached result if fresh (10-second TTL).
    # The GROUP BY queries take ~800ms on warm cache, so a 2s TTL was too tight —
    # the prewarm result would expire before the first browser request arrived.
    with STATE._summary_cache_lock:
        if STATE._summary_cache and (time.monotonic() - STATE._summary_cache_ts) < 10.0:
            return dict(STATE._summary_cache)
        # Mark cache as being refreshed so concurrent requests return stale data
        # instead of all piling into DB queries at once.
        refreshing = STATE._summary_cache_ts == -1.0
        if not refreshing:
            STATE._summary_cache_ts = -1.0  # sentinel: refresh in progress

    if refreshing:
        # Another thread is already refreshing — return stale data if available
        with STATE._summary_cache_lock:
            if STATE._summary_cache:
                return dict(STATE._summary_cache)

    try:
        conn = get_db()
        # Totals by risk
        risk_rows = conn.execute(
            "SELECT risk, COUNT(*) as cnt, SUM(size) as total FROM files "
            "WHERE in_trash=0 AND protected=0 GROUP BY risk"
        ).fetchall()
        by_risk = {r["risk"]: {"count": r["cnt"], "size": r["total"] or 0} for r in risk_rows}

        # Totals by category — cache_count and dup_count derived from this, not separate queries
        cat_rows = conn.execute(
            "SELECT category, COUNT(*) as cnt, SUM(size) as total FROM files "
            "WHERE in_trash=0 AND protected=0 GROUP BY category"
        ).fetchall()
        by_cat = {r["category"]: {"count": r["cnt"], "size": r["total"] or 0} for r in cat_rows}

        # Totals by type (temp, cache, log, etc.) — sorted by count desc
        type_rows = conn.execute(
            "SELECT type, COUNT(*) as cnt FROM files "
            "WHERE in_trash=0 AND protected=0 AND type IS NOT NULL AND type != '' "
            "GROUP BY type ORDER BY cnt DESC"
        ).fetchall()
        by_type = {r["type"]: r["cnt"] for r in type_rows}

        # Top consumers
        top = conn.execute(
            "SELECT path, size FROM files WHERE in_trash=0 AND protected=0 "
            "ORDER BY size DESC LIMIT 10"
        ).fetchall()

        # Meta
        meta = conn.execute(
            "SELECT * FROM scan_meta ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

        # Trash count and large_count need dedicated queries;
        # cache_count and dup_count are derived from by_cat above (saves 2 queries).
        trash_count = conn.execute(
            "SELECT COUNT(*) FROM trash_log WHERE restored=0 AND method='recycle'"
        ).fetchone()[0]
        large_count = conn.execute(
            "SELECT COUNT(*) FROM files WHERE in_trash=0 AND protected=0 AND size >= ?",
            (LARGE_FILE_MIN,),
        ).fetchone()[0]

        conn.close()

        cache_count = by_cat.get("Cache & Junk", {}).get("count", 0)
        dup_count   = by_cat.get("Duplicates",   {}).get("count", 0)

        reclaimable = sum(
            by_risk.get(r, {}).get("size", 0) for r in ("SAFE", "LOW", "MEDIUM")
        )

        # Free disk space per scanned drive root
        drive_space = {}
        if meta and meta["drives"]:
            try:
                drives_list = json.loads(meta["drives"])
                for drive_path in drives_list:
                    root = drive_path[:3]  # e.g. "C:\"
                    try:
                        import ctypes
                        # DRIVE_FIXED=3 — skip network/remote drives (e.g. Google Drive H:\)
                        # which can hang for 2-3s on disk_usage when disconnected.
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
                        if drive_type == 3:
                            usage = shutil.disk_usage(root)
                            drive_space[root] = {"free": usage.free, "total": usage.total}
                    except Exception:
                        pass
            except Exception:
                pass

        result = {
            "by_risk": by_risk,
            "by_category": by_cat,
            "by_type": by_type,
            "reclaimable": reclaimable,
            "top_consumers": [dict(r) for r in top],
            "scan_meta": dict(meta) if meta else {},
            "trash_count": trash_count,
            "cache_count": cache_count,
            "dup_count": dup_count,
            "large_count": large_count,
            "drive_space": drive_space,
        }

        with STATE._summary_cache_lock:
            STATE._summary_cache = result
            STATE._summary_cache_ts = time.monotonic()
        return result
    except Exception as e:
        # Reset sentinel so next request tries again
        with STATE._summary_cache_lock:
            if STATE._summary_cache_ts == -1.0:
                STATE._summary_cache_ts = 0.0
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Trash helpers — the Trash tab is a view of trash_log (survives re-scans)
# ---------------------------------------------------------------------------
def _clean_ids(ids) -> list:
    if not isinstance(ids, list):
        return []
    return [i for i in ids if isinstance(i, str) and 1 <= len(i) <= 64 and i.replace("-", "").isalnum()]


def _trash_entries(ids: list | None = None) -> list:
    """Unrestored Recycle Bin entries from trash_log (optionally just the given ids)."""
    conn = get_db()
    try:
        if ids is None:
            rows = conn.execute(
                "SELECT id,original_path,trashed_at,size FROM trash_log WHERE restored=0 AND method='recycle'"
            ).fetchall()
        else:
            rows = []
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                ph = ",".join("?" * len(part))
                rows += conn.execute(
                    f"SELECT id,original_path,trashed_at,size FROM trash_log "
                    f"WHERE restored=0 AND method='recycle' AND id IN ({ph})", part
                ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _epoch(iso: str) -> float | None:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except Exception:
        return None


def _group_by_path(entries: list) -> list:
    """[(original_path, [trashed_at_epoch, ...])] — one item per distinct path."""
    grouped: dict = {}
    for e in entries:
        t = _epoch(e["trashed_at"])
        grouped.setdefault(e["original_path"], [])
        if t is not None:
            grouped[e["original_path"]].append(t)
    return [(p, ts or None) for p, ts in grouped.items()]


def reconcile_trash_log(force: bool = False) -> None:
    """Drop trash_log entries whose item is no longer in the Recycle Bin (restored or emptied
    outside this app). Only drives whose bin could actually be read are judged."""
    if not force and time.monotonic() - STATE.last_reconcile < RECONCILE_TTL:
        return
    STATE.last_reconcile = time.monotonic()
    try:
        entries = _trash_entries()
        if not entries:
            return
        drives = {rc._drive_root(e["original_path"]) for e in entries if os.path.splitdrive(e["original_path"])[0]}
        index, readable = rc.build_bin_index(drives)
        stale = [e for e in entries
                 if rc._drive_root(e["original_path"]) in readable
                 and rc.path_key(e["original_path"]) not in index]
        if not stale:
            return
        conn = get_db()
        conn.executemany("DELETE FROM trash_log WHERE id=?", [(e["id"],) for e in stale])
        back = [(e["original_path"],) for e in stale if os.path.exists(e["original_path"])]
        conn.executemany("UPDATE files SET in_trash=0 WHERE path=?", back)
        conn.commit()
        conn.close()
        _invalidate_summary_cache()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Background scan launcher
# ---------------------------------------------------------------------------
def _run_scan():
    import scanner as sc
    try:
        sc.scan(DB_PATH, STATE.progress_queue, STATE.cancel_flag)
    except Exception as e:
        STATE.progress_queue.put({"phase": f"Error: {e}", "pct": 0, "status": "error"})


def _progress_dispatcher():
    """Reads from STATE.progress_queue and broadcasts to all SSE clients."""
    while True:
        try:
            event = STATE.progress_queue.get(timeout=1)
            # Update state
            with STATE.lock:
                STATE.scan_phase = event.get("phase", STATE.scan_phase)
                STATE.scan_pct = event.get("pct", STATE.scan_pct)
                STATE.scan_files_found = event.get("files_found", STATE.scan_files_found)
                status = event.get("status", "scanning")
                STATE.scan_status = status

            STATE.broadcast(event)
        except queue.Empty:
            # If scanning thread is dead but we think we're scanning, check
            with STATE.lock:
                if STATE.scan_status == "scanning" and STATE.scan_thread and not STATE.scan_thread.is_alive():
                    STATE.scan_status = "complete"
        except Exception:
            time.sleep(0.1)


# ---------------------------------------------------------------------------
# Background reclaim job
# ---------------------------------------------------------------------------
def _sync_trashed(conn, paths: list, meta: dict) -> None:
    """Mark paths as trashed in the files table and log them in trash_log."""
    now_ts = datetime.now(timezone.utc).isoformat()
    log_rows = []
    for p in paths:
        fid, size, risk = meta.get(p, (None, 0, None))
        log_rows.append((str(uuid.uuid4()), fid, p, size, risk, now_ts, "recycle", 0, None))
    conn.executemany("UPDATE files SET in_trash=1 WHERE path=?", [(p,) for p in paths])
    conn.executemany(
        "INSERT OR IGNORE INTO trash_log "
        "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        log_rows,
    )
    conn.commit()


def _run_reclaim_bg(risks: list) -> None:
    """Recycle SAFE/LOW files in batches. rc.recycle_files decides each file's outcome
    from what is actually on disk, so a partly-successful batch is never miscounted."""
    BATCH_SIZE = 25
    DB_SYNC_INTERVAL = 50
    try:
        conn = get_db()
        ph = ",".join("?" * len(risks))
        rows = conn.execute(
            f"SELECT id,path,size,risk FROM files WHERE in_trash=0 AND protected=0 AND risk IN ({ph})",
            risks,
        ).fetchall()
    except Exception as e:
        with STATE.reclaim_job_lock:
            STATE.reclaim_job.update({"status": "error", "error": str(e)})
        return

    meta = {r["path"]: (r["id"], r["size"], r["risk"]) for r in rows}
    all_paths = [r["path"] for r in rows if os.path.isfile(r["path"]) and rc._safety_check(r["path"])[0]]
    with STATE.reclaim_job_lock:
        STATE.reclaim_job["total"] = len(all_paths)

    succeeded: list[str] = []
    failed_count = 0
    db_synced = 0
    db_error = ""

    for i in range(0, len(all_paths), BATCH_SIZE):
        chunk = all_paths[i:i + BATCH_SIZE]
        ok_paths, fail_paths = rc.recycle_files(chunk)
        succeeded.extend(ok_paths)
        failed_count += len(fail_paths)

        if len(succeeded) - db_synced >= DB_SYNC_INTERVAL:
            try:
                _sync_trashed(conn, succeeded[db_synced:], meta)
                db_synced = len(succeeded)
            except Exception as e:
                db_error = str(e)

        with STATE.reclaim_job_lock:
            STATE.reclaim_job["succeeded"] = len(succeeded)
            STATE.reclaim_job["failed_count"] = failed_count

    if len(succeeded) > db_synced:
        try:
            _sync_trashed(conn, succeeded[db_synced:], meta)
        except Exception as e:
            db_error = str(e)

    conn.close()
    _invalidate_summary_cache()
    with STATE.reclaim_job_lock:
        STATE.reclaim_job.update({
            "status": "complete",
            "succeeded": len(succeeded),
            "failed_count": failed_count,
        })
        if db_error:
            STATE.reclaim_job["error"] = f"Files were moved but the list could not be updated: {db_error}"


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress access log noise

    def log_error(self, format, *args):
        print(f"[ERROR] {format % args}", file=sys.stderr)

    # -----------------------------------------------------------------------
    def do_OPTIONS(self):
        self._send_cors()
        self.end_headers()

    def _send_cors(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", f"http://localhost:{PORT}")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", f"http://localhost:{PORT}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _validate_origin(self) -> bool:
        """Reject cross-origin POST/DELETE — simple CSRF mitigation for localhost server."""
        origin = self.headers.get("Origin", "")
        if not origin:
            return True  # non-browser clients (curl, scripts) send no Origin
        return origin in {f"http://localhost:{PORT}", f"http://127.0.0.1:{PORT}"}

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _parse_qs(self) -> dict:
        parsed = urlparse(self.path)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    # -----------------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path in ("/", "/index.html"):
            self._serve_html()
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/scan/progress":
            self._handle_sse()
        elif path == "/api/results":
            self._handle_results()
        elif path == "/api/summary":
            self._handle_summary()
        elif path == "/api/reclaim/preview":
            self._handle_reclaim_preview()
        elif path == "/api/reclaim/status":
            self._handle_reclaim_status()
        elif path == "/api/trash":
            self._handle_trash_list()
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._validate_origin():
            self._json({"error": "Forbidden"}, 403)
            return
        path = urlparse(self.path).path.rstrip("/")

        if path == "/api/scan/start":
            self._handle_scan_start()
        elif path == "/api/scan/cancel":
            self._handle_scan_cancel()
        elif path == "/api/delete":
            self._handle_delete()
        elif path == "/api/trash/restore":
            self._handle_restore()
        elif path == "/api/trash/remove":
            self._handle_trash_remove()
        elif path == "/api/trash/clear":
            self._handle_trash_clear()
        elif path == "/api/reclaim":
            self._handle_reclaim()
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        if not self._validate_origin():
            self._json({"error": "Forbidden"}, 403)
            return
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/delete":
            self._handle_delete()
        else:
            self._json({"error": "not found"}, 404)

    # -----------------------------------------------------------------------
    def _serve_html(self):
        if not _HTML_BYTES:
            self._json({"error": "dashboard.html not found"}, 404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(_HTML_BYTES)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(_HTML_BYTES)

    def _handle_status(self):
        with STATE.lock:
            self._json({
                "status": STATE.scan_status,
                "pct": STATE.scan_pct,
                "phase": STATE.scan_phase,
                "files_found": STATE.scan_files_found,
            })

    def _handle_scan_start(self):
        with STATE.lock:
            if STATE.scan_status == "scanning":
                self._json({"error": "Scan already running"}, 409)
                return

            STATE.cancel_flag.clear()
            STATE.scan_status = "scanning"
            STATE.scan_pct = 0
            STATE.scan_files_found = 0
            STATE.scan_phase = "Starting…"
            STATE.scan_id = str(uuid.uuid4())

            t = threading.Thread(target=_run_scan, daemon=True)
            STATE.scan_thread = t
            t.start()

        self._json({"ok": True, "scan_id": STATE.scan_id})

    def _handle_scan_cancel(self):
        STATE.cancel_flag.set()
        self._json({"ok": True})

    def _handle_sse(self):
        """Server-Sent Events endpoint for scan progress."""
        with STATE.sse_lock:
            if len(STATE.sse_clients) >= MAX_SSE_CLIENTS:
                self._json({"error": "Too many SSE connections"}, 429)
                return
        client_q: queue.Queue = queue.Queue(maxsize=100)
        STATE.add_sse_client(client_q)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        # If scan already complete, send one event and close
        with STATE.lock:
            current_status = STATE.scan_status

        if current_status in ("complete", "idle"):
            try:
                payload = json.dumps({"status": current_status, "pct": STATE.scan_pct})
                self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.flush()
            except Exception:
                pass
            STATE.remove_sse_client(client_q)
            return

        try:
            while True:
                try:
                    event = client_q.get(timeout=15)
                    payload = json.dumps(event)
                    self.wfile.write(f"data: {payload}\n\n".encode())
                    self.wfile.flush()
                    if event.get("status") in ("complete", "error", "cancelled"):
                        break
                except queue.Empty:
                    # Send keepalive comment
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass
        finally:
            STATE.remove_sse_client(client_q)

    def _handle_trash_results(self, qs: dict, sort: str, direction: str, page: int):
        """Trash tab: Recycle Bin items this app trashed (from trash_log)."""
        reconcile_trash_log()
        col = {"size": "size", "path": "original_path", "risk": "COALESCE(risk,'')",
               "type": "method", "category": "method",
               "last_accessed": "trashed_at", "last_modified": "trashed_at"}[sort]
        where, params = ["restored=0", "method='recycle'"], []
        risk = qs.get("risk", "").upper()
        if risk in ("SAFE", "LOW", "MEDIUM", "HIGH"):
            where.append("risk=?")
            params.append(risk)
        drive = qs.get("drive", "")
        if drive and len(drive) == 1 and drive.isalpha():
            where.append("UPPER(SUBSTR(original_path,1,1))=?")
            params.append(drive.upper())
        if qs.get("q"):
            where.append("LOWER(original_path) LIKE ?")
            params.append(f"%{qs['q'].lower()}%")
        where_sql = " AND ".join(where)
        conn = get_db()
        total = conn.execute(f"SELECT COUNT(*) FROM trash_log WHERE {where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT id,original_path,size,risk,trashed_at FROM trash_log WHERE {where_sql} "
            f"ORDER BY {col} {direction} LIMIT ? OFFSET ?",
            params + [PAGE_SIZE, page * PAGE_SIZE],
        ).fetchall()
        conn.close()
        results = [{
            "id": r["id"], "path": r["original_path"], "drive": r["original_path"][:1].upper(),
            "size": r["size"] or 0, "risk": r["risk"] or "UNKNOWN", "risk_reason": "",
            "type": "trash", "category": "Trash",
            "last_accessed": r["trashed_at"], "last_modified": r["trashed_at"],
            "is_duplicate": 0, "duplicate_group": None, "in_trash": 1,
        } for r in rows]
        self._json({"total": total, "page": page, "page_size": PAGE_SIZE, "results": results})

    def _handle_results(self):
        qs = self._parse_qs()
        tab = qs.get("tab", "all")
        risk = qs.get("risk", "")
        q = qs.get("q", "")
        sort = qs.get("sort", "size")
        direction = qs.get("dir", "desc")
        try:
            page = max(0, int(qs.get("page", "0")))
        except ValueError:
            page = 0

        allowed_sorts = {"size", "risk", "type", "category", "last_accessed", "last_modified", "path"}
        if sort not in allowed_sorts:
            sort = "size"
        direction = "DESC" if direction.lower() != "asc" else "ASC"

        try:
            if tab == "trash":
                self._handle_trash_results(qs, sort, direction, page)
                return
            conn = get_db()
            where_parts = ["in_trash=0", "protected=0"]
            params: list = []

            if tab == "cache":
                where_parts.append("category='Cache & Junk'")
            elif tab == "duplicates":
                where_parts.append("is_duplicate=1")
            elif tab == "large":
                where_parts.append("size >= ?")
                params.append(LARGE_FILE_MIN)

            if risk and risk.upper() in ("SAFE", "LOW", "MEDIUM", "HIGH"):
                where_parts.append("risk=?")
                params.append(risk.upper())

            type_filter = qs.get("type", "")
            if type_filter:
                where_parts.append("type=?")
                params.append(type_filter.lower())

            drive = qs.get("drive", "")
            if drive and len(drive) == 1 and drive.isalpha():
                where_parts.append("drive=?")
                params.append(drive.upper())

            if q:
                where_parts.append("LOWER(path) LIKE ?")
                params.append(f"%{q.lower()}%")

            where_sql = " AND ".join(where_parts)
            offset = page * PAGE_SIZE

            total = conn.execute(f"SELECT COUNT(*) FROM files WHERE {where_sql}", list(params)).fetchone()[0]
            rows = conn.execute(
                f"SELECT id,path,drive,size,risk,risk_reason,type,category,"
                f"last_accessed,last_modified,is_duplicate,duplicate_group,in_trash "
                f"FROM files WHERE {where_sql} "
                f"ORDER BY {sort} {direction} LIMIT ? OFFSET ?",
                params + [PAGE_SIZE, offset],
            ).fetchall()
            conn.close()

            self._json({
                "total": total,
                "page": page,
                "page_size": PAGE_SIZE,
                "results": [dict(r) for r in rows],
            })
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_summary(self):
        self._json(db_summary())

    def _handle_trash_list(self):
        try:
            conn = get_db()
            rows = conn.execute(
                "SELECT * FROM trash_log ORDER BY trashed_at DESC LIMIT 200"
            ).fetchall()
            conn.close()
            self._json({"trash": [dict(r) for r in rows]})
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_delete(self):
        """Delete active files: to the Recycle Bin (default) or permanently (permanent=true)."""
        body = self._read_body()
        ids = body.get("ids", [])
        permanent = body.get("permanent") is True

        if not isinstance(ids, list) or not ids:
            self._json({"error": "No ids provided"}, 400)
            return

        # Validate IDs — must be non-empty alphanumeric strings (UUIDs); reject anything else.
        ids = [i for i in ids if isinstance(i, str) and 1 <= len(i) <= 64 and i.replace("-", "").isalnum()]
        if not ids:
            self._json({"error": "No valid ids provided"}, 400)
            return

        try:
            conn = get_db()
            rows = []
            for i in range(0, len(ids), 500):
                part = ids[i:i + 500]
                ph = ",".join("?" * len(part))
                rows += conn.execute(
                    f"SELECT id,path,size,risk FROM files WHERE in_trash=0 AND id IN ({ph})", part
                ).fetchall()
            conn.close()
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return

        found = {r["id"] for r in rows}
        failed = [{"path": i, "reason": "Not in the current scan results"} for i in ids if i not in found]
        paths = [r["path"] for r in rows]
        meta = {r["path"]: (r["id"], r["size"], r["risk"]) for r in rows}

        try:
            if permanent:
                result = rc.permanently_delete(paths, DB_PATH)
            else:
                result = rc.send_to_recycle_bin(paths, DB_PATH, meta)
        except Exception as e:
            result = {"succeeded": [], "failed": [{"path": p, "reason": str(e)} for p in paths], "missing": []}

        succeeded = result.get("succeeded", [])
        failed += result.get("failed", [])

        # Reflect the real on-disk outcome in the list.
        db_error = ""
        if succeeded:
            try:
                conn = get_db()
                sql = ("DELETE FROM files WHERE path=?" if permanent
                       else "UPDATE files SET in_trash=1 WHERE path=?")
                conn.executemany(sql, [(p,) for p in succeeded])
                conn.commit()
                conn.close()
            except Exception as e:
                db_error = str(e)
                failed.append({"path": "list update", "reason": f"Files were processed but the list could not be updated: {e}"})

        _invalidate_summary_cache()
        self._json({
            "ok": len(failed) == 0,
            "succeeded": succeeded,
            "failed": failed,
            "missing": result.get("missing", []),
            "db_error": db_error,
        })

    def _handle_restore(self):
        """Restore Recycle Bin items back to their original location. Accepts id or ids."""
        body = self._read_body()
        ids = body.get("ids") or ([body["id"]] if body.get("id") else [])
        ids = _clean_ids(ids)
        if not ids:
            self._json({"error": "No id provided"}, 400)
            return

        try:
            entries = _trash_entries(ids)
            if not entries:
                self._json({"error": "Item is no longer in the trash list"}, 404)
                return
            result = rc.restore_from_recycle_bin(_group_by_path(entries))
            done = set(result["succeeded"])
            now = datetime.now(timezone.utc).isoformat()
            conn = get_db()
            restored_ids = [e["id"] for e in entries if e["original_path"] in done]
            conn.executemany("UPDATE trash_log SET restored=1, restored_at=? WHERE id=?",
                             [(now, i) for i in restored_ids])
            conn.executemany("UPDATE files SET in_trash=0 WHERE path=?", [(p,) for p in done])
            conn.commit()
            conn.close()
            _invalidate_summary_cache()
            self._json({
                "ok": result["ok"],
                "restored": len(restored_ids),
                "path": entries[0]["original_path"],
                "failed": result["failed"],
                "error": result["failed"][0]["reason"] if result["failed"] else "",
            })
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_reclaim_preview(self):
        try:
            conn = get_db()
            rows = conn.execute(
                "SELECT risk, COUNT(*) as cnt, SUM(size) as total FROM files "
                "WHERE in_trash=0 AND protected=0 AND risk IN ('SAFE','LOW','MEDIUM') "
                "GROUP BY risk"
            ).fetchall()
            conn.close()
            tiers = {r["risk"]: {"count": r["cnt"], "size": r["total"] or 0} for r in rows}
            self._json({"tiers": tiers})
        except Exception as e:
            self._json({"error": str(e)}, 500)

    def _handle_reclaim(self):
        """Start background reclaim job. Returns immediately — poll /api/reclaim/status."""
        body = self._read_body()
        risks = body.get("risks", ["SAFE"])
        allowed = {"SAFE", "LOW"}
        risks = [r.upper() for r in risks if r.upper() in allowed]
        if not risks:
            self._json({"error": "No valid risk levels"}, 400)
            return

        with STATE.reclaim_job_lock:
            if STATE.reclaim_job.get("status") == "running":
                self._json({"error": "Reclaim already running", "status": "running", "already_running": True}, 409)
                return
            STATE.reclaim_job = {"status": "running", "succeeded": 0, "total": 0, "failed_count": 0}

        threading.Thread(target=_run_reclaim_bg, args=(risks,), daemon=True).start()
        self._json({"ok": True, "status": "running"})

    def _handle_reclaim_status(self):
        with STATE.reclaim_job_lock:
            job = dict(STATE.reclaim_job)
        self._json(job)

    def _empty_bin_entries(self, entries: list) -> None:
        """Permanently delete the given trash_log entries from the Recycle Bin, then drop them
        from the list. Only items this app recycled are touched — never the whole bin."""
        try:
            result = rc.delete_from_recycle_bin(_group_by_path(entries))
            offline = set(result.get("unavailable", []))
            done = set(result["succeeded"]) | offline          # unreachable drive: drop from list only
            gone_ids = [e["id"] for e in entries if e["original_path"] in done]
            offline_n = len([e for e in entries if e["original_path"] in offline])
            conn = get_db()
            conn.executemany("DELETE FROM trash_log WHERE id=?", [(i,) for i in gone_ids])
            conn.executemany("DELETE FROM files WHERE path=? AND in_trash=1", [(p,) for p in done])
            conn.commit()
            conn.close()
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return
        _invalidate_summary_cache()
        STATE.last_reconcile = time.monotonic()
        self._json({
            "ok": result["ok"],
            "removed": len(gone_ids) - offline_n,
            "unavailable": offline_n,
            "bytes_freed": result["bytes_freed"],
            "failed": result["failed"],
        })

    def _handle_trash_clear(self):
        """Empty Trash: permanently delete every Recycle Bin item this app trashed."""
        try:
            entries = _trash_entries()
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return
        self._empty_bin_entries(entries)

    def _handle_trash_remove(self):
        """Permanently delete the selected trash items from the Recycle Bin (frees disk space)."""
        ids = _clean_ids(self._read_body().get("ids", []))
        if not ids:
            self._json({"error": "No ids provided"}, 400)
            return
        try:
            entries = _trash_entries(ids)
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return
        self._empty_bin_entries(entries)


# ---------------------------------------------------------------------------
# Threaded Server
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    global _HTML_BYTES
    try:
        with open(DASHBOARD_HTML, "rb") as f:
            _HTML_BYTES = f.read()
    except FileNotFoundError:
        print(f"[WARN] dashboard.html not found at {DASHBOARD_HTML}", file=sys.stderr)

    init_db()

    # A previous scan's results are still in the DB — show them instead of "No scan data".
    try:
        conn = get_db()
        last = conn.execute("SELECT status FROM scan_meta ORDER BY started_at DESC LIMIT 1").fetchone()
        conn.close()
        if last and last["status"] == "complete":
            STATE.scan_status = "complete"
            STATE.scan_pct = 100
    except Exception:
        pass

    # Start the progress dispatcher thread
    dispatcher = threading.Thread(target=_progress_dispatcher, daemon=True)
    dispatcher.start()

    # Pre-warm summary cache so the first browser request gets an instant response
    def _prewarm():
        try:
            db_summary()
        except Exception:
            pass
    threading.Thread(target=_prewarm, daemon=True).start()
    threading.Thread(target=lambda: reconcile_trash_log(force=True), daemon=True).start()

    server = ThreadedHTTPServer(("127.0.0.1", PORT), DashboardHandler)

    url = f"http://localhost:{PORT}"
    print(f"\n  Disk Cleanup Dashboard")
    print(f"  Ready at {url}")
    print(f"  Press Ctrl+C to stop\n")

    # Open browser after a short delay
    def _open_browser():
        time.sleep(0.8)
        webbrowser.open(url)

    if not os.environ.get("CLEANUP_NO_BROWSER"):
        threading.Thread(target=_open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
