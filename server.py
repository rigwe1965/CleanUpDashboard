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
PORT = 8765
DB_PATH = os.path.join(os.path.dirname(__file__), "scan_results.db")
DASHBOARD_HTML = os.path.join(os.path.dirname(__file__), "dashboard.html")
PAGE_SIZE = 100
LARGE_FILE_MIN = 100 * 1024 * 1024   # 100 MB — must match scanner.py


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


# ---------------------------------------------------------------------------
# DB Helpers
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA cache_size=-32000")   # 32 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")   # temp tables in RAM
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
            "SELECT COUNT(*) FROM files WHERE in_trash=1"
        ).fetchone()[0]
        large_count = conn.execute(
            f"SELECT COUNT(*) FROM files WHERE in_trash=0 AND protected=0 AND size >= {LARGE_FILE_MIN}"
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
def _run_reclaim_bg(risks: list) -> None:
    """Recycle SAFE/LOW files one at a time in a background thread.
    Batching 500+ files into a single SHFileOperationW call hangs — process
    files individually so locked/inaccessible files fail fast without blocking."""
    DB_SYNC_INTERVAL = 50   # write to DB every N successes
    try:
        conn = get_db()
        ph = ",".join("?" * len(risks))
        rows = conn.execute(
            f"SELECT path FROM files WHERE in_trash=0 AND protected=0 AND risk IN ({ph})",
            risks,
        ).fetchall()
        conn.close()
    except Exception as e:
        with STATE.reclaim_job_lock:
            STATE.reclaim_job.update({"status": "error", "error": str(e)})
        return

    # Pre-filter to files that actually exist on disk right now.
    all_paths = [r["path"] for r in rows
                 if os.path.isfile(r["path"]) and not is_protected(r["path"])]
    with STATE.reclaim_job_lock:
        STATE.reclaim_job["total"] = len(all_paths)

    succeeded: list[str] = []
    failed_count = 0
    db_synced = 0

    for p in all_paths:
        ok, _ = rc._recycle_paths_windows([p])
        if ok:
            succeeded.append(p)
        else:
            failed_count += 1

        # Persist DB every DB_SYNC_INTERVAL successes
        new_ok = succeeded[db_synced:]
        if len(new_ok) >= DB_SYNC_INTERVAL:
            try:
                conn = get_db()
                now_ts = datetime.now(timezone.utc).isoformat()
                conn.executemany("UPDATE files SET in_trash=1 WHERE path=?", [(p,) for p in new_ok])
                conn.executemany(
                    "INSERT OR IGNORE INTO trash_log "
                    "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    [(str(uuid.uuid4()), None, p, 0, None, now_ts, "recycle", 0, None) for p in new_ok],
                )
                conn.commit()
                conn.close()
                db_synced = len(succeeded)
            except Exception:
                pass

        with STATE.reclaim_job_lock:
            STATE.reclaim_job["succeeded"] = len(succeeded)
            STATE.reclaim_job["failed_count"] = failed_count

    # Final DB sync for any remaining succeeded files
    new_ok = succeeded[db_synced:]
    if new_ok:
        try:
            conn = get_db()
            now_ts = datetime.now(timezone.utc).isoformat()
            conn.executemany("UPDATE files SET in_trash=1 WHERE path=?", [(p,) for p in new_ok])
            conn.executemany(
                "INSERT OR IGNORE INTO trash_log "
                "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [(str(uuid.uuid4()), None, p, 0, None, now_ts, "recycle", 0, None) for p in new_ok],
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    _invalidate_summary_cache()
    with STATE.reclaim_job_lock:
        STATE.reclaim_job.update({
            "status": "complete",
            "succeeded": len(succeeded),
            "failed_count": failed_count,
        })


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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

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
        elif path == "/api/reclaim":
            self._handle_reclaim()
        else:
            self._json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path.rstrip("/")
        if path == "/api/delete":
            self._handle_delete()
        else:
            self._json({"error": "not found"}, 404)

    # -----------------------------------------------------------------------
    def _serve_html(self):
        try:
            with open(DASHBOARD_HTML, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self._json({"error": "dashboard.html not found"}, 404)

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

    def _handle_results(self):
        qs = self._parse_qs()
        tab = qs.get("tab", "all")
        risk = qs.get("risk", "")
        q = qs.get("q", "")
        sort = qs.get("sort", "size")
        direction = qs.get("dir", "desc")
        page = max(0, int(qs.get("page", "0")))

        allowed_sorts = {"size", "risk", "type", "category", "last_accessed", "last_modified", "path"}
        if sort not in allowed_sorts:
            sort = "size"
        direction = "DESC" if direction.lower() != "asc" else "ASC"

        try:
            conn = get_db()
            where_parts = ["in_trash=0", "protected=0"]
            params: list = []

            if tab == "cache":
                where_parts.append("category='Cache & Junk'")
            elif tab == "duplicates":
                where_parts.append("is_duplicate=1")
            elif tab == "large":
                where_parts.append(f"size >= {LARGE_FILE_MIN}")
            elif tab == "trash":
                where_parts.remove("in_trash=0")
                where_parts.append("in_trash=1")

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

            where_sql = " AND ".join(where_parts) if where_parts else "1=1"
            offset = page * PAGE_SIZE

            total = conn.execute(f"SELECT COUNT(*) FROM files WHERE {where_sql}", params).fetchone()[0]
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
        body = self._read_body()
        ids = body.get("ids", [])
        permanent = body.get("permanent", False)

        if not ids:
            self._json({"error": "No ids provided"}, 400)
            return

        # Resolve paths from DB — separate trash items from active items
        try:
            conn = get_db()
            placeholders = ",".join("?" * len(ids))
            rows = conn.execute(
                f"SELECT id,path,size,risk,in_trash FROM files WHERE id IN ({placeholders})",
                ids,
            ).fetchall()
            conn.close()
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return

        # Items already in trash: they're in Windows Recycle Bin — just remove from our DB
        trash_ids = [r["id"] for r in rows if r["in_trash"]]
        active_rows = [r for r in rows if not r["in_trash"]]

        succeeded = []
        failed = []

        # Remove trash-tab items from DB (they're already in Recycle Bin)
        if trash_ids:
            try:
                conn = get_db()
                ph = ",".join("?" * len(trash_ids))
                removed = conn.execute(f"SELECT path FROM files WHERE id IN ({ph})", trash_ids).fetchall()
                conn.execute(f"DELETE FROM files WHERE id IN ({ph})", trash_ids)
                conn.commit()
                conn.close()
                succeeded.extend([r["path"] for r in removed])
            except Exception as e:
                failed.append({"path": "trash items", "reason": str(e)})

        # Active items: send to Recycle Bin or permanently delete
        if active_rows:
            paths = [r["path"] for r in active_rows]
            try:
                if permanent:
                    result = rc.permanently_delete(paths, DB_PATH)
                else:
                    result = rc.send_to_recycle_bin(paths, DB_PATH)
            except Exception as e:
                result = {"succeeded": [], "failed": [{"path": p, "reason": str(e)} for p in paths]}

            succeeded.extend(result.get("succeeded", []))
            failed.extend(result.get("failed", []))

            # Mark active files in DB
            if result.get("succeeded"):
                try:
                    conn = get_db()
                    if permanent:
                        conn.executemany("DELETE FROM files WHERE path=?", [(p,) for p in result["succeeded"]])
                    else:
                        conn.executemany("UPDATE files SET in_trash=1 WHERE path=?", [(p,) for p in result["succeeded"]])
                    conn.commit()
                    conn.close()
                except Exception:
                    pass

        _invalidate_summary_cache()
        self._json({"ok": len(failed) == 0, "succeeded": succeeded, "failed": failed})

    def _handle_restore(self):
        body = self._read_body()
        file_id = body.get("id", "")
        if not file_id:
            self._json({"error": "No id provided"}, 400)
            return

        try:
            conn = get_db()
            row = conn.execute("SELECT path FROM files WHERE id=?", (file_id,)).fetchone()
            if not row:
                conn.close()
                self._json({"error": "File not found"}, 404)
                return
            path = row["path"]
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE files SET in_trash=0 WHERE id=?", (file_id,))
            conn.execute(
                "UPDATE trash_log SET restored=1, restored_at=? WHERE original_path=? AND restored=0",
                (now, path),
            )
            conn.commit()
            conn.close()
            _invalidate_summary_cache()
            self._json({"ok": True, "path": path})
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

    def _handle_trash_remove(self):
        """Remove trash records from the DB. Files are already in Windows Recycle Bin;
        scanning 200K+ $I files to find them hangs the server, so we skip that and just
        clean our tracking records. User can empty the Recycle Bin via Windows to free space."""
        body = self._read_body()
        ids = body.get("ids", [])
        if not ids:
            self._json({"error": "No ids provided"}, 400)
            return
        try:
            conn = get_db()
            ph = ",".join("?" * len(ids))
            rows = conn.execute(
                f"SELECT id, path FROM files WHERE id IN ({ph})", ids
            ).fetchall()
            paths = [r["path"] for r in rows]
            if paths:
                conn.execute(f"DELETE FROM files WHERE id IN ({ph})", ids)
                conn.executemany(
                    "DELETE FROM trash_log WHERE original_path=?",
                    [(p,) for p in paths],
                )
                conn.commit()
            conn.close()
        except Exception as e:
            self._json({"error": str(e)}, 500)
            return

        _invalidate_summary_cache()
        self._json({
            "ok": True,
            "removed": len(paths),
            "bytes_freed": 0,
            "failed": [],
        })


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
    init_db()

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

    server = ThreadedHTTPServer(("127.0.0.1", PORT), DashboardHandler)

    url = f"http://localhost:{PORT}"
    print(f"\n  Disk Cleanup Dashboard")
    print(f"  Ready at {url}")
    print(f"  Press Ctrl+C to stop\n")

    # Open browser after a short delay
    def _open_browser():
        time.sleep(0.8)
        webbrowser.open(url)

    threading.Thread(target=_open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
