"""
recycle.py — Safe file deletion via Windows Recycle Bin (SHFileOperationW).
Provides:
  send_to_recycle_bin(paths)  → reversible move to Recycle Bin
  permanently_delete(paths)   → zero-overwrite then unlink (secure wipe)
Never called automatically — only via POST /api/delete.
"""

import ctypes
import ctypes.wintypes
import os
import shutil
import sqlite3
import stat
import struct
import subprocess
import uuid
from datetime import datetime, timezone
from typing import NamedTuple

from classifier import is_protected, classify, has_system_attribute

# ---------------------------------------------------------------------------
# SHFILEOPSTRUCT constants
# ---------------------------------------------------------------------------
FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400


class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", ctypes.wintypes.HWND),
        ("wFunc", ctypes.wintypes.UINT),
        ("pFrom", ctypes.c_wchar_p),
        ("pTo", ctypes.c_wchar_p),
        ("fFlags", ctypes.wintypes.WORD),
        ("fAnyOperationsAborted", ctypes.wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", ctypes.c_wchar_p),
    ]


_SHFILEOPSTRUCT_ERRORS = {
    2:   "File not found",
    5:   "Access denied",
    32:  "File is in use by another application — close that app and retry",
    112: "Disk full",
    123: "Invalid file name",
    124: "File path invalid or inaccessible",
    1026: "Windows could not move the file to the Recycle Bin (in use, or path too long)",
}

MAX_SHELL_PATH = 259   # SHFileOperationW cannot handle longer paths
RECYCLE_BATCH = 100


def _recycle_paths_windows(paths: list[str]) -> tuple[bool, str]:
    """Call SHFileOperationW to move paths to Recycle Bin.
    COM must be initialised on the calling thread (worker threads from
    ThreadingMixIn are not COM-aware by default), so we call
    CoInitializeEx/CoUninitialize around the Shell operation.
    """
    # COINIT_APARTMENTTHREADED = 0x2, COINIT_MULTITHREADED = 0x0
    # S_OK = 0, S_FALSE = 1 (already initialised — still must Uninitialize)
    coinit_hr = ctypes.windll.ole32.CoInitializeEx(None, 0x2)
    try:
        combined = "\0".join(paths) + "\0\0"

        op = _SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        op.pFrom = combined
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        op.fAnyOperationsAborted = False
        op.hNameMappings = None
        op.lpszProgressTitle = None

        ret = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if ret != 0:
            msg = _SHFILEOPSTRUCT_ERRORS.get(ret, f"Windows error {ret}")
            return False, msg
        if op.fAnyOperationsAborted:
            return False, "Operation was aborted by the user"
        return True, ""
    finally:
        # Only call CoUninitialize if we actually initialised (not RPC_E_CHANGED_MODE)
        if coinit_hr in (0, 1):  # S_OK or S_FALSE
            ctypes.windll.ole32.CoUninitialize()


def _safety_check(path: str, stat_result=None) -> tuple[bool, str]:
    """Return (ok, reason). ok=False means refuse the delete."""
    # Resolve symlinks first — prevents symlink attacks that bypass protected-path checks.
    real = os.path.realpath(path)
    if not os.path.exists(real):
        return False, f"File not found: {path}"
    if not os.path.isfile(real):
        return False, f"Not a file (directories are not allowed): {path}"
    if is_protected(real) or is_protected(path):
        return False, f"Protected system data — never deleted: {path}"
    if "\\$recycle.bin\\" in real.lower():
        return False, f"Inside the Recycle Bin — manage it from the Trash tab: {path}"
    # Re-classify at delete time using the resolved real path. Fail closed: if the file
    # cannot be inspected it is not deleted.
    try:
        s = stat_result or os.stat(real)
        if has_system_attribute(s):
            return False, f"Windows system file (SYSTEM attribute) — never deleted: {path}"
        result = classify(real, s.st_size, s)
    except Exception as e:
        return False, f"Could not verify the file is safe to delete ({e}): {path}"
    if result.get("protected"):
        return False, f"Protected system data — never deleted: {path}"
    if result["risk"] == "HIGH" and not real.lower().endswith(".log"):
        return False, f"HIGH risk file — not touched: {path}"
    return True, ""


def recycle_files(paths: list[str]) -> tuple[list[str], list[dict]]:
    """
    Move already-vetted paths to the Recycle Bin and report the real outcome.
    Returns (succeeded, failed[{path, reason}]).

    SHFileOperationW can move some files and still return an error for the batch,
    so the verdict for every path is decided by whether it is still on disk, never
    by the batch return code alone.
    """
    succeeded: list[str] = []
    failed: list[dict] = []

    shell_paths = []
    for p in paths:
        if len(p) > MAX_SHELL_PATH:
            failed.append({"path": p, "reason": "Path is longer than 259 characters — Windows cannot move it to the Recycle Bin"})
        else:
            shell_paths.append(p)

    for i in range(0, len(shell_paths), RECYCLE_BATCH):
        chunk = shell_paths[i:i + RECYCLE_BATCH]
        _recycle_paths_windows(chunk)
        for p in chunk:
            if not os.path.lexists(p):
                succeeded.append(p)
                continue
            # Still there: retry on its own to isolate a locked file.
            ok, err = _recycle_paths_windows([p])
            if not os.path.lexists(p):
                succeeded.append(p)
            else:
                failed.append({"path": p, "reason": err or "File could not be moved to the Recycle Bin"})
    return succeeded, failed


def send_to_recycle_bin(paths: list[str], db_path: str, meta: dict | None = None) -> dict:
    """
    Move files to the Windows Recycle Bin (reversible).
    meta: optional {path: (file_id, size, risk)} used to enrich the trash_log.
    Returns {"ok": bool, "succeeded": [...], "failed": [...], "missing": [...]}
    "missing" paths were already gone from disk — they count as succeeded.
    No os.remove fallback — this function is reversible-only.
    """
    meta = meta or {}
    failed: list[dict] = []
    missing: list[str] = []
    safe: list[str] = []

    for p in paths:
        if not os.path.lexists(p):
            missing.append(p)
            continue
        ok, reason = _safety_check(p)
        if ok:
            safe.append(p)
        else:
            failed.append({"path": p, "reason": reason})

    sizes = {}
    for p in safe:
        try:
            sizes[p] = os.path.getsize(p)
        except Exception:
            sizes[p] = 0

    moved, move_failed = recycle_files(safe)
    failed.extend(move_failed)

    if moved and db_path:
        now_ts = datetime.now(timezone.utc).isoformat()
        entries = []
        for p in moved:
            fid, size, risk = meta.get(p, (None, sizes.get(p, 0), None))
            entries.append((str(uuid.uuid4()), fid, p, size or sizes.get(p, 0), risk, now_ts, "recycle", 0, None))
        try:
            conn = sqlite3.connect(db_path, timeout=15)
            conn.executemany(
                "INSERT OR IGNORE INTO trash_log "
                "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                entries,
            )
            conn.commit()
            conn.close()
        except Exception as e:
            failed.append({"path": "trash log", "reason": f"Files were moved but the trash log could not be written: {e}"})

    return {
        "ok": len(failed) == 0,
        "succeeded": moved + missing,
        "failed": failed,
        "missing": missing,
    }


def permanently_delete(paths: list[str], db_path: str) -> dict:
    """
    Permanently delete files (no Recycle Bin, no overwrite pass — it is a plain delete).
    Every path still goes through the same safety check as a recycle: protected system
    data and HIGH-risk files are refused. Read-only files are handled.
    Returns {"ok", "succeeded": [...], "failed": [{path, reason}], "missing": [...], "bytes_freed"}.
    "missing" paths were already gone — they count as succeeded.
    """
    succeeded: list[str] = []
    failed: list[dict] = []
    missing: list[str] = []
    freed = 0

    for p in paths:
        if not os.path.lexists(p):
            missing.append(p)
            continue
        ok, reason = _safety_check(p)
        if not ok:
            failed.append({"path": p, "reason": reason})
            continue
        try:
            size = os.path.getsize(p)
        except Exception:
            size = 0
        try:
            try:
                os.remove(p)
            except PermissionError:
                os.chmod(p, stat.S_IWRITE)      # read-only attribute
                os.remove(p)
        except FileNotFoundError:
            missing.append(p)
            continue
        except Exception as e:
            reason = "File is in use by another application — close it and retry" \
                if getattr(e, "winerror", None) in (32, 33) else f"Delete failed: {e}"
            failed.append({"path": p, "reason": reason})
            continue
        if os.path.lexists(p):
            failed.append({"path": p, "reason": "File is still present after delete"})
            continue
        succeeded.append(p)
        freed += size

    if succeeded and db_path:
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn = sqlite3.connect(db_path, timeout=15)
            conn.executemany(
                "INSERT OR IGNORE INTO trash_log "
                "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [(str(uuid.uuid4()), None, p, 0, None, now, "permanent", 0, None) for p in succeeded],
            )
            conn.commit()
            conn.close()
        except Exception:
            pass    # audit trail only — the files are already deleted

    return {
        "ok": len(failed) == 0,
        "succeeded": succeeded + missing,
        "failed": failed,
        "missing": missing,
        "bytes_freed": freed,
    }


# ---------------------------------------------------------------------------
# Recycle Bin access — find, restore and permanently delete items by $I/$R pair
# ---------------------------------------------------------------------------
_FILETIME_EPOCH = 116444736000000000   # 100-ns ticks between 1601-01-01 and 1970-01-01
_current_sid_cache: str | None = None

# trash_log is stamped just after the move (a reclaim syncs every ~50 files, so within minutes)
TRASH_TIME_BEFORE = 300
TRASH_TIME_AFTER = 60


class BinItem(NamedTuple):
    i_file: str        # $I metadata file
    r_file: str        # $R data file (or folder)
    path: str          # original path recorded by Windows
    size: int          # original size recorded by Windows
    deleted_at: float  # epoch seconds


def current_sid() -> str | None:
    """SID string of the user running this process (names the per-user bin folder)."""
    global _current_sid_cache
    if _current_sid_cache is None:
        try:
            exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "whoami.exe")
            out = subprocess.run([exe, "/user", "/fo", "csv", "/nh"], capture_output=True,
                                 text=True, timeout=10).stdout.strip()
            _current_sid_cache = out.split(",")[-1].strip().strip('"')
        except Exception:
            _current_sid_cache = ""
    return _current_sid_cache or None


def _bin_dir(drive_root: str) -> str | None:
    sid = current_sid()
    if not sid:
        return None
    d = os.path.join(drive_root, "$RECYCLE.BIN", sid)
    return d if os.path.isdir(d) else None


def _parse_i_file(i_file: str) -> tuple[str, int, float] | None:
    """Parse a $I record -> (original_path, size, deleted_at_epoch), or None if unreadable.
    v1 (Vista-8.1): path = 520 bytes at offset 24.  v2 (Win10+): char count at 24, path at 28."""
    try:
        with open(i_file, "rb") as f:
            data = f.read()
        if len(data) < 28:
            return None
        version, size, ft = struct.unpack_from("<qqq", data, 0)
        if version == 1:
            raw = data[24:24 + 520]
        elif version == 2:
            n = struct.unpack_from("<i", data, 24)[0]
            raw = data[28:28 + n * 2]
        else:
            return None
        path = raw.decode("utf-16-le", errors="ignore").split("\x00")[0]
        if not path:
            return None
        return path, size, (ft - _FILETIME_EPOCH) / 1e7
    except Exception:
        return None


def build_bin_index(drive_roots) -> tuple[dict[str, list[BinItem]], set[str]]:
    """
    Index the current user's Recycle Bin on the given drives.
    Returns ({path_key(original_path): [BinItem, ...]}, drives_that_were_readable).
    Callers must only treat "absent from the index" as "gone" for readable drives.
    """
    index: dict[str, list[BinItem]] = {}
    readable: set[str] = set()
    for root in drive_roots:
        root = root.upper()
        d = _bin_dir(root)
        if d is None:
            continue
        try:
            with os.scandir(d) as it:
                names = [e.name for e in it]
        except OSError:
            continue
        readable.add(root)
        for name in names:
            if not name.upper().startswith("$I"):
                continue
            i_file = os.path.join(d, name)
            parsed = _parse_i_file(i_file)
            if parsed is None:
                continue
            path, size, ts = parsed
            index.setdefault(path_key(path), []).append(
                BinItem(i_file, os.path.join(d, "$R" + name[2:]), path, size, ts))
    for items in index.values():
        items.sort(key=lambda b: b.deleted_at)
    return index, readable


def path_key(path: str) -> str:
    """Canonical lookup key for a path: case-folded, one separator style, no '.'/'..'."""
    return os.path.normcase(os.path.normpath(path))


def _drive_root(path: str) -> str:
    return os.path.splitdrive(path)[0].upper() + "\\"


def _pick_items(items: list[BinItem], trashed_at: list[float] | None) -> list[BinItem]:
    """Items for one path that belong to this app. With trash-log timestamps, only records
    deleted just before a logged trash time qualify; without any, all of them."""
    if not trashed_at:
        return items
    return [b for b in items
            if any(t - TRASH_TIME_BEFORE <= b.deleted_at <= t + TRASH_TIME_AFTER for t in trashed_at)]


def _inside(child: str, parent: str) -> bool:
    try:
        child = os.path.normcase(os.path.realpath(child))
        parent = os.path.normcase(os.path.realpath(parent))
        return os.path.commonpath([child, parent]) == parent and child != parent
    except ValueError:
        return False


def _force_remove(path: str) -> None:
    """Remove a file or folder, clearing the read-only attribute if needed."""
    def _onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path, onerror=_onerror)
    else:
        try:
            os.remove(path)
        except PermissionError:
            os.chmod(path, stat.S_IWRITE)
            os.remove(path)


def delete_from_recycle_bin(entries: list[tuple[str, list[float] | None]]) -> dict:
    """
    Permanently delete items from the Recycle Bin.
    entries: [(original_path, [trashed_at_epoch, ...] | None)]
    Returns {"ok", "succeeded": [paths], "failed": [{path, reason}], "bytes_freed"}.
    A path that is no longer in a readable bin counts as already gone (succeeded).
    """
    succeeded, failed, freed, unavailable = [], [], 0, []
    drives = {_drive_root(p) for p, _ in entries if os.path.splitdrive(p)[0]}
    index, readable = build_bin_index(drives)

    for path, trashed_at in entries:
        root = _drive_root(path)
        if root not in readable:
            if not os.path.exists(root):
                unavailable.append(path)      # drive not connected: its bin cannot be reached at all
            else:
                failed.append({"path": path, "reason": f"Recycle Bin on {root} could not be read"})
            continue
        bin_dir = _bin_dir(root)
        ok = True
        for b in _pick_items(index.get(path_key(path), []), trashed_at):
            if not (_inside(b.i_file, bin_dir) and (not os.path.lexists(b.r_file) or _inside(b.r_file, bin_dir))):
                failed.append({"path": path, "reason": "Path escapes the Recycle Bin — refused"})
                ok = False
                break
            try:
                if os.path.lexists(b.r_file):
                    _force_remove(b.r_file)     # data first: if this fails the $I record stays valid
                _force_remove(b.i_file)
                freed += b.size
            except Exception as e:
                failed.append({"path": path, "reason": f"Could not remove from Recycle Bin: {e}"})
                ok = False
                break
        if ok:
            succeeded.append(path)
    return {"ok": not failed, "succeeded": succeeded, "failed": failed, "bytes_freed": freed,
            "unavailable": unavailable}


def restore_from_recycle_bin(entries: list[tuple[str, list[float] | None]]) -> dict:
    """Move items back from the Recycle Bin to their original location (never overwrites)."""
    succeeded, failed = [], []
    drives = {_drive_root(p) for p, _ in entries if os.path.splitdrive(p)[0]}
    index, readable = build_bin_index(drives)
    for path, trashed_at in entries:
        root = _drive_root(path)
        if root not in readable:
            failed.append({"path": path, "reason": f"Recycle Bin on {root} could not be read"})
            continue
        items = _pick_items(index.get(path_key(path), []), trashed_at)
        if not items:
            failed.append({"path": path, "reason": "Not found in the Recycle Bin (already restored or emptied)"})
            continue
        b = items[-1]                      # newest deletion of that path
        if os.path.lexists(path):
            failed.append({"path": path, "reason": "A file already exists at the original location"})
            continue
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.replace(b.r_file, path)
            _force_remove(b.i_file)
            succeeded.append(path)
        except Exception as e:
            failed.append({"path": path, "reason": f"Restore failed: {e}"})
    return {"ok": not failed, "succeeded": succeeded, "failed": failed}
