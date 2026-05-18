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
import sqlite3
import struct
import uuid
from datetime import datetime, timezone

from classifier import is_protected, classify

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
            return False, f"SHFileOperationW returned error code {ret}"
        if op.fAnyOperationsAborted:
            return False, "Operation was aborted by the user"
        return True, ""
    finally:
        # Only call CoUninitialize if we actually initialised (not RPC_E_CHANGED_MODE)
        if coinit_hr in (0, 1):  # S_OK or S_FALSE
            ctypes.windll.ole32.CoUninitialize()


def _safety_check(path: str, stat_result=None) -> tuple[bool, str]:
    """Return (ok, reason). ok=False means refuse the delete."""
    if not os.path.exists(path):
        return False, f"File not found: {path}"
    if not os.path.isfile(path):
        return False, f"Not a file (directories are not allowed): {path}"
    if is_protected(path):
        return False, f"Path is in a protected system directory: {path}"
    # Re-classify at delete time
    try:
        s = stat_result or os.stat(path)
        result = classify(path, s.st_size, s)
        if result["risk"] == "HIGH" and not path.lower().endswith(".log"):
            return False, f"Re-classification returned HIGH risk — delete refused: {path}"
    except Exception:
        pass
    return True, ""


def send_to_recycle_bin(paths: list[str], db_path: str) -> dict:
    """
    Move files to the Windows Recycle Bin (reversible).
    Returns {"ok": True/False, "succeeded": [...], "failed": [...]}
    """
    succeeded = []
    failed = []
    trash_entries = []

    for p in paths:
        ok, reason = _safety_check(p)
        if not ok:
            failed.append({"path": p, "reason": reason})
            continue

        # Capture size before moving — file won't be at original path afterward.
        try:
            size = os.path.getsize(p)
        except Exception:
            size = 0

        # Process one file at a time so a single locked/inaccessible file
        # does not cause the entire batch to fail.
        ok, err = _recycle_paths_windows([p])
        if ok:
            entry_id = str(uuid.uuid4())
            now_ts = datetime.now(timezone.utc).isoformat()
            trash_entries.append((entry_id, None, p, size, None, now_ts, "recycle", 0, None))
            succeeded.append(p)
        else:
            failed.append({"path": p, "reason": err})

    # Log to trash_log table
    if trash_entries and db_path:
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            conn.executemany(
                "INSERT OR IGNORE INTO trash_log "
                "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                trash_entries,
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    return {
        "ok": len(failed) == 0,
        "succeeded": succeeded,
        "failed": failed,
    }


def permanently_delete(paths: list[str], db_path: str) -> dict:
    """
    Permanently delete files with a single-pass zero-overwrite (secure wipe).
    REQUIRES that the caller has already verified permanent=True and user typed 'DELETE'.
    """
    succeeded = []
    failed = []

    for p in paths:
        ok, reason = _safety_check(p)
        if not ok:
            failed.append({"path": p, "reason": reason})
            continue

        # Secure wipe: overwrite with zeros in chunks to avoid OOM on large files
        try:
            size = os.path.getsize(p)
            chunk = b"\x00" * 65536
            with open(p, "r+b") as f:
                remaining = size
                while remaining > 0:
                    f.write(chunk if remaining >= 65536 else b"\x00" * remaining)
                    remaining -= 65536
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            failed.append({"path": p, "reason": f"Overwrite failed: {e}"})
            continue

        # Now delete
        try:
            os.remove(p)
            succeeded.append(p)
            # Log to trash_log as permanent
            if db_path:
                try:
                    entry_id = str(uuid.uuid4())
                    now = datetime.now(timezone.utc).isoformat()
                    conn = sqlite3.connect(db_path, timeout=10)
                    conn.execute(
                        "INSERT OR IGNORE INTO trash_log "
                        "(id,file_id,original_path,size,risk,trashed_at,method,restored,restored_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (entry_id, None, p, 0, None, now, "permanent", 0, None),
                    )
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
        except Exception as e:
            failed.append({"path": p, "reason": f"Delete failed: {e}"})

    return {
        "ok": len(failed) == 0,
        "succeeded": succeeded,
        "failed": failed,
    }


# ---------------------------------------------------------------------------
# Permanent deletion of files already sitting in the Recycle Bin
# ---------------------------------------------------------------------------
def _parse_recycle_bin_path(i_file: str) -> str | None:
    """
    Read a $I metadata file and return the original path encoded inside it.
    Windows Vista+ format:
      version=1 → path at offset 24 (MAX_PATH*2 bytes, UTF-16LE)
      version=2 → path length (DWORD) at 24, path at 28
    Returns None if the file cannot be parsed.
    """
    try:
        with open(i_file, "rb") as f:
            data = f.read()
        if len(data) < 24:
            return None
        version = struct.unpack_from("<q", data, 0)[0]
        if version == 1:
            raw = data[24:24 + 520]
            return raw.decode("utf-16-le", errors="ignore").split("\x00")[0]
        elif version == 2:
            if len(data) < 28:
                return None
            path_len = struct.unpack_from("<i", data, 24)[0]
            raw = data[28:28 + path_len * 2]
            return raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return None


def permanently_delete_from_recycle_bin(original_paths: list[str]) -> dict:
    """
    Permanently delete files that are already in the Windows Recycle Bin.
    Scans $RECYCLE.BIN/{SID}/$I* metadata files to locate each item by its
    original path, then deletes the $R (data) and $I (metadata) files.
    Returns {"ok": bool, "succeeded": [...paths], "failed": [...],
             "bytes_freed": int}
    """
    succeeded = []
    failed = []
    bytes_freed = 0

    targets = {p.lower(): p for p in original_paths}

    drives = set()
    for p in original_paths:
        drive = os.path.splitdrive(p)[0]
        if drive:
            drives.add(drive + "\\")

    found_map: dict[str, tuple[str, str, int]] = {}

    for drive_root in drives:
        recycle_root = os.path.join(drive_root, "$RECYCLE.BIN")
        if not os.path.exists(recycle_root):
            continue
        try:
            sid_dirs = os.listdir(recycle_root)
        except PermissionError:
            continue
        for sid_name in sid_dirs:
            sid_path = os.path.join(recycle_root, sid_name)
            if not os.path.isdir(sid_path):
                continue
            try:
                items = os.listdir(sid_path)
            except PermissionError:
                continue
            for fname in items:
                if not fname.upper().startswith("$I"):
                    continue
                i_file = os.path.join(sid_path, fname)
                orig = _parse_recycle_bin_path(i_file)
                if orig is None:
                    continue
                key = orig.lower()
                if key not in targets:
                    continue
                r_name = "$R" + fname[2:]
                r_file = os.path.join(sid_path, r_name)
                size = 0
                try:
                    if os.path.exists(r_file):
                        size = os.path.getsize(r_file)
                except Exception:
                    pass
                found_map[key] = (i_file, r_file, size)

    for lower_path, orig_path in targets.items():
        if lower_path in found_map:
            i_file, r_file, size = found_map[lower_path]
            try:
                if os.path.exists(r_file):
                    os.remove(r_file)
                os.remove(i_file)
                succeeded.append(orig_path)
                bytes_freed += size
            except Exception as e:
                failed.append({"path": orig_path, "reason": str(e)})
        else:
            # Not found in Recycle Bin — already gone, just clean DB record
            succeeded.append(orig_path)

    return {
        "ok": len(failed) == 0,
        "succeeded": succeeded,
        "failed": failed,
        "bytes_freed": bytes_freed,
    }
