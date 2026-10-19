"""
classifier.py — Risk classification rules engine.
No I/O. Pure logic. First matching rule wins.
"""

import os
import re
import sys
import time

# ---------------------------------------------------------------------------
# Protected system data — NEVER deletable, whatever the risk rating says.
# Matching is case-insensitive, works on any drive letter, and is checked again
# at delete time on the symlink/junction-resolved path (see recycle._safety_check).
# ---------------------------------------------------------------------------
_SYS_DRIVE = os.environ.get("SystemDrive", "C:").rstrip("\\").lower()

# Kept for callers that import it: system-drive roots that are always off limits.
PROTECTED_PATHS = frozenset([
    f"{_SYS_DRIVE}\\windows",
    f"{_SYS_DRIVE}\\program files",
    f"{_SYS_DRIVE}\\program files (x86)",
    f"{_SYS_DRIVE}\\programdata\\microsoft",
    f"{_SYS_DRIVE}\\recovery",
    f"{_SYS_DRIVE}\\system volume information",
    f"{_SYS_DRIVE}\\users\\all users",
    f"{_SYS_DRIVE}\\users\\default",
    f"{_SYS_DRIVE}\\users\\public",
    f"{_SYS_DRIVE}\\boot",
    f"{_SYS_DRIVE}\\pagefile.sys",
    f"{_SYS_DRIVE}\\hiberfil.sys",
    f"{_SYS_DRIVE}\\swapfile.sys",
])

# First folder under ANY drive root (an OS can live on any drive).
_ROOT_DIRS = frozenset([
    "windows", "program files", "program files (x86)", "recovery", "system volume information",
    "boot", "efi", "config.msi", "msocache", "documents and settings",
    "$windows.~bt", "$windows.~ws", "$sysreset", "$winreagent", "$getcurrent", "$windows.~ls",
])

# Files that sit directly in a drive root and are needed to boot / run Windows.
_ROOT_FILES = frozenset([
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr", "bootnxt", "bootsect.bak", "bcd",
    "ntldr", "ntdetect.com", "boot.ini", "config.sys", "io.sys", "msdos.sys",
])

# Two-level folders under any drive root.
_ROOT_PAIRS = frozenset([
    ("programdata", "microsoft"), ("programdata", "package cache"), ("programdata", "ssh"),
    ("users", "all users"), ("users", "default"), ("users", "default user"),
    ("users", "defaultuser0"), ("users", "public"),
])

# File names that are system/registry/shell data wherever they appear.
_PROTECTED_NAMES = frozenset(["desktop.ini", "ntuser.ini", "ntuser.pol"])
_PROTECTED_NAME_PREFIXES = ("ntuser.dat", "usrclass.dat")   # + .LOG1/.LOG2/{guid}.TM.blf/.regtrans-ms

# Per-user system data, matched anywhere in the path on a folder boundary
# (profiles can live outside C:\Users).
_PROFILE_PROTECTED = re.compile(
    r"\\appdata\\local\\microsoft\\(windows|windowsapps|credentials|vault)(\\|$)"
    r"|\\appdata\\roaming\\microsoft\\(windows|protect|credentials|crypto|systemcertificates|vault)(\\|$)"
    r"|\\appdata\\local\\packages\\(microsoft\.|windows)"
)
# Inside that tree these are plain, regenerable caches (and the classifier already rates them SAFE).
_PROFILE_CACHE_EXCEPTION = re.compile(
    r"\\appdata\\local\\microsoft\\windows\\(inetcache|temporary internet files)(\\|$)"
)


def _split(p: str) -> list[str]:
    # Windows ignores trailing dots/spaces on a path segment ("Windows \System32"), so we do too.
    return [c for c in (x.rstrip(" .") for x in os.path.splitdrive(p)[1].split("\\")) if c]


def _dynamic_roots() -> tuple[str, ...]:
    """Folders this machine/app needs, taken from the live environment."""
    cands = [os.path.dirname(os.path.abspath(__file__)), sys.prefix, sys.base_prefix, sys.exec_prefix,
             os.path.dirname(sys.executable)]
    for var in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
                "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432"):
        if os.environ.get(var):
            cands.append(os.environ[var])
    if os.environ.get("ProgramData"):
        cands.append(os.path.join(os.environ["ProgramData"], "Microsoft"))
    roots = set()
    for c in cands:
        n = os.path.normcase(os.path.abspath(c))
        if len(_split(n)) >= 1:            # never a bare drive root
            roots.add(n)
    return tuple(sorted(roots))


_DYNAMIC_ROOTS = _dynamic_roots()


def is_protected(path: str) -> bool:
    """Return True if path is system-required data that must never be deleted."""
    p = os.path.normcase(os.path.abspath(path))
    if p.startswith("\\\\?\\"):
        p = p[4:]
    if "~" in p:                            # 8.3 short name (PROGRA~1): resolve to the long form
        p = os.path.normcase(os.path.realpath(p))
        if p.startswith("\\\\?\\"):
            p = p[4:]

    parts = _split(p)
    if not parts:
        return True                         # a drive root itself
    p = os.path.splitdrive(p)[0] + "\\" + "\\".join(parts)
    first = parts[0]
    if first in _ROOT_DIRS:
        return True
    if len(parts) == 1 and first in _ROOT_FILES:
        return True
    if len(parts) >= 2 and (first, parts[1]) in _ROOT_PAIRS:
        return True

    name = parts[-1]
    if name in _PROTECTED_NAMES or name.startswith(_PROTECTED_NAME_PREFIXES):
        return True

    tail = "\\" + "\\".join(parts)
    if _PROFILE_PROTECTED.search(tail) and not _PROFILE_CACHE_EXCEPTION.search(tail):
        return True

    for root in _DYNAMIC_ROOTS:
        if p == root or p.startswith(root + "\\"):
            return True
    return False


def has_system_attribute(stat_result) -> bool:
    """FILE_ATTRIBUTE_SYSTEM (0x4): Windows marks OS-owned files this way."""
    return bool(getattr(stat_result, "st_file_attributes", 0) & 0x4)


SAFE_CACHE_FRAGMENTS = [
    "\\appdata\\local\\google\\chrome\\user data\\default\\cache",
    "\\appdata\\local\\google\\chrome\\user data\\default\\code cache",
    "\\appdata\\local\\microsoft\\edge\\user data\\default\\cache",
    "\\appdata\\local\\microsoft\\edge\\user data\\default\\code cache",
    "\\appdata\\local\\mozilla\\firefox\\profiles",
    "\\appdata\\local\\slack\\cache",
    "\\appdata\\local\\discord\\cache",
    "\\appdata\\local\\teams\\current\\cache",
    "\\appdata\\roaming\\spotify\\data",
    "\\appdata\\local\\temp",
    "\\appdata\\locallow\\temp",
    "\\windows\\temp",
    "\\appdata\\local\\microsoft\\windows\\inetcache",
    "\\appdata\\local\\microsoft\\windows\\temporary internet files",
    "\\appdata\\local\\pip\\cache",
    "\\appdata\\local\\yarn\\cache",
    "\\appdata\\local\\npm-cache",
    "\\appdata\\local\\nuget\\cache",
    "\\appdata\\roaming\\npm-cache",
    "\\node_modules\\.cache",
    "\\.next\\cache",
    "\\.turbo",
    "\\__pycache__",
    "\\.gradle\\caches",
    "\\.mypy_cache",
    "\\.pytest_cache",
    "\\crashreports",
    "\\crashdumps",
]

JUNK_EXTENSIONS = frozenset([
    ".tmp", ".temp", ".log", ".old", ".bak", ".orig",
    ".dmp", ".chk", ".gid", ".fts", ".~", ".crdownload",
    ".part", ".partial",
])

INSTALLER_EXTENSIONS = frozenset([".exe", ".msi", ".msix", ".appx", ".pkg"])

BACKUP_EXTENSIONS = frozenset([".bak", ".backup", ".old", ".orig", ".~bak"])

SIXTY_DAYS = 60 * 86400
NINETY_DAYS = 90 * 86400
LARGE_FILE_BYTES = 100 * 1024 * 1024   # 100 MB


def classify(path: str, size: int, stat_result) -> dict:
    """
    Classify a file and return a dict with:
      risk, risk_reason, type, category, protected
    """
    p = path.lower()
    ext = os.path.splitext(p)[1]
    now = time.time()

    try:
        last_accessed = stat_result.st_atime
        last_modified = stat_result.st_mtime
    except Exception:
        last_accessed = now
        last_modified = now

    age_accessed = now - last_accessed
    age_modified = now - last_modified

    # 1. Protected paths and OS-owned (SYSTEM attribute) files — block everything
    if is_protected(path) or has_system_attribute(stat_result):
        return {
            "risk": "HIGH",
            "risk_reason": "Located in a protected system directory — deletion blocked",
            "type": "system",
            "category": "System",
            "protected": True,
        }

    # 2. Recycle Bin contents (scan only, mark in_trash)
    if "\\$recycle.bin" in p:
        return {
            "risk": "SAFE",
            "risk_reason": "File is already in the Recycle Bin",
            "type": "trash",
            "category": "Trash",
            "protected": False,
        }

    # 3. Temp files by extension
    if ext in (".tmp", ".temp") or "\\temp\\" in p or "\\tmp\\" in p:
        return {
            "risk": "SAFE",
            "risk_reason": "Temporary file — auto-regenerated by Windows or applications",
            "type": "temp",
            "category": "Cache & Junk",
            "protected": False,
        }

    # 4. Safe cache locations
    for frag in SAFE_CACHE_FRAGMENTS:
        if frag in p:
            return {
                "risk": "SAFE",
                "risk_reason": "Cache file — automatically rebuilt by the owning application",
                "type": "cache",
                "category": "Cache & Junk",
                "protected": False,
            }

    # 5. Log files outside Windows
    if ext == ".log" and "\\windows\\" not in p:
        return {
            "risk": "SAFE",
            "risk_reason": "Application log file — safe to delete",
            "type": "log",
            "category": "Cache & Junk",
            "protected": False,
        }

    # 6. Dump / crash files
    if ext == ".dmp" or "crashdump" in p or "crashreport" in p:
        return {
            "risk": "SAFE",
            "risk_reason": "Crash dump / diagnostic file — no longer needed",
            "type": "dump",
            "category": "Cache & Junk",
            "protected": False,
        }

    # 7. Backup file extensions
    if ext in BACKUP_EXTENSIONS:
        return {
            "risk": "LOW",
            "risk_reason": "Backup copy of another file — review before deleting",
            "type": "backup",
            "category": "Cache & Junk",
            "protected": False,
        }

    # 8. Old installers in Downloads
    if ext in INSTALLER_EXTENSIONS and "\\downloads\\" in p and age_modified > SIXTY_DAYS:
        return {
            "risk": "LOW",
            "risk_reason": "Installer not modified in over 60 days — likely safe to remove",
            "type": "installer",
            "category": "Large Files",
            "protected": False,
        }

    # 9. Downloads folder (non-installers)
    if "\\downloads\\" in p:
        return {
            "risk": "LOW",
            "risk_reason": "User download — review before deleting",
            "type": "download",
            "category": "Cache & Junk",
            "protected": False,
        }

    # 10. AppData Roaming
    if "\\appdata\\roaming\\" in p:
        return {
            "risk": "MEDIUM",
            "risk_reason": "Application settings in Roaming AppData — may affect app behavior",
            "type": "appdata",
            "category": "App Data",
            "protected": False,
        }

    # 11. AppData Local (non-cache, non-temp already caught above)
    if "\\appdata\\local\\" in p:
        return {
            "risk": "MEDIUM",
            "risk_reason": "Application data in Local AppData — review before deleting",
            "type": "appdata",
            "category": "App Data",
            "protected": False,
        }

    # 12. Large and old files
    if size >= LARGE_FILE_BYTES and age_accessed > NINETY_DAYS:
        return {
            "risk": "LOW",
            "risk_reason": "Large file not accessed in over 90 days — review and archive or delete",
            "type": "large",
            "category": "Large Files",
            "protected": False,
        }

    if size >= LARGE_FILE_BYTES:
        return {
            "risk": "MEDIUM",
            "risk_reason": "Large file — review before deleting",
            "type": "large",
            "category": "Large Files",
            "protected": False,
        }

    # 13. Default fallback — unknown, block it
    return {
        "risk": "HIGH",
        "risk_reason": "File does not match any known safe pattern — blocked for safety",
        "type": "unknown",
        "category": "Unknown",
        "protected": False,
    }
