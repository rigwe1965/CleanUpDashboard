import os, ctypes, ctypes.wintypes, sqlite3

FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400

class S(ctypes.Structure):
    _fields_ = [("hwnd",ctypes.wintypes.HWND),("wFunc",ctypes.wintypes.UINT),
                ("pFrom",ctypes.c_wchar_p),("pTo",ctypes.c_wchar_p),
                ("fFlags",ctypes.wintypes.WORD),("fAnyOperationsAborted",ctypes.wintypes.BOOL),
                ("hNameMappings",ctypes.c_void_p),("lpszProgressTitle",ctypes.c_wchar_p)]

src = "C:\\Users\\rigwe\\Desktop\\CleanUpDashboard\\test_del2.tmp"
with open(src, "w") as f:
    f.write("test delete")

hr = ctypes.windll.ole32.CoInitializeEx(None, 0x2)
print("CoInitializeEx:", hex(hr & 0xFFFFFFFF))
op = S()
op.hwnd = None
op.wFunc = FO_DELETE
op.pFrom = src + "\x00\x00"
op.pTo = None
op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
ret = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
print("SHFileOp ret:", ret, "file exists:", os.path.exists(src))
if hr in (0, 1):
    ctypes.windll.ole32.CoUninitialize()
if os.path.exists(src):
    os.remove(src)
    print("cleaned up via os.remove")

# Now check DB - find an unlocked cache file
print("\n--- DB check ---")
conn = sqlite3.connect("scan_results.db")
rows = conn.execute(
    "SELECT id, path FROM files WHERE in_trash=0 AND protected=0 AND risk='SAFE' "
    "AND category='Cache & Junk' AND type='log' ORDER BY size ASC LIMIT 20"
).fetchall()
conn.close()
for fid, p in rows:
    if not os.path.exists(p):
        continue
    try:
        with open(p, "r+b") as f:
            pass
        print("WRITABLE:", p[-80:])
        print("ID:", fid)
        break
    except Exception as e:
        pass
