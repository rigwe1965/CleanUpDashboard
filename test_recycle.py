import ctypes, ctypes.wintypes, os

rb = "C:\\" + chr(36) + "RECYCLE.BIN"
attrs = ctypes.windll.kernel32.GetFileAttributesW(rb)
print("RECYCLE.BIN attrs:", hex(attrs) if attrs != 0xFFFFFFFF else "NOT FOUND")

src = "C:\\Users\\rigwe\\AppData\\Local\\Temp\\test_del_check.tmp"
with open(src, "w") as f:
    f.write("test")

FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400

class _S(ctypes.Structure):
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

hr = ctypes.windll.ole32.CoInitializeEx(None, 0x2)
print("CoInitializeEx:", hex(hr & 0xFFFFFFFF))
op = _S()
op.hwnd = None
op.wFunc = FO_DELETE
op.pFrom = src + "\x00\x00"
op.pTo = None
op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
ret = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
print("SHFileOp FOF_ALLOWUNDO ret:", ret, "still exists:", os.path.exists(src))
if hr in (0, 1):
    ctypes.windll.ole32.CoUninitialize()

# Cleanup if still there
if os.path.exists(src):
    os.remove(src)
