"""
test_cleanup.py — end-to-end tests for delete / permanent delete / empty trash / system protection.

Runs an ISOLATED server (own port, own throw-away DB) against synthetic files it creates itself.
It never reads or writes scan_results.db and never touches real user files.

    python test_cleanup.py            # all tests
    python test_cleanup.py Step1      # one group (Step1, Step2, Step3, Step4)
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PORT = 8799
BASE = f"http://127.0.0.1:{PORT}"

# Synthetic files live under %LOCALAPPDATA%\Temp so the classifier rates them SAFE,
# exactly like real temp files. HIGH-risk probes live under the user profile instead.
TEMP_ROOT = os.path.join(os.environ["LOCALAPPDATA"], "Temp")


def api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            return json.loads(e.read())


class Env:
    """One throw-away server + DB + scratch dirs for a test class."""

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="cleanup_test_", dir=TEMP_ROOT)                          # SAFE (temp)
        self.high_dir = tempfile.mkdtemp(prefix="cleanup_test_high_", dir=os.path.expanduser("~"))  # HIGH
        self.db = os.path.join(TEMP_ROOT, f"cleanup_test_{uuid.uuid4().hex[:8]}.db")
        env = dict(os.environ, CLEANUP_PORT=str(PORT), CLEANUP_DB=self.db, CLEANUP_NO_BROWSER="1",
                   CLEANUP_RECONCILE_TTL="0")
        self.proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=HERE)
        for _ in range(80):
            try:
                urllib.request.urlopen(BASE + "/api/status", timeout=1).read()
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError("test server did not start")

    # -- helpers -----------------------------------------------------------
    def make_file(self, name="f.tmp", content=b"x" * 200, where=None):
        p = os.path.join(where or self.tmp, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(content)
        return p

    def register(self, path):
        """Insert a files row the way the scanner would (real classifier output)."""
        from classifier import classify
        st = os.stat(path)
        c = classify(path, st.st_size, st)
        fid = str(uuid.uuid4())
        conn = sqlite3.connect(self.db, timeout=15)
        conn.execute(
            "INSERT INTO files (id,scan_id,path,drive,size,risk,risk_reason,type,category,"
            "last_accessed,last_modified,is_duplicate,duplicate_group,protected,in_trash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,0,NULL,?,0)",
            (fid, "t", path, path[0].upper(), st.st_size, c["risk"], c["risk_reason"], c["type"],
             c["category"], "", "", 1 if c["protected"] else 0))
        conn.commit()
        conn.close()
        return fid

    def row(self, fid):
        conn = sqlite3.connect(self.db, timeout=15)
        conn.row_factory = sqlite3.Row
        r = conn.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone()
        conn.close()
        return r

    def q(self, sql, args=()):
        conn = sqlite3.connect(self.db, timeout=15)
        r = conn.execute(sql, args).fetchall()
        conn.commit()
        conn.close()
        return r

    def close(self):
        try:
            api("POST", "/api/trash/clear", {})      # leave nothing of ours in the real Recycle Bin
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.high_dir, ignore_errors=True)
        for suf in ("", "-wal", "-shm"):
            try:
                os.remove(self.db + suf)
            except OSError:
                pass


def bin_item(path):
    """The current user's Recycle Bin records for `path` (list, newest last)."""
    import recycle as rc
    index, _ = rc.build_bin_index({os.path.splitdrive(path)[0] + "\\"})
    return index.get(rc.path_key(path), [])


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()


# ===========================================================================
# STEP 1 — Delete (move to Recycle Bin)
# ===========================================================================
class Step1_Delete(Base):
    def test_single_file_is_deleted_and_lands_in_recycle_bin(self):
        p = self.env.make_file("single.tmp")
        fid = self.env.register(p)
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": False})
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(p))
        self.assertEqual(self.env.row(fid)["in_trash"], 1)
        self.assertTrue(bin_item(p), "file should be restorable from the Recycle Bin")
        self.assertEqual(len(self.env.q("SELECT 1 FROM trash_log WHERE original_path=?", (p,))), 1)

    def test_many_files_more_than_one_batch(self):
        paths = [self.env.make_file(f"many/{i}.tmp") for i in range(60)]
        ids = [self.env.register(p) for p in paths]
        r = api("POST", "/api/delete", {"ids": ids})
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(r["succeeded"]), 60)
        self.assertFalse(any(os.path.exists(p) for p in paths))
        self.assertTrue(all(self.env.row(i)["in_trash"] == 1 for i in ids))

    def test_read_only_and_unicode_names(self):
        a = self.env.make_file("ro.tmp")
        os.chmod(a, 0o444)
        b = self.env.make_file("héllo wörld ✓.tmp")
        ids = [self.env.register(a), self.env.register(b)]
        r = api("POST", "/api/delete", {"ids": ids})
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(a) or os.path.exists(b))

    def test_locked_file_in_batch_does_not_break_the_others(self):
        paths = [self.env.make_file(f"lock/{i}.tmp") for i in range(5)]
        ids = [self.env.register(p) for p in paths]
        held = open(paths[2], "rb")           # open handle blocks the delete
        try:
            r = api("POST", "/api/delete", {"ids": ids})
        finally:
            held.close()
        self.assertEqual(len(r["succeeded"]), 4, r)
        self.assertEqual(len(r["failed"]), 1, r)
        self.assertEqual(r["failed"][0]["path"], paths[2])
        for i, p in enumerate(paths):
            if i == 2:
                self.assertTrue(os.path.exists(p))
                self.assertEqual(self.env.row(ids[i])["in_trash"], 0)
            else:
                self.assertFalse(os.path.exists(p))
                self.assertEqual(self.env.row(ids[i])["in_trash"], 1)

    def test_file_already_gone_is_cleaned_up_not_an_error(self):
        p = self.env.make_file("gone.tmp")
        fid = self.env.register(p)
        os.remove(p)
        r = api("POST", "/api/delete", {"ids": [fid]})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["missing"], [p])

    def test_high_risk_file_is_never_touched(self):
        p = self.env.make_file("keepme.dat", where=self.env.high_dir)
        fid = self.env.register(p)
        self.assertEqual(self.env.row(fid)["risk"], "HIGH")
        r = api("POST", "/api/delete", {"ids": [fid]})
        self.assertFalse(r["ok"])
        self.assertTrue(os.path.exists(p))
        self.assertIn("HIGH", r["failed"][0]["reason"])
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertFalse(r["ok"])
        self.assertTrue(os.path.exists(p))

    def test_unknown_id_is_reported(self):
        r = api("POST", "/api/delete", {"ids": ["deadbeef-0000"]})
        self.assertFalse(r["ok"])
        self.assertEqual(len(r["failed"]), 1)

    def test_bad_requests(self):
        self.assertIn("error", api("POST", "/api/delete", {"ids": []}))
        self.assertIn("error", api("POST", "/api/delete", {"ids": ["../../x"]}))


# ===========================================================================
# STEP 2 — Delete permanently
# ===========================================================================
class Step2_PermanentDelete(Base):
    def test_file_is_gone_for_good(self):
        p = self.env.make_file("perm.tmp", content=b"y" * 5000)
        fid = self.env.register(p)
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["succeeded"], [p])
        self.assertFalse(os.path.exists(p))
        self.assertFalse(bin_item(p), "permanent delete must NOT land in the Recycle Bin")
        self.assertIsNone(self.env.row(fid), "row removed from the list")

    def test_read_only_file(self):
        p = self.env.make_file("perm_ro.tmp")
        os.chmod(p, 0o444)
        fid = self.env.register(p)
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(p))

    def test_large_file_is_fast(self):
        p = self.env.make_file("big.tmp", content=b"")
        with open(p, "wb") as f:
            f.truncate(300 * 1024 * 1024)            # 300 MB sparse
        fid = self.env.register(p)
        t = time.time()
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(p))
        self.assertLess(time.time() - t, 10, "plain delete must not rewrite the file")

    def test_many_files(self):
        paths = [self.env.make_file(f"permmany/{i}.tmp") for i in range(80)]
        ids = [self.env.register(p) for p in paths]
        r = api("POST", "/api/delete", {"ids": ids, "permanent": True})
        self.assertTrue(r["ok"], r)
        self.assertEqual(len(r["succeeded"]), 80)
        self.assertFalse(any(os.path.exists(p) for p in paths))

    def test_locked_file_fails_cleanly_others_still_deleted(self):
        paths = [self.env.make_file(f"permlock/{i}.tmp") for i in range(3)]
        ids = [self.env.register(p) for p in paths]
        held = open(paths[1], "rb")
        try:
            r = api("POST", "/api/delete", {"ids": ids, "permanent": True})
        finally:
            held.close()
        self.assertEqual(len(r["succeeded"]), 2, r)
        self.assertEqual([f["path"] for f in r["failed"]], [paths[1]])
        self.assertTrue(os.path.exists(paths[1]))
        self.assertIsNotNone(self.env.row(ids[1]), "failed file stays in the list")
        self.assertIsNone(self.env.row(ids[0]))
        self.assertIsNone(self.env.row(ids[2]))

    def test_already_missing_file_is_cleaned_from_list(self):
        p = self.env.make_file("permgone.tmp")
        fid = self.env.register(p)
        os.remove(p)
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertTrue(r["ok"], r)
        self.assertIsNone(self.env.row(fid))

    def test_permanent_must_be_explicit_true(self):
        p = self.env.make_file("notperm.tmp")
        fid = self.env.register(p)
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": "false"})   # truthy string must not wipe
        self.assertTrue(r["ok"], r)
        self.assertTrue(bin_item(p), "string 'false' must behave as a normal recycle")


# ===========================================================================
# STEP 3 — Trash tab: restore, delete forever, Empty Trash
# ===========================================================================
class Step3_Trash(Base):
    def setUp(self):
        # every test starts from an empty trash list so counts are exact
        api("POST", "/api/trash/clear", {})

    def trash(self, n, prefix="t"):
        paths = [self.env.make_file(f"{prefix}/{i}.tmp", content=b"z" * 1000) for i in range(n)]
        ids = [self.env.register(p) for p in paths]
        r = api("POST", "/api/delete", {"ids": ids})
        self.assertTrue(r["ok"], r)
        return paths

    def trash_rows(self):
        return api("GET", "/api/results?tab=trash&sort=path&dir=asc")

    def test_trash_tab_lists_what_was_deleted_and_count_matches(self):
        paths = self.trash(3)
        d = self.trash_rows()
        self.assertEqual(d["total"], 3)
        self.assertEqual(sorted(r["path"] for r in d["results"]), sorted(paths))
        self.assertEqual(api("GET", "/api/summary")["trash_count"], 3)

    def test_delete_selected_trash_items_removes_them_from_the_recycle_bin(self):
        paths = self.trash(4)
        rows = self.trash_rows()["results"]
        pick = [r for r in rows if r["path"] in paths[:2]]
        r = api("POST", "/api/trash/remove", {"ids": [x["id"] for x in pick]})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["removed"], 2)
        self.assertGreaterEqual(r["bytes_freed"], 2000)
        for p in paths[:2]:
            self.assertFalse(bin_item(p), "gone from the real Recycle Bin")
        for p in paths[2:]:
            self.assertTrue(bin_item(p), "unselected items untouched")
        self.assertEqual(self.trash_rows()["total"], 2)

    def test_delete_removes_the_r_data_file_too(self):
        (p,) = self.trash(1)
        (item,) = bin_item(p)
        self.assertTrue(os.path.exists(item.r_file))
        rows = self.trash_rows()["results"]
        api("POST", "/api/trash/remove", {"ids": [rows[0]["id"]]})
        self.assertFalse(os.path.exists(item.r_file))
        self.assertFalse(os.path.exists(item.i_file))

    def test_empty_trash_clears_everything_this_app_trashed(self):
        paths = self.trash(25)
        r = api("POST", "/api/trash/clear", {})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["removed"], 25)
        self.assertGreaterEqual(r["bytes_freed"], 25000)
        self.assertFalse(any(bin_item(p) for p in paths))
        self.assertEqual(self.trash_rows()["total"], 0)
        self.assertEqual(api("GET", "/api/summary")["trash_count"], 0)

    def test_empty_trash_leaves_items_the_app_did_not_trash(self):
        import recycle as rc
        outside = self.env.make_file("outside/keep_in_bin.tmp")
        ok, err = rc._recycle_paths_windows([outside])          # trashed by "the user", not the app
        self.assertTrue(ok, err)
        paths = self.trash(2)
        r = api("POST", "/api/trash/clear", {})
        self.assertTrue(r["ok"], r)
        self.assertFalse(any(bin_item(p) for p in paths))
        self.assertTrue(bin_item(outside), "the user's own Recycle Bin item must survive Empty Trash")
        rc.delete_from_recycle_bin([(outside, None)])           # tidy up after ourselves

    def test_empty_trash_when_already_empty(self):
        r = api("POST", "/api/trash/clear", {})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["removed"], 0)

    def test_trash_survives_a_rescan(self):
        paths = self.trash(2)
        self.env.q("DELETE FROM files")                          # what a new scan does first
        self.assertEqual(self.trash_rows()["total"], 2)
        r = api("POST", "/api/trash/clear", {})
        self.assertEqual(r["removed"], 2)
        self.assertFalse(any(bin_item(p) for p in paths))

    def test_restore_puts_the_file_back(self):
        (p,) = self.trash(1)
        row = self.trash_rows()["results"][0]
        r = api("POST", "/api/trash/restore", {"id": row["id"]})
        self.assertTrue(r["ok"], r)
        self.assertTrue(os.path.exists(p))
        self.assertEqual(open(p, "rb").read(), b"z" * 1000)
        self.assertFalse(bin_item(p))
        self.assertEqual(self.trash_rows()["total"], 0)

    def test_restore_never_overwrites_a_newer_file(self):
        (p,) = self.trash(1)
        with open(p, "wb") as f:
            f.write(b"newer")
        row = self.trash_rows()["results"][0]
        r = api("POST", "/api/trash/restore", {"id": row["id"]})
        self.assertFalse(r["ok"])
        self.assertEqual(open(p, "rb").read(), b"newer")
        self.assertTrue(bin_item(p), "item stays in the bin")

    def test_items_removed_from_bin_outside_the_app_drop_off_the_list(self):
        import recycle as rc
        (p,) = self.trash(1)
        rc.delete_from_recycle_bin([(p, None)])                  # user emptied it in Explorer
        self.assertEqual(self.trash_rows()["total"], 0)

    def test_items_on_a_disconnected_drive_can_be_cleared_from_the_list(self):
        ghost = "Z:\\gone\\x.tmp"
        if os.path.exists("Z:\\"):
            self.skipTest("Z: exists on this machine")
        self.env.q("INSERT INTO trash_log (id,original_path,size,trashed_at,method,restored) VALUES (?,?,?,?,?,0)",
                   (str(uuid.uuid4()), ghost, 1, "2026-01-01T00:00:00+00:00", "recycle"))
        self.assertEqual(self.trash_rows()["total"], 1, "kept: the drive could be reconnected")
        r = api("POST", "/api/trash/clear", {})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["unavailable"], 1)
        self.assertEqual(r["removed"], 0)
        self.assertEqual(self.trash_rows()["total"], 0)

    def test_locked_bin_item_is_reported_and_kept(self):
        (p,) = self.trash(1)
        (item,) = bin_item(p)
        held = open(item.r_file, "rb")
        try:
            r = api("POST", "/api/trash/clear", {})
        finally:
            held.close()
        self.assertFalse(r["ok"])
        self.assertEqual(len(r["failed"]), 1)
        self.assertEqual(self.trash_rows()["total"], 1, "failed item stays listed")
        self.assertTrue(api("POST", "/api/trash/clear", {})["ok"])   # works once the lock is gone
        self.assertFalse(bin_item(p))


# ===========================================================================
# STEP 4 — System-required data is never deleted
# ===========================================================================
USER = os.path.expanduser("~")


class Step4_Protection(Base):
    # -- pure checks: nothing here can delete anything ---------------------
    def test_system_locations_are_protected(self):
        from classifier import is_protected
        protected = [
            r"C:\Windows\System32\config\SAM", r"C:\WINDOWS\notepad.exe", r"c:\windows",
            r"C:\Program Files\Foo\foo.dll", r"C:\Program Files (x86)\Foo\a.exe",
            r"D:\Windows\System32\x.dll", r"E:\Program Files\x.exe",           # other drives
            r"C:\pagefile.sys", r"C:\hiberfil.sys", r"C:\swapfile.sys", r"C:\bootmgr", r"C:\BCD",
            r"C:\System Volume Information\x", r"D:\System Volume Information\tracking.log",
            r"C:\Recovery\WindowsRE\Winre.wim", r"C:\Boot\BCD", r"C:\EFI\Microsoft\Boot\bootmgfw.efi",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\x", r"C:\ProgramData\Package Cache\{g}\x.msi",
            r"C:\Users\Public\Documents\x", r"C:\Users\Default\NTUSER.DAT", r"C:\Users\All Users\x",
            USER + r"\NTUSER.DAT", USER + r"\ntuser.dat.LOG1", USER + r"\NTUSER.DAT{abc}.TMContainer0001.regtrans-ms",
            r"D:\Profiles\bob\NTUSER.DAT",                                     # profile off C:
            USER + r"\AppData\Local\Microsoft\Windows\UsrClass.dat",
            USER + r"\AppData\Local\Microsoft\Windows\Explorer\iconcache_32.db",
            USER + r"\AppData\Local\Microsoft\WindowsApps\python.exe",
            USER + r"\AppData\Local\Microsoft\Credentials\x", USER + r"\AppData\Local\Microsoft\Vault\x",
            USER + r"\AppData\Roaming\Microsoft\Protect\S-1-5-21\masterkey",
            USER + r"\AppData\Roaming\Microsoft\Credentials\x", USER + r"\AppData\Roaming\Microsoft\Crypto\RSA\k",
            USER + r"\AppData\Roaming\Microsoft\SystemCertificates\My\x",
            USER + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\x.lnk",
            USER + r"\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_x\LocalState\a",
            USER + r"\Documents\desktop.ini", USER + r"\Downloads\Desktop.INI",
        ]
        missed = [p for p in protected if not is_protected(p)]
        self.assertEqual(missed, [], f"must be protected: {missed}")

    def test_evasion_attempts_are_still_protected(self):
        from classifier import is_protected
        tricks = [
            r"C:\Windows\..\Windows\System32\cmd.exe",       # dot-dot
            "C:/Windows/System32/cmd.exe",                    # forward slashes
            r"c:\WINDOWS\System32\CMD.EXE",                   # case
            r"\\?\C:\Windows\System32\cmd.exe",               # extended-length prefix
            r"C:\Windows.\System32\cmd.exe",                  # trailing dot
            r"C:\PROGRA~1\Common Files\x.dll",                # 8.3 short name
            r"C:\Windows \System32\cmd.exe",                  # trailing space
        ]
        missed = [p for p in tricks if not is_protected(p)]
        self.assertEqual(missed, [], f"evasion not caught: {missed}")

    def test_this_app_and_python_are_protected(self):
        from classifier import is_protected
        self.assertTrue(is_protected(os.path.join(HERE, "server.py")))
        self.assertTrue(is_protected(os.path.join(HERE, "scan_results.db")))
        self.assertTrue(is_protected(sys.executable))

    def test_ordinary_user_data_is_not_wrongly_blocked(self):
        from classifier import is_protected
        ok = [
            USER + r"\Downloads\setup.exe", USER + r"\Documents\notes.txt",
            USER + r"\AppData\Local\Temp\x.tmp", USER + r"\AppData\Local\Google\Chrome\User Data\Default\Cache\f_1",
            USER + r"\AppData\Local\Microsoft\Windows\INetCache\IE\x.gif",
            USER + r"\AppData\Local\Microsoft\Windows\Temporary Internet Files\x",
            USER + r"\AppData\Roaming\Code\Cache\x", USER + r"\AppData\Local\Microsoft\Edge\User Data\Default\Cache\x",
            r"D:\Games\bigfile.bin", r"C:\Windows10Backup\old.txt", r"C:\Users\bob\Videos\a.mp4",
        ]
        wrongly = [p for p in ok if is_protected(p)]
        self.assertEqual(wrongly, [], f"over-blocking: {wrongly}")

    def test_safety_check_refuses_real_system_files(self):
        import recycle as rc
        for p in [r"C:\Windows\System32\drivers\etc\hosts", r"C:\Windows\System32\cmd.exe",
                  USER + r"\NTUSER.DAT", sys.executable, os.path.join(HERE, "server.py")]:
            if os.path.exists(p):
                ok, reason = rc._safety_check(p)
                self.assertFalse(ok, p)
                self.assertTrue(reason, p)

    def test_junction_into_system_folder_cannot_smuggle_a_delete(self):
        import recycle as rc
        link = os.path.join(self.env.tmp, "linkdir")
        target = r"C:\Windows\System32\drivers\etc"
        r = subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True, text=True)
        if r.returncode != 0:
            self.skipTest("could not create junction: " + r.stdout + r.stderr)
        try:
            ok, reason = rc._safety_check(os.path.join(link, "hosts"))
            self.assertFalse(ok, "path through a junction must resolve to the real (protected) target")
        finally:
            os.rmdir(link)                                  # removes only the junction

    def test_system_attribute_files_are_refused(self):
        import recycle as rc
        p = self.env.make_file("sysfile.tmp")
        subprocess.run(["attrib", "+s", p], check=True)
        try:
            ok, reason = rc._safety_check(p)
            self.assertFalse(ok)
            self.assertIn("SYSTEM", reason)
        finally:
            subprocess.run(["attrib", "-s", p])

    # -- end to end through the real API: files must survive ---------------
    def test_api_refuses_protected_files_recycle_and_permanent(self):
        probe_app = os.path.join(HERE, "zz_protect_probe.tmp")            # inside this app's folder
        names = ["NTUSER.DAT", "desktop.ini"]
        probes = [probe_app] + [self.env.make_file(n) for n in names]    # protected by name, in temp
        with open(probe_app, "wb") as f:
            f.write(b"probe")
        try:
            ids = [self.env.register(p) for p in probes]
            for permanent in (False, True):
                r = api("POST", "/api/delete", {"ids": ids, "permanent": permanent})
                self.assertFalse(r["ok"], r)
                self.assertEqual(len(r["failed"]), len(probes), r)
                self.assertEqual(r["succeeded"], [])
                for p in probes:
                    self.assertTrue(os.path.exists(p), f"{p} must still exist (permanent={permanent})")
        finally:
            os.remove(probe_app) if os.path.exists(probe_app) else None

    def test_protected_file_forced_to_safe_in_db_is_still_refused(self):
        """Even if a stale/poisoned DB row claims SAFE + unprotected, delete-time checks win."""
        p = self.env.make_file("NTUSER.DAT.LOG1")
        fid = str(uuid.uuid4())
        self.env.q("INSERT INTO files (id,scan_id,path,drive,size,risk,risk_reason,type,category,"
                   "is_duplicate,protected,in_trash) VALUES (?,?,?,?,?,?,?,?,?,0,0,0)",
                   (fid, "t", p, "C", 5, "SAFE", "", "temp", "Cache & Junk"))
        r = api("POST", "/api/delete", {"ids": [fid], "permanent": True})
        self.assertFalse(r["ok"], r)
        self.assertTrue(os.path.exists(p))

    def test_reclaim_skips_protected_files(self):
        keep = self.env.make_file("reclaimkeep/NTUSER.DAT")
        junk = self.env.make_file("reclaimkeep/junk.tmp")
        for p in (keep, junk):
            fid = str(uuid.uuid4())
            self.env.q("INSERT INTO files (id,scan_id,path,drive,size,risk,risk_reason,type,category,"
                       "is_duplicate,protected,in_trash) VALUES (?,?,?,?,?,?,?,?,?,0,0,0)",
                       (fid, "t", p, "C", 5, "SAFE", "", "temp", "Cache & Junk"))
        self.assertEqual(api("POST", "/api/reclaim", {"risks": ["SAFE"]}).get("status"), "running")
        for _ in range(100):
            st = api("GET", "/api/reclaim/status")
            if st["status"] != "running":
                break
            time.sleep(0.3)
        self.assertEqual(st["status"], "complete", st)
        self.assertTrue(os.path.exists(keep), "protected file must survive Reclaim")
        self.assertFalse(os.path.exists(junk), "ordinary junk is reclaimed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
