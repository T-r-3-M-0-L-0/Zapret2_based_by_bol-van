#!/usr/bin/env python3
# ztool.py - zapret2 python control plane toolbox.
# Covers the data-plane-adjacent operator tasks that are painful in ps1:
#
#   debug <strategy.bat> [--duration S]  live debug session: stop service,
#                                        run winws2 with --debug=@file,
#                                        parse profile hits / SNI rewrites /
#                                        lua errors, restore service on exit
#   config <strategy.bat> [--out FILE]   convert a .bat strategy into a
#                                        winws2 @config file (no bat/sc
#                                        quoting hell), validate via dry-run
#   watch [--once] [--interval S] [domains...]
#                                        probe key domains, keep history in
#                                        logs\dpiwatch.json, report DPI window
#                                        changes (blocked <-> unblocked flips)
#   update                               check GitHub releases: zapret2 engine,
#                                        Flowseal lists, tg-ws-proxy; compare
#                                        with local versions
#   hostlists stats|dedupe|resolve [file]  list hygiene: counts, duplicates,
#                                        dead-domain detection
#   autoanalyze [file]                   summarize a --hostlist-auto debug log
#                                        (or auto hostlist file)
#   diag                                 collect statuses/logs/versions into
#                                        logs\diag_<timestamp>.zip
#   snapshot save|list|diff|restore [id] version snapshots of Custom.bat and
#                                        profiles\
#   wfcheck <strategy.bat>               dump the effective WinDivert filter
#                                        (--wf-save) and warn about CPU traps
#
# Pure stdlib, ASCII-only (console codepage safety). Admin required for
# debug/wfcheck (they spawn the engine). Never force-kills winws2.

import argparse
import ctypes
import datetime
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(ROOT, "bin")
LUA = os.path.join(ROOT, "lua")
LISTS = os.path.join(ROOT, "lists")
PROFS = os.path.join(ROOT, "profiles")
LOGS = os.path.join(ROOT, "logs")
SNAPS = os.path.join(ROOT, "snapshots")
WINWS2 = os.path.join(BIN, "winws2.exe")

CTRL_BREAK_EVENT = 1
WATCH_DEFAULT_DOMAINS = ["www.youtube.com", "discord.com", "github.com"]

# ================================================================ shared
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def service_state(name):
    r = subprocess.run(["sc.exe", "query", name], capture_output=True, text=True)
    if r.returncode != 0:
        return "NOT_INSTALLED"
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", r.stdout)
    return m.group(1) if m else "UNKNOWN"

def stop_service(name):
    subprocess.run(["sc.exe", "stop", name], capture_output=True)
    for _ in range(20):
        if service_state(name) != "RUNNING":
            return True
        time.sleep(0.5)
    return False

def start_service(name):
    subprocess.run(["sc.exe", "start", name], capture_output=True)
    time.sleep(1)
    return service_state(name)

def stop_engine_graceful(p):
    if p.poll() is not None:
        return True
    ctypes.windll.kernel32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, p.pid)
    try:
        p.wait(timeout=10)
        return True
    except subprocess.TimeoutExpired:
        return False

def probe(domain, timeout=8):
    try:
        r = subprocess.run(["curl.exe", "-s", "-o", "NUL", "-w",
                            "%{http_code} %{time_total}", "--max-time",
                            str(timeout), "https://%s/" % domain],
                           capture_output=True, text=True, timeout=timeout + 3)
        parts = r.stdout.split()
        return parts[0], float(parts[1])
    except Exception:
        return "000", float(timeout)

def ok_code(code):
    return bool(re.match(r"^(2|3)\d\d$", code)) or code in ("401", "403", "404")

def parse_bat_argline(bat_path):
    """Extract the winws2 argument line from a .bat strategy (one long string,
    original quoting preserved). Same rules as service.ps1 Get-Winws2Args."""
    raw = open(bat_path, encoding="utf-8", errors="replace").read()
    m = re.search(r'winws2\.exe"?\s*(?:\^|--)', raw)
    if not m:
        raise ValueError("no winws2.exe invocation found in %s" % bat_path)
    sub = raw[m.start() + len("winws2.exe"):]
    sub = re.sub(r"\^\s*\r?\n", " ", sub)
    sub = sub.split("\n")[0]
    sub = sub.lstrip(' "')
    sub = (sub.replace("%BIN%", BIN + "\\").replace("%LISTS%", LISTS + "\\")
              .replace("%LUA%", LUA + "\\")
              .replace("%~dp0", ROOT + "\\"))
    return sub.strip()

def spawn_engine_raw(argline, logfile, extra=""):
    """Spawn winws2 passing the command line AS A RAW STRING.
    subprocess list2cmdline would backslash-escape the embedded quotes and
    winws2's own tokenizer does not understand that (lua chunk corruption).
    A raw string reproduces the SCM/binPath scenario exactly."""
    lf = open(logfile, "ab")
    cmd = '"%s" %s %s' % (WINWS2, argline, extra)
    p = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return p, lf

def need_engine_prereqs():
    if not is_admin():
        print("ERROR: admin rights required. Run from service.ps1 menu or an elevated console.")
        return False
    if not os.path.exists(WINWS2):
        print("ERROR: %s not found" % WINWS2)
        return False
    return True

class ServicePause:
    """Stop zapret2 for a test window, always restore (even on exceptions)."""
    def __init__(self):
        self.was = service_state("zapret2") == "RUNNING"
    def __enter__(self):
        if self.was:
            print("stopping zapret2 service for the test window ...")
            stop_service("zapret2")
        return self
    def __exit__(self, *exc):
        if self.was:
            print("restoring zapret2 service ...")
            print("zapret2: %s" % start_service("zapret2"))
        return False

# ================================================================ 4. debug
DBG_PROFILE = re.compile(r"desync profile (\d+)(?: \(([^)]*)\))? matches")
DBG_SNI = re.compile(r"change SNI : (\S+) => (\S+)")
DBG_FUN = re.compile(r"^\s*\[?\d*\]?\s*(\w+):\s*(sending|applying|drop)")
DBG_LUAERR = re.compile(r"LUA ERROR")

def cmd_debug(a):
    if not need_engine_prereqs():
        return 2
    bat = a.bat if os.path.exists(a.bat) else os.path.join(ROOT, a.bat)
    if not os.path.exists(bat):
        print("ERROR: %s not found" % a.bat)
        return 2
    os.makedirs(LOGS, exist_ok=True)
    argline = parse_bat_argline(bat)
    argline = re.sub(r"--debug(=\S+)?\s*", "", argline)  # force our own target
    logfile = os.path.join(LOGS, "debug_live.log")
    open(logfile, "w").close()

    print("debug session: %s" % os.path.basename(bat))
    print("log: %s   (Ctrl+C to stop)" % logfile)
    with ServicePause():
        p, lf = spawn_engine_raw(argline, logfile, "--debug=@\"%s\"" % logfile)
        time.sleep(1.5)
        if p.poll() is not None:
            print("ERROR: engine exited immediately, last log lines:")
            lf.close()
            print("".join(open(logfile, errors="replace").readlines()[-15:]))
            return 1
        prof_hits = {}
        sni_rewrites = {}
        lua_errors = []
        pos = 0
        t0 = time.time()
        try:
            while time.time() - t0 < a.duration:
                if p.poll() is not None:
                    print("engine exited on its own.")
                    break
                try:
                    with open(logfile, errors="replace") as f:
                        f.seek(pos)
                        chunk = f.read()
                        pos = f.tell()
                except OSError:
                    chunk = ""
                for line in chunk.splitlines():
                    m = DBG_PROFILE.search(line)
                    if m:
                        key = m.group(1) + (" (%s)" % m.group(2) if m.group(2) else "")
                        prof_hits[key] = prof_hits.get(key, 0) + 1
                    m = DBG_SNI.search(line)
                    if m:
                        k = "%s -> %s" % (m.group(1), m.group(2))
                        sni_rewrites[k] = sni_rewrites.get(k, 0) + 1
                    if DBG_LUAERR.search(line):
                        lua_errors.append(line.strip())
                        print("LUA ERROR: %s" % line.strip())
                time.sleep(1.0)
        except KeyboardInterrupt:
            pass
        if not stop_engine_graceful(p):
            print("WARNING: engine ignored CTRL_BREAK - close its window manually!")
        lf.close()

    print("\n=== debug summary ===")
    if prof_hits:
        print("profile hits:")
        for prof, n in sorted(prof_hits.items(), key=lambda x: -x[1]):
            print("  profile %-4s %d hits" % (prof, n))
    else:
        print("profile hits: none seen (no intercepted traffic during the window?)")
    if sni_rewrites:
        print("SNI rewrites:")
        for k, n in sorted(sni_rewrites.items(), key=lambda x: -x[1]):
            print("  %-40s %d" % (k, n))
    print("lua errors: %d" % len(lua_errors))
    return 0

# ================================================================ 5. config
def cmd_config(a):
    bat = a.bat if os.path.exists(a.bat) else os.path.join(ROOT, a.bat)
    if not os.path.exists(bat):
        print("ERROR: %s not found" % a.bat)
        return 2
    argline = parse_bat_argline(bat)
    out = a.out or os.path.join(ROOT, "zapret2.conf")
    # one token per line; quoting from the bat is preserved verbatim -
    # winws2 reads the file with the same tokenizer as the command line
    tokens = re.findall(r'"[^"]*"|\S+', argline)
    with open(out, "w", newline="\r\n") as f:
        f.write("\r\n".join(tokens) + "\r\n")
    print("written: %s (%d options)" % (out, len(tokens)))
    # validate: a copy with --dry-run appended (@file must be the only arg,
    # so the flags go inside the copy). --wf-dup-check=0: the running service
    # holds the same WinDivert filter and would abort the probe otherwise.
    probe_conf = out + ".dryrun"
    shutil.copyfile(out, probe_conf)
    with open(probe_conf, "a") as f:
        f.write("\r\n--wf-dup-check=0\r\n--dry-run\r\n")
    r = subprocess.run('"%s" @"%s"' % (WINWS2, probe_conf),
                       capture_output=True, text=True)
    os.remove(probe_conf)
    tail = (r.stdout + r.stderr).strip().splitlines()
    if r.returncode == 0:
        print("dry-run: OK")
        print("install it via service.ps1 menu 1 choosing this .conf, or manually:")
        print('  sc create zapret2 binPath= "\\"%s\\" @\\"%s\\"" start= auto' % (WINWS2, out))
        return 0
    print("dry-run FAILED (code %d):" % r.returncode)
    print("\n".join(tail[-10:]))
    return 1

# ================================================================ 6. watch
WATCH_STATE = os.path.join(LOGS, "dpiwatch.json")
WATCH_HIST = os.path.join(LOGS, "dpiwatch_history.log")

def cmd_watch(a):
    os.makedirs(LOGS, exist_ok=True)
    domains = a.domains or WATCH_DEFAULT_DOMAINS
    state = {}
    if os.path.exists(WATCH_STATE):
        try:
            state = json.load(open(WATCH_STATE))
        except Exception:
            state = {}
    print("dpi watch: %s (Ctrl+C to stop)" % ", ".join(domains))
    try:
        while True:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            changed = False
            for d in domains:
                code, sec = probe(d)
                prev = state.get(d, {}).get("code")
                mark = ""
                if prev is not None and ok_code(prev) != ok_code(code):
                    mark = "  <<< DPI WINDOW FLIP (was %s)" % prev
                    changed = True
                state[d] = {"code": code, "sec": sec,
                            "ts": datetime.datetime.now().isoformat()}
                line = "%s %-24s HTTP %-4s %5.2fs%s" % (ts, d, code, sec, mark)
                print(line)
                # append-only history for long-term DPI window analysis;
                # the json keeps only the last state per domain
                with open(WATCH_HIST, "a", encoding="utf-8") as hf:
                    hf.write(line + "\n")
            json.dump(state, open(WATCH_STATE, "w"), indent=1)
            if changed:
                print("window change detected - consider re-running blockcheck")
            if a.once:
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        pass
    return 0

# ================================================================ 7. update
GH_API = "https://api.github.com/repos/%s/releases/latest"

def gh_latest(repo):
    import urllib.request
    req = urllib.request.Request(GH_API % repo,
                                 headers={"User-Agent": "ztool"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r).get("tag_name", "?")
    except Exception as e:
        return "ERR: %s" % e

def local_engine_version():
    r = subprocess.run([WINWS2, "--version"], capture_output=True, text=True)
    m = re.search(r"v([\d.]+)", r.stdout + r.stderr)
    return m.group(1) if m else "?"

def local_tgproxy_version():
    ini = os.path.join(ROOT, "tg-ws-proxy", "proxy", "__init__.py")
    if not os.path.exists(ini):
        return None
    m = re.search(r'__version__\s*=\s*"([^"]+)"', open(ini).read())
    return m.group(1) if m else "?"

def local_flowseal_version():
    # the Flowseal checkout lives next to the project dirs, version in dir name
    parent = os.path.dirname(ROOT)
    for base in (parent, os.path.expanduser(r"~\Documents")):
        try:
            for d in os.listdir(base):
                m = re.match(r"zapret-discord-youtube-([\d.]+)$", d)
                if m:
                    return m.group(1)
        except OSError:
            pass
    return None

def cmd_update(a):
    checks = [
        ("zapret2 engine", "bol-van/zapret2", local_engine_version()),
        ("Flowseal lists", "Flowseal/zapret-discord-youtube", local_flowseal_version()),
        ("tg-ws-proxy", "Flowseal/tg-ws-proxy", local_tgproxy_version()),
    ]
    for name, repo, local in checks:
        latest = gh_latest(repo).lstrip("v")
        local_s = (local or "not found").lstrip("v")
        if latest.startswith("ERR"):
            print("%-16s local %-12s latest %s" % (name, local_s, latest))
        elif local and local_s == latest:
            print("%-16s local %-12s latest %-12s up to date" % (name, local_s, latest))
        else:
            print("%-16s local %-12s latest %-12s <-- UPDATE AVAILABLE: github.com/%s/releases"
                  % (name, local_s, latest, repo))
    print("\nnote: engine and lua\\ must update TOGETHER (lua_compat_ver),")
    print("see MIGRATION_ZAPRET2.md section 3 before upgrading the engine.")
    return 0

# ================================================================ 8. hostlists
def read_hostlist(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s.lower())
    return out

def cmd_hostlists(a):
    if a.action == "stats":
        files = sorted(f for f in os.listdir(LISTS) if f.endswith(".txt"))
        for f in files:
            entries = read_hostlist(os.path.join(LISTS, f))
            dup = len(entries) - len(set(entries))
            print("%-28s %5d entries, %d dupes" % (f, len(entries), dup))
        return 0
    if not a.file:
        print("ERROR: file required (in lists\\)")
        return 2
    path = a.file if os.path.exists(a.file) else os.path.join(LISTS, a.file)
    if not os.path.exists(path):
        print("ERROR: %s not found" % a.file)
        return 2
    if a.action == "dedupe":
        entries = read_hostlist(path)
        uniq = sorted(set(entries))
        shutil.copyfile(path, path + ".bak")
        with open(path, "w", newline="\r\n") as f:
            f.write("\r\n".join(uniq) + "\r\n")
        print("%s: %d -> %d entries (backup: %s.bak)" % (path, len(entries), len(uniq), path))
        return 0
    if a.action == "resolve":
        import socket
        entries = sorted(set(read_hostlist(path)))
        print("resolving %d domains ..." % len(entries))
        def res(d):
            try:
                socket.setdefaulttimeout(4)
                socket.gethostbyname(d)
                return d, True
            except Exception:
                return d, False
        dead = []
        with ThreadPoolExecutor(max_workers=16) as ex:
            for d, ok in ex.map(res, entries):
                if not ok:
                    dead.append(d)
        print("dead (NXDOMAIN/timeout): %d of %d" % (len(dead), len(entries)))
        for d in dead[:50]:
            print("  %s" % d)
        if len(dead) > 50:
            print("  ... and %d more" % (len(dead) - 50))
        if dead:
            print("review and remove manually or via: hostlists dedupe after editing")
        return 0

# ================================================================ 9. autoanalyze
def cmd_autoanalyze(a):
    path = a.file
    if not path:
        cands = [os.path.join(LISTS, f) for f in os.listdir(LISTS)
                 if "auto" in f.lower()]
        if not cands:
            print("no --hostlist-auto files found in lists\\ (the engine is not")
            print("running with --hostlist-auto; pass a file explicitly)")
            return 1
        path = cands[0]
    if not os.path.exists(path):
        print("ERROR: %s not found" % path)
        return 2
    entries = read_hostlist(path)
    print("%s: %d auto-detected entries" % (path, len(entries)))
    for e in entries[:40]:
        print("  %s" % e)
    if len(entries) > 40:
        print("  ... and %d more" % (len(entries) - 40))
    if entries:
        print("\nto promote into the permanent set: append to lists\\list-general-user.txt")
    return 0

# ================================================================ 10. diag
def cmd_diag(a):
    os.makedirs(LOGS, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(LOGS, "diag_%s.zip" % ts)
    rep = []
    rep.append("=== diag %s ===" % ts)
    rep.append("zapret2 service: %s" % service_state("zapret2"))
    rep.append("zapret  service: %s" % service_state("zapret"))
    for img in ("winws2.exe", "winws.exe"):
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq %s" % img, "/NH"],
                           capture_output=True, text=True)
        rep.append("%s: %s" % (img, "running" if img.lower() in r.stdout.lower() else "no"))
    rep.append("engine version: %s" % local_engine_version())
    rep.append("tg-ws-proxy version: %s" % local_tgproxy_version())
    rep.append("")
    rep.append("=== probes ===")
    for d in WATCH_DEFAULT_DOMAINS:
        code, sec = probe(d)
        rep.append("%-24s HTTP %s %.2fs" % (d, code, sec))
    rep.append("")
    rep.append("=== scheduled tasks ===")
    for t in ("zapret2-ensure", "Telegram WS Proxy AutoStart"):
        r = subprocess.run(["schtasks", "/Query", "/TN", t, "/FO", "LIST"],
                           capture_output=True, text=True)
        rep.append(r.stdout if r.returncode == 0 else "%s: not found" % t)
    r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
    rep.append("=== ipconfig ===")
    rep.append(r.stdout)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("status.txt", "\n".join(rep))
        for f in os.listdir(LOGS):
            if f.endswith(".log"):
                p = os.path.join(LOGS, f)
                try:
                    tail = open(p, errors="replace").readlines()[-200:]
                    z.writestr("logs/" + f, "".join(tail))
                except OSError:
                    pass
        cb = os.path.join(ROOT, "Custom.bat")
        if os.path.exists(cb):
            z.write(cb, "Custom.bat")
    print("diag bundle: %s" % out)
    return 0

# ================================================================ 11. snapshot
def snap_id():
    existing = [d for d in os.listdir(SNAPS) if re.match(r"\d{3}_", d)] if os.path.isdir(SNAPS) else []
    n = max([int(d[:3]) for d in existing], default=0) + 1
    return "%03d_%s" % (n, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))

def snap_save(note=""):
    os.makedirs(SNAPS, exist_ok=True)
    sid = snap_id()
    dst = os.path.join(SNAPS, sid)
    os.makedirs(dst)
    cb = os.path.join(ROOT, "Custom.bat")
    if os.path.exists(cb):
        shutil.copyfile(cb, os.path.join(dst, "Custom.bat"))
    shutil.copytree(PROFS, os.path.join(dst, "profiles"))
    if note:
        open(os.path.join(dst, "note.txt"), "w").write(note)
    return sid

def cmd_snapshot(a):
    if a.action == "save":
        sid = snap_save(" ".join(a.note or []))
        print("snapshot saved: %s" % sid)
        return 0
    if not os.path.isdir(SNAPS):
        print("no snapshots yet")
        return 1
    snaps = sorted(os.listdir(SNAPS))
    if a.action == "list":
        for s in snaps:
            note = ""
            nf = os.path.join(SNAPS, s, "note.txt")
            if os.path.exists(nf):
                note = " - " + open(nf, errors="replace").read().strip()
            print("%s%s" % (s, note))
        return 0
    if not a.id:
        print("ERROR: snapshot id required (see: snapshot list)")
        return 2
    sid = a.id
    matches = [s for s in snaps if s.startswith(sid)]
    if not matches:
        print("ERROR: no snapshot matching '%s'" % sid)
        return 2
    dst = os.path.join(SNAPS, matches[0])
    if a.action == "diff":
        for rel in ["Custom.bat"]:
            cur = os.path.join(ROOT, rel)
            old = os.path.join(dst, rel)
            if os.path.exists(old) and os.path.exists(cur):
                d = list(difflib.unified_diff(
                    open(old, errors="replace").read().splitlines(),
                    open(cur, errors="replace").read().splitlines(),
                    "snapshot/" + rel, "current/" + rel, lineterm=""))
                print("\n".join(d[:120]) if d else "%s: identical" % rel)
        oldp = set(os.listdir(os.path.join(dst, "profiles"))) if os.path.isdir(os.path.join(dst, "profiles")) else set()
        curp = set(os.listdir(PROFS))
        for f in sorted(oldp - curp):
            print("profiles: REMOVED since snapshot: %s" % f)
        for f in sorted(curp - oldp):
            print("profiles: ADDED since snapshot: %s" % f)
        return 0
    if a.action == "restore":
        backup = snap_save("auto-backup before restore of %s" % matches[0])
        if os.path.exists(os.path.join(dst, "Custom.bat")):
            shutil.copyfile(os.path.join(dst, "Custom.bat"), os.path.join(ROOT, "Custom.bat"))
        if os.path.isdir(os.path.join(dst, "profiles")):
            shutil.rmtree(PROFS)
            shutil.copytree(os.path.join(dst, "profiles"), PROFS)
        print("restored: %s (pre-restore state saved as %s)" % (matches[0], backup))
        print("reinstall the service (menu 1) to apply the restored Custom.bat")
        return 0

# ================================================================ 12. wfcheck
def cmd_wfcheck(a):
    if not need_engine_prereqs():
        return 2
    bat = a.bat if os.path.exists(a.bat) else os.path.join(ROOT, a.bat)
    if not os.path.exists(bat):
        print("ERROR: %s not found" % a.bat)
        return 2
    argline = parse_bat_argline(bat)
    os.makedirs(LOGS, exist_ok=True)
    dump = os.path.join(LOGS, "wf_dump.txt")
    r = subprocess.run('"%s" %s --wf-save="%s"' % (WINWS2, argline, dump),
                       capture_output=True, text=True)
    if not os.path.exists(dump):
        print("ERROR: filter was not saved, engine output:")
        print((r.stdout + r.stderr)[-800:])
        return 1
    filt = open(dump, errors="replace").read().strip()
    print("effective WinDivert filter: %d chars, saved to %s" % (len(filt), dump))
    ors = filt.count(" or ")
    print("OR-branches: %d" % ors)
    warns = []
    if re.search(r"tcp\.DstPort\s*==\s*443\b", filt) and "PayloadLength" not in filt:
        warns.append("full tcp/443 capture without payload filter: every https "
                     "packet hits the engine (CPU). Consider --wf-raw-part payload filters.")
    if re.search(r"udp\.DstPort\s*>=?\s*\d+", filt) and "udp.PayloadLength" not in filt:
        warns.append("broad udp range capture (check torrent/p2p offload paths)")
    if "loopback" not in filt:
        warns.append("loopback is not excluded (--wf-filter-loopback=0?)")
    if warns:
        print("\nwarnings:")
        for w in warns:
            print("  ! %s" % w)
    else:
        print("no CPU-trap patterns found")
    return 0

# ================================================================ main
def main():
    ap = argparse.ArgumentParser(prog="ztool", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("debug", help="live debug session with log parsing")
    p.add_argument("bat")
    p.add_argument("--duration", type=int, default=86400)
    p.set_defaults(f=cmd_debug)

    p = sub.add_parser("config", help="convert .bat strategy to winws2 @config file")
    p.add_argument("bat")
    p.add_argument("--out")
    p.set_defaults(f=cmd_config)

    p = sub.add_parser("watch", help="probe domains, detect DPI window changes")
    p.add_argument("domains", nargs="*")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=int, default=300)
    p.set_defaults(f=cmd_watch)

    p = sub.add_parser("update", help="check GitHub for new releases")
    p.set_defaults(f=cmd_update)

    p = sub.add_parser("hostlists", help="hostlist hygiene")
    p.add_argument("action", choices=["stats", "dedupe", "resolve"])
    p.add_argument("file", nargs="?")
    p.set_defaults(f=cmd_hostlists)

    p = sub.add_parser("autoanalyze", help="summarize a hostlist-auto file")
    p.add_argument("file", nargs="?")
    p.set_defaults(f=cmd_autoanalyze)

    p = sub.add_parser("diag", help="collect diagnostic bundle (zip)")
    p.set_defaults(f=cmd_diag)

    p = sub.add_parser("snapshot", help="version snapshots of Custom.bat + profiles")
    p.add_argument("action", choices=["save", "list", "diff", "restore"])
    p.add_argument("id", nargs="?")
    p.add_argument("note", nargs="*")
    p.set_defaults(f=cmd_snapshot)

    p = sub.add_parser("wfcheck", help="dump and analyze the WinDivert filter")
    p.add_argument("bat")
    p.set_defaults(f=cmd_wfcheck)

    a = ap.parse_args()
    return a.f(a)

if __name__ == "__main__":
    sys.exit(main())
