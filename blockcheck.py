#!/usr/bin/env python3
# blockcheck.py - DPI desync technique matrix tester for zapret2 (winws2).
# Windows port of the zapret1 blockcheck idea, adapted to this project layout.
#
# For a given blocked domain it tries desync techniques one by one:
#   stop zapret2 service -> start a temporary winws2 with ONE test profile
#   -> probe with curl -> graceful stop (CTRL_BREAK, never taskkill)
#   -> restore the service -> print the ranked table.
#
# Usage:
#   blockcheck.py <domain> [--proto tls|http|quic] [--quick] [--apply] [--keep-service]
#
#   --proto         protocol level: tls (tcp/443, default), http (tcp/80),
#                   quic (udp/443; needs: python -m pip install aioquic)
#
#   --quick         run only the 5 most promising techniques
#   --apply         save the winning technique as profiles\zz_bc_<domain>.conf
#   --keep-service  do not touch the zapret2 service (fails if it is running:
#                   two engines on the same WinDivert filter are forbidden)
#
# Requires: admin rights, curl.exe (Windows 10+ builtin), winws2 in .\bin.
# Pure stdlib, ASCII-only on purpose (console codepage safety).

import argparse
import ctypes
import datetime
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(ROOT, "bin")
LUA = os.path.join(ROOT, "lua")
PROFS = os.path.join(ROOT, "profiles")
LOGS = os.path.join(ROOT, "logs")
WINWS2 = os.path.join(BIN, "winws2.exe")

CTRL_BREAK_EVENT = 1
PROBE_TIMEOUT = 8          # seconds per curl attempt
PROBE_TRIES = 2
ENGINE_SETTLE = 1.5        # seconds to wait after engine start

# ---------------------------------------------------------------- techniques
# (name, [lua-desync chains]).
TECHNIQUES_TLS = [              # TLS ClientHello level, tcp/443
    ("fake_ggl_x6",
     ["fake:blob=tls_google:repeats=6"]),
    ("fake_ggl_ttl5",
     ["fake:blob=tls_google:ip_ttl=5:repeats=6"]),
    ("fake_ggl_autottl",
     ["fake:blob=tls_google:ip_autottl=-2,3-20:repeats=6"]),
    ("fake_ozon_ts",
     ["fake:blob=tls_ozon:tcp_ts=-600000:repeats=8"]),
    ("fake_ozon_badseq",
     ["fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8"]),
    ("multisplit_1_midsld",
     ["multisplit:pos=1,midsld"]),
    ("multidisorder_1_midsld",
     ["multidisorder:pos=1,midsld"]),
    ("fake_fakedsplit00_ts",
     ["fake:blob=tls_max_ozon:tcp_ts=-600000:repeats=8",
      "fakedsplit:pattern=0x00:tcp_ts=-600000"]),
    ("hostfakesplit_ya_ts",
     ["fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=ya.ru:tcp_ts=-600000",
      "hostfakesplit:host=ya.ru:tcp_ts=-600000"]),
    ("seqovl681_badseq",
     ["fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8",
      "multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google"]),
    ("seqovl652_md_badseq",
     ["fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8",
      "multidisorder:pos=1,midsld:seqovl=652:seqovl_pattern=tls_ozon"]),
]
TECHNIQUES_HTTP = [             # plain HTTP request level, tcp/80
    ("fake_http_x6",
     ["fake:blob=fake_default_http:repeats=6"]),
    ("fake_http_ttl5",
     ["fake:blob=fake_default_http:ip_ttl=5:repeats=6"]),
    ("fake_http_autottl",
     ["fake:blob=fake_default_http:ip_autottl=-2,3-20:repeats=6"]),
    ("fake_http_badseq",
     ["fake:blob=fake_default_http:tcp_seq=-10000:tcp_ack=-66000:repeats=8"]),
    ("multisplit_method",
     ["multisplit:pos=method+2"]),
    ("multisplit_1_host",
     ["multisplit:pos=1,host"]),
    ("multidisorder_host_midsld",
     ["multidisorder:pos=host,midsld"]),
    ("hostfakesplit_ya_ts",
     ["hostfakesplit:host=ya.ru:tcp_ts=-600000"]),
    ("fake_fakedsplit00",
     ["fake:blob=fake_default_http:repeats=8",
      "fakedsplit:pattern=0x00"]),
]
TECHNIQUES_QUIC = [             # QUIC Initial level, udp/443
    ("fake_quic_ggl_x2",
     ["fake:blob=quic_google:repeats=2"]),
    ("fake_quic_ggl_x6",
     ["fake:blob=quic_google:repeats=6"]),
    ("fake_quic_ggl_x11",
     ["fake:blob=quic_google:repeats=11"]),
    ("fake_quic_default_x6",
     ["fake:blob=fake_default_quic:repeats=6"]),
    ("fake_quic_ttl5",
     ["fake:blob=quic_google:ip_ttl=5:repeats=6"]),
    ("fake_quic_autottl",
     ["fake:blob=quic_google:ip_autottl=-2,3-20:repeats=6"]),
]
QUICK_SETS = {
    "tls":  ["fake_ggl_x6", "fake_ozon_badseq", "multisplit_1_midsld",
             "multidisorder_1_midsld", "seqovl681_badseq"],
    "http": ["fake_http_x6", "fake_http_badseq", "multisplit_1_host",
             "multidisorder_host_midsld", "multisplit_method"],
    "quic": ["fake_quic_ggl_x2", "fake_quic_ggl_x6", "fake_quic_ttl5"],
}
TECHNIQUES_ALL = {"tls": TECHNIQUES_TLS, "http": TECHNIQUES_HTTP,
                  "quic": TECHNIQUES_QUIC}

# ---------------------------------------------------------------- refine axes
# After the base matrix, the winner is refined along these axes.
POS_AXIS = ["1", "midsld", "sld", "endhost-1", "1,midsld",
            "sniext+1,midsld", "1,sniext+1,midsld"]
SEQOVL_AXIS = ["1", "5", "64", "480", "568", "652", "664", "679", "681"]
REPEATS_AXIS = ["1", "2", "4", "6", "8", "12"]
# fooling combinations tried on fake chains (None = keep as is)
FOOLING_AXIS = ["tcp_ts=-600000", "tcp_seq=-10000:tcp_ack=-66000",
                "tcp_md5", "tcp_ts=-600000:tcp_md5"]
FOOLING_KEYS = ("tcp_ts", "tcp_seq", "tcp_ack", "tcp_md5")
SPLIT_FUNCS = ("multisplit", "multidisorder", "fakedsplit", "hostfakesplit")
MAX_REFINE = 30          # hard cap on refinement engine restarts

def chain_fname(c):
    return c.split(":")[0]

def set_param(chain, key, value):
    """Replace or append key=value in a 'fname:p1=v1:flag:p2=v2' chain."""
    parts = chain.split(":")
    out, done = [], False
    for p in parts[1:]:
        if p.startswith(key + "="):
            out.append("%s=%s" % (key, value))
            done = True
        else:
            out.append(p)
    if not done:
        out.append("%s=%s" % (key, value))
    return parts[0] + ":" + ":".join(out)

def remove_params(chain, keys):
    parts = chain.split(":")
    out = [p for p in parts[1:] if p.split("=")[0] not in keys]
    return parts[0] + (":" + ":".join(out) if out else "")

def replace_chain(chains, i, new):
    return [new if j == i else c for j, c in enumerate(chains)]

def refine_cases(chains):
    """Generate (label, chains) refinement variants for a winning technique."""
    seen = set()
    for i, c in enumerate(chains):
        fn = chain_fname(c)
        if fn in SPLIT_FUNCS:
            for pos in POS_AXIS:
                nc = set_param(c, "pos", pos)
                if nc != c and nc not in seen:
                    seen.add(nc)
                    yield ("pos=%s" % pos, replace_chain(chains, i, nc))
            if fn in ("multisplit", "multidisorder"):
                for v in SEQOVL_AXIS:
                    nc = set_param(c, "seqovl", v)
                    if "seqovl_pattern" not in nc:
                        nc += ":seqovl_pattern=tls_google"
                    if nc != c and nc not in seen:
                        seen.add(nc)
                        yield ("seqovl=%s" % v, replace_chain(chains, i, nc))
        if fn == "fake":
            for r in REPEATS_AXIS:
                nc = set_param(c, "repeats", r)
                if nc != c and nc not in seen:
                    seen.add(nc)
                    yield ("repeats=%s" % r, replace_chain(chains, i, nc))
            for fz in FOOLING_AXIS:
                nc = remove_params(c, FOOLING_KEYS) + ":" + fz
                if nc != c and nc not in seen:
                    seen.add(nc)
                    yield ("fooling:%s" % fz.split(":")[0].split("=")[0],
                           replace_chain(chains, i, nc))

def aggressiveness(chains):
    """Lower is better: fewer repeats, no fooling, no seqovl."""
    score = 0
    for c in chains:
        for p in c.split(":")[1:]:
            if p.startswith("repeats="):
                score += int(p.split("=")[1])
            elif p.split("=")[0] in FOOLING_KEYS:
                score += 2
            elif p.startswith("seqovl="):
                score += 2
    return score

# ---------------------------------------------------------------- helpers
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def service_state(name):
    r = subprocess.run(["sc.exe", "query", name],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return "NOT_INSTALLED"
    m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", r.stdout)
    return m.group(1) if m else "UNKNOWN"

def stray_engine_running():
    for img in ("winws2.exe", "winws.exe"):
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq %s" % img, "/NH"],
                           capture_output=True, text=True)
        if img.lower() in r.stdout.lower():
            return img
    return None

def probe(domain, proto):
    """Returns (code, seconds) of the best attempt. code is an HTTP status
    for tls/http, or 'H3OK'/'000' for quic (handshake-only)."""
    if proto == "quic":
        return probe_quic(domain)
    scheme = "http" if proto == "http" else "https"
    best = None
    for _ in range(PROBE_TRIES):
        try:
            r = subprocess.run(
                ["curl.exe", "-s", "-o", "NUL", "-w", "%{http_code} %{time_total}",
                 "--max-time", str(PROBE_TIMEOUT), "%s://%s/" % (scheme, domain)],
                capture_output=True, text=True, timeout=PROBE_TIMEOUT + 3)
            parts = r.stdout.split()
            code, sec = parts[0], float(parts[1])
            if best is None or (code != "000" and best[0] == "000") or \
               (code != "000" and best[0] != "000" and sec < best[1]):
                best = (code, sec)
            if code != "000":
                break
        except Exception:
            if best is None:
                best = ("000", float(PROBE_TIMEOUT))
    return best

def probe_quic(domain):
    """QUIC handshake-only probe via aioquic. Returns ('H3OK', sec) on a
    completed handshake, ('000', sec) on timeout/failure."""
    try:
        import asyncio
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
    except ImportError:
        print("ERROR: aioquic is required for --proto quic. Install it:")
        print('  python -m pip install aioquic')
        sys.exit(2)
    async def attempt():
        asyncio.get_event_loop().set_exception_handler(lambda l, c: None)
        cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        t0 = time.monotonic()
        try:
            async with connect(domain, 443, configuration=cfg,
                               wait_connected=True) as _c:
                return True, time.monotonic() - t0
        except Exception:
            return False, time.monotonic() - t0
    best = None
    for _ in range(PROBE_TRIES):
        try:
            ok, sec = asyncio.run(asyncio.wait_for(attempt(),
                                                   timeout=PROBE_TIMEOUT))
        except Exception:
            ok, sec = False, float(PROBE_TIMEOUT)
        code = "H3OK" if ok else "000"
        if best is None or ok or (best[0] == "H3OK" and sec < best[1]):
            best = (code, sec)
        if ok:
            break
    return best

def ok_code(code):
    return code == "H3OK" or bool(re.match(r"^(2|3)\d\d$", code)) \
        or code in ("401", "403", "404")

# ---------------------------------------------------------------- engine
def build_engine_args(domain, chains, proto):
    # lua-init goes through a FILE, not inline text:
    # winws2 splits unquoted option values on commas, and its tokenizer
    # does not understand backslash-escaped quotes (bat/service.exe quoting
    # rules do not apply to a direct process spawn). @file sidesteps both.
    init_file = os.path.join(LOGS, "blockcheck_init.lua")
    with open(init_file, "w", newline="\n") as f:
        f.write("fake_default_tls = tls_mod(fake_default_tls,'rnd,rndsni')\n")
        f.write("tls_ozon = tls_mod(tls_google,'sni=ozon.ru')\n")
        f.write("tls_max_ozon = tls_mod(tls_max,'sni=ozon.ru')\n")
    args = [
        WINWS2,
        "--lua-init=@%s" % os.path.join(LUA, "zapret-lib.lua"),
        "--lua-init=@%s" % os.path.join(LUA, "zapret-antidpi.lua"),
        "--blob=tls_google:@%s" % os.path.join(BIN, "tls_clienthello_www_google_com.bin"),
        "--blob=tls_max:@%s" % os.path.join(BIN, "tls_clienthello_max_ru.bin"),
        "--lua-init=@%s" % init_file,
    ]
    if proto == "quic":
        args += [
            "--wf-udp-out=443",
            "--blob=quic_google:@%s" % os.path.join(
                BIN, "quic_initial_www_google_com.bin"),
            "--filter-udp=443", "--filter-l7=quic",
            "--hostlist-domains=%s" % domain,
            "--payload=quic_initial", "--out-range=-d10",
        ]
    elif proto == "http":
        args += [
            "--wf-tcp-out=80,443",
            "--filter-tcp=80", "--filter-l7=http",
            "--hostlist-domains=%s" % domain,
            "--payload=http_req", "--out-range=-d10",
        ]
    else:
        args += [
            "--wf-tcp-out=80,443",
            "--filter-tcp=443", "--filter-l7=tls",
            "--hostlist-domains=%s" % domain,
            "--payload=tls_client_hello", "--out-range=-d10",
        ]
    for c in chains:
        args.append("--lua-desync=%s" % c)
    return args

def start_engine(args, logfile):
    lf = open(logfile, "ab")
    # new process group: we must be able to send CTRL_BREAK to the engine only
    p = subprocess.Popen(args, stdout=lf, stderr=subprocess.STDOUT,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return p, lf

def stop_engine(p):
    """Graceful stop via CTRL_BREAK. Never TerminateProcess: a force-kill
    wedges the WinDivert driver (FWP_E_IN_USE, reboot to cure)."""
    if p.poll() is not None:
        return True
    ctypes.windll.kernel32.GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, p.pid)
    try:
        p.wait(timeout=10)
        return True
    except subprocess.TimeoutExpired:
        return False

def run_case(domain, name, chains, logfile, proto):
    """Start a test engine with one profile, probe, graceful stop.
    Returns (status, code, sec): status in OK/FAIL/ERR/HANG."""
    args = build_engine_args(domain, chains, proto)
    p, lf = start_engine(args, logfile)
    time.sleep(ENGINE_SETTLE)
    if p.poll() is not None:
        lf.close()
        print("%-34s engine failed to start (see logs\\blockcheck_engine.log)" % name)
        return ("ERR", "000", 0.0)
    code, sec = probe(domain, proto)
    graceful = stop_engine(p)
    lf.close()
    if not graceful:
        print("%-34s WARNING: engine ignored CTRL_BREAK, close it manually!" % name)
        return ("HANG", code, sec)
    mark = "OK " if ok_code(code) else "---"
    print("%-34s %s %s in %.2fs" % (name, mark, code, sec))
    return ("OK" if ok_code(code) else "FAIL", code, sec)

# ---------------------------------------------------------------- apply
def save_profile(domain, tech_name, chains, proto):
    san = re.sub(r"[^A-Za-z0-9]+", "_", domain).strip("_")
    path = os.path.join(PROFS, "zz_bc_%s_%s.conf" % (proto, san))
    # zz_ prefix: sorts last, does not shift the positional profile numbering
    filt = {
        "tls":  ["--filter-tcp=443 --filter-l7=tls --hostlist-domains=%s" % domain,
                 "--payload=tls_client_hello --out-range=-d10"],
        "http": ["--filter-tcp=80 --filter-l7=http --hostlist-domains=%s" % domain,
                 "--payload=http_req --out-range=-d10"],
        "quic": ["--filter-udp=443 --filter-l7=quic --hostlist-domains=%s" % domain,
                 "--payload=quic_initial --out-range=-d10"],
    }[proto]
    lines = [
        "# blockcheck winner for %s (%s) [%s]: %s" % (
            domain, datetime.date.today().isoformat(), proto, tech_name),
    ] + filt
    lines += ["--lua-desync=%s" % c for c in chains]
    with open(path, "w", newline="\r\n") as f:
        f.write("\r\n".join(lines) + "\r\n")
    return path

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="zapret2 desync technique matrix tester")
    ap.add_argument("domain", help="blocked domain to test, e.g. example.com")
    ap.add_argument("--proto", choices=("tls", "http", "quic"), default="tls",
                    help="protocol level to test (default tls)")
    ap.add_argument("--quick", action="store_true", help="only the most promising techniques")
    ap.add_argument("--apply", action="store_true", help="save winner to profiles\\zz_bc_<proto>_<domain>.conf")
    ap.add_argument("--keep-service", action="store_true",
                    help="do not stop/start the zapret2 service (fails if engines run)")
    ap.add_argument("--no-refine", action="store_true",
                    help="skip the refinement pass (axes: pos/seqovl/repeats/fooling)")
    a = ap.parse_args()
    proto = a.proto

    domain = a.domain.lower().strip()
    if not re.match(r"^[a-z0-9.-]+$", domain):
        print("ERROR: domain must be plain ascii (punycode for IDN)")
        return 2
    if not is_admin():
        print("ERROR: admin rights required (WinDivert). Run from service.ps1 menu or an elevated console.")
        return 2
    if not os.path.exists(WINWS2):
        print("ERROR: %s not found" % WINWS2)
        return 2
    os.makedirs(LOGS, exist_ok=True)

    print("=== blockcheck: %s [%s] ===" % (domain, proto))

    # baseline without any engine
    svc = service_state("zapret2")
    svc_was_running = (svc == "RUNNING")
    if svc_was_running:
        if a.keep_service:
            print("ERROR: zapret2 service is RUNNING and --keep-service was given.")
            print("Two engines cannot share one WinDivert filter. Stop the service first.")
            return 2
        print("stopping zapret2 service for the test window ...")
        subprocess.run(["sc.exe", "stop", "zapret2"], capture_output=True)
        time.sleep(2)
    stray = stray_engine_running()
    if stray:
        print("ERROR: stray %s process is running. Close its console window first" % stray)
        print("(never taskkill it - that wedges the WinDivert driver).")
        if svc_was_running:
            subprocess.run(["sc.exe", "start", "zapret2"], capture_output=True)
        return 2

    code, sec = probe(domain, proto)
    print("baseline (no bypass): %s in %.2fs" % (code, sec))
    if ok_code(code):
        print("Domain is NOT blocked here - nothing to test. Done.")
        if svc_was_running:
            subprocess.run(["sc.exe", "start", "zapret2"], capture_output=True)
        return 0

    techniques = TECHNIQUES_ALL[proto]
    if a.quick:
        techs = [t for t in techniques if t[0] in QUICK_SETS[proto]]
    else:
        techs = techniques
    results = []
    logfile = os.path.join(LOGS, "blockcheck_engine.log")
    hang = False
    try:
        print("--- pass 1: technique matrix ---")
        for name, chains in techs:
            status, code, sec = run_case(domain, name, chains, logfile, proto)
            results.append((name, code, sec, chains))
            if status == "HANG":
                hang = True
                break

        good = [r for r in results if ok_code(r[1])]
        if good and not a.no_refine and not hang:
            # refine the least aggressive winner (not the fastest: stability first)
            best = sorted(good, key=lambda r: (aggressiveness(r[3]), r[2]))[0]
            print("--- pass 2: refinement of '%s' (axes: pos/seqovl/repeats/fooling) ---"
                  % best[0])
            n = 0
            for label, vchains in refine_cases(best[3]):
                if n >= MAX_REFINE:
                    print("(refine cap %d reached)" % MAX_REFINE)
                    break
                status, code, sec = run_case(domain, "refine:%s" % label, vchains, logfile, proto)
                results.append(("%s|%s" % (best[0], label), code, sec, vchains))
                n += 1
                if status == "HANG":
                    break
    finally:
        if svc_was_running:
            print("restoring zapret2 service ...")
            subprocess.run(["sc.exe", "start", "zapret2"], capture_output=True)
            time.sleep(1)
            print("zapret2: %s" % service_state("zapret2"))

    good = [r for r in results if ok_code(r[1])]
    print("\n=== results ===")
    if not good:
        print("no technique worked. Likely IP-block or full-reassembly DPI;")
        print("try another provider route/proxy, or re-run in a different DPI window.")
        return 1
    # recommendation: least aggressive among the working, then fastest
    good.sort(key=lambda r: (aggressiveness(r[3]), r[2]))
    print("recommended (least aggressive): %s (%s in %.2fs, score %d)"
          % (good[0][0], good[0][1], good[0][2], aggressiveness(good[0][3])))
    for name, code, sec, chains in good[1:8]:
        print("  also: %-32s %s in %.2fs (score %d)"
              % (name, code, sec, aggressiveness(chains)))
    if a.apply:
        path = save_profile(domain, good[0][0], good[0][3], proto)
        print("\nsaved: %s" % path)
        print("rebuild the strategy via service.ps1 menu 7 (the zz_ profile sorts last),")
        print("then install the new Custom.bat via menu 1.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
