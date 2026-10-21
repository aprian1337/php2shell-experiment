# PHP2Shell Lab

Docker lab reproducing **CVE-2026-109618** and **CVE-2026-109619** (publicly called PHP2Shell) on PHP **8.2.34**, the last 8.2.x release before the fix.

`check.py` verifies whether an endpoint sits on the vulnerable code path. It ships **no exploit payload**: reachability only, never code execution.

> [!WARNING]
> **Lab experiment only.** Run this against the Docker containers on your own machine.
> Do **not** run it against real websites, third-party servers, or any host you do not
> control. It is not a scanner or a pentest tool, and the OOM probe can crash PHP
> workers and drop connections for everyone on that host.

## The bugs

| CVE | Advisory | Failure |
|---|---|---|
| **CVE-2026-109618** | GHSA-w8hw-w9fx-j79w | Fatal OOM calls `longjmp()`, skipping cleanup. Request shutdown then runs on half-initialized state. Apache mod_php is worst, since it invokes shutdown unconditionally. |
| **CVE-2026-109619** | GHSA-6wmf-4rv5-p3rp | After a fatal error the worker keeps globals pointing at freed request memory. The next request trusts the dangling pointer: use-after-free, memory disclosure, or OPcache type confusion. |

- **One root cause:** request-owned pointers live in worker-global state, and a fatal error aborts before clearing them.
- **Affected:** PHP 5.4.0 through 8.5.11. **Fixed:** 8.2.35, 8.3.36, 8.4.27, 8.5.12.
- **Severity:** CVSS 9.2, pre-auth, application-agnostic (the bug is in the engine, not any app).
- **Enabling feature:** `session.upload_progress`, on by default since 5.4. It parses multipart POSTs in the SAPI layer before any app code runs, so no login or cooperating app is needed.

Found by Wiz Research with Calif and OpenAI, disclosed and patched 2026-10-21.

## The lab

Four containers, pinned to exact tags so a rebuild gives the same PHP:

| Container | Image | Port | Role |
|---|---|---|---|
| `php2shell-apache` | `php:8.2.34-apache` | `18080` | mod_php, `memory_limit` 32M so the OOM probe trips. Chain D target. |
| `php2shell-fpm` | `php:8.2.34-fpm` | `9000` (internal) | PHP-FPM, `memory_limit` 128M, `pm.max_requests` 500 so workers survive across requests. |
| `php2shell-nginx` | `nginx:1.27-alpine` | `18081` | Fronts FPM. Needs `fastcgi_request_buffering off` so uploads stream and progress tracks mid-flight. |
| `php2shell-asan` | built from `lab/asan/` | `18082` | PHP 8.2.34 compiled with AddressSanitizer. `check.py uaf` arms it and reads the sanitizer report, confirming the heap-use-after-free itself. |

Both PHP containers share `lab/www` and these effective ini values:

```ini
session.upload_progress.enabled = On
session.upload_progress.min_freq = 1
memory_limit      = 32M (apache) / 128M (fpm)
post_max_size     = 8M
session.save_path = /tmp
```

- `index.php` — calls `session_start()` and echoes version, `min_freq`, session id, and session contents as JSON, so the script can read progress back out.
- `lfi_lab.php` — a deliberate LFI sink for Chain A. Lab-only; never let it leave an isolated environment.

## Prerequisites

Docker + Compose plugin (verified on Docker 29.8.0 / Compose v5.5.1), Python 3.8+ (verified on 3.13.0), and ~1 GB disk. No PHP toolchain on the host; PHP lives only inside the containers. `check.py` is stdlib-only, so there is nothing to `pip install`.

## Quick start

```bash
cd lab && docker compose up -d --build
```

Then, from the repo root:

```bash
# 1) Is session.upload_progress reachable, and does it issue a PHPSESSID?
python3 check.py probe --target http://127.0.0.1:18080/

# 2) Stall-window arming test. --docker cats /tmp/sess_<sid> mid-stall.
python3 check.py arm --target http://127.0.0.1:18080/ \
    --stall 1.5 --rounds 3 --docker php2shell-apache

# 3) OOM precondition (Chain D) against mod_php.
python3 check.py oom --target http://127.0.0.1:18080/

# Same arming test against the FPM stack.
python3 check.py arm --target http://127.0.0.1:18081/ --docker php2shell-fpm

# 4) ASAN-confirmed heap-use-after-free. Requires the asan image (first build
#    compiles PHP from source and takes a few minutes).
python3 check.py uaf --target http://127.0.0.1:18082/ --docker php2shell-asan
```

Teardown: `docker compose down -v` (from inside `lab/`).

## What each check proves

### `probe`

Sends a GET, then a small multipart POST with a `PHP_SESSION_UPLOAD_PROGRESS` field and no cookie. Vulnerable default-config PHP issues `Set-Cookie: PHPSESSID` from the upload handler itself, and flags the version if it predates a fixed release. **Exit 0 = feature on.** Confirms the config prerequisite only; says nothing about whether a worker would actually corrupt memory.

### `arm`

The check that maps to the bug. Sends a multipart POST over a raw socket in two halves with a deliberate pause:

```
chunk1  →  stall > min_freq (1s)  →  chunk2  →  finish
```

The first chunk makes the rfc1867 callback cache `zval*` pointers into the session HashTable. The stall lets the next callback re-run `php_session_initialize()`, freeing that HashTable. The second chunk writes `bytes_processed` through the now-stale pointer. That write is the use-after-free.

Success, captured mid-stall from inside the container:

```
upload_progress_php2shell-verify|a:5:{s:10:"start_time";i:1792606561;
s:14:"content_length";i:131376;s:15:"bytes_processed";i:5241; ...}
```

> [!NOTE]
> The progress key is cleared once the upload completes, so reading the session file
> *after* the request returns empty. Expected, not a failure.

**Two gotchas for a reliable run.** First, the default first chunk is **64 KiB**; a tiny chunk never gets the rfc1867 handler far enough to flush progress to disk, so nothing appears mid-stall. Second, on the FPM stack nginx must have `fastcgi_request_buffering off`, or it buffers the whole body and PHP never sees a partial upload.

Reaching the arming path is **not** code execution. It means the vulnerable sequence is reachable on that build.

### `oom`

Checks the CVE-2026-109619 precondition: can a fatal OOM be forced during multipart parsing. Two tricks combine. `Transfer-Encoding: chunked` with no `Content-Length` stops PHP from pre-checking the body against `post_max_size`; then one multipart part carrying ~10,000 header lines of 4,000 bytes each pushes engine memory past `memory_limit` while the wire payload stays modest.

```
Allowed memory size of 33554432 bytes exhausted (tried to allocate 4096 bytes)
```

Needs `display_errors=On` (the lab sets it). On production you get a bare 500 and must read logs; on PHP-FPM the worker child tends to exit rather than render the fatal. This check is really only meaningful against **Apache mod_php**.

### `uaf`

The memory-corruption confirmation. Runs the same stall-window arming sequence as `arm`, but against the `php2shell-asan` container (PHP 8.2.34 built with `-fsanitize=address`, `USE_ZEND_ALLOC=0`). After each round it cats the sanitizer log out of the container. A capture looks like:

```
==12==ERROR: AddressSanitizer: heap-use-after-free on address ...
WRITE of size 8 at ... thread T0
    #0 php_session_initialize ext/session/session.c:...
    #1 php_rfc1867_callback ext/session/session.c:...
```

That is the stale-pointer write described under `arm`, made visible by the sanitizer. **Exit 0 = UAF confirmed.** It is still not code execution; it is the bug itself, caught red-handed. No report usually means patched PHP, a non-ASAN container, or a first chunk under 64 KiB.

## Control experiment

A check *failing* against a patched build is the expected result and proves the harness is honest. An override file ships for this:

```bash
cd lab
docker compose -f docker-compose.yml -f docker-compose.patched.yml up -d --build
python3 ../check.py arm --target http://127.0.0.1:18080/ --docker php2shell-apache
python3 ../check.py uaf --target http://127.0.0.1:18082/ --docker php2shell-asan
```

That swaps the PHP images to `php:8.2.35-*`. Expected: `probe` still says `FEATURE-ON` (the ini setting did not change), `arm` may still complete its HTTP sequence (the feature is real), but the mid-stall session no longer contains the vulnerable write path and `uaf` produces **no ASAN report**. That contrast is the evidence the harness distinguishes vulnerable from patched.

The patch (php-src `3584a98bda` + `31c0ea7d7ff`) removes the cached `zval*` pointer, turns the hard OOM `longjmp()` into a soft error at a VM safe point, resets all long-lived state at shutdown, and keeps upload-progress-decoded objects as `__PHP_Incomplete_Class` so no autoload or `__destruct()` runs. Full walkthrough in [`docs/PATCH-ANALYSIS.md`](docs/PATCH-ANALYSIS.md).

## External targets

`--target` accepts any URL, but the intended target is the local Docker lab. There is no support for scanning, enumeration, or host sweeps. Against a host you *do* control, a remote run is still weaker than the lab: `display_errors=Off` hides the OOM fatal, a WAF may block the multipart shape, and `probe`/`arm` prove reachability on the endpoints they hit, not that a specific worker corrupts. The lab is ground truth; a remote result is a hint.

## Mitigation

| Priority | Action |
|---|---|
| **1. Patch** | Install **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. LTS vendors backported fixes for older branches; the PHP team published source backports for 7.4, 8.0, 8.1. EOL branches get no binaries. |
| **2. Stopgaps (partial)** | `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` (8.5.x), `memory_limit=-1`, `pm.max_requests=1`. Each covers some chains, none cover all. Chain D lives in the Zend core, so ini settings alone do not close it. The only complete defense is the patch. |
| **3. Detect** | First-pass network signatures (Suricata + ModSecurity) ship in [`detection/php2shell.rules`](detection/php2shell.rules). They catch the *shape* of the traffic (progress field in multipart, chunked-without-Content-Length, absurd header counts), not the bug itself. Pair with the host signals below: memory-limit fatals, repeated 500s, malformed oversized `PHPSESSID` cookies (the disclosure arm reflects worker memory into that cookie), worker churn, `httpd`/`apache2`/`php-fpm` spawning `sh`/`bash`. |

## Disclosure timeline

See [`docs/TIMELINE.md`](docs/TIMELINE.md). Summary: discovered 2026-08-19, reported 2026-08-24, patched and disclosed 2026-10-21. The bug sat in default-enabled code for 14 years.

## Layout

```
PHP2Shell/
├── check.py                        # verification script (stdlib only)
├── detection/
│   └── php2shell.rules             # Suricata + ModSecurity first-pass signatures
├── docs/
│   ├── PATCH-ANALYSIS.md           # what the php-src commits actually changed
│   └── TIMELINE.md                 # discovery to disclosure
├── lab/
│   ├── docker-compose.yml          # the four services above
│   ├── docker-compose.patched.yml  # override: php:8.2.35-* for the control run
│   ├── asan/Dockerfile             # builds PHP 8.2.34 with -fsanitize=address
│   ├── apache/php.ini              # 32M memory_limit for the OOM probe
│   ├── fpm/php.ini                 # 128M memory_limit
│   ├── fpm/zz-pm.conf              # pm.max_requests 500
│   ├── fpm/nginx.conf              # fastcgi_request_buffering off
│   └── www/                        # index.php + lfi_lab.php
└── README.md
```

## References

- [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce)
- [JFrog](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- [Qi Deng, chains A–D](https://qideng.substack.com/p/php2shell-dissecting-phps-critical)
- Patch: php-src `3584a98bda`, `31c0ea7d7ff`
