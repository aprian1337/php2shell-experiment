# PHP2Shell Lab

A self-contained reproduction environment for CVE-2026-109618 and CVE-2026-109619 (publicly called PHP2Shell), plus a verification script that confirms whether an endpoint sits on the vulnerable code path. The lab runs PHP 8.2.34, which is the last 8.2.x release before the fix. It ships no exploit payload. Everything here checks for reachability of the bug, not code execution.

## Scope and authorization

Run this only against machines you own or have written permission to test. The verification script will happily point at any URL you give it; that is your responsibility, not the tool's. Pointing it at infrastructure you do not control is a crime in most jurisdictions.

The two flaws were found by Wiz Research with Calif and OpenAI, disclosed 2026-10-21, and patched the same day. Both rate CVSS 9.2. Both are pre-authentication and application-agnostic, meaning the bug sits in the PHP engine itself and does not need a vulnerable app on top. WordPress, Drupal, and Joomla were used as demonstration targets only to show reach, not because any of them are required.

## What the bugs are

| CVE | Advisory | Failure |
|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | Out-of-memory handling. A fatal OOM calls `longjmp()` and skips cleanup, so request shutdown runs on half-initialized state. Apache mod_php is worst here because it invokes shutdown unconditionally. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | Stale global state. After a fatal error the worker keeps globals that still point at freed request memory. The next request on that worker trusts the dangling pointer, giving use-after-free, memory disclosure, or OPcache type confusion. |

One root cause produces both. PHP stores request-owned pointers in worker-global state, and a fatal error (most easily OOM) aborts before those pointers are cleared. PHP 5.4.0 through 8.5.11 are affected. Fixed releases are 8.2.35, 8.3.36, 8.4.27, and 8.5.12.

The enabling feature is `session.upload_progress`, on by default since PHP 5.4. It parses multipart POST bodies in the SAPI layer before any application code runs, in `php_session_rfc1867_callback`. That is why the bug needs no login and no cooperating application.

## What the lab is made of

Three containers, all pinned to exact image tags so a rebuild tomorrow gives the same PHP:

| Container | Image | Port | Role |
|---|---|---|---|
| `php2shell-apache` | `php:8.2.34-apache` | 18080 | Apache with mod_php. `memory_limit` set to 32M so the OOM probe can trip it. This is the Chain D target. |
| `php2shell-fpm` | `php:8.2.34-fpm` | (internal 9000) | PHP-FPM, `memory_limit` 128M, `pm.max_requests` 500 so workers stay alive and stale state can persist across requests. |
| `php2shell-nginx` | `nginx:1.27-alpine` | 18081 | Fronts the FPM container. `fastcgi_request_buffering off` is required so the upload body streams and progress can be tracked mid-upload. |

Both PHP containers share `lab/www` and carry a `php.ini` drop-in in `lab/*/php.ini`. Confirmed effective values inside the containers:

```
session.upload_progress.enabled => On
session.upload_progress.min_freq => 1
memory_limit       => 32M (apache) / 128M (fpm)
post_max_size      => 8M (both)
session.save_path  => (unset, so /tmp)
```

Two PHP files, both deliberately simple:

- `lab/www/index.php`: calls `session_start()` and prints PHP version, whether upload progress is on, the `min_freq` value, the session id, and the session contents as JSON. It exists so the script can read progress data back out of a session for verification.
- `lab/www/lfi_lab.php`: a local-file-inclusion sink, included so Chain A can be demonstrated against this lab. It is a known-vulnerable file that must never leave an isolated environment.

## Prerequisites

- Docker with the Compose plugin. Verified here on Docker 29.8.0 and Compose v5.5.1.
- Python 3.8 or newer. Verified here on 3.13.0.
- `check.py` uses only the Python standard library (`socket`, `ssl`, `argparse`, `subprocess`, `json`, `re`). There is nothing to `pip install`.
- Roughly 1 GB of disk for the images.
- No PHP toolchain is needed on the host. PHP exists only inside the containers.

## Files

```
PHP2Shell/
├── check.py                  # verification script, stdlib only
├── lab/
│   ├── docker-compose.yml    # the three services above
│   ├── apache/php.ini        # 32M memory_limit for the OOM probe
│   ├── fpm/php.ini           # 128M memory_limit, pm.max_requests 500
│   ├── fpm/nginx.conf        # fastcgi_request_buffering off
│   └── www/
│       ├── index.php         # status endpoint, echoes session
│       └── lfi_lab.php       # lab-only LFI sink for Chain A
└── README.md
```

## Running it

Start the lab:

```bash
cd lab
docker compose up -d --build
```

Three checks, run from the `PHP2Shell` directory:

```bash
# 1) Is the upload-progress feature reachable, and does it issue a PHPSESSID?
python3 check.py probe --target http://127.0.0.1:18080/

# 2) Stall-window arming test against mod_php.
#    --docker reads /tmp/sess_<sid> out of the container mid-stall.
python3 check.py arm --target http://127.0.0.1:18080/ \
    --stall 1.5 --rounds 3 --docker php2shell-apache

# 3) OOM precondition, Chain D, against mod_php.
#    Chunked encoding bypasses post_max_size; ~40MB of headers passes 32M memory_limit.
python3 check.py oom --target http://127.0.0.1:18080/

# Same arming test against the FPM stack instead.
python3 check.py arm --target http://127.0.0.1:18081/ --docker php2shell-fpm
```

Tear down with `docker compose down -v` from inside `lab/`.

## What each check proves

### `probe`

Sends a GET, then a small multipart POST containing a `PHP_SESSION_UPLOAD_PROGRESS` field and no cookie. A vulnerable, default-configured PHP issues `Set-Cookie: PHPSESSID` from the upload handler itself. It also reports the PHP version, and flags it when it falls below a fixed release. Exit code 0 means the feature is on.

This confirms the configuration prerequisite only. It says nothing about whether a given worker would actually corrupt memory.

### `arm`

This is the check that maps to the bug. It sends a multipart POST over a raw socket in two halves with a deliberate pause in between:

```
chunk1  ->  stall longer than min_freq (1s)  ->  chunk2  ->  finish
```

The first chunk makes the rfc1867 callback cache `zval*` pointers into the session HashTable. The stall lets the next callback re-run `php_session_initialize()`, which frees that HashTable. The second chunk then writes `bytes_processed` through the now-stale pointer. That is the use-after-free write.

Success looks like this, captured mid-stall from inside the container:

```
upload_progress_php2shell-verify|a:5:{s:10:"start_time";i:1792606561;
s:14:"content_length";i:131376;s:15:"bytes_processed";i:5241;
s:4:"done";b:0;s:5:"files";a:1:{...}}
```

Seeing that live progress HashTable is the proof the stall-window re-init path is reachable. Note that the progress key is removed once the upload completes, so reading the session file after the request returns empty. That is expected, not a failure.

Two things matter for a reliable run. First, the default first chunk is 64 KiB. A tiny first chunk does not get the rfc1867 handler far enough to flush progress to disk, so nothing appears mid-stall. Second, on the FPM stack nginx must have `fastcgi_request_buffering off`, or nginx buffers the whole body and PHP never sees a partial upload.

Reaching the arming path is not code execution. It means the vulnerable sequence is reachable on that build.

### `oom`

This checks the CVE-2026-109619 precondition: can a fatal OOM be forced during multipart parsing. Two techniques combine. The request uses `Transfer-Encoding: chunked` with no `Content-Length`, which stops PHP from pre-checking the body against `post_max_size`. Then a single multipart part carries about 10,000 header lines of 4,000 bytes each, which pushes the engine's own memory past `memory_limit` even though the wire payload is only moderately larger.

A successful run surfaces the fatal:

```
Allowed memory size of 33554432 bytes exhausted (tried to allocate 4096 bytes)
```

This needs `display_errors=On` to be visible in the response, which the lab sets. On a production host with `display_errors=Off` you get a bare 500 instead, and you would need the server logs to tell OOM apart from anything else. On PHP-FPM the worker child tends to exit rather than render the fatal, so this check is really meaningful against Apache mod_php.

## Control experiment

Any of these checks failing against a patched build is the expected result and confirms the harness is not lying to you. Bump the images to `php:8.2.35-apache` and `php:8.2.35-fpm`, rerun, and `arm` and `oom` should stop reporting a reachable path.

The patch, php-src commit `3584a98bda` with `31c0ea7d7ff`, does four things. It removes the long-lived `zval*` cache and re-derives the pointer on each write. It turns the hard OOM `longjmp()` into a soft error raised at a VM safe point, so cleanup always runs and pointers are always cleared before memory is freed. It resets all long-lived state (backtrace, OPcache, session, error globals) at request shutdown unconditionally. It keeps objects decoded by the upload-progress handler as `__PHP_Incomplete_Class`, so no autoload and no `__destruct()` run.

## Using an external target

`check.py --target` takes any URL. Three reasons a remote run is weaker than the lab. `display_errors=Off` hides the OOM fatal, so `oom` goes inconclusive. A WAF, including Cloudflare's temporary PHP2Shell rules, may block the multipart shape outright. And `probe` and `arm` prove feature reachability on the endpoints they reach, not that a specific worker would corrupt. The lab is the ground truth; a remote result is a hint.

## Mitigation

1. Patch. Install 8.5.12, 8.4.27, 8.3.36, or 8.2.35. Distribution and LTS vendors backported fixes for older branches, and the PHP team published minimal source backports for 7.4, 8.0, and 8.1 for people building from source without a vendor. EOL branches get no binaries.
2. The ini stopgaps are partial, each covering some chains and none covering all. `session.upload_progress.enabled=0`, `fatal_error_backtraces=0` on 8.5.x, `memory_limit=-1`, and `pm.max_requests=1` (which breaks the same-worker requirement). Chain D lives in the Zend core, not in session handling, so ini settings alone do not close it. PHP maintainers stated plainly that the only complete defense is the patch.
3. Watch for the signals: multipart bursts followed by memory-limit fatals or repeated 500s, malformed oversized `PHPSESSID` cookies (the memory-disclosure arm reflects worker memory into that cookie), unexpected PHP worker churn, and `httpd`, `apache2`, or `php-fpm` spawning `sh` or `bash` children.

## References

- Wiz Research: https://www.wiz.io/blog/php2shell-php-rce
- JFrog: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Qi Deng, chains A through D: https://qideng.substack.com/p/php2shell-dissecting-phps-critical
- Patch: php-src commits `3584a98bda` and `31c0ea7d7ff`
