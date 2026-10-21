# Patch analysis: php-src 3584a98bda and 31c0ea7d7ff

Both commits carry the same message:

> Avoid state corruption via bailout
> - Replace bailout on OOM with UnwindExit
> - Properly reset various globals that may be accessed during startup

They are the upstream fixes for **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w) and
**CVE-2026-109619** (GHSA-6wmf-4rv5-p3rp), landed across the supported branches
and shipped as 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 on 2026-10-21.

| Commit | Parent | Diffstat | Branch |
|---|---|---|---|
| `3584a98bda` | `512c04e` | 389 files, +10,759 / -988 | 8.2 / 8.3 line |
| `31c0ea7d7ff` | `dd83055` | 423 files, +11,556 / -1,017 | 8.4 / 8.5 line |

The 8.4/8.5 commit touches more files because that line also needed OOM-path
cleanups in newer extensions. The semantic change is the same in both.

Co-authors: Ilija Tovilo, Jakub Zelenka, Nora Dossche, Nicolas Grekas, with
review from Arnaud, Tim Düsterhus, Máté, and Dmitry.

## What actually changed

### 1. Bailout becomes UnwindExit

Before: a fatal OOM called `zend_error` -> `bailout` (`longjmp`). The jump
skipped every destructor, every module RSHUTDOWN, and request shutdown
bookkeeping. mod_php is the worst SAPI because it invokes request shutdown
unconditionally after the longjmp lands, running cleanup on half-initialized
state.

After: the OOM path raises `UnwindExit`, a VM-level unwind that passes through
the normal shutdown sequence. Modules get their RSHUTDOWN callbacks. Globals
get cleared in a defined order. The longjmp shortcut is gone from the OOM
path.

Files: `Zend/zend_alloc.c`, `Zend/zend_execute.c`, `Zend/zend_vm_def.h`,
`Zend/zend_API.c`, plus every extension that had an OOM bailout path
(~100 new `oom_*.phpt` tests pin the new behavior).

### 2. session.c stops caching request-owned zvals

The root cause of the stall-window UAF (CVE-2026-109619): the rfc1867 upload
handler held `zval*` pointers into the session HashTable as file-scope state.
Between two progress callbacks the stall lets `php_session_initialize()` run
again, freeing that HashTable. The next callback then writes
`bytes_processed` through the stale pointer.

The patch removes the long-lived `zval*` cache. Each callback now resolves
values fresh from the (possibly new) session data, so there is no pointer
left to go stale.

Files: `ext/session/session.c`. Companion tests:
- `rfc1867_no_user_code.phpt` — uploaded objects stay `__PHP_Incomplete_Class`
  so no `__autoload` / `__destruct` runs on attacker-controlled data
- `rfc1867_sid_invalid.phpt` — malformed SID handling
- `rfc1867_incomplete_class_reserved_props.phpt` — reserved property layout

### 3. Long-lived globals reset at shutdown

A second class of dangling state: module globals (opcache, session, standard
library) that stored request-scoped pointers and were not cleared on the way
out. The next request inherited them.

The patch adds explicit resets in the shutdown path for every global that can
be reached during startup. Files span `Zend/`, `ext/opcache/`, `ext/standard/`,
`ext/session/`, and persist.c (opcache shm).

### 4. Unserializer hardening

`ext/standard/var.c` and `var_unserializer.re` were touched so that decoding
untrusted session payloads (the disclosure arm reflects worker memory into
`PHPSESSID`) cannot instantiate arbitrary classes or trigger autoload during
request startup.

## Mapping to this lab's checks

| Lab check | Bug arm | Patch line that closes it |
|---|---|---|
| `probe` (FEATURE-ON) | Config prerequisite | Unchanged. `session.upload_progress` is still on by default after the fix. A FEATURE-ON result against 8.2.35 is expected. |
| `arm` (mid-stall progress capture) | CVE-2026-109619 stall-window UAF | session.c zval cache removal. The progress key may still appear mid-stall (that is a feature, not the bug), but the stale write no longer happens. |
| `uaf` (ASAN report) | Same, memory-corruption confirmation | Same. Against a patched ASAN build, no `heap-use-after-free` report. |
| `oom` (memory-limit fatal) | CVE-2026-109618 longjmp bailout | Bailout -> UnwindExit. The fatal still happens (memory really is exhausted), but shutdown runs cleanly. The fatal alone is not proof of exploitability on a patched build. |

The honest control: run `arm` + `uaf` against 8.2.35. Arming traffic still
completes; the ASAN report does not appear. That contrast is the evidence the
harness distinguishes vulnerable from patched.

## Running the control

```bash
cd lab
docker compose -f docker-compose.yml -f docker-compose.patched.yml up -d --build
python3 ../check.py arm --target http://127.0.0.1:18080/ --docker php2shell-apache
# same against 8.2.34 for the vulnerable baseline
```

## References

- https://github.com/php/php-src/commit/3584a98bda
- https://github.com/php/php-src/commit/31c0ea7d7ff
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
