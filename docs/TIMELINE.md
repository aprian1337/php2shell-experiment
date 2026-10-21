# Timeline

Dates from the Wiz Research disclosure and the php-src commit metadata. All
times UTC where a time is given.

| Date | Event |
|---|---|
| 2012-03 | `session.upload_progress` ships in PHP 5.4.0. The rfc1867 callback path is now reachable pre-auth on every default install. |
| 2026-08-19 | Wiz Research discovers the first vulnerability (disclosed tooling: Wiz Atlas, Gemini 4 Argon, GPT-5.6 Sol). |
| 2026-08-20 | Unauthenticated RCE confirmed against Drupal on a live target. |
| 2026-08-21 | Unauthenticated RCE confirmed against WordPress. |
| 2026-08-24 | Reported to the PHP security team. |
| 2026-09-21 | PHP acknowledges the report and begins developing the fix. |
| 2026-10-20 | Details leak ahead of the embargo. PHP advances the release schedule. |
| 2026-10-21 14:00 | Patches scheduled/released: 8.5.12, 8.4.27, 8.3.36, 8.2.35. Public disclosure. |
| 2026-10-21 | This lab built against `php:8.2.34` (last vulnerable 8.2.x) for verification. |

## Notes

- Discovery to disclosure: ~2 months. Disclosure to public release: same day,
  after the early leak forced PHP's hand.
- The bug sat in default-enabled code for **14 years**. Nothing in an
  application's code was required; the vulnerable path is in the engine's SAPI
  layer and runs before any app logic.
- Vendor backports exist for older LTS branches. The PHP team published source
  backports for 7.4, 8.0, and 8.1. EOL branches receive no binaries.

## References

- https://www.wiz.io/blog/php2shell-php-rce
- https://github.com/php/php-src/commit/3584a98bda
- https://github.com/php/php-src/commit/31c0ea7d7ff
