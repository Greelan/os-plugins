# Changelog

## 1.0_2 - 2026-09-25

- Old backups are removed in one request where the service supports it, and requests share one connection, so lowering the backup count a lot no longer risks a timeout.

## 1.0_1 - 2026-09-25

- A bucket listing that S3 cuts short without a continuation token is reported as an error instead of treated as complete.
- Unexpected errors during Setup/Test S3 show on the page instead of breaking it.

## 1.0 - 2026-09-25

- Initial release.
