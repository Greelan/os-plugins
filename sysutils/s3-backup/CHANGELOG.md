# Changelog

## 1.0_4 - 2026-09-26

- The running configuration is what is sent, found by its contents rather than by the newest file name, and read only once a save in progress has finished.

## 1.0_3 - 2026-09-26

- The newest local backup is found by its time, so a backup with a shorter name no longer stops later ones being sent.

## 1.0_2 - 2026-09-25

- Old backups are removed in one request where the service supports it, and requests share one connection, so lowering the backup count a lot no longer risks a timeout.

## 1.0_1 - 2026-09-25

- A bucket listing that S3 cuts short without a continuation token is reported as an error instead of treated as complete.
- Unexpected errors during Setup/Test S3 show on the page instead of breaking it.

## 1.0 - 2026-09-25

- Initial release.
