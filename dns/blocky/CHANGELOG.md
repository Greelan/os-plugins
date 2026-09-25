# Changelog

## 1.4_4 - 2026-09-25

- Blocky no longer reads or connects to what free text names: zone $INCLUDE lines, resolv files outside the list directory, and Unix sockets for Redis (other than the Redis plugin's) or dnstap are refused, and removed or switched off on upgrade.

## 1.4_3 - 2026-09-25

- The unauthenticated HTTP API is off by default, as upstream has it, and the old default port 4000 is switched off on upgrade.

## 1.4_2 - 2026-09-25

- Files Blocky writes or reads from disk use fixed locations; see the field help.
- Certificate file paths are removed; use the trust store.
- Secrets are no longer sent to the browser.
- Restart Blocky DNS proxy can be run from cron or an ACME automation.

## 1.3_3 - 2026-09-25

- A quote in a cache exclude pattern or query log ignored domain no longer stops Blocky from starting, and neither field can add settings to the generated configuration.
- Importing a config.yml respects read-only accounts and no longer races other saves.
- Download cache directories and CSV or SQLite query log targets must be under /var.

## 1.3_2 - 2026-09-23

- The certificate and key path fields stay hidden until advanced mode is on.

## 1.3_1 - 2026-09-22

- Importing a config.yml that quotes a value no longer fails.

## 1.3 - 2026-09-22

- Internal architecture and namespaces refactored.

## 1.2_1 - 2026-09-21

- A list entry holding several lines no longer breaks the generated configuration.
- An unquoted MAC address in config.yml is reported rather than imported as a number.

## 1.2 - 2026-09-21

- The exported certificate now carries its issuing chain, so clients can validate it.
- Certificate file paths are hidden when a trust store certificate is selected.
- The certificate written to disk is recorded in the log.

## 1.1_1 - 2026-09-20

- Import results no longer show escaped characters.

## 1.1 - 2026-09-20

- Certificate for DoT/DoH can be picked from System: Trust.
- Generated files are removed on uninstall.

## 1.0 - 2026-09-16

- Initial release.
