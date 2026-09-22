# Changelog

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
