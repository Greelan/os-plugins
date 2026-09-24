# Changelog

## 1.2_1 - 2026-09-25

- Channel URLs with headers or extra parameters are kept as custom URLs, so those values are not sent to the browser.
- Importing a URL no longer mangles characters such as `&`.
- Queued notifications survive a long shutdown or a failed settings read.

## 1.2 - 2026-09-24

- Channels and settings can only be changed by an administrator, since every event reports on the firewall rather than on one account. This replaces the per-event check added in 1.1.

## 1.1 - 2026-09-24

- A channel can only be given events whose data the account saving it can already see elsewhere in the web interface.

## 1.0_4 - 2026-09-24

- Channel URLs, which hold credentials, are no longer sent to the browser with the channel list.
- The record of queued notifications is readable only by root.

## 1.0_3 - 2026-09-23

- System Status reports each new occurrence, not only the first, and says when one is resolved.
- A configd answer with nothing in it is no longer read as a failure.
- Notifications with nothing but a title, such as a VPN connection, are sent rather than refused.

## 1.0 - 2026-09-22

- Initial release.
