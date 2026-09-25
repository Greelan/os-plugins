# Changelog

## 1.3_4 - 2026-09-25

- Importing a URL is faster: the list of Apprise services is built once per request.

## 1.3_3 - 2026-09-25

- Failed logins shortly before midnight are no longer missed when the audit log moves to a new day.
- Raising the System Status level no longer reports the items it hides as resolved.
- Queued notifications dropped over the queue limit are logged.

## 1.3_2 - 2026-09-25

- A saved template, key or other optional secret on a channel can be removed with the Remove link under it; typing a new value replaces it.

## 1.3 - 2026-09-25

- Files a service uses, such as a Discord or Telegram template, FCM and VAPID keys or PGP keys, are pasted into the channel and stored with it, and templates and public keys may be an https address; a URL can no longer point at a local file.
- Text from outside, such as a failed login's user name, is escaped for services that show HTML.

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
