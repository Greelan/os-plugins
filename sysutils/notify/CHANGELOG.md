# Changelog

## 1.5_2 - 2026-09-30

- A channel URL is checked as Apprise builds its service, so no local file can be named after a # or a ;, in a native webhook URL or in a second URL; a channel takes one URL.
- A header written with a leading space stays write-only, like one with a +.
- A delivery that trips up Apprise fails alone and is retried, rather than stopping the check.
- A log removed, or rotated and removed, before it is read is reported as not checked.
- An imported URL fills the fields from Apprise's own form of it, so e.g. ntfy tags, email recipients and a Slack channel no longer leave it a custom URL.

## 1.5_1 - 2026-09-29

- A channel's saved URL shows addresses as typed, e.g. @ rather than %40.

## 1.5 - 2026-09-29

- Service stopped event: a service down for 5 minutes, and back, as the Services widget shows it; not while booting or updating firmware, nor on a CARP standby.
- A UPS status that cannot be read for a moment no longer hides its return to online.
- A log message at a higher severity is sent even when the same text was sent within the hour.
- Archived summaries of a deleted channel are removed within two checks, not only when a summary is due.
- System data is read through core's own actions, as the dashboard reads it; memory and disk use in summaries match the dashboard.
- UPS power reads the UPS the apcupsd or NUT plugin is set up for, and only while that plugin is enabled.
- Firmware updates list reinstalls, downgrades and obsolete packages too, as the Firmware page does.

## 1.4_6 - 2026-09-28

- Processor and state table graphs are drawn in a single color, like the interface graphs.

## 1.4_5 - 2026-09-28

- Summary graphs setting: none, the busiest interface, the 3 busiest (the default, now for blocks as well as traffic) or all.
- A VPN status that cannot be read no longer reports every peer as disconnected, then connected again.

## 1.4_4 - 2026-09-28

- Summary reports follow dark mode, charts included, where the browser or mail app supports it.
- On a phone, summary reports fit the screen and keep their text sizes: long values wrap and pie charts sit above their tables.

## 1.4_3 - 2026-09-27

- The summary's current status lists stopped services, as the Services widget shows them.
- The short text summary counts gateways online and names only those with a problem.

## 1.4_2 - 2026-09-27

- Apply is shown only on the General and Channels tabs.
- With health reporting off, a summary says why it has no graphs; a graph with no data in the period is logged.

## 1.4_1 - 2026-09-27

- The Status queue and the Archive are grids, with paging, search and sorting.

## 1.4 - 2026-09-27

- Daily, weekly or monthly summary per channel: current status, chosen events, firewall blocks, traffic and system health; by email as HTML with graphs and pie charts.
- Other services get a short summary, split if the service needs it, with a link to the full report on the firewall.
- Sent summaries are kept, 60 daily, 52 weekly and 12 monthly per channel, and open from the new Archive tab, where they can also be deleted.
- Critical log messages event, from the local logs, with a severity setting.
- Summaries list top IDS signatures and sources, login outcomes, users and sources, VPN peer changes and log programs.
- WireGuard peers are reported online, stale or offline, as on the dashboard.
- Wireless access point links in running state count as up.
- A UPS battery fault while on line power is reported as a failure.
- A System Status entry dropping below the chosen level is reported as resolved.
- IDS alerts are no longer missed around log rotation or in a busy log.
- A malformed IDS alert is skipped instead of stalling the log.
- A failed command no longer resets link, address, CARP or counter baselines.
- Templates and public keys are fetched over https only.
- Text from outside, such as a login name of @everyone, no longer pings anyone on Discord.
- A failed settings read no longer resets recorded state.
- Queued digests are dropped once the channel no longer takes their events.
- An IPv6-only uplink (DHCPv6, SLAAC, 6rd, 6to4 or an IPv6 gateway) is watched for address changes.
- A digest lists titles while they fit and counts the rest, and a notification longer than the service accepts is cut rather than refused.

## 1.3_6 - 2026-09-26

- Email set to mailto with STARTTLS uses STARTTLS instead of unencrypted SMTP, and the dialog shows the mode actually used.

## 1.3_5 - 2026-09-25

- A channel with a saved advanced secret or file, such as a Discord template, opens with advanced settings shown.

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
