# Changelog

## 1.2 - 2026-11-09

- Backups are sent with rclone, which is installed with the plugin.
- A new Provider setting tells rclone which service it talks to, e.g. AWS or Cloudflare, so it uses that service's own settings. After the upgrade it is Other, or GCS for a Google Cloud Storage endpoint: set it to your service under System > Configuration > Backups.
- Other is for services rclone does not list. With it, Ceph, Linode and endpoints behind a proxy that rewrites the Accept-Encoding header, such as Cloudflare's, can refuse uploads with SignatureDoesNotMatch.
- A backup counts as stored only once the bucket lists it.
- An endpoint whose certificate names it only in the common name, or that offers only RSA key exchange, is refused.
- UCloud US3 fails with "rclone knows no S3 provider named US3." until rclone fixes it.

## 1.1 - 2026-10-30

- A new secret access key or password typed among the dots of the saved one is stored as typed, without the dots.
- When older backups cannot be removed, the message says the new one is stored, and those that were removed are logged.
- A setting the page refuses is named, once.

## 1.0_5 - 2026-10-03

- Backups upload to a bucket with Object Lock.
- Old backups are removed one by one only when the service has no bulk delete, and a failure says why.
- A configuration saved in a language with a decimal comma is sent.
- A user with read-only access cannot change the settings.
- Unusual object names in the folder no longer break the listing or count as backups.
- Names from a clock that ran ahead are removed first, and one save is stored once.
- With 0 to keep, only the new backup is looked up, however large the folder.
- The page shows settings as stored, an invalid setting is named, a bucket in another region names its endpoint, and a port above 65535 is refused.

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
