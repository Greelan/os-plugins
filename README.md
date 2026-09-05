[![Build](https://img.shields.io/github/actions/workflow/status/Greelan/os-plugins/build.yml?style=for-the-badge&logo=github&label=Build)](https://github.com/Greelan/os-plugins/actions/workflows/build.yml)
[![Donate](https://img.shields.io/badge/Ko--fi-donate-blueviolet?style=for-the-badge&logo=kofi&logoColor=white)](https://ko-fi.com/greelan)


# os-plugins

OPNsense plugins maintained and distributed by Greelan.

## Add the repository

Add the repository to your OPNsense installation via the console/SSH:

```sh
fetch -o /usr/local/etc/pkg/repos/Greelan.conf https://pkg.greelan.net/greelan.conf
pkg update
```

Plugins are then installed from the web UI under **System > Firmware > Plugins**. Find the relevant package and click **+**.

## Plugins

### os-blocky-greelan

[Blocky](https://0xerr0r.github.io/blocky/) is a fast DNS proxy and ad-blocker.

This plugin provides a fully featured OPNsense UI, including log viewer, settings validation, and config.yml importer.

Blocky answers on the DNS port (53 by default); disable the built-in Unbound/Dnsmasq resolver or run Blocky on another port.
