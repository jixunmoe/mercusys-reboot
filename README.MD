# Mercusys Halo WiFi Mesh Router Reboot

A simple tool to reboot the whole mesh network.

## Usage

```sh
./mercusys-reboot --url "http://192.168.68.1" --password "secret"
```

### Full help

```sh
Mercusys Halo WiFi Mesh Reboot Tool

Usage: mercusys-reboot [OPTIONS] --password <PASSWORD>

Options:
  -l, --url <URL>            Base URL for Mercusys Halo Router [default: http://192.168.68.1]
  -u, --user <USER>          Router username (internal). If unsure, leave it blank [default: admin]
  -p, --password <PASSWORD>  Router admin password
  -v, --verbose              verbose logging (request body/decrypted response)
  -d, --dry-run              don't actually reboot
  -h, --help                 Print help
  -V, --version              Print version
```

### Cron job

Assume the executable is located at `/opt/mercusys-reboot/mercusys-reboot`:

```sh
echo '30 4 * * * /opt/mercusys-reboot/mercusys-reboot --url "http://192.168.68.1" --password "secret"' > /etc/cron.d/reboot_mercusys_halo_daily

# or, for system without "cron.d", e.g. alpine:
echo '30 4 * * * /opt/mercusys-reboot/mercusys-reboot --url "http://192.168.68.1" --password "secret"' >> /etc/crontab
```

## Tested device

* Mercusys Halo H80X

## License

This project is distributed under the terms of both the MIT license and the Apache License (Version 2.0).
