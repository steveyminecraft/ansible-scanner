# Changelog

## 0.3.0

- Lynis via `security-scan audit` when `scanner_lynis_enabled` is true.
- Parse `lynis-report.dat`; warnings are `warning`, suggestions stay informational.
- Distro Lynis cron taken over. Default remains disabled on LAN hosts.

## 0.2.0

- ClamAV `security-scan full`: local filesystems, `--cross-fs=no`, ZFS/NFS/docker excludes.
- Record distro `freshclam` cron takeover; one updater path (daemon or none).
- `playbooks/scan.yml` accepts `-e scanner_scan_type=full`.
- Schedules remain disabled.

## 0.1.0

- Collection scaffold for `steveyminecraft.scanner`.
- v1: common controller, on-demand ClamAV, JSON reports, cron installed but disabled.
- Lynis, AIDE, rkhunter, Wazuh, and Falco are not implemented.
