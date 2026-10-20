# Changelog

## 0.5.0

- rkhunter via `security-scan rootkit` when `scanner_rkhunter_enabled` is true.
- Exit 1 is `warning`, never malware. Distro rkhunter cron taken over.
- `--propupd` is confirm-gated (`rkhunter_propupd.yml`). Install never updates properties.
- chkrootkit stays unimplemented and default off. Homelab default remains disabled.

## 0.4.0

- AIDE install and extra-exclude drop-in. Distro AIDE cron/timer taken over.
- `security-scan integrity` runs `aide --check` when enabled.
- Package-owned files matching dpkg checksums are warning, not integrity_violation.
- Baseline init/update stay confirm-gated (`aide_baseline.yml`, `aide_update.yml`).
- Install never initialises a baseline. Homelab default remains disabled.

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
