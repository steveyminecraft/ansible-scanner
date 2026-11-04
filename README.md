# ansible-scanner (`steveyminecraft.scanner`)

Ansible collection for host-based Linux security scanning on **Devuan**, **Debian**, and **Ubuntu**.

Installs on-demand **ClamAV (`clamscan`)** with **quick** and **full** profiles, optional **Lynis** (`security-scan audit`), optional **AIDE** (`security-scan integrity`), optional **rkhunter** (`security-scan rootkit`), a combined **`security-scan all`**, optional **ntfy** on status change, a `/usr/local/sbin/security-scan` controller, schema-valid JSON reports, and a cron file that is **disabled** unless inventory opts in. Distro `freshclam` / Lynis / AIDE / rkhunter cron is taken over. It does not install `clamd`, does not auto-delete detections, does not initialise an AIDE baseline or run `rkhunter --propupd` on install, and does not apply hardening.

chkrootkit, Wazuh, and Falco are **not** in this slice.

Do not add these roles to `ansible-server-01` `playbooks/restore.yml`.

## Requirements

- ansible-core >= 2.17
- Target: apt-based Devuan / Debian / Ubuntu
- Python 3 on the controller and the target
- No systemd required on the target

## Install (controller)

```bash
cd ~/Documents/Projects/ansible-scanner
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/ansible-galaxy collection install -r requirements.yml -p .ansible/collections
```

## Inventory

- Example (RFC5737): `inventory/example/hosts.yml`
- LAN v1: `inventory/homelab/hosts.yml`
  - prod-01 `172.16.7.20` (`service`)
  - pihole-01/02 `172.16.7.25` / `.30` (`service`)
  - backup-01 `172.16.7.11` (`richardl`)
  - silver-laptop `172.16.6.60` (`talon`, Devuan)

Collection `scanner_schedule_enabled` still defaults to **false**. Homelab inventory sets it **true** and runs jobs **once a week** (Sunday) plus a **monthly** deeper scan.

When that flag is true, always-on hosts write `scanner_schedule_jobs` into `/etc/cron.d/ansible-scanner`. The default weekly job is Sunday ClamAV quick. Pi-holes stagger Sunday quick (03:20 vs 05:20). prod-01 also runs Sunday Lynis and rkhunter. Monthly jobs (`scanner_schedule_monthly_jobs`) are the first matching weekday of the month (`date +%d` ≤ 7) ClamAV full then AIDE; Pi-holes use Saturday vs Friday so they do not share a deep-scan day. Hosts with `scanner_anacron` (silver-laptop, backup-01) keep the clock file empty, use `/etc/cron.weekly/ansible-scanner` for quick/Lynis/rkhunter, and `/etc/cron.monthly/ansible-scanner` for full and AIDE. silver-laptop keeps AIDE off and monthly jobs empty.

Homelab ntfy URL lives in gitignored `inventory/homelab/group_vars/all/ntfy.local.yml` (copy the `.example`). Keep `scanner_ntfy_url` empty in committed vars.

## Commands

Syntax only:

```bash
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/install.yml --syntax-check
```

Check mode (no changes):

```bash
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/install.yml --check --diff --limit silver-laptop
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/install.yml --check --diff --limit prod-01
```

Apply only when Richard asks:

```bash
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/install.yml --limit silver-laptop
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/scan.yml --limit prod-01 -e scanner_scan_type=full
```

After install, as root on a host:

```bash
security-scan quick
security-scan full
security-scan audit
security-scan integrity
security-scan rootkit
security-scan all
security-scan status
```

AIDE baseline (confirm-gated, serial 1):

```bash
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/aide_baseline.yml --limit prod-01 -e scanner_aide_confirm_baseline=true
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/aide_update.yml --limit prod-01 -e scanner_aide_confirm_update=true
.venv/bin/ansible-playbook -i inventory/homelab/hosts.yml playbooks/rkhunter_propupd.yml --limit prod-01 -e scanner_rkhunter_confirm_propupd=true
```

Reports: `/var/log/linux-security/latest.json` and `scans.ndjson`.

## Tests

```bash
.venv/bin/pytest
.venv/bin/ansible-lint
.venv/bin/molecule test
```

Molecule Docker proves idempotence on Ubuntu. It does **not** prove Devuan-without-systemd. That needs libvirt/Vagrant (`tests/integration/Vagrantfile`).

Verified this slice:

- pytest (report JSON / ClamAV exit map)
- ansible-lint production
- Molecule Docker Ubuntu: converge, idempotence, verify (no `clamav-daemon`)
- libvirt Vagrant `devuan-desktop`: install on Devuan Excalibur; `systemd-sysv` not installed; cron remains commented
- `--check --diff` against prod-01 (`172.16.7.20`) — no apply
- silver-laptop current DHCP address is `172.16.6.60` (was `172.16.6.208`)

Untested: live AIDE/rkhunter apply, enabled cron.

## Spec

See [docs/AntMalWarePLan.md](docs/AntMalWarePLan.md).
