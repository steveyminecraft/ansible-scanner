# ansible-scanner (`steveyminecraft.scanner`)

Ansible collection for host-based Linux security scanning on **Devuan**, **Debian**, and **Ubuntu**.

Installs on-demand **ClamAV (`clamscan`)** with **quick** and **full** profiles, optional **Lynis** (`security-scan audit`), a `/usr/local/sbin/security-scan` controller, schema-valid JSON reports, and a **disabled** cron file. Distro `freshclam` cron is taken over so only the daemon (or nothing) updates signatures. It does not install `clamd`, does not auto-delete detections, and does not apply hardening.

Lynis, AIDE, rkhunter, Wazuh, and Falco are **not** in this slice.

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

`scanner_schedule_enabled` defaults to **false**. Do not enable cron until a manual report is reviewed.

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
security-scan status
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

Untested: live Lynis apply, enabled cron, AIDE/rkhunter.

## Spec

See [docs/AntMalWarePLan.md](docs/AntMalWarePLan.md).
