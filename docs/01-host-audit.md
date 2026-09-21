# Phase 0 — Host & Existing-Service Audit

## Rules
- Read-only discovery first.
- Do not prune Docker, delete volumes, alter firewall rules, stop services, or change mounts during discovery.
- Redact secrets, tokens, private keys, personal data, and sensitive environment variables from output.
- Preserve command output in a dated, access-controlled audit directory.

## Read-only collection checklist
Run commands individually; inspect before sharing output.

```bash
date -Is
cat /etc/os-release
uname -a
lscpu
free -h
df -hT
lsblk -f
ip -brief address
ip route
sudo ss -lntup
docker version
docker info
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker network ls
docker volume ls
docker system df
systemctl --failed
```

For each running container, record image/tag, ports, health, networks, mounts, restart policy, and owning Compose project. Avoid dumping environment variables because they may contain secrets.

## Audit outputs
- `audit-summary.md`
- `host-resources.txt`
- `docker-inventory.csv`
- `listening-ports.txt`
- `network-map.md`
- `data-and-volume-register.md`
- `risk-register.md`
- `agent-capability-inventory.md`

## Capacity decision
Do not deploy a full SIEM stack until measured free RAM, disk, CPU headroom, and ingestion expectations are known. Start with a small profile and synthetic telemetry. Move heavy indexing, packet analysis, or multiple VMs to a dedicated host when necessary.
