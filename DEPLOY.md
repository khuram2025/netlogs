# Zentryc SOAR/SIEM - Deployment

## One-Command Install

On a fresh Ubuntu 22.04/24.04 server (min 4 CPU, 16 GB RAM, 100 GB disk):

```bash
curl -fsSL https://raw.githubusercontent.com/khuram2025/netlogs/main/install.sh | sudo bash
```

That's it. The script will:
- Install Docker if missing
- Clone the repo to `/opt/zentryc`
- Generate `.env` with secure random passwords
- Build and start all 8 containers
- Print the URL and login when ready

**Default login:** `admin` / `changeme` - change it after first login.

## After Install

Point your firewalls to send syslog to `<SERVER_IP>:514 UDP`.

## Common Commands

```bash
cd /opt/zentryc
docker compose ps              # Status
docker compose logs -f web     # App logs
docker compose restart web     # Restart a service
docker compose down            # Stop all (keeps data)
sudo bash install.sh           # Update to latest version
```
