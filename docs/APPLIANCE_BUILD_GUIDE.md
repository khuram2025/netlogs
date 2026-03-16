# Zentryc Virtual Appliance — Complete Build & Deploy Guide

## Overview

This guide covers two paths:

- **Path A**: Build the OVA/QCOW2 appliance image (for distributing to customers)
- **Path B**: Install the appliance CLI on your existing bare-metal server

---

## PATH A: Build Virtual Appliance (OVA/QCOW2)

You need a **build machine** (Ubuntu 22.04/24.04, can be your existing server or a separate one).

### Step 1: Install Build Prerequisites

```bash
# On your build machine (Ubuntu 24.04)
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-dev python3-pip \
    build-essential \
    qemu-system-x86 qemu-utils \
    curl wget git

# Install Packer
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install -y packer
```

### Step 2: Prepare the Source Code

```bash
cd /home/net/zentryc

# Make sure venv exists with all deps
python3 -m venv venv
source venv/bin/activate
pip install -r fastapi_app/requirements.txt
pip install -r build/requirements-build.txt
pip install "bcrypt==4.0.1"
```

### Step 3: Compile Python → .so (Cython Build)

```bash
# This compiles all .py files to binary .so files
# Customers cannot read your source code
bash build/build_appliance.sh
```

**Output**: `build/output/zentryc-3.0.0-compiled.tar.gz`

You can verify:
```bash
ls -lh build/output/
# Should see: zentryc-3.0.0-compiled.tar.gz
```

### Step 4: Build the VM Image (Packer)

```bash
cd /home/net/zentryc/packer

# Initialize Packer plugins (first time only)
packer init .

# Build the VM — this takes 15-30 minutes
# It downloads Ubuntu 24.04 ISO, installs OS, installs Zentryc, hardens
packer build \
    -var "version=3.0.0" \
    -var "compiled_tarball=../build/output/zentryc-3.0.0-compiled.tar.gz" \
    .
```

**Output** (in `packer/output/release/`):
- `zentryc-3.0.0.qcow2` — For Proxmox/KVM
- `zentryc-3.0.0.ova` — For VMware/VirtualBox

### Step 5: (Alternative) One-Command Release Build

Instead of Steps 3-4 separately, you can run the master release script:

```bash
cd /home/net/zentryc
bash build/release.sh
```

**Output** (in `release/zentryc-3.0.0/`):
```
zentryc-3.0.0.ova                    # VMware/VirtualBox
zentryc-3.0.0.qcow2                 # Proxmox/KVM
zentryc-3.0.0-compiled.tar.gz       # Bare-metal offline
SHA256SUMS                           # Checksums
RELEASE_NOTES.md                     # Instructions
```

### Step 6: Deploy the OVA

#### VMware ESXi / Workstation / VirtualBox:
1. Open VMware/VirtualBox
2. File → Import Appliance → Select `zentryc-3.0.0.ova`
3. Allocate: 2 vCPUs, 4GB RAM, 40GB disk (defaults)
4. Boot the VM

#### Proxmox VE:
1. Upload `zentryc-3.0.0.qcow2` to Proxmox storage
2. Create VM: 2 cores, 4GB RAM
3. Import disk: `qm importdisk <vmid> zentryc-3.0.0.qcow2 local-lvm`
4. Attach disk to VM, set as boot disk
5. Start VM

### Step 7: First-Boot Wizard (on VM console)

When the VM boots for the first time, a wizard appears on the **console** (not SSH):

```
╔══════════════════════════════════════════════════════════╗
║              Zentryc SOAR/SIEM Platform                  ║
║                  First-Time Setup                        ║
╚══════════════════════════════════════════════════════════╝

Screen 1: Welcome           → Press Enter
Screen 2: Network Config    → Set IP/DHCP, gateway, DNS
Screen 3: System Settings   → Hostname, timezone, NTP
Screen 4: Admin Account     → Set admin password
Screen 5: Summary           → Review, press "Yes, apply"
Screen 6: Complete          → Shows web URL
```

After the wizard completes:
- Web UI: `https://<IP>/`
- SSH: `ssh zentryc@<IP>` → Appliance CLI

### Step 8: Use the Appliance

#### Web UI:
Open browser → `https://<IP>/` → Login with admin / (password you set in wizard)

#### SSH (Appliance CLI):
```bash
ssh zentryc@<IP>
# Password: (the OS password, default: zentryc)

# You get the CLI shell:
zentryc> show system status
zentryc> show system health
zentryc> show interfaces
zentryc> set interface ens18 address 10.0.0.5/24 gateway 10.0.0.1
zentryc> request backup now
zentryc> help
```

---

## PATH B: Install CLI on Existing Bare-Metal Server

If you already have Zentryc running on bare-metal and just want the CLI shell:

### Step 1: Install Dependencies

```bash
cd /home/net/zentryc
source venv/bin/activate
pip install prompt_toolkit pyyaml
```

### Step 2: Test the CLI (as current user)

```bash
source venv/bin/activate
python -m fastapi_app.cli.shell.main
```

You're now in the CLI shell:
```
zentryc> show system status
zentryc> show version
zentryc> show services
zentryc> help
zentryc> exit
```

### Step 3: (Optional) Install as System CLI

If you want SSH to drop into the CLI shell:

```bash
# Create the CLI wrapper
sudo mkdir -p /opt/zentryc/venv/bin
sudo tee /opt/zentryc/venv/bin/zentryc-cli > /dev/null <<'EOF'
#!/bin/bash
exec /opt/zentryc/venv/bin/python -m fastapi_app.cli.shell.main
EOF
sudo chmod 755 /opt/zentryc/venv/bin/zentryc-cli

# Install sudoers (so CLI can restart services etc)
sudo cp deploy/bare-metal/zentryc-cli-sudoers /etc/sudoers.d/zentryc-cli
sudo chmod 440 /etc/sudoers.d/zentryc-cli
sudo visudo -cf /etc/sudoers.d/zentryc-cli  # Verify syntax

# Add to shells
echo "/opt/zentryc/venv/bin/zentryc-cli" | sudo tee -a /etc/shells

# Set as login shell for zentryc user
sudo chsh -s /opt/zentryc/venv/bin/zentryc-cli zentryc
```

Now `ssh zentryc@server` drops directly into the CLI.

### Step 4: (Optional) Run Full Bare-Metal Install with Appliance Mode

```bash
cd /home/net/zentryc
sudo bash deploy/bare-metal/install.sh --appliance
```

This does everything: installs PostgreSQL, ClickHouse, Nginx, Python deps, sets up CLI as login shell, enables first-boot wizard.

---

## Quick Reference

| What | Command |
|------|---------|
| Test CLI now | `source venv/bin/activate && python -m fastapi_app.cli.shell.main` |
| Compile source | `bash build/build_appliance.sh` |
| Build VM image | `cd packer && packer init . && packer build .` |
| Full release | `bash build/release.sh` |
| Tarball only (no VM) | `bash build/release.sh --skip-vm` |
| Bare-metal install | `sudo bash deploy/bare-metal/install.sh` |
| Appliance install | `sudo bash deploy/bare-metal/install.sh --appliance` |

---

## Troubleshooting

**Packer build fails with "KVM not available":**
```bash
# Check KVM support
kvm-ok
# If not available, run Packer without KVM (slower):
# Edit packer/zentryc.pkr.hcl, change accelerator = "kvm" to "tcg"
```

**Cython build fails:**
```bash
# Make sure build deps are installed
source venv/bin/activate
pip install cython>=3.0.0 setuptools>=70.0
# Also need C compiler
sudo apt install build-essential python3-dev
```

**CLI shows "command not found" for show/set/request:**
You need to be INSIDE the CLI shell first:
```bash
source venv/bin/activate
python -m fastapi_app.cli.shell.main
# NOW type commands:
# zentryc> show system status
```
