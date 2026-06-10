# Detection Lab Deployment Guide

Step-by-step documentation of my homelab setup for future reference and rebuilds.

## Infrastructure

| Component | Specs |
|-----------|-------|
| **Server** | Dell R720 |
| **Hypervisor** | Proxmox VE |
| **Storage** | BigData (primary), local-lvm (disabled) |

---

## VM Overview

| VM ID | Name | OS | IP | Role | RAM | CPU |
|-------|------|----|----|------|-----|-----|
| 200 | wazuh-server | Amazon Linux | 10.10.0.154 (static) | SIEM | 8GB | 4 cores |
| 201 | debian-01 | Debian 12 | DHCP | Target | 2GB | 2 cores |
| 202 | windows-01 | Windows 11 Pro | DHCP | Target + Sysmon | 12GB | 6 cores |


---

## Wazuh Server Deployment (VM 200)

### 1. Download OVA

```bash
# On local machine, download from:
# https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html
wget https://packages.wazuh.com/4.x/vm/wazuh-4.14.2.ova
```

### 2. Import to Proxmox

```bash
# SSH into Proxmox
ssh root@<proxmox-ip>

# Create import directory
mkdir /tmp/wazuh-import
cd /tmp/wazuh-import

# Transfer OVA to Proxmox (from local machine)
# scp wazuh-4.14.2.ova root@<proxmox-ip>:/tmp/wazuh-import/

# Extract OVA (it's a tar archive)
tar -xvf wazuh-4.14.2.ova

# Convert VMDK to QCOW2
qemu-img convert -f vmdk -O qcow2 wazuh-4.14.2-disk001.vmdk wazuh.qcow2

# Create VM in Proxmox UI:
# - Name: wazuh-server
# - OS: Linux
# - RAM: 8GB
# - CPU: 4 cores
# - Don't add disk yet

# Import disk to VM
qm importdisk 200 wazuh.qcow2 BigData
```

### 3. Attach Disk in Proxmox UI

1. Go to **VM 200 → Hardware**
2. Double-click **Unused Disk** → **Add** as SCSI
3. Go to **Options → Boot Order** → Enable new disk, move to top
4. **Start** the VM

### 4. Initial Wazuh Setup

```bash
# Default login
# User: wazuh-user
# Pass: wazuh

# Get IP
ip a

# Access dashboard: https://<wazuh-ip>
# Login: admin / admin
```

### 5. Change Admin Password

```bash
sudo su -
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p '<YourNewPassword>'
```

### 6. Fix Manager Timeout (if needed after disk move)

```bash
systemctl edit wazuh-manager

# Add:
[Service]
TimeoutStartSec=300

# Save, then:
systemctl daemon-reload
systemctl restart wazuh-manager
```

---

## Debian Target Deployment (VM 201)

### 1. Download ISO

- URL: https://www.debian.org/download (netinst)
- Upload to Proxmox: **BigData → ISO Images → Upload**

### 2. Create VM in Proxmox

| Setting | Value |
|---------|-------|
| VM ID | 201 |
| Name | debian-01 |
| OS Type | Linux |
| BIOS | SeaBIOS |
| Disk | 32GB on BigData |
| CPU | 2 cores |
| RAM | 4GB |
| Network | vmbr0 |

### 3. Install Debian

- Hostname: `debian`
- Root password: Set one
- User: `labuser`
- Software: SSH server + standard utilities only

### 4. Post-Install Setup

```bash
su -
apt update && apt upgrade -y
apt install -y curl wget net-tools htop qemu-guest-agent
ip a  # Note the IP
```

### 5. Install Wazuh Agent

Follow the instructions here:
https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html

```bash
# Enable and start
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Verify
systemctl status wazuh-agent
```

---

## Verification Checklist

- [ ] Wazuh dashboard accessible at https://10.10.0.154
- [ ] windows-01 shows as **Active** in Agents
- [ ] debian-01 shows as **Active** in Agents
- [ ] Sysmon events visible from Windows agent
- [ ] Custom detection rules firing

---

## Windows 11 Target Deployment (VM 202)

### 1. Download ISO

- URL: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
- Upload to Proxmox: **BigData → ISO Images → Upload**

### 2. Create VM in Proxmox

| Setting | Value |
|---------|-------|
| VM ID | 202 |
| Name | win11-target |
| OS Type | Microsoft Windows 11/2022 |
| Machine | q35 |
| BIOS | OVMF (UEFI) |
| EFI Disk | ✅ Add |
| TPM | ✅ v2.0 |
| Disk | 64GB on BigData |
| CPU | 6 cores, type: host |
| RAM | 12GB |
| Network | vmbr0 |

### 3. Bypass Network Requirement During Install

At "Let's connect you to a network" screen:
1. Press **Shift + F10** to open CMD
2. Type: `oobe\bypassnro`
3. PC reboots → Click **"I don't have internet"** → **"Continue with limited setup"**

### 4. Install VirtIO Network Drivers

```bash
# On Proxmox, download VirtIO ISO
cd /var/lib/vz/template/iso
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
```

1. Add CD drive to VM: **Hardware → Add → CD/DVD → virtio-win.iso**
2. In Windows, open the CD drive
3. Run **virtio-win-gt-x64.msi** to install all drivers

### 5. Enable SSH (Optional)

```powershell
# PowerShell as Admin
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH Server (SSH)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 6. Configure SSHD_CONFIG

```powershell
notepad C:\ProgramData\ssh\sshd_config
```

To allow password login, ensure these lines exist:

```
PasswordAuthentication yes
PubkeyAuthentication yes
```

Then restart the SSH service:

```powershell
Restart-Service sshd
```

### 7. Install Sysmon

```powershell
# PowerShell as Admin
New-Item -Path "C:\Tools" -ItemType Directory -Force
cd C:\Tools

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify
Get-Service Sysmon64
```

### 8. Install Wazuh Agent

Follow the instructions here:
https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html

```powershell
# Start service
NET START WazuhSvc

# Verify
Get-Service WazuhSvc
```


### 9. Add Sysmon to Agent Config

Edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart agent:
```powershell
Restart-Service WazuhSvc
```

---

## Troubleshooting

### Agent Not Connecting

```powershell
# Windows - check config IP
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.conf" | Select-String "address"

# Re-register
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 10.10.0.154
Restart-Service WazuhSvc
```

```bash
# Linux - check config IP
grep "address" /var/ossec/etc/ossec.conf

# Re-register
/var/ossec/bin/agent-auth -m 10.10.0.154
systemctl restart wazuh-agent
```

### Wazuh Manager Won't Start

```bash
systemctl restart wazuh-indexer
sleep 30
systemctl restart wazuh-manager
sleep 10
systemctl restart wazuh-dashboard
```

### No Sysmon Events in Wazuh

1. Verify Sysmon is running: `Get-Service Sysmon64`
2. Check ossec.conf has Sysmon localfile entry
3. Restart Wazuh agent: `Restart-Service WazuhSvc`

---

## Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sysmon Config by SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [VirtIO Drivers](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/)

---

*Last updated: January 2026*