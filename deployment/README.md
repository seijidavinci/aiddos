# Deployment Assets & Automation Scripts

This directory contains automated deployment scripts, container definitions, and system service unit templates for the **AI-Driven DDoS Detection and Automated Mitigation Framework in SDN**.

---

## Files in this Directory

| File / Folder | Purpose | Operating System |
| :--- | :--- | :--- |
| **`windows_deploy.bat`** | Automated 1-click startup batch script | Windows (CMD / PowerShell) |
| **`linux_deploy.sh`** | Automated 1-click startup shell script | Linux, macOS, WSL2 |
| **`docker_deploy.bat`** | 1-click Docker Compose build and startup | Windows with Docker Desktop |
| **`docker_deploy.sh`** | 1-click Docker Compose build and startup | Linux / macOS with Docker |
| **`systemd/`** | Linux systemd service unit files for 24/7 server hosting | Ubuntu / Debian / RHEL |
| **`nginx/`** | Production Nginx reverse proxy configuration | Linux production servers |

---

## Quick Usage

### Windows:
Simply run:
```cmd
deployment\windows_deploy.bat
```

### Linux / macOS:
```bash
chmod +x deployment/*.sh
./deployment/linux_deploy.sh
```

### Docker:
```bash
deployment\docker_deploy.bat   # Windows
# or
./deployment/docker_deploy.sh  # Linux / macOS
```

For the complete step-by-step documentation with screenshots and testing guides, see **[HOW_TO_DEPLOY.md](../HOW_TO_DEPLOY.md)** at the root of the project.
