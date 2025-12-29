[← Back to README](../README.md) | [User Guide](USER_GUIDE.md) | [Honeypot](HONEYPOT.md) | [Reporting](REPORTING.md) | [Docker](DOCKER.md) | [Architecture](ARCHITECTURE.md)

---

# Installation Guide

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.8+ | 3.10+ |
| OS | Windows/Linux/macOS | Linux/WSL |
| RAM | 4GB | 8GB+ |
| Privileges | User | Root/sudo |

**Note:** Root/sudo is required for raw socket access (network scanning, packet crafting).

---

## Quick Install (Linux/WSL)

```bash
git clone https://github.com/YOUR_USERNAME/5G-Gibbon.git
cd 5G-Gibbon
chmod +x setup.sh
./setup.sh
```

---

## Manual Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/5G-Gibbon.git
cd 5G-Gibbon
```

### Step 2: Create Virtual Environment

```bash
# Linux/macOS/WSL
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python install.py
```

This runs a verification check and shows which modules loaded successfully.

---

## Platform-Specific Notes

### Linux (Recommended)

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip python3-venv libpcap-dev

# For Scapy raw sockets
sudo setcap cap_net_raw+ep $(which python3)
```

### Windows

- Use WSL2 for best compatibility with network tools
- Native Windows works but some features require admin privileges
- Install from PowerShell as Administrator

```powershell
# Run as Administrator
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
```

### macOS

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 libpcap

# Create venv and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Docker Installation

See [DOCKER.md](DOCKER.md) for container-based deployment.

```bash
# Quick Docker start
docker-compose up -d gibbon-dashboard
docker-compose run gibbon --help
```

---

## Verify Everything Works

```bash
# Activate environment
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\Activate   # Windows

# Check CLI loads
python run.py --help

# Check modules
python -c "from core.cli import main; print('CLI OK')"
python -c "from reporting.html_report import ReportGenerator; print('Reporting OK')"
python -c "from defense.honeypot import Honeypot5GOrchestrator; print('Honeypot OK')"
```

---

## Troubleshooting

### "Permission denied" errors
```bash
sudo python run.py discover --network 10.0.0.0/24
```

### "Module not found" errors
```bash
pip install -r requirements.txt --force-reinstall
```

### Scapy import errors
```bash
pip install scapy --upgrade
```

### Windows raw socket issues
Run PowerShell as Administrator or use WSL2.

---

## Next Steps

- [USER_GUIDE.md](USER_GUIDE.md) - How to use the toolkit
- [HONEYPOT.md](HONEYPOT.md) - Set up the honeypot network
- [REPORTING.md](REPORTING.md) - Generate security reports

