[← Back to README](../README.md) | [Installation](INSTALLATION.md) | [User Guide](USER_GUIDE.md) | [Honeypot](HONEYPOT.md) | [Reporting](REPORTING.md) | [Architecture](ARCHITECTURE.md)

---

# Docker Setup Guide

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

```bash
# Check versions
docker --version
docker-compose --version
```

---

## Quick Start

### Build and Run

```bash
# Build the image
docker-compose build

# Run the toolkit
docker-compose run gibbon --help

# Start the dashboard
docker-compose up -d gibbon-dashboard
```

---

## Available Services

| Service | Description | Port |
|---------|-------------|------|
| `gibbon` | Main toolkit container | - |
| `gibbon-dashboard` | Web dashboard | 8080 |
| `gibbon-honeypot` | Honeypot network | 2152, 8805, 7777 |

---

## Running Commands

### One-off Commands

```bash
# Discovery scan
docker-compose run gibbon discover --network 10.0.0.0/24

# TEID enumeration
docker-compose run gibbon async teid --target 10.0.0.10

# Generate report
docker-compose run gibbon report html --output report.html

# 4G/LTE assessment
docker-compose run gibbon lte assessment --mme 10.0.0.40 --hss 10.0.0.50
```

### Interactive Mode

```bash
docker-compose run gibbon
```

This opens the menu-driven interface inside the container.

---

## Dashboard

### Start Dashboard

```bash
docker-compose up -d gibbon-dashboard
```

Access at: `http://localhost:8080`

### Stop Dashboard

```bash
docker-compose stop gibbon-dashboard
```

### View Logs

```bash
docker-compose logs -f gibbon-dashboard
```

---

## Honeypot Deployment

### Start Honeypots

```bash
docker-compose up -d gibbon-honeypot
```

This exposes:
- Port 2152 (GTP-U honeypot)
- Port 8805 (PFCP honeypot)
- Port 7777 (SBI honeypot)

### Stop Honeypots

```bash
docker-compose stop gibbon-honeypot
```

### Get Honeypot Events

```bash
docker-compose exec gibbon-honeypot cat /app/honeypot_all_events.json
```

---

## Volumes and Data

### Persist Reports

Reports are saved to the `reports/` folder which is mounted as a volume:

```yaml
volumes:
  - ./reports:/app/reports
```

### Persist Results Database

The session database is also persisted:

```yaml
volumes:
  - ./results:/app/results
```

---

## Network Configuration

### Host Network Mode

For network scanning to work properly, use host network mode:

```bash
docker-compose run --network host gibbon discover --network 10.0.0.0/24
```

Or modify `docker-compose.yml`:

```yaml
services:
  gibbon:
    network_mode: host
```

### Custom Networks

To scan specific networks, add them to docker-compose:

```yaml
networks:
  target_network:
    external: true
    name: my_5g_network
```

---

## Building Custom Images

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "run.py"]
```

### Build

```bash
docker build -t 5g-gibbon:latest .
```

### Run

```bash
docker run -it --rm --network host 5g-gibbon:latest --help
docker run -it --rm --network host 5g-gibbon:latest discover --network 10.0.0.0/24
```

---

## Docker Compose Reference

```yaml
version: '3.8'

services:
  gibbon:
    build: .
    image: 5g-gibbon:latest
    volumes:
      - ./reports:/app/reports
      - ./results:/app/results
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN

  gibbon-dashboard:
    build: .
    image: 5g-gibbon:latest
    command: dashboard --port 8080
    ports:
      - "8080:8080"
    volumes:
      - ./reports:/app/reports
      - ./results:/app/results

  gibbon-honeypot:
    build: .
    image: 5g-gibbon:latest
    command: defense honeypot --duration 0
    ports:
      - "2152:2152/udp"
      - "8805:8805/udp"
      - "7777:7777"
    volumes:
      - ./reports:/app/reports
    cap_add:
      - NET_RAW
```

---

## Troubleshooting

### Permission Denied

Add capabilities for raw sockets:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

### Cannot Scan Network

Use host network mode:

```bash
docker-compose run --network host gibbon discover --network 10.0.0.0/24
```

### Container Exits Immediately

Check logs:

```bash
docker-compose logs gibbon
```

### Port Already in Use

Change the port mapping:

```yaml
ports:
  - "9090:8080"  # Use 9090 instead of 8080
```

---

## Cleaning Up

```bash
# Stop all containers
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

---

## Next Steps

- [USER_GUIDE.md](USER_GUIDE.md) - CLI command reference
- [HONEYPOT.md](HONEYPOT.md) - Honeypot configuration
- [REPORTING.md](REPORTING.md) - Report generation

