# jakki-server

## Getting started

### Run Docker Hub image with Docker Compose
```yaml
services:
  jakkiserver:
    image: jan5u/jakki
    container_name: jakki
    restart: unless-stopped
    ports:
      - "7777:7777/udp"
    volumes:
      - ./jakkiserver_data:/jakkiserver_data
```

### Build on local
```bash
make tidy
make build
make bin
```

### Build with Docker Compose
```bash
docker compose up -d
```

## Optimizations
It is recommended to increase the maximum buffer size.

1. Create a config file `/etc/sysctl.d/99-buffer-size.conf` with content:
```bash
net.core.rmem_max=7500000
net.core.wmem_max=7500000
```
2. Load the config
```bash
sudo sysctl -p /etc/sysctl.d/99-buffer-size.conf
```

Alternative way that is non persistent
```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```