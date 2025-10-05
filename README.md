# jakki-server

## Getting started

### Running on local
```bash
make tidy
make build
make bin
```

### Running with Docker Compose
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