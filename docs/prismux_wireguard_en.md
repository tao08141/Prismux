# Prismux + WireGuard One-Click Deployment Guide

## Why Prismux can improve game tunnel quality

Prismux improves UDP tunnel stability with:
1. Multi-path redundant forwarding: packets can be sent over two paths in parallel.
2. Better loss tolerance: one healthy path can still deliver data when the other path jitters or drops.
3. Smarter split strategy: bandwidth-aware policy avoids always duplicating traffic at high throughput.
4. Fast failover behavior: path rules can quickly shift traffic when one line is unstable.

## Topology

```text
Game client -> WireGuard(Client) -> Prismux Client -> Forward line #1 -> Prismux Server -> WireGuard(Server) -> Game server
                                               -> Forward line #2 ->
```

## Requirements

- 1 Entry host (close to player)
- 1 Exit host (close to game server)
- At least 2 usable network paths from entry to exit
- Linux with `sudo` privileges on both hosts
- Public internet access for package/image downloads

## One-click install and initialization

Run on both Entry and Exit hosts. The script will:
- install Docker and docker compose if missing
- install WireGuard if missing
- generate WireGuard keys and print local public key
- interactively generate Prismux + WireGuard config files

### Script download address

Download and grant execute permission:

```bash
curl -fsSL -o prismux-wg-manager.sh https://raw.githubusercontent.com/tao08141/Prismux/main/prismux-wg-manager.sh
chmod +x prismux-wg-manager.sh
```

If you already cloned this repo, you can use the local file directly:

```bash
chmod +x prismux-wg-manager.sh
```

### Install on both sides

```bash
sudo bash ./prismux-wg-manager.sh install
```

Install flow highlights:
- Exchange WireGuard public keys between Entry and Exit.
- Choose language (English/中文).
- Set bandwidth threshold in bps (default `50000000`, 50 Mbps).
- Select role: `1=Entry(client)`, `2=Exit(server)`.
- Paste peer WireGuard public key.
- Fill port parameters:
  - Entry: local Prismux listen port (default `7000`), line #1/#2 target (`ExitIP:9000`, `ExitIP:9001`)
  - Exit: line #1/#2 listen port (default `9000`/`9001`), WireGuard server port (default `51820`)
- Default WireGuard addresses:
  - Entry: `10.0.0.1/24`
  - Exit: `10.0.0.2/24`

Generated files:
- `/opt/prismux/docker-compose.yml`
- `/opt/prismux/config.yaml`
- `/opt/prismux/secret`
- `/opt/prismux/threshold`
- `/etc/wireguard/wg0.conf`

## Start and enable on boot

Run on both hosts:

```bash
sudo bash ./prismux-wg-manager.sh start
```

This will:
- start Prismux container
- bring up WireGuard (`wg0`)
- enable `wg-quick@wg0` on boot

## Common management commands

```bash
sudo bash ./prismux-wg-manager.sh status     # Prismux/WireGuard/ports/meta
sudo bash ./prismux-wg-manager.sh logs       # Follow Prismux logs
sudo bash ./prismux-wg-manager.sh stop       # Stop Prismux and WireGuard
sudo bash ./prismux-wg-manager.sh pause      # Down wg0, keep Prismux running
sudo bash ./prismux-wg-manager.sh resume     # Up wg0
sudo bash ./prismux-wg-manager.sh update     # Pull latest image and restart
sudo bash ./prismux-wg-manager.sh reload     # Reload config (compose up -d)
sudo bash ./prismux-wg-manager.sh show-keys  # Show local WireGuard public key
sudo bash ./prismux-wg-manager.sh lang en    # Switch script language (zh/en)
```

## Smart split and threshold

Generated `config.yaml` includes bandwidth + sequence based split:
- When `bps <= threshold`: dual-line redundant forwarding (better resilience)
- When `bps > threshold`: split by packet sequence parity (`seq % 2`) to save bandwidth

Update threshold online:

```bash
sudo bash ./prismux-wg-manager.sh set-threshold 80000000
sudo bash ./prismux-wg-manager.sh reload
```

## Firewall and UDP ports

If default values are used, open these UDP ports:
- Entry: `7000/udp` (local Prismux listen; WireGuard client points to `127.0.0.1:7000`)
- Exit: `9000/udp` and `9001/udp` (two forwarding lines)
- Exit: `51820/udp` (WireGuard server port)

## Validate connectivity

After both sides are started:

```bash
sudo bash ./prismux-wg-manager.sh status
sudo wg show
# From Entry (with default addressing):
ping 10.0.0.2
```

## Troubleshooting

- Prismux container logs:
  ```bash
  sudo bash ./prismux-wg-manager.sh logs
  ```
- WireGuard status:
  ```bash
  sudo wg show
  ```
- UDP listening ports:
  ```bash
  ss -lunpt | grep -E ":(7000|9000|9001|51820)\b" || netstat -tulpn | grep -E ":(7000|9000|9001|51820)\b"
  ```
- Docker network restart:
  ```bash
  sudo systemctl restart docker
  ```

## Security notes

- The installer generates Prismux auth secret automatically (must be consistent on both ends): `/opt/prismux/secret`
- Update image periodically:
  ```bash
  sudo bash ./prismux-wg-manager.sh update
  ```
- Only allow required UDP ports and restrict source IP when possible.
- Review logs regularly.

## Optional image override

Default image:

```text
ghcr.io/tao08141/prismux:latest
```

Use a custom tag:

```bash
sudo PRISMUX_IMAGE=ghcr.io/tao08141/prismux:dev bash ./prismux-wg-manager.sh install
```
