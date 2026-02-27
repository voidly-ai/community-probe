# Voidly Community Probe

[![PyPI](https://img.shields.io/pypi/v/voidly-probe)](https://pypi.org/project/voidly-probe/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/docker/pulls/emperormew2/voidly-probe)](https://hub.docker.com/r/emperormew2/voidly-probe)

Help measure internet censorship worldwide. Run a lightweight probe node from anywhere.

## What it does

Tests connectivity to **62 websites** (social media, news, messaging, privacy tools, human rights organizations) every 15 minutes from your network. Detects:

- **DNS blocking** — NXDOMAIN, DNS poisoning (compared against Cloudflare DoH)
- **TCP resets** — connection reset by peer
- **TLS/SNI filtering** — Server Name Indication based blocking
- **HTTP redirects** — government/ISP redirect to block pages
- **Block page fingerprinting** — identifies 13 known blocking entities

Results feed into [Voidly's censorship intelligence network](https://voidly.ai) — a real-time global censorship dataset used by researchers, journalists, and developers.

## Install

```bash
pip install voidly-probe
```

> **Tip:** If `voidly-probe` is not recognized after install, use `python -m voidly_probe` instead.

**Requirements:** Python 3.8+ · No external dependencies (stdlib only) · No root required · No VPN

## Quick start

```bash
# First run — review consent and register
voidly-probe --consent
# Alternative: python -m voidly_probe --consent

# Run continuously (default: every 15 minutes)
voidly-probe

# Single test cycle then exit
voidly-probe --once

# Check your node's status
voidly-probe --status

# Custom interval (minimum 300s / 5 min)
voidly-probe --interval 600

# Run in background (Linux/Mac)
nohup voidly-probe --consent &

# Stop contributing and remove config
voidly-probe --unregister
```

## Docker

```bash
# Run in background with persistent config
docker run -d --name voidly-probe \
  -v voidly-data:/data/.voidly \
  emperormew2/voidly-probe:latest

# View logs
docker logs -f voidly-probe

# Check node status
docker exec voidly-probe voidly-probe --status

# Find your Node ID (for claiming)
docker exec voidly-probe cat /data/.voidly/node.json

# Stop
docker stop voidly-probe
```

The Docker image auto-consents and starts probing immediately. Config persists across restarts via the volume mount.

## Claim your node

After your node is running, link your identity to appear on the [leaderboard](https://voidly.ai/probes) and be eligible for prizes:

1. Find your Node ID and Token: `cat ~/.voidly/node.json`
2. Visit [voidly.ai/probes/claim](https://voidly.ai/probes/claim)
3. Enter your Node ID, Token, and Twitter/X handle
4. Your name appears on the leaderboard instead of `cp-xxxxxxxx`

> **Important:** Back up `~/.voidly/node.json` — your token is shown once during registration and cannot be recovered. If you lose it, you'll need to re-register as a new node.

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Your Node   │────▶│  api.voidly.ai │────▶│  Voidly Dataset  │
│  (probe)     │     │  (HMAC auth)   │     │  (CC BY 4.0)     │
└─────────────┘     └──────────────┘     └─────────────────┘
     │                                           │
     │  Tests 62 domains:                        │  Powers:
     │  DNS · HTTP · TLS · SNI                   │  voidly.ai/probes
     │  every 15 min                             │  Censorship Index
     │                                           │  MCP Server
     └───────────────────────────────────────────┘
```

Each probe cycle:
1. **DNS resolution** — checks if the domain resolves, compares against DoH
2. **HTTP/HTTPS request** — tests connectivity, checks for redirects
3. **Block page detection** — fingerprints known government/ISP block pages
4. **TLS/SNI probing** — tests for SNI-based filtering
5. **Certificate fingerprinting** — detects MITM certificate injection
6. **Results signed** with HMAC-SHA256 and reported to the API

Failed submissions are **cached locally** and retried next cycle — no data loss even with spotty connectivity.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VOIDLY_PROBE_INTERVAL` | `900` | Seconds between probe cycles |
| `VOIDLY_PROBE_TIMEOUT` | `10` | Timeout per request (seconds) |
| `VOIDLY_BATCH_SIZE` | `20` | Domains per cycle |
| `VOIDLY_CONFIG_DIR` | `~/.voidly` | Config directory |
| `VOIDLY_API_URL` | `https://api.voidly.ai` | API endpoint (for development) |

## Privacy

### What we collect
- Domain, blocked/accessible status, latency, blocking method
- Your approximate location (country, city) — detected once during registration
- SHA256 hash of your IP (for deduplication — raw IP never stored)

### What we don't collect
- No browsing data
- No passwords or personal information
- No traffic inspection beyond the 62 test domains
- Your raw IP address is never stored

### Your rights
- Stop the probe at any time with Ctrl+C
- Run `voidly-probe --unregister` to remove your config
- Data is used for censorship research under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Learn more: [voidly.ai/probes](https://voidly.ai/probes)

## Contributing

Found a bug? Have a suggestion? [Open an issue](https://github.com/voidly-ai/community-probe/issues).

## License

[MIT](LICENSE) — [voidly.ai](https://voidly.ai)
