# Security Policy

## Reporting Vulnerabilities

If you discover a security issue, please email **security@voidly.ai**.

Do **NOT** open a public GitHub issue for security vulnerabilities.

We aim to respond within 48 hours and will work with you on a coordinated disclosure timeline.

## What We Protect

- **Node tokens** are stored with `0600` file permissions (owner-only read/write)
- **All API communication** uses HTTPS (enforced — the probe refuses plain HTTP)
- **HMAC-SHA256 signatures** on every result submission (prevents tampering)
- **IP addresses are never stored** — only SHA256 hashes for rate limiting
- **Constant-time token comparison** to prevent timing attacks

## Third-Party Services

| Service | Purpose | What's Visible |
|---------|---------|----------------|
| **ipinfo.io** | Country/city detection at registration | Your IP address is sent to ipinfo.io once. Skip with: `VOIDLY_COUNTRY=XX VOIDLY_CITY=YourCity voidly-probe --consent` |
| **Cloudflare DoH** | DNS poisoning detection (cloudflare-dns.com) | Domain names being tested are visible to Cloudflare |
| **api.voidly.ai** | Result submission (Cloudflare Worker) | Probe results, hashed IP, country/city |

## Data We Collect

| Data | Stored | Purpose |
|------|--------|---------|
| IP address | **No** — SHA256 hash only | Rate limiting, deduplication |
| Country/city | Yes | Geographic attribution of censorship |
| Domain test results | Yes | Censorship measurement |
| Latency, block type | Yes | Blocking method analysis |
| Node version | Yes | Compatibility tracking |

## Data We Do NOT Collect

- Browsing history
- Passwords or credentials
- Personal information
- DNS queries from your normal browsing
- Any traffic beyond the 62 tested domains

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.13  | ✅ Current |
| 1.0.12  | ✅ Supported |
| 1.0.11  | ✅ Security fixes |
| < 1.0.8 | ❌ Please upgrade |

## Best Practices for Operators

1. **High-risk countries**: Consider running behind a VPN (the probe warns you automatically)
2. **Privacy override**: Use `VOIDLY_COUNTRY` / `VOIDLY_CITY` env vars to skip ipinfo.io
3. **Docker**: Mount a persistent volume for `/data/.voidly` to preserve your node identity
4. **Updates**: Always run the latest version (`pip install --upgrade voidly-probe`)
