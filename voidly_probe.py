#!/usr/bin/env python3
"""
Voidly Community Probe — Help measure internet censorship worldwide.

Run a lightweight probe node from anywhere in the world.
Tests 62 domains for DNS, HTTP, TLS, and SNI-based blocking every 15 minutes.
Reports results to Voidly's censorship intelligence network.

No VPN, no root required. Zero external dependencies (Python 3.8+ stdlib only).

Usage:
    pip install voidly-probe
    voidly-probe --consent          # First run: register + start probing
    voidly-probe                    # Subsequent runs
    voidly-probe --once             # Single probe cycle then exit
    voidly-probe --status           # Show node status
    python -m voidly_probe --consent  # Windows (if voidly-probe not on PATH)

Learn more: https://voidly.ai/probes
"""

import os
import sys
import json
import time
import signal
import socket
import ssl
import hmac
import hashlib
import uuid
import urllib.request
import urllib.error
import threading
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any


__version__ = "1.0.12"

# ─── Graceful Shutdown ────────────────────────────────────────────────────────

_shutdown_requested = False


def _handle_shutdown(signum: int, frame: Any) -> None:
    """Handle SIGTERM/SIGHUP for graceful Docker shutdown."""
    global _shutdown_requested
    sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
    print(f"\n  Received {sig_name} — shutting down gracefully...")
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGHUP, _handle_shutdown)

# ─── Configuration ────────────────────────────────────────────────────────────

API_URL = os.environ.get("VOIDLY_API_URL", "https://api.voidly.ai")
if not API_URL.startswith("https://") and "localhost" not in API_URL and "127.0.0.1" not in API_URL:
    print(f"  ERROR: API URL must use HTTPS for security. Got: {API_URL}")
    sys.exit(1)
def _safe_int_env(name: str, default: int) -> int:
    """Parse an integer env var with fallback + warning on bad values."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"  WARNING: {name}={raw!r} is not a valid integer, using default {default}")
        return default

PROBE_INTERVAL = _safe_int_env("VOIDLY_PROBE_INTERVAL", 900)   # 15 minutes
PROBE_TIMEOUT = _safe_int_env("VOIDLY_PROBE_TIMEOUT", 10)      # 10 seconds per request
PROBE_BATCH_SIZE = _safe_int_env("VOIDLY_BATCH_SIZE", 20)      # Domains per cycle
USER_AGENT = f"Mozilla/5.0 (compatible; VoidlyProbe/{__version__}; +https://voidly.ai/probes)"
CONFIG_DIR = Path(os.environ.get("VOIDLY_CONFIG_DIR", Path.home() / ".voidly"))

# ─── Probe Targets (62 domains) ──────────────────────────────────────────────

PROBE_TARGETS = [
    # === Social Media (12) ===
    {"url": "https://x.com", "domain": "x.com", "category": "social"},
    {"url": "https://twitter.com", "domain": "twitter.com", "category": "social"},
    {"url": "https://facebook.com", "domain": "facebook.com", "category": "social"},
    {"url": "https://instagram.com", "domain": "instagram.com", "category": "social"},
    {"url": "https://youtube.com", "domain": "youtube.com", "category": "social"},
    {"url": "https://tiktok.com", "domain": "tiktok.com", "category": "social"},
    {"url": "https://reddit.com", "domain": "reddit.com", "category": "social"},
    {"url": "https://linkedin.com", "domain": "linkedin.com", "category": "social"},
    {"url": "https://pinterest.com", "domain": "pinterest.com", "category": "social"},
    {"url": "https://tumblr.com", "domain": "tumblr.com", "category": "social"},
    {"url": "https://snapchat.com", "domain": "snapchat.com", "category": "social"},
    {"url": "https://discord.com", "domain": "discord.com", "category": "social"},

    # === Messaging (8) ===
    {"url": "https://web.whatsapp.com", "domain": "whatsapp.com", "category": "messaging"},
    {"url": "https://web.telegram.org", "domain": "telegram.org", "category": "messaging"},
    {"url": "https://signal.org", "domain": "signal.org", "category": "messaging"},
    {"url": "https://viber.com", "domain": "viber.com", "category": "messaging"},
    {"url": "https://messenger.com", "domain": "messenger.com", "category": "messaging"},
    {"url": "https://line.me", "domain": "line.me", "category": "messaging"},
    {"url": "https://wechat.com", "domain": "wechat.com", "category": "messaging"},
    {"url": "https://skype.com", "domain": "skype.com", "category": "messaging"},

    # === News & Media (12) ===
    {"url": "https://bbc.com", "domain": "bbc.com", "category": "news"},
    {"url": "https://nytimes.com", "domain": "nytimes.com", "category": "news"},
    {"url": "https://reuters.com", "domain": "reuters.com", "category": "news"},
    {"url": "https://theguardian.com", "domain": "theguardian.com", "category": "news"},
    {"url": "https://washingtonpost.com", "domain": "washingtonpost.com", "category": "news"},
    {"url": "https://cnn.com", "domain": "cnn.com", "category": "news"},
    {"url": "https://aljazeera.com", "domain": "aljazeera.com", "category": "news"},
    {"url": "https://dw.com", "domain": "dw.com", "category": "news"},
    {"url": "https://rferl.org", "domain": "rferl.org", "category": "news"},
    {"url": "https://voanews.com", "domain": "voanews.com", "category": "news"},
    {"url": "https://medium.com", "domain": "medium.com", "category": "news"},
    {"url": "https://substack.com", "domain": "substack.com", "category": "news"},

    # === Privacy & VPN (10) ===
    {"url": "https://torproject.org", "domain": "torproject.org", "category": "privacy"},
    {"url": "https://nordvpn.com", "domain": "nordvpn.com", "category": "privacy"},
    {"url": "https://expressvpn.com", "domain": "expressvpn.com", "category": "privacy"},
    {"url": "https://protonvpn.com", "domain": "protonvpn.com", "category": "privacy"},
    {"url": "https://mullvad.net", "domain": "mullvad.net", "category": "privacy"},
    {"url": "https://surfshark.com", "domain": "surfshark.com", "category": "privacy"},
    {"url": "https://vpngate.net", "domain": "vpngate.net", "category": "privacy"},
    {"url": "https://psiphon.ca", "domain": "psiphon.ca", "category": "privacy"},
    {"url": "https://getlantern.org", "domain": "getlantern.org", "category": "privacy"},
    {"url": "https://proton.me", "domain": "proton.me", "category": "privacy"},

    # === Human Rights & NGOs (8) ===
    {"url": "https://amnesty.org", "domain": "amnesty.org", "category": "rights"},
    {"url": "https://hrw.org", "domain": "hrw.org", "category": "rights"},
    {"url": "https://rsf.org", "domain": "rsf.org", "category": "rights"},
    {"url": "https://eff.org", "domain": "eff.org", "category": "rights"},
    {"url": "https://accessnow.org", "domain": "accessnow.org", "category": "rights"},
    {"url": "https://freedomhouse.org", "domain": "freedomhouse.org", "category": "rights"},
    {"url": "https://article19.org", "domain": "article19.org", "category": "rights"},
    {"url": "https://cpj.org", "domain": "cpj.org", "category": "rights"},

    # === Search & Reference (6) ===
    {"url": "https://google.com", "domain": "google.com", "category": "search"},
    {"url": "https://duckduckgo.com", "domain": "duckduckgo.com", "category": "search"},
    {"url": "https://bing.com", "domain": "bing.com", "category": "search"},
    {"url": "https://wikipedia.org", "domain": "wikipedia.org", "category": "reference"},
    {"url": "https://archive.org", "domain": "archive.org", "category": "reference"},
    {"url": "https://wikileaks.org", "domain": "wikileaks.org", "category": "reference"},

    # === Developer & Tech (6) ===
    {"url": "https://github.com", "domain": "github.com", "category": "tech"},
    {"url": "https://gitlab.com", "domain": "gitlab.com", "category": "tech"},
    {"url": "https://stackoverflow.com", "domain": "stackoverflow.com", "category": "tech"},
    {"url": "https://hackerone.com", "domain": "hackerone.com", "category": "tech"},
    {"url": "https://pastebin.com", "domain": "pastebin.com", "category": "tech"},
    {"url": "https://dropbox.com", "domain": "dropbox.com", "category": "tech"},
]

# ─── Block Page Fingerprints ─────────────────────────────────────────────────

BLOCKPAGE_FINGERPRINTS = {
    "iran-tic": {
        "patterns": ["10.10.34.34", "10.10.34.35", "peyvandha.ir"],
        "entity": "Iran Telecommunications Company",
        "type": "government-mandated",
    },
    "russia-roskomnadzor": {
        "patterns": ["rkn.gov.ru", "eais.rkn.gov.ru", "blocklist.rkn.gov.ru"],
        "entity": "Roskomnadzor",
        "type": "government-direct",
    },
    "china-gfw": {
        "patterns": ["Connection reset by peer", "ERR_CONNECTION_RESET"],
        "entity": "Great Firewall of China",
        "type": "government-firewall",
    },
    "turkey-btk": {
        "patterns": ["5651", "internet-sitemiz.com", "BTK"],
        "entity": "BTK (Turkey)",
        "type": "government-mandated",
    },
    "saudi-citc": {
        "patterns": ["blocked.com.sa", "mcit.gov.sa", "CITC"],
        "entity": "CITC (Saudi Arabia)",
        "type": "government-mandated",
    },
    "uae-tra": {
        "patterns": ["blocked.ae", "tra.gov.ae"],
        "entity": "TRA (UAE)",
        "type": "government-mandated",
    },
    "pakistan-pta": {
        "patterns": ["pta.gov.pk", "surfguard", "This site is blocked"],
        "entity": "PTA (Pakistan)",
        "type": "government-mandated",
    },
    "indonesia-kominfo": {
        "patterns": ["trustpositif", "kominfo.go.id", "internet sehat"],
        "entity": "Kominfo (Indonesia)",
        "type": "government-mandated",
    },
    "india-dot": {
        "patterns": ["blocked as per instructions", "Department of Telecom", "dot.gov.in"],
        "entity": "DoT (India)",
        "type": "government-mandated",
    },
    "fortiguard": {
        "patterns": ["FortiGuard", "fortinet", "Web Filter Block"],
        "entity": "Fortinet FortiGuard",
        "type": "isp-filter",
    },
    "netsweeper": {
        "patterns": ["netsweeper", "webfilter", "categorized as"],
        "entity": "Netsweeper",
        "type": "isp-filter",
    },
    "bluecoat": {
        "patterns": ["Blue Coat", "ProxySG"],
        "entity": "Blue Coat Systems",
        "type": "isp-filter",
    },
    "cisco-umbrella": {
        "patterns": ["umbrella.cisco.com", "blocked by Cisco", "OpenDNS"],
        "entity": "Cisco Umbrella",
        "type": "corporate-filter",
    },
}


# ─── Node Configuration ──────────────────────────────────────────────────────

def get_config_path() -> Path:
    """Get or create the config directory."""
    # Safety: ensure CONFIG_DIR is a directory, not a file
    if CONFIG_DIR.exists() and not CONFIG_DIR.is_dir():
        print(f"ERROR: {CONFIG_DIR} exists but is not a directory. Remove it and try again.")
        sys.exit(1)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR / "node.json"


def load_config() -> Optional[Dict[str, Any]]:
    """Load node configuration from disk."""
    config_path = get_config_path()
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text())
            # Validate required fields
            if not isinstance(config, dict):
                return None
            node_id = config.get("nodeId", "")
            node_token = config.get("nodeToken", "")
            if not isinstance(node_id, str) or not (8 <= len(node_id) <= 64):
                print("  Warning: invalid nodeId in config, re-registering...")
                return None
            if not isinstance(node_token, str) or not (16 <= len(node_token) <= 256):
                print("  Warning: invalid nodeToken in config, re-registering...")
                return None
            # Ensure country field exists (older configs may lack it)
            if not config.get("country"):
                config["country"] = "XX"
            return config
        except (json.JSONDecodeError, IOError) as e:
            print(f"  Warning: corrupt config ({e}), will re-register...")
            return None
    return None


def save_config(config: Dict[str, Any]) -> None:
    """Save node configuration to disk atomically."""
    config_path = get_config_path()
    tmp_path = config_path.with_suffix(".tmp")
    try:
        # Write to temp file first, then rename (atomic on most filesystems)
        tmp_path.write_text(json.dumps(config, indent=2))
        try:
            tmp_path.chmod(0o600)
        except OSError:
            print(f"  WARNING: Could not set file permissions on token file.")
            print(f"  Please manually secure: {config_path}")
        tmp_path.rename(config_path)
    except Exception:
        # Fallback: direct write
        config_path.write_text(json.dumps(config, indent=2))
        try:
            config_path.chmod(0o600)
        except OSError:
            print(f"  WARNING: Could not set file permissions on token file.")
            print(f"  Please manually secure: {config_path}")


def detect_location() -> Dict[str, str]:
    """Auto-detect country and city using a public GeoIP API.

    Set VOIDLY_COUNTRY (and optionally VOIDLY_CITY) to skip ipinfo.io entirely.
    """
    # Manual override — skip ipinfo.io for privacy-sensitive users
    manual_country = os.environ.get("VOIDLY_COUNTRY")
    if manual_country:
        return {
            "country": manual_country.upper()[:2],
            "city": os.environ.get("VOIDLY_CITY", "Unknown"),
            "region": "",
        }

    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            return {
                "country": data.get("country", "XX"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", ""),
            }
    except Exception as e:
        print(f"  Warning: Could not detect location ({e}). Using defaults.")
        return {"country": "XX", "city": "Unknown", "region": ""}


def register_node() -> Dict[str, Any]:
    """Register this node with the Voidly network and get a token."""
    location = detect_location()
    print(f"  Detected location: {location['city']}, {location['country']}")

    payload = json.dumps({
        "country": location["country"],
        "city": location["city"],
        "version": __version__,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{API_URL}/v1/community/register",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
            node_id = data.get("nodeId", "")
            node_token = data.get("nodeToken", "")
            if not isinstance(node_id, str) or not (8 <= len(node_id) <= 64):
                print("  Registration failed: invalid nodeId format from API")
                sys.exit(1)
            if not isinstance(node_token, str) or not (16 <= len(node_token) <= 256):
                print("  Registration failed: invalid nodeToken format from API")
                sys.exit(1)
            config = {
                "nodeId": node_id,
                "nodeToken": node_token,
                "country": location["country"],
                "city": location["city"],
                "registeredAt": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
            }
            save_config(config)
            return config
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")[:200]
        print(f"  Registration failed: HTTP {e.code} — {body}")
        sys.exit(1)
    except Exception as e:
        print(f"  Registration failed: {e}")
        sys.exit(1)


# ─── HMAC Signing ─────────────────────────────────────────────────────────────

def sign_payload(payload: bytes, token: str) -> str:
    """Sign a payload with the node token using HMAC-SHA256."""
    return hmac.new(token.encode("utf-8"), payload, hashlib.sha256).hexdigest()


# ─── Probe Logic ──────────────────────────────────────────────────────────────

class ProbeResult:
    """Result of a single HTTP/DNS/TLS probe."""
    def __init__(self, target: Dict[str, str], node_id: str, node_country: str):
        self.target_url = target["url"]
        self.domain = target["domain"]
        self.category = target["category"]
        self.node_id = node_id
        self.node_country = node_country
        self.success = False
        self.latency_ms: Optional[int] = None
        self.http_status: Optional[int] = None
        self.error_type: Optional[str] = None
        self.error_detail: Optional[str] = None
        self.is_blocked = False
        self.block_type: Optional[str] = None
        self.confidence = 0.0
        self.dns_resolved: Optional[str] = None
        self.tls_version: Optional[str] = None
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.blocking_entity: Optional[str] = None
        self.blocking_type: Optional[str] = None
        self.blockpage_hash: Optional[str] = None
        self.sni_blocked: Optional[bool] = None
        self.dns_poisoned: Optional[bool] = None
        self.cert_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targetUrl": self.target_url,
            "domain": self.domain,
            "category": self.category,
            "nodeId": self.node_id,
            "nodeCountry": self.node_country,
            "success": self.success,
            "latencyMs": self.latency_ms,
            "httpStatus": self.http_status,
            "errorType": self.error_type,
            "errorDetail": self.error_detail,
            "isBlocked": self.is_blocked,
            "blockType": self.block_type,
            "confidence": self.confidence,
            "dnsResolved": self.dns_resolved,
            "tlsVersion": self.tls_version,
            "timestamp": self.timestamp,
            "blockingEntity": self.blocking_entity,
            "blockingType": self.blocking_type,
            "blockpageHash": self.blockpage_hash,
            "sniBlocked": self.sni_blocked,
            "dnsPoisoned": self.dns_poisoned,
            "certFingerprint": self.cert_fingerprint,
        }


def fingerprint_blockpage(content: str) -> Optional[Dict[str, str]]:
    """Identify blocking entity from block page content."""
    content_lower = content.lower()
    for fp_id, fp in BLOCKPAGE_FINGERPRINTS.items():
        for pattern in fp["patterns"]:
            if pattern.lower() in content_lower:
                return {
                    "id": fp_id,
                    "entity": fp["entity"],
                    "type": fp["type"],
                }
    return None


def probe_sni(domain: str, timeout: int = 5) -> Optional[bool]:
    """
    Test if SNI-based TLS filtering is active.
    Returns: True = SNI filtered, False = OK, None = inconclusive.
    """
    try:
        try:
            ip = socket.gethostbyname(domain)
        except (socket.gaierror, socket.timeout):
            return None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((ip, 443))
            tls_sock = ctx.wrap_socket(sock, server_hostname=domain)
            tls_sock.close()
            return False
        except ConnectionResetError:
            return True
        except ssl.SSLError as e:
            if "connection reset" in str(e).lower() or "eof" in str(e).lower():
                return True
            return None
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        return None


def probe_doh_dns(domain: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
    """
    Compare system DNS with Cloudflare DoH to detect DNS poisoning.
    Returns: {poisoned: bool, system_ips: list, doh_ips: list} or None.
    """
    try:
        try:
            system_ips = sorted(socket.gethostbyname_ex(domain)[2])
        except (socket.gaierror, socket.timeout):
            system_ips = []

        doh_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
        req = urllib.request.Request(doh_url, headers={"Accept": "application/dns-json"})

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
                doh_ips = sorted([
                    ans["data"] for ans in data.get("Answer", [])
                    if ans.get("type") == 1
                ])
        except Exception:
            return None

        if not system_ips and not doh_ips:
            return None

        if not system_ips:
            # System DNS failed entirely — could be transient outage, not poisoning
            poisoned = None
            return {"poisoned": poisoned, "system_ips": system_ips, "doh_ips": doh_ips}
        elif not doh_ips:
            return None
        elif set(system_ips) & set(doh_ips):
            poisoned = False
        else:
            poisoned = True

        return {"poisoned": poisoned, "system_ips": system_ips, "doh_ips": doh_ips}
    except Exception:
        return None


def probe_cert_fingerprint(domain: str, timeout: int = 5) -> Optional[str]:
    """Get SHA256 fingerprint of the server's TLS certificate."""
    try:
        cert_pem = ssl.get_server_certificate((domain, 443), timeout=timeout)
        cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
        return hashlib.sha256(cert_der).hexdigest()
    except Exception:
        return None


# Known safe redirects (not censorship)
SAFE_REDIRECTS = [
    ("twitter.com", "x.com"),
    ("facebook.com", "www.facebook.com"),
    ("google.com", "www.google.com"),
    ("bbc.com", "www.bbc.com"),
    ("instagram.com", "www.instagram.com"),
    ("reddit.com", "www.reddit.com"),
    ("medium.com", "medium.com"),
    ("linkedin.com", "www.linkedin.com"),
]


def is_redirect_safe(domain: str, final_url: str) -> bool:
    """Check if a redirect is a known-safe pattern (not censorship)."""
    for orig, redir in SAFE_REDIRECTS:
        if domain == orig and redir in final_url:
            return True
    # Generic: redirect to www.{domain} is always safe
    if f"www.{domain}" in final_url:
        return True
    # Generic: redirect to subdomain of same root domain is safe
    host = final_url.split("//")[-1].split("/")[0].split(":")[0]
    if host.endswith(f".{domain}"):
        return True
    return False

# Countries where timeouts are almost never censorship
FREE_COUNTRIES = {
    "US", "CA", "GB", "NL", "DE", "ES", "AU", "JP", "KR", "SG", "BR", "MX", "ZA", "IN",
}


def probe_target(target: Dict[str, str], node_id: str, node_country: str) -> ProbeResult:
    """Probe a single target for blocking. Returns ProbeResult."""
    result = ProbeResult(target, node_id, node_country)
    url = target["url"]
    domain = target["domain"]
    start_time = time.time()

    try:
        # Step 1: DNS Resolution
        try:
            ip = socket.gethostbyname(domain)
            result.dns_resolved = ip
        except socket.gaierror as e:
            result.error_type = "dns_failure"
            result.error_detail = str(e)
            result.is_blocked = True
            result.block_type = "dns-nxdomain"
            result.confidence = 0.9
            return result
        except socket.timeout:
            result.error_type = "dns_timeout"
            result.error_detail = "DNS resolution timed out"
            if node_country in FREE_COUNTRIES:
                result.is_blocked = False
                result.confidence = 0.15
            else:
                result.is_blocked = True
                result.confidence = 0.7
            result.block_type = "dns-timeout"
            return result

        # Step 2: HTTP/HTTPS Request
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            method="GET",
        )

        context = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT, context=context) as response:
                result.http_status = response.status
                result.latency_ms = int((time.time() - start_time) * 1000)
                result.success = True

                final_url = response.geturl()
                if domain not in final_url and not is_redirect_safe(domain, final_url):
                    result.is_blocked = True
                    result.block_type = "http-redirect"
                    result.confidence = 0.6
                    result.error_detail = f"Redirected to {final_url}"

                    try:
                        content = response.read(10000).decode("utf-8", errors="ignore")
                        fp = fingerprint_blockpage(content)
                        if fp:
                            result.blocking_entity = fp["entity"]
                            result.blocking_type = fp["type"]
                            result.blockpage_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
                            result.confidence = 0.85
                    except Exception:
                        pass

        except urllib.error.HTTPError as e:
            result.http_status = e.code
            result.latency_ms = int((time.time() - start_time) * 1000)

            if e.code == 403:
                result.is_blocked = False
                result.error_type = "http_forbidden"
                result.error_detail = "403 - likely CDN rate limit, not censorship"
            elif e.code == 451:
                result.is_blocked = True
                result.block_type = "http-451"
                result.confidence = 0.95
                result.error_type = "http_legal_block"
            else:
                result.error_type = "http_error"
            result.error_detail = str(e)

        except urllib.error.URLError as e:
            result.latency_ms = int((time.time() - start_time) * 1000)
            reason = str(e.reason)

            if "Connection refused" in reason:
                result.is_blocked = True
                result.block_type = "tcp-refused"
                result.confidence = 0.85
                result.error_type = "connection_refused"
            elif "Connection reset" in reason or "reset by peer" in reason.lower():
                result.is_blocked = True
                result.block_type = "tcp-reset"
                result.confidence = 0.9
                result.error_type = "connection_reset"
            elif "timed out" in reason.lower():
                if node_country in FREE_COUNTRIES:
                    result.is_blocked = False
                    result.confidence = 0.15
                else:
                    result.is_blocked = True
                    result.confidence = 0.6
                result.block_type = "tcp-timeout"
                result.error_type = "timeout"
            else:
                result.error_type = "url_error"
            result.error_detail = reason

        except ssl.SSLError as e:
            result.latency_ms = int((time.time() - start_time) * 1000)
            result.error_type = "ssl_error"
            result.error_detail = str(e)
            if "certificate" in str(e).lower():
                result.is_blocked = True
                result.block_type = "tls-cert-invalid"
                result.confidence = 0.75
            else:
                result.is_blocked = True
                result.block_type = "tls-reset"
                result.confidence = 0.8

    except Exception as e:
        result.error_type = "unknown"
        result.error_detail = str(e)
        result.latency_ms = int((time.time() - start_time) * 1000)

    # === Advanced measurements ===
    try:
        sni_result = probe_sni(domain, timeout=5)
        result.sni_blocked = sni_result
        if sni_result is True and not result.is_blocked:
            result.is_blocked = True
            result.block_type = "sni-filtering"
            result.confidence = max(result.confidence, 0.85)
    except Exception:
        pass

    try:
        doh_result = probe_doh_dns(domain, timeout=5)
        if doh_result is not None:
            result.dns_poisoned = doh_result["poisoned"]
            if doh_result["poisoned"] and not result.is_blocked:
                result.is_blocked = True
                result.block_type = "dns-poisoned"
                result.confidence = max(result.confidence, 0.9)
    except Exception:
        pass

    try:
        cert_fp = probe_cert_fingerprint(domain, timeout=5)
        result.cert_fingerprint = cert_fp
    except Exception:
        pass

    return result


# ─── Batch Rotation ───────────────────────────────────────────────────────────

_probe_offset = 0


def get_probe_batch() -> List[Dict[str, Any]]:
    """Get the next rotating batch of domains to probe."""
    global _probe_offset
    total = len(PROBE_TARGETS)
    batch_size = min(PROBE_BATCH_SIZE, total)

    batch = []
    for i in range(batch_size):
        idx = (_probe_offset + i) % total
        batch.append(PROBE_TARGETS[idx])

    _probe_offset = (_probe_offset + batch_size) % total
    return batch


# ─── Result Reporting ─────────────────────────────────────────────────────────

def _cache_results(payload: Dict[str, Any]) -> None:
    """Save failed results to disk for retry. Age-based eviction (24h max)."""
    cache_path = CONFIG_DIR / "pending_results.json"
    try:
        pending: List[Dict[str, Any]] = []
        if cache_path.exists():
            try:
                loaded = json.loads(cache_path.read_text())
                if isinstance(loaded, list):
                    pending = loaded
            except (json.JSONDecodeError, IOError):
                pass
        # Evict entries older than 24 hours
        cutoff = (datetime.now(timezone.utc).timestamp()) - 86400
        pending = [
            p for p in pending
            if p.get("_cached_at", cutoff + 1) > cutoff
        ]
        payload["_cached_at"] = datetime.now(timezone.utc).timestamp()
        pending.append(payload)
        cache_path.write_text(json.dumps(pending))
        print(f"  Cached {len(payload.get('results', []))} results for retry ({len(pending)} pending)")
    except Exception as e:
        print(f"  Failed to cache results: {e}")


def flush_pending_results(node_id: str, node_country: str, node_token: str) -> None:
    """Attempt to send any cached results from previous failures."""
    cache_path = CONFIG_DIR / "pending_results.json"
    if not cache_path.exists():
        return
    try:
        pending = json.loads(cache_path.read_text())
        if not isinstance(pending, list) or not pending:
            cache_path.unlink(missing_ok=True)
            return
    except (json.JSONDecodeError, IOError):
        cache_path.unlink(missing_ok=True)
        return

    remaining = []
    for payload in pending:
        data = json.dumps(payload).encode("utf-8")
        signature = sign_payload(data, node_token)
        try:
            req = urllib.request.Request(
                f"{API_URL}/v1/probe/results",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {node_token}",
                    "X-Voidly-Signature": f"sha256={signature}",
                    "User-Agent": USER_AGENT,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    print(f"  Flushed {len(payload.get('results', []))} cached results")
                else:
                    remaining.append(payload)
        except Exception:
            remaining.append(payload)

    if remaining:
        cache_path.write_text(json.dumps(remaining))
    else:
        cache_path.unlink(missing_ok=True)


def report_results(
    results: List[Dict[str, Any]],
    node_id: str,
    node_country: str,
    node_token: str,
) -> bool:
    """Send probe results to Voidly API with HMAC signature. Retries once on failure."""
    if not results:
        return True

    payload = {
        "nodeId": node_id,
        "nodeCountry": node_country,
        "nodeType": "community",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "submissionId": uuid.uuid4().hex,  # 32-char nonce for replay prevention
        "results": results,
    }

    data = json.dumps(payload).encode("utf-8")
    signature = sign_payload(data, node_token)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {node_token}",
        "X-Voidly-Signature": f"sha256={signature}",
        "User-Agent": USER_AGENT,
    }

    for attempt in range(2):
        try:
            req = urllib.request.Request(
                f"{API_URL}/v1/probe/results",
                data=data,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    return True
                else:
                    print(f"  Server returned {response.status}")
        except Exception as e:
            print(f"  Failed to report (attempt {attempt + 1}/2): {e}")
        if attempt == 0:
            time.sleep(5)

    # Both attempts failed — cache to disk for next cycle
    _cache_results(payload)
    return False


# ─── Main Loop ────────────────────────────────────────────────────────────────

def run_probe_cycle(config: Dict[str, Any]) -> Dict[str, Any]:
    """Run a single probe cycle and report results."""
    node_id = config["nodeId"]
    node_country = config["country"]
    node_token = config["nodeToken"]

    # Flush any cached results from previous failed submissions
    flush_pending_results(node_id, node_country, node_token)

    batch = get_probe_batch()
    results = []

    for target in batch:
        try:
            result = probe_target(target, node_id, node_country)
            results.append(result.to_dict())
            time.sleep(0.5)
        except Exception as e:
            print(f"  Error probing {target['domain']}: {e}")

    blocked = sum(1 for r in results if r.get("isBlocked"))
    success = sum(1 for r in results if r.get("success"))
    errors = len(results) - success - blocked

    reported = report_results(results, node_id, node_country, node_token)

    return {
        "probed": len(results),
        "success": success,
        "blocked": blocked,
        "errors": errors,
        "reported": reported,
    }


def _check_connectivity() -> bool:
    """Quick health check to verify API is reachable."""
    try:
        req = urllib.request.Request(
            f"{API_URL}/health",
            headers={"User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except Exception:
        return False


def probe_loop(config: Dict[str, Any]) -> None:
    """Main probe loop — runs until shutdown signal."""
    global _shutdown_requested
    node_id = config["nodeId"]
    node_country = config["country"]

    print(f"\n{'='*60}")
    print(f"  Voidly Community Probe v{__version__}")
    print(f"  Node: {node_id} ({node_country})")
    print(f"  Targets: {len(PROBE_TARGETS)} domains")
    print(f"  Interval: {PROBE_INTERVAL}s ({PROBE_INTERVAL // 60} min)")
    print(f"  Reporting to: {API_URL}")
    print(f"{'='*60}\n")

    # Connectivity check before starting
    print("  Checking API connectivity...")
    for attempt in range(3):
        if _check_connectivity():
            print("  API reachable. Starting probe loop.\n")
            break
        wait = (attempt + 1) * 10
        print(f"  API unreachable (attempt {attempt + 1}/3). Retrying in {wait}s...")
        time.sleep(wait)
    else:
        print("  WARNING: API unreachable — starting anyway (results will be cached)\n")

    cycle = 0
    session_total = 0
    consecutive_failures = 0
    session_start = datetime.now(timezone.utc)

    while not _shutdown_requested:
        cycle += 1
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        print(f"[{timestamp}] Cycle {cycle}: probing {PROBE_BATCH_SIZE}/{len(PROBE_TARGETS)} domains...")

        try:
            stats = run_probe_cycle(config)
            session_total += stats["probed"]
            elapsed = datetime.now(timezone.utc) - session_start
            hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
            mins = remainder // 60
            elapsed_str = f"{hours}h {mins}m" if hours else f"{mins}m"
            status = "reported" if stats["reported"] else "FAILED to report"
            print(
                f"  {stats['success']} ok, {stats['blocked']} blocked, "
                f"{stats['errors']} errors — {status} "
                f"(session: {session_total} probes, {elapsed_str})"
            )
            # Track consecutive report failures for backoff
            if stats["reported"]:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
        except Exception as e:
            print(f"  Error in probe cycle: {e}")
            consecutive_failures += 1

        if _shutdown_requested:
            break

        # Exponential backoff on consecutive failures (5min, 15min, 60min max)
        if consecutive_failures >= 3:
            backoff = min(3600, 300 * (2 ** (consecutive_failures - 3)))
            print(f"  {consecutive_failures} consecutive failures — backing off {backoff}s")
            _interruptible_sleep(backoff)
        else:
            _interruptible_sleep(PROBE_INTERVAL)

    # Graceful shutdown: flush any pending results
    print("\n  Flushing pending results before exit...")
    try:
        flush_pending_results(config["nodeId"], config["country"], config["nodeToken"])
    except Exception:
        pass
    print("  Probe stopped. Thank you for contributing!")


def _interruptible_sleep(seconds: float) -> None:
    """Sleep that can be interrupted by shutdown signal."""
    end = time.time() + seconds
    while time.time() < end and not _shutdown_requested:
        time.sleep(min(1.0, end - time.time()))


# ─── CLI ──────────────────────────────────────────────────────────────────────

CONSENT_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║                   Voidly Community Probe                        ║
║                                                                  ║
║  By running this probe, you agree to the following:              ║
║                                                                  ║
║  • This tool tests connectivity to {n} websites every           ║
║    {interval} minutes from your network                          ║
║                                                                  ║
║  • Results (domain, blocked/accessible, latency, blocking        ║
║    method) are sent to api.voidly.ai                             ║
║                                                                  ║
║  • Your IP address is NOT stored — only a SHA256 hash            ║
║    for deduplication                                             ║
║                                                                  ║
║  • Country detection uses ipinfo.io (third-party). You can       ║
║    skip this with VOIDLY_COUNTRY and VOIDLY_CITY env vars        ║
║                                                                  ║
║  • DNS tests query Cloudflare DoH to detect DNS poisoning        ║
║                                                                  ║
║  • No browsing data, passwords, or personal information          ║
║    is collected                                                  ║
║                                                                  ║
║  • You can stop the probe at any time with Ctrl+C                ║
║                                                                  ║
║  • Data is used for censorship research under CC BY 4.0          ║
║                                                                  ║
║  Learn more: https://voidly.ai/probes                            ║
╚══════════════════════════════════════════════════════════════════╝
""".format(n=len(PROBE_TARGETS), interval=PROBE_INTERVAL // 60)


def main():
    global PROBE_INTERVAL

    parser = argparse.ArgumentParser(
        description="Voidly Community Probe — Help measure internet censorship",
        epilog="Learn more: https://voidly.ai/probes",
    )
    parser.add_argument(
        "--consent",
        action="store_true",
        help="Acknowledge data collection (required for first run)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single probe cycle then exit",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show node registration status",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"voidly-probe {__version__}",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help=f"Probe interval in seconds (default: {PROBE_INTERVAL})",
    )
    parser.add_argument(
        "--unregister",
        action="store_true",
        help="Remove node config and stop contributing",
    )

    args = parser.parse_args()

    # Override interval if specified
    if args.interval is not None:
        if args.interval < 300:
            print(f"  Note: minimum interval is 300s (5 min). Using 300s instead of {args.interval}s.")
        PROBE_INTERVAL = max(300, args.interval)  # Minimum 5 minutes

    # Unregister command
    if args.unregister:
        config_path = get_config_path()
        if config_path.exists():
            config_path.unlink()
            print(f"Node config deleted: {config_path}")
            print("You are no longer contributing. Thank you for your help!")
        else:
            print("No config found. Nothing to unregister.")
        return

    # Status command
    if args.status:
        config = load_config()
        if config:
            print(f"Node ID:      {config['nodeId']}")
            print(f"Country:      {config.get('country', 'XX')}")
            print(f"City:         {config.get('city', 'Unknown')}")
            print(f"Registered:   {config.get('registeredAt', 'Unknown')}")
            print(f"Version:      {__version__}")
            print(f"Config:       {get_config_path()}")
            # Fetch live stats from API
            try:
                req = urllib.request.Request(
                    f"{API_URL}/v1/community/nodes/{config['nodeId']}",
                    headers={"User-Agent": USER_AGENT},
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode("utf-8"))
                    node = data.get("node", {})
                    if node:
                        print(f"Total probes: {node.get('total_probes', 0)}")
                        print(f"Trust score:  {node.get('trust_score', 0)}")
                        print(f"Last seen:    {node.get('last_seen', 'Never')}")
            except Exception:
                pass
            print(f"\nClaim your node: https://voidly.ai/probes/claim")
        else:
            print("Not registered. Run with --consent to register.")
            print("  Windows: python -m voidly_probe --consent")
        return

    # Load or register
    config = load_config()

    if config is None:
        if not args.consent:
            print(CONSENT_TEXT)
            print("To start probing, run:")
            print("  voidly-probe --consent")
            print("")
            print("  Windows (if not recognized):")
            print("  python -m voidly_probe --consent\n")
            return

        print("Registering with Voidly network...")
        config = register_node()
        print(f"  Registered as: {config['nodeId']}")
        print(f"  Config saved to: {get_config_path()}")
        print(f"\n  ** Keep {get_config_path()} safe — your token cannot be recovered! **")
        print(f"  Claim your node: https://voidly.ai/probes/claim\n")

    # Risk advisory for high-censorship countries
    HIGH_RISK_COUNTRIES = {"CN", "IR", "KP", "TM", "ER", "RU", "SA", "CU", "SY", "MM", "BY"}
    node_country = config.get("country", "").upper()
    if node_country in HIGH_RISK_COUNTRIES:
        print("\n  \u26a0\ufe0f  RISK ADVISORY: You're in a high-censorship country.")
        print("  Your ISP may be able to detect that you're running a censorship probe.")
        print("  Consider running behind a VPN for additional protection.")
        print("  Learn more: https://voidly.ai/probes#risks\n")

    # Run probes
    if args.once:
        print(f"Running single probe cycle ({PROBE_BATCH_SIZE} domains)...")
        stats = run_probe_cycle(config)
        print(
            f"Done: {stats['success']} ok, {stats['blocked']} blocked, "
            f"{stats['errors']} errors"
        )
        if stats["reported"]:
            print("Results reported to Voidly.")
        else:
            print("WARNING: Failed to report results.")
    else:
        try:
            probe_loop(config)
        except KeyboardInterrupt:
            print("\n\n  Flushing pending results before exit...")
            try:
                flush_pending_results(config["nodeId"], config["country"], config["nodeToken"])
            except Exception:
                pass
            print("  Probe stopped. Thank you for contributing!")


if __name__ == "__main__":
    main()
