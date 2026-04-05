def load_domain_set(url: str) -> set[str]:
    with urllib.request.urlopen(url, timeout=10) as r:
        lines = r.read().decode().splitlines()

    domain_set = set()

    for line in lines:
        # Remove comments and whitespaces
        if line.strip() and not line.startswith("#"):
            domain_set.add(line.strip())

    return domain_set


# Malicious domains that are known to be malicious domains in general
DYNAMIC_DNS_DOMAINS = load_domain_set(
    "https://raw.githubusercontent.com/alexandrosmagos/dyn-dns-list/refs/heads/master/links.txt"
)


# Known command and control domains
KNOWN_C2_DOMAINS = load_domain_set(
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts"
)

# Ports that are unusual for legitimate apps — may indicate tunnelling or C2
SUSPICIOUS_PORTS = {
    1080,  # SOCKS proxy
    4444,  # Classic Metasploit default
    5555,  # ADB (suspicious if contacted externally)
    6666,
    6667,
    6668,
    6669,  # IRC (common C2)
    8080,
    8443,
    8888,  # Alt HTTP/HTTPS (less suspicious but still flagged)
    9001,
    9030,  # Tor
    31337,  # l33t hacking port — rarely legitimate
}

# Private / loopback ranges to exclude from "external IP" counts
_PRIVATE_RANGES = [
    (0x7F000000, 0xFF000000),  # 127.0.0.0/8  — loopback
    (0x0A000000, 0xFF000000),  # 10.0.0.0/8   — RFC1918
    (0xAC100000, 0xFFF00000),  # 172.16.0.0/12 — RFC1918
    (0xC0A80000, 0xFFFF0000),  # 192.168.0.0/16 — RFC1918
    (0xA9FE0000, 0xFFFF0000),  # 169.254.0.0/16 — link-local
]


def _is_private_ip(ip_bytes: bytes) -> bool:
    """Return True if the 4-byte IPv4 address is private/loopback."""
    ip_int = struct.unpack("!I", ip_bytes)[0]
    return any((ip_int & mask) == network for network, mask in _PRIVATE_RANGES)


def _extract_domain_root(hostname: str) -> str:
    """Return the registrable domain (last two labels) of a hostname."""
    parts = hostname.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname
