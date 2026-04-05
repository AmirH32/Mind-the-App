# Before you run this, push tcpdump to the emulator first:
#   adb push tcpdump /data/local/tmp/tcpdump
#   adb shell chmod +x /data/local/tmp/tcpdump


import urllib.request
import ipaddress


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


# ports that you wouldnt really expect to see in a legit app
# 4444 and 5555 are classic meterpreter, 9001/9030 are tor
SUSPICIOUS_PORTS = {
    1080,  # Socks protocol used to be inconspicious and tunnel through a proxy server
    4444,  # found in meterpreter
    5555,  # If app tries to connect externally then it may attempt to execute shell commands without consent
    6666,  # Irc channnel
    6667,  # irc channel
    6668,  # irc channels
    6669,  # irc channels
    9001,  # tor network to anonymise traffic
    9030,  # tor network
    31337,  # typical old malicious 1337 type port
}

# private IP ranges as (network, mask) tuples — used to filter out local traffic that is not suspicious
# Used ipaddress library as it is more readable
_PRIVATE_RANGES = [
    ipaddress.IPv4Network("127.0.0.0/8"),  # Loopback
    ipaddress.IPv4Network("10.0.0.0/8"),  # Private/Emulator
    ipaddress.IPv4Network("172.16.0.0/12"),  # Private
    ipaddress.IPv4Network("192.168.0.0/16"),  # Local Wi-Fi
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
]


def _is_private(ip_bytes: bytes) -> bool:
    # Convert bytes directly to an IP object
    try:
        ip = ipaddress.IPv4Address(ip_bytes)
    except ValueError:
        return False  # Handle malformed data

    # Check if the IP is in any of your defined networks
    return any(ip in net for net in _PRIVATE_NETWORKS)
