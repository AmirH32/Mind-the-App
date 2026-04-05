# Before you run this, push tcpdump to the emulator first:
#   adb push tcpdump /data/local/tmp/tcpdump
#   adb shell chmod +x /data/local/tmp/tcpdump

import urllib


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
_PRIVATE_RANGES = [
    (0x7F000000, 0xFF000000),  # 127/8 loopback - device talking to itself
    (
        0x0A000000,
        0xFF000000,
    ),  # 10/8 private network range used by emulator for internal comms
    (0xAC100000, 0xFFF00000),  # 172.16/12 Private range
    (0xC0A80000, 0xFFFF0000),  # 192.168/16 Wifi/local home range (192.168)
    (0xA9FE0000, 0xFFFF0000),  # 169.254/16 link-local when device can't find DHCP
]
