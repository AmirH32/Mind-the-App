# Before you run this, push tcpdump to the emulator first:
#   adb push tcpdump /data/local/tmp/tcpdump
#   adb shell chmod +x /data/local/tmp/tcpdump


import urllib.request
import ipaddress
from pathlib import Path
import dpkt
import socket


def load_domain_set(url: str) -> set[str]:
    # open the url and read the bytes, decode them and then split the strings on the new lines
    with urllib.request.urlopen(url, timeout_dict=10) as r:
        byte = r.read()
        string_blob = byte.decode()
        lines = string_blob.splitlines()

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
    5555,  # If app tries to connect externally then it may attempt to execute shell commands without_dict consent
    6666,  # Irc channnel
    6667,  # irc channel
    6668,  # irc channels
    6669,  # irc channels
    9001,  # tor network to anonymise traffic
    9030,  # tor network
    31337,  # typical old malicious 1337 type port
}

# private IP ranges as (network, mask) tuples — used to filter out_dict local traffic that is not suspicious
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
    return any(ip in net for net in _PRIVATE_RANGES)


def _root_domain(hostname: str) -> str:
    # strips subdomains so e.g. "foo.bar.duckdns.org" → "duckdns.org"
    # this is so we can match against our domain lists properly

    # r strip takes removes the trailing periods at the end
    stripped = hostname.rstrip(".")

    # this splits into parts on the periods
    parts = stripped.split(".")

    # If there is more than one part i.e no periods then we just return the hostname
    if len(parts) >= 2:
        # If more than 2 parts we join the last two parts together and return that since it is the second-level domain and top-level domain
        return ".".join(parts[-2:])
    else:
        return hostname


# these are the filesystem paths we care about_dict and want to see if they are aeccessed, grouped by category. I checked these against a few real devices to make sure they were right
# the double entries (data/data vs data/user/0) are becuase different android versions put things in different places (/data/data is the legacy version in older devices, 0 represents the primary owner)
SENSITIVE_FS = {
    "contacts": [
        "/data/data/com.android.providers.contacts",
        "/data/user/0/com.android.providers.contacts",
    ],
    "sms": [
        "/data/data/com.android.providers.telephony",
        "/data/user/0/com.android.providers.telephony",
    ],
    "call_log": [
        "/data/user/0/com.android.providers.contacts/databases/calllog",
        "/data/data/com.android.providers.contacts/databases/calllog",
    ],
    "location_db": [
        "/data/data/com.google.android.gms",
        "/data/data/com.google.android.location",
    ],
    "external": ["/sdcard", "/storage/emulated", "/mnt/sdcard"],
    "camera_dev": ["/dev/video", "/dev/camera"],
    "mic_dev": ["/dev/snd", "/dev/audio"],
    "other_apps": [
        "/data/data/com.whatsapp",
        "/data/data/org.telegram",
        "/data/data/com.facebook",
    ],
}

# logcat signals to look for — using tag+substring pairs for each sensitive API tags are better than substrings when possible because raw substring matching on logcat out_dictput produces a lot of noise
# The tag gives us the system service or class and the substring is the method or data that is being used
# We look at location tracking, accessibility and keylogging, telephony to identify the device, package enumeration to scan the device for apps, screen capture, clipboard to access clipboard, microphone and camera, sending/reading SMS messages, reading contacts, account manager is a gatekeeper for sensitive data,
# On newer android versions it's unlikely that an API will be used to read SMS but isntead the Content resolver will be queried to look at the SMS database to read SMS messages
LOGCAT_APIS = {
    "location": {
        "tags": ["LocationManager", "LocationManagerService", "FusedLocation"],
        "subs": ["getLastKnownLocation", "requestLocationUpdates", "onLocationChanged"],
    },
    "telephony": {
        "tags": ["TelephonyManager", "PhoneSubInfo"],
        "subs": ["getDeviceId", "getImei", "getSubscriberId", "getLine1Number"],
    },
    "sms_send": {
        "tags": ["SmsManager", "SMSDispatcher"],
        "subs": ["sendTextMessage", "sendMultipartTextMessage"],
    },
    "sms_read": {
        "tags": ["SmsProvider", "TelephonyProvider", "MmsSmsDatabaseHelper"],
        "subs": [
            "content://sms/inbox",
            "content://sms/sent",
            "content://sms/conversations",
            "content://mms-sms/",
            "SmsMessage.createFromPdu",
        ],
    },
    "camera": {
        "tags": ["CameraService", "CameraManager", "Camera2"],
        "subs": ["CameraDevice.StateCallback", "Camera.open("],
    },
    "microphone": {
        "tags": ["MediaRecorder", "AudioRecord"],
        "subs": ["AudioRecord(", "startRecording(", "setAudioSource"],
    },
    "contacts_read": {
        "tags": ["ContactsProvider2"],
        "subs": ["ContactsContract", "content://com.android.contacts"],
    },
    "clipboard": {
        "tags": ["ClipboardManager"],
        "subs": ["getPrimaryClip", "hasPrimaryClip"],
    },
    "pkg_enum": {
        "tags": ["PackageManager"],
        "subs": [
            "getInstalledPackages",
            "getInstalledApplications",
            "queryIntentActivities",
        ],
    },
    "accessibility": {
        "tags": ["AccessibilityService", "AccessibilityManager"],
        "subs": ["BIND_ACCESSIBILITY_SERVICE", "onAccessibilityEvent"],
    },
    "screen_capture": {
        "tags": ["MediaProjection"],
        "subs": ["MediaProjectionManager", "createVirtualDisplay"],
    },
    "account_mgr": {
        "tags": ["AccountManager"],
        "subs": ["getAccountsByType", "getAuthToken"],
    },
}


class PcapParser:
    """Parses a pcap file pulled off the device and returns network features."""

    # these are all the keys this class will out_dictput makes it easier to initialise the dict with zeros later
    KEYS = [
        "dyn_net_unique_ips",
        "dyn_net_unique_domains",
        "dyn_net_dns_queries",
        "dyn_net_tls_connections",
        "dyn_net_cleartext_http",
        "dyn_net_cleartext_http_count",
        "dyn_net_suspicious_ports",
        "dyn_net_bytes_sent",
        "dyn_net_dyndns_hit",
        "dyn_net_c2_hit",
    ]

    def __init__(self, path: Path):
        self.path = path

    def parse(self) -> dict:
        # start with everything zeroed out_dict so we always return a complete dict
        # even if something goes wrong
        out_dict = {}
        for k in self.KEYS:
            out_dict[k] = 0

        # If there is no pcap print an error
        if not self.path.exists():
            print(f"no pcap at {self.path}")
            return out_dict

        try:
            with open(self.path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
                # Walk through pcap file and modify the out_dictput dictionary
                self._walk(reader, out_dict)
        except Exception as e:
            print(f"pcap parse failed: {e}")

        return out_dict

    def _walk(self, pcap, out_dict: dict):
        # tracking these as we go through packets
        external_ips: set[str] = set()
        domains: set[str] = set()
        tls_flows: set[tuple] = set()
        http_n = 0
        sus_ports = 0
        bytes_sent = 0
        dyndns = False
        c2 = False

        # loop over each packet and timestamp in PCAP file
        for _, buf in pcap:
            # try to parse each packet from ethernet layer — skip anything that fails
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue

            # we only care about_dict IP packets so make sure ethernet data is an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            # Ignore since dpkt is old library without type stubs that specify attributes the class has
            src = ip.src  # type: ignore
            dst = ip.dst  # type: ignore

            # count bytes sent from private → public IPs (i.e., out_dictbound traffic)
            if _is_private(src) and not _is_private(dst):
                bytes_sent += len(ip.data)

            # track external destination IPs
            if not _is_private(dst):
                dst_str = socket.inet_ntoa(dst)
                external_ips.add(dst_str)

            # Grab the transport layer encapsulated in the IP packet
            transport = ip.data

            # handle DNS — port 53 UDP (Check if udp and port 53 - DNS requests)
            is_udp = isinstance(transport, dpkt.udp.UDP)
            if is_udp and (transport.dport == 53 or transport.sport == 53):  # type: ignore
                try:
                    # Try decode the transport layer payload into DNS
                    dns = dpkt.dns.DNS(transport.data)
                    # only count actual DNS queries, not responses
                    if dns.qr == dpkt.dns.DNS_Q:
                        out_dict["dyn_net_dns_queries"] += 1
                        for q in dns.qd:
                            # Get the hostname and the root domain
                            hostname = q.name.lower()
                            domains.add(hostname)
                            root = _root_domain(hostname)
                            # check against our bad domain lists
                            if root in DYNAMIC_DNS_DOMAINS:
                                dyndns = True
                            if root in KNOWN_C2_DOMAINS:
                                c2 = True
                except Exception:
                    # malformed dns packet or something, just skip it
                    pass

            # handle TCP — check for suspicious ports, TLS, and cleartext HTTP
            is_tcp = isinstance(transport, dpkt.tcp.TCP)
            if is_tcp:
                # Check if using a suspicious TCP port
                if transport.dport in SUSPICIOUS_PORTS:  # type: ignore
                    sus_ports += 1

                payload = transport.data

                # TLS client Hello packet starts with 0x16 (Handshake record type) 0x03 — not perfect but good enough
                if len(payload) >= 3 and payload[0] == 0x16 and payload[1] == 0x03:
                    # Uniquely identify flows using this fingerprint of source destination and destination port
                    flow_key = (
                        socket.inet_ntoa(src),
                        socket.inet_ntoa(dst),
                        transport.dport,  # type: ignore
                    )
                    # Add the unique flow key
                    tls_flows.add(flow_key)

                # rough HTTP detection on port 80
                # I'm just checking the first 8 bytes for common methods
                if transport.dport == 80 and len(payload) > 4:  # type: ignore
                    try:
                        head = payload[:8].decode("ascii", errors="ignore")
                        http_methods = ("GET ", "POST", "PUT ", "HEAD")
                        for method in http_methods:
                            if head.startswith(method):
                                http_n += 1
                                break
                    except Exception:
                        pass

        # write everything to output dictionary
        out_dict["dyn_net_unique_ips"] = len(external_ips)
        out_dict["dyn_net_unique_domains"] = len(domains)
        out_dict["dyn_net_tls_connections"] = len(tls_flows)
        out_dict["dyn_net_cleartext_http"] = int(http_n > 0)
        out_dict["dyn_net_cleartext_http_count"] = http_n
        out_dict["dyn_net_suspicious_ports"] = sus_ports
        out_dict["dyn_net_bytes_sent"] = bytes_sent
        out_dict["dyn_net_dyndns_hit"] = int(dyndns)
        out_dict["dyn_net_c2_hit"] = int(c2)
