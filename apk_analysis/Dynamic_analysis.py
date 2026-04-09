# Before you run this, push tcpdump to the emulator first:
#   adb push tcpdump /data/local/tmp/tcpdump
#   adb shell chmod +x /data/local/tmp/tcpdump


import urllib.request
import ipaddress
from pathlib import Path
import re
import dpkt
import socket
import time
import subprocess
from typing import Optional


def load_domain_set(url: str) -> set[str]:
    # open the url and read the bytes, decode them and then split the strings on the new lines
    with urllib.request.urlopen(url, timeout=10) as r:
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


### Helper functions


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

    # these are all the keys this class will out_dictput makes it easier to initialise the dict with zeros later. We share this attribute across all instances since it is a class attribute
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


def _adb(cmd: list, timeout=10) -> str:
    """Runs an adb command and returns stdout as a string. Returns empty string if it fails."""
    try:
        full_cmd = ["adb"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        # Returns the output from the command
        return result.stdout

    except Exception:
        # idk if swallowing all exceptions here is best practice but return empty string back
        return ""


def _get_pid(pkg: str) -> Optional[str]:
    # pidof can return multiple pids if theres multiple processes for the same package, returns the pid table
    raw_output = _adb(["shell", "pidof", pkg], timeout=5)

    stripped = raw_output.strip()
    parts = stripped.split()

    # split the processes into parts, the first pid is the main process
    if parts and parts[0].isdigit():
        return parts[0]
    return None


def _snapshot_open_files(pid: str) -> set[str]:
    """Reads /proc/<pid>/fd to see what files the process currently has open.
    This works without root on the Android Virtual Device which is handy."""
    # Dynamically scan memory for files currently open
    raw = _adb(["shell", f"ls -la /proc/{pid}/fd 2>/dev/null"], timeout=10)
    paths = set()
    for line in raw.splitlines():
        # each line looks like: "lrwxrwxrwx ... /proc/123/fd/4 -> /some/file"
        if " -> " in line:
            parts = line.split(" -> ", 1)
            # Split by the arrow and take what came after the arrow
            target = parts[1].strip()
            paths.add(target)
    return paths


def _categorise_paths(open_paths: set[str]) -> dict[str, int]:
    """Takes a set of file paths and figures out which sensitive categories were accessed."""
    result = {}
    triggered_count = 0

    for category_name, prefix_list in SENSITIVE_FS.items():
        # check if any of the open paths start with any of the sensitive prefixes
        hit = False
        for open_path in open_paths:
            for prefix in prefix_list:
                # For each path we found accessed by app, for each prefix that is sensitive, we see if the path starts with the prefix
                if open_path.startswith(prefix):
                    hit = True
                    break
            if hit:
                # Break out since a path can't be in multiple categories
                break

        # Save the key and if it was a hit
        key = f"dyn_fs_{category_name}"
        result[key] = int(hit)

        if hit:
            triggered_count += 1

    # Also get the number of sensitive categories hit by unique API calls and save this as a feature
    result["dyn_fs_sensitive_category_count"] = triggered_count
    return result


class FilesystemAnalyser:
    """
    Takes snapshots of /proc/<pid>/fd at three points during the run:
    - pre: right after launch before any monkey events
    - during: while monkey is interacting with the app
    - post: idle period after monkey stops

    A legit parental control app should only touch contacts/location
    when the user is actively using it, a stalkerware app will do it
    in the background. We look for any feature and feed it to ML models to find correlations across APKs
    """

    # all the feature column names this class produces
    KEYS = (
        [f"dyn_fs_{c}" for c in SENSITIVE_FS]
        + ["dyn_fs_sensitive_category_count"]
        + [
            "dyn_fs_preinteraction_access",
            "dyn_fs_background_access",
            "dyn_fs_silent_harvest",  # silent = pre or post access but NOT during interaction
        ]
    )

    def analyse_phased(self, pkg: str, monkey_fn, idle_secs=12) -> dict:
        """
        Does the three-phase filesystem snapshot. monkey_fn is a callable that triggers the monkey tool so we can take snapshots before and after it runs.
        """
        # Intialise the output dictionary
        out_dict = {}
        for k in self.KEYS:
            out_dict[k] = 0

        # get the process ID of the application
        pid = _get_pid(pkg)
        if not pid:
            print(f"[fs] cant find pid for {pkg}")
            return out_dict

        # Pre-snapshot before any user interaction
        pre_paths = _snapshot_open_files(pid)
        pre_cats = _categorise_paths(pre_paths)

        # run monkey to simulate user interaction, then snapshot mid-way through
        monkey_fn()

        # pid might change if the app crashed and restarted during monkey
        new_pid = _get_pid(pkg)
        if new_pid:
            pid = new_pid
        # else keep the old pid and hope for the best

        # During snapshot, during interaction
        during_paths = _snapshot_open_files(pid)
        during_cats = _categorise_paths(during_paths)

        # Post-snapshot wait a bit and snapshot again. Background harvest shows up here
        time.sleep(idle_secs)

        # Again update if crashed
        new_pid = _get_pid(pkg)
        if new_pid:
            pid = new_pid

        post_paths = _snapshot_open_files(pid)
        post_cats = _categorise_paths(post_paths)

        # for the base category flags we combine all three phases
        all_paths = pre_paths.union(during_paths, post_paths)
        # Then categorise the paths to find which sensitive categories they used
        combined_cats = _categorise_paths(all_paths)
        out_dict.update(combined_cats)

        # was anything sensitive open before the user touched the app?
        pre_triggered = pre_cats["dyn_fs_sensitive_category_count"] > 0

        # which categories were open in post but NOT during interaction?
        # this is the "silent harvest" signal
        background_only = set()
        for cat in SENSITIVE_FS:
            key = f"dyn_fs_{cat}"
            post_hit = post_cats.get(key, 0)
            during_hit = during_cats.get(key, 0)
            if post_hit and not during_hit:
                # Find categories that were accessed not during use but outside of use
                background_only.add(cat)

        if len(background_only) > 0:
            background_detected = True
        else:
            background_detected = False

        out_dict["dyn_fs_preinteraction_access"] = int(pre_triggered)
        out_dict["dyn_fs_background_access"] = int(background_detected)
        # silent harvest = sensitive access without user interaction causing it
        out_dict["dyn_fs_silent_harvest"] = int(pre_triggered or background_detected)

        return out_dict


class LogcatAPIAnalyser:
    """Looks through logcat output for sensitive API usage after monkey runs."""

    # Creates a list of keys for each logcat API (defined above)
    KEYS = [f"dyn_api_{k}" for k in LOGCAT_APIS] + ["dyn_api_category_count"]

    def analyse(self, pkg: str) -> dict:
        output = {}

        # Zero out each category
        for k in self.KEYS:
            output[k] = 0

        # Dumps the current system logs from device
        raw = _adb(["logcat", "-d"], timeout=15)
        if not raw:
            return output

        all_lines = raw.splitlines()

        # filter to lines mentioning our package, this cuts down on noise a lot
        pkg_lines = []
        for line in all_lines:
            if pkg in line:
                pkg_lines.append(line)

        api_hit_count = 0

        for api_name, signals in LOGCAT_APIS.items():
            hit = False

            # first try tag matching, looks for tag in the logs
            tag_list = signals.get("tags", [])
            for tag in tag_list:
                pattern = rf"\b{re.escape(tag)}\b"
                # Search all lines because the service is a system service (not a method) - global identifier
                for line in all_lines:
                    if re.search(pattern, line):
                        hit = True
                        break
                if hit:
                    break

            # fallback to matching on substring in the logs, we use the pkg_lines to make sure the method belongs to the app
            if not hit:
                sub_list = signals.get("subs", [])
                for sub in sub_list:
                    for line in pkg_lines:
                        if sub in line:
                            hit = True
                            break
                    if hit:
                        break

            if hit:
                # Record which API was found and increase the count of API hits
                output[f"dyn_api_{api_name}"] = 1
                api_hit_count += 1

        output["dyn_api_category_count"] = api_hit_count
        print(f"[api] {api_hit_count} API categories triggered for {pkg}")
        return output
