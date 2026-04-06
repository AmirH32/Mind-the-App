# Before you run this, push tcpdump to the emulator first:
#   adb push tcpdump /data/local/tmp/tcpdump
#   adb shell chmod +x /data/local/tmp/tcpdump


import urllib.request
import ipaddress


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


# these are the filesystem paths we care about and want to see if they are aeccessed, grouped by category. I checked these against a few real devices to make sure they were right
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

# logcat signals to look for — using tag+substring pairs for each sensitive API tags are better than substrings when possible because raw substring matching on logcat output produces a lot of noise
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
