# Known UDP services
UDP_SERVICES = {
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    161: "SNMP",
    1900: "SSDP",
    5353: "mDNS",
    443: "QUIC"
}

# Protocol Icons
PROTO_ICONS = {
    "HTTP": "🌐",
    "HTTPS": "🔒",
    "DNS": "🔍",
    "DHCP": "⚙️",
    "NTP": "🕒",
    "SNMP": "📊",
    "SSH": "🔑",
    "FTP": "📂",
    "Telnet": "🖥️",
    "SMTP": "📧",
    "ICMP": "📡",
    "TCP": "🔗",
    "UDP": "📨",
    "ARP": "🙋",
}

# ICMP Types
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp",
    14: "Timestamp Reply",
}

# Suspicious Ports (Backdoors, malware, plain text)
SUSPICIOUS_PORTS = {4444, 23, 21, 3389, 5900, 1337, 666}

# Global Packet Counters (Initial State)
PACKET_COUNTS = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0, "Suspicious": 0}
