from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, get_if_addr, get_if_list, wrpcap, Raw
from colorama import init, Fore, Style
from datetime import datetime
import argparse
import sys

# Initialize colorama
init(autoreset=True)

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

# Suspicious Ports (Backdoors, malware, plain text)
SUSPICIOUS_PORTS = {4444, 23, 21, 3389, 5900, 1337, 666}

# Global Packet Counters
PACKET_COUNTS = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0, "Suspicious": 0}

def get_args():
    """
    Parse command line arguments.
    """
    banner = rf"""{Fore.CYAN}
   _   _      _                      _      Sniffer 
  | \ | | ___| |___      _____  _ __| | __  Tool
  |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /  
  | |\  |  __/ |_ \ V  V / (_) | |  |   <   v1.0
  |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ 
    {Style.RESET_ALL}"""
    
    parser = argparse.ArgumentParser(
        description=f"{banner}\nAdvanced Network Sniffer Tool - Capture and Analyze Traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python network_sniffer.py -i eth0
  python network_sniffer.py -f "tcp port 80" -c 100
  python network_sniffer.py -o capture.pcap
        """
    )
    parser.add_argument("-i", "--interface", type=str, help="Interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF Filter (e.g., 'tcp port 80')")
    parser.add_argument("-o", "--output", type=str, help="Output PCAP file to save packets (e.g., capture.pcap)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed packet info")
    
    # If no arguments are provided, we can choose to show help or let it run default.
    # For now, let's return the args as is, but we removed the conflicting -h argument.
    
    return parser.parse_args()


def select_interface():
    """
    Return the first active network interface with a valid IP
    (excluding 0.0.0.0, 169.254.x.x, 127.0.0.1).
    """
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith(("0.", "169.254", "127.")):
                return iface, ip
        except Exception:
            continue
    return None, None


def handle_tcp(packet):
    tcp = packet[TCP]
    
    info = f"Flags: {tcp.flags}"
    
    # HTTP Detection (Basic)
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if "HTTP" in payload or "GET " in payload or "POST " in payload:
                # Extract first line of HTTP request/response
                http_line = payload.split('\n')[0].strip()
                info = f"{Fore.MAGENTA}HTTP: {http_line}{Style.RESET_ALL} | {info}"
        except:
            pass
            
    return info


def handle_udp(packet):
    udp = packet[UDP]

    service = UDP_SERVICES.get(udp.dport) or UDP_SERVICES.get(udp.sport) or "UDP"
    length = udp.len if udp.len else len(packet)

    # DNS detection
    if packet.haslayer(DNS):
        if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            return f"{Fore.CYAN}DNS Query: {query}{Style.RESET_ALL}"
        elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1: # Response
             resp_ip = "N/A"
             if packet[DNS].ancount > 0:
                 # Try to extract the first A record (IP) if available
                 for i in range(packet[DNS].ancount):
                     rr = packet[DNS].an[i]
                     if rr.type == 1: # A record
                        resp_ip = rr.rdata
                        break
             return f"{Fore.CYAN}DNS Response: {resp_ip}{Style.RESET_ALL}"

    return f"{service} | Len: {length}"


def process_packet(packet, local_ip, verbose=False, output_file=None):
    if IP not in packet:
        return

    # If output file is specified, append packet to pcap
    if output_file:
        wrpcap(output_file, packet, append=True)

    ip_layer = packet[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    
    # Determine protocol name
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    proto_name = proto_map.get(ip_layer.proto, str(ip_layer.proto))
    
    # Update Stats
    PACKET_COUNTS["Total"] += 1
    if proto_name in PACKET_COUNTS:
        PACKET_COUNTS[proto_name] += 1
    
    # Get Ports if applicable
    src_port, dst_port = 0, 0
    payload_info = ""
    icon = PROTO_ICONS.get(proto_name, "📡")

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload_info = handle_tcp(packet)
        if src_port == 80 or dst_port == 80: icon = PROTO_ICONS["HTTP"]
        if src_port == 443 or dst_port == 443: icon = PROTO_ICONS["HTTPS"]
        if src_port == 22 or dst_port == 22: icon = PROTO_ICONS["SSH"]
        if src_port == 21 or dst_port == 21: icon = PROTO_ICONS["FTP"]
        if src_port == 23 or dst_port == 23: icon = PROTO_ICONS["Telnet"]
        if src_port == 25 or dst_port == 25: icon = PROTO_ICONS["SMTP"]

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        payload_info = handle_udp(packet)
        if src_port == 53 or dst_port == 53: icon = PROTO_ICONS["DNS"]
        if src_port == 67 or dst_port == 67: icon = PROTO_ICONS["DHCP"]
        if src_port == 123 or dst_port == 123: icon = PROTO_ICONS["NTP"]
    
    elif ICMP in packet:
        icon = PROTO_ICONS["ICMP"]
        payload_info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"

    # Suspicious Port Check
    is_suspicious = False
    if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
        is_suspicious = True
        PACKET_COUNTS["Suspicious"] += 1
        payload_info = f"{Fore.RED}[!] SUSPICIOUS TRAFFIC{Style.RESET_ALL} | {payload_info}"

    # Timestamp & Length
    timestamp = datetime.now().strftime("%H:%M:%S")
    pkt_len = len(packet)

    # Color logic & Direction
    if dst == local_ip:
        direction = f"{Fore.GREEN}IN  {Style.RESET_ALL}"
        color = Fore.GREEN
    else:
        direction = f"{Fore.BLUE}OUT {Style.RESET_ALL}"
        color = Fore.BLUE
    
    if is_suspicious:
        color = Fore.RED

    # Construct Addresses
    src_addr = f"{src}:{src_port}" if src_port else src
    dst_addr = f"{dst}:{dst_port}" if dst_port else dst
    
    # Print Main Packet Info (Aligned)
    # {Timestamp} {Proto} {Dir} {Src} -> {Dst} | {Len} | {Payload}
    print(
        f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} "
        f"{color}{proto_name:<4}{Style.RESET_ALL} "
        f"{direction} "
        f"{icon}  "
        f"{Fore.CYAN}{src_addr:>21}{Style.RESET_ALL} "
        f"{Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} "
        f"{Fore.GREEN}{dst_addr:<21}{Style.RESET_ALL} "
        f"{Fore.WHITE}| {pkt_len:<4} | {payload_info}{Style.RESET_ALL}"
    )
    
    if verbose:
        print(f"{Fore.LIGHTBLACK_EX}      [VERBOSE] TTL: {ip_layer.ttl} | Len: {ip_layer.len} | ID: {ip_layer.id}{Style.RESET_ALL}")
    
    # Separate packets visually
    # print("-" * 50)


def start_sniffing():
    args = get_args()
    
    # Determine Interface
    if args.interface:
        interface = args.interface
        local_ip = get_if_addr(interface)
    else:
        interface, local_ip = select_interface()
        if not interface:
            print(f"{Fore.RED}[!] No active interface found. Exiting.{Style.RESET_ALL}")
            return
            
    print(f"{Fore.YELLOW}" + "="*60)
    print(f" NETWORK SNIFFER STARTED")
    print(f" Interface  : {Fore.CYAN}{interface} ({local_ip}){Fore.YELLOW}")
    print(f" Filter     : {Fore.CYAN}{args.filter or 'None'}{Fore.YELLOW}")
    print(f" Sub-Log    : {Fore.CYAN}{args.output or 'None'}{Fore.YELLOW}")
    print("="*60 + f"{Style.RESET_ALL}")

    try:
        sniff(
            iface=interface,
            prn=lambda pkt: process_packet(pkt, local_ip, args.verbose, args.output),
            filter=args.filter,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Stopping sniffer...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.YELLOW}" + "="*60)
        print(f" CAPTURE SUMMARY")
        print("="*60 + f"{Style.RESET_ALL}")
        print(f" Total Packets : {PACKET_COUNTS['Total']}")
        print(f" TCP Packets   : {PACKET_COUNTS['TCP']}")
        print(f" UDP Packets   : {PACKET_COUNTS['UDP']}")
        print(f" ICMP Packets  : {PACKET_COUNTS['ICMP']}")
        print(f" Suspicious    : {Fore.RED}{PACKET_COUNTS['Suspicious']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}" + "="*60 + f"{Style.RESET_ALL}")

if __name__ == "__main__":
    start_sniffing()