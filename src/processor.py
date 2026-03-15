from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap, Raw
from colorama import Fore, Style
from datetime import datetime
from src.config import UDP_SERVICES, PROTO_ICONS, SUSPICIOUS_PORTS, PACKET_COUNTS, ICMP_TYPES

def handle_icmp(packet):
    """
    Handle ICMP packets to identify message types.
    """
    icmp = packet[ICMP]
    type_name = ICMP_TYPES.get(icmp.type, f"Type: {icmp.type}")
    
    # Add more context for specific types
    if icmp.type == 3: # Destination Unreachable
        return f"{Fore.RED}{type_name} (Code: {icmp.code}){Style.RESET_ALL}"
    elif icmp.type == 8: # Echo Request
        return f"{Fore.CYAN}{type_name}{Style.RESET_ALL}"
    elif icmp.type == 0: # Echo Reply
        return f"{Fore.GREEN}{type_name}{Style.RESET_ALL}"
        
    return f"{type_name} (Code: {icmp.code})"

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
        payload_info = handle_icmp(packet)

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
