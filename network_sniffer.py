from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_addr, get_if_list
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

def select_interface():
    """
    Return the first active network interface with a valid IP
    (excluding 0.0.0.0, 169.254.x.x, 127.0.0.1).
    """
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("0.") and not ip.startswith("169.254") and not ip.startswith("127."):
                print(f"Using active interface: {Fore.CYAN}{iface}{Style.RESET_ALL} | IP: {Fore.CYAN}{ip}{Style.RESET_ALL}")
                return iface, ip  # Return both interface name and IP
        except:
            continue
    print("No active interface found. Using default.")
    return None, None

def process_packet(packet, local_ip):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_name = proto_map.get(ip_layer.proto, str(ip_layer.proto))

        # Color based on direction
        color = Fore.GREEN if dst == local_ip else Fore.BLUE

        print(f"{color}[IP] {src} → {dst} | Protocol: {proto_name}{Style.RESET_ALL}")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"{Fore.YELLOW}  └── [TCP] Port: {tcp.sport} → {tcp.dport}{Style.RESET_ALL}")
        elif UDP in packet:
            udp = packet[UDP]
            print(f"{Fore.YELLOW}  └── [UDP] Port: {udp.sport} → {udp.dport}{Style.RESET_ALL}")
        elif ICMP in packet:
            print(f"{Fore.YELLOW}  └── [ICMP] Type: {packet[ICMP].type}{Style.RESET_ALL}")

def start_sniffing(interface=None, local_ip=None, packet_count=0):
    print(f"\n[+] Starting packet sniffing on interface: {interface or 'default'}...\n")
    sniff(iface=interface, prn=lambda pkt: process_packet(pkt, local_ip), count=packet_count, store=False)

if __name__ == "__main__":
    print("Python Network Sniffer (Scapy)")
    iface, local_ip = select_interface()
    
    count_input = input("How many packets to capture? (0 for infinite): ").strip()
    try:
        count = int(count_input) if count_input else 0
    except ValueError:
        count = 0

    start_sniffing(interface=iface, local_ip=local_ip, packet_count=count)