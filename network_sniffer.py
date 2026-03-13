from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_addr, get_if_list

def select_interface():
    """
    Return the first active network interface with a valid IP
    (excluding 0.0.0.0, 169.254.x.x, 127.0.0.1).
    """
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and not ip.startswith("0.") and not ip.startswith("169.254") and not ip.startswith("127."):
                print(f"Using active interface: {iface} | IP: {ip}")
                return iface
        except:
            continue
    print("No active interface found. Using default.")
    return None

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("ip_layer:", ip_layer.show(dump=True))  # Debug: Show IP layer details
        src = ip_layer.src
        dst = ip_layer.dst
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_name = proto_map.get(ip_layer.proto, str(ip_layer.proto))


        print(f"[IP] {src} → {dst} | Protocol: {proto_name}")

        if TCP in packet:
            tcp = packet[TCP]
            print(f"  └── [TCP] Port: {tcp.sport} → {tcp.dport}")
        elif UDP in packet:
            udp = packet[UDP]
            print(f"  └── [UDP] Port: {udp.sport} → {udp.dport}")
        elif ICMP in packet:
            print(f"  └── [ICMP] Type: {packet[ICMP].type}")

def start_sniffing(interface=None, packet_count=0):
    print(f"\n[+] Starting packet sniffing on interface: {interface or 'default'}...\n")
    sniff(iface=interface, prn=process_packet, count=packet_count, store=False)

if __name__ == "__main__":
    print("Python Network Sniffer (Scapy)")
    iface = select_interface()
    count_input = input("How many packets to capture? (0 for infinite): ").strip()

    try:
        count = int(count_input) if count_input else 0
    except ValueError:
        count = 0

    start_sniffing(interface=iface if iface else None, packet_count=count)
