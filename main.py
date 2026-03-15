import argparse
import sys
from scapy.all import sniff, get_if_addr
from colorama import init, Fore, Style
from src.utils import select_interface
from src.processor import process_packet 
from src.config import PACKET_COUNTS

# Initialize colorama
init(autoreset=True)

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
  python main.py -i eth0
  python main.py -f "tcp port 80" -c 100
  python main.py -o capture.pcap
        """
    )
    parser.add_argument("-i", "--interface", type=str, help="Interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", type=str, default="", help="BPF Filter (e.g., 'tcp port 80')")
    parser.add_argument("-o", "--output", type=str, help="Output PCAP file to save packets (e.g., capture.pcap)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed packet info")
    
    return parser.parse_args()

def start_sniffing():
    args = get_args()
    
    # Determine Interface
    if args.interface:
        interface = args.interface
        try:
            local_ip = get_if_addr(interface)
        except:
             local_ip = None
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
