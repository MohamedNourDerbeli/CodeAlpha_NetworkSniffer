from scapy.all import get_if_addr, get_if_list

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
