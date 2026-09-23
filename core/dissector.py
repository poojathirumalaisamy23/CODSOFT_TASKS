"""Protocol dissector — turns Scapy packets into plain dicts."""
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from typing import Optional


def dissect(packet) -> Optional[dict]:
    """Extract key fields from a Scapy packet. Returns None if unparseable."""
    result = {
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "dns_query": None,
        "payload_len": 0,
        "raw": packet,
    }

    # Layer 2
    if packet.haslayer(Ether):
        result["src_mac"] = packet[Ether].src
        result["dst_mac"] = packet[Ether].dst

    # ARP
    if packet.haslayer(ARP):
        result["protocol"] = "ARP"
        result["src_ip"] = packet[ARP].psrc
        result["dst_ip"] = packet[ARP].pdst
        return result

    # IP
    if packet.haslayer(IP):
        result["src_ip"] = packet[IP].src
        result["dst_ip"] = packet[IP].dst

        if packet.haslayer(TCP):
            result["protocol"] = "TCP"
            result["src_port"] = packet[TCP].sport
            result["dst_port"] = packet[TCP].dport
            result["tcp_flags"] = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            result["protocol"] = "UDP"
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport

            if packet.haslayer(DNS):
                result["protocol"] = "DNS"
                dns = packet[DNS]
                if dns.qd is not None:
                    try:
                        result["dns_query"] = dns.qd.qname.decode(errors="ignore")
                    except Exception:
                        pass

        elif packet.haslayer(ICMP):
            result["protocol"] = "ICMP"

        else:
            result["protocol"] = "IP"

    if packet.payload:
        result["payload_len"] = len(bytes(packet.payload))

    return result if result["protocol"] else None