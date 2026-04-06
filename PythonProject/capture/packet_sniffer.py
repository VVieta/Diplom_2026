import time
import random
import datetime


def start_sniffing(interface, packet_callback):
    print("[SNIFFER] Packet simulation started")

    while True:
        packet = {
            "timestamp": datetime.datetime.now(),
            "src_ip": f"192.168.0.{random.randint(2, 50)}",
            "dst_ip": "192.168.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 21]),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "size": random.randint(64, 1500)
        }

        packet_callback(packet)
        time.sleep(random.uniform(0.01, 0.2))


# ______________ SCAPY _______________

# from scapy.all import sniff, IP, TCP, UDP, ICMP
# import datetime
#
# def start_sniffing(interface, packet_callback):
#     print("[SNIFFER] Scapy sniffing started")
#
#     def handle_packet(pkt):
#         if IP not in pkt:
#             return
#
#         packet = {
#             "timestamp": datetime.datetime.now(),
#             "src_ip": pkt[IP].src,
#             "dst_ip": pkt[IP].dst,
#             "src_port": pkt[TCP].sport if TCP in pkt else None,
#             "dst_port": pkt[TCP].dport if TCP in pkt else None,
#             "protocol": "TCP" if TCP in pkt else
#                         "UDP" if UDP in pkt else
#                         "ICMP" if ICMP in pkt else "OTHER",
#             "size": len(pkt)
#         }
#
#         packet_callback(packet)
#
#     sniff(iface=interface, prn=handle_packet, store=False)