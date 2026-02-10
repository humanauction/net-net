from scapy.layers.l2 import Ether
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
import time

packets = []
base_time = int(time.time())
for i in range(100):
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
    )
    pkt.time = base_time + i  # Increment timestamp for each packet
    packets.append(pkt)

wrpcap("tests/fixtures/sample.pcap", packets)
