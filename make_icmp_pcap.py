from scapy.layers.l2 import Ether
from scapy.all import wrpcap
from scapy.layers.inet import IP, ICMP
import time

packets = []
base_time = int(time.time())
for i in range(128):
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    pkt.time = base_time + i  # Each packet gets a unique timestamp
    packets.append(pkt)

wrpcap("tests/fixtures/icmp_sample.pcap", packets)
