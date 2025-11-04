from scapy.layers.l2 import Ether
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP

packets = []
for i in range(10):
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
    )
    packets.append(pkt)

wrpcap("tests/fixtures/tcp_sample.pcap", packets)
