from scapy.all import Ether, IP, TCP, wrpcap

packets = []
for i in range(10):
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
    )
    packets.append(pkt)

wrpcap("tests/fixtures/sample.pcap", packets)
