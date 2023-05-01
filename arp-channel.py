#!/usr/bin/env python3

from scapy.all import ARP, Ether, Padding, TCP, UDP, sendp, raw
import sys

hwsrc='9c:b6:d0:dc:26:5f'
hwdst='00:00:00:00:00:00'
broadcast='ff:ff:ff:ff:ff:ff'

# create an ARP packet
arp = ARP(
    op=1, 
    pdst='10.87.3.27',
    hwdst=hwdst,
    psrc='10.87.3.19',
    hwsrc=hwsrc,
)

# create an Ethernet frame containing the ARP packet
# ether = Ether(
#    src=hwsrc,
#    dst=broadcast,
#    type=0x0806,
#)


# create an Ethernet frame with custom type field
# ether = Ether(dst='00:11:22:33:44:55', src='11:22:33:44:55:66', type=0x0800)


# pkt = Ether()/ARP()
#pkt[Ether].type = 0x0806
#pkt[Ether].src = hwsrc
#pkt[Ether].dst = broadcast

# pkt = Ether(raw(pkt))

#pkt[ARP] = arp

raw_e = b"\x5c\x5f\x67\x4a\xe9\x17\x9c\xb6\xd0\xdc\x26\x5f\x08\x06"
raw_a = b"\x00\x01\x08\x00\x06\x04\x00\x01\x9c\xb6\xd0\xdc\x26\x5f\x0a\x57\x03\x13\x00\x00\x00\x00\x00\x00\x0a\x57\x03\x1b"

# packet = packet/padding

# tcp = TCP(sport=src_port, dport=dst_port)
pkt = Ether(raw_e)/ARP(raw_a)/UDP(
    sport=1234,
    dport=80,
)

# Total limit: 1314 bytes with an ARP message

# padding = Padding(load=b'\xfe' * 1272)

# s = "Sup ARP nerds?"

s = sys.stdin.readline()
padding = Padding(load=bytes(s.encode("ascii")) + bytes(b"\0\0\0\0"))
pkt = pkt/padding

print("=" * 32)
print(str(raw(pkt)))
print("=" * 32)

# send the packet
sendp(pkt)