"""Deterministic small captures for decoder tests; never a training dataset."""
from pathlib import Path
import hashlib,json,struct
from scapy.all import Ether,IP,IPv6,TCP,UDP,ICMP,Dot1Q,Raw,wrpcap
from scapy.utils import PcapNgWriter
R=Path(__file__).resolve().parents[1]/'tests/fixtures/pcap';R.mkdir(parents=True,exist_ok=True)
a=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')
frames=[a/IP(src='192.0.2.10',dst='198.51.100.20')/TCP(sport=50000,dport=443,flags='S'),
        a/IP(src='192.0.2.10',dst='198.51.100.20')/TCP(sport=50000,dport=443,flags='S'),
        a/IPv6(src='2001:db8::1',dst='2001:db8::2')/UDP(sport=50001,dport=53),
        a/IP(src='192.0.2.10',dst='198.51.100.20')/ICMP(),
        a/Dot1Q(vlan=7)/IP(src='192.0.2.11',dst='198.51.100.20')/UDP(sport=50002,dport=53)]
for i,p in enumerate(frames):p.time=1700000000+i
wrpcap(str(R/'mixed.pcap'),frames)
wrpcap(str(R/'syn-retry.pcap'),frames[:2])
with PcapNgWriter(str(R/'mixed.pcapng')) as out:
    for p in frames:out.write(p)
# Truncated IPv4 capture: wire length exceeds captured record bytes.
raw=bytes(frames[0]); header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
(R/'truncated.pcap').write_bytes(header+struct.pack('<IIII',1700000000,0,30,len(raw))+raw[:30])
(R/'malformed.pcap').write_bytes(b'not a pcap file')
fragment=a/IP(src='192.0.2.10',dst='198.51.100.20',flags='MF')/UDP(sport=1,dport=2)/Raw(b'12345678')
fragment.time=1700000000
wrpcap(str(R/'fragment.pcap'),[fragment])
(R/'unsupported-linktype.pcap').write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,65000))
expected={'purpose':'decoder fixtures, not training data','mixed':{'record_count':5,'ipv4':4,'ipv6':1,'tcp':2,'udp':2,'icmp':1,'vlan':1,'first_two_tcp_ip_lengths':[40,40],'first_two_tcp_unique_flows':1,'first_two_tcp_new_attempts':1,'timestamps_seconds':[1700000000+i for i in range(5)]},'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(R.glob('*.pcap*'))}}
(R/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
print(R)
