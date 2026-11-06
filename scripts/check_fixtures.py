from pathlib import Path
import hashlib,json
from scapy.all import rdpcap,IP,IPv6,TCP,UDP,ICMP,Dot1Q
R=Path(__file__).resolve().parents[1]/'tests/fixtures/pcap'
e=json.loads((R/'expected.json').read_text())
for name,digest in e['sha256'].items():assert hashlib.sha256((R/name).read_bytes()).hexdigest()==digest,name
for name in ['mixed.pcap','mixed.pcapng']:
    packets=rdpcap(str(R/name))
    assert len(packets)==5
    assert sum(IP in p for p in packets)==4
    assert sum(IPv6 in p for p in packets)==1
    assert sum(TCP in p for p in packets)==2
    assert sum(UDP in p for p in packets)==2
    assert sum(ICMP in p for p in packets)==1
    assert sum(Dot1Q in p for p in packets)==1
    assert [p[IP].len for p in packets[:2]]==[40,40]
print('PCAP fixture counts and hashes verified')
