"""Check the registered Somfy flow labels against directional packets and timestamps."""
from collections import Counter, defaultdict
from decimal import Decimal
import json

from scapy.all import IP, IPv6, TCP, UDP, PcapReader

from netwatch_ml.contracts import ROOT
from netwatch_ml.data.dataset import digest


def main():
    manifest = json.loads((ROOT / 'data/manifests/iot23-somfy-01.json').read_text())
    directory = ROOT / 'data/raw/iot23'
    capture = directory / manifest['file_name']
    labels = directory / manifest['labels']['file_name']
    if digest(capture) != manifest['sha256'] or digest(labels) != manifest['labels']['sha256']:
        raise ValueError('registered input checksum mismatch')
    times = defaultdict(list)
    with PcapReader(str(capture)) as reader:
        for packet in reader:
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None:
                continue
            for proto, cls in [('tcp', TCP), ('udp', UDP)]:
                if cls in packet:
                    transport = packet[cls]
                    key = (ip.src, str(transport.sport), ip.dst, str(transport.dport), proto)
                    times[key].append(Decimal(str(packet.time)))
    by_protocol, by_label, matched = Counter(), Counter(), Counter()
    for line in labels.read_text().splitlines():
        if line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) != 23:
            raise ValueError('unexpected Somfy Zeek record layout')
        proto = fields[6]
        by_protocol[proto] += 1
        by_label[fields[-2]] += 1
        if proto in ('tcp', 'udp'):
            start = Decimal(fields[0])
            if any(abs(t - start) <= Decimal('.001') for t in times[tuple(fields[2:7])]):
                matched[proto] += 1
    audit = dict(records=by_label.total(), labels=dict(by_label), protocols=dict(by_protocol),
                 matched_directional_start_within_1ms=dict(matched))
    if audit != manifest['labels']['audit']:
        raise ValueError(f'flow-label audit differs: {audit}')
    print(json.dumps(audit, indent=2))


if __name__ == '__main__':
    main()
