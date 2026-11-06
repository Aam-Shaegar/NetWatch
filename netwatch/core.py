from collections import defaultdict
from dataclasses import dataclass
from ipaddress import ip_address
import math
from statistics import mean, pstdev


@dataclass(frozen=True)
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int

    def __post_init__(self):
        if not math.isfinite(self.timestamp) or self.timestamp < 0:
            raise ValueError('timestamp должен быть конечным и неотрицательным')
        ip_address(self.src_ip)
        ip_address(self.dst_ip)
        if not 0 <= self.src_port <= 65535 or not 0 <= self.dst_port <= 65535:
            raise ValueError('Порт вне диапазона 0..65535')
        if self.size < 0 or self.protocol not in {'TCP', 'UDP', 'ICMP', 'OTHER'}:
            raise ValueError('Некорректный размер или протокол')


def aggregate(packets, window_seconds=5.0):
    """Активные окна [start, end), отдельно по IP источника.

    flow_count = уникальные направленные 5-tuples в окне, НЕ число новых
    TCP-соединений. Пустые окна не создаются. Размер — байты записи источника.
    Сортировка поддерживает неупорядоченный CSV; весь ввод хранится в памяти.
    """
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError('Размер окна должен быть положительным конечным числом')
    groups = defaultdict(list)
    for p in packets:
        groups[(math.floor(p.timestamp / window_seconds), p.src_ip)].append(p)
    result = []
    for (index, host), events in sorted(groups.items()):
        timestamps = sorted(p.timestamp for p in events)
        gaps = [b-a for a,b in zip(timestamps, timestamps[1:])]
        flows = {(p.src_ip,p.dst_ip,p.src_port,p.dst_port,p.protocol) for p in events}
        total = sum(p.size for p in events)
        result.append(dict(window_start=index*window_seconds, src_ip=host,
            packet_count=len(events), byte_count=total,
            packets_per_second=len(events)/window_seconds,
            bytes_per_second=total/window_seconds,
            unique_destinations=len({p.dst_ip for p in events}),
            unique_destination_ports=len({p.dst_port for p in events}),
            flow_count=len(flows), flows_per_second=len(flows)/window_seconds,
            mean_packet_size=total/len(events),
            mean_interarrival=mean(gaps) if gaps else 0.0,
            std_interarrival=pstdev(gaps) if gaps else 0.0,
            tcp_fraction=sum(p.protocol=='TCP' for p in events)/len(events)))
    return result


def flag_windows(windows, max_ports=20, max_packet_rate=1000):
    """Объяснимый фиксированный baseline; пороги пока демонстрационные."""
    if max_ports < 0 or not math.isfinite(max_packet_rate) or max_packet_rate < 0:
        raise ValueError('Пороги должны быть конечными и неотрицательными')
    for window in windows:
        reasons=[]
        if window['unique_destination_ports'] > max_ports:
            reasons.append('many_destination_ports')
        if window['packets_per_second'] > max_packet_rate:
            reasons.append('high_packet_rate')
        yield dict(window, is_anomaly=bool(reasons), reasons=reasons)
