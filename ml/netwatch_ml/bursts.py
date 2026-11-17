"""Five-second incoming packet rates within a minute for one destination."""

from dataclasses import dataclass, field


@dataclass
class BurstRates:
    # Allocate bins only for an active destination, not for an empty baseline.
    bins: dict = field(default_factory=dict)

    def add(self, second, protocol):
        counts = self.bins.setdefault(int(second) % 60 // 5, [0, 0, 0])
        counts[0] += 1
        if protocol == "UDP":
            counts[1] += 1
        elif protocol == "ICMP":
            counts[2] += 1

    def metrics(self):
        peak = udp = icmp = 0
        for total, n_udp, n_icmp in self.bins.values():
            peak = max(peak, total)
            if n_udp * 5 >= total * 4:
                udp = max(udp, n_udp)
            if n_icmp * 5 >= total * 4:
                icmp = max(icmp, n_icmp)
        return {
            "peak_pps_5s": peak / 5,
            "peak_udp_pps_5s": udp / 5,
            "peak_icmp_pps_5s": icmp / 5,
        }
