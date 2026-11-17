"""TCP handshakes initiated towards one target during one observed minute."""

from dataclasses import dataclass, field


@dataclass
class Handshakes:
    attempts: set = field(default_factory=set)
    replies: dict = field(default_factory=dict)
    completed: set = field(default_factory=set)
    observable: bool = True

    def observe(self, inbound, peer, peer_port, local_port, flags, seq, ack):
        if None in (peer_port, local_port, flags, seq, ack):
            self.observable = False
            return
        flow = (peer, peer_port, local_port)
        if inbound and flags & 0x16 == 2:
            self.attempts.add((flow, seq))
        elif not inbound and flags & 0x16 == 0x12:
            attempt = (flow, (ack - 1) % 2**32)
            if attempt in self.attempts:
                self.replies[flow, (seq + 1) % 2**32] = attempt
        elif inbound and flags & 0x16 == 0x10:
            attempt = self.replies.get((flow, ack))
            if attempt is not None and seq == (attempt[1] + 1) % 2**32:
                self.completed.add(attempt)

    def metrics(self):
        if not self.observable:
            return {}
        result = {"syn_per_second": len(self.attempts) / 60}
        if self.attempts:
            result["handshake_fraction"] = len(self.completed) / len(self.attempts)
        return result
