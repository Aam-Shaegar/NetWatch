# NetWatch v1 detection catalog

A v1 sensor publishes `traffic-v3` windows for a protected host. The Go
decoder and window engine supply the same features for live capture and replay.
Protocol packet and byte counts use inbound packets and IP bytes. The TCP
port count is the largest per-source set of distinct destination ports observed
on opening TCP attempts to that host. A null count denotes unavailable
measurement, including bounded-state overflow.

The worker persists one decision for each observation. Only a rule miss can
reach ML Stage 1. An anomalous Stage 1 result goes to Stage 2, which can return
one of the catalog types or `unknown`. ML outages keep the job retryable. An
incomplete capture, unknown or nonzero packet loss, late packets, and evicted
state result in `insufficient_data`.

## Initial rules

| ID | Version | Condition |
| --- | --- | --- |
| `tcp_port_scan` | 1 | A source opens attempts to at least 16 distinct TCP destination ports on the protected host in a window. |
| `udp_flood` | 1 | At least 100 inbound UDP packets/s, UDP is at least 70% of inbound packets, and the rate exceeds the host's UDP baseline. |
| `icmp_flood` | 1 | At least 100 inbound ICMP packets/s, ICMP is at least 70% of inbound packets, and the rate exceeds the host's ICMP baseline. |

The flood baseline uses at least five eligible, preceding observations in
the same sensor, capture epoch and host over the last five minutes. The
boundary is the median rate plus the larger of that rate and six median
absolute deviations. If two rules match, the protocol-specific flood takes
precedence over the port scan. These initial thresholds are hypotheses.
Validate them on ordinary activity and labeled episodes before establishing
release thresholds. Disable individual rules with the comma-separated
`NETWATCH_DISABLED_RULES` variable. Use the same setting for offline
evaluation and change the policy version when changing the deployed ruleset.

Incidents combine observations of the same sensor, capture epoch, host,
attack type, detection source, detector version and policy when their
intervals overlap or are at most five seconds apart. Late observations can
merge two matching incidents, retaining their evidence links. A flood
incident records the traffic pattern. Service availability is measured
separately.

## External labels

* TCP port scan — [Gotham TCP Scan](https://zenodo.org/records/14502760)
  and [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) with
  [corrected annotations](https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html).
  Select phases where one source probes several TCP ports on one destination.
* UDP flood — [GeNIS dos-udp](https://pmc.ncbi.nlm.nih.gov/articles/PMC11986601/)
  and [CIC-DDoS2019 UDP](https://www.unb.ca/cic/datasets/ddos-2019.html).
* ICMP flood — [GeNIS dos-icmp](https://pmc.ncbi.nlm.nih.gov/articles/PMC11986601/).
  [CICIoT2023](https://www.mdpi.com/1424-8220/23/13/5941) labels entire
  captures. Use these only for whole-scenario checks unless independently
  verified interval bounds are available.

Use previously inspected recordings for regression. Freeze new capture
groups and their labels before model selection and retain all views and
slices of a recording in one group. Record coverage and measured drops
separately from the attack or normal label.

For the manifest fields, artifact pinning and evaluation commands, see
[model training and acceptance](v1-evaluation.md).
