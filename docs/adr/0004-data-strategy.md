# ADR 0004 — Split training data by capture

Accepted 2026-11-06.

The laboratory provides ordinary traffic, controlled demand changes and a request log for each run. The Go sensor derives features from the packets. Each capture belongs to a single partition so neighbouring windows from one event stay together.

External PCAPs go through the same extractor. Published flow tables use different features and time boundaries. Each experiment records the source, checksum and labels used to interpret the capture. [Data preparation](../runbooks/data.md) · [External evaluation](../runbooks/classification.md)
