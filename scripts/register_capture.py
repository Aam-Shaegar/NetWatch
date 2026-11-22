"""Record the provenance and checksum of a local capture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile


# PCAP supports both byte orders and both timestamp resolutions.
CAPTURE_HEADERS = {
    bytes.fromhex(header)
    for header in ("d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a")
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.capture.resolve() == args.output.resolve():
        parser.error("output must differ from capture")
    if args.output.exists():
        parser.error("manifest already exists")

    with args.capture.open("rb") as capture:
        header = capture.read(4)
        if header not in CAPTURE_HEADERS:
            parser.error("not a recognized PCAP/PCAPNG header")
        digest = hashlib.sha256(header)
        size = len(header)
        for block in iter(lambda: capture.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)

    manifest = {
        "schema_version": 1,
        "run_id": args.run_id,
        "source": args.source,
        "file_name": args.capture.name,
        "bytes": size,
        "sha256": digest.hexdigest(),
        "labels_status": "not_verified",
        "training_ready": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", dir=args.output.parent) as temporary:
        temporary.write(json.dumps(manifest, indent=2) + "\n")
        temporary.flush()
        try:
            os.link(temporary.name, args.output)
        except FileExistsError:
            parser.error("manifest already exists")
    print(args.output)


if __name__ == "__main__":
    main()
