"""Fetch checksum-pinned, bounded offline excerpts for the external classification audit."""

import argparse
import hashlib
from pathlib import Path
import struct
import tempfile
import urllib.request

FRIDAY = (
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/"
    "70bac6246d99cf046186a02e1cce6883e2ffe7ea/pcap/Friday-WorkingHours.pcap"
)
FRIDAY_BYTES = 8839309056
CHUNK = 8 * 1024 * 1024
DIGESTS = {
    "Friday-scan.pcap": "d98514ebbe8da0db95019ea812fdb8668b062728053c3bfce95a1523deb558b8",
    "Friday-ddos.pcap": "0dc04860f2f4406f5d54881ae4e977123fa70df5d995497873406bf1e4a1f5c8",
    "CIC-DDoS-2019-WebDDoS.pcap": "a57eb8e792b72430902c606f6953780c4005053c1e4606085582a7049f8c4aa2",
}


def block(offset):
    end = offset + CHUNK - 1
    req = urllib.request.Request(
        FRIDAY + f"?section={offset}-{end}", headers={"Range": f"bytes={offset}-{end}"}
    )
    with urllib.request.urlopen(req, timeout=90) as response:
        if (
            response.status != 206
            or response.headers["Content-Range"]
            != f"bytes {offset}-{end}/{FRIDAY_BYTES}"
        ):
            raise ValueError("mirror did not supply bounded range")
        data = response.read(CHUNK + 1)
    if len(data) != CHUNK:
        raise ValueError("truncated range")
    return data


def packets(data):
    # This pinned PCAPNG section uses little-endian EPBs, one Ethernet interface and microsecond timestamps.
    i = 0
    while True:
        i = data.find(b"\x06\x00\x00\x00", i)
        if i < 0 or i + 32 > len(data):
            return
        _, length, iface, hi, lo, cap, wire = struct.unpack_from("<7I", data, i)
        if (
            iface == 0
            and length >= 32 + cap
            and 14 <= cap <= wire <= 65535
            and i + length <= len(data)
            and struct.unpack_from("<I", data, i + length - 4)[0] == length
        ):
            yield (hi << 32) + lo, data[i + 28 : i + 28 + cap], wire
            i += length
        else:
            i += 1


def excerpt(name):
    if name.startswith("Friday-scan"):
        rows = [
            r
            for r in packets(block(6752439690))
            if 1499449920 <= r[0] / 1e6 < 1499449960
        ]
    else:
        offset = 7654086768
        rows = list(packets(block(offset)))
        following = list(packets(block(offset + CHUNK - 65536)))
        rows.extend(following[following.index(rows[-1]) + 1 :])
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, payload, wire in rows:
        result.extend(
            struct.pack("<IIII", ts // 1000000, ts % 1000000, len(payload), wire)
        )
        result.extend(payload)
    return result


def fetch(folder):
    folder.mkdir(parents=True, exist_ok=True)
    for name, digest in DIGESTS.items():
        path = folder / name
        if path.exists():
            data = path.read_bytes()
        elif name.startswith("Friday"):
            data = excerpt(name)
        else:
            url = "https://zenodo.org/records/17121740/files/" + name + "?download=1"
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read(830805)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"checksum mismatch for {name}")
        if not path.exists():
            with tempfile.NamedTemporaryFile(dir=folder, delete=False) as f:
                f.write(data)
            Path(f.name).replace(path)
        print(name, len(data), digest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    fetch(parser.parse_args().folder)
