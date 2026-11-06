"""Register a local raw capture without pretending it has verified training labels."""
import argparse, hashlib, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument("capture",type=Path);p.add_argument("--source",required=True);p.add_argument("--run-id",required=True);p.add_argument("--output",type=Path,required=True)
a=p.parse_args()
if a.capture.resolve()==a.output.resolve():p.error("output must differ from capture")
if a.output.exists():p.error("manifest already exists")
h=hashlib.sha256()
with a.capture.open("rb") as f:
    magic=f.read(4);f.seek(0)
    if magic not in [bytes.fromhex(x) for x in ['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d','0a0d0d0a']]:p.error("not a recognized PCAP/PCAPNG header")
    for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(dict(schema_version=1,run_id=a.run_id,source=a.source,file_name=a.capture.name,bytes=a.capture.stat().st_size,sha256=h.hexdigest(),labels_status="not_verified",training_ready=False),indent=2)+'\n')
print(a.output)
