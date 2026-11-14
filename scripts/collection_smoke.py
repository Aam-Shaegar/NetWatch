"""Check one real pause run, including PCAP counts, live/replay parity and labels."""
from pathlib import Path
import tempfile

from server_smoke import main as check_pipeline
from collect_dataset import collect, command
from netwatch_ml.data.dataset import read_run


def main():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        sensor = folder / 'netwatch-sensor'
        command(['go', 'build', '-o', str(sensor), './cmd/netwatch-sensor'])
        group = collect(folder, 'pause', 42, 45, 3, {})
        _, _, audit = read_run(folder / group, sensor, folder)
        check_pipeline(folder / group / 'live.jsonl')
        print(audit)


if __name__ == '__main__':
    main()
