import argparse
import csv
import json
from pathlib import Path
from .core import Packet, aggregate, flag_windows


def main():
    parser=argparse.ArgumentParser(description='NetWatch: CSV пакетов → статистика и сигналы JSON')
    parser.add_argument('input',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--window',type=float,default=5)
    parser.add_argument('--max-ports',type=int,default=20)
    parser.add_argument('--max-packet-rate',type=float,default=1000)
    args=parser.parse_args()
    if args.input.resolve()==args.output.resolve():
        parser.error('Вход и выход должны быть разными файлами')
    try:
        packets=[]
        with args.input.open(newline='',encoding='utf-8') as f:
            for line,row in enumerate(csv.DictReader(f),start=2):
                try:
                    packets.append(Packet(float(row['timestamp']),row['src_ip'],row['dst_ip'],
                        int(row['src_port']),int(row['dst_port']),row['protocol'].upper(),int(row['size'])))
                except (KeyError,TypeError,ValueError) as exc:
                    raise ValueError(f'Строка {line}: {exc}') from exc
        windows=list(flag_windows(aggregate(packets,args.window),args.max_ports,args.max_packet_rate))
        payload=dict(schema_version=1,window_seconds=args.window,
            packet_count=len(packets),active_window_count=len(windows),windows=windows)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(payload,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
        print(f'Пакетов: {len(packets)}; активных окон: {len(windows)}; сигналов: {sum(w["is_anomaly"] for w in windows)}')
    except (OSError,ValueError) as exc:
        parser.error(str(exc))

if __name__=='__main__':
    main()
