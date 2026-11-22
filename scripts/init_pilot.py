"""Prepare a private loopback TLS configuration for a single Linux observation host."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new private directory for credentials and work.env")
    parser.add_argument("--host", type=ipaddress.ip_address, help="protected host address")
    parser.add_argument("--interface", help="Linux interface carrying that host's traffic")
    args = parser.parse_args()
    if (args.host is None) != (args.interface is None):
        parser.error("set --host and --interface together")
    if args.interface is not None and not re.fullmatch(r"[\w.:@-]+", args.interface, flags=re.ASCII):
        parser.error("invalid interface name")
    dest = args.directory.expanduser().resolve()
    if any(c in str(dest) for c in "\r\n"):
        parser.error("directory name contains a newline")
    template = (ROOT / "deploy/work.env.example").read_text()
    os.umask(0o077)
    try:
        dest.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        parser.error(f"directory already exists: {dest}")
    try:
        (dest / ".gitignore").write_text("*\n")
        tls = dest / "tls"
        tls.mkdir()
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
             "-days", "365", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
             "-keyout", tls / "key.pem", "-out", tls / "cert.pem"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        # Docker mounts only this subdirectory into the unprivileged API. Its parent remains 0700.
        for file in tls.iterdir():
            file.chmod(0o444)
        tls.chmod(0o755)
        operator = secrets.token_hex(32)
        password = secrets.token_hex(32)
        (dest / "operator.token").write_text(operator + "\n")
        settings = {
            "NETWATCH_TLS_DIR": "'" + str(tls).replace("'", "\\'") + "'",
            "NETWATCH_DB_PASSWORD": password,
            "NETWATCH_DATABASE_URL": f"postgres://netwatch:{password}@db/netwatch?sslmode=disable",
            "NETWATCH_OPERATOR_TOKENS": "'" + json.dumps({"operator": operator}) + "'",
            "NETWATCH_CAPTURE_HOST": str(args.host) if args.host else "",
            "NETWATCH_CAPTURE_INTERFACE": args.interface or "",
        }
        for key, value in settings.items():
            template, count = re.subn(rf"^{key}=$", lambda _: f"{key}={value}", template, flags=re.MULTILINE)
            if count != 1:
                raise ValueError(f"missing or repeated setting {key} in the pilot template")
        (dest / "work.env").write_text(template)
    except BaseException:
        shutil.rmtree(dest)
        raise
    print(f"Pilot configuration: {dest / 'work.env'}")


if __name__ == "__main__":
    main()
