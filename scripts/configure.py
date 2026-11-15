"""Create local PostgreSQL credentials on first setup."""

import os
from pathlib import Path
import secrets
from tempfile import NamedTemporaryFile


def main():
    path = Path(".env")
    if path.exists():
        print(".env already exists; preserved")
        return

    # Publish the complete, mode-0600 file only if another setup has not won the race.
    with NamedTemporaryFile(mode="w", dir=path.parent) as temp:
        temp.write(f"NETWATCH_DB_PASSWORD={secrets.token_urlsafe(32)}\n")
        temp.flush()
        try:
            os.link(temp.name, path)
        except FileExistsError:
            print(".env already exists; preserved")
        else:
            print("Created local .env (ignored by Git)")


if __name__ == "__main__":
    main()
