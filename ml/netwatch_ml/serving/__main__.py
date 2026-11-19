"""Run the inference service with the same JSON logging fields as Go."""

import argparse
import json
import logging
import os
from datetime import datetime, timezone

import uvicorn


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "time": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "component": "ml",
            "version": os.getenv("NETWATCH_BUILD_VERSION") or "dev",
            "event": record.getMessage() if record.name.startswith("netwatch_ml.") else "server_event",
        }
        if entry["event"] == "server_event":
            entry["message"] = record.getMessage()
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["error_type"] = record.exc_info[0].__name__
        return json.dumps(entry, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    level = os.getenv("NETWATCH_LOG_LEVEL", "INFO").upper()
    if level not in {"DEBUG", "INFO", "WARN", "WARNING", "ERROR"}:
        parser.error("NETWATCH_LOG_LEVEL must be DEBUG, INFO, WARN or ERROR")
    uvicorn.run(
        "netwatch_ml.serving.app:app",
        host=args.host,
        port=args.port,
        access_log=False,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {"json": {"()": JSONFormatter}},
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                    "stream": "ext://sys.stderr",
                }
            },
            "root": {"handlers": ["console"], "level": level},
        },
    )


if __name__ == "__main__":
    main()
