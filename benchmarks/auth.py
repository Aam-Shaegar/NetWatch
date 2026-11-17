"""Score published positive authentication case files (one verdict per source case)."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))
from netwatch_ml.security import assess
from netwatch_ml.security_import import from_events

FILES = [
    "esxi_ssh_brute_force.log",
    "o365_brute_force_login.json",
    "aws_login_failure.records",
    "azure_ad_high_number_of_failed_authentications_for_user.records",
    "o365_high_number_authentications_for_user.records",
]


def events(path):
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        if path.suffix == ".log":
            # Only the final PAM outcome; its companion pam_unix line repeats the attempt.
            match = re.search(
                r"(\S+Z) (\S+) sshd-session\[\d+\]: error: PAM: Authentication failure for (\S+) from",
                line,
            )
            if match:
                ts, entity, principal = match.groups()
                yield line, ts, entity, principal, False
            continue
        row = json.loads(line)
        if "CreationTime" in row and row["Operation"] in {
            "UserLoggedIn",
            "UserLoginFailed",
        }:
            yield (
                row["Id"],
                row["CreationTime"],
                row["OrganizationId"],
                row["UserId"],
                row["Operation"] == "UserLoggedIn",
            )
        elif row.get("eventName") == "ConsoleLogin":
            outcome = row["responseElements"]["ConsoleLogin"]
            if outcome not in ("Failure", "Success"):
                raise ValueError("unknown login result")
            yield (
                row["eventID"],
                row["eventTime"],
                row["recipientAccountId"],
                row["userIdentity"]["userName"],
                outcome == "Success",
            )
        elif row.get("category") == "SignInLogs":
            item = row["properties"]
            yield (
                item["id"],
                item["createdDateTime"],
                row["tenantId"],
                item["userPrincipalName"],
                int(item["status"]["errorCode"]) == 0,
            )


def examine(path):
    seen, buckets = set(), defaultdict(list)
    failures = []
    invalid_clock = 0
    hidden_principals = 0
    for uid, ts, entity, principal, ok in events(path):
        if uid in seen:
            continue
        seen.add(uid)
        if not principal or principal == "HIDDEN_DUE_TO_SECURITY_REASONS":
            hidden_principals += 1
            continue
        try:
            time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            invalid_clock += 1
            continue
        if time.tzinfo is None:
            time = time.replace(tzinfo=timezone.utc)
        stamp = time.timestamp()
        buckets[(int(stamp) // 60 * 60, entity)].append(
            json.dumps(
                dict(time_s=stamp, entity=entity, principal=principal, success=ok)
            )
        )
        if not ok:
            failures.append(stamp)
    if not failures:
        raise ValueError("case has no usable authentication failures")
    hits = []
    for (minute, entity), lines in sorted(buckets.items()):
        history = (
            line
            for offset in range(4, -1, -1)
            for line in buckets.get((minute - offset * 60, entity), [])
        )
        result = assess(from_events(history, entity, minute, "auth", auth_history=True))
        if any(item["label"] == "password_guessing" for item in result["findings"]):
            hits.append(minute + 60)
    with path.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    return dict(
        file=path.name,
        sha256=digest,
        distinct_events=len(seen) - invalid_clock - hidden_principals,
        hidden_principals=hidden_principals,
        invalid_clock=invalid_clock,
        failures=len(failures),
        detected=bool(hits),
        delay_from_first_logged_failure_s=round(min(hits) - min(failures), 3)
        if hits
        else None,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    print(json.dumps([examine(args.folder / file) for file in FILES], indent=2))
