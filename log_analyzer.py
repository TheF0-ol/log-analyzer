#!/usr/bin/env python3
"""
SSH auth.log Analyzer
======================
Parses a Linux SSH authentication log (the format used by /var/log/auth.log
on Debian/Ubuntu, or /var/log/secure on RHEL) and flags suspicious activity:

    - Brute force: an IP with N or more failed logins within a time window
    - Invalid user attempts: logins tried against usernames that don't exist
    - Possible successful brute force: a success for an IP that had enough
      recent failures to also be flagged as brute force

Usage:
    python log_analyzer.py fixtures/brute_force.log
    python log_analyzer.py auth.log --threshold 5 --window 60 --output results.csv

Notes:
    - Lines that don't match the expected sshd log format are skipped and
      counted, not silently dropped; the summary reports how many.
    - This is a learning / portfolio tool, not a production SIEM. It has no
      log rotation handling, no live tailing, and assumes the current year
      for timestamps (syslog lines have no year field).

Exit codes: 0 = ran successfully (alerts or not), 1 = error (e.g. file not found).
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

CURRENT_YEAR = datetime.now().year

# e.g. "Jan 11 02:10:01 webserver sshd[2001]: Failed password for root from 203.0.113.9 port 44110 ssh2"
LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
INVALID_USER_RE = re.compile(r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


@dataclass
class LogEvent:
    timestamp: datetime
    ip: str
    user: str
    event_type: str  # "failed", "accepted"
    invalid_user: bool = False


@dataclass
class Alert:
    timestamp: str
    alert_type: str
    ip: str
    detail: str
    severity: str = "medium"


def parse_line(line, year=CURRENT_YEAR):
    """
    Parse one sshd auth.log line into a LogEvent, or return None if the
    line doesn't match a known pattern (malformed, or an sshd message type
    this tool doesn't track, like 'Disconnected from' or session-opened).
    """
    m = LINE_RE.match(line.strip())
    if not m:
        return None

    try:
        ts = datetime.strptime(f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg = m["msg"]

    fm = FAILED_RE.match(msg)
    if fm:
        is_invalid = INVALID_USER_RE.match(msg) is not None
        return LogEvent(ts, fm["ip"], fm["user"], "failed", invalid_user=is_invalid)

    am = ACCEPTED_RE.match(msg)
    if am:
        return LogEvent(ts, am["ip"], am["user"], "accepted")

    return None  # a recognized sshd line type we don't track (session opened, disconnected, etc.)


def parse_log(path, year=CURRENT_YEAR):
    """
    Read `path` and return (events, skipped_count). Every non-blank line
    that doesn't parse into a LogEvent counts as skipped, rather than being
    silently dropped, so malformed input is visible in the summary.
    """
    events = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            event = parse_line(line, year=year)
            if event is None:
                skipped += 1
            else:
                events.append(event)
    return events, skipped


def analyze(events, threshold=5, window_seconds=60):
    """
    Apply detection rules to a list of LogEvent and return a list of Alert.

    Rules:
      - brute_force: threshold or more "failed" events from the same IP
        within any window_seconds-wide span.
      - invalid_user: any failed login attempt against a username that
        doesn't exist on the target (reported individually, one alert per
        distinct invalid username per IP).
      - possible_successful_brute_force: an "accepted" event for an IP that
        also triggered brute_force.
    """
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    brute_force_ips = set()

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        failed = [e for e in ip_events if e.event_type == "failed"]

        # Sliding window: for each failure, count failures within
        # window_seconds after it.
        for i, start in enumerate(failed):
            count = 1
            for other in failed[i + 1:]:
                if (other.timestamp - start.timestamp).total_seconds() <= window_seconds:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append(Alert(
                    timestamp=start.timestamp.isoformat(timespec="seconds"),
                    alert_type="brute_force",
                    ip=ip,
                    detail=f"{count} failed logins within {window_seconds}s "
                           f"(threshold: {threshold})",
                    severity="high",
                ))
                brute_force_ips.add(ip)
                break  # one brute_force alert per IP is enough

        # Invalid user attempts: one alert per distinct bad username per IP
        invalid_users = sorted({e.user for e in failed if e.invalid_user})
        for user in invalid_users:
            first = next(e for e in failed if e.invalid_user and e.user == user)
            alerts.append(Alert(
                timestamp=first.timestamp.isoformat(timespec="seconds"),
                alert_type="invalid_user",
                ip=ip,
                detail=f"login attempted against nonexistent user '{user}'",
                severity="low",
            ))

        # Possible successful brute force
        if ip in brute_force_ips:
            for e in ip_events:
                if e.event_type == "accepted":
                    alerts.append(Alert(
                        timestamp=e.timestamp.isoformat(timespec="seconds"),
                        alert_type="possible_successful_brute_force",
                        ip=ip,
                        detail=f"successful login for '{e.user}' from an IP "
                               f"already flagged for brute force",
                        severity="critical",
                    ))

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def write_csv(path, alerts):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "alert_type", "ip", "detail", "severity"])
        for a in alerts:
            w.writerow([a.timestamp, a.alert_type, a.ip, a.detail, a.severity])


def build_parser():
    p = argparse.ArgumentParser(description="Flag suspicious activity in an SSH auth.log file.")
    p.add_argument("logfile", help="Path to the auth.log-style file to analyze")
    p.add_argument("--threshold", type=int, default=5,
                    help="Failed logins from one IP to trigger a brute-force alert (default: 5)")
    p.add_argument("--window", type=int, default=60,
                    help="Time window in seconds for the brute-force threshold (default: 60)")
    p.add_argument("--year", type=int, default=CURRENT_YEAR,
                    help="Year to assume for log timestamps, since syslog lines omit it "
                         "(default: current year)")
    p.add_argument("--output", default=None,
                    help="CSV file to write alerts to (default: <logfile>.alerts.csv)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    log_path = Path(args.logfile)
    if not log_path.is_file():
        print(f"Error: file not found: {log_path}", file=sys.stderr)
        return 1

    events, skipped = parse_log(log_path, year=args.year)
    alerts = analyze(events, threshold=args.threshold, window_seconds=args.window)

    out_path = Path(args.output) if args.output else log_path.with_suffix(".alerts.csv")
    write_csv(out_path, alerts)

    print(f"Parsed {len(events)} event(s) from {log_path} ({skipped} line(s) skipped/unrecognized)")
    print(f"Found {len(alerts)} alert(s):")
    by_type = defaultdict(int)
    for a in alerts:
        by_type[a.alert_type] += 1
    for alert_type, count in sorted(by_type.items()):
        print(f"  {alert_type}: {count}")
    print(f"\nSaved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
