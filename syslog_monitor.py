#!/usr/bin/env python3
"""Simple syslog monitor with rolling window alerts."""

import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Thresholds for alerts per event keyword
THRESHOLDS = {
    'ERROR': 10,
}

# Rolling window length in minutes for counting events
ALERT_WINDOW_MINUTES = 5

TIME_PATTERN = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]')
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Store event timestamps for each event keyword
EVENT_TIMES = defaultdict(list)

def parse_time(line):
    """Parse a timestamp from the beginning of a line."""
    match = TIME_PATTERN.match(line)
    if match:
        try:
            return datetime.strptime(match.group(1), TIME_FORMAT)
        except ValueError:
            pass
    return datetime.now()

def purge_old(event, now):
    """Remove timestamps outside the alert window."""
    window_start = now - timedelta(minutes=ALERT_WINDOW_MINUTES)
    EVENT_TIMES[event] = [t for t in EVENT_TIMES[event] if t >= window_start]

def record_event(event, timestamp):
    EVENT_TIMES[event].append(timestamp)
    purge_old(event, timestamp)

    if len(EVENT_TIMES[event]) >= THRESHOLDS[event]:
        print(
            f"ALERT: {event} occurred {len(EVENT_TIMES[event])} times in the last "
            f"{ALERT_WINDOW_MINUTES} minutes"
        )

def monitor(log_file):
    """Read a log file and process each line for alerts."""
    with open(log_file, "r") as f:
        for line in f:
            ts = parse_time(line)
            for event in THRESHOLDS:
                if event in line:
                    record_event(event, ts)

def main(argv):
    """Entry point for command-line execution."""
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <logfile>")
        return 1
    monitor(argv[1])
    return 0


if __name__ == "__main__":  # pragma: no cover - manual invocation only
    raise SystemExit(main(sys.argv))
