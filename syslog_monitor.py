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

# Store event timestamps
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
    with open(log_file, 'r') as f:
        for line in f:
            ts = parse_time(line)
            for event in THRESHOLDS:
                if event in line:
                    record_event(event, ts)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <logfile>")
        sys.exit(1)
    monitor(sys.argv[1])
