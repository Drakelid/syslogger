# Syslog Monitor

This repository provides a simple Python script to monitor syslog files and trigger alerts when certain events occur too frequently.

## Usage

```
python syslog_monitor.py /path/to/syslog
```

Log lines may optionally begin with a timestamp in square brackets using the format `YYYY-MM-DD HH:MM:SS`:

```
[2024-03-09 10:15:00] ERROR something went wrong
```

If a timestamp is not present, the current time is used.

## Configuration

The script defines two main settings that can be adjusted at the top of `syslog_monitor.py`:

- `THRESHOLDS`: Mapping of keywords to the count required to trigger an alert.
- `ALERT_WINDOW_MINUTES`: The rolling time window, in minutes, used to count events. Older events are purged so alerts only fire when the threshold is exceeded within this window.

Adjust these values to suit your monitoring needs.
