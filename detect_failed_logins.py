#!/usr/bin/env python3
"""Offline SSH journal detector. Counts Failed password events only."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import json
import re

PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)")

def detect(records, threshold=5, window=300):
    events = []
    for record in records:
        match = PATTERN.search(str(record.get('MESSAGE', '')))
        if not match:
            continue
        try:
            timestamp = int(record['__REALTIME_TIMESTAMP']) / 1_000_000
            ipaddress.ip_address(match[2])
        except (KeyError, ValueError, TypeError):
            continue
        events.append((timestamp, match[2], match[1]))
    windows = defaultdict(deque)
    alerts = []
    for timestamp, source, username in sorted(events):
        queue = windows[source]
        while queue and timestamp - queue[0][0] > window:
            queue.popleft()
        queue.append((timestamp, username))
        if len(queue) >= threshold:
            alerts.append({
                'timestamp_utc': datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                'source_ip': source,
                'failure_count': len(queue),
                'window_seconds': window,
                'usernames': sorted({user for _, user in queue}),
                'rule': 'ssh_failed_password_threshold'
            })
            queue.clear()
    return alerts

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input')
    parser.add_argument('--output', default='alerts.json')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=300)
    args = parser.parse_args()
    if args.threshold < 1 or args.window < 1:
        parser.error('threshold and window must be positive')
    records = []
    skipped = 0
    with open(args.input, encoding='utf-8') as stream:
        for line in stream:
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                skipped += 1
    alerts = detect(records, args.threshold, args.window)
    with open(args.output, 'w', encoding='utf-8') as stream:
        json.dump(alerts, stream, indent=2)
    print(f'{len(alerts)} alert(s); {skipped} malformed line(s) skipped')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
