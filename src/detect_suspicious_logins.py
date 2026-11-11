#!/usr/bin/env python3
"""Analyze authentication logs for brute-force and fail-then-success patterns.

Designed as an educational lab, not a production detection engine.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED = {'timestamp', 'event_id', 'username', 'source_ip', 'hostname'}
FAILURE = '4625'
SUCCESS = '4624'

def parse_timestamp(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError(f'Timestamp must have a timezone: {s}')
    return dt.astimezone(timezone.utc)


def load_events(path: Path) -> list[dict]:
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError(f'Missing columns: {sorted(REQUIRED - set(reader.fieldnames or []))}')
        events = []
        for line, row in enumerate(reader, 2):
            if row['event_id'] not in {FAILURE, SUCCESS}:
                continue
            try:
                dt = parse_timestamp(row['timestamp'])
            except ValueError as e:
                raise ValueError(f'Line {line}: {e}') from e
            if not row['source_ip'] or not row['username'] or not row['hostname']:
                raise ValueError(f'Line {line}: source_ip, username, hostname required')
            events.append({**row, '_time':dt})
    events.sort(key=lambda e:e['_time'])
    return events


def detect(events: list[dict], threshold: int = 5, window_minutes: int = 10) -> list[dict]:
    """Group by host+source IP+username to avoid conflating distinct accounts."""
    window = timedelta(minutes=window_minutes)
    failures = defaultdict(deque)
    alerts = []
    last_bruteforce = {}
    for event in events:
        key = (event['hostname'],event['source_ip'],event['username'])
        recent = failures[key]
        while recent and event['_time'] - recent[0] > window:
            recent.popleft()
        if event['event_id'] == FAILURE:
            recent.append(event['_time'])
            if len(recent) >= threshold and last_bruteforce.get(key) != recent[0]:
                alerts.append({
                    'rule':'repeated_failed_logins', 'severity':'medium',
                    'hostname':key[0], 'source_ip':key[1], 'username':key[2],
                    'event_time':event['_time'].isoformat(), 'failure_count':len(recent),
                    'window_minutes':window_minutes,
                    'reason':f'{len(recent)} failed logins inside {window_minutes} minutes',
                    'recommended_action':'Validate source and user activity; inspect nearby logs; check for account lockout or spraying.'
                })
                last_bruteforce[key] = recent[0]
        elif recent and len(recent) >= threshold:
            alerts.append({
                'rule':'failed_logins_followed_by_success', 'severity':'high',
                'hostname':key[0], 'source_ip':key[1], 'username':key[2],
                'event_time':event['_time'].isoformat(), 'failure_count':len(recent),
                'window_minutes':window_minutes,
                'reason':f'Successful login following {len(recent)} recent failures',
                'recommended_action':'Confirm login legitimacy with owner; review session activity and endpoint evidence; escalate per IR playbook.'
            })
            recent.clear()
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description='Educational Windows authentication event detector')
    parser.add_argument('--input', default='data/sample_security_events.csv', type=Path)
    parser.add_argument('--output', default='reports/alerts.json', type=Path)
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window', type=int, default=10, help='Sliding window in minutes')
    args = parser.parse_args()
    if args.threshold < 1 or args.window < 1:
        parser.error('--threshold and --window must be positive')
    events = load_events(args.input)
    alerts = detect(events,args.threshold,args.window)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'metadata':{'source':str(args.input),'events_processed':len(events),'threshold':args.threshold,'window_minutes':args.window,'synthetic_data':args.input.name == 'sample_security_events.csv'},'alerts':alerts},indent=2)+'\n',encoding='utf-8')
    print(f'Processed {len(events)} events | Generated {len(alerts)} alerts')
    for alert in alerts:
        print(f"[{alert['severity'].upper()}] {alert['rule']} | {alert['username']} @ {alert['source_ip']} | {alert['event_time']}")
    print(f'Output: {args.output}')

if __name__ == '__main__':
    main()
