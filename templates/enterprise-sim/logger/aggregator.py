#!/usr/bin/env python3
"""
Honey Claw - Log Aggregator
Aggregates logs from all services and ships to S3
"""

import os
import json
import time
import datetime
import glob
from pathlib import Path

LOG_DIR = '/var/log/honeypot'
AGGREGATED_LOG = os.path.join(LOG_DIR, 'aggregated.json')
S3_BUCKET = os.environ.get('S3_BUCKET', '')
S3_ENDPOINT = os.environ.get('S3_ENDPOINT', 'https://s3.amazonaws.com')
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

# Log files to watch
LOG_FILES = [
    'rdp.json',
    'winrm.json',
    'ldap.json',
    'sshd.log',
    'nginx.log',
    'smbd.log'
]

def parse_log_line(line, source):
    """Parse a log line and add metadata"""
    try:
        # Try JSON first
        event = json.loads(line.strip())
    except json.JSONDecodeError:
        # Plain text log
        event = {
            'raw': line.strip(),
            'format': 'text'
        }
    
    event['source_file'] = source
    event['aggregated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    
    return event

def tail_file(filepath, position):
    """Read new lines from file since last position"""
    try:
        with open(filepath, 'r') as f:
            f.seek(position)
            lines = f.readlines()
            new_position = f.tell()
            return lines, new_position
    except FileNotFoundError:
        return [], 0

def aggregate_logs():
    """Main aggregation loop"""
    print(f"[Aggregator] Starting log aggregation for {HONEYPOT_ID}")
    print(f"[Aggregator] Watching directory: {LOG_DIR}")
    
    # Track file positions
    positions = {f: 0 for f in LOG_FILES}
    
    while True:
        new_events = []
        
        for log_file in LOG_FILES:
            filepath = os.path.join(LOG_DIR, log_file)
            lines, new_pos = tail_file(filepath, positions[log_file])
            
            if lines:
                for line in lines:
                    if line.strip():
                        event = parse_log_line(line, log_file)
                        new_events.append(event)
                        
                positions[log_file] = new_pos
        
        # Write aggregated events
        if new_events:
            with open(AGGREGATED_LOG, 'a') as f:
                for event in new_events:
                    f.write(json.dumps(event) + '\n')
            
            print(f"[Aggregator] Wrote {len(new_events)} events")
            
            # TODO: Ship to S3 if configured
            if S3_BUCKET:
                ship_to_s3(new_events)
        
        # Sleep before next check
        time.sleep(5)

def ship_to_s3(events):
    """Ship events to S3 bucket"""
    # TODO: Implement S3 upload using boto3
    pass

if __name__ == '__main__':
    aggregate_logs()
