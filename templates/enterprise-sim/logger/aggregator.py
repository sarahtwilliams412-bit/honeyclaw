#!/usr/bin/env python3
"""
Honey Claw - Log Aggregator
Aggregates logs from all services and ships to S3
Version: 1.1.0 (input validation)
"""

import os
import json
import time
import datetime
import sys
from pathlib import Path

# Add parent path for common imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.validation import (
    sanitize_for_log,
    sanitize_path,
    MAX_LOG_LINE_LENGTH,
)

LOG_DIR = '/var/log/honeypot'
AGGREGATED_LOG = os.path.join(LOG_DIR, 'aggregated.json')
S3_BUCKET = os.environ.get('S3_BUCKET', '')
S3_ENDPOINT = os.environ.get('S3_ENDPOINT', 'https://s3.amazonaws.com')
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

# Safety limits
MAX_LINE_LENGTH = 16384  # 16KB per log line
MAX_EVENTS_PER_CYCLE = 1000  # Max events to process per cycle
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max aggregated log before rotation

# Log files to watch
LOG_FILES = [
    'rdp.json',
    'winrm.json',
    'ldap.json',
    'sshd.log',
    'nginx.log',
    'smbd.log'
]

def validate_log_filename(filename):
    """Validate log filename is in allowed list"""
    if not filename or not isinstance(filename, str):
        return False
    # Only allow whitelisted files
    return filename in LOG_FILES

def parse_log_line(line, source):
    """Parse a log line and add metadata with validation"""
    # Validate source is allowed
    if not validate_log_filename(source):
        source = "unknown"
    
    # Truncate line if too long
    if len(line) > MAX_LINE_LENGTH:
        line = line[:MAX_LINE_LENGTH]
        truncated = True
    else:
        truncated = False
    
    try:
        # Try JSON first
        event = json.loads(line.strip())
        if not isinstance(event, dict):
            event = {'data': event, 'format': 'json-non-dict'}
    except json.JSONDecodeError:
        # Plain text log - sanitize for safety
        event = {
            'raw': sanitize_for_log(line.strip(), max_length=MAX_LINE_LENGTH),
            'format': 'text'
        }
    
    event['source_file'] = source
    event['aggregated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    if truncated:
        event['_line_truncated'] = True
    
    return event

def tail_file(filepath, position):
    """Read new lines from file since last position with validation"""
    # Validate filepath
    safe_path, path_valid = sanitize_path(filepath)
    if not path_valid:
        print(f"[Aggregator] Invalid path: {safe_path}")
        return [], 0
    
    # Ensure path is within LOG_DIR
    try:
        resolved = Path(filepath).resolve()
        log_dir_resolved = Path(LOG_DIR).resolve()
        if not str(resolved).startswith(str(log_dir_resolved)):
            print(f"[Aggregator] Path outside LOG_DIR: {filepath}")
            return [], 0
    except Exception:
        return [], 0
    
    try:
        with open(filepath, 'r') as f:
            f.seek(position)
            lines = f.readlines()
            new_position = f.tell()
            
            # Limit lines per read
            if len(lines) > MAX_EVENTS_PER_CYCLE:
                lines = lines[:MAX_EVENTS_PER_CYCLE]
                # Don't update position if we're rate limiting
                new_position = position + sum(len(l) for l in lines)
            
            return lines, new_position
    except FileNotFoundError:
        return [], 0
    except Exception as e:
        print(f"[Aggregator] Error reading {safe_path}: {sanitize_for_log(str(e), max_length=256)}")
        return [], position

def check_rotation_needed():
    """Check if aggregated log needs rotation"""
    try:
        if os.path.exists(AGGREGATED_LOG):
            size = os.path.getsize(AGGREGATED_LOG)
            if size > MAX_FILE_SIZE:
                # Rotate file
                timestamp = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                rotated = f"{AGGREGATED_LOG}.{timestamp}"
                os.rename(AGGREGATED_LOG, rotated)
                print(f"[Aggregator] Rotated log to {rotated}")
                return True
    except Exception as e:
        print(f"[Aggregator] Rotation error: {sanitize_for_log(str(e), max_length=256)}")
    return False

def aggregate_logs():
    """Main aggregation loop"""
    print(f"[Aggregator] Starting log aggregation for {HONEYPOT_ID}")
    print(f"[Aggregator] Watching directory: {LOG_DIR}")
    print(f"[Aggregator] Input validation enabled (v1.1.0)")
    
    # Track file positions
    positions = {f: 0 for f in LOG_FILES}
    
    while True:
        new_events = []
        total_processed = 0
        
        # Check if rotation needed
        check_rotation_needed()
        
        for log_file in LOG_FILES:
            if total_processed >= MAX_EVENTS_PER_CYCLE:
                break
                
            filepath = os.path.join(LOG_DIR, log_file)
            lines, new_pos = tail_file(filepath, positions[log_file])
            
            if lines:
                for line in lines:
                    if total_processed >= MAX_EVENTS_PER_CYCLE:
                        break
                    if line.strip():
                        event = parse_log_line(line, log_file)
                        new_events.append(event)
                        total_processed += 1
                        
                positions[log_file] = new_pos
        
        # Write aggregated events
        if new_events:
            try:
                Path(AGGREGATED_LOG).parent.mkdir(parents=True, exist_ok=True)
                with open(AGGREGATED_LOG, 'a') as f:
                    for event in new_events:
                        line = json.dumps(event)
                        # Final length check
                        if len(line) > MAX_LINE_LENGTH:
                            event['_truncated'] = True
                            line = json.dumps(event)[:MAX_LINE_LENGTH]
                        f.write(line + '\n')
                
                print(f"[Aggregator] Wrote {len(new_events)} events")
            except Exception as e:
                print(f"[Aggregator] Write error: {sanitize_for_log(str(e), max_length=256)}")
            
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
