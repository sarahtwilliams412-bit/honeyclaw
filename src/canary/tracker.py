#!/usr/bin/env python3
"""
Honey Claw - Canary Token Tracker
Detect and track canary token triggers with alerting capabilities.

This module provides:
- HTTP server for tracking URL visits
- AWS credential usage detection  
- Webhook alerting when canaries are triggered
- Central dashboard for all canary events
"""
import os
import re
import json
import time
import threading
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Callable, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error


@dataclass
class TriggerEvent:
    """Represents a canary trigger event"""
    id: str                        # Event ID
    canary_id: str                 # ID of triggered canary
    canary_type: str               # Type of canary
    timestamp: str                 # ISO timestamp
    source_ip: str                 # IP address that triggered
    user_agent: str = ""           # User agent (for HTTP triggers)
    method: str = ""               # HTTP method (for URL triggers)
    path: str = ""                 # Request path
    headers: Dict[str, str] = None # Request headers
    payload: Dict[str, Any] = None # Additional trigger data
    alerted: bool = False          # Whether webhook was called
    alert_response: str = ""       # Response from webhook
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.payload is None:
            self.payload = {}
    
    def to_dict(self) -> dict:
        return asdict(self)


class CanaryTracker:
    """
    Track canary token triggers and send alerts.
    
    Supports:
    - Tracking URL hit detection (via HTTP server)
    - AWS credential scanning in logs
    - Manual trigger reporting
    - Webhook alerting
    - Event history and dashboard data
    """
    
    def __init__(self,
                 storage_path: str = None,
                 canary_storage_path: str = None,
                 alert_cooldown: int = 300):
        """
        Initialize the canary tracker.
        
        Args:
            storage_path: Path to store trigger events (JSON file)
            canary_storage_path: Path to canary definitions (for lookups)
            alert_cooldown: Minimum seconds between alerts for same canary
        """
        self.storage_path = Path(storage_path or os.environ.get(
            'CANARY_EVENTS_STORAGE', '/data/canary_events.json'
        ))
        self.canary_storage_path = Path(canary_storage_path or os.environ.get(
            'CANARY_STORAGE', '/data/canaries.json'
        ))
        self.alert_cooldown = alert_cooldown
        
        # In-memory state
        self.events: List[TriggerEvent] = []
        self.canaries: Dict[str, dict] = {}  # Loaded from generator's storage
        self.last_alert_time: Dict[str, float] = {}  # canary_id -> timestamp
        
        # Callbacks
        self.on_trigger: Optional[Callable[[TriggerEvent], None]] = None
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Ensure storage directory exists
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing data
        self._load()
        self._load_canaries()
    
    def _load(self):
        """Load events from storage"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for event_data in data.get('events', []):
                        self.events.append(TriggerEvent(**event_data))
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Warning: Failed to load events: {e}")
    
    def _load_canaries(self):
        """Load canary definitions for lookups"""
        if self.canary_storage_path.exists():
            try:
                with open(self.canary_storage_path, 'r') as f:
                    data = json.load(f)
                    self.canaries = data.get('canaries', {})
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Failed to load canaries: {e}")
    
    def _save(self):
        """Save events to storage"""
        data = {
            'version': 1,
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'events': [e.to_dict() for e in self.events[-10000:]]  # Keep last 10k events
        }
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _generate_event_id(self) -> str:
        """Generate a unique event ID"""
        timestamp = int(time.time() * 1000)
        random_part = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
        return f"evt_{timestamp}_{random_part}"
    
    def _should_alert(self, canary_id: str) -> bool:
        """Check if we should send an alert (respecting cooldown)"""
        last_time = self.last_alert_time.get(canary_id, 0)
        return time.time() - last_time > self.alert_cooldown
    
    def _send_webhook(self, webhook_url: str, event: TriggerEvent) -> tuple[bool, str]:
        """Send alert to webhook"""
        payload = {
            'event': 'canary_triggered',
            'timestamp': event.timestamp,
            'canary_id': event.canary_id,
            'canary_type': event.canary_type,
            'source_ip': event.source_ip,
            'user_agent': event.user_agent,
            'path': event.path,
            'details': event.payload,
        }
        
        # Add canary details if available
        if event.canary_id in self.canaries:
            canary = self.canaries[event.canary_id]
            payload['memo'] = canary.get('memo', '')
        
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                return True, response.read().decode('utf-8')[:500]
                
        except urllib.error.URLError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    def record_trigger(self,
                      canary_id: str,
                      canary_type: str,
                      source_ip: str,
                      user_agent: str = "",
                      method: str = "",
                      path: str = "",
                      headers: dict = None,
                      payload: dict = None,
                      send_alert: bool = True) -> TriggerEvent:
        """
        Record a canary trigger event.
        
        Args:
            canary_id: ID of the triggered canary
            canary_type: Type of canary (for display)
            source_ip: IP address of the trigger source
            user_agent: User agent string (if HTTP)
            method: HTTP method (if applicable)
            path: Request path (if applicable)
            headers: Request headers (if applicable)
            payload: Additional trigger data
            send_alert: Whether to send webhook alert
            
        Returns:
            The created TriggerEvent
        """
        event = TriggerEvent(
            id=self._generate_event_id(),
            canary_id=canary_id,
            canary_type=canary_type,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            source_ip=source_ip,
            user_agent=user_agent,
            method=method,
            path=path,
            headers=headers or {},
            payload=payload or {},
        )
        
        with self._lock:
            self.events.append(event)
            
            # Update canary as triggered
            if canary_id in self.canaries:
                self.canaries[canary_id]['triggered'] = True
                self.canaries[canary_id]['trigger_count'] = \
                    self.canaries[canary_id].get('trigger_count', 0) + 1
                self.canaries[canary_id]['last_triggered'] = event.timestamp
            
            # Send webhook alert
            if send_alert and canary_id in self.canaries:
                webhook_url = self.canaries[canary_id].get('webhook_url')
                if webhook_url and self._should_alert(canary_id):
                    success, response = self._send_webhook(webhook_url, event)
                    event.alerted = success
                    event.alert_response = response
                    self.last_alert_time[canary_id] = time.time()
            
            self._save()
        
        # Call callback if registered
        if self.on_trigger:
            try:
                self.on_trigger(event)
            except Exception as e:
                print(f"Error in trigger callback: {e}")
        
        return event
    
    def find_canary_by_token(self, token: str) -> Optional[str]:
        """Find canary ID by token value (for tracking URLs)"""
        for canary_id, canary in self.canaries.items():
            # Check various token fields
            if canary.get('token_value') and token in canary.get('token_value', ''):
                return canary_id
            if canary.get('metadata', {}).get('token') == token:
                return canary_id
        return None
    
    def find_canary_by_aws_key(self, access_key_id: str) -> Optional[str]:
        """Find canary ID by AWS access key ID"""
        for canary_id, canary in self.canaries.items():
            if canary.get('type') == 'aws-key' and canary.get('token_value') == access_key_id:
                return canary_id
        return None
    
    def find_canary_by_credential(self, username: str = None, password: str = None) -> Optional[str]:
        """Find canary ID by credential username or password"""
        for canary_id, canary in self.canaries.items():
            if canary.get('type') != 'credential':
                continue
            if username and canary.get('username') == username:
                return canary_id
            if password and canary.get('password') == password:
                return canary_id
        return None
    
    def scan_for_aws_keys(self, text: str, source_ip: str = "scanner") -> List[TriggerEvent]:
        """
        Scan text for AWS canary keys.
        
        Useful for scanning CloudTrail logs, application logs, etc.
        
        Args:
            text: Text to scan for AWS key patterns
            source_ip: Source to attribute the trigger to
            
        Returns:
            List of trigger events for any found canary keys
        """
        events = []
        
        # AWS access key pattern
        key_pattern = r'AKIA[0-9A-Z]{16}'
        
        for match in re.finditer(key_pattern, text):
            access_key = match.group()
            canary_id = self.find_canary_by_aws_key(access_key)
            
            if canary_id:
                event = self.record_trigger(
                    canary_id=canary_id,
                    canary_type='aws-key',
                    source_ip=source_ip,
                    payload={
                        'access_key_id': access_key,
                        'context': text[max(0, match.start()-50):match.end()+50]
                    }
                )
                events.append(event)
        
        return events
    
    def get_events(self,
                  canary_id: str = None,
                  since: str = None,
                  limit: int = 100) -> List[TriggerEvent]:
        """
        Get trigger events with filtering.
        
        Args:
            canary_id: Filter by canary ID
            since: ISO timestamp to filter events after
            limit: Maximum events to return
            
        Returns:
            List of matching events (newest first)
        """
        result = list(reversed(self.events))
        
        if canary_id:
            result = [e for e in result if e.canary_id == canary_id]
        
        if since:
            result = [e for e in result if e.timestamp > since]
        
        return result[:limit]
    
    def get_dashboard_data(self) -> dict:
        """
        Get summary data for dashboard display.
        
        Returns dict with:
        - total_canaries: Total canary count
        - triggered_canaries: Count of triggered canaries
        - total_events: Total trigger events
        - events_24h: Events in last 24 hours
        - top_sources: Most active source IPs
        - recent_events: Last 10 events
        """
        now = datetime.utcnow()
        day_ago = (now.timestamp() - 86400)
        
        # Count events in last 24h
        events_24h = [e for e in self.events 
                     if datetime.fromisoformat(e.timestamp.rstrip('Z')).timestamp() > day_ago]
        
        # Top source IPs
        source_counts: Dict[str, int] = {}
        for event in self.events:
            source_counts[event.source_ip] = source_counts.get(event.source_ip, 0) + 1
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Triggered canaries
        triggered = [c for c in self.canaries.values() if c.get('triggered')]
        
        return {
            'timestamp': now.isoformat() + 'Z',
            'total_canaries': len(self.canaries),
            'triggered_canaries': len(triggered),
            'total_events': len(self.events),
            'events_24h': len(events_24h),
            'top_sources': [{'ip': ip, 'count': count} for ip, count in top_sources],
            'recent_events': [e.to_dict() for e in list(reversed(self.events))[:10]],
            'canaries_by_type': self._count_by_type(),
        }
    
    def _count_by_type(self) -> dict:
        """Count canaries by type"""
        counts = {}
        for canary in self.canaries.values():
            t = canary.get('type', 'unknown')
            counts[t] = counts.get(t, 0) + 1
        return counts


class TrackingHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for tracking URL canaries"""
    
    tracker: CanaryTracker = None  # Set by server
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_HEAD(self):
        self._handle_request('HEAD')
    
    def _handle_request(self, method: str):
        """Handle tracking URL request"""
        # Extract token from path
        path_parts = self.path.strip('/').split('/')
        token = path_parts[-1] if path_parts else ''
        
        # Remove query string
        if '?' in token:
            token = token.split('?')[0]
        
        # Find matching canary
        canary_id = self.tracker.find_canary_by_token(token) if self.tracker else None
        
        # Get client IP
        client_ip = self.headers.get('X-Forwarded-For', self.client_address[0])
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # Record trigger
        if canary_id and self.tracker:
            self.tracker.record_trigger(
                canary_id=canary_id,
                canary_type='tracking-url',
                source_ip=client_ip,
                user_agent=self.headers.get('User-Agent', ''),
                method=method,
                path=self.path,
                headers=dict(self.headers),
            )
        
        # Send response (look like a normal page)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        response = b"""<!DOCTYPE html>
<html>
<head><title>Page Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body>
</html>"""
        self.wfile.write(response)


class TrackingServer:
    """HTTP server for tracking URL canaries"""
    
    def __init__(self, tracker: CanaryTracker, host: str = '0.0.0.0', port: int = 8080):
        self.tracker = tracker
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the tracking server in a background thread"""
        TrackingHTTPHandler.tracker = self.tracker
        self.server = HTTPServer((self.host, self.port), TrackingHTTPHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"🕵️ Tracking server started on {self.host}:{self.port}")
    
    def stop(self):
        """Stop the tracking server"""
        if self.server:
            self.server.shutdown()
            self.server = None


def main():
    """CLI entry point for tracker"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Honey Claw - Canary Tracker")
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start tracking server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    server_parser.add_argument('--port', '-p', type=int, default=8080, help='Port')
    
    # Events command
    events_parser = subparsers.add_parser('events', help='List trigger events')
    events_parser.add_argument('--canary', '-c', help='Filter by canary ID')
    events_parser.add_argument('--limit', '-n', type=int, default=20, help='Max events')
    
    # Dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Show dashboard summary')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan file for canary tokens')
    scan_parser.add_argument('file', help='File to scan')
    scan_parser.add_argument('--source', default='file-scan', help='Source label')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    tracker = CanaryTracker()
    
    if args.command == 'server':
        server = TrackingServer(tracker, args.host, args.port)
        server.start()
        print("Press Ctrl+C to stop...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping server...")
            server.stop()
    
    elif args.command == 'events':
        events = tracker.get_events(canary_id=args.canary, limit=args.limit)
        
        if not events:
            print("No events found.")
            return 0
        
        print(f"{'Timestamp':<25} {'Canary ID':<20} {'Type':<15} {'Source IP':<18} {'Alerted'}")
        print("-" * 90)
        for e in events:
            alerted = "✅" if e.alerted else "❌"
            print(f"{e.timestamp:<25} {e.canary_id:<20} {e.canary_type:<15} {e.source_ip:<18} {alerted}")
    
    elif args.command == 'dashboard':
        data = tracker.get_dashboard_data()
        
        print("=" * 60)
        print("           🍯 HONEY CLAW CANARY DASHBOARD")
        print("=" * 60)
        print(f"\n📊 Overview (as of {data['timestamp'][:19]})")
        print(f"   Total Canaries:     {data['total_canaries']}")
        print(f"   Triggered:          {data['triggered_canaries']} 🚨" if data['triggered_canaries'] else f"   Triggered:          {data['triggered_canaries']}")
        print(f"   Total Events:       {data['total_events']}")
        print(f"   Events (24h):       {data['events_24h']}")
        
        if data['canaries_by_type']:
            print("\n📁 Canaries by Type:")
            for t, count in data['canaries_by_type'].items():
                print(f"   {t}: {count}")
        
        if data['top_sources']:
            print("\n🔍 Top Source IPs:")
            for item in data['top_sources'][:5]:
                print(f"   {item['ip']}: {item['count']} events")
        
        if data['recent_events']:
            print("\n📋 Recent Events:")
            for e in data['recent_events'][:5]:
                print(f"   [{e['timestamp'][:19]}] {e['canary_type']} from {e['source_ip']}")
        
        print("\n" + "=" * 60)
    
    elif args.command == 'scan':
        try:
            with open(args.file, 'r') as f:
                content = f.read()
            
            events = tracker.scan_for_aws_keys(content, source_ip=args.source)
            
            if events:
                print(f"🚨 Found {len(events)} canary triggers!")
                for e in events:
                    print(f"   AWS Key: {e.payload.get('access_key_id')} (Canary: {e.canary_id})")
            else:
                print("No canary tokens found in file.")
                
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
