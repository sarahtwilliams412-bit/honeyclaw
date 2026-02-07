#!/usr/bin/env python3
"""
Honeyclaw CLI - Main entry point
"""

import argparse
import asyncio
import json
import os
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.replay.storage import LocalStorage, S3Storage, RecordingInfo
from src.replay.player import SessionPlayer


def get_storage():
    """Get the configured storage backend"""
    storage_type = os.environ.get('HONEYCLAW_STORAGE', 'local')
    
    if storage_type == 's3':
        bucket = os.environ.get('HONEYCLAW_S3_BUCKET')
        if not bucket:
            print("Error: HONEYCLAW_S3_BUCKET environment variable required for S3 storage", file=sys.stderr)
            sys.exit(1)
        return S3Storage(
            bucket=bucket,
            prefix=os.environ.get('HONEYCLAW_S3_PREFIX', 'recordings/'),
            region=os.environ.get('AWS_REGION', 'us-east-1'),
            endpoint_url=os.environ.get('HONEYCLAW_S3_ENDPOINT')
        )
    else:
        base_path = os.environ.get('HONEYCLAW_RECORDINGS_PATH', '/var/lib/honeyclaw/recordings')
        return LocalStorage(base_path)


def format_table(headers: list, rows: list, max_widths: Optional[dict] = None) -> str:
    """Format data as a table"""
    if not rows:
        return "No recordings found."
    
    # Calculate column widths
    widths = {h: len(h) for h in headers}
    for row in rows:
        for i, h in enumerate(headers):
            val = str(row[i]) if i < len(row) else ""
            widths[h] = max(widths[h], len(val))
    
    # Apply max widths
    if max_widths:
        for h, max_w in max_widths.items():
            if h in widths:
                widths[h] = min(widths[h], max_w)
    
    # Build table
    header_line = " | ".join(h.ljust(widths[h]) for h in headers)
    separator = "-+-".join("-" * widths[h] for h in headers)
    
    lines = [header_line, separator]
    for row in rows:
        cells = []
        for i, h in enumerate(headers):
            val = str(row[i]) if i < len(row) else ""
            if len(val) > widths[h]:
                val = val[:widths[h]-3] + "..."
            cells.append(val.ljust(widths[h]))
        lines.append(" | ".join(cells))
    
    return "\n".join(lines)


def cmd_replay_list(args):
    """List recorded sessions"""
    storage = get_storage()
    
    recordings = storage.list_recordings(
        protocol=args.protocol,
        source_ip=args.ip,
        limit=args.limit,
        offset=args.offset
    )
    
    if args.json:
        print(json.dumps([r.to_dict() for r in recordings], indent=2))
        return
    
    if not recordings:
        print("No recordings found.")
        return
    
    headers = ["Session ID", "Protocol", "Source IP", "Username", "Duration", "Events", "Time"]
    rows = []
    for r in recordings:
        # Format time
        try:
            dt = datetime.fromisoformat(r.start_time.replace('Z', '+00:00'))
            time_str = dt.strftime('%Y-%m-%d %H:%M')
        except:
            time_str = r.start_time[:16] if r.start_time else "?"
        
        rows.append([
            r.session_id[:12] + "...",
            r.protocol,
            r.source_ip,
            r.username or "-",
            r._format_duration(),
            str(r.event_count),
            time_str
        ])
    
    print(format_table(headers, rows))
    print(f"\nTotal: {len(recordings)} recording(s)")


def cmd_replay_show(args):
    """Show/play a recorded session"""
    storage = get_storage()
    
    # Try to find the session
    session_id = args.session_id
    
    # Allow partial ID match
    all_recordings = storage.list_recordings(limit=1000)
    matches = [r for r in all_recordings if r.session_id.startswith(session_id)]
    
    if not matches:
        print(f"Error: No recording found matching '{session_id}'", file=sys.stderr)
        sys.exit(1)
    
    if len(matches) > 1:
        print(f"Error: Multiple recordings match '{session_id}':", file=sys.stderr)
        for m in matches[:5]:
            print(f"  {m.session_id}", file=sys.stderr)
        sys.exit(1)
    
    recording_info = matches[0]
    full_session_id = recording_info.session_id
    
    if args.web:
        # Launch web player
        launch_web_player(storage, full_session_id, args.port)
    elif args.export:
        # Export recording
        export_recording(storage, full_session_id, args.export)
    else:
        # Console playback
        console_playback(storage, full_session_id, args.speed)


def console_playback(storage, session_id: str, speed: float):
    """Play back session in console"""
    import time
    
    recording = storage.load(session_id)
    player = SessionPlayer()
    player.load_from_dict(recording)
    player.set_speed(speed)
    
    print(f"Playing session {session_id}")
    print(f"Protocol: {player.protocol}")
    print(f"Duration: {player.duration_ms / 1000:.1f}s at {speed}x speed")
    print("-" * 60)
    
    try:
        for event in player.stream_events(realtime=True):
            if event.event_type == 'output':
                sys.stdout.write(event.data)
                sys.stdout.flush()
            elif event.event_type == 'input':
                # Show input in different color
                sys.stdout.write(f"\033[33m{event.data}\033[0m")
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n\n[Playback stopped]")
    
    print("\n" + "-" * 60)
    print("[End of recording]")


def export_recording(storage, session_id: str, output_path: str):
    """Export recording to file"""
    recording = storage.load(session_id)
    metadata = recording.get('metadata', {})
    protocol = metadata.get('protocol', 'ssh')
    
    output_path = Path(output_path)
    
    # Determine format
    if output_path.suffix == '.cast' or protocol == 'ssh':
        player = SessionPlayer()
        player.load_from_dict(recording)
        
        # Write asciinema format
        header = recording.get('header', {})
        events = recording.get('events', [])
        
        with open(output_path, 'w') as f:
            f.write(json.dumps(header) + '\n')
            for event in events:
                f.write(json.dumps(event) + '\n')
        
        print(f"Exported to {output_path} (asciinema format)")
    else:
        # Write HAR format
        with open(output_path, 'w') as f:
            json.dump(recording.get('har', recording), f, indent=2)
        
        print(f"Exported to {output_path} (HAR format)")


def launch_web_player(storage, session_id: str, port: int):
    """Launch web-based replay player"""
    import http.server
    import socketserver
    import threading
    import urllib.parse
    
    # Get the recording
    recording = storage.load(session_id)
    info = storage.get_info(session_id)
    
    # Get dashboard path
    dashboard_path = Path(__file__).parent.parent.parent / "dashboard" / "replay"
    
    if not dashboard_path.exists():
        print(f"Error: Dashboard not found at {dashboard_path}", file=sys.stderr)
        sys.exit(1)
    
    class ReplayHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(dashboard_path), **kwargs)
        
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            
            if parsed.path == '/api/recording':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                # Convert to player format
                player = SessionPlayer()
                player.load_from_dict(recording)
                self.wfile.write(json.dumps(player.to_json()).encode())
                
            elif parsed.path == '/api/info':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(info.to_dict()).encode())
                
            elif parsed.path == '/api/cast':
                # Return raw asciinema format for asciinema-player
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-ndjson')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                header = recording.get('header', {})
                events = recording.get('events', [])
                self.wfile.write((json.dumps(header) + '\n').encode())
                for event in events:
                    self.wfile.write((json.dumps(event) + '\n').encode())
            else:
                super().do_GET()
        
        def log_message(self, format, *args):
            pass  # Suppress logging
    
    with socketserver.TCPServer(("", port), ReplayHandler) as httpd:
        url = f"http://localhost:{port}/"
        print(f"Replay player running at {url}")
        print(f"Session: {session_id}")
        print("Press Ctrl+C to stop")
        
        # Open browser
        webbrowser.open(url)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")


def cmd_replay_info(args):
    """Show detailed info about a recording"""
    storage = get_storage()
    
    # Find session
    all_recordings = storage.list_recordings(limit=1000)
    matches = [r for r in all_recordings if r.session_id.startswith(args.session_id)]
    
    if not matches:
        print(f"Error: No recording found matching '{args.session_id}'", file=sys.stderr)
        sys.exit(1)
    
    info = matches[0]
    
    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
        return
    
    print(f"Session ID:   {info.session_id}")
    print(f"Protocol:     {info.protocol}")
    print(f"Source IP:    {info.source_ip}")
    print(f"Username:     {info.username or '-'}")
    print(f"Start Time:   {info.start_time}")
    print(f"Duration:     {info.duration_ms / 1000:.1f}s ({info._format_duration()})")
    print(f"Events:       {info.event_count}")
    print(f"File Size:    {info._format_size()}")
    print(f"File Path:    {info.file_path}")
    if info.share_token:
        print(f"Share Token:  {info.share_token}")


def cmd_replay_share(args):
    """Create or revoke share token for a recording"""
    storage = get_storage()
    
    # Find session
    all_recordings = storage.list_recordings(limit=1000)
    matches = [r for r in all_recordings if r.session_id.startswith(args.session_id)]
    
    if not matches:
        print(f"Error: No recording found matching '{args.session_id}'", file=sys.stderr)
        sys.exit(1)
    
    full_session_id = matches[0].session_id
    
    if args.revoke:
        # Revoke existing token
        info = storage.get_info(full_session_id)
        if info and info.share_token:
            if hasattr(storage, 'revoke_share_token'):
                storage.revoke_share_token(info.share_token)
                print(f"Share token revoked for {full_session_id}")
            else:
                print("Storage backend does not support token revocation")
        else:
            print("No share token exists for this recording")
    else:
        # Create share token
        token = storage.create_share_token(full_session_id)
        base_url = os.environ.get('HONEYCLAW_BASE_URL', 'http://localhost:8080')
        share_url = f"{base_url}/replay/shared/{token}"
        
        print(f"Share Token: {token}")
        print(f"Share URL:   {share_url}")


def cmd_replay_delete(args):
    """Delete a recording"""
    storage = get_storage()
    
    # Find session
    all_recordings = storage.list_recordings(limit=1000)
    matches = [r for r in all_recordings if r.session_id.startswith(args.session_id)]
    
    if not matches:
        print(f"Error: No recording found matching '{args.session_id}'", file=sys.stderr)
        sys.exit(1)
    
    full_session_id = matches[0].session_id
    
    if not args.force:
        confirm = input(f"Delete recording {full_session_id}? [y/N] ").strip().lower()
        if confirm != 'y':
            print("Cancelled")
            return
    
    if storage.delete(full_session_id):
        print(f"Deleted: {full_session_id}")
    else:
        print(f"Failed to delete: {full_session_id}")


# === Report Commands ===

def cmd_report(args):
    """Report an IP address to abuse databases"""
    from src.reporting import ReportingEngine, ReportingConfig
    
    # Build config from args
    config = ReportingConfig(
        enabled=True,
        min_severity='low' if args.force else 'high',
        cooldown_hours=0 if args.force else 24,
        providers=args.providers.split(',') if args.providers else ['abuseipdb'],
        honeypot_id=os.environ.get('HONEYPOT_ID', 'honeyclaw'),
    )
    
    engine = ReportingEngine(config=config)
    
    # Check provider status
    if not engine.providers:
        print("Error: No reporting providers configured.", file=sys.stderr)
        print("Set ABUSEIPDB_API_KEY environment variable for AbuseIPDB reporting.", file=sys.stderr)
        sys.exit(1)
    
    async def do_report():
        if args.dry_run:
            print(f"[DRY RUN] Would report {args.ip}")
            print(f"  Reason: {args.reason}")
            print(f"  Providers: {list(engine.providers.keys())}")
            return
        
        results = await engine.report_ip(
            ip=args.ip,
            reason=args.reason,
            force=args.force,
        )
        
        if not results:
            print(f"Report filtered - IP may have been recently reported or classified as benign.")
            print("Use --force to bypass filters.")
            return
        
        for result in results:
            if result.success:
                print(f"✓ Reported to {result.provider}: {result.message}")
            else:
                print(f"✗ Failed to report to {result.provider}: {result.error}")
    
    asyncio.run(do_report())


def cmd_report_status(args):
    """Show reporting system status"""
    from src.reporting import ReportingEngine
    
    engine = ReportingEngine()
    stats = engine.get_stats()
    
    if args.json:
        print(json.dumps(stats, indent=2))
        return
    
    print("=== Honeyclaw Reporting Status ===\n")
    
    print("Configuration:")
    config = stats['config']
    print(f"  Enabled:          {config['enabled']}")
    print(f"  Min Severity:     {config['min_severity']}")
    print(f"  Cooldown:         {config['cooldown_hours']}h")
    print(f"  Require Confirm:  {config['require_confirmation']}")
    
    print("\nProviders:")
    providers = stats['providers_enabled']
    if providers:
        for p in providers:
            print(f"  ✓ {p}")
    else:
        print("  (none configured)")
    
    print("\nStatistics:")
    print(f"  Reports Submitted: {stats['reports_submitted']}")
    print(f"  Reports Filtered:  {stats['reports_filtered']}")
    print(f"  Reports Failed:    {stats['reports_failed']}")
    
    filter_stats = stats['filter_stats']
    print(f"\nFilter Status:")
    print(f"  Cached IPs:        {filter_stats['reported_ips_cached']}")
    print(f"  Today's Reports:   {filter_stats['daily_count']}/{filter_stats['daily_limit']}")


def cmd_report_log(args):
    """Show recent report audit log"""
    from src.reporting import ReportingEngine
    
    engine = ReportingEngine()
    entries = engine.get_audit_log(limit=args.limit)
    
    if args.json:
        print(json.dumps(entries, indent=2))
        return
    
    if not entries:
        print("No audit log entries found.")
        return
    
    print("=== Recent Report Audit Log ===\n")
    
    for entry in entries:
        status = "✓" if entry.get('success') else "✗"
        print(f"{status} {entry.get('timestamp', '?')}")
        print(f"  IP:       {entry.get('ip')}")
        print(f"  Event:    {entry.get('event_type')}")
        print(f"  Provider: {entry.get('provider')}")
        if entry.get('error'):
            print(f"  Error:    {entry.get('error')}")
        print()


def cmd_report_lookup(args):
    """Lookup abuse contact for an IP"""
    from src.reporting.providers.isp_abuse import ISPAbuseReporter
    
    reporter = ISPAbuseReporter()
    
    async def do_lookup():
        contact = await reporter.lookup_abuse_contact(args.ip)
        
        if args.json:
            print(json.dumps(contact.to_dict(), indent=2))
            return
        
        if contact.error:
            print(f"Error: {contact.error}")
            sys.exit(1)
        
        print(f"=== Abuse Contact for {args.ip} ===\n")
        print(f"Organization: {contact.org_name or 'Unknown'}")
        print(f"ASN:          {contact.asn or 'Unknown'}")
        print(f"Country:      {contact.country or 'Unknown'}")
        print(f"Abuse Email:  {contact.abuse_email or 'Not found'}")
        
        if contact.whois_raw and args.verbose:
            print(f"\n=== Raw WHOIS ===\n{contact.whois_raw[:2000]}")
    
    asyncio.run(do_lookup())


# === Logs Commands ===

def cmd_logs_correlations(args):
    """Show active correlation sessions"""
    from src.utils.correlation import get_correlation_engine

    engine = get_correlation_engine()
    sessions = engine.get_active_sessions()

    if args.json:
        print(json.dumps([s.to_dict() for s in sessions], indent=2))
        return

    if not sessions:
        print("No active correlation sessions.")
        return

    headers = ["Source IP", "Correlation ID", "First Seen", "Last Seen", "Events", "Services"]
    rows = []
    for session in sessions:
        rows.append([
            session.source_ip,
            session.correlation_id,
            datetime.fromtimestamp(session.first_seen).strftime('%H:%M:%S'),
            datetime.fromtimestamp(session.last_seen).strftime('%H:%M:%S'),
            str(session.event_count),
            ", ".join(session.services) if session.services else "-",
        ])

    print(format_table(headers, rows))
    print(f"\nActive sessions: {len(sessions)}")


def cmd_logs_stats(args):
    """Show enhanced logging pipeline statistics"""
    stats = {}

    try:
        from src.utils.correlation import get_correlation_engine
        stats["correlation"] = get_correlation_engine().get_stats()
    except Exception as e:
        stats["correlation"] = {"error": str(e)}

    try:
        from src.utils.geoip import get_geoip
        geoip = get_geoip()
        stats["geoip"] = {"enabled": geoip.enabled}
    except Exception as e:
        stats["geoip"] = {"error": str(e)}

    try:
        from src.integrations.immutable_storage import ImmutableLogStore
        store = ImmutableLogStore()
        stats["immutable_storage"] = store.get_stats()
    except Exception as e:
        stats["immutable_storage"] = {"error": str(e)}

    try:
        from src.logging.backup import get_backup_stream
        stats["backup_stream"] = get_backup_stream().get_stats()
    except Exception as e:
        stats["backup_stream"] = {"error": str(e)}

    if args.json:
        print(json.dumps(stats, indent=2))
        return

    print("=== Honeyclaw Enhanced Logging Status ===\n")

    # Correlation
    corr = stats.get("correlation", {})
    print("Correlation IDs:")
    if "error" in corr:
        print(f"  Error: {corr['error']}")
    else:
        print(f"  Active sessions:   {corr.get('active_sessions', 0)}")
        print(f"  Total sessions:    {corr.get('total_sessions', 0)}")
        print(f"  Events correlated: {corr.get('total_events_correlated', 0)}")
        print(f"  Multi-service:     {corr.get('multi_service_sessions', 0)}")
        print(f"  Window:            {corr.get('correlation_window_seconds', 0)}s")

    # GeoIP
    geo = stats.get("geoip", {})
    print(f"\nGeolocation:")
    if "error" in geo:
        print(f"  Error: {geo['error']}")
    else:
        print(f"  Enabled: {geo.get('enabled', False)}")

    # Immutable storage
    imm = stats.get("immutable_storage", {})
    print(f"\nImmutable Storage:")
    if "error" in imm:
        print(f"  Error: {imm['error']}")
    else:
        print(f"  Enabled:        {imm.get('enabled', False)}")
        if imm.get("enabled"):
            print(f"  Bucket:         {imm.get('bucket')}")
            print(f"  Retention:      {imm.get('retention_days')}d ({imm.get('retention_mode')})")
            print(f"  Events shipped: {imm.get('events_shipped', 0)}")
            print(f"  Objects:        {imm.get('objects_uploaded', 0)}")
            print(f"  Bytes:          {imm.get('bytes_uploaded', 0)}")
            print(f"  Errors:         {imm.get('upload_errors', 0)}")

    # Backup
    bak = stats.get("backup_stream", {})
    print(f"\nBackup Stream:")
    if "error" in bak:
        print(f"  Error: {bak['error']}")
    else:
        print(f"  Enabled:  {bak.get('enabled', False)}")
        if bak.get("enabled"):
            print(f"  Backend:  {bak.get('backend')}")
            print(f"  Shipped:  {bak.get('events_shipped', 0)}")
            print(f"  Dropped:  {bak.get('events_dropped', 0)}")
            print(f"  Errors:   {bak.get('ship_errors', 0)}")


def cmd_logs_setup_immutable(args):
    """Set up S3 bucket for immutable log storage"""
    from src.integrations.immutable_storage import ImmutableLogStore

    store = ImmutableLogStore()
    if not store.enabled:
        print("Error: Immutable storage not configured.", file=sys.stderr)
        print("Set IMMUTABLE_S3_BUCKET environment variable.", file=sys.stderr)
        sys.exit(1)

    print(f"Setting up immutable storage on s3://{store.config.bucket}/")
    print(f"  Retention: {store.config.retention_days} days ({store.config.retention_mode})")
    print(f"  Versioning: {'enabled' if store.config.versioning_enabled else 'disabled'}")

    if not args.force:
        confirm = input("\nProceed? [y/N] ").strip().lower()
        if confirm != 'y':
            print("Cancelled")
            return

    results = store.setup_bucket()
    print("\nResults:")
    print(json.dumps(results, indent=2, default=str))


def cmd_logs_verify(args):
    """Verify integrity of a stored log object"""
    from src.integrations.immutable_storage import ImmutableLogStore

    store = ImmutableLogStore()
    if not store.enabled:
        print("Error: Immutable storage not configured.", file=sys.stderr)
        sys.exit(1)

    result = store.verify_integrity(args.key)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)

    print(f"Key:             {result.get('key')}")
    print(f"Version:         {result.get('version_id', 'N/A')}")
    print(f"Size:            {result.get('content_length', 0)} bytes")
    print(f"ETag:            {result.get('etag', 'N/A')}")
    print(f"Last Modified:   {result.get('last_modified', 'N/A')}")
    print(f"Immutable:       {result.get('immutable', False)}")
    if result.get("immutable"):
        print(f"Lock Mode:       {result.get('lock_mode')}")
        print(f"Retain Until:    {result.get('lock_retain_until')}")


# === Health Commands ===

def cmd_health(args):
    """Run a health check"""
    from src.health.monitor import HealthMonitor

    # Parse services
    services = {}
    if args.services:
        for svc in args.services.split(","):
            parts = svc.strip().split(":")
            if len(parts) == 2:
                services[parts[0]] = int(parts[1])

    monitor = HealthMonitor(
        honeypot_id=os.environ.get('HONEYPOT_ID', 'honeyclaw'),
        services=services,
    )

    report = asyncio.run(monitor.check())

    if args.json:
        print(report.to_json())
        return

    status_colors = {
        "healthy": "\033[32m",     # green
        "degraded": "\033[33m",    # yellow
        "compromised": "\033[31m", # red
        "unknown": "\033[90m",     # gray
    }
    reset = "\033[0m"
    color = status_colors.get(report.status.value, "")

    print(f"=== Honeyclaw Health Check ===\n")
    print(f"Status:     {color}{report.status.value.upper()}{reset}")
    print(f"Honeypot:   {report.honeypot_id}")
    print(f"Uptime:     {report.uptime_seconds:.0f}s")

    if report.services:
        print(f"\nServices:")
        for name, svc in report.services.items():
            svc_icon = "UP" if svc.status == "up" else "DOWN"
            print(f"  {name}: {svc_icon}" + (f" ({svc.reason})" if svc.reason else ""))

    if report.resources:
        r = report.resources
        print(f"\nResources:")
        print(f"  CPU:    {r.cpu_percent:.1f}%")
        print(f"  Memory: {r.memory_mb:.0f} MB ({r.memory_percent:.1f}%)")
        print(f"  Disk:   {r.disk_percent:.1f}%")
        print(f"  FDs:    {r.open_fds}")

    if report.isolation:
        iso = report.isolation
        print(f"\nIsolation:")
        print(f"  Egress blocked:       {'Yes' if iso.egress_blocked else 'NO - WARNING'}")
        print(f"  No shared creds:      {'Yes' if iso.no_shared_credentials else 'NO - WARNING'}")
        print(f"  Filesystem integrity:  {'Yes' if iso.filesystem_integrity else 'NO - WARNING'}")

    if report.compromise_indicators:
        print(f"\nCompromise Indicators ({len(report.compromise_indicators)}):")
        for ci in report.compromise_indicators:
            print(f"  [{ci.severity.upper()}] {ci.description}")


def cli():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='honeyclaw',
        description='Honeyclaw - SSH/HTTP Honeypot Framework'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # replay command group
    replay_parser = subparsers.add_parser('replay', help='Session replay commands')
    replay_subparsers = replay_parser.add_subparsers(dest='subcommand', help='Replay subcommands')
    
    # replay list
    list_parser = replay_subparsers.add_parser('list', help='List recorded sessions')
    list_parser.add_argument('--protocol', '-p', choices=['ssh', 'http'], help='Filter by protocol')
    list_parser.add_argument('--ip', '-i', help='Filter by source IP')
    list_parser.add_argument('--limit', '-l', type=int, default=50, help='Maximum results')
    list_parser.add_argument('--offset', '-o', type=int, default=0, help='Result offset')
    list_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    list_parser.set_defaults(func=cmd_replay_list)
    
    # replay show
    show_parser = replay_subparsers.add_parser('show', help='Play a recorded session')
    show_parser.add_argument('session_id', help='Session ID (or prefix)')
    show_parser.add_argument('--web', '-w', action='store_true', help='Open web player')
    show_parser.add_argument('--port', type=int, default=8765, help='Web player port')
    show_parser.add_argument('--speed', '-s', type=float, default=1.0, help='Playback speed')
    show_parser.add_argument('--export', '-e', help='Export to file')
    show_parser.set_defaults(func=cmd_replay_show)
    
    # replay info
    info_parser = replay_subparsers.add_parser('info', help='Show recording details')
    info_parser.add_argument('session_id', help='Session ID (or prefix)')
    info_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    info_parser.set_defaults(func=cmd_replay_info)
    
    # replay share
    share_parser = replay_subparsers.add_parser('share', help='Create/manage share links')
    share_parser.add_argument('session_id', help='Session ID (or prefix)')
    share_parser.add_argument('--revoke', '-r', action='store_true', help='Revoke share token')
    share_parser.set_defaults(func=cmd_replay_share)
    
    # replay delete
    delete_parser = replay_subparsers.add_parser('delete', help='Delete a recording')
    delete_parser.add_argument('session_id', help='Session ID (or prefix)')
    delete_parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation')
    delete_parser.set_defaults(func=cmd_replay_delete)
    
    # === Report command group ===
    report_parser = subparsers.add_parser('report', help='Abuse reporting commands')
    report_subparsers = report_parser.add_subparsers(dest='subcommand', help='Report subcommands')
    
    # report ip (default action when called as 'honeyclaw report <ip>')
    report_ip_parser = report_subparsers.add_parser('ip', help='Report an IP address')
    report_ip_parser.add_argument('ip', help='IP address to report')
    report_ip_parser.add_argument('--reason', '-r', required=True, help='Reason for report')
    report_ip_parser.add_argument('--providers', '-p', help='Comma-separated providers (default: abuseipdb)')
    report_ip_parser.add_argument('--force', '-f', action='store_true', help='Skip filters (cooldown, etc.)')
    report_ip_parser.add_argument('--dry-run', '-n', action='store_true', help='Show what would be reported')
    report_ip_parser.set_defaults(func=cmd_report)
    
    # report status
    report_status_parser = report_subparsers.add_parser('status', help='Show reporting status')
    report_status_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    report_status_parser.set_defaults(func=cmd_report_status)
    
    # report log
    report_log_parser = report_subparsers.add_parser('log', help='Show report audit log')
    report_log_parser.add_argument('--limit', '-l', type=int, default=20, help='Number of entries')
    report_log_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    report_log_parser.set_defaults(func=cmd_report_log)
    
    # report lookup
    report_lookup_parser = report_subparsers.add_parser('lookup', help='Lookup abuse contact for IP')
    report_lookup_parser.add_argument('ip', help='IP address to lookup')
    report_lookup_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    report_lookup_parser.add_argument('--verbose', '-v', action='store_true', help='Show raw WHOIS')
    report_lookup_parser.set_defaults(func=cmd_report_lookup)
    
    # === Logs command group ===
    logs_parser = subparsers.add_parser('logs', help='Enhanced logging commands')
    logs_subparsers = logs_parser.add_subparsers(dest='subcommand', help='Logs subcommands')

    # logs correlations
    logs_corr_parser = logs_subparsers.add_parser('correlations', help='Show active correlation sessions')
    logs_corr_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    logs_corr_parser.set_defaults(func=cmd_logs_correlations)

    # logs stats
    logs_stats_parser = logs_subparsers.add_parser('stats', help='Show logging pipeline statistics')
    logs_stats_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    logs_stats_parser.set_defaults(func=cmd_logs_stats)

    # logs setup-immutable
    logs_setup_parser = logs_subparsers.add_parser('setup-immutable', help='Set up S3 bucket for immutable storage')
    logs_setup_parser.add_argument('--force', '-f', action='store_true', help='Skip confirmation')
    logs_setup_parser.set_defaults(func=cmd_logs_setup_immutable)

    # logs verify
    logs_verify_parser = logs_subparsers.add_parser('verify', help='Verify integrity of stored log object')
    logs_verify_parser.add_argument('key', help='S3 object key to verify')
    logs_verify_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    logs_verify_parser.set_defaults(func=cmd_logs_verify)
    
    # === Health command ===
    health_parser = subparsers.add_parser('health', help='Run health check')
    health_parser.add_argument('--json', '-j', action='store_true', help='Output as JSON')
    health_parser.add_argument('--services', '-s',
                               help='Services to check (name:port,...). e.g. ssh:22,api:8080')
    health_parser.set_defaults(func=cmd_health)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == 'replay' and not args.subcommand:
        replay_parser.print_help()
        sys.exit(0)

    if args.command == 'report' and not args.subcommand:
        report_parser.print_help()
        sys.exit(0)

    if args.command == 'logs' and not args.subcommand:
        logs_parser.print_help()
        sys.exit(0)

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


def main():
    """Entry point"""
    cli()


if __name__ == '__main__':
    main()
