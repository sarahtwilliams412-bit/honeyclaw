#!/usr/bin/env python3
"""
Honeyclaw CLI - Main entry point
"""

import argparse
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    if args.command == 'replay' and not args.subcommand:
        replay_parser.print_help()
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
