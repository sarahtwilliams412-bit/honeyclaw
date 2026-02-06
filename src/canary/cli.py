#!/usr/bin/env python3
"""
Honey Claw - Canary Token CLI
Unified CLI for canary token management.

Usage:
    honeyclaw canary create --type aws-key --webhook https://hooks.example.com/alert
    honeyclaw canary create --type tracking-url --webhook https://hooks.example.com/alert
    honeyclaw canary list
    honeyclaw canary show <id>
    honeyclaw canary dashboard
    honeyclaw canary server --port 8080
"""
import sys
import argparse

from .generator import CanaryGenerator, CanaryType
from .tracker import CanaryTracker, TrackingServer


def cmd_create(args, generator: CanaryGenerator):
    """Create a new canary token"""
    try:
        if args.type == 'aws-key':
            canary = generator.create_aws_key(
                webhook_url=args.webhook,
                memo=args.memo
            )
        elif args.type == 'tracking-url':
            canary = generator.create_tracking_url(
                webhook_url=args.webhook,
                memo=args.memo,
                path_hint=getattr(args, 'path_hint', '') or ''
            )
        elif args.type == 'dns':
            canary = generator.create_dns_canary(
                webhook_url=args.webhook,
                memo=args.memo
            )
        elif args.type == 'credential':
            canary = generator.create_credential(
                username=getattr(args, 'username', None),
                password=getattr(args, 'password', None),
                webhook_url=args.webhook,
                memo=args.memo
            )
        elif args.type == 'webhook':
            canary = generator.create_webhook_token(
                webhook_url=args.webhook,
                memo=args.memo
            )
        else:
            print(f"❌ Unknown type: {args.type}")
            return 1
        
        print("✅ Canary created successfully!\n")
        print(canary.display())
        
        # Output machine-readable format if requested
        if getattr(args, 'json', False):
            import json
            print("\n--- JSON ---")
            print(json.dumps(canary.to_dict(), indent=2))
        
        return 0
        
    except ValueError as e:
        print(f"❌ Error: {e}")
        return 1


def cmd_list(args, generator: CanaryGenerator):
    """List canary tokens"""
    canary_type = CanaryType(args.type) if args.type else None
    canaries = generator.list_canaries(
        canary_type=canary_type,
        triggered_only=args.triggered
    )
    
    if not canaries:
        print("No canaries found.")
        return 0
    
    print(f"{'ID':<20} {'Type':<15} {'Memo':<30} {'Triggered'}")
    print("-" * 75)
    for c in canaries:
        triggered = "🚨 YES" if c.triggered else "No"
        memo = (c.memo[:27] + "...") if len(c.memo) > 30 else c.memo
        print(f"{c.id:<20} {c.type.value:<15} {memo:<30} {triggered}")
    
    print(f"\nTotal: {len(canaries)} canaries")
    return 0


def cmd_show(args, generator: CanaryGenerator):
    """Show canary details"""
    canary = generator.get(args.id)
    if canary:
        print(canary.display())
        return 0
    else:
        print(f"❌ Canary not found: {args.id}")
        return 1


def cmd_delete(args, generator: CanaryGenerator):
    """Delete a canary"""
    if generator.delete(args.id):
        print(f"✅ Deleted canary: {args.id}")
        return 0
    else:
        print(f"❌ Canary not found: {args.id}")
        return 1


def cmd_generate_files(args, generator: CanaryGenerator):
    """Generate honeypot files with embedded canaries"""
    if args.webhook:
        generator.default_webhook = args.webhook
    
    try:
        files = generator.generate_honeypot_files(output_dir=args.output)
        print(f"✅ Generated {len(files)} honeypot files:")
        for path in sorted(files.keys()):
            print(f"  📄 {path}")
        if args.output:
            print(f"\nFiles written to: {args.output}")
        return 0
    except ValueError as e:
        print(f"❌ Error: {e}")
        return 1


def cmd_dashboard(args, tracker: CanaryTracker):
    """Show canary dashboard"""
    data = tracker.get_dashboard_data()
    
    print("=" * 60)
    print("           🍯 HONEY CLAW CANARY DASHBOARD")
    print("=" * 60)
    print(f"\n📊 Overview (as of {data['timestamp'][:19]})")
    print(f"   Total Canaries:     {data['total_canaries']}")
    triggered_line = f"   Triggered:          {data['triggered_canaries']} 🚨" if data['triggered_canaries'] else f"   Triggered:          {data['triggered_canaries']}"
    print(triggered_line)
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
    return 0


def cmd_events(args, tracker: CanaryTracker):
    """List trigger events"""
    events = tracker.get_events(canary_id=args.canary, limit=args.limit)
    
    if not events:
        print("No events found.")
        return 0
    
    print(f"{'Timestamp':<25} {'Canary ID':<20} {'Type':<15} {'Source IP':<18} {'Alerted'}")
    print("-" * 90)
    for e in events:
        alerted = "✅" if e.alerted else "❌"
        print(f"{e.timestamp:<25} {e.canary_id:<20} {e.canary_type:<15} {e.source_ip:<18} {alerted}")
    
    print(f"\nTotal: {len(events)} events")
    return 0


def cmd_server(args, tracker: CanaryTracker):
    """Start the tracking server"""
    import time
    
    server = TrackingServer(tracker, args.host, args.port)
    server.start()
    print("Press Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()
    return 0


def main(argv=None):
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='honeyclaw canary',
        description="🍯 Honey Claw - Canary Token Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create an AWS key canary:
    honeyclaw canary create --type aws-key --webhook https://hooks.example.com/alert

  Create a tracking URL canary:
    honeyclaw canary create --type tracking-url --webhook https://hooks.example.com/alert --memo "Hidden in fake docs"

  Create fake credentials:
    honeyclaw canary create --type credential --webhook https://hooks.example.com/alert

  List all canaries:
    honeyclaw canary list

  Show dashboard:
    honeyclaw canary dashboard

  Start tracking server:
    honeyclaw canary server --port 8080

  Generate honeypot files:
    honeyclaw canary generate-files --output /path/to/honeypot --webhook https://hooks.example.com/alert
        """
    )
    
    parser.add_argument('--storage', help='Path to canary storage file')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new canary token')
    create_parser.add_argument('--type', '-t', required=True,
                              choices=['aws-key', 'tracking-url', 'dns', 'credential', 'webhook'],
                              help='Type of canary to create')
    create_parser.add_argument('--webhook', '-w', help='Webhook URL for alerts')
    create_parser.add_argument('--memo', '-m', default='', help='Description/note')
    create_parser.add_argument('--username', help='Username (for credential type)')
    create_parser.add_argument('--password', help='Password (for credential type)')
    create_parser.add_argument('--path-hint', help='URL path hint (for tracking-url type)')
    create_parser.add_argument('--json', action='store_true', help='Output JSON format')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List canary tokens')
    list_parser.add_argument('--type', '-t', 
                            choices=['aws-key', 'tracking-url', 'dns', 'credential', 'webhook'],
                            help='Filter by type')
    list_parser.add_argument('--triggered', action='store_true', help='Show only triggered canaries')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show canary details')
    show_parser.add_argument('id', help='Canary ID')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a canary')
    delete_parser.add_argument('id', help='Canary ID')
    
    # Generate files command
    gen_parser = subparsers.add_parser('generate-files', help='Generate honeypot files with canaries')
    gen_parser.add_argument('--output', '-o', help='Output directory')
    gen_parser.add_argument('--webhook', '-w', help='Webhook URL for alerts')
    
    # Dashboard command
    subparsers.add_parser('dashboard', help='Show canary dashboard')
    
    # Events command
    events_parser = subparsers.add_parser('events', help='List trigger events')
    events_parser.add_argument('--canary', '-c', help='Filter by canary ID')
    events_parser.add_argument('--limit', '-n', type=int, default=20, help='Max events')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start tracking server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Bind address')
    server_parser.add_argument('--port', '-p', type=int, default=8080, help='Port')
    
    args = parser.parse_args(argv)
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Initialize components
    storage_path = args.storage if hasattr(args, 'storage') and args.storage else None
    generator = CanaryGenerator(storage_path=storage_path)
    tracker = CanaryTracker(canary_storage_path=storage_path)
    
    # Route to command handler
    if args.command == 'create':
        return cmd_create(args, generator)
    elif args.command == 'list':
        return cmd_list(args, generator)
    elif args.command == 'show':
        return cmd_show(args, generator)
    elif args.command == 'delete':
        return cmd_delete(args, generator)
    elif args.command == 'generate-files':
        return cmd_generate_files(args, generator)
    elif args.command == 'dashboard':
        return cmd_dashboard(args, tracker)
    elif args.command == 'events':
        return cmd_events(args, tracker)
    elif args.command == 'server':
        return cmd_server(args, tracker)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
