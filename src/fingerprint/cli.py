#!/usr/bin/env python3
"""
Honeyclaw Fingerprint CLI

Command-line interface for managing attacker fingerprints.

Usage:
    honeyclaw fingerprint show <attacker_id>
    honeyclaw fingerprint list [--threat-level=<level>] [--limit=<n>]
    honeyclaw fingerprint search --ip=<ip>
    honeyclaw fingerprint search --ttp=<ttp_id>
    honeyclaw fingerprint stats
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .database import FingerprintDatabase
from .engine import FingerprintEngine, AttackerProfile


def format_timestamp(ts: float) -> str:
    """Format Unix timestamp as human-readable string"""
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def format_profile_summary(profile: AttackerProfile) -> str:
    """Format profile as summary line"""
    threat_colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[33m',    # Orange
        'low': '\033[32m',       # Green
        'unknown': '\033[90m',   # Gray
    }
    reset = '\033[0m'
    
    color = threat_colors.get(profile.threat_level, '')
    return (
        f"{profile.attacker_id}  "
        f"{color}[{profile.threat_level.upper()}]{reset}  "
        f"Sessions: {profile.session_count}  "
        f"IPs: {len(profile.known_ips)}  "
        f"Last: {format_timestamp(profile.last_seen)}"
    )


def format_profile_detail(profile: AttackerProfile) -> str:
    """Format profile as detailed view"""
    lines = [
        "=" * 70,
        f"ATTACKER PROFILE: {profile.attacker_id}",
        "=" * 70,
        "",
        "Overview:",
        f"  Threat Level:    {profile.threat_level.upper()}",
        f"  Confidence:      {profile.confidence:.1%}",
        f"  First Seen:      {format_timestamp(profile.first_seen)}",
        f"  Last Seen:       {format_timestamp(profile.last_seen)}",
        f"  Sessions:        {profile.session_count}",
        "",
        "Known IPs:",
    ]
    
    for ip in profile.known_ips[:10]:  # Limit to 10
        lines.append(f"  • {ip}")
    if len(profile.known_ips) > 10:
        lines.append(f"  ... and {len(profile.known_ips) - 10} more")
    
    if profile.identified_tools:
        lines.append("")
        lines.append("Identified Tools:")
        for tool in profile.identified_tools:
            lines.append(f"  • {tool}")
    
    if profile.ttp_matches:
        lines.append("")
        lines.append("TTPs Detected:")
        for ttp in profile.ttp_matches:
            lines.append(f"  • {ttp}")
    
    if profile.threat_indicators:
        lines.append("")
        lines.append("Threat Indicators:")
        for indicator in profile.threat_indicators[:15]:
            lines.append(f"  ⚠ {indicator}")
    
    # SSH Fingerprints
    if profile.ssh_fingerprints:
        lines.append("")
        lines.append("SSH Fingerprints:")
        for i, ssh_fp in enumerate(profile.ssh_fingerprints[-3:], 1):
            lines.append(f"  [{i}] Client: {ssh_fp.client_software or 'unknown'}")
            if ssh_fp.ssh_fingerprint_hash:
                lines.append(f"      Hash: {ssh_fp.ssh_fingerprint_hash}")
            if ssh_fp.kex_algorithms:
                lines.append(f"      KEX: {', '.join(ssh_fp.kex_algorithms[:3])}...")
    
    # HTTP Fingerprints
    if profile.http_fingerprints:
        lines.append("")
        lines.append("HTTP Fingerprints:")
        for i, http_fp in enumerate(profile.http_fingerprints[-3:], 1):
            lines.append(f"  [{i}] User-Agent: {http_fp.user_agent[:60] or 'N/A'}")
            if http_fp.tls and http_fp.tls.ja3_hash:
                lines.append(f"      JA3: {http_fp.tls.ja3_hash}")
            if http_fp.header_order_hash:
                lines.append(f"      Header Order: {http_fp.header_order_hash}")
    
    # Behavior
    if profile.behavior:
        lines.append("")
        lines.append("Behavioral Fingerprint:")
        lines.append(f"  Phase Progression: {profile.behavior.phase_progression or 'unknown'}")
        lines.append(f"  Command Hash: {profile.behavior.command_sequence_hash or 'N/A'}")
        
        if profile.behavior.typing:
            lines.append(f"  Avg Keystroke Delay: {profile.behavior.typing.avg_char_delay:.0f}ms")
        
        if profile.behavior.session:
            lines.append(f"  Commands/Min: {profile.behavior.session.commands_per_minute:.1f}")
            lines.append(f"  Active Hours: ~{profile.behavior.session.time_of_day}:00")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def cmd_show(args, db: FingerprintDatabase):
    """Show detailed attacker profile"""
    profile = db.get_profile(args.attacker_id)
    
    if not profile:
        print(f"Error: Attacker '{args.attacker_id}' not found.", file=sys.stderr)
        return 1
    
    if args.json:
        print(json.dumps(profile.to_dict(), indent=2))
    else:
        print(format_profile_detail(profile))
    
    return 0


def cmd_list(args, db: FingerprintDatabase):
    """List attackers"""
    if args.threat_level:
        profiles = db.search_by_threat_level(args.threat_level, limit=args.limit)
        print(f"Attackers with threat level '{args.threat_level}':")
    else:
        profiles = db.get_recent_attackers(hours=24*30, limit=args.limit)  # Last 30 days
        print("Recent attackers:")
    
    print()
    
    if not profiles:
        print("  No attackers found.")
        return 0
    
    if args.json:
        print(json.dumps([p.to_dict() for p in profiles], indent=2))
    else:
        for profile in profiles:
            print(format_profile_summary(profile))
    
    print()
    print(f"Total: {len(profiles)} attacker(s)")
    
    return 0


def cmd_search(args, db: FingerprintDatabase):
    """Search for attackers"""
    profiles = []
    search_type = ""
    
    if args.ip:
        profiles = db.search_by_ip(args.ip, limit=args.limit)
        search_type = f"IP {args.ip}"
    elif args.ttp:
        profiles = db.search_by_ttp(args.ttp, limit=args.limit)
        search_type = f"TTP {args.ttp}"
    elif args.tool:
        # Search by tool requires scanning profiles
        all_profiles = db.get_recent_attackers(hours=24*365, limit=1000)
        for p in all_profiles:
            if any(args.tool.lower() in t.lower() for t in p.identified_tools):
                profiles.append(p)
        profiles = profiles[:args.limit]
        search_type = f"tool '{args.tool}'"
    else:
        print("Error: Specify --ip, --ttp, or --tool to search", file=sys.stderr)
        return 1
    
    print(f"Search results for {search_type}:")
    print()
    
    if not profiles:
        print("  No attackers found.")
        return 0
    
    if args.json:
        print(json.dumps([p.to_dict() for p in profiles], indent=2))
    else:
        for profile in profiles:
            print(format_profile_summary(profile))
    
    print()
    print(f"Total: {len(profiles)} attacker(s)")
    
    return 0


def cmd_stats(args, db: FingerprintDatabase):
    """Show database statistics"""
    stats = db.get_stats()
    
    if args.json:
        print(json.dumps(stats, indent=2))
        return 0
    
    print("Fingerprint Database Statistics")
    print("=" * 40)
    print(f"Total Profiles:     {stats['total_profiles']}")
    print(f"Total Fingerprints: {stats['total_fingerprints']}")
    print(f"Unique IPs:         {stats['unique_ips']}")
    print(f"Total Sessions:     {stats['total_sessions']}")
    print(f"Active (24h):       {stats['active_24h']}")
    print()
    print("By Threat Level:")
    for level, count in stats.get('by_threat_level', {}).items():
        print(f"  {level}: {count}")
    
    return 0


def cmd_correlate(args, db: FingerprintDatabase):
    """Find related attackers"""
    profile = db.get_profile(args.attacker_id)
    
    if not profile:
        print(f"Error: Attacker '{args.attacker_id}' not found.", file=sys.stderr)
        return 1
    
    engine = FingerprintEngine(database=db)
    similar = engine.find_similar_profiles(profile, limit=args.limit)
    
    print(f"Attackers similar to {args.attacker_id}:")
    print()
    
    if not similar:
        print("  No similar attackers found.")
        return 0
    
    for related_profile, similarity in similar:
        print(f"  {related_profile.attacker_id}  "
              f"Similarity: {similarity:.1%}  "
              f"IPs: {len(related_profile.known_ips)}")
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='honeyclaw fingerprint',
        description='Manage attacker fingerprints and profiles'
    )
    parser.add_argument(
        '--db', 
        default=None,
        help='Path to fingerprint database'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output in JSON format'
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # show command
    show_parser = subparsers.add_parser('show', help='Show attacker profile')
    show_parser.add_argument('attacker_id', help='Attacker ID (e.g., ATK-ABCD1234-5678)')
    
    # list command
    list_parser = subparsers.add_parser('list', help='List attackers')
    list_parser.add_argument('--threat-level', choices=['low', 'medium', 'high', 'critical'])
    list_parser.add_argument('--limit', type=int, default=20)
    
    # search command
    search_parser = subparsers.add_parser('search', help='Search for attackers')
    search_parser.add_argument('--ip', help='Search by IP address')
    search_parser.add_argument('--ttp', help='Search by TTP ID')
    search_parser.add_argument('--tool', help='Search by tool name')
    search_parser.add_argument('--limit', type=int, default=20)
    
    # stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    
    # correlate command
    correlate_parser = subparsers.add_parser('correlate', help='Find related attackers')
    correlate_parser.add_argument('attacker_id', help='Attacker ID to find similar profiles for')
    correlate_parser.add_argument('--limit', type=int, default=10)
    
    args = parser.parse_args()
    
    # Initialize database
    db = FingerprintDatabase(args.db)
    
    # Route to command handler
    commands = {
        'show': cmd_show,
        'list': cmd_list,
        'search': cmd_search,
        'stats': cmd_stats,
        'correlate': cmd_correlate,
    }
    
    handler = commands.get(args.command)
    if handler:
        return handler(args, db)
    
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
