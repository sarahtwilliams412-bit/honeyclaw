#!/usr/bin/env python3
"""
Honeyclaw Enrichment CLI - Manual threat intelligence lookup.

Usage:
    honeyclaw-enrich <ip>
    honeyclaw-enrich <ip> --providers abuseipdb,greynoise
    honeyclaw-enrich <ip> --json
    honeyclaw-enrich <ip> --skip-cache
    honeyclaw-enrich status
    honeyclaw-enrich cache-stats
"""

import argparse
import asyncio
import json
import sys
from typing import Optional

from .engine import EnrichmentEngine, get_engine


def format_result(result: dict, verbose: bool = False) -> str:
    """Format enrichment result for human-readable output"""
    lines = []
    
    ip = result.get("ip", "unknown")
    lines.append(f"\n{'='*60}")
    lines.append(f"  IP: {ip}")
    lines.append(f"{'='*60}")
    
    if not result.get("enriched"):
        lines.append(f"  ⚠️  Not enriched: {result.get('reason', 'Unknown')}")
        return "\n".join(lines)
    
    # Summary
    summary = result.get("summary", {})
    verdict = summary.get("verdict", "unknown")
    verdict_emoji = {
        "malicious": "🔴",
        "benign": "🟢",
        "unknown": "🟡",
        "error": "⚠️",
    }.get(verdict, "❓")
    
    lines.append(f"\n  {verdict_emoji} Verdict: {verdict.upper()}")
    lines.append(f"     Confidence: {summary.get('confidence', 0):.0%}")
    lines.append(f"     Risk Score: {summary.get('risk_score', 0)}/100")
    lines.append(f"     Verdicts: {summary.get('malicious_verdicts', 0)} malicious, "
                f"{summary.get('benign_verdicts', 0)} benign, "
                f"{summary.get('unknown_verdicts', 0)} unknown")
    
    # Categories
    categories = result.get("categories", [])
    if categories:
        lines.append(f"\n  📁 Categories: {', '.join(categories)}")
    
    # Tags (show first 10)
    tags = result.get("tags", [])
    if tags:
        display_tags = tags[:10]
        lines.append(f"\n  🏷️  Tags: {', '.join(display_tags)}")
        if len(tags) > 10:
            lines.append(f"       ... and {len(tags) - 10} more")
    
    # Provider details
    providers = result.get("providers", {})
    if providers:
        lines.append(f"\n  📊 Provider Results:")
        for name, data in providers.items():
            status = "✓" if data.get("success") else "✗"
            if data.get("success"):
                mal = data.get("is_malicious")
                mal_str = "malicious" if mal else ("benign" if mal is False else "unknown")
                conf = data.get("confidence", 0)
                lines.append(f"     {status} {name}: {mal_str} (confidence: {conf:.0%})")
                
                # Show extra details in verbose mode
                if verbose:
                    if data.get("country"):
                        lines.append(f"        Country: {data.get('country')}")
                    if data.get("isp"):
                        lines.append(f"        ISP: {data.get('isp')}")
                    if data.get("report_count"):
                        lines.append(f"        Reports: {data.get('report_count')}")
            else:
                lines.append(f"     {status} {name}: {data.get('error', 'Unknown error')}")
    
    # Errors
    errors = result.get("errors")
    if errors:
        lines.append(f"\n  ⚠️  Errors:")
        for err in errors:
            lines.append(f"     - {err}")
    
    lines.append(f"\n  🕐 Timestamp: {result.get('timestamp', 'unknown')}")
    lines.append("")
    
    return "\n".join(lines)


def format_provider_status(engine: EnrichmentEngine) -> str:
    """Format provider status for display"""
    lines = ["\n  Provider Status:"]
    lines.append("  " + "-" * 50)
    
    for name, status in engine.provider_status.items():
        enabled = "✓ enabled" if status["enabled"] else "✗ disabled (no API key)"
        free = "free tier" if status["free_tier"] else "paid"
        limit = f", {status['rate_limit_per_day']}/day" if status["rate_limit_per_day"] else ""
        lines.append(f"  {name:15} {enabled:30} ({free}{limit})")
    
    lines.append("")
    return "\n".join(lines)


def format_cache_stats(engine: EnrichmentEngine) -> str:
    """Format cache statistics for display"""
    stats = engine.get_cache_stats()
    
    lines = ["\n  Cache Statistics:"]
    lines.append("  " + "-" * 40)
    lines.append(f"  Active entries:  {stats['active_entries']}")
    lines.append(f"  Expired entries: {stats['expired_entries']}")
    lines.append(f"  Total hits:      {stats['total_hits']}")
    lines.append(f"  Max entries:     {stats['max_entries']}")
    lines.append(f"  TTL:             {stats['ttl_seconds']} seconds")
    lines.append(f"  Persistent:      {stats['persistent']}")
    
    by_provider = stats.get("by_provider", {})
    if by_provider:
        lines.append("\n  Entries by provider:")
        for provider, count in by_provider.items():
            lines.append(f"    {provider}: {count}")
    
    lines.append("")
    return "\n".join(lines)


async def run_enrichment(
    ip: str,
    providers: Optional[list] = None,
    skip_cache: bool = False,
) -> dict:
    """Run enrichment for an IP"""
    engine = get_engine()
    return await engine.enrich(ip, providers=providers, skip_cache=skip_cache)


def main():
    parser = argparse.ArgumentParser(
        description="Honeyclaw Threat Intelligence Enrichment CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  honeyclaw-enrich 185.220.101.1
  honeyclaw-enrich 185.220.101.1 --providers abuseipdb,greynoise
  honeyclaw-enrich 185.220.101.1 --json
  honeyclaw-enrich 185.220.101.1 --skip-cache
  honeyclaw-enrich status
  honeyclaw-enrich cache-stats

Environment Variables:
  ABUSEIPDB_API_KEY   - AbuseIPDB API key (free tier: 1000/day)
  GREYNOISE_API_KEY   - GreyNoise API key (community API is free)
  SHODAN_API_KEY      - Shodan API key (optional, free tier limited)
  VIRUSTOTAL_API_KEY  - VirusTotal API key (optional, 500/day)
        """
    )
    
    parser.add_argument(
        "target",
        help="IP address to enrich, or command (status, cache-stats)"
    )
    parser.add_argument(
        "-p", "--providers",
        help="Comma-separated list of providers to query"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output raw JSON instead of formatted text"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output with more details"
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Skip cache and force fresh lookups"
    )
    
    args = parser.parse_args()
    
    # Handle commands
    if args.target == "status":
        engine = get_engine()
        print(format_provider_status(engine))
        return 0
    
    if args.target == "cache-stats":
        engine = get_engine()
        print(format_cache_stats(engine))
        return 0
    
    # Validate IP format
    import re
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if not re.match(ip_pattern, args.target):
        print(f"Error: Invalid IP address format: {args.target}", file=sys.stderr)
        return 1
    
    # Parse providers
    providers = None
    if args.providers:
        providers = [p.strip() for p in args.providers.split(",")]
    
    # Run enrichment
    try:
        result = asyncio.run(
            run_enrichment(
                args.target,
                providers=providers,
                skip_cache=args.skip_cache
            )
        )
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(format_result(result, verbose=args.verbose))
        
        # Exit code based on verdict
        verdict = result.get("summary", {}).get("verdict", "unknown")
        if verdict == "malicious":
            return 2
        elif verdict == "error":
            return 1
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
