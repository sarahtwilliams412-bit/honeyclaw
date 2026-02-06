#!/usr/bin/env python3
"""
Honey Claw - Canary Token Generator
Generate various types of canary tokens that alert when accessed/used.

Supports self-hosted callbacks and canarytokens.org integration.
"""
import os
import re
import json
import string
import secrets
import hashlib
import base64
from enum import Enum
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import urllib.request
import urllib.parse


class CanaryType(Enum):
    """Supported canary token types"""
    AWS_KEY = "aws-key"           # Fake AWS access key
    TRACKING_URL = "tracking-url"  # Unique URL that alerts on visit
    DNS = "dns"                    # DNS subdomain lookup trigger
    CREDENTIAL = "credential"      # Fake credential pair
    WEBHOOK_TOKEN = "webhook"      # Generic webhook trigger token


@dataclass
class Canary:
    """Represents a generated canary token"""
    id: str                        # Unique identifier
    type: CanaryType               # Token type
    created_at: str                # ISO timestamp
    webhook_url: str               # URL to call when triggered
    memo: str = ""                 # Description/note
    
    # Type-specific values
    token_value: str = ""          # The actual canary value (key, URL, etc.)
    token_secret: str = ""         # Secret component (for AWS keys)
    hostname: str = ""             # For DNS canaries
    username: str = ""             # For credential canaries
    password: str = ""             # For credential canaries
    
    # Tracking
    triggered: bool = False
    trigger_count: int = 0
    last_triggered: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        d = asdict(self)
        d['type'] = self.type.value
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Canary':
        """Create from dictionary"""
        data['type'] = CanaryType(data['type'])
        return cls(**data)
    
    def display(self) -> str:
        """Human-readable display of the canary"""
        lines = [
            f"Canary ID: {self.id}",
            f"Type: {self.type.value}",
            f"Created: {self.created_at}",
            f"Memo: {self.memo or '(none)'}",
            f"Webhook: {self.webhook_url}",
        ]
        
        if self.type == CanaryType.AWS_KEY:
            lines.extend([
                "",
                "AWS Credentials (FAKE - for detection only):",
                f"  Access Key ID:     {self.token_value}",
                f"  Secret Access Key: {self.token_secret}",
            ])
        elif self.type == CanaryType.TRACKING_URL:
            lines.extend([
                "",
                f"Tracking URL: {self.token_value}",
            ])
        elif self.type == CanaryType.DNS:
            lines.extend([
                "",
                f"DNS Hostname: {self.hostname}",
            ])
        elif self.type == CanaryType.CREDENTIAL:
            lines.extend([
                "",
                "Fake Credentials:",
                f"  Username: {self.username}",
                f"  Password: {self.password}",
            ])
        elif self.type == CanaryType.WEBHOOK_TOKEN:
            lines.extend([
                "",
                f"Token: {self.token_value}",
            ])
        
        return "\n".join(lines)


class CanaryGenerator:
    """
    Generate canary tokens with alerting capabilities.
    
    Supports two modes:
    1. Self-hosted: Generates tokens that callback to your webhook
    2. Canarytokens.org: Uses the public canarytokens.org API
    """
    
    def __init__(self, 
                 storage_path: str = None,
                 default_webhook: str = None,
                 tracking_domain: str = None,
                 dns_domain: str = None,
                 use_canarytokens_org: bool = False):
        """
        Initialize the canary generator.
        
        Args:
            storage_path: Path to store canary database (JSON file)
            default_webhook: Default webhook URL for alerts
            tracking_domain: Base domain for tracking URLs (self-hosted)
            dns_domain: Base domain for DNS canaries
            use_canarytokens_org: Use canarytokens.org API instead of self-hosted
        """
        self.storage_path = Path(storage_path or os.environ.get(
            'CANARY_STORAGE', '/data/canaries.json'
        ))
        self.default_webhook = default_webhook or os.environ.get('CANARY_WEBHOOK_URL', '')
        self.tracking_domain = tracking_domain or os.environ.get(
            'CANARY_TRACKING_DOMAIN', 'http://localhost:8080/canary'
        )
        self.dns_domain = dns_domain or os.environ.get('CANARY_DNS_DOMAIN', '')
        self.use_canarytokens_org = use_canarytokens_org
        
        # Ensure storage directory exists
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing canaries
        self.canaries: Dict[str, Canary] = {}
        self._load()
    
    def _load(self):
        """Load canaries from storage"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for cid, cdata in data.get('canaries', {}).items():
                        self.canaries[cid] = Canary.from_dict(cdata)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Failed to load canaries: {e}")
    
    def _save(self):
        """Save canaries to storage"""
        data = {
            'version': 1,
            'updated_at': datetime.utcnow().isoformat() + 'Z',
            'canaries': {cid: c.to_dict() for cid, c in self.canaries.items()}
        }
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _generate_id(self) -> str:
        """Generate a unique canary ID"""
        return f"cnry_{secrets.token_hex(8)}"
    
    def _generate_aws_access_key_id(self) -> str:
        """
        Generate a realistic-looking AWS Access Key ID.
        Format: AKIA + 16 uppercase alphanumeric characters
        """
        # AWS access keys start with AKIA (for users) or ASIA (for temp creds)
        prefix = "AKIA"
        # Rest is 16 characters of uppercase letters and digits
        chars = string.ascii_uppercase + string.digits
        suffix = ''.join(secrets.choice(chars) for _ in range(16))
        return prefix + suffix
    
    def _generate_aws_secret_key(self) -> str:
        """
        Generate a realistic-looking AWS Secret Access Key.
        Format: 40 characters of base64-like characters
        """
        # AWS secret keys are 40 characters of base64-like chars
        chars = string.ascii_letters + string.digits + '+/'
        return ''.join(secrets.choice(chars) for _ in range(40))
    
    def _generate_tracking_token(self) -> str:
        """Generate a unique tracking token for URLs"""
        return secrets.token_urlsafe(16)
    
    def _generate_dns_subdomain(self) -> str:
        """Generate a unique subdomain for DNS canaries"""
        return secrets.token_hex(12)
    
    def _generate_password(self, length: int = 16) -> str:
        """Generate a realistic-looking password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def create_aws_key(self, 
                       webhook_url: str = None, 
                       memo: str = "") -> Canary:
        """
        Create a fake AWS access key that alerts when used.
        
        The key looks realistic and will trigger an alert if anyone
        attempts to use it with AWS services.
        
        Args:
            webhook_url: URL to receive alert when key is used
            memo: Description of where this canary is placed
            
        Returns:
            Canary object with fake AWS credentials
        """
        webhook = webhook_url or self.default_webhook
        if not webhook:
            raise ValueError("No webhook URL provided and no default configured")
        
        canary = Canary(
            id=self._generate_id(),
            type=CanaryType.AWS_KEY,
            created_at=datetime.utcnow().isoformat() + 'Z',
            webhook_url=webhook,
            memo=memo,
            token_value=self._generate_aws_access_key_id(),
            token_secret=self._generate_aws_secret_key(),
        )
        
        self.canaries[canary.id] = canary
        self._save()
        return canary
    
    def create_tracking_url(self,
                           webhook_url: str = None,
                           memo: str = "",
                           path_hint: str = "") -> Canary:
        """
        Create a tracking URL that alerts when visited.
        
        Args:
            webhook_url: URL to receive alert when URL is visited
            memo: Description of where this canary is placed
            path_hint: Optional hint for the URL path (e.g., "login", "admin")
            
        Returns:
            Canary object with tracking URL
        """
        webhook = webhook_url or self.default_webhook
        if not webhook:
            raise ValueError("No webhook URL provided and no default configured")
        
        token = self._generate_tracking_token()
        
        # Build the tracking URL
        if path_hint:
            # Make the URL look more realistic
            safe_hint = re.sub(r'[^a-zA-Z0-9-]', '', path_hint)
            tracking_url = f"{self.tracking_domain}/{safe_hint}/{token}"
        else:
            tracking_url = f"{self.tracking_domain}/t/{token}"
        
        canary = Canary(
            id=self._generate_id(),
            type=CanaryType.TRACKING_URL,
            created_at=datetime.utcnow().isoformat() + 'Z',
            webhook_url=webhook,
            memo=memo,
            token_value=tracking_url,
            metadata={'token': token, 'path_hint': path_hint}
        )
        
        self.canaries[canary.id] = canary
        self._save()
        return canary
    
    def create_dns_canary(self,
                         webhook_url: str = None,
                         memo: str = "") -> Canary:
        """
        Create a DNS canary that alerts when the hostname is looked up.
        
        Requires a DNS domain configured to forward lookups to your
        tracking server.
        
        Args:
            webhook_url: URL to receive alert when DNS is queried
            memo: Description of where this canary is placed
            
        Returns:
            Canary object with DNS hostname
        """
        webhook = webhook_url or self.default_webhook
        if not webhook:
            raise ValueError("No webhook URL provided and no default configured")
        
        if not self.dns_domain:
            raise ValueError("No DNS domain configured. Set CANARY_DNS_DOMAIN or dns_domain parameter.")
        
        subdomain = self._generate_dns_subdomain()
        hostname = f"{subdomain}.{self.dns_domain}"
        
        canary = Canary(
            id=self._generate_id(),
            type=CanaryType.DNS,
            created_at=datetime.utcnow().isoformat() + 'Z',
            webhook_url=webhook,
            memo=memo,
            hostname=hostname,
            metadata={'subdomain': subdomain}
        )
        
        self.canaries[canary.id] = canary
        self._save()
        return canary
    
    def create_credential(self,
                         username: str = None,
                         password: str = None,
                         webhook_url: str = None,
                         memo: str = "") -> Canary:
        """
        Create fake credentials that alert when used.
        
        Args:
            username: Specific username or auto-generate
            password: Specific password or auto-generate
            webhook_url: URL to receive alert when credentials are used
            memo: Description of where this canary is placed
            
        Returns:
            Canary object with fake credentials
        """
        webhook = webhook_url or self.default_webhook
        if not webhook:
            raise ValueError("No webhook URL provided and no default configured")
        
        # Generate realistic usernames if not provided
        if not username:
            prefixes = ['admin', 'backup', 'service', 'deploy', 'jenkins', 'ansible', 'api']
            username = secrets.choice(prefixes) + '_' + secrets.token_hex(4)
        
        if not password:
            password = self._generate_password()
        
        canary = Canary(
            id=self._generate_id(),
            type=CanaryType.CREDENTIAL,
            created_at=datetime.utcnow().isoformat() + 'Z',
            webhook_url=webhook,
            memo=memo,
            username=username,
            password=password,
        )
        
        self.canaries[canary.id] = canary
        self._save()
        return canary
    
    def create_webhook_token(self,
                            webhook_url: str = None,
                            memo: str = "") -> Canary:
        """
        Create a generic webhook token.
        
        This creates a unique token that can be embedded anywhere.
        When you detect this token, you know it was accessed.
        
        Args:
            webhook_url: URL to receive alert when token is seen
            memo: Description of where this canary is placed
            
        Returns:
            Canary object with unique token
        """
        webhook = webhook_url or self.default_webhook
        if not webhook:
            raise ValueError("No webhook URL provided and no default configured")
        
        canary = Canary(
            id=self._generate_id(),
            type=CanaryType.WEBHOOK_TOKEN,
            created_at=datetime.utcnow().isoformat() + 'Z',
            webhook_url=webhook,
            memo=memo,
            token_value=secrets.token_urlsafe(24),
        )
        
        self.canaries[canary.id] = canary
        self._save()
        return canary
    
    def create_via_canarytokens_org(self,
                                   canary_type: str,
                                   webhook_url: str = None,
                                   memo: str = "") -> dict:
        """
        Create a canary token via canarytokens.org public API.
        
        Args:
            canary_type: Type of canary (aws-id, web, dns, etc.)
            webhook_url: URL to receive alerts (or email for some types)
            memo: Description/memo for the canary
            
        Returns:
            Response from canarytokens.org API
        """
        webhook = webhook_url or self.default_webhook
        
        # Map our types to canarytokens.org types
        type_map = {
            'aws-key': 'aws-id',
            'tracking-url': 'web',
            'dns': 'dns',
        }
        
        ct_type = type_map.get(canary_type, canary_type)
        
        # Canarytokens.org API endpoint
        api_url = "https://canarytokens.org/generate"
        
        data = {
            'type': ct_type,
            'memo': memo or 'Honeyclaw canary',
            'webhook_url': webhook,
        }
        
        # Make request
        req_data = urllib.parse.urlencode(data).encode('utf-8')
        req = urllib.request.Request(api_url, data=req_data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to create canary via canarytokens.org: {e}")
    
    def get(self, canary_id: str) -> Optional[Canary]:
        """Get a canary by ID"""
        return self.canaries.get(canary_id)
    
    def list_canaries(self, 
                     canary_type: CanaryType = None,
                     triggered_only: bool = False) -> List[Canary]:
        """
        List canaries with optional filtering.
        
        Args:
            canary_type: Filter by type
            triggered_only: Only return triggered canaries
            
        Returns:
            List of matching canaries
        """
        result = list(self.canaries.values())
        
        if canary_type:
            result = [c for c in result if c.type == canary_type]
        
        if triggered_only:
            result = [c for c in result if c.triggered]
        
        return sorted(result, key=lambda c: c.created_at, reverse=True)
    
    def delete(self, canary_id: str) -> bool:
        """Delete a canary by ID"""
        if canary_id in self.canaries:
            del self.canaries[canary_id]
            self._save()
            return True
        return False
    
    def export_for_filesystem(self, canary_ids: List[str] = None) -> dict:
        """
        Export canaries in a format suitable for embedding in fake filesystems.
        
        Returns a dict with file paths and contents for different canary types.
        """
        canaries = [self.canaries[cid] for cid in (canary_ids or self.canaries.keys())
                   if cid in self.canaries]
        
        files = {}
        
        for canary in canaries:
            if canary.type == CanaryType.AWS_KEY:
                # AWS credentials file format
                files['.aws/credentials'] = f"""[default]
aws_access_key_id = {canary.token_value}
aws_secret_access_key = {canary.token_secret}
"""
                files['.aws/config'] = """[default]
region = us-east-1
output = json
"""
                
            elif canary.type == CanaryType.CREDENTIAL:
                # Various credential file formats
                files['.env'] = f"""# Production environment
DATABASE_URL=postgres://{canary.username}:{canary.password}@db.internal:5432/prod
API_KEY={canary.password}
SECRET_KEY={secrets.token_hex(32)}
"""
                files['config/database.yml'] = f"""production:
  adapter: postgresql
  host: db.internal
  database: production
  username: {canary.username}
  password: {canary.password}
"""
                
            elif canary.type == CanaryType.TRACKING_URL:
                # Embed tracking URLs in documentation
                files['INTERNAL_LINKS.md'] = f"""# Internal Resources

- [Admin Panel]({canary.token_value})
- [Monitoring Dashboard]({self.tracking_domain}/dashboard)
- [API Documentation](/docs/api)
"""
        
        return files
    
    def generate_honeypot_files(self, 
                               output_dir: str = None,
                               include_types: List[CanaryType] = None) -> dict:
        """
        Generate a complete set of honeypot files with embedded canaries.
        
        Args:
            output_dir: Directory to write files (or return in-memory if None)
            include_types: Types of canaries to create and embed
            
        Returns:
            Dict mapping file paths to contents
        """
        include = include_types or [CanaryType.AWS_KEY, CanaryType.CREDENTIAL, CanaryType.TRACKING_URL]
        
        # Create fresh canaries for the honeypot
        created = []
        
        if CanaryType.AWS_KEY in include:
            created.append(self.create_aws_key(memo="Honeypot: AWS credentials"))
        
        if CanaryType.CREDENTIAL in include:
            created.append(self.create_credential(
                username="backup_admin",
                memo="Honeypot: Database credentials"
            ))
        
        if CanaryType.TRACKING_URL in include:
            created.append(self.create_tracking_url(
                memo="Honeypot: Internal URL",
                path_hint="admin"
            ))
        
        # Generate files
        files = self.export_for_filesystem([c.id for c in created])
        
        # Add some decoy files
        files['passwords.txt'] = "# Old passwords - DO NOT USE\nadmin:changeme123\nroot:toor\n"
        files['backup_keys.pem'] = f"""-----BEGIN RSA PRIVATE KEY-----
{base64.b64encode(secrets.token_bytes(256)).decode()}
{base64.b64encode(secrets.token_bytes(256)).decode()}
{base64.b64encode(secrets.token_bytes(256)).decode()}
-----END RSA PRIVATE KEY-----
"""
        
        # Write to disk if output_dir specified
        if output_dir:
            output_path = Path(output_dir)
            for filepath, content in files.items():
                full_path = output_path / filepath
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(content)
        
        return files


# CLI Helper
def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Honey Claw - Canary Token Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  honeyclaw canary create --type aws-key --webhook https://hooks.example.com/alert
  honeyclaw canary create --type tracking-url --webhook https://hooks.example.com/alert
  honeyclaw canary list
  honeyclaw canary show cnry_abc123
        """
    )
    
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    generator = CanaryGenerator()
    
    if args.command == 'create':
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
                    path_hint=args.path_hint or ''
                )
            elif args.type == 'dns':
                canary = generator.create_dns_canary(
                    webhook_url=args.webhook,
                    memo=args.memo
                )
            elif args.type == 'credential':
                canary = generator.create_credential(
                    username=args.username,
                    password=args.password,
                    webhook_url=args.webhook,
                    memo=args.memo
                )
            elif args.type == 'webhook':
                canary = generator.create_webhook_token(
                    webhook_url=args.webhook,
                    memo=args.memo
                )
            
            print("✅ Canary created successfully!\n")
            print(canary.display())
            
        except ValueError as e:
            print(f"❌ Error: {e}")
            return 1
    
    elif args.command == 'list':
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
    
    elif args.command == 'show':
        canary = generator.get(args.id)
        if canary:
            print(canary.display())
        else:
            print(f"❌ Canary not found: {args.id}")
            return 1
    
    elif args.command == 'delete':
        if generator.delete(args.id):
            print(f"✅ Deleted canary: {args.id}")
        else:
            print(f"❌ Canary not found: {args.id}")
            return 1
    
    elif args.command == 'generate-files':
        if args.webhook:
            generator.default_webhook = args.webhook
        
        try:
            files = generator.generate_honeypot_files(output_dir=args.output)
            print(f"✅ Generated {len(files)} honeypot files:")
            for path in sorted(files.keys()):
                print(f"  📄 {path}")
            if args.output:
                print(f"\nFiles written to: {args.output}")
        except ValueError as e:
            print(f"❌ Error: {e}")
            return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
