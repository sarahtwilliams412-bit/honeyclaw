#!/usr/bin/env python3
"""
ISP Abuse Reporter - Lookup and notify ISP abuse contacts.

Uses WHOIS data to find abuse contacts and can send automated
abuse reports via email.

Note: Email reporting requires SMTP configuration.
Environment variables:
  - SMTP_HOST: SMTP server hostname
  - SMTP_PORT: SMTP server port (default: 587)
  - SMTP_USER: SMTP username
  - SMTP_PASS: SMTP password
  - SMTP_FROM: Sender email address
"""

import os
import re
import asyncio
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any


@dataclass
class AbuseContact:
    """Information about an ISP's abuse contact."""
    ip: str
    abuse_email: Optional[str] = None
    org_name: Optional[str] = None
    asn: Optional[str] = None
    network_name: Optional[str] = None
    country: Optional[str] = None
    whois_raw: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'abuse_email': self.abuse_email,
            'org_name': self.org_name,
            'asn': self.asn,
            'network_name': self.network_name,
            'country': self.country,
            'error': self.error,
        }


@dataclass
class ISPReportResult:
    """Result of an ISP abuse report."""
    success: bool
    ip: str
    provider: str = "isp_abuse"
    abuse_email: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'ip': self.ip,
            'provider': self.provider,
            'abuse_email': self.abuse_email,
            'message': self.message,
            'error': self.error,
            'timestamp': self.timestamp,
        }


class ISPAbuseReporter:
    """
    Lookup ISP abuse contacts and send abuse reports.
    
    Features:
    - WHOIS-based abuse contact lookup
    - Automated email reporting (optional)
    - Support for RDAP protocol
    - Caching of WHOIS lookups
    """
    
    name = "isp_abuse"
    
    # Common WHOIS servers by region
    WHOIS_SERVERS = {
        'default': 'whois.iana.org',
        'ARIN': 'whois.arin.net',      # North America
        'RIPE': 'whois.ripe.net',       # Europe
        'APNIC': 'whois.apnic.net',     # Asia-Pacific
        'LACNIC': 'whois.lacnic.net',   # Latin America
        'AFRINIC': 'whois.afrinic.net', # Africa
    }
    
    # Regex patterns for extracting abuse email
    ABUSE_EMAIL_PATTERNS = [
        r'(?:abuse-mailbox|abuse-c|OrgAbuseEmail|abuse@\S+):\s*(\S+@\S+)',
        r'(?:e-mail|email|abuse):\s*(\S+@\S+)',
        r'(abuse@[\w.-]+\.\w{2,})',
        r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    ]
    
    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: int = None,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        smtp_from: Optional[str] = None,
    ):
        """
        Initialize the ISP abuse reporter.
        
        Args:
            smtp_*: SMTP configuration for sending emails
        """
        self.smtp_host = smtp_host or os.environ.get('SMTP_HOST')
        self.smtp_port = smtp_port or int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_user = smtp_user or os.environ.get('SMTP_USER')
        self.smtp_pass = smtp_pass or os.environ.get('SMTP_PASS')
        self.smtp_from = smtp_from or os.environ.get('SMTP_FROM')
        
        self._email_enabled = all([
            self.smtp_host, self.smtp_user, self.smtp_pass, self.smtp_from
        ])
        
        # Cache WHOIS lookups
        self._whois_cache: Dict[str, AbuseContact] = {}
    
    @property
    def email_enabled(self) -> bool:
        """Check if email reporting is configured."""
        return self._email_enabled
    
    async def lookup_abuse_contact(self, ip: str) -> AbuseContact:
        """
        Look up the abuse contact for an IP address.
        
        Args:
            ip: IPv4 address to look up
            
        Returns:
            AbuseContact with abuse email and org info
        """
        # Check cache
        if ip in self._whois_cache:
            return self._whois_cache[ip]
        
        # Validate IP
        if not self._validate_ip(ip):
            return AbuseContact(ip=ip, error="Invalid IP address format")
        
        if self._is_private_ip(ip):
            return AbuseContact(ip=ip, error="Cannot look up private IP addresses")
        
        # Try RDAP first (modern, structured)
        contact = await self._lookup_rdap(ip)
        if contact.abuse_email:
            self._whois_cache[ip] = contact
            return contact
        
        # Fall back to WHOIS
        contact = await self._lookup_whois(ip)
        self._whois_cache[ip] = contact
        return contact
    
    async def _lookup_rdap(self, ip: str) -> AbuseContact:
        """Query RDAP for abuse contact."""
        import aiohttp
        
        # RDAP bootstrap URL
        rdap_url = f"https://rdap.db.ripe.net/ip/{ip}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    rdap_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={'Accept': 'application/rdap+json'}
                ) as response:
                    if response.status != 200:
                        return AbuseContact(ip=ip, error=f"RDAP error: {response.status}")
                    
                    data = await response.json()
        except Exception as e:
            return AbuseContact(ip=ip, error=f"RDAP lookup failed: {str(e)}")
        
        # Extract abuse contact from RDAP response
        abuse_email = None
        org_name = None
        
        # Check entities for abuse contact
        for entity in data.get('entities', []):
            roles = entity.get('roles', [])
            if 'abuse' in roles:
                # Found abuse contact
                vcards = entity.get('vcardArray', [])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if vcard[0] == 'email':
                            abuse_email = vcard[3]
                            break
            
            if 'registrant' in roles:
                vcards = entity.get('vcardArray', [])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if vcard[0] == 'fn':
                            org_name = vcard[3]
        
        # Get network name
        network_name = data.get('name')
        
        return AbuseContact(
            ip=ip,
            abuse_email=abuse_email,
            org_name=org_name,
            network_name=network_name,
            country=data.get('country'),
        )
    
    async def _lookup_whois(self, ip: str) -> AbuseContact:
        """Query WHOIS for abuse contact."""
        whois_raw = ""
        
        try:
            # Query IANA first to find the right RIR
            whois_raw = await self._whois_query(ip, 'whois.iana.org')
            
            # Find the authoritative WHOIS server
            refer_match = re.search(r'refer:\s*(\S+)', whois_raw)
            if refer_match:
                whois_server = refer_match.group(1)
                whois_raw = await self._whois_query(ip, whois_server)
        except Exception as e:
            return AbuseContact(ip=ip, error=f"WHOIS lookup failed: {str(e)}")
        
        # Extract abuse email
        abuse_email = None
        for pattern in self.ABUSE_EMAIL_PATTERNS:
            match = re.search(pattern, whois_raw, re.IGNORECASE)
            if match:
                email = match.group(1).lower()
                # Prefer explicit abuse@ emails
                if 'abuse' in email:
                    abuse_email = email
                    break
                elif abuse_email is None:
                    abuse_email = email
        
        # Extract organization name
        org_match = re.search(r'(?:OrgName|org-name|organisation|netname):\s*(.+)', whois_raw, re.IGNORECASE)
        org_name = org_match.group(1).strip() if org_match else None
        
        # Extract ASN
        asn_match = re.search(r'(?:origin|aut-num|ASN):\s*(AS?\d+)', whois_raw, re.IGNORECASE)
        asn = asn_match.group(1) if asn_match else None
        
        # Extract country
        country_match = re.search(r'(?:Country|country):\s*(\S+)', whois_raw, re.IGNORECASE)
        country = country_match.group(1).upper() if country_match else None
        
        return AbuseContact(
            ip=ip,
            abuse_email=abuse_email,
            org_name=org_name,
            asn=asn,
            country=country,
            whois_raw=whois_raw[:5000] if whois_raw else None,  # Truncate for storage
        )
    
    async def _whois_query(self, ip: str, server: str, port: int = 43) -> str:
        """Perform a raw WHOIS query."""
        loop = asyncio.get_event_loop()
        
        def _query():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((server, port))
            s.send((ip + '\r\n').encode())
            
            response = b''
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            
            s.close()
            return response.decode('utf-8', errors='ignore')
        
        return await loop.run_in_executor(None, _query)
    
    async def send_abuse_email(
        self,
        ip: str,
        event_type: str,
        evidence: Dict[str, Any],
        honeypot_id: str = "honeyclaw",
        abuse_email: Optional[str] = None,
    ) -> ISPReportResult:
        """
        Send an abuse report email to the ISP.
        
        Args:
            ip: Attacker IP address
            event_type: Type of attack
            evidence: Dict containing attack evidence
            honeypot_id: Identifier for this honeypot
            abuse_email: Override abuse email (otherwise looked up)
            
        Returns:
            ISPReportResult with sending status
        """
        if not self.email_enabled:
            return ISPReportResult(
                success=False,
                ip=ip,
                error="SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS, SMTP_FROM."
            )
        
        # Look up abuse contact if not provided
        if not abuse_email:
            contact = await self.lookup_abuse_contact(ip)
            if contact.error:
                return ISPReportResult(
                    success=False,
                    ip=ip,
                    error=f"Failed to find abuse contact: {contact.error}"
                )
            if not contact.abuse_email:
                return ISPReportResult(
                    success=False,
                    ip=ip,
                    error="No abuse email found for this IP"
                )
            abuse_email = contact.abuse_email
        
        # Build email
        subject = f"[Abuse Report] Malicious activity from {ip}"
        body = self._format_abuse_email(ip, event_type, evidence, honeypot_id)
        
        try:
            await self._send_email(abuse_email, subject, body)
            return ISPReportResult(
                success=True,
                ip=ip,
                abuse_email=abuse_email,
                message=f"Abuse report sent to {abuse_email}"
            )
        except Exception as e:
            return ISPReportResult(
                success=False,
                ip=ip,
                abuse_email=abuse_email,
                error=f"Failed to send email: {str(e)}"
            )
    
    def _format_abuse_email(
        self,
        ip: str,
        event_type: str,
        evidence: Dict[str, Any],
        honeypot_id: str,
    ) -> str:
        """Format the abuse report email body."""
        timestamp = evidence.get('timestamp', datetime.utcnow().isoformat())
        
        body = f"""
Dear Abuse Team,

We are writing to report malicious activity originating from an IP address
within your network. Our honeypot system detected the following attack:

=== Attack Summary ===
IP Address: {ip}
Attack Type: {event_type.replace('_', ' ').title()}
Time (UTC): {timestamp}
Honeypot ID: {honeypot_id}

=== Evidence ===
"""
        
        # Add evidence fields
        for key, value in evidence.items():
            if key not in ('timestamp', 'raw'):
                # Mask sensitive data
                if 'password' in key.lower() and value:
                    value = value[0] + '*' * (len(str(value)) - 2) + value[-1] if len(str(value)) > 2 else '***'
                body += f"{key}: {value}\n"
        
        body += f"""
=== Request ===
We kindly request that you investigate this activity and take appropriate
action. This IP address may be compromised or may be intentionally engaging
in malicious behavior.

=== About This Report ===
This is an automated report from the Honeyclaw honeypot system. Honeypots are
security research systems designed to attract and analyze malicious activity.
All activity logged by our system represents unauthorized access attempts
to systems that have no legitimate users.

If you believe this report is in error, please contact us and we will
investigate.

Best regards,
Honeyclaw Automated Reporting System
"""
        
        return body
    
    async def _send_email(self, to: str, subject: str, body: str):
        """Send an email via SMTP."""
        loop = asyncio.get_event_loop()
        
        def _send():
            msg = MIMEMultipart()
            msg['From'] = self.smtp_from
            msg['To'] = to
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
        
        await loop.run_in_executor(None, _send)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        octets = [int(x) for x in ip.split('.')]
        
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True
        if octets[0] == 169 and octets[1] == 254:
            return True
        
        return False
