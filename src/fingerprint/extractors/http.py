#!/usr/bin/env python3
"""
HTTP/TLS Fingerprint Extractor

Extracts unique fingerprints from HTTP/TLS connections:
- JA3 TLS fingerprint (client hello parameters)
- JA4 fingerprint (enhanced JA3 successor)
- HTTP header ordering and values
- User-Agent analysis
- Request patterns
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class TLSFingerprint:
    """TLS Client Hello fingerprint data"""
    # JA3 components
    tls_version: int = 0
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    elliptic_curves: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)
    
    # Computed fingerprints
    ja3_string: str = ""
    ja3_hash: str = ""
    
    # JA4 components (enhanced)
    ja4_string: str = ""
    ja4_hash: str = ""
    alpn_protocols: List[str] = field(default_factory=list)
    signature_algorithms: List[int] = field(default_factory=list)
    
    # SNI (Server Name Indication)
    sni_hostname: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'tls_version': self.tls_version,
            'ja3_hash': self.ja3_hash,
            'ja3_string': self.ja3_string,
            'ja4_hash': self.ja4_hash,
            'cipher_suites_count': len(self.cipher_suites),
            'extensions_count': len(self.extensions),
            'alpn': self.alpn_protocols,
            'sni': self.sni_hostname,
        }


@dataclass  
class HTTPFingerprint:
    """HTTP request fingerprint data"""
    # Headers (order matters!)
    header_order: List[str] = field(default_factory=list)
    header_order_hash: str = ""
    
    # User-Agent analysis
    user_agent: str = ""
    user_agent_parsed: Dict[str, str] = field(default_factory=dict)
    
    # Request characteristics
    method: str = ""
    http_version: str = ""
    accept_encoding: List[str] = field(default_factory=list)
    accept_language: List[str] = field(default_factory=list)
    
    # Connection behavior
    keep_alive: bool = False
    has_cookies: bool = False
    
    # Combined fingerprint
    http_fingerprint_hash: str = ""
    
    # TLS fingerprint if HTTPS
    tls: Optional[TLSFingerprint] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'header_order': self.header_order,
            'header_order_hash': self.header_order_hash,
            'user_agent': self.user_agent,
            'method': self.method,
            'http_version': self.http_version,
            'http_fingerprint_hash': self.http_fingerprint_hash,
        }
        if self.tls:
            result['tls'] = self.tls.to_dict()
        return result


class HTTPFingerprintExtractor:
    """
    Extracts fingerprints from HTTP/TLS connection data.
    
    HTTP fingerprinting leverages:
    1. TLS Client Hello (JA3/JA4) - uniquely identifies TLS implementation
    2. HTTP Header ordering - different libraries/tools have different orders
    3. User-Agent analysis - detect spoofing and identify tools
    4. Request patterns - paths, methods, timing
    
    References:
    - JA3: https://github.com/salesforce/ja3
    - JA4: https://github.com/FoxIO-LLC/ja4
    """
    
    # Known tool signatures in User-Agent
    KNOWN_TOOLS = {
        'curl': {'pattern': r'^curl/', 'threat_level': 'low'},
        'wget': {'pattern': r'^Wget/', 'threat_level': 'low'},
        'python-requests': {'pattern': r'python-requests/', 'threat_level': 'medium'},
        'python-urllib': {'pattern': r'Python-urllib/', 'threat_level': 'medium'},
        'go-http': {'pattern': r'^Go-http-client/', 'threat_level': 'high'},
        'httpx': {'pattern': r'python-httpx/', 'threat_level': 'medium'},
        'aiohttp': {'pattern': r'aiohttp/', 'threat_level': 'medium'},
        'scrapy': {'pattern': r'Scrapy/', 'threat_level': 'high'},
        'nikto': {'pattern': r'Nikto', 'threat_level': 'critical'},
        'sqlmap': {'pattern': r'sqlmap', 'threat_level': 'critical'},
        'nmap': {'pattern': r'Nmap', 'threat_level': 'critical'},
        'masscan': {'pattern': r'masscan', 'threat_level': 'critical'},
        'zgrab': {'pattern': r'zgrab', 'threat_level': 'high'},
        'nuclei': {'pattern': r'Nuclei', 'threat_level': 'critical'},
        'dirbuster': {'pattern': r'DirBuster', 'threat_level': 'critical'},
        'gobuster': {'pattern': r'gobuster', 'threat_level': 'critical'},
    }
    
    # Known malicious JA3 hashes (examples - would be loaded from threat intel)
    KNOWN_MALICIOUS_JA3 = {
        # Cobalt Strike
        '72a589da586844d7f0818ce684948eea': 'cobalt_strike',
        # Metasploit
        '3b5074b1b5d032e5620f69f9f700ff0e': 'metasploit',
        # TrickBot
        '6734f37431670b3ab4292b8f60f29984': 'trickbot',
        # Generic Python TLS
        '3b5074b1b5d032e5620f69f9f700ff0e': 'python_default',
    }
    
    # GREASE values to filter from JA3
    GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }
    
    def __init__(self):
        self._ja3_cache = {}
    
    def extract_from_client_hello(self, client_hello: bytes) -> TLSFingerprint:
        """
        Extract JA3/JA4 fingerprint from TLS Client Hello message.
        
        Client Hello structure:
        - 1 byte: handshake type (0x01)
        - 3 bytes: length
        - 2 bytes: version
        - 32 bytes: random
        - 1 byte: session ID length + session ID
        - 2 bytes: cipher suites length + cipher suites
        - 1 byte: compression methods length + methods
        - 2 bytes: extensions length + extensions
        """
        fp = TLSFingerprint()
        
        try:
            if len(client_hello) < 42:
                return fp
            
            offset = 0
            
            # Skip record layer if present (TLS record type 0x16 = handshake)
            if client_hello[0] == 0x16:
                offset = 5  # Skip record header
            
            # Handshake type should be 0x01 (Client Hello)
            if client_hello[offset] != 0x01:
                return fp
            
            offset += 4  # Skip handshake type + length
            
            # TLS Version
            fp.tls_version = int.from_bytes(client_hello[offset:offset+2], 'big')
            offset += 2
            
            # Random (32 bytes)
            offset += 32
            
            # Session ID
            session_id_len = client_hello[offset]
            offset += 1 + session_id_len
            
            # Cipher Suites
            cipher_len = int.from_bytes(client_hello[offset:offset+2], 'big')
            offset += 2
            
            for i in range(0, cipher_len, 2):
                cipher = int.from_bytes(client_hello[offset+i:offset+i+2], 'big')
                if cipher not in self.GREASE_VALUES:
                    fp.cipher_suites.append(cipher)
            offset += cipher_len
            
            # Compression methods
            comp_len = client_hello[offset]
            offset += 1 + comp_len
            
            # Extensions
            if offset + 2 <= len(client_hello):
                ext_len = int.from_bytes(client_hello[offset:offset+2], 'big')
                offset += 2
                ext_end = offset + ext_len
                
                while offset + 4 <= ext_end:
                    ext_type = int.from_bytes(client_hello[offset:offset+2], 'big')
                    ext_data_len = int.from_bytes(client_hello[offset+2:offset+4], 'big')
                    ext_data = client_hello[offset+4:offset+4+ext_data_len]
                    
                    if ext_type not in self.GREASE_VALUES:
                        fp.extensions.append(ext_type)
                    
                    # Parse specific extensions
                    if ext_type == 0x0000:  # SNI
                        fp.sni_hostname = self._parse_sni(ext_data)
                    elif ext_type == 0x000a:  # Elliptic curves / supported groups
                        fp.elliptic_curves = self._parse_curves(ext_data)
                    elif ext_type == 0x000b:  # EC point formats
                        fp.ec_point_formats = self._parse_ec_formats(ext_data)
                    elif ext_type == 0x0010:  # ALPN
                        fp.alpn_protocols = self._parse_alpn(ext_data)
                    elif ext_type == 0x000d:  # Signature algorithms
                        fp.signature_algorithms = self._parse_sig_algs(ext_data)
                    
                    offset += 4 + ext_data_len
            
            # Compute JA3
            fp.ja3_string = self._compute_ja3_string(fp)
            fp.ja3_hash = hashlib.md5(fp.ja3_string.encode()).hexdigest()
            
            # Compute JA4
            fp.ja4_string = self._compute_ja4_string(fp)
            fp.ja4_hash = hashlib.sha256(fp.ja4_string.encode()).hexdigest()[:24]
            
        except Exception:
            pass
        
        return fp
    
    def extract_from_headers(self, headers: Dict[str, str], method: str = "GET", 
                            http_version: str = "1.1") -> HTTPFingerprint:
        """
        Extract fingerprint from HTTP headers.
        
        Header order is significant - different tools/libraries send
        headers in different orders, creating a unique fingerprint.
        """
        fp = HTTPFingerprint()
        fp.method = method
        fp.http_version = http_version
        
        # Preserve header order (case-insensitive normalization)
        fp.header_order = [k.lower() for k in headers.keys()]
        fp.header_order_hash = self._hash_list(fp.header_order)
        
        # Extract specific headers
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower == 'user-agent':
                fp.user_agent = value
                fp.user_agent_parsed = self._parse_user_agent(value)
            elif key_lower == 'accept-encoding':
                fp.accept_encoding = [e.strip() for e in value.split(',')]
            elif key_lower == 'accept-language':
                fp.accept_language = [l.strip().split(';')[0] for l in value.split(',')]
            elif key_lower == 'connection':
                fp.keep_alive = value.lower() == 'keep-alive'
            elif key_lower == 'cookie':
                fp.has_cookies = True
        
        # Compute combined fingerprint
        fp.http_fingerprint_hash = self._compute_http_fingerprint(fp)
        
        return fp
    
    def identify_tool(self, fingerprint: HTTPFingerprint) -> Dict[str, Any]:
        """
        Attempt to identify the HTTP client/tool.
        """
        result = {
            'identified': False,
            'tool': 'unknown',
            'threat_level': 'unknown',
            'indicators': [],
            'ja3_match': None,
        }
        
        # Check User-Agent
        if fingerprint.user_agent:
            for tool_id, info in self.KNOWN_TOOLS.items():
                if re.search(info['pattern'], fingerprint.user_agent, re.I):
                    result['identified'] = True
                    result['tool'] = tool_id
                    result['threat_level'] = info['threat_level']
                    break
        
        # Check JA3 against known malicious hashes
        if fingerprint.tls and fingerprint.tls.ja3_hash:
            if fingerprint.tls.ja3_hash in self.KNOWN_MALICIOUS_JA3:
                result['ja3_match'] = self.KNOWN_MALICIOUS_JA3[fingerprint.tls.ja3_hash]
                result['threat_level'] = 'critical'
                result['indicators'].append(f'malicious_ja3:{result["ja3_match"]}')
        
        # Check for suspicious patterns
        if not fingerprint.user_agent:
            result['indicators'].append('missing_user_agent')
        
        if fingerprint.header_order and 'host' not in fingerprint.header_order[:3]:
            result['indicators'].append('unusual_header_order')
        
        # Empty or minimal Accept headers
        if not fingerprint.accept_encoding:
            result['indicators'].append('no_accept_encoding')
        
        return result
    
    def _parse_sni(self, data: bytes) -> str:
        """Parse SNI extension data"""
        try:
            if len(data) < 5:
                return ""
            offset = 2  # Skip list length
            name_type = data[offset]
            if name_type != 0:  # host_name
                return ""
            name_len = int.from_bytes(data[offset+1:offset+3], 'big')
            return data[offset+3:offset+3+name_len].decode('utf-8', errors='replace')
        except Exception:
            return ""
    
    def _parse_curves(self, data: bytes) -> List[int]:
        """Parse supported curves extension"""
        try:
            curves = []
            if len(data) < 2:
                return curves
            length = int.from_bytes(data[0:2], 'big')
            for i in range(2, min(2 + length, len(data)), 2):
                curve = int.from_bytes(data[i:i+2], 'big')
                if curve not in self.GREASE_VALUES:
                    curves.append(curve)
            return curves
        except Exception:
            return []
    
    def _parse_ec_formats(self, data: bytes) -> List[int]:
        """Parse EC point formats extension"""
        try:
            if len(data) < 1:
                return []
            length = data[0]
            return list(data[1:1+length])
        except Exception:
            return []
    
    def _parse_alpn(self, data: bytes) -> List[str]:
        """Parse ALPN extension"""
        try:
            protocols = []
            if len(data) < 2:
                return protocols
            offset = 2  # Skip list length
            while offset < len(data):
                proto_len = data[offset]
                proto = data[offset+1:offset+1+proto_len].decode('utf-8', errors='replace')
                protocols.append(proto)
                offset += 1 + proto_len
            return protocols
        except Exception:
            return []
    
    def _parse_sig_algs(self, data: bytes) -> List[int]:
        """Parse signature algorithms extension"""
        try:
            algs = []
            if len(data) < 2:
                return algs
            length = int.from_bytes(data[0:2], 'big')
            for i in range(2, min(2 + length, len(data)), 2):
                alg = int.from_bytes(data[i:i+2], 'big')
                algs.append(alg)
            return algs
        except Exception:
            return []
    
    def _parse_user_agent(self, ua: str) -> Dict[str, str]:
        """Parse User-Agent string into components"""
        result = {
            'raw': ua,
            'browser': '',
            'os': '',
            'device': '',
        }
        
        # Common patterns
        if 'Chrome/' in ua:
            result['browser'] = 'chrome'
        elif 'Firefox/' in ua:
            result['browser'] = 'firefox'
        elif 'Safari/' in ua and 'Chrome/' not in ua:
            result['browser'] = 'safari'
        elif 'curl/' in ua:
            result['browser'] = 'curl'
        elif 'python' in ua.lower():
            result['browser'] = 'python'
        
        if 'Windows' in ua:
            result['os'] = 'windows'
        elif 'Mac OS X' in ua or 'macOS' in ua:
            result['os'] = 'macos'
        elif 'Linux' in ua:
            result['os'] = 'linux'
        elif 'Android' in ua:
            result['os'] = 'android'
        elif 'iOS' in ua or 'iPhone' in ua:
            result['os'] = 'ios'
        
        return result
    
    def _compute_ja3_string(self, fp: TLSFingerprint) -> str:
        """
        Compute JA3 string from TLS fingerprint.
        
        Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        """
        parts = [
            str(fp.tls_version),
            '-'.join(str(c) for c in fp.cipher_suites),
            '-'.join(str(e) for e in fp.extensions),
            '-'.join(str(c) for c in fp.elliptic_curves),
            '-'.join(str(f) for f in fp.ec_point_formats),
        ]
        return ','.join(parts)
    
    def _compute_ja4_string(self, fp: TLSFingerprint) -> str:
        """
        Compute JA4 fingerprint string.
        
        JA4 format: t{version}d{ciphers}{extensions}_{alpn}_{sha256_first12}
        """
        # Simplified JA4-like computation
        version_map = {
            0x0301: '10', 0x0302: '11', 0x0303: '12', 0x0304: '13',
        }
        version = version_map.get(fp.tls_version, '00')
        
        cipher_count = f'{min(len(fp.cipher_suites), 99):02d}'
        ext_count = f'{min(len(fp.extensions), 99):02d}'
        
        alpn = fp.alpn_protocols[0][:2] if fp.alpn_protocols else '00'
        
        # Sort ciphers and extensions for deterministic ordering
        sorted_ciphers = sorted(fp.cipher_suites)
        sorted_exts = sorted(fp.extensions)
        
        hash_input = f"{sorted_ciphers},{sorted_exts}"
        hash_suffix = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        
        return f"t{version}d{cipher_count}{ext_count}_{alpn}_{hash_suffix}"
    
    def _hash_list(self, items: List[str]) -> str:
        """Hash a list preserving order"""
        if not items:
            return ""
        return hashlib.sha256(','.join(items).encode()).hexdigest()[:16]
    
    def _compute_http_fingerprint(self, fp: HTTPFingerprint) -> str:
        """Compute combined HTTP fingerprint hash"""
        components = [
            fp.header_order_hash,
            fp.method,
            fp.http_version,
            fp.user_agent[:50] if fp.user_agent else '',
        ]
        combined = '|'.join(filter(None, components))
        return hashlib.sha256(combined.encode()).hexdigest()[:24]
    
    def compute_similarity(self, fp1: HTTPFingerprint, fp2: HTTPFingerprint) -> float:
        """Compute similarity between two HTTP fingerprints"""
        if not fp1 or not fp2:
            return 0.0
        
        score = 0.0
        
        # Header order is highly significant
        if fp1.header_order_hash and fp1.header_order_hash == fp2.header_order_hash:
            score += 0.3
        
        # User-Agent match
        if fp1.user_agent and fp1.user_agent == fp2.user_agent:
            score += 0.2
        elif fp1.user_agent_parsed.get('browser') == fp2.user_agent_parsed.get('browser'):
            score += 0.1
        
        # JA3 match (if both have TLS)
        if fp1.tls and fp2.tls:
            if fp1.tls.ja3_hash and fp1.tls.ja3_hash == fp2.tls.ja3_hash:
                score += 0.4
        
        # Accept-Encoding similarity
        if fp1.accept_encoding and fp1.accept_encoding == fp2.accept_encoding:
            score += 0.1
        
        return min(score, 1.0)
