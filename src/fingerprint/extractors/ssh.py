#!/usr/bin/env python3
"""
SSH Fingerprint Extractor

Extracts unique fingerprints from SSH connection parameters:
- Client version string (software, version, comments)
- Key exchange algorithms (order and preferences)
- Cipher preferences (encryption algorithms)
- MAC algorithms
- Compression preferences
- Public key types offered
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class SSHFingerprint:
    """SSH connection fingerprint data"""
    # Client identification
    client_version: str = ""
    client_software: str = ""
    client_software_version: str = ""
    client_comments: str = ""
    
    # Key exchange
    kex_algorithms: List[str] = field(default_factory=list)
    kex_hash: str = ""
    
    # Encryption
    ciphers_client_to_server: List[str] = field(default_factory=list)
    ciphers_server_to_client: List[str] = field(default_factory=list)
    cipher_hash: str = ""
    
    # MAC
    macs_client_to_server: List[str] = field(default_factory=list)
    macs_server_to_client: List[str] = field(default_factory=list)
    mac_hash: str = ""
    
    # Compression
    compression_client_to_server: List[str] = field(default_factory=list)
    compression_server_to_client: List[str] = field(default_factory=list)
    
    # Host keys
    host_key_algorithms: List[str] = field(default_factory=list)
    host_key_hash: str = ""
    
    # Combined fingerprint
    ssh_fingerprint_hash: str = ""
    
    # Raw data for deep analysis
    raw_kex_init: bytes = field(default_factory=bytes, repr=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage"""
        return {
            'client_version': self.client_version,
            'client_software': self.client_software,
            'client_software_version': self.client_software_version,
            'kex_algorithms': self.kex_algorithms,
            'kex_hash': self.kex_hash,
            'ciphers': self.ciphers_client_to_server,
            'cipher_hash': self.cipher_hash,
            'macs': self.macs_client_to_server,
            'mac_hash': self.mac_hash,
            'host_key_algorithms': self.host_key_algorithms,
            'host_key_hash': self.host_key_hash,
            'ssh_fingerprint_hash': self.ssh_fingerprint_hash,
        }


class SSHFingerprintExtractor:
    """
    Extracts fingerprints from SSH connection data.
    
    SSH fingerprinting is based on the SSH2 protocol's key exchange init
    message (SSH_MSG_KEXINIT) which contains the client's algorithm 
    preferences. The order and selection of algorithms creates a unique
    fingerprint even when the client version string is spoofed.
    
    Reference: RFC 4253 - SSH Transport Layer Protocol
    """
    
    # Known SSH client signatures for TTP matching
    KNOWN_CLIENTS = {
        'paramiko': {'pattern': r'^paramiko', 'threat_level': 'medium', 'notes': 'Python SSH library, common in scripts'},
        'libssh': {'pattern': r'^libssh', 'threat_level': 'medium', 'notes': 'C library, used by many tools'},
        'openssh': {'pattern': r'^OpenSSH', 'threat_level': 'low', 'notes': 'Standard SSH client'},
        'putty': {'pattern': r'^PuTTY', 'threat_level': 'low', 'notes': 'Windows SSH client'},
        'dropbear': {'pattern': r'^dropbear', 'threat_level': 'medium', 'notes': 'Lightweight SSH, embedded systems'},
        'asyncssh': {'pattern': r'^AsyncSSH', 'threat_level': 'high', 'notes': 'Python async SSH, common in botnets'},
        'golang': {'pattern': r'^SSH-2\.0-Go', 'threat_level': 'high', 'notes': 'Go SSH library, common in scanners'},
        'ncrack': {'pattern': r'^ncrack', 'threat_level': 'critical', 'notes': 'Known brute-force tool'},
        'medusa': {'pattern': r'^medusa', 'threat_level': 'critical', 'notes': 'Known brute-force tool'},
        'hydra': {'pattern': r'^hydra|^libssh2.*hydra', 'threat_level': 'critical', 'notes': 'Known brute-force tool'},
    }
    
    # Algorithm preferences that indicate automated tools
    TOOL_INDICATORS = {
        # Minimal algorithm sets often indicate scripts
        'minimal_kex': 3,  # Less than this many kex algs is suspicious
        'minimal_ciphers': 3,
        # Deprecated algorithms may indicate old/modified tools
        'deprecated_kex': ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'],
        'deprecated_ciphers': ['3des-cbc', 'arcfour', 'arcfour128', 'arcfour256', 'blowfish-cbc'],
    }
    
    def __init__(self):
        self._cache = {}  # Cache computed fingerprints
    
    def extract_from_version(self, version_string: str) -> SSHFingerprint:
        """
        Extract fingerprint from SSH version string.
        
        Format: SSH-protoversion-softwareversion SP comments CR LF
        Example: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        """
        fp = SSHFingerprint()
        fp.client_version = version_string.strip()
        
        # Parse version string
        # SSH-2.0-SoftwareVersion [Comments]
        match = re.match(r'^SSH-[\d.]+-([\w._-]+)\s*(.*)?$', version_string)
        if match:
            fp.client_software = match.group(1)
            fp.client_comments = match.group(2) or ""
            
            # Extract version number from software name
            ver_match = re.search(r'[_-]?([\d.]+[a-z]?\d*)', fp.client_software)
            if ver_match:
                fp.client_software_version = ver_match.group(1)
        
        return fp
    
    def extract_from_kex_init(self, kex_init_payload: bytes, fingerprint: SSHFingerprint = None) -> SSHFingerprint:
        """
        Extract fingerprint from SSH_MSG_KEXINIT payload.
        
        The KEXINIT message contains algorithm preferences that uniquely
        identify the SSH implementation and configuration.
        
        Payload format (after msg type byte):
        - 16 bytes: random cookie
        - string: kex_algorithms (comma-separated)
        - string: server_host_key_algorithms
        - string: encryption_algorithms_client_to_server
        - string: encryption_algorithms_server_to_client
        - string: mac_algorithms_client_to_server
        - string: mac_algorithms_server_to_client
        - string: compression_algorithms_client_to_server
        - string: compression_algorithms_server_to_client
        - string: languages_client_to_server
        - string: languages_server_to_client
        - boolean: first_kex_packet_follows
        - uint32: reserved
        """
        fp = fingerprint or SSHFingerprint()
        fp.raw_kex_init = kex_init_payload
        
        try:
            offset = 16  # Skip random cookie
            
            # Helper to read SSH string (4-byte length + data)
            def read_string(data: bytes, pos: int) -> tuple:
                if pos + 4 > len(data):
                    return "", pos
                length = int.from_bytes(data[pos:pos+4], 'big')
                if pos + 4 + length > len(data):
                    return "", pos
                value = data[pos+4:pos+4+length].decode('utf-8', errors='replace')
                return value, pos + 4 + length
            
            # Read all algorithm lists
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.kex_algorithms = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.host_key_algorithms = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.ciphers_client_to_server = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.ciphers_server_to_client = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.macs_client_to_server = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.macs_server_to_client = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.compression_client_to_server = alg_string.split(',') if alg_string else []
            
            alg_string, offset = read_string(kex_init_payload, offset)
            fp.compression_server_to_client = alg_string.split(',') if alg_string else []
            
            # Compute hashes
            fp.kex_hash = self._hash_list(fp.kex_algorithms)
            fp.cipher_hash = self._hash_list(fp.ciphers_client_to_server)
            fp.mac_hash = self._hash_list(fp.macs_client_to_server)
            fp.host_key_hash = self._hash_list(fp.host_key_algorithms)
            
            # Compute combined SSH fingerprint
            fp.ssh_fingerprint_hash = self._compute_ssh_fingerprint(fp)
            
        except Exception as e:
            # Log error but don't fail - partial fingerprint is still useful
            pass
        
        return fp
    
    def extract_from_asyncssh_conn(self, conn) -> SSHFingerprint:
        """
        Extract fingerprint from an AsyncSSH connection object.
        
        Args:
            conn: asyncssh.SSHClientConnection or similar
        """
        fp = SSHFingerprint()
        
        try:
            # Get client version from connection
            if hasattr(conn, 'get_extra_info'):
                client_version = conn.get_extra_info('client_version', '')
                if client_version:
                    fp = self.extract_from_version(client_version)
            
            # Try to get algorithm info if available
            if hasattr(conn, '_kex_algs'):
                fp.kex_algorithms = list(conn._kex_algs or [])
            if hasattr(conn, '_encryption_algs'):
                fp.ciphers_client_to_server = list(conn._encryption_algs or [])
            if hasattr(conn, '_mac_algs'):
                fp.macs_client_to_server = list(conn._mac_algs or [])
            
            # Compute hashes if we have data
            if fp.kex_algorithms:
                fp.kex_hash = self._hash_list(fp.kex_algorithms)
            if fp.ciphers_client_to_server:
                fp.cipher_hash = self._hash_list(fp.ciphers_client_to_server)
            if fp.macs_client_to_server:
                fp.mac_hash = self._hash_list(fp.macs_client_to_server)
            
            fp.ssh_fingerprint_hash = self._compute_ssh_fingerprint(fp)
            
        except Exception:
            pass
        
        return fp
    
    def identify_client(self, fingerprint: SSHFingerprint) -> Dict[str, Any]:
        """
        Attempt to identify the SSH client and assess threat level.
        
        Returns dict with:
        - identified: bool
        - client_type: str
        - threat_level: str (low/medium/high/critical)
        - notes: str
        - indicators: list of suspicious indicators
        """
        result = {
            'identified': False,
            'client_type': 'unknown',
            'threat_level': 'unknown',
            'notes': '',
            'indicators': []
        }
        
        # Check version string against known clients
        for client_id, info in self.KNOWN_CLIENTS.items():
            if re.search(info['pattern'], fingerprint.client_software, re.I):
                result['identified'] = True
                result['client_type'] = client_id
                result['threat_level'] = info['threat_level']
                result['notes'] = info['notes']
                break
        
        # Check for suspicious algorithm configurations
        if len(fingerprint.kex_algorithms) < self.TOOL_INDICATORS['minimal_kex']:
            result['indicators'].append('minimal_kex_algorithms')
        
        if len(fingerprint.ciphers_client_to_server) < self.TOOL_INDICATORS['minimal_ciphers']:
            result['indicators'].append('minimal_cipher_set')
        
        # Check for deprecated algorithms (may indicate modified/old tools)
        for kex in fingerprint.kex_algorithms:
            if kex in self.TOOL_INDICATORS['deprecated_kex']:
                result['indicators'].append(f'deprecated_kex:{kex}')
        
        for cipher in fingerprint.ciphers_client_to_server:
            if cipher in self.TOOL_INDICATORS['deprecated_ciphers']:
                result['indicators'].append(f'deprecated_cipher:{cipher}')
        
        # Escalate threat level based on indicators
        if result['indicators'] and result['threat_level'] == 'low':
            result['threat_level'] = 'medium'
        if len(result['indicators']) >= 3:
            result['threat_level'] = 'high'
        
        return result
    
    def _hash_list(self, items: List[str]) -> str:
        """Create hash of algorithm list preserving order"""
        if not items:
            return ""
        combined = ','.join(items)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def _compute_ssh_fingerprint(self, fp: SSHFingerprint) -> str:
        """Compute combined SSH fingerprint hash"""
        components = [
            fp.client_software,
            fp.kex_hash,
            fp.cipher_hash,
            fp.mac_hash,
            fp.host_key_hash,
        ]
        combined = '|'.join(filter(None, components))
        if not combined:
            return ""
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def compute_similarity(self, fp1: SSHFingerprint, fp2: SSHFingerprint) -> float:
        """
        Compute similarity score between two SSH fingerprints.
        
        Returns: float between 0.0 (no match) and 1.0 (identical)
        """
        if not fp1 or not fp2:
            return 0.0
        
        score = 0.0
        weights = {
            'ssh_fingerprint_hash': 0.4,  # Exact match is highly significant
            'client_software': 0.15,
            'kex_hash': 0.15,
            'cipher_hash': 0.15,
            'mac_hash': 0.1,
            'host_key_hash': 0.05,
        }
        
        # Exact hash match
        if fp1.ssh_fingerprint_hash and fp1.ssh_fingerprint_hash == fp2.ssh_fingerprint_hash:
            score += weights['ssh_fingerprint_hash']
        
        # Component matches
        if fp1.client_software and fp1.client_software == fp2.client_software:
            score += weights['client_software']
        
        if fp1.kex_hash and fp1.kex_hash == fp2.kex_hash:
            score += weights['kex_hash']
        
        if fp1.cipher_hash and fp1.cipher_hash == fp2.cipher_hash:
            score += weights['cipher_hash']
        
        if fp1.mac_hash and fp1.mac_hash == fp2.mac_hash:
            score += weights['mac_hash']
        
        if fp1.host_key_hash and fp1.host_key_hash == fp2.host_key_hash:
            score += weights['host_key_hash']
        
        return min(score, 1.0)
