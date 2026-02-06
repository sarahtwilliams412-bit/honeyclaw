#!/usr/bin/env python3
"""
Honeyclaw Fingerprinting Engine

Core fingerprinting logic that combines multiple extractors to build
unique attacker profiles that can be correlated across different IPs.
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from .extractors.ssh import SSHFingerprintExtractor, SSHFingerprint
from .extractors.http import HTTPFingerprintExtractor, HTTPFingerprint, TLSFingerprint
from .extractors.behavior import BehaviorFingerprintExtractor, BehaviorFingerprint, CommandPattern


@dataclass
class AttackerProfile:
    """
    Complete attacker profile combining all fingerprint types.
    
    This represents a unique attacker identity that can be tracked
    across multiple sessions and IP addresses.
    """
    # Unique identifier for this attacker
    attacker_id: str = ""
    
    # Confidence score (0.0 - 1.0) for the profile match
    confidence: float = 0.0
    
    # First and last seen timestamps
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # All IPs associated with this attacker
    known_ips: List[str] = field(default_factory=list)
    
    # Session count
    session_count: int = 0
    
    # Protocol fingerprints
    ssh_fingerprints: List[SSHFingerprint] = field(default_factory=list)
    http_fingerprints: List[HTTPFingerprint] = field(default_factory=list)
    
    # Behavioral fingerprint (aggregated)
    behavior: Optional[BehaviorFingerprint] = None
    
    # Threat assessment
    threat_level: str = "unknown"  # low, medium, high, critical
    threat_indicators: List[str] = field(default_factory=list)
    ttp_matches: List[str] = field(default_factory=list)
    
    # Tool identification
    identified_tools: List[str] = field(default_factory=list)
    
    # Combined fingerprint hash (for quick matching)
    combined_hash: str = ""
    
    # Metadata
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary for storage/display"""
        return {
            'attacker_id': self.attacker_id,
            'confidence': round(self.confidence, 3),
            'first_seen': datetime.fromtimestamp(self.first_seen).isoformat() if self.first_seen else None,
            'last_seen': datetime.fromtimestamp(self.last_seen).isoformat() if self.last_seen else None,
            'known_ips': self.known_ips,
            'session_count': self.session_count,
            'threat_level': self.threat_level,
            'threat_indicators': self.threat_indicators,
            'ttp_matches': self.ttp_matches,
            'identified_tools': self.identified_tools,
            'combined_hash': self.combined_hash,
            'ssh_fingerprints': [fp.to_dict() for fp in self.ssh_fingerprints[-3:]],  # Last 3
            'http_fingerprints': [fp.to_dict() for fp in self.http_fingerprints[-3:]],
            'behavior': self.behavior.to_dict() if self.behavior else None,
            'notes': self.notes,
            'tags': self.tags,
        }
    
    def to_log_entry(self) -> Dict[str, Any]:
        """Generate compact log entry for session logs"""
        return {
            'attacker_id': self.attacker_id,
            'confidence': round(self.confidence, 2),
            'threat_level': self.threat_level,
            'session_count': self.session_count,
            'known_ips_count': len(self.known_ips),
            'ttp_matches': self.ttp_matches[:3],  # Top 3
            'identified_tools': self.identified_tools[:2],  # Top 2
        }


class FingerprintEngine:
    """
    Core fingerprinting engine that orchestrates fingerprint extraction,
    profile matching, and attacker correlation.
    
    Usage:
        engine = FingerprintEngine()
        
        # Process a new session
        profile = engine.process_session(session_data)
        
        # Get attacker info for logging
        log_entry = profile.to_log_entry()
    """
    
    # Similarity thresholds for matching
    MATCH_THRESHOLD_HIGH = 0.85  # Very likely same attacker
    MATCH_THRESHOLD_MEDIUM = 0.65  # Probably same attacker
    MATCH_THRESHOLD_LOW = 0.45  # Possibly related
    
    # Weights for combining fingerprint types
    FINGERPRINT_WEIGHTS = {
        'ssh': 0.35,
        'http': 0.30,
        'behavior': 0.35,
    }
    
    def __init__(self, database=None):
        """
        Initialize fingerprinting engine.
        
        Args:
            database: Optional FingerprintDatabase for persistence
        """
        self.ssh_extractor = SSHFingerprintExtractor()
        self.http_extractor = HTTPFingerprintExtractor()
        self.behavior_extractor = BehaviorFingerprintExtractor()
        self.database = database
        
        # In-memory cache for quick lookups
        self._profile_cache: Dict[str, AttackerProfile] = {}
        self._hash_index: Dict[str, str] = {}  # fingerprint_hash -> attacker_id
    
    def process_session(self, session_data: Dict[str, Any]) -> AttackerProfile:
        """
        Process a session and return/update attacker profile.
        
        Args:
            session_data: Dict containing session information:
                - ip: Client IP address
                - timestamp: Session start time
                - protocol: 'ssh', 'http', 'rdp', etc.
                - ssh_version: (optional) SSH version string
                - ssh_kex_init: (optional) SSH KEXINIT payload bytes
                - http_headers: (optional) Dict of HTTP headers
                - http_method: (optional) HTTP method
                - tls_client_hello: (optional) TLS Client Hello bytes
                - commands: (optional) List of command dicts with timing
                
        Returns:
            AttackerProfile for this session (new or matched existing)
        """
        ip = session_data.get('ip', 'unknown')
        timestamp = session_data.get('timestamp', time.time())
        protocol = session_data.get('protocol', 'unknown')
        
        # Extract fingerprints based on protocol
        ssh_fp = None
        http_fp = None
        behavior_fp = None
        
        if protocol == 'ssh' or 'ssh_version' in session_data:
            ssh_fp = self._extract_ssh_fingerprint(session_data)
        
        if protocol == 'http' or 'http_headers' in session_data:
            http_fp = self._extract_http_fingerprint(session_data)
        
        if 'commands' in session_data:
            behavior_fp = self._extract_behavior_fingerprint(session_data)
        
        # Try to match against existing profiles
        matched_profile, confidence = self._find_matching_profile(
            ssh_fp, http_fp, behavior_fp, ip
        )
        
        if matched_profile and confidence >= self.MATCH_THRESHOLD_MEDIUM:
            # Update existing profile
            profile = self._update_profile(
                matched_profile, ssh_fp, http_fp, behavior_fp, ip, timestamp
            )
            profile.confidence = confidence
        else:
            # Create new profile
            profile = self._create_new_profile(
                ssh_fp, http_fp, behavior_fp, ip, timestamp
            )
        
        # Assess threat level
        self._assess_threat(profile)
        
        # Persist if database available
        if self.database:
            self.database.save_profile(profile)
        
        # Update caches
        self._cache_profile(profile)
        
        return profile
    
    def process_ssh_connection(self, ip: str, version_string: str = None,
                               kex_init: bytes = None, conn=None) -> AttackerProfile:
        """
        Convenience method for processing SSH connections.
        
        Args:
            ip: Client IP
            version_string: SSH version string
            kex_init: SSH KEXINIT payload
            conn: AsyncSSH connection object (alternative to version_string)
        """
        session_data = {
            'ip': ip,
            'protocol': 'ssh',
            'timestamp': time.time(),
        }
        
        if version_string:
            session_data['ssh_version'] = version_string
        if kex_init:
            session_data['ssh_kex_init'] = kex_init
        if conn:
            session_data['ssh_conn'] = conn
        
        return self.process_session(session_data)
    
    def add_commands(self, attacker_id: str, commands: List[Dict]) -> Optional[AttackerProfile]:
        """
        Add command data to an existing profile.
        
        Args:
            attacker_id: Attacker profile ID
            commands: List of command dicts with 'command' and 'timestamp'
        """
        profile = self._get_profile(attacker_id)
        if not profile:
            return None
        
        session_data = {'commands': commands}
        behavior_fp = self._extract_behavior_fingerprint(session_data)
        
        if behavior_fp:
            if profile.behavior:
                # Merge behaviors
                profile.behavior.command_sequence.extend(behavior_fp.command_sequence)
                profile.behavior.ttp_matches = list(set(
                    profile.behavior.ttp_matches + behavior_fp.ttp_matches
                ))
                profile.behavior.threat_indicators = list(set(
                    profile.behavior.threat_indicators + behavior_fp.threat_indicators
                ))
            else:
                profile.behavior = behavior_fp
            
            # Update combined hash
            profile.combined_hash = self._compute_combined_hash(profile)
            
            # Re-assess threat
            self._assess_threat(profile)
            
            if self.database:
                self.database.save_profile(profile)
        
        return profile
    
    def get_profile(self, attacker_id: str) -> Optional[AttackerProfile]:
        """Get attacker profile by ID"""
        return self._get_profile(attacker_id)
    
    def find_similar_profiles(self, profile: AttackerProfile, 
                             limit: int = 10) -> List[Tuple[AttackerProfile, float]]:
        """
        Find profiles similar to the given one.
        
        Returns list of (profile, similarity_score) tuples.
        """
        results = []
        
        for cached_profile in self._profile_cache.values():
            if cached_profile.attacker_id == profile.attacker_id:
                continue
            
            similarity = self._compute_similarity(profile, cached_profile)
            if similarity >= self.MATCH_THRESHOLD_LOW:
                results.append((cached_profile, similarity))
        
        # Also check database
        if self.database:
            db_profiles = self.database.search_similar(profile.combined_hash, limit=limit*2)
            for db_profile in db_profiles:
                if db_profile.attacker_id not in self._profile_cache:
                    similarity = self._compute_similarity(profile, db_profile)
                    if similarity >= self.MATCH_THRESHOLD_LOW:
                        results.append((db_profile, similarity))
        
        # Sort by similarity and limit
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            'profiles_cached': len(self._profile_cache),
            'hash_index_size': len(self._hash_index),
            'database_connected': self.database is not None,
        }
    
    # -------------------------------------------------------------------------
    # Private methods
    # -------------------------------------------------------------------------
    
    def _extract_ssh_fingerprint(self, session_data: Dict) -> Optional[SSHFingerprint]:
        """Extract SSH fingerprint from session data"""
        fp = None
        
        if 'ssh_conn' in session_data:
            fp = self.ssh_extractor.extract_from_asyncssh_conn(session_data['ssh_conn'])
        elif 'ssh_version' in session_data:
            fp = self.ssh_extractor.extract_from_version(session_data['ssh_version'])
        
        if fp and 'ssh_kex_init' in session_data:
            fp = self.ssh_extractor.extract_from_kex_init(
                session_data['ssh_kex_init'], fp
            )
        
        return fp
    
    def _extract_http_fingerprint(self, session_data: Dict) -> Optional[HTTPFingerprint]:
        """Extract HTTP fingerprint from session data"""
        fp = None
        
        if 'http_headers' in session_data:
            fp = self.http_extractor.extract_from_headers(
                session_data['http_headers'],
                method=session_data.get('http_method', 'GET'),
                http_version=session_data.get('http_version', '1.1')
            )
        
        if 'tls_client_hello' in session_data:
            tls_fp = self.http_extractor.extract_from_client_hello(
                session_data['tls_client_hello']
            )
            if fp:
                fp.tls = tls_fp
            else:
                fp = HTTPFingerprint(tls=tls_fp)
        
        return fp
    
    def _extract_behavior_fingerprint(self, session_data: Dict) -> Optional[BehaviorFingerprint]:
        """Extract behavioral fingerprint from session data"""
        if 'commands' not in session_data:
            return None
        
        commands = []
        last_ts = None
        
        for cmd_data in session_data['commands']:
            ts = cmd_data.get('timestamp', 0)
            cmd = CommandPattern(
                command=cmd_data.get('command', ''),
                timestamp=ts,
                time_since_last=ts - last_ts if last_ts else 0
            )
            last_ts = ts
            commands.append(cmd)
        
        if not commands:
            return None
        
        return self.behavior_extractor.extract_from_commands(commands)
    
    def _find_matching_profile(self, ssh_fp: Optional[SSHFingerprint],
                               http_fp: Optional[HTTPFingerprint],
                               behavior_fp: Optional[BehaviorFingerprint],
                               ip: str) -> Tuple[Optional[AttackerProfile], float]:
        """Find best matching existing profile"""
        best_match = None
        best_score = 0.0
        
        # Quick lookup by fingerprint hashes
        hashes_to_check = []
        if ssh_fp and ssh_fp.ssh_fingerprint_hash:
            hashes_to_check.append(ssh_fp.ssh_fingerprint_hash)
        if http_fp and http_fp.http_fingerprint_hash:
            hashes_to_check.append(http_fp.http_fingerprint_hash)
        if behavior_fp and behavior_fp.behavior_hash:
            hashes_to_check.append(behavior_fp.behavior_hash)
        
        # Check hash index for quick matches
        for fp_hash in hashes_to_check:
            if fp_hash in self._hash_index:
                attacker_id = self._hash_index[fp_hash]
                profile = self._get_profile(attacker_id)
                if profile:
                    score = self._compute_fingerprint_similarity(
                        profile, ssh_fp, http_fp, behavior_fp
                    )
                    if score > best_score:
                        best_score = score
                        best_match = profile
        
        # If no quick match, do full search
        if not best_match or best_score < self.MATCH_THRESHOLD_HIGH:
            for profile in self._profile_cache.values():
                score = self._compute_fingerprint_similarity(
                    profile, ssh_fp, http_fp, behavior_fp
                )
                if score > best_score:
                    best_score = score
                    best_match = profile
        
        # Check database if needed
        if self.database and (not best_match or best_score < self.MATCH_THRESHOLD_MEDIUM):
            # Search by IP first (fast)
            db_profiles = self.database.search_by_ip(ip)
            for profile in db_profiles:
                score = self._compute_fingerprint_similarity(
                    profile, ssh_fp, http_fp, behavior_fp
                )
                if score > best_score:
                    best_score = score
                    best_match = profile
        
        return best_match, best_score
    
    def _compute_fingerprint_similarity(self, profile: AttackerProfile,
                                        ssh_fp: Optional[SSHFingerprint],
                                        http_fp: Optional[HTTPFingerprint],
                                        behavior_fp: Optional[BehaviorFingerprint]) -> float:
        """Compute similarity between profile and new fingerprints"""
        total_score = 0.0
        total_weight = 0.0
        
        # SSH similarity
        if ssh_fp and profile.ssh_fingerprints:
            best_ssh = max(
                self.ssh_extractor.compute_similarity(ssh_fp, existing)
                for existing in profile.ssh_fingerprints
            )
            total_score += best_ssh * self.FINGERPRINT_WEIGHTS['ssh']
            total_weight += self.FINGERPRINT_WEIGHTS['ssh']
        
        # HTTP similarity
        if http_fp and profile.http_fingerprints:
            best_http = max(
                self.http_extractor.compute_similarity(http_fp, existing)
                for existing in profile.http_fingerprints
            )
            total_score += best_http * self.FINGERPRINT_WEIGHTS['http']
            total_weight += self.FINGERPRINT_WEIGHTS['http']
        
        # Behavior similarity
        if behavior_fp and profile.behavior:
            behavior_score = self.behavior_extractor.compute_similarity(
                behavior_fp, profile.behavior
            )
            total_score += behavior_score * self.FINGERPRINT_WEIGHTS['behavior']
            total_weight += self.FINGERPRINT_WEIGHTS['behavior']
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _compute_similarity(self, p1: AttackerProfile, p2: AttackerProfile) -> float:
        """Compute similarity between two profiles"""
        score = 0.0
        
        # Combined hash match
        if p1.combined_hash and p1.combined_hash == p2.combined_hash:
            return 0.95
        
        # Compare fingerprints
        if p1.ssh_fingerprints and p2.ssh_fingerprints:
            ssh_scores = []
            for fp1 in p1.ssh_fingerprints:
                for fp2 in p2.ssh_fingerprints:
                    ssh_scores.append(self.ssh_extractor.compute_similarity(fp1, fp2))
            if ssh_scores:
                score += max(ssh_scores) * 0.35
        
        if p1.http_fingerprints and p2.http_fingerprints:
            http_scores = []
            for fp1 in p1.http_fingerprints:
                for fp2 in p2.http_fingerprints:
                    http_scores.append(self.http_extractor.compute_similarity(fp1, fp2))
            if http_scores:
                score += max(http_scores) * 0.30
        
        if p1.behavior and p2.behavior:
            score += self.behavior_extractor.compute_similarity(p1.behavior, p2.behavior) * 0.35
        
        return min(score, 1.0)
    
    def _create_new_profile(self, ssh_fp: Optional[SSHFingerprint],
                           http_fp: Optional[HTTPFingerprint],
                           behavior_fp: Optional[BehaviorFingerprint],
                           ip: str, timestamp: float) -> AttackerProfile:
        """Create a new attacker profile"""
        profile = AttackerProfile(
            attacker_id=self._generate_attacker_id(),
            confidence=1.0,  # New profile, 100% match to itself
            first_seen=timestamp,
            last_seen=timestamp,
            known_ips=[ip],
            session_count=1,
        )
        
        if ssh_fp:
            profile.ssh_fingerprints.append(ssh_fp)
            # Identify SSH client
            client_info = self.ssh_extractor.identify_client(ssh_fp)
            if client_info['identified']:
                profile.identified_tools.append(f"ssh:{client_info['client_type']}")
            profile.threat_indicators.extend(client_info.get('indicators', []))
        
        if http_fp:
            profile.http_fingerprints.append(http_fp)
            # Identify HTTP client
            tool_info = self.http_extractor.identify_tool(http_fp)
            if tool_info['identified']:
                profile.identified_tools.append(f"http:{tool_info['tool']}")
            profile.threat_indicators.extend(tool_info.get('indicators', []))
        
        if behavior_fp:
            profile.behavior = behavior_fp
            profile.ttp_matches = behavior_fp.ttp_matches
            profile.threat_indicators.extend(behavior_fp.threat_indicators)
        
        profile.combined_hash = self._compute_combined_hash(profile)
        
        return profile
    
    def _update_profile(self, profile: AttackerProfile,
                       ssh_fp: Optional[SSHFingerprint],
                       http_fp: Optional[HTTPFingerprint],
                       behavior_fp: Optional[BehaviorFingerprint],
                       ip: str, timestamp: float) -> AttackerProfile:
        """Update existing profile with new session data"""
        profile.last_seen = timestamp
        profile.session_count += 1
        
        if ip not in profile.known_ips:
            profile.known_ips.append(ip)
        
        if ssh_fp:
            # Only add if significantly different
            if not any(self.ssh_extractor.compute_similarity(ssh_fp, existing) > 0.95
                      for existing in profile.ssh_fingerprints):
                profile.ssh_fingerprints.append(ssh_fp)
                # Keep only last 10
                profile.ssh_fingerprints = profile.ssh_fingerprints[-10:]
        
        if http_fp:
            if not any(self.http_extractor.compute_similarity(http_fp, existing) > 0.95
                      for existing in profile.http_fingerprints):
                profile.http_fingerprints.append(http_fp)
                profile.http_fingerprints = profile.http_fingerprints[-10:]
        
        if behavior_fp:
            if profile.behavior:
                # Merge TTPs and indicators
                profile.ttp_matches = list(set(profile.ttp_matches + behavior_fp.ttp_matches))
                profile.threat_indicators = list(set(
                    profile.threat_indicators + behavior_fp.threat_indicators
                ))
                # Update command sequence
                profile.behavior.command_sequence.extend(behavior_fp.command_sequence)
                profile.behavior.command_sequence = profile.behavior.command_sequence[-100:]
            else:
                profile.behavior = behavior_fp
        
        profile.combined_hash = self._compute_combined_hash(profile)
        
        return profile
    
    def _assess_threat(self, profile: AttackerProfile):
        """Assess and update threat level for profile"""
        threat_score = 0
        
        # Check for critical tool indicators
        critical_tools = ['ncrack', 'medusa', 'hydra', 'nikto', 'sqlmap', 'nuclei']
        for tool in profile.identified_tools:
            if any(ct in tool.lower() for ct in critical_tools):
                threat_score += 50
        
        # TTPs detected
        threat_score += len(profile.ttp_matches) * 10
        
        # Threat indicators
        critical_indicators = ['malicious_ja3', 'download_execute', 'direct_exploitation']
        for indicator in profile.threat_indicators:
            if any(ci in indicator.lower() for ci in critical_indicators):
                threat_score += 20
            else:
                threat_score += 5
        
        # Multiple IPs is suspicious
        if len(profile.known_ips) > 3:
            threat_score += 10
        
        # High session count
        if profile.session_count > 10:
            threat_score += 10
        
        # Determine level
        if threat_score >= 50:
            profile.threat_level = 'critical'
        elif threat_score >= 30:
            profile.threat_level = 'high'
        elif threat_score >= 15:
            profile.threat_level = 'medium'
        else:
            profile.threat_level = 'low'
    
    def _compute_combined_hash(self, profile: AttackerProfile) -> str:
        """Compute combined fingerprint hash for profile"""
        components = []
        
        if profile.ssh_fingerprints:
            components.append(profile.ssh_fingerprints[0].ssh_fingerprint_hash)
        if profile.http_fingerprints:
            components.append(profile.http_fingerprints[0].http_fingerprint_hash)
        if profile.behavior:
            components.append(profile.behavior.behavior_hash)
        
        if not components:
            return ""
        
        combined = '|'.join(filter(None, components))
        return hashlib.sha256(combined.encode()).hexdigest()[:32]
    
    def _generate_attacker_id(self) -> str:
        """Generate unique attacker ID"""
        # Format: ATK-<random>-<timestamp_suffix>
        random_part = uuid.uuid4().hex[:8].upper()
        time_suffix = hex(int(time.time()) % 0xFFFF)[2:].upper().zfill(4)
        return f"ATK-{random_part}-{time_suffix}"
    
    def _cache_profile(self, profile: AttackerProfile):
        """Cache profile and update hash index"""
        self._profile_cache[profile.attacker_id] = profile
        
        # Index all fingerprint hashes
        if profile.combined_hash:
            self._hash_index[profile.combined_hash] = profile.attacker_id
        
        for ssh_fp in profile.ssh_fingerprints:
            if ssh_fp.ssh_fingerprint_hash:
                self._hash_index[ssh_fp.ssh_fingerprint_hash] = profile.attacker_id
        
        for http_fp in profile.http_fingerprints:
            if http_fp.http_fingerprint_hash:
                self._hash_index[http_fp.http_fingerprint_hash] = profile.attacker_id
        
        if profile.behavior and profile.behavior.behavior_hash:
            self._hash_index[profile.behavior.behavior_hash] = profile.attacker_id
    
    def _get_profile(self, attacker_id: str) -> Optional[AttackerProfile]:
        """Get profile from cache or database"""
        if attacker_id in self._profile_cache:
            return self._profile_cache[attacker_id]
        
        if self.database:
            profile = self.database.get_profile(attacker_id)
            if profile:
                self._cache_profile(profile)
                return profile
        
        return None
