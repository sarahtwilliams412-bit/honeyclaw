#!/usr/bin/env python3
"""
Honeyclaw Fingerprint Database

Persistent storage for attacker fingerprints and profiles.
Supports SQLite for single-node and can be extended for distributed storage.
"""

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Any, List, Optional

from .engine import AttackerProfile
from .extractors.ssh import SSHFingerprint
from .extractors.http import HTTPFingerprint, TLSFingerprint
from .extractors.behavior import BehaviorFingerprint, TypingPattern, SessionPattern


class FingerprintDatabase:
    """
    SQLite-based fingerprint storage with indexing for fast lookups.
    
    Tables:
    - profiles: Core attacker profiles
    - fingerprints: All fingerprint hashes (indexed)
    - sessions: Individual session records
    - ip_associations: IP to attacker mapping
    
    Usage:
        db = FingerprintDatabase('/path/to/fingerprints.db')
        
        # Save profile
        db.save_profile(profile)
        
        # Lookup
        profile = db.get_profile('ATK-ABCD1234-5678')
        profiles = db.search_by_ip('192.168.1.1')
    """
    
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file. Defaults to fingerprints.db
        """
        if db_path is None:
            db_path = str(Path.home() / '.honeyclaw' / 'fingerprints.db')
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._local = threading.local()
        self._init_schema()
    
    @contextmanager
    def _get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute('PRAGMA journal_mode=WAL')
            self._local.conn.execute('PRAGMA synchronous=NORMAL')
        
        try:
            yield self._local.conn
        except Exception:
            self._local.conn.rollback()
            raise
    
    def _init_schema(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Schema version tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            # Profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS profiles (
                    attacker_id TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    session_count INTEGER DEFAULT 0,
                    threat_level TEXT DEFAULT 'unknown',
                    combined_hash TEXT,
                    profile_data TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    updated_at REAL DEFAULT (strftime('%s', 'now'))
                )
            ''')
            
            # Fingerprint hashes (for fast lookup)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fingerprints (
                    hash TEXT PRIMARY KEY,
                    attacker_id TEXT,
                    fingerprint_type TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (attacker_id) REFERENCES profiles(attacker_id)
                )
            ''')
            
            # IP associations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_associations (
                    ip TEXT,
                    attacker_id TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    session_count INTEGER DEFAULT 1,
                    PRIMARY KEY (ip, attacker_id),
                    FOREIGN KEY (attacker_id) REFERENCES profiles(attacker_id)
                )
            ''')
            
            # Sessions table (individual session records)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    attacker_id TEXT,
                    ip TEXT,
                    timestamp REAL,
                    protocol TEXT,
                    fingerprint_data TEXT,
                    FOREIGN KEY (attacker_id) REFERENCES profiles(attacker_id)
                )
            ''')
            
            # TTP detections
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ttp_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attacker_id TEXT,
                    ttp_id TEXT,
                    detected_at REAL,
                    session_id TEXT,
                    FOREIGN KEY (attacker_id) REFERENCES profiles(attacker_id)
                )
            ''')
            
            # Indices
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_profiles_combined_hash ON profiles(combined_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_profiles_threat_level ON profiles(threat_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON profiles(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_fingerprints_attacker ON fingerprints(attacker_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_attacker ON ip_associations(attacker_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_last_seen ON ip_associations(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_attacker ON sessions(attacker_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ttp_attacker ON ttp_detections(attacker_id)')
            
            # Set schema version
            cursor.execute(
                'INSERT OR REPLACE INTO schema_info (key, value) VALUES (?, ?)',
                ('version', str(self.SCHEMA_VERSION))
            )
            
            conn.commit()
    
    def save_profile(self, profile: AttackerProfile) -> bool:
        """
        Save or update attacker profile.
        
        Args:
            profile: AttackerProfile to save
            
        Returns:
            True if successful
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = time.time()
            
            # Serialize profile data
            profile_data = json.dumps(profile.to_dict())
            
            # Upsert profile
            cursor.execute('''
                INSERT INTO profiles (
                    attacker_id, first_seen, last_seen, session_count,
                    threat_level, combined_hash, profile_data, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(attacker_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    session_count = excluded.session_count,
                    threat_level = excluded.threat_level,
                    combined_hash = excluded.combined_hash,
                    profile_data = excluded.profile_data,
                    updated_at = ?
            ''', (
                profile.attacker_id,
                profile.first_seen,
                profile.last_seen,
                profile.session_count,
                profile.threat_level,
                profile.combined_hash,
                profile_data,
                now,
                now
            ))
            
            # Index all fingerprint hashes
            self._index_fingerprints(cursor, profile)
            
            # Update IP associations
            for ip in profile.known_ips:
                cursor.execute('''
                    INSERT INTO ip_associations (ip, attacker_id, first_seen, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip, attacker_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        session_count = session_count + 1
                ''', (ip, profile.attacker_id, profile.first_seen, profile.last_seen))
            
            # Index TTPs
            for ttp in profile.ttp_matches:
                cursor.execute('''
                    INSERT OR IGNORE INTO ttp_detections (attacker_id, ttp_id, detected_at)
                    VALUES (?, ?, ?)
                ''', (profile.attacker_id, ttp, now))
            
            conn.commit()
            return True
    
    def _index_fingerprints(self, cursor, profile: AttackerProfile):
        """Index all fingerprint hashes for quick lookup"""
        hashes = []
        
        # Combined hash
        if profile.combined_hash:
            hashes.append((profile.combined_hash, 'combined'))
        
        # SSH fingerprints
        for ssh_fp in profile.ssh_fingerprints:
            if ssh_fp.ssh_fingerprint_hash:
                hashes.append((ssh_fp.ssh_fingerprint_hash, 'ssh'))
            if ssh_fp.kex_hash:
                hashes.append((ssh_fp.kex_hash, 'ssh_kex'))
            if ssh_fp.cipher_hash:
                hashes.append((ssh_fp.cipher_hash, 'ssh_cipher'))
        
        # HTTP fingerprints
        for http_fp in profile.http_fingerprints:
            if http_fp.http_fingerprint_hash:
                hashes.append((http_fp.http_fingerprint_hash, 'http'))
            if http_fp.header_order_hash:
                hashes.append((http_fp.header_order_hash, 'http_headers'))
            if http_fp.tls and http_fp.tls.ja3_hash:
                hashes.append((http_fp.tls.ja3_hash, 'ja3'))
        
        # Behavior fingerprint
        if profile.behavior:
            if profile.behavior.behavior_hash:
                hashes.append((profile.behavior.behavior_hash, 'behavior'))
            if profile.behavior.command_sequence_hash:
                hashes.append((profile.behavior.command_sequence_hash, 'commands'))
            if profile.behavior.n_gram_hash:
                hashes.append((profile.behavior.n_gram_hash, 'ngrams'))
        
        # Insert all hashes
        for fp_hash, fp_type in hashes:
            cursor.execute('''
                INSERT OR REPLACE INTO fingerprints (hash, attacker_id, fingerprint_type)
                VALUES (?, ?, ?)
            ''', (fp_hash, profile.attacker_id, fp_type))
    
    def get_profile(self, attacker_id: str) -> Optional[AttackerProfile]:
        """
        Retrieve attacker profile by ID.
        
        Args:
            attacker_id: Attacker ID to lookup
            
        Returns:
            AttackerProfile or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT profile_data FROM profiles WHERE attacker_id = ?',
                (attacker_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
            
            return self._deserialize_profile(json.loads(row['profile_data']))
    
    def search_by_ip(self, ip: str, limit: int = 10) -> List[AttackerProfile]:
        """
        Find all attackers associated with an IP.
        
        Args:
            ip: IP address to search
            limit: Maximum results
            
        Returns:
            List of AttackerProfile objects
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT p.profile_data
                FROM profiles p
                JOIN ip_associations ia ON p.attacker_id = ia.attacker_id
                WHERE ia.ip = ?
                ORDER BY ia.last_seen DESC
                LIMIT ?
            ''', (ip, limit))
            
            profiles = []
            for row in cursor.fetchall():
                profiles.append(self._deserialize_profile(json.loads(row['profile_data'])))
            
            return profiles
    
    def search_by_fingerprint(self, fp_hash: str) -> Optional[AttackerProfile]:
        """
        Find attacker by any fingerprint hash.
        
        Args:
            fp_hash: Fingerprint hash to search
            
        Returns:
            AttackerProfile or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT p.profile_data
                FROM profiles p
                JOIN fingerprints f ON p.attacker_id = f.attacker_id
                WHERE f.hash = ?
                LIMIT 1
            ''', (fp_hash,))
            
            row = cursor.fetchone()
            if row:
                return self._deserialize_profile(json.loads(row['profile_data']))
            
            return None
    
    def search_similar(self, combined_hash: str, limit: int = 10) -> List[AttackerProfile]:
        """
        Find profiles with similar fingerprints.
        
        This does prefix matching on hashes for approximate similarity.
        For true similarity, use FingerprintEngine.find_similar_profiles().
        
        Args:
            combined_hash: Combined hash to match
            limit: Maximum results
            
        Returns:
            List of similar profiles
        """
        if not combined_hash:
            return []
        
        # Use prefix matching (first 8 chars) for approximate similarity
        prefix = combined_hash[:8]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT profile_data
                FROM profiles
                WHERE combined_hash LIKE ? || '%'
                ORDER BY last_seen DESC
                LIMIT ?
            ''', (prefix, limit))
            
            profiles = []
            for row in cursor.fetchall():
                profiles.append(self._deserialize_profile(json.loads(row['profile_data'])))
            
            return profiles
    
    def search_by_threat_level(self, threat_level: str, 
                               limit: int = 100) -> List[AttackerProfile]:
        """
        Find attackers by threat level.
        
        Args:
            threat_level: 'low', 'medium', 'high', or 'critical'
            limit: Maximum results
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT profile_data
                FROM profiles
                WHERE threat_level = ?
                ORDER BY last_seen DESC
                LIMIT ?
            ''', (threat_level, limit))
            
            profiles = []
            for row in cursor.fetchall():
                profiles.append(self._deserialize_profile(json.loads(row['profile_data'])))
            
            return profiles
    
    def search_by_ttp(self, ttp_id: str, limit: int = 100) -> List[AttackerProfile]:
        """
        Find attackers who used a specific TTP.
        
        Args:
            ttp_id: MITRE ATT&CK TTP ID (e.g., 'T1087_account_discovery')
            limit: Maximum results
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT p.profile_data
                FROM profiles p
                JOIN ttp_detections t ON p.attacker_id = t.attacker_id
                WHERE t.ttp_id = ?
                ORDER BY t.detected_at DESC
                LIMIT ?
            ''', (ttp_id, limit))
            
            profiles = []
            for row in cursor.fetchall():
                profiles.append(self._deserialize_profile(json.loads(row['profile_data'])))
            
            return profiles
    
    def get_recent_attackers(self, hours: int = 24, 
                            limit: int = 100) -> List[AttackerProfile]:
        """Get recently active attackers"""
        cutoff = time.time() - (hours * 3600)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT profile_data
                FROM profiles
                WHERE last_seen > ?
                ORDER BY last_seen DESC
                LIMIT ?
            ''', (cutoff, limit))
            
            profiles = []
            for row in cursor.fetchall():
                profiles.append(self._deserialize_profile(json.loads(row['profile_data'])))
            
            return profiles
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            cursor.execute('SELECT COUNT(*) FROM profiles')
            stats['total_profiles'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM fingerprints')
            stats['total_fingerprints'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT ip) FROM ip_associations')
            stats['unique_ips'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM sessions')
            stats['total_sessions'] = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT threat_level, COUNT(*) as count
                FROM profiles
                GROUP BY threat_level
            ''')
            stats['by_threat_level'] = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT COUNT(*)
                FROM profiles
                WHERE last_seen > ?
            ''', (time.time() - 86400,))
            stats['active_24h'] = cursor.fetchone()[0]
            
            return stats
    
    def _deserialize_profile(self, data: Dict[str, Any]) -> AttackerProfile:
        """Deserialize profile from stored JSON"""
        profile = AttackerProfile(
            attacker_id=data.get('attacker_id', ''),
            confidence=data.get('confidence', 0.0),
            session_count=data.get('session_count', 0),
            threat_level=data.get('threat_level', 'unknown'),
            combined_hash=data.get('combined_hash', ''),
            threat_indicators=data.get('threat_indicators', []),
            ttp_matches=data.get('ttp_matches', []),
            identified_tools=data.get('identified_tools', []),
            known_ips=data.get('known_ips', []),
            notes=data.get('notes', []),
            tags=data.get('tags', []),
        )
        
        # Parse timestamps
        if data.get('first_seen'):
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(data['first_seen'].replace('Z', '+00:00'))
                profile.first_seen = dt.timestamp()
            except Exception:
                pass
        
        if data.get('last_seen'):
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(data['last_seen'].replace('Z', '+00:00'))
                profile.last_seen = dt.timestamp()
            except Exception:
                pass
        
        # Deserialize SSH fingerprints
        for ssh_data in data.get('ssh_fingerprints', []):
            ssh_fp = SSHFingerprint(
                client_version=ssh_data.get('client_version', ''),
                client_software=ssh_data.get('client_software', ''),
                client_software_version=ssh_data.get('client_software_version', ''),
                kex_algorithms=ssh_data.get('kex_algorithms', []),
                kex_hash=ssh_data.get('kex_hash', ''),
                ciphers_client_to_server=ssh_data.get('ciphers', []),
                cipher_hash=ssh_data.get('cipher_hash', ''),
                macs_client_to_server=ssh_data.get('macs', []),
                mac_hash=ssh_data.get('mac_hash', ''),
                host_key_algorithms=ssh_data.get('host_key_algorithms', []),
                host_key_hash=ssh_data.get('host_key_hash', ''),
                ssh_fingerprint_hash=ssh_data.get('ssh_fingerprint_hash', ''),
            )
            profile.ssh_fingerprints.append(ssh_fp)
        
        # Deserialize HTTP fingerprints
        for http_data in data.get('http_fingerprints', []):
            http_fp = HTTPFingerprint(
                header_order=http_data.get('header_order', []),
                header_order_hash=http_data.get('header_order_hash', ''),
                user_agent=http_data.get('user_agent', ''),
                method=http_data.get('method', ''),
                http_version=http_data.get('http_version', ''),
                http_fingerprint_hash=http_data.get('http_fingerprint_hash', ''),
            )
            if http_data.get('tls'):
                tls_data = http_data['tls']
                http_fp.tls = TLSFingerprint(
                    tls_version=tls_data.get('tls_version', 0),
                    ja3_hash=tls_data.get('ja3_hash', ''),
                    ja3_string=tls_data.get('ja3_string', ''),
                    ja4_hash=tls_data.get('ja4_hash', ''),
                    alpn_protocols=tls_data.get('alpn', []),
                    sni_hostname=tls_data.get('sni', ''),
                )
            profile.http_fingerprints.append(http_fp)
        
        # Deserialize behavior fingerprint
        if data.get('behavior'):
            bdata = data['behavior']
            profile.behavior = BehaviorFingerprint(
                command_sequence_hash=bdata.get('command_sequence_hash', ''),
                n_gram_hash=bdata.get('n_gram_hash', ''),
                phase_progression=bdata.get('phase_progression', ''),
                behavior_hash=bdata.get('behavior_hash', ''),
                threat_indicators=bdata.get('threat_indicators', []),
                ttp_matches=bdata.get('ttp_matches', []),
            )
            
            if bdata.get('typing'):
                tdata = bdata['typing']
                profile.behavior.typing = TypingPattern(
                    avg_char_delay=tdata.get('avg_char_delay_ms', 0),
                    char_delay_stddev=tdata.get('char_delay_stddev', 0),
                    avg_word_pause=tdata.get('avg_word_pause_ms', 0),
                    backspace_rate=tdata.get('backspace_rate', 0),
                    common_typos=tdata.get('common_typos', []),
                )
            
            if bdata.get('session'):
                sdata = bdata['session']
                profile.behavior.session = SessionPattern(
                    time_of_day=sdata.get('time_of_day', 0),
                    day_of_week=sdata.get('day_of_week', 0),
                    session_duration=sdata.get('session_duration_s', 0),
                    command_count=sdata.get('command_count', 0),
                    commands_per_minute=sdata.get('commands_per_minute', 0),
                )
        
        return profile
    
    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Convenience function for quick database access
def get_database(path: str = None) -> FingerprintDatabase:
    """Get or create fingerprint database instance"""
    return FingerprintDatabase(path)
