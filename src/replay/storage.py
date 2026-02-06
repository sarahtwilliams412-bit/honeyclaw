#!/usr/bin/env python3
"""
Honeyclaw Replay Storage
Store and retrieve recordings from local filesystem or S3.
"""

import json
import os
import hashlib
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from .recorder import RecordingMetadata


@dataclass
class RecordingInfo:
    """Summary info for a recording"""
    session_id: str
    protocol: str
    source_ip: str
    start_time: str
    duration_ms: int
    event_count: int
    username: Optional[str]
    file_path: str
    file_size: int
    share_token: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'protocol': self.protocol,
            'source_ip': self.source_ip,
            'start_time': self.start_time,
            'duration_ms': self.duration_ms,
            'duration_human': self._format_duration(),
            'event_count': self.event_count,
            'username': self.username,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_size_human': self._format_size(),
            'share_token': self.share_token
        }
    
    def _format_duration(self) -> str:
        """Format duration as human-readable string"""
        seconds = self.duration_ms // 1000
        if seconds < 60:
            return f"{seconds}s"
        minutes = seconds // 60
        seconds = seconds % 60
        if minutes < 60:
            return f"{minutes}m {seconds}s"
        hours = minutes // 60
        minutes = minutes % 60
        return f"{hours}h {minutes}m"
    
    def _format_size(self) -> str:
        """Format file size as human-readable string"""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


class ReplayStorage(ABC):
    """Abstract base class for replay storage"""
    
    @abstractmethod
    def save(self, session_id: str, data: Dict[str, Any], protocol: str) -> str:
        """Save recording, returns file path"""
        pass
    
    @abstractmethod
    def load(self, session_id: str) -> Dict[str, Any]:
        """Load recording by session ID"""
        pass
    
    @abstractmethod
    def delete(self, session_id: str) -> bool:
        """Delete recording"""
        pass
    
    @abstractmethod
    def list_recordings(
        self,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[RecordingInfo]:
        """List recordings with optional filters"""
        pass
    
    @abstractmethod
    def get_info(self, session_id: str) -> Optional[RecordingInfo]:
        """Get recording info without loading full data"""
        pass
    
    @abstractmethod
    def create_share_token(self, session_id: str) -> str:
        """Create a shareable token for a recording"""
        pass
    
    @abstractmethod
    def get_by_share_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get recording by share token"""
        pass


class LocalStorage(ReplayStorage):
    """Local filesystem storage for recordings"""
    
    def __init__(self, base_path: str = "/var/lib/honeyclaw/recordings"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Index file for metadata
        self.index_path = self.base_path / "index.json"
        self._index: Dict[str, Dict[str, Any]] = {}
        self._load_index()
        
        # Share tokens mapping
        self.tokens_path = self.base_path / "tokens.json"
        self._tokens: Dict[str, str] = {}  # token -> session_id
        self._load_tokens()
    
    def _load_index(self) -> None:
        """Load or create index file"""
        if self.index_path.exists():
            try:
                self._index = json.loads(self.index_path.read_text())
            except json.JSONDecodeError:
                self._index = {}
        else:
            self._index = {}
            self._save_index()
    
    def _save_index(self) -> None:
        """Save index file"""
        self.index_path.write_text(json.dumps(self._index, indent=2))
    
    def _load_tokens(self) -> None:
        """Load share tokens"""
        if self.tokens_path.exists():
            try:
                self._tokens = json.loads(self.tokens_path.read_text())
            except json.JSONDecodeError:
                self._tokens = {}
        else:
            self._tokens = {}
    
    def _save_tokens(self) -> None:
        """Save share tokens"""
        self.tokens_path.write_text(json.dumps(self._tokens, indent=2))
    
    def _get_file_path(self, session_id: str, protocol: str) -> Path:
        """Get file path for a session"""
        ext = '.cast' if protocol == 'ssh' else '.har'
        # Organize by date
        now = datetime.now()
        date_dir = self.base_path / now.strftime('%Y/%m/%d')
        date_dir.mkdir(parents=True, exist_ok=True)
        return date_dir / f"{session_id}{ext}"
    
    def save(self, session_id: str, data: Dict[str, Any], protocol: str) -> str:
        """Save recording to local filesystem"""
        file_path = self._get_file_path(session_id, protocol)
        
        # Format based on protocol
        if protocol == 'ssh':
            # asciinema NDJSON format
            header = data.get('header', {})
            events = data.get('events', [])
            lines = [json.dumps(header)]
            for event in events:
                lines.append(json.dumps(event))
            content = '\n'.join(lines)
        else:
            # HAR JSON format
            content = json.dumps(data.get('har', data), indent=2)
        
        file_path.write_text(content)
        
        # Update index
        metadata = data.get('metadata', {})
        self._index[session_id] = {
            'session_id': session_id,
            'protocol': protocol,
            'source_ip': metadata.get('source_ip', 'unknown'),
            'start_time': metadata.get('start_time', datetime.now(timezone.utc).isoformat()),
            'duration_ms': metadata.get('duration_ms', 0),
            'event_count': metadata.get('event_count', 0),
            'username': metadata.get('username'),
            'file_path': str(file_path),
            'file_size': file_path.stat().st_size
        }
        self._save_index()
        
        return str(file_path)
    
    def load(self, session_id: str) -> Dict[str, Any]:
        """Load recording from local filesystem"""
        if session_id not in self._index:
            raise FileNotFoundError(f"Recording not found: {session_id}")
        
        info = self._index[session_id]
        file_path = Path(info['file_path'])
        
        if not file_path.exists():
            raise FileNotFoundError(f"Recording file missing: {file_path}")
        
        content = file_path.read_text()
        protocol = info.get('protocol', 'ssh')
        
        if protocol == 'ssh':
            # Parse asciinema format
            lines = content.strip().split('\n')
            header = json.loads(lines[0])
            events = [json.loads(line) for line in lines[1:] if line.strip()]
            return {
                'header': header,
                'events': events,
                'metadata': header.get('honeyclaw', info)
            }
        else:
            # Parse HAR format
            har = json.loads(content)
            return {
                'har': har,
                'metadata': har.get('log', {}).get('_honeyclaw', info)
            }
    
    def delete(self, session_id: str) -> bool:
        """Delete recording"""
        if session_id not in self._index:
            return False
        
        info = self._index[session_id]
        file_path = Path(info['file_path'])
        
        # Delete file
        if file_path.exists():
            file_path.unlink()
        
        # Remove from index
        del self._index[session_id]
        self._save_index()
        
        # Remove any share tokens
        tokens_to_remove = [t for t, sid in self._tokens.items() if sid == session_id]
        for token in tokens_to_remove:
            del self._tokens[token]
        if tokens_to_remove:
            self._save_tokens()
        
        return True
    
    def list_recordings(
        self,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[RecordingInfo]:
        """List recordings with optional filters"""
        results = []
        
        for session_id, info in self._index.items():
            # Apply filters
            if protocol and info.get('protocol') != protocol:
                continue
            if source_ip and info.get('source_ip') != source_ip:
                continue
            
            # Find share token if any
            share_token = None
            for token, sid in self._tokens.items():
                if sid == session_id:
                    share_token = token
                    break
            
            results.append(RecordingInfo(
                session_id=info['session_id'],
                protocol=info.get('protocol', 'ssh'),
                source_ip=info.get('source_ip', 'unknown'),
                start_time=info.get('start_time', ''),
                duration_ms=info.get('duration_ms', 0),
                event_count=info.get('event_count', 0),
                username=info.get('username'),
                file_path=info.get('file_path', ''),
                file_size=info.get('file_size', 0),
                share_token=share_token
            ))
        
        # Sort by start time (newest first)
        results.sort(key=lambda x: x.start_time, reverse=True)
        
        # Apply pagination
        return results[offset:offset + limit]
    
    def get_info(self, session_id: str) -> Optional[RecordingInfo]:
        """Get recording info without loading full data"""
        if session_id not in self._index:
            return None
        
        info = self._index[session_id]
        
        # Find share token
        share_token = None
        for token, sid in self._tokens.items():
            if sid == session_id:
                share_token = token
                break
        
        return RecordingInfo(
            session_id=info['session_id'],
            protocol=info.get('protocol', 'ssh'),
            source_ip=info.get('source_ip', 'unknown'),
            start_time=info.get('start_time', ''),
            duration_ms=info.get('duration_ms', 0),
            event_count=info.get('event_count', 0),
            username=info.get('username'),
            file_path=info.get('file_path', ''),
            file_size=info.get('file_size', 0),
            share_token=share_token
        )
    
    def create_share_token(self, session_id: str) -> str:
        """Create a shareable token for a recording"""
        if session_id not in self._index:
            raise FileNotFoundError(f"Recording not found: {session_id}")
        
        # Check if token already exists
        for token, sid in self._tokens.items():
            if sid == session_id:
                return token
        
        # Generate new token
        token = secrets.token_urlsafe(32)
        self._tokens[token] = session_id
        self._save_tokens()
        
        return token
    
    def get_by_share_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get recording by share token"""
        session_id = self._tokens.get(token)
        if not session_id:
            return None
        
        try:
            return self.load(session_id)
        except FileNotFoundError:
            return None
    
    def revoke_share_token(self, token: str) -> bool:
        """Revoke a share token"""
        if token in self._tokens:
            del self._tokens[token]
            self._save_tokens()
            return True
        return False


class S3Storage(ReplayStorage):
    """S3 storage for recordings (requires boto3)"""
    
    def __init__(
        self,
        bucket: str,
        prefix: str = "recordings/",
        region: str = "us-east-1",
        endpoint_url: Optional[str] = None
    ):
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 required for S3Storage: pip install boto3")
        
        self.bucket = bucket
        self.prefix = prefix.rstrip('/') + '/'
        self.region = region
        
        # Create S3 client
        client_kwargs = {'region_name': region}
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url
        
        self.s3 = boto3.client('s3', **client_kwargs)
        
        # Local cache for index (in production, use DynamoDB or similar)
        self._local_index_path = Path('/tmp/honeyclaw_s3_index.json')
        self._index: Dict[str, Dict[str, Any]] = {}
        self._tokens: Dict[str, str] = {}
        self._load_index()
    
    def _load_index(self) -> None:
        """Load index from S3"""
        try:
            response = self.s3.get_object(
                Bucket=self.bucket,
                Key=f"{self.prefix}index.json"
            )
            data = json.loads(response['Body'].read().decode('utf-8'))
            self._index = data.get('recordings', {})
            self._tokens = data.get('tokens', {})
        except self.s3.exceptions.NoSuchKey:
            self._index = {}
            self._tokens = {}
        except Exception:
            # Fall back to local cache
            if self._local_index_path.exists():
                data = json.loads(self._local_index_path.read_text())
                self._index = data.get('recordings', {})
                self._tokens = data.get('tokens', {})
    
    def _save_index(self) -> None:
        """Save index to S3"""
        data = {
            'recordings': self._index,
            'tokens': self._tokens,
            'updated': datetime.now(timezone.utc).isoformat()
        }
        content = json.dumps(data, indent=2)
        
        # Save to S3
        self.s3.put_object(
            Bucket=self.bucket,
            Key=f"{self.prefix}index.json",
            Body=content.encode('utf-8'),
            ContentType='application/json'
        )
        
        # Update local cache
        self._local_index_path.write_text(content)
    
    def _get_s3_key(self, session_id: str, protocol: str) -> str:
        """Get S3 key for a session"""
        ext = '.cast' if protocol == 'ssh' else '.har'
        now = datetime.now()
        return f"{self.prefix}{now.strftime('%Y/%m/%d')}/{session_id}{ext}"
    
    def save(self, session_id: str, data: Dict[str, Any], protocol: str) -> str:
        """Save recording to S3"""
        s3_key = self._get_s3_key(session_id, protocol)
        
        # Format based on protocol
        if protocol == 'ssh':
            header = data.get('header', {})
            events = data.get('events', [])
            lines = [json.dumps(header)]
            for event in events:
                lines.append(json.dumps(event))
            content = '\n'.join(lines)
            content_type = 'application/x-ndjson'
        else:
            content = json.dumps(data.get('har', data), indent=2)
            content_type = 'application/json'
        
        # Upload to S3
        self.s3.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=content.encode('utf-8'),
            ContentType=content_type
        )
        
        # Update index
        metadata = data.get('metadata', {})
        self._index[session_id] = {
            'session_id': session_id,
            'protocol': protocol,
            'source_ip': metadata.get('source_ip', 'unknown'),
            'start_time': metadata.get('start_time', datetime.now(timezone.utc).isoformat()),
            'duration_ms': metadata.get('duration_ms', 0),
            'event_count': metadata.get('event_count', 0),
            'username': metadata.get('username'),
            's3_key': s3_key,
            'file_size': len(content)
        }
        self._save_index()
        
        return f"s3://{self.bucket}/{s3_key}"
    
    def load(self, session_id: str) -> Dict[str, Any]:
        """Load recording from S3"""
        if session_id not in self._index:
            raise FileNotFoundError(f"Recording not found: {session_id}")
        
        info = self._index[session_id]
        s3_key = info.get('s3_key')
        
        response = self.s3.get_object(Bucket=self.bucket, Key=s3_key)
        content = response['Body'].read().decode('utf-8')
        protocol = info.get('protocol', 'ssh')
        
        if protocol == 'ssh':
            lines = content.strip().split('\n')
            header = json.loads(lines[0])
            events = [json.loads(line) for line in lines[1:] if line.strip()]
            return {
                'header': header,
                'events': events,
                'metadata': header.get('honeyclaw', info)
            }
        else:
            har = json.loads(content)
            return {
                'har': har,
                'metadata': har.get('log', {}).get('_honeyclaw', info)
            }
    
    def delete(self, session_id: str) -> bool:
        """Delete recording from S3"""
        if session_id not in self._index:
            return False
        
        info = self._index[session_id]
        s3_key = info.get('s3_key')
        
        # Delete from S3
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=s3_key)
        except Exception:
            pass
        
        # Remove from index
        del self._index[session_id]
        
        # Remove tokens
        tokens_to_remove = [t for t, sid in self._tokens.items() if sid == session_id]
        for token in tokens_to_remove:
            del self._tokens[token]
        
        self._save_index()
        return True
    
    def list_recordings(
        self,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[RecordingInfo]:
        """List recordings"""
        results = []
        
        for session_id, info in self._index.items():
            if protocol and info.get('protocol') != protocol:
                continue
            if source_ip and info.get('source_ip') != source_ip:
                continue
            
            share_token = None
            for token, sid in self._tokens.items():
                if sid == session_id:
                    share_token = token
                    break
            
            results.append(RecordingInfo(
                session_id=info['session_id'],
                protocol=info.get('protocol', 'ssh'),
                source_ip=info.get('source_ip', 'unknown'),
                start_time=info.get('start_time', ''),
                duration_ms=info.get('duration_ms', 0),
                event_count=info.get('event_count', 0),
                username=info.get('username'),
                file_path=info.get('s3_key', ''),
                file_size=info.get('file_size', 0),
                share_token=share_token
            ))
        
        results.sort(key=lambda x: x.start_time, reverse=True)
        return results[offset:offset + limit]
    
    def get_info(self, session_id: str) -> Optional[RecordingInfo]:
        """Get recording info"""
        if session_id not in self._index:
            return None
        
        info = self._index[session_id]
        share_token = None
        for token, sid in self._tokens.items():
            if sid == session_id:
                share_token = token
                break
        
        return RecordingInfo(
            session_id=info['session_id'],
            protocol=info.get('protocol', 'ssh'),
            source_ip=info.get('source_ip', 'unknown'),
            start_time=info.get('start_time', ''),
            duration_ms=info.get('duration_ms', 0),
            event_count=info.get('event_count', 0),
            username=info.get('username'),
            file_path=info.get('s3_key', ''),
            file_size=info.get('file_size', 0),
            share_token=share_token
        )
    
    def create_share_token(self, session_id: str) -> str:
        """Create shareable token"""
        if session_id not in self._index:
            raise FileNotFoundError(f"Recording not found: {session_id}")
        
        for token, sid in self._tokens.items():
            if sid == session_id:
                return token
        
        token = secrets.token_urlsafe(32)
        self._tokens[token] = session_id
        self._save_index()
        return token
    
    def get_by_share_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get recording by share token"""
        session_id = self._tokens.get(token)
        if not session_id:
            return None
        try:
            return self.load(session_id)
        except:
            return None
