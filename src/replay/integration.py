#!/usr/bin/env python3
"""
Honeyclaw Replay Integration
Helpers to integrate session recording into honeypot services.
"""

import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from .recorder import SSHRecorder, HTTPRecorder
from .storage import LocalStorage, S3Storage, ReplayStorage


def get_default_storage() -> ReplayStorage:
    """Get the default storage backend from environment"""
    storage_type = os.environ.get('HONEYCLAW_STORAGE', 'local')
    
    if storage_type == 's3':
        return S3Storage(
            bucket=os.environ.get('HONEYCLAW_S3_BUCKET', 'honeyclaw-recordings'),
            prefix=os.environ.get('HONEYCLAW_S3_PREFIX', 'recordings/'),
            region=os.environ.get('AWS_REGION', 'us-east-1'),
            endpoint_url=os.environ.get('HONEYCLAW_S3_ENDPOINT')
        )
    else:
        base_path = os.environ.get('HONEYCLAW_RECORDINGS_PATH', '/var/lib/honeyclaw/recordings')
        return LocalStorage(base_path)


class RecordingSSHSession:
    """
    Wrapper to add recording to SSH sessions.
    
    Usage:
        session = RecordingSSHSession(
            source_ip=client_ip,
            source_port=client_port,
            dest_port=22,
            username=username
        )
        
        # Record output (what honeypot sends)
        session.record_output("Welcome to server\\n$ ")
        
        # Record input (what attacker types)
        session.record_input("ls -la\\n")
        
        # Finalize and save
        await session.save()
    """
    
    def __init__(
        self,
        source_ip: str,
        source_port: int = 0,
        dest_port: int = 22,
        username: Optional[str] = None,
        storage: Optional[ReplayStorage] = None
    ):
        self.recorder = SSHRecorder(
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            username=username
        )
        self.storage = storage or get_default_storage()
        self._saved = False
    
    @property
    def session_id(self) -> str:
        return self.recorder.session_id
    
    def record_output(self, data: str) -> None:
        """Record output sent to the attacker"""
        self.recorder.record_output(data)
    
    def record_input(self, data: str) -> None:
        """Record input from the attacker"""
        self.recorder.record_input(data)
    
    def record_resize(self, width: int, height: int) -> None:
        """Record terminal resize"""
        self.recorder.record_resize(width, height)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the recording"""
        if tag not in self.recorder.metadata.tags:
            self.recorder.metadata.tags.append(tag)
    
    def set_note(self, note: str) -> None:
        """Set a note on the recording"""
        self.recorder.metadata.notes = note
    
    def save(self) -> str:
        """Finalize and save the recording, returns file path"""
        if self._saved:
            raise RuntimeError("Recording already saved")
        
        self._saved = True
        recording = self.recorder.finalize()
        return self.storage.save(
            self.recorder.session_id,
            recording,
            'ssh'
        )
    
    async def save_async(self) -> str:
        """Async wrapper for save()"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.save)


class RecordingHTTPSession:
    """
    Wrapper to add recording to HTTP sessions.
    
    Usage:
        session = RecordingHTTPSession(
            source_ip=client_ip,
            source_port=client_port,
            dest_port=80
        )
        
        # Record request/response pairs
        req_id = session.record_request(
            method='POST',
            url='/login',
            headers={'Content-Type': 'application/json'},
            body='{"user": "admin"}'
        )
        session.record_response(
            request_id=req_id,
            status=200,
            status_text='OK',
            headers={'Content-Type': 'application/json'},
            body='{"success": false}'
        )
        
        # Save
        await session.save()
    """
    
    def __init__(
        self,
        source_ip: str,
        source_port: int = 0,
        dest_port: int = 80,
        storage: Optional[ReplayStorage] = None
    ):
        self.recorder = HTTPRecorder(
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port
        )
        self.storage = storage or get_default_storage()
        self._saved = False
    
    @property
    def session_id(self) -> str:
        return self.recorder.session_id
    
    def record_request(
        self,
        method: str,
        url: str,
        headers: dict,
        body: Optional[str] = None
    ) -> str:
        """Record an HTTP request, returns request_id for matching response"""
        return self.recorder.record_request(method, url, headers, body)
    
    def record_response(
        self,
        request_id: str,
        status: int,
        status_text: str,
        headers: dict,
        body: Optional[str] = None
    ) -> None:
        """Record an HTTP response"""
        self.recorder.record_response(request_id, status, status_text, headers, body)
    
    def save(self) -> str:
        """Finalize and save the recording, returns file path"""
        if self._saved:
            raise RuntimeError("Recording already saved")
        
        self._saved = True
        recording = self.recorder.finalize()
        return self.storage.save(
            self.recorder.session_id,
            recording,
            'http'
        )
    
    async def save_async(self) -> str:
        """Async wrapper for save()"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.save)


# Decorator for recording honeypot methods
def record_session(session_factory: Callable):
    """
    Decorator to automatically record session methods.
    
    Usage:
        @record_session(RecordingSSHSession)
        async def handle_connection(self, conn):
            # session.record_* methods available via self.recording
            ...
    """
    def decorator(func):
        async def wrapper(self, *args, **kwargs):
            # Create recording session
            self.recording = session_factory(
                source_ip=getattr(self, 'client_ip', 'unknown'),
                source_port=getattr(self, 'client_port', 0),
                dest_port=getattr(self, 'port', 22)
            )
            
            try:
                return await func(self, *args, **kwargs)
            finally:
                # Always save recording
                try:
                    await self.recording.save_async()
                except Exception as e:
                    print(f"[ERROR] Failed to save recording: {e}")
        
        return wrapper
    return decorator
