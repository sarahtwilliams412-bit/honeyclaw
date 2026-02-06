#!/usr/bin/env python3
"""
Honeyclaw Session Recorder
Records attacker sessions with precise timing for replay.

Formats:
- SSH: asciinema-compatible JSON (v2)
- HTTP: HAR (HTTP Archive) format
"""

import json
import time
import uuid
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict


@dataclass
class RecordingMetadata:
    """Metadata for a recording session"""
    session_id: str
    protocol: str  # ssh, http, telnet, etc.
    source_ip: str
    source_port: int
    dest_port: int
    start_time: str  # ISO format
    end_time: Optional[str] = None
    duration_ms: Optional[int] = None
    username: Optional[str] = None
    event_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RecordingMetadata':
        return cls(**data)


class SessionRecorder(ABC):
    """Abstract base class for session recording"""
    
    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or str(uuid.uuid4())
        self.start_time = time.time()
        self.start_timestamp = datetime.now(timezone.utc).isoformat()
        self.events: List[Dict[str, Any]] = []
        self.metadata: Optional[RecordingMetadata] = None
        self._finalized = False
        
    @abstractmethod
    def record_event(self, event_type: str, data: Any, direction: str = 'server') -> None:
        """Record an event with timing"""
        pass
    
    @abstractmethod
    def finalize(self) -> Dict[str, Any]:
        """Finalize recording and return complete session data"""
        pass
    
    def get_elapsed_ms(self) -> int:
        """Get milliseconds since recording started"""
        return int((time.time() - self.start_time) * 1000)
    
    def get_elapsed_seconds(self) -> float:
        """Get seconds since recording started (for asciinema compatibility)"""
        return time.time() - self.start_time


class SSHRecorder(SessionRecorder):
    """
    SSH Session Recorder - asciinema v2 compatible format
    
    Format spec: https://github.com/asciinema/asciinema/blob/develop/doc/asciicast-v2.md
    
    Output:
    {
        "version": 2,
        "width": 80,
        "height": 24,
        "timestamp": 1234567890,
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        "honeyclaw": { ... metadata ... }
    }
    [0.0, "o", "output text"]
    [1.5, "i", "input text"]
    """
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        source_ip: str = "unknown",
        source_port: int = 0,
        dest_port: int = 22,
        width: int = 80,
        height: int = 24,
        username: Optional[str] = None
    ):
        super().__init__(session_id)
        self.width = width
        self.height = height
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.username = username
        self.bytes_in = 0
        self.bytes_out = 0
        
        # Initialize metadata
        self.metadata = RecordingMetadata(
            session_id=self.session_id,
            protocol='ssh',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            start_time=self.start_timestamp,
            username=username
        )
    
    def record_output(self, data: str) -> None:
        """Record server output (what attacker sees)"""
        self.record_event('output', data, 'server')
        
    def record_input(self, data: str) -> None:
        """Record attacker input (what attacker types)"""
        self.record_event('input', data, 'client')
        
    def record_event(self, event_type: str, data: Any, direction: str = 'server') -> None:
        """Record an SSH event in asciinema format"""
        if self._finalized:
            raise RuntimeError("Cannot record to finalized session")
            
        elapsed = self.get_elapsed_seconds()
        
        # asciinema event types: "o" = output, "i" = input
        event_code = 'o' if direction == 'server' else 'i'
        
        # Convert data to string if needed
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        
        # Track bytes
        byte_count = len(data.encode('utf-8'))
        if direction == 'server':
            self.bytes_out += byte_count
        else:
            self.bytes_in += byte_count
        
        self.events.append([elapsed, event_code, data])
        self.metadata.event_count = len(self.events)
        
    def record_resize(self, width: int, height: int) -> None:
        """Record terminal resize event"""
        elapsed = self.get_elapsed_seconds()
        self.width = width
        self.height = height
        # asciinema v2 uses "r" for resize, but not all players support it
        # Store as metadata event instead
        self.events.append([elapsed, 'o', f'\x1b[8;{height};{width}t'])
        
    def finalize(self) -> Dict[str, Any]:
        """Finalize and return asciinema-compatible recording"""
        if self._finalized:
            return self._get_recording()
            
        self._finalized = True
        end_time = datetime.now(timezone.utc).isoformat()
        duration_ms = self.get_elapsed_ms()
        
        # Update metadata
        self.metadata.end_time = end_time
        self.metadata.duration_ms = duration_ms
        self.metadata.bytes_in = self.bytes_in
        self.metadata.bytes_out = self.bytes_out
        
        return self._get_recording()
    
    def _get_recording(self) -> Dict[str, Any]:
        """Get the recording data structure"""
        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(self.start_time),
            "env": {
                "SHELL": "/bin/bash",
                "TERM": "xterm-256color"
            },
            "honeyclaw": self.metadata.to_dict()
        }
        
        return {
            "header": header,
            "events": self.events,
            "metadata": self.metadata.to_dict()
        }
    
    def to_asciicast(self) -> str:
        """Export as asciinema cast file (NDJSON format)"""
        recording = self.finalize()
        lines = [json.dumps(recording["header"])]
        for event in recording["events"]:
            lines.append(json.dumps(event))
        return '\n'.join(lines)
    
    def save(self, path: Path) -> None:
        """Save recording to file"""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(self.to_asciicast())


class HTTPRecorder(SessionRecorder):
    """
    HTTP Session Recorder - HAR (HTTP Archive) format
    
    Format spec: http://www.softwareishard.com/blog/har-12-spec/
    """
    
    def __init__(
        self,
        session_id: Optional[str] = None,
        source_ip: str = "unknown",
        source_port: int = 0,
        dest_port: int = 80
    ):
        super().__init__(session_id)
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.entries: List[Dict[str, Any]] = []
        self.bytes_in = 0
        self.bytes_out = 0
        
        # Initialize metadata
        self.metadata = RecordingMetadata(
            session_id=self.session_id,
            protocol='http',
            source_ip=source_ip,
            source_port=source_port,
            dest_port=dest_port,
            start_time=self.start_timestamp
        )
        
    def record_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        http_version: str = "HTTP/1.1"
    ) -> str:
        """Record HTTP request, returns request_id for matching response"""
        request_id = str(uuid.uuid4())
        
        # Calculate body size
        body_size = len(body.encode('utf-8')) if body else 0
        self.bytes_in += body_size
        
        # Calculate headers size
        headers_size = sum(len(f"{k}: {v}\r\n".encode()) for k, v in headers.items())
        self.bytes_in += headers_size
        
        entry = {
            "_request_id": request_id,
            "_timestamp_ms": self.get_elapsed_ms(),
            "startedDateTime": datetime.now(timezone.utc).isoformat(),
            "request": {
                "method": method,
                "url": url,
                "httpVersion": http_version,
                "headers": [{"name": k, "value": v} for k, v in headers.items()],
                "queryString": [],
                "cookies": [],
                "headersSize": headers_size,
                "bodySize": body_size,
                "postData": {
                    "mimeType": headers.get("Content-Type", ""),
                    "text": body or ""
                } if body else None
            },
            "response": None,
            "cache": {},
            "timings": {
                "send": 0,
                "wait": 0,
                "receive": 0
            }
        }
        
        self.entries.append(entry)
        self.metadata.event_count = len(self.entries)
        return request_id
    
    def record_response(
        self,
        request_id: str,
        status: int,
        status_text: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        http_version: str = "HTTP/1.1"
    ) -> None:
        """Record HTTP response matching a request"""
        # Find matching request
        entry = None
        for e in self.entries:
            if e.get("_request_id") == request_id:
                entry = e
                break
                
        if not entry:
            raise ValueError(f"No request found with id {request_id}")
        
        # Calculate body size
        body_size = len(body.encode('utf-8')) if body else 0
        self.bytes_out += body_size
        
        # Calculate headers size
        headers_size = sum(len(f"{k}: {v}\r\n".encode()) for k, v in headers.items())
        self.bytes_out += headers_size
        
        entry["response"] = {
            "status": status,
            "statusText": status_text,
            "httpVersion": http_version,
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
            "cookies": [],
            "content": {
                "size": body_size,
                "mimeType": headers.get("Content-Type", "text/html"),
                "text": body or ""
            },
            "redirectURL": "",
            "headersSize": headers_size,
            "bodySize": body_size
        }
        
        # Calculate timing
        entry["timings"]["receive"] = self.get_elapsed_ms() - entry["_timestamp_ms"]
        entry["time"] = entry["timings"]["receive"]
        
    def record_event(self, event_type: str, data: Any, direction: str = 'server') -> None:
        """Generic event recording (for interface compatibility)"""
        if event_type == 'request':
            self.record_request(**data)
        elif event_type == 'response':
            self.record_response(**data)
    
    def finalize(self) -> Dict[str, Any]:
        """Finalize and return HAR-format recording"""
        if self._finalized:
            return self._get_recording()
            
        self._finalized = True
        end_time = datetime.now(timezone.utc).isoformat()
        duration_ms = self.get_elapsed_ms()
        
        # Update metadata
        self.metadata.end_time = end_time
        self.metadata.duration_ms = duration_ms
        self.metadata.bytes_in = self.bytes_in
        self.metadata.bytes_out = self.bytes_out
        
        return self._get_recording()
    
    def _get_recording(self) -> Dict[str, Any]:
        """Get the HAR recording structure"""
        # Clean up internal fields from entries
        clean_entries = []
        for entry in self.entries:
            clean_entry = {k: v for k, v in entry.items() if not k.startswith('_')}
            clean_entries.append(clean_entry)
        
        har = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Honeyclaw",
                    "version": "1.0.0"
                },
                "entries": clean_entries,
                "comment": "",
                "_honeyclaw": self.metadata.to_dict()
            }
        }
        
        return {
            "har": har,
            "metadata": self.metadata.to_dict()
        }
    
    def to_har(self) -> str:
        """Export as HAR JSON"""
        recording = self.finalize()
        return json.dumps(recording["har"], indent=2)
    
    def save(self, path: Path) -> None:
        """Save recording to file"""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(self.to_har())
