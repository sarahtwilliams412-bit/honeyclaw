#!/usr/bin/env python3
"""
Honeyclaw Session Player
Playback logic for recorded attacker sessions.
"""

import json
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, Generator, Callable


class PlaybackState(Enum):
    """Playback state machine"""
    STOPPED = "stopped"
    PLAYING = "playing"
    PAUSED = "paused"
    FINISHED = "finished"


@dataclass
class ReplayEvent:
    """A single replay event"""
    timestamp_ms: int
    event_type: str  # 'input', 'output', 'request', 'response'
    data: Any
    direction: str  # 'client' or 'server'
    
    def __post_init__(self):
        # Normalize timestamp to int
        if isinstance(self.timestamp_ms, float):
            self.timestamp_ms = int(self.timestamp_ms * 1000)


class SessionPlayer:
    """
    Session playback controller
    Supports play/pause, speed control, and seeking.
    """
    
    def __init__(self, recording_path: Optional[Path] = None):
        self.events: List[ReplayEvent] = []
        self.metadata: Dict[str, Any] = {}
        self.protocol: str = "unknown"
        
        self.state = PlaybackState.STOPPED
        self.speed = 1.0  # Playback speed multiplier
        self.current_index = 0
        self.current_time_ms = 0
        
        self._on_event: Optional[Callable[[ReplayEvent], None]] = None
        self._on_state_change: Optional[Callable[[PlaybackState], None]] = None
        
        if recording_path:
            self.load(recording_path)
    
    def load(self, path: Path) -> None:
        """Load a recording from file"""
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Recording not found: {path}")
        
        content = path.read_text()
        
        # Detect format and parse
        if path.suffix == '.cast' or self._is_asciicast(content):
            self._load_asciicast(content)
        elif path.suffix == '.har' or content.strip().startswith('{'):
            self._load_har(content)
        else:
            raise ValueError(f"Unknown recording format: {path.suffix}")
    
    def _is_asciicast(self, content: str) -> bool:
        """Check if content looks like asciinema format"""
        try:
            first_line = content.split('\n')[0]
            header = json.loads(first_line)
            return 'version' in header and 'width' in header
        except:
            return False
    
    def _load_asciicast(self, content: str) -> None:
        """Load asciinema v2 format"""
        lines = content.strip().split('\n')
        
        # Parse header (first line)
        header = json.loads(lines[0])
        self.metadata = header.get('honeyclaw', {})
        self.metadata['width'] = header.get('width', 80)
        self.metadata['height'] = header.get('height', 24)
        self.metadata['duration_ms'] = 0
        self.protocol = 'ssh'
        
        # Parse events (remaining lines)
        self.events = []
        for line in lines[1:]:
            if not line.strip():
                continue
            event_data = json.loads(line)
            timestamp_sec, event_code, data = event_data
            
            event_type = 'output' if event_code == 'o' else 'input'
            direction = 'server' if event_code == 'o' else 'client'
            
            event = ReplayEvent(
                timestamp_ms=int(timestamp_sec * 1000),
                event_type=event_type,
                data=data,
                direction=direction
            )
            self.events.append(event)
            self.metadata['duration_ms'] = event.timestamp_ms
        
        self.metadata['event_count'] = len(self.events)
    
    def _load_har(self, content: str) -> None:
        """Load HAR format"""
        data = json.loads(content)
        
        if 'log' not in data:
            raise ValueError("Invalid HAR format: missing 'log' key")
        
        log = data['log']
        self.metadata = log.get('_honeyclaw', {})
        self.protocol = 'http'
        
        # Parse entries into events
        self.events = []
        base_time = None
        
        for entry in log.get('entries', []):
            started = entry.get('startedDateTime', '')
            if started:
                entry_time = datetime.fromisoformat(started.replace('Z', '+00:00'))
                if base_time is None:
                    base_time = entry_time
                offset_ms = int((entry_time - base_time).total_seconds() * 1000)
            else:
                offset_ms = 0
            
            # Request event
            request = entry.get('request', {})
            self.events.append(ReplayEvent(
                timestamp_ms=offset_ms,
                event_type='request',
                data={
                    'method': request.get('method', 'GET'),
                    'url': request.get('url', '/'),
                    'headers': {h['name']: h['value'] for h in request.get('headers', [])},
                    'body': request.get('postData', {}).get('text', '')
                },
                direction='client'
            ))
            
            # Response event
            response = entry.get('response', {})
            if response:
                response_time = offset_ms + entry.get('time', 0)
                self.events.append(ReplayEvent(
                    timestamp_ms=int(response_time),
                    event_type='response',
                    data={
                        'status': response.get('status', 200),
                        'statusText': response.get('statusText', 'OK'),
                        'headers': {h['name']: h['value'] for h in response.get('headers', [])},
                        'body': response.get('content', {}).get('text', '')
                    },
                    direction='server'
                ))
        
        # Sort events by timestamp
        self.events.sort(key=lambda e: e.timestamp_ms)
        
        if self.events:
            self.metadata['duration_ms'] = self.events[-1].timestamp_ms
        self.metadata['event_count'] = len(self.events)
    
    def load_from_dict(self, data: Dict[str, Any]) -> None:
        """Load from in-memory recording dict"""
        if 'header' in data and 'events' in data:
            # asciinema format
            self.metadata = data.get('metadata', {})
            self.metadata['width'] = data['header'].get('width', 80)
            self.metadata['height'] = data['header'].get('height', 24)
            self.protocol = 'ssh'
            
            self.events = []
            for event_data in data['events']:
                timestamp_sec, event_code, text = event_data
                self.events.append(ReplayEvent(
                    timestamp_ms=int(timestamp_sec * 1000),
                    event_type='output' if event_code == 'o' else 'input',
                    data=text,
                    direction='server' if event_code == 'o' else 'client'
                ))
        elif 'har' in data:
            # HAR format
            self._load_har(json.dumps(data['har']))
    
    @property
    def duration_ms(self) -> int:
        """Total duration in milliseconds"""
        return self.metadata.get('duration_ms', 0)
    
    @property
    def progress(self) -> float:
        """Current progress as 0.0-1.0"""
        if self.duration_ms == 0:
            return 0.0
        return min(1.0, self.current_time_ms / self.duration_ms)
    
    def play(self) -> None:
        """Start or resume playback"""
        if self.state == PlaybackState.FINISHED:
            self.seek(0)
        self._set_state(PlaybackState.PLAYING)
    
    def pause(self) -> None:
        """Pause playback"""
        if self.state == PlaybackState.PLAYING:
            self._set_state(PlaybackState.PAUSED)
    
    def stop(self) -> None:
        """Stop and reset playback"""
        self._set_state(PlaybackState.STOPPED)
        self.current_index = 0
        self.current_time_ms = 0
    
    def seek(self, time_ms: int) -> None:
        """Seek to specific time"""
        time_ms = max(0, min(time_ms, self.duration_ms))
        self.current_time_ms = time_ms
        
        # Find the event index at this time
        self.current_index = 0
        for i, event in enumerate(self.events):
            if event.timestamp_ms > time_ms:
                break
            self.current_index = i
    
    def seek_percent(self, percent: float) -> None:
        """Seek to percentage of duration"""
        time_ms = int(self.duration_ms * max(0.0, min(1.0, percent)))
        self.seek(time_ms)
    
    def set_speed(self, speed: float) -> None:
        """Set playback speed (0.25 to 4.0)"""
        self.speed = max(0.25, min(4.0, speed))
    
    def get_events_until(self, target_time_ms: int) -> List[ReplayEvent]:
        """Get all events from current position to target time"""
        events = []
        while self.current_index < len(self.events):
            event = self.events[self.current_index]
            if event.timestamp_ms > target_time_ms:
                break
            events.append(event)
            self.current_index += 1
        self.current_time_ms = target_time_ms
        return events
    
    def stream_events(self, realtime: bool = True) -> Generator[ReplayEvent, None, None]:
        """
        Stream events in real-time (respecting timing) or as fast as possible.
        
        Args:
            realtime: If True, wait between events based on timestamps
        """
        self._set_state(PlaybackState.PLAYING)
        last_time = 0
        
        for event in self.events[self.current_index:]:
            if self.state != PlaybackState.PLAYING:
                break
            
            if realtime and last_time > 0:
                delay = (event.timestamp_ms - last_time) / 1000.0 / self.speed
                if delay > 0:
                    time.sleep(delay)
            
            last_time = event.timestamp_ms
            self.current_time_ms = event.timestamp_ms
            self.current_index += 1
            
            if self._on_event:
                self._on_event(event)
            
            yield event
        
        if self.current_index >= len(self.events):
            self._set_state(PlaybackState.FINISHED)
    
    def get_all_output(self) -> str:
        """Get concatenated output (for SSH sessions)"""
        output = []
        for event in self.events:
            if event.event_type == 'output':
                output.append(event.data)
        return ''.join(output)
    
    def get_all_input(self) -> str:
        """Get concatenated input (for SSH sessions)"""
        input_data = []
        for event in self.events:
            if event.event_type == 'input':
                input_data.append(event.data)
        return ''.join(input_data)
    
    def on_event(self, callback: Callable[[ReplayEvent], None]) -> None:
        """Register event callback"""
        self._on_event = callback
    
    def on_state_change(self, callback: Callable[[PlaybackState], None]) -> None:
        """Register state change callback"""
        self._on_state_change = callback
    
    def _set_state(self, state: PlaybackState) -> None:
        """Set state and fire callback"""
        old_state = self.state
        self.state = state
        if self._on_state_change and old_state != state:
            self._on_state_change(state)
    
    def to_json(self) -> Dict[str, Any]:
        """Export player state as JSON-serializable dict"""
        return {
            'metadata': self.metadata,
            'protocol': self.protocol,
            'events': [
                {
                    'timestamp_ms': e.timestamp_ms,
                    'event_type': e.event_type,
                    'data': e.data,
                    'direction': e.direction
                }
                for e in self.events
            ],
            'state': {
                'playback': self.state.value,
                'speed': self.speed,
                'current_time_ms': self.current_time_ms,
                'current_index': self.current_index,
                'duration_ms': self.duration_ms,
                'progress': self.progress
            }
        }
