#!/usr/bin/env python3
"""
Tests for the session player module.
"""

import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.replay.player import SessionPlayer, ReplayEvent, PlaybackState
from src.replay.recorder import SSHRecorder


class TestSessionPlayer:
    """Tests for session playback"""
    
    def test_load_asciicast(self):
        """Test loading asciinema format"""
        with TemporaryDirectory() as tmpdir:
            # Create a recording
            recorder = SSHRecorder(source_ip="1.2.3.4", username="test")
            recorder.record_output("$ ")
            recorder.record_input("ls\n")
            recorder.record_output("file.txt\n$ ")
            
            path = Path(tmpdir) / "test.cast"
            recorder.save(path)
            
            # Load it
            player = SessionPlayer(path)
            
            assert player.protocol == 'ssh'
            assert len(player.events) == 3
            assert player.metadata.get('width') == 80
    
    def test_load_from_dict(self):
        """Test loading from in-memory dict"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        recorder.record_output("test output")
        recording = recorder.finalize()
        
        player = SessionPlayer()
        player.load_from_dict(recording)
        
        assert len(player.events) == 1
        assert player.events[0].event_type == 'output'
    
    def test_playback_state(self):
        """Test playback state transitions"""
        player = SessionPlayer()
        
        # Initial state
        assert player.state == PlaybackState.STOPPED
        
        # Play
        player.play()
        assert player.state == PlaybackState.PLAYING
        
        # Pause
        player.pause()
        assert player.state == PlaybackState.PAUSED
        
        # Stop
        player.stop()
        assert player.state == PlaybackState.STOPPED
        assert player.current_index == 0
    
    def test_seek(self):
        """Test seeking to specific time"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        recorder.events = [
            [0.0, 'o', 'first'],
            [1.0, 'o', 'second'],
            [2.0, 'o', 'third'],
            [3.0, 'o', 'fourth'],
        ]
        recorder.metadata.duration_ms = 3000
        recording = recorder.finalize()
        
        player = SessionPlayer()
        player.load_from_dict(recording)
        
        # Seek to 1.5 seconds
        player.seek(1500)
        
        assert player.current_time_ms == 1500
        # Should be at index 1 (after 'second')
        assert player.current_index == 1
    
    def test_seek_percent(self):
        """Test seeking by percentage"""
        player = SessionPlayer()
        player.metadata = {'duration_ms': 10000}
        
        player.seek_percent(0.5)
        assert player.current_time_ms == 5000
        
        player.seek_percent(0.0)
        assert player.current_time_ms == 0
        
        player.seek_percent(1.0)
        assert player.current_time_ms == 10000
    
    def test_speed_control(self):
        """Test playback speed setting"""
        player = SessionPlayer()
        
        player.set_speed(2.0)
        assert player.speed == 2.0
        
        # Clamp to valid range
        player.set_speed(10.0)
        assert player.speed == 4.0
        
        player.set_speed(0.1)
        assert player.speed == 0.25
    
    def test_get_events_until(self):
        """Test getting events up to a time"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        recorder.events = [
            [0.0, 'o', 'a'],
            [0.5, 'o', 'b'],
            [1.0, 'o', 'c'],
            [1.5, 'o', 'd'],
        ]
        recording = recorder.finalize()
        
        player = SessionPlayer()
        player.load_from_dict(recording)
        
        events = player.get_events_until(1000)
        
        assert len(events) == 3  # a, b, c (not d)
        assert events[0].data == 'a'
        assert events[2].data == 'c'
    
    def test_progress(self):
        """Test progress calculation"""
        player = SessionPlayer()
        player.metadata = {'duration_ms': 10000}
        
        player.current_time_ms = 0
        assert player.progress == 0.0
        
        player.current_time_ms = 5000
        assert player.progress == 0.5
        
        player.current_time_ms = 10000
        assert player.progress == 1.0
    
    def test_get_all_output(self):
        """Test concatenating all output"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        recorder.record_output("Hello ")
        recorder.record_input("test")
        recorder.record_output("World!")
        recording = recorder.finalize()
        
        player = SessionPlayer()
        player.load_from_dict(recording)
        
        output = player.get_all_output()
        assert output == "Hello World!"
    
    def test_to_json(self):
        """Test exporting player state as JSON"""
        recorder = SSHRecorder(source_ip="1.2.3.4", username="attacker")
        recorder.record_output("$ ")
        recording = recorder.finalize()
        
        player = SessionPlayer()
        player.load_from_dict(recording)
        player.set_speed(2.0)
        
        data = player.to_json()
        
        assert 'metadata' in data
        assert 'events' in data
        assert 'state' in data
        assert data['state']['speed'] == 2.0
        assert data['protocol'] == 'ssh'
    
    def test_event_callbacks(self):
        """Test event and state change callbacks"""
        events_received = []
        states_received = []
        
        player = SessionPlayer()
        player.on_event(lambda e: events_received.append(e))
        player.on_state_change(lambda s: states_received.append(s))
        
        player.play()
        assert PlaybackState.PLAYING in states_received
        
        player.pause()
        assert PlaybackState.PAUSED in states_received


class TestReplayEvent:
    """Tests for ReplayEvent dataclass"""
    
    def test_create_event(self):
        """Test event creation"""
        event = ReplayEvent(
            timestamp_ms=1000,
            event_type='output',
            data='test',
            direction='server'
        )
        
        assert event.timestamp_ms == 1000
        assert event.event_type == 'output'
    
    def test_float_timestamp_conversion(self):
        """Test that float timestamps are converted to int ms"""
        event = ReplayEvent(
            timestamp_ms=1.5,  # 1.5 seconds as float
            event_type='input',
            data='x',
            direction='client'
        )
        
        assert event.timestamp_ms == 1500
        assert isinstance(event.timestamp_ms, int)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
