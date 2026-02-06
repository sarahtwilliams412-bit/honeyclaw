#!/usr/bin/env python3
"""
Tests for the session recorder module.
"""

import json
import pytest
import time
from pathlib import Path
from tempfile import TemporaryDirectory

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.replay.recorder import SSHRecorder, HTTPRecorder, RecordingMetadata


class TestSSHRecorder:
    """Tests for SSH session recording"""
    
    def test_create_recorder(self):
        """Test basic recorder creation"""
        recorder = SSHRecorder(
            source_ip="192.168.1.100",
            source_port=54321,
            dest_port=22,
            username="attacker"
        )
        
        assert recorder.session_id is not None
        assert len(recorder.session_id) == 36  # UUID format
        assert recorder.metadata.source_ip == "192.168.1.100"
        assert recorder.metadata.username == "attacker"
        assert recorder.metadata.protocol == "ssh"
    
    def test_record_output(self):
        """Test recording output events"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        
        recorder.record_output("Welcome to server\n")
        recorder.record_output("$ ")
        
        assert len(recorder.events) == 2
        assert recorder.events[0][1] == 'o'  # output
        assert recorder.events[0][2] == "Welcome to server\n"
        assert recorder.events[1][2] == "$ "
    
    def test_record_input(self):
        """Test recording input events"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        
        recorder.record_input("ls -la\n")
        
        assert len(recorder.events) == 1
        assert recorder.events[0][1] == 'i'  # input
        assert recorder.events[0][2] == "ls -la\n"
    
    def test_event_timing(self):
        """Test that events have timing"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        
        recorder.record_output("first")
        time.sleep(0.1)
        recorder.record_output("second")
        
        # First event should be near 0
        assert recorder.events[0][0] < 0.1
        
        # Second event should be at least 0.1s later
        assert recorder.events[1][0] >= 0.1
        assert recorder.events[1][0] > recorder.events[0][0]
    
    def test_finalize_recording(self):
        """Test finalizing a recording"""
        recorder = SSHRecorder(
            source_ip="1.2.3.4",
            username="test"
        )
        
        recorder.record_output("test output")
        recorder.record_input("test input")
        
        result = recorder.finalize()
        
        assert 'header' in result
        assert 'events' in result
        assert 'metadata' in result
        
        header = result['header']
        assert header['version'] == 2
        assert header['width'] == 80
        assert header['height'] == 24
        assert 'honeyclaw' in header
        
        metadata = result['metadata']
        assert metadata['session_id'] == recorder.session_id
        assert metadata['event_count'] == 2
        assert metadata['end_time'] is not None
        assert metadata['duration_ms'] is not None
    
    def test_to_asciicast(self):
        """Test export to asciinema format"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        recorder.record_output("$ ")
        recorder.record_input("whoami\n")
        recorder.record_output("root\n")
        
        cast = recorder.to_asciicast()
        lines = cast.split('\n')
        
        # First line should be JSON header
        header = json.loads(lines[0])
        assert header['version'] == 2
        
        # Subsequent lines should be events
        event1 = json.loads(lines[1])
        assert event1[1] == 'o'
        assert event1[2] == "$ "
    
    def test_save_to_file(self):
        """Test saving recording to file"""
        with TemporaryDirectory() as tmpdir:
            recorder = SSHRecorder(source_ip="1.2.3.4")
            recorder.record_output("test")
            
            path = Path(tmpdir) / "test.cast"
            recorder.save(path)
            
            assert path.exists()
            content = path.read_text()
            lines = content.split('\n')
            
            # Verify it's valid NDJSON
            header = json.loads(lines[0])
            assert header['version'] == 2
    
    def test_bytes_tracking(self):
        """Test byte counting"""
        recorder = SSHRecorder(source_ip="1.2.3.4")
        
        recorder.record_output("Hello!")  # 6 bytes
        recorder.record_input("Hi")  # 2 bytes
        
        assert recorder.bytes_out == 6
        assert recorder.bytes_in == 2
        
        result = recorder.finalize()
        assert result['metadata']['bytes_in'] == 2
        assert result['metadata']['bytes_out'] == 6


class TestHTTPRecorder:
    """Tests for HTTP session recording"""
    
    def test_create_recorder(self):
        """Test basic HTTP recorder creation"""
        recorder = HTTPRecorder(
            source_ip="192.168.1.100",
            source_port=54321,
            dest_port=80
        )
        
        assert recorder.metadata.protocol == 'http'
        assert recorder.metadata.dest_port == 80
    
    def test_record_request_response(self):
        """Test recording HTTP request/response pairs"""
        recorder = HTTPRecorder(source_ip="1.2.3.4")
        
        req_id = recorder.record_request(
            method='GET',
            url='/api/users',
            headers={'Accept': 'application/json'}
        )
        
        assert req_id is not None
        assert len(recorder.entries) == 1
        
        recorder.record_response(
            request_id=req_id,
            status=200,
            status_text='OK',
            headers={'Content-Type': 'application/json'},
            body='{"users": []}'
        )
        
        entry = recorder.entries[0]
        assert entry['response']['status'] == 200
    
    def test_to_har(self):
        """Test export to HAR format"""
        recorder = HTTPRecorder(source_ip="1.2.3.4")
        
        req_id = recorder.record_request(
            method='POST',
            url='/login',
            headers={'Content-Type': 'application/json'},
            body='{"user": "admin"}'
        )
        
        recorder.record_response(
            request_id=req_id,
            status=401,
            status_text='Unauthorized',
            headers={'Content-Type': 'application/json'},
            body='{"error": "invalid credentials"}'
        )
        
        har = recorder.to_har()
        parsed = json.loads(har)
        
        assert 'log' in parsed
        assert parsed['log']['version'] == '1.2'
        assert len(parsed['log']['entries']) == 1
        
        entry = parsed['log']['entries'][0]
        assert entry['request']['method'] == 'POST'
        assert entry['response']['status'] == 401


class TestRecordingMetadata:
    """Tests for recording metadata"""
    
    def test_create_metadata(self):
        """Test metadata creation"""
        meta = RecordingMetadata(
            session_id="test-123",
            protocol="ssh",
            source_ip="1.2.3.4",
            source_port=12345,
            dest_port=22,
            start_time="2024-02-05T12:00:00Z"
        )
        
        assert meta.session_id == "test-123"
        assert meta.event_count == 0
        assert meta.tags == []
    
    def test_metadata_to_dict(self):
        """Test metadata serialization"""
        meta = RecordingMetadata(
            session_id="test-123",
            protocol="ssh",
            source_ip="1.2.3.4",
            source_port=12345,
            dest_port=22,
            start_time="2024-02-05T12:00:00Z",
            tags=["suspicious", "brute-force"]
        )
        
        d = meta.to_dict()
        
        assert d['session_id'] == "test-123"
        assert d['tags'] == ["suspicious", "brute-force"]
    
    def test_metadata_from_dict(self):
        """Test metadata deserialization"""
        data = {
            'session_id': 'test-456',
            'protocol': 'http',
            'source_ip': '5.6.7.8',
            'source_port': 54321,
            'dest_port': 80,
            'start_time': '2024-02-05T13:00:00Z'
        }
        
        meta = RecordingMetadata.from_dict(data)
        
        assert meta.session_id == 'test-456'
        assert meta.protocol == 'http'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
