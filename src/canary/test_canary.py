#!/usr/bin/env python3
"""
Tests for Honey Claw Canary Token Generator
"""
import os
import json
import tempfile
import unittest
from pathlib import Path

from generator import CanaryGenerator, CanaryType, Canary
from tracker import CanaryTracker, TriggerEvent


class TestCanaryGenerator(unittest.TestCase):
    """Tests for CanaryGenerator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.storage_path = os.path.join(self.temp_dir, 'canaries.json')
        self.generator = CanaryGenerator(
            storage_path=self.storage_path,
            default_webhook='https://test.webhook.example.com/alert',
            tracking_domain='http://localhost:8080/canary'
        )
    
    def tearDown(self):
        """Clean up"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_aws_key(self):
        """Test AWS key creation"""
        canary = self.generator.create_aws_key(memo="Test AWS key")
        
        self.assertIsNotNone(canary.id)
        self.assertTrue(canary.id.startswith('cnry_'))
        self.assertEqual(canary.type, CanaryType.AWS_KEY)
        self.assertEqual(canary.memo, "Test AWS key")
        
        # Check AWS key format
        self.assertTrue(canary.token_value.startswith('AKIA'))
        self.assertEqual(len(canary.token_value), 20)  # AKIA + 16 chars
        self.assertEqual(len(canary.token_secret), 40)
        
        # Check persistence
        self.assertIn(canary.id, self.generator.canaries)
        self.assertTrue(os.path.exists(self.storage_path))
    
    def test_create_tracking_url(self):
        """Test tracking URL creation"""
        canary = self.generator.create_tracking_url(
            memo="Test tracking URL",
            path_hint="admin"
        )
        
        self.assertEqual(canary.type, CanaryType.TRACKING_URL)
        self.assertIn('http://localhost:8080/canary', canary.token_value)
        self.assertIn('/admin/', canary.token_value)
        self.assertIn('token', canary.metadata)
    
    def test_create_dns_canary(self):
        """Test DNS canary creation"""
        generator = CanaryGenerator(
            storage_path=self.storage_path,
            default_webhook='https://test.webhook.example.com/alert',
            dns_domain='canary.example.com'
        )
        
        canary = generator.create_dns_canary(memo="Test DNS")
        
        self.assertEqual(canary.type, CanaryType.DNS)
        self.assertTrue(canary.hostname.endswith('.canary.example.com'))
        self.assertIn('subdomain', canary.metadata)
    
    def test_create_credential(self):
        """Test credential canary creation"""
        canary = self.generator.create_credential(
            username="test_admin",
            memo="Test credential"
        )
        
        self.assertEqual(canary.type, CanaryType.CREDENTIAL)
        self.assertEqual(canary.username, "test_admin")
        self.assertIsNotNone(canary.password)
        self.assertGreater(len(canary.password), 10)
    
    def test_create_credential_auto_username(self):
        """Test credential canary with auto-generated username"""
        canary = self.generator.create_credential(memo="Auto username")
        
        self.assertIsNotNone(canary.username)
        # Should be in format prefix_hexstring
        self.assertIn('_', canary.username)
    
    def test_create_webhook_token(self):
        """Test webhook token creation"""
        canary = self.generator.create_webhook_token(memo="Test webhook")
        
        self.assertEqual(canary.type, CanaryType.WEBHOOK_TOKEN)
        self.assertIsNotNone(canary.token_value)
        self.assertGreater(len(canary.token_value), 20)
    
    def test_list_canaries(self):
        """Test listing canaries"""
        # Create multiple canaries
        self.generator.create_aws_key(memo="AWS 1")
        self.generator.create_aws_key(memo="AWS 2")
        self.generator.create_tracking_url(memo="URL 1")
        
        # List all
        all_canaries = self.generator.list_canaries()
        self.assertEqual(len(all_canaries), 3)
        
        # Filter by type
        aws_only = self.generator.list_canaries(canary_type=CanaryType.AWS_KEY)
        self.assertEqual(len(aws_only), 2)
    
    def test_delete_canary(self):
        """Test deleting a canary"""
        canary = self.generator.create_aws_key(memo="To delete")
        canary_id = canary.id
        
        self.assertIn(canary_id, self.generator.canaries)
        
        result = self.generator.delete(canary_id)
        self.assertTrue(result)
        self.assertNotIn(canary_id, self.generator.canaries)
        
        # Delete non-existent
        result = self.generator.delete('fake_id')
        self.assertFalse(result)
    
    def test_persistence(self):
        """Test canary persistence across instances"""
        canary = self.generator.create_aws_key(memo="Persistent")
        canary_id = canary.id
        
        # Create new generator instance
        generator2 = CanaryGenerator(
            storage_path=self.storage_path,
            default_webhook='https://test.webhook.example.com/alert'
        )
        
        loaded = generator2.get(canary_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.memo, "Persistent")
        self.assertEqual(loaded.token_value, canary.token_value)
    
    def test_export_for_filesystem(self):
        """Test exporting canaries for fake filesystem"""
        self.generator.create_aws_key(memo="FS AWS")
        self.generator.create_credential(username="db_admin", memo="FS cred")
        
        files = self.generator.export_for_filesystem()
        
        self.assertIn('.aws/credentials', files)
        self.assertIn('aws_access_key_id', files['.aws/credentials'])
        self.assertIn('.env', files)
        self.assertIn('db_admin', files['.env'])
    
    def test_generate_honeypot_files(self):
        """Test generating honeypot files"""
        output_dir = os.path.join(self.temp_dir, 'honeypot')
        
        files = self.generator.generate_honeypot_files(output_dir=output_dir)
        
        # Check files were created
        self.assertTrue(os.path.exists(os.path.join(output_dir, '.aws', 'credentials')))
        self.assertTrue(os.path.exists(os.path.join(output_dir, 'passwords.txt')))
        
        # Verify canaries were created
        self.assertGreater(len(self.generator.canaries), 0)
    
    def test_canary_display(self):
        """Test canary display output"""
        canary = self.generator.create_aws_key(memo="Display test")
        display = canary.display()
        
        self.assertIn('Canary ID:', display)
        self.assertIn('Type: aws-key', display)
        self.assertIn('Access Key ID:', display)
        self.assertIn('AKIA', display)
    
    def test_no_webhook_error(self):
        """Test error when no webhook configured"""
        generator = CanaryGenerator(storage_path=self.storage_path)
        
        with self.assertRaises(ValueError):
            generator.create_aws_key()


class TestCanaryTracker(unittest.TestCase):
    """Tests for CanaryTracker"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.canary_storage = os.path.join(self.temp_dir, 'canaries.json')
        self.events_storage = os.path.join(self.temp_dir, 'events.json')
        
        # Create some canaries first
        self.generator = CanaryGenerator(
            storage_path=self.canary_storage,
            default_webhook='https://test.webhook.example.com/alert',
            tracking_domain='http://localhost:8080/canary'
        )
        self.aws_canary = self.generator.create_aws_key(memo="Test AWS")
        self.url_canary = self.generator.create_tracking_url(memo="Test URL")
        self.cred_canary = self.generator.create_credential(
            username="test_user",
            password="test_pass123"
        )
        
        # Create tracker
        self.tracker = CanaryTracker(
            storage_path=self.events_storage,
            canary_storage_path=self.canary_storage,
            alert_cooldown=0  # Disable cooldown for tests
        )
    
    def tearDown(self):
        """Clean up"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_record_trigger(self):
        """Test recording a trigger event"""
        event = self.tracker.record_trigger(
            canary_id=self.aws_canary.id,
            canary_type='aws-key',
            source_ip='192.168.1.100',
            user_agent='boto3/1.26.0',
            send_alert=False  # Skip webhook for test
        )
        
        self.assertIsNotNone(event.id)
        self.assertTrue(event.id.startswith('evt_'))
        self.assertEqual(event.canary_id, self.aws_canary.id)
        self.assertEqual(event.source_ip, '192.168.1.100')
        
        # Check event was stored
        self.assertEqual(len(self.tracker.events), 1)
    
    def test_find_canary_by_aws_key(self):
        """Test finding canary by AWS key"""
        found = self.tracker.find_canary_by_aws_key(self.aws_canary.token_value)
        self.assertEqual(found, self.aws_canary.id)
        
        not_found = self.tracker.find_canary_by_aws_key('AKIAXXXXXXXXXXXXXXXX')
        self.assertIsNone(not_found)
    
    def test_find_canary_by_token(self):
        """Test finding canary by URL token"""
        token = self.url_canary.metadata['token']
        found = self.tracker.find_canary_by_token(token)
        self.assertEqual(found, self.url_canary.id)
    
    def test_find_canary_by_credential(self):
        """Test finding canary by credential"""
        found = self.tracker.find_canary_by_credential(username="test_user")
        self.assertEqual(found, self.cred_canary.id)
        
        found = self.tracker.find_canary_by_credential(password="test_pass123")
        self.assertEqual(found, self.cred_canary.id)
    
    def test_scan_for_aws_keys(self):
        """Test scanning text for AWS keys"""
        text = f"""
        Some log output here
        AWS Access Key: {self.aws_canary.token_value}
        More stuff after
        """
        
        events = self.tracker.scan_for_aws_keys(text, source_ip="log-scanner")
        
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].canary_id, self.aws_canary.id)
        self.assertEqual(events[0].source_ip, "log-scanner")
    
    def test_get_events(self):
        """Test getting events with filtering"""
        # Create multiple events
        self.tracker.record_trigger(
            canary_id=self.aws_canary.id,
            canary_type='aws-key',
            source_ip='10.0.0.1',
            send_alert=False
        )
        self.tracker.record_trigger(
            canary_id=self.url_canary.id,
            canary_type='tracking-url',
            source_ip='10.0.0.2',
            send_alert=False
        )
        self.tracker.record_trigger(
            canary_id=self.aws_canary.id,
            canary_type='aws-key',
            source_ip='10.0.0.3',
            send_alert=False
        )
        
        # Get all
        all_events = self.tracker.get_events()
        self.assertEqual(len(all_events), 3)
        
        # Filter by canary
        aws_events = self.tracker.get_events(canary_id=self.aws_canary.id)
        self.assertEqual(len(aws_events), 2)
        
        # Limit
        limited = self.tracker.get_events(limit=2)
        self.assertEqual(len(limited), 2)
    
    def test_get_dashboard_data(self):
        """Test dashboard data generation"""
        self.tracker.record_trigger(
            canary_id=self.aws_canary.id,
            canary_type='aws-key',
            source_ip='192.168.1.1',
            send_alert=False
        )
        
        data = self.tracker.get_dashboard_data()
        
        self.assertIn('total_canaries', data)
        self.assertIn('triggered_canaries', data)
        self.assertIn('total_events', data)
        self.assertIn('events_24h', data)
        self.assertIn('top_sources', data)
        self.assertIn('recent_events', data)
        
        self.assertEqual(data['total_events'], 1)
        self.assertEqual(len(data['top_sources']), 1)
        self.assertEqual(data['top_sources'][0]['ip'], '192.168.1.1')
    
    def test_event_persistence(self):
        """Test event persistence across instances"""
        self.tracker.record_trigger(
            canary_id=self.aws_canary.id,
            canary_type='aws-key',
            source_ip='10.10.10.10',
            send_alert=False
        )
        
        # Create new tracker
        tracker2 = CanaryTracker(
            storage_path=self.events_storage,
            canary_storage_path=self.canary_storage
        )
        
        events = tracker2.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_ip, '10.10.10.10')


class TestCanarySerialization(unittest.TestCase):
    """Tests for canary serialization"""
    
    def test_canary_to_dict(self):
        """Test canary to dict conversion"""
        canary = Canary(
            id='cnry_test123',
            type=CanaryType.AWS_KEY,
            created_at='2026-02-06T00:00:00Z',
            webhook_url='https://example.com/webhook',
            memo='Test',
            token_value='AKIAIOSFODNN7EXAMPLE',
            token_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        )
        
        d = canary.to_dict()
        
        self.assertEqual(d['id'], 'cnry_test123')
        self.assertEqual(d['type'], 'aws-key')  # Serialized as string
        self.assertEqual(d['token_value'], 'AKIAIOSFODNN7EXAMPLE')
    
    def test_canary_from_dict(self):
        """Test canary from dict conversion"""
        d = {
            'id': 'cnry_test456',
            'type': 'tracking-url',
            'created_at': '2026-02-06T00:00:00Z',
            'webhook_url': 'https://example.com/webhook',
            'memo': 'Test URL',
            'token_value': 'http://example.com/track/abc123',
            'token_secret': '',
            'hostname': '',
            'username': '',
            'password': '',
            'triggered': False,
            'trigger_count': 0,
            'last_triggered': None,
            'metadata': {'token': 'abc123'}
        }
        
        canary = Canary.from_dict(d)
        
        self.assertEqual(canary.id, 'cnry_test456')
        self.assertEqual(canary.type, CanaryType.TRACKING_URL)
        self.assertEqual(canary.metadata['token'], 'abc123')


if __name__ == '__main__':
    unittest.main()
