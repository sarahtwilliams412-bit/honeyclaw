#!/usr/bin/env python3
"""
Honeyclaw MITRE ATT&CK Event Mapper

Comprehensive mapping of observed honeypot behaviors to MITRE ATT&CK framework.

Auto-tags events as they flow through the logging pipeline, supporting:
- Tactic identification (TA0001-TA0011)
- Technique identification (T1xxx)
- Sub-technique identification (T1xxx.xxx)
- Custom mapping rules via configuration
- Confidence scoring per mapping

Reference: https://attack.mitre.org/
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# --- MITRE ATT&CK IDs ---

class TacticID:
    """MITRE ATT&CK Tactic IDs."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class TechniqueID:
    """MITRE ATT&CK Technique IDs (commonly observed in honeypots)."""
    # Initial Access
    VALID_ACCOUNTS = "T1078"
    EXPLOIT_PUBLIC_APP = "T1190"
    EXTERNAL_REMOTE_SERVICES = "T1133"

    # Execution
    COMMAND_SCRIPTING = "T1059"
    UNIX_SHELL = "T1059.004"
    PYTHON = "T1059.006"

    # Persistence
    ACCOUNT_MANIPULATION = "T1098"
    CREATE_ACCOUNT = "T1136"
    SSH_AUTHORIZED_KEYS = "T1098.004"
    CRON_JOB = "T1053.003"
    SYSTEMD_SERVICE = "T1543.002"
    BOOT_LOGON_AUTOSTART = "T1547"
    RC_SCRIPTS = "T1037.004"

    # Privilege Escalation
    ABUSE_ELEVATION = "T1548"
    SUDO_ABUSE = "T1548.003"
    SETUID_SETGID = "T1548.001"
    EXPLOITATION_FOR_PRIV_ESC = "T1068"
    CONTAINER_ESCAPE = "T1611"

    # Defense Evasion
    INDICATOR_REMOVAL = "T1070"
    CLEAR_LINUX_LOGS = "T1070.002"
    FILE_DELETION = "T1070.004"
    TIMESTOMP = "T1070.006"
    HIDE_ARTIFACTS = "T1564"
    DISABLE_SECURITY_TOOLS = "T1562"
    PROCESS_INJECTION = "T1055"

    # Credential Access
    BRUTE_FORCE = "T1110"
    PASSWORD_GUESSING = "T1110.001"
    CREDENTIAL_STUFFING = "T1110.004"
    CREDENTIAL_DUMPING = "T1003"
    UNSECURED_CREDENTIALS = "T1552"
    CREDENTIALS_IN_FILES = "T1552.001"

    # Discovery
    SYSTEM_INFO_DISCOVERY = "T1082"
    FILE_DIR_DISCOVERY = "T1083"
    NETWORK_SERVICE_DISCOVERY = "T1046"
    PROCESS_DISCOVERY = "T1057"
    ACCOUNT_DISCOVERY = "T1087"
    SYSTEM_NETWORK_CONFIG = "T1016"
    SYSTEM_NETWORK_CONNECTIONS = "T1049"
    PERMISSION_GROUPS_DISCOVERY = "T1069"
    SYSTEM_OWNER_DISCOVERY = "T1033"
    SOFTWARE_DISCOVERY = "T1518"

    # Lateral Movement
    REMOTE_SERVICES = "T1021"
    SSH = "T1021.004"
    REMOTE_FILE_COPY = "T1105"

    # Collection
    DATA_FROM_LOCAL_SYSTEM = "T1005"
    DATA_STAGED = "T1074"
    ARCHIVE_DATA = "T1560"

    # Command and Control
    APPLICATION_LAYER_PROTOCOL = "T1071"
    INGRESS_TOOL_TRANSFER = "T1105"
    NON_STANDARD_PORT = "T1571"
    ENCRYPTED_CHANNEL = "T1573"

    # Exfiltration
    EXFIL_OVER_C2 = "T1041"
    EXFIL_OVER_WEB = "T1567"

    # Impact
    DATA_DESTRUCTION = "T1485"
    RESOURCE_HIJACKING = "T1496"
    DEFACEMENT = "T1491"


@dataclass
class MitreMapping:
    """A single MITRE ATT&CK mapping result."""
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    confidence: float = 0.8  # 0.0-1.0
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "confidence": round(self.confidence, 2),
        }
        if self.sub_technique_id:
            d["sub_technique_id"] = self.sub_technique_id
            d["sub_technique_name"] = self.sub_technique_name
        return d


# --- Mapping Rules ---

@dataclass
class MappingRule:
    """A rule that maps event patterns to MITRE ATT&CK."""
    name: str
    event_types: List[str]  # Event types to match (supports wildcards)
    patterns: Dict[str, str]  # field -> regex pattern to match
    mappings: List[MitreMapping]
    enabled: bool = True


# --- Built-in Rules ---

BUILTIN_RULES: List[MappingRule] = [
    # === Initial Access ===
    MappingRule(
        name="successful_auth",
        event_types=["auth_success", "login_success", "session_established"],
        patterns={},
        mappings=[
            MitreMapping(TacticID.INITIAL_ACCESS, "Initial Access",
                         TechniqueID.VALID_ACCOUNTS, "Valid Accounts", 0.9),
        ],
    ),
    MappingRule(
        name="ssh_connection",
        event_types=["connection", "ssh_connection"],
        patterns={},
        mappings=[
            MitreMapping(TacticID.INITIAL_ACCESS, "Initial Access",
                         TechniqueID.EXTERNAL_REMOTE_SERVICES, "External Remote Services", 0.7),
        ],
    ),
    MappingRule(
        name="api_exploit",
        event_types=["api_request", "http_request"],
        patterns={"path": r"(%27|--|union.*select|;.*exec|/\.\./|%2e%2e)"},
        mappings=[
            MitreMapping(TacticID.INITIAL_ACCESS, "Initial Access",
                         TechniqueID.EXPLOIT_PUBLIC_APP, "Exploit Public-Facing Application", 0.85),
        ],
    ),

    # === Execution ===
    MappingRule(
        name="shell_command",
        event_types=["command", "shell_command"],
        patterns={},
        mappings=[
            MitreMapping(TacticID.EXECUTION, "Execution",
                         TechniqueID.COMMAND_SCRIPTING, "Command and Scripting Interpreter", 0.7),
            MitreMapping(TacticID.EXECUTION, "Execution",
                         TechniqueID.UNIX_SHELL, "Unix Shell", 0.8,
                         TechniqueID.UNIX_SHELL, "Unix Shell"),
        ],
    ),
    MappingRule(
        name="python_execution",
        event_types=["command", "shell_command"],
        patterns={"command": r"python[23]?\s+(-c|.*\.py)"},
        mappings=[
            MitreMapping(TacticID.EXECUTION, "Execution",
                         TechniqueID.PYTHON, "Python", 0.9,
                         TechniqueID.PYTHON, "Python"),
        ],
    ),

    # === Credential Access ===
    MappingRule(
        name="brute_force",
        event_types=["login_attempt", "auth_attempt", "auth_failure"],
        patterns={},
        mappings=[
            MitreMapping(TacticID.CREDENTIAL_ACCESS, "Credential Access",
                         TechniqueID.BRUTE_FORCE, "Brute Force", 0.7),
        ],
    ),
    MappingRule(
        name="credential_stuffing",
        event_types=["rate_limit_auth"],
        patterns={},
        mappings=[
            MitreMapping(TacticID.CREDENTIAL_ACCESS, "Credential Access",
                         TechniqueID.CREDENTIAL_STUFFING, "Credential Stuffing", 0.85,
                         TechniqueID.CREDENTIAL_STUFFING, "Credential Stuffing"),
        ],
    ),
    MappingRule(
        name="read_credentials",
        event_types=["command", "file_read"],
        patterns={"command": r"cat.*(passwd|shadow|credentials|\.env|\.aws|id_rsa)"},
        mappings=[
            MitreMapping(TacticID.CREDENTIAL_ACCESS, "Credential Access",
                         TechniqueID.UNSECURED_CREDENTIALS, "Unsecured Credentials", 0.85),
            MitreMapping(TacticID.CREDENTIAL_ACCESS, "Credential Access",
                         TechniqueID.CREDENTIALS_IN_FILES, "Credentials In Files", 0.85,
                         TechniqueID.CREDENTIALS_IN_FILES, "Credentials In Files"),
        ],
    ),

    # === Discovery ===
    MappingRule(
        name="system_info",
        event_types=["command", "shell_command"],
        patterns={"command": r"^(uname|hostnamectl|lsb_release|cat\s+/etc/(os-release|issue))"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.SYSTEM_INFO_DISCOVERY, "System Information Discovery", 0.9),
        ],
    ),
    MappingRule(
        name="file_discovery",
        event_types=["command", "shell_command"],
        patterns={"command": r"^(ls|find|dir|tree)\s"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.FILE_DIR_DISCOVERY, "File and Directory Discovery", 0.8),
        ],
    ),
    MappingRule(
        name="process_discovery",
        event_types=["command", "shell_command"],
        patterns={"command": r"^(ps|top|htop)\s?"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.PROCESS_DISCOVERY, "Process Discovery", 0.85),
        ],
    ),
    MappingRule(
        name="network_discovery",
        event_types=["command", "shell_command"],
        patterns={"command": r"(netstat|ss\s|nmap|ip\s+(addr|route)|ifconfig|arp)"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.SYSTEM_NETWORK_CONFIG, "System Network Configuration Discovery", 0.85),
        ],
    ),
    MappingRule(
        name="network_connections",
        event_types=["command", "shell_command"],
        patterns={"command": r"(netstat\s+-[a-z]*[tn]|ss\s+-[a-z]*[tn]|lsof\s+-i)"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.SYSTEM_NETWORK_CONNECTIONS, "System Network Connections Discovery", 0.85),
        ],
    ),
    MappingRule(
        name="account_discovery",
        event_types=["command", "shell_command"],
        patterns={"command": r"(cat\s+/etc/passwd|getent\s+passwd|id\s|whoami|w\s*$|who\s)"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.ACCOUNT_DISCOVERY, "Account Discovery", 0.8),
        ],
    ),
    MappingRule(
        name="user_discovery",
        event_types=["command", "shell_command"],
        patterns={"command": r"^(whoami|id)$"},
        mappings=[
            MitreMapping(TacticID.DISCOVERY, "Discovery",
                         TechniqueID.SYSTEM_OWNER_DISCOVERY, "System Owner/User Discovery", 0.9),
        ],
    ),

    # === Privilege Escalation ===
    MappingRule(
        name="sudo_abuse",
        event_types=["command", "shell_command", "privilege_escalation"],
        patterns={"command": r"sudo\s"},
        mappings=[
            MitreMapping(TacticID.PRIVILEGE_ESCALATION, "Privilege Escalation",
                         TechniqueID.ABUSE_ELEVATION, "Abuse Elevation Control Mechanism", 0.85),
            MitreMapping(TacticID.PRIVILEGE_ESCALATION, "Privilege Escalation",
                         TechniqueID.SUDO_ABUSE, "Sudo and Sudo Caching", 0.85,
                         TechniqueID.SUDO_ABUSE, "Sudo and Sudo Caching"),
        ],
    ),
    MappingRule(
        name="suid_setgid",
        event_types=["command", "shell_command"],
        patterns={"command": r"(chmod\s+[u+]*s|find.*-perm.*4000|find.*-perm.*2000)"},
        mappings=[
            MitreMapping(TacticID.PRIVILEGE_ESCALATION, "Privilege Escalation",
                         TechniqueID.SETUID_SETGID, "Setuid and Setgid", 0.9,
                         TechniqueID.SETUID_SETGID, "Setuid and Setgid"),
        ],
    ),
    MappingRule(
        name="container_escape",
        event_types=["command", "shell_command", "escape_attempt"],
        patterns={"command": r"(docker\.sock|nsenter|unshare|/proc/\d+/root|cgroup.*release_agent)"},
        mappings=[
            MitreMapping(TacticID.PRIVILEGE_ESCALATION, "Privilege Escalation",
                         TechniqueID.CONTAINER_ESCAPE, "Escape to Host", 0.95),
        ],
    ),

    # === Persistence ===
    MappingRule(
        name="cron_persistence",
        event_types=["command", "shell_command"],
        patterns={"command": r"(crontab|/etc/cron)"},
        mappings=[
            MitreMapping(TacticID.PERSISTENCE, "Persistence",
                         TechniqueID.CRON_JOB, "Cron", 0.9,
                         TechniqueID.CRON_JOB, "Scheduled Task: Cron"),
        ],
    ),
    MappingRule(
        name="ssh_key_persistence",
        event_types=["command", "shell_command"],
        patterns={"command": r"(authorized_keys|\.ssh/)"},
        mappings=[
            MitreMapping(TacticID.PERSISTENCE, "Persistence",
                         TechniqueID.SSH_AUTHORIZED_KEYS, "SSH Authorized Keys", 0.9,
                         TechniqueID.SSH_AUTHORIZED_KEYS, "SSH Authorized Keys"),
        ],
    ),
    MappingRule(
        name="systemd_persistence",
        event_types=["command", "shell_command"],
        patterns={"command": r"(systemctl\s+enable|/etc/systemd/system/)"},
        mappings=[
            MitreMapping(TacticID.PERSISTENCE, "Persistence",
                         TechniqueID.SYSTEMD_SERVICE, "Systemd Service", 0.9,
                         TechniqueID.SYSTEMD_SERVICE, "Systemd Service"),
        ],
    ),

    # === Defense Evasion ===
    MappingRule(
        name="log_clearing",
        event_types=["command", "shell_command"],
        patterns={"command": r"(rm\s+.*(/var/log|auth\.log|syslog|wtmp)|echo\s*>\s*/var/log|truncate.*log|history\s+-c|unset\s+HISTFILE)"},
        mappings=[
            MitreMapping(TacticID.DEFENSE_EVASION, "Defense Evasion",
                         TechniqueID.INDICATOR_REMOVAL, "Indicator Removal", 0.9),
            MitreMapping(TacticID.DEFENSE_EVASION, "Defense Evasion",
                         TechniqueID.CLEAR_LINUX_LOGS, "Clear Linux or Mac System Logs", 0.9,
                         TechniqueID.CLEAR_LINUX_LOGS, "Clear Linux or Mac System Logs"),
        ],
    ),
    MappingRule(
        name="timestomp",
        event_types=["command", "shell_command"],
        patterns={"command": r"touch\s+-[a-z]*r\s"},
        mappings=[
            MitreMapping(TacticID.DEFENSE_EVASION, "Defense Evasion",
                         TechniqueID.TIMESTOMP, "Timestomping", 0.9,
                         TechniqueID.TIMESTOMP, "Timestomping"),
        ],
    ),

    # === Lateral Movement ===
    MappingRule(
        name="ssh_lateral",
        event_types=["command", "shell_command", "lateral_movement"],
        patterns={"command": r"(ssh\s|scp\s|ssh-keyscan)"},
        mappings=[
            MitreMapping(TacticID.LATERAL_MOVEMENT, "Lateral Movement",
                         TechniqueID.REMOTE_SERVICES, "Remote Services", 0.85),
            MitreMapping(TacticID.LATERAL_MOVEMENT, "Lateral Movement",
                         TechniqueID.SSH, "SSH", 0.85,
                         TechniqueID.SSH, "SSH"),
        ],
    ),

    # === Collection ===
    MappingRule(
        name="data_collection",
        event_types=["command", "file_read"],
        patterns={"command": r"cat\s+(.*\.(conf|cfg|env|key|pem|json|yaml|yml|xml|sql|csv|db|sqlite))"},
        mappings=[
            MitreMapping(TacticID.COLLECTION, "Collection",
                         TechniqueID.DATA_FROM_LOCAL_SYSTEM, "Data from Local System", 0.8),
        ],
    ),
    MappingRule(
        name="data_staging",
        event_types=["command", "shell_command"],
        patterns={"command": r"(tar\s+[a-z]*[czf]|zip\s|7z\s|gzip\s)"},
        mappings=[
            MitreMapping(TacticID.COLLECTION, "Collection",
                         TechniqueID.ARCHIVE_DATA, "Archive Collected Data", 0.85),
        ],
    ),

    # === Command and Control ===
    MappingRule(
        name="ingress_tool_transfer",
        event_types=["command", "shell_command", "download_attempt"],
        patterns={"command": r"(wget|curl|fetch|lwp-download)\s+http"},
        mappings=[
            MitreMapping(TacticID.COMMAND_AND_CONTROL, "Command and Control",
                         TechniqueID.INGRESS_TOOL_TRANSFER, "Ingress Tool Transfer", 0.9),
        ],
    ),

    # === Exfiltration ===
    MappingRule(
        name="exfiltration",
        event_types=["command", "shell_command"],
        patterns={"command": r"(curl\s+.*-d|wget\s+.*--post|nc\s+.*<|scp\s+.*@|rsync\s+.*@)"},
        mappings=[
            MitreMapping(TacticID.EXFILTRATION, "Exfiltration",
                         TechniqueID.EXFIL_OVER_C2, "Exfiltration Over C2 Channel", 0.8),
        ],
    ),

    # === Impact ===
    MappingRule(
        name="resource_hijacking",
        event_types=["command", "shell_command"],
        patterns={"command": r"(xmrig|minerd|cpuminer|stratum|nicehash|coinhive|cryptonight)"},
        mappings=[
            MitreMapping(TacticID.IMPACT, "Impact",
                         TechniqueID.RESOURCE_HIJACKING, "Resource Hijacking", 0.95),
        ],
    ),
    MappingRule(
        name="data_destruction",
        event_types=["command", "shell_command"],
        patterns={"command": r"(rm\s+-rf\s+/|dd\s+if=/dev/(zero|urandom)\s+of=|shred\s|wipe\s)"},
        mappings=[
            MitreMapping(TacticID.IMPACT, "Impact",
                         TechniqueID.DATA_DESTRUCTION, "Data Destruction", 0.9),
        ],
    ),
]


class MitreMapper:
    """
    Maps honeypot events to MITRE ATT&CK tactics and techniques.

    Evaluates events against mapping rules and returns all applicable
    MITRE ATT&CK classifications.
    """

    def __init__(
        self,
        rules: Optional[List[MappingRule]] = None,
        enable_builtin: bool = True,
    ):
        self.rules: List[MappingRule] = []
        if enable_builtin:
            self.rules.extend(BUILTIN_RULES)
        if rules:
            self.rules.extend(rules)

        # Stats
        self._events_processed = 0
        self._events_mapped = 0

    def map_event(self, event: Dict[str, Any], event_type: str) -> List[MitreMapping]:
        """
        Map an event to MITRE ATT&CK tactics/techniques.

        Args:
            event: The event data dict
            event_type: The event type string

        Returns:
            List of MitreMapping objects
        """
        self._events_processed += 1
        mappings: List[MitreMapping] = []
        seen: Set[str] = set()  # Dedup by technique ID

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check event type match
            if not self._matches_event_type(event_type, rule.event_types):
                continue

            # Check pattern match
            if not self._matches_patterns(event, rule.patterns):
                continue

            # Add mappings (deduped)
            for mapping in rule.mappings:
                key = f"{mapping.tactic_id}:{mapping.technique_id}"
                if mapping.sub_technique_id:
                    key += f":{mapping.sub_technique_id}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(mapping)

        if mappings:
            self._events_mapped += 1

        return mappings

    def enrich_event(self, event: Dict[str, Any], event_type: str) -> Dict[str, Any]:
        """
        Enrich an event with MITRE ATT&CK tags.

        Adds 'mitre_tactics', 'mitre_techniques', and 'mitre_mappings'
        fields to the event dict.

        Args:
            event: The event data dict (modified in-place)
            event_type: The event type string

        Returns:
            The enriched event dict
        """
        mappings = self.map_event(event, event_type)

        if mappings:
            event["mitre_tactics"] = list(set(m.tactic_id for m in mappings))
            event["mitre_techniques"] = list(set(m.technique_id for m in mappings))
            event["mitre_mappings"] = [m.to_dict() for m in mappings]

        return event

    def add_rule(self, rule: MappingRule):
        """Add a custom mapping rule."""
        self.rules.append(rule)

    def get_stats(self) -> Dict[str, Any]:
        """Get mapping statistics."""
        return {
            "events_processed": self._events_processed,
            "events_mapped": self._events_mapped,
            "coverage_percent": round(
                (self._events_mapped / self._events_processed * 100)
                if self._events_processed > 0 else 0.0, 1
            ),
            "rules_count": len(self.rules),
            "rules_enabled": sum(1 for r in self.rules if r.enabled),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _matches_event_type(event_type: str, patterns: List[str]) -> bool:
        """Check if event type matches any pattern (supports * wildcard)."""
        if not patterns:
            return True
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern == event_type:
                return True
            # Simple wildcard
            if "*" in pattern:
                regex = pattern.replace("*", ".*")
                if re.match(regex, event_type):
                    return True
        return False

    @staticmethod
    def _matches_patterns(event: Dict[str, Any], patterns: Dict[str, str]) -> bool:
        """Check if event matches all field patterns."""
        if not patterns:
            return True

        for field_path, regex_pattern in patterns.items():
            # Navigate nested fields with dot notation
            value = event
            for key in field_path.split("."):
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    value = None
                    break

            if value is None:
                return False

            if not re.search(regex_pattern, str(value), re.IGNORECASE):
                return False

        return True


# Singleton for default mapper
_default_mapper: Optional[MitreMapper] = None


def get_mapper() -> MitreMapper:
    """Get or create the default MITRE mapper."""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = MitreMapper()
    return _default_mapper


def map_event(event: Dict[str, Any], event_type: str) -> List[MitreMapping]:
    """Convenience function to map an event."""
    return get_mapper().map_event(event, event_type)


def enrich_event(event: Dict[str, Any], event_type: str) -> Dict[str, Any]:
    """Convenience function to enrich an event."""
    return get_mapper().enrich_event(event, event_type)
