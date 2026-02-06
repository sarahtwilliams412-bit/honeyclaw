#!/usr/bin/env python3
"""
Container Escape Detection Patterns

Regex patterns for detecting container/sandbox escape attempts.
Covers Docker socket access, namespace manipulation, cgroup exploits,
capability abuse, and known CVE exploit signatures.
"""

import re
from enum import Enum
from typing import Dict, List, Pattern, Tuple
from dataclasses import dataclass


class EscapeCategory(Enum):
    """Categories of container escape techniques."""
    DOCKER_SOCKET = "docker_socket"
    PROC_MANIPULATION = "proc_manipulation"
    NAMESPACE_ESCAPE = "namespace_escape"
    CAPABILITY_ABUSE = "capability_abuse"
    CGROUP_EXPLOIT = "cgroup_exploit"
    KNOWN_CVE = "known_cve"
    MOUNT_ESCAPE = "mount_escape"
    KERNEL_EXPLOIT = "kernel_exploit"
    PRIVILEGED_EXEC = "privileged_exec"


@dataclass
class EscapePattern:
    """
    A single escape detection pattern.
    
    Attributes:
        name: Unique identifier for the pattern
        pattern: Compiled regex pattern
        category: Type of escape technique
        severity: Threat level (1-10, 10 = most severe)
        description: Human-readable description
        mitre_technique: MITRE ATT&CK technique ID
        references: CVE IDs or documentation links
    """
    name: str
    pattern: Pattern
    category: EscapeCategory
    severity: int
    description: str
    mitre_technique: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
    
    def match(self, text: str) -> bool:
        """Check if text matches this pattern."""
        return bool(self.pattern.search(text))
    
    def findall(self, text: str) -> List[str]:
        """Find all matches in text."""
        return self.pattern.findall(text)


# =============================================================================
# Docker Socket Access Patterns
# =============================================================================

DOCKER_SOCKET_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="docker_socket_access",
        pattern=re.compile(
            r'(/var/run/docker\.sock|docker\.sock|/run/docker\.sock)',
            re.IGNORECASE
        ),
        category=EscapeCategory.DOCKER_SOCKET,
        severity=10,
        description="Direct Docker socket access attempt",
        mitre_technique="T1611",
        references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation"],
    ),
    EscapePattern(
        name="docker_api_curl",
        pattern=re.compile(
            r'curl\s+.*--unix-socket.*docker|'
            r'curl\s+.*unix:///var/run/docker',
            re.IGNORECASE
        ),
        category=EscapeCategory.DOCKER_SOCKET,
        severity=10,
        description="Docker API access via curl unix socket",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="docker_privileged_run",
        pattern=re.compile(
            r'docker\s+run\s+.*--privileged|'
            r'docker\s+run\s+.*--pid\s*=\s*host|'
            r'docker\s+run\s+.*--network\s*=\s*host|'
            r'docker\s+run\s+.*--cap-add\s*=\s*SYS_ADMIN',
            re.IGNORECASE
        ),
        category=EscapeCategory.DOCKER_SOCKET,
        severity=10,
        description="Attempt to spawn privileged container from honeypot",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="docker_mount_host",
        pattern=re.compile(
            r'docker\s+run\s+.*-v\s*/:/|'
            r'docker\s+run\s+.*--mount.*source=/|'
            r'docker\s+.*-v\s*/etc:/|'
            r'docker\s+.*-v\s*/root:/',
            re.IGNORECASE
        ),
        category=EscapeCategory.DOCKER_SOCKET,
        severity=10,
        description="Docker volume mount of host filesystem",
        mitre_technique="T1611",
    ),
]

# =============================================================================
# /proc Manipulation Patterns  
# =============================================================================

PROC_MANIPULATION_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="proc_root_access",
        pattern=re.compile(
            r'/proc/\d+/root|'
            r'/proc/1/root|'
            r'/proc/self/root',
            re.IGNORECASE
        ),
        category=EscapeCategory.PROC_MANIPULATION,
        severity=9,
        description="Access to /proc/*/root (container escape vector)",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="proc_ns_access",
        pattern=re.compile(
            r'/proc/\d+/ns/|'
            r'/proc/1/ns/|'
            r'/proc/self/ns/',
            re.IGNORECASE
        ),
        category=EscapeCategory.PROC_MANIPULATION,
        severity=8,
        description="Namespace file access via /proc",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="proc_fd_escape",
        pattern=re.compile(
            r'/proc/\d+/fd/|'
            r'/proc/1/fd/|'
            r'/proc/self/fd/',
            re.IGNORECASE
        ),
        category=EscapeCategory.PROC_MANIPULATION,
        severity=7,
        description="File descriptor access via /proc (potential escape)",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="proc_environ_read",
        pattern=re.compile(
            r'cat\s+/proc/1/environ|'
            r'/proc/\d+/environ',
            re.IGNORECASE
        ),
        category=EscapeCategory.PROC_MANIPULATION,
        severity=6,
        description="Reading process environment from /proc",
        mitre_technique="T1057",
    ),
]

# =============================================================================
# Namespace Escape Patterns
# =============================================================================

NAMESPACE_ESCAPE_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="nsenter_command",
        pattern=re.compile(
            r'\bnsenter\s+.*(-t|--target)\s*\d+|'
            r'\bnsenter\s+.*--mount|'
            r'\bnsenter\s+.*--pid|'
            r'\bnsenter\s+.*--net|'
            r'\bnsenter\s+-a',
            re.IGNORECASE
        ),
        category=EscapeCategory.NAMESPACE_ESCAPE,
        severity=10,
        description="nsenter command to join host namespaces",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="unshare_command",
        pattern=re.compile(
            r'\bunshare\s+.*--map-root-user|'
            r'\bunshare\s+.*-r|'
            r'\bunshare\s+-U.*-r',
            re.IGNORECASE
        ),
        category=EscapeCategory.NAMESPACE_ESCAPE,
        severity=8,
        description="unshare with root mapping (user namespace escape)",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="setns_syscall",
        pattern=re.compile(
            r'\bsetns\s*\(|'
            r'syscall.*setns|'
            r'CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET',
            re.IGNORECASE
        ),
        category=EscapeCategory.NAMESPACE_ESCAPE,
        severity=9,
        description="setns syscall or namespace clone flags",
        mitre_technique="T1611",
    ),
]

# =============================================================================
# Capability Abuse Patterns
# =============================================================================

CAPABILITY_ABUSE_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="cap_sys_admin_abuse",
        pattern=re.compile(
            r'capsh\s+.*--caps.*cap_sys_admin|'
            r'CAP_SYS_ADMIN|'
            r'--cap-add\s*=?\s*SYS_ADMIN',
            re.IGNORECASE
        ),
        category=EscapeCategory.CAPABILITY_ABUSE,
        severity=10,
        description="CAP_SYS_ADMIN capability abuse",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="cap_sys_ptrace_abuse",
        pattern=re.compile(
            r'CAP_SYS_PTRACE|'
            r'--cap-add\s*=?\s*SYS_PTRACE|'
            r'ptrace\s*\(\s*PTRACE_ATTACH',
            re.IGNORECASE
        ),
        category=EscapeCategory.CAPABILITY_ABUSE,
        severity=9,
        description="CAP_SYS_PTRACE capability abuse (process injection)",
        mitre_technique="T1055",
    ),
    EscapePattern(
        name="cap_net_admin_abuse",
        pattern=re.compile(
            r'CAP_NET_ADMIN|'
            r'--cap-add\s*=?\s*NET_ADMIN',
            re.IGNORECASE
        ),
        category=EscapeCategory.CAPABILITY_ABUSE,
        severity=7,
        description="CAP_NET_ADMIN capability abuse",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="cap_dac_override",
        pattern=re.compile(
            r'CAP_DAC_OVERRIDE|'
            r'CAP_DAC_READ_SEARCH|'
            r'--cap-add\s*=?\s*DAC_OVERRIDE',
            re.IGNORECASE
        ),
        category=EscapeCategory.CAPABILITY_ABUSE,
        severity=8,
        description="DAC capability override (bypass file permissions)",
        mitre_technique="T1548",
    ),
    EscapePattern(
        name="getcap_setcap",
        pattern=re.compile(
            r'\bgetcap\s+|'
            r'\bsetcap\s+|'
            r'/sbin/getcap|'
            r'/sbin/setcap',
            re.IGNORECASE
        ),
        category=EscapeCategory.CAPABILITY_ABUSE,
        severity=6,
        description="Capability enumeration/modification tools",
        mitre_technique="T1548",
    ),
]

# =============================================================================
# Cgroup Escape Patterns
# =============================================================================

CGROUP_ESCAPE_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="cgroup_release_agent",
        pattern=re.compile(
            r'/sys/fs/cgroup.*release_agent|'
            r'release_agent\s*=|'
            r'echo.*>\s*/sys/fs/cgroup.*release_agent',
            re.IGNORECASE
        ),
        category=EscapeCategory.CGROUP_EXPLOIT,
        severity=10,
        description="Cgroup release_agent exploitation (CVE-2022-0492)",
        mitre_technique="T1611",
        references=["CVE-2022-0492"],
    ),
    EscapePattern(
        name="cgroup_notify_on_release",
        pattern=re.compile(
            r'notify_on_release|'
            r'echo\s+1\s*>\s*/sys/fs/cgroup',
            re.IGNORECASE
        ),
        category=EscapeCategory.CGROUP_EXPLOIT,
        severity=9,
        description="Cgroup notify_on_release manipulation",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="rdma_cgroup_escape",
        pattern=re.compile(
            r'/sys/fs/cgroup/rdma|'
            r'cgroup.*rdma',
            re.IGNORECASE
        ),
        category=EscapeCategory.CGROUP_EXPLOIT,
        severity=8,
        description="RDMA cgroup escape attempt",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="cgroup_mkdir_escape",
        pattern=re.compile(
            r'mkdir\s+.*(/sys/fs/cgroup|/cgroup)|'
            r'mount.*cgroup',
            re.IGNORECASE
        ),
        category=EscapeCategory.CGROUP_EXPLOIT,
        severity=8,
        description="Cgroup hierarchy manipulation",
        mitre_technique="T1611",
    ),
]

# =============================================================================
# Known CVE Exploit Signatures
# =============================================================================

CVE_PATTERNS: List[EscapePattern] = [
    # CVE-2022-0492: cgroup release_agent
    EscapePattern(
        name="cve_2022_0492",
        pattern=re.compile(
            r'echo\s+["\']?/[^"\']*["\']?\s*>\s*'
            r'/sys/fs/cgroup/[^/]+/[^/]+/release_agent',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=10,
        description="CVE-2022-0492: Cgroup v1 release_agent escape",
        mitre_technique="T1611",
        references=["CVE-2022-0492"],
    ),
    # CVE-2020-15257: Containerd
    EscapePattern(
        name="cve_2020_15257",
        pattern=re.compile(
            r'/run/containerd/containerd\.sock|'
            r'containerd-shim.*-namespace',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=10,
        description="CVE-2020-15257: Containerd socket exposure",
        mitre_technique="T1611",
        references=["CVE-2020-15257"],
    ),
    # CVE-2019-5736: runc
    EscapePattern(
        name="cve_2019_5736",
        pattern=re.compile(
            r'/proc/self/exe.*runc|'
            r'overwrite.*runc|'
            r'#!/proc/self/exe',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=10,
        description="CVE-2019-5736: runc container escape",
        mitre_technique="T1611",
        references=["CVE-2019-5736"],
    ),
    # CVE-2021-22555: Netfilter (kernel)
    EscapePattern(
        name="cve_2021_22555",
        pattern=re.compile(
            r'xt_compat_target_from_user|'
            r'ip6?tables.*-j.*TARGE',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=9,
        description="CVE-2021-22555: Netfilter heap OOB write",
        mitre_technique="T1068",
        references=["CVE-2021-22555"],
    ),
    # CVE-2022-0185: fsconfig heap overflow
    EscapePattern(
        name="cve_2022_0185",
        pattern=re.compile(
            r'fsconfig\s*\(|'
            r'FSCONFIG_SET_STRING',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=10,
        description="CVE-2022-0185: fsconfig heap overflow",
        mitre_technique="T1068",
        references=["CVE-2022-0185"],
    ),
    # CVE-2021-3490: eBPF verifier bypass
    EscapePattern(
        name="cve_2021_3490",
        pattern=re.compile(
            r'bpf\s*\(.*BPF_PROG_LOAD|'
            r'BPF_ALU64.*BPF_AND|'
            r'/sys/kernel/debug/tracing',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=9,
        description="CVE-2021-3490: eBPF privilege escalation",
        mitre_technique="T1068",
        references=["CVE-2021-3490"],
    ),
    # Dirty Pipe CVE-2022-0847
    EscapePattern(
        name="cve_2022_0847_dirty_pipe",
        pattern=re.compile(
            r'splice\s*\(.*SPLICE_F_GIFT|'
            r'pipe2\s*\(.*O_DIRECT',
            re.IGNORECASE
        ),
        category=EscapeCategory.KNOWN_CVE,
        severity=10,
        description="CVE-2022-0847: Dirty Pipe privilege escalation",
        mitre_technique="T1068",
        references=["CVE-2022-0847"],
    ),
]

# =============================================================================
# Mount/Filesystem Escape Patterns
# =============================================================================

MOUNT_ESCAPE_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="mount_host_fs",
        pattern=re.compile(
            r'mount\s+.*-o.*bind.*(/host|/mnt/host)|'
            r'mount\s+.*/dev/[hsv]d[a-z]|'
            r'mount\s+.*--bind\s+/',
            re.IGNORECASE
        ),
        category=EscapeCategory.MOUNT_ESCAPE,
        severity=10,
        description="Mounting host filesystem",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="debugfs_access",
        pattern=re.compile(
            r'\bdebugfs\s+|'
            r'/sys/kernel/debug',
            re.IGNORECASE
        ),
        category=EscapeCategory.MOUNT_ESCAPE,
        severity=8,
        description="debugfs access (kernel debugging filesystem)",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="sysfs_manipulation",
        pattern=re.compile(
            r'echo.*>\s*/sys/(class|bus|devices)/|'
            r'/sys/module/.*/parameters',
            re.IGNORECASE
        ),
        category=EscapeCategory.MOUNT_ESCAPE,
        severity=7,
        description="sysfs manipulation",
        mitre_technique="T1611",
    ),
]

# =============================================================================
# Privileged Execution Patterns
# =============================================================================

PRIVILEGED_EXEC_PATTERNS: List[EscapePattern] = [
    EscapePattern(
        name="kmod_load",
        pattern=re.compile(
            r'\binsmod\s+|'
            r'\bmodprobe\s+|'
            r'\brmmod\s+|'
            r'/lib/modules/',
            re.IGNORECASE
        ),
        category=EscapeCategory.PRIVILEGED_EXEC,
        severity=10,
        description="Kernel module loading attempt",
        mitre_technique="T1547.006",
    ),
    EscapePattern(
        name="mknod_device",
        pattern=re.compile(
            r'\bmknod\s+.*[bc]\s+\d+\s+\d+|'
            r'mknod.*/dev/',
            re.IGNORECASE
        ),
        category=EscapeCategory.PRIVILEGED_EXEC,
        severity=9,
        description="Creating device nodes (mknod)",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="chroot_escape",
        pattern=re.compile(
            r'\bchroot\s+/|'
            r'pivot_root\s+|'
            r'/host/|/hostfs/',
            re.IGNORECASE
        ),
        category=EscapeCategory.PRIVILEGED_EXEC,
        severity=8,
        description="chroot/pivot_root escape attempt",
        mitre_technique="T1611",
    ),
    EscapePattern(
        name="seccomp_bypass",
        pattern=re.compile(
            r'prctl\s*\(.*PR_SET_NO_NEW_PRIVS|'
            r'seccomp\s*\(|'
            r'/proc/self/status.*Seccomp',
            re.IGNORECASE
        ),
        category=EscapeCategory.PRIVILEGED_EXEC,
        severity=7,
        description="Seccomp bypass/enumeration",
        mitre_technique="T1562",
    ),
]

# =============================================================================
# Aggregated Pattern Collections
# =============================================================================

ESCAPE_PATTERNS: List[EscapePattern] = (
    DOCKER_SOCKET_PATTERNS +
    PROC_MANIPULATION_PATTERNS +
    NAMESPACE_ESCAPE_PATTERNS +
    CAPABILITY_ABUSE_PATTERNS +
    CGROUP_ESCAPE_PATTERNS +
    CVE_PATTERNS +
    MOUNT_ESCAPE_PATTERNS +
    PRIVILEGED_EXEC_PATTERNS
)


def get_all_patterns() -> List[EscapePattern]:
    """Get all escape detection patterns."""
    return ESCAPE_PATTERNS


def get_patterns_by_category(category: EscapeCategory) -> List[EscapePattern]:
    """Get patterns for a specific category."""
    return [p for p in ESCAPE_PATTERNS if p.category == category]


def get_patterns_by_severity(min_severity: int) -> List[EscapePattern]:
    """Get patterns at or above a severity threshold."""
    return [p for p in ESCAPE_PATTERNS if p.severity >= min_severity]


def match_text(text: str) -> List[Tuple[EscapePattern, List[str]]]:
    """
    Match text against all patterns.
    
    Returns:
        List of (pattern, matches) tuples for all matching patterns.
    """
    results = []
    for pattern in ESCAPE_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            results.append((pattern, matches))
    return results


# Pattern count for documentation
PATTERN_STATS = {
    'total': len(ESCAPE_PATTERNS),
    'by_category': {
        cat.value: len(get_patterns_by_category(cat))
        for cat in EscapeCategory
    },
    'high_severity_count': len(get_patterns_by_severity(8)),
}
