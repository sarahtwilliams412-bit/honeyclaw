#!/usr/bin/env python3
"""
Honeyclaw Fake Filesystem

Generates and maintains a realistic filesystem tree with:
- OS-appropriate directory structure
- Fake /etc/passwd, /etc/shadow, /etc/hosts
- Realistic home directories with .bash_history, .ssh/, .aws/
- Canary tokens embedded in config files
- Process list simulation (/proc entries)
- Size, permission, timestamp metadata
"""

import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FakeFile:
    """Represents a file in the fake filesystem."""
    name: str
    is_dir: bool = False
    content: str = ""
    size: int = 0
    permissions: str = "-rw-r--r--"
    owner: str = "root"
    group: str = "root"
    mtime: float = 0.0
    children: Dict[str, "FakeFile"] = field(default_factory=dict)

    def __post_init__(self):
        if self.is_dir and not self.permissions.startswith("d"):
            self.permissions = "d" + self.permissions[1:]
        if not self.size and self.content:
            self.size = len(self.content.encode())
        if not self.mtime:
            # Random time in last 90 days
            self.mtime = time.time() - random.randint(0, 90 * 86400)

    def ls_entry(self) -> str:
        """Generate ls -la style entry."""
        dt = datetime.fromtimestamp(self.mtime)
        date_str = dt.strftime("%b %d %H:%M")
        links = len(self.children) + 2 if self.is_dir else 1
        size_str = str(self.size) if not self.is_dir else "4096"
        return f"{self.permissions} {links:>3} {self.owner:<8} {self.group:<8} {size_str:>8} {date_str} {self.name}"


class FakeFilesystem:
    """
    Maintains a complete fake filesystem for shell emulation.

    Generates realistic directory trees based on an OS profile,
    embeds canary tokens, and supports standard file operations.
    """

    def __init__(self, profile: Optional[Dict[str, Any]] = None, username: str = "user"):
        self.username = username
        self.profile = profile or self._default_profile()
        self.root = FakeFile(name="/", is_dir=True, permissions="drwxr-xr-x", owner="root", group="root")
        self._build_tree()

    def _default_profile(self) -> Dict[str, Any]:
        return {
            "os": "Ubuntu",
            "version": "22.04.3 LTS",
            "kernel": "5.15.0-91-generic",
            "arch": "x86_64",
            "hostname": "prod-web-01",
        }

    def _build_tree(self):
        """Build the complete filesystem tree."""
        self._create_system_dirs()
        self._create_etc_files()
        self._create_home_dir()
        self._create_var_dirs()
        self._create_proc_entries()
        self._create_opt_dirs()

    def _create_system_dirs(self):
        """Create standard system directories."""
        system_dirs = [
            "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
            "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
            "/srv", "/sys", "/tmp", "/usr", "/var",
            "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/share",
            "/usr/local/bin", "/usr/local/lib",
            "/var/log", "/var/tmp", "/var/lib", "/var/cache", "/var/run",
        ]
        for d in system_dirs:
            self._mkdir(d)

    def _create_etc_files(self):
        """Create realistic /etc files."""
        hostname = self.profile.get("hostname", "server")

        # /etc/hostname
        self._create_file("/etc/hostname", hostname + "\n", permissions="-rw-r--r--")

        # /etc/hosts
        self._create_file("/etc/hosts", f"""127.0.0.1\tlocalhost
127.0.1.1\t{hostname}
10.0.0.1\tgateway
10.0.0.5\tdb-master
10.0.0.10\tcache-01
10.0.0.20\tfiles-01

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
""")

        # /etc/passwd
        self._create_file("/etc/passwd", f"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
{self.username}:x:1000:1000:{self.username}:/home/{self.username}:/bin/bash
mysql:x:111:117:MySQL Server,,,:/var/lib/mysql:/bin/false
postgres:x:112:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
""")

        # /etc/shadow (restricted)
        self._create_file("/etc/shadow", f"""root:$6$rounds=656000$rNqPV.bFgH$XhW3J8xV2RqGZH1kPJ.QOA5M3Nv7eK2yHm4J:19401:0:99999:7:::
daemon:*:19401:0:99999:7:::
bin:*:19401:0:99999:7:::
{self.username}:$6$rounds=656000$kL9mQz$aBcDeFgHiJkLmNoPqRsT1234567890:19450:0:99999:7:::
mysql:!:19401:::::
postgres:!:19401:::::
""", permissions="-rw-------")

        # /etc/os-release
        os_name = self.profile.get("os", "Ubuntu")
        version = self.profile.get("version", "22.04.3 LTS")
        self._create_file("/etc/os-release", f"""PRETTY_NAME="{os_name} {version}"
NAME="{os_name}"
VERSION_ID="22.04"
VERSION="{version}"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
""")

        # /etc/ssh/sshd_config (abbreviated)
        self._create_file("/etc/ssh/sshd_config", """# OpenSSH server configuration
Port 22
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
MaxAuthTries 6
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
""")

        self._mkdir("/etc/ssh")

    def _create_home_dir(self):
        """Create realistic home directory."""
        home = f"/home/{self.username}"
        self._mkdir(home, owner=self.username, group=self.username, permissions="drwxr-xr-x")
        self._mkdir(f"{home}/.ssh", owner=self.username, group=self.username, permissions="drwx------")
        self._mkdir(f"{home}/Desktop", owner=self.username, group=self.username)
        self._mkdir(f"{home}/Documents", owner=self.username, group=self.username)
        self._mkdir(f"{home}/Downloads", owner=self.username, group=self.username)

        # .bash_history (canary - tracks what an attacker looks for)
        self._create_file(f"{home}/.bash_history", """cd /var/www/html
sudo systemctl restart nginx
mysql -u root -p'Str0ngP@ss2024!' -e "SHOW DATABASES"
ssh deploy@10.0.0.5
cat /opt/app/.env
sudo tail -f /var/log/auth.log
docker ps
kubectl get pods -n production
aws s3 ls s3://company-backups/
git pull origin main
pip install -r requirements.txt
""", owner=self.username, group=self.username, permissions="-rw-------")

        # .bashrc
        self._create_file(f"{home}/.bashrc", """# ~/.bashrc
export PATH=$PATH:/usr/local/bin
export EDITOR=vim
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi
""", owner=self.username, group=self.username)

        # .ssh/authorized_keys (canary)
        self._create_file(f"{home}/.ssh/authorized_keys",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7... deploy@ci-server\n",
            owner=self.username, group=self.username, permissions="-rw-------")

        # Fake AWS credentials (canary token)
        self._mkdir(f"{home}/.aws", owner=self.username, group=self.username, permissions="drwx------")
        self._create_file(f"{home}/.aws/credentials", """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
""", owner=self.username, group=self.username, permissions="-rw-------")

        # notes.txt (breadcrumb)
        self._create_file(f"{home}/notes.txt", """TODO:
- Update database password (still using old one from migration)
- Fix SSL cert renewal - expires March 15
- Move backup keys to vault (currently in /opt/backups/keys/)
- Ask Sarah about the new VPN config
- DB connection string: postgresql://admin:Pr0dDBp@ss!@10.0.0.5:5432/maindb
""", owner=self.username, group=self.username)

    def _create_var_dirs(self):
        """Create /var subdirectories with realistic content."""
        self._mkdir("/var/www")
        self._mkdir("/var/www/html")
        self._create_file("/var/www/html/index.html",
            "<html><body><h1>Welcome</h1></body></html>\n",
            owner="www-data", group="www-data")

        self._mkdir("/var/log/nginx")
        self._create_file("/var/log/auth.log", "", size=24576)
        self._create_file("/var/log/syslog", "", size=102400)

    def _create_proc_entries(self):
        """Create fake /proc entries."""
        kernel = self.profile.get("kernel", "5.15.0-91-generic")
        hostname = self.profile.get("hostname", "server")

        self._create_file("/proc/version",
            f"Linux version {kernel} ({hostname}) (gcc version 11.4.0) #101-Ubuntu SMP\n")
        self._create_file("/proc/cpuinfo", """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz
stepping\t: 7
cpu MHz\t\t: 2999.998
cache size\t: 36608 KB
physical id\t: 0
siblings\t: 2
core id\t\t: 0
cpu cores\t: 1
bogomips\t: 5999.99
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl
""")
        self._create_file("/proc/meminfo", """MemTotal:        4028440 kB
MemFree:          512340 kB
MemAvailable:    2847200 kB
Buffers:          234112 kB
Cached:          2100748 kB
SwapCached:            0 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
""")
        self._create_file("/proc/loadavg", "0.08 0.12 0.09 1/234 5678\n")

    def _create_opt_dirs(self):
        """Create /opt application directories with breadcrumbs."""
        self._mkdir("/opt/app")
        self._create_file("/opt/app/.env", """# Application Environment
NODE_ENV=production
DATABASE_URL=postgresql://admin:Pr0dDBp@ss!@10.0.0.5:5432/maindb
REDIS_URL=redis://10.0.0.10:6379
SECRET_KEY=canary_secret_4eC39HqLyjWDarjtT1zdp7dc
API_KEY=ak_prod_9f8e7d6c5b4a3210
AWS_BUCKET=company-uploads
""", permissions="-rw-------")

        self._mkdir("/opt/backups")
        self._mkdir("/opt/backups/keys")
        self._create_file("/opt/backups/keys/id_rsa", """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0EXAMPLE_CANARY_KEY_NOT_REAL_0000000000000000000000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END OPENSSH PRIVATE KEY-----
""", permissions="-rw-------")

    # ------------------------------------------------------------------
    # Filesystem operations
    # ------------------------------------------------------------------

    def _mkdir(self, path: str, owner: str = "root", group: str = "root",
               permissions: str = "drwxr-xr-x"):
        """Create a directory in the fake filesystem."""
        parts = PurePosixPath(path).parts
        current = self.root
        for part in parts[1:]:  # skip root "/"
            if part not in current.children:
                current.children[part] = FakeFile(
                    name=part, is_dir=True,
                    owner=owner, group=group,
                    permissions=permissions,
                )
            current = current.children[part]

    def _create_file(self, path: str, content: str = "", size: int = 0,
                     owner: str = "root", group: str = "root",
                     permissions: str = "-rw-r--r--"):
        """Create a file in the fake filesystem."""
        p = PurePosixPath(path)
        parent_path = str(p.parent)
        if parent_path != "/":
            self._mkdir(parent_path)

        parent = self._resolve(str(p.parent))
        if parent and parent.is_dir:
            parent.children[p.name] = FakeFile(
                name=p.name,
                content=content,
                size=size or len(content.encode()) if content else 0,
                owner=owner, group=group,
                permissions=permissions,
            )

    def _resolve(self, path: str) -> Optional[FakeFile]:
        """Resolve a path to a FakeFile."""
        if path == "/":
            return self.root
        parts = PurePosixPath(path).parts
        current = self.root
        for part in parts[1:]:
            if part == "..":
                continue  # simplified - just ignore ..
            if not current.is_dir or part not in current.children:
                return None
            current = current.children[part]
        return current

    def resolve(self, path: str, cwd: str = "/") -> Optional[FakeFile]:
        """Resolve a path (absolute or relative) to a FakeFile."""
        if not path.startswith("/"):
            path = str(PurePosixPath(cwd) / path)
        # Normalize
        path = str(PurePosixPath(path))
        return self._resolve(path)

    def list_dir(self, path: str, cwd: str = "/") -> Optional[List[FakeFile]]:
        """List contents of a directory."""
        node = self.resolve(path, cwd)
        if node and node.is_dir:
            return sorted(node.children.values(), key=lambda f: f.name)
        return None

    def read_file(self, path: str, cwd: str = "/") -> Optional[str]:
        """Read a file's content."""
        node = self.resolve(path, cwd)
        if node and not node.is_dir:
            return node.content
        return None

    def file_exists(self, path: str, cwd: str = "/") -> bool:
        """Check if a path exists."""
        return self.resolve(path, cwd) is not None

    def stat(self, path: str, cwd: str = "/") -> Optional[Dict[str, Any]]:
        """Return stat-like info for a path."""
        node = self.resolve(path, cwd)
        if not node:
            return None
        return {
            "name": node.name,
            "is_dir": node.is_dir,
            "size": node.size,
            "permissions": node.permissions,
            "owner": node.owner,
            "group": node.group,
            "mtime": node.mtime,
        }
