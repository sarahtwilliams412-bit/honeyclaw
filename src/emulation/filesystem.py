#!/usr/bin/env python3
"""
Honeyclaw Fake Filesystem

Generates and maintains a realistic filesystem tree with:
- OS-appropriate directory structure based on profiles
- Fake /etc/passwd, /etc/shadow, /etc/hosts
- Realistic home directories with .bash_history, .ssh/, .aws/
- Canary tokens embedded in config files
- Process list simulation (/proc entries)
- Size, permission, timestamp metadata
- Symlink support
"""

import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Dict, List, Optional


@dataclass
class FileNode:
    """Represents a single file or directory in the fake filesystem."""
    name: str
    is_dir: bool = False
    content: str = ""
    size: int = 0
    permissions: str = "-rw-r--r--"
    owner: str = "root"
    group: str = "root"
    mtime: float = 0.0
    links: int = 1
    symlink_target: Optional[str] = None
    children: Dict[str, "FileNode"] = field(default_factory=dict)

    def __post_init__(self):
        if self.is_dir and not self.permissions.startswith("d"):
            self.permissions = "d" + self.permissions[1:]
        if not self.size and self.content:
            self.size = len(self.content.encode())
        if not self.mtime:
            # Random time in last 90 days
            self.mtime = time.time() - random.randint(0, 90 * 86400)

    @property
    def is_symlink(self) -> bool:
        return self.symlink_target is not None

    def mtime_str(self) -> str:
        """Format mtime like ls -l output."""
        t = time.localtime(self.mtime)
        now = time.localtime()
        if t.tm_year == now.tm_year:
            return time.strftime("%b %d %H:%M", t)
        return time.strftime("%b %d  %Y", t)

    def ls_entry(self) -> str:
        """Generate ls -la style entry."""
        date_str = self.mtime_str()
        link_count = len(self.children) + 2 if self.is_dir else self.links
        size_str = str(self.size) if not self.is_dir else "4096"
        return f"{self.permissions} {link_count:>3} {self.owner:<8} {self.group:<8} {size_str:>8} {date_str} {self.name}"


class FakeFilesystem:
    """
    In-memory filesystem tree that generates realistic directory structures
    based on an OS profile. Supports navigation, listing, reading, canary
    token embedding, and symlinks.
    """

    def __init__(self, profile: Optional[dict] = None, username: str = "user"):
        self._root = FileNode(name="/", is_dir=True, permissions="drwxr-xr-x",
                              links=20, mtime=time.time() - 86400 * 30)
        self._profile = profile or {}
        self.profile = self._profile  # Alias for compatibility
        self.username = username
        self._canary_files: Dict[str, str] = {}
        self._boot_time = time.time() - random.randint(86400, 86400 * 60)
        self._build_base_tree()
        if profile:
            self._apply_profile(profile)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, path: str, cwd: str = "/") -> Optional[FileNode]:
        """Resolve a path to a FileNode, following symlinks once."""
        abs_path = self._abspath(path, cwd)
        node = self._walk(abs_path)
        if node and node.is_symlink:
            node = self._walk(node.symlink_target)
        return node

    def list_dir(self, path: str, cwd: str = "/", show_hidden: bool = False) -> List[FileNode]:
        """List children of a directory."""
        node = self.resolve(path, cwd)
        if not node or not node.is_dir:
            return []
        children = list(node.children.values())
        if not show_hidden:
            children = [c for c in children if not c.name.startswith(".")]
        return sorted(children, key=lambda n: n.name)

    def read_file(self, path: str, cwd: str = "/") -> Optional[str]:
        """Read a file's content. Returns None if not found or is a directory."""
        node = self.resolve(path, cwd)
        if not node or node.is_dir:
            return None
        return node.content

    def stat(self, path: str, cwd: str = "/") -> Optional[FileNode]:
        """Stat a path (resolve without following final symlink)."""
        abs_path = self._abspath(path, cwd)
        return self._walk(abs_path)

    def exists(self, path: str, cwd: str = "/") -> bool:
        return self.resolve(path, cwd) is not None

    def file_exists(self, path: str, cwd: str = "/") -> bool:
        """Alias for exists()."""
        return self.exists(path, cwd)

    def is_dir(self, path: str, cwd: str = "/") -> bool:
        node = self.resolve(path, cwd)
        return node is not None and node.is_dir

    def add_canary(self, path: str, content: str, token_id: str = ""):
        """Add a canary token file at the given absolute path."""
        self._ensure_path(path, content)
        self._canary_files[path] = token_id

    def is_canary(self, path: str, cwd: str = "/") -> bool:
        """Check if accessing this path triggers a canary."""
        abs_path = self._abspath(path, cwd)
        return abs_path in self._canary_files

    def get_canary_id(self, path: str, cwd: str = "/") -> Optional[str]:
        abs_path = self._abspath(path, cwd)
        return self._canary_files.get(abs_path)

    @property
    def boot_time(self) -> float:
        return self._boot_time

    # ------------------------------------------------------------------
    # Tree construction
    # ------------------------------------------------------------------

    def _build_base_tree(self):
        """Build minimum Linux FHS directories."""
        base_dirs = [
            "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib",
            "/usr/local", "/usr/local/bin", "/usr/share",
            "/etc", "/etc/ssh", "/etc/apt", "/etc/default", "/etc/network",
            "/etc/systemd", "/etc/systemd/system", "/etc/cron.d",
            "/var", "/var/log", "/var/lib", "/var/run", "/var/tmp", "/var/cache",
            "/var/www", "/var/www/html",
            "/home", "/root",
            "/tmp", "/dev", "/proc", "/sys", "/opt", "/srv", "/mnt", "/media",
            "/run", "/boot", "/lib", "/lib64",
        ]
        for d in base_dirs:
            self._mkdir(d)

        # /root home dir
        self._mkdir("/root/.ssh", perms="drwx------")
        self._add_file("/root/.bashrc", self._gen_bashrc("root"), owner="root")
        self._add_file("/root/.profile", self._gen_profile(), owner="root")
        self._add_file("/root/.bash_history", self._gen_bash_history(), owner="root",
                        perms="-rw-------")

        # /etc essentials
        self._add_file("/etc/hostname", "server-01\n")
        self._add_file("/etc/hosts", self._gen_hosts())
        self._add_file("/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n")
        self._add_file("/etc/fstab", self._gen_fstab())
        self._add_file("/etc/passwd", self._gen_passwd([]))
        self._add_file("/etc/shadow", self._gen_shadow([]), perms="-rw-r-----", group="shadow")
        self._add_file("/etc/group", self._gen_group([]))
        self._add_file("/etc/os-release", "")
        self._add_file("/etc/ssh/sshd_config", self._gen_sshd_config())

        # /var/log
        self._add_file("/var/log/syslog", self._gen_syslog(), size=random.randint(50000, 200000))
        self._add_file("/var/log/auth.log", self._gen_auth_log(), size=random.randint(10000, 80000))
        self._add_file("/var/log/kern.log", "", size=random.randint(5000, 40000))
        self._add_file("/var/log/dpkg.log", "", size=random.randint(20000, 100000))

        # /var/www
        self._add_file("/var/www/html/index.html",
                       "<html><body><h1>Welcome</h1></body></html>\n",
                       owner="www-data", group="www-data")

        # /tmp
        self._mkdir("/tmp", perms="drwxrwxrwt")
        self._add_file("/tmp/.X0-lock", "1234\n", perms="-r--r--r--")

        # /proc - dynamic entries
        self._build_proc()

        # /opt application dirs with breadcrumbs
        self._build_opt()

    def _build_proc(self):
        """Generate realistic /proc entries."""
        uptime_secs = time.time() - self._boot_time
        idle_secs = uptime_secs * random.uniform(0.85, 0.98)
        self._add_file("/proc/uptime", f"{uptime_secs:.2f} {idle_secs:.2f}\n")
        self._add_file("/proc/version", "")  # filled by profile
        self._add_file("/proc/cpuinfo", self._gen_cpuinfo())
        self._add_file("/proc/meminfo", self._gen_meminfo())
        self._add_file("/proc/loadavg",
                        f"{random.uniform(0.01, 0.3):.2f} "
                        f"{random.uniform(0.05, 0.4):.2f} "
                        f"{random.uniform(0.05, 0.3):.2f} "
                        f"1/{random.randint(80, 200)} "
                        f"{random.randint(1000, 9999)}\n")

        # Fake /proc/1 (init/systemd)
        self._mkdir("/proc/1")
        self._add_file("/proc/1/cmdline", "/sbin/init\x00")
        self._add_file("/proc/1/status", "Name:\tinit\nPid:\t1\nUid:\t0\t0\t0\t0\n")

    def _build_opt(self):
        """Create /opt application directories with breadcrumbs."""
        self._mkdir("/opt/app")
        self._add_file("/opt/app/.env", """# Application Environment
NODE_ENV=production
DATABASE_URL=postgresql://admin:Pr0dDBp@ss!@10.0.0.5:5432/maindb
REDIS_URL=redis://10.0.0.10:6379
SECRET_KEY=canary_secret_4eC39HqLyjWDarjtT1zdp7dc
API_KEY=ak_prod_9f8e7d6c5b4a3210
AWS_BUCKET=company-uploads
""", perms="-rw-------")

        self._mkdir("/opt/backups")
        self._mkdir("/opt/backups/keys")
        self._add_file("/opt/backups/keys/id_rsa", """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0EXAMPLE_CANARY_KEY_NOT_REAL_0000000000000000000000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END OPENSSH PRIVATE KEY-----
""", perms="-rw-------")

    def _apply_profile(self, profile: dict):
        """Apply an OS profile to populate OS-specific files."""
        # Support both key naming conventions
        os_name = profile.get("os_name") or profile.get("os", "Ubuntu")
        os_version = profile.get("os_version") or profile.get("version", "22.04")
        kernel = profile.get("kernel", "5.15.0-91-generic")
        arch = profile.get("arch", "x86_64")

        # /etc/os-release
        os_release = profile.get("os_release", "")
        if not os_release:
            os_release = (
                f'NAME="{os_name}"\n'
                f'VERSION="{os_version}"\n'
                f'ID={os_name.lower().replace(" ", "")}\n'
                f'VERSION_ID="{os_version.split()[0]}"\n'
                f'PRETTY_NAME="{os_name} {os_version}"\n'
            )
        self._update_file("/etc/os-release", os_release)

        # /etc/passwd & shadow & group
        users = profile.get("users", [])
        passwd_lines = self._gen_passwd(users)
        shadow_lines = self._gen_shadow(users)
        group_lines = self._gen_group(users)
        self._update_file("/etc/passwd", passwd_lines)
        self._update_file("/etc/shadow", shadow_lines)
        self._update_file("/etc/group", group_lines)

        # hostname
        hostname = profile.get("hostname", "server-01")
        self._update_file("/etc/hostname", hostname + "\n")
        self._update_file("/etc/hosts", self._gen_hosts(hostname))

        # /proc/version
        proc_version = (
            f"Linux version {kernel} ({os_name.lower().replace(' ', '-')}-builder@build) "
            f"(gcc version 11.4.0) #101-{os_name.split()[0]} SMP "
            f"Tue Nov 14 13:30:08 UTC 2025\n"
        )
        self._update_file("/proc/version", proc_version)

        # home directories for users
        for user in users:
            user_name = user.get("name", "")
            if not user_name or user_name in ("root", "www-data", "daemon", "sshd", "nobody"):
                continue

            home = user.get("home", f"/home/{user_name}")
            if home.startswith("/home/") or home.startswith("/var/"):
                self._mkdir(home, perms="drwxr-xr-x", owner=user_name)
                self._mkdir(home + "/.ssh", perms="drwx------", owner=user_name)
                self._add_file(home + "/.bashrc", self._gen_bashrc(user_name),
                               owner=user_name)
                self._add_file(home + "/.bash_history",
                               self._gen_bash_history(), owner=user_name,
                               perms="-rw-------")
                # Desktop directories for interactive users
                if user.get("shell", "/bin/bash") != "/usr/sbin/nologin":
                    self._mkdir(home + "/Desktop", owner=user_name)
                    self._mkdir(home + "/Documents", owner=user_name)
                    self._mkdir(home + "/Downloads", owner=user_name)

                    # Notes breadcrumb
                    self._add_file(home + "/notes.txt", """TODO:
- Update database password (still using old one from migration)
- Fix SSL cert renewal - expires March 15
- Move backup keys to vault (currently in /opt/backups/keys/)
- Ask Sarah about the new VPN config
- DB connection string: postgresql://admin:Pr0dDBp@ss!@10.0.0.5:5432/maindb
""", owner=user_name)

                # Fake .aws directory for select users
                if user.get("has_aws"):
                    self._mkdir(home + "/.aws", perms="drwx------", owner=user_name)
                    self._add_file(home + "/.aws/credentials",
                                   self._gen_aws_credentials(), owner=user_name,
                                   perms="-rw-------")

        # Extra packages / binaries from profile
        for binary in profile.get("extra_binaries", []):
            self._add_file(f"/usr/bin/{binary}", "", perms="-rwxr-xr-x", size=random.randint(10000, 500000))

    # ------------------------------------------------------------------
    # Content generators
    # ------------------------------------------------------------------

    def _gen_passwd(self, users: list) -> str:
        lines = [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
        ]
        uid = 1000
        for u in users:
            name = u.get("name", "")
            if not name or name in ("root", "www-data", "daemon", "sshd", "nobody"):
                continue
            home = u.get("home", f"/home/{name}")
            shell = u.get("shell", "/bin/bash")
            gecos = u.get("gecos", name)
            user_uid = u.get("uid", uid)
            lines.append(f"{name}:x:{user_uid}:{user_uid}:{gecos}:{home}:{shell}")
            if user_uid >= uid:
                uid = user_uid + 1
        return "\n".join(lines) + "\n"

    def _gen_shadow(self, users: list) -> str:
        lines = [
            "root:$6$rounds=656000$fakesalt$fakehashedpassword:19700:0:99999:7:::",
            "daemon:*:19700:0:99999:7:::",
            "sshd:*:19700:0:99999:7:::",
        ]
        for u in users:
            name = u.get("name", "")
            if name and name not in ("root", "daemon", "sshd"):
                lines.append(f"{name}:$6$rounds=656000$salt${name}hash:19700:0:99999:7:::")
        return "\n".join(lines) + "\n"

    def _gen_group(self, users: list) -> str:
        lines = [
            "root:x:0:",
            "daemon:x:1:",
            "sys:x:3:",
            "adm:x:4:",
            "sudo:x:27:",
            "www-data:x:33:",
            "shadow:x:42:",
            "staff:x:50:",
            "users:x:100:",
            "nogroup:x:65534:",
            "ssh:x:111:",
        ]
        gid = 1000
        for u in users:
            name = u.get("name", "")
            if name and name not in ("root", "www-data", "daemon", "sshd", "nobody"):
                user_gid = u.get("uid", gid)  # Use UID as GID
                lines.append(f"{name}:x:{user_gid}:")
                if user_gid >= gid:
                    gid = user_gid + 1
        return "\n".join(lines) + "\n"

    @staticmethod
    def _gen_hosts(hostname: str = "server-01") -> str:
        return (
            "127.0.0.1\tlocalhost\n"
            f"127.0.1.1\t{hostname}\n"
            "10.0.0.1\tgateway\n"
            "10.0.0.5\tdb-master\n"
            "10.0.0.10\tcache-01\n"
            "10.0.0.20\tfiles-01\n"
            "\n"
            "# The following lines are desirable for IPv6 capable hosts\n"
            "::1     localhost ip6-localhost ip6-loopback\n"
            "fe00::0 ip6-localnet\n"
            "ff00::0 ip6-mcastprefix\n"
            "ff02::1 ip6-allnodes\n"
            "ff02::2 ip6-allrouters\n"
        )

    @staticmethod
    def _gen_fstab() -> str:
        return (
            "# /etc/fstab: static file system information.\n"
            "UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 / ext4 errors=remount-ro 0 1\n"
            "/dev/sda2 none swap sw 0 0\n"
        )

    @staticmethod
    def _gen_sshd_config() -> str:
        return (
            "# OpenSSH Server Configuration\n"
            "Port 22\n"
            "ListenAddress 0.0.0.0\n"
            "Protocol 2\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
            "HostKey /etc/ssh/ssh_host_ed25519_key\n"
            "PermitRootLogin prohibit-password\n"
            "MaxAuthTries 6\n"
            "PubkeyAuthentication yes\n"
            "PasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server\n"
        )

    @staticmethod
    def _gen_bashrc(user: str) -> str:
        return (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "export HISTSIZE=1000\n"
            "export HISTFILESIZE=2000\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
            "alias l='ls -CF'\n"
            f"# User: {user}\n"
        )

    @staticmethod
    def _gen_profile() -> str:
        return (
            "# ~/.profile: executed by the command interpreter for login shells.\n"
            "if [ -n \"$BASH_VERSION\" ]; then\n"
            "    if [ -f \"$HOME/.bashrc\" ]; then\n"
            "        . \"$HOME/.bashrc\"\n"
            "    fi\n"
            "fi\n"
            "PATH=\"$HOME/bin:$HOME/.local/bin:$PATH\"\n"
        )

    @staticmethod
    def _gen_bash_history() -> str:
        commands = [
            "ls -la",
            "cd /var/log",
            "tail -f syslog",
            "systemctl status nginx",
            "df -h",
            "free -m",
            "top",
            "cat /etc/hostname",
            "ip addr show",
            "apt update",
            "systemctl restart sshd",
            "netstat -tlnp",
            "ps aux",
            "uptime",
            "mysql -u root -p'Str0ngP@ss2024!' -e \"SHOW DATABASES\"",
            "ssh deploy@10.0.0.5",
            "cat /opt/app/.env",
            "docker ps",
            "kubectl get pods -n production",
            "aws s3 ls s3://company-backups/",
        ]
        selected = random.sample(commands, min(len(commands), random.randint(8, 15)))
        return "\n".join(selected) + "\n"

    @staticmethod
    def _gen_aws_credentials() -> str:
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        fake_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        return (
            "[default]\n"
            f"aws_access_key_id = {fake_key}\n"
            f"aws_secret_access_key = {fake_secret}\n"
            "region = us-east-1\n"
        )

    @staticmethod
    def _gen_cpuinfo() -> str:
        return (
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\n"
            "stepping\t: 7\n"
            "cpu MHz\t\t: 3000.000\n"
            "cache size\t: 36608 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 2\n"
            "core id\t\t: 0\n"
            "cpu cores\t: 1\n"
            "bogomips\t: 5999.99\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep "
            "mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht "
            "syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon\n"
            "\n"
            "processor\t: 1\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\n"
            "stepping\t: 7\n"
            "cpu MHz\t\t: 3000.000\n"
            "cache size\t: 36608 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 2\n"
            "core id\t\t: 1\n"
            "cpu cores\t: 1\n"
            "bogomips\t: 5999.99\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep "
            "mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht "
            "syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon\n"
        )

    @staticmethod
    def _gen_meminfo() -> str:
        total_kb = 4028416
        free_kb = random.randint(500000, 1500000)
        available_kb = free_kb + random.randint(200000, 800000)
        buffers_kb = random.randint(50000, 200000)
        cached_kb = random.randint(500000, 1500000)
        return (
            f"MemTotal:       {total_kb} kB\n"
            f"MemFree:        {free_kb} kB\n"
            f"MemAvailable:   {available_kb} kB\n"
            f"Buffers:        {buffers_kb} kB\n"
            f"Cached:         {cached_kb} kB\n"
            f"SwapTotal:      2097148 kB\n"
            f"SwapFree:       2097148 kB\n"
        )

    @staticmethod
    def _gen_syslog() -> str:
        return (
            "Feb  6 10:00:01 server-01 CRON[1234]: (root) CMD (test -x /usr/sbin/anacron)\n"
            "Feb  6 10:05:32 server-01 systemd[1]: Started Session 42 of user root.\n"
            "Feb  6 10:17:01 server-01 CRON[1280]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
        )

    @staticmethod
    def _gen_auth_log() -> str:
        return (
            "Feb  6 09:12:33 server-01 sshd[1100]: Accepted password for root from 10.0.0.1 port 52340 ssh2\n"
            "Feb  6 09:12:33 server-01 sshd[1100]: pam_unix(sshd:session): session opened for user root\n"
            "Feb  6 10:05:32 server-01 systemd-logind[500]: New session 42 of user root.\n"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _abspath(self, path: str, cwd: str) -> str:
        """Resolve a path to an absolute path string."""
        if not path:
            return cwd
        p = PurePosixPath(path)
        if not p.is_absolute():
            p = PurePosixPath(cwd) / p
        # Normalize (resolve ..)
        parts = []
        for part in p.parts:
            if part == "/":
                continue
            elif part == "..":
                if parts:
                    parts.pop()
            elif part != ".":
                parts.append(part)
        return "/" + "/".join(parts) if parts else "/"

    def _walk(self, abs_path: str) -> Optional[FileNode]:
        """Walk the tree to find a node at the given absolute path."""
        if abs_path == "/":
            return self._root
        parts = abs_path.strip("/").split("/")
        node = self._root
        for part in parts:
            if not node.is_dir or part not in node.children:
                return None
            node = node.children[part]
        return node

    def _mkdir(self, path: str, perms: str = "drwxr-xr-x", owner: str = "root",
               group: str = "root"):
        """Create a directory (and parents) in the tree."""
        parts = path.strip("/").split("/")
        node = self._root
        for i, part in enumerate(parts):
            is_leaf = (i == len(parts) - 1)
            if part not in node.children:
                node.children[part] = FileNode(
                    name=part, is_dir=True, permissions=perms if is_leaf else "drwxr-xr-x",
                    owner=owner, group=group if is_leaf else "root", links=2,
                    mtime=time.time() - random.randint(3600, 86400 * 90),
                )
            elif is_leaf:
                # Update permissions on existing leaf directory
                node.children[part].permissions = perms
                node.children[part].owner = owner
                node.children[part].group = group
            node = node.children[part]

    def _ensure_parents(self, path: str):
        """Create parent directories without overwriting existing permissions."""
        parts = path.strip("/").split("/")
        node = self._root
        for part in parts:
            if part not in node.children:
                node.children[part] = FileNode(
                    name=part, is_dir=True, permissions="drwxr-xr-x",
                    owner="root", group="root", links=2,
                    mtime=time.time() - random.randint(3600, 86400 * 90),
                )
            node = node.children[part]

    def _add_file(self, path: str, content: str, perms: str = "-rw-r--r--",
                  owner: str = "root", group: str = "root", size: int = 0):
        """Add a file to the tree, creating parent dirs as needed."""
        parts = path.strip("/").split("/")
        name = parts[-1]
        dir_parts = parts[:-1]

        # Ensure parent exists (without overwriting existing dir permissions)
        parent_path = "/" + "/".join(dir_parts) if dir_parts else "/"
        if parent_path != "/":
            self._ensure_parents(parent_path)

        parent = self._walk(parent_path)
        if parent is None:
            return

        file_size = size if size > 0 else len(content.encode("utf-8", errors="replace"))
        parent.children[name] = FileNode(
            name=name, content=content, size=file_size,
            permissions=perms, owner=owner, group=group,
            mtime=time.time() - random.randint(3600, 86400 * 90),
        )

    def _update_file(self, path: str, content: str):
        """Update content of an existing file."""
        node = self._walk(path)
        if node and not node.is_dir:
            node.content = content
            node.size = len(content.encode("utf-8", errors="replace"))

    def _ensure_path(self, path: str, content: str):
        """Ensure a file exists at path with given content (for canaries)."""
        if self._walk(path) is None:
            self._add_file(path, content)
        else:
            self._update_file(path, content)


def load_profile(profile_name: str) -> dict:
    """Load an OS profile JSON from the profiles directory."""
    profiles_dir = os.path.join(os.path.dirname(__file__), "profiles")
    profile_path = os.path.join(profiles_dir, f"{profile_name}.json")
    if not os.path.isfile(profile_path):
        return {}
    with open(profile_path) as f:
        return json.load(f)
