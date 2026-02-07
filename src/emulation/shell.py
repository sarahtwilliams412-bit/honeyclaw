#!/usr/bin/env python3
"""
Honeyclaw Stateful Shell Emulator

Maintains shell state (cwd, env, history, user context) across commands
and provides realistic responses for common Linux commands.

Designed to integrate with the SSH honeypot and AI conversation handler.
"""

import random
import shlex
import time
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

from .filesystem import FakeFilesystem
from .timing import TimingSimulator


class ShellEmulator:
    """
    State-aware shell emulator for honeypot interaction.

    Maintains:
    - Current working directory
    - Environment variables
    - Command history
    - User context (uid, groups)
    """

    def __init__(
        self,
        filesystem: Optional[FakeFilesystem] = None,
        username: str = "user",
        hostname: str = "prod-web-01",
        uid: int = 1000,
        gid: int = 1000,
        groups: Optional[List[str]] = None,
        timing: Optional[TimingSimulator] = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.fs = filesystem or FakeFilesystem(username=username)
        self.username = username
        self.hostname = hostname
        self.uid = uid
        self.gid = gid
        self.groups = groups or [username, "sudo"]
        self.timing = timing or TimingSimulator()
        self.on_event = on_event

        # Shell state
        self.cwd = f"/home/{username}"
        self.history: List[str] = []
        self.env: Dict[str, str] = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": f"/home/{username}",
            "USER": username,
            "LOGNAME": username,
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "PWD": self.cwd,
            "HOSTNAME": hostname,
        }
        self.last_exit_code = 0

        # Built-in command handlers
        self._builtins: Dict[str, Callable] = {
            "ls": self._cmd_ls,
            "cat": self._cmd_cat,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "hostname": self._cmd_hostname,
            "ps": self._cmd_ps,
            "netstat": self._cmd_netstat,
            "ss": self._cmd_netstat,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "echo": self._cmd_echo,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "wc": self._cmd_wc,
            "grep": self._cmd_grep,
            "find": self._cmd_find,
            "which": self._cmd_which,
            "file": self._cmd_file,
            "stat": self._cmd_stat,
            "uptime": self._cmd_uptime,
            "w": self._cmd_w,
            "who": self._cmd_who,
            "last": self._cmd_last,
            "df": self._cmd_df,
            "free": self._cmd_free,
            "mount": self._cmd_mount,
            "history": self._cmd_history,
            "date": self._cmd_date,
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "sudo": self._cmd_sudo,
            "su": self._cmd_su,
            "scp": self._cmd_scp,
            "ssh": self._cmd_ssh,
            "mkdir": self._cmd_mkdir,
            "touch": self._cmd_touch,
            "rm": self._cmd_rm,
            "cp": self._cmd_cp,
            "mv": self._cmd_mv,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, command_line: str) -> Tuple[str, float]:
        """
        Execute a command and return (output, delay_seconds).

        Args:
            command_line: The full command string

        Returns:
            Tuple of (output_string, recommended_delay)
        """
        self.history.append(command_line)
        command_line = command_line.strip()

        if not command_line:
            return "", 0.0

        # Fire event
        self._emit("command", {"command": command_line, "cwd": self.cwd})

        # Handle pipes (simplified: only process last command for output)
        if "|" in command_line:
            parts = command_line.split("|")
            # Execute first command, use its output context
            first_output, _ = self._execute_single(parts[0].strip())
            # For piped commands, return simplified output
            last_cmd = parts[-1].strip()
            if last_cmd.startswith("wc"):
                lines = first_output.count("\n") + (1 if first_output and not first_output.endswith("\n") else 0)
                return f"      {lines}\n", self.timing.command_delay(last_cmd)
            if last_cmd.startswith("grep"):
                try:
                    args = shlex.split(last_cmd)
                    pattern = args[1] if len(args) > 1 else ""
                    matched = [l for l in first_output.split("\n") if pattern.lower() in l.lower()]
                    return "\n".join(matched) + "\n" if matched else "", self.timing.command_delay(last_cmd)
                except Exception:
                    pass
            if last_cmd.startswith("head"):
                lines = first_output.split("\n")[:10]
                return "\n".join(lines) + "\n", self.timing.command_delay(last_cmd)
            if last_cmd.startswith("tail"):
                lines = first_output.split("\n")[-10:]
                return "\n".join(lines) + "\n", self.timing.command_delay(last_cmd)
            return first_output, self.timing.command_delay(command_line)

        # Handle redirects (simplified)
        if ">>" in command_line or ">" in command_line:
            self._emit("file_write", {"command": command_line})
            return "", self.timing.command_delay(command_line)

        return self._execute_single(command_line)

    def get_prompt(self) -> str:
        """Get the current shell prompt."""
        short_cwd = self.cwd
        home = self.env.get("HOME", "")
        if home and short_cwd.startswith(home):
            short_cwd = "~" + short_cwd[len(home):]
        return f"{self.username}@{self.hostname}:{short_cwd}$ "

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------

    def _execute_single(self, command_line: str) -> Tuple[str, float]:
        """Execute a single command (no pipes)."""
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()

        if not parts:
            return "", 0.0

        cmd = parts[0]
        args = parts[1:]

        # Check builtins
        handler = self._builtins.get(cmd)
        if handler:
            try:
                output = handler(args)
                self.last_exit_code = 0
                delay = self.timing.command_delay(cmd)
                return output, delay
            except Exception:
                self.last_exit_code = 1
                return "", 0.0

        # Unknown command
        self.last_exit_code = 127
        return f"bash: {cmd}: command not found\n", 0.05

    # ------------------------------------------------------------------
    # Built-in command handlers
    # ------------------------------------------------------------------

    def _cmd_ls(self, args: List[str]) -> str:
        show_all = "-a" in args or "-la" in args or "-al" in args
        long_format = "-l" in args or "-la" in args or "-al" in args or "-lh" in args
        path_args = [a for a in args if not a.startswith("-")]
        target = path_args[0] if path_args else "."

        if target == ".":
            target = self.cwd

        entries = self.fs.list_dir(target, self.cwd)
        if entries is None:
            return f"ls: cannot access '{target}': No such file or directory\n"

        if not show_all:
            entries = [e for e in entries if not e.name.startswith(".")]

        if long_format:
            lines = [f"total {len(entries) * 4}"]
            if show_all:
                lines.append("drwxr-xr-x  2 {0} {0} 4096 Feb  6 09:00 .".format(self.username))
                lines.append("drwxr-xr-x  3 root root 4096 Feb  5 10:00 ..")
            for e in entries:
                lines.append(e.ls_entry())
            return "\n".join(lines) + "\n"
        else:
            return "  ".join(e.name for e in entries) + "\n" if entries else ""

    def _cmd_cat(self, args: List[str]) -> str:
        path_args = [a for a in args if not a.startswith("-")]
        if not path_args:
            return ""
        output_parts = []
        for path in path_args:
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                output_parts.append(f"cat: {path}: No such file or directory\n")
                self._emit("file_read", {"path": path, "found": False})
            else:
                output_parts.append(content)
                self._emit("file_read", {"path": path, "found": True, "size": len(content)})
        return "".join(output_parts)

    def _cmd_cd(self, args: List[str]) -> str:
        target = args[0] if args else self.env.get("HOME", "/")
        if target == "-":
            target = self.env.get("OLDPWD", self.cwd)
        if not target.startswith("/"):
            target = str(PurePosixPath(self.cwd) / target)
        target = str(PurePosixPath(target))

        node = self.fs.resolve(target, self.cwd)
        if node is None:
            return f"bash: cd: {args[0] if args else target}: No such file or directory\n"
        if not node.is_dir:
            return f"bash: cd: {target}: Not a directory\n"

        self.env["OLDPWD"] = self.cwd
        self.cwd = target
        self.env["PWD"] = self.cwd
        return ""

    def _cmd_pwd(self, args: List[str]) -> str:
        return self.cwd + "\n"

    def _cmd_whoami(self, args: List[str]) -> str:
        return self.username + "\n"

    def _cmd_id(self, args: List[str]) -> str:
        groups_str = ",".join(f"{1000+i}({g})" for i, g in enumerate(self.groups))
        return f"uid={self.uid}({self.username}) gid={self.gid}({self.username}) groups={groups_str}\n"

    def _cmd_uname(self, args: List[str]) -> str:
        kernel = self.fs.profile.get("kernel", "5.15.0-91-generic")
        if "-a" in args:
            return f"Linux {self.hostname} {kernel} #101-Ubuntu SMP x86_64 GNU/Linux\n"
        if "-r" in args:
            return kernel + "\n"
        if "-n" in args:
            return self.hostname + "\n"
        return "Linux\n"

    def _cmd_hostname(self, args: List[str]) -> str:
        return self.hostname + "\n"

    def _cmd_ps(self, args: List[str]) -> str:
        if "aux" in " ".join(args) or "auxf" in " ".join(args):
            return f"""USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 169432 11584 ?        Ss   Jan20   0:03 /sbin/init
root         345  0.0  0.1  72308  5632 ?        Ss   Jan20   0:00 /usr/sbin/sshd -D
root         567  0.0  0.0  13136  3456 ?        Ss   Jan20   0:00 /usr/sbin/cron
www-data     890  0.0  0.3 141876 14720 ?        S    Jan20   0:12 nginx: worker process
mysql       1123  0.1  2.5 1794572 102400 ?      Sl   Jan20   5:34 /usr/sbin/mysqld
{self.username}     {random.randint(2000,9999)}  0.0  0.0   8212  3328 pts/0    Ss   09:12   0:00 -bash
{self.username}     {random.randint(2000,9999)}  0.0  0.0  10616  1536 pts/0    R+   {datetime.now().strftime('%H:%M')}   0:00 ps aux
"""
        return f"""  PID TTY          TIME CMD
 {random.randint(2000,9999)} pts/0    00:00:00 bash
 {random.randint(2000,9999)} pts/0    00:00:00 ps
"""

    def _cmd_netstat(self, args: List[str]) -> str:
        return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
tcp        0     36 10.0.0.25:22            10.0.0.50:54312         ESTABLISHED
tcp6       0      0 :::22                   :::*                    LISTEN
"""

    def _cmd_ifconfig(self, args: List[str]) -> str:
        return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.25  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::42:acff:fe00:19  prefixlen 64  scopeid 0x20<link>
        ether 02:42:0a:00:00:19  txqueuelen 0  (Ethernet)
        RX packets 1284567  bytes 987654321 (941.9 MiB)
        TX packets 876543  bytes 123456789 (117.7 MiB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
"""

    def _cmd_ip(self, args: List[str]) -> str:
        if args and args[0] == "addr":
            return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 10.0.0.25/24 brd 10.0.0.255 scope global eth0
"""
        if args and args[0] == "route":
            return """default via 10.0.0.1 dev eth0
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.25
"""
        return self._cmd_ifconfig(args)

    def _cmd_env(self, args: List[str]) -> str:
        return "\n".join(f"{k}={v}" for k, v in sorted(self.env.items())) + "\n"

    def _cmd_export(self, args: List[str]) -> str:
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.env[key] = val
        return ""

    def _cmd_echo(self, args: List[str]) -> str:
        text = " ".join(args)
        # Handle $VAR expansion
        for key, val in self.env.items():
            text = text.replace(f"${key}", val).replace(f"${{{key}}}", val)
        return text + "\n"

    def _cmd_head(self, args: List[str]) -> str:
        n = 10
        path = None
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                n = int(args[i + 1])
            elif not a.startswith("-"):
                path = a
        if not path:
            return ""
        content = self.fs.read_file(path, self.cwd)
        if content is None:
            return f"head: cannot open '{path}' for reading: No such file or directory\n"
        lines = content.split("\n")[:n]
        return "\n".join(lines) + "\n"

    def _cmd_tail(self, args: List[str]) -> str:
        n = 10
        path = None
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                n = int(args[i + 1])
            elif not a.startswith("-"):
                path = a
        if not path:
            return ""
        content = self.fs.read_file(path, self.cwd)
        if content is None:
            return f"tail: cannot open '{path}' for reading: No such file or directory\n"
        lines = content.split("\n")[-n:]
        return "\n".join(lines) + "\n"

    def _cmd_wc(self, args: List[str]) -> str:
        path_args = [a for a in args if not a.startswith("-")]
        if not path_args:
            return ""
        path = path_args[0]
        content = self.fs.read_file(path, self.cwd)
        if content is None:
            return f"wc: {path}: No such file or directory\n"
        lines = content.count("\n")
        words = len(content.split())
        chars = len(content)
        return f"  {lines}   {words}  {chars} {path}\n"

    def _cmd_grep(self, args: List[str]) -> str:
        non_flag = [a for a in args if not a.startswith("-")]
        if len(non_flag) < 2:
            return ""
        pattern = non_flag[0].lower()
        path = non_flag[1]
        content = self.fs.read_file(path, self.cwd)
        if content is None:
            return f"grep: {path}: No such file or directory\n"
        matches = [l for l in content.split("\n") if pattern in l.lower()]
        return "\n".join(matches) + "\n" if matches else ""

    def _cmd_find(self, args: List[str]) -> str:
        # Simplified find
        self._emit("recon", {"command": "find", "args": args})
        target = args[0] if args and not args[0].startswith("-") else "."
        return f"{target}\n"

    def _cmd_which(self, args: List[str]) -> str:
        common = {
            "python3": "/usr/bin/python3",
            "python": "/usr/bin/python3",
            "node": "/usr/bin/node",
            "git": "/usr/bin/git",
            "vim": "/usr/bin/vim",
            "nano": "/usr/bin/nano",
            "gcc": "/usr/bin/gcc",
            "make": "/usr/bin/make",
            "docker": "/usr/bin/docker",
            "kubectl": "/usr/local/bin/kubectl",
            "aws": "/usr/local/bin/aws",
            "ssh": "/usr/bin/ssh",
            "scp": "/usr/bin/scp",
            "wget": "/usr/bin/wget",
            "curl": "/usr/bin/curl",
            "mysql": "/usr/bin/mysql",
            "psql": "/usr/bin/psql",
        }
        results = []
        for arg in args:
            if arg in common:
                results.append(common[arg])
            else:
                results.append(f"which: no {arg} in ({self.env.get('PATH', '')})")
        return "\n".join(results) + "\n" if results else ""

    def _cmd_file(self, args: List[str]) -> str:
        path_args = [a for a in args if not a.startswith("-")]
        if not path_args:
            return ""
        path = path_args[0]
        node = self.fs.resolve(path, self.cwd)
        if node is None:
            return f"{path}: cannot open (No such file or directory)\n"
        if node.is_dir:
            return f"{path}: directory\n"
        if node.name.endswith(".py"):
            return f"{path}: Python script, ASCII text executable\n"
        if node.name.endswith(".sh"):
            return f"{path}: Bourne-Again shell script, ASCII text executable\n"
        return f"{path}: ASCII text\n"

    def _cmd_stat(self, args: List[str]) -> str:
        path_args = [a for a in args if not a.startswith("-")]
        if not path_args:
            return ""
        path = path_args[0]
        info = self.fs.stat(path, self.cwd)
        if not info:
            return f"stat: cannot stat '{path}': No such file or directory\n"
        dt = datetime.fromtimestamp(info["mtime"])
        return f"""  File: {info['name']}
  Size: {info['size']}\tBlocks: 8\tIO Block: 4096\t{'directory' if info['is_dir'] else 'regular file'}
Access: ({info['permissions']})\tUid: ({self.uid}/{info['owner']})\tGid: ({self.gid}/{info['group']})
Modify: {dt.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}
Change: {dt.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}
"""

    def _cmd_uptime(self, args: List[str]) -> str:
        now = datetime.now()
        days = random.randint(20, 90)
        users = random.randint(1, 3)
        return f" {now.strftime('%H:%M:%S')} up {days} days,  3:21,  {users} users,  load average: 0.08, 0.12, 0.09\n"

    def _cmd_w(self, args: List[str]) -> str:
        now = datetime.now()
        return f""" {now.strftime('%H:%M:%S')} up 47 days,  3:21,  2 users,  load average: 0.08, 0.12, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{self.username:<8} pts/0    10.0.0.50        09:12    0.00s  0.03s  0.00s w
root     pts/1    10.0.0.1         08:45    2:15   0.01s  0.01s -bash
"""

    def _cmd_who(self, args: List[str]) -> str:
        return f"""{self.username}  pts/0        2026-02-06 09:12 (10.0.0.50)
root     pts/1        2026-02-06 08:45 (10.0.0.1)
"""

    def _cmd_last(self, args: List[str]) -> str:
        return f"""{self.username}  pts/0    10.0.0.50        Thu Feb  6 09:12   still logged in
root     pts/1    10.0.0.1         Thu Feb  6 08:45   still logged in
{self.username}  pts/0    10.0.0.50        Wed Feb  5 14:20 - 18:30  (04:10)
reboot   system boot  5.15.0-91-generic Thu Jan 20 10:00   still running
"""

    def _cmd_df(self, args: List[str]) -> str:
        return """Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       41284928 8234567  31005432  22% /
tmpfs            2014220       0   2014220   0% /dev/shm
/dev/sda2       10240000 3456789   6783211  34% /var
"""

    def _cmd_free(self, args: List[str]) -> str:
        return """               total        used        free      shared  buff/cache   available
Mem:         4028440     1181240      512340       45678     2334860     2847200
Swap:        2097148           0     2097148
"""

    def _cmd_mount(self, args: List[str]) -> str:
        return """/dev/sda1 on / type ext4 (rw,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run type tmpfs (rw,nosuid,nodev,size=803688k,mode=755)
"""

    def _cmd_history(self, args: List[str]) -> str:
        lines = []
        for i, cmd in enumerate(self.history[-20:], 1):
            lines.append(f"  {i:>4}  {cmd}")
        return "\n".join(lines) + "\n" if lines else ""

    def _cmd_date(self, args: List[str]) -> str:
        return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"

    def _cmd_wget(self, args: List[str]) -> str:
        url = None
        for a in args:
            if a.startswith("http://") or a.startswith("https://"):
                url = a
                break
            if not a.startswith("-"):
                url = a

        self._emit("download_attempt", {"command": "wget", "url": url or "unknown"})

        if url:
            filename = url.split("/")[-1] or "index.html"
            return f"""--2026-02-06 14:23:05--  {url}
Resolving {url.split('/')[2]}... failed: Name or service not known.
wget: unable to resolve host address '{url.split('/')[2]}'
"""
        return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n"

    def _cmd_curl(self, args: List[str]) -> str:
        url = None
        for a in args:
            if a.startswith("http://") or a.startswith("https://"):
                url = a
                break
            if not a.startswith("-"):
                url = a

        self._emit("download_attempt", {"command": "curl", "url": url or "unknown"})

        if url:
            return f"curl: (6) Could not resolve host: {url.split('/')[2] if '/' in url else url}\n"
        return "curl: try 'curl --help' for more information\n"

    def _cmd_sudo(self, args: List[str]) -> str:
        self._emit("privilege_escalation", {"command": "sudo " + " ".join(args)})
        if not args:
            return "usage: sudo [-h] command\n"
        # Execute the command as if sudo worked
        output, delay = self._execute_single(" ".join(args))
        return output

    def _cmd_su(self, args: List[str]) -> str:
        self._emit("privilege_escalation", {"command": "su " + " ".join(args)})
        return "Password: \nsu: Authentication failure\n"

    def _cmd_scp(self, args: List[str]) -> str:
        self._emit("lateral_movement", {"command": "scp " + " ".join(args)})
        return "ssh: connect to host 10.0.0.5 port 22: Connection timed out\n"

    def _cmd_ssh(self, args: List[str]) -> str:
        self._emit("lateral_movement", {"command": "ssh " + " ".join(args)})
        target = args[-1] if args else "unknown"
        return f"ssh: connect to host {target} port 22: Connection timed out\n"

    def _cmd_mkdir(self, args: List[str]) -> str:
        return ""  # Silently succeed

    def _cmd_touch(self, args: List[str]) -> str:
        return ""  # Silently succeed

    def _cmd_rm(self, args: List[str]) -> str:
        self._emit("file_delete", {"command": "rm " + " ".join(args)})
        return ""

    def _cmd_cp(self, args: List[str]) -> str:
        return ""

    def _cmd_mv(self, args: List[str]) -> str:
        return ""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, data: Dict[str, Any]):
        """Emit an event for logging/alerting."""
        if self.on_event:
            data["username"] = self.username
            data["timestamp"] = time.time()
            try:
                self.on_event(event_type, data)
            except Exception:
                pass
