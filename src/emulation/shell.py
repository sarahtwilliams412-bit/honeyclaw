"""
State-Aware Shell Emulator

Maintains CWD, environment variables, command history, and user context.
Provides built-in handlers for common Linux commands that return realistic
output from the FakeFilesystem.
"""

import random
import re
import shlex
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from src.emulation.filesystem import FakeFilesystem


class ShellEmulator:
    """
    Interactive shell emulator backed by a FakeFilesystem. Maintains session
    state (cwd, env, history) and dispatches commands to built-in handlers.
    """

    def __init__(
        self,
        filesystem: FakeFilesystem,
        username: str = "root",
        hostname: str = "server-01",
        uid: int = 0,
        gid: int = 0,
        groups: Optional[List[str]] = None,
        home: str = "/root",
        on_command: Optional[Callable] = None,
        on_canary: Optional[Callable] = None,
    ):
        self.fs = filesystem
        self.username = username
        self.hostname = hostname
        self.uid = uid
        self.gid = gid
        self.groups = groups or (["root"] if uid == 0 else [username])
        self.home = home
        self.cwd = home if filesystem.is_dir(home) else "/"

        self.env: Dict[str, str] = {
            "HOME": home,
            "USER": username,
            "LOGNAME": username,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "PWD": self.cwd,
            "HOSTNAME": hostname,
        }

        self.history: List[str] = []
        self.last_exit_code = 0
        self._on_command = on_command
        self._on_canary = on_canary

        # Built-in command registry
        self._builtins: Dict[str, Callable] = {
            "ls": self._cmd_ls,
            "dir": self._cmd_ls,
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
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "sudo": self._cmd_sudo,
            "su": self._cmd_su,
            "scp": self._cmd_scp,
            "ssh": self._cmd_ssh,
            "echo": self._cmd_echo,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "set": self._cmd_env,
            "printenv": self._cmd_env,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "grep": self._cmd_grep,
            "find": self._cmd_find,
            "wc": self._cmd_wc,
            "which": self._cmd_which,
            "type": self._cmd_type,
            "file": self._cmd_file,
            "stat": self._cmd_stat,
            "df": self._cmd_df,
            "free": self._cmd_free,
            "uptime": self._cmd_uptime,
            "w": self._cmd_w,
            "last": self._cmd_last,
            "history": self._cmd_history,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "mount": self._cmd_mount,
            "date": self._cmd_date,
            "touch": self._cmd_touch,
            "mkdir": self._cmd_mkdir_cmd,
            "rm": self._cmd_rm,
            "cp": self._cmd_cp,
            "mv": self._cmd_mv,
            "chmod": self._cmd_chmod,
            "chown": self._cmd_chown,
            "systemctl": self._cmd_systemctl,
            "service": self._cmd_service,
            "dpkg": self._cmd_dpkg,
            "apt": self._cmd_apt,
            "yum": self._cmd_yum,
            "pip": self._cmd_pip,
            "python": self._cmd_python,
            "python3": self._cmd_python,
            "crontab": self._cmd_crontab,
        }

    @property
    def prompt(self) -> str:
        """Generate the shell prompt."""
        if self.uid == 0:
            suffix = "#"
        else:
            suffix = "$"
        # Shorten home dir to ~
        display_cwd = self.cwd
        if display_cwd == self.home:
            display_cwd = "~"
        elif display_cwd.startswith(self.home + "/"):
            display_cwd = "~" + display_cwd[len(self.home):]
        return f"{self.username}@{self.hostname}:{display_cwd}{suffix} "

    def execute(self, line: str) -> Tuple[str, int]:
        """
        Execute a command line. Returns (output, exit_code).
        Handles pipes at a basic level by passing output through.
        """
        line = line.strip()
        if not line:
            return "", 0

        self.history.append(line)

        # Callback for command logging
        if self._on_command:
            self._on_command(line, self.cwd, self.username)

        # Handle pipes (basic: run each command, feed output forward)
        if "|" in line:
            return self._handle_pipe(line)

        # Handle output redirection (just swallow it)
        redir_target = None
        for redir in [" >> ", " > ", " 2>&1", " 2>/dev/null"]:
            if redir in line:
                line = line.split(redir)[0].strip()
                break

        # Handle command chaining with ; or &&
        if " && " in line:
            parts = line.split(" && ")
            full_output = []
            for part in parts:
                output, code = self.execute(part.strip())
                full_output.append(output)
                if code != 0:
                    return "\n".join(filter(None, full_output)), code
            return "\n".join(filter(None, full_output)), 0

        if " ; " in line or line.endswith(";"):
            parts = re.split(r"\s*;\s*", line)
            full_output = []
            last_code = 0
            for part in parts:
                part = part.strip()
                if part:
                    output, last_code = self.execute(part)
                    full_output.append(output)
            return "\n".join(filter(None, full_output)), last_code

        # Expand environment variables
        line = self._expand_vars(line)

        # Parse command and args
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()

        if not tokens:
            return "", 0

        cmd = tokens[0]
        args = tokens[1:]

        # Dispatch to built-in handler
        handler = self._builtins.get(cmd)
        if handler:
            try:
                output, code = handler(args)
                self.last_exit_code = code
                return output, code
            except Exception:
                self.last_exit_code = 1
                return f"bash: {cmd}: unexpected error", 1

        # Unknown command
        self.last_exit_code = 127
        return f"bash: {cmd}: command not found", 127

    # ------------------------------------------------------------------
    # Pipe handling
    # ------------------------------------------------------------------

    def _handle_pipe(self, line: str) -> Tuple[str, int]:
        """Basic pipe: run each segment, pass stdout text as stdin to the next."""
        segments = [s.strip() for s in line.split("|")]
        current_output = ""
        last_code = 0
        for i, seg in enumerate(segments):
            if not seg:
                continue
            if i == 0:
                output, last_code = self.execute(seg)
                current_output = output
            else:
                output, last_code = self._execute_with_stdin(seg, current_output)
                current_output = output
        return current_output, last_code

    def _execute_with_stdin(self, line: str, stdin_text: str) -> Tuple[str, int]:
        """Execute a command with piped stdin text."""
        line = self._expand_vars(line.strip())
        try:
            tokens = shlex.split(line)
        except ValueError:
            tokens = line.split()
        if not tokens:
            return stdin_text, 0

        cmd = tokens[0]
        args = tokens[1:]

        # For pipe-aware commands, filter stdin_text
        if cmd == "grep":
            return self._pipe_grep(args, stdin_text)
        if cmd == "head":
            return self._pipe_head(args, stdin_text)
        if cmd == "tail":
            return self._pipe_tail(args, stdin_text)
        if cmd == "wc":
            return self._pipe_wc(args, stdin_text)
        if cmd == "sort":
            lines = stdin_text.split("\n")
            return "\n".join(sorted(lines)), 0

        # For other commands, just run normally (ignore stdin)
        handler = self._builtins.get(cmd)
        if handler:
            return handler(args)
        return f"bash: {cmd}: command not found", 127

    def _pipe_grep(self, args: List[str], stdin_text: str) -> Tuple[str, int]:
        if not args:
            return "Usage: grep [OPTION]... PATTERN [FILE]...", 2
        pattern = args[0]
        matches = [line for line in stdin_text.split("\n") if pattern in line]
        if matches:
            return "\n".join(matches), 0
        return "", 1

    def _pipe_head(self, args: List[str], stdin_text: str) -> Tuple[str, int]:
        n = 10
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
        lines = stdin_text.split("\n")[:n]
        return "\n".join(lines), 0

    def _pipe_tail(self, args: List[str], stdin_text: str) -> Tuple[str, int]:
        n = 10
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
        lines = stdin_text.rstrip("\n").split("\n")[-n:]
        return "\n".join(lines), 0

    def _pipe_wc(self, args: List[str], stdin_text: str) -> Tuple[str, int]:
        lines = stdin_text.count("\n")
        words = len(stdin_text.split())
        chars = len(stdin_text)
        return f"  {lines}  {words} {chars}", 0

    # ------------------------------------------------------------------
    # Variable expansion
    # ------------------------------------------------------------------

    def _expand_vars(self, line: str) -> str:
        """Expand $VAR and ${VAR} references."""
        def replacer(match):
            var_name = match.group(1) or match.group(2)
            if var_name == "?":
                return str(self.last_exit_code)
            return self.env.get(var_name, "")
        return re.sub(r'\$\{(\w+)\}|\$(\w+|\?)', replacer, line)

    # ------------------------------------------------------------------
    # Built-in command handlers
    # ------------------------------------------------------------------

    def _cmd_ls(self, args: List[str]) -> Tuple[str, int]:
        show_all = False
        long_format = False
        targets = []
        for a in args:
            if a.startswith("-"):
                if "a" in a:
                    show_all = True
                if "l" in a:
                    long_format = True
            else:
                targets.append(a)
        if not targets:
            targets = ["."]

        all_output = []
        for target in targets:
            path = target if target != "." else self.cwd
            node = self.fs.resolve(path, self.cwd)
            if node is None:
                all_output.append(f"ls: cannot access '{target}': No such file or directory")
                continue

            if not node.is_dir:
                if long_format:
                    all_output.append(self._ls_long_line(node))
                else:
                    all_output.append(node.name)
                continue

            children = self.fs.list_dir(path, self.cwd, show_hidden=show_all)
            if len(targets) > 1:
                all_output.append(f"{target}:")

            if long_format:
                total = sum(max(c.size // 1024, 1) for c in children)
                all_output.append(f"total {total}")
                for child in children:
                    all_output.append(self._ls_long_line(child))
            else:
                names = [c.name for c in children]
                all_output.append("  ".join(names))

        return "\n".join(all_output), 0

    def _ls_long_line(self, node) -> str:
        return (
            f"{node.permissions} {node.links:>2} {node.owner:<8} {node.group:<8} "
            f"{node.size:>8} {node.mtime_str()} {node.name}"
        )

    def _cmd_cat(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "", 0
        outputs = []
        code = 0
        for path in args:
            if path.startswith("-"):
                continue
            # Check canary
            if self.fs.is_canary(path, self.cwd):
                if self._on_canary:
                    self._on_canary(path, self.fs.get_canary_id(path, self.cwd))
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                node = self.fs.resolve(path, self.cwd)
                if node and node.is_dir:
                    outputs.append(f"cat: {path}: Is a directory")
                else:
                    outputs.append(f"cat: {path}: No such file or directory")
                code = 1
            else:
                outputs.append(content.rstrip("\n"))
        return "\n".join(outputs), code

    def _cmd_cd(self, args: List[str]) -> Tuple[str, int]:
        target = args[0] if args else self.home
        if target == "-":
            target = self.env.get("OLDPWD", self.cwd)
        if target == "~" or target.startswith("~/"):
            target = self.home + target[1:]

        if not self.fs.is_dir(target, self.cwd):
            if self.fs.exists(target, self.cwd):
                return f"bash: cd: {target}: Not a directory", 1
            return f"bash: cd: {target}: No such file or directory", 1

        old = self.cwd
        abs_path = self.fs._abspath(target, self.cwd)
        self.cwd = abs_path
        self.env["OLDPWD"] = old
        self.env["PWD"] = abs_path
        return "", 0

    def _cmd_pwd(self, args: List[str]) -> Tuple[str, int]:
        return self.cwd, 0

    def _cmd_whoami(self, args: List[str]) -> Tuple[str, int]:
        return self.username, 0

    def _cmd_id(self, args: List[str]) -> Tuple[str, int]:
        groups_str = ",".join(
            f"{self.gid}({g})" for g in self.groups
        )
        return f"uid={self.uid}({self.username}) gid={self.gid}({self.groups[0]}) groups={groups_str}", 0

    def _cmd_uname(self, args: List[str]) -> Tuple[str, int]:
        kernel_release = "5.15.0-91-generic"
        machine = "x86_64"
        proc_version = self.fs.read_file("/proc/version")
        if proc_version and "version" in proc_version.lower():
            parts = proc_version.split()
            if len(parts) > 2:
                kernel_release = parts[2]

        if not args or args == ["-s"]:
            return "Linux", 0
        if "-a" in args:
            return (
                f"Linux {self.hostname} {kernel_release} "
                f"#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2025 "
                f"{machine} {machine} {machine} GNU/Linux"
            ), 0
        if "-r" in args:
            return kernel_release, 0
        if "-n" in args:
            return self.hostname, 0
        if "-m" in args:
            return machine, 0
        return "Linux", 0

    def _cmd_hostname(self, args: List[str]) -> Tuple[str, int]:
        return self.hostname, 0

    def _cmd_ps(self, args: List[str]) -> Tuple[str, int]:
        show_all = any("a" in a or "e" in a for a in args if a.startswith("-"))
        if show_all or (args and args[0] == "aux"):
            header = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
            procs = [
                "root           1  0.0  0.2 167892 11464 ?        Ss   Jan06   0:12 /sbin/init",
                "root           2  0.0  0.0      0     0 ?        S    Jan06   0:00 [kthreadd]",
                "root         380  0.0  0.3  47524 14208 ?        Ss   Jan06   0:02 /lib/systemd/systemd-journald",
                "root         412  0.0  0.1  21960  5680 ?        Ss   Jan06   0:01 /lib/systemd/systemd-udevd",
                "systemd+     580  0.0  0.1  24272  7308 ?        Ss   Jan06   0:03 /lib/systemd/systemd-resolved",
                "root         650  0.0  0.1  15420  6936 ?        Ss   Jan06   0:00 sshd: /usr/sbin/sshd -D",
                "root         662  0.0  0.0   6076  1708 ?        Ss   Jan06   0:00 /usr/sbin/cron -f",
                "syslog       670  0.0  0.1 224344  4576 ?        Ssl  Jan06   0:05 /usr/sbin/rsyslogd -n",
                f"root       {random.randint(1200, 9999)}  0.0  0.1  16852  7408 ?        Ss   10:12   0:00 sshd: {self.username} [priv]",
                f"{self.username:<9}{random.randint(1200, 9999)}  0.0  0.1  17132  7680 ?        S    10:12   0:00 sshd: {self.username}@pts/0",
                f"{self.username:<9}{random.randint(1200, 9999)}  0.0  0.0   8536  5192 pts/0    Ss   10:12   0:00 -bash",
                f"{self.username:<9}{random.randint(1200, 9999)}  0.0  0.0  10072  3304 pts/0    R+   {datetime.now().strftime('%H:%M')}   0:00 ps aux",
            ]
            return header + "\n" + "\n".join(procs), 0
        else:
            header = "    PID TTY          TIME CMD"
            procs = [
                f"  {random.randint(1200, 9999)} pts/0    00:00:00 bash",
                f"  {random.randint(1200, 9999)} pts/0    00:00:00 ps",
            ]
            return header + "\n" + "\n".join(procs), 0

    def _cmd_netstat(self, args: List[str]) -> Tuple[str, int]:
        header = "Proto Recv-Q Send-Q Local Address           Foreign Address         State"
        connections = [
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN",
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN",
            f"tcp        0    288 10.0.0.5:22             {random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}:{random.randint(30000,65535)}         ESTABLISHED",
            "udp        0      0 127.0.0.53:53           0.0.0.0:*",
        ]
        if any("l" in a for a in args if a.startswith("-")):
            connections = [c for c in connections if "LISTEN" in c or "udp" in c.lower()]
        return header + "\n" + "\n".join(connections), 0

    def _cmd_wget(self, args: List[str]) -> Tuple[str, int]:
        url = None
        for a in args:
            if not a.startswith("-"):
                url = a
                break
        if not url:
            return "wget: missing URL\nUsage: wget [OPTION]... [URL]...", 1
        filename = url.rstrip("/").split("/")[-1] or "index.html"
        return (
            f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
            f"Resolving {url.split('/')[2]}... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{url.split('/')[2]}'"
        ), 4

    def _cmd_curl(self, args: List[str]) -> Tuple[str, int]:
        url = None
        for a in args:
            if not a.startswith("-"):
                url = a
                break
        if not url:
            return "curl: try 'curl --help' for more information", 2
        host = url.split("/")[2] if "/" in url and len(url.split("/")) > 2 else url
        return f"curl: (6) Could not resolve host: {host}", 6

    def _cmd_sudo(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "usage: sudo [-h] command", 1
        if self.uid == 0:
            return self.execute(" ".join(args))
        # Simulate sudo for non-root
        return self.execute(" ".join(args))

    def _cmd_su(self, args: List[str]) -> Tuple[str, int]:
        return "su: Authentication failure", 1

    def _cmd_scp(self, args: List[str]) -> Tuple[str, int]:
        target = args[-1] if args else ""
        return f"ssh: connect to host {target.split(':')[0]} port 22: Network is unreachable", 1

    def _cmd_ssh(self, args: List[str]) -> Tuple[str, int]:
        host = ""
        for a in args:
            if not a.startswith("-"):
                host = a
                break
        if not host:
            return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] destination", 255
        return f"ssh: connect to host {host} port 22: Network is unreachable", 255

    def _cmd_echo(self, args: List[str]) -> Tuple[str, int]:
        return " ".join(args), 0

    def _cmd_env(self, args: List[str]) -> Tuple[str, int]:
        lines = [f"{k}={v}" for k, v in sorted(self.env.items())]
        return "\n".join(lines), 0

    def _cmd_export(self, args: List[str]) -> Tuple[str, int]:
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.env[key] = val
        return "", 0

    def _cmd_head(self, args: List[str]) -> Tuple[str, int]:
        n = 10
        paths = []
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            elif args[i].startswith("-"):
                i += 1
            else:
                paths.append(args[i])
                i += 1
        if not paths:
            return "", 0
        outputs = []
        for path in paths:
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                outputs.append(f"head: cannot open '{path}' for reading: No such file or directory")
            else:
                lines = content.split("\n")[:n]
                outputs.append("\n".join(lines))
        return "\n".join(outputs), 0

    def _cmd_tail(self, args: List[str]) -> Tuple[str, int]:
        n = 10
        paths = []
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            elif args[i].startswith("-"):
                i += 1
            else:
                paths.append(args[i])
                i += 1
        if not paths:
            return "", 0
        outputs = []
        for path in paths:
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                outputs.append(f"tail: cannot open '{path}' for reading: No such file or directory")
            else:
                lines = content.rstrip("\n").split("\n")
                outputs.append("\n".join(lines[-n:]))
        return "\n".join(outputs), 0

    def _cmd_grep(self, args: List[str]) -> Tuple[str, int]:
        if len(args) < 2:
            return "Usage: grep [OPTION]... PATTERN [FILE]...", 2
        pattern = args[0]
        files = [a for a in args[1:] if not a.startswith("-")]
        if not files:
            return "", 1
        outputs = []
        found = False
        for path in files:
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                outputs.append(f"grep: {path}: No such file or directory")
                continue
            for line in content.split("\n"):
                if pattern in line:
                    prefix = f"{path}:" if len(files) > 1 else ""
                    outputs.append(f"{prefix}{line}")
                    found = True
        return "\n".join(outputs), (0 if found else 1)

    def _cmd_find(self, args: List[str]) -> Tuple[str, int]:
        search_path = "."
        name_pat = None
        i = 0
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                name_pat = args[i + 1]
                i += 2
            elif not args[i].startswith("-"):
                search_path = args[i]
                i += 1
            else:
                i += 1

        results = []
        self._find_recursive(search_path, self.cwd, name_pat, results, depth=0)
        return "\n".join(results) if results else "", 0

    def _find_recursive(self, path: str, cwd: str, name_pat: Optional[str],
                        results: list, depth: int):
        if depth > 5:
            return
        node = self.fs.resolve(path, cwd)
        if not node:
            return
        abs_path = self.fs._abspath(path, cwd)
        if name_pat is None or self._fnmatch(node.name, name_pat):
            results.append(abs_path)
        if node.is_dir:
            for child in node.children.values():
                child_path = abs_path.rstrip("/") + "/" + child.name
                self._find_recursive(child_path, "/", name_pat, results, depth + 1)

    @staticmethod
    def _fnmatch(name: str, pattern: str) -> bool:
        """Simple fnmatch: supports * and ?"""
        regex = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
        return bool(re.fullmatch(regex, name))

    def _cmd_wc(self, args: List[str]) -> Tuple[str, int]:
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            return "", 0
        outputs = []
        for path in paths:
            content = self.fs.read_file(path, self.cwd)
            if content is None:
                outputs.append(f"wc: {path}: No such file or directory")
            else:
                lines = content.count("\n")
                words = len(content.split())
                chars = len(content)
                outputs.append(f"  {lines}  {words} {chars} {path}")
        return "\n".join(outputs), 0

    def _cmd_which(self, args: List[str]) -> Tuple[str, int]:
        known_binaries = {
            "bash": "/usr/bin/bash", "sh": "/usr/bin/sh", "ls": "/usr/bin/ls",
            "cat": "/usr/bin/cat", "grep": "/usr/bin/grep", "find": "/usr/bin/find",
            "python3": "/usr/bin/python3", "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
            "wget": "/usr/bin/wget", "curl": "/usr/bin/curl", "sudo": "/usr/bin/sudo",
            "systemctl": "/usr/bin/systemctl", "journalctl": "/usr/bin/journalctl",
            "ip": "/usr/sbin/ip", "netstat": "/usr/bin/netstat", "ss": "/usr/sbin/ss",
            "ps": "/usr/bin/ps", "top": "/usr/bin/top", "htop": "/usr/bin/htop",
            "nano": "/usr/bin/nano", "vi": "/usr/bin/vi", "vim": "/usr/bin/vim",
            "apt": "/usr/bin/apt", "dpkg": "/usr/bin/dpkg",
        }
        if not args:
            return "", 1
        outputs = []
        code = 0
        for cmd in args:
            if cmd in known_binaries:
                outputs.append(known_binaries[cmd])
            else:
                outputs.append(f"{cmd} not found")
                code = 1
        return "\n".join(outputs), code

    def _cmd_type(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "", 1
        cmd = args[0]
        if cmd in self._builtins:
            return f"{cmd} is a shell builtin", 0
        return f"bash: type: {cmd}: not found", 1

    def _cmd_file(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "Usage: file [FILE]...", 1
        outputs = []
        for path in args:
            if path.startswith("-"):
                continue
            node = self.fs.resolve(path, self.cwd)
            if node is None:
                outputs.append(f"{path}: cannot open (No such file or directory)")
            elif node.is_dir:
                outputs.append(f"{path}: directory")
            elif path.endswith((".py", ".sh", ".bash")):
                outputs.append(f"{path}: ASCII text")
            elif path.endswith((".so", ".o")):
                outputs.append(f"{path}: ELF 64-bit LSB shared object, x86-64")
            else:
                outputs.append(f"{path}: ASCII text")
        return "\n".join(outputs), 0

    def _cmd_stat(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "stat: missing operand", 1
        outputs = []
        for path in args:
            if path.startswith("-"):
                continue
            node = self.fs.resolve(path, self.cwd)
            if node is None:
                outputs.append(f"stat: cannot stat '{path}': No such file or directory")
            else:
                abs_path = self.fs._abspath(path, self.cwd)
                ftype = "directory" if node.is_dir else "regular file"
                outputs.append(
                    f"  File: {abs_path}\n"
                    f"  Size: {node.size:<14}Blocks: {node.size // 512:<11}IO Block: 4096   {ftype}\n"
                    f"Access: ({node.permissions})  Uid: (    0/    {node.owner})   "
                    f"Gid: (    0/    {node.group})\n"
                    f"Modify: {datetime.fromtimestamp(node.mtime).isoformat()}"
                )
        return "\n".join(outputs), 0

    def _cmd_df(self, args: List[str]) -> Tuple[str, int]:
        total = random.randint(40, 100)
        used = random.randint(10, total - 5)
        avail = total - used
        pct = int(used / total * 100)
        header = "Filesystem      Size  Used Avail Use% Mounted on"
        lines = [
            f"/dev/sda1        {total}G   {used}G   {avail}G  {pct}% /",
            "tmpfs            2.0G     0  2.0G   0% /dev/shm",
            "tmpfs            398M  1.1M  397M   1% /run",
            "tmpfs            5.0M     0  5.0M   0% /run/lock",
        ]
        return header + "\n" + "\n".join(lines), 0

    def _cmd_free(self, args: List[str]) -> Tuple[str, int]:
        total = 4028416
        used = random.randint(1000000, 3000000)
        free_mem = total - used
        shared = random.randint(10000, 50000)
        buff = random.randint(200000, 800000)
        avail = free_mem + buff
        header = "               total        used        free      shared  buff/cache   available"
        mem_line = f"Mem:       {total:>10}  {used:>10}  {free_mem:>10}  {shared:>10}  {buff:>10}  {avail:>10}"
        swap_line = f"Swap:       2097148           0     2097148"
        return header + "\n" + mem_line + "\n" + swap_line, 0

    def _cmd_uptime(self, args: List[str]) -> Tuple[str, int]:
        uptime_secs = time.time() - self.fs.boot_time
        days = int(uptime_secs // 86400)
        hours = int((uptime_secs % 86400) // 3600)
        mins = int((uptime_secs % 3600) // 60)
        now = datetime.now().strftime("%H:%M:%S")
        users = random.randint(1, 3)
        load1 = random.uniform(0.01, 0.5)
        load5 = random.uniform(0.05, 0.4)
        load15 = random.uniform(0.03, 0.3)
        return (
            f" {now} up {days} days, {hours:2d}:{mins:02d},  "
            f"{users} user{'s' if users > 1 else ''},  "
            f"load average: {load1:.2f}, {load5:.2f}, {load15:.2f}"
        ), 0

    def _cmd_w(self, args: List[str]) -> Tuple[str, int]:
        uptime_output, _ = self._cmd_uptime([])
        header = "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
        user_line = (
            f"{self.username:<8} pts/0    10.0.0.1         "
            f"{datetime.now().strftime('%H:%M')}    0.00s  0.04s  0.00s w"
        )
        return uptime_output + "\n" + header + "\n" + user_line, 0

    def _cmd_last(self, args: List[str]) -> Tuple[str, int]:
        lines = [
            f"{self.username:<8} pts/0        10.0.0.1         {datetime.now().strftime('%a %b %d %H:%M')}   still logged in",
            f"root     pts/0        10.0.0.1         Mon Feb  3 09:12 - 10:45  (01:33)",
            f"root     pts/0        10.0.0.1         Sun Feb  2 14:20 - 16:08  (01:48)",
            "",
            "wtmp begins Sun Feb  2 14:20:13 2025",
        ]
        return "\n".join(lines), 0

    def _cmd_history(self, args: List[str]) -> Tuple[str, int]:
        lines = []
        for i, cmd in enumerate(self.history, 1):
            lines.append(f"  {i:>4}  {cmd}")
        return "\n".join(lines), 0

    def _cmd_ifconfig(self, args: List[str]) -> Tuple[str, int]:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            "        inet6 fe80::42:acff:fe11:5  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 02:42:ac:11:00:05  txqueuelen 0  (Ethernet)\n"
            "        RX packets 128943  bytes 152847392 (145.7 MiB)\n"
            "        TX packets 98234  bytes 12394823 (11.8 MiB)\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
            "        RX packets 4382  bytes 421984 (412.1 KiB)\n"
            "        TX packets 4382  bytes 421984 (412.1 KiB)"
        ), 0

    def _cmd_ip(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "Usage: ip [ OPTIONS ] OBJECT { COMMAND }", 255
        obj = args[0]
        if obj in ("addr", "a", "address"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                "    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever"
            ), 0
        if obj in ("route", "r"):
            return (
                "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"
                "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 metric 100"
            ), 0
        if obj in ("link", "l"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
                "    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff"
            ), 0
        return f"Object \"{obj}\" is unknown, try \"ip help\".", 255

    def _cmd_mount(self, args: List[str]) -> Tuple[str, int]:
        return (
            "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
            "tmpfs on /run type tmpfs (rw,nosuid,nodev,mode=755)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)"
        ), 0

    def _cmd_date(self, args: List[str]) -> Tuple[str, int]:
        return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"), 0

    def _cmd_touch(self, args: List[str]) -> Tuple[str, int]:
        # Touch is a no-op on our read-only-ish filesystem
        return "", 0

    def _cmd_mkdir_cmd(self, args: List[str]) -> Tuple[str, int]:
        return "", 0

    def _cmd_rm(self, args: List[str]) -> Tuple[str, int]:
        # Pretend it worked
        return "", 0

    def _cmd_cp(self, args: List[str]) -> Tuple[str, int]:
        return "", 0

    def _cmd_mv(self, args: List[str]) -> Tuple[str, int]:
        return "", 0

    def _cmd_chmod(self, args: List[str]) -> Tuple[str, int]:
        return "", 0

    def _cmd_chown(self, args: List[str]) -> Tuple[str, int]:
        return "", 0

    def _cmd_systemctl(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "systemctl: missing command", 1
        action = args[0]
        service = args[1] if len(args) > 1 else ""
        if action == "status":
            if not service:
                return "systemctl: missing service name", 1
            svc_name = service.replace(".service", "")
            active_since = datetime.now().strftime("%a %Y-%m-%d %H:%M:%S UTC")
            pid = random.randint(500, 2000)
            return (
                f"● {svc_name}.service - {svc_name.capitalize()} Service\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc_name}.service; enabled; vendor preset: enabled)\n"
                f"     Active: active (running) since {active_since}; 47 days ago\n"
                f"   Main PID: {pid} ({svc_name})\n"
                f"      Tasks: {random.randint(1, 10)} (limit: 4915)\n"
                f"     Memory: {random.randint(2, 64)}M\n"
                f"        CPU: {random.randint(1, 300)}ms\n"
                f"     CGroup: /system.slice/{svc_name}.service\n"
                f"             └─{pid} /usr/sbin/{svc_name}"
            ), 0
        if action in ("start", "stop", "restart", "reload", "enable", "disable"):
            if self.uid != 0:
                return f"Failed to {action} {service}: Access denied", 1
            return "", 0
        if action == "list-units":
            return (
                "UNIT                     LOAD   ACTIVE SUB     DESCRIPTION\n"
                "cron.service             loaded active running Regular background program processing daemon\n"
                "dbus.service             loaded active running D-Bus System Message Bus\n"
                "networking.service       loaded active exited  Raise network interfaces\n"
                "rsyslog.service          loaded active running System Logging Service\n"
                "ssh.service              loaded active running OpenBSD Secure Shell server\n"
                "systemd-journald.service loaded active running Journal Service\n"
            ), 0
        return f"Unknown command '{action}'", 1

    def _cmd_service(self, args: List[str]) -> Tuple[str, int]:
        if len(args) < 2:
            return "Usage: service <service> <action>", 1
        return self._cmd_systemctl([args[1], args[0]])

    def _cmd_dpkg(self, args: List[str]) -> Tuple[str, int]:
        if args and args[0] == "-l":
            packages = [
                "ii  bash           5.1-6ubuntu1   amd64  GNU Bourne Again SHell",
                "ii  coreutils      8.32-4.1       amd64  GNU core utilities",
                "ii  openssh-server 1:8.9p1-3      amd64  secure shell (SSH) server",
                "ii  openssl        3.0.2-0ubuntu1 amd64  Secure Sockets Layer toolkit",
                "ii  python3        3.10.6-1~22.04 amd64  interactive high-level object-oriented language",
                "ii  sudo           1.9.9-1ubuntu2 amd64  Provide limited super user privileges",
                "ii  systemd        249.11-0ubuntu3 amd64  system and service manager",
                "ii  wget           1.21.2-2ubuntu1 amd64  retrieves files from the web",
                "ii  curl           7.81.0-1ubuntu1 amd64  command line tool for transferring data",
            ]
            return "\n".join(packages), 0
        return "dpkg: error: need an action option", 2

    def _cmd_apt(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "apt: missing command", 1
        if args[0] == "update":
            if self.uid != 0:
                return "E: Could not open lock file - open (13: Permission denied)", 100
            return (
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Hit:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n"
                "Hit:3 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "All packages are up to date."
            ), 0
        if args[0] == "list" and "--installed" in args:
            return self._cmd_dpkg(["-l"])
        return f"E: Invalid operation {args[0]}", 100

    def _cmd_yum(self, args: List[str]) -> Tuple[str, int]:
        return "bash: yum: command not found", 127

    def _cmd_pip(self, args: List[str]) -> Tuple[str, int]:
        if args and args[0] == "list":
            return (
                "Package    Version\n"
                "---------- -------\n"
                "pip        22.0.2\n"
                "setuptools 59.6.0\n"
                "wheel      0.37.1"
            ), 0
        return "pip: command requires arguments", 1

    def _cmd_python(self, args: List[str]) -> Tuple[str, int]:
        if not args:
            return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>>", 0
        if args[0] == "--version" or args[0] == "-V":
            return "Python 3.10.12", 0
        if args[0] == "-c" and len(args) > 1:
            return "", 0
        return "python3: can't open file: [Errno 2] No such file or directory", 2

    def _cmd_crontab(self, args: List[str]) -> Tuple[str, int]:
        if args and args[0] == "-l":
            return "no crontab for " + self.username, 0
        return "", 0
