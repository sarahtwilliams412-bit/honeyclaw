"""Tests for the ShellEmulator."""

import pytest

from src.emulation.filesystem import FakeFilesystem
from src.emulation.shell import ShellEmulator


@pytest.fixture
def shell():
    """Create a shell emulator with default settings."""
    fs = FakeFilesystem()
    return ShellEmulator(
        filesystem=fs,
        username="root",
        hostname="test-host",
        uid=0,
        gid=0,
        home="/root",
    )


@pytest.fixture
def user_shell():
    """Create a shell emulator as a non-root user."""
    profile = {
        "os_name": "Ubuntu",
        "os_version": "22.04",
        "kernel": "5.15.0-91-generic",
        "hostname": "test-host",
        "users": [
            {"name": "testuser", "home": "/home/testuser", "shell": "/bin/bash",
             "gecos": "Test User"},
        ],
    }
    fs = FakeFilesystem(profile)
    return ShellEmulator(
        filesystem=fs,
        username="testuser",
        hostname="test-host",
        uid=1000,
        gid=1000,
        groups=["testuser"],
        home="/home/testuser",
    )


class TestPrompt:
    def test_root_prompt(self, shell):
        assert "root@test-host" in shell.prompt
        assert shell.prompt.endswith("# ")

    def test_user_prompt(self, user_shell):
        assert "testuser@test-host" in user_shell.prompt
        assert user_shell.prompt.endswith("$ ")

    def test_prompt_shows_home_as_tilde(self, shell):
        assert "~" in shell.prompt

    def test_prompt_updates_on_cd(self, shell):
        shell.execute("cd /tmp")
        assert "/tmp" in shell.prompt


class TestNavigation:
    def test_pwd(self, shell):
        output, code = shell.execute("pwd")
        assert output == "/root"
        assert code == 0

    def test_cd_absolute(self, shell):
        output, code = shell.execute("cd /tmp")
        assert code == 0
        output, code = shell.execute("pwd")
        assert output == "/tmp"

    def test_cd_relative(self, shell):
        shell.execute("cd /")
        output, code = shell.execute("cd etc")
        assert code == 0
        output, code = shell.execute("pwd")
        assert output == "/etc"

    def test_cd_dotdot(self, shell):
        shell.execute("cd /etc/ssh")
        shell.execute("cd ..")
        output, _ = shell.execute("pwd")
        assert output == "/etc"

    def test_cd_home(self, shell):
        shell.execute("cd /tmp")
        shell.execute("cd")
        output, _ = shell.execute("pwd")
        assert output == "/root"

    def test_cd_tilde(self, shell):
        shell.execute("cd /tmp")
        shell.execute("cd ~")
        output, _ = shell.execute("pwd")
        assert output == "/root"

    def test_cd_nonexistent(self, shell):
        output, code = shell.execute("cd /nonexistent")
        assert code == 1
        assert "No such file" in output

    def test_cd_to_file(self, shell):
        output, code = shell.execute("cd /etc/hostname")
        assert code == 1
        assert "Not a directory" in output


class TestFileOperations:
    def test_ls_root(self, shell):
        output, code = shell.execute("ls /")
        assert code == 0
        assert "etc" in output
        assert "var" in output

    def test_ls_long(self, shell):
        output, code = shell.execute("ls -la /etc")
        assert code == 0
        assert "hostname" in output
        # Long format should have permissions
        assert "r" in output

    def test_ls_nonexistent(self, shell):
        output, code = shell.execute("ls /nonexistent")
        assert "No such file" in output

    def test_cat_file(self, shell):
        output, code = shell.execute("cat /etc/hostname")
        assert code == 0
        assert "server-01" in output

    def test_cat_etc_passwd(self, shell):
        output, code = shell.execute("cat /etc/passwd")
        assert code == 0
        assert "root" in output
        assert "/bin/bash" in output

    def test_cat_nonexistent(self, shell):
        output, code = shell.execute("cat /nonexistent")
        assert code == 1
        assert "No such file" in output

    def test_cat_directory(self, shell):
        output, code = shell.execute("cat /etc")
        assert code == 1
        assert "Is a directory" in output

    def test_head(self, shell):
        output, code = shell.execute("head /etc/passwd")
        assert code == 0
        assert "root" in output

    def test_tail(self, shell):
        output, code = shell.execute("tail /etc/passwd")
        assert code == 0

    def test_grep(self, shell):
        output, code = shell.execute("grep root /etc/passwd")
        assert code == 0
        assert "root" in output

    def test_grep_no_match(self, shell):
        output, code = shell.execute("grep zzzznotfound /etc/hostname")
        assert code == 1

    def test_find(self, shell):
        output, code = shell.execute("find /etc -name hostname")
        assert code == 0
        assert "/etc/hostname" in output

    def test_wc(self, shell):
        output, code = shell.execute("wc /etc/hostname")
        assert code == 0

    def test_stat(self, shell):
        output, code = shell.execute("stat /etc/hostname")
        assert code == 0
        assert "File:" in output

    def test_file_command(self, shell):
        output, code = shell.execute("file /etc/hostname")
        assert code == 0
        assert "ASCII text" in output


class TestSystemInfo:
    def test_whoami(self, shell):
        output, code = shell.execute("whoami")
        assert output == "root"
        assert code == 0

    def test_id(self, shell):
        output, code = shell.execute("id")
        assert "uid=0(root)" in output
        assert code == 0

    def test_uname(self, shell):
        output, code = shell.execute("uname")
        assert output == "Linux"

    def test_uname_a(self, shell):
        output, code = shell.execute("uname -a")
        assert "Linux" in output
        assert "test-host" in output
        assert "GNU/Linux" in output

    def test_uname_r(self, shell):
        output, code = shell.execute("uname -r")
        assert code == 0
        assert len(output) > 0

    def test_hostname(self, shell):
        output, code = shell.execute("hostname")
        assert output == "test-host"

    def test_uptime(self, shell):
        output, code = shell.execute("uptime")
        assert "up" in output
        assert "load average" in output

    def test_date(self, shell):
        output, code = shell.execute("date")
        assert code == 0
        assert len(output) > 5

    def test_df(self, shell):
        output, code = shell.execute("df -h")
        assert "Filesystem" in output
        assert "/" in output

    def test_free(self, shell):
        output, code = shell.execute("free -m")
        assert "Mem:" in output
        assert "Swap:" in output

    def test_ps(self, shell):
        output, code = shell.execute("ps")
        assert "PID" in output
        assert "bash" in output

    def test_ps_aux(self, shell):
        output, code = shell.execute("ps aux")
        assert "USER" in output
        assert "sshd" in output

    def test_w(self, shell):
        output, code = shell.execute("w")
        assert "USER" in output
        assert "load average" in output

    def test_last(self, shell):
        output, code = shell.execute("last")
        assert "root" in output

    def test_mount(self, shell):
        output, code = shell.execute("mount")
        assert "/dev/sda1" in output
        assert "ext4" in output


class TestNetworking:
    def test_netstat(self, shell):
        output, code = shell.execute("netstat -tlnp")
        assert "LISTEN" in output
        assert ":22" in output

    def test_ifconfig(self, shell):
        output, code = shell.execute("ifconfig")
        assert "eth0" in output
        assert "inet" in output

    def test_ip_addr(self, shell):
        output, code = shell.execute("ip addr")
        assert "eth0" in output
        assert "10.0.0.5" in output

    def test_ip_route(self, shell):
        output, code = shell.execute("ip route")
        assert "default" in output

    def test_ssh_unreachable(self, shell):
        output, code = shell.execute("ssh 10.0.0.99")
        assert "unreachable" in output.lower() or "Network is unreachable" in output

    def test_scp_unreachable(self, shell):
        output, code = shell.execute("scp file.txt 10.0.0.99:/tmp/")
        assert code != 0

    def test_wget_fails(self, shell):
        output, code = shell.execute("wget http://example.com/file.txt")
        assert code != 0
        assert "resolve" in output.lower() or "failed" in output.lower()

    def test_curl_fails(self, shell):
        output, code = shell.execute("curl http://example.com/api")
        assert code != 0


class TestPackageManagement:
    def test_dpkg_list(self, shell):
        output, code = shell.execute("dpkg -l")
        assert code == 0
        assert "bash" in output

    def test_apt_update_as_root(self, shell):
        output, code = shell.execute("apt update")
        assert code == 0
        assert "Reading package lists" in output

    def test_apt_update_as_user(self, user_shell):
        output, code = user_shell.execute("apt update")
        assert code != 0
        assert "Permission denied" in output

    def test_pip_list(self, shell):
        output, code = shell.execute("pip list")
        assert code == 0
        assert "pip" in output


class TestServiceManagement:
    def test_systemctl_status(self, shell):
        output, code = shell.execute("systemctl status sshd")
        assert code == 0
        assert "active (running)" in output

    def test_systemctl_list_units(self, shell):
        output, code = shell.execute("systemctl list-units")
        assert code == 0
        assert "ssh.service" in output

    def test_service_command(self, shell):
        output, code = shell.execute("service sshd status")
        assert code == 0


class TestShellFeatures:
    def test_env(self, shell):
        output, code = shell.execute("env")
        assert "HOME=/root" in output
        assert "USER=root" in output
        assert "PATH=" in output

    def test_export(self, shell):
        shell.execute("export MY_VAR=hello")
        output, _ = shell.execute("env")
        assert "MY_VAR=hello" in output

    def test_variable_expansion(self, shell):
        output, code = shell.execute("echo $HOME")
        assert output == "/root"

    def test_variable_expansion_braces(self, shell):
        output, code = shell.execute("echo ${USER}")
        assert output == "root"

    def test_echo(self, shell):
        output, code = shell.execute("echo hello world")
        assert output == "hello world"

    def test_which(self, shell):
        output, code = shell.execute("which bash")
        assert "/usr/bin/bash" in output

    def test_which_not_found(self, shell):
        output, code = shell.execute("which nonexistent_binary")
        assert "not found" in output
        assert code == 1

    def test_history(self, shell):
        shell.execute("whoami")
        shell.execute("pwd")
        output, code = shell.execute("history")
        assert "whoami" in output
        assert "pwd" in output

    def test_command_not_found(self, shell):
        output, code = shell.execute("nonexistent_command")
        assert code == 127
        assert "command not found" in output

    def test_empty_command(self, shell):
        output, code = shell.execute("")
        assert output == ""
        assert code == 0

    def test_command_chaining_semicolon(self, shell):
        output, code = shell.execute("whoami ; hostname")
        assert "root" in output
        assert "test-host" in output

    def test_command_chaining_and(self, shell):
        output, code = shell.execute("whoami && hostname")
        assert "root" in output
        assert "test-host" in output

    def test_pipe(self, shell):
        output, code = shell.execute("cat /etc/passwd | grep root")
        assert "root" in output

    def test_python_version(self, shell):
        output, code = shell.execute("python3 --version")
        assert "Python" in output

    def test_crontab_l(self, shell):
        output, code = shell.execute("crontab -l")
        assert "no crontab" in output


class TestCanaryCallbacks:
    def test_canary_triggers_callback(self):
        fs = FakeFilesystem()
        fs.add_canary("/root/.ssh/id_rsa", "FAKE_KEY", token_id="key1")
        triggered = []

        def on_canary(path, token_id):
            triggered.append((path, token_id))

        shell = ShellEmulator(filesystem=fs, on_canary=on_canary)
        shell.execute("cat /root/.ssh/id_rsa")
        assert len(triggered) == 1
        assert triggered[0] == ("/root/.ssh/id_rsa", "key1")

    def test_non_canary_no_callback(self):
        fs = FakeFilesystem()
        triggered = []

        def on_canary(path, token_id):
            triggered.append((path, token_id))

        shell = ShellEmulator(filesystem=fs, on_canary=on_canary)
        shell.execute("cat /etc/hostname")
        assert len(triggered) == 0


class TestNonRootUser:
    def test_user_whoami(self, user_shell):
        output, _ = user_shell.execute("whoami")
        assert output == "testuser"

    def test_user_id(self, user_shell):
        output, _ = user_shell.execute("id")
        assert "uid=1000" in output
        assert "testuser" in output

    def test_user_home(self, user_shell):
        output, _ = user_shell.execute("pwd")
        assert output == "/home/testuser"
