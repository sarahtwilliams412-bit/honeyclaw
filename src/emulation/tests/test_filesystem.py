"""Tests for the FakeFilesystem emulation layer."""

import json
import os
import pytest

from src.emulation.filesystem import FakeFilesystem, load_profile


class TestFakeFilesystemBase:
    """Test the base filesystem tree (no profile)."""

    def setup_method(self):
        self.fs = FakeFilesystem()

    def test_root_exists(self):
        node = self.fs.resolve("/")
        assert node is not None
        assert node.is_dir

    def test_standard_directories_exist(self):
        for d in ["/etc", "/var", "/usr", "/home", "/root", "/tmp",
                  "/dev", "/proc", "/sys", "/opt", "/bin", "/sbin"]:
            assert self.fs.is_dir(d), f"{d} should exist as a directory"

    def test_etc_files_present(self):
        for f in ["/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
                  "/etc/fstab", "/etc/passwd", "/etc/shadow",
                  "/etc/os-release", "/etc/ssh/sshd_config"]:
            assert self.fs.exists(f), f"{f} should exist"

    def test_read_hostname(self):
        content = self.fs.read_file("/etc/hostname")
        assert content is not None
        assert "server-01" in content

    def test_read_hosts(self):
        content = self.fs.read_file("/etc/hosts")
        assert "127.0.0.1" in content
        assert "localhost" in content

    def test_proc_uptime(self):
        content = self.fs.read_file("/proc/uptime")
        assert content is not None
        parts = content.strip().split()
        assert len(parts) == 2
        assert float(parts[0]) > 0

    def test_proc_cpuinfo(self):
        content = self.fs.read_file("/proc/cpuinfo")
        assert "processor" in content
        assert "model name" in content

    def test_proc_meminfo(self):
        content = self.fs.read_file("/proc/meminfo")
        assert "MemTotal" in content
        assert "MemFree" in content

    def test_root_home_files(self):
        assert self.fs.exists("/root/.bashrc")
        assert self.fs.exists("/root/.profile")
        assert self.fs.exists("/root/.bash_history")

    def test_log_files(self):
        assert self.fs.exists("/var/log/syslog")
        assert self.fs.exists("/var/log/auth.log")

    def test_list_dir(self):
        children = self.fs.list_dir("/etc")
        names = [c.name for c in children]
        assert "hostname" in names
        assert "hosts" in names

    def test_list_dir_hidden(self):
        visible = self.fs.list_dir("/root", show_hidden=False)
        hidden = self.fs.list_dir("/root", show_hidden=True)
        visible_names = {c.name for c in visible}
        hidden_names = {c.name for c in hidden}
        # .bashrc should only appear in hidden listing
        assert ".bashrc" not in visible_names
        assert ".bashrc" in hidden_names

    def test_resolve_nonexistent(self):
        assert self.fs.resolve("/nonexistent/path") is None

    def test_read_directory_returns_none(self):
        assert self.fs.read_file("/etc") is None

    def test_read_nonexistent_returns_none(self):
        assert self.fs.read_file("/no/such/file") is None

    def test_relative_path_resolution(self):
        node = self.fs.resolve("hostname", cwd="/etc")
        assert node is not None
        content = self.fs.read_file("hostname", cwd="/etc")
        assert "server-01" in content

    def test_dotdot_resolution(self):
        node = self.fs.resolve("../etc/hostname", cwd="/var")
        assert node is not None

    def test_tmp_permissions(self):
        node = self.fs.resolve("/tmp")
        assert node is not None
        assert "t" in node.permissions  # sticky bit


class TestFakeFilesystemCanary:
    """Test canary token functionality."""

    def setup_method(self):
        self.fs = FakeFilesystem()

    def test_add_canary(self):
        self.fs.add_canary("/root/.ssh/id_rsa", "FAKE_KEY", token_id="ssh1")
        assert self.fs.exists("/root/.ssh/id_rsa")
        assert self.fs.is_canary("/root/.ssh/id_rsa")

    def test_canary_content_readable(self):
        self.fs.add_canary("/root/.ssh/id_rsa", "FAKE_KEY_DATA", token_id="ssh1")
        content = self.fs.read_file("/root/.ssh/id_rsa")
        assert content == "FAKE_KEY_DATA"

    def test_canary_id(self):
        self.fs.add_canary("/root/.ssh/id_rsa", "KEY", token_id="tok123")
        assert self.fs.get_canary_id("/root/.ssh/id_rsa") == "tok123"

    def test_non_canary_not_flagged(self):
        assert not self.fs.is_canary("/etc/hostname")

    def test_canary_creates_parents(self):
        self.fs.add_canary("/opt/secret/data.txt", "secret", token_id="s1")
        assert self.fs.is_dir("/opt/secret")
        assert self.fs.exists("/opt/secret/data.txt")


class TestFakeFilesystemProfile:
    """Test filesystem with an OS profile applied."""

    def setup_method(self):
        self.profile = {
            "os_name": "Ubuntu",
            "os_version": "22.04",
            "kernel": "5.15.0-91-generic",
            "arch": "x86_64",
            "hostname": "test-host",
            "users": [
                {
                    "name": "admin",
                    "home": "/home/admin",
                    "shell": "/bin/bash",
                    "gecos": "Admin User",
                    "has_aws": True,
                },
                {
                    "name": "deploy",
                    "home": "/home/deploy",
                    "shell": "/bin/bash",
                    "gecos": "Deploy User",
                },
            ],
            "extra_binaries": ["nginx", "node"],
        }
        self.fs = FakeFilesystem(self.profile)

    def test_hostname_from_profile(self):
        content = self.fs.read_file("/etc/hostname")
        assert "test-host" in content

    def test_os_release(self):
        content = self.fs.read_file("/etc/os-release")
        assert "Ubuntu" in content

    def test_passwd_has_users(self):
        content = self.fs.read_file("/etc/passwd")
        assert "admin" in content
        assert "deploy" in content
        assert "root" in content

    def test_shadow_has_users(self):
        content = self.fs.read_file("/etc/shadow")
        assert "admin" in content

    def test_user_home_dirs(self):
        assert self.fs.is_dir("/home/admin")
        assert self.fs.is_dir("/home/deploy")
        assert self.fs.exists("/home/admin/.bashrc")
        assert self.fs.exists("/home/deploy/.bashrc")

    def test_aws_credentials_for_flagged_user(self):
        assert self.fs.exists("/home/admin/.aws/credentials")
        content = self.fs.read_file("/home/admin/.aws/credentials")
        assert "aws_access_key_id" in content

    def test_no_aws_for_unflagged_user(self):
        assert not self.fs.exists("/home/deploy/.aws")

    def test_extra_binaries(self):
        assert self.fs.exists("/usr/bin/nginx")
        assert self.fs.exists("/usr/bin/node")

    def test_proc_version(self):
        content = self.fs.read_file("/proc/version")
        assert "5.15.0-91-generic" in content


class TestLoadProfile:
    """Test profile loading from JSON files."""

    def test_load_existing_profile(self):
        profile = load_profile("ubuntu-22.04")
        assert profile.get("os_name") == "Ubuntu"
        assert "users" in profile

    def test_load_nonexistent_profile(self):
        profile = load_profile("nonexistent-os")
        assert profile == {}

    def test_all_bundled_profiles_valid(self):
        for name in ["ubuntu-22.04", "centos-7", "debian-12", "amazon-linux-2"]:
            profile = load_profile(name)
            assert profile, f"Profile {name} should load successfully"
            assert "os_name" in profile
            assert "kernel" in profile
            assert "users" in profile
            # Verify profile can be used to create a filesystem
            fs = FakeFilesystem(profile)
            assert fs.exists("/etc/os-release")
