# =============================================================================
# Honeyclaw AppArmor Profile - SSH Honeypot
#
# Restricts the SSH honeypot container to only the operations it needs.
# Install: sudo apparmor_parser -r -W honeyclaw-ssh.profile
# =============================================================================

#include <tunables/global>

profile honeyclaw-ssh flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Network: allow listening on SSH and health check ports
  network inet  stream,
  network inet6 stream,
  network inet  dgram,   # DNS
  network inet6 dgram,

  # Deny raw sockets (prevent packet crafting)
  deny network raw,
  deny network packet,

  # Python and honeypot execution
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,

  # Honeypot application
  /opt/honeyclaw/** r,
  /opt/honeyclaw/src/** r,
  /opt/honeyclaw/templates/** r,

  # Writable paths (logging only)
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,
  /tmp/** rw,

  # Read-only system info (for fake responses)
  /proc/loadavg r,
  /proc/meminfo r,
  /proc/cpuinfo r,
  /proc/net/tcp r,
  /proc/net/tcp6 r,
  /proc/sys/kernel/hostname r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/@{pid}/cmdline r,
  @{PROC}/@{pid}/stat r,

  # Deny sensitive operations
  deny /proc/*/mem rw,
  deny /proc/*/root/** rw,
  deny /proc/sysrq-trigger rw,
  deny /proc/kcore r,

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny ptrace (no debugging other processes)
  deny ptrace,

  # Deny module loading
  deny @{PROC}/sys/kernel/modprobe w,

  # Deny access to Docker socket
  deny /var/run/docker.sock rw,
  deny /run/docker.sock rw,

  # Deny capability abuse
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability net_admin,
  deny capability sys_boot,
  deny capability sys_time,
  deny capability mknod,
}
