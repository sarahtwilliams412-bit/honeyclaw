# AppArmor profile for HoneyClaw SSH Honeypot
#
# Install:
#   sudo cp deploy/apparmor/honeyclaw-ssh.profile /etc/apparmor.d/honeyclaw-ssh
#   sudo apparmor_parser -r /etc/apparmor.d/honeyclaw-ssh
#
# Use with Docker:
#   docker run --security-opt apparmor=honeyclaw-ssh ...

#include <tunables/global>

profile honeyclaw-ssh flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Deny all capabilities by default, grant only what's needed
  capability net_bind_service,
  capability setuid,
  capability setgid,

  # Network: allow TCP listen (honeypot) and DNS
  network inet tcp,
  network inet6 tcp,
  network inet udp,
  network inet6 udp,

  # Deny raw sockets (prevents network sniffing)
  deny network raw,
  deny network packet,

  # Python interpreter
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,
  /usr/local/lib/python*/** r,

  # Application code (read-only)
  /app/** r,
  /app/**/*.py r,
  /app/**/*.pyc r,
  /common/** r,
  /usr/** r,
  /lib/** r,
  /lib64/** r,

  # Honeypot application
  /opt/honeyclaw/** r,
  /opt/honeyclaw/src/** r,
  /opt/honeyclaw/templates/** r,

  # Data directory (logs, recordings)
  /data/ rw,
  /data/** rw,
  /data/logs/** w,

  # Logging - write access only to honeypot log directory
  /var/log/honeypot/** rw,
  /var/log/honeypot/ r,
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,

  # Temp files
  /tmp/ rw,
  /tmp/** rw,

  # Required system files
  /etc/passwd r,
  /etc/group r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/localtime r,
  /etc/ssl/** r,
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,

  # /proc and /sys - limited read access (for fake responses)
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/kernel/hostname r,
  @{PROC}/meminfo r,
  @{PROC}/cpuinfo r,
  @{PROC}/loadavg r,
  @{PROC}/net/tcp r,
  @{PROC}/net/tcp6 r,
  @{PROC}/self/fd/ r,
  @{PROC}/self/maps r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/@{pid}/cmdline r,
  @{PROC}/@{pid}/stat r,
  owner @{PROC}/self/status r,
  /proc/sys/net/** r,

  # Deny sensitive filesystem areas
  deny /etc/shadow r,
  deny /root/** rw,
  deny /home/** rw,
  deny /boot/** rw,
  deny /sys/firmware/** r,
  deny /sys/kernel/security/** r,

  # Deny container escape vectors
  deny /proc/sysrq-trigger rw,
  deny /proc/sys/kernel/core_pattern rw,
  deny /proc/sys/kernel/modprobe rw,
  deny /proc/kcore r,
  deny /proc/kmem rw,
  deny /proc/*/mem rw,
  deny /proc/*/root/** rw,
  deny /sys/fs/cgroup/** w,
  deny /sys/devices/virtual/dmi/** r,
  deny /sys/firmware/** rw,
  deny /sys/kernel/** rw,

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny ptrace (prevents debugging/process injection)
  deny ptrace,

  # Deny loading kernel modules
  deny @{PROC}/sys/kernel/modules_disabled w,

  # Deny access to Docker socket
  deny /var/run/docker.sock rw,
  deny /run/docker.sock rw,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability net_admin,
  deny capability sys_boot,
  deny capability sys_time,
  deny capability mknod,

  # Deny write to system paths
  deny /bin/** w,
  deny /sbin/** w,
  deny /usr/** w,
  deny /etc/** w,

  # Signal handling - only to own processes
  signal (send,receive) peer=honeyclaw-ssh,
}
