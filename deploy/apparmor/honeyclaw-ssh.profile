#include <tunables/global>

# AppArmor profile for HoneyClaw SSH honeypot containers.
# Restricts filesystem access, network capabilities, and system calls
# to the minimum required for SSH honeypot operation.

profile honeyclaw-ssh flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Network: allow only TCP listening (inbound SSH) and established connections
  network inet tcp,
  network inet6 tcp,

  # DNS resolution for log shipping / SIEM integration
  network inet udp,
  network inet6 udp,

  # Deny raw sockets (no ICMP, no packet sniffing)
  deny network raw,
  deny network packet,

  # Filesystem - read-only access to application files
  /app/** r,
  /common/** r,
  /usr/** r,
  /lib/** r,
  /lib64/** r,
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,
  /etc/nsswitch.conf r,
  /etc/ssl/** r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/localtime r,
  /etc/passwd r,
  /etc/group r,

  # Python runtime
  /usr/local/bin/python* ix,
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/local/lib/python*/** r,
  /usr/lib/python3/** r,

  # Honeypot application
  /opt/honeyclaw/** r,
  /opt/honeyclaw/src/** r,
  /opt/honeyclaw/templates/** r,

  # Logging - write access only to honeypot log directory
  /var/log/honeypot/** rw,
  /var/log/honeypot/ r,
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,

  # Temporary files needed by Python
  /tmp/** rw,
  /tmp/ r,

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

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny ptrace (anti-debugging / anti-escape)
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

  # Signal handling - only to own processes
  signal (send,receive) peer=honeyclaw-ssh,
}
