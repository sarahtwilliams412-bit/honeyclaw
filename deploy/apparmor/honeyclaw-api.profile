# AppArmor profile for HoneyClaw Fake API Honeypot (Node.js)
#
# Install:
#   sudo cp deploy/apparmor/honeyclaw-api.profile /etc/apparmor.d/honeyclaw-api
#   sudo apparmor_parser -r /etc/apparmor.d/honeyclaw-api
#
# Use with Docker:
#   docker run --security-opt apparmor=honeyclaw-api ...

#include <tunables/global>

profile honeyclaw-api flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Minimal capabilities
  capability net_bind_service,
  capability setuid,
  capability setgid,

  # Network: TCP and UDP (DNS)
  network inet tcp,
  network inet6 tcp,
  network inet udp,
  network inet6 udp,

  # Deny raw sockets
  deny network raw,
  deny network packet,

  # Node.js runtime
  /usr/bin/node rix,
  /usr/local/bin/node rix,
  /usr/lib/node_modules/** r,
  /usr/local/lib/node_modules/** r,
  /usr/lib/nodejs/** r,

  # Application code (read-only)
  /app/** r,
  /app/node_modules/** r,
  /app/**/*.js r,
  /app/**/*.json r,
  /app/node_modules/.package-lock.json r,

  # Honeypot application (both paths for compatibility)
  /opt/honeyclaw/** r,
  /opt/honeyclaw/templates/fake-api/** r,
  /opt/honeyclaw/node_modules/** r,

  # Data directory
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

  # System files
  /etc/passwd r,
  /etc/group r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/localtime r,
  /etc/ssl/** r,
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,
  /usr/** r,
  /lib/** r,
  /lib64/** r,

  # /proc and /sys - limited read access
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/kernel/hostname r,
  @{PROC}/meminfo r,
  @{PROC}/cpuinfo r,
  @{PROC}/loadavg r,
  @{PROC}/self/fd/ r,
  @{PROC}/self/maps r,
  @{PROC}/@{pid}/fd/ r,
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

  # Deny ptrace
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

  # Deny write to system paths
  deny /bin/** w,
  deny /sbin/** w,
  deny /usr/** w,
  deny /etc/** w,

  # Signal handling - only to own processes
  signal (send,receive) peer=honeyclaw-api,
}
