#include <tunables/global>

# AppArmor profile for HoneyClaw Fake API honeypot containers.
# Restricts filesystem access, network capabilities, and system calls
# to the minimum required for the Node.js REST API honeypot.

profile honeyclaw-api flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Network: allow TCP for HTTP serving and established connections
  network inet tcp,
  network inet6 tcp,

  # DNS resolution for log shipping / SIEM integration
  network inet udp,
  network inet6 udp,

  # Deny raw sockets
  deny network raw,
  deny network packet,

  # Filesystem - read-only access to application files
  /app/** r,
  /app/node_modules/** r,
  /app/node_modules/.package-lock.json r,
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

  # Node.js runtime
  /usr/local/bin/node ix,
  /usr/local/lib/node_modules/** r,

  # Logging - write access only to honeypot log directory
  /var/log/honeypot/** rw,
  /var/log/honeypot/ r,

  # Temporary files needed by Node.js
  /tmp/** rw,
  /tmp/ r,

  # /proc and /sys - limited read access
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/kernel/hostname r,
  @{PROC}/meminfo r,
  @{PROC}/cpuinfo r,
  @{PROC}/self/fd/ r,
  @{PROC}/self/maps r,
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
  deny /sys/fs/cgroup/** w,
  deny /sys/devices/virtual/dmi/** r,

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

  # Signal handling - only to own processes
  signal (send,receive) peer=honeyclaw-api,
}
