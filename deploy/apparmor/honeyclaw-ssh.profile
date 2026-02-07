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
  network tcp,
  network udp,

  # Python interpreter
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,

  # Application code (read-only)
  /app/** r,
  /app/**/*.py r,
  /app/**/*.pyc r,

  # Data directory (logs, recordings)
  /data/ rw,
  /data/** rw,
  /data/logs/** w,

  # Temp files
  /tmp/ rw,
  /tmp/** rw,

  # Required system files
  /etc/passwd r,
  /etc/group r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/ssl/** r,
  /proc/sys/net/** r,

  # Deny dangerous operations
  deny /proc/*/mem rw,
  deny /proc/sysrq-trigger rw,
  deny /proc/kcore r,
  deny /sys/firmware/** rw,
  deny /sys/kernel/** rw,

  # Deny mount operations
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny ptrace (prevents debugging/process injection)
  deny ptrace,

  # Deny raw sockets (prevents network sniffing)
  deny network raw,
  deny network packet,

  # Deny write to system paths
  deny /bin/** w,
  deny /sbin/** w,
  deny /usr/** w,
  deny /etc/** w,
  deny /boot/** rw,
  deny /root/** rw,
}
