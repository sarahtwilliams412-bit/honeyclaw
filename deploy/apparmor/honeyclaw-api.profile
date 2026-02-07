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
  network tcp,
  network udp,

  # Node.js runtime
  /usr/bin/node rix,
  /usr/local/bin/node rix,
  /usr/lib/node_modules/** r,
  /usr/local/lib/node_modules/** r,

  # Application code (read-only)
  /app/** r,
  /app/node_modules/** r,
  /app/**/*.js r,
  /app/**/*.json r,

  # Data directory
  /data/ rw,
  /data/** rw,
  /data/logs/** w,

  # Temp files
  /tmp/ rw,
  /tmp/** rw,

  # System files
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
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,
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
