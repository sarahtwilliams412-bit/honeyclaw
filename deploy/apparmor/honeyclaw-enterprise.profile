# =============================================================================
# Honeyclaw AppArmor Profile - Enterprise Simulation
#
# More permissive profile for multi-service enterprise honeypot,
# but still blocks dangerous operations.
# Install: sudo apparmor_parser -r -W honeyclaw-enterprise.profile
# =============================================================================

#include <tunables/global>

profile honeyclaw-enterprise flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Network: allow multiple service ports
  network inet  stream,
  network inet6 stream,
  network inet  dgram,
  network inet6 dgram,

  deny network raw,
  deny network packet,

  # Python and Node.js
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/bin/node rix,
  /usr/local/bin/node rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,

  # Honeypot application
  /opt/honeyclaw/** r,
  /opt/honeyclaw/templates/enterprise-sim/** r,

  # Writable paths
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,
  /tmp/** rw,

  # Proc access for monitoring
  /proc/loadavg r,
  /proc/meminfo r,
  /proc/cpuinfo r,
  /proc/net/tcp r,
  /proc/net/tcp6 r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/@{pid}/cmdline r,
  @{PROC}/@{pid}/stat r,

  # Deny dangerous operations
  deny /proc/*/mem rw,
  deny /proc/*/root/** rw,
  deny /proc/sysrq-trigger rw,
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,
  deny /var/run/docker.sock rw,
  deny /run/docker.sock rw,

  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability net_admin,
  deny capability sys_boot,
  deny capability sys_time,
}
