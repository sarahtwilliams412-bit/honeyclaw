# =============================================================================
# Honeyclaw AppArmor Profile - API Honeypot
#
# Restricts the API (Node.js) honeypot container.
# Install: sudo apparmor_parser -r -W honeyclaw-api.profile
# =============================================================================

#include <tunables/global>

profile honeyclaw-api flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Network: allow HTTP/HTTPS and health
  network inet  stream,
  network inet6 stream,
  network inet  dgram,
  network inet6 dgram,

  deny network raw,
  deny network packet,

  # Node.js execution
  /usr/bin/node rix,
  /usr/local/bin/node rix,
  /usr/lib/nodejs/** r,

  # Honeypot application
  /opt/honeyclaw/** r,
  /opt/honeyclaw/templates/fake-api/** r,
  /opt/honeyclaw/node_modules/** r,

  # Writable paths
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,
  /tmp/** rw,

  # Read-only proc
  /proc/loadavg r,
  /proc/meminfo r,
  @{PROC}/@{pid}/fd/ r,

  # Deny sensitive operations
  deny /proc/*/mem rw,
  deny /proc/*/root/** rw,
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
}
