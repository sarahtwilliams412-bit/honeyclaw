# AppArmor profile for HoneyClaw Enterprise Simulation Honeypot
#
# Slightly more permissive than basic profiles because the enterprise
# simulation runs multiple services (SSH, HTTP, RDP sim, LDAP sim, SMB).
#
# Install:
#   sudo cp deploy/apparmor/honeyclaw-enterprise.profile /etc/apparmor.d/honeyclaw-enterprise
#   sudo apparmor_parser -r /etc/apparmor.d/honeyclaw-enterprise
#
# Use with Docker:
#   docker run --security-opt apparmor=honeyclaw-enterprise ...

#include <tunables/global>

profile honeyclaw-enterprise flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/python>

  # Capabilities needed for multi-service simulation
  capability net_bind_service,
  capability setuid,
  capability setgid,
  capability chown,
  capability dac_override,

  # Network: TCP and UDP
  network inet tcp,
  network inet6 tcp,
  network inet udp,
  network inet6 udp,

  # Deny raw sockets
  deny network raw,
  deny network packet,

  # System binaries needed by services
  /usr/** rix,
  /bin/** rix,
  /sbin/** rix,
  /lib/** r,
  /lib64/** r,

  # Python runtime
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,
  /usr/local/lib/python*/** r,

  # Node.js runtime
  /usr/bin/node rix,
  /usr/local/bin/node rix,

  # Supervisor - process manager
  /usr/bin/supervisord ix,
  /usr/bin/supervisorctl ix,
  /usr/local/bin/supervisord rix,
  /etc/supervisor/** r,
  /var/run/supervisor/ rw,
  /var/run/supervisor/** rw,
  /var/log/supervisor/** rw,

  # SSH service
  /usr/sbin/sshd ix,
  /etc/ssh/** r,
  /run/sshd/ rw,
  /run/sshd/** rw,

  # Nginx web server
  /usr/sbin/nginx ix,
  /etc/nginx/** r,
  /var/www/html/** r,
  /var/lib/nginx/** rw,
  /run/nginx.pid rw,

  # Samba (SMB)
  /usr/sbin/smbd ix,
  /usr/sbin/nmbd ix,
  /etc/samba/** r,
  /shares/** r,
  /var/lib/samba/** rw,
  /var/run/samba/** rw,
  /var/cache/samba/** rw,
  /var/log/samba/** rw,

  # Application code (read-only)
  /app/** r,

  # Config files for services
  /etc/ssh/sshd_config r,

  # HoneyClaw service simulators
  /opt/honeyclaw/** r,
  /opt/honeyclaw/services/*.py ix,
  /opt/honeyclaw/logger/*.py ix,
  /opt/honeyclaw/templates/enterprise-sim/** r,

  # General config files
  /etc/ld.so.cache r,
  /etc/ld.so.preload r,
  /etc/nsswitch.conf r,
  /etc/ssl/** r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/localtime r,
  /etc/passwd r,
  /etc/group r,
  /etc/shadow r,
  /etc/hostname r,

  # Data directory
  /data/ rw,
  /data/** rw,

  # Logging - write access to honeypot log directory
  /var/log/honeypot/** rw,
  /var/log/honeypot/ r,
  /var/log/honeyclaw/** rw,
  /var/lib/honeyclaw/** rw,

  # Service runtime directories
  /var/run/** rw,
  /var/log/** rw,
  /tmp/ rw,
  /tmp/** rw,
  /var/tmp/** rw,
  /run/** rw,

  # Fake files served to attackers
  /app/fake-files/** r,

  # /proc and /sys - limited read access for monitoring
  @{PROC}/sys/kernel/random/uuid r,
  @{PROC}/sys/kernel/hostname r,
  @{PROC}/meminfo r,
  @{PROC}/cpuinfo r,
  @{PROC}/self/fd/ r,
  @{PROC}/self/maps r,
  @{PROC}/stat r,
  @{PROC}/uptime r,
  @{PROC}/loadavg r,
  @{PROC}/filesystems r,
  @{PROC}/net/tcp r,
  @{PROC}/net/tcp6 r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/@{pid}/cmdline r,
  @{PROC}/@{pid}/stat r,
  owner @{PROC}/self/status r,
  owner @{PROC}/[0-9]*/stat r,
  owner @{PROC}/[0-9]*/status r,
  /proc/sys/net/** r,

  # Deny sensitive filesystem areas
  deny /root/** rw,
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
  deny capability sys_time,

  # Signal handling - supervisor needs to manage child processes
  signal (send,receive) peer=honeyclaw-enterprise,
  signal (send) peer=unconfined,
}
