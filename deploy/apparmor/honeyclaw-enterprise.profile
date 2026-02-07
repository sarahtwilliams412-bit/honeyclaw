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
  network tcp,
  network udp,

  # Python runtime
  /usr/bin/python3* rix,
  /usr/local/bin/python3* rix,
  /usr/lib/python3/** r,
  /usr/local/lib/python3/** r,

  # Service binaries (nginx, samba, sshd - all are honeypot versions)
  /usr/sbin/nginx rix,
  /usr/sbin/sshd rix,
  /usr/sbin/smbd rix,
  /usr/bin/supervisord rix,
  /usr/local/bin/supervisord rix,

  # Application code (read-only)
  /app/** r,

  # Config files for services
  /etc/nginx/** r,
  /etc/ssh/sshd_config r,
  /etc/samba/** r,
  /etc/supervisor/** r,

  # Data directory
  /data/ rw,
  /data/** rw,

  # Service runtime directories
  /var/run/** rw,
  /var/log/** rw,
  /tmp/ rw,
  /tmp/** rw,

  # System files
  /etc/passwd r,
  /etc/group r,
  /etc/shadow r,
  /etc/nsswitch.conf r,
  /etc/resolv.conf r,
  /etc/hosts r,
  /etc/ssl/** r,
  /proc/sys/net/** r,

  # Fake files served to attackers
  /app/fake-files/** r,

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

  # Deny write to critical system paths
  deny /boot/** rw,
  deny /root/** rw,
}
