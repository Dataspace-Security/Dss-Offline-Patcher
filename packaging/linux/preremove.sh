#!/bin/sh
# Stop the service on removal (the enrolled identity in /var/lib/offpatch is
# kept; retire the endpoint in the console to revoke it).
case "$1" in
  remove|0) /usr/sbin/pmagent service uninstall >/dev/null 2>&1 || true ;;
esac
exit 0
