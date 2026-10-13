#!/bin/sh
# Runs after a package install or upgrade, and at the end of the tarball installer.
set -e

share=/usr/share/nokkud
have() { command -v "$1" >/dev/null 2>&1; }

if [ -d /usr/lib/systemd/system ] && have systemctl; then
	install -m 0644 $share/systemd/nokkud.service /usr/lib/systemd/system/nokkud.service
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl enable nokkud.service >/dev/null 2>&1 || true
	# An upgrade picks up the new binary. Live connections end with the restart.
	systemctl try-restart nokkud.service >/dev/null 2>&1 || true
fi

if have rc-update; then
	install -m 0755 $share/openrc/nokkud.openrc /etc/init.d/nokkud
	rc-update add nokkud default >/dev/null 2>&1 || true
fi

# Firewall definitions only. Opening the port stays the admin's call.
if [ -d /etc/ufw/applications.d ]; then
	install -m 0644 $share/ufw/nokkud /etc/ufw/applications.d/nokkud
	ufw app update nokkud >/dev/null 2>&1 || true
fi

if [ -d /usr/lib/firewalld/services ]; then
	install -m 0644 $share/firewalld/nokkud.xml /usr/lib/firewalld/services/nokkud.xml
	firewall-cmd --reload >/dev/null 2>&1 || true
fi
