#!/bin/sh
# Puts down the files a package ships, then runs the package's own post-install step.
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root (sudo ./install.sh)" >&2
	exit 1
fi
cd "$(dirname "$0")"

install -D -m 0755 nokkud /usr/bin/nokkud
install -D -m 0644 nokkud.service /usr/share/nokkud/systemd/nokkud.service
install -D -m 0644 nokkud.openrc /usr/share/nokkud/openrc/nokkud.openrc
install -D -m 0644 nokkud.ufw /usr/share/nokkud/ufw/nokkud
install -D -m 0644 nokkud.firewalld.xml /usr/share/nokkud/firewalld/nokkud.xml
sh ./postinstall.sh
