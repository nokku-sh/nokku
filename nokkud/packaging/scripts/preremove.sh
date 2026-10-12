#!/bin/sh
set -e

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Upgrades call this too (Debian "upgrade", RPM 1), and stopping then would leave the host without nokkud.
if [ "$1" != "0" ] && [ "$1" != "remove" ] && [ ! -f /etc/alpine-release ]; then
	exit 0
fi

if has_cmd systemctl && [ -f /usr/lib/systemd/system/nokkud.service ]; then
	systemctl disable --now nokkud.service >/dev/null 2>&1 || true
fi

if has_cmd rc-update && [ -f /etc/init.d/nokkud ]; then
	rc-service nokkud stop >/dev/null 2>&1 || true
	rc-update del nokkud default >/dev/null 2>&1 || true
fi
