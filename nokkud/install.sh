#!/bin/sh
# Installs nokkud, the Nokku edge daemon.
#
#   curl -fsSL https://get.nokku.sh/nokkud | sudo sh
#
# Installs the distro package (deb, rpm, apk) from the Cloudsmith repository.
# Other distros and pinned versions (--version 1.2.3 or NOKKUD_VERSION=1.2.3)
# get the release tarball from GitHub.
set -eu

REPO="https://dl.cloudsmith.io/public/nokku/nokkud"
RELEASES="https://github.com/nokku-sh/nokku/releases"
VERSION="${NOKKUD_VERSION:-}"

die() {
	echo "error: $*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

install_tarball() {
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	riscv64) arch=riscv64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
	esac

	url="$RELEASES/latest/download"
	[ -z "$VERSION" ] || url="$RELEASES/download/v$VERSION"
	tarball="nokkud_linux_$arch.tar.gz"
	sums="checksums.txt"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cd "$tmp"

	echo "Downloading $tarball..."
	curl -fsSL -O "$url/$tarball" -O "$url/$sums" || die "no release at $url"

	# Without cosign only the download is checked, not where it came from. The repository is pinned too.
	if have cosign; then
		curl -fsSL -O "$url/$sums.sigstore.json"
		cosign verify-blob --bundle "$sums.sigstore.json" \
			--certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com \
			--certificate-github-workflow-repository nokku-sh/nokku \
			"$sums" || die "the signature on $sums is not valid"
	else
		echo "note: cosign is not installed, the release signature is not checked" >&2
	fi

	want=$(awk -v name="$tarball" '$2 == name { print $1 }' "$sums")
	got=$(sha256sum "$tarball" | cut -d' ' -f1)
	[ -n "$want" ] || die "$tarball is not listed in $sums"
	[ "$want" = "$got" ] || die "checksum mismatch for $tarball"

	tar -xzf "$tarball"
	sh ./install.sh
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version)
		[ "$#" -ge 2 ] || die "--version needs a value"
		VERSION="$2"
		shift
		;;
	-h | --help)
		echo "Usage: install.sh [--version <x.y.z>]"
		exit 0
		;;
	*) die "unknown option: $1" ;;
	esac
	shift
done
VERSION="${VERSION#v}"

[ "$(uname -s)" = Linux ] || die "nokkud runs on Linux only"
[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL https://get.nokku.sh/nokkud | sudo sh"
have curl || die "curl is required"

if [ -n "$VERSION" ]; then
	install_tarball
elif have apt-get; then
	curl -fsSL "$REPO/gpg.DE69C459F5C4C71B.key" -o /usr/share/keyrings/nokku-nokkud.asc
	echo "deb [signed-by=/usr/share/keyrings/nokku-nokkud.asc] $REPO/deb/debian any-version main" \
		>/etc/apt/sources.list.d/nokku-nokkud.list
	apt-get update
	apt-get install -y nokkud
elif have dnf || have yum || have zypper; then
	dir=/etc/yum.repos.d
	have dnf || have yum || dir=/etc/zypp/repos.d
	cat >"$dir/nokku-nokkud.repo" <<EOF
[nokku-nokkud]
name=nokku-nokkud
baseurl=$REPO/rpm/any-distro/any-version/\$basearch
gpgkey=$REPO/gpg.DE69C459F5C4C71B.key
gpgcheck=1
repo_gpgcheck=1
enabled=1
EOF
	if have dnf; then
		dnf install -y nokkud
	elif have yum; then
		yum install -y nokkud
	else
		zypper --gpg-auto-import-keys --non-interactive install nokkud
	fi
elif have apk; then
	curl -fsSL "$REPO/rsa.6B8A412616F12677.key" -o /etc/apk/keys/nokkud@nokku-6B8A412616F12677.rsa.pub
	grep -qxF "$REPO/alpine/any-version/main" /etc/apk/repositories ||
		echo "$REPO/alpine/any-version/main" >>/etc/apk/repositories
	apk add --update-cache nokkud
else
	install_tarball
fi

echo "nokkud is installed. Enroll this host with: nokkud enroll"
