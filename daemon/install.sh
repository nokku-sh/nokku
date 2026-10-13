#!/bin/sh
# Installs nokkud, the Nokku edge daemon.
#
#   curl -fsSL https://get.nokku.sh/nokkud | sudo sh
#   curl -fsSL https://get.nokku.sh/nokkud | sudo sh -s -- --version 1.2.3
#
# Installs the distro package (deb, rpm, apk) from the Cloudsmith repository.
# Other distros and pinned versions (--version 1.2.3 or NOKKUD_VERSION=1.2.3)
# get the release tarball from GitHub.
set -eu

REPO="https://dl.cloudsmith.io/public/nokku/nokkud"
RELEASES="https://github.com/nokku-sh/nokku/releases"
GPG_KEY="gpg.DE69C459F5C4C71B.key"
APK_KEY="rsa.6B8A412616F12677.key"
# apk looks the key up by this name, it is part of the package signature.
APK_KEY_NAME="nokkud@nokku-6B8A412616F12677.rsa.pub"
VERSION="${NOKKUD_VERSION:-}"

die() {
	echo "error: $*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$1" "$2"; }

# verify checks a downloaded release file against the release checksums.
verify() {
	fetch checksums.txt "$url/checksums.txt" || die "could not download checksums.txt from $url"

	# The release signs the checksum file. Without cosign only the download
	# is checked, not where it came from. Every Nokku release is signed by the
	# same shared workflow, so the repository is pinned as well.
	if have cosign; then
		fetch checksums.txt.sigstore.json "$url/checksums.txt.sigstore.json" ||
			die "could not download the signature of checksums.txt"
		cosign verify-blob --bundle checksums.txt.sigstore.json \
			--certificate-identity https://github.com/nokku-sh/.github/.github/workflows/go-release.yaml@refs/heads/main \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com \
			--certificate-github-workflow-repository nokku-sh/nokku \
			checksums.txt || die "the signature on checksums.txt is not valid (cosign older than 3 cannot read it)"
	else
		echo "note: cosign is not installed, the release signature is not checked" >&2
	fi

	want=$(awk -v name="$1" '$2 == name { print $1 }' checksums.txt)
	got=$(sha256sum "$1" | cut -d' ' -f1)
	[ -n "$want" ] || die "$1 is not listed in checksums.txt"
	[ "$want" = "$got" ] || die "checksum mismatch for $1"
}

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

	echo "Downloading $tarball..."
	fetch "$tarball" "$url/$tarball" || die "could not download $tarball from $url"
	verify "$tarball"

	tar -xzf "$tarball"
	sh ./install.sh
}

install_deb() {
	list=/etc/apt/sources.list.d/nokku-nokkud.list
	fetch key "$REPO/$GPG_KEY" || die "could not download the repository key"
	install -D -m 0644 key /usr/share/keyrings/nokku-nokkud.asc
	echo "deb [signed-by=/usr/share/keyrings/nokku-nokkud.asc] $REPO/deb/debian any-version main" >"$list"
	# Only this repository is refreshed, a broken third-party one must not stop the install.
	apt-get update -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
	DEBIAN_FRONTEND=noninteractive apt-get install -y nokkud
}

install_rpm() {
	dir=/etc/yum.repos.d
	have dnf || have yum || dir=/etc/zypp/repos.d
	cat >"$dir/nokku-nokkud.repo" <<EOF
[nokku-nokkud]
name=nokku-nokkud
baseurl=$REPO/rpm/any-distro/any-version/\$basearch
gpgkey=$REPO/$GPG_KEY
gpgcheck=1
repo_gpgcheck=1
enabled=1
metadata_expire=300
EOF
	# Only this repository is used, a broken third-party one must not stop the install.
	if have dnf; then
		dnf install -y --disablerepo='*' --enablerepo=nokku-nokkud nokkud
	elif have yum; then
		yum install -y --disablerepo='*' --enablerepo=nokku-nokkud nokkud
	else
		zypper --gpg-auto-import-keys --non-interactive install --repo nokku-nokkud nokkud
	fi
}

install_apk() {
	fetch key "$REPO/$APK_KEY" || die "could not download the repository key"
	install -m 0644 key "/etc/apk/keys/$APK_KEY_NAME"
	grep -qxF "$REPO/alpine/any-version/main" /etc/apk/repositories ||
		echo "$REPO/alpine/any-version/main" >>/etc/apk/repositories
	apk add --update-cache --upgrade nokkud
}

# Everything runs from main, so a download that was cut off runs nothing.
main() {
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

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cd "$tmp"

	if [ -n "$VERSION" ]; then
		install_tarball
	elif have apt-get; then
		install_deb
	elif have dnf || have yum || have zypper; then
		install_rpm
	elif have apk; then
		install_apk
	else
		install_tarball
	fi

	echo "nokkud is installed. Enroll this host with: nokkud enroll"
}

main "$@"
