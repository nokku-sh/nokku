#!/bin/sh
# Installs nk, the Nokku CLI.
#
#   curl -fsSL https://get.nokku.sh/nk | sh
#   curl -fsSL https://get.nokku.sh/nk | sh -s -- --version 1.2.3
#
# On Linux this installs the distro package (deb, rpm, apk) from the
# Cloudsmith repository. macOS, other distros, machines without root and
# pinned versions (--version 1.2.3 or NK_VERSION=1.2.3) get the release binary
# from GitHub, in ~/.local/bin or with --system in /usr/local/bin.
# Windows has its own installer: irm https://get.nokku.sh/nk.ps1 | iex
set -eu

REPO="https://dl.cloudsmith.io/public/nokku/nk"
RELEASES="https://github.com/nokku-sh/nokku/releases"
GPG_KEY="gpg.2558AB0D27507F7B.key"
APK_KEY="rsa.29939CA19815BA87.key"
# apk looks the key up by this name, it is part of the package signature.
APK_KEY_NAME="nk@nokku-29939CA19815BA87.rsa.pub"
VERSION="${NK_VERSION:-}"
SYSTEM=false

die() {
	echo "error: $*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$1" "$2"; }

can_root() { [ "$(id -u)" -eq 0 ] || have sudo; }

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		have sudo || die "sudo is required for this step"
		sudo -E "$@"
	fi
}

sha256() {
	if have sha256sum; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

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
	got=$(sha256 "$1")
	[ -n "$want" ] || die "$1 is not listed in checksums.txt"
	[ "$want" = "$got" ] || die "checksum mismatch for $1"
}

install_binary() {
	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "no installer for $(uname -s), binaries are at $RELEASES" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	riscv64) arch=riscv64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
	esac
	# A shell under Rosetta reports x86_64 on Apple silicon.
	if [ "$os" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then
		arch=arm64
	fi

	url="$RELEASES/latest/download"
	[ -z "$VERSION" ] || url="$RELEASES/download/v$VERSION"
	binary="nk_${os}_${arch}"

	echo "Downloading $binary..."
	fetch "$binary" "$url/$binary" || die "could not download $binary from $url"
	verify "$binary"
	chmod 0755 "$binary"

	dir="$HOME/.local/bin"
	as=""
	if [ "$SYSTEM" = true ]; then
		dir=/usr/local/bin
		as=as_root
	fi
	# Copy next to the target and rename, so nk is never half written.
	$as mkdir -p "$dir"
	$as cp "$binary" "$dir/.nk.new"
	$as mv -f "$dir/.nk.new" "$dir/nk"

	case ":$PATH:" in
	*":$dir:"*) ;;
	*) echo "Add $dir to your PATH." ;;
	esac
}

install_deb() {
	list=/etc/apt/sources.list.d/nokku-nk.list
	fetch key "$REPO/$GPG_KEY" || die "could not download the repository key"
	echo "deb [signed-by=/usr/share/keyrings/nokku-nk.asc] $REPO/deb/debian any-version main" >repo
	as_root install -D -m 0644 key /usr/share/keyrings/nokku-nk.asc
	as_root install -m 0644 repo "$list"
	# Only this repository is refreshed, a broken third-party one must not stop the install.
	as_root apt-get update -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
	as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nk
}

install_rpm() {
	dir=/etc/yum.repos.d
	have dnf || have yum || dir=/etc/zypp/repos.d
	cat >repo <<EOF
[nokku-nk]
name=nokku-nk
baseurl=$REPO/rpm/any-distro/any-version/\$basearch
gpgkey=$REPO/$GPG_KEY
gpgcheck=1
repo_gpgcheck=1
enabled=1
metadata_expire=300
EOF
	as_root install -m 0644 repo "$dir/nokku-nk.repo"
	# Other repositories are left out, Fedora ships an unrelated nk that dnf would pick.
	if have dnf; then
		as_root dnf install -y --disablerepo='*' --enablerepo=nokku-nk nk
	elif have yum; then
		as_root yum install -y --disablerepo='*' --enablerepo=nokku-nk nk
	else
		as_root zypper --gpg-auto-import-keys --non-interactive install --repo nokku-nk nk
	fi
}

install_apk() {
	fetch key "$REPO/$APK_KEY" || die "could not download the repository key"
	as_root install -m 0644 key "/etc/apk/keys/$APK_KEY_NAME"
	grep -qxF "$REPO/alpine/any-version/main" /etc/apk/repositories ||
		echo "$REPO/alpine/any-version/main" | as_root tee -a /etc/apk/repositories >/dev/null
	as_root apk add --update-cache --upgrade nk
}

# Everything runs from main, so a download that was cut off runs nothing.
main() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--system) SYSTEM=true ;;
		--version)
			[ "$#" -ge 2 ] || die "--version needs a value"
			VERSION="$2"
			shift
			;;
		-h | --help)
			echo "Usage: install.sh [--system] [--version <x.y.z>]"
			exit 0
			;;
		*) die "unknown option: $1" ;;
		esac
		shift
	done
	VERSION="${VERSION#v}"

	have curl || die "curl is required"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cd "$tmp"

	if [ -n "$VERSION" ] || [ "$(uname -s)" != Linux ] || ! can_root; then
		install_binary
	elif have apt-get; then
		install_deb
	elif have dnf || have yum || have zypper; then
		install_rpm
	elif have apk; then
		install_apk
	else
		install_binary
	fi

	echo "nk is installed. Sign in with: nk login"
}

main "$@"
