#!/bin/sh
# Installs nk, the Nokku CLI.
#
#   curl -fsSL https://get.nokku.sh/nk | sh
#
# On Linux this installs the distro package (deb, rpm, apk) from the
# Cloudsmith repository. macOS, other distros and pinned versions
# (--version 1.2.3 or NK_VERSION=1.2.3) get the release binary from GitHub,
# in ~/.local/bin or with --system in /usr/local/bin.
set -eu

REPO="https://dl.cloudsmith.io/public/nokku/nk"
RELEASES="https://github.com/nokku-sh/nokku/releases"
VERSION="${NK_VERSION:-}"
SYSTEM=false

die() {
	echo "error: $*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		sudo -E "$@"
	fi
}

# install_binary checks the release binary against the release checksums and
# puts it on the PATH.
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

	url="$RELEASES/latest/download"
	[ -z "$VERSION" ] || url="$RELEASES/download/v$VERSION"
	binary="nk_${os}_${arch}"
	sums="checksums.txt"

	echo "Downloading $binary..."
	cd "$tmp"
	curl -fsSL -O "$url/$binary" -O "$url/$sums" || die "no release at $url"

	# The release signs the checksum file. Without cosign only the download
	# is checked, not where it came from. Every Nokku release is signed by the
	# same shared workflow, so the repository is pinned as well.
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

	want=$(awk -v name="$binary" '$2 == name { print $1 }' "$sums")
	if have sha256sum; then
		got=$(sha256sum "$binary" | cut -d' ' -f1)
	else
		got=$(shasum -a 256 "$binary" | cut -d' ' -f1)
	fi
	[ -n "$want" ] || die "$binary is not listed in $sums"
	[ "$want" = "$got" ] || die "checksum mismatch for $binary"
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

	have nk || echo "Add $dir to your PATH."
}

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

if [ -n "$VERSION" ] || [ "$(uname -s)" != Linux ]; then
	install_binary
elif have apt-get; then
	curl -fsSL "$REPO/gpg.2558AB0D27507F7B.key" -o "$tmp/key"
	echo "deb [signed-by=/usr/share/keyrings/nokku-nk.asc] $REPO/deb/debian any-version main" >"$tmp/repo"
	as_root install -m 0644 "$tmp/key" /usr/share/keyrings/nokku-nk.asc
	as_root install -m 0644 "$tmp/repo" /etc/apt/sources.list.d/nokku-nk.list
	as_root apt-get update
	as_root apt-get install -y nk
elif have dnf || have yum || have zypper; then
	dir=/etc/yum.repos.d
	have dnf || have yum || dir=/etc/zypp/repos.d
	cat >"$tmp/repo" <<EOF
[nokku-nk]
name=nokku-nk
baseurl=$REPO/rpm/any-distro/any-version/\$basearch
gpgkey=$REPO/gpg.2558AB0D27507F7B.key
gpgcheck=1
repo_gpgcheck=1
enabled=1
EOF
	as_root install -m 0644 "$tmp/repo" "$dir/nokku-nk.repo"
	if have dnf; then
		as_root dnf install -y nk
	elif have yum; then
		as_root yum install -y nk
	else
		as_root zypper --gpg-auto-import-keys --non-interactive install nk
	fi
elif have apk; then
	curl -fsSL "$REPO/rsa.29939CA19815BA87.key" -o "$tmp/key"
	as_root install -m 0644 "$tmp/key" /etc/apk/keys/nk@nokku-29939CA19815BA87.rsa.pub
	grep -qxF "$REPO/alpine/any-version/main" /etc/apk/repositories ||
		echo "$REPO/alpine/any-version/main" | as_root tee -a /etc/apk/repositories >/dev/null
	as_root apk add --update-cache nk
else
	install_binary
fi

echo "nk is installed. Sign in with: nk login"
