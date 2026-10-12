#!/bin/sh
# Builds enclave.swift into a universal static library for cgo to link.
# Needs the Xcode command line tools. Run before: go build -tags enclave
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
	echo "the Secure Enclave bridge only builds on macOS" >&2
	exit 1
fi

cd "$(dirname "$0")"
mkdir -p build

for arch in arm64 x86_64; do
	# No compatibility libraries, cgo could not find them and this code
	# uses nothing they backport.
	xcrun swiftc -O -parse-as-library -static -emit-library \
		-module-name nkenclave \
		-runtime-compatibility-version none \
		-target "$arch-apple-macos13" \
		-o "build/libnkenclave-$arch.a" enclave.swift
done

xcrun lipo -create build/libnkenclave-arm64.a build/libnkenclave-x86_64.a \
	-output build/libnkenclave.a
