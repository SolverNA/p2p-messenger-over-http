#!/bin/sh
# Download a release into the user's private cache, verify it, and open the TUI.
set -eu
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
repo=${P2PMESSENGER_REPO:-}
version=${P2PMESSENGER_VERSION:-latest}
case "$repo" in ''|*[!A-Za-z0-9._/-]*) fail 'Set P2PMESSENGER_REPO=OWNER/REPOSITORY.';; esac
case "$repo" in */*) ;; *) fail 'Repository must be OWNER/REPOSITORY.';; esac
owner=${repo%%/*}; project=${repo#*/}
case "$owner/$project" in /*|*/|*/*/*|*/.|*/..) fail 'Invalid repository.';; esac
case "$owner" in .|..) fail 'Invalid repository owner.';; esac
case "$version" in latest) ;; v[0-9]*) case "$version" in *[!A-Za-z0-9._-]*) fail 'Invalid release version.';; esac;; *) fail 'Version must be latest or vNUMBER.';; esac
case "$(uname -s)" in Linux) platform=linux;; Darwin) platform=darwin;; *) fail 'Unsupported OS; on Windows use run.ps1.';; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) fail 'Supported architectures: x86_64 and arm64.';; esac
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
if command -v sha256sum >/dev/null 2>&1; then hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then hash_tool=shasum
else fail 'sha256sum or shasum is required.'; fi
asset=p2pmessenger-$platform-$arch
if [ "$version" = latest ]; then base=https://github.com/$repo/releases/latest/download
else base=https://github.com/$repo/releases/download/$version; fi
cache=${XDG_CACHE_HOME:-$HOME/.cache}/p2pmessenger
mkdir -p "$cache"
chmod 700 "$cache"
work=$(mktemp -d "$cache/launch.XXXXXXXX")
cleanup() { rm -f "$work/$asset" "$work/SHA256SUMS"; rmdir "$work" 2>/dev/null || :; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
download() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 300 --retry 2 "$1" -o "$2"; }
printf 'Downloading %s (%s)…\n' "$asset" "$version" >&2
download "$base/SHA256SUMS" "$work/SHA256SUMS"
download "$base/$asset" "$work/$asset"
expected=$(awk -v file="$asset" '$2 == file { print $1 }' "$work/SHA256SUMS")
[ "${#expected}" -eq 64 ] || fail 'Missing or ambiguous checksum.'
case "$expected" in *[!0-9a-f]*) fail 'Invalid checksum.';; esac
if [ "$hash_tool" = sha256sum ]; then actual=$(sha256sum "$work/$asset" | awk '{print $1}')
else actual=$(shasum -a 256 "$work/$asset" | awk '{print $1}'); fi
[ "$actual" = "$expected" ] || fail 'Checksum mismatch; nothing was executed.'
chmod 700 "$work/$asset"
# A curl | sh pipeline consumes stdin. Reopen the real terminal for the TUI.
needs_tty=1
for arg do
    case "$arg" in --help|-help|-h|--headless|--status|--send) needs_tty=0;; esac
done
if [ ! -t 0 ] && [ "$needs_tty" -eq 1 ]; then
    [ -r /dev/tty ] || fail 'Open an interactive terminal to run the messenger.'
    "$work/$asset" "$@" </dev/tty
else
    "$work/$asset" "$@"
fi
