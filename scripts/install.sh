#!/bin/sh
# ANAL installer.
#
# Data arrives, in order, with consent. This script downloads the `anal`
# binary for your platform from the latest GitHub Release, verifies its
# SHA-256, and inserts it into your PATH.
#
# Environment overrides:
#   ANAL_VERSION       Tag to install (default: latest, e.g. v0.1.0).
#   ANAL_INSTALL_DIR   Destination directory (default: $HOME/.local/bin).
#   ANAL_NO_MODIFY_PATH=1   Skip PATH-hint message.

set -eu

REPO="1xn/anal"
BIN="anal"

say()  { printf '%s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf 'EVACUATE: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need uname
need mktemp
need tar

# Prefer curl, fall back to wget.
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q "$1" -O "$2"; }
  fetch_stdout() { wget -q "$1" -O -; }
else
  die "need curl or wget"
fi

# --- detect target ----------------------------------------------------------

os_raw="$(uname -s)"
arch_raw="$(uname -m)"

case "$os_raw" in
  Linux)  os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) die "unsupported OS: $os_raw (use install.ps1 on Windows)" ;;
esac

case "$arch_raw" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch_raw" ;;
esac

TARGET="${arch}-${os}"

# --- pick version -----------------------------------------------------------

VERSION="${ANAL_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "PREP install"
  note "asking GitHub for the latest tag..."
  VERSION="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$VERSION" ] || die "could not determine latest version"
else
  say "PREP install"
  note "version pinned: $VERSION"
fi

VERSION_BARE="${VERSION#v}"
NAME="anal-${VERSION_BARE}-${TARGET}"
ASSET="${NAME}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
SUM_URL="${URL}.sha256"

note "target: ${TARGET}"
note "asset:  ${ASSET}"

# --- consent --------------------------------------------------------------

say ""
say "CONSENT install"
note "will fetch:  ${URL}"

INSTALL_DIR="${ANAL_INSTALL_DIR:-$HOME/.local/bin}"
note "will insert: ${INSTALL_DIR}/${BIN}"
say ""

# --- fetch + verify + insert -----------------------------------------------

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t anal-install)"
trap 'rm -rf "$tmp"' EXIT

say "INSERT ${BIN}"
note "downloading..."
fetch "$URL"     "${tmp}/${ASSET}"
fetch "$SUM_URL" "${tmp}/${ASSET}.sha256"

note "verifying checksum..."
if command -v shasum >/dev/null 2>&1; then
  (cd "$tmp" && shasum -a 256 -c "${ASSET}.sha256" >/dev/null) \
    || die "checksum mismatch — refusing insertion"
elif command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c "${ASSET}.sha256" >/dev/null) \
    || die "checksum mismatch — refusing insertion"
else
  note "no shasum/sha256sum available; skipping verification (not recommended)"
fi

note "unpacking..."
tar -xzf "${tmp}/${ASSET}" -C "$tmp"

mkdir -p "$INSTALL_DIR"
mv "${tmp}/${NAME}/${BIN}" "${INSTALL_DIR}/${BIN}"
chmod +x "${INSTALL_DIR}/${BIN}"

say ""
say "EXPEL"
note "installed ${VERSION} to ${INSTALL_DIR}/${BIN}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    if [ -z "${ANAL_NO_MODIFY_PATH:-}" ]; then
      say ""
      note "${INSTALL_DIR} is not on your PATH. Add this to your shell profile:"
      note "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
    ;;
esac

say ""
note "try it:  ${BIN} --help"
