#!/bin/sh
# clawall installer. No prebuilt binaries — fetches the repo and builds
# from source. Installs Go on the fly if needed.
#
# Usage:
#   curl -fsSL https://littledivy.github.io/clawall/install.sh | sh
#
# Options (env vars):
#   CLAWALL_REPO     — defaults to https://github.com/littledivy/clawall
#   CLAWALL_REF      — git ref to build (default: main)
#   CLAWALL_PREFIX   — install dir (default: $HOME/.local/bin)
#   CLAWALL_GO_VER   — go toolchain version to fetch if `go` missing (default: 1.23.4)
#
# POSIX sh — `pipefail` is bash-only and dash chokes on it, so we rely
# on `set -eu` plus explicit `|| fail` checks at every pipe.

set -eu

REPO="${CLAWALL_REPO:-https://github.com/littledivy/clawall}"
REF="${CLAWALL_REF:-main}"
PREFIX="${CLAWALL_PREFIX:-$HOME/.local/bin}"
GO_VER="${CLAWALL_GO_VER:-1.23.4}"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

OS=$(uname -s)
OS_LC=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) fail "unsupported arch: $ARCH" ;;
esac

case "$OS_LC" in darwin|linux) ;; *) fail "unsupported OS: $OS" ;; esac

need() { command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"; }
need git
need curl
need tar

TMPDIR_GO=""
SRC=""
cleanup() { [ -n "$SRC" ] && rm -rf "$SRC"; [ -n "$TMPDIR_GO" ] && rm -rf "$TMPDIR_GO"; }
trap cleanup EXIT INT TERM

# --- 1. ensure Go ---------------------------------------------------------
if command -v go >/dev/null 2>&1 && go version | grep -qE "go1\.(2[1-9]|[3-9][0-9])"; then
  say "go: $(go version)"
  GO_BIN=$(command -v go)
else
  say "installing go ${GO_VER} (no recent go on PATH)"
  TMPDIR_GO=$(mktemp -d)
  TARBALL="go${GO_VER}.${OS_LC}-${ARCH}.tar.gz"
  curl -fsSL "https://go.dev/dl/${TARBALL}" -o "${TMPDIR_GO}/${TARBALL}" || fail "download go"
  tar -C "$TMPDIR_GO" -xzf "${TMPDIR_GO}/${TARBALL}" || fail "extract go"
  GO_BIN="${TMPDIR_GO}/go/bin/go"
  PATH="${TMPDIR_GO}/go/bin:$PATH"
  export PATH
fi

# --- 2. clone repo --------------------------------------------------------
SRC=$(mktemp -d)
say "fetching ${REPO}@${REF}"
git clone --depth 1 --branch "$REF" "$REPO" "$SRC" >/dev/null 2>&1 || \
  git clone --depth 1 "$REPO" "$SRC" >/dev/null 2>&1 || \
  fail "git clone failed"

# --- 3. build dashboard (if npm available; otherwise skip — gateway still
#       works, dashboard just won't be served until rebuilt) -------------
if command -v npm >/dev/null 2>&1 && [ -d "$SRC/www" ]; then
  say "building dashboard"
  ( cd "$SRC/www" && npm ci --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1 ) || \
    say "dashboard build failed (skipping — gateway still works)"
fi

# --- 4. build clawall -----------------------------------------------------
# go:embed in web.go points at www/dist — must exist or `go build`
# refuses. Drop a placeholder when the npm build was skipped/failed
# so the gateway binary still compiles (CLI subcommands don't need
# the real dashboard).
mkdir -p "$SRC/www/dist"
if [ -z "$(ls -A "$SRC/www/dist" 2>/dev/null)" ]; then
  printf '<!doctype html><html><body><pre>dashboard not built — re-run install.sh on a host with npm</pre></body></html>' > "$SRC/www/dist/index.html"
fi
say "building clawall"
( cd "$SRC" && "$GO_BIN" build -ldflags "-s -w" -o clawall . ) || fail "build failed"

# --- 5. install -----------------------------------------------------------
mkdir -p "$PREFIX"
mv "$SRC/clawall" "$PREFIX/clawall"
chmod +x "$PREFIX/clawall"
say "installed: $PREFIX/clawall"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) printf '\n  add to PATH:  export PATH="%s:$PATH"\n\n' "$PREFIX" ;;
esac

"$PREFIX/clawall" version 2>/dev/null || true
echo
echo "next: clawall join --url <gateway-url>"
