#!/bin/sh
set -eu

REPOSITORY="${LATCH_REPOSITORY:-princebabou/Latch}"
INSTALL_DIR="${LATCH_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION="${LATCH_VERSION:-latest}"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "latch installer: required command not found: $1" >&2
    exit 1
  }
}

require curl
require tar
require install

case "$(uname -s)" in
  Linux) release_os="Linux" ;;
  Darwin) release_os="Darwin" ;;
  *)
    echo "latch installer: unsupported operating system: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64) release_arch="amd64" ;;
  arm64|aarch64) release_arch="arm64" ;;
  *)
    echo "latch installer: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ "$REQUESTED_VERSION" = "latest" ]; then
  release_api="https://api.github.com/repos/$REPOSITORY/releases/latest"
else
  case "$REQUESTED_VERSION" in
    v*) release_tag="$REQUESTED_VERSION" ;;
    *) release_tag="v$REQUESTED_VERSION" ;;
  esac
  release_api="https://api.github.com/repos/$REPOSITORY/releases/tags/$release_tag"
fi

curl -fsSL \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "$release_api" -o "$tmp_dir/release.json"

asset_urls="$(
  sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp_dir/release.json"
)"
archive_url="$(
  printf '%s\n' "$asset_urls" |
    grep -Ei "_${release_os}_${release_arch}\.(tar\.gz|zip)$" |
    head -n 1 || true
)"
checksums_url="$(
  printf '%s\n' "$asset_urls" |
    grep '/checksums\.txt$' |
    head -n 1 || true
)"

if [ -z "$archive_url" ] || [ -z "$checksums_url" ]; then
  echo "latch installer: release has no verified archive for ${release_os}/${release_arch}" >&2
  exit 1
fi

archive_name="${archive_url##*/}"
curl -fsSL "$archive_url" -o "$tmp_dir/$archive_name"
curl -fsSL "$checksums_url" -o "$tmp_dir/checksums.txt"

expected="$(
  awk -v name="$archive_name" '$2 == name || $2 == "*" name { print $1; exit }' "$tmp_dir/checksums.txt"
)"
if [ -z "$expected" ]; then
  echo "latch installer: archive is missing from checksums.txt" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp_dir/$archive_name" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$tmp_dir/$archive_name" | awk '{print $1}')"
else
  echo "latch installer: sha256sum or shasum is required" >&2
  exit 1
fi

if [ "$actual" != "$expected" ]; then
  echo "latch installer: checksum verification failed" >&2
  exit 1
fi

mkdir -p "$tmp_dir/unpacked"
case "$archive_name" in
  *.tar.gz) tar -xzf "$tmp_dir/$archive_name" -C "$tmp_dir/unpacked" ;;
  *.zip)
    require unzip
    unzip -q "$tmp_dir/$archive_name" -d "$tmp_dir/unpacked"
    ;;
esac

binary="$(find "$tmp_dir/unpacked" -type f -name latch -print | head -n 1)"
if [ -z "$binary" ]; then
  echo "latch installer: archive did not contain the latch binary" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$binary" "$INSTALL_DIR/latch"

echo "Installed latch to $INSTALL_DIR/latch"
case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add $INSTALL_DIR to PATH to run latch from any directory." ;;
esac
