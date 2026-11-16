#!/usr/bin/env bash
# Point Formula/sec-audit.rb at a released tag, then prove the formula's own
# build and test steps work on that tag's source tarball.
#
# Usage: scripts/bump-formula.sh <version>     e.g. 0.2.1 or v0.2.1
#
# Exit 0 means the formula names the tag tarball with its real sha256 and a
# binary built the way Homebrew builds it reports <version> and passes
# `sec-audit demo`. The file is rewritten only if url or sha256 changed.
set -euo pipefail

ver="${1:?usage: $0 <version>}"
ver="${ver#v}"
if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "invalid version: $ver" >&2
  exit 1
fi

repo="${GITHUB_REPOSITORY:-fabriziosalmi/security-audit-cli}"
formula="$(cd "$(dirname "$0")/.." && pwd)/Formula/sec-audit.rb"
url="https://github.com/${repo}/archive/refs/tags/v${ver}.tar.gz"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# GitHub builds source archives on demand; a hash that differs between two
# downloads would break every brew install, so require them to agree.
curl -fsSL --retry 3 -o "$work/a.tar.gz" "$url"
curl -fsSL --retry 3 -o "$work/b.tar.gz" "$url"
sha="$(sha256 "$work/a.tar.gz")"
if [ "$sha" != "$(sha256 "$work/b.tar.gz")" ]; then
  echo "two downloads of $url hash differently; refusing to pin either" >&2
  exit 1
fi

sed -E -i.bak \
  -e "s|^  url \"[^\"]*\"$|  url \"${url}\"|" \
  -e "s|^  sha256 \"[^\"]*\"$|  sha256 \"${sha}\"|" \
  "$formula"
rm -f "$formula.bak"
grep -qxF "  url \"${url}\"" "$formula" || { echo "url line not found in $formula" >&2; exit 1; }
grep -qxF "  sha256 \"${sha}\"" "$formula" || { echo "sha256 line not found in $formula" >&2; exit 1; }

# Same build and test as the formula: std_go_args adds -trimpath.
mkdir "$work/src"
tar -xzf "$work/a.tar.gz" -C "$work/src" --strip-components 1
(cd "$work/src" && go build -trimpath -ldflags "-s -w -X main.Version=${ver}" -o "$work/sec-audit" ./cmd/sec-audit)
"$work/sec-audit" version --format text | grep -qF "sec-audit ${ver} "
"$work/sec-audit" demo --dir "$work/demo" >/dev/null
test -f "$work/demo/run/REPORT.md"

echo "Formula/sec-audit.rb -> v${ver} (sha256 ${sha}); build, version and demo verified"
