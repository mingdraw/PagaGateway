#!/usr/bin/env bash
set -euo pipefail

version="${1:-dev}"
if [[ ! "$version" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo 'Version must use letters, digits, dot, underscore or hyphen' >&2
  exit 1
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
mkdir -p dist
for platform in linux darwin windows; do
  for arch in amd64 arm64; do
    name="pagagateway_${version}_${platform}_${arch}"
    staging="dist/$name"
    mkdir -p "$staging"
    extension=''
    if [[ "$platform" == windows ]]; then extension='.exe'; fi
    CGO_ENABLED=0 GOOS="$platform" GOARCH="$arch" go build -trimpath \
      -ldflags "-s -w -X main.version=$version" -o "$staging/pagagateway$extension" ./cmd/pagagateway
    cp README.md LICENSE "$staging/"
    cp -R examples "$staging/"
    cp -R docs "$staging/"
    if [[ "$platform" == windows ]]; then
      (cd dist && zip -qr "$name.zip" "$name")
    else
      tar -czf "dist/$name.tar.gz" -C dist "$name"
    fi
    rm -r "$staging"
  done
done
if command -v sha256sum >/dev/null 2>&1; then
  (cd dist && sha256sum pagagateway_"$version"_*.tar.gz pagagateway_"$version"_*.zip > checksums.txt)
else
  (cd dist && shasum -a 256 pagagateway_"$version"_*.tar.gz pagagateway_"$version"_*.zip > checksums.txt)
fi
