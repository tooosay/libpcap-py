#!/usr/bin/env bash
set -euo pipefail

versions=("3.10" "3.11" "3.12" "3.13")

uv python install "${versions[@]}"

rm -rf artifacts
mkdir -p artifacts

for version in "${versions[@]}"; do
  tag="${version/./}"

  echo "==> Building Python ${version}"

  rm -rf build dist .venv

  UV_PYTHON="${version}" nix develop -c uv build --wheel

  mkdir -p "artifacts/py${tag}"
  cp dist/*.whl "artifacts/py${tag}/"

  echo "==> Built artifacts/py${tag}"
done

echo "==> Done"
find artifacts -type f
