#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

versions=("3.12" "3.13" "3.14" "3.15")

uv python install "${versions[@]}"

rm -rf artifacts
mkdir -p artifacts

for version in "${versions[@]}"; do
  tag="${version/./}"

  echo "==> Building Python ${version}"

  rm -rf build dist .venv

  nix develop -c env UV_PYTHON="${version}" uv build --wheel

  mkdir -p "artifacts/py${tag}"
  cp dist/*.whl "artifacts/py${tag}/"

  echo "==> Built artifacts/py${tag}"
done

echo "==> Done"
find artifacts -type f
