project_root := justfile_directory()
python_module_name := "libpcap-py"

guard-project-root:
    #!/usr/bin/env bash
    set -euo pipefail

    root="{{ project_root }}"
    [[ -n "$root" ]] || { echo "ERROR: project_root is empty" >&2; exit 1; }
    [[ "$root" != "/"  ]] || { echo "ERROR: project_root must not be '/'" >&2; exit 1; }
    [[ -f "$root/pyproject.toml" ]] || {
        echo "ERROR: '$root' doesn't look like a project root (pyproject.toml missing)" >&2
        exit 1
    }

guard-python-module:
    #!/usr/bin/env bash
    set -euo pipefail
    mod="{{ python_module_name }}"
    [[ ! -z "$mod" ]] || { echo "ERROR: python_module_name is empty" >&2; exit 1; }

default:
    just --list

build:
    uv run python -m build

build-libpcap:
    uv run python -m build -w -Csetup-args=-Dpcap_backend=libpcap

install:
    uv pip install --force-reinstall {{ project_root }}/dist/*.whl --python {{ project_root }}/.venv

uninstall:
    uv pip uninstall {{ python_module_name }}

test *ARGS:
    uv run pytest -m "not online" {{ ARGS }}

build-test:
    uv run python -u {{ project_root }}/build_test/test.py

clean: guard-project-root guard-python-module
    rm -rf {{ project_root }}/dist
    uv pip uninstall {{ python_module_name }}

clean-uv: guard-project-root
    rm -rf {{ project_root }}/.venv {{ project_root }}/.dist {{ project_root }}/uv.lock

clean-all: guard-project-root clean-uv
    rm -rf {{ project_root }}/build {{ project_root }}/.pytest_cache

uv:
    UV_NO_CACHE=1 UV_NO_EDITABLE=1 UV_PROJECT_ENVIRONMENT={{ project_root }}/.venv uv sync

tidy-configure:
  meson setup build-clang -Dbuildtype=debug || meson setup --reconfigure build-clang -Dbuildtype=debug
  ninja -C build-clang

lint-nix:
    deadnix -f .
    statix check .

lint-ruff:
    ruff check .

lint-clang nproc="4": tidy-configure
    run-clang-tidy -p build-clang -j {{nproc}}

vc-current PY="3.10": guard-project-root
    #!/usr/bin/env bash
    set -euo pipefail

    py="{{ PY }}"
    py="${py,,}"
    py="${py#python}"
    py="${py#cp}"
    tag="cp${py//./}"  # 3.10 -> cp310

    buildDir="{{ project_root }}/build"

    if [[ ! -f "${buildDir}/$tag/compile_commands.json" ]]; then
      echo "missing: ${buildDir}/$tag/compile_commands.json"
      echo "hint: run meson once"
      exit 1
    fi

    ln -sfn "$tag" ${buildDir}/current
    echo "${buildDir}/current -> $tag"

vc-rm-current: guard-project-root
    #!/usr/bin/env bash
    set -euo pipefail

    target={{ project_root }}/build/current

    if [[ -L "${target}" ]]; then
      rm -f "${target}"
      echo "removed: ${target}"
      exit 0
    fi

    if [[ -e "${target}" ]]; then
      echo "refuse: ${target} exists but is not a symlink"
      ls -la "${target}" || true
      exit 1
    fi

    echo "${target} not found"
