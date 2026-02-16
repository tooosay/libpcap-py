project_root := justfile_directory()
python_module_name := "libpcap-py"

default:
   just --list

build:
    uv run python -m build

install:
    uv pip install --force-reinstall {{project_root}}/dist/*.whl --python {{project_root}}/.venv

uninstall:
    uv pip uninstall {{python_module_name}}

build-test:
    uv run python -u {{project_root}}/build_test/test.py

clean:
    rm -rf {{project_root}}/dist
    uv pip uninstall {{python_module_name}}

clean-uv:
    rm -rf {{project_root}}/.venv {{project_root}}/.dist {{project_root}}/uv.lock

uv:
    UV_NO_CACHE=1 UV_NO_EDITABLE=1 UV_PROJECT_ENVIRONMENT={{project_root}}/.venv uv sync