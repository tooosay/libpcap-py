#!/usr/bin/env python3
"""Check that README's supported-function list matches the X-macro list."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
XMACRO_PATH = REPO_ROOT / "src/libpcap_py/_pcap/include/pycap_methods.inc"
README_PATH = REPO_ROOT / "README.md"

XMACRO_RE = re.compile(r'^X\((?P<impl>[01]),\s*(?P<kind>[A-Z_]+),\s*(?P<name>[A-Za-z0-9_]+),\s*"(?P<doc>.*)"\)$')
README_SECTION_RE = re.compile(r"^## Supported Functions \[\d+/\d+\]\[\d+%\]\s*$")


@dataclass(frozen=True)
class FunctionEntry:
    name: str
    implemented: bool


def c_name_from_xmacro_name(name: str) -> str:
    if name.startswith(("pcap_", "bpf_")):
        return name

    return f"pcap_{name}"


def parse_xmacro(path: Path) -> list[FunctionEntry]:
    entries: list[FunctionEntry] = []
    seen: dict[str, int] = {}

    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or not stripped.startswith("X("):
            continue

        match = XMACRO_RE.match(stripped)
        if not match:
            raise SystemExit(f"{path}:{lineno}: malformed X-macro entry: {line}")

        name = c_name_from_xmacro_name(match.group("name"))
        if name in seen:
            raise SystemExit(f"{path}:{lineno}: duplicate function {name}; first seen on line {seen[name]}")

        seen[name] = lineno
        entries.append(FunctionEntry(name=name, implemented=match.group("impl") == "1"))

    if not entries:
        raise SystemExit(f"{path}: no X-macro entries found")

    return entries


def find_readme_supported_functions_section(lines: list[str]) -> tuple[int, int]:
    start = None

    for index, line in enumerate(lines):
        if README_SECTION_RE.match(line):
            start = index
            break

    if start is None:
        raise SystemExit(f"{README_PATH}: supported-functions section header not found")

    end = start + 1
    while end < len(lines):
        if lines[end].startswith("## "):
            break
        end += 1

    return start, end


def render_supported_functions_section(entries: list[FunctionEntry]) -> list[str]:
    implemented = sum(entry.implemented for entry in entries)
    total = len(entries)
    percent = round((implemented / total) * 100) if total else 0

    lines = [f"## Supported Functions [{implemented}/{total}][{percent}%]\n"]
    lines.extend(f"- [{'X' if entry.implemented else ' '}] {entry.name}\n" for entry in entries)
    lines.append("\n")

    return lines


def check_or_update(*, update: bool) -> int:
    entries = parse_xmacro(XMACRO_PATH)
    readme_lines = README_PATH.read_text(encoding="utf-8").splitlines(keepends=True)
    section_start, section_end = find_readme_supported_functions_section(readme_lines)
    current_section = readme_lines[section_start:section_end]
    expected_section = render_supported_functions_section(entries)

    if current_section == expected_section:
        return 0

    if update:
        new_readme_lines = readme_lines[:section_start] + expected_section + readme_lines[section_end:]
        README_PATH.write_text("".join(new_readme_lines), encoding="utf-8")
        return 0

    sys.stderr.writelines(
        difflib.unified_diff(
            current_section,
            expected_section,
            fromfile=str(README_PATH),
            tofile=f"{README_PATH} (expected)",
        )
    )
    print(
        f"\n{README_PATH}: supported-functions list is out of sync with {XMACRO_PATH}.\n"
        "Run: python3 scripts/check-readme-functions.py --update",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite README.md's supported-functions section from the X-macro list",
    )
    args = parser.parse_args()

    return check_or_update(update=args.update)


if __name__ == "__main__":
    raise SystemExit(main())
