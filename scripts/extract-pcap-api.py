#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
import subprocess
import shlex

from clang.cindex import Config, Cursor, CursorKind, Index, TranslationUnit
import traceback


def configure_libclang() -> None:
    libclang = os.environ.get("LIBCLANG_PATH")
    if libclang:
        Config.set_library_file(libclang)


def walk(cursor: Cursor):
    yield cursor
    for child in cursor.get_children():
        yield from walk(child)


def is_from_pcap_header(cursor: Cursor) -> bool:
    if cursor.location.file is None:
        return False

    path = str(cursor.location.file)

    return path.endswith("/pcap/pcap.h") or path.endswith("/pcap.h")


def pkg_config_cflags(package: str) -> list[str]:
    try:
        out = subprocess.check_output(
            ["pkg-config", "--cflags", package],
            text=True,
        ).strip()
        return shlex.split(out)
    except Exception:
        return []


def extract_functions(include_arg: str = "#include <pcap.h>") -> list[dict[str, Any]]:
    configure_libclang()

    index = Index.create()

    source = "extract_pcap_api.c"

    args = [
        "-x",
        "c",
        "-std=gnu2x",
    ]

    if libc_include_dir := os.environ.get("LIBC_INCLUDE_DIR"):
        args.append(f"-I{libc_include_dir}")

    if nix_cflags := os.environ.get("NIX_CFLAGS_COMPILE"):
        args.extend(shlex.split(nix_cflags))

    args.extend(pkg_config_cflags("libpcap"))

    tu = None
    try:
        tu = index.parse(
            source,
            args=args,
            unsaved_files=[(source, include_arg + "\n")],
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except Exception as e:
        traceback.print_exc(e)
        return 1

    # parse error確認
    for diag in tu.diagnostics:
        if diag.severity >= diag.Error:
            print(diag, file=sys.stderr)

    funcs: dict[str, dict[str, Any]] = {}

    for cursor in walk(tu.cursor):
        if cursor.kind != CursorKind.FUNCTION_DECL:
            continue

        if not cursor.spelling.startswith(("pcap_", "bpf_")):
            continue

        if not is_from_pcap_header(cursor):
            continue

        args_info = []
        for i, arg in enumerate(cursor.get_arguments()):
            args_info.append(
                {
                    "name": arg.spelling or f"arg{i}",
                    "type": arg.type.spelling,
                }
            )

        funcs[cursor.spelling] = {
            "name": cursor.spelling,
            "return_type": cursor.result_type.spelling,
            "args": args_info,
            "is_variadic": cursor.type.is_function_variadic(),
            "location": str(cursor.location.file),
            "line": cursor.location.line,
        }

    return sorted(funcs.values(), key=lambda x: x["name"])


def main() -> None:
    funcs = extract_functions()
    try:
        print(json.dumps(funcs, indent=2, ensure_ascii=False))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(0)


if __name__ == "__main__":
    main()
