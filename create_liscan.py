#!/usr/bin/env python3
"""Configure and build LiScan without modifying source files.

The old version of this helper deleted the build tree and regenerated the
project from stale templates.  That made it easy to lose local changes and
could produce code that no longer matched the checked-in API.  The historical
filename is kept for compatibility, but this script is now a small, safe
wrapper around CMake.

Examples:

    ./create_liscan.py
    ./create_liscan.py --clean --build-type Debug
    ./create_liscan.py --build-dir out --target libscan_cli

Only a build directory inside the repository may be removed with ``--clean``.
No source, header, or configuration file is generated or overwritten.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def _repo_build_dir(value: str) -> Path:
    """Resolve a build directory and reject paths outside this repository."""

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    root = ROOT.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--build-dir must point inside the project directory"
        ) from exc
    if candidate == root:
        raise argparse.ArgumentTypeError("--build-dir cannot be the project root")
    protected = {
        ".git",
        ".github",
        ".gapcode",
        ".freebuff",
        "include",
        "src",
        "examples",
        "tests",
        "docs",
    }
    relative = candidate.relative_to(root)
    if relative.parts and relative.parts[0] in protected:
        raise argparse.ArgumentTypeError(
            "--build-dir cannot be inside source or repository metadata directories"
        )
    return candidate


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure and build LiScan using the checked-in CMake project."
    )
    parser.add_argument(
        "--build-dir",
        type=_repo_build_dir,
        default=ROOT / "build",
        help="build directory inside the repository (default: build)",
    )
    parser.add_argument(
        "--build-type",
        choices=("Debug", "Release", "RelWithDebInfo", "MinSizeRel"),
        default=None,
        help="CMake build type (single-config generators)",
    )
    parser.add_argument(
        "-G",
        "--generator",
        default=None,
        help="CMake generator to use when configuring",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="build only this CMake target (may be repeated)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove the selected build directory before configuring",
    )
    parser.add_argument(
        "--configure-only",
        action="store_true",
        help="configure but do not invoke cmake --build",
    )
    parser.add_argument(
        "cmake_args",
        nargs=argparse.REMAINDER,
        help="additional arguments passed to CMake configure (after --)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    build_dir: Path = args.build_dir

    if args.clean and build_dir.exists():
        # The path was validated by _repo_build_dir; do not broaden this
        # operation to arbitrary user-provided locations.
        if not build_dir.is_dir() or build_dir.is_symlink():
            print(
                f"error: cannot clean non-directory build path: {build_dir}",
                file=sys.stderr,
            )
            return 2
        shutil.rmtree(build_dir)

    configure = [
        "cmake",
        "-S",
        str(ROOT),
        "-B",
        str(build_dir),
    ]
    if args.generator:
        configure.extend(("-G", args.generator))
    if args.build_type:
        configure.append(f"-DCMAKE_BUILD_TYPE={args.build_type}")
    extra_cmake_args = list(args.cmake_args or [])
    if extra_cmake_args and extra_cmake_args[0] == "--":
        extra_cmake_args.pop(0)
    configure.extend(extra_cmake_args)

    try:
        subprocess.run(configure, check=True)
        if args.configure_only:
            return 0

        build = ["cmake", "--build", str(build_dir)]
        for target in args.target:
            build.extend(("--target", target))
        subprocess.run(build, check=True)
    except FileNotFoundError:
        print("error: cmake was not found in PATH", file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as exc:
        return exc.returncode

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
