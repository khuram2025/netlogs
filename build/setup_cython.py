"""Cython compilation setup for Zentryc appliance build.

Compiles all .py files under fastapi_app/ to .so shared objects,
except files that must remain as .py (init files, version, migrations).

Usage:
    cd build/staging
    python setup_cython.py build_ext --inplace
"""

import os
import sys
from pathlib import Path
from setuptools import setup, find_packages
from Cython.Build import cythonize

# Root of the staged source tree
ROOT = Path(__file__).parent

# Directories to compile
COMPILE_DIRS = [
    "fastapi_app/api",
    "fastapi_app/core",
    "fastapi_app/services",
    "fastapi_app/services/ai",
    "fastapi_app/models",
    "fastapi_app/schemas",
    "fastapi_app/db",
    "fastapi_app/cli/shell",
    "fastapi_app/cli/shell/commands",
    "fastapi_app/cli/firstboot",
    "fastapi_app/cli",
]

# Individual files to compile at the root of fastapi_app
COMPILE_ROOT_FILES = [
    "fastapi_app/main.py",
]

# Files/patterns that must NEVER be compiled (keep as .py)
EXCLUDE_PATTERNS = {
    # All __init__.py files — required for Python package structure
    "__init__.py",
    # Version file — read by shell scripts via grep
    "__version__.py",
}

EXCLUDE_PATHS = {
    # Alembic requires these as .py
    "fastapi_app/db/migrations/env.py",
    # Alembic migration versions
    "fastapi_app/db/migrations/versions",
    # ClickHouse migration discovery uses glob("*.py")
    "fastapi_app/db/clickhouse_migrations",
}


def should_compile(filepath: str) -> bool:
    """Determine if a .py file should be compiled to .so."""
    path = Path(filepath)

    # Never compile excluded filenames
    if path.name in EXCLUDE_PATTERNS:
        return False

    # Never compile excluded paths
    filepath_posix = path.as_posix()
    for exclude in EXCLUDE_PATHS:
        if filepath_posix.startswith(exclude):
            return False

    return True


def collect_modules() -> list[str]:
    """Collect all .py files to compile."""
    modules = []

    # Collect from compile directories
    for dir_path in COMPILE_DIRS:
        full_dir = ROOT / dir_path
        if not full_dir.is_dir():
            continue
        for py_file in full_dir.glob("*.py"):
            rel = py_file.relative_to(ROOT).as_posix()
            if should_compile(rel):
                modules.append(rel)

    # Collect individual root files
    for filepath in COMPILE_ROOT_FILES:
        full_path = ROOT / filepath
        if full_path.exists() and should_compile(filepath):
            modules.append(filepath)

    return sorted(set(modules))


def main():
    modules = collect_modules()

    if not modules:
        print("ERROR: No modules found to compile!", file=sys.stderr)
        sys.exit(1)

    print(f"Compiling {len(modules)} modules to .so:")
    for m in modules:
        print(f"  {m}")

    setup(
        name="zentryc",
        ext_modules=cythonize(
            modules,
            compiler_directives={
                "language_level": "3",
                "boundscheck": False,
                "wraparound": False,
            },
            nthreads=os.cpu_count() or 4,
            quiet=False,
        ),
        zip_safe=False,
    )


if __name__ == "__main__":
    main()
