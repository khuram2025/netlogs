"""Delete .py source files where corresponding .so exists.

Runs after Cython compilation to remove source code from distribution.
Only deletes .py files that were successfully compiled to .so.

Usage:
    cd build/staging
    python ../cleanup_sources.py
"""

import os
import sys
from pathlib import Path

# Files that must NEVER be deleted
KEEP_PATTERNS = {
    "__init__.py",
    "__version__.py",
}

KEEP_PATHS = {
    "fastapi_app/db/migrations/",
    "fastapi_app/db/clickhouse_migrations/",
}

# Entry point scripts to keep as .py
KEEP_FILES = {
    "run_fastapi.py",
    "run_syslog.py",
}


def should_keep(filepath: str) -> bool:
    """Check if a .py file should be kept (not deleted)."""
    path = Path(filepath)

    if path.name in KEEP_PATTERNS:
        return True

    if path.name in KEEP_FILES:
        return True

    filepath_posix = path.as_posix()
    for keep_path in KEEP_PATHS:
        if filepath_posix.startswith(keep_path):
            return True

    return False


def find_so_for_py(py_path: Path) -> Path | None:
    """Find the .so file corresponding to a .py file.

    Cython generates files like: module.cpython-312-x86_64-linux-gnu.so
    """
    stem = py_path.stem
    parent = py_path.parent

    for f in parent.iterdir():
        if f.suffix == ".so" and f.name.startswith(stem + "."):
            return f
    return None


def main():
    root = Path(".")
    deleted = 0
    skipped = 0
    missing_so = 0

    print("Cleaning up .py source files where .so exists...\n")

    for py_file in sorted(root.rglob("*.py")):
        rel = py_file.relative_to(root).as_posix()

        # Skip files that must be kept
        if should_keep(rel):
            skipped += 1
            continue

        # Only delete if .so exists
        so_file = find_so_for_py(py_file)
        if so_file:
            print(f"  DELETE  {rel}  (compiled: {so_file.name})")
            py_file.unlink()
            deleted += 1
        else:
            missing_so += 1

    # Clean up .c intermediary files from Cython
    c_deleted = 0
    for c_file in root.rglob("*.c"):
        if c_file.relative_to(root).parts[0] == "fastapi_app":
            c_file.unlink()
            c_deleted += 1

    print(f"\nSummary:")
    print(f"  Deleted:    {deleted} .py files (compiled to .so)")
    print(f"  Kept:       {skipped} .py files (protected)")
    print(f"  No .so:     {missing_so} .py files (not compiled, kept)")
    print(f"  C files:    {c_deleted} removed")


if __name__ == "__main__":
    main()
