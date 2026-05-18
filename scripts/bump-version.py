#!/usr/bin/env python3
import re
import sys
import subprocess
from pathlib import Path

def bump_version():
    arg = sys.argv[1] if len(sys.argv) > 1 else "patch"
    
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        print("Error: pyproject.toml not found.")
        sys.exit(1)

    content = pyproject_path.read_text()
    
    # Simple regex to find version = "x.y.z"
    match = re.search(r'version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', content)
    if not match:
        print("Error: Could not find current version in pyproject.toml")
        sys.exit(1)

    major, minor, patch = map(int, match.groups())

    if arg == "major":
        major += 1
        minor = 0
        patch = 0
        new_version = f"{major}.{minor}.{patch}"
    elif arg == "minor":
        minor += 1
        patch = 0
        new_version = f"{major}.{minor}.{patch}"
    elif arg == "patch":
        patch += 1
        new_version = f"{major}.{minor}.{patch}"
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        new_version = arg
    else:
        print(f"Error: Invalid argument '{arg}'. Use major, minor, patch, or an explicit version like 1.2.3")
        sys.exit(1)

    new_content = re.sub(
        r'version\s*=\s*"\d+\.\d+\.\d+"',
        f'version = "{new_version}"',
        content,
        count=1
    )

    pyproject_path.write_text(new_content)
    print(f"Updated version to {new_version}")

    # Sync lock file
    print("Syncing uv.lock...")
    subprocess.run(["uv", "sync"], check=True)

if __name__ == "__main__":
    bump_version()