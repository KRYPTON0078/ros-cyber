#!/usr/bin/env python3
"""Run demo attack against local stack."""

import asyncio
import subprocess
import sys


def main() -> None:
    script = "ros2_ws/scripts/attack_injector.py"
    result = subprocess.run([sys.executable, script], check=False)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
