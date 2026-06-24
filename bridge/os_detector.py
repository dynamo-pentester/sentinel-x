# bridge/os_detector.py
"""
OS detection for SENTINEL-X bridge.
Auto-detects Linux or Windows, allows manual override via .env
"""

import os
import platform

def get_os() -> str:
    """
    Returns 'linux' or 'windows'.
    Checks SENTINEL_OS env var first for manual override.
    """
    override = os.environ.get("SENTINEL_OS", "").lower().strip()
    if override in ("linux", "windows"):
        return override

    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    else:
        raise RuntimeError(f"Unsupported OS: {system}. "
                           f"Set SENTINEL_OS=linux or SENTINEL_OS=windows in .env")
