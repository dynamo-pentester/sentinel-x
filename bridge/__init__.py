# bridge/__init__.py
from .os_detector import get_os
from .event_parser import parse_line
from .linux_bridge import LinuxBridge

try:
    from .windows_bridge import WindowsBridge
except ImportError:
    WindowsBridge = None  # only available on Windows with pywin32

__all__ = ["get_os", "parse_line", "LinuxBridge", "WindowsBridge"]
