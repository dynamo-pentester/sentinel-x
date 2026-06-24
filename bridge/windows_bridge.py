# bridge/windows_bridge.py
"""
Windows bridge for SENTINEL-X.
Reads kernel events from \\.\\SentinelX via DeviceIoControl.
Produces the same KernelEvent dict format as LinuxBridge.

SENTINEL_EVENT struct (matches sentinelx.h):
    ULONG   type        (4 bytes)
    ULONG   severity    (4 bytes)
    LARGE_INTEGER ts    (8 bytes)
    WCHAR   message[256] (512 bytes)
    Total = 528 bytes

IOCTL_READ_EVENT:
    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
    = (0x8000 << 16) | (0x0001 << 14) | (0x800 << 2) | 0
    = 0x80004000 | 0x4000 | 0x2000 | 0 = 0x80006000
    Actually: (0x8000<<16)|(1<<14)|(0x800<<2)|0 = 0x80006000
"""

import struct, time, queue, threading, logging
from typing import Optional

log = logging.getLogger("sentinel.windows_bridge")

DEVICE_PATH      = r"\\.\SentinelX"
IOCTL_READ_EVENT = 0x80006000   # CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
IOCTL_FLUSH      = 0x8000A004   # CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

# SENTINEL_EVENT layout
EVENT_FMT  = "<II q 512s"
EVENT_SIZE = struct.calcsize(EVENT_FMT)  # 528 bytes

# Severity mapping
SEV_MAP = {0: "INFO", 1: "HIGH", 2: "CRITICAL"}

# Event type mapping (matches KS_EVENT_TYPE enum in sentinelx.h)
TYPE_MAP = {
    1: "SCT_HOOK",        # EVT_SSDT_HOOK
    2: "SCT_RESTORED",    # EVT_SSDT_RESTORED
    3: "DKOM_ALERT",      # EVT_DKOM_ALERT
    4: "MODULE_HIDDEN",   # EVT_DRIVER_HIDDEN
    5: "MODULE_RESTORED", # EVT_DRIVER_RESTORED
}

SEV_OVERRIDE = {
    "SCT_RESTORED":    "INFO",
    "MODULE_RESTORED": "INFO",
}


class WindowsBridge:
    """
    Reads sentinelx.sys events via DeviceIoControl.
    Same interface as LinuxBridge: start() / stop() / get_event().
    """

    def __init__(self):
        self.event_queue: queue.Queue = queue.Queue(maxsize=1024)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._handle = None

    def start(self):
        self._open_device()
        self._thread = threading.Thread(
            target=self._reader_loop, name="windows_bridge_reader", daemon=True)
        self._thread.start()
        log.info("Windows bridge started — reading from %s", DEVICE_PATH)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._close_device()
        log.info("Windows bridge stopped")

    def get_event(self, timeout: float = 1.0) -> Optional[dict]:
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _open_device(self):
        try:
            import win32file, win32con
            self._handle = win32file.CreateFile(
                DEVICE_PATH,
                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, None, win32con.OPEN_EXISTING,
                win32con.FILE_ATTRIBUTE_NORMAL, None)
            log.info("Opened device: %s", DEVICE_PATH)
        except ImportError:
            raise RuntimeError("pywin32 required: pip install pywin32")
        except Exception as e:
            raise RuntimeError(
                f"Cannot open {DEVICE_PATH}: {e}\n"
                "Make sure sentinelx.sys is loaded: sc start sentinelx")

    def _close_device(self):
        if self._handle:
            try:
                import win32file
                win32file.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def _ioctl_read_event(self) -> Optional[bytes]:
        import win32file, pywintypes
        try:
            err, data = win32file.DeviceIoControl(
                self._handle, IOCTL_READ_EVENT, None, EVENT_SIZE)
            if err == 0 and data and len(data) >= EVENT_SIZE:
                return data[:EVENT_SIZE]
            return None
        except pywintypes.error as e:
            if e.args[0] == 259:  # ERROR_NO_MORE_ITEMS = queue empty
                return None
            log.error("DeviceIoControl error: %s", e)
            return None

    def _reader_loop(self):
        consecutive_empty = 0
        while not self._stop_event.is_set():
            raw = self._ioctl_read_event()
            if raw is None:
                consecutive_empty += 1
                self._stop_event.wait(timeout=min(0.1 * consecutive_empty, 1.0))
                continue
            consecutive_empty = 0
            event = self._parse_event(raw)
            if event:
                try:
                    self.event_queue.put_nowait(event)
                except queue.Full:
                    log.warning("Event queue full — dropping event")

    def _parse_event(self, raw: bytes) -> Optional[dict]:
        if len(raw) < EVENT_SIZE:
            return None
        try:
            evt_type_int, sev_int, ts_raw, msg_raw = struct.unpack(EVENT_FMT, raw)
        except struct.error as e:
            log.error("Failed to unpack event: %s", e)
            return None
        try:
            msg = msg_raw.decode("utf-16-le").rstrip("\x00").strip()
        except UnicodeDecodeError:
            msg = "<decode error>"

        event_type = TYPE_MAP.get(evt_type_int, f"UNKNOWN_{evt_type_int}")
        severity   = SEV_MAP.get(sev_int, "INFO")
        severity   = SEV_OVERRIDE.get(event_type, severity)
        details    = self._extract_details(event_type, msg)

        return {
            "os":         "windows",
            "event_type": event_type,
            "severity":   severity,
            "raw":        msg,
            "body":       msg,
            "details":    details,
            "timestamp":  time.time(),
            "dmesg_ts":   ts_raw / 1e7,
        }

    def _extract_details(self, event_type: str, msg: str) -> dict:
        import re
        d = {}
        if event_type in ("SCT_HOOK", "SCT_RESTORED"):
            m = re.search(r"syscall\[(\d+)\]", msg)
            if m: d["syscall_nr"] = int(m.group(1))
            m2 = re.search(r"expected=(\S+)", msg)
            if m2: d["expected"] = m2.group(1)
            m3 = re.search(r"got=(\S+)", msg)
            if m3: d["got"] = m3.group(1)
        elif event_type == "DKOM_ALERT":
            m = re.search(r"pid=(\d+)", msg)
            if m: d["pid"] = int(m.group(1))
        elif event_type in ("MODULE_HIDDEN", "MODULE_RESTORED"):
            m = re.search(r"PE image @ (\S+)", msg)
            if m: d["base"] = m.group(1)
            m2 = re.search(r"size=(0x[0-9a-fA-F]+)", msg)
            if m2: d["size"] = m2.group(1)
        return d
