# bridge/linux_bridge.py
"""
Linux bridge for SENTINEL-X.

Reads kernel events from /dev/kmsg (primary) with /proc/kmsg fallback.
Streams parsed KernelEvent dicts to the sentinel daemon.

/dev/kmsg  — character device, supports non-blocking seek to current position
/proc/kmsg — older interface, blocking read, requires root
"""

import os
import time
import threading
import queue
import logging
from typing import Optional
from .event_parser import parse_line

log = logging.getLogger("sentinel.linux_bridge")

KMSG_DEV  = "/dev/kmsg"
KMSG_PROC = "/proc/kmsg"

class LinuxBridge:
    """
    Reads sentinelx events from kernel ring buffer.
    Puts parsed KernelEvent dicts into self.event_queue.
    """

    def __init__(self):
        self.event_queue: queue.Queue = queue.Queue(maxsize=1024)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._source: Optional[str] = None

    def start(self):
        """Start background reader thread."""
        if os.path.exists(KMSG_DEV) and os.access(KMSG_DEV, os.R_OK):
            self._source = KMSG_DEV
            log.info(f"Using {KMSG_DEV} as kernel log source")
        elif os.path.exists(KMSG_PROC) and os.access(KMSG_PROC, os.R_OK):
            self._source = KMSG_PROC
            log.info(f"Using {KMSG_PROC} as kernel log source (fallback)")
        else:
            raise PermissionError(
                "Cannot read kernel log. Run as root or with CAP_SYSLOG.\n"
                "Try: sudo python3 sentinel_daemon.py"
            )

        self._thread = threading.Thread(
            target=self._reader_loop,
            name="linux_bridge_reader",
            daemon=True
        )
        self._thread.start()
        log.info("Linux bridge started")

    def stop(self):
        """Signal reader thread to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        log.info("Linux bridge stopped")

    def _reader_loop(self):
        """Main reader loop — handles both /dev/kmsg and /proc/kmsg."""
        if self._source == KMSG_DEV:
            self._read_dev_kmsg()
        else:
            self._read_proc_kmsg()

    def _read_dev_kmsg(self):
        """
        Read from /dev/kmsg.
        Format: priority,seqnum,timestamp,flags;message
        We seek to end first so we only get new messages.
        """
        try:
            fd = os.open(KMSG_DEV, os.O_RDONLY | os.O_NONBLOCK)
            # Seek to end to skip old messages
            import fcntl
            SEEK_DATA = 3  # SEEK_DATA on /dev/kmsg seeks to current end
            try:
                os.lseek(fd, 0, os.SEEK_END)
            except OSError:
                pass  # some kernels don't support seek on /dev/kmsg

            buf = b""
            while not self._stop_event.is_set():
                try:
                    chunk = os.read(fd, 4096)
                    if chunk:
                        buf += chunk
                        while b"\n" in buf:
                            line_bytes, buf = buf.split(b"\n", 1)
                            self._process_raw_kmsg_line(
                                line_bytes.decode("utf-8", errors="replace")
                            )
                except BlockingIOError:
                    time.sleep(0.1)
                except OSError as e:
                    log.error(f"kmsg read error: {e}")
                    time.sleep(1)
            os.close(fd)
        except Exception as e:
            log.error(f"_read_dev_kmsg failed: {e}")

    def _read_proc_kmsg(self):
        """
        Read from /proc/kmsg — blocking readline.
        """
        try:
            with open(KMSG_PROC, "r", errors="replace") as f:
                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        self._process_raw_kmsg_line(line.strip())
                    else:
                        time.sleep(0.05)
        except Exception as e:
            log.error(f"_read_proc_kmsg failed: {e}")

    def _process_raw_kmsg_line(self, raw: str):
        """
        /dev/kmsg format:  6,12345,1234567890,-;sentinelx: [SCT HOOK] ...
        /proc/kmsg format: <6>[12345.678] sentinelx: [SCT HOOK] ...

        We normalize both to dmesg-style and pass to event_parser.
        """
        # /dev/kmsg: strip "priority,seqnum,timestamp,flags;" prefix
        if ";" in raw and not raw.startswith("["):
            parts = raw.split(";", 1)
            if len(parts) == 2:
                # reconstruct as dmesg-style for parser
                meta = parts[0].split(",")
                ts_usec = int(meta[2]) if len(meta) > 2 else 0
                ts_sec  = ts_usec / 1_000_000
                raw = f"[{ts_sec:>10.6f}] {parts[1]}"

        # /proc/kmsg: strip leading <N>
        if raw.startswith("<") and ">" in raw:
            raw = raw[raw.index(">") + 1:].strip()

        # Only process sentinelx lines
        if "sentinelx:" not in raw:
            return

        event = parse_line(raw, os_type="linux")
        if event:
            try:
                self.event_queue.put_nowait(event)
            except queue.Full:
                log.warning("Event queue full — dropping event")

    def get_event(self, timeout: float = 1.0) -> Optional[dict]:
        """Get next event from queue. Returns None on timeout."""
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None
