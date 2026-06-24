# bridge/event_parser.py
"""
Parses raw sentinelx kernel log lines into structured KernelEvents.

KernelEvent format:
{
    "os":         "linux",
    "event_type": "SCT_HOOK" | "SCT_RESTORED" | "CR0_TAMPER" | "LSTAR_TAMPER" |
                  "LSTAR_RESTORED" | "PROLOGUE_HOOK" | "MODULE_HIDDEN" |
                  "MODULE_RESTORED" | "DKOM_ALERT" | "PRIVESC" | "NF_HOOK" |
                  "FTRACE_HOOK" | "CR0_RESTORED" | "WATCHLIST_CHANGE" |
                  "WATCHLIST_RESTORED" | "MOD_TRACK",
    "severity":   "CRITICAL" | "HIGH" | "MEDIUM" | "INFO",
    "raw":        "<original log line>",
    "details":    { ... parsed fields ... },
    "timestamp":  <unix float>
}
"""

import re
import time
from typing import Optional

# ORDER MATTERS — more specific patterns before general ones.
ALERT_PATTERNS = [
    (r"\[SCT HOOK\]",             "SCT_HOOK",           "CRITICAL"),
    (r"\[SCT RESTORED\]",         "SCT_RESTORED",       "INFO"),
    (r"\[CR0 ALERT\]",            "CR0_TAMPER",         "CRITICAL"),
    (r"\[CR0 RESTORED\]",         "CR0_RESTORED",       "INFO"),
    (r"\[LSTAR TAMPERED\]",       "LSTAR_TAMPER",       "CRITICAL"),
    (r"\[LSTAR RESTORED\]",       "LSTAR_RESTORED",     "INFO"),
    (r"\[MODULE HIDDEN\]",        "MODULE_HIDDEN",      "CRITICAL"),
    (r"\[MODULE RESTORED\]",      "MODULE_RESTORED",    "INFO"),
    (r"\[MOD TRACK\]",            "MOD_TRACK",          "INFO"),
    (r"\[DKOM ALERT\]",           "DKOM_ALERT",         "CRITICAL"),
    (r"\[PRIVESC\]",              "PRIVESC",            "CRITICAL"),
    (r"\[NF HOOK\]",              "NF_HOOK",            "HIGH"),
    (r"\[FTRACE HOOK\]",          "FTRACE_HOOK",        "HIGH"),
    (r"\[CHANGE.*HOOK PATTERN\]", "PROLOGUE_HOOK",      "CRITICAL"),
    (r"\[CHANGE\]",               "WATCHLIST_CHANGE",   "HIGH"),
    (r"\[RESTORED\]",             "WATCHLIST_RESTORED", "INFO"),
]

DMESG_LINE_RE = re.compile(
    r"^\[\s*(?P<ts>[\d.]+)\]\s+sentinelx:\s+(?P<body>.+)$"
)


def parse_line(line: str, os_type: str = "linux") -> Optional[dict]:
    line = line.strip()
    if "sentinelx:" not in line:
        return None

    m = DMESG_LINE_RE.match(line)
    if not m:
        return None

    ts_str = m.group("ts")
    body   = m.group("body")

    event_type = None
    severity   = "INFO"
    for pattern, etype, esev in ALERT_PATTERNS:
        if re.search(pattern, body):
            event_type = etype
            severity   = esev
            break

    if event_type is None:
        return None

    return {
        "os":         os_type,
        "event_type": event_type,
        "severity":   severity,
        "raw":        line,
        "body":       body,
        "details":    _extract_details(event_type, body),
        "timestamp":  time.time(),
        "dmesg_ts":   float(ts_str),
    }


def _c(s: str) -> str:
    """Strip trailing control bytes and their literal escaped representations.

    /dev/kmsg sometimes emits escape sequences as printable text (e.g. the
    4-char string '\\x0a' instead of the actual newline byte).  Strip both
    forms so evidence fields are clean.
    """
    s = s.strip()
    # strip actual control bytes
    s = s.rstrip('\x0a\x0d\x00')
    # strip literal escaped sequences emitted as text: \\x0a  \\x0d  \\x00
    s = re.sub(r'(\\x[0-9a-fA-F]{2})+$', '', s)
    return s


def _extract_details(event_type: str, body: str) -> dict:
    d = {}

    if event_type == "SCT_HOOK":
        m = re.search(r"syscall\[\s*(\d+)\].*expected=(\S+)\s+got=(\S+)", body)
        if m:
            d["syscall_nr"] = int(m.group(1))
            d["expected"]   = _c(m.group(2))
            d["got"]        = _c(m.group(3))
        sym = re.search(r"\(([^)]+)\)", body)
        if sym:
            d["symbol"] = _c(sym.group(1))

    elif event_type == "SCT_RESTORED":
        m = re.search(r"syscall\[\s*(\d+)\]", body)
        if m:
            d["syscall_nr"] = int(m.group(1))

    elif event_type == "CR0_TAMPER":
        m = re.search(r"CPU(\d+).*val=(0x[0-9a-fA-F]+)", body)
        if m:
            d["cpu"]     = int(m.group(1))
            d["cr0_val"] = m.group(2)

    elif event_type in ("LSTAR_TAMPER", "LSTAR_RESTORED"):
        m = re.search(r"baseline=(\S+)", body)
        if m:
            d["baseline"] = _c(m.group(1))
        m2 = re.search(r"\bnow=(\S+)", body)
        if m2:
            d["now"] = _c(m2.group(1))
        sym = re.search(r"\(([^)]+)\)", body)
        if sym:
            d["symbol"] = _c(sym.group(1))

    elif event_type in ("MODULE_HIDDEN", "MODULE_RESTORED", "MOD_TRACK"):
        m = re.search(r"'([^']+)'", body)
        if m:
            d["module_name"] = m.group(1)

    elif event_type == "DKOM_ALERT":
        m = re.search(r"pid=(\d+)", body)
        if m:
            d["pid"] = int(m.group(1))

    elif event_type == "PRIVESC":
        m = re.search(r"'([^']+)'\s*\(pid=(\d+),\s*uid=(\d+)\)", body)
        if m:
            d["process"] = m.group(1)
            d["pid"]     = int(m.group(2))
            d["uid"]     = int(m.group(3))
        if "PKC_NULL" in body:
            d["vector"] = "PKC_NULL"
        elif "ZERO_CAP" in body:
            d["vector"] = "ZERO_CAP"

    elif event_type in ("PROLOGUE_HOOK", "WATCHLIST_CHANGE"):
        m = re.search(r"\]\s+(\S+)\s+@\s+(\S+)", body)
        if m:
            d["function"] = _c(m.group(1))
            d["address"]  = _c(m.group(2))

    elif event_type == "NF_HOOK":
        m = re.search(r"process='([^']+)'\s+pid=(\d+)", body)
        if m:
            d["process"] = m.group(1)
            d["pid"]     = int(m.group(2))

    elif event_type == "FTRACE_HOOK":
        m = re.search(r"called by '([^']+)'\s*\(pid=(\d+)\)", body)
        if m:
            d["process"] = m.group(1)
            d["pid"]     = int(m.group(2))
        addr = re.search(r"@\s+(\S+)", body)
        if addr:
            d["address"] = _c(addr.group(1))

    return d