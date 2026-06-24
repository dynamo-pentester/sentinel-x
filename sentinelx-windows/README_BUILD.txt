SENTINEL-X Windows Kernel Driver — Build Instructions
======================================================

Requirements:
  - Visual Studio 2022
  - WDK (Windows Driver Kit) 10.0.26100 or later
  - Spectre-mitigated libraries

Build steps:
  1. Open Visual Studio → File → New → Project from Existing Code
     OR: Create a new "Empty WDM Driver" project
  2. Add source files: driver.c, ssdt.c, dkom.c, sentinelx.h
  3. Project Properties:
       Configuration: Debug | x64
       Driver Settings → Target OS: Windows 10+
       C/C++ → Treat Warnings as Errors: No (/WX-)
       C/C++ → Additional Dependencies: aux_klib.lib
  4. Build Solution

Load driver (requires test-signing enabled):
  bcdedit /set testsigning on   (reboot required)
  sc create sentinelx type= kernel binPath= C:\path\to\sentinelx.sys
  sc start sentinelx
  sc stop sentinelx
  sc delete sentinelx

View alerts (DebugView):
  Download Sysinternals DebugView and run as Administrator
  Filter: sentinel*

Python bridge (on same Windows machine):
  pip install pywin32
  python sentinel_daemon.py --os windows --dry-run
