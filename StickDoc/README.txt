StickDoc 1.0.0
==============

Portable health check for RMA work. Nothing is installed and nothing
on the PC is changed. The check only reads the system.

USE
1. Plug in the stick and open this folder.
2. Double-click "StickDoc.cmd" and allow administrator rights.
3. Enter the RMA / ticket number (or press Enter to skip).
4. After about a minute the report opens in the browser.

REPORTS
Every run saves into the "Reports" folder:
  <date>_<RMA>_<serial>.html   report to view, print or save as PDF
  <date>_<RMA>_<serial>.txt    short summary for the ticket
  <date>_<RMA>_<serial>.json   all data, machine-readable
  ..._battery.html             Windows battery report (laptops)
  ..._dumps                    copied bluescreen minidumps (if any)
If the stick is write-protected the report goes to the desktop.

In the report: click a card for details, "Copy summary" puts a short
text into the clipboard for the ticket, "Print / PDF" prints all
details. Notes typed into "Technician notes" are printed too.

"Kundenbericht" opens a one-page report for the customer in German.
It lists only the areas with problems, in plain words with a
recommendation, plus fields for diagnosis, result and signature.
It contains no private data (accounts, network, programs).

WHAT IT CHECKS
System info   maker, model, serial, SKU, Windows, activation, CPU,
              GPU + driver, RAM modules per slot, mainboard, BIOS
Usage         RAM, page file, CPU, top programs
Drives        SMART health, wear, temperature, hours, errors
Disk space    fill level, file system health, BitLocker
Temperatures  ACPI zones, NVIDIA GPU, drives, CPU throttling events
Battery       health (capacity vs design), cycles, charging
Devices       devices with errors (yellow mark), missing drivers,
              camera, audio, Bluetooth, fingerprint, card reader ...
Bluescreens   bugcheck codes with likely cause, unexpected restarts,
              minidumps, recovered GPU hangs
Hardware events  WHEA, disk, NTFS, storage resets, GPU TDR (30 days)
Program crashes  crashing and hanging programs, stability index
Services      important Windows services, failed services
Updates       last update, failed updates, pending restart
Security      antivirus, firewall, Secure Boot, TPM, BitLocker
Network       adapters, MAC addresses, link speed, internet
Screens       connected screens with size, serial, connection

OPTIONAL: FULL SMART DATA
Put smartctl.exe from smartmontools into the "tools" folder
(see tools\README.txt). Without it the Windows storage counters
are used, which have fewer details.

ADVANCED
Run the script directly for options, for example:
  powershell -ExecutionPolicy Bypass -File app\StickDoc.ps1 -Rma 12345 -Days 60
  -Rma <text>    RMA number without asking
  -Days <n>      how far back to look in the event logs (default 30)
  -OutDir <dir>  different folder for the reports
  -NoOpen        do not open the browser
  -NoDumps       do not copy minidumps

VENTOY
Copy the whole "StickDoc" folder onto the Ventoy stick next to the
ISO files. Ventoy ignores it when booting, Windows sees it as a
normal folder.
