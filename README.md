# StickDoc

Portable health check for Windows 10/11, made for RMA work. Runs from a USB
stick (also next to the ISOs on a Ventoy stick), installs nothing and only
reads the system. Every run saves an HTML report, a short text summary and
the full data as JSON into `StickDoc\Reports`.

Sister project of [System Doctor for Linux](https://github.com/Flezzonkeys/system-doctor).

## Use

1. Copy the `StickDoc` folder onto a USB stick.
2. On the PC, double-click `StickDoc.cmd` and allow administrator rights.
3. Type the RMA / ticket number (or press Enter).
4. The report opens in the browser after about a minute.

## What it checks

| Card | Details |
|---|---|
| System info | Maker, model, serial, SKU, UUID, Windows version, activation, firmware product key, CPU, GPU + driver, RAM per slot with part and serial number, mainboard, BIOS, boot mode, boot time |
| Usage | RAM, page file, committed memory, CPU, top programs |
| Drives | SMART health, wear, temperature, power-on hours, TB written, errors (smartctl if present, otherwise Windows storage counters) |
| Disk space | Fill level, file system health, BitLocker per drive |
| Temperatures | ACPI zones, NVIDIA GPU via nvidia-smi, drives, CPU throttling events |
| Battery | Health vs. design capacity, cycles, charge state, Windows battery report |
| Devices | Devices with errors and their meaning, disabled devices, which components exist (camera, audio, Bluetooth, fingerprint, touch, card reader, WWAN, Thunderbolt) |
| Bluescreens | Bugcheck codes with likely cause, unexpected restarts, minidumps (copied to the stick), recovered GPU hangs |
| Hardware events | WHEA, disk, NTFS, storage controller resets, GPU TDR, unexpected shutdowns, USB errors |
| Program crashes | Crashing and hanging programs, Windows stability index |
| Services | Important Windows services, failed automatic services, third-party services |
| Updates | Last update, failed updates, pending restart |
| Security | Antivirus, Defender, firewall, Secure Boot, TPM, BitLocker, accounts |
| Network | Adapters, MAC addresses, link speed, Wi-Fi, internet |
| Screens | Connected screens with size, serial, connection type, resolution |

The report has a light and dark theme, a "Copy summary" button for tickets,
a notes field and a print layout (Print / PDF shows all details).

The "Kundenbericht" button opens a one-page customer report in German: only the
areas with problems, explained in plain words with a recommendation, plus fields
for diagnosis, result and signature. No private data such as accounts or network
details.

## Full SMART data (optional)

Put `smartctl.exe` from [smartmontools](https://github.com/smartmontools/smartmontools/releases)
into `StickDoc\tools`. See `tools\README.txt`.

## Options

```
powershell -ExecutionPolicy Bypass -File app\StickDoc.ps1 -Rma 12345 -Days 60 -NoOpen
```

`-Rma`, `-Days` (event log range, default 30), `-OutDir`, `-NoPrompt`, `-NoOpen`, `-NoDumps`.

## License

MIT
