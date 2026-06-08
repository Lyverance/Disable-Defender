Английская версия | [Russian Version](README_RU.md)

# 🛡️ Clean Windows Defender Disable

A native, safe, and fully reversible method to disable Windows Defender — without deleting files or third-party software.

Tested on **Windows 11 IoT Enterprise 25H2**. Should work on other Windows 10/11 editions, but has not been verified.

> ⚠️ **Disclaimer:** This project was developed for personal use and tested on my own system. You use these scripts at your own risk.

---

## ❓ Why Not Defender Remover / Killer and Similar Tools

These utilities physically delete Defender components from `WinSxS`. Consequences:

- Cumulative updates fail with error `0x800f081f` — Windows cannot find files during integrity checks
- `sfc /scannow` and `DISM` either don't work or restore Defender in a broken state
- Backup-based rollback is unreliable — on failure, reinstallation is the only option

This method does not touch a single file — registry only. Updates work normally, rollback takes one script run.

---

## 📖 Two Ways to Use

ℹ️ **Interactive web guide:** [Open guide in browser](https://lyverance.github.io/Disable-Defender/defender_guide_ru.html)

1. **Method A — Scripts (recommended).** Fully automatic, with checks and rollback.
2. **Method B — Manual.** The same [web guide](https://lyverance.github.io/Disable-Defender/defender_guide_ru.html), commands run manually. For those who don't run other people's scripts.

---

## ⚙️ Instructions (Method A)

### Disabling

**Step 0 — required manual step**
Disable Tamper Protection manually:
*Settings ➔ Privacy & Security ➔ Windows Security ➔ Virus & threat protection ➔ Manage settings ➔ Tamper Protection ➔ Off*

**Step 1 — normal mode**
Double-click `Disable-Defender.cmd`. The script will request elevated rights via UAC, perform preparation, and reboot the PC into Safe Mode.

**Step 2 — Safe Mode**
The console will open automatically. The script will disable services and return the system to normal mode. No manual actions required.

### Restoration

Double-click `Restore-Defender.cmd`. The script will restore the original system state and reboot the PC. Afterwards, re-enable Tamper Protection.

### Status Check

Double-click `Check-Status.cmd` — a report on the status of all Defender components will open.

> ℹ️ **Major Windows updates (Feature Updates)** may restore Defender to its original state. After such an update, run `Check-Status.cmd` and repeat the disable process if necessary. Regular cumulative updates (Cumulative Updates) are not affected.

---

## 📋 What the Script Disables

| Component | Details |
|---|---|
| **Defender Core** | WinDefend, WdFilter, WdBoot, WdNisSvc, WdNisDrv |
| **Telemetry** | Sense, webthreatdefsvc, webthreatdefusersvc |
| **Security Center** | wscsvc (Windows Security Center) |
| **Scheduler** | 5 Defender maintenance tasks |
| **Context Menu** | EPP ("Scan with Microsoft Defender" entry) |
| **SmartScreen** | Registry + smartscreen.exe block |
| **Notifications** | Security Center, HealthCenter |
