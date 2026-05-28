[Русская версия](README_RU.md) | English Version

# 🛡️ Clean Windows Defender Disable

A native, safe, and fully reversible method to disable Windows Defender — no third-party software required.

Tested on Windows 11 IoT Enterprise 25H2.

> ⚠️ **I'm not a professional system software developer.** This method and scripts were developed and tested on my own system. The logic and automation code are my own; LLM assistants were used for code formatting, HTML guide layout, and English translation. Shared as-is — if you repeat this on your system, you do so at your own risk.

---

## ❓ Why not Defender Killer and similar tools

Tools like Defender Killer physically remove components from `WinSxS`. After that, cumulative Windows updates fail with error `0x800f081f`, and rollback is only possible by reinstalling the system.

This method disables Defender through the registry — the system stays intact, updates keep working, rollback is one script and a reboot.

---

## 📖 Two ways to use

**Option A — manually via guide**
Open `defender_guide_en.html` in your browser and follow the steps. Best if you want to understand what's happening.

**Option B — scripts**
All steps are automated. Best if you've already read the guide or just want to get it done quickly.

---

## ⚙️ Using the scripts

### Disabling

**Step 0 — required before you start**

Manually disable Tamper Protection:

`Settings` ➔ `Privacy & Security` ➔ `Windows Security` ➔ `Virus & threat protection` ➔ `Manage settings` ➔ `Tamper Protection` ➔ `Off`

This is the only step that can't be automated — Windows requires manual confirmation.

**Step 1 — normal mode**

Double-click `1-Normal-Mode.bat` — the script will request administrator rights via UAC automatically.

The script will perform the preparation steps and automatically reboot into Safe Mode. There will be a pause before the reboot — save any open files.

**Step 2 — Safe Mode**

After the reboot, double-click `2-Safe-Mode.cmd` — the script will request administrator rights via UAC automatically.

The script will disable all Defender services via the registry and reboot back into normal mode.

---

### 🔄 Restore

Double-click `Restore-Defender.cmd` in **normal Windows mode** — the script will request administrator rights via UAC automatically.

After the reboot, manually re-enable Tamper Protection (same way you disabled it in Step 0).

---

### 🔍 Check status

Double-click `Check-Status.bat` — a report on the current state of all Defender components will open.

---

## 📋 What gets disabled

| Component | Method |
|---|---|
| WinDefend, WdFilter, WdBoot, WdNisSvc, WdNisDrv | registry (Safe Mode) |
| Sense, webthreatdefsvc, webthreatdefusersvc | registry (Safe Mode) |
| wscsvc (Windows Security Center) | registry (Safe Mode) |
| Defender scheduled tasks | PowerShell |
| EPP context menu entry | registry |
| SmartScreen | registry |
| Security Center notifications | registry |

---

> **📌 Note:** Major Windows updates (Feature Updates) may restore Defender services to their default state. After such an update, run `Check-Status.bat` and repeat Step 2 if needed.
