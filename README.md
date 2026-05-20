# ⚡ Windows Debloat & Gaming Optimization Tool

<img src="./.github/images/windows.svg" alt="Windows Logo" width="96" />

A powerful and customizable PowerShell script designed to **debloat**, **optimize**, and **tweak Windows** for **maximum performance**, reduced latency, and an enhanced **gaming experience**.

> Is currently in development.

![Status](https://badgen.net/badge/Status/Stable/red?icon=dockbit)
![Platform](https://badgen.net/badge/Platform/Windows/red?icon=windows)
![SOCD](https://badgen.net/badge/SOCD/2.0/red?icon=terminal)
[![License: MIT](https://badgen.net/github/license/JonathanFerraz/debloat-windows?color=red&icon=github)](LICENSE)

<p align="right"><a href="README.ptbr.md">Switch to Portuguese (PT-BR)</a></p>

---

## 🚀 Key Features

- **System Cleanup**
  - Clears temporary files
  - Performs disk cleanup using native utilities

- **App Removal**
  - Uninstalls unnecessary built-in apps
  - Removes OneDrive, Edge, and other preinstalled bloatware
  - Optional Xbox login debloat mode (choose whether to keep Xbox sign-in compatibility)

- **Network Optimization**
  - Tweaks TCP/IP stack for lower latency
  - Sets fast and reliable DNS servers

- **Performance Tweaks**
  - Enables the **Ultimate Performance** power plan
  - Disables hibernation and unnecessary scheduled tasks
  - Disables visual effects for better responsiveness

- **System Tweaks**
  - Applies registry and service-level optimizations
  - Disables telemetry, data collection, and unnecessary background services

- **Feature Disabling**
  - Disables legacy and unused features: Internet Explorer, Hyper-V, Media Player, etc.

- **Input Latency Improvements**
  - Enables SOCD (Simultaneous Opposite Cardinal Direction)
  - Disables high-latency system components

- **System Restore Point**
  - Automatically creates a restore point before making changes

---

## 🧠 Recommended Device Manager Tweaks

To further reduce latency and improve gaming performance, disable the following devices via **Device Manager**:

- AMD Controller Emulation
- AMD Crash Defender
- Composite Bus Enumerator
- High Precision Event Timer (HPET)
- Microsoft Hyper-V Virtualization Infrastructure Driver
- Microsoft Virtual Drive Enumerator
- NDIS Virtual Network Adapter Enumerator
- Remote Desktop Device Redirector Bus
- System Speaker

---

## 🛠️ How to Use

1. **Download**  
   Clone or download this repository to your local machine.

2. **Run as Administrator**  
   Right-click `debloat.ps1` and select **"Run as administrator"**.

3. **Choose Xbox Login Mode**

- The script asks if you want to disable Xbox login related features.
- If you choose **Yes**, Xbox/Microsoft sign-in components can be debloated.
- If you choose **No**, Xbox login compatibility is preserved.

4. **Optional (CLI mode)**

- Run with `-DisableXboxLoginFeatures` to force Xbox login debloat without prompt.

5. **Optional (Post-debloat Xbox toggle scripts)**

- Re-enable Microsoft Store / Xbox compatibility: [scripts/fixes/restore-xbox-store.ps1](scripts/fixes/restore-xbox-store.ps1) — re-applies services and registry fixes and attempts to re-register Store/Xbox packages.
- Repair Xbox login (alternate): [scripts/fixes/repair-xbox-login.ps1](scripts/fixes/repair-xbox-login.ps1) — cleans hosts and fixes services/registry.
- Disable Microsoft Store / Xbox compatibility: [scripts/fixes/disable-xbox-store-features.ps1](scripts/fixes/disable-xbox-store-features.ps1) — sets AppPrivacy deny, adds hosts block for login.live.com and disables Xbox services.
- Remove Xbox app packages (optional): run `scripts\bloatware\remove-apps.ps1 -RemoveXboxComponents` to remove Xbox-related Appx packages.

6. **Optional (GPU vendor post-install debloat scripts)**

- AMD: `scripts\\bloatware\\radeon-software-post-install-debloat.ps1`
- NVIDIA: `scripts\\bloatware\\nvidia-software-post-install-debloat.ps1`

7. **Reboot Required**  
   Restart your system to fully apply all changes.

---

## ✅ Best Practices

- ⚠️ **Backup your system** before running any system-level scripts.
- 🎮 Check and install the latest GPU, chipset, and network drivers after optimization.
- 🧩 Customize scripts like `registry.ps1` or `services.ps1` to match your specific needs.

---

## 📌 Notes

- Some features and apps will be **permanently removed or disabled**.
- This script is **performance-focused**: ideal for **gaming rigs**, low-latency setups, and power users.
- Use responsibly and review each section if you're unsure.

---

## 📄 License

This project is open-source and provided under the [MIT License](LICENSE).  
**Use at your own risk.**

---

💬 Found a bug or have a suggestion? [Open an issue](https://github.com/JonathanFerraz/debloat-windows/issues)

---

<p align="center">© 2025 R Y Z Ξ N Optimizer.</p>
