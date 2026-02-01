# [ GLASSWORM SCANNER // UNIT_07 ]
> **MAINFRAME STATUS:** SECURE // **V4 INTERFACE:** ACTIVE

## SYNOPSIS
The **GlassWorm-Scanner** is a specialized PowerShell utility developed to detect and neutralize malicious VS Code extensions. This tool is based on the October 2025 supply chain attack research regarding the first self-propagating VS Code worm.

## FEATURES
* **IDENTIFICATION:** Targets known infected extension IDs and versions.
* **HEURISTICS:** Scans for invisible Unicode variation selectors used to hide malicious logic.
* **C2 RECON:** Detects hardcoded connections to known malicious servers.
* **SYSTEM AUDIT:** Performs system-level checks for credential theft and network compromise.

## QUICK START
Initialize the scanner within a PowerShell 5.1+ environment:

```powershell
# Standard Scan
.\GlassWorm-Scanner.ps1

# Full System Check with Auto-Removal
.\GlassWorm-Scanner.ps1 -Remove -SystemCheck

RESEARCH & DOCUMENTATION

This project is part of the Seven's Domain code repository. For more technical papers and esoteric code research, visit the mainframe.

    Mainframe: SEVEN'S DOMAIN (Update with your final domain)

    Research Source: Koi Security Blog

LEGAL

(C) 2026 SEVEN LEGEND. Distributed under the MIT License. Use at your own risk.
