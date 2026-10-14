# ThreatHunt Pro - Automated Windows Threat-Hunting Toolkit

PowerShell triage toolkit for SOC / IR. Single script, Windows PowerShell 5.1 or PowerShell 7, packaged to EXE with PS2EXE.

## Files
| File | Purpose |
|---|---|
| `ThreatHuntPro.ps1` | The toolkit |
| `Build-Exe.ps1` | PS2EXE packaging (+ optional Authenticode signing) |
| `tests/Test-ThreatHuntPro.ps1` | Offline unit tests (32 checks; no admin/network) |

## Run
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\ThreatHuntPro.ps1                 # all modules, auto-elevates
.\ThreatHuntPro.ps1 -Modules Autoruns,WMI -OutputDir D:\IR\host01
$env:VT_API_KEY = '...'; .\ThreatHuntPro.ps1 -VirusTotal                                  # reputation lookups
.\ThreatHuntPro.ps1 -VirusTotal -VTApiKeyFile C:\keys\vt.txt -VTRatePerMinute 4 -VTMaxLookups 200
dist\ThreatHuntPro.exe -NoElevate -NoOpen                                                 # packaged build
```
Exit code `2` if any finding scores >= `-MinScore` (default 30), else `0`; usable from RMM/EDR live-response scripts.

## Spec coverage
1. **Enumeration modules**: `Listeners` (TCP listen + UDP), `Outbound` (established, non-loopback), `Drivers` (Win32_SystemDriver), `Autoruns` (HKLM/HKCU Run/RunOnce incl. WOW64 and Policies, Winlogon Shell/Userinit, IFEO Debugger, SilentProcessExit, AppInit_DLLs, Startup folders with .lnk resolution, auto-start/running services incl. svchost `ServiceDll`, scheduled tasks), `WMI` (root\subscription filters, consumers, bindings).
2. **Reporting**: per run, `ThreatHunt_<HOST>_<stamp>.{html,txt,json,csv,log}` in `Documents\ThreatHuntPro` (or `-OutputDir`). HTML has severity cards, per-module tables, a "show clean rows" toggle, and HTML-encodes all values (names/paths/command lines are attacker-controlled, so no XSS from a malicious task name). JSON records carry `@timestamp` and `host` for SIEM ingestion; the log is ISO-8601 timestamped.
3. **VirusTotal v3**: hash-only `GET /api/v3/files/{sha256}`, never uploads. Client-side spacing (`60/VTRatePerMinute` s), 429 back-off 60 s with retry, 401/403 disables lookups, 404 = `NotFound`, per-run cache, `-VTMaxLookups` cap. Quota goes to highest-score hashes first; valid Microsoft-signed binaries are skipped unless `-VTAll`. Free tier is 4 req/min, so 200 lookups is about 50 min.
4. **Signature / hash analysis**: SHA256 + Authenticode (catalog signatures included) for every referenced binary, cached.
5. **Elevation**: if not admin, relaunches itself (script or EXE) with `Start-Process -Verb RunAs`, i.e. the normal UAC consent prompt. No UAC bypass. Arguments are carried over; a VT key is passed via a per-user temp file deleted on read, not on the elevated command line. If UAC is declined it continues unelevated with a warning.
6. **Packaging**: `Build-Exe.ps1` -> `dist\ThreatHuntPro.exe`.

## Scoring (0-100; HIGH >= 60, MEDIUM >= 30, LOW > 0, INFO = 0)
| Signal | Points |
|---|---|
| Lookalike name (svch0st.exe) / system binary from wrong path | +50 each |
| Unexpected parent (svchost not from services.exe, etc.) | +30 |
| Script host / LOLBin listening / connecting out | +35 / +30 |
| Suspicious port (4444, 31337, 50050, 9050, ...) | +25 |
| Command-line IOC (encoded PS, hidden window, IEX, download cradle, certutil/bitsadmin/regsvr32/mshta abuse, raw-IP URL) | +30 each, max 70 |
| Temp / Public / Recycle / PerfLogs location | +35 |
| AppData / Downloads / Desktop / ProgramData root (vendor allowlist applies) | +20 |
| Unsigned binary / unsigned **kernel driver** | +20 / +40 |
| Bad signature (HashMismatch, NotTrusted) | +40 |
| Running binary deleted from disk | +20 |
| Winlogon Shell/Userinit modified; AppInit_DLLs; IFEO/SilentProcessExit | +60 / +50 / +40 |
| WMI CommandLine / ActiveScript consumer (unbound: -20) | 60 / 70 |
| VirusTotal detections | +15 per engine (max 60); >= 3 engines forces HIGH |
| Valid Microsoft signature | -15 |

## Tests
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ThreatHuntPro.ps1
```
Covers path resolution, LOLBin target extraction, command-line IOCs, location rules, masquerade detection, central scoring, VT parsing/caching/rate spacing (mocked), and report generation including HTML-encoding of hostile strings.

## Limits (be honest in triage notes)
- Heuristic. False positives: per-user installers, dev tools, unsigned internal apps, IT scripts using `-enc`. False negatives: injected code in signed processes, signed-binary abuse on normal ports, BYOVD with validly signed vulnerable drivers (consider adding the LOLDrivers hash list), rootkits that hide sockets/registry, COM hijacks, services' DLL side-loading, Office/browser add-ins (not yet covered).
- Live-system view only; no memory, no event logs, no historical artefacts.
- Without elevation, SYSTEM process paths, some tasks and WMI subscriptions are hidden.
- PS2EXE binaries are frequently flagged by AV/EDR as suspicious. Sign the EXE (`-CertThumbprint`) and allowlist the hash, or ship the signed .ps1 instead.
- Requires Windows 8 / Server 2012 or later (NetTCPIP and ScheduledTasks modules).
- Tested only offline (pwsh 7 on Linux, Windows cmdlets unavailable). Not yet run on a real Windows host.
