<div align="center">

# ◆ ThreatHunter

**A standalone PowerShell TUI for Windows incident response & threat hunting.**

One file. Zero installs. Zero modules. Eleven curated hunting modules behind a chat-style terminal interface.

[![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](#compatibility)
[![Standalone](https://img.shields.io/badge/Standalone-yes-D97757)](#why)
[![License](https://img.shields.io/badge/License-MIT-6e7681)](#license)

![ThreatHunter main menu](docs/screenshots/01_main_menu.png)

</div>

---

## Why

You are looking at a Windows endpoint that may be compromised. You have a remote shell, RDP or physical access, and roughly an hour. You need a consistent set of views over events, processes, network state and persistence — without dragging a toolkit onto the host, and with everything captured as evidence.

ThreatHunter wraps the most useful built-in cmdlets behind one TUI. There is nothing to install, nothing to clean up, and nothing leaves the host without your hand on the keyboard.

## Highlights

| | |
|---|---|
| **Single `.ps1`** | Drop it onto any modern Windows endpoint and run. No modules, no internet, no telemetry. |
| **11 modules** | Events, processes, network, persistence, forensic artefacts, auth, files & IOC, plus arbitrary cmd / PowerShell with a destructive-command guard. |
| **Evidence-aware** | Auto-logged session. Per-view CSV / JSON exports. One-key flagging as findings. Consolidated Markdown report on exit. |
| **Compatible** | Windows PowerShell 5.1 and PowerShell 7+. Auto-detects ANSI / true colour and falls back to console colours when needed. |
| **Operator-friendly** | Numbered menus and slash commands side by side. `/events`, `/procs`, `/net`, `/files`, `/q` … |

---

## Quick start

```powershell
# clone or copy the script onto the target host
git clone https://github.com/<your-org>/ThreatHunter.git
cd ThreatHunter

# launch
.\ThreatHunter.ps1
```

If execution policy gets in the way:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\ThreatHunter.ps1
```

With an indicator list and a custom output path:

```powershell
.\ThreatHunter.ps1 -IocFile .\iocs.sample.csv -OutputRoot D:\IR\Cases\Q2
```

Run monochrome (restricted terminals / SSH):

```powershell
.\ThreatHunter.ps1 -NoColor -NoLog
```

## Modules

| Slash | Module | What it does |
|---|---|---|
| `/events`    | Event Viewer        | Browse channels, quick views over System / Security / PowerShell / Sysmon. |
| `/search`    | Event Search        | Filter by channel, event ID, level, message regex and time range. |
| `/procs`     | Process Monitor     | Live snapshot, parent/child tree, signing, owners, command lines, DLLs. |
| `/hunt`      | Process Hunting     | Pre-built queries: unsigned, suspicious paths, LOLBin chains, network-active. |
| `/net`       | Network state       | TCP/UDP with PID, listening ports, DNS cache, ARP, firewall, SMB. |
| `/persist`   | Persistence         | Tasks, services, run keys, IFEO, WMI subs, Winlogon, drivers, PS profiles. |
| `/forensics` | Forensic artefacts  | Prefetch, Amcache, ShimCache, BAM, RecentApps, UserAssist, MUICache. |
| `/auth`      | Users / Logons      | 4624, 4625, 4672, 4740, 4648, RDP sessions, privileged groups. |
| `/files`     | Files & IOC         | Hashes, recent files, IOC matching (hash / IP / domain / filename), Sysmon parser. |
| `/cmd`       | Run cmd             | Arbitrary `cmd.exe` with destructive-pattern detection. |
| `/ps`        | Run PowerShell      | Arbitrary PowerShell expression or `.ps1` file with pattern detection. |
| `/report`    | Reports             | Findings list, exports index, consolidated Markdown report. |

---

## Screenshots

<table>
  <tr>
    <td align="center"><strong>Main menu</strong><br><img src="docs/screenshots/01_main_menu.png" width="420"></td>
    <td align="center"><strong>Help / slash commands</strong><br><img src="docs/screenshots/02_help_crop.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Process Monitor</strong><br><img src="docs/screenshots/03_procs_crop.png" width="420"></td>
    <td align="center"><strong>Persistence</strong><br><img src="docs/screenshots/04_persist_crop.png" width="420"></td>
  </tr>
  <tr>
    <td align="center"><strong>Files &amp; IOC</strong><br><img src="docs/screenshots/05_files_crop.png" width="420"></td>
    <td align="center"><strong>Destructive-command guard</strong><br><img src="docs/screenshots/06_destructive.png" width="420"></td>
  </tr>
  <tr>
    <td colspan="2" align="center"><strong>Live result view (Get-Process inside <code>/ps</code>)</strong><br><img src="docs/screenshots/07_result_crop.png" width="860"></td>
  </tr>
</table>

---

## Hunting workflows

<details>
<summary><b>“Something feels off” — rapid triage in ~10 minutes</b></summary>

```text
/hunt    → unsigned binaries running
/hunt    → procs from Temp / AppData / ProgramData
/net     → established TCP + PID
/persist → tasks (non-Microsoft) + run keys
/q       → save the report
```
</details>

<details>
<summary><b>IOC sweep — you have indicators, check this host</b></summary>

```text
.\ThreatHunter.ps1 -IocFile .\incident.csv

/files  → match running procs against IOC list
/files  → match TCP remotes against IOC list
/files  → match DNS cache against IOC list
/files  → hash %TEMP% and %APPDATA% recursively   (hash hits auto-flag CRITICAL)
/findings → /report
```
</details>

<details>
<summary><b>Auth anomaly — login behaviour investigation</b></summary>

```text
/auth → 4625 failed logons        (24h)
/auth → 4624 successful logons    (LogonType 10 / 3)
/auth → 4672 privileged · 4648 explicit credentials
/auth → account changes (4720…4738)
/auth → RDP session history
```
</details>

---

## IOC CSV format

Three columns. Header row required.

```csv
type,value,description
sha256,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Empty file placeholder
md5,d41d8cd98f00b204e9800998ecf8427e,Empty file placeholder
ip,185.220.101.1,Sample known-bad IP
domain,malicious-example.com,Sample bad domain
filename,mimikatz.exe,Credential dumping tool
filename,rclone.exe,Often abused for exfiltration
regkey,HKCU:\Software\Classes\ms-settings\shell\open\command,UAC bypass via fodhelper
```

| `type` | matched against |
|---|---|
| `md5` / `sha1` / `sha256` | Hashes computed by the *Hash files* view. |
| `ip`       | Remote address column of `Get-NetTCPConnection`. |
| `domain`   | Substring match against `Entry` in the DNS client cache. |
| `filename` | Substring match against the running process Name **and** Path. |
| `regkey`   | Reference value — listed in the loaded set for context. |

A working sample is shipped as [`iocs.sample.csv`](iocs.sample.csv).

---

## Output & evidence

Every session creates its own folder so the whole thing can be shipped as evidence.

```
ThreatHunt_Output\
└── 20260507_142133\           # session id (YYYYMMDD_HHMMSS)
    ├── session.log            # every action + raw output, append-only
    ├── exports\
    │   ├── 142357_evt_search.csv
    │   ├── 142412_proc_list.json
    │   └── …
    └── report.md              # written on exit, or via /report
```

* `session.log` — timestamped record of every action, the rendered tables, every cmd / PS command and its output, and every flagged finding.
* `exports/`    — CSV / JSON snapshots saved on demand from any result view (key `e`).
* `report.md`   — consolidated Markdown report with session metadata, findings table and exports index.

## Result-view actions

Every result view ends with a short action prompt:

| Key | Action |
|---|---|
| `e` | export current dataset to CSV / JSON / both |
| `f` | flag finding (severity + title + detail) |
| `v` | view all rows (un-paginated) |
| `↵` | continue without exporting / flagging |

## Time range syntax

Anywhere a module asks for a time range, you can type:

```text
1h     6h     24h        # last N hours
7d     30d    90d        # last N days
2w     6w                # last N weeks
3m     12m               # last N calendar months
all                      # epoch → now
2026-04-15..2026-05-07   # explicit, inclusive
```

## Safety net

The cmd and PowerShell modules screen every input against a list of patterns commonly associated with destructive actions and evidence tampering. When a match is found, the action is paused and confirmation is required.

```text
ps › Remove-Item C:\Tools\evidence
⚠ destructive pattern matched: 'Remove-Item'
run anyway?  [y/N] › n
◆ skipped.
```

Patterns include `Remove-Item`, `Format-Volume`, `Stop-Computer`, `taskkill`, `Stop-Service`, `Clear-EventLog`, `wevtutil cl`, `reg delete`, `Disable-NetAdapter`, `netsh advfirewall reset`, `Invoke-Expression`, `iex`, `DownloadString`, `Set-MpPreference -DisableRealtimeMonitoring`, `cipher /w`, `sdelete`, and others. This is a hint, not a hard block — confirming with `y` runs the command as-is. Every command and its output is appended to the session log regardless.

---

## Compatibility

| | |
|---|---|
| Windows 10 / 11 | ✓ |
| Windows Server 2016+ | ✓ |
| Windows PowerShell 5.1 | ✓ |
| PowerShell 7+ | ✓ |
| Windows Terminal | ✓ true colour |
| `conhost.exe` (legacy) | ✓ falls back to console colours |
| VS Code terminal | ✓ |
| ConEmu | ✓ |

Admin is **recommended but not required**. The banner shows `ADMIN` or `USER`. Without elevation, the Security log and full process inventory are partially or fully invisible — the TUI tells you when that affects a result.

## Parameters

| Parameter | Description |
|---|---|
| `-OutputRoot <path>` | Root for session folders. Defaults to `.\ThreatHunt_Output\`. |
| `-IocFile <path>`    | CSV of indicators (see format above). Loaded on demand. |
| `-NoLog`             | Disable session logging entirely (also disables exports / report). |
| `-NoColor`           | Force monochrome output. Useful in restricted terminals. |

---

## Documentation

This repository ships full documentation:

* **[`ThreatHunter-Guide.html`](ThreatHunter-Guide.html)** — full UK-English reference manual (single self-contained HTML).
* **[`ThreatHunter-Presentation.pptx`](ThreatHunter-Presentation.pptx)** — slide deck overview of the tool.
* **[`ThreatHunter-Presentation.pdf`](ThreatHunter-Presentation.pdf)** — PDF export of the deck.
* **[`iocs.sample.csv`](iocs.sample.csv)** — starter IOC list to use as a template.

---

## Repository layout

```
ThreatHunter/
├── ThreatHunter.ps1               # the script itself
├── iocs.sample.csv                # sample IOC list
├── ThreatHunter-Guide.html        # full user guide
├── ThreatHunter-Presentation.pptx
├── ThreatHunter-Presentation.pdf
├── docs/
│   └── screenshots/               # images used by this README
└── README.md
```

---

## Contributing

Issues and pull requests are welcome. Useful directions:

* New modules (DPAPI keys, Defender exclusions, BITS jobs, RDP cache, etc.).
* Better Sysmon parsing — friendly views per Event ID rather than raw messages.
* Additional destructive-pattern coverage.
* Locale / language packs for the prompts.

When opening an issue, include the PowerShell version, the host OS build, and a redacted excerpt from `session.log` if relevant.

## License

MIT — see [`LICENSE`](LICENSE).

> ThreatHunter is provided **as-is**, with no warranty. It is intended to be operated by analysts who understand the actions being taken on the host. Some operations (cmd / PowerShell execution, registry reads in privileged hives, scanning sensitive paths) may interact with monitoring on the endpoint. Always review your organisation’s policies before running it on production systems.

---

<div align="center">
<sub>Built for the analyst on the keyboard. ◆ Stay sharp.</sub>
</div>
