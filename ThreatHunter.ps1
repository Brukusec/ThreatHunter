#Requires -Version 5.1
<#
.SYNOPSIS
    ThreatHunter.ps1 - Standalone Threat Hunting TUI for Windows.

.DESCRIPTION
    Single-file PowerShell TUI for incident responders / threat hunters.
    Zero external dependencies. Compatible with Windows PowerShell 5.1
    and PowerShell 7+. Provides curated views over event logs, processes,
    network state, persistence mechanisms, forensic artefacts, user
    activity, file/IOC hunting plus arbitrary cmd/PS execution.

.NOTES
    Author : built with Claude (Cowork)
    Theme  : Dark (green + cyan on black)
    Output : ./ThreatHunt_Output/<timestamp>/
                 session.log    (every action + result, auto)
                 exports/*.csv  (per-module CSV/JSON exports)
                 report.md      (final consolidated report on exit)

.PARAMETER OutputRoot
    Root folder for session output. Default: ./ThreatHunt_Output

.PARAMETER NoLog
    Disable automatic session logging.

.PARAMETER NoColor
    Disable ANSI/Console colors (compat for restricted terminals).

.PARAMETER IocFile
    Path to IOC CSV file. Format: type,value,description
    type ∈ md5|sha1|sha256|ip|domain|filename|regkey

.EXAMPLE
    .\ThreatHunter.ps1
    .\ThreatHunter.ps1 -IocFile .\iocs.csv
    .\ThreatHunter.ps1 -NoColor -NoLog
#>
[CmdletBinding()]
param(
    # -- Common -------------------------------------------------------
    [string]$OutputRoot = (Join-Path -Path $PSScriptRoot -ChildPath 'ThreatHunt_Output'),
    [switch]$NoLog,
    [switch]$NoColor,
    [string]$IocFile,

    # -- Action mode (any of these triggers non-interactive auto-quiet)
    # Cmd / PS execution
    [string]$Cmd,           # cmd.exe one-liner   (e.g. -Cmd "whoami")
    [string]$PS,            # PowerShell expr     (e.g. -PS "Get-Date")
    [string]$Script,        # path to a .ps1 file
    [switch]$Force,         # bypass destructive-pattern guard

    # Quick-view actions (each = the module's primary snapshot)
    [switch]$Procs,
    [switch]$Net,
    [switch]$Persist,
    [switch]$Forensics,
    [switch]$Auth,
    [switch]$Files,

    # Event search
    [switch]$EvtSearch,
    [string]$Channel = 'System',
    [int[]] $Id,
    [int]   $Level,
    [string]$Keyword,
    [string]$Range = '24h',

    # Process search
    [switch]$ProcSearch,
    [string]$ProcQuery,

    # Hash files / File search
    [switch]$Hash,
    [switch]$FileSearch,
    [string]$Path,
    [string]$Pattern,
    [ValidateSet('MD5','SHA1','SHA256')][string]$Algo = 'SHA256',
    [switch]$Recurse,
    [int]   $Hours,

    # IOC matching (requires -IocFile)
    [switch]$IocMatch,
    [ValidateSet('procs','tcp','dns','all')][string]$IocAgainst = 'all',

    # Sub-view modifier (works with -Net / -Persist / -Forensics / -Auth / -Procs / -Files)
    [string]$Sub,

    # Process Hunting
    [switch]$Hunt,
    [ValidateSet('unsigned','paths','shortcmd','chain','owners','netactive','all')]
    [string]$HuntType = 'unsigned',

    # Event quick-views
    [switch]$EvtQuick,         # -EvtQuick -Channel X [-Count N]
    [switch]$EvtChannels,      # list channels with non-zero count
    [int]   $Count = 50,

    # Helpers used by sub-views
    [int]   $ProcId,           # for -Procs -Sub dlls
    [int]   $Mb = 50,          # for -Files -Sub large

    # Output / verbosity
    [ValidateSet('Auto','Table','Json','Csv')][string]$Format = 'Auto',
    [switch]$Quiet,
    [int]   $Top = 50,
    [switch]$ListActions,
    [switch]$Help
)

# ---------------------------------------------------------------------------
# 0. GLOBAL STATE & COMPATIBILITY
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# Try to set UTF-8 so box-drawing chars render. Best-effort.
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding           = [System.Text.Encoding]::UTF8
} catch { }

if (-not $PSScriptRoot) {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue
    if (-not $PSScriptRoot) { $PSScriptRoot = (Get-Location).Path }
}

$Script:TH = [ordered]@{
    Version       = '1.0.0'
    StartedAt     = Get-Date
    SessionId     = (Get-Date).ToString('yyyyMMdd_HHmmss')
    Host          = $env:COMPUTERNAME
    User          = $env:USERNAME
    PSVersion     = $PSVersionTable.PSVersion.ToString()
    IsAdmin       = $false
    OutRoot       = $OutputRoot
    OutDir        = $null
    LogPath       = $null
    ExportsDir    = $null
    ReportPath    = $null
    NoLog         = [bool]$NoLog
    NoColor       = [bool]$NoColor
    IocFile       = $IocFile
    Iocs          = @()
    Findings      = New-Object System.Collections.Generic.List[object]
    LastResult    = $null
}

# Detect admin
try {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    $Script:TH.IsAdmin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $Script:TH.IsAdmin = $false }

# Build session output folders
try {
    $Script:TH.OutDir     = Join-Path $Script:TH.OutRoot $Script:TH.SessionId
    $Script:TH.ExportsDir = Join-Path $Script:TH.OutDir 'exports'
    $Script:TH.LogPath    = Join-Path $Script:TH.OutDir 'session.log'
    $Script:TH.ReportPath = Join-Path $Script:TH.OutDir 'report.md'
    if (-not $Script:TH.NoLog) {
        New-Item -ItemType Directory -Force -Path $Script:TH.OutDir     | Out-Null
        New-Item -ItemType Directory -Force -Path $Script:TH.ExportsDir | Out-Null
    }
} catch {
    Write-Warning "Failed to prepare output dir: $($_.Exception.Message). Disabling auto-log."
    $Script:TH.NoLog = $true
}

# ---------------------------------------------------------------------------
# 1. UI / COLOR / ANSI HELPERS  (chat-style — Claude CLI inspired)
# ---------------------------------------------------------------------------

# Try to enable Virtual Terminal Processing on legacy Windows consoles (PS 5.1).
function Enable-VTMode {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }
    if ($env:WT_SESSION -or $env:ConEmuANSI -eq 'ON' -or $env:TERM_PROGRAM -eq 'vscode') { return $true }
    try {
        if (-not ('TH.VT' -as [type])) {
            Add-Type -ErrorAction Stop -Namespace TH -Name VT -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint mode);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint mode);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int n);
'@
        }
        $h = [TH.VT]::GetStdHandle(-11)
        if ($h -eq [System.IntPtr]::Zero) { return $false }
        $mode = 0
        if (-not [TH.VT]::GetConsoleMode($h, [ref]$mode)) { return $false }
        return [TH.VT]::SetConsoleMode($h, ($mode -bor 0x4))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    } catch { return $false }
}

$Script:UseAnsi = (-not $Script:TH.NoColor) -and (Enable-VTMode)

# ANSI palette (Claude-ish warm coral on neutral)
$ESC = [char]27
$Script:Ansi = @{
    Reset = "$ESC[0m"; Bold = "$ESC[1m"; Dim = "$ESC[2m"; Italic = "$ESC[3m"
}
function _RGB { param([int]$R,[int]$G,[int]$B) "$ESC[38;2;${R};${G};${B}m" }

$Script:Pal = @{
    Accent   = (_RGB 217 119  87)   # warm coral (Claude-ish)
    AccentHi = (_RGB 235 152 124)
    Title    = (_RGB 235 235 235)
    Text     = (_RGB 200 200 200)
    Mute     = (_RGB 130 130 130)
    Faint    = (_RGB  90  90  90)
    Border   = (_RGB  85  85  85)
    OK       = (_RGB 137 196 137)
    Warn     = (_RGB 230 188 117)
    Danger   = (_RGB 224 108 117)
    Info     = (_RGB  97 175 239)
    Prompt   = (_RGB 217 119  87)
}

# Console-color fallback (used when ANSI isn't available)
$Script:Theme = @{
    Accent='Yellow'; Title='White'; Text='Gray'; Mute='DarkGray'; Faint='DarkGray'; Border='DarkGray';
    OK='Green'; Warn='Yellow'; Danger='Red'; Info='Cyan'; Prompt='White'
}

function _StyleFallback {
    param([string]$Style)
    switch ($Style) {
        'accent'   { 'Yellow' }
        'accenthi' { 'Yellow' }
        'title'    { 'White' }
        'text'     { 'Gray' }
        'mute'     { 'DarkGray' }
        'faint'    { 'DarkGray' }
        'border'   { 'DarkGray' }
        'ok'       { 'Green' }
        'warn'     { 'Yellow' }
        'danger'   { 'Red' }
        'info'     { 'Cyan' }
        'prompt'   { 'White' }
        default    { 'Gray' }
    }
}
function _StyleAnsi {
    param([string]$Style)
    switch ($Style) {
        'accent'   { $Script:Pal.Accent }
        'accenthi' { $Script:Pal.AccentHi + $Script:Ansi.Bold }
        'title'    { $Script:Pal.Title + $Script:Ansi.Bold }
        'text'     { $Script:Pal.Text }
        'mute'     { $Script:Pal.Mute }
        'faint'    { $Script:Pal.Faint }
        'border'   { $Script:Pal.Border }
        'ok'       { $Script:Pal.OK }
        'warn'     { $Script:Pal.Warn }
        'danger'   { $Script:Pal.Danger }
        'info'     { $Script:Pal.Info }
        'prompt'   { $Script:Pal.Prompt + $Script:Ansi.Bold }
        default    { $Script:Pal.Text }
    }
}

function Write-C {
    [CmdletBinding(DefaultParameterSetName='Style')]
    param(
        [Parameter(Mandatory, Position=0)][AllowEmptyString()][string]$Text,
        [Parameter(ParameterSetName='Style')][string]$Style = 'text',
        [Parameter(ParameterSetName='Color')][string]$Color,
        [switch]$NoNewline
    )
    if ($Script:TH.NoColor) {
        if ($NoNewline) { Write-Host -NoNewline $Text } else { Write-Host $Text }
        return
    }
    if ($PSCmdlet.ParameterSetName -eq 'Color' -and $Color) {
        # legacy console-color path
        $params = @{ Object = $Text; ForegroundColor = $Color }
        if ($NoNewline) { $params['NoNewline'] = $true }
        Write-Host @params
        return
    }
    if ($Script:UseAnsi) {
        $code = _StyleAnsi $Style
        $out  = "$code$Text$($Script:Ansi.Reset)"
        if ($NoNewline) { [Console]::Write($out) } else { [Console]::WriteLine($out) }
    } else {
        $col = _StyleFallback $Style
        $params = @{ Object = $Text; ForegroundColor = $col }
        if ($NoNewline) { $params['NoNewline'] = $true }
        Write-Host @params
    }
}

function Get-ConsoleWidth {
    try {
        $w = $Host.UI.RawUI.WindowSize.Width
        if ($w -lt 60)  { return 80 }
        if ($w -gt 140) { return 140 }
        return $w
    } catch { return 100 }
}

function _Pad {
    param([string]$S, [int]$W)
    if ($S.Length -ge $W) { return $S.Substring(0, $W) }
    return $S + (' ' * ($W - $S.Length))
}

function Show-Card {
    <#
        Renders a rounded-corner card with a title and body lines.
        Body items can be:
          - a string                              (rendered as text)
          - @{ Text='..'; Style='accent' }       (styled line)
          - @{ Sep=$true }                       (faint inner separator)
    #>
    param(
        [string]$Title,
        [object[]]$Body,
        [int]$Width = 0
    )
    if ($Width -le 0) { $Width = [Math]::Min(96, (Get-ConsoleWidth) - 2) }
    $inner = $Width - 4   # 2 borders + 2 spaces

    # top
    $titleText = if ($Title) { " $Title " } else { '' }
    $top = '╭─' + $titleText + ('─' * [Math]::Max(0, $Width - 3 - $titleText.Length)) + '╮'
    Write-C $top -Style 'border'

    foreach ($row in $Body) {
        if ($row -is [hashtable] -and $row.ContainsKey('Sep') -and $row.Sep) {
            Write-C ('├' + ('─' * ($Width - 2)) + '┤') -Style 'border'
            continue
        }
        $text = $null; $style = 'text'
        if ($row -is [hashtable]) { $text = [string]$row.Text; if ($row.Style) { $style = [string]$row.Style } }
        else { $text = [string]$row }
        # word-safe truncate to inner width
        $padded = _Pad $text $inner
        Write-C ('│ ') -Style 'border' -NoNewline
        Write-C $padded -Style $style -NoNewline
        Write-C ' │' -Style 'border'
    }

    Write-C ('╰' + ('─' * ($Width - 2)) + '╯') -Style 'border'
}

function Write-Banner {
    $w = [Math]::Min(96, (Get-ConsoleWidth) - 2)
    $admin = if ($Script:TH.IsAdmin) { 'ADMIN' } else { 'USER ' }
    $adminStyle = if ($Script:TH.IsAdmin) { 'ok' } else { 'warn' }

    Write-Host ''
    Write-C "  ◆ ThreatHunter " -Style 'accenthi' -NoNewline
    Write-C ("v" + $Script:TH.Version) -Style 'mute' -NoNewline
    Write-C "  ·  " -Style 'faint' -NoNewline
    Write-C ("$($Script:TH.Host)") -Style 'title' -NoNewline
    Write-C "  ·  " -Style 'faint' -NoNewline
    Write-C ("$($Script:TH.User)") -Style 'text' -NoNewline
    Write-C "  ·  " -Style 'faint' -NoNewline
    Write-C ($admin) -Style $adminStyle -NoNewline
    Write-C "  ·  " -Style 'faint' -NoNewline
    Write-C ("PS " + $Script:TH.PSVersion) -Style 'mute' -NoNewline
    Write-C "  ·  " -Style 'faint' -NoNewline
    Write-C ("session " + $Script:TH.SessionId) -Style 'mute'
    Write-Host ''

    if (-not $Script:TH.IsAdmin) {
        Write-C "  ⚠  Not elevated — Security log and some processes will be invisible." -Style 'warn'
        Write-Host ''
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-C ("  ▸ $Title") -Style 'accenthi'
    Write-Host ''
}

function Write-Sub   { param([string]$T) Write-C ("    $T") -Style 'mute' }
function Write-Ok    { param([string]$T) Write-C ("  ✓ ") -Style 'ok'     -NoNewline; Write-C $T -Style 'text' }
function Write-Warn2 { param([string]$T) Write-C ("  ⚠ ") -Style 'warn'   -NoNewline; Write-C $T -Style 'text' }
function Write-Err   { param([string]$T) Write-C ("  ✗ ") -Style 'danger' -NoNewline; Write-C $T -Style 'text' }
function Write-Info  { param([string]$T) Write-C ("  ◆ ") -Style 'info'   -NoNewline; Write-C $T -Style 'mute' }

function Read-Prompt {
    param([string]$Label = '')
    if ($Label) {
        Write-C ("  $Label ") -Style 'mute' -NoNewline
    }
    Write-C "› " -Style 'prompt' -NoNewline
    return Read-Host
}

function Pause-Any {
    Write-Host ''
    Write-C "  press enter to continue " -Style 'faint' -NoNewline
    [void](Read-Host)
}

function Confirm-Yes {
    param([string]$Question)
    while ($true) {
        $a = Read-Prompt "$Question  [y/N]"
        if ([string]::IsNullOrWhiteSpace($a)) { return $false }
        switch ($a.Trim().ToLower()) {
            'y'   { return $true }
            'yes' { return $true }
            'n'   { return $false }
            'no'  { return $false }
            default { Write-Warn2 "Answer y or n." }
        }
    }
}

function Show-Menu {
    <#
        Renders a chat-style menu: rounded card with numbered items + slash-command hints.
        $SlashHints (optional) is a hashtable mapping number-string to slash command label.
    #>
    param(
        [string]$Title,
        [object[]]$Items,
        [string]$Footer = '0) back   ·   /help   ·   /q to quit',
        [hashtable]$SlashHints
    )
    if (-not $Title) { $Title = 'menu' }
    Write-Host ''
    $rows = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $n   = ($i + 1).ToString().PadLeft(2)
        $sl  = if ($SlashHints -and $SlashHints[$n]) { "  /" + $SlashHints[$n] } else { '' }
        $rows += @{ Text = (" {0}  {1}{2}" -f $n, $Items[$i], $sl); Style = 'text' }
    }
    Show-Card -Title $Title -Body $rows
    Write-C ("  $Footer") -Style 'faint'
    Write-Host ''
    return Read-Prompt
}

# Spinner that runs a script block with a "thinking…" indicator.
# Falls back to a static line on redirected output.
function Invoke-WithSpinner {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $frames = '⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'
    $redirected = $true
    try { $redirected = [Console]::IsOutputRedirected } catch { }
    if ($redirected -or $Script:TH.NoColor) {
        Write-C ("  ⠿ $Label...") -Style 'mute'
        try { $r = & $Action } catch { Write-Err $_.Exception.Message; return $null }
        return $r
    }

    $job = Start-Job -ScriptBlock $Action
    $i = 0
    try {
        while ($job.State -eq 'Running') {
            $f = $frames[$i % $frames.Length]
            $i++
            $line = "  $f $Label"
            [Console]::Write("`r" + (' ' * 100) + "`r")
            if ($Script:UseAnsi) {
                [Console]::Write($Script:Pal.Accent + $line + $Script:Ansi.Reset)
            } else {
                [Console]::Write($line)
            }
            Start-Sleep -Milliseconds 90
        }
    } finally {
        [Console]::Write("`r" + (' ' * 100) + "`r")
    }
    $r = Receive-Job -Job $job -ErrorAction SilentlyContinue
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    return $r
}

# Slash-command map (filled by Main-Loop). Allows /events /procs /net etc.
$Script:SlashMap = [ordered]@{
    'events'   = @{ Desc='browse event logs';        Action='1'  }
    'search'   = @{ Desc='filter events';            Action='2'  }
    'procs'    = @{ Desc='process monitor';          Action='3'  }
    'hunt'     = @{ Desc='advanced process hunt';    Action='4'  }
    'net'      = @{ Desc='network state';            Action='5'  }
    'persist'  = @{ Desc='persistence';              Action='6'  }
    'forensics'= @{ Desc='forensic artefacts';       Action='7'  }
    'auth'     = @{ Desc='users / logons / auth';    Action='8'  }
    'files'    = @{ Desc='files & IOC';              Action='9'  }
    'cmd'      = @{ Desc='run cmd command';          Action='10' }
    'ps'       = @{ Desc='run powershell command';   Action='11' }
    'findings' = @{ Desc='show flagged findings';    Action='12' }
    'report'   = @{ Desc='save report now';          Action='13' }
    'help'     = @{ Desc='about / help';             Action='14' }
    'about'    = @{ Desc='about / help';             Action='14' }
    'q'        = @{ Desc='exit';                     Action='0'  }
    'quit'     = @{ Desc='exit';                     Action='0'  }
    'exit'     = @{ Desc='exit';                     Action='0'  }
}

function Resolve-Slash {
    param([string]$Raw)
    if (-not $Raw) { return $null }
    $t = $Raw.Trim()
    if (-not $t.StartsWith('/')) { return $null }
    $name = $t.Substring(1).ToLower().Split(' ')[0]
    if ($Script:SlashMap.Contains($name)) {
        return $Script:SlashMap[$name].Action
    }
    return '__UNKNOWN__'
}

# ---------------------------------------------------------------------------
# 2. LOGGING / EXPORT / FINDINGS
# ---------------------------------------------------------------------------
function Write-Session {
    param(
        [string]$Category = 'INFO',
        [Parameter(Mandatory)][string]$Message
    )
    if ($Script:TH.NoLog) { return }
    $line = "[{0}] [{1}] {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Category.ToUpper(), $Message
    try { Add-Content -Path $Script:TH.LogPath -Value $line -Encoding UTF8 } catch { }
}

function Write-SessionBlock {
    param(
        [string]$Title,
        [object]$Data
    )
    if ($Script:TH.NoLog) { return }
    try {
        Add-Content -Path $Script:TH.LogPath -Value ("`n=== $Title @ " + (Get-Date).ToString('HH:mm:ss') + " ===") -Encoding UTF8
        if ($null -ne $Data) {
            $text = ($Data | Out-String).TrimEnd()
            Add-Content -Path $Script:TH.LogPath -Value $text -Encoding UTF8
        }
        Add-Content -Path $Script:TH.LogPath -Value '' -Encoding UTF8
    } catch { }
}

function Export-Result {
    param(
        [Parameter(Mandatory)][object]$Data,
        [Parameter(Mandatory)][string]$BaseName
    )
    if ($null -eq $Data) { Write-Warn2 'Nothing to export.'; return }
    if ($Script:TH.NoLog) {
        Write-Warn2 'Logging disabled — exports require an output folder. Run without -NoLog.'
        return
    }
    Write-C "  Export format: " -Color $Script:Theme.Prompt -NoNewline
    Write-C "(c)sv  (j)son  (b)oth  (s)kip" -Color $Script:Theme.Dim
    $f = (Read-Prompt 'fmt').ToLower()
    $stamp = (Get-Date).ToString('HHmmss')
    $safe  = ($BaseName -replace '[^a-zA-Z0-9_\-]', '_')
    try {
        switch ($f) {
            'c' {
                $p = Join-Path $Script:TH.ExportsDir "${stamp}_${safe}.csv"
                $Data | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
                Write-Ok "Saved CSV: $p"
            }
            'j' {
                $p = Join-Path $Script:TH.ExportsDir "${stamp}_${safe}.json"
                ($Data | ConvertTo-Json -Depth 6) | Out-File -FilePath $p -Encoding UTF8
                Write-Ok "Saved JSON: $p"
            }
            'b' {
                $p1 = Join-Path $Script:TH.ExportsDir "${stamp}_${safe}.csv"
                $p2 = Join-Path $Script:TH.ExportsDir "${stamp}_${safe}.json"
                $Data | Export-Csv -Path $p1 -NoTypeInformation -Encoding UTF8
                ($Data | ConvertTo-Json -Depth 6) | Out-File -FilePath $p2 -Encoding UTF8
                Write-Ok "Saved: $p1"
                Write-Ok "Saved: $p2"
            }
            default { Write-Info 'Skipped export.' }
        }
    } catch {
        Write-Err "Export failed: $($_.Exception.Message)"
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Module,
        [Parameter(Mandatory)][string]$Severity,   # info|low|med|high|critical
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [object]$Evidence
    )
    $obj = [pscustomobject]@{
        Time     = Get-Date
        Module   = $Module
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
        Evidence = $Evidence
    }
    $Script:TH.Findings.Add($obj) | Out-Null
    Write-Session -Category "FINDING/$Severity" -Message "$Module :: $Title :: $Detail"
}

function Show-Findings {
    Write-Section 'Current findings'
    if ($Script:TH.Findings.Count -eq 0) {
        Write-Info 'No findings flagged this session.'
        return
    }
    $i = 0
    foreach ($f in $Script:TH.Findings) {
        $i++
        $col = switch ($f.Severity.ToLower()) {
            'critical' { $Script:Theme.Danger }
            'high'     { $Script:Theme.Danger }
            'med'      { $Script:Theme.Warn }
            'low'      { $Script:Theme.Accent }
            default    { $Script:Theme.Info }
        }
        Write-C ("  [{0,2}] [{1}] {2,-12} {3}" -f $i, $f.Severity.ToUpper().PadRight(8), $f.Module, $f.Title) -Color $col
        if ($f.Detail) { Write-C ("       $($f.Detail)") -Color $Script:Theme.Dim }
    }
}

function Save-Report {
    if ($Script:TH.NoLog) { Write-Warn2 'Logging disabled — no report.'; return }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# ThreatHunter Session Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- **Session:** $($Script:TH.SessionId)")
    [void]$sb.AppendLine("- **Host:** $($Script:TH.Host)")
    [void]$sb.AppendLine("- **User:** $($Script:TH.User)  (Admin: $($Script:TH.IsAdmin))")
    [void]$sb.AppendLine("- **PowerShell:** $($Script:TH.PSVersion)")
    [void]$sb.AppendLine("- **Started:** $($Script:TH.StartedAt.ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine("- **Ended:**   $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    [void]$sb.AppendLine("- **Output:**  $($Script:TH.OutDir)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Findings ($($Script:TH.Findings.Count))")
    [void]$sb.AppendLine("")
    if ($Script:TH.Findings.Count -eq 0) {
        [void]$sb.AppendLine("_No findings flagged._")
    } else {
        [void]$sb.AppendLine("| # | Time | Severity | Module | Title | Detail |")
        [void]$sb.AppendLine("|---|------|----------|--------|-------|--------|")
        $i = 0
        foreach ($f in $Script:TH.Findings) {
            $i++
            $t = $f.Time.ToString('HH:mm:ss')
            $det = if ($f.Detail) { ($f.Detail -replace '\|','\|' -replace '[\r\n]+',' ') } else { '' }
            $title = ($f.Title -replace '\|','\|')
            [void]$sb.AppendLine("| $i | $t | $($f.Severity.ToUpper()) | $($f.Module) | $title | $det |")
        }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Exports")
    [void]$sb.AppendLine("")
    if (Test-Path $Script:TH.ExportsDir) {
        $files = Get-ChildItem -Path $Script:TH.ExportsDir -File -ErrorAction SilentlyContinue
        if ($files) {
            foreach ($x in $files) { [void]$sb.AppendLine("- $($x.Name)  ($([math]::Round($x.Length/1KB,1)) KB)") }
        } else { [void]$sb.AppendLine("_No exports._") }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Session log")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Full action log: ``$($Script:TH.LogPath)``")
    try {
        $sb.ToString() | Out-File -FilePath $Script:TH.ReportPath -Encoding UTF8
        Write-Ok "Report saved: $($Script:TH.ReportPath)"
    } catch {
        Write-Err "Could not save report: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 3. SHARED HELPERS
# ---------------------------------------------------------------------------
function Get-TimeRange {
    param([string]$Default = '24h')
    Write-C "  Time range examples: 1h, 6h, 24h, 7d, 30d, all, or yyyy-MM-dd..yyyy-MM-dd" -Color $Script:Theme.Dim
    $r = Read-Prompt "range [$Default]"
    if ([string]::IsNullOrWhiteSpace($r)) { $r = $Default }
    $now = Get-Date
    if ($r -eq 'all') {
        return [pscustomobject]@{ Start=[datetime]'1970-01-01'; End=$now; Label='all' }
    }
    if ($r -match '^\s*(\d+)\s*([hdwm])\s*$') {
        $n = [int]$matches[1]; $u = $matches[2].ToLower()
        $start = switch ($u) {
            'h' { $now.AddHours(-$n) }
            'd' { $now.AddDays(-$n) }
            'w' { $now.AddDays(-$n*7) }
            'm' { $now.AddMonths(-$n) }
        }
        return [pscustomobject]@{ Start=$start; End=$now; Label="${n}${u}" }
    }
    if ($r -match '^\s*(\d{4}-\d{2}-\d{2})\.\.(\d{4}-\d{2}-\d{2})\s*$') {
        try {
            $s = [datetime]::ParseExact($matches[1],'yyyy-MM-dd',$null)
            $e = [datetime]::ParseExact($matches[2],'yyyy-MM-dd',$null).AddDays(1).AddSeconds(-1)
            return [pscustomobject]@{ Start=$s; End=$e; Label="$($matches[1])..$($matches[2])" }
        } catch { Write-Warn2 'Invalid date range — defaulting to 24h.' }
    }
    Write-Warn2 "Could not parse '$r' — defaulting to 24h."
    return [pscustomobject]@{ Start=$now.AddDays(-1); End=$now; Label='24h' }
}

function Out-Result {
    param(
        [Parameter(Mandatory)][object]$Data,
        [string]$BaseName = 'result',
        [int]$Top = 50,
        [string[]]$Properties
    )
    $Script:TH.LastResult = $Data
    if ($null -eq $Data -or ($Data -is [System.Array] -and $Data.Count -eq 0)) {
        Write-Info 'No results.'
        return
    }
    $count = if ($Data -is [System.Collections.IEnumerable] -and -not ($Data -is [string])) { @($Data).Count } else { 1 }
    Write-Sub "rows: $count   (showing top $Top)"
    $view = if ($count -gt $Top) { @($Data) | Select-Object -First $Top } else { $Data }
    if ($Properties) {
        $view | Format-Table -Property $Properties -AutoSize -Wrap | Out-Host
    } else {
        $view | Format-Table -AutoSize -Wrap | Out-Host
    }
    Write-SessionBlock -Title $BaseName -Data ($view | Format-Table -AutoSize | Out-String)
    Write-Host ''
    Write-C "  Actions: " -Color $Script:Theme.Prompt -NoNewline
    Write-C "(e)xport  (f)lag finding  (v)iew all  (Enter) continue" -Color $Script:Theme.Dim
    $a = (Read-Prompt 'action').ToLower()
    switch ($a) {
        'e' { Export-Result -Data $Data -BaseName $BaseName }
        'f' {
            $sev   = Read-Prompt 'severity (info/low/med/high/critical)'
            $title = Read-Prompt 'finding title'
            $det   = Read-Prompt 'detail (one line)'
            if ([string]::IsNullOrWhiteSpace($sev))   { $sev = 'med' }
            if ([string]::IsNullOrWhiteSpace($title)) { $title = $BaseName }
            Add-Finding -Module $BaseName -Severity $sev -Title $title -Detail $det -Evidence $view
            Write-Ok 'Finding flagged.'
        }
        'v' {
            $Data | Format-Table -AutoSize -Wrap | Out-Host
            Pause-Any
        }
        default { }
    }
}

function Test-Admin {
    if (-not $Script:TH.IsAdmin) {
        Write-Warn2 'This action typically requires elevation. Some results may be missing.'
    }
}

# ---------------------------------------------------------------------------
# 4. MODULE: EVENT VIEWER (browse + search)
# ---------------------------------------------------------------------------
function Module-EventViewer {
    while ($true) {
        $items = @(
            'Browse all log channels (with event counts)',
            'Quick view: System last N events',
            'Quick view: Application last N events',
            'Quick view: Security last N events (admin)',
            'Quick view: Setup last N events',
            'Quick view: PowerShell Operational',
            'Quick view: Windows Defender Operational',
            'Quick view: Sysmon (if installed)',
            'Quick view: TaskScheduler Operational',
            'Quick view: WMI-Activity Operational'
        )
        $c = Show-Menu -Title 'Event Viewer' -Items $items
        switch ($c) {
            '0' { return }
            '1' { TH-EvtListChannels }
            '2' { TH-EvtQuickView 'System' }
            '3' { TH-EvtQuickView 'Application' }
            '4' { Test-Admin; TH-EvtQuickView 'Security' }
            '5' { TH-EvtQuickView 'Setup' }
            '6' { TH-EvtQuickView 'Microsoft-Windows-PowerShell/Operational' }
            '7' { TH-EvtQuickView 'Microsoft-Windows-Windows Defender/Operational' }
            '8' { TH-EvtQuickView 'Microsoft-Windows-Sysmon/Operational' }
            '9' { TH-EvtQuickView 'Microsoft-Windows-TaskScheduler/Operational' }
            '10'{ TH-EvtQuickView 'Microsoft-Windows-WMI-Activity/Operational' }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function TH-EvtListChannels {
    Write-Section 'Available log channels'
    Write-Sub 'enumerating (this can take 10-30s)...'
    Write-Session -Message 'Enumerated event log channels'
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 } |
            Sort-Object -Property RecordCount -Descending |
            Select-Object LogName, RecordCount, IsEnabled, LogMode, FileSize, LastWriteTime
        Out-Result -Data $logs -BaseName 'evt_channels' -Top 80 -Properties LogName,RecordCount,IsEnabled,LogMode,LastWriteTime
    } catch {
        Write-Err $_.Exception.Message
        Pause-Any
    }
}

function TH-EvtQuickView {
    param([string]$LogName, [int]$Default = 50)
    Write-Section "Quick view: $LogName"
    $n = Read-Prompt "how many events [$Default]"
    if ([string]::IsNullOrWhiteSpace($n)) { $n = $Default }
    $n = [int]$n
    Write-Session -Message "QuickView log=$LogName n=$n"
    try {
        $ev = Get-WinEvent -LogName $LogName -MaxEvents $n -ErrorAction Stop |
            Select-Object TimeCreated,
                          @{n='Level';e={$_.LevelDisplayName}},
                          Id,
                          ProviderName,
                          @{n='Message';e={ ([string]$_.Message -replace '\s+',' ').Substring(0, [Math]::Min(160, ([string]$_.Message).Length)) }}
        Out-Result -Data $ev -BaseName ("evt_" + ($LogName -replace '[\\/]','_')) -Top 50
    } catch {
        Write-Err $_.Exception.Message
        Pause-Any
    }
}

function Module-EventSearch {
    Write-Section 'Event search'
    Write-Sub 'Build a filter — leave blank to skip a field.'
    $log = Read-Prompt 'channel (e.g., Security, System, Microsoft-Windows-Sysmon/Operational)'
    if ([string]::IsNullOrWhiteSpace($log)) { Write-Info 'Aborted.'; return }
    $idsRaw = Read-Prompt 'event IDs (comma sep, blank = any)'
    $level  = Read-Prompt 'level (1=Crit 2=Err 3=Warn 4=Info 5=Verb, blank = any)'
    $kw     = Read-Prompt 'keyword in message (blank = any)'
    $tr     = Get-TimeRange '24h'

    $hash = @{ LogName = $log; StartTime = $tr.Start; EndTime = $tr.End }
    if ($idsRaw) {
        $ids = $idsRaw -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
        if ($ids) { $hash['Id'] = $ids }
    }
    if ($level -match '^\d+$') { $hash['Level'] = [int]$level }

    Write-Session -Message ("EventSearch " + ($hash | ConvertTo-Json -Compress -Depth 3) + " kw='$kw'")
    try {
        $events = Get-WinEvent -FilterHashtable $hash -ErrorAction Stop
        if ($kw) { $events = $events | Where-Object { $_.Message -match [regex]::Escape($kw) } }
        $rows = $events | Select-Object TimeCreated,
                                        @{n='Level';e={$_.LevelDisplayName}},
                                        Id,
                                        ProviderName,
                                        MachineName,
                                        @{n='Message';e={ ($_.Message -replace '\s+',' ') }}
        Out-Result -Data $rows -BaseName 'evt_search' -Top 80
    } catch {
        Write-Err $_.Exception.Message
        Pause-Any
    }
}

# ---------------------------------------------------------------------------
# 5. MODULE: PROCESS MONITOR + ADVANCED HUNT
# ---------------------------------------------------------------------------
function Get-ThProcessMap {
    # Returns a map of all processes with rich metadata.
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $list  = New-Object System.Collections.Generic.List[object]
    foreach ($p in $procs) {
        $sigStatus = $null
        $signer    = $null
        $owner     = $null
        try {
            if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath -ErrorAction SilentlyContinue)) {
                $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
                if ($sig) {
                    $sigStatus = $sig.Status.ToString()
                    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
                }
            }
        } catch { }
        try { $owner = ($p | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User } catch { }
        $list.Add([pscustomobject]@{
            PID         = [int]$p.ProcessId
            PPID        = [int]$p.ParentProcessId
            Name        = $p.Name
            Path        = $p.ExecutablePath
            CmdLine     = $p.CommandLine
            Owner       = $owner
            SigStatus   = $sigStatus
            Signer      = $signer
            CreatedAt   = if ($p.CreationDate) { $p.CreationDate } else { $null }
        }) | Out-Null
    }
    return ,$list.ToArray()
}

function Module-ProcessMonitor {
    while ($true) {
        $items = @(
            'List all processes (live snapshot)',
            'Process tree (parent/child)',
            'Top by CPU',
            'Top by working set (RAM)',
            'Search processes by name/path/cmdline',
            'Show DLLs/modules of a PID',
            'Refresh & loop (every 3s, ESC to stop)'
        )
        $c = Show-Menu -Title 'Process Monitor' -Items $items
        switch ($c) {
            '0' { return }
            '1' { $m = Get-ThProcessMap; Out-Result -Data $m -BaseName 'proc_list' -Top 80 -Properties PID,PPID,Name,Owner,SigStatus,Path }
            '2' { TH-ProcTree }
            '3' {
                $p = Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Id, ProcessName, CPU, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, Path
                Out-Result -Data $p -BaseName 'proc_top_cpu' -Top 30
            }
            '4' {
                $p = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 30 Id, ProcessName, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, CPU, Path
                Out-Result -Data $p -BaseName 'proc_top_mem' -Top 30
            }
            '5' { TH-ProcSearch }
            '6' { TH-ProcModules }
            '7' { TH-ProcLoop }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function TH-ProcTree {
    Write-Section 'Process tree'
    $m = Get-ThProcessMap
    $byPid = @{}
    foreach ($p in $m) { $byPid[$p.PID] = $p }
    $children = @{}
    foreach ($p in $m) {
        if (-not $children.ContainsKey($p.PPID)) { $children[$p.PPID] = New-Object System.Collections.Generic.List[object] }
        $children[$p.PPID].Add($p) | Out-Null
    }
    $roots = $m | Where-Object { -not $byPid.ContainsKey($_.PPID) -or $_.PPID -eq 0 -or $_.PID -eq $_.PPID } | Sort-Object Name
    function _Print($node, $indent) {
        $tag = ''
        if ($node.SigStatus -and $node.SigStatus -ne 'Valid') { $tag += " [SIG:$($node.SigStatus)]" }
        if ($node.Path -and $node.Path -match '\\(Temp|AppData|ProgramData|Users\\Public)\\') { $tag += ' [PATH-SUSP]' }
        $color = if ($tag) { $Script:Theme.Warn } else { $Script:Theme.Info }
        Write-C ("  " + ('  ' * $indent) + ("[{0,5}] {1} {2}" -f $node.PID, $node.Name, $tag)) -Color $color
        if ($children.ContainsKey($node.PID)) {
            foreach ($ch in ($children[$node.PID] | Sort-Object Name)) { _Print $ch ($indent+1) }
        }
    }
    foreach ($r in $roots) { _Print $r 0 }
    Write-SessionBlock -Title 'process tree' -Data ($m | Format-Table PID,PPID,Name,Path -AutoSize | Out-String)
    Pause-Any
}

function TH-ProcSearch {
    $q = Read-Prompt 'search term (regex; matches name|path|cmdline)'
    if ([string]::IsNullOrWhiteSpace($q)) { return }
    $m = Get-ThProcessMap
    try {
        $hits = $m | Where-Object {
            ($_.Name    -and $_.Name    -match $q) -or
            ($_.Path    -and $_.Path    -match $q) -or
            ($_.CmdLine -and $_.CmdLine -match $q)
        }
        Out-Result -Data $hits -BaseName 'proc_search' -Top 80
    } catch { Write-Err $_.Exception.Message; Pause-Any }
}

function TH-ProcModules {
    $pidStr = Read-Prompt 'PID'
    if ($pidStr -notmatch '^\d+$') { Write-Warn2 'Bad PID.'; return }
    try {
        $p = Get-Process -Id ([int]$pidStr) -ErrorAction Stop
        $mods = $p.Modules | Select-Object ModuleName, FileName, FileVersion, Company
        Out-Result -Data $mods -BaseName "proc_${pidStr}_modules" -Top 200
    } catch {
        Write-Err $_.Exception.Message
        Pause-Any
    }
}

function TH-ProcLoop {
    Write-Section 'Live process loop (Ctrl+C to stop)'
    try {
        while ($true) {
            Clear-Host
            Write-Banner
            Write-Section "Live processes — $(Get-Date -Format 'HH:mm:ss')"
            Get-Process | Sort-Object CPU -Descending |
                Select-Object -First 25 Id, ProcessName, CPU, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, Path |
                Format-Table -AutoSize | Out-Host
            Start-Sleep -Seconds 3
        }
    } catch { }
}

function Module-ProcessHunt {
    while ($true) {
        $items = @(
            'Unsigned / invalid-signature binaries running',
            'Processes from Temp/AppData/ProgramData/Public',
            'Processes with empty/short command lines',
            'Hollow-looking parents (cmd/wscript/mshta/rundll32 spawning)',
            'Processes by uncommon owners',
            'Network-active processes (with connections)'
        )
        $c = Show-Menu -Title 'Process hunting (advanced)' -Items $items
        switch ($c) {
            '0' { return }
            '1' {
                $m = Get-ThProcessMap | Where-Object { $_.Path -and $_.SigStatus -and $_.SigStatus -ne 'Valid' }
                Out-Result -Data $m -BaseName 'hunt_unsigned' -Top 80 -Properties PID,Name,SigStatus,Signer,Path
            }
            '2' {
                $m = Get-ThProcessMap | Where-Object { $_.Path -and $_.Path -match '\\(Temp|AppData|ProgramData|Users\\Public|Windows\\Temp)\\' }
                Out-Result -Data $m -BaseName 'hunt_susp_paths' -Top 80 -Properties PID,Name,Owner,SigStatus,Path
            }
            '3' {
                $m = Get-ThProcessMap | Where-Object {
                    -not $_.CmdLine -or ($_.CmdLine -and $_.CmdLine.Length -lt 8)
                }
                Out-Result -Data $m -BaseName 'hunt_short_cmd' -Top 80 -Properties PID,Name,CmdLine,Path
            }
            '4' {
                $sus = 'cmd.exe|wscript.exe|cscript.exe|mshta.exe|rundll32.exe|regsvr32.exe|powershell.exe|pwsh.exe|wmic.exe|certutil.exe|bitsadmin.exe'
                $m = Get-ThProcessMap
                $byPid = @{}; foreach ($p in $m) { $byPid[$p.PID] = $p }
                $hits = foreach ($p in $m) {
                    $par = $byPid[$p.PPID]
                    if ($par -and $par.Name -and ($par.Name -match $sus)) {
                        [pscustomobject]@{
                            ParentPid  = $par.PID
                            ParentName = $par.Name
                            ParentCmd  = $par.CmdLine
                            ChildPid   = $p.PID
                            ChildName  = $p.Name
                            ChildCmd   = $p.CmdLine
                        }
                    }
                }
                Out-Result -Data $hits -BaseName 'hunt_susp_chain' -Top 80
            }
            '5' {
                $m = Get-ThProcessMap | Group-Object -Property Owner |
                    Sort-Object Count | Select-Object Count, Name
                Out-Result -Data $m -BaseName 'hunt_owners' -Top 30
            }
            '6' {
                $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
                $m = Get-ThProcessMap; $byPid = @{}; foreach ($p in $m) { $byPid[$p.PID] = $p }
                $rows = foreach ($c in $conns) {
                    $p = $byPid[[int]$c.OwningProcess]
                    [pscustomobject]@{
                        Pid     = $c.OwningProcess
                        Process = if ($p) { $p.Name } else { '?' }
                        Path    = if ($p) { $p.Path } else { '' }
                        Local   = "$($c.LocalAddress):$($c.LocalPort)"
                        Remote  = "$($c.RemoteAddress):$($c.RemotePort)"
                        State   = $c.State
                    }
                }
                Out-Result -Data $rows -BaseName 'hunt_netproc' -Top 100
            }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. MODULE: NETWORK
# ---------------------------------------------------------------------------
function Module-Network {
    while ($true) {
        $items = @(
            'TCP connections (Established) with PID + process',
            'TCP connections (All states)',
            'Listening ports (TCP)',
            'Listening ports (UDP)',
            'DNS client cache',
            'ARP table',
            'Routing table',
            'Network adapters / IPs',
            'Firewall profiles state',
            'Active SMB sessions / shares'
        )
        $c = Show-Menu -Title 'Network state' -Items $items
        switch ($c) {
            '0' { return }
            '1' { TH-NetTCP -State 'Established' }
            '2' { TH-NetTCP -State $null }
            '3' { TH-NetTCP -State 'Listen' }
            '4' { TH-NetUDPListen }
            '5' {
                try { $d = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordType, Status, TimeToLive, Data } catch { $d = @() }
                Out-Result -Data $d -BaseName 'net_dns' -Top 200
            }
            '6' {
                try { $a = Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias } catch { $a = @() }
                Out-Result -Data $a -BaseName 'net_arp' -Top 200
            }
            '7' {
                try { $r = Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, AddressFamily } catch { $r = @() }
                Out-Result -Data $r -BaseName 'net_route' -Top 200
            }
            '8' {
                try { $ad = Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, AddressState } catch { $ad = @() }
                Out-Result -Data $ad -BaseName 'net_addrs' -Top 100
            }
            '9' {
                try { $fw = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked } catch { $fw = @() }
                Out-Result -Data $fw -BaseName 'net_fw' -Top 10
            }
            '10' {
                try {
                    $shares = Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ScopeName, ShareType
                    $sess   = Get-SmbSession -ErrorAction Stop | Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
                } catch { $shares = @(); $sess = @() }
                Write-Section 'SMB shares'
                Out-Result -Data $shares -BaseName 'net_smb_shares' -Top 50
                Write-Section 'SMB sessions'
                Out-Result -Data $sess -BaseName 'net_smb_sessions' -Top 50
            }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function TH-NetTCP {
    param([string]$State)
    try {
        $params = @{ ErrorAction = 'Stop' }
        if ($State) { $params['State'] = $State }
        $conns = Get-NetTCPConnection @params
    } catch {
        Write-Err $_.Exception.Message; Pause-Any; return
    }
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $rows = foreach ($c in $conns) {
        $p = $byPid[[int]$c.OwningProcess]
        [pscustomobject]@{
            Local   = "$($c.LocalAddress):$($c.LocalPort)"
            Remote  = "$($c.RemoteAddress):$($c.RemotePort)"
            State   = $c.State
            Pid     = $c.OwningProcess
            Process = if ($p) { $p.Name } else { '?' }
            Path    = if ($p) { $p.ExecutablePath } else { '' }
        }
    }
    Out-Result -Data $rows -BaseName "net_tcp_$($State -as [string])" -Top 200
}

function TH-NetUDPListen {
    try { $u = Get-NetUDPEndpoint -ErrorAction Stop } catch { Write-Err $_.Exception.Message; Pause-Any; return }
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $rows = foreach ($c in $u) {
        $p = $byPid[[int]$c.OwningProcess]
        [pscustomobject]@{
            Local   = "$($c.LocalAddress):$($c.LocalPort)"
            Pid     = $c.OwningProcess
            Process = if ($p) { $p.Name } else { '?' }
            Path    = if ($p) { $p.ExecutablePath } else { '' }
        }
    }
    Out-Result -Data $rows -BaseName 'net_udp_listen' -Top 200
}

# ---------------------------------------------------------------------------
# 7. MODULE: PERSISTENCE + FORENSIC ARTEFACTS
# ---------------------------------------------------------------------------
function Module-Persistence {
    while ($true) {
        $items = @(
            'Scheduled tasks (all)',
            'Scheduled tasks (non-Microsoft / suspicious)',
            'Services (all)',
            'Services (non-Microsoft / auto-start)',
            'Run keys (HKLM + HKCU)',
            'Image File Execution Options (debugger hijack)',
            'WMI event subscriptions',
            'Startup folders (All Users + per-user)',
            'AppInit_DLLs',
            'Winlogon Userinit / Shell',
            'Drivers (non-Microsoft)',
            'PowerShell profiles on disk'
        )
        $c = Show-Menu -Title 'Persistence' -Items $items
        switch ($c) {
            '0' { return }
            '1' {
                try {
                    $t = Get-ScheduledTask -ErrorAction Stop | Select-Object TaskPath, TaskName, State, Author,
                        @{n='Action';e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }},
                        @{n='Trigger';e={ ($_.Triggers | ForEach-Object { $_.PSObject.TypeNames[0] }) -join ',' }}
                    Out-Result -Data $t -BaseName 'persist_tasks' -Top 200
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '2' {
                try {
                    $t = Get-ScheduledTask -ErrorAction Stop |
                        Where-Object { $_.Author -notmatch 'Microsoft|^$' -and $_.TaskPath -notmatch '^\\Microsoft' } |
                        Select-Object TaskPath, TaskName, State, Author,
                            @{n='Action';e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }}
                    Out-Result -Data $t -BaseName 'persist_tasks_susp' -Top 200
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '3' {
                $s = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                    Select-Object Name, DisplayName, State, StartMode, StartName, PathName
                Out-Result -Data $s -BaseName 'persist_services' -Top 300
            }
            '4' {
                $s = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                    Where-Object { $_.StartMode -eq 'Auto' } |
                    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
                    Where-Object { $_.PathName -and $_.PathName -notmatch 'Windows\\(System32|SysWOW64|Microsoft)' }
                Out-Result -Data $s -BaseName 'persist_services_susp' -Top 200
            }
            '5' {
                $paths = @(
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
                )
                $rows = foreach ($p in $paths) {
                    if (Test-Path $p) {
                        $vals = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                        if ($vals) {
                            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                                [pscustomobject]@{ Hive=$p; Name=$_.Name; Value=$_.Value }
                            }
                        }
                    }
                }
                Out-Result -Data $rows -BaseName 'persist_runkeys' -Top 200
            }
            '6' {
                $base = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
                if (Test-Path $base) {
                    $rows = Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                        $sub = $_.PSPath
                        $debugger = (Get-ItemProperty -Path $sub -Name Debugger -ErrorAction SilentlyContinue).Debugger
                        if ($debugger) {
                            [pscustomobject]@{ Image=$_.PSChildName; Debugger=$debugger }
                        }
                    }
                    Out-Result -Data $rows -BaseName 'persist_ifeo' -Top 100
                } else { Write-Info 'IFEO key not present.' }
            }
            '7' {
                try {
                    $f  = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter      -ErrorAction SilentlyContinue
                    $cs = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
                    $b  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
                    Write-Section '__EventFilter';            Out-Result -Data $f  -BaseName 'persist_wmi_filter'   -Top 50
                    Write-Section 'CommandLineEventConsumer'; Out-Result -Data $cs -BaseName 'persist_wmi_consumer' -Top 50
                    Write-Section '__FilterToConsumerBinding'; Out-Result -Data $b  -BaseName 'persist_wmi_binding'  -Top 50
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '8' {
                $paths = @(
                    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                )
                $rows = foreach ($p in $paths) {
                    if (Test-Path $p) {
                        Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue |
                            Select-Object @{n='Folder';e={$p}}, Name, Length, LastWriteTime, FullName
                    }
                }
                Out-Result -Data $rows -BaseName 'persist_startup' -Top 100
            }
            '9' {
                $keys = @(
                    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
                    'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
                )
                $rows = foreach ($k in $keys) {
                    if (Test-Path $k) {
                        $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                        if ($v) {
                            [pscustomobject]@{
                                Key             = $k
                                AppInit_DLLs    = $v.AppInit_DLLs
                                LoadAppInit_DLLs= $v.LoadAppInit_DLLs
                                RequireSigned   = $v.RequireSignedAppInit_DLLs
                            }
                        }
                    }
                }
                Out-Result -Data $rows -BaseName 'persist_appinit' -Top 10
            }
            '10' {
                $key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
                if (Test-Path $key) {
                    $v = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    $row = [pscustomobject]@{
                        Userinit = $v.Userinit
                        Shell    = $v.Shell
                        Taskman  = $v.Taskman
                        AutoAdminLogon = $v.AutoAdminLogon
                        DefaultUserName = $v.DefaultUserName
                    }
                    Out-Result -Data $row -BaseName 'persist_winlogon' -Top 5
                }
            }
            '11' {
                try {
                    $d = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                        Where-Object { $_.PathName -and $_.PathName -notmatch 'system32\\drivers\\(Microsoft|Windows)' } |
                        Select-Object Name, DisplayName, State, StartMode, PathName
                    Out-Result -Data $d -BaseName 'persist_drivers' -Top 200
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '12' {
                $profPaths = @(
                    "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1",
                    "$env:WINDIR\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
                    (Join-Path $HOME 'Documents\WindowsPowerShell\profile.ps1'),
                    (Join-Path $HOME 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
                    (Join-Path $HOME 'Documents\PowerShell\profile.ps1'),
                    (Join-Path $HOME 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1')
                )
                $rows = foreach ($p in $profPaths) {
                    if (Test-Path $p) {
                        $fi = Get-Item $p
                        [pscustomobject]@{
                            Path   = $p
                            Bytes  = $fi.Length
                            Modified = $fi.LastWriteTime
                            Head   = (Get-Content $p -TotalCount 5 -ErrorAction SilentlyContinue) -join ' / '
                        }
                    }
                }
                Out-Result -Data $rows -BaseName 'persist_psprofiles' -Top 20
            }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function Module-Forensics {
    while ($true) {
        $items = @(
            'Prefetch (recently executed binaries)',
            'Amcache (registry — execution history)',
            'ShimCache / AppCompatCache (note: limited extraction)',
            'BAM/DAM activity (HKLM\System\CurrentControlSet\Services\bam)',
            'Recent docs / RecentApps',
            'UserAssist (decoded ROT13)',
            'MUICache (executed names)'
        )
        $c = Show-Menu -Title 'Forensic artefacts' -Items $items
        switch ($c) {
            '0' { return }
            '1' {
                $pf = "$env:WINDIR\Prefetch"
                if (-not (Test-Path $pf)) { Write-Warn2 'Prefetch not found.'; Pause-Any; continue }
                try {
                    $rows = Get-ChildItem -Path $pf -Filter *.pf -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object Name, LastWriteTime, CreationTime, Length, FullName
                    Out-Result -Data $rows -BaseName 'forensic_prefetch' -Top 200
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '2' {
                $am = 'HKLM:\SOFTWARE\Microsoft\Amcache.hve\Root\InventoryApplicationFile'
                $am2= 'HKLM:\SOFTWARE\Microsoft\Amcache\Root\InventoryApplicationFile'
                $rows = @()
                foreach ($k in @($am, $am2)) {
                    if (Test-Path $k) {
                        $rows += Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                            $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                            [pscustomobject]@{
                                Key      = $_.PSChildName
                                Name     = $v.Name
                                Path     = $v.LowerCaseLongPath
                                Hash     = $v.FileId
                                Publisher= $v.Publisher
                                Version  = $v.Version
                            }
                        }
                    }
                }
                Out-Result -Data $rows -BaseName 'forensic_amcache' -Top 200
            }
            '3' {
                Write-Info 'ShimCache lives in HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache (binary). Decoding it properly requires a parser. Listing raw value sizes only.'
                $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
                if (Test-Path $k) {
                    $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    if ($v.AppCompatCache) {
                        $row = [pscustomobject]@{
                            ValueBytes = $v.AppCompatCache.Length
                            Note       = 'Use a dedicated parser (AppCompatCacheParser.exe) for full content.'
                        }
                        Out-Result -Data $row -BaseName 'forensic_shimcache' -Top 1
                    }
                }
            }
            '4' {
                $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
                $base2= 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
                $rows = @()
                foreach ($b in @($base, $base2)) {
                    if (Test-Path $b) {
                        Get-ChildItem $b -ErrorAction SilentlyContinue | ForEach-Object {
                            $sid = $_.PSChildName
                            $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                            $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Version|^SequenceNumber' } | ForEach-Object {
                                $rows += [pscustomobject]@{ SID=$sid; Path=$_.Name; ValueBytes=([byte[]]$_.Value).Length }
                            }
                        }
                    }
                }
                Out-Result -Data $rows -BaseName 'forensic_bam' -Top 300
            }
            '5' {
                $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'
                if (Test-Path $k) {
                    $rows = Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                        $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        [pscustomobject]@{
                            AppId       = $v.AppId
                            AppPath     = $v.AppPath
                            LastAccessed = if ($v.LastAccessedTime) { [datetime]::FromFileTime([int64]$v.LastAccessedTime) } else { $null }
                            LaunchCount = $v.LaunchCount
                        }
                    }
                    Out-Result -Data $rows -BaseName 'forensic_recentapps' -Top 100
                } else { Write-Info 'RecentApps key not found.' }
            }
            '6' {
                $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
                if (Test-Path $base) {
                    $rows = @()
                    Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                        $countKey = Join-Path $_.PSPath 'Count'
                        if (Test-Path $countKey) {
                            $vals = Get-ItemProperty -Path $countKey -ErrorAction SilentlyContinue
                            $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                                $name = $_.Name
                                # ROT13 decode
                                $dec = -join ($name.ToCharArray() | ForEach-Object {
                                    $ch = $_
                                    if ($ch -match '[a-z]') { [char](((([int][char]$ch) - 97 + 13) % 26) + 97) }
                                    elseif ($ch -match '[A-Z]') { [char](((([int][char]$ch) - 65 + 13) % 26) + 65) }
                                    else { $ch }
                                })
                                $rows += [pscustomobject]@{ Decoded=$dec; ValueBytes=([byte[]]$_.Value).Length }
                            }
                        }
                    }
                    Out-Result -Data $rows -BaseName 'forensic_userassist' -Top 200
                } else { Write-Info 'UserAssist key not found.' }
            }
            '7' {
                $k = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
                if (Test-Path $k) {
                    $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    $rows = $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -match '\.exe' } |
                        ForEach-Object { [pscustomobject]@{ Path=$_.Name; Friendly=$_.Value } }
                    Out-Result -Data $rows -BaseName 'forensic_muicache' -Top 200
                } else { Write-Info 'MUICache key not found.' }
            }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

# ---------------------------------------------------------------------------
# 8. MODULE: USERS / LOGONS / AUTH
# ---------------------------------------------------------------------------
function Module-UsersLogons {
    while ($true) {
        $items = @(
            'Local users',
            'Local groups + members',
            'Privileged group members (Administrators / Backup Operators / etc.)',
            'Currently logged on (quser/CIM)',
            'Successful logons (4624) — choose time range',
            'Failed logons (4625) — choose time range',
            'Privileged logons (4672) — choose time range',
            'Account lockouts (4740)',
            'Explicit credential use (4648)',
            'Account changes (4720/4722/4723/4724/4725/4726/4738)',
            'RDP sessions history (TerminalServices-LocalSessionManager)',
            'Last password set / password ages'
        )
        $c = Show-Menu -Title 'Users / Logons / Authentication' -Items $items
        switch ($c) {
            '0' { return }
            '1' {
                try {
                    $u = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired, Description
                    Out-Result -Data $u -BaseName 'auth_localusers' -Top 100
                } catch {
                    $u = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue | Select-Object Name, Disabled, Lockout, FullName, SID
                    Out-Result -Data $u -BaseName 'auth_localusers_wmi' -Top 100
                }
            }
            '2' {
                try {
                    $g = Get-LocalGroup -ErrorAction Stop
                    $rows = foreach ($grp in $g) {
                        $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
                        [pscustomobject]@{
                            Group   = $grp.Name
                            Count   = ($members | Measure-Object).Count
                            Members = ($members | ForEach-Object { $_.Name }) -join ', '
                        }
                    }
                    Out-Result -Data $rows -BaseName 'auth_localgroups' -Top 50
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '3' {
                $priv = @('Administrators','Backup Operators','Remote Desktop Users','Remote Management Users','Hyper-V Administrators','Power Users','Distributed COM Users')
                $rows = foreach ($g in $priv) {
                    try {
                        $m = Get-LocalGroupMember -Group $g -ErrorAction Stop
                        foreach ($mb in $m) {
                            [pscustomobject]@{ Group=$g; Member=$mb.Name; ObjectClass=$mb.ObjectClass; PrincipalSource=$mb.PrincipalSource }
                        }
                    } catch { }
                }
                Out-Result -Data $rows -BaseName 'auth_priv_members' -Top 100
            }
            '4' {
                try {
                    $q = quser 2>$null
                    if ($q) {
                        Write-SessionBlock -Title 'quser' -Data ($q -join "`n")
                        $q | ForEach-Object { Write-Host ('  ' + $_) }
                    } else {
                        $s = Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
                            Select-Object LogonId, LogonType, StartTime, AuthenticationPackage
                        Out-Result -Data $s -BaseName 'auth_logonsessions' -Top 50
                    }
                    Pause-Any
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '5'  { Test-Admin; TH-AuthEvents 4624 'auth_4624' }
            '6'  { Test-Admin; TH-AuthEvents 4625 'auth_4625' }
            '7'  { Test-Admin; TH-AuthEvents 4672 'auth_4672' }
            '8'  { Test-Admin; TH-AuthEvents 4740 'auth_4740' }
            '9'  { Test-Admin; TH-AuthEvents 4648 'auth_4648' }
            '10' { Test-Admin; TH-AuthEvents @(4720,4722,4723,4724,4725,4726,4738) 'auth_acct_changes' }
            '11' {
                Test-Admin
                $tr = Get-TimeRange '7d'
                try {
                    $ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; StartTime=$tr.Start; EndTime=$tr.End } -ErrorAction Stop |
                        Where-Object { $_.Id -in 21,22,23,24,25,39,40 } |
                        Select-Object TimeCreated, Id, @{n='Msg';e={ ([string]$_.Message -replace '\s+',' ').Substring(0,[Math]::Min(200,([string]$_.Message).Length)) }}
                    Out-Result -Data $ev -BaseName 'auth_rdp_session' -Top 100
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            '12' {
                try {
                    $u = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
                        @{n='PwdAgeDays';e={ if ($_.PasswordLastSet) { [int](((Get-Date) - $_.PasswordLastSet).TotalDays) } else { $null } }}
                    Out-Result -Data $u -BaseName 'auth_pwdages' -Top 50
                } catch { Write-Err $_.Exception.Message; Pause-Any }
            }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function TH-AuthEvents {
    param([object]$EventIds, [string]$BaseName)
    $tr = Get-TimeRange '24h'
    try {
        $hash = @{ LogName='Security'; Id=$EventIds; StartTime=$tr.Start; EndTime=$tr.End }
        $ev = Get-WinEvent -FilterHashtable $hash -ErrorAction Stop |
            Select-Object TimeCreated, Id,
                @{n='Account';e={ ($_.Properties[5].Value) }},
                @{n='Domain'; e={ ($_.Properties[6].Value) }},
                @{n='Source'; e={ try { $_.Properties[18].Value } catch { '' } }},
                @{n='Type';   e={ try { $_.Properties[8].Value }  catch { '' } }},
                @{n='Msg';    e={ ([string]$_.Message -replace '\s+',' ').Substring(0, [Math]::Min(200, ([string]$_.Message).Length)) }}
        Out-Result -Data $ev -BaseName $BaseName -Top 200
    } catch { Write-Err $_.Exception.Message; Pause-Any }
}

# ---------------------------------------------------------------------------
# 9. MODULE: FILES & IOC
# ---------------------------------------------------------------------------
function Load-IOCs {
    if (-not $Script:TH.IocFile) { return @() }
    if (-not (Test-Path $Script:TH.IocFile)) { Write-Warn2 "IOC file not found: $($Script:TH.IocFile)"; return @() }
    try {
        $rows = Import-Csv -Path $Script:TH.IocFile
        # Ensure expected columns
        $clean = foreach ($r in $rows) {
            if (-not $r.type -or -not $r.value) { continue }
            [pscustomobject]@{
                Type        = $r.type.ToLower().Trim()
                Value       = $r.value.Trim()
                Description = $r.description
            }
        }
        Write-Ok ("Loaded $(@($clean).Count) IOC(s) from $($Script:TH.IocFile)")
        return ,$clean
    } catch { Write-Err "IOC load failed: $($_.Exception.Message)"; return @() }
}

function Module-FilesIOC {
    if ($Script:TH.Iocs.Count -eq 0) { $Script:TH.Iocs = Load-IOCs }
    while ($true) {
        $iocCount = @($Script:TH.Iocs).Count
        $items = @(
            "Load / reload IOC CSV  (current: $iocCount loaded)",
            'Hash files (compute MD5/SHA1/SHA256)',
            'Find recently created/modified files in suspicious paths',
            'Search files by name pattern in path',
            'Match running processes against IOC list',
            'Match TCP remote IPs against IOC list',
            'Match DNS cache against IOC list',
            'Sysmon: parse last N events',
            'Files larger than X MB in user paths'
        )
        $c = Show-Menu -Title 'Files & IOC' -Items $items
        switch ($c) {
            '0' { return }
            '1' {
                $p = Read-Prompt 'IOC CSV path (blank = use param)'
                if ($p) { $Script:TH.IocFile = $p }
                $Script:TH.Iocs = Load-IOCs
                Pause-Any
            }
            '2' { TH-HashFiles }
            '3' { TH-RecentSuspFiles }
            '4' { TH-FileSearch }
            '5' { TH-IocMatchProcs }
            '6' { TH-IocMatchTcp }
            '7' { TH-IocMatchDns }
            '8' { TH-SysmonParse }
            '9' { TH-LargeFiles }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

function TH-HashFiles {
    $p = Read-Prompt 'file or folder path'
    if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path $p)) { Write-Warn2 'Path not found.'; return }
    $algo = (Read-Prompt 'algorithm: MD5/SHA1/SHA256 [SHA256]').ToUpper()
    if ([string]::IsNullOrWhiteSpace($algo)) { $algo = 'SHA256' }
    $rec = Confirm-Yes 'Recurse into subfolders?'
    try {
        $files = if ((Get-Item $p).PSIsContainer) {
            if ($rec) { Get-ChildItem -Path $p -File -Recurse -ErrorAction SilentlyContinue }
            else      { Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue }
        } else { Get-Item $p }
        $rows = foreach ($f in $files) {
            try {
                $h = Get-FileHash -Path $f.FullName -Algorithm $algo -ErrorAction Stop
                [pscustomobject]@{
                    Hash     = $h.Hash
                    Algo     = $h.Algorithm
                    Path     = $f.FullName
                    SizeKB   = [math]::Round($f.Length/1KB,1)
                    Modified = $f.LastWriteTime
                }
            } catch { }
        }
        # Auto-match against IOCs if loaded
        if ($Script:TH.Iocs.Count -gt 0) {
            $hashIocs = $Script:TH.Iocs | Where-Object { $_.Type -in @('md5','sha1','sha256') }
            if ($hashIocs) {
                $hits = $rows | Where-Object { $hashIocs.Value -contains $_.Hash }
                if ($hits) {
                    Write-Section 'IOC HASH MATCHES'
                    Out-Result -Data $hits -BaseName 'ioc_hash_match' -Top 100
                    foreach ($h in $hits) { Add-Finding -Module 'Files/IOC' -Severity 'critical' -Title 'IOC hash match' -Detail "$($h.Algo) $($h.Hash) :: $($h.Path)" -Evidence $h }
                }
            }
        }
        Out-Result -Data $rows -BaseName 'hashes' -Top 200
    } catch { Write-Err $_.Exception.Message; Pause-Any }
}

function TH-RecentSuspFiles {
    $hours = Read-Prompt 'modified within last N hours [24]'
    if ([string]::IsNullOrWhiteSpace($hours)) { $hours = 24 }
    $hours = [int]$hours
    $cut = (Get-Date).AddHours(-$hours)
    $paths = @(
        $env:TEMP,
        "$env:WINDIR\Temp",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:ProgramData",
        "$env:PUBLIC"
    )
    $rows = foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cut } |
                Select-Object FullName, Length, LastWriteTime, CreationTime
        }
    }
    Out-Result -Data $rows -BaseName 'files_recent_susp' -Top 200
}

function TH-FileSearch {
    $base = Read-Prompt 'base path'
    $pat  = Read-Prompt 'name pattern (wildcards, e.g., *.ps1, *invoice*)'
    if (-not (Test-Path $base)) { Write-Warn2 'Path not found.'; return }
    try {
        $rec = Confirm-Yes 'Recurse?'
        $gci = @{ Path=$base; Filter=$pat; File=$true; ErrorAction='SilentlyContinue' }
        if ($rec) { $gci['Recurse'] = $true }
        $rows = Get-ChildItem @gci | Select-Object FullName, Length, LastWriteTime, CreationTime
        Out-Result -Data $rows -BaseName 'files_search' -Top 300
    } catch { Write-Err $_.Exception.Message; Pause-Any }
}

function TH-IocMatchProcs {
    if ($Script:TH.Iocs.Count -eq 0) { Write-Warn2 'Load an IOC CSV first.'; return }
    $procs = Get-ThProcessMap
    $names = $Script:TH.Iocs | Where-Object { $_.Type -eq 'filename' } | Select-Object -ExpandProperty Value
    $hits = @()
    foreach ($p in $procs) {
        foreach ($n in $names) {
            if ($p.Path -and ($p.Path -like "*$n*")) { $hits += $p; break }
            if ($p.Name -and ($p.Name -like "*$n*")) { $hits += $p; break }
        }
    }
    Out-Result -Data $hits -BaseName 'ioc_match_procs' -Top 100
    if ($hits) { foreach ($h in $hits) { Add-Finding -Module 'Files/IOC' -Severity 'high' -Title 'IOC filename match in running process' -Detail "$($h.Name) — $($h.Path)" -Evidence $h } }
}

function TH-IocMatchTcp {
    if ($Script:TH.Iocs.Count -eq 0) { Write-Warn2 'Load an IOC CSV first.'; return }
    try { $conns = Get-NetTCPConnection -ErrorAction Stop } catch { Write-Err $_.Exception.Message; return }
    $ips = $Script:TH.Iocs | Where-Object { $_.Type -eq 'ip' } | Select-Object -ExpandProperty Value
    $hits = $conns | Where-Object { $ips -contains $_.RemoteAddress }
    Out-Result -Data ($hits | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess) -BaseName 'ioc_match_tcp' -Top 100
    if ($hits) { foreach ($h in $hits) { Add-Finding -Module 'Files/IOC' -Severity 'critical' -Title 'IOC IP match in TCP connection' -Detail "$($h.RemoteAddress):$($h.RemotePort) PID=$($h.OwningProcess)" -Evidence $h } }
}

function TH-IocMatchDns {
    if ($Script:TH.Iocs.Count -eq 0) { Write-Warn2 'Load an IOC CSV first.'; return }
    try { $cache = Get-DnsClientCache -ErrorAction Stop } catch { Write-Err $_.Exception.Message; return }
    $doms = $Script:TH.Iocs | Where-Object { $_.Type -eq 'domain' } | Select-Object -ExpandProperty Value
    $hits = $cache | Where-Object { $e = $_.Entry; $doms | Where-Object { $e -like "*$_*" } }
    Out-Result -Data $hits -BaseName 'ioc_match_dns' -Top 100
    if ($hits) { foreach ($h in $hits) { Add-Finding -Module 'Files/IOC' -Severity 'high' -Title 'IOC domain in DNS cache' -Detail "$($h.Entry)" -Evidence $h } }
}

function TH-SysmonParse {
    $tr = Get-TimeRange '24h'
    $idsRaw = Read-Prompt 'Sysmon event IDs (comma; blank = 1,3,7,11,22,25)'
    if ([string]::IsNullOrWhiteSpace($idsRaw)) { $ids = @(1,3,7,11,22,25) }
    else { $ids = $idsRaw -split '[,;\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } }
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=$ids; StartTime=$tr.Start; EndTime=$tr.End } -ErrorAction Stop |
            Select-Object TimeCreated, Id, @{n='Msg';e={ ([string]$_.Message -replace '\s+',' ').Substring(0,[Math]::Min(220,([string]$_.Message).Length)) }}
        Out-Result -Data $ev -BaseName 'sysmon_events' -Top 300
    } catch { Write-Err "Sysmon channel not available or no data: $($_.Exception.Message)"; Pause-Any }
}

function TH-LargeFiles {
    $mb = Read-Prompt 'min size in MB [50]'
    if ([string]::IsNullOrWhiteSpace($mb)) { $mb = 50 }
    $bytes = [int64]$mb * 1MB
    $paths = @($env:USERPROFILE, $env:ProgramData, $env:TEMP)
    $rows = foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -ge $bytes } |
                Select-Object FullName, @{n='SizeMB';e={[math]::Round($_.Length/1MB,1)}}, LastWriteTime
        }
    }
    Out-Result -Data $rows -BaseName 'files_large' -Top 100
}

# ---------------------------------------------------------------------------
# 10. MODULE: ARBITRARY CMD / POWERSHELL EXECUTION
# ---------------------------------------------------------------------------
$Script:DestructivePatterns = @(
    'Remove-Item','rm\s','rmdir','del\s','erase\s',
    'Format-Volume','format\s+[a-z]:',
    'Stop-Computer','Restart-Computer','shutdown\s','logoff',
    'Stop-Process','taskkill','kill\s+',
    'Stop-Service','sc\s+stop','sc\s+delete',
    'Disable-Service','Set-Service.*-StartupType\s+Disabled',
    'Clear-EventLog','Remove-EventLog','wevtutil\s+(cl|clear-log)',
    'Disable-NetAdapter','netsh\s+advfirewall\s+reset','netsh\s+advfirewall\s+set\s+all\s+state\s+off',
    'reg\s+delete','Remove-ItemProperty',
    'New-PSDrive.*-Persist',
    'Set-ExecutionPolicy.*Unrestricted',
    'Invoke-Expression','iex\s',
    'DownloadString','DownloadFile','Invoke-WebRequest.*-OutFile',
    'Add-MpPreference.*ExclusionPath','Set-MpPreference.*DisableRealtimeMonitoring',
    'cipher\s+/w','sdelete'
)

function Test-Destructive {
    param([string]$Command)
    foreach ($p in $Script:DestructivePatterns) {
        if ($Command -match $p) { return $p }
    }
    return $null
}

function Module-Cmd {
    Write-Section 'cmd execution'
    Write-Sub 'type a cmd.exe command. multi-line not supported. empty = back.'
    while ($true) {
        $cmd = Read-Prompt 'cmd'
        if ([string]::IsNullOrWhiteSpace($cmd)) { return }
        $hit = Test-Destructive $cmd
        if ($hit) {
            Write-Warn2 "destructive pattern matched: '$hit'"
            if (-not (Confirm-Yes 'run anyway?')) { Write-Info 'skipped.'; continue }
        }
        Write-Session -Category 'CMD' -Message $cmd
        try {
            $out = & cmd.exe /c $cmd 2>&1
            $text = $out | Out-String
            Write-Host $text
            Write-SessionBlock -Title "cmd: $cmd" -Data $text
            $Script:TH.LastResult = $out
        } catch { Write-Err $_.Exception.Message }
    }
}

function Module-PowerShell {
    Write-Section 'powershell execution'
    Write-Sub 'type a PS expression.  type SCRIPT to load and run a .ps1 file.  empty = back.'
    while ($true) {
        $cmd = Read-Prompt 'ps'
        if ([string]::IsNullOrWhiteSpace($cmd)) { return }
        if ($cmd -match '^\s*SCRIPT\s*$') {
            $p = Read-Prompt 'script path'
            if (-not (Test-Path $p)) { Write-Warn2 'file not found.'; continue }
            $body = Get-Content -Raw -Path $p
            $hit = Test-Destructive $body
            if ($hit) {
                Write-Warn2 "destructive pattern in script: '$hit'"
                if (-not (Confirm-Yes 'run anyway?')) { continue }
            }
            Write-Session -Category 'PS-SCRIPT' -Message $p
            try {
                $sb = [scriptblock]::Create($body)
                $out = & $sb 2>&1
                $text = $out | Out-String
                Write-Host $text
                Write-SessionBlock -Title "ps script: $p" -Data $text
                $Script:TH.LastResult = $out
            } catch { Write-Err $_.Exception.Message }
            continue
        }
        $hit = Test-Destructive $cmd
        if ($hit) {
            Write-Warn2 "destructive pattern matched: '$hit'"
            if (-not (Confirm-Yes 'run anyway?')) { Write-Info 'skipped.'; continue }
        }
        Write-Session -Category 'PS' -Message $cmd
        try {
            $sb = [scriptblock]::Create($cmd)
            $out = & $sb 2>&1
            $text = $out | Out-String
            Write-Host $text
            Write-SessionBlock -Title "ps: $cmd" -Data $text
            $Script:TH.LastResult = $out
        } catch { Write-Err $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------
# 11. ABOUT / HELP
# ---------------------------------------------------------------------------
function Show-About {
    Write-Section 'about'

    $info = @(
        @{ Text = " ◆ ThreatHunter  v$($Script:TH.Version)"; Style = 'accenthi' },
        @{ Text = "   standalone PowerShell TUI for IR / threat hunting"; Style = 'mute' },
        @{ Sep  = $true },
        @{ Text = "   output dir : $($Script:TH.OutDir)"; Style = 'mute' },
        @{ Text = "   session log: $($Script:TH.LogPath)"; Style = 'mute' },
        @{ Text = "   IOC file   : $(if ($Script:TH.IocFile) { $Script:TH.IocFile } else { '(none)' })"; Style = 'mute' }
    )
    Show-Card -Title 'session' -Body $info

    Write-Host ''
    Write-C "  slash commands" -Style 'accenthi'
    $slashRows = foreach ($k in $Script:SlashMap.Keys) {
        @{ Text = ("  /{0,-10}  {1}" -f $k, $Script:SlashMap[$k].Desc); Style = 'text' }
    }
    Show-Card -Title 'commands' -Body $slashRows

    Write-Host ''
    Write-C "  tips" -Style 'accenthi'
    $tips = @(
        "  · time ranges accept   1h  6h  24h  7d  30d  all   or   yyyy-MM-dd..yyyy-MM-dd",
        "  · in any result view:  (e)xport CSV/JSON  ·  (f)lag as finding  ·  (v)iew all",
        "  · destructive cmd/PS commands always prompt for confirmation",
        "  · IOC CSV format:      type,value,description",
        "      type ∈ md5 | sha1 | sha256 | ip | domain | filename | regkey",
        "  · on exit you can save a Markdown report consolidating findings"
    )
    foreach ($t in $tips) { Write-C $t -Style 'text' }
    Write-Host ''
    Pause-Any
}

# ---------------------------------------------------------------------------
# 12. MAIN MENU LOOP
# ---------------------------------------------------------------------------
function Main-Loop {
    Clear-Host
    Write-Banner
    Write-Session -Category 'SESSION' -Message "Started session $($Script:TH.SessionId) by $($Script:TH.User) on $($Script:TH.Host) (Admin=$($Script:TH.IsAdmin), PS=$($Script:TH.PSVersion))"

    $hints = @{
        ' 1' = 'events';   ' 2' = 'search';   ' 3' = 'procs';     ' 4' = 'hunt';
        ' 5' = 'net';      ' 6' = 'persist';  ' 7' = 'forensics'; ' 8' = 'auth';
        ' 9' = 'files';    '10' = 'cmd';      '11' = 'ps';        '12' = 'findings';
        '13' = 'report';   '14' = 'help'
    }

    while ($true) {
        $items = @(
            'Event Viewer (browse & quick views)',
            'Event Search (filter by channel/ID/level/keyword/time)',
            'Process Monitor',
            'Process Hunting (advanced)',
            'Network state',
            'Persistence',
            'Forensic artefacts (Prefetch/Amcache/UserAssist/...)',
            'Users / Logons / Authentication',
            'Files & IOC',
            'Run CMD command',
            'Run PowerShell command / script',
            'Show findings',
            'Save report now',
            'About / Help'
        )
        $titleStr = "main menu  ·  findings: $($Script:TH.Findings.Count)"
        $c = Show-Menu -Title $titleStr -Items $items -Footer "0) exit   ·   /q to quit   ·   try /events  /procs  /net  /files" -SlashHints $hints

        if ($c -and $c.StartsWith('/')) {
            $resolved = Resolve-Slash $c
            if ($resolved -eq '__UNKNOWN__') {
                Write-Warn2 "unknown slash command: $c. type /help for the list."
                continue
            }
            $c = $resolved
        }

        switch ($c) {
            '0' {
                if ($Script:TH.Findings.Count -gt 0 -or -not $Script:TH.NoLog) {
                    if (Confirm-Yes 'save final markdown report before exit?') { Save-Report }
                }
                Write-Session -Category 'SESSION' -Message 'Session ended'
                Write-Host ''
                Write-C "  ◆ session closed. stay sharp." -Style 'accent'
                Write-Host ''
                return
            }
            '1'  { Module-EventViewer }
            '2'  { Module-EventSearch }
            '3'  { Module-ProcessMonitor }
            '4'  { Module-ProcessHunt }
            '5'  { Module-Network }
            '6'  { Module-Persistence }
            '7'  { Module-Forensics }
            '8'  { Module-UsersLogons }
            '9'  { Module-FilesIOC }
            '10' { Module-Cmd }
            '11' { Module-PowerShell }
            '12' { Show-Findings; Pause-Any }
            '13' { Save-Report; Pause-Any }
            '14' { Show-About }
            default { Write-Warn2 "unrecognised input. type a number, or a /command." }
        }
    }
}

# ---------------------------------------------------------------------------
# 13. NON-INTERACTIVE ACTION MODE  (Live Response / scripting)
# ---------------------------------------------------------------------------

# Detect action mode. Any of these switches/strings triggers non-interactive flow.
$Script:ActionMode = $false
if ($Cmd -or $PS -or $Script -or $Procs -or $Net -or $Persist -or $Forensics -or
    $Auth -or $Files -or $EvtSearch -or $EvtQuick -or $EvtChannels -or $ProcSearch -or
    $Hash -or $FileSearch -or $IocMatch -or $Hunt -or $ListActions -or $Help) {
    $Script:ActionMode = $true
}

# Resolve effective output format for non-interactive emission.
function Resolve-Format {
    if ($Format -ne 'Auto') { return $Format }
    try { if ([Console]::IsOutputRedirected) { return 'Json' } } catch { }
    return 'Table'
}

# Belt-and-braces: silence banners / colours when running in action mode.
if ($Script:ActionMode) {
    $Script:TH.NoColor = $true
    $Script:UseAnsi    = $false
    if (-not $PSBoundParameters.ContainsKey('Quiet')) { $Quiet = $true }
}
$Script:OutFmt = Resolve-Format

# Single emitter used by every Action-* function.
function Out-Action {
    param(
        [Parameter(Mandatory)][AllowNull()]$Data,
        [string]$BaseName = 'result',
        [int]$TopN
    )
    if (-not $TopN) { $TopN = $Top }
    if ($null -eq $Data -or ($Data -is [System.Array] -and $Data.Count -eq 0)) {
        if ($Script:OutFmt -eq 'Json') { '[]' | Write-Output }
        elseif (-not $Quiet)           { Write-Host '(no data)' }
        Write-Session -Category 'ACTION' -Message "$BaseName : 0 rows"
        return
    }
    $arr = @($Data)
    $count = $arr.Count
    $view  = if ($count -gt $TopN) { $arr | Select-Object -First $TopN } else { $arr }
    Write-Session -Category 'ACTION' -Message "$BaseName : $count rows (emitting $($view.Count))"
    Write-SessionBlock -Title $BaseName -Data ($view | Format-Table -AutoSize | Out-String)
    switch ($Script:OutFmt) {
        'Json'  { $view | ConvertTo-Json -Depth 6 | Write-Output }
        'Csv'   { ($view | ConvertTo-Csv -NoTypeInformation) | Write-Output }
        default { $view | Format-Table -AutoSize -Wrap | Out-Host }
    }
}

# Parametric time-range parser (no prompts).
function Resolve-Range {
    param([string]$R = '24h')
    $now = Get-Date
    if ($R -eq 'all') { return [pscustomobject]@{ Start=[datetime]'1970-01-01'; End=$now } }
    if ($R -match '^\s*(\d+)\s*([hdwm])\s*$') {
        $n = [int]$matches[1]; $u = $matches[2].ToLower()
        $start = switch ($u) {
            'h' { $now.AddHours(-$n) }
            'd' { $now.AddDays(-$n) }
            'w' { $now.AddDays(-$n*7) }
            'm' { $now.AddMonths(-$n) }
        }
        return [pscustomobject]@{ Start=$start; End=$now }
    }
    if ($R -match '^\s*(\d{4}-\d{2}-\d{2})\.\.(\d{4}-\d{2}-\d{2})\s*$') {
        $s = [datetime]::ParseExact($matches[1],'yyyy-MM-dd',$null)
        $e = [datetime]::ParseExact($matches[2],'yyyy-MM-dd',$null).AddDays(1).AddSeconds(-1)
        return [pscustomobject]@{ Start=$s; End=$e }
    }
    return [pscustomobject]@{ Start=$now.AddDays(-1); End=$now }
}

# ---- Action implementations ----------------------------------------------
function Action-Fail {
    param([string]$Message, [int]$Code = 2)
    try { [Console]::Error.WriteLine("[ERR] $Message") } catch { Write-Error $Message }
    Write-Session -Category 'ERROR' -Message $Message
    exit $Code
}


function Action-Cmd {
    if (-not $Force) {
        $hit = Test-Destructive $Cmd
        if ($hit) { Action-Fail "destructive pattern matched: '$hit'. use -Force to bypass." 2 }
    }
    Write-Session -Category 'CMD' -Message $Cmd
    $out  = & cmd.exe /c $Cmd 2>&1
    $code = $LASTEXITCODE
    $text = ($out | Out-String).TrimEnd()
    Write-SessionBlock -Title "cmd: $Cmd" -Data $text
    if ($Script:OutFmt -eq 'Json') {
        [pscustomobject]@{ cmd=$Cmd; exitCode=$code; output=$text } | ConvertTo-Json -Depth 4
    } else {
        Write-Output $text
    }
}

function Action-PS {
    if (-not $Force) {
        $hit = Test-Destructive $PS
        if ($hit) { Action-Fail "destructive pattern matched: '$hit'. use -Force to bypass." 2 }
    }
    Write-Session -Category 'PS' -Message $PS
    $sb  = [scriptblock]::Create($PS)
    $out = & $sb 2>&1
    $arr = @($out)
    Write-SessionBlock -Title "ps: $PS" -Data ($arr | Out-String)
    if ($Script:OutFmt -eq 'Json') {
        $clean = $arr | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                [pscustomobject]@{ type='error'; message=$_.Exception.Message }
            } else { $_ }
        }
        $clean | ConvertTo-Json -Depth 6
    } else {
        $out | Out-Host
    }
}

function Action-Script {
    if (-not (Test-Path $Script)) { Action-Fail "script not found: $Script" 2 }
    $body = Get-Content -Raw -Path $Script
    if (-not $Force) {
        $hit = Test-Destructive $body
        if ($hit) { Action-Fail "destructive pattern in script: '$hit'. use -Force to bypass." 2 }
    }
    Write-Session -Category 'PS-SCRIPT' -Message $Script
    $sb   = [scriptblock]::Create($body)
    $out  = & $sb 2>&1
    $text = $out | Out-String
    Write-SessionBlock -Title "ps script: $Script" -Data $text
    if ($Script:OutFmt -eq 'Json') {
        [pscustomobject]@{ script=$Script; output=$text.TrimEnd() } | ConvertTo-Json -Depth 4
    } else {
        Write-Output $text
    }
}

function Action-Procs {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'list' }
    switch ($sub) {
        'list' {
            $m = Get-ThProcessMap | Select-Object PID, PPID, Name, Owner, SigStatus, Path, CmdLine
            Out-Action -Data $m -BaseName 'procs_list' -TopN ($Top * 4)
        }
        'tree' {
            # Flat representation of the parent/child tree, with depth + path
            $m = Get-ThProcessMap
            $byPid = @{}; foreach ($p in $m) { $byPid[$p.PID] = $p }
            $children = @{}
            foreach ($p in $m) {
                if (-not $children.ContainsKey($p.PPID)) { $children[$p.PPID] = New-Object System.Collections.Generic.List[object] }
                $children[$p.PPID].Add($p) | Out-Null
            }
            $rows = New-Object System.Collections.Generic.List[object]
            $script:_visit = {
                param($node, $depth)
                $tag = ''
                if ($node.SigStatus -and $node.SigStatus -ne 'Valid') { $tag += "SIG:$($node.SigStatus) " }
                if ($node.Path -and $node.Path -match '\\(Temp|AppData|ProgramData|Users\\Public)\\') { $tag += 'PATH-SUSP ' }
                $rows.Add([pscustomobject]@{
                    Depth=$depth; PID=$node.PID; PPID=$node.PPID; Name=$node.Name
                    Owner=$node.Owner; SigStatus=$node.SigStatus; Tag=$tag.Trim()
                    Path=$node.Path; CmdLine=$node.CmdLine
                }) | Out-Null
                if ($children.ContainsKey($node.PID)) {
                    foreach ($ch in ($children[$node.PID] | Sort-Object Name)) {
                        & $script:_visit $ch ($depth+1)
                    }
                }
            }
            $roots = $m | Where-Object { -not $byPid.ContainsKey($_.PPID) -or $_.PPID -eq 0 -or $_.PID -eq $_.PPID } | Sort-Object Name
            foreach ($r in $roots) { & $script:_visit $r 0 }
            Out-Action -Data $rows.ToArray() -BaseName 'procs_tree' -TopN ($Top * 8)
        }
        'topcpu' {
            $p = Get-Process | Sort-Object CPU -Descending | Select-Object -First ($Top * 2) `
                Id, ProcessName, CPU, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, Path
            Out-Action -Data $p -BaseName 'procs_top_cpu' -TopN ($Top * 2)
        }
        'topmem' {
            $p = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First ($Top * 2) `
                Id, ProcessName, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,1)}}, CPU, Path
            Out-Action -Data $p -BaseName 'procs_top_mem' -TopN ($Top * 2)
        }
        'dlls' {
            if (-not $ProcId) { Action-Fail 'specify -ProcId <pid>' 2 }
            try {
                $p = Get-Process -Id $ProcId -ErrorAction Stop
                $mods = $p.Modules | Select-Object ModuleName, FileName, FileVersion, Company
                Out-Action -Data $mods -BaseName "procs_dlls_$ProcId" -TopN 500
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: list,tree,topcpu,topmem,dlls" 2 }
    }
}

function Action-Net {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'est' }
    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    function _Tcp($state) {
        $params = @{ ErrorAction = 'SilentlyContinue' }
        if ($state) { $params['State'] = $state }
        Get-NetTCPConnection @params | ForEach-Object {
            $p = $byPid[[int]$_.OwningProcess]
            [pscustomobject]@{
                Local   = "$($_.LocalAddress):$($_.LocalPort)"
                Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
                State   = $_.State
                Pid     = $_.OwningProcess
                Process = if ($p) { $p.Name } else { '?' }
                Path    = if ($p) { $p.ExecutablePath } else { '' }
            }
        }
    }
    switch ($sub) {
        'est'    { Out-Action -Data (_Tcp 'Established') -BaseName 'net_tcp_est'    -TopN ($Top * 4) }
        'tcp'    { Out-Action -Data (_Tcp $null)         -BaseName 'net_tcp_all'    -TopN ($Top * 4) }
        'listen' { Out-Action -Data (_Tcp 'Listen')      -BaseName 'net_tcp_listen' -TopN ($Top * 4) }
        'udp' {
            try { $u = Get-NetUDPEndpoint -ErrorAction Stop } catch { Action-Fail $_.Exception.Message 3 }
            $rows = foreach ($c in $u) {
                $p = $byPid[[int]$c.OwningProcess]
                [pscustomobject]@{
                    Local   = "$($c.LocalAddress):$($c.LocalPort)"
                    Pid     = $c.OwningProcess
                    Process = if ($p) { $p.Name } else { '?' }
                    Path    = if ($p) { $p.ExecutablePath } else { '' }
                }
            }
            Out-Action -Data $rows -BaseName 'net_udp_listen' -TopN ($Top * 4)
        }
        'dns' {
            try { $d = Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordType, Status, TimeToLive, Data } catch { $d = @() }
            Out-Action -Data $d -BaseName 'net_dns' -TopN ($Top * 4)
        }
        'arp' {
            try { $a = Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias } catch { $a = @() }
            Out-Action -Data $a -BaseName 'net_arp' -TopN ($Top * 4)
        }
        'route' {
            try { $r = Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias, AddressFamily } catch { $r = @() }
            Out-Action -Data $r -BaseName 'net_route' -TopN ($Top * 4)
        }
        'ip' {
            try { $ad = Get-NetIPAddress -ErrorAction Stop | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, AddressState } catch { $ad = @() }
            Out-Action -Data $ad -BaseName 'net_ip' -TopN ($Top * 2)
        }
        'firewall' {
            try { $fw = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked } catch { $fw = @() }
            Out-Action -Data $fw -BaseName 'net_firewall' -TopN 10
        }
        'smb' {
            $shares = try { Get-SmbShare -ErrorAction Stop | Select-Object @{n='Type';e={'Share'}}, Name, Path, Description, ShareType } catch { @() }
            $sess   = try { Get-SmbSession -ErrorAction Stop | Select-Object @{n='Type';e={'Session'}}, ClientComputerName, ClientUserName, NumOpens, SessionId } catch { @() }
            Out-Action -Data (@($shares) + @($sess)) -BaseName 'net_smb' -TopN ($Top * 2)
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: est,tcp,listen,udp,dns,arp,route,ip,firewall,smb" 2 }
    }
}

function Action-Persist {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'all' }
    function _Tasks($filter) {
        $t = Get-ScheduledTask -ErrorAction SilentlyContinue
        if ($filter -eq 'susp') { $t = $t | Where-Object { $_.Author -notmatch 'Microsoft|^$' -and $_.TaskPath -notmatch '^\\Microsoft' } }
        $t | Select-Object @{n='Type';e={'Task'}}, TaskPath, TaskName, State, Author,
            @{n='Action';e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' }}
    }
    function _Services($filter) {
        $s = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        if ($filter -eq 'susp') { $s = $s | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch 'Windows\\(System32|SysWOW64|Microsoft)' } }
        $s | Select-Object @{n='Type';e={'Service'}}, Name, DisplayName, State, StartMode, StartName, PathName
    }
    function _RunKeys {
        $keys = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($k in $keys) {
            if (Test-Path $k) {
                $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if ($v) {
                    $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        [pscustomobject]@{ Type='RunKey'; Hive=$k; Name=$_.Name; Value=$_.Value }
                    }
                }
            }
        }
    }
    switch ($sub) {
        'all' {
            $rows = @(_Tasks 'susp') + @(_Services 'susp') + @(_RunKeys)
            Out-Action -Data $rows -BaseName 'persist_all' -TopN ($Top * 6)
        }
        'tasks'         { Out-Action -Data (_Tasks $null)    -BaseName 'persist_tasks'         -TopN ($Top * 8) }
        'tasks-susp'    { Out-Action -Data (_Tasks 'susp')   -BaseName 'persist_tasks_susp'    -TopN ($Top * 6) }
        'services'      { Out-Action -Data (_Services $null) -BaseName 'persist_services'      -TopN ($Top * 8) }
        'services-susp' { Out-Action -Data (_Services 'susp') -BaseName 'persist_services_susp' -TopN ($Top * 4) }
        'runkeys'       { Out-Action -Data (_RunKeys)        -BaseName 'persist_runkeys'       -TopN 200 }
        'ifeo' {
            $base = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
            $rows = @()
            if (Test-Path $base) {
                $rows = Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                    $debugger = (Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
                    if ($debugger) { [pscustomobject]@{ Image=$_.PSChildName; Debugger=$debugger } }
                }
            }
            Out-Action -Data $rows -BaseName 'persist_ifeo' -TopN 100
        }
        'wmi' {
            $f  = try { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop } catch { @() }
            $cs = try { Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop } catch { @() }
            $b  = try { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop } catch { @() }
            $rows = @()
            foreach ($x in @($f))  { $rows += [pscustomobject]@{ Type='Filter';   Name=$x.Name;   Query=$x.Query } }
            foreach ($x in @($cs)) { $rows += [pscustomobject]@{ Type='Consumer'; Name=$x.Name;   CommandLineTemplate=$x.CommandLineTemplate } }
            foreach ($x in @($b))  { $rows += [pscustomobject]@{ Type='Binding';  Filter=$x.Filter; Consumer=$x.Consumer } }
            Out-Action -Data $rows -BaseName 'persist_wmi' -TopN 100
        }
        'startup' {
            $paths = @(
                "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            $rows = foreach ($p in $paths) {
                if (Test-Path $p) {
                    Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue |
                        Select-Object @{n='Folder';e={$p}}, Name, Length, LastWriteTime, FullName
                }
            }
            Out-Action -Data $rows -BaseName 'persist_startup' -TopN 100
        }
        'appinit' {
            $keys = @(
                'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
                'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
            )
            $rows = foreach ($k in $keys) {
                if (Test-Path $k) {
                    $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                    if ($v) {
                        [pscustomobject]@{
                            Key=$k; AppInit_DLLs=$v.AppInit_DLLs; LoadAppInit_DLLs=$v.LoadAppInit_DLLs; RequireSigned=$v.RequireSignedAppInit_DLLs
                        }
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'persist_appinit' -TopN 10
        }
        'winlogon' {
            $key = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
            if (Test-Path $key) {
                $v = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $row = [pscustomobject]@{
                    Userinit=$v.Userinit; Shell=$v.Shell; Taskman=$v.Taskman
                    AutoAdminLogon=$v.AutoAdminLogon; DefaultUserName=$v.DefaultUserName
                }
                Out-Action -Data @($row) -BaseName 'persist_winlogon' -TopN 5
            } else { Out-Action -Data @() -BaseName 'persist_winlogon' }
        }
        'drivers' {
            $d = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                Where-Object { $_.PathName -and $_.PathName -notmatch 'system32\\drivers\\(Microsoft|Windows)' } |
                Select-Object Name, DisplayName, State, StartMode, PathName
            Out-Action -Data $d -BaseName 'persist_drivers' -TopN ($Top * 4)
        }
        'psprofile' {
            $profs = @(
                "$env:WINDIR\System32\WindowsPowerShell\v1.0\profile.ps1",
                "$env:WINDIR\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
                (Join-Path $HOME 'Documents\WindowsPowerShell\profile.ps1'),
                (Join-Path $HOME 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
                (Join-Path $HOME 'Documents\PowerShell\profile.ps1'),
                (Join-Path $HOME 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1')
            )
            $rows = foreach ($p in $profs) {
                if (Test-Path $p) {
                    $fi = Get-Item $p
                    [pscustomobject]@{
                        Path=$p; Bytes=$fi.Length; Modified=$fi.LastWriteTime
                        Head=((Get-Content $p -TotalCount 5 -ErrorAction SilentlyContinue) -join ' / ')
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'persist_psprofile' -TopN 20
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: all,tasks,tasks-susp,services,services-susp,runkeys,ifeo,wmi,startup,appinit,winlogon,drivers,psprofile" 2 }
    }
}

function Action-Forensics {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'prefetch' }
    switch ($sub) {
        'prefetch' {
            $pf = "$env:WINDIR\Prefetch"
            if (-not (Test-Path $pf)) { Out-Action -Data @() -BaseName 'forensic_prefetch'; return }
            $rows = Get-ChildItem -Path $pf -Filter *.pf -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object Name, LastWriteTime, CreationTime, Length, FullName
            Out-Action -Data $rows -BaseName 'forensic_prefetch' -TopN ($Top * 4)
        }
        'amcache' {
            $keys = @(
                'HKLM:\SOFTWARE\Microsoft\Amcache.hve\Root\InventoryApplicationFile',
                'HKLM:\SOFTWARE\Microsoft\Amcache\Root\InventoryApplicationFile'
            )
            $rows = @()
            foreach ($k in $keys) {
                if (Test-Path $k) {
                    $rows += Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                        $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        [pscustomobject]@{
                            Key=$_.PSChildName; Name=$v.Name; Path=$v.LowerCaseLongPath
                            Hash=$v.FileId; Publisher=$v.Publisher; Version=$v.Version
                        }
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'forensic_amcache' -TopN ($Top * 4)
        }
        'shimcache' {
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
            $row = $null
            if (Test-Path $k) {
                $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if ($v.AppCompatCache) {
                    $row = [pscustomobject]@{
                        ValueBytes=$v.AppCompatCache.Length
                        Note='Use AppCompatCacheParser.exe for full content.'
                    }
                }
            }
            Out-Action -Data @($row | Where-Object { $_ }) -BaseName 'forensic_shimcache' -TopN 1
        }
        'bam' {
            $bases = @(
                'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
                'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
            )
            $rows = @()
            foreach ($b in $bases) {
                if (Test-Path $b) {
                    Get-ChildItem $b -ErrorAction SilentlyContinue | ForEach-Object {
                        $sid = $_.PSChildName
                        $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Version|^SequenceNumber' } | ForEach-Object {
                            $rows += [pscustomobject]@{ SID=$sid; Path=$_.Name; ValueBytes=([byte[]]$_.Value).Length }
                        }
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'forensic_bam' -TopN ($Top * 6)
        }
        'recentapps' {
            $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps'
            $rows = @()
            if (Test-Path $k) {
                $rows = Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                    $v = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    [pscustomobject]@{
                        AppId=$v.AppId; AppPath=$v.AppPath
                        LastAccessed=if ($v.LastAccessedTime) { [datetime]::FromFileTime([int64]$v.LastAccessedTime) } else { $null }
                        LaunchCount=$v.LaunchCount
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'forensic_recentapps' -TopN 100
        }
        'userassist' {
            $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
            $rows = @()
            if (Test-Path $base) {
                Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
                    $countKey = Join-Path $_.PSPath 'Count'
                    if (Test-Path $countKey) {
                        $vals = Get-ItemProperty -Path $countKey -ErrorAction SilentlyContinue
                        $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $name = $_.Name
                            $dec = -join ($name.ToCharArray() | ForEach-Object {
                                $ch = $_
                                if ($ch -match '[a-z]') { [char](((([int][char]$ch) - 97 + 13) % 26) + 97) }
                                elseif ($ch -match '[A-Z]') { [char](((([int][char]$ch) - 65 + 13) % 26) + 65) }
                                else { $ch }
                            })
                            $rows += [pscustomobject]@{ Decoded=$dec; ValueBytes=([byte[]]$_.Value).Length }
                        }
                    }
                }
            }
            Out-Action -Data $rows -BaseName 'forensic_userassist' -TopN ($Top * 4)
        }
        'muicache' {
            $k = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
            $rows = @()
            if (Test-Path $k) {
                $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                $rows = $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -match '\.exe' } |
                    ForEach-Object { [pscustomobject]@{ Path=$_.Name; Friendly=$_.Value } }
            }
            Out-Action -Data $rows -BaseName 'forensic_muicache' -TopN ($Top * 4)
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: prefetch,amcache,shimcache,bam,recentapps,userassist,muicache" 2 }
    }
}

function Action-Auth {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'priv' }
    function _AuthEvents($ids, [string]$base) {
        $tr = Resolve-Range $Range
        try {
            $hash = @{ LogName='Security'; Id=$ids; StartTime=$tr.Start; EndTime=$tr.End }
            $ev = Get-WinEvent -FilterHashtable $hash -ErrorAction Stop |
                Select-Object TimeCreated, Id,
                    @{n='Account';e={ $_.Properties[5].Value }},
                    @{n='Domain'; e={ $_.Properties[6].Value }},
                    @{n='Source'; e={ try { $_.Properties[18].Value } catch { '' } }},
                    @{n='Type';   e={ try { $_.Properties[8].Value }  catch { '' } }},
                    @{n='Msg';    e={ ([string]$_.Message -replace '\s+',' ') }}
            Out-Action -Data $ev -BaseName $base -TopN ($Top * 4)
        } catch { Action-Fail $_.Exception.Message 3 }
    }
    switch ($sub) {
        'users' {
            $u = try { Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired, Description } catch { @() }
            Out-Action -Data $u -BaseName 'auth_users' -TopN 200
        }
        'groups' {
            try {
                $g = Get-LocalGroup -ErrorAction Stop
                $rows = foreach ($grp in $g) {
                    $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
                    [pscustomobject]@{
                        Group=$grp.Name; Count=($members | Measure-Object).Count
                        Members=($members | ForEach-Object { $_.Name }) -join ', '
                    }
                }
                Out-Action -Data $rows -BaseName 'auth_groups' -TopN 100
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        'priv' {
            $priv = @('Administrators','Backup Operators','Remote Desktop Users','Remote Management Users','Hyper-V Administrators','Power Users','Distributed COM Users')
            $rows = foreach ($g in $priv) {
                try {
                    $m = Get-LocalGroupMember -Group $g -ErrorAction Stop
                    foreach ($mb in $m) {
                        [pscustomobject]@{ Group=$g; Member=$mb.Name; ObjectClass=$mb.ObjectClass; Source=$mb.PrincipalSource }
                    }
                } catch { }
            }
            Out-Action -Data $rows -BaseName 'auth_priv' -TopN 200
        }
        'sessions' {
            try {
                $q = quser 2>$null
                if ($q) {
                    $rows = $q | Select-Object @{n='Line';e={$_}}
                    Out-Action -Data $rows -BaseName 'auth_sessions' -TopN 50
                } else {
                    $s = Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
                        Select-Object LogonId, LogonType, StartTime, AuthenticationPackage
                    Out-Action -Data $s -BaseName 'auth_sessions_cim' -TopN 50
                }
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        'logons'      { _AuthEvents @(4624) 'auth_4624' }
        'failed'      { _AuthEvents @(4625) 'auth_4625' }
        'privlogons'  { _AuthEvents @(4672) 'auth_4672' }
        'lockouts'    { _AuthEvents @(4740) 'auth_4740' }
        'explicit'    { _AuthEvents @(4648) 'auth_4648' }
        'changes'     { _AuthEvents @(4720,4722,4723,4724,4725,4726,4738) 'auth_acct_changes' }
        'rdp' {
            $tr = Resolve-Range $Range
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; StartTime=$tr.Start; EndTime=$tr.End } -ErrorAction Stop |
                    Where-Object { $_.Id -in 21,22,23,24,25,39,40 } |
                    Select-Object TimeCreated, Id, @{n='Msg';e={ ([string]$_.Message -replace '\s+',' ') }}
                Out-Action -Data $ev -BaseName 'auth_rdp' -TopN ($Top * 2)
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        'pwdage' {
            try {
                $u = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
                    @{n='PwdAgeDays';e={ if ($_.PasswordLastSet) { [int](((Get-Date) - $_.PasswordLastSet).TotalDays) } else { $null } }}
                Out-Action -Data $u -BaseName 'auth_pwdage' -TopN 100
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: users,groups,priv,sessions,logons,failed,privlogons,lockouts,explicit,changes,rdp,pwdage" 2 }
    }
}

function Action-Files {
    $sub = if ($Sub) { $Sub.ToLower() } else { 'recent' }
    switch ($sub) {
        'recent' {
            $h = if ($Hours -gt 0) { $Hours } else { 24 }
            $cut = (Get-Date).AddHours(-$h)
            $paths = @($env:TEMP, "$env:WINDIR\Temp", $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:PUBLIC)
            $rows = foreach ($p in $paths) {
                if (Test-Path $p) {
                    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -ge $cut } |
                        Select-Object FullName, Length, LastWriteTime, CreationTime
                }
            }
            Out-Action -Data $rows -BaseName 'files_recent' -TopN ($Top * 4)
        }
        'large' {
            $bytes = [int64]$Mb * 1MB
            $paths = @($env:USERPROFILE, $env:ProgramData, $env:TEMP)
            $rows = foreach ($p in $paths) {
                if (Test-Path $p) {
                    Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -ge $bytes } |
                        Select-Object FullName, @{n='SizeMB';e={[math]::Round($_.Length/1MB,1)}}, LastWriteTime
                }
            }
            Out-Action -Data $rows -BaseName 'files_large' -TopN ($Top * 2)
        }
        'sysmon' {
            $tr = Resolve-Range $Range
            $ids = if ($Id) { $Id } else { @(1,3,7,11,22,25) }
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=$ids; StartTime=$tr.Start; EndTime=$tr.End } -ErrorAction Stop |
                    Select-Object TimeCreated, Id, @{n='Msg';e={ ([string]$_.Message -replace '\s+',' ') }}
                Out-Action -Data $ev -BaseName 'files_sysmon' -TopN ($Top * 4)
            } catch { Action-Fail $_.Exception.Message 3 }
        }
        default { Action-Fail "unknown -Sub '$sub'. valid: recent,large,sysmon" 2 }
    }
}

function Action-EvtSearch {
    $tr = Resolve-Range $Range
    $hash = @{ LogName = $Channel; StartTime = $tr.Start; EndTime = $tr.End }
    if ($Id)    { $hash['Id']    = $Id }
    if ($Level) { $hash['Level'] = $Level }
    try {
        $events = Get-WinEvent -FilterHashtable $hash -ErrorAction Stop
        if ($Keyword) { $events = $events | Where-Object { $_.Message -match $Keyword } }
        $rows = $events | Select-Object TimeCreated,
            @{n='Level';e={$_.LevelDisplayName}}, Id, ProviderName, MachineName,
            @{n='Message';e={ ([string]$_.Message -replace '\s+',' ') }}
        Out-Action -Data $rows -BaseName "evt_search_$Channel" -TopN $Top
    } catch {
        Action-Fail $_.Exception.Message 3
    }
}

function Action-ProcSearch {
    if (-not $ProcQuery) { Action-Fail "specify -ProcQuery <regex>" 2 }
    $m = Get-ThProcessMap | Where-Object {
        ($_.Name    -and $_.Name    -match $ProcQuery) -or
        ($_.Path    -and $_.Path    -match $ProcQuery) -or
        ($_.CmdLine -and $_.CmdLine -match $ProcQuery)
    } | Select-Object PID, PPID, Name, Owner, SigStatus, Path, CmdLine
    Out-Action -Data $m -BaseName 'proc_search' -TopN $Top
}

function Action-Hash {
    if (-not $Path -or -not (Test-Path $Path)) { Action-Fail "specify -Path <file or folder>" 2 }
    $files = if ((Get-Item $Path).PSIsContainer) {
        if ($Recurse) { Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue }
        else          { Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue }
    } else { Get-Item $Path }
    $rows = foreach ($f in $files) {
        try {
            $h = Get-FileHash -Path $f.FullName -Algorithm $Algo -ErrorAction Stop
            [pscustomobject]@{
                Hash=$h.Hash; Algo=$h.Algorithm; Path=$f.FullName;
                SizeKB=[math]::Round($f.Length/1KB,1); Modified=$f.LastWriteTime
            }
        } catch { }
    }
    if ($Script:TH.Iocs.Count -eq 0 -and $Script:TH.IocFile) { $Script:TH.Iocs = Load-IOCs }
    if ($Script:TH.Iocs.Count -gt 0) {
        $hashIocs = $Script:TH.Iocs | Where-Object { $_.Type -in @('md5','sha1','sha256') }
        if ($hashIocs) {
            $hits = $rows | Where-Object { $hashIocs.Value -contains $_.Hash }
            foreach ($h in $hits) {
                Add-Finding -Module 'Action/Hash' -Severity 'critical' -Title 'IOC hash match' -Detail "$($h.Algo) $($h.Hash) :: $($h.Path)" -Evidence $h
            }
        }
    }
    Out-Action -Data $rows -BaseName 'hashes' -TopN ($Top * 4)
}

function Action-FileSearch {
    if (-not $Path)    { Action-Fail "specify -Path <folder>" 2 }
    if (-not $Pattern) { $Pattern = '*' }
    $gci = @{ Path=$Path; Filter=$Pattern; File=$true; ErrorAction='SilentlyContinue' }
    if ($Recurse) { $gci['Recurse'] = $true }
    $rows = Get-ChildItem @gci | Select-Object FullName, Length, LastWriteTime, CreationTime
    Out-Action -Data $rows -BaseName 'file_search' -TopN ($Top * 4)
}

function Action-IocMatch {
    if ($Script:TH.Iocs.Count -eq 0 -and $Script:TH.IocFile) { $Script:TH.Iocs = Load-IOCs }
    if ($Script:TH.Iocs.Count -eq 0) { Action-Fail "no IOCs loaded - use -IocFile <path>" 2 }
    $results = New-Object System.Collections.Generic.List[object]
    if ($IocAgainst -in @('procs','all')) {
        $procs = Get-ThProcessMap
        $names = $Script:TH.Iocs | Where-Object { $_.Type -eq 'filename' } | Select-Object -ExpandProperty Value
        foreach ($p in $procs) {
            foreach ($n in $names) {
                if (($p.Path -and $p.Path -like "*$n*") -or ($p.Name -and $p.Name -like "*$n*")) {
                    $results.Add([pscustomobject]@{ Match='proc'; IOC=$n; Pid=$p.PID; Name=$p.Name; Path=$p.Path }) | Out-Null
                    break
                }
            }
        }
    }
    if ($IocAgainst -in @('tcp','all')) {
        try { $conns = Get-NetTCPConnection -ErrorAction Stop } catch { $conns = @() }
        $ips = $Script:TH.Iocs | Where-Object { $_.Type -eq 'ip' } | Select-Object -ExpandProperty Value
        foreach ($c in $conns) {
            if ($ips -contains $c.RemoteAddress) {
                $results.Add([pscustomobject]@{
                    Match='tcp'; IOC=$c.RemoteAddress
                    Local="$($c.LocalAddress):$($c.LocalPort)"
                    Remote="$($c.RemoteAddress):$($c.RemotePort)"
                    State=$c.State; Pid=$c.OwningProcess
                }) | Out-Null
            }
        }
    }
    if ($IocAgainst -in @('dns','all')) {
        try { $cache = Get-DnsClientCache -ErrorAction Stop } catch { $cache = @() }
        $doms = $Script:TH.Iocs | Where-Object { $_.Type -eq 'domain' } | Select-Object -ExpandProperty Value
        foreach ($e in $cache) {
            foreach ($d in $doms) {
                if ($e.Entry -like "*$d*") {
                    $results.Add([pscustomobject]@{ Match='dns'; IOC=$d; Entry=$e.Entry; Type=$e.RecordType; Data=$e.Data }) | Out-Null
                    break
                }
            }
        }
    }
    foreach ($r in $results) {
        Add-Finding -Module 'Action/IocMatch' -Severity 'high' -Title "IOC match ($($r.Match))" -Detail "$($r.IOC)" -Evidence $r
    }
    Out-Action -Data $results.ToArray() -BaseName "ioc_match_$IocAgainst" -TopN ($Top * 6)
}

function Action-Hunt {
    $kind = if ($HuntType) { $HuntType.ToLower() } else { 'unsigned' }
    $m = Get-ThProcessMap
    $byPid = @{}; foreach ($p in $m) { $byPid[$p.PID] = $p }
    function _Unsigned {
        $m | Where-Object { $_.Path -and $_.SigStatus -and $_.SigStatus -ne 'Valid' } |
            Select-Object @{n='Type';e={'unsigned'}}, PID, Name, SigStatus, Signer, Path
    }
    function _SuspPaths {
        $m | Where-Object { $_.Path -and $_.Path -match '\\(Temp|AppData|ProgramData|Users\\Public|Windows\\Temp)\\' } |
            Select-Object @{n='Type';e={'paths'}}, PID, Name, Owner, SigStatus, Path
    }
    function _ShortCmd {
        $m | Where-Object { -not $_.CmdLine -or ($_.CmdLine -and $_.CmdLine.Length -lt 8) } |
            Select-Object @{n='Type';e={'shortcmd'}}, PID, Name, CmdLine, Path
    }
    function _Chain {
        $sus = 'cmd.exe|wscript.exe|cscript.exe|mshta.exe|rundll32.exe|regsvr32.exe|powershell.exe|pwsh.exe|wmic.exe|certutil.exe|bitsadmin.exe'
        foreach ($p in $m) {
            $par = $byPid[$p.PPID]
            if ($par -and $par.Name -and ($par.Name -match $sus)) {
                [pscustomobject]@{
                    Type='chain'
                    ParentPid=$par.PID; ParentName=$par.Name; ParentCmd=$par.CmdLine
                    ChildPid=$p.PID;    ChildName=$p.Name;    ChildCmd=$p.CmdLine
                }
            }
        }
    }
    function _Owners {
        $m | Group-Object -Property Owner | Sort-Object Count |
            Select-Object @{n='Type';e={'owners'}}, Count, Name
    }
    function _NetActive {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            $p = $byPid[[int]$c.OwningProcess]
            [pscustomobject]@{
                Type='netactive'; Pid=$c.OwningProcess; Process=if ($p) { $p.Name } else { '?' }
                Path=if ($p) { $p.Path } else { '' }
                Local="$($c.LocalAddress):$($c.LocalPort)"; Remote="$($c.RemoteAddress):$($c.RemotePort)"
                State=$c.State
            }
        }
    }
    switch ($kind) {
        'unsigned'  { Out-Action -Data (_Unsigned)  -BaseName 'hunt_unsigned'  -TopN ($Top * 2) }
        'paths'     { Out-Action -Data (_SuspPaths) -BaseName 'hunt_paths'     -TopN ($Top * 2) }
        'shortcmd'  { Out-Action -Data (_ShortCmd)  -BaseName 'hunt_shortcmd'  -TopN ($Top * 2) }
        'chain'     { Out-Action -Data (_Chain)     -BaseName 'hunt_chain'     -TopN ($Top * 2) }
        'owners'    { Out-Action -Data (_Owners)    -BaseName 'hunt_owners'    -TopN 50 }
        'netactive' { Out-Action -Data (_NetActive) -BaseName 'hunt_netactive' -TopN ($Top * 2) }
        'all' {
            $rows = @()
            $rows += @(_Unsigned)
            $rows += @(_SuspPaths)
            $rows += @(_ShortCmd)
            $rows += @(_Chain)
            $rows += @(_NetActive)
            Out-Action -Data $rows -BaseName 'hunt_all' -TopN ($Top * 6)
        }
        default { Action-Fail "unknown -HuntType '$kind'. valid: unsigned,paths,shortcmd,chain,owners,netactive,all" 2 }
    }
}

function Action-EvtQuick {
    if (-not $Channel) { Action-Fail 'specify -Channel <name>' 2 }
    try {
        $ev = Get-WinEvent -LogName $Channel -MaxEvents $Count -ErrorAction Stop |
            Select-Object TimeCreated,
                @{n='Level';e={$_.LevelDisplayName}},
                Id, ProviderName,
                @{n='Message';e={ ([string]$_.Message -replace '\s+',' ') }}
        Out-Action -Data $ev -BaseName ("evt_quick_" + ($Channel -replace '[\\/]','_')) -TopN $Count
    } catch { Action-Fail $_.Exception.Message 3 }
}

function Action-EvtChannels {
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 } |
            Sort-Object -Property RecordCount -Descending |
            Select-Object LogName, RecordCount, IsEnabled, LogMode, FileSize, LastWriteTime
        Out-Action -Data $logs -BaseName 'evt_channels' -TopN ($Top * 4)
    } catch { Action-Fail $_.Exception.Message 3 }
}

function Action-ListActions {
    $rows = @(
        # Top-level
        [pscustomobject]@{ Module='Cmd/PS';     Switch='-Cmd <s>';                  Description='Run cmd.exe one-liner';                       Example='-Cmd "whoami /all"' }
        [pscustomobject]@{ Module='Cmd/PS';     Switch='-PS <s>';                   Description='Run PowerShell expression';                   Example='-PS "Get-Process | Where CPU -gt 10"' }
        [pscustomobject]@{ Module='Cmd/PS';     Switch='-Script <p>';               Description='Run a .ps1 file (with destructive guard)';    Example='-Script .\extra.ps1' }
        # Procs
        [pscustomobject]@{ Module='Procs';      Switch='-Procs [-Sub <s>]';         Description='list (default), tree, topcpu, topmem, dlls';  Example='-Procs -Sub tree' }
        [pscustomobject]@{ Module='Procs';      Switch='-Procs -Sub dlls -ProcId N';Description='List DLLs of a given PID';                    Example='-Procs -Sub dlls -ProcId 1234' }
        [pscustomobject]@{ Module='Procs';      Switch='-ProcSearch -ProcQuery <re>';Description='Regex on name/path/cmdline';                  Example='-ProcSearch -ProcQuery "(powershell|wscript)"' }
        # Hunt
        [pscustomobject]@{ Module='Hunt';       Switch='-Hunt -HuntType <kind>';    Description='unsigned|paths|shortcmd|chain|owners|netactive|all'; Example='-Hunt -HuntType chain' }
        # Net
        [pscustomobject]@{ Module='Net';        Switch='-Net [-Sub <s>]';           Description='est (default), tcp, listen, udp, dns, arp, route, ip, firewall, smb'; Example='-Net -Sub listen' }
        # Persist
        [pscustomobject]@{ Module='Persist';    Switch='-Persist [-Sub <s>]';       Description='all (default), tasks, tasks-susp, services, services-susp, runkeys, ifeo, wmi, startup, appinit, winlogon, drivers, psprofile'; Example='-Persist -Sub ifeo' }
        # Forensics
        [pscustomobject]@{ Module='Forensics';  Switch='-Forensics [-Sub <s>]';     Description='prefetch (default), amcache, shimcache, bam, recentapps, userassist, muicache'; Example='-Forensics -Sub amcache' }
        # Auth
        [pscustomobject]@{ Module='Auth';       Switch='-Auth [-Sub <s>]';          Description='priv (default), users, groups, sessions, logons, failed, privlogons, lockouts, explicit, changes, rdp, pwdage'; Example='-Auth -Sub failed -Range 24h' }
        # Events
        [pscustomobject]@{ Module='Events';     Switch='-EvtChannels';              Description='List event log channels with non-zero records'; Example='-EvtChannels' }
        [pscustomobject]@{ Module='Events';     Switch='-EvtQuick -Channel <name> [-Count N]'; Description='Quick read of any channel';        Example='-EvtQuick -Channel "Microsoft-Windows-Sysmon/Operational" -Count 100' }
        [pscustomobject]@{ Module='Events';     Switch='-EvtSearch -Channel -Id -Level -Keyword -Range'; Description='Filter Windows events'; Example='-EvtSearch -Channel Security -Id 4624,4625 -Range 24h' }
        # Files
        [pscustomobject]@{ Module='Files';      Switch='-Files [-Sub <s>]';         Description='recent (default; -Hours N), large (-Mb N), sysmon (-Range / -Id)'; Example='-Files -Sub large -Mb 100' }
        [pscustomobject]@{ Module='Files';      Switch='-Hash -Path <p> [-Recurse]';Description='SHA256 (default), MD5, SHA1; auto IOC match if -IocFile';     Example='-Hash -Path C:\Temp -Recurse' }
        [pscustomobject]@{ Module='Files';      Switch='-FileSearch -Path -Pattern';Description='Find files by name pattern';                  Example='-FileSearch -Path C:\Users -Pattern *.ps1 -Recurse' }
        [pscustomobject]@{ Module='Files';      Switch='-IocMatch -IocFile <csv>';  Description='Sweep host (procs, tcp, dns) against IOC list';                Example='-IocMatch -IocFile .\iocs.csv -IocAgainst all' }
    )
    Out-Action -Data $rows -BaseName 'actions' -TopN 100
}

function Invoke-Action {
    if ($ListActions) { Action-ListActions; return }
    if ($Cmd)         { Action-Cmd;         return }
    if ($PS)          { Action-PS;          return }
    if ($Script)      { Action-Script;      return }
    if ($EvtChannels) { Action-EvtChannels; return }
    if ($EvtQuick)    { Action-EvtQuick;    return }
    if ($EvtSearch)   { Action-EvtSearch;   return }
    if ($ProcSearch)  { Action-ProcSearch;  return }
    if ($Hunt)        { Action-Hunt;        return }
    if ($Hash)        { Action-Hash;        return }
    if ($FileSearch)  { Action-FileSearch;  return }
    if ($IocMatch)    { Action-IocMatch;    return }
    if ($Procs)       { Action-Procs;       return }
    if ($Net)         { Action-Net;         return }
    if ($Persist)     { Action-Persist;     return }
    if ($Forensics)   { Action-Forensics;   return }
    if ($Auth)        { Action-Auth;        return }
    if ($Files)       { Action-Files;       return }
    try { [Console]::Error.WriteLine("[ERR] no recognised action specified. use -ListActions to see options.") } catch { Write-Error 'no action' }
    exit 2
}


function Show-Help {
    $h = @"

ThreatHunter v$($Script:TH.Version) - standalone PowerShell TUI for Windows IR / threat hunting

USAGE
  .\ThreatHunter.ps1                          launch interactive TUI
  .\ThreatHunter.ps1 -<action> [-Sub <s>]     run a single action and exit
  .\ThreatHunter.ps1 -Help                    show this help
  .\ThreatHunter.ps1 -ListActions             machine-readable list of actions

COMMON PARAMETERS
  -OutputRoot <path>     session output folder            default .\ThreatHunt_Output
  -IocFile <csv>         load IOCs at startup
  -NoLog                 disable session logging entirely
  -NoColor               force monochrome output
  -Format <fmt>          Auto | Table | Json | Csv        default Auto
  -Quiet                 suppress banner (implied with action switches)
  -Top <n>               cap rows per result              default 50

CMD / POWERSHELL EXECUTION
  -Cmd "<s>"             run cmd.exe one-liner
  -PS "<s>"              run a PowerShell expression
  -Script <p>            run a .ps1 file (body scanned for destructive patterns)
  -Force                 bypass the destructive-pattern guard

QUICK-VIEW MODULES
  -Procs [-Sub <s>]      list (default), tree, topcpu, topmem, dlls -ProcId N
  -Hunt -HuntType <k>    unsigned, paths, shortcmd, chain, owners, netactive, all
  -Net [-Sub <s>]        est, tcp, listen, udp, dns, arp, route, ip, firewall, smb
  -Persist [-Sub <s>]    all, tasks, tasks-susp, services, services-susp, runkeys,
                         ifeo, wmi, startup, appinit, winlogon, drivers, psprofile
  -Forensics [-Sub <s>]  prefetch, amcache, shimcache, bam, recentapps, userassist, muicache
  -Auth [-Sub <s>]       priv, users, groups, sessions, logons, failed,
                         privlogons, lockouts, explicit, changes, rdp, pwdage
  -Files [-Sub <s>]      recent (-Hours N), large (-Mb N), sysmon (-Range, -Id)

SEARCH ACTIONS
  -EvtChannels                                                    list channels
  -EvtQuick -Channel <n> [-Count N]                               quick read
  -EvtSearch -Channel <n> -Id <ids> -Level <n> -Keyword <re> -Range <r>
  -ProcSearch -ProcQuery <re>                                     name|path|cmd regex
  -Hash -Path <p> [-Recurse] [-Algo MD5|SHA1|SHA256]              hash files
  -FileSearch -Path <p> -Pattern <wildcard> [-Recurse]            find by pattern
  -IocMatch -IocFile <csv> [-IocAgainst procs|tcp|dns|all]        IOC sweep

TIME RANGES
  1h, 6h, 24h         last N hours
  7d, 30d, 90d        last N days
  2w, 6w              last N weeks
  3m, 12m             last N calendar months
  all                 epoch -> now
  yyyy-MM-dd..yyyy-MM-dd      explicit, inclusive

EXIT CODES
  0   action ran successfully (the dataset may still be empty)
  1   fatal exception during execution
  2   destructive guard fired or required parameter missing
  3   underlying cmdlet raised (channel not found, access denied, etc.)

EXAMPLES
  .\ThreatHunter.ps1 -Cmd "whoami /all"
  .\ThreatHunter.ps1 -PS "Get-LocalGroupMember Administrators"
  .\ThreatHunter.ps1 -EvtSearch -Channel Security -Id 4624,4625 -Range 24h
  .\ThreatHunter.ps1 -EvtQuick -Channel "Microsoft-Windows-Sysmon/Operational" -Count 200
  .\ThreatHunter.ps1 -Hunt -HuntType chain
  .\ThreatHunter.ps1 -Net -Sub listen
  .\ThreatHunter.ps1 -Persist -Sub ifeo
  .\ThreatHunter.ps1 -Auth -Sub failed -Range 24h
  .\ThreatHunter.ps1 -Forensics -Sub amcache
  .\ThreatHunter.ps1 -Hash -Path C:\Temp -Recurse -IocFile .\iocs.csv
  .\ThreatHunter.ps1 -IocMatch -IocFile .\iocs.csv

For the full reference run -ListActions, or read README.md / ThreatHunter-Guide.html.

"@
    Write-Output $h
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
try {
    if ($Help) {
        Show-Help
        exit 0
    }
    if ($Script:ActionMode) {
        Write-Session -Category 'SESSION' -Message "Action-mode session $($Script:TH.SessionId) by $($Script:TH.User) on $($Script:TH.Host)"
        Invoke-Action
        Write-Session -Category 'SESSION' -Message 'Action-mode session ended'
        exit 0
    } else {
        Main-Loop
    }
} catch {
    if ($Script:ActionMode) {
        try { [Console]::Error.WriteLine("[ERR] " + $_.Exception.Message) } catch { Write-Error $_.Exception.Message }
        Write-Session -Category 'FATAL' -Message $_.Exception.Message
        exit 1
    } else {
        Write-Err "fatal: $($_.Exception.Message)"
        Write-Session -Category 'FATAL' -Message $_.Exception.Message
    }
}
