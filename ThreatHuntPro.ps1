<#
.SYNOPSIS
    ThreatHunt Pro - automated Windows threat-hunting triage toolkit.

.DESCRIPTION
    Enumerates network listeners, outbound connections, kernel drivers, autoruns
    (Run keys, services, scheduled tasks, startup folders, Winlogon, IFEO, AppInit)
    and WMI event-subscription persistence. Every referenced binary is hashed
    (SHA256) and its Authenticode signature verified. Optional VirusTotal v3 hash
    reputation with client-side rate limiting. Writes TXT, HTML, JSON and CSV
    reports plus a timestamped log.

    Scores are heuristic (0-100): HIGH >= 60, MEDIUM >= 30, LOW > 0, INFO = 0.
    Treat every finding as a lead to verify, not a verdict.

    Elevation: if not elevated, the script relaunches itself through the standard
    UAC consent prompt (Start-Process -Verb RunAs). No UAC bypass is used. If the
    prompt is declined, it continues with reduced visibility.

    Compatible with Windows PowerShell 5.1 (required for PS2EXE) and PowerShell 7.

.EXAMPLE
    .\ThreatHuntPro.ps1
.EXAMPLE
    .\ThreatHuntPro.ps1 -VirusTotal -VTApiKeyFile C:\keys\vt.txt -Modules Autoruns,WMI
.EXAMPLE
    ThreatHuntPro.exe -OutputDir D:\IR\host01 -NoElevate
#>
[CmdletBinding()]
param(
    [string]   $OutputDir,
    [string[]] $Modules = @('All'),       # Listeners,Outbound,Drivers,Autoruns,WMI
    [switch]   $VirusTotal,
    [string]   $VTApiKey,                  # prefer env:VT_API_KEY or -VTApiKeyFile (command lines are visible to other processes)
    [string]   $VTApiKeyFile,
    [int]      $VTRatePerMinute = 4,       # public API: 4/min, 500/day
    [int]      $VTMaxLookups = 200,
    [switch]   $VTAll,                     # also look up valid Microsoft-signed binaries
    [int]      $MinScore = 30,             # exit code 2 if any finding >= this
    [switch]   $NoElevate,
    [switch]   $NoOpen,
    [switch]   $DeleteKeyFile              # internal: remove the key file after reading (used on relaunch)
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:Version = '1.0.0'
$script:LogFile = $null; $script:OutDir = $null
$script:AllModules = @('Listeners', 'Outbound', 'Drivers', 'Autoruns', 'WMI')

# ============================================================== knowledge ==
$script:SuspiciousPorts = @{
    1080 = 'SOCKS proxy'; 1234 = 'common backdoor/test'; 1337 = 'leet/backdoor'; 2222 = 'alt SSH/backdoor'
    3333 = 'crypto-miner stratum'; 4444 = 'Metasploit default'; 4445 = 'Metasploit alt'; 4899 = 'Radmin'
    5554 = 'Sasser'; 5555 = 'ADB/backdoor'; 6666 = 'IRC/backdoor'; 6667 = 'IRC C2'; 6697 = 'IRC TLS C2'
    7777 = 'common RAT'; 8888 = 'common RAT/proxy'; 9001 = 'Tor ORPort'; 9030 = 'Tor DirPort'
    9050 = 'Tor SOCKS'; 9150 = 'Tor Browser SOCKS'; 12345 = 'NetBus'; 14444 = 'Monero stratum'
    20000 = 'common RAT'; 27374 = 'SubSeven'; 31337 = 'Back Orifice'; 50050 = 'Cobalt Strike team server'
    54321 = 'common backdoor'; 65535 = 'common backdoor'
}
$script:ExposurePorts = @{ 21 = 'FTP'; 23 = 'Telnet'; 135 = 'RPC'; 139 = 'NetBIOS'; 445 = 'SMB'; 3389 = 'RDP'; 5900 = 'VNC'; 5985 = 'WinRM'; 5986 = 'WinRM-TLS' }

$sys32 = "$env:SystemRoot\System32".ToLower()
$wow64 = "$env:SystemRoot\SysWOW64".ToLower()
$script:ExpectedLocations = @{
    'svchost.exe' = @($sys32, $wow64); 'lsass.exe' = @($sys32); 'services.exe' = @($sys32); 'csrss.exe' = @($sys32)
    'wininit.exe' = @($sys32); 'winlogon.exe' = @($sys32); 'smss.exe' = @($sys32); 'spoolsv.exe' = @($sys32)
    'taskhostw.exe' = @($sys32); 'dllhost.exe' = @($sys32, $wow64); 'conhost.exe' = @($sys32)
    'rundll32.exe' = @($sys32, $wow64); 'explorer.exe' = @("$env:SystemRoot".ToLower())
    'searchindexer.exe' = @($sys32); 'wmiprvse.exe' = @("$sys32\wbem", "$wow64\wbem")
}
$script:ExpectedParent = @{
    'svchost.exe' = @('services.exe', 'msmpeng.exe'); 'lsass.exe' = @('wininit.exe')
    'services.exe' = @('wininit.exe'); 'spoolsv.exe' = @('services.exe')
}
$script:Lookalikes = @('svch0st.exe', 'svhost.exe', 'svchosts.exe', 'scvhost.exe', 'svchost32.exe', 'lsasss.exe', 'lsas.exe',
    'isass.exe', 'csrsss.exe', 'csrs.exe', 'winlogin.exe', 'explore.exe', 'explorer32.exe', 'iexplorer.exe', 'rundll.exe',
    'services32.exe', 'taskhost32.exe', 'spoolsvc.exe', 'dllhst.exe', 'conhosts.exe')
$script:RiskyHosts = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe',
    'regsvr32.exe', 'msbuild.exe', 'installutil.exe', 'certutil.exe', 'bitsadmin.exe', 'nc.exe', 'nc64.exe', 'ncat.exe',
    'netcat.exe', 'socat.exe', 'plink.exe', 'wmic.exe', 'msiexec.exe', 'chisel.exe', 'ngrok.exe', 'frpc.exe', 'frps.exe',
    'python.exe', 'pythonw.exe')
$script:HighRiskDirs = @('\appdata\local\temp\', '\windows\temp\', '\users\public\', '\$recycle.bin\', '\perflogs\')
$script:UserDirs = @('\appdata\', '\downloads\', '\desktop\', '\documents\', '\music\', '\videos\', '\pictures\')
$script:AppDataAllow = @('\microsoft\teams\', '\microsoft\onedrive\', '\zoom\', '\slack\', '\discord\', '\spotify\',
    '\dropbox\', '\google\chrome\', '\programs\microsoft vs code\', '\microsoft\edgewebview\', '\1password\', '\whatsapp\')
$script:CmdPatterns = [ordered]@{
    '(?i)\s-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}' = 'encoded PowerShell command'
    '(?i)-w(indowstyle)?\s+h(idden)?\b'                 = 'hidden window'
    '(?i)\b(iex|invoke-expression)\b'                    = 'Invoke-Expression'
    '(?i)downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|start-bitstransfer' = 'download cradle'
    '(?i)frombase64string'                               = 'base64 decoding'
    '(?i)certutil.*-(urlcache|decode)'                   = 'certutil download/decode'
    '(?i)bitsadmin.*/transfer'                           = 'bitsadmin transfer'
    '(?i)regsvr32.*/i:\s*https?:'                        = 'regsvr32 remote scriptlet (Squiblydoo)'
    '(?i)mshta(\.exe)?\s+["'']?(https?:|javascript:|vbscript:)' = 'mshta remote/inline script'
    '(?i)rundll32.*javascript:'                          = 'rundll32 javascript'
    '(?i)https?://\d{1,3}(\.\d{1,3}){3}'                 = 'URL with raw IP'
}

# ================================================================ helpers ==
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffzzz'), $Level, $Message
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
}

function Resolve-ExePath {
    # Turn a command line / ImagePath / Run value into the executable path.
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    $c = $c -replace '^(?i)\\SystemRoot\\', "$env:SystemRoot\"
    if ($c -match '^(?i)system32\\') { $c = "$env:SystemRoot\$c" }
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        $p = if ($end -gt 0) { $c.Substring(1, $end - 1) } else { $c.Trim('"') }
    } else {
        $p = $null
        $tokens = $c -split ' '
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $cand = ($tokens[0..$i] -join ' ').TrimEnd(',')
            if (Test-Path -LiteralPath $cand -PathType Leaf -ErrorAction SilentlyContinue) { $p = $cand; break }
            if (Test-Path -LiteralPath "$cand.exe" -PathType Leaf -ErrorAction SilentlyContinue) { $p = "$cand.exe"; break }
        }
        if (-not $p) { $p = $tokens[0].TrimEnd(',') }
    }
    if ($p -and $p -notmatch '[\\/]') {
        foreach ($d in @("$env:SystemRoot\System32", "$env:SystemRoot")) {
            foreach ($n in @($p, "$p.exe")) {
                $t = Join-Path $d $n
                if (Test-Path -LiteralPath $t -PathType Leaf -ErrorAction SilentlyContinue) { return $t }
            }
        }
    }
    return $p
}

function Get-ScriptTarget {
    # For LOLBins / script hosts, return the DLL or script they execute.
    param([string]$Command)
    if (-not $Command) { return '' }
    $m = [regex]::Match([Environment]::ExpandEnvironmentVariables($Command),
        '(?i)([a-z]:\\[^"*?<>|,]+?\.(dll|cpl|ocx|sct|ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd))\b')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-CmdReasons {
    param([string]$Command)
    $score = 0; $why = @()
    if (-not $Command) { return @{ Score = 0; Reasons = @() } }
    foreach ($k in $script:CmdPatterns.Keys) {
        if ($Command -match $k) { $score += 30; $why += "command line: $($script:CmdPatterns[$k])" }
    }
    return @{ Score = [math]::Min($score, 70); Reasons = $why }
}

function Get-LocationReasons {
    param([string]$Path, [string]$Label = 'binary')
    $p = "$Path".ToLower()
    if (-not $p) { return @{ Score = 0; Reasons = @() } }
    foreach ($d in $script:HighRiskDirs) { if ($p.Contains($d)) { return @{ Score = 35; Reasons = @("$Label in temp/public/recycle/perflogs location") } } }
    foreach ($d in $script:UserDirs) {
        if ($p.Contains($d)) {
            foreach ($a in $script:AppDataAllow) { if ($p.Contains($a)) { return @{ Score = 0; Reasons = @() } } }
            return @{ Score = 20; Reasons = @("$Label in user-writable location") }
        }
    }
    if ($p -match '^[a-z]:\\programdata\\[^\\]+$') { return @{ Score = 20; Reasons = @("$Label in ProgramData root") } }
    return @{ Score = 0; Reasons = @() }
}

$script:FileCache = @{}
function Get-FileIntel {
    param([string]$Path)
    if (-not $Path) { return $null }
    $key = $Path.ToLower()
    if ($script:FileCache.ContainsKey($key)) { return $script:FileCache[$key] }
    $i = [pscustomobject]@{ Path = $Path; Exists = $false; SHA256 = ''; Signature = ''; Signer = ''; IsOSBinary = $false; Size = 0; Modified = '' }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $fi = Get-Item -LiteralPath $Path -Force
            $i.Exists = $true; $i.Size = $fi.Length; $i.Modified = $fi.LastWriteTime.ToString('s')
            try { $i.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash } catch { }
            if (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $Path
                    $i.Signature = [string]$sig.Status
                    if ($sig.SignerCertificate) { $i.Signer = $sig.SignerCertificate.Subject }
                    if ($sig.PSObject.Properties['IsOSBinary']) { $i.IsOSBinary = [bool]$sig.IsOSBinary }
                } catch { $i.Signature = 'Error' }
            }
        }
    } catch { }
    $script:FileCache[$key] = $i
    return $i
}

$script:Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding {
    param([string]$Category, [string]$Name, [string]$Path, [string]$Detail = '', [int]$Score = 0,
          [string[]]$Reasons = @(), [string]$Target = '', [hashtable]$Extra = @{})
    $f = [ordered]@{
        Category = $Category; Name = $Name; Path = $Path; Target = $Target; Detail = $Detail
        Score = $Score; Severity = ''; Reasons = @($Reasons | Where-Object { $_ })
        SHA256 = ''; Signature = ''; Signer = ''; VT = ''; VTLink = ''
    }
    foreach ($k in $Extra.Keys) { $f[$k] = $Extra[$k] }
    $script:Findings.Add([pscustomobject]$f)
}

function Get-Severity { param([int]$s) if ($s -ge 60) { 'HIGH' } elseif ($s -ge 30) { 'MEDIUM' } elseif ($s -gt 0) { 'LOW' } else { 'INFO' } }

function Get-ProcessContextReasons {
    # Masquerading / location / parent checks for a running process.
    param($Proc)
    $score = 0; $why = @()
    $name = "$($Proc.Name)".ToLower(); $exe = "$($Proc.Path)".ToLower()
    $dir = if ($exe.Contains('\')) { $exe.Substring(0, $exe.LastIndexOf('\')) } else { '' }
    if ($script:Lookalikes -contains $name) { $score += 50; $why += "name '$name' mimics a system binary" }
    if ($script:ExpectedLocations.ContainsKey($name) -and $exe -and ($script:ExpectedLocations[$name] -notcontains $dir)) {
        $score += 50; $why += "$name running from unexpected path $dir"
    }
    if ($script:ExpectedParent.ContainsKey($name) -and $Proc.Parent -and ($script:ExpectedParent[$name] -notcontains $Proc.Parent.ToLower())) {
        $score += 30; $why += "$name has unusual parent $($Proc.Parent)"
    }
    return @{ Score = $score; Reasons = $why }
}

$script:ProcMap = $null
function Get-ProcMap {
    if ($script:ProcMap) { return $script:ProcMap }
    $map = @{}
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $names = @{}; foreach ($p in $all) { $names[[int]$p.ProcessId] = $p.Name }
    foreach ($p in $all) {
        $path = $p.ExecutablePath
        if (-not $path) { try { $path = (Get-Process -Id $p.ProcessId -ErrorAction Stop).Path } catch { } }
        $ppid = [int]$p.ParentProcessId
        $map[[int]$p.ProcessId] = [pscustomobject]@{
            Pid = [int]$p.ProcessId; Name = $p.Name; Path = $path; CommandLine = $p.CommandLine
            ParentPid = $ppid; Parent = $(if ($names.ContainsKey($ppid)) { $names[$ppid] } else { '' })
        }
    }
    $script:ProcMap = $map
    return $map
}

function Get-ProcFor { param([int]$ProcessId)
    $m = Get-ProcMap
    if ($m.ContainsKey($ProcessId)) { return $m[$ProcessId] }
    $n = if ($ProcessId -eq 4) { 'System' } elseif ($ProcessId -eq 0) { 'Idle' } else { '<unknown>' }
    return [pscustomobject]@{ Pid = $ProcessId; Name = $n; Path = ''; CommandLine = ''; ParentPid = 0; Parent = '' }
}

# ============================================================== collectors ==
function Invoke-Listeners {
    $socks = @()
    $socks += @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Proto = 'TCP'; Addr = $_.LocalAddress; Port = [int]$_.LocalPort; ProcessId = [int]$_.OwningProcess } })
    $socks += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Proto = 'UDP'; Addr = $_.LocalAddress; Port = [int]$_.LocalPort; ProcessId = [int]$_.OwningProcess } })
    foreach ($s in $socks) {
        $p = Get-ProcFor $s.ProcessId
        $score = 0; $why = @()
        if ($script:SuspiciousPorts.ContainsKey($s.Port)) { $score += 25; $why += "port $($s.Port): $($script:SuspiciousPorts[$s.Port])" }
        if ($script:ExposurePorts.ContainsKey($s.Port) -and $s.Addr -in @('0.0.0.0', '::')) { $score += 5; $why += "$($script:ExposurePorts[$s.Port]) exposed on all interfaces" }
        if ($script:RiskyHosts -contains "$($p.Name)".ToLower()) { $score += 35; $why += "script host / LOLBin '$($p.Name)' owns a listening socket" }
        $ctx = Get-ProcessContextReasons $p; $score += $ctx.Score; $why += $ctx.Reasons
        $cmd = Get-CmdReasons $p.CommandLine; $score += $cmd.Score; $why += $cmd.Reasons
        if ($s.ProcessId -in 0, 4) { $score = [math]::Min($score, 10) }   # kernel: SMB, HTTP.sys
        Add-Finding -Category 'Listeners' -Name "$($p.Name) ($($s.ProcessId))" -Path $p.Path `
            -Detail "$($s.Proto) $($s.Addr):$($s.Port)  parent=$($p.Parent)  cmd=$($p.CommandLine)" -Score $score -Reasons $why `
            -Extra @{ Proto = $s.Proto; LocalAddress = $s.Addr; LocalPort = $s.Port; ProcessId = $s.ProcessId }
    }
    Write-Log "Listeners: $($socks.Count) sockets"
}

function Invoke-Outbound {
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$|::$)' })
    foreach ($c in $conns) {
        $p = Get-ProcFor ([int]$c.OwningProcess)
        $score = 0; $why = @(); $rport = [int]$c.RemotePort
        if ($script:SuspiciousPorts.ContainsKey($rport)) { $score += 25; $why += "remote port $rport`: $($script:SuspiciousPorts[$rport])" }
        if ($script:RiskyHosts -contains "$($p.Name)".ToLower()) { $score += 30; $why += "script host / LOLBin '$($p.Name)' has an outbound connection" }
        $ctx = Get-ProcessContextReasons $p; $score += $ctx.Score; $why += $ctx.Reasons
        $cmd = Get-CmdReasons $p.CommandLine; $score += $cmd.Score; $why += $cmd.Reasons
        Add-Finding -Category 'Outbound' -Name "$($p.Name) ($($c.OwningProcess))" -Path $p.Path `
            -Detail "$($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$rport  cmd=$($p.CommandLine)" -Score $score -Reasons $why `
            -Extra @{ RemoteAddress = $c.RemoteAddress; RemotePort = $rport; ProcessId = [int]$c.OwningProcess }
    }
    Write-Log "Outbound: $($conns.Count) established connections"
}

function Invoke-Drivers {
    $drv = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)
    foreach ($d in $drv) {
        $path = Resolve-ExePath $d.PathName
        $score = 0; $why = @(); $lp = "$path".ToLower()
        if ($lp -and -not $lp.StartsWith("$env:SystemRoot\".ToLower())) { $score += 15; $why += 'driver outside the Windows directory' }
        Add-Finding -Category 'Drivers' -Name $d.Name -Path $path -Detail "$($d.DisplayName)  state=$($d.State)  start=$($d.StartMode)" `
            -Score $score -Reasons $why -Extra @{ State = $d.State; StartMode = $d.StartMode }
    }
    Write-Log "Drivers: $($drv.Count) kernel/file-system drivers"
}

function Add-AutorunEntry {
    param([string]$Location, [string]$Name, [string]$Command, [int]$Score = 0, [string[]]$Reasons = @())
    $path = Resolve-ExePath $Command
    $target = ''
    $leaf = if ($path) { [IO.Path]::GetFileName($path).ToLower() } else { '' }
    $why = @($Reasons)
    if ($script:RiskyHosts -contains $leaf) {
        $target = Get-ScriptTarget $Command
        $score += 10; $why += "launches via $leaf"
        if ($target) { $loc = Get-LocationReasons $target 'script/DLL target'; $score += $loc.Score; $why += $loc.Reasons }
    }
    $cmd = Get-CmdReasons $Command; $score += $cmd.Score; $why += $cmd.Reasons
    Add-Finding -Category 'Autoruns' -Name $Name -Path $path -Target $target -Detail "[$Location] $Command" -Score $Score -Reasons $why `
        -Extra @{ Location = $Location; CommandLine = $Command }
}

function Invoke-Autoruns {
    $n = $script:Findings.Count
    # --- Run keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    foreach ($k in $runKeys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-Item -LiteralPath $k
        foreach ($v in $item.GetValueNames()) {
            if (-not $v) { continue }
            Add-AutorunEntry -Location $k -Name $v -Command ([string]$item.GetValue($v))
        }
    }
    # --- Winlogon Shell / Userinit
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $wl) {
        $w = Get-Item -LiteralPath $wl
        $shell = "$($w.GetValue('Shell'))".Trim(); $ui = "$($w.GetValue('Userinit'))".Trim().TrimEnd(',')
        if ($shell -and $shell.ToLower() -ne 'explorer.exe') { Add-AutorunEntry $wl 'Winlogon Shell' $shell 60 @('Winlogon Shell is not explorer.exe') }
        if ($ui -and $ui.ToLower() -ne "$sys32\userinit.exe") { Add-AutorunEntry $wl 'Winlogon Userinit' $ui 60 @('Winlogon Userinit modified') }
    }
    # --- IFEO debugger / SilentProcessExit hijacks
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        foreach ($sk in Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue) {
            $dbg = $sk.GetValue('Debugger')
            if ($dbg) { Add-AutorunEntry $ifeo "IFEO Debugger: $($sk.PSChildName)" ([string]$dbg) 40 @("IFEO Debugger hijacks $($sk.PSChildName)") }
        }
    }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path $spe) {
        foreach ($sk in Get-ChildItem -LiteralPath $spe -ErrorAction SilentlyContinue) {
            $mp = $sk.GetValue('MonitorProcess')
            if ($mp) { Add-AutorunEntry $spe "SilentProcessExit: $($sk.PSChildName)" ([string]$mp) 40 @('SilentProcessExit MonitorProcess persistence') }
        }
    }
    # --- AppInit_DLLs
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        if (-not (Test-Path $k)) { continue }
        $p = Get-Item -LiteralPath $k
        $dlls = "$($p.GetValue('AppInit_DLLs'))".Trim()
        if ($dlls -and $p.GetValue('LoadAppInit_DLLs') -eq 1) {
            foreach ($dll in ($dlls -split '[ ,]' | Where-Object { $_ })) {
                Add-AutorunEntry $k 'AppInit_DLLs' $dll 50 @('AppInit_DLLs enabled')
            }
        }
    }
    # --- Startup folders
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if (-not $dir -or -not (Test-Path $dir)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue) {
            if ($f.Name -eq 'desktop.ini') { continue }
            if ($f.Extension -eq '.lnk' -and $shell) {
                $lnk = $shell.CreateShortcut($f.FullName)
                $cmdline = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim()
                Add-AutorunEntry "Startup: $dir" $f.Name $cmdline
            } else {
                $s = 0; $w = @()
                if ($f.Extension -match '^\.(bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|scr|pif)$') { $s = 25; $w = @("script/executable ($($f.Extension)) dropped directly in Startup") }
                Add-AutorunEntry "Startup: $dir" $f.Name "`"$($f.FullName)`"" $s $w
            }
        }
    }
    # --- Services (auto-start or running), including svchost ServiceDll
    foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq 'Auto' -or $_.State -eq 'Running' })) {
        $cmd = [string]$svc.PathName
        $score = 0; $why = @()
        if ($cmd -and -not $cmd.StartsWith('"') -and $cmd -match '^[a-zA-Z]:\\[^"]*\s[^"]*\.exe' -and $cmd -notmatch '(?i)^[a-z]:\\windows\\') {
            $score += 10; $why += 'unquoted service path with spaces (privilege-escalation risk)'
        }
        if ($cmd -match '(?i)\\svchost\.exe') {
            $dll = $null
            try { $dll = (Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters" -ErrorAction Stop).GetValue('ServiceDll') } catch { }
            if ($dll) { $cmd = [Environment]::ExpandEnvironmentVariables($dll); $why += "svchost-hosted; ServiceDll checked" }
        }
        Add-AutorunEntry "Service ($($svc.StartMode), $($svc.State))" "$($svc.Name) - $($svc.DisplayName)" $cmd $score $why
    }
    # --- Scheduled tasks
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        foreach ($a in @($t.Actions)) {
            if (-not $a.PSObject.Properties['Execute'] -or -not $a.Execute) { continue }   # COM handler actions skipped
            $score = 0; $why = @()
            if ($t.Settings -and $t.Settings.Hidden) { $score += 10; $why += 'task is hidden' }
            $exe = [string]$a.Execute
            $cmdline = if ($exe.StartsWith('"')) { "$exe $($a.Arguments)" } else { "`"$exe`" $($a.Arguments)" }
            Add-AutorunEntry "Task $($t.TaskPath) [$($t.State)]" "$($t.TaskPath)$($t.TaskName)" $cmdline.Trim() $score $why
        }
    }
    Write-Log "Autoruns: $($script:Findings.Count - $n) entries"
}

function Invoke-WMI {
    $ns = 'root\subscription'
    $filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)
    $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    $benign = @('SCM Event Log Consumer')
    foreach ($c in $consumers) {
        $cls = $c.CimClass.CimClassName
        $bound = @($bindings | Where-Object { "$($_.Consumer)" -match [regex]::Escape("$($c.Name)") })
        $filterNames = ($bound | ForEach-Object { if ("$($_.Filter)" -match 'Name\s*=\s*"([^"]+)"') { $Matches[1] } }) -join ', '
        $query = ($filters | Where-Object { $filterNames -and ($filterNames -split ', ') -contains $_.Name } | ForEach-Object { $_.Query }) -join ' | '
        $score = 0; $why = @(); $cmd = ''; $path = ''
        switch ($cls) {
            'CommandLineEventConsumer' {
                $cmd = "$($c.ExecutablePath) $($c.CommandLineTemplate)".Trim()
                $path = Resolve-ExePath $(if ($c.ExecutablePath) { $c.ExecutablePath } else { $c.CommandLineTemplate })
                $score = 60; $why += 'WMI CommandLineEventConsumer (classic persistence)'
            }
            'ActiveScriptEventConsumer' {
                $cmd = if ($c.ScriptText) { "[$($c.ScriptingEngine)] $($c.ScriptText)" } else { "[$($c.ScriptingEngine)] $($c.ScriptFileName)" }
                $score = 70; $why += 'WMI ActiveScriptEventConsumer (script persistence)'
            }
            default { if ($benign -notcontains $c.Name) { $score = 10; $why += "WMI $cls consumer" } }
        }
        if ($bound.Count -eq 0 -and $score -gt 0) { $score -= 20; $why += 'not bound to any filter (inactive)' }
        $cr = Get-CmdReasons $cmd; $score += $cr.Score; $why += $cr.Reasons
        Add-Finding -Category 'WMI' -Name "$cls`: $($c.Name)" -Path $path -Detail "filters=[$filterNames] query=[$query] action=[$cmd]" `
            -Score ([math]::Max(0, $score)) -Reasons $why -Extra @{ CommandLine = $cmd }
    }
    Write-Log "WMI: $($filters.Count) filters, $($consumers.Count) consumers, $($bindings.Count) bindings"
}

# ===================================================== file intel / scoring ==
function Add-FileScoring {
    foreach ($f in $script:Findings) {
        if (-not $f.Path) { continue }
        $i = Get-FileIntel $f.Path
        $why = @($f.Reasons); $score = $f.Score
        $loc = Get-LocationReasons $f.Path; $score += $loc.Score; $why += $loc.Reasons
        if (-not $i.Exists) {
            if ($f.Category -in 'Listeners', 'Outbound') { $score += 20; $why += 'binary missing on disk (deleted after launch?)' }
            elseif ($f.Path -match '^[a-zA-Z]:\\') { $score += 5; $why += 'referenced file not found (orphaned entry)' }
        }
        $f.SHA256 = $i.SHA256; $f.Signature = $i.Signature; $f.Signer = $i.Signer
        switch ($i.Signature) {
            'NotSigned' {
                if ($f.Category -eq 'Drivers') { $score += 40; $why += 'kernel driver is unsigned' } else { $score += 20; $why += 'binary is unsigned' }
            }
            { $_ -in 'HashMismatch', 'NotTrusted', 'UnknownError' } { $score += 40; $why += "signature $($i.Signature)" }
            'Valid' { if ($i.Signer -match 'O=Microsoft' -and $score -gt 0) { $score = [math]::Max(0, $score - 15) } }
        }
        $f.Score = [math]::Min(100, [math]::Max(0, $score)); $f.Reasons = $why
    }
}

$script:VTCache = @{}; $script:VTLast = [datetime]::MinValue; $script:VTCount = 0; $script:VTDisabled = $false
function Invoke-VTLookup {
    param([string]$Hash, [string]$Key)
    if ($script:VTCache.ContainsKey($Hash)) { return $script:VTCache[$Hash] }
    $res = [pscustomobject]@{ Status = 'Skipped'; Malicious = 0; Suspicious = 0; Total = 0 }
    if ($script:VTDisabled -or $script:VTCount -ge $VTMaxLookups) { return $res }
    $interval = 60.0 / [math]::Max(1, $VTRatePerMinute)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $wait = $interval - ((Get-Date) - $script:VTLast).TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
        $script:VTLast = Get-Date; $script:VTCount++
        try {
            $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Hash" -Headers @{ 'x-apikey' = $Key } -TimeoutSec 30 -UseBasicParsing
            $s = $r.data.attributes.last_analysis_stats
            $res.Status = 'Found'; $res.Malicious = [int]$s.malicious; $res.Suspicious = [int]$s.suspicious
            $res.Total = [int](($s.PSObject.Properties | Measure-Object -Property Value -Sum).Sum)
            break
        } catch {
            $code = 0
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 404) { $res.Status = 'NotFound'; break }
            if ($code -eq 429) { Write-Log 'VirusTotal rate limit hit (429); backing off 60s' 'WARN'; Start-Sleep -Seconds 60; continue }
            if ($code -in 401, 403) { Write-Log "VirusTotal rejected the API key (HTTP $code); disabling lookups" 'ERROR'; $script:VTDisabled = $true; $res.Status = 'AuthError'; break }
            $res.Status = "Error: $($_.Exception.Message)"; break
        }
    }
    $script:VTCache[$Hash] = $res
    return $res
}

function Add-VTScoring {
    param([string]$Key)
    if ($PSVersionTable.PSVersion.Major -lt 6) {   # Windows PowerShell 5.1 may default to TLS 1.0
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    # Spend quota on the most suspicious hashes first; skip valid Microsoft-signed unless -VTAll.
    $queue = $script:Findings | Where-Object { $_.SHA256 -and ($VTAll -or -not ($_.Signature -eq 'Valid' -and $_.Signer -match 'O=Microsoft')) } |
        Sort-Object Score -Descending | Select-Object -ExpandProperty SHA256 -Unique
    $queue = @($queue)
    $eta = [math]::Ceiling([math]::Min($queue.Count, $VTMaxLookups) * 60.0 / [math]::Max(1, $VTRatePerMinute) / 60)
    Write-Log "VirusTotal: $($queue.Count) unique hashes queued (max $VTMaxLookups, $VTRatePerMinute/min, ~$eta min)"
    foreach ($h in $queue) { [void](Invoke-VTLookup $h $Key) }
    foreach ($f in $script:Findings) {
        if (-not $f.SHA256 -or -not $script:VTCache.ContainsKey($f.SHA256)) { continue }
        $v = $script:VTCache[$f.SHA256]
        $f.VT = if ($v.Status -eq 'Found') { "$($v.Malicious)/$($v.Total)" } else { $v.Status }
        $f.VTLink = "https://www.virustotal.com/gui/file/$($f.SHA256)"
        if ($v.Status -eq 'Found' -and $v.Malicious -gt 0) {
            $add = [math]::Min(60, 15 * $v.Malicious)
            $f.Score = [math]::Min(100, $f.Score + $add)
            if ($v.Malicious -ge 3) { $f.Score = [math]::Max($f.Score, 60) }
            $f.Reasons = @($f.Reasons) + "VirusTotal: $($v.Malicious)/$($v.Total) engines flag this hash"
        }
    }
    Write-Log "VirusTotal: $($script:VTCount) API requests made"
}

# ================================================================ reports ==
function Write-Reports {
    param([string]$Dir, [string]$Stamp, [hashtable]$Meta)
    $all = @($script:Findings | Sort-Object @{ e = 'Score'; Descending = $true }, Category, Name)
    $base = Join-Path $Dir "ThreatHunt_$($env:COMPUTERNAME)_$Stamp"

    # JSON + CSV for SIEM ingestion
    $records = @($all | ForEach-Object {
        $o = [ordered]@{ '@timestamp' = $Meta.Start; host = $env:COMPUTERNAME }
        foreach ($p in $_.PSObject.Properties) { $o[$p.Name] = $p.Value }
        [pscustomobject]$o
    })
    $json = if ($records.Count) { ConvertTo-Json -InputObject $records -Depth 4 } else { '[]' }
    Set-Content -LiteralPath "$base.json" -Value $json -Encoding UTF8
    $all | Select-Object Category, Severity, Score, Name, Path, Target, Signature, Signer, SHA256, VT, @{ n = 'Reasons'; e = { $_.Reasons -join '; ' } }, Detail |
        Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8

    # TXT
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("ThreatHunt Pro v$($script:Version) - forensic triage report")
    [void]$sb.AppendLine(('=' * 78))
    foreach ($k in $Meta.Keys) { [void]$sb.AppendLine(('{0,-14}: {1}' -f $k, $Meta[$k])) }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(($all | Group-Object Category | ForEach-Object {
        $g = $_.Group
        [pscustomobject]@{ Category = $_.Name; Total = $g.Count; HIGH = @($g | ? Severity -eq 'HIGH').Count
            MEDIUM = @($g | ? Severity -eq 'MEDIUM').Count; LOW = @($g | ? Severity -eq 'LOW').Count }
    } | Format-Table -AutoSize | Out-String -Width 300).TrimEnd())
    foreach ($cat in $script:AllModules) {
        $flag = @($all | Where-Object { $_.Category -eq $cat -and $_.Score -gt 0 })
        if (-not ($all | Where-Object Category -eq $cat)) { continue }
        [void]$sb.AppendLine(''); [void]$sb.AppendLine("--- $cat : $($flag.Count) flagged " + ('-' * 50))
        foreach ($f in $flag) {
            [void]$sb.AppendLine(('[{0,-6} {1,3}] {2}' -f $f.Severity, $f.Score, $f.Name))
            if ($f.Path) { [void]$sb.AppendLine("    Path     : $($f.Path)") }
            if ($f.Target) { [void]$sb.AppendLine("    Target   : $($f.Target)") }
            [void]$sb.AppendLine("    Detail   : $($f.Detail)")
            [void]$sb.AppendLine("    Signature: $($f.Signature) $($f.Signer)")
            if ($f.SHA256) { [void]$sb.AppendLine("    SHA256   : $($f.SHA256)  VT: $($f.VT)") }
            foreach ($r in $f.Reasons) { [void]$sb.AppendLine("      - $r") }
        }
    }
    [void]$sb.AppendLine(''); [void]$sb.AppendLine('--- Full inventory ' + ('-' * 59))
    [void]$sb.AppendLine(($all | Format-Table Category, Severity, Score, Name, Signature, Path -AutoSize | Out-String -Width 400))
    Set-Content -LiteralPath "$base.txt" -Value $sb.ToString() -Encoding UTF8

    # HTML (every value encoded: names/paths/command lines are attacker-controlled)
    function E([object]$s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>ThreatHunt Pro - $(E $env:COMPUTERNAME)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f6f7f9;color:#1d2330}
h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:2px solid #d0d5dd;padding-bottom:4px}
.meta td{padding:2px 12px 2px 0;font-size:13px}
table.f{border-collapse:collapse;width:100%;background:#fff;font-size:12.5px}
table.f th{background:#1d2330;color:#fff;text-align:left;padding:6px;position:sticky;top:0}
table.f td{border-bottom:1px solid #e3e6ea;padding:5px 6px;vertical-align:top;word-break:break-all}
.b{display:inline-block;padding:1px 7px;border-radius:9px;font-weight:600;font-size:11px;color:#fff}
.HIGH{background:#c62828}.MEDIUM{background:#e08a00}.LOW{background:#5a7bb5}.INFO{background:#8a929e}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:10px 16px;min-width:120px}
.card b{font-size:22px;display:block}
ul{margin:0;padding-left:16px}
#sc:not(:checked) ~ section tr.clean{display:none}
code{font-size:11.5px;color:#444}
</style></head><body>
<h1>ThreatHunt Pro - Triage Report</h1><table class="meta">
"@)
    foreach ($k in $Meta.Keys) { [void]$h.Append("<tr><td><b>$(E $k)</b></td><td>$(E $Meta[$k])</td></tr>") }
    [void]$h.Append('</table><div class="cards">')
    foreach ($sev in 'HIGH', 'MEDIUM', 'LOW') {
        [void]$h.Append("<div class='card'><span class='b $sev'>$sev</span><b>$(@($all | ? Severity -eq $sev).Count)</b></div>")
    }
    [void]$h.Append("<div class='card'>Items scanned<b>$($all.Count)</b></div></div>")
    [void]$h.Append('<input type="checkbox" id="sc"><label for="sc"> Show clean (INFO) rows</label>')
    foreach ($cat in $script:AllModules) {
        $rows = @($all | Where-Object Category -eq $cat)
        if (-not $rows) { continue }
        [void]$h.Append("<section><h2>$cat <small>($(@($rows | ? Score -gt 0).Count) flagged / $($rows.Count))</small></h2>")
        [void]$h.Append('<table class="f"><tr><th>Sev</th><th>Score</th><th>Name</th><th>Path / Detail</th><th>Signature</th><th>VT</th><th>Reasons</th></tr>')
        foreach ($f in $rows) {
            $cls = if ($f.Score -gt 0) { '' } else { ' class="clean"' }
            $vt = if ($f.VTLink) { "<a href='$(E $f.VTLink)'>$(E $f.VT)</a>" } else { '' }
            $reasons = ($f.Reasons | ForEach-Object { "<li>$(E $_)</li>" }) -join ''
            $tgt = if ($f.Target) { "<br>target: $(E $f.Target)" } else { '' }
            [void]$h.Append("<tr$cls><td><span class='b $($f.Severity)'>$($f.Severity)</span></td><td>$($f.Score)</td><td>$(E $f.Name)</td>" +
                "<td>$(E $f.Path)$tgt<br><code>$(E $f.Detail)</code>$(if ($f.SHA256) { "<br><code>sha256 $($f.SHA256)</code>" })</td>" +
                "<td>$(E $f.Signature)<br><code>$(E $f.Signer)</code></td><td>$vt</td><td><ul>$reasons</ul></td></tr>")
        }
        [void]$h.Append('</table></section>')
    }
    [void]$h.Append('<p><small>Scores are heuristic leads, not verdicts. Verify before remediation.</small></p></body></html>')
    Set-Content -LiteralPath "$base.html" -Value $h.ToString() -Encoding UTF8
    return $base
}

# =================================================================== main ==
function Invoke-Main {
    # Modules may arrive as "A,B" in one string after a -File relaunch.
    $mods = @($Modules | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($mods -contains 'All') { $mods = $script:AllModules }
    $bad = @($mods | Where-Object { $script:AllModules -notcontains $_ })
    if ($bad) { throw "Unknown module(s): $($bad -join ', '). Valid: $($script:AllModules -join ', '), All" }

    if (-not $OutputDir) { $OutputDir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'ThreatHuntPro' }
    $script:OutDir = [IO.Path]::GetFullPath($OutputDir)

    # Resolve the VT key before any relaunch.
    $key = $VTApiKey
    if (-not $key -and $VTApiKeyFile) {
        $key = (Get-Content -LiteralPath $VTApiKeyFile -TotalCount 1).Trim()
        if ($DeleteKeyFile) { Remove-Item -LiteralPath $VTApiKeyFile -Force -ErrorAction SilentlyContinue }
    }
    if (-not $key) { $key = $env:VT_API_KEY }

    # ---- UAC-safe auto-elevation: relaunch via the standard consent prompt.
    $isAdmin = Test-IsAdmin
    $kf = $null
    if (-not $isAdmin -and -not $NoElevate -and $env:OS -eq 'Windows_NT') {
        $self = (Get-Process -Id $PID).Path
        $isHost = [IO.Path]::GetFileName($self) -match '^(powershell|pwsh)(\.exe)?$'
        $argList = New-Object System.Collections.Generic.List[string]
        if ($isHost) {
            if (-not $PSCommandPath) { Write-Warning 'Cannot locate script path for relaunch; continuing unelevated.' }
            else { $argList.AddRange([string[]]@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")) }
        }
        if (-not $isHost -or $PSCommandPath) {
            $argList.AddRange([string[]]@('-OutputDir', "`"$($script:OutDir)`"", '-Modules', ($mods -join ','),
                '-VTRatePerMinute', "$VTRatePerMinute", '-VTMaxLookups', "$VTMaxLookups", '-MinScore', "$MinScore"))
            foreach ($sw in 'VirusTotal', 'VTAll', 'NoOpen') { if ((Get-Variable $sw -ValueOnly)) { $argList.Add("-$sw") } }
            if ($VirusTotal -and $key) {
                # Hand the key over in a per-user temp file, never on the elevated command line.
                $kf = Join-Path $env:TEMP ("thp_{0}.key" -f [guid]::NewGuid().ToString('N'))
                Set-Content -LiteralPath $kf -Value $key -Encoding ASCII -NoNewline
                $argList.AddRange([string[]]@('-VTApiKeyFile', "`"$kf`"", '-DeleteKeyFile'))
            }
            try {
                Write-Host '[*] Not elevated. Requesting Administrator rights via UAC...' -ForegroundColor Cyan
                $p = Start-Process -FilePath $self -ArgumentList ($argList -join ' ') -Verb RunAs -PassThru -Wait
                exit $p.ExitCode
            } catch {
                Write-Warning "Elevation declined or failed ($($_.Exception.Message)). Continuing with limited visibility."
                if ($kf) { Remove-Item -LiteralPath $kf -Force -ErrorAction SilentlyContinue }
            }
        }
    }

    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile = Join-Path $script:OutDir "ThreatHunt_$($env:COMPUTERNAME)_$stamp.log"
    $start = Get-Date
    Write-Log "ThreatHunt Pro v$($script:Version) on $env:COMPUTERNAME as $([Environment]::UserDomainName)\$([Environment]::UserName) (admin=$isAdmin, PS $($PSVersionTable.PSVersion))"
    if (-not $isAdmin) { Write-Log 'Not elevated: SYSTEM process paths, some tasks and WMI subscriptions may be hidden.' 'WARN' }

    foreach ($m in $mods) {
        try { & "Invoke-$m" } catch { Write-Log "$m module failed: $($_.Exception.Message)" 'ERROR' }
    }
    Write-Log "Hashing and signature verification of $(@($script:Findings | ? Path | select -Expand Path -Unique).Count) unique files..."
    Add-FileScoring
    if ($VirusTotal) {
        if ($key) { Add-VTScoring $key } else { Write-Log '-VirusTotal set but no API key (env:VT_API_KEY, -VTApiKeyFile or -VTApiKey); skipping.' 'WARN' }
    }
    foreach ($f in $script:Findings) { $f.Severity = Get-Severity $f.Score }

    $os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { [Environment]::OSVersion.VersionString }
    $meta = [ordered]@{
        Host = $env:COMPUTERNAME; OS = $os; User = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        Elevated = $isAdmin; Start = $start.ToString('o'); Duration = ('{0:n1}s' -f ((Get-Date) - $start).TotalSeconds)
        Modules = ($mods -join ', '); VirusTotal = $(if ($VirusTotal -and $key) { "on ($($script:VTCount) requests)" } else { 'off' })
    }
    $base = Write-Reports -Dir $script:OutDir -Stamp $stamp -Meta $meta

    $hi = @($script:Findings | ? Severity -eq 'HIGH'); $med = @($script:Findings | ? Severity -eq 'MEDIUM')
    Write-Host ''
    foreach ($f in @($hi + $med | Sort-Object Score -Descending | Select-Object -First 15)) {
        $c = if ($f.Severity -eq 'HIGH') { 'Red' } else { 'Yellow' }
        Write-Host ('[{0,-6} {1,3}] {2,-9} {3}' -f $f.Severity, $f.Score, $f.Category, $f.Name) -ForegroundColor $c
        Write-Host ("               $($f.Reasons -join '; ')") -ForegroundColor DarkGray
    }
    Write-Log "Done: $($hi.Count) HIGH, $($med.Count) MEDIUM of $($script:Findings.Count) items. Reports: $base.{html,txt,json,csv}"
    if (-not $NoOpen -and $env:OS -eq 'Windows_NT' -and [Environment]::UserInteractive) { try { Invoke-Item "$base.html" } catch { } }
    if (@($script:Findings | Where-Object { $_.Score -ge $MinScore }).Count) { exit 2 } else { exit 0 }
}

# Dot-sourcing (tests) loads functions without running a scan.
if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
