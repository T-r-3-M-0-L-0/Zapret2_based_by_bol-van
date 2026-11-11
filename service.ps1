#requires -Version 5.1
<#
.SYNOPSIS
  ZAPRET2 SERVICE MANAGER - service.bat (zapret1) equivalent for winws2/zapret2.
.DESCRIPTION
  Menu: install/remove the zapret2 service from any .bat strategy,
  run without service, status with live test, build Custom.bat from profiles\*.conf.
  The zapret1 service ("zapret") is never deleted, only stopped while winws2 runs.
  NOTE: this file is pure ASCII on purpose - PowerShell 5.1 misreads UTF-8
  without BOM on systems with a non-UTF-8 system codepage (cp1251 etc.).
.PARAMETER ParseOnly
  Hidden test mode: print winws2 arguments extracted from the given .bat and exit.
.PARAMETER BuildOnly
  Hidden test mode: build Custom.bat from profiles by numbers (e.g. "1,2,3") and exit.
#>
param(
    [string]$ParseOnly = "",
    [string]$BuildOnly = "",
    [string]$InstallFrom = "",
    [switch]$RemoveService,
    [switch]$StatusOnly,
    [switch]$EnsureRunning
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$ROOT   = Split-Path -Parent $MyInvocation.MyCommand.Path
$BIN    = Join-Path $ROOT "bin\"
$LISTS  = Join-Path $ROOT "lists\"
$LUA    = Join-Path $ROOT "lua\"
$PROFS  = Join-Path $ROOT "profiles"
$SRV2   = "zapret2"          # our service
$SRV1   = "zapret"           # zapret1 service (never delete, only stop/start)
$REGKEY = "HKLM:\System\CurrentControlSet\Services\$SRV2"

# ---------- helpers ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-C([string]$Text, [string]$Color = "Gray") { Write-Host $Text -ForegroundColor $Color }

function Get-ServiceState([string]$Name) {
    $s = sc.exe query $Name 2>$null
    if ($LASTEXITCODE -ne 0) { return "NOT_INSTALLED" }
    $line = ($s | Select-String -Pattern "STATE\s*:\s*\d+\s+(\w+)").Matches
    if ($line -and $line.Groups.Count -gt 1) { return $line.Groups[1].Value }
    return "UNKNOWN"
}

function Test-Process([string]$Image) {
    return [bool](Get-Process -Name ($Image -replace '\.exe$','') -ErrorAction SilentlyContinue)
}

function Stop-ConflictingEngines {
    # winws and winws2 share WinDivert: they must not run at the same time.
    # Returns $false when a stray engine process blocks the install.
    # A stray process must be closed gracefully (its console window / Ctrl+C):
    # a force-kill wedges the WinDivert driver in the kernel (FWP_E_IN_USE).
    if ((Get-ServiceState $SRV1) -eq "RUNNING") {
        Write-C "Stopping service '$SRV1' (zapret1)..." Yellow
        sc.exe stop $SRV1 | Out-Null
    }
    $stray = @()
    foreach ($img in "winws","winws2") {
        $p = Get-Process -Name $img -ErrorAction SilentlyContinue
        if ($p) { $stray += $img }
    }
    if ($stray.Count -gt 0) {
        Write-C "Stray engine process(es) running: $($stray -join ', ')" Red
        Write-C "Close them gracefully (their console window, not taskkill) and retry." Yellow
        Write-C "If they cannot be closed - reboot, then install again." Yellow
        return $false
    }
    return $true
}

function Get-CurrentStrategy {
    try {
        $v = (Get-ItemProperty -Path $REGKEY -Name "strategy" -ErrorAction Stop).strategy
        return $v
    } catch { return "(not installed)" }
}

# Extract winws2 arguments from a .bat strategy
function Get-Winws2Args([string]$BatPath) {
    $raw = Get-Content -Raw -LiteralPath $BatPath
    # find the launch line: winws2.exe followed by closing quote + "^" or options
    $m = [regex]::Match($raw, 'winws2\.exe"?\s*(?:\^|--)\s*\r?\n?\s*--')
    if (-not $m.Success) { $m = [regex]::Match($raw, 'winws2\.exe"?\s*\^') }
    if (-not $m.Success) { throw "No winws2.exe invocation with arguments found in $BatPath" }
    $idx = $m.Index
    $sub = $raw.Substring($idx + "winws2.exe".Length)
    # join continuation lines " ^\n"
    $sub = $sub -replace "\^\s*\r?\n", " "
    # take the first (now single long) argument line
    $sub = ($sub -split "`n")[0]
    # strip the leftover closing quote of the exe path at the start
    $sub = $sub.TrimStart(' ','"')
    # expand directory variables
    $sub = $sub.Replace('%BIN%',$BIN).Replace('%LISTS%',$LISTS).Replace('%LUA%',$LUA).Replace('%~dp0',"$ROOT\")
    $sub = $sub.Trim()
    if ($sub -notmatch '^--') { throw "Failed to parse arguments (do not start with '--'): $($sub.Substring(0,[Math]::Min(80,$sub.Length)))" }
    return $sub
}

function Reset-WinDivertDriver {
    # Returns $true when no WinDivert driver service/driver is present.
    # After a failed or killed winws2 the driver can stay loaded with DeleteFlag=1
    # and Start=4; every later WinDivertOpen then fails 0x8032000A (FWP_E_IN_USE).
    # A graceful stop clears it; if the driver cannot unload -> reboot is the only cure.
    sc.exe query WinDivert 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { return $true }  # not installed: clean
    sc.exe stop WinDivert 2>$null | Out-Null
    for ($i=0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        sc.exe query WinDivert 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $true }  # entry gone: fully unloaded
        $line = (sc.exe query WinDivert 2>$null | Select-String 'STATE').ToString()
        if ($line -match 'STOPPED') { sc.exe delete WinDivert 2>$null | Out-Null }
    }
    return $false
}

function Install-ServiceFromBat([string]$BatPath) {
    $argLine = Get-Winws2Args $BatPath
    # sc.exe tokenizes binPath by spaces, ignoring quotes:
    # "x = f(...)" inside --lua-init yields a bare "=" token and error 1639.
    # Remove spaces around '=' - equivalent for lua.
    $argLine = $argLine -replace ' = ', '='
    Write-C "`nService arguments:" DarkGray
    Write-C $argLine DarkGray

    if (-not (Stop-ConflictingEngines)) { return }
    if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
        sc.exe stop $SRV2 | Out-Null
        sc.exe delete $SRV2 | Out-Null
        # wait for physical deletion: otherwise create hits "pending deletion"
        # and leaves an empty registry key without ImagePath
        for ($i=0; $i -lt 20 -and (Get-ServiceState $SRV2) -ne "NOT_INSTALLED"; $i++) {
            Start-Sleep -Milliseconds 250
        }
        Remove-Item -LiteralPath $REGKEY -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Pre-flight: a stuck WinDivert driver dooms the new service (FWP_E_IN_USE).
    if (-not (Reset-WinDivertDriver)) {
        Write-C "WinDivert driver is stuck in the kernel (pending delete, still loaded)." Red
        Write-C "No service was created. Reboot the PC, then run the install again." Yellow
        Write-C "Never kill winws2 (taskkill/Stop-Process) - that is what wedges the driver." Yellow
        return
    }
    $exe = Join-Path $BIN "winws2.exe"
    # sc.exe from PowerShell breaks a long binPath with quotes (error 1639),
    # WMI Create writes an empty ImagePath - so we generate a .cmd like zapret1 service.bat.
    # Escape every double quote inside the value as \" :
    # otherwise sc eats them and winws2 then splits --lua-init on commas inside 'rnd,rndsni'
    $argEsc = $argLine.Replace('"', '\"')
    $tmpCmd = Join-Path $env:TEMP "zapret2_create.cmd"
    # start= auto + failure recovery: at boot winws2 touches SCM/WinDivert while the
    # RPC endpoint mapper is not ready yet (event 7023, error 1753, ~1s after boot).
    # SCM restarts the service 5s later when RPC is up. delayed-auto was rejected:
    # its ~120s delay is hardcoded in SCM and not configurable.
    $cmdBody = "@echo off`r`nsc.exe create $SRV2 binPath= `"\`"$exe\`" $argEsc`" DisplayName= `"zapret2`" start= auto`r`n"
    Set-Content -LiteralPath $tmpCmd -Value $cmdBody -Encoding ASCII
    cmd.exe /c "`"$tmpCmd`"" | Out-Null
    $rc = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpCmd -Force -ErrorAction SilentlyContinue
    if ($rc -ne 0) { throw "sc create exited with code $rc" }
    $imgPath = (Get-ItemProperty "$REGKEY" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if (-not $imgPath) { throw "Service created but ImagePath is empty - creation failed" }
    sc.exe description $SRV2 "zapret2 DPI bypass (winws2)" | Out-Null
    sc.exe failure $SRV2 reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
    $name = [IO.Path]::GetFileNameWithoutExtension($BatPath)
    # the key already exists (created by sc.exe); New-Item -Force is forbidden here:
    # it recreates the key and wipes ImagePath
    Set-ItemProperty -Path $REGKEY -Name "strategy" -Value $name
    sc.exe start $SRV2 | Out-Null
    Start-Sleep -Seconds 1
    $st = Get-ServiceState $SRV2
    if ($st -eq "RUNNING") {
        Write-C "Service '$SRV2' is running, strategy: $name" Green
    } else {
        Write-C "Service created but state is: $st. Check logs/permissions." Red
    }
}

function Remove-Service2 {
    if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
        sc.exe stop $SRV2 | Out-Null
        sc.exe delete $SRV2 | Out-Null
        Write-C "Service '$SRV2' removed." Green
    } else {
        Write-C "Service '$SRV2' is not installed." Yellow
    }
    # Never Stop-Process winws2 here: a force-kill wedges the WinDivert driver
    # in the kernel (pending delete) and every later start fails FWP_E_IN_USE.
    if (Get-Process -Name winws2 -ErrorAction SilentlyContinue) {
        Write-C "A stray winws2.exe process is still running outside the service." Yellow
        Write-C "Close it gracefully; if the next install reports a stuck driver - reboot." Yellow
    }
}

function Test-Endpoint([string]$Url) {
    $code = & curl.exe -s -o NUL -w "%{http_code}" --max-time 8 $Url 2>$null
    return $code
}

# ---------- TG WS Proxy (tg-ws-proxy\ subfolder, optional) ----------
$TGROOT  = Join-Path $ROOT "tg-ws-proxy"
$TGMAIN  = Join-Path $TGROOT "proxy\tg_ws_proxy.py"
# the secret below must match proxy\add_proxy.bat: changing it breaks the configured tg:// link

function Get-TgProxyProcess {
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' or Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'tg_ws_proxy\.py' }
}

# Resolve a python interpreter able to run the proxy.
# Order: fixed system paths -> py launcher -> PATH.
# Microsoft Store stubs (WindowsApps) are skipped: they only open the Store.
function Resolve-TgPython {
    $candidates = @(
        "C:\Program Files\Python312\pythonw.exe",
        "C:\Program Files\Python313\pythonw.exe",
        "C:\Program Files\Python314\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python314\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\pythonw.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $py = (Get-Command py.exe -ErrorAction SilentlyContinue).Source
    if ($py) {
        $p = (& py.exe -3 -c "import sys,os;print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" 2>$null)
        if ($p -and (Test-Path $p)) { return ($p | Select-Object -Last 1) }
        $p = (& py.exe -3 -c "import sys;print(sys.executable)" 2>$null)
        if ($p -and (Test-Path ($p | Select-Object -Last 1))) { return ($p | Select-Object -Last 1) }
    }
    foreach ($name in 'pythonw.exe','python.exe') {
        $p = (Get-Command $name -ErrorAction SilentlyContinue).Source
        if ($p -and $p -notlike '*WindowsApps*') { return $p }
    }
    return $null
}

# Direct python.org install (fallback when winget is missing/fails: LTSC, old Win10).
# Finds the newest 3.12.x on the FTP index, downloads the amd64 installer, silent install.
function Install-TgPythonFromWeb {
    try {
        Write-C "Downloading Python 3.12 from python.org ..." Yellow
        $idx = Invoke-WebRequest -Uri "https://www.python.org/ftp/python/" -UseBasicParsing -TimeoutSec 30
        $vers = [regex]::Matches($idx.Content, 'href="(3\.12\.\d+)/"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
        if (-not $vers) { throw "no 3.12.x found on python.org index" }
        # newest 3.12.x are source-only security releases (no Windows installer) -
        # walk versions down until one actually ships python-<ver>-amd64.exe
        $latest = $null
        foreach ($v in ($vers | Sort-Object { [version]$_ } -Descending)) {
            $dir = Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$v/" -UseBasicParsing -TimeoutSec 30
            if ($dir.Content -match "python-$v-amd64\.exe") { $latest = $v; break }
        }
        if (-not $latest) { throw "no 3.12.x with a Windows installer found" }
        $url = "https://www.python.org/ftp/python/$latest/python-$latest-amd64.exe"
        $pkg = Join-Path $env:TEMP "python-$latest-amd64.exe"
        Write-C "  $url" DarkGray
        Invoke-WebRequest -Uri $url -OutFile $pkg -UseBasicParsing -TimeoutSec 300
        Write-C "Installing (silent, all users, add to PATH)..." Yellow
        $proc = Start-Process -FilePath $pkg -ArgumentList '/quiet','InstallAllUsers=1','PrependPath=1','Include_test=0','Include_doc=0' -Wait -PassThru
        Remove-Item $pkg -Force -ErrorAction SilentlyContinue
        if ($proc.ExitCode -ne 0) { throw "installer exited with code $($proc.ExitCode)" }
        return $true
    } catch {
        Write-C "python.org install failed: $_" Red
        return $false
    }
}

# No python anywhere -> install Python 3.12 (winget first, python.org fallback).
function Install-TgPython {
    Write-C "Python not found on this system." Yellow
    $ok = $false
    $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if ($winget) {
        Write-C "Installing Python 3.12 via winget (silent)..." Yellow
        & winget.exe install --id Python.Python.3.12 -e --silent --accept-source-agreements --accept-package-agreements
        $ok = ($LASTEXITCODE -eq 0)
        if (-not $ok) { Write-C "winget install failed (code $LASTEXITCODE), trying python.org ..." Yellow }
    } else {
        Write-C "winget is unavailable, using the python.org installer." DarkYellow
    }
    if (-not $ok) { $ok = Install-TgPythonFromWeb }
    if (-not $ok) {
        Write-C "Automatic install failed. Install Python manually: https://www.python.org/downloads/" Red
        Write-C "(tick 'Add python.exe to PATH' in the installer), then retry." Yellow
        return $null
    }
    # a fresh install updates the registry PATH, but not this process - reload it
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
    $p = Resolve-TgPython
    if (-not $p) { Write-C "Python was installed but not found - reopen the console and retry." Yellow }
    return $p
}

# The proxy needs httpx[http2] (cf_h2.py). Auto-install if missing.
function Ensure-TgProxyDeps([string]$Python) {
    $exe = $Python -replace 'pythonw\.exe$','python.exe'
    & $exe -c "import httpx, h2" 2>$null
    if ($LASTEXITCODE -eq 0) { return $true }
    Write-C "Installing proxy dependencies (httpx[http2])..." Yellow
    & $exe -m ensurepip --upgrade 2>$null | Out-Null
    & $exe -m pip install --quiet "httpx[http2]>=0.28"
    if ($LASTEXITCODE -ne 0) {
        Write-C "pip install failed. Check the internet connection and retry." Red
        return $false
    }
    & $exe -c "import httpx, h2" 2>$null
    if ($LASTEXITCODE -eq 0) { Write-C "Dependencies OK." Green; return $true }
    Write-C "Dependencies still not importable after install." Red
    return $false
}

# Sanity-check the logon autostart task: right copy, existing python.
function Test-TgAutostartTask {
    $t = Get-ScheduledTask -TaskName 'Telegram WS Proxy AutoStart' -ErrorAction SilentlyContinue
    if (-not $t) { Write-C "  autostart task: not found (proxy will not start at logon)" DarkYellow; return }
    $exe = [string]$t.Actions[0].Execute
    $arg = [string]$t.Actions[0].Arguments
    if ($arg -notlike "*$TGROOT*") { Write-C "  autostart task: points to ANOTHER copy - $arg" Yellow; return }
    if (-not (Test-Path $exe)) { Write-C "  autostart task: python missing - $exe" Yellow; return }
    Write-C "  autostart task: OK (logon -> $exe)" DarkGray
}

function Show-TgProxyStatus {
    if (-not (Test-Path $TGMAIN)) { Write-C "tg-ws-proxy: not deployed in $TGROOT" DarkGray; return }
    $p = @(Get-TgProxyProcess)
    if ($p.Count -gt 0) {
        # version and path of the ACTUALLY RUNNING copy (it may live outside $TGROOT)
        # $p can hold launcher+child - walk until a quoted tg_ws_proxy.py path matches
        $ver = "?"; $from = ""
        foreach ($proc in $p) {
            $mm = [regex]::Match([string]$proc.CommandLine, '"([^"]*tg_ws_proxy\.py)"')
            if (-not $mm.Success) { $mm = [regex]::Match([string]$proc.CommandLine, '(\S*tg_ws_proxy\.py)') }
            if ($mm.Success) { $from = $mm.Groups[1].Value; break }
        }
        if ($from) {
            $ini = Join-Path (Split-Path $from) '__init__.py'
            if (Test-Path $ini) {
                $m = (Select-String -Path $ini -Pattern '__version__\s*=\s*"([^"]+)"').Matches
                if ($m) { $ver = $m[0].Groups[1].Value }
            }
        }
        Write-C ("tg-ws-proxy: RUNNING (pid " + $p[0].ProcessId + ", v" + $ver + ")") Green
        if ($from -and ($from -notlike "$TGROOT*")) { Write-C ("  note: running from another copy: " + $from) Yellow }
    } else {
        Write-C "tg-ws-proxy: not running" Yellow
    }
    Test-TgAutostartTask
}

function Start-TgProxy {
    if (-not (Test-Path $TGMAIN)) { Write-C "tg-ws-proxy not found in $TGROOT" Red; return $false }
    if (Get-TgProxyProcess) { Write-C "tg-ws-proxy is already running." Green; return $true }
    # resolve python (fixed paths -> py launcher -> PATH); install via winget if none
    $pythonw = Resolve-TgPython
    if (-not $pythonw) { $pythonw = Install-TgPython }
    if (-not $pythonw) { return $false }
    if (-not (Ensure-TgProxyDeps $pythonw)) { return $false }
    $logDir = Join-Path $ROOT "logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    # pool-size 8: since 1.11.0 direct DC connections go only through the pool, author recommends > 4
    $argLine = "`"$TGMAIN`" --port 1080 --host 127.0.0.1 --secret c36be8ffc5f480784b4c5fc31f1eefe8 --pool-size 8 --log-file `"$logDir\tgproxy.log`""
    Start-Process -FilePath $pythonw -ArgumentList $argLine -WorkingDirectory $TGROOT -WindowStyle Hidden
    Start-Sleep -Seconds 2
    if (Get-TgProxyProcess) { Write-C "tg-ws-proxy started (port 1080)." Green; return $true }
    Write-C "tg-ws-proxy failed to start. See logs\tgproxy.log" Red
    return $false
}

function Stop-TgProxy {
    # plain python process, no drivers - Stop-Process is safe here
    Get-TgProxyProcess | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Menu-TgProxy {
    Show-TgProxyStatus
    Write-Host "      a. Start"
    Write-Host "      b. Restart"
    Write-Host "      c. Stop"
    Write-Host "      d. Open Telegram with proxy link"
    $ch = Read-Host "  Choice (a-d, Enter = cancel)"
    switch ($ch) {
        "a" { [void](Start-TgProxy) }
        "b" { Stop-TgProxy; Start-Sleep -Seconds 1; [void](Start-TgProxy) }
        "c" { Stop-TgProxy; Write-C "tg-ws-proxy stopped." Green }
        "d" { $lnk = Join-Path $TGROOT "proxy\add_proxy.bat"; if (Test-Path $lnk) { Start-Process $lnk } }
    }
}

# ztool.py - python control plane toolbox (debug/config/watch/update/...)
function Menu-Ztool {
    $zt = Join-Path $ROOT "ztool.py"
    if (-not (Test-Path $zt)) { Write-C "ztool.py not found in $ROOT" Red; return }
    $pythonw = Resolve-TgPython
    if (-not $pythonw) { Write-C "Python not found - menu 8 can bootstrap it." Red; return }
    $python = $pythonw -replace 'pythonw\.exe$','python.exe'
    Write-Host "      1. debug <bat>     - live debug session (parses profile hits)"
    Write-Host "      2. config <bat>    - convert strategy to winws2 @config file"
    Write-Host "      3. watch --once    - probe key domains (DPI window check)"
    Write-Host "      4. update          - check GitHub for engine/lists/proxy updates"
    Write-Host "      5. hostlists stats - list hygiene overview"
    Write-Host "      6. diag            - diagnostic bundle (logs\diag_*.zip)"
    Write-Host "      7. snapshot save   - version Custom.bat + profiles\"
    Write-Host "      8. wfcheck <bat>   - WinDivert filter CPU-trap analysis"
    Write-Host "      (or type any raw ztool args, e.g.: snapshot restore 001)"
    $ch = Read-Host "  Choice / args (Enter = cancel)"
    $zargs = switch ($ch) {
        "1" { $b = Select-StrategyBat; if ($b) { @('debug', $b) } }
        "2" { $b = Select-StrategyBat; if ($b) { @('config', $b) } }
        "3" { @('watch','--once') }
        "4" { @('update') }
        "5" { @('hostlists','stats') }
        "6" { @('diag') }
        "7" { @('snapshot','save') }
        "8" { $b = Select-StrategyBat; if ($b) { @('wfcheck', $b) } }
        default { if ($ch) { $ch -split ' ' } }
    }
    # a single-element switch result unwraps to a plain string; re-wrap it,
    # otherwise splatting passes the string char by char ('u','p','d',...)
    if ($zargs -is [string]) { $zargs = @($zargs) }
    if ($zargs) { & $python $zt @zargs }
}
# Blockcheck: python matrix tester (blockcheck.py next to this script).
# The zapret2 service is stopped for the test window and restored after.
function Invoke-Blockcheck {
    $bc = Join-Path $ROOT "blockcheck.py"
    if (-not (Test-Path $bc)) { Write-C "blockcheck.py not found in $ROOT" Red; return }
    $pythonw = Resolve-TgPython
    if (-not $pythonw) { Write-C "Python not found - install it first (menu 8 can bootstrap it)." Red; return }
    $python = $pythonw -replace 'pythonw\.exe$','python.exe'
    $domain = Read-Host "  Domain to test (e.g. example.com)"
    if (-not $domain) { return }
    $proto = Read-Host "  Protocol: tls/http/quic (Enter = tls)"
    $bargs = @($bc, $domain)
    if ($proto -eq 'http' -or $proto -eq 'quic') { $bargs += @('--proto', $proto) }
    $mode = Read-Host "  Full matrix or quick? (f/q, Enter = quick)"
    if ($mode -ne 'f') { $bargs += '--quick' }
    $ap = Read-Host "  Save the winner as a profile? (y/N)"
    if ($ap -eq 'y') { $bargs += '--apply' }
    Write-C "NOTE: the zapret2 service is paused during the test (~1-2 min)." Yellow
    & $python @bargs
}

function Show-Status {
    Write-C "`n--- Services ---" Cyan
    $st2 = Get-ServiceState $SRV2
    $st1 = Get-ServiceState $SRV1
    Write-C ("zapret2 : " + $st2 + "   (strategy: " + (Get-CurrentStrategy) + ")") ($(if($st2 -eq 'RUNNING'){'Green'}else{'Yellow'}))
    Write-C ("zapret  : " + $st1 + "  (zapret1, winws)") Gray
    Write-C ("winws2.exe process: " + ($(if(Test-Process 'winws2.exe'){'RUNNING'}else{'no'}))) Gray
    Write-C ("winws.exe  process: " + ($(if(Test-Process 'winws.exe'){'RUNNING'}else{'no'}))) Gray
    Show-TgProxyStatus
    if (-not (Get-ChildItem $BIN -Filter *.sys -ErrorAction SilentlyContinue)) {
        Write-C "WinDivert*.sys NOT found in bin\ !" Red
    }
    Write-C "`n--- Live test (HTTP codes, 000 = no response) ---" Cyan
    foreach ($u in @("https://www.youtube.com","https://discord.com","https://github.com")) {
        $c = Test-Endpoint $u
        $color = if ($c -match '^(2|3)\d\d$') {'Green'} elseif ($c -match '^(401|403|404)$') {'Green'} else {'Red'}
        Write-C ("{0,-28} {1}" -f $u, $c) $color
    }
}

function Select-StrategyBat {
    $files = Get-ChildItem -LiteralPath $ROOT -Filter *.bat |
        Where-Object { $_.Name -notlike 'service*' } | Sort-Object Name
    if (-not $files) { Write-C "No .bat strategies in $ROOT." Red; return $null }
    Write-C "`nAvailable strategies:" Cyan
    for ($i=0; $i -lt $files.Count; $i++) { Write-C ("  {0}. {1}" -f ($i+1), $files[$i].Name) }
    Write-C "  0. Cancel"
    $ch = Read-Host "Choice (0-$($files.Count))"
    $n = 0; if (-not [int]::TryParse($ch,[ref]$n) -or $n -lt 1 -or $n -gt $files.Count) { return $null }
    return $files[$n-1].FullName
}

# Build Custom.bat from profiles. $Numbers - numbers from the profiles\*.conf list (excluding 00_base)
function Build-CustomBat([string]$Numbers) {
    $base = Join-Path $PROFS "00_base.conf"
    $profs = Get-ChildItem -LiteralPath $PROFS -Filter *.conf | Sort-Object Name |
        Where-Object { $_.Name -ne "00_base.conf" }
    if (-not (Test-Path $base) -or -not $profs) { throw "profiles\ is empty or 00_base.conf is missing" }

    $sel = @()
    foreach ($t in ($Numbers -split '[,\s]+' | Where-Object { $_ -ne "" })) {
        $n = 0
        if ([int]::TryParse($t,[ref]$n) -and $n -ge 1 -and $n -le $profs.Count) { $sel += $profs[$n-1] }
    }
    if (-not $sel) { throw "No profiles selected" }

    $readConf = { param($p) Get-Content -LiteralPath $p | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } }

    $lines = @()
    $lines += '@echo off'
    $lines += 'chcp 65001 > nul'
    $lines += ':: Custom.bat - built by service.ps1 from profiles: ' + (($sel | ForEach-Object Name) -join ', ')
    $lines += 'cd /d "%~dp0"'
    $lines += 'set "BIN=%~dp0bin\"'
    $lines += 'set "LISTS=%~dp0lists\"'
    $lines += 'set "LUA=%~dp0lua\"'
    $lines += ''
    $body = @()
    $body += 'start "zapret2: custom" /min "%BIN%winws2.exe"'
    $body += (& $readConf $base)
    $first = $true
    foreach ($p in $sel) {
        if (-not $first) { $body += '--new' }
        $body += (& $readConf $p.FullName)
        $first = $false
    }
    for ($i=0; $i -lt $body.Count; $i++) {
        $suffix = if ($i -lt $body.Count - 1) { ' ^' } else { '' }
        $lines += ($body[$i] + $suffix)
    }
    $out = Join-Path $ROOT "Custom.bat"
    # BOM-less ASCII: Set-Content -Encoding OEM adds a UTF-8 BOM that cmd.exe chokes on
    [IO.File]::WriteAllLines($out, [string[]]$lines, [Text.Encoding]::ASCII)
    Write-C "Built: $out" Green
    Write-C ("Profiles: " + (($sel | ForEach-Object Name) -join ', ')) Gray
    return $out
}

function Build-CustomInteractive {
    $profs = Get-ChildItem -LiteralPath $PROFS -Filter *.conf | Sort-Object Name |
        Where-Object { $_.Name -ne "00_base.conf" }
    Write-C "`nProfiles (00_base is always added):" Cyan
    for ($i=0; $i -lt $profs.Count; $i++) {
        $hint = (Get-Content -LiteralPath $profs[$i].FullName -TotalCount 1) -replace '^\s*#\s*',''
        Write-C ("  {0,2}. {1,-36} {2}" -f ($i+1), $profs[$i].Name, $hint) Gray
    }
    $all = Read-Host "Numbers comma-separated (Enter = all)"
    if ($all -eq "") { $all = ($profs | ForEach-Object { $_.Name }) -join ',' }
    Build-CustomBat $all | Out-Null
}

# ---------- test modes (no menu) ----------
if ($ParseOnly -ne "") {
    $p = if (Test-Path $ParseOnly) { $ParseOnly } else { Join-Path $ROOT $ParseOnly }
    Write-Output (Get-Winws2Args $p)
    exit 0
}
if ($BuildOnly -ne "") {
    Build-CustomBat $BuildOnly | Out-Null
    exit 0
}
if ($InstallFrom -ne "") {
    $p = if (Test-Path $InstallFrom) { $InstallFrom } else { Join-Path $ROOT $InstallFrom }
    try { Install-ServiceFromBat $p; exit 0 } catch { Write-C "ERROR: $_" Red; exit 1 }
}
if ($RemoveService) {
    Remove-Service2
    exit 0
}
if ($StatusOnly) {
    Show-Status
    exit 0
}
if ($EnsureRunning) {
    # Watchdog mode for the startup scheduled task: SCM recovery does NOT fire
    # when winws2 dies before reporting SERVICE_RUNNING (boot RPC race, 7023).
    # Up to 4 start attempts with 15s gaps; silent, appends to logs\watchdog.log.
    $logDir = Join-Path $ROOT "logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $log = Join-Path $logDir "watchdog.log"
    # log rotation: keep the file small - trim to the last 200 lines once it passes 64 KB
    if ((Test-Path $log) -and ((Get-Item $log).Length -gt 65536)) {
        Set-Content -LiteralPath $log -Value (Get-Content $log -Tail 200) -Encoding UTF8
    }
    function WD([string]$m) { Add-Content -LiteralPath $log -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 }
    $st = Get-ServiceState $SRV2
    if ($st -eq "NOT_INSTALLED") { WD "service not installed, nothing to do"; exit 0 }
    if ($st -eq "RUNNING") { WD "already running"; exit 0 }
    for ($try=1; $try -le 4 -and $st -ne "RUNNING"; $try++) {
        WD "state=$st, start attempt $try"
        sc.exe start $SRV2 | Out-Null
        Start-Sleep -Seconds 15
        $st = Get-ServiceState $SRV2
    }
    WD ("final state: " + $st)
    if ($st -eq "RUNNING") { exit 0 } else { exit 1 }
}

# ---------- elevate ----------
if (-not (Test-Admin)) {
    Write-Host "Requesting administrator rights..."
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$($MyInvocation.MyCommand.Path)`""
    exit
}

# ---------- menu ----------
while ($true) {
    Clear-Host
    Write-Host ""
    Write-C "  ZAPRET2 SERVICE MANAGER (winws2)" Cyan
    Write-C ("  Service strategy: " + (Get-CurrentStrategy)) Gray
    Write-C  "  ----------------------------------------" DarkGray
    Write-Host "   :: SERVICE"
    Write-Host "      1. Install Service (from .bat strategy)"
    Write-Host "      2. Remove Service (zapret2)"
    Write-Host "      3. Check Status (+ live test)"
    Write-Host "      4. Restart Service"
    Write-Host ""
    Write-Host "   :: RUN WITHOUT SERVICE"
    Write-Host "      5. Run once (pick a .bat)"
    Write-Host "      6. Stop ALL bypass (zapret1+zapret2)"
    Write-Host ""
    Write-Host "   :: BUILD"
    Write-Host "      7. Build Custom.bat from profiles\"
    Write-Host ""
    Write-Host "   :: TELEGRAM"
    Write-Host "      8. TG WS Proxy (start/restart/stop)"
    Write-Host ""
    Write-Host "   :: TESTING"
    Write-Host "      9. Blockcheck domain (python matrix tester)"
    Write-Host ""
    Write-Host "   :: PYTHON TOOLS"
    Write-Host "      10. ztool (debug/config/watch/update/snapshots)"
    Write-Host ""
    Write-C  "  ----------------------------------------" DarkGray
    Write-Host "      0. Exit"
    Write-Host ""
    $ch = Read-Host "  Choice (0-10)"
    switch ($ch) {
        "1" { $b = Select-StrategyBat; if ($b) { try { Install-ServiceFromBat $b } catch { Write-C "ERROR: $_" Red } }; Pause }
        "2" { Remove-Service2; Pause }
        "3" { Show-Status; Pause }
        "4" {
            if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
                if (Stop-ConflictingEngines) {
                    sc.exe stop $SRV2 | Out-Null; Start-Sleep -Milliseconds 500
                    sc.exe start $SRV2 | Out-Null
                    Write-C ("zapret2: " + (Get-ServiceState $SRV2)) Green
                }
            } else { Write-C "Service is not installed." Yellow }
            Pause
        }
        "5" {
            $b = Select-StrategyBat
            if ($b -and (Stop-ConflictingEngines)) {
                Write-C "Starting $([IO.Path]::GetFileName($b)) ..." Green
                Start-Process cmd.exe -ArgumentList '/c',"`"$b`"" -WorkingDirectory $ROOT
            }
            Pause
        }
        "6" {
            Remove-Service2 | Out-Null
            if ((Get-ServiceState $SRV1) -eq "RUNNING") { sc.exe stop $SRV1 | Out-Null }
            [void](Reset-WinDivertDriver)
            # no force-kill of winws/winws2: it wedges the WinDivert driver
            $stray = @()
            foreach ($img in "winws","winws2") {
                if (Get-Process -Name $img -ErrorAction SilentlyContinue) { $stray += $img }
            }
            if ($stray.Count -gt 0) {
                Write-C "Still running: $($stray -join ', ') - close their console windows manually." Yellow
            }
            Write-C "All engines stopped. zapret1 service NOT removed, only stopped." Green
            Pause
        }
        "7" { try { Build-CustomInteractive } catch { Write-C "ERROR: $_" Red }; Pause }
        "8" { Menu-TgProxy; Pause }
        "9" { Invoke-Blockcheck; Pause }
        "10" { Menu-Ztool; Pause }
        "0" { exit }
    }
}
