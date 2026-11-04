#requires -Version 5.1
<#
.SYNOPSIS
  ZAPRET2 SERVICE MANAGER - аналог service.bat (zapret1) для winws2/zapret2.
.DESCRIPTION
  Меню: установка/удаление службы zapret2 из любого .bat-стратегии,
  запуск без службы, статус с живым тестом, сборка Custom.bat из профилей profiles\*.conf.
  Служба zapret1 ("zapret") не удаляется, только останавливается на время запуска winws2.
.PARAMETER ParseOnly
  Скрытый тестовый режим: напечатать аргументы winws2, извлечённые из указанного .bat, и выйти.
.PARAMETER BuildOnly
  Скрытый тестовый режим: собрать Custom.bat из профилей по номерам (например "1,2,3") и выйти.
#>
param(
    [string]$ParseOnly = "",
    [string]$BuildOnly = "",
    [string]$InstallFrom = "",
    [switch]$RemoveService,
    [switch]$StatusOnly
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

$ROOT   = Split-Path -Parent $MyInvocation.MyCommand.Path
$BIN    = Join-Path $ROOT "bin\"
$LISTS  = Join-Path $ROOT "lists\"
$LUA    = Join-Path $ROOT "lua\"
$PROFS  = Join-Path $ROOT "profiles"
$SRV2   = "zapret2"          # наша служба
$SRV1   = "zapret"           # служба zapret1 (не трогаем, только stop/start)
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
    # winws и winws2 делят WinDivert: одновременно работать не должны
    if ((Get-ServiceState $SRV1) -eq "RUNNING") {
        Write-C "Останавливаю службу '$SRV1' (zapret1)..." Yellow
        sc.exe stop $SRV1 | Out-Null
    }
    foreach ($img in "winws","winws2") {
        $p = Get-Process -Name $img -ErrorAction SilentlyContinue
        if ($p) {
            Write-C "Завершаю $img.exe ..." Yellow
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-CurrentStrategy {
    try {
        $v = (Get-ItemProperty -Path $REGKEY -Name "strategy" -ErrorAction Stop).strategy
        return $v
    } catch { return "(не установлена)" }
}

# Извлечь аргументы winws2 из .bat стратегии
function Get-Winws2Args([string]$BatPath) {
    $raw = Get-Content -Raw -LiteralPath $BatPath
    # ищем строку запуска: winws2.exe, сразу за которым идёт закрывающая кавычка + "^" или опции
    $m = [regex]::Match($raw, 'winws2\.exe"?\s*(?:\^|--)\s*\r?\n?\s*--')
    if (-not $m.Success) { $m = [regex]::Match($raw, 'winws2\.exe"?\s*\^') }
    if (-not $m.Success) { throw "В $BatPath не найден вызов winws2.exe с аргументами" }
    $idx = $m.Index
    $sub = $raw.Substring($idx + "winws2.exe".Length)
    # склеить строки продолжения " ^\n"
    $sub = $sub -replace "\^\s*\r?\n", " "
    # взять первую (теперь единственную длинную) строку аргументов
    $sub = ($sub -split "`n")[0]
    # убрать остаток закрывающей кавычки пути к exe в начале
    $sub = $sub.TrimStart(' ','"')
    # раскрыть переменные каталогов
    $sub = $sub.Replace('%BIN%',$BIN).Replace('%LISTS%',$LISTS).Replace('%LUA%',$LUA).Replace('%~dp0',"$ROOT\")
    $sub = $sub.Trim()
    if ($sub -notmatch '^--') { throw "Не удалось распарсить аргументы (не начинаются с '--'): $($sub.Substring(0,[Math]::Min(80,$sub.Length)))" }
    return $sub
}

function Install-ServiceFromBat([string]$BatPath) {
    $argLine = Get-Winws2Args $BatPath
    # sc.exe токенизирует binPath по пробелам, игнорируя кавычки:
    # "x = f(...)" внутри --lua-init даёт голый токен "=" и ошибку 1639.
    # Убираем пробелы вокруг '=' - для lua это эквивалентно.
    $argLine = $argLine -replace ' = ', '='
    Write-C "`nАргументы службы:" DarkGray
    Write-C $argLine DarkGray

    Stop-ConflictingEngines
    if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
        sc.exe stop $SRV2 | Out-Null
        sc.exe delete $SRV2 | Out-Null
        # ждём физического удаления: иначе create попадает в "pending deletion"
        # и в реестре остаётся пустой ключ без ImagePath
        for ($i=0; $i -lt 20 -and (Get-ServiceState $SRV2) -ne "NOT_INSTALLED"; $i++) {
            Start-Sleep -Milliseconds 250
        }
        Remove-Item -LiteralPath $REGKEY -Recurse -Force -ErrorAction SilentlyContinue
    }
    $exe = Join-Path $BIN "winws2.exe"
    # sc.exe из PowerShell ломает длинный binPath с кавычками (код 1639),
    # WMI Create пишет пустой ImagePath - поэтому генерируем .cmd как в zapret1 service.bat.
    # Все двойные кавычки внутри значения экранируем как \" :
    # иначе sc их съедает, а winws2 тогда режет --lua-init по запятым внутри 'rnd,rndsni'
    $argEsc = $argLine.Replace('"', '\"')
    $tmpCmd = Join-Path $env:TEMP "zapret2_create.cmd"
    $cmdBody = "@echo off`r`nsc.exe create $SRV2 binPath= `"\`"$exe\`" $argEsc`" DisplayName= `"zapret2`" start= auto`r`n"
    Set-Content -LiteralPath $tmpCmd -Value $cmdBody -Encoding ASCII
    cmd.exe /c "`"$tmpCmd`"" | Out-Null
    $rc = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpCmd -Force -ErrorAction SilentlyContinue
    if ($rc -ne 0) { throw "sc create завершился с кодом $rc" }
    $imgPath = (Get-ItemProperty "$REGKEY" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if (-not $imgPath) { throw "Служба создана, но ImagePath пуст - создание не удалось" }
    sc.exe description $SRV2 "zapret2 DPI bypass (winws2)" | Out-Null
    $name = [IO.Path]::GetFileNameWithoutExtension($BatPath)
    # ключ уже создан sc.exe; New-Item -Force здесь запретно: пересоздаёт ключ и затирает ImagePath
    Set-ItemProperty -Path $REGKEY -Name "strategy" -Value $name
    sc.exe start $SRV2 | Out-Null
    Start-Sleep -Seconds 1
    $st = Get-ServiceState $SRV2
    if ($st -eq "RUNNING") {
        Write-C "Служба '$SRV2' запущена, стратегия: $name" Green
    } else {
        Write-C "Служба создана, но состояние: $st. Смотрите логи/права." Red
    }
}

function Remove-Service2 {
    if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
        sc.exe stop $SRV2 | Out-Null
        sc.exe delete $SRV2 | Out-Null
        Write-C "Служба '$SRV2' удалена." Green
    } else {
        Write-C "Служба '$SRV2' не установлена." Yellow
    }
    Get-Process -Name winws2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Test-Endpoint([string]$Url) {
    $code = & curl.exe -s -o NUL -w "%{http_code}" --max-time 8 $Url 2>$null
    return $code
}

function Show-Status {
    Write-C "`n--- Службы ---" Cyan
    $st2 = Get-ServiceState $SRV2
    $st1 = Get-ServiceState $SRV1
    Write-C ("zapret2 : " + $st2 + "   (стратегия: " + (Get-CurrentStrategy) + ")") ($(if($st2 -eq 'RUNNING'){'Green'}else{'Yellow'}))
    Write-C ("zapret  : " + $st1 + "  (zapret1, winws)") Gray
    Write-C ("winws2.exe процесс: " + ($(if(Test-Process 'winws2.exe'){'RUNNING'}else{'нет'}))) Gray
    Write-C ("winws.exe  процесс: " + ($(if(Test-Process 'winws.exe'){'RUNNING'}else{'нет'}))) Gray
    if (-not (Get-ChildItem $BIN -Filter *.sys -ErrorAction SilentlyContinue)) {
        Write-C "WinDivert*.sys в bin\ НЕ найден!" Red
    }
    Write-C "`n--- Живой тест (HTTP-коды, 000 = нет ответа) ---" Cyan
    foreach ($u in @("https://www.youtube.com","https://discord.com","https://github.com")) {
        $c = Test-Endpoint $u
        $color = if ($c -match '^(2|3)\d\d$') {'Green'} elseif ($c -match '^(401|403|404)$') {'Green'} else {'Red'}
        Write-C ("{0,-28} {1}" -f $u, $c) $color
    }
}

function Select-StrategyBat {
    $files = Get-ChildItem -LiteralPath $ROOT -Filter *.bat |
        Where-Object { $_.Name -notlike 'service*' } | Sort-Object Name
    if (-not $files) { Write-C "В $ROOT нет .bat-стратегий." Red; return $null }
    Write-C "`nДоступные стратегии:" Cyan
    for ($i=0; $i -lt $files.Count; $i++) { Write-C ("  {0}. {1}" -f ($i+1), $files[$i].Name) }
    Write-C "  0. Отмена"
    $ch = Read-Host "Выбор (0-$($files.Count))"
    $n = 0; if (-not [int]::TryParse($ch,[ref]$n) -or $n -lt 1 -or $n -gt $files.Count) { return $null }
    return $files[$n-1].FullName
}

# Сборка Custom.bat из профилей. $Numbers - номера по списку profiles\*.conf (без 00_base)
function Build-CustomBat([string]$Numbers) {
    $base = Join-Path $PROFS "00_base.conf"
    $profs = Get-ChildItem -LiteralPath $PROFS -Filter *.conf | Sort-Object Name |
        Where-Object { $_.Name -ne "00_base.conf" }
    if (-not (Test-Path $base) -or -not $profs) { throw "Каталог profiles\ пуст или нет 00_base.conf" }

    $sel = @()
    foreach ($t in ($Numbers -split '[,\s]+' | Where-Object { $_ -ne "" })) {
        $n = 0
        if ([int]::TryParse($t,[ref]$n) -and $n -ge 1 -and $n -le $profs.Count) { $sel += $profs[$n-1] }
    }
    if (-not $sel) { throw "Не выбрано ни одного профиля" }

    $readConf = { param($p) Get-Content -LiteralPath $p | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } }

    $lines = @()
    $lines += '@echo off'
    $lines += 'chcp 65001 > nul'
    $lines += ':: Custom.bat - собран service2.ps1 из профилей: ' + (($sel | ForEach-Object Name) -join ', ')
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
    Set-Content -LiteralPath $out -Value $lines -Encoding OEM
    Write-C "Собран: $out" Green
    Write-C ("Профили: " + (($sel | ForEach-Object Name) -join ', ')) Gray
    return $out
}

function Build-CustomInteractive {
    $profs = Get-ChildItem -LiteralPath $PROFS -Filter *.conf | Sort-Object Name |
        Where-Object { $_.Name -ne "00_base.conf" }
    Write-C "`nПрофили (00_base добавляется всегда):" Cyan
    for ($i=0; $i -lt $profs.Count; $i++) {
        $hint = (Get-Content -LiteralPath $profs[$i].FullName -TotalCount 1) -replace '^\s*#\s*',''
        Write-C ("  {0,2}. {1,-32} {2}" -f ($i+1), $profs[$i].Name, $hint) Gray
    }
    $all = Read-Host "Номера через запятую (Enter = все)"
    if ($all -eq "") { $all = ($profs | ForEach-Object { $_.Name }) -join ',' }
    Build-CustomBat $all | Out-Null
}

# ---------- тестовые режимы (без меню) ----------
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
    try { Install-ServiceFromBat $p; exit 0 } catch { Write-C "ОШИБКА: $_" Red; exit 1 }
}
if ($RemoveService) {
    Remove-Service2
    exit 0
}
if ($StatusOnly) {
    Show-Status
    exit 0
}

# ---------- elevate ----------
if (-not (Test-Admin)) {
    Write-Host "Запрашиваю права администратора..."
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$($MyInvocation.MyCommand.Path)`""
    exit
}

# ---------- menu ----------
while ($true) {
    Clear-Host
    Write-Host ""
    Write-C "  ZAPRET2 SERVICE MANAGER (winws2)" Cyan
    Write-C ("  Стратегия службы: " + (Get-CurrentStrategy)) Gray
    Write-C  "  ----------------------------------------" DarkGray
    Write-Host "   :: СЛУЖБА"
    Write-Host "      1. Install Service (из .bat-стратегии)"
    Write-Host "      2. Remove Service (zapret2)"
    Write-Host "      3. Check Status (+ живой тест)"
    Write-Host "      4. Restart Service"
    Write-Host ""
    Write-Host "   :: ЗАПУСК БЕЗ СЛУЖБЫ"
    Write-Host "      5. Run once (выбрать .bat)"
    Write-Host "      6. Stop ALL bypass (zapret1+zapret2)"
    Write-Host ""
    Write-Host "   :: СБОРКА"
    Write-Host "      7. Build Custom.bat из profiles\"
    Write-Host ""
    Write-C  "  ----------------------------------------" DarkGray
    Write-Host "      0. Exit"
    Write-Host ""
    $ch = Read-Host "  Выбор (0-7)"
    switch ($ch) {
        "1" { $b = Select-StrategyBat; if ($b) { try { Install-ServiceFromBat $b } catch { Write-C "ОШИБКА: $_" Red } }; Pause }
        "2" { Remove-Service2; Pause }
        "3" { Show-Status; Pause }
        "4" {
            if ((Get-ServiceState $SRV2) -ne "NOT_INSTALLED") {
                Stop-ConflictingEngines
                sc.exe stop $SRV2 | Out-Null; Start-Sleep -Milliseconds 500
                sc.exe start $SRV2 | Out-Null
                Write-C ("zapret2: " + (Get-ServiceState $SRV2)) Green
            } else { Write-C "Служба не установлена." Yellow }
            Pause
        }
        "5" {
            $b = Select-StrategyBat
            if ($b) {
                Stop-ConflictingEngines
                Write-C "Запускаю $([IO.Path]::GetFileName($b)) ..." Green
                Start-Process cmd.exe -ArgumentList '/c',"`"$b`"" -WorkingDirectory $ROOT
            }
            Pause
        }
        "6" {
            Remove-Service2 | Out-Null
            if ((Get-ServiceState $SRV1) -eq "RUNNING") { sc.exe stop $SRV1 | Out-Null }
            foreach ($img in "winws","winws2") { Get-Process -Name $img -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
            Write-C "Все движки остановлены. Служба zapret1 НЕ удалена, только остановлена." Green
            Pause
        }
        "7" { try { Build-CustomInteractive } catch { Write-C "ОШИБКА: $_" Red }; Pause }
        "0" { exit }
    }
}
