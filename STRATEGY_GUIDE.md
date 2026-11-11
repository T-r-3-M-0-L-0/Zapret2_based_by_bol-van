# Руководство: подбор стратегий zapret2 и самостоятельная работа с Lua

Смежные документы: `PROFILES_GUIDE.md` (свои профили + единый bat под service.ps1), `LUA_GUIDE.md` (lua-памятка).

---

## 1. Эксплуатация

### Запуск
1. Остановить zapret1, если работает (служба `zapret` или окно winws.exe) — WinDivert один на оба движка.
2. Запустить `New2.bat` **от администратора**. Окно сворачивается, процесс — `winws2.exe`.
3. Стоп: **только закрытие окна winws2** (или `sc stop zapret2`, если это служба). **`taskkill`/`Stop-Process` по winws2 запрещены**: принудительный kill клиниет драйвер WinDivert — все дальнейшие запуски падают с `windivert: error opening filter: The object is referenced by other objects so cannot be deleted` (0x8032000A), лечится только перезагрузкой. Если ошибка уже поймана — reboot, затем установка службы заново. Проверено (05.11): Ctrl+C в консоли winws2 не срабатывает, корректно глушит только **CTRL_BREAK** (или закрытие окна) — в логе `quit requested` + `LUA SHUTDOWN`.

### Служба (автозапуск) — service.ps1
Запуск: `service.bat` (сам запросит админа). Меню:
1. **Install Service** — выбор любого `.bat` в каталоге → служба `zapret2` (autostart) с аргументами из этого bat. Перед установкой pre-flight: глушит драйвер WinDivert и проверяет, что он выгрузился; если драйвер «застрял» — установка отменяется с просьбой о reboot (защита от мёртвой службы).
2. **Remove Service** — удалить службу (штатный `sc stop` + `sc delete`; stray-процессы не киляются — только предупреждение).
3. **Check Status** — состояние служб/процессов + живой тест youtube/discord/github (HTTP-коды).
4. **Restart Service** — `sc stop` + `sc start`.
5. **Run once** — запуск выбранного .bat без службы (проверяет конфликтующие движки; если висят stray-процессы — просит закрыть их окна, не киляет).
6. **Stop ALL bypass** — остановить zapret2 и zapret1 + сброс драйвера WinDivert (служба zapret1 не удаляется).
7. **Build Custom.bat** — сборка стратегии из кусков `profiles\*.conf` (см. ниже).

Неинтерактивные режимы (для скриптов): `-InstallFrom <bat>`, `-RemoveService`, `-StatusOnly`, `-ParseOnly <bat>`, `-BuildOnly "1,2,3"`, `-EnsureRunning` (watchdog, см. ниже).

### Автозапуск: три уровня надёжности
1. **`start= auto`** — SCM запускает службу сразу при загрузке. В ~секунду после boot winws2 дёргает SCM/WinDivert, когда RPC endpoint mapper ещё не готов → падение 7023 «no more endpoints».
2. **SCM recovery** — `restart/5000/restart/15000/restart/60000`: если процесс успел дойти до RUNNING и упал, SCM перезапускает его через 5 сек. **Не срабатывает**, если процесс умер до SERVICE_RUNNING (SCM считает это провалом запуска, а не сбоем) — поэтому одного recovery мало.
3. **Watchdog `zapret2-ensure`** — задача планировщика (SYSTEM, AtStartup + 30 сек): `service.ps1 -EnsureRunning`. Если служба не RUNNING — до 4 попыток `sc start` с паузой 15 сек. Пишет `logs\watchdog.log` (автообрезка до последних 200 строк при каждом запуске). Гарантированный подъём через ~30–45 сек после boot.

Проверка после загрузки: `service.ps1 -StatusOnly` → `RUNNING` + HTTP-коды; лог `logs\watchdog.log` показывает, кто поднял службу («already running» = штатный механизм, «start attempt» = страховка). Подробности — MIGRATION_ZAPRET2.md, п. 11, 13, 14.

**Модульные профили** (`profiles\`): каждый `.conf` = один профиль без `--new` (фильтры + payload + lua-desync), `00_base.conf` — глобальный блок (wf-фильтры, lua-init, blobs) — подключается всегда первым. Сборка склеивает `base + выбранные профили` с `--new` между ними. Проверено: набор всех 13 профилей даёт `Custom.bat`, идентичный `New2.bat` по токенам. Чтобы выработать свой вариант: копируете профиль, правите домены/технику, собираете, ставите в службу — всё из меню.

Ручная установка службы (без service.ps1) — только так:
```bat
sc create zapret2 binPath= "\"C:\...\bin\winws2.exe\" --wf-... --lua-init=\"x=tls_mod(y,'rnd,rndsni')\" ..." start= auto
```
Двойные кавычки внутри binPath экранировать `\"` (иначе sc их съест и winws2 сломает lua-init), пробелов вокруг `=` в lua не оставлять (ошибка 1639). Подробности — MIGRATION_ZAPRET2.md, раздел 3, п. 6–9.

### Отладка
Добавьте `--debug` в начало параметров (перед `--wf-...`) и уберите `start ... /min` — весь вывод пойдёт в консоль. Там видно: загрузку блобов, список профилей, какой профиль захватил соединение, вызовы Lua и вердикты (PASS/MODIFY/DROP). **Без --debug ошибки Lua невидимы** — это первое правило zapret2.

---

## 2. Методика подбора стратегии под новый случай

### Принцип
Стратегия = профиль (что перехватываем) + цепочка desync-функций (как «ломаем» пакет для DPI). Подбирается **один домен за раз**, от простого к сложному. DPI у разных провайдеров разный: то, что пробивает Ростелеком, может не работать у мелкого регионального — и наоборот.

### Шаг 0. Проверка, что блок именно DPI, а не IP
```bat
ping <домен>
curl -v https://<домен> --resolve <домен>:443:<другой_IP_того_же_CDN>
```
Если по альтернативному IP работает — проблема в подмене DNS/IP, добавьте домен в `lists\list-general-user.txt`, движок почти не при чём.

### Шаг 1. Минимальный тестовый стенд
Сделайте копию `New2.bat` → `test.bat`, удалите все профили, оставьте один:
```bat
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist-domains=<целевой.домен> ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_google:repeats=6
```
Проверка результата: `curl -w "%%{http_code} %%{time_total}s\n" -o NUL https://<домен>` до и после запуска.

### Шаг 2. Матрица перебора техник (по возрастанию агрессивности)

| # | Техника | lua-desync | Когда пробовать |
|---|---------|-----------|-----------------|
| 1 | Только фейк | `fake:blob=tls_google:repeats=6` | База. DPI проглатывает фейк и рассинхронизируется |
| 2 | Фейк + TTL | добавить `ip_ttl=1..5` или `ip_autottl=2,1-20` | DPI дальше/ближе по маршруту; фейк не должен дойти до сервера |
| 3 | Фейк с фулингом | добавить `tcp_ts=-600000` / `tcp_md5` / `tcp_seq=-10000:tcp_ack=-66000` | DPI не проверяет контрольные поля, сервер — проверяет |
| 4 | Резка | `multisplit:pos=1,midsld` | DPI не умеет реассемблинг |
| 5 | Резка вразнобой | `multidisorder:pos=1,midsld` | DPI слабее реассемблинга с disorder |
| 6 | Фейк + резка | `fake:...` затем `fakedsplit:pattern=0x00` | Комбинация 1+4 (рабочая связка в New2.bat) |
| 7 | hostfakesplit | `hostfakesplit:host=ozon.ru:repeats=4` | DPI парсит SNI/Host, срабатывает на «разрешённом» хосте |
| 8 | Kyber-фейк | `--blob=tls_kyber:@"bin\tls_clienthello_vk_com_kyber.bin"` + `fake:blob=tls_kyber` | Против DPI, анализирующих структуру ClientHello |

Правила перебора:
- **Меняйте один параметр за раз.** Сначала техника, потом repeats (1→6→12), потом fooling, потом позиции резки.
- Позиции резки: `1` (первый байт), `midsld` (середина домена в SNI), `host`, `sld`, `endhost-1`, смещения `+N`/`-N`.
- Если работает несколько вариантов — берите наименее агрессивный (меньше repeats, без fooling): меньше нагрузка и меньше побочек.

### Шаг 3. Оформление в общий .bat
- Профиль ставится **до** catch-all профилей: в мультистратегии соединение захватывает первый совпавший профиль (урок мёртвого дубликата в ESK_Hybrid_Ult).
- Узкие фильтры (hostlist-domains) — в начало, широкие (ipset, диапазоны портов) — в конец.
- Всегда `--payload=` и `--out-range=-d10` для TCP: экономия CPU в разы.
- UDP-игры: не забывайте диапазон 49152-65535 (эфемерные порты Windows).

### Шаг 4. Регрессионная проверка
- `curl` по 5-6 доменам из каждого списка.
- YouTube (QUIC + TCP), Discord (login + voice), GitHub.
- Игры: p2p-сессия + лаунчер.
- Скорость закачки: перехват не должен резать throughput (иначе сузьте `--wf-*` или ужесточите `--payload`).

---

## 3. Lua в zapret2: минимум для самостоятельной работы

### Модель
C-движок перехватывает пакет → строит **диссект** (дерево разобранных полей, как в Wireshark) → вызывает по очереди ваши `--lua-desync` функции профиля → каждая возвращает вердикт:
- `VERDICT_PASS` — отпустить как есть;
- `VERDICT_MODIFY` — отпустить изменённым;
- `VERDICT_DROP` — не отправлять (после того, как функция сама отослала свои варианты).

Любой DROP в цепочке = итоговый DROP. Функции видят изменения друг друга: `pktmod` (фулинг текущего пакета) + `multisplit` = резка уже «испорченного» пакета.

### Где смотреть справку
`lua\zapret-antidpi.lua` — первые ~75 строк: полное описание стандартных блоков аргументов (fooling, reconstruct, rawsend, payload, ip_id, ipfrag). Перед каждой функцией — её параметры и аналог из nfqws1. Это ваша шпаргалка, она всегда под рукой и соответствует установленной версии.

### Стандартные аргументы (памятка)
```
fooling:      ip_ttl=N  ip6_ttl=N  ip_autottl=delta,min-max
              tcp_seq=N  tcp_ack=N  tcp_ts=N  tcp_md5[=hex]
              tcp_flags_set=...  tcp_flags_unset=...  tcp_ts_up
reconstruct:  badsum
rawsend:      repeats=N
ip_id:        ip_id=seq|rnd|zero|none
payload:      payload=tls_client_hello,http_req,quic_initial,...
direction:    dir=in|out|any
```

### Своё за 5 минут: luaexec
Не нужно писать функцию — можно выполнить кусок Lua в цепочке:
```bat
--lua-desync=luaexec:code="desync.rnd=brandom_az(math.random(5,10))" ^
--lua-desync=tcpseg:pos=0,-1:seqovl=#rnd:seqovl_pattern=rnd ^
--lua-desync=drop:payload=known
```
`%имя` — подстановка блоба, `#имя` — его размера. `desync` — таблица, живая в пределах обработки одного пакета (передаётся между инстансами).

### Своя функция
Добавьте в `zapret-antidpi.lua` (или свой файл через `--lua-init=@my.lua`):
```lua
function my_fake2(ctx, desync)
    -- desync.dis - диссект, desync.arg - таблица аргументов из --lua-desync
    DLOG("my_fake2: payload=" .. tostring(desync.dis.payload and #desync.dis.payload))
    rawsend_dissect_segmented(desync, desync.dis, nil)  -- отправка с авто-сегментацией по MSS
    return VERDICT_DROP
end
```
Вызов: `--lua-desync=my_fake2:foo=bar`. Смотрите готовые `fake`, `fakedsplit` как образцы — они короткие.

### Что даёт zapret2 против zapret1 (практически)
- `tls_client_hello_clone` — фейк из реального ClientHello клиента;
- входящее направление: `--in-range=a`, функции `synack_split`, `wsize` — атака на DPI со стороны ответов;
- автосегментация по MSS: kyber-фейки и большие `seqovl` просто работают;
- `zapret-obfs.lua` — обфускация (udp2icmp и т.п.) против сигнатурных блокировок VPN.

### Типовые ошибки
| Симптом | Причина |
|---|---|
| Тихо не работает | Нет `--debug`; ошибка Lua невидима |
| **Вообще ничего не десинхронизируется, в логе всегда «profile 1 matches, no lua functions»** | **Первый `--new` сразу после глобальных опций (`--blob`, `--lua-init`) создаёт пустой профиль-1 без фильтров — он catch-all и перехватывает ВСЁ. Первый профиль описывается БЕЗ `--new` (реальный кейс 2026-11-01)** |
| `Incompatible NFQWS2_COMPAT_VER` | winws2 и lua\ из разных релизов — обновлять вместе |
| Стратегия «не ловит» домен | Профиль ниже catch-all; переставьте выше |
| Жрёт CPU | Нет `--payload`/`--out-range`, либо в `--wf-udp` попали торренты — сужайте windivert-фильтр |
| UDP-игра отваливается | Порт попал под два профиля или выпал из диапазона (49152-65535!) |
| Сайт не открывается ни с какой стратегией, curl висит на «Trying IP:443» | IP-блокировка (SYN в чёрную дыру) — DPI-обход бессилен, нужен прокси/VPN. Проверка: `curl -v` — если нет строки «Connected to», это IP-блок |
| TCP соединяется, TLS висит, и **ни одна** из 10+ техник (fake/multisplit/multidisorder/hostfakesplit/badsum/ttl/ipfrag/шреддинг) не помогает | DPI с полным TCP-реассемблингом (новые ТСПУ). Подтверждено на Discord у этого провайдера 2026-11-01: перехват и desync работают (видно в --debug), но ServerHello не приходит. Лечение: прокси/VPN, либо браузер с ECH |

### Диагностика «IP-блок / SNI-блок / реассемблинг» за 2 минуты
```powershell
# 1. TCP жив? (True = SYN проходит)
Test-NetConnection <IP> -Port 443
# 2. TLS жив? Если TCP OK, а TLS висит - блок по SNI на этапе ClientHello
$tcp=New-Object Net.Sockets.TcpClient; $tcp.Connect('<IP>',443)
$ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,{$true})
$ssl.AuthenticateAsClientAsync('<домен>').Wait(6000)
# 3. Тот же IP, НЕзаблокированный SNI (напр. www.google.com):
#    handshake проходит (пусть с ошибкой серта) = блок именно по SNI;
#    тоже таймаут = блок по IP/потоку.
```

---

## 5. Discord: эволюция блокировки и рабочая техника (обновлено 2026-11-04)

Режим DPI на маршруте меняется «окнами» (замеры на этой машине):
- **01.11** — агрессивное окно: TCP SYN проходит, ServerHello рвётся; 14 классических техник (fake/сплиты/дизордер/фулинги/ipfrag/шреддинг) не пробивали — ТСПУ с полным реассемблингом.
- **02.11** — пробивает только **seqovl-перекрытие** (стратегия Hybrid, zapret1): DPI собирает поток с фейкового ClientHello (SNI=ozon.ru), сервер отбрасывает перекрытие.
- **04.11** — мягкое окно: работают все стратегии, включая базовые fake/fakedsplit.

Дополнительно: **UDP 443/853 глушится провайдером целиком** (проверено aioquic: youtube/vk/cloudflare/DoQ — все таймаут). Discord-приложение лезет в HTTP/3 по Alt-Svc → флаки аватаров и «Checking update». Лечение: запуск `Discord.exe --disable-quic` (ярлык «Discord (no QUIC)» создан на рабочем столе).

**Вывод по техникам:** держите в стратегии оба уровня — базовый (fake/fakedsplit/hostfakesplit) для мягких окон и тяжёлый (seqovl 681/652 + sni=ozon.ru + badseq) для агрессивных. В New2.bat v2 Discord-профили — тяжёлые, они не мешают в мягких окнах.

## 6. Эталон: разбор New2.bat v2 по профилям (04.11)

| # | Фильтр | Действие | Назначение |
|---|--------|----------|-----------|
| 1 | udp/443 + quic + hostlists | fake QUIC-google x6 | YouTube/прочее по QUIC (здесь UDP мёртв, профиль — для других провайдеров) |
| 2 | udp/19294-19344,50000-50100 + discord,stun | fake quic_vk x6 | Discord voice |
| 3 | tcp/443 + updates.discord.com | fake tls_ozon (badseq) x8 + multisplit pos=1 **seqovl=681** | Апдейтер Discord |
| 4 | tcp/443 + media/images-ext-1/images-ext-2 | fake tls_max_ozon (ts) x8 + fakedsplit 0x00 | Картинки/внешние медиа |
| 5 | tcp/443 + cdn.discordapp.com, stable.dl2 | fake tls_ozon (badseq) x8 + multidisorder pos=1,midsld **seqovl=652** | CDN Discord |
| 6 | tcp/443,CF-порты + основные домены discord | fake tls_def_ozon (badseq) x8 + multidisorder pos=1,**sniext+1**,midsld | API/gateway |
| 7 | tcp/443 + list-google | fake+fakedsplit ts x6 | YouTube по TCP |
| 8 | tcp/443 + list-github | fake+fakedsplit ts x6 | GitHub |
| 9 | tcp/80,443 + list-general | hostfakesplit host=ozon.ru, ts+md5, x4 | Общий список |
| 10-11 | ipset-all (заглушка) | fake / hostfakesplit | Резерв под ipset-режим |
| 12 | udp/7711,12000 | fake x1, autottl | Отдельные игры |
| 13 | udp/1024-65535 (минус discord-слоты) | fake x8, autottl, cutoff n2 | Игровой UDP, включая эфемерные порты |
