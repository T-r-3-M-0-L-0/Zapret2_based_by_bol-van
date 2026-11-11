# Руководство: свои профили (`profiles\*.conf`) и единый .bat под service.ps1

Целевая аудитория: ИТ-инженер, Windows 10/11. Дистрибутив: `fZapret2` (winws2 v1.0.6, lua compat 6).
Связанные документы: `STRATEGY_GUIDE.md` (методика подбора техник), `LUA_GUIDE.md` (lua-минимум), `..\fZapret\MIGRATION_ZAPRET2.md` (маппинг опций zapret1→zapret2, грабли).

---

## 1. Модель: как winws2 применяет профили

- Конфигурация = **глобальный блок** + **N профилей**.
- Глобальный блок: `--wf-*` (что вообще попадает в перехват WinDivert), `--lua-init`, `--blob`. Профилей не касается напрямую, но blobs и lua-переменные, объявленные здесь, доступны всем профилям.
- Профиль = **фильтры** (`--filter-*`, hostlist/ipset) + **условие срабатывания** (`--payload`, `--out-range`) + **цепочка действий** (`--lua-desync=...`).
- Пакет обрабатывается **первым подошедшим профилем**: проверка идёт от первого к последнему до первого совпадения фильтров (подтверждено readme zapret; в zapret2 логика профилей сохранена). Поэтому: **частные профили выше, общие ниже**. В текущей стратегии: updates.discord.com → media/cdn → основные домены Discord → list-google/github → list-general → ipset → UDP catch-all.
- Тонкость: пока L7/имя хоста неизвестны, соединение может идти по одному профилю, а после выяснения хоста — переключиться на другой на лету. Если в профилях есть действия «нулевой фазы» (до ClientHello), продумывайте, что случится при таком переключении; при сомнениях — `--debug`.
- Первый профиль в командной строке описывается **без `--new`**, каждый следующий начинается с `--new`. `--new` сразу после глобального блока = пустой catch-all профиль, который глушит всё (классическая ошибка, см. MIGRATION_ZAPRET2.md, раздел 3, п.1).

---

## 2. Формат файла профиля `profiles\NN_name.conf`

Правила:

1. Один файл = один профиль. `--new` **не писать** — сборщик вставит сам.
2. Строки, начинающиеся с `#` — комментарий (первая строка = подсказка, она показывается в меню сборки).
3. Одна логическая группа опций = одна строка. Без `^` в конце (это не bat).
4. Пути — через токены: `%LISTS%`, `%BIN%`, `%LUA%` — сборщик и service.ps1 раскроют их сам (в bat — как есть, в службу — в абсолютные пути).
5. Имя файла = порядок применения: сортировка по имени, поэтому префикс `NN_`. `00_base.conf` — зарезервирован под глобальный блок и идёт всегда первым.
6. Blobs, которые использует профиль (`blob=tls_ozon` и т.п.), должны быть объявлены в `00_base.conf` через `--blob=name:@"..."`. Если нужен новый blob — добавляйте объявление в `00_base.conf` и `.bin` в `bin\`.

Скелет профиля:

```
# <однострочное описание: что и зачем>
--filter-tcp=443 --filter-l7=tls --hostlist-domains=example.com,www.example.com
--payload=tls_client_hello --out-range=-d10
--lua-desync=<действие1>
--lua-desync=<действие2>
```

### Что писать в фильтрах

| Задача | Фильтр |
|---|---|
| Один-два домена | `--hostlist-domains=a.com,b.com` (быстро, без файлов) |
| Список доменов | `--hostlist="%LISTS%my-list.txt"` (домен на строку) |
| IP-диапазоны | `--ipset="%LISTS%my-ipset.txt"` (CIDR на строку) |
| Протокол | `--filter-tcp=443` / `--filter-udp=443,1024-65535` / `--filter-l7=tls,http,quic,discord,stun` |
| Исключения | `--hostlist-exclude=...`, `--ipset-exclude=...` |

`--payload=tls_client_hello` — срабатывать только на ClientHello (стандарт для TCP-обхода). `--out-range=-d10` — не более 10 срабатываний на соединение (защита от зацикливания на ретрансляциях). Для UDP: `--payload=all` или `quic_initial`, для игр — `--out-range=-n2` (только первые 2 пакета).

### Выбор техники (`--lua-desync`)

По возрастанию агрессивности (подробная матрица — STRATEGY_GUIDE.md, раздел 2):

1. `multidisorder:pos=1,sniext+1,midsld` — разбиение без мусора.
2. `fake:blob=tls_google:tcp_ts=-600000:repeats=6` + `fakedsplit:pattern=0x00:tcp_ts=-600000` — фейк с плохим timestamp.
3. `fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8` + `multisplit:pos=1:seqovl=681:seqovl_pattern=tls_ozon` — фейк с badseq + перекрытие seq (тяжёлый случай, приём Hybrid).
4. `hostfakesplit:host=ozon.ru:tcp_ts=-600000:tcp_md5:repeats=4` — фейк с подменой SNI прямо в разбиении.

Несколько `--lua-desync` в одном профиле выполняются по порядку (фейк отправляется до реального разбиения).

---

## 3. Рецепт «новый профиль под задачу» за 5 шагов

Пример: перестал открываться `somecdn.net` (TLS, SNI-блок).

1. **Диагностика** (STRATEGY_GUIDE.md, раздел «Диагностика за 2 минуты»): TCP жив? TLS жив? Блок по SNI или по IP? От этого зависит, нужен ли ipset-профиль (IP) или хватит SNI-обхода.
2. **Прогон техник вручную** — минимальный стенд: один `--filter-tcp=443 --hostlist-domains=somecdn.net` + одна техника, curl на домен. Нашли рабочую — идём дальше.
3. **Оформление**: `copy profiles\50_discord_cdn.conf profiles\55_somecdn.conf`, правим домены и технику, правим первую строку-комментарий.
4. **Сборка и тест**: `service.bat` → 7 (Build) → номера профилей (Enter = все) → получаем `Custom.bat` → 5 (Run once) → curl/браузер. Порядок: новый профиль должен стоять **выше** пересекающихся общих (list-general, ipset) — проверьте префикс номера.
5. **В службу**: service.bat → 1 (Install) → выбрать `Custom.bat`. Готово, автозапуск.

Откат: service.bat → 1 → выбрать `Hybrid.bat` (эталон всегда под рукой).

---

## 4. Единый .bat под service.ps1: требования к формату

service.ps1 извлекает аргументы из bat автоматически. Чтобы парсинг и установка в службу прошли, bat должен соответствовать шаблону (Hybrid.bat — эталон):

```bat
@echo off
chcp 65001 > nul
cd /d "%~dp0"
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
set "LUA=%~dp0lua\"

start "zapret2: %~n0" /min "%BIN%winws2.exe" ^
--wf-tcp-out=80,443 --wf-udp-out=443,1024-65535 ^
--lua-init=@"%LUA%zapret-lib.lua" ^
  <глобальные опции> ^
  <профиль 1, БЕЗ --new> ^
--new ^
  <профиль 2> ^
--new ^
  <профиль N>
```

Обязательные условия:

1. Строка запуска содержит `winws2.exe`, за которым идут опции (парсер ищет именно её, комментарии в шапке не мешают).
2. Переменные только `%BIN%`, `%LISTS%`, `%LUA%` — другие не раскроются.
3. Продолжение строк — `^` в конце, как обычно в cmd.
4. Первый профиль без `--new` (см. раздел 1).
5. В lua-коде внутри `--lua-init="..."` **не ставьте пробелы вокруг `=`**: пишите `tls_ozon=tls_mod(...)`, а не `tls_ozon = tls_mod(...)`. Из bat с пробелами работает, но при установке в службу service.ps1 всё равно вычистит их (sc.exe иначе ломается с кодом 1639) — лучше сразу писать чисто.
6. Кириллицы в путях и пробелов в путях к fZapret2 быть не должно.

Сборка через меню (пункт 7) генерирует `Custom.bat`, уже соответствующий всем пунктам — руками bat писать необязательно.

---

## 5. ALT-профили (порты готовых стратегий Flowseal zapret1)

Порты общего TCP-профиля из стратегий zapret1 (репозиторий `Flowseal/zapret-discord-youtube`, плюс локальные варианты из `C:\fZapret`). Это **взаимозаменяемые альтернативы** базовому `80_general_tcp.conf` (и `72` — альтернатива `70_google.conf`): включайте в сборку **только один** из группы, иначе сработает первый по порядку, остальные — мёртвый груз. Префикс `fs_` = порт напрямую из репозитория Flowseal.

| Профиль | Источник | Техника |
|---|---|---|
| `72_alt11_google_seqovl.conf` | general (ALT11), google-профиль | fake tls_google ts x8 + multisplit seqovl=681 |
| `73_fs_alt3_hfs_ya.conf` | general (ALT3) | fake tls_mod=rnd,dupsid,sni=ya.ru + hostfakesplit host=ya.ru, ts |
| `74_fs_alt13_hfs_mail.conf` | general (ALT13) | fake sochi+stun2 ts x5 + hostfakesplit host=mail.ru |
| `75_fs_fta_alt2_seqovl681.conf` | FAKE TLS AUTO ALT2 | fake tls_mod(rnd,dupsid,sni=google) + multisplit seqovl=681, badseq inc=10000000 x8 |
| `76_fs_simplefake_alt_badseq.conf` | SIMPLE FAKE ALT | fake badseq inc=2 x6 (tls=stun2+google) |
| `83_alt10_general_fake.conf` | general (ALT10) | чистый fake ts x6 (tls=4pda, http=max_ru) |
| `84_alt11_general_seqovl.conf` | general (ALT11) | fake tls_max ts x8 + multisplit seqovl=664 |
| `85_alt13_hfs_google.conf` | ALT13_01 (локальный) | hostfakesplit host=www.google.com ts+md5 x6 |
| `86_mgts_general_fake.conf` | MGTS | чистый fake ts x6 (tls=google, http=max_ru) |
| `87_fs_general_seqovl568.conf` | general.bat (дефолт Flowseal) | multisplit seqovl=568 pos=1, pattern=4pda |
| `88_fs_alt_fakefakedsplit.conf` | general (ALT) | fake stun+google ts x6 + fakedsplit pattern=0x00 |
| `89_fs_alt2_seqovl652p2.conf` | general (ALT2) | multisplit seqovl=652 pos=2, pattern=google |
| `92_fs_alt4_fake_badseq.conf` | general (ALT4) | fake stun+google badseq inc=1000 x6 + multisplit |
| `93_fs_alt6_seqovl681.conf` | general (ALT6) | multisplit seqovl=681 pos=1, pattern=google |
| `94_fs_alt7_seqovl679.conf` | general (ALT7) | multisplit pos=2,sniext+1 seqovl=679, pattern=google |
| `95_fs_alt8_fake_badseq2.conf` | general (ALT8) | fake default-tls badseq inc=2 x6 |
| `96_fs_exp_seqovl480.conf` | general (EXP) | fake sferum ts x4 + multisplit seqovl=480 pattern=stun2 |
| `97_fs_fta_multidisorder.conf` | FAKE TLS AUTO | fake 0x00000000 + default-tls tls_mod + multidisorder pos=1,midsld, badseq x11 |
| `98_fs_fta_alt_fakedsplit.conf` | FAKE TLS AUTO ALT | fake tls_mod + fakedsplit pos=1, badseq inc=2 x8 |
| `99_fs_alt5_syndata.conf` | general (ALT5) | syndata + multidisorder, **без hostlist** — на все TCP-порты |
| `A1_fs_fta_alt3_seqovl681.conf` | FAKE TLS AUTO ALT3 (1.10.4) | fake tls_mod(rnd,dupsid,sni=google) ts x8 + multisplit seqovl=681 pattern=google |
| `A2_fs_alt12_seqovl664_sferum.conf` | general (ALT12) (1.10.4) | fake stun+sferum ts x8 + multisplit seqovl=664 pattern=sferum |
| `A3_fs_simplefake_google.conf` | SIMPLE FAKE (1.10.4) | чистый fake ts x6 (tls=google, http=sferum) |
| `A4_fs_simplefake_alt2_sferum.conf` | SIMPLE FAKE ALT2 (1.10.4) | чистый fake ts x6 (tls=stun2+sferum, http=sferum) |

Профили `A1`–`A4` названы буквенным префиксом намеренно: сборщик выбирает по **позиции** в алфавитной сортировке, и любая вставка в середину сдвинула бы номера всех наборов; `A*` сортируется после `99_*` и занимает позиции 34–37, не ломая существующие. Сознательно пропущен только ALT9 — он полностью идентичен базовому `80_general_tcp.conf`. Сверено с Flowseal 1.10.4: профили 72–99 соответствуют актуальным bat-файлам (spot-check general/ALT5/ALT6/FTA).

Правила порта zapret1 → zapret2, применённые в этих профилях (проверено по исходникам nfqws/zapret2):

1. `fooling=ts` → `tcp_ts=-600000`; `badseq` → `tcp_seq=-10000:tcp_ack=-66000`; `badseq-increment=N` → `tcp_seq=-N` (дефолты из readme zapret1).
2. **Fooling ставится только на fake-инстансы.** В zapret1 fooling действует лишь на фейковые пакеты (проверено по `desync.c`: оригинальные сегменты идут с `FOOL_NONE`), а в zapret2 `multisplit`/`multidisorder` применяют fooling ко **всем** частям, включая оригинальные данные (см. `apply_fooling` в `rawsend_dissect_segmented`). Поэтому у сплит-инстансов fooling убран; у `hostfakesplit`/`fakedsplit` оставлен — там zapret2 тоже применяет его только к фейкам.
3. `--dpi-desync-fake-tls=0x...` → `fake:blob=0x...` (инлайн-hex); `=^!` (дефолтный встроенный фейк zapret1) → `blob=fake_default_tls`.
4. Два `--dpi-desync-fake-tls=A,B` → два инстанса fake; `--dpi-desync-fake-http=C` → инстанс fake с `payload=http_req`.
5. `hostfakesplit-mod=...,altorder=1` — altorder в zapret2 не поддержан, опущен (помечено комментарием в профиле).
6. Дефолтная позиция сплита в обоих движках — 2 (zapret1 `nfqws.c:split_compat`, zapret2 `arg.pos or "2"`), голый `multidisorder`/`multisplit` переносится как есть.

Новые блобы объявлены в `00_base.conf`: `tls_sferum`, `tls_sochi`, `stun`, `stun2` (файлы в `bin\`).

Пример сборки с FAKE TLS AUTO (97) вместо базового general (номера = позиции в меню сборки, всего 37 профилей): `service.ps1 -BuildOnly "1,2,3,4,5,6,7,8,15,16,24,25,31"`. Стандартный набор без ALT: `1,2,3,4,5,6,7,8,14,15,16,24,25` (14 = `80_general_tcp`). Позиции новых: 34 = A1, 35 = A2, 36 = A3, 37 = A4.

## 6. Типовые ошибки

| Симптом | Причина | Решение |
|---|---|---|
| Служба стартует и сразу падает | в `--lua-init` потеряны кавычки / запятые (см. п.4.5 и MIGRATION, раздел 3, п.6) | ставить в службу только через service.ps1 |
| Весь трафик мёртв | `--new` сразу после глобального блока | первый профиль без `--new` |
| Профиль «не срабатывает» | выше стоит более общий профиль, который перехватывает пакет | поднять номер префикса, смотреть `--debug`: `profile N matches` |
| `bad identifier` на blob | объявление blob не `name:@"path"` или blob не объявлен в base | править `00_base.conf` |
| Профиль из .conf не виден в меню сборки | файл не в `profiles\` или не `.conf` | — |
| Сайт не открывается под любой техникой | окно DPI изменилось (бывают агрессивные периоды) или блок по IP | диагностика из STRATEGY_GUIDE.md; ipset-профиль |
| `windivert: error opening filter: The object is referenced by other objects so cannot be deleted` | winws2 был убит принудительно (Stop-Process/taskkill) с открытым фильтром — объект фильтра в ядре остался «подвешенным»; выгрузка драйвера и пересоздание сервиса НЕ помогают | не убивать winws2, останавливать через `sc stop zapret2`; если уже случилось — перезагрузка. Запускать winws2 одновременно только из одного каталога (служба живёт в `C:\fZapret2`) |
