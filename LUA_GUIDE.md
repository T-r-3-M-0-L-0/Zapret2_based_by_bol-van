# Lua в zapret2: краткая памятка для разработки своих приёмов

Зачем: winws2 исполняет lua-функции на каждый перехваченный пакет. Все техники обхода (`fake`, `multisplit`, `multidisorder`, …) — обычные lua-функции из `lua\zapret-antidpi.lua`. Своя функция подключается так же, без перекомпиляции.

Источники истины (смотреть при сомнениях, всё локально):
- `lua\zapret-antidpi.lua` — боевые функции и их аргументы (в комментарии над каждой);
- `lua\zapret-lib.lua` — инфраструктура (blobs, позиции, rawsend, cutoff, `tls_mod`);
- `lua\zapret-tests.lua` — примеры синтаксиса маркеров позиций.

---

## 1. Модель исполнения

```
--lua-init=<код|@файл>      выполняется 1 раз при старте (библиотеки, свои переменные)
--lua-desync=<func>:arg=v:arg=v   цепочка функций профиля; выполняется на пакет
```

Сигнатура любой функции:

```lua
function myfunc(ctx, desync)
    -- ctx    : контекст соединения/пакета
    -- desync : состояние + аргументы (desync.arg.X), dissect (desync.dis), reasm_data
    -- вернуть verdict: "pass" | "drop" | "modify" (необязательно; по умолчанию pass)
end
```

Цепочка из нескольких `--lua-desync` в одном профиле выполняется по порядку объявления (типовой паттерн: сначала `fake` отправляет фейк-пакет, затем `multisplit` режет настоящий).

---

## 2. Стандартные аргументы (работают в большинстве функций)

Передаются через двоеточие: `--lua-desync=fake:blob=tls_google:repeats=6:ip_id=zero`

| Аргумент | Значение | Пример |
|---|---|---|
| Fooling IP | `ip_ttl=N`, `ip_autottl=delta,min-max` | `ip_ttl=3`, `ip_autottl=6,1-20` |
| Fooling TCP | `tcp_seq=N`, `tcp_ack=N`, `tcp_ts=N`, `tcp_md5`, `tcp_flags_set=…`, `tcp_flags_unset=…` | `tcp_seq=-10000:tcp_ack=-66000`, `tcp_ts=-600000` |
| `badsum` | битая TCP-контролька | `badsum` |
| `repeats` | сколько раз отправить | `repeats=8` |
| `ip_id` | `seq` / `rnd` / `zero` / `none` | `ip_id=zero` |
| `ipfrag` | фрагментация IP | `ipfrag=8` |
| `payload` | ограничение по типу payload внутри функции | `payload=all`, `payload=quic_initial` |
| `dir` | направление | `dir=out` |

Специфичные (смотреть комментарий над функцией в zapret-antidpi.lua):
- `fake`: `blob=<имя>` (обязателен), `tls_mod=<список>` — модификация фейка на лету, `optional` — пропустить, если blob отсутствует;
- `multisplit` / `multidisorder`: `pos=<маркеры>`, `seqovl=N`, `seqovl_pattern=<blob>`;
- `fakedsplit`: `pattern=0x00`;
- `hostfakesplit`: `host=домен` (подмена SNI/Host в разбиении).

---

## 3. Маркеры позиций (`pos=`)

| Маркер | Значение |
|---|---|
| `1` | начало payload |
| `host` | начало Host/SNI |
| `midsld` | середина домена 2-го уровня |
| `sld` | начало SLD |
| `endhost` | конец хоста |
| `sniext+1` | сразу после SNI-расширения в ClientHello |
| `extlen` | конец блока расширений |
| `-N` | N байт от конца payload |
| `+N` / `-N` | смещение от маркера: `midsld+1`, `host-2` |

Списком через запятую: `pos=1,sniext+1,midsld`.

Особенности, проверенные вживую (05.11): маркера `sni` не существует (движок: `bad marker : 'sni'`) — для TLS используйте `sld`, `midsld`, `sniext+1`; host-маркеры не резолвятся, если SNI в ClientHello нет вообще (обращение по IP вместо домена) — функция должна переживать `nil` от `resolve_pos`.

---

## 4. Blobs и `tls_mod`

Blob = бинарный шаблон (например, записанный ClientHello). Объявление глобально:

```
--blob=tls_google:@"C:\...\bin\tls_clienthello_www_google_com.bin"
```

(двоеточие и `@` обязательны; без них — `bad identifier`).

В lua-init создаём производные шаблоны:

```lua
--lua-init="tls_ozon=tls_mod(tls_google,'sni=ozon.ru')"
```

Флаги `tls_mod` (через запятую в одной строке): `rnd`, `rndsni`, `sni=<строка>`, `dupsid`, `padencap`. Поддерживается `sni=%var` (переменная из lua-init).

Встроенные шаблоны из zapret-lib.lua: `fake_default_tls`, `fake_default_quic`, `fake_default_http` и др.

---

## 5. Своя функция за 15 минут

1. Пишете файл, например `lua\mytech.lua`:

```lua
function my_split(ctx, desync)
    -- действуем только на исходящий TLS ClientHello
    if not (desync.dis and desync.dis.tcp) then return end
    if not payload_check(desync) then return end
    -- взять payload: desync.dis.payload (string) или desync.reasm_data
    local pl = desync.dis.payload
    if not pl or #pl < 10 then return end
    -- отправить кусок через rawsend (см. rawsend_payload_segmented в zapret-lib.lua)
    rawsend_payload_segmented(desync, pl:sub(1,1))   -- первый байт отдельно
    rawsend_payload_segmented(desync, pl)            -- полный payload (будет разрезан ядром)
end
```

2. Подключаете в профиле:

```
--lua-init=@"%LUA%mytech.lua"
--lua-desync=my_split:repeats=1
```

3. Отладка: запуск с `--debug` и `DLOG("my_split: len="..#pl)` внутри функции. Без `--debug` ошибки lua не видны — первое правило.

Готовые примеры для кражи: `desync_orchestrator_example` (zapret-lib.lua), `http_domcase`/`udplen` (zapret-antidpi.lua) — короткие и показательные. Для произвольной логики без своего файла есть `luaexec:code=...` (код инлайн, см. `luaexec` в zapret-lib.lua).

**Учебная библиотека `lua\zapret-testlib.lua`** (05.11): пять прокомментированных функций-заготовок, покрывающих все основные механики — `myinfo` (диагностика: что приходит в функцию), `myfake` (фейк + паддинг + стандартные fooling/repeats), `mysplit` (сплит с disorder и seqovl), `mycount` (per-connection состояние через `track.lua_state`), `mydelayed` (отложенная отправка через `timer_set`). В заголовке файла — полный контракт `ctx`/`desync`, вердикты и правила replay/cutoff. Проверка без запуска трафика: `winws2 --intercept=0 --lua-init=@... --lua-desync=myfake:blob=...` — загружает lua, валидирует имена функций и выходит (движок ругается на несуществующие функции, `--dry-run` lua не загружает).

Живой тест без конфликта со службой: `testlib_run.cmd` (корень fZapret2) поднимает второй winws2 **только на порту 853** (фильтры не пересекаются со службой — так разрешено) с `myinfo+myfake+mysplit` и `--debug` в `logs\testlib_debug.txt`. Трафик для него: `curl -k --resolve dns.google:853:8.8.8.8 https://dns.google:853/` (обязательно с доменом — по IP нет SNI, host-маркеры не сработают). Остановка: **CTRL_BREAK** в консоль процесса (`_ctrlc.ps1` в Documents\fZapret шлёт его по PID) — winws2 пишет `quit requested`, `LUA SHUTDOWN` и выходит чисто; Ctrl+C не работает, taskkill запрещён (клин WinDivert).

---

## 6. Полезные хелперы (zapret-lib.lua)

| Функция | Назначение |
|---|---|
| `blob(desync, "name")` | получить blob по имени |
| `rawsend_payload_segmented(desync, data)` | отправка с учётом fooling/repeats/ip_id/ipfrag |
| `payload_check(desync)`, `direction_check(desync)` | стандартные проверки условий |
| `DLOG(...)` | отладочный вывод (только при `--debug`) |
| `hexdump_dlog(data)` | hex-дамп в debug |
| `pos_get(desync, "midsld")` | вычислить позицию маркера |
| `seq_within/seq_ge/...` | сравнение TCP seq с учётом wrap |
| `is_retransmission(desync)` | отсечь ретрансляции |

---

## 7. Чем отличаются библиотеки в `lua\`

| Файл | Роль | Когда трогать |
|---|---|---|
| `zapret-lib.lua` | **База**: хелперы (blobs, fooling, rawsend, позиции, TLS/HTTP-диссекторы), обязательна первой | Никогда не править — обновляется с релизом winws2 |
| `zapret-antidpi.lua` | **Боевые приёмы**: `fake`, `multisplit`, `multidisorder`, `hostfakesplit`, `fakedsplit`, `syndata`, `rst` и т.д. — то, что вызывается из профилей | Не править; свои приёмы — в отдельный файл |
| `zapret-auto.lua` | **Оркестрация**: детекторы успеха/провала, выбор стратегии на лету (per-host), без переписывания самих приёмов | Для продвинутых авто-стратегий («пробуем A, если не сработало — B») |
| `zapret-obfs.lua` | **Обфускация**: `wgobfs` — шифрование WireGuard-хендшейков по общему секрету | Только для пары «клиент-сервер» со своим VPS |
| `zapret-pcap.lua` | **Запись трафика**: `pcap:file=...` сбрасывает пакеты в .pcap для Wireshark | Диагностика: посмотреть, что реально уходит в сеть |
| `zapret-tests.lua` | **Самотест движка**: `--lua-init="test_all()"` гоняет тесты C-функций (crypto, dissect, rawsend) | Проверка, что релиз не битый; к стратегиям отношения не имеет |
| `zapret-testlib.lua` | **Учебная либа**: 5 прокомментированных заготовок `myinfo/myfake/mysplit/mycount/mydelayed` | База для своих функций — копировать и править |

## 8. Правила безопасности конфигурации

- В `--lua-init` внутри bat: **без пробелов вокруг `=`** и с двойными кавычками снаружи (`--lua-init="x=tls_mod(y,'rnd')"`). Иначе сломается установка в службу (service.ps1 чистит пробелы сам, но лучше писать сразу правильно).
- Синтаксическая ошибка в lua-файле = winws2 падает на старте или профиль молча не работает. Проверка: `winws2.exe --debug` + смотреть первые строки вывода.
- lua-compat: `lua\` и `bin\winws2.exe` строго из одного релиза (проверка `NFQWS2_COMPAT_VER`, у нас 6).
