# OpenWrt + zapret2 — инженерный гайд

Аппарат: **Tenda BE12 Pro** (mediatek/filogic, 4x Cortex-A53, 512 МБ RAM, 128 МБ NAND, Wi-Fi 7).
Прошивка: **OpenWrt SNAPSHOT r38259**, ядро 6.18, пакетный менеджер **apk** (не opkg!).
Стек: zapret2 1.0.7 + Zapret-Manager 5.083 + dnsmasq + https-dns-proxy + SQM(cake) + stgws.

---

## ЧАСТЬ 1. Работа с OpenWrt

### 1.1. Доступ
- LuCI: http://<ROUTER_IP> (uhttpd).
- SSH: `ssh user@<ROUTER_IP>` (dropbear, вход по паролю; `CONECTION.md` в проекте).
- Файлы заливать: sftp-сервера на роутере НЕТ. Рабочие пути:
  - `scp -O file user@<ROUTER_IP>:/path` (legacy-режим scp);
  - paramiko: `exec_command("cat > /path", stdin=data)`;
  - `base64` на роутере отсутствует — не использовать.

### 1.2. UCI — система конфигурации
Все настройки в `/etc/config/*`, формат UCI. Работа из CLI:
```sh
uci show dhcp                          # дамп секции
uci get dhcp.@dnsmasq[0].cachesize
uci set dhcp.@dnsmasq[0].cachesize='10000'
uci add_list dhcp.@dnsmasq[0].server='77.88.8.8'
uci commit dhcp                        # записать на flash
/etc/init.d/dnsmasq restart            # применить
```
Экспорт/бэкап конфига: `uci export dhcp`. Анонимные секции адресуются `@type[N]` или `@type[-1]` (последняя).

### 1.3. Пакеты (apk на SNAPSHOT)
```sh
apk update          # обновить индексы
apk add tcpdump     # поставить
apk del пакет       # удалить
apk info            # список установленного
```
**ВАЖНО:** SNAPSHOT-репозиторий привязан к сборке ядра. Через недели после установки kmod-пакеты могут стать несовместимы (`kernel version mismatch`). Перед установкой kmod-* — сверяйся, лучше сразу после прошивки. Список наших пакетов: `backup/20261115/apk_packages.txt`.

### 1.4. Sysupgrade
- Сохраняемые файлы: `/etc/sysupgrade.conf` (+ `/lib/upgrade/keep.d/*`). Туда внесены наши `/opt/zapret2/ipset/`, `files/fake/`, `allow.txt`, `/etc/stgws/`, скрипты.
- Обновление: attendedsysupgrade (LuCI) или `sysupgrade -k`. Только с полным бэкапом (см. 1.5).
- NAND 128 МБ, overlay 69 МБ (занято ~17%) — место ограничено, следи за `df -h /overlay`.

### 1.5. Бэкап
- `uci_*.txt` — экспорты конфигов (восстановление: `uci import`);
- `fz_backup.tgz` — листы, fake-блобы, adblock allow, /etc/stgws;
- `apk_packages.txt`, `sysupgrade.conf`, `crontab.txt`, `adblock_settings.txt`.
После любых существенных правок — обновлять слепок.

### 1.6. Сеть (наша топология)
- WAN `eth2`, DHCP от провайдера, серый IP 10.x.x.0/16 (CGNAT).
- LAN `br-lan` (lan1-3 + eth1) = <ROUTER_IP>/24, DHCP .100-.249.
- IPv6: только ULA (fdXX:XXXX:XXXX::/48), wan6 выключен — у провайдера нет v6.
- firewall4 (nftables): WAN input REJECT, LAN open, masq на WAN. Flow offload **намеренно выключен** (несовместим с NFQUEUE zapret2 — включение сломает desync).
- Wi-Fi: radio0 = 2.4 ГГц (ch6, EHT20, psk2), radio1 = 5 ГГц (ch48, EHT160, sae, ocv=0).

---

## ЧАСТЬ 2. zapret2 на этом роутере

### 2.1. Архитектура
```
LAN-клиент → prerouting(nft, reply pkts) ┐
             postrouting(nft, 1-25 pkts TCP / 1-5 UDP) → NFQUEUE 300 → nfqws2 (daemon 1, 14 профилей)
             UDP 19294-19344 len==82  → NFQUEUE 65300 → nfqws2 (discord ip discovery)
             STUN magic cookie        → NFQUEUE 65301 → nfqws2 (stun)
```
Три демона nfqws2. Конфиг генерится init-скриптом из UCI `/etc/config/zapret2` в `/opt/zapret2/config`. Править конфиг руками бессмысленно — перезапишется; править через UCI.

Ключевые main-опции (`uci show zapret2.main`):
- `nfqws_ports_tcp='80,443,853,1024-65535'`, `nfqws_ports_udp='80,88,443,1024-65535'` — какие порты попадают в очередь (первые N пакетов потока).
- `enable_ipv6='0'` — v6 не обрабатывается (у провайдера нет v6).
- `flowoffload='donttouch'` — не трогать offload (он и так off; включать нельзя).

### 2.2. Профили (стратегии)
14 активных секций `fzNN_*` в UCI (см. `uci show zapret2 | grep =strategy`). Портированы с Windows-сборки ПК:

| Профиль | Что делает |
|---|---|
| fz09_quic_discord | QUIC fake x6 для discord-доменов (лечит аватары/медиа) |
| fz10_quic_general | QUIC fake по hostlist general |
| fz20_discord_voice_udp | fake по UDP-портам voice/stun |
| fz30/40/50/60_discord_* | TLS-цепочки для updates/media/cdn/main Discord |
| fz68_googlevideo | multidisorder для googlevideo |
| fz70_google, fz71_github | fake+fakedsplit |
| fz81_ipset_quic, fz82_ipset_tcp | desync по ipset-all.txt (там диапазоны Meta) |
| fz90_game_udp | UDP fake на 7711/12000 |
| fz97_general | основная TLS-цепочка (fake badseq x11 + multidisorder) по list-general* |

**fz91_udp_catchall ВЫКЛЮЧЕН** (ломал Fortnite: фейки в чистый игровой UDP → `initial connection failed`). Тумблер: `/opt/zapret2/game-udp.sh on|off|status`.

### 2.3. Листы
`/opt/zapret2/ipset/`:
- `list-general.txt` — стоковый; `list-general-user.txt` — наш (84 домена: Meta, Discord, кинозалы...);
- `ipset-all.txt` — IP-диапазоны (Meta 57.144/16, 157.240/16, 31.13/16, 185.60.216/22, 2a03:2880::/32);
- `ipset-exclude*.txt`, `list-exclude*.txt` — исключения (в т.ч. игровые серверы из наследия zapret1);
- `list-google.txt`, `list-github.txt`, `list-googlevideo.txt`.

**Правило №1: не добавлять незаблокированный домен в hostlist** — агрессивный fz97 ломает к нему доступ (доказано на filmix.watch и tiktok.com). Сначала проверь `curl` без обхода.

После правки листов: `/etc/init.d/zapret2 restart`. Мастер-копии листов на ПК: `C:\fZapret2\lists\` (синхронизировать!).

### 2.4. DNS-слой (критичен, без него обход не работает)
```
клиент → dnsmasq (:53, no-resolv) → https-dns-proxy (127.0.0.1:5053) → Cloudflare DoH
```
- Провайдерский DNS спуфит NXDOMAIN на заблокированные домены; UDP/53 к 8.8.8.8 подменяется ТСПУ (гонка ответов). Yandex 77.88.8.8 отвечает честно, но мы на DoH.
- `force_dns='1'` у https-dns-proxy: весь LAN DNS заворачивается на роутер.
- **Пиннинг Meta** (`config domain` в /etc/config/dhcp): instagram/facebook/whatsapp → живые IP из 57.144.0.0/16. Остальные диапазоны Meta (157.240.x, часть 31.13.x) — null-route, desync не спасает. Если Meta сменит IP — обновить пины (проверка: `curl --resolve domain:443:IP`).
- dnsmasq cache-size=10000.

### 2.5. Диагностика
```sh
pidof nfqws2                    # 3 PID = живо
/etc/init.d/zapret2 status
grep -o 'name=fz[0-9a-z_]*' /opt/zapret2/config   # активные профили
tail -20 /tmp/zhealth.log       # почасовой healthcheck (7 эталонов, 200/301/302 = ок)
logread | grep -i zapret
curl -s -o /dev/null -w '%{http_code}\n' https://домен/    # тест с роутера (трафик идёт через postrouting → через nfqws2, валидный тест desync-пути)
```
Типовые коды: 000 = таймаут/обрыв, 200/301/302 = ок.

### 2.6. Частые сценарии
- **Сайт X не открывается**: резолвится? (`nslookup X 127.0.0.1`) → NXDOMAIN = DNS-проблема (см. адблок/DoH). TCP таймаут → проверить тип блока: `curl http://IP/` на 80-й: отвечает = TSPU-drop 443 (лечится добавлением в hostlist/ipset), молчит + ping мёртв = null-route (только VPN).
- **Игра выкидывает**: `game-udp.sh status`; если on — выключить. Если off и всё равно ломается — захват: `apk add tcpdump`, `tcpdump -i eth2 -nn host <ip_пк> -w /tmp/cap.pcap`, анализ на ПК в Wireshark; дальше точечный профиль или ipset-exclude.
- **Добавить домен в обход**: добавить в `/opt/zapret2/ipset/list-general-user.txt` + на ПК в `C:\fZapret2\lists\`, restart zapret2.

---

## ЧАСТЬ 3. Прочий функционал прошивки

### 3.1. Zapret-Manager (LuCI → Zapret-Manager)
Панель управления zapret + модули. У нас используются:
- **AdBlock**: 223k доменов (multi-лист) + TIF IP-листы (spamhaus, hagezi, botnet — таблица `zm_adblock_ip`). Белый список: `state/adblock/allow.txt` (там alloha.tv). Управление: `backend.sh adblock_action allow_set '<домены>'`, off — выключить.
- **zm_watch** (cron */2 мин): самолечение; наших правок не откатывает, но наблюдать.
- Модули, которые есть, но не используем: bytetube, steer1/2, tg-прокси управление, forkozz, mixomo, monitor.

### 3.2. SQM (cake)
`/etc/config/sqm`: cake + piece_of_cake на eth2, 470/220 Мбит. Закрывает буферблоат (пинг под нагрузкой 4.1 мс против 4.0 в простое). Включить/выключить: `uci set sqm.eth1.enabled='1'/'0' && /etc/init.d/sqm start/stop`.

### 3.3. stgws (Telegram WS-прокси)
`/usr/sbin/stgws`, конфиг `/etc/stgws/spec.json`, автозапуск S97tgws, таблица nft `stgws`. Основной инстанс (ПК-версия отключена).

### 3.4. Healthcheck
`/opt/zapret2/healthcheck.sh`, cron `17 * * * *`, лог `/tmp/zhealth.log` (tmpfs — не переживает ребут, 500 строк).

### 3.5. Что ещё можно поставить (проверенные идеи под нашу конфигурацию)
| Задача | Пакет | Примечание |
|---|---|---|
| VPN-сервер домой | `wireguard-tools`, `luci-proto-wireguard` | CGNAT! Нужен внешний VPS или провайдерский белый IP — иначе только исходящий WG-клиент |
| VPN-клиент (полный туннель) | `openvpn` / `wireguard` + policy-routing | для null-route ресурсов (filmix.gg и т.п.) |
| Гостевая сеть | штатно (interface + firewall zone + Wi-Fi SSID) | изолировать IoT/гостей |
| Мониторинг | `prometheus-node-exporter` или collectd | RAM/CPU/трафик |
| Wake-on-LAN | `etherwake` + LuCI-app | будить ПК |
| Статические лизы | штатно в dhcp | для ПК/приставок |
| Adblock-статистика | встроена в ZM (off сейчас) | `adblock_action stats_set on` |
| Ускорение DNS ещё | `unbound` вместо dnsmasq | избыточно, DoH достаточно |
| Файлопомойка | `ksmbd` | USB у BE12 Pro нет — неактуально |
| Расписание Wi-Fi | `wifischedule` | глушить ночью |

### 3.6. Известные ограничения/причуды
- SNAPSHOT + apk: kmod-пакеты привязаны к билду ядра; установку софта делать безотлагательно после прошивки.
- `udhcpc: no lease, failing` при рестарте dnsmasq — косметика хуков netifd, WAN не рвётся.
- RAM 512 МБ: сейчас свободно ~240 МБ; не ставить тяжёлые сервисы (AdGuard Home и пр.).
- Overlay 69 МБ: большие листы/логи — только в /tmp (tmpfs 242 МБ) или на ПК.
- WhatsApp звонки (Noise/UDP) — не тестировались; при жалобах смотреть UDP-трафик и, возможно, точечный профиль.

---

*История всех изменений: `C:\Users\user\Documents\fZapret\MIGRATION_ZAPRET2.md` (разделы 19-23).*
