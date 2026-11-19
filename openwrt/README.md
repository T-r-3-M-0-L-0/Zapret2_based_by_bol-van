## Что в папке

| Файл | Назначение |
|---|---|
| `nfqws2_opt_custom.conf` | Полная стратегия zapret2 (глобальный init + 15 профилей). **Основной файл.** |
| `nfqws1_opt_approx.conf` | Приближённая конверсия под zapret1 (nfqws) — только если zapret2 недоступен |
| `lists\` | Хостлисты и ipset, на которые ссылается стратегия |
| `lua\` | zapret-lib.lua + zapret-antidpi.lua (наши версии, v1.0.7) |

## Путь А (основной): Zapret2 через Zapret-Manager

Требование: роутер на **aarch64_cortex-a53** (пакеты Routerich). Проверка:
Дашборд панели показывает архитектуру, либо `opkg print-architecture` в SSH.
Не a53 → см. «Путь В» (zapret2 от remittor под любую архитектуру) или запасной `nfqws1_opt_approx.conf`.

1. Установить Zapret-Manager (SSH на роутере):
   ```
   sh <(wget -O - https://raw.githubusercontent.com/StressOzz/Zapret-Manager/main/Zapret-Manager.sh)
   ```
2. В панели: раздел **Zapret2 → Установить**. Панель сама поставит пакеты
   `zapret2` + `luci-app-zapret2` (packages.routerich.ru) и запустит службу.
   Zapret1 и Zapret2 одновременно ставить нельзя — панель следит сама.
3. Скопировать файлы на роутер (с ПК, WinSCP или scp):
   ```
   scp lists\*  user@<ROUTER_IP>:/opt/zapret2/ipset/
   scp lua\*    user@<ROUTER_IP>:/opt/zapret2/files/lua/
   ```
   Если папок нет — создать: `mkdir -p /opt/zapret2/ipset /opt/zapret2/files/lua`.
   Если scp падает с `/usr/libexec/sftp-server: not found` (Dropbear без
   sftp) — либо добавить флаг `-O` к scp (старый протокол), либо на роутере:
   `opkg update && opkg install openssh-sftp-server`, либо tar по ssh:
   `tar -cf - lists lua | ssh user@<ROUTER_IP> "cd /opt/zapret2 && mkdir -p ipset files/lua && tar -xf - && mv lists/* ipset/ && mv lua/* files/lua/ && rmdir lists lua"`
   Проверить, что lua-пакета совпадают с нашими (если пакет принёс свои —
   оставить пакетные, наши класть только при отсутствии).
4. Открыть **LuCI → Zapret2** (из панели: «Перейти в настройки»):
   - Blobs: включить google quic initial и остальные стандартные блобы
     (tls_clienthello_www_google_com, tls_clienthello_max_ru, tls_clienthello_4pda,
     tls_clienthello_www_sferum, tls_clienthello_sochi_park, stun, stun2,
     quic_initial_www_google_com, quic_initial_vk_com, quic_initial_dbankcloud_ru).
     Все они стандартные из репозитория bol-van и идут с пакетом.
   - Порты перехвата:
     `NFQWS2_PORTS_TCP=80,443,2053,2083,2087,2096,8443`
     `NFQWS2_PORTS_UDP=443,1024-65535`
   - В редактор стратегии вставить **весь текст** `nfqws2_opt_custom.conf`.
   - Save & Apply.
5. Проверка с роутера: `logread -e zapret2`, затем с ПК за роутером —
   youtube, discord, github.

## Путь В: роутер не a53, но хочется zapret2

Пакеты zapret2 под все архитектуры: github.com/remittor/zapret-openwrt
(релизы `zapret2_*` + `luci-app-zapret2`). Ставятся вручную (`opkg install`),
стратегия и списки — те же файлы из этой папки, пути те же.

## Путь С (запасной): только Zapret1

Если zapret2 недоступен — раздел **Zapret** панели, редактор стратегии,
вставить `nfqws1_opt_approx.conf`. Ограничения конверсии описаны в шапке
файла: zapret1 без lua, часть тонкостей (ip_id=zero по-цепочечно,
fake_default_quic, tls_mod) передаётся приближённо. Списки класть в
`/opt/zapret/ipset/`, блобы уже есть в `/opt/zapret/files/fake/`.

## Важные нюансы на роутере

- **Flow offloading:** hw offload ломает обход (пакеты идут мимо nfqws).
  Zapret-Manager ставит поправку сам; при ручной установке — выключить
  hardware flow offloading в Network → Firewall.
- **IPv6:** стратегия работает на обоих семействах (проверено на ПК),
  на роутере NFQUEUE настраивается пакетом для обоих.
- **Память:** один процесс nfqws2 — ~10–20 МБ. На роутерах < 128 МБ
  не раздувать количество профилей.
- **Порядок профилей критичен** (первое совпадение выигрывает): не менять
  порядок блоков в стратегии.
- **Обновление листов:** `lists\` обновляются с ПК по мере изменений —
  просто перезаливать в /opt/zapret2/ipset/.

## Отличия от Windows-версии

- `--wf-tcp-out/--wf-udp-out` (WinDivert) убраны: на OpenWrt перехват делают
  правила nftables NFQUEUE по портам (задаются отдельно).
- Пути: `%LISTS%` → `/opt/zapret2/ipset/`, `%BIN%` → `/opt/zapret2/files/fake/`,
  `%LUA%` → `/opt/zapret2/files/lua/`.
- Остальное (фильтры, payload, lua-desync цепочки) — без изменений, синтаксис
  zapret2 идентичен на всех платформах.

---

## Фактический деплой (2026-11-15)

**Окружение роутера:** OpenWrt SNAPSHOT r38259, mediatek/filogic, aarch64_cortex-a53,
RAM 496 МБ, zapret2 1.0.7-r2 + luci-app-zapret2 (UCI-модель: секции
`config strategy` / `config blob` / `config list` в `/etc/config/zapret2`).

**Что применено:**
1. Бэкап: `/etc/config/zapret2` → `openwrt\backup\zapret2.uci.bak` (ПК) и
   `/etc/config/zapret2.bak_fz` (роутер).
2. Блоб `tls_clienthello_www_sferum_ru.bin` залит в `/opt/zapret2/files/fake/`,
   зарегистрирован в UCI; включены блобы `tls_clienthello_max_ru`,
   `quic_initial_www_google_com`, `quic_initial_vk_com`,
   `quic_initial_dbankcloud_ru`.
3. Стоковые стратегии выключены (enabled '0'): Discord_circular, discord_media,
   discord_udp, Youtube_UDP, Yv08, V_circular, games_tcp, games_udp.
4. Добавлены 15 секций `fz09..fz97` — порт профилей ПК. Трансляции:
   - блобы по UCI-именам (`tls_google` → `blob_tls_clienthello_www_google_com`);
   - `tls_ozon/tls_max_ozon/tls_def_ozon` → инлайн `tls_mod=sni=ozon.ru` в цепочках;
   - хостлисты/ipset — инлайн-путями `/opt/zapret2/ipset/...` в поле script;
   - порты перехвата роутера не менялись (уже надмножество наших).
   Итоговый конфиг: `openwrt\zapret2.uci.new`.
5. `enable_ipv6=0` на роутере — обход работает только для IPv4 (как и было
   настроено до нас; включение v6 — отдельная тема).

**Проверки (ПК без локальной службы, трафик только через роутер):**
youtube TLS 200, discord TLS 200 (0.18с), github 200,
cdn.discordapp.com QUIC H3OK 0.09с. youtube QUIC 000 — ожидаемо (TCP-фолбэк,
как на ПК). googlevideo вечером 238 КБ/с — прайм-тайм шейпер, не конфигурация.

**Откат:**
```
ssh user@<ROUTER_IP> "cp /etc/config/zapret2.bak_fz /etc/config/zapret2 && /etc/init.d/zapret2 restart"
```

**Правка стратегий:** LuCI → Zapret2 (секции fz*) или правка
`/etc/config/zapret2` + `/etc/init.d/zapret2 restart`. После правок на ПК —
регенерировать секции по той же таблице трансляции.

## DNS-слой (добавлено 15.11.2026, вечер)

- **https-dns-proxy** установлен: Cloudflare DoH на 127.0.0.1#5053, dnsmasq `noresolv=1`, апстрим только DoH. Причина: провайдерский DNS спуфил NXDOMAIN на заблокированные домены, ТСПУ подменял UDP/53 к 8.8.8.8 (гонка ответов).
- **Пиннинг Meta** в `/etc/config/dhcp` (config domain): instagram/facebook/whatsapp -> живые IP из 57.144.0.0/16 (остальные диапазоны Meta null-route, см. журнал раздел 20).
- **Адблок Zapret-Manager**: белый список `/opt/zapret-manager-luci/state/adblock/allow.txt` — там `alloha.tv` (попадал в блок-лист -> NXDOMAIN).
- ВАЖНО: незаблокированные домены (tiktok.com, filmix.watch) НЕ добавлять в list-general-user.txt — профиль 97 ломает к ним доступ.

Откат DNS: `uci set dhcp.@dnsmasq[0].noresolv='0'; uci -q delete dhcp.@dnsmasq[0].server; uci commit dhcp; /etc/init.d/https-dns-proxy stop; /etc/init.d/https-dns-proxy disable; /etc/init.d/dnsmasq restart`
