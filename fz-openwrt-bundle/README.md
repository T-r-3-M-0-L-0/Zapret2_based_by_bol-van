# fz-openwrt-bundle — полный перенос сетапа zapret2 на другой роутер

Пять независимых пакетов. Ставятся на OpenWrt-роутер с Zapret-Manager,
на котором из панели уже установлен компонент **Zapret2** (и **tgws** для п.3).

## Состав и порядок установки

| # | Папка | Что даёт |
|---|-------|----------|
| 1 | `zapret2-config/` | UCI-конфиг со всеми профилями/стратегиями + списки ipset + lua |
| 2 | `strategy-check/` | Сравнение стратегий: вкладка LuCI, healthcheck с автоподбором и автоприменением, curl с HTTP/3 |
| 3 | `stgws-smart/` | Умная карта sTGWS (Telegram) + кнопки управления в панели |
| 4 | `zapret2-presets/` | Страница LuCI «Zapret2 пресеты»: переключение наборов стратегий одной кнопкой |
| 5 | `zm-plugin-system/` | Система манифест-плагинов: страницы :7788 без JS, manifest.json + backend.sh |

Порядок важен: 1 → 2 → 3 → 4. Пакет 3 нужен только если на целевом роутере
используется sTGWS (компонент tgws из Zapret-Manager). Пакет 5 независим,
ставится в любой момент.

## Копирование на роутер (scp без SFTP)

В OpenSSH 9+ scp по умолчанию ходит через SFTP, которого в dropbear нет —
поэтому обязательно флаг `-O` (legacy-режим):

```sh
scp -O fz-openwrt-bundle.tar.gz root@<роутер>:/root/
ssh root@<роутер>
tar xzf /root/fz-openwrt-bundle.tar.gz -C /root
```

Либо без архива, потоком:

```sh
tar czf - fz-openwrt-bundle | ssh root@<роутер> "tar xzf - -C /root"
```

## Установка (на роутере, под root)

```sh
cd /root/fz-openwrt-bundle/zapret2-config  && sh install-zapret2-config.sh --check
cd /root/fz-openwrt-bundle/zapret2-config  && sh install-zapret2-config.sh

cd /root/fz-openwrt-bundle/strategy-check  && sh install-strategy-compare.sh

cd /root/fz-openwrt-bundle/stgws-smart     && sh install-stgws-smart.sh --check
cd /root/fz-openwrt-bundle/stgws-smart     && sh install-stgws-smart.sh

cd /root/fz-openwrt-bundle/zapret2-presets && sh install-zapret2-presets.sh

cd /root/fz-openwrt-bundle/zm-plugin-system && sh install-zm-plugins.sh
```

У каждого установщика: preflight без записи, бэкап заменяемых файлов,
автоматический откат при сбое. Подробности — в README.md внутри каждой папки.

## После установки

1. Панель → Zapret2: профили/стратегии совпадают с донором, служба запущена.
2. Панель → Zapret2 → «Сравнение стратегий»: вкладка открывается,
   cron `zhealth` на месте (`crontab -l | grep zhealth`).
3. Панель → Zapret Manager → tgproxy: карточка sTGWS с кнопками карты
   (Ctrl+F5 для обновления JS).
4. Службы → Zapret2 пресеты: список пресетов, у «hybrid-fz» отметка «активен».
5. Панель :7788 → группа «Плагины» → «Проба сервисов»: таблица проб заполняется
   (Ctrl+F5 после установки пакета 5).
6. Проверочные сайты: youtube.com, discord.com, web.telegram.org.

## Откат

Каждый пакет пишет бэкап в /root/ (`zapret2-config-backup-*`,
`stgws-smart-backup-*`, `zapret2-tools/backups/ui-*`,
`/opt/zapret-manager-luci/backups/plugin-system-*`). Команды отката —
в README соответствующего пакета.
