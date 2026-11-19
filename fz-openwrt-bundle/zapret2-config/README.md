# zapret2-config — перенос конфигурации zapret2 между роутерами

Готовый снимок рабочей конфигурации zapret2 (Zapret-Manager, OpenWrt):
UCI-конфиг со всеми профилями и стратегиями, списки доменов/IP, lua-скрипты.
Ставится поверх уже установленного пакета zapret2 — отдельно копировать
`/opt/zapret2/ipset` и `/opt/zapret2/lua` не нужно, установщик сделает это сам.

## Состав

```
install-zapret2-config.sh   ← запускается на роутере
src/
├── etc/config/zapret2        ← UCI: профили, стратегии, порядок
└── opt/zapret2/
    ├── ipset/*.txt           ← списки доменов и IP (general, exclude, discord,
    │                           youtube, google, github, user-листы, auto)
    └── lua/*.lua             ← lua-библиотеки и действия профилей
```

НЕ входит (это отдельные пакеты/шаги): сам пакет zapret2, fake-файлы
(`/opt/zapret2/files`), strategy-check (сравнение стратегий и вкладка LuCI),
healthcheck с cron-автоподбором, sTGWS и умная карта, curl-h3.

## Требования на целевом роутере

1. OpenWrt с Zapret-Manager, из панели уже установлен компонент **Zapret2**
   (должны существовать `/etc/init.d/zapret2`, `/etc/config/zapret2`,
   `/opt/zapret2/ipset`, `/opt/zapret2/lua`).
2. Доступ root по SSH.

## Установка

1. Скопировать папку на роутер (SFTP в OpenWrt обычно нет — через tar):
   ```sh
   tar czf - zapret2-config | ssh root@<роутер> "tar xzf - -C /root"
   ```
2. Проверка совместимости без записи:
   ```sh
   cd /root/zapret2-config && sh install-zapret2-config.sh --check
   ```
   `PREFLIGHT_OK` — можно ставить.
3. Установка:
   ```sh
   sh install-zapret2-config.sh
   ```
   Установщик бэкапит текущие конфиг и перезаписываемые листы в
   `/root/zapret2-config-backup-<дата>`, копирует файлы, перезапускает zapret2
   и проверяет, что служба и демоны nfqws2 поднялись. При любой ошибке —
   автоматический откат к прежней конфигурации.

## Откат вручную

```sh
BK=/root/zapret2-config-backup-<дата> && \
cp -p $BK/zapret2 /etc/config/zapret2 && \
cp -p $BK/ipset/*.txt /opt/zapret2/ipset/ && \
cp -p $BK/lua/*.lua /opt/zapret2/lua/ && \
/etc/init.d/zapret2 restart && echo ROLLBACK_OK
```

Файлы, которых не было до установки (новые листы/lua из пакета), при ручном
откате останутся — удалите их при желании по списку из `src/`.

## После установки

- Проверьте вкладку Zapret2 в панели: профили и стратегии должны совпадать
  с донором.
- Если на доноре был настроен healthcheck/автоподбор (cron `zhealth`),
  он переносится отдельным пакетом strategy-check.
