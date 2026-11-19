# stgws-smart — умная карта sTGWS для Zapret-Manager

Пакет добавляет в карточку sTGWS (Службы → Zapret Manager → tgproxy) управление
картой «дата-центр → домен»:

- **Умная карта** — перестраивает route.conf по стабильным диапазонам Cloudflare:
  резолвит `kws1.<домен>` всех фронтов, 3 TLS-handshake на каждый уникальный IP
  (SNI www.cloudflare.com), любой сбой = диапазон нестабилен. Каждый ДЦ сохраняет
  свой домен, если он здоров, иначе получает следующий здоровый.
  Бэкап `route.conf.auto-bak` + перезапуск моста с верификацией.
- **Сохранить карту / Восстановить карту** — эталон `route.conf.custom`.
  Восстановление проверяет, что мост поднялся; если нет — возвращает прежнюю карту.
- **Авто-карта вкл/выкл** — флаг `/etc/stgws/smart-map`: когда включено, штатный
  «Подобрать новый домен» после pick'а сам вызывает умную карту.

Зачем: фронты tg-ws-proxy сидят на двух CF-диапазонах; на части из них
(наблюдалось на 188.114.96/97.1) DPI рвёт ~50% TLS-handshake — сообщения идут,
медиа виснет. `tgws pick` меряет успех рукопожатия, а не стабильность, поэтому
смена домена не помогала.

## Установка

Требуется: OpenWrt с Zapret-Manager и установленный sTGWS.

```sh
sh install-stgws-smart.sh --check   # диагностика без изменений
sh install-stgws-smart.sh           # установка
```

## Как работает установщик (v2, универсальный)

Установщик **не подменяет файлы панели** и не привязан к версии Zapret-Manager:
он вставляет свои блоки по текстовым якорям прямо в существующие файлы.

- `--check` показывает по каждому файлу: `READY` (якоря найдены, можно патчить),
  `SKIP` (уже пропатчен или версия панели отличается — файл не будет тронут).
- Установка идемпотентна: повторный запуск безопасен, пропатченные файлы
  пропускаются по маркерам.
- Если на другой версии панели якорь не найден — файл остаётся нетронутым,
  остальные файлы патчатся независимо (all-or-nothing в пределах одного файла).
- Перед изменением каждый файл копируется в бэкап
  `/opt/zapret-manager-luci/backups/stgws-smart-<дата>/`.
- Shell-файлы после патча проверяются `ash -n` до записи на место.

Проверено: прогон на эталонных оригиналах воспроизводит рабочее состояние
бит-в-бит (md5 совпадают).

## Что куда ставится

| Что | Куда | Как |
|---|---|---|
| хук умной карты + функции `do_route_*` + ветки `route_smart/save/restore/auto_*` | `/opt/zapret-manager-luci/mod/tg.sh` | вставка по якорям |
| поля `route_saved`, `smart_auto` в `tgws_status` | `/opt/zapret-manager-luci/backend.sh` | замена одной строки printf по якорю |
| кнопки «Умная карта», «Сохранить/Восстановить карту», «Авто-карта» | `/www/luci-static/resources/view/zapret-manager/tgproxy.js` | вставки по якорям |
| движок умной карты | `/etc/stgws/route-smart.sh` | копирование |

## Откат

```sh
BK=/opt/zapret-manager-luci/backups/stgws-smart-<дата>
cp -p $BK/_opt_zapret-manager-luci_mod_tg.sh /opt/zapret-manager-luci/mod/tg.sh
cp -p $BK/_opt_zapret-manager-luci_backend.sh /opt/zapret-manager-luci/backend.sh
cp -p $BK/_www_luci-static_resources_view_zapret-manager_tgproxy.js \
  /www/luci-static/resources/view/zapret-manager/tgproxy.js
rm -f /etc/stgws/route-smart.sh /etc/stgws/smart-map
/etc/init.d/rpcd restart
```

## Обновление панели Zapret-Manager

После обновления панели пакет нужно ставить заново: сначала `--check`.
Если все файлы `READY` — ставьте. Если какой-то файл `SKIP` по якорям —
сообщите автору пакета: нужна адаптация якорей под новую версию.

## Для разработчика

- `files/` — эталонные пропатченные файлы (источник блоков вставок).
- `patches/` — извлечённые блоки вставок (генерируются из `files/`).
- `gen_installer.py` — пересборка `install-stgws-smart.sh` из `files/`:
  `python gen_installer.py`.
