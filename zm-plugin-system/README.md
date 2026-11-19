# zm-plugin-system — система манифест-плагинов для Zapret Manager

Добавляет в SPA-панель Zapret Manager (`http://<роутер>:7788`) поддержку плагинов:
новая страница панели собирается из `manifest.json` + `backend.sh`, без написания
JavaScript. Плагины появляются в меню в группе «Плагины».

## Что устанавливается

| Путь | Назначение |
|---|---|
| `view/zapret-manager/plugin.js` | Универсальный рендерер страниц плагинов (SPA :7788 и LuCI) |
| `view/zm-plugins/manager.js` | Страница «Службы → ZM плагины» в LuCI (обёртка над тем же рендерером) |
| `/usr/share/luci/menu.d/luci-app-zm-plugins.json` | Пункт меню LuCI |
| `/usr/sbin/zm-pluginctl` | CLI: install / remove / list / reindex |
| `/usr/share/rpcd/acl.d/luci-app-zm-plugins.json` | Права rpcd: чтение `/etc/zm-plugins/**`, запуск `backend.sh` |
| `/www/zm-plugins/index.json` | Реестр установленных плагинов (генерируется автоматически) |
| Патч `/www/zm/app.js` | Якорь-загрузчик: подмешивает маршруты плагинов до построения меню (ставится один раз, бэкап в `/opt/zapret-manager-luci/backups/`) |

## Установка

```sh
scp -O -r zm-plugin-system root@<роутер>:/tmp/
ssh root@<роутер> 'cd /tmp/zm-plugin-system && sh install-zm-plugins.sh'
```

Режимы установщика:

- `sh install-zm-plugins.sh --check` — только проверка (preflight), ничего не меняет.
- `sh install-zm-plugins.sh --no-example` — не ставить пример-плагин service-probe.
- `sh install-zm-plugins.sh --remove` — полное удаление системы (откат app.js из бэкапа).

После установки пример-плагин «Проба сервисов» доступен в меню: **Плагины → Проба сервисов**.

## Управление плагинами

```sh
zm-pluginctl list                              # список установленных
zm-pluginctl install /tmp/my-plugin            # установить из каталога (manifest.json + backend.sh)
zm-pluginctl install /tmp/my-plugin --no-enable
zm-pluginctl remove my-plugin
zm-pluginctl reindex                           # пересобрать /www/zm-plugins/index.json
```

Плагин — это каталог из двух файлов: `manifest.json` (виджеты страницы) и
`backend.sh` (действия, отвечают JSON). Полная спецификация формата, контракт
backend и пошаговый шаблон — в **PLUGIN_DEV.md** этого пакета. Рабочий пример —
`examples/service-probe/`.

## Ограничения v1.1

- Страницы плагинов: SPA :7788 (все плагины) и LuCI «Службы → ZM плагины» (менеджер).
- Виджет `form` — только текстовые поля (нет выбора из списка, чекбоксов, загрузки файлов).
- Исполнение действий — только на роутере через `backend.sh`.

## Откат

```sh
sh install-zm-plugins.sh --remove
```

Восстанавливает app.js из бэкапа, удаляет рендерер, реестр, ACL и zm-pluginctl.
Каталоги плагинов в `/etc/zm-plugins/` сохраняются (удалите вручную при
необходимости).
