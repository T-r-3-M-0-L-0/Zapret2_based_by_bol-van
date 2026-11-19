#!/bin/ash
# install-zm-plugins.sh — система манифест-плагинов для Zapret Manager (SPA :7788).
# Что делает:
#   1) ставит универсальный рендерер view/zapret-manager/plugin.js;
#   2) ставит менеджер /usr/sbin/zm-pluginctl и ACL luci-app-zm-plugins;
#   3) патчит /www/zm/app.js: загрузчик маршрутов из /zm-plugins/index.json
#      (два якоря, бэкап, строгие проверки — иначе файл не трогается);
#   4) по желанию ставит пример-плагин service-probe.
# Режимы: --check | --remove | --no-example
set -u

SRC="$(cd "$(dirname "$0")" && pwd)"
ZM_DIR="/opt/zapret-manager-luci"
APP_JS="/www/zm/app.js"
APP_HTML="/www/zm-webui.html"
VIEW_DST="/www/luci-static/resources/view/zapret-manager/plugin.js"
ACL_DST="/usr/share/rpcd/acl.d/luci-app-zm-plugins.json"
CTL_DST="/usr/sbin/zm-pluginctl"
PLUG_DIR="/etc/zm-plugins"
TS="$(date +%Y%m%d%H%M%S)"
BK_DIR="$ZM_DIR/backups/plugin-system-$TS"

A1='ROUTES.forEach(function (r) { ROUTE_BY_ID[r.id] = r; });'
A2='function startApp() {'
MARKER='zm-plugin-loader'

say() { echo "$*"; }
fail() { say "FAIL: $*"; exit 1; }

MODE="install"
EXAMPLE=1
[ "${1:-}" = "--check" ] && MODE="check"
[ "${1:-}" = "--remove" ] && MODE="remove"
[ "${1:-}" = "--no-example" ] && EXAMPLE=0

[ -f "$APP_JS" ] || fail "нет $APP_JS — SPA-панель не найдена"
command -v jsonfilter >/dev/null || fail "нет jsonfilter"

TMPA="/tmp/zm-appjs.$$"
trap 'rm -f "$TMPA"' EXIT

app_patched() { grep -q "$MARKER" "$APP_JS"; }

LOADER_FILE="$SRC/files/zm-plugin-loader.js"
GUARD='	if (!zmPluginsReady) { zmLoadPlugins(startApp); return; }'

patch_app() {
	app_patched && { say "..  app.js: загрузчик плагинов уже есть"; return 0; }
	[ -f "$LOADER_FILE" ] || fail "нет $LOADER_FILE"
	[ "$(grep -cF "$A1" "$APP_JS")" = "1" ] || { say "!!  app.js: якорь ROUTE_BY_ID не найден/не уникален — файл не тронут"; return 1; }
	[ "$(grep -cF "$A2" "$APP_JS")" = "1" ] || { say "!!  app.js: якорь startApp не найден/не уникален — файл не тронут"; return 1; }
	mkdir -p "$BK_DIR"
	cp -p "$APP_JS" "$BK_DIR/app.js" || fail "бэкап app.js"
	local before after want
	before="$(wc -l < "$APP_JS")"
	want="$(wc -l < "$LOADER_FILE")"
	awk -v a1="$A1" -v a2="$A2" -v f="$LOADER_FILE" -v guard="$GUARD" '
		{ print }
		!d1 && index($0, a1) { while ((getline l < f) > 0) print l; d1=1 }
		!d2 && index($0, a2) { print guard; d2=1 }
		END { if (!d1 || !d2) exit 1 }
	' "$APP_JS" > "$TMPA" || { say "!!  app.js: вставка не выполнена"; return 1; }
	after="$(wc -l < "$TMPA")"
	[ "$after" = "$((before + want + 1))" ] || { say "!!  app.js: число строк $before -> $after (ожидалось +$((want + 1))) — отклонено"; return 1; }
	grep -q "$MARKER" "$TMPA" || { say "!!  app.js: маркер не встал"; return 1; }
	grep -qF "$GUARD" "$TMPA" || { say "!!  app.js: guard не встал"; return 1; }
	sed -i "s/^var BUILD = '[0-9]*';/var BUILD = '$TS';/" "$TMPA"
	cat "$TMPA" > "$APP_JS" || fail "app.js: запись"
	[ -f "$APP_HTML" ] && sed -i "s|/zm/app\.js?v=[0-9]*|/zm/app.js?v=$TS|" "$APP_HTML"
	say "OK  app.js: загрузчик плагинов добавлен (бэкап: $BK_DIR)"
}

unpatch_app() {
	app_patched || { say "..  app.js: загрузчика нет"; return 0; }
	local bk
	bk="$(ls -dt $ZM_DIR/backups/plugin-system-* 2>/dev/null | head -1)"
	if [ -n "$bk" ] && [ -f "$bk/app.js" ]; then
		cp -p "$bk/app.js" "$APP_JS" && say "OK  app.js: восстановлен из $bk"
	else
		say "!!  app.js: бэкап не найден — не трогаю (удалите блок zm-plugin-loader вручную)"
	fi
}

if [ "$MODE" = "remove" ]; then
	unpatch_app
	rm -f "$VIEW_DST" "$ACL_DST" "$CTL_DST" \
		/www/luci-static/resources/view/zm-plugins/manager.js \
		/usr/share/luci/menu.d/luci-app-zm-plugins.json
	rmdir /www/luci-static/resources/view/zm-plugins 2>/dev/null
	rm -rf /tmp/luci-modulecache /tmp/luci-indexcache 2>/dev/null
	/etc/init.d/rpcd restart >/dev/null 2>&1
	say "OK: система плагинов удалена (каталог $PLUG_DIR и /www/zm-plugins оставлены)"
	exit 0
fi

if [ "$MODE" = "check" ]; then
	rc=0
	[ -f "$SRC/files/www/luci-static/resources/view/zapret-manager/plugin.js" ] && say "OK  пакет: plugin.js" || { say "!!  пакет: нет plugin.js"; rc=1; }
	[ -f "$SRC/files/usr/sbin/zm-pluginctl" ] && say "OK  пакет: zm-pluginctl" || { say "!!  пакет: нет zm-pluginctl"; rc=1; }
	[ -f "$SRC/files/usr/share/rpcd/acl.d/luci-app-zm-plugins.json" ] && say "OK  пакет: acl" || { say "!!  пакет: нет acl"; rc=1; }
	[ -d "$SRC/examples/service-probe" ] && say "OK  пакет: пример service-probe" || { say "!!  пакет: нет примера"; rc=1; }
	[ -d "$SRC/examples/plugin-manager" ] && say "OK  пакет: менеджер плагинов" || { say "!!  пакет: нет plugin-manager"; rc=1; }
	if app_patched; then say "OK  app.js: загрузчик уже установлен"
	elif [ "$(grep -cF "$A1" "$APP_JS")" = "1" ] && [ "$(grep -cF "$A2" "$APP_JS")" = "1" ]; then say "..  app.js: якоря на месте, можно патчить"
	else say "!!  app.js: якоря не найдены — версия панели отличается"; rc=1; fi
	exit $rc
fi

# --- install ---
cp "$SRC/files/www/luci-static/resources/view/zapret-manager/plugin.js" "$VIEW_DST" || fail "копирование plugin.js"
mkdir -p /www/luci-static/resources/view/zm-plugins
cp "$SRC/files/www/luci-static/resources/view/zm-plugins/manager.js" /www/luci-static/resources/view/zm-plugins/manager.js || fail "копирование manager.js"
cp "$SRC/files/usr/share/rpcd/acl.d/luci-app-zm-plugins.json" "$ACL_DST" || fail "копирование acl"
mkdir -p /usr/share/luci/menu.d
cp "$SRC/files/usr/share/luci/menu.d/luci-app-zm-plugins.json" /usr/share/luci/menu.d/luci-app-zm-plugins.json || fail "копирование menu"
cp "$SRC/files/usr/sbin/zm-pluginctl" "$CTL_DST" && chmod +x "$CTL_DST" || fail "копирование zm-pluginctl"
mkdir -p "$PLUG_DIR" /www/zm-plugins
say "OK  файлы: plugin.js + manager.js (LuCI) + acl + menu + zm-pluginctl"

# пустой индекс, если ещё нет
if [ ! -f /www/zm-plugins/index.json ]; then
	printf '{"plugins":[]}\n' > /www/zm-plugins/index.json
	say "OK  создан пустой /www/zm-plugins/index.json"
fi

patch_app

# встроенные плагины: менеджер + пример
if [ "$EXAMPLE" = 1 ]; then
	for ex in plugin-manager service-probe; do
		if [ -d "$PLUG_DIR/$ex" ]; then
			say "..  плагин $ex уже установлен"
		elif [ -d "$SRC/examples/$ex" ]; then
			"$CTL_DST" install "$SRC/examples/$ex" || say "!!  плагин $ex не установился (не критично)"
		fi
	done
fi

/etc/init.d/rpcd restart >/dev/null 2>&1
rm -rf /tmp/luci-modulecache /tmp/luci-indexcache 2>/dev/null
say "---"
say "Готово. Панель :7788: обновите страницу — в меню появятся плагины из /etc/zm-plugins."
say "LuCI: Службы → ZM плагины (тот же рендерер, страница менеджера плагинов)."
say "Управление: zm-pluginctl list | install <каталог> | remove <id> | reindex"
say "Удаление системы: sh install-zm-plugins.sh --remove"
