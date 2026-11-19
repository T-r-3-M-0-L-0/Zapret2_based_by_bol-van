#!/bin/ash
# install-zapret2-presets.sh — страница «Zapret2 конструктор» внутри Zapret-Manager.
# Аддитивно: свой view + ACL + check.sh; единственная правка чужого файла —
# один пункт меню в luci-app-zapret-manager.json (с бэкапом и валидацией JSON).
# Режимы: без аргументов — установка; --check — диагностика; --remove — удаление.
set -u

SRC="$(cd "$(dirname "$0")" && pwd)"
ZM_DIR="/opt/zapret-manager-luci"
VIEW_DST="/www/luci-static/resources/view/zapret-manager/presets.js"
MENU="/usr/share/luci/menu.d/luci-app-zapret-manager.json"
LEGACY_MENU="/usr/share/luci/menu.d/luci-app-zapret2-presets.json"
LEGACY_VIEW="/www/luci-static/resources/view/zapret2-presets"
ACL_DST="/usr/share/rpcd/acl.d/luci-app-zapret2-presets.json"
PRESETS_DIR="/etc/zapret2-presets"
TS="$(date +%Y%m%d%H%M%S)"
BK_DIR="$ZM_DIR/backups/presets-menu-$TS"

MENU_ENTRY='	"admin/services/zapret-manager/presets": {
		"title": "Zapret2 конструктор",
		"order": 28,
		"action": { "type": "view", "path": "zapret-manager/presets" }
	}
}'

# SPA-панель (:7788): маршрут в ROUTES файла app.js
APP_JS="/www/zm/app.js"
APP_HTML="/www/zm-webui.html"
APP_ANCHOR="	{ id: 'zapret2', title: 'Zapret2', sub: 'Установка и управление', icon: 'bolt', group: 'Обход блокировок', dot: 'zapret2' },"
APP_ROUTE="	{ id: 'presets', title: 'Zapret2 конструктор', sub: 'Сборка набора стратегий и пресеты', icon: 'shield', group: 'Обход блокировок' },"

say() { echo "$*"; }
fail() { say "FAIL: $*"; exit 1; }

MODE="install"
[ "${1:-}" = "--check" ] && MODE="check"
[ "${1:-}" = "--remove" ] && MODE="remove"

[ -f /etc/config/zapret2 ] || fail "нет /etc/config/zapret2 — zapret2 не установлен"
[ -f "$MENU" ] || fail "нет $MENU — Zapret-Manager не найден"

menu_patched() { grep -q 'zapret-manager/presets' "$MENU"; }

patch_menu() {
	menu_patched && { say "..  меню: пункт уже есть"; return 0; }
	# структура: последняя строка '}', перед ней закрытие последнего пункта '\t}'
	local last prev
	last="$(tail -n1 "$MENU" | tr -d ' \t')"
	[ "$last" = "}" ] || { say "!!  меню: неожиданный формат конца файла — пропускаю (view всё равно установится)"; return 1; }
	mkdir -p "$BK_DIR"
	cp -p "$MENU" "$BK_DIR/luci-app-zapret-manager.json" || fail "бэкап меню"
	sed '$d' "$MENU" > "$TMPM" || fail "menu: sed \$d"
	sed -i '$ s/$/,/' "$TMPM" || fail "menu: запятая"
	printf '%s\n' "$MENU_ENTRY" >> "$TMPM"
	if ! jsonfilter -i "$TMPM" -e '$["admin/services/zapret-manager/presets"]["title"]' >/dev/null 2>&1; then
		say "!!  меню: JSON после патча невалиден — откат, файл не тронут"
		return 1
	fi
	cat "$TMPM" > "$MENU" || fail "menu: запись"
	say "OK  меню: добавлен пункт «Zapret2 конструктор» (бэкап: $BK_DIR)"
}

unpatch_menu() {
	if ! menu_patched; then say "..  меню: нашего пункта нет"; return 0; fi
	local bk
	bk="$(ls -dt $ZM_DIR/backups/presets-menu-* 2>/dev/null | head -1)"
	if [ -n "$bk" ] && [ -f "$bk/luci-app-zapret-manager.json" ]; then
		cp -p "$bk/luci-app-zapret-manager.json" "$MENU" && say "OK  меню: восстановлено из $bk"
	else
		say "!!  меню: бэкап не найден — удалите пункт admin/services/zapret-manager/presets из $MENU вручную"
	fi
}

app_patched() { [ -f "$APP_JS" ] && grep -qF "id: 'presets'," "$APP_JS"; }

patch_appjs() {
	[ -f "$APP_JS" ] || { say "..  app.js не найден — SPA-панель (:7788) отсутствует, пропускаю"; return 0; }
	app_patched && { say "..  app.js: маршрут presets уже есть"; return 0; }
	[ "$(grep -cF "$APP_ANCHOR" "$APP_JS")" = "1" ] || { say "!!  app.js: якорь ROUTES не найден/не уникален — файл не тронут (LuCI-страница работает и без этого)"; return 1; }
	mkdir -p "$BK_DIR"
	cp -p "$APP_JS" "$BK_DIR/app.js" || fail "бэкап app.js"
	local before
	before="$(wc -l < "$APP_JS")"
	awk -v a="$APP_ANCHOR" -v r="$APP_ROUTE" '
		{ print }
		!done && index($0, a) { print r; done=1 }
	' "$APP_JS" > "$TMPA" || { say "!!  app.js: ошибка вставки"; return 1; }
	[ "$(grep -cF "$APP_ROUTE" "$TMPA")" = "1" ] || { say "!!  app.js: маршрут не встал"; return 1; }
	[ "$(wc -l < "$TMPA")" = "$((before + 1))" ] || { say "!!  app.js: число строк изменилось не на 1 — отклонено"; return 1; }
	# cache-bust: новый BUILD, чтобы браузеры подтянули свежий app.js
	sed -i "s/^var BUILD = '[0-9]*';/var BUILD = '$TS';/" "$TMPA"
	cat "$TMPA" > "$APP_JS" || fail "app.js: запись"
	# и ?v= в загрузчике
	[ -f "$APP_HTML" ] && sed -i "s|/zm/app\.js?v=[0-9]*|/zm/app.js?v=$TS|" "$APP_HTML"
	say "OK  app.js: маршрут «Zapret2 конструктор» добавлен в SPA (бэкап: $BK_DIR)"
}

unpatch_appjs() {
	[ -f "$APP_JS" ] || return 0
	app_patched || { say "..  app.js: нашего маршрута нет"; return 0; }
	[ "$(grep -cF "$APP_ROUTE" "$APP_JS")" = "1" ] || { say "!!  app.js: маршрут не уникален — удалите вручную"; return 1; }
	grep -vF "$APP_ROUTE" "$APP_JS" > "$TMPA" && cat "$TMPA" > "$APP_JS" && say "OK  app.js: маршрут presets удалён"
}

TMPM="/tmp/zm-menu.$$"
TMPA="/tmp/zm-appjs.$$"
trap 'rm -f "$TMPM" "$TMPA"' EXIT

if [ "$MODE" = "remove" ]; then
	rm -f "$VIEW_DST" "$ACL_DST" "$LEGACY_MENU"
	rm -rf "$LEGACY_VIEW"
	unpatch_menu
	unpatch_appjs
	/etc/init.d/rpcd restart >/dev/null 2>&1
	say "OK: страница удалена (пресеты и check.sh в $PRESETS_DIR оставлены)"
	exit 0
fi

if [ "$MODE" = "check" ]; then
	rc=0
	[ -f "$SRC/files/www/luci-static/resources/view/zapret-manager/presets.js" ] && say "OK  пакет: presets.js" || { say "!!  пакет: нет presets.js"; rc=1; }
	[ -f "$SRC/files/usr/share/rpcd/acl.d/luci-app-zapret2-presets.json" ] && say "OK  пакет: acl" || { say "!!  пакет: нет acl.json"; rc=1; }
	[ -f "$SRC/files/etc/zapret2-presets/check.sh" ] && say "OK  пакет: check.sh" || { say "!!  пакет: нет check.sh"; rc=1; }
	if menu_patched; then say "OK  меню LuCI: пункт «Zapret2 конструктор» на месте"
	elif [ -f "$LEGACY_MENU" ]; then say "..  меню LuCI: стоит старый отдельный пункт — будет заменён на пункт внутри Zapret Manager"
	else say "..  меню LuCI: пункт будет добавлен"; fi
	if [ -f "$APP_JS" ]; then
		if app_patched; then say "OK  SPA (:7788): маршрут presets на месте"
		elif grep -qF "$APP_ANCHOR" "$APP_JS"; then say "..  SPA (:7788): маршрут будет добавлен в ROUTES"
		else say "!!  SPA (:7788): якорь ROUTES не найден — app.js не будет тронут"; fi
	else
		say "..  SPA (:7788): app.js не найден, панель отсутствует"
	fi
	grep -q '^config strategy' /etc/config/zapret2 && say "OK  стратегий в конфиге: $(grep -c '^config strategy' /etc/config/zapret2)" || { say "!!  в конфиге нет стратегий"; rc=1; }
	exit $rc
fi

# --- install ---
mkdir -p "$PRESETS_DIR" || fail "нет доступа к $PRESETS_DIR"
cp "$SRC/files/www/luci-static/resources/view/zapret-manager/presets.js" "$VIEW_DST" || fail "копирование presets.js"
cp "$SRC/files/usr/share/rpcd/acl.d/luci-app-zapret2-presets.json" "$ACL_DST" || fail "копирование acl"
cp "$SRC/files/etc/zapret2-presets/check.sh" "$PRESETS_DIR/check.sh" && chmod +x "$PRESETS_DIR/check.sh" || fail "копирование check.sh"
say "OK  файлы: view + acl + check.sh"

# миграция с v1: убрать отдельный пункт меню и старый каталог view
[ -f "$LEGACY_MENU" ] && { rm -f "$LEGACY_MENU"; say "OK  удалён старый отдельный пункт меню"; }
[ -d "$LEGACY_VIEW" ] && { rm -rf "$LEGACY_VIEW"; say "OK  удалён старый каталог view"; }

patch_menu
patch_appjs

# штатные пресеты — только если своих ещё нет
for p in "$SRC"/presets/*.txt; do
	[ -f "$p" ] || continue
	base="$(basename "$p")"
	if [ ! -f "$PRESETS_DIR/$base" ]; then
		cp "$p" "$PRESETS_DIR/$base" && say "OK  пресет: $base"
	else
		say "..  пресет $base уже есть — не трогаю"
	fi
done

/etc/init.d/rpcd restart >/dev/null 2>&1
say "---"
say "Готово. Страница: Службы → Zapret Manager → Zapret2 конструктор (Ctrl+F5)."
say "Удаление: sh install-zapret2-presets.sh --remove"
