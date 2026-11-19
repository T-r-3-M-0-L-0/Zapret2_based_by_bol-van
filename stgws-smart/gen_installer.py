# -*- coding: utf-8 -*-
# Генератор install-stgws-smart.sh v2 — универсальный anchor-based патчер.
import os

BASE = r'C:\fZapret2\stgws-smart'

def rd(p):
    with open(os.path.join(BASE, p), encoding='utf-8') as f:
        return f.read()

names = ['tg_a.txt', 'tg_b.txt', 'tg_c.txt', 'be_d.txt',
         'js_e.txt', 'js_f1.txt', 'js_f2.txt', 'js_g.txt']
patches = {n: rd('patches/' + n) for n in names}
route_smart = rd('files/route-smart.sh')

def heredoc(fname, content):
    tag = 'ZMEOF_' + fname.replace('.', '_').replace('-', '_').upper()
    assert tag not in content, fname
    assert content.endswith('\n'), fname
    return 'cat > "$TMP/%s" <<\'%s\'\n%s%s\n' % (fname, tag, content, tag)

hdr = r'''#!/bin/ash
# install-stgws-smart.sh v2 — универсальный патчер sTGWS smart-map для Zapret-Manager
# Не подменяет файлы панели: вставляет аддитивные блоки по текстовым якорям.
# Идемпотентен (маркеры), all-or-nothing на файл, бэкап + запись, ручной откат из бэкапа.
# Режимы: без аргументов — установка; --check — только диагностика.
set -u

ZM_DIR="${ZM_DIR:-/opt/zapret-manager-luci}"
TG_SH="${TG_SH:-$ZM_DIR/mod/tg.sh}"
BACKEND="${BACKEND:-$ZM_DIR/backend.sh}"
TGPROXY="${TGPROXY:-/www/luci-static/resources/view/zapret-manager/tgproxy.js}"
STGWS_DIR="${STGWS_DIR:-/etc/stgws}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

TS="$(date +%Y%m%d%H%M%S)"
BK_DIR="$ZM_DIR/backups/stgws-smart-$TS"
TMP="/tmp/stgws-smart.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

say() { echo "$*"; }
fail() { say "FAIL: $*"; exit 1; }

# --- preflight окружения ---
[ -f "$TG_SH" ] || fail "нет $TG_SH — Zapret-Manager не найден"
[ -f "$BACKEND" ] || fail "нет $BACKEND"
[ -f "$TGPROXY" ] || fail "нет $TGPROXY"
if [ ! -x /usr/sbin/stgws ] || [ ! -f /etc/init.d/tgws ]; then
	say "ВНИМАНИЕ: sTGWS не установлен (нет /usr/sbin/stgws или /etc/init.d/tgws)."
	say "Сначала установите sTGWS из панели Zapret-Manager, затем повторите."
	exit 1
fi

# --- материалы патчей ---
'''

body = [heredoc('route-smart.sh', route_smart)]
for n in names:
    body.append(heredoc(n, patches[n]))

footer = r'''
# --- примитивы ---
have_marker() { grep -qF "$2" "$1" 2>/dev/null; }
have_anchor() { grep -qF "$2" "$1" 2>/dev/null; }

# ins_after SRC DST ANCHOR INS_FILE
ins_after() {
	awk -v a="$3" -v f="$4" '
		{ print }
		!done && index($0, a) { while ((getline l < f) > 0) print l; done=1 }
	' "$1" > "$2" || return 1
	grep -qF "$(head -n1 "$4")" "$2"
}

# rep_line SRC DST ANCHOR INS_FILE — заменить строку с якорем на блок
rep_line() {
	awk -v a="$3" -v f="$4" '
		!done && index($0, a) { while ((getline l < f) > 0) print l; done=1; next }
		{ print }
	' "$1" > "$2" || return 1
	grep -qF "$(head -n1 "$4")" "$2"
}

# ins_after_prev SRC DST ANCHOR PREV_SUBSTR INS_FILE
ins_after_prev() {
	awk -v a="$3" -v p="$4" -v f="$5" '
		{ print }
		!done && index($0, a) && index(prev, p) { while ((getline l < f) > 0) print l; done=1 }
		{ prev = $0 }
	' "$1" > "$2" || return 1
	grep -qF "$(head -n1 "$5")" "$2"
}

backup_file() {
	mkdir -p "$BK_DIR"
	cp -p "$1" "$BK_DIR/$(echo "$1" | tr '/' '_')" || fail "не удалось сделать бэкап $1"
}

RESULT=""

patch_tg_sh() {
	local f="$TG_SH" out="$TMP/tg.sh.new"
	if have_marker "$f" 'do_route_smart() {'; then
		say "SKIP  tg.sh — уже пропатчен (маркер найден)"; return 0
	fi
	local miss=""
	have_anchor "$f" 'echo "==> Новый домен: $domain"' || miss="$miss domain-hook"
	have_anchor "$f" 'tgws_action() {' || miss="$miss tgws_action"
	have_anchor "$f" 'reconfigure)    job_start tgws_reconfigure do_tgws_reconfigure ;;' || miss="$miss case-reconfigure"
	if [ -n "$miss" ]; then
		say "SKIP  tg.sh — якоря не найдены:$miss (файл не тронут, версия панели отличается)"; return 0
	fi
	[ "$CHECK_ONLY" = 1 ] && { say "READY tg.sh — все якоря на месте, можно патчить"; return 0; }
	backup_file "$f"
	ins_after "$f" "$out" 'echo "==> Новый домен: $domain"' "$TMP/tg_a.txt" \
		|| { say "FAIL  tg.sh — вставка хука домена"; return 1; }
	awk -v a='tgws_action() {' -v f="$TMP/tg_b.txt" '
		!done && index($0, a) { while ((getline l < f) > 0) print l; done=1 }
		{ print }
	' "$out" > "$out.2" && mv "$out.2" "$out" || { say "FAIL  tg.sh — вставка функций"; return 1; }
	grep -qF 'do_route_smart() {' "$out" || { say "FAIL  tg.sh — функции не встали"; return 1; }
	ins_after "$out" "$out.2" 'reconfigure)    job_start tgws_reconfigure do_tgws_reconfigure ;;' "$TMP/tg_c.txt" \
		&& mv "$out.2" "$out" || { say "FAIL  tg.sh — вставка веток case"; return 1; }
	ash -n "$out" || { say "FAIL  tg.sh — синтаксис после патча"; return 1; }
	cat "$out" > "$f" || { say "FAIL  tg.sh — запись"; return 1; }
	say "OK    tg.sh — пропатчен"
	RESULT="$RESULT tg.sh"
}

patch_backend() {
	local f="$BACKEND" out="$TMP/backend.sh.new"
	if have_marker "$f" 'route_saved'; then
		say "SKIP  backend.sh — уже пропатчен"; return 0
	fi
	local ANCH='printf '\''{"installed":"%s","running":%s,"version":"%s","latest":"%s","newer":%s,"domain":"%s"}'
	if ! have_anchor "$f" "$ANCH"; then
		say "SKIP  backend.sh — якорь tgws_status не найден (файл не тронут)"; return 0
	fi
	[ "$CHECK_ONLY" = 1 ] && { say "READY backend.sh — можно патчить"; return 0; }
	backup_file "$f"
	rep_line "$f" "$out" "$ANCH" "$TMP/be_d.txt" \
		|| { say "FAIL  backend.sh — замена printf"; return 1; }
	ash -n "$out" || { say "FAIL  backend.sh — синтаксис после патча"; return 1; }
	cat "$out" > "$f" || { say "FAIL  backend.sh — запись"; return 1; }
	say "OK    backend.sh — пропатчен"
	RESULT="$RESULT backend.sh"
}

patch_tgproxy() {
	local f="$TGPROXY" out="$TMP/tgproxy.js.new"
	if have_marker "$f" "'route_smart'"; then
		say "SKIP  tgproxy.js — уже пропатчен"; return 0
	fi
	local miss=""
	have_anchor "$f" "}, 'Подобрать новый домен'));" || miss="$miss btn-reconfigure"
	have_anchor "$f" ": action === 'restart' ? 'tgws_restart'" || miss="$miss job-map"
	have_anchor "$f" ": action === 'restart' ? 'Перезапускаем sTGWS'" || miss="$miss job-label"
	have_anchor "$f" 'tgwsBusy = false;' || miss="$miss busy"
	if [ -n "$miss" ]; then
		say "SKIP  tgproxy.js — якоря не найдены:$miss (файл не тронут)"; return 0
	fi
	[ "$CHECK_ONLY" = 1 ] && { say "READY tgproxy.js — можно патчить"; return 0; }
	backup_file "$f"
	ins_after "$f" "$out" "}, 'Подобрать новый домен'));" "$TMP/js_e.txt" \
		|| { say "FAIL  tgproxy.js — кнопки"; return 1; }
	ins_after "$out" "$out.2" ": action === 'restart' ? 'tgws_restart'" "$TMP/js_f1.txt" \
		&& mv "$out.2" "$out" || { say "FAIL  tgproxy.js — job-map"; return 1; }
	ins_after "$out" "$out.2" ": action === 'restart' ? 'Перезапускаем sTGWS'" "$TMP/js_f2.txt" \
		&& mv "$out.2" "$out" || { say "FAIL  tgproxy.js — job-label"; return 1; }
	ins_after_prev "$out" "$out.2" 'tgwsBusy = false;' '} else {' "$TMP/js_g.txt" \
		&& mv "$out.2" "$out" || { say "FAIL  tgproxy.js — обновление статуса"; return 1; }
	cat "$out" > "$f" || { say "FAIL  tgproxy.js — запись"; return 1; }
	say "OK    tgproxy.js — пропатчен"
	RESULT="$RESULT tgproxy.js"
}

deploy_route_smart() {
	[ "$CHECK_ONLY" = 1 ] && { say "READY route-smart.sh — будет установлен в $STGWS_DIR"; return 0; }
	mkdir -p "$STGWS_DIR" || { say "FAIL  route-smart.sh — нет $STGWS_DIR"; return 1; }
	cp "$TMP/route-smart.sh" "$STGWS_DIR/route-smart.sh" && chmod +x "$STGWS_DIR/route-smart.sh" \
		|| { say "FAIL  route-smart.sh — установка"; return 1; }
	say "OK    route-smart.sh → $STGWS_DIR/route-smart.sh"
	RESULT="$RESULT route-smart.sh"
}

patch_tg_sh
patch_backend
patch_tgproxy
deploy_route_smart

if [ "$CHECK_ONLY" = 1 ]; then
	say "---"
	say "Режим диагностики: файлы не изменялись."
	exit 0
fi

say "---"
if [ -d "$BK_DIR" ]; then
	say "Бэкапы: $BK_DIR"
	say "Откат: скопируйте нужный файл обратно, напр.:"
	say "  cp $BK_DIR/_opt_zapret-manager-luci_mod_tg.sh $TG_SH"
fi
if [ -n "$RESULT" ]; then
	say "Изменено:$RESULT"
	say "Перезапустите rpcd для обновления LuCI: /etc/init.d/rpcd restart"
else
	say "Изменений не потребовалось."
fi
'''

script = hdr + ''.join(body) + footer
out = os.path.join(BASE, 'install-stgws-smart.sh')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write(script)
print('written', out, len(script), 'bytes')
