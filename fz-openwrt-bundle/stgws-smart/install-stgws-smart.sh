#!/bin/ash
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
cat > "$TMP/route-smart.sh" <<'ZMEOF_ROUTE_SMART_SH'
#!/bin/ash
# route-smart.sh v2 — rebuild tgws route.conf preferring fronts on stable CF ranges.
#
# Principles (post-review):
# - 'direct' entries and any non-ws lines are preserved verbatim; only ws entries
#   whose current domain is unhealthy get a replacement.
# - All A-records of kws1.<domain> are measured; a healthy IP passes 3/3 TLS
#   handshakes with HTTP < 400. The health quorum counts unique IPs, not domains.
# - Normalized comparison of route tuples: header/date drift never causes a restart.
# - Atomic write in the same filesystem, flock serialization, post-restart
#   verification of the bridge with automatic rollback on failure.
DIR=/etc/stgws
DOMAINS=$DIR/tgws-domains.lst
ROUTE=$DIR/route.conf
LOCK=/var/lock/tgws-route-smart.lock

exec 9>"$LOCK" 2>/dev/null || { echo '{"error":"no lock file"}'; exit 1; }
flock -n 9 || { echo '{"error":"route-smart уже выполняется"}'; exit 1; }

WORK=$(mktemp -d /tmp/routesmart-XXXXXX) || exit 1
trap 'rm -rf "$WORK"' 0

# --- 1. Resolve kws1.<domain> -> all A-records via dns.google -----------------
: > "$WORK/ipmap"     # "domain ip" per line
: > "$WORK/dnsfail"
for D in $(cat "$DOMAINS"); do
  IPS=$(curl -s -m 6 "https://dns.google/resolve?name=kws1.$D&type=A" | jsonfilter -e '@.Answer[@.type=1].data' 2>/dev/null)
  if [ -z "$IPS" ]; then
    echo "$D" >> "$WORK/dnsfail"
    continue
  fi
  for IP in $IPS; do
    case "$IP" in ''|*[!0-9.]*) continue ;; esac
    echo "$D $IP" >> "$WORK/ipmap"
  done
done
[ -s "$WORK/ipmap" ] || { echo '{"error":"не удалось резолвить kws-поддомены"}'; exit 1; }

# --- 2. Measure each unique IP: 3 handshakes, HTTP < 400 every time -----------
: > "$WORK/badips"
for IP in $(awk '{print $2}' "$WORK/ipmap" | sort -u); do
  OK=1
  i=1
  while [ "$i" -le 3 ]; do
    CODE=$(curl -s -o /dev/null --connect-timeout 5 -m 8 -w '%{http_code}' \
      --resolve "www.cloudflare.com:443:$IP" https://www.cloudflare.com/ 2>/dev/null)
    case "$CODE" in
      2*|3*) ;;
      *) OK=0; break ;;
    esac
    i=$((i+1))
  done
  [ "$OK" = 0 ] && echo "$IP" >> "$WORK/badips"
done

# --- 3. Healthy domains; quorum by unique healthy IPs --------------------------
if [ -s "$WORK/badips" ]; then
  awk 'NR==FNR {bad[$1]=1; next} !($2 in bad) {print $1}' "$WORK/badips" "$WORK/ipmap" | sort -u > "$WORK/healthy"
  HIP_N=$(awk 'NR==FNR {bad[$1]=1; next} !($2 in bad) {print $2}' "$WORK/badips" "$WORK/ipmap" | sort -u | wc -l | tr -d ' ')
else
  awk '{print $1}' "$WORK/ipmap" | sort -u > "$WORK/healthy"
  HIP_N=$(awk '{print $2}' "$WORK/ipmap" | sort -u | wc -l | tr -d ' ')
fi
HEALTHY_N=$(wc -l < "$WORK/healthy" | tr -d ' ')
if [ "$HIP_N" -lt 3 ]; then
  printf '{"error":"здоровых диапазонов мало (%s уникальных IP) — карту не трогаю","healthy_ips":%s}\n' "$HIP_N" "$HIP_N"
  exit 1
fi

# --- 4. New map: keep direct/non-ws verbatim; reassign only unhealthy ws ------
awk '!/^#/ && NF >= 2 {print}' "$ROUTE" > "$WORK/oldentries"
: > "$WORK/new"
USED=" "
while read -r DC MODE DOMAIN REST; do
  [ -n "$DC" ] || continue
  if [ "$MODE" != "ws" ] || [ -z "$DOMAIN" ]; then
    # direct entries, media keys, unknown formats — keep byte-identical
    echo "$DC $MODE $DOMAIN $REST" | sed 's/ *$//' >> "$WORK/new"
    continue
  fi
  PICK=""
  if grep -qx "$DOMAIN" "$WORK/healthy"; then
    PICK=$DOMAIN
  else
    while read -r H; do
      case "$USED" in *" $H "*) continue ;; esac
      PICK=$H
      break
    done < "$WORK/healthy"
    [ -n "$PICK" ] || PICK=$(head -1 "$WORK/healthy")
  fi
  USED="$USED$PICK "
  echo "$DC ws $PICK" >> "$WORK/new"
done < "$WORK/oldentries"

# --- 5. Normalized compare: tuples only, no comments/date ---------------------
NORM() { awk '{print $1, $2, $3}' "$1" | sort; }
CHANGED=0
NORM "$WORK/oldentries" > "$WORK/old.norm"
NORM "$WORK/new" > "$WORK/new.norm"
cmp -s "$WORK/old.norm" "$WORK/new.norm" || CHANGED=1

APPLIED=0
if [ "$CHANGED" = 1 ]; then
  # --- 6. Validate, then atomic write in the same FS --------------------------
  # Every DC key from the old map must be present exactly once in the new map.
  VALID=1
  for DC in $(awk '{print $1}' "$WORK/oldentries" | sort -u); do
    [ "$(awk -v d="$DC" '$1==d' "$WORK/new" | wc -l)" = 1 ] || { VALID=0; break; }
  done
  [ -s "$WORK/new" ] || VALID=0
  if [ "$VALID" != 1 ]; then
    echo '{"error":"новая карта неполная — старая сохранена"}'
    exit 1
  fi
  {
    echo '# Карта «дата-центр → путь». Пишет её подбор, читает мост.'
    echo '# Править руками можно, но следующий `tgws pick` перепишет файл целиком.'
    echo "# $(date '+%Y-%m-%d %H:%M') route-smart: домены на нестабильных CF-диапазонах заменены."
    cat "$WORK/new"
  } > "$DIR/.route.conf.new"
  cp -p "$ROUTE" "$ROUTE.auto-bak"
  mv -f "$DIR/.route.conf.new" "$ROUTE"

  # --- 7. Restart and verify the bridge; rollback on failure ------------------
  /etc/init.d/tgws restart >/dev/null 2>&1
  OK=0
  i=0
  while [ "$i" -lt 8 ]; do
    if pgrep -f 'stgws tgws' >/dev/null 2>&1 && \
       stgws tgws-instances --spec "$DIR/spec.json" --state-dir /var/lib/stgws 2>/dev/null | grep -q .; then
      OK=1
      break
    fi
    sleep 1
    i=$((i+1))
  done
  if [ "$OK" != 1 ]; then
    cp -p "$ROUTE.auto-bak" "$ROUTE"
    /etc/init.d/tgws restart >/dev/null 2>&1
    echo '{"error":"мост не поднялся после смены карты — выполнен откат"}'
    exit 1
  fi
  APPLIED=1
fi

MAP=$(awk '$2=="ws" {printf "%s->%s ", $1, $3} $2!="ws" {printf "%s->%s ", $1, $2}' "$WORK/new" | sed 's/ $//')
FLAKY_N=$(wc -l < "$WORK/badips" | tr -d ' ')
DNSFAIL_N=$(wc -l < "$WORK/dnsfail" | tr -d ' ')
printf '{"ok":true,"changed":%s,"applied":%s,"healthy":%s,"healthy_ips":%s,"flaky_ips":%s,"dns_failed":%s,"map":"%s"}\n' \
  "$CHANGED" "$APPLIED" "$HEALTHY_N" "$HIP_N" "$FLAKY_N" "$DNSFAIL_N" "$MAP"
ZMEOF_ROUTE_SMART_SH
cat > "$TMP/tg_a.txt" <<'ZMEOF_TG_A_TXT'
	if [ -f /etc/stgws/smart-map ] && [ -x /etc/stgws/route-smart.sh ]; then
		echo "==> Умная карта: перестраиваю по стабильным диапазонам"
		ash /etc/stgws/route-smart.sh || echo "ОШИБКА: умная карта не применилась — оставлена карта подбора"
	fi
ZMEOF_TG_A_TXT
cat > "$TMP/tg_b.txt" <<'ZMEOF_TG_B_TXT'
do_route_smart() {
	[ -x /etc/stgws/route-smart.sh ] || { echo "ОШИБКА: нет /etc/stgws/route-smart.sh"; return 1; }
	ash /etc/stgws/route-smart.sh || return 1
	echo "==> Карта перестроена по стабильным диапазонам"
}

do_route_save() {
	[ -s /etc/stgws/route.conf ] || { echo '{"error":"карта пуста"}'; return 1; }
	cp -p /etc/stgws/route.conf /etc/stgws/route.conf.custom || { echo '{"error":"не удалось сохранить карту"}'; return 1; }
	echo '{"ok":true}'
}

do_route_restore() {
	[ -s /etc/stgws/route.conf.custom ] || { echo '{"error":"нет сохранённой карты"}'; return 1; }
	cp -p /etc/stgws/route.conf /etc/stgws/.route.conf.pre-restore || { echo '{"error":"не удалось сохранить текущую карту"}'; return 1; }
	cp -p /etc/stgws/route.conf.custom /etc/stgws/route.conf || { echo '{"error":"не удалось восстановить карту"}'; return 1; }
	/etc/init.d/tgws restart >/dev/null 2>&1
	local i=0 ok=0
	while [ "$i" -lt 8 ]; do
		if pgrep -f 'stgws tgws' >/dev/null 2>&1 && 			stgws tgws-instances --spec /etc/stgws/spec.json --state-dir /var/lib/stgws 2>/dev/null | grep -q .; then
			ok=1; break
		fi
		sleep 1; i=$((i+1))
	done
	if [ "$ok" != 1 ]; then
		cp -p /etc/stgws/.route.conf.pre-restore /etc/stgws/route.conf
		/etc/init.d/tgws restart >/dev/null 2>&1
		echo '{"error":"мост не поднялся после восстановления — карта возвращена"}'
		return 1
	fi
	rm -f /etc/stgws/.route.conf.pre-restore
	echo '{"ok":true}'
}

ZMEOF_TG_B_TXT
cat > "$TMP/tg_c.txt" <<'ZMEOF_TG_C_TXT'
		route_smart)    job_start tgws_route_smart do_route_smart ;;
		route_save)     do_route_save ;;
		route_restore)  do_route_restore ;;
		route_auto_on)  : > /etc/stgws/smart-map; echo '{"ok":true}' ;;
		route_auto_off) rm -f /etc/stgws/smart-map; echo '{"ok":true}' ;;
ZMEOF_TG_C_TXT
cat > "$TMP/be_d.txt" <<'ZMEOF_BE_D_TXT'
	local saved=false smart=false
	[ -s /etc/stgws/route.conf.custom ] && saved=true
	[ -f /etc/stgws/smart-map ] && smart=true
	printf '{"installed":"%s","running":%s,"version":"%s","latest":"%s","newer":%s,"domain":"%s","route_saved":%s,"smart_auto":%s}\n' "$installed" "$running" "$(esc "$ver")" "$(esc "$latest")" "$(_tg_newer "$ver" "$latest" && echo true || echo false)" "$(esc "$domain")" "$saved" "$smart"
ZMEOF_BE_D_TXT
cat > "$TMP/js_e.txt" <<'ZMEOF_JS_E_TXT'
				actions.push(E('button', {
					'class': 'cbi-button',
					'title': 'Перестроить карту дата-центров по стабильным диапазонам Cloudflare',
					'click': function() { doTgwsAction('route_smart'); }
				}, 'Умная карта'));
				actions.push(E('button', {
					'class': 'cbi-button',
					'title': 'Сохранить текущую карту как эталон',
					'click': function() { doTgwsAction('route_save'); }
				}, 'Сохранить карту'));
				if (d.route_saved) {
					actions.push(E('button', {
						'class': 'cbi-button',
						'title': 'Вернуть сохранённую карту и перезапустить',
						'click': function() { doTgwsAction('route_restore'); }
					}, 'Восстановить карту'));
				}
				actions.push(E('button', {
					'class': 'cbi-button' + (d.smart_auto ? ' cbi-button-positive' : ''),
					'title': 'После подбора домена автоматически перестраивать карту по стабильным диапазонам',
					'click': function() { doTgwsAction(d.smart_auto ? 'route_auto_off' : 'route_auto_on'); }
				}, d.smart_auto ? 'Авто-карта: вкл' : 'Авто-карта: выкл'));
ZMEOF_JS_E_TXT
cat > "$TMP/js_f1.txt" <<'ZMEOF_JS_F1_TXT'
				: action === 'route_smart' ? 'tgws_route_smart'
ZMEOF_JS_F1_TXT
cat > "$TMP/js_f2.txt" <<'ZMEOF_JS_F2_TXT'
				: action === 'route_smart' ? 'Перестраиваем карту sTGWS'
ZMEOF_JS_F2_TXT
cat > "$TMP/js_g.txt" <<'ZMEOF_JS_G_TXT'
					if (res.ok) {
						zm.toast('Готово', 'info');
						zm.tgwsStatus().then(function(d) { tgwsData = d; renderTgws(d); });
					}
ZMEOF_JS_G_TXT

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
