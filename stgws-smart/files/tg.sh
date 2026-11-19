_tg_arch_init() {
	[ -n "$TG_ARCH" ] && return 0
	if [ "$PKG" = "opkg" ]; then TG_ARCH="$(opkg print-architecture 2>/dev/null | awk '{print $2}' | tail -n1)"
	else TG_ARCH="$(apk --print-arch 2>/dev/null)"; fi
}

_zm_pkg_fmt() {
	awk '
		{ sub(/\r$/, "") }
		/^Downloading / { next }
		/^Updated list of available packages in / { n = $0; sub(/.*\//, "", n); print "     · обновлён список: " n; next }
		/^Installing [^ ]+ \(/ { v = $3; gsub(/[()]/, "", v); print "     · ставим " $2 " " v; next }
		/^Upgrading [^ ]+ / { print "     · обновляем " $2; next }
		/^Configuring / { n = $2; sub(/\.$/, "", n); print "     · настраиваем " n; next }
		/^Removing package / { print "     · удаляем " $3; next }
		/^Package .* is up to date/ { print "     · " $2 " уже стоит последней версии"; next }
		/^\([0-9]+\/[0-9]+\) Installing / { v = $4; gsub(/[()]/, "", v); print "     · ставим " $3 " " v; next }
		/^\([0-9]+\/[0-9]+\) Upgrading / { print "     · обновляем " $3; next }
		/^\([0-9]+\/[0-9]+\) (Purging|Deleting) / { print "     · удаляем " $3; next }
		/^OK: [0-9]+ distinct packages available/ { print "     · доступно пакетов: " $2; next }
		/^fetch / { next }
		/ubus call service delete .*Not found/ { next }
		/(write error|[Ww]rite error): [Bb]roken pipe|^[^ ]*: [Bb]roken pipe$/ { next }
		/linuxfw: clear ip6?tables: exec: "ip6?tables": executable file not found/ { next }
		/router: enumerating tailscale0 addresses for cleanup failed/ { next }
		/^steer: / && /apk database|Resource temporarily unavailable/ { if (!stlk++) print "     · плагины ядра steer поставим сразу после пакета"; next }
		/^  [A-Za-z0-9][^ ]*-[0-9][^ ]*:$/ { l = $0; sub(/^ +/, "", l); sub(/:$/, "", l); if (!seen[l]++) print "     ! пакет " l; next }
		/[Ee]rror|ERROR|Collected errors|^ \* |[Uu]nknown package|not found|No such|unable|cannot|failed|Failed|unsatisfiable|breaks:/ { l = $0; sub(/^[ *]+/, "", l); if (l != "" && !seen[l]++) print "     ! " l; next }
	'
}

_zm_pkg_update() {
	local try=1 rc t0 bad h
	h="$(_mirror_host)"
	while :; do
		t0="$(date +%s)"
		echo "   → Скачиваем свежий список пакетов из репозитория"
		_zm_run 150 $PKG_UPD > "/tmp/zm-pkg.$$" 2>&1
		rc=$?
		_zm_pkg_fmt < "/tmp/zm-pkg.$$"
		bad=""; [ -n "$h" ] && _mirror_upd_bad "/tmp/zm-pkg.$$" "$h" && bad=1
		rm -f "/tmp/zm-pkg.$$"
		if [ "$rc" = 0 ] && [ -z "$bad" ]; then
			echo "   ✓ Список пакетов обновлён за $(( $(date +%s) - t0 )) с"
			return 0
		fi
		_zm_pkg_unlock
		[ "$try" -ge 2 ] && break
		_zm_dns_ok "$(h="${h:-downloads.openwrt.org}"; echo "${h%%/*}")" || _zm_net_heal
		echo "   ↻ $([ "$rc" = 0 ] && echo "Обновился не полностью" || echo "Не получилось") — пробуем ещё раз"
		try=$((try + 1))
		sleep 3
	done
	if { [ -n "$bad" ] || [ "$rc" != 0 ]; } && [ -n "$h" ]; then
		if [ -n "$bad" ] || ! _mirror_probe "$h" "$(_mirror_feed1)" >/dev/null; then
			_mirror_auto && return 0
		fi
	fi
	if [ "$rc" = 0 ]; then
		echo "   ! Список пакетов обновился не полностью — часть репозиториев не ответила"
		return 0
	fi
	echo "   ✗ Список пакетов не обновился — проверьте интернет и доступ к ${h:-downloads.openwrt.org}"
	return 1
}

_zm_pkg_add() {
	local rc names p miss=""
	names="$(_zm_pkg_names "$@")"
	echo "   → Устанавливаем: $names"
	_zm_run 300 $PKG_ADD "$@" > "/tmp/zm-pkg.$$" 2>&1
	rc=$?
	_zm_pkg_fmt < "/tmp/zm-pkg.$$"
	rm -f "/tmp/zm-pkg.$$"
	_zm_pkg_unlock
	if [ "$rc" = 0 ]; then echo "   ✓ Установлено: $names"
	else
		for p; do case "$p" in -*|*/*|*.ipk|*.apk) continue ;; esac; _pkg_is_installed "$p" || miss="$miss${miss:+, }$p"; done
		echo "   ✗ Не установилось: ${miss:-$names}"
	fi
	return $rc
}

_zm_pkg_del() {
	local rc p have="" names ca=0
	_zm_ca_have && ca=1
	for p; do
		case "$p" in -*) have="$have $p"; continue ;; esac
		_pkg_is_installed "$p" && have="$have $p"
	done
	names="$(_zm_pkg_names $have)"
	[ -n "$names" ] || return 0
	echo "   → Удаляем пакеты: $names"
	_zm_run 180 $PKG_DEL $have > "/tmp/zm-pkg.$$" 2>&1
	rc=$?
	_zm_pkg_fmt < "/tmp/zm-pkg.$$"
	rm -f "/tmp/zm-pkg.$$"
	_zm_pkg_unlock
	if [ "$rc" = 0 ]; then echo "   ✓ Удалено: $names"
	else echo "   ✗ Не удалось удалить: $names"; fi
	[ "$ca" = 1 ] && _zm_ca_keep
	return $rc
}

_zm_ca_keep() {
	_zm_ca_have && return 0
	echo "   → Возвращаем корневые сертификаты (ca-bundle) — без них не работает HTTPS"
	_zm_run 180 $PKG_ADD ca-bundle >/dev/null 2>&1 || { _zm_run 150 $PKG_UPD >/dev/null 2>&1; _zm_run 180 $PKG_ADD ca-bundle >/dev/null 2>&1; }
	if _zm_ca_have; then echo "   ✓ Сертификаты на месте"
	else echo "   ! Не удалось поставить ca-bundle — установите его вручную, иначе HTTPS-загрузки не заработают"; fi
	return 0
}

_zm_clean_job() {
	local r n f t
	r="$(ZM_CLEAN_SELF="$1" zm_cleanup job 2>/dev/null)"
	case "$r" in *'"ok":true'*) ;; *) return 0 ;; esac
	n="$(printf '%s' "$r" | sed -n 's/.*"removed":\([0-9]*\).*/\1/p')"
	f="$(printf '%s' "$r" | sed -n 's/.*"freed_flash_kb":\([0-9]*\).*/\1/p')"
	t="$(printf '%s' "$r" | sed -n 's/.*"freed_tmp_kb":\([0-9]*\).*/\1/p')"
	echo "==> Убираем мусор — как кнопка «Очистить мусор»"
	if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
		echo "   ✓ Удалено файлов и папок: $n · освобождено на флеше $(_zm_size_txt $(( ${f:-0} * 1024 ))), в ОЗУ $(_zm_size_txt $(( ${t:-0} * 1024 )))"
	else
		echo "   ✓ Мусора не осталось"
	fi
}

_zm_dns_scrub() {
	local rx="$1" s v ch=0 sc
	for s in $(uci -q show dhcp | sed -n "s/^dhcp\.\([^.=]*\)=dnsmasq\$/\1/p"); do
		sc=0
		for v in $(uci -q get "dhcp.$s.server"); do
			printf '%s' "$v" | grep -qE "$rx" && { uci -q del_list "dhcp.$s.server=$v"; ch=1; sc=1; }
		done
		if [ "$sc" = 1 ] && [ -z "$(uci -q get "dhcp.$s.server" | tr ' ' '\n' | grep -v '^/')" ] && [ "$(uci -q get "dhcp.$s.noresolv")" = 1 ]; then
			uci -q delete "dhcp.$s.noresolv"
		fi
	done
	[ "$ch" = 1 ] && { uci -q commit dhcp; echo "   ✓ Из настроек DNS роутера убраны оставшиеся ссылки"; }
	return 0
}

_zm_net_recover() {
	_rb_say "Проверяем интернет и DNS после удаления"
	/etc/init.d/firewall restart >/dev/null 2>&1
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	if _zm_inet_wait 15; then
		echo "   ✓ Интернет и DNS на роутере работают"
		return 0
	fi
	if _zm_ip_ok; then
		_rb_warn "Связь есть, а DNS роутера не отвечает — перезапускаем службы DNS"
		[ -x /etc/init.d/https-dns-proxy ] && /etc/init.d/https-dns-proxy enabled 2>/dev/null && _zm_run 30 /etc/init.d/https-dns-proxy restart >/dev/null 2>&1
		/etc/init.d/dnsmasq restart >/dev/null 2>&1
		if _zm_inet_wait 20; then
			echo "   ✓ После перезапуска DNS интернет на роутере работает"
			return 0
		fi
	fi
	_rb_warn "Интернет не отвечает — перезапускаем сеть (панель может на полминуты потерять связь с роутером)"
	_zm_run 90 /etc/init.d/network restart >/dev/null 2>&1
	sleep 5
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	if _zm_inet_wait 45; then
		echo "   ✓ После перезапуска сети интернет работает"
		return 0
	fi
	_rb_warn "Интернет так и не появился — перезагрузите роутер"
	_zm_net_why
	return 1
}

reboot_hint_clear() {
	rm -f "$ZM_REBOOT_HINT"
	printf '{"ok":true}\n'
}

_tg_url_ok1() { curl -sfIL --connect-timeout 6 --max-time 15 -o /dev/null "$1" 2>/dev/null; }

_tg_url_ok() {
	local a
	_tg_url_ok1 "$1" && return 0
	case "$1" in *"$ZM_A73"*) ;; *) return 1 ;; esac
	[ "$(_zm_arch)" = "$ZM_A73" ] || return 1
	for a in $ZM_A73_ALTS; do _tg_url_ok1 "$(printf '%s' "$1" | sed "s/$ZM_A73/$a/g")" && return 0; done
	return 1
}

_tg_mt_url() {
	local sfx="$3" raz="ipk" arch
	[ "$PKG" = apk ] && { sfx="r$3"; raz="apk"; }
	arch="$(awk -F\' '/DISTRIB_ARCH/ {print $2}' /etc/openwrt_release)"
	echo "${GH_MAIN}/$TG_REPO_MT/releases/download/$1/tg-ws-proxy_$2-${sfx}_openwrt_${arch}.${raz}"
}

_tg_mt_base() { _ver_norm "${1%%-rev*}"; }

_tg_mt_rev() { case "$1" in *-rev[0-9]*) echo "${1##*-rev}" ;; *) echo 1 ;; esac; }

_tg_tag_mt() {
	local t v r r0
	t="$(_gh_latest_tag "$TG_REPO_MT")"; [ -n "$t" ] || return 1
	v="$(_tg_mt_base "$t")"; r0="$(_tg_mt_rev "$t")"
	for r in $r0 $(for r in 1 2 3; do [ "$r" = "$r0" ] || echo "$r"; done); do
		_tg_url_ok "$(_tg_mt_url "$t" "$v" "$r")" && { echo "$t $r"; return 0; }
	done
	return 1
}

_tg_tag_go() {
	local t f
	f="$(_tg_arch_go)" || return 1
	t="$(_gh_latest_tag "$TG_REPO_GO")"; [ -n "$t" ] || return 1
	_tg_url_ok "${GH_MAIN}/$TG_REPO_GO/releases/download/$t/$f" && echo "$t"
}

_tg_tag_rs() {
	local t f
	f="$(_tg_arch_rs)" || return 1
	t="$(_gh_latest_tag "$TG_REPO_RS")"; [ -n "$t" ] || return 1
	_tg_url_ok "${GH_MAIN}/$TG_REPO_RS/releases/download/$t/$f.tar.gz" && echo "$t"
}

_tg_fresh_tag() {
	local t
	t="$(ZM_VER_FORCE=1 _zm_cached "tg_$1" "_tg_tag_$1")"
	[ -n "$t" ] || t="$(_tg_latest "$1")"
	echo "$t"
}

_zm_pkg_reg_drop() {
	local p="$1"
	if [ "$PKG" = apk ]; then
		[ -f /etc/apk/world ] && sed -i "/^$p\$/d; /^$p[<>=~]/d" /etc/apk/world 2>/dev/null
	else
		rm -f "/usr/lib/opkg/info/$p".* 2>/dev/null
		if [ -f /usr/lib/opkg/status ]; then
			awk -v p="$p" 'BEGIN { RS = ""; ORS = "\n\n" } { split($0, l, "\n"); if (l[1] != "Package: " p) print }' /usr/lib/opkg/status > /usr/lib/opkg/status.zm 2>/dev/null &&
				cat /usr/lib/opkg/status.zm > /usr/lib/opkg/status
			rm -f /usr/lib/opkg/status.zm
		fi
	fi
}

_tg_arch_rs() {
	_tg_arch_init
	case "$TG_ARCH" in
		aarch64*) echo "tg-ws-proxy-aarch64-unknown-linux-musl" ;;
		x86_64) echo "tg-ws-proxy-x86_64-unknown-linux-musl" ;;
		arm*) echo "tg-ws-proxy-armv7-unknown-linux-musleabihf" ;;
		mips64*) return 1 ;;
		mipsel*) echo "tg-ws-proxy-mipsel-unknown-linux-musl" ;;
		mips*) echo "tg-ws-proxy-mips-unknown-linux-musl" ;;
		*) return 1 ;;
	esac
}

_tg_arch_go() {
	_tg_arch_init
	case "$TG_ARCH" in
		aarch64*) echo "tg-ws-proxy-openwrt-aarch64" ;;
		arm*) echo "tg-ws-proxy-openwrt-armv7" ;;
		mips64*) return 1 ;;
		mipsel*) echo "tg-ws-proxy-openwrt-mipsel_24kc" ;;
		mips*) echo "tg-ws-proxy-openwrt-mips_24kc" ;;
		x86_64) echo "tg-ws-proxy-openwrt-x86_64" ;;
		*) return 1 ;;
	esac
}

_tg_rs_off() {
	_tg_rs_uci && [ "$(uci -q get tg-ws-proxy-rs.main.enabled)" != 1 ]
}

_tg_bin_of() { case "$1" in mtproto) echo tg-ws-proxy ;; socks5) echo tg-ws-proxy-go ;; rust) echo tg-ws-proxy-rs ;; esac; }

_tg_port_state() {
	local id="$1" p="$2" sk="$3" o x c
	case "$p" in ''|*[!0-9]*) echo bad; return ;; esac
	[ "${#p}" -le 5 ] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo bad; return; }
	if [ -n "$sk" ]; then
		[ "$p" = "$(_tg_port_of rust)" ] && { echo "tg rust"; return; }
	else
		c="$(_tg_rs_socks_cfg)"
		[ "${c%% *}" = 1 ] && [ "${c##* }" = "$p" ] && { echo "tg rsocks"; return; }
	fi
	for x in mtproto socks5 rust; do
		[ "$x" = "$id" ] && [ -z "$sk" ] && continue
		[ "$x" = rust ] && [ -n "$sk" ] && continue
		[ -x "$(_tg_auto_init "$x")" ] || continue
		[ "$(_tg_port_of "$x")" = "$p" ] && { echo "tg $x"; return; }
	done
	o="$(_zm_port_owner "$p")"
	[ -n "$o" ] || { echo free; return; }
	[ "$o" = "$(_tg_bin_of "$id")" ] && { echo self; return; }
	echo "busy $o"
}

tg_port_check() {
	local st
	st="$(_tg_port_state "$1" "$2" "$3")"
	case "$st" in
		free|self) printf '{"ok":true,"free":true,"self":%s}\n' "$([ "$st" = self ] && echo true || echo false)" ;;
		bad) echo '{"ok":true,"free":false,"why":"порт — число от 1 до 65535"}' ;;
		"tg "*) printf '{"ok":true,"free":false,"why":"этот порт уже у %s"}\n' "$(esc "$(_tg_title_of "${st#tg }")")" ;;
		*) printf '{"ok":true,"free":false,"why":"порт занят программой %s"}\n' "$(esc "${st#busy }")" ;;
	esac
}

_tg_secret_norm() {
	local id="$1" s d
	s="$(printf '%s' "$2" | tr -d ' \t\r\n' | tr 'A-F' 'a-f')"
	case "$s" in *[!0-9a-f]*|'') echo "ключ — только цифры 0-9 и буквы a-f" >&2; return 1 ;; esac
	if [ "$id" = mtproto ]; then
		case "$s" in dd*) [ "${#s}" = 34 ] && s="${s#dd}" ;; esac
		[ "${#s}" = 32 ] || { echo "нужно ровно 32 знака, сейчас ${#s}" >&2; return 1; }
		printf '%s' "$s"; return 0
	fi
	[ "${#s}" = 32 ] && { printf '%s' "$s"; return 0; }
	case "$s" in
		dd*) [ "${#s}" = 34 ] && { printf '%s' "$s"; return 0; } ;;
		ee*)
			[ "${#s}" -ge 38 ] && [ $(( ${#s} % 2 )) = 0 ] || { echo "ключ ee… — это ee, 32 знака ключа и имя сайта в hex" >&2; return 1; }
			d="$(printf '%s' "$s" | cut -c35- | awk '{ h = "0123456789abcdef"; o = ""; for (i = 1; i < length($0); i += 2) o = o sprintf("%c", (index(h, substr($0, i, 1)) - 1) * 16 + index(h, substr($0, i + 1, 1)) - 1); print o }')"
			printf '%s' "$d" | grep -qE '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' && [ "${#d}" -le 253 ] \
				|| { echo "в ключе ee… после 32 знаков должно быть имя сайта в hex (например, google.com)" >&2; return 1; }
			printf '%s' "$s"; return 0 ;;
	esac
	echo "нужно 32 знака (или dd + 32, или ee + 32 + сайт в hex), сейчас ${#s}" >&2
	return 1
}

_tg_bk() {
	local f b d="$JOBS_DIR/tg-conf-bak"
	mkdir -p "$d"
	for f in "$TG_INIT_GO" "$TG_INIT_RS" /etc/init.d/tg-ws-proxy "$TG_CONF_MT" "$TG_SECRET_MT_FILE" "$TG_SECRET_RS_FILE"; do
		b="$d/$(printf '%s' "$f" | tr / _)"
		case "$1" in
			save) rm -f "$b"; [ -f "$f" ] && cp -p "$f" "$b" ;;
			restore) [ -f "$b" ] && cp -p "$b" "$f" ;;
		esac
	done
	[ "$1" = save ] || rm -rf "$d"
	return 0
}

_tg_listening() {
	local t=0
	while [ "$t" -lt 10 ]; do
		sleep 1
		pidof "$(_tg_bin_of "$1")" >/dev/null 2>&1 && _zm_tcp_listen "$2" && return 0
		t=$((t + 1))
	done
	return 1
}

tg_conf_set() {
	local id="$1" port="${2%%:*}" sec="${2#*:}" init was="" st err cur_port cur_sec tls_new=- s d
	case "$id" in mtproto|socks5|rust) ;; *) echo '{"error":"у этого прокси порт и ключ не меняются"}'; return 1 ;; esac
	init="$(_tg_auto_init "$id")"
	[ -f "$init" ] || { echo '{"error":"прокси не установлен"}'; return 1; }
	[ "$id" = rust ] && _tg_rs_uci && { echo '{"error":"Rust установлен пакетом luci-app-tg-ws-proxy-rs — порт и ключ меняются в его настройках"}'; return 1; }
	_tg_auto_busy "$id" && { echo '{"error":"Идёт установка или удаление этого прокси — дождитесь окончания"}'; return 1; }
	[ "$id" = socks5 ] && sec=""
	port="$(printf '%s' "$port" | sed 's/^0*//')"
	st="$(_tg_port_state "$id" "$port")"
	case "$st" in
		free|self) ;;
		bad) echo '{"error":"Порт — число от 1 до 65535"}'; return 1 ;;
		"tg "*) printf '{"error":"Порт %s уже у %s — выберите другой"}\n' "$port" "$(esc "$(_tg_title_of "${st#tg }")")"; return 1 ;;
		*) printf '{"error":"Порт %s уже занят программой %s — выберите другой"}\n' "$port" "$(esc "${st#busy }")"; return 1 ;;
	esac
	if [ "$id" != socks5 ]; then
		s="$(printf '%s' "$sec" | tr -d ' \t\r\n' | tr 'A-F' 'a-f')"
		case "$s" in
			ee*)
				if [ "${#s}" -gt 34 ]; then
					d=""
					case "$s" in *[!0-9a-f]*) ;; *) [ $(( (${#s} - 34) % 2 )) = 0 ] && d="$(_tg_unhex "$(printf '%s' "$s" | cut -c35-)" | tr 'A-Z' 'a-z')" ;; esac
					{ _tg_dom_ok "$d" && ! _tg_ip4_ok "$d"; } || { echo '{"error":"Ключ не подходит: в ключе ee… после 32 знаков должно быть имя сайта в hex (например, google.com)"}'; return 1; }
					_tg_ftls_ok "$id" || { printf '{"error":"Ключ ee… — это FakeTLS, а эта версия %s его не умеет. Обновите прокси или введите ключ из 32 знаков"}\n' "$(esc "$(_tg_title_of "$id")")"; return 1; }
					tls_new="$d"; sec="$(printf '%s' "$s" | cut -c3-34)"
				fi ;;
		esac
		[ "$id" = rust ] && [ "$tls_new" = - ] && case "$(_tg_rs_init_secret)" in ee*) tls_new="$(_tg_tls_of rust)" ;; esac
		sec="$(_tg_secret_norm "$id" "$sec" 2>"$JOBS_DIR/tg_conf.err")" || { err="$(cat "$JOBS_DIR/tg_conf.err")"; rm -f "$JOBS_DIR/tg_conf.err"; printf '{"error":"Ключ не подходит: %s"}\n' "$(esc "$err")"; return 1; }
		rm -f "$JOBS_DIR/tg_conf.err"
	fi
	cur_port="$(_tg_port_of "$id")"
	case "$id" in mtproto) cur_sec="$(_tg_mt_secret)" ;; rust) cur_sec="$(_tg_rs_init_secret)" ;; esac
	[ "$port" = "$cur_port" ] && [ "$sec" = "$cur_sec" ] && { [ "$tls_new" = - ] || [ "$tls_new" = "$(_tg_tls_of "$id")" ]; } && { printf '{"ok":true,"same":true}\n'; return 0; }
	pidof "$(_tg_bin_of "$id")" >/dev/null 2>&1 && was=1
	_tg_bk save
	case "$id" in
		mtproto)
			mkdir -p "$(dirname "$TG_CONF_MT")"
			[ -f "$TG_CONF_MT" ] || printf 'HOST=0.0.0.0\nPORT=1443\n' > "$TG_CONF_MT"
			if grep -q '^PORT=' "$TG_CONF_MT"; then sed -i "s/^PORT=.*/PORT=$port/" "$TG_CONF_MT"; else echo "PORT=$port" >> "$TG_CONF_MT"; fi
			if grep -q '^SECRET=' "$TG_SECRET_MT_FILE" 2>/dev/null; then sed -i "s/^SECRET=.*/SECRET=$sec/" "$TG_SECRET_MT_FILE"; else echo "SECRET=$sec" >> "$TG_SECRET_MT_FILE"; fi ;;
		socks5)
			if grep -q -- '--port[[:space:]=]\{1,\}[0-9]' "$init"; then sed -i "s/--port\([[:space:]=]\{1,\}\)[0-9]\{1,5\}/--port\1$port/" "$init"
			else sed -i "s#\($TG_BIN_GO\)#\1 --port $port#" "$init"; fi ;;
		rust)
			if grep -q -- '--port[[:space:]=]\{1,\}[0-9]' "$init"; then sed -i "s/--port\([[:space:]=]\{1,\}\)[0-9]\{1,5\}/--port\1$port/" "$init"
			else sed -i "s#\($TG_BIN_RS\)#\1 --port $port#" "$init"; fi
			if grep -q -- '--secret[[:space:]=]\{1,\}["'"'"']\{0,1\}[0-9a-fA-F]' "$init"; then sed -i "s/--secret\([[:space:]=]\{1,\}[\"']\{0,1\}\)[0-9a-fA-F,]\{1,\}/--secret\1$sec/" "$init"
			else sed -i "s#\($TG_BIN_RS\)#\1 --secret $sec#" "$init"; fi
			printf '%s\n' "$sec" > "$TG_SECRET_RS_FILE" ;;
	esac
	[ "$tls_new" != - ] && _tg_tls_write "$id" "$tls_new"
	"$init" restart >/dev/null 2>&1
	if _tg_listening "$id" "$port"; then
		_tg_bk drop
		_tg_fw_sync "$id"
		logger -t zapret-manager "TG WS Proxy ($id): порт $port${sec:+, ключ изменён}$([ "$tls_new" != - ] && echo ", FakeTLS $tls_new")"
		printf '{"ok":true,"running":true}\n'
		return 0
	fi
	if [ -z "$was" ]; then
		_tg_bk drop
		_tg_fw_sync "$id"
		printf '{"ok":true,"running":false}\n'
		return 0
	fi
	_tg_bk restore
	"$init" restart >/dev/null 2>&1
	printf '{"error":"С портом %s прокси не запустился — вернули прежние порт и ключ, прокси работает как раньше"}\n' "$port"
	return 1
}

_tg_args_write() {
	local init="$1" t="$1.zm.$$"
	awk -v A="$2" '
		/procd_set_param[ \t]+command/ && !d {
			d = 1; o = ""; seen = 0; ind = $0; sub(/[^ \t].*$/, "", ind)
			for (i = 1; i <= NF; i++) {
				t = $i; u = t; gsub(/^["\047]|["\047]$/, "", u)
				if (!seen) { o = o (o == "" ? "" : " ") t; if (u ~ /tg-ws-proxy-(go|rs)$/) seen = 1; continue }
				if (u ~ /^--?(host|port|secret|listen-faketls-domain|socks-host|socks-port)$/) { o = o " " t; if (i < NF) o = o " " $(i + 1); i++; continue }
				if (u ~ /^--?(host|port|secret|listen-faketls-domain|socks-host|socks-port)=/ || u == "--socks-enabled") o = o " " t
			}
			if (A != "") o = o " " A
			print ind o; next
		}
		{ print }' "$init" > "$t" && [ -s "$t" ] && cat "$t" > "$init"
	rm -f "$t"
}

_tg_args_probe() {
	local init cmd f="$JOBS_DIR/tg_args.probe" p
	init="$(_tg_auto_init "$1")" || return 0
	cmd="$(sed -n 's/^[[:space:]]*procd_set_param[[:space:]]\{1,\}command[[:space:]]\{1,\}//p' "$init" | head -n1)"
	[ -n "$cmd" ] || return 0
	mkdir -p "$JOBS_DIR"
	( set -f; exec $cmd ) > "$f" 2>&1 < /dev/null &
	p=$!
	sleep 2
	kill "$p" 2>/dev/null; wait "$p" 2>/dev/null
	tr -d '\r' < "$f" | grep -v '^[[:space:]]*$' | head -n 4 | cut -c1-200
	rm -f "$f"
}

tg_args_set() {
	local id="$1" args init was="" port t bad="" out
	case "$id" in socks5|rust) ;; *) echo '{"error":"параметры запуска меняются только у SOCKS5 (Go) и Rust"}'; return 1 ;; esac
	init="$(_tg_auto_init "$id")"
	[ -f "$init" ] || { echo '{"error":"прокси не установлен"}'; return 1; }
	[ "$id" = rust ] && _tg_rs_uci && { echo '{"error":"Rust установлен пакетом luci-app-tg-ws-proxy-rs — параметры меняются в его настройках"}'; return 1; }
	_tg_auto_busy "$id" && { echo '{"error":"Идёт установка или удаление этого прокси — дождитесь окончания"}'; return 1; }
	grep -q 'procd_set_param[[:space:]]\{1,\}command' "$init" || { echo '{"error":"в init-скрипте прокси нет строки запуска — переустановите прокси"}'; return 1; }
	args="$(printf '%s' "$2" | tr '\t\r\n' '   ' | tr -s ' ' | sed 's/^ //; s/ $//')"
	[ "${#args}" -le 512 ] || { echo '{"error":"слишком длинно — не больше 512 знаков"}'; return 1; }
	set -f
	for t in $args; do
		case "$t" in
			*[!A-Za-z0-9._:/,=@+%-]*) bad="«$t» — можно только буквы, цифры и . _ : / , = @ + % -"; break ;;
			--host|--port|--secret|--listen-faketls-domain|-host|-port|-secret|--host=*|--port=*|--secret=*|--listen-faketls-domain=*|-host=*|-port=*|-secret=*)
				bad="${t%%=*} задаётся в «Порт и ключ» — уберите его отсюда"; break ;;
			--socks-enabled|--socks-enabled=*|--socks-host|--socks-host=*|--socks-port|--socks-port=*)
				[ "$id" = rust ] && { bad="${t%%=*} задаётся переключателем «SOCKS5» — уберите его отсюда"; break; } ;;
		esac
	done
	set +f
	[ -z "$bad" ] || { printf '{"error":"%s"}\n' "$(esc "$bad")"; return 1; }
	[ "$args" = "$(_tg_args_of "$id")" ] && { printf '{"ok":true,"same":true}\n'; return 0; }
	port="$(_tg_port_of "$id")"
	pidof "$(_tg_bin_of "$id")" >/dev/null 2>&1 && was=1
	_tg_bk save
	_tg_args_write "$init" "$args"
	[ "$(_tg_args_of "$id")" = "$args" ] || { _tg_bk restore; echo '{"error":"не удалось записать параметры в init-скрипт — оставили как было"}'; return 1; }
	"$init" restart >/dev/null 2>&1
	if _tg_listening "$id" "$port"; then
		_tg_bk drop
		logger -t zapret-manager "TG WS Proxy ($id): параметры запуска — ${args:-без параметров}"
		printf '{"ok":true,"running":true}\n'
		return 0
	fi
	if [ -z "$was" ]; then
		_tg_bk drop
		printf '{"ok":true,"running":false}\n'
		return 0
	fi
	"$init" stop >/dev/null 2>&1
	out="$(_tg_args_probe "$id")"
	_tg_bk restore
	"$init" restart >/dev/null 2>&1
	printf '{"error":"С новыми параметрами прокси не запустился — вернули прежние, прокси работает как раньше","log":"%s"}\n' "$(esc_ml "$out")"
	return 1
}

_tg_socks_write() {
	local init="$1" t="$1.zm.$$"
	awk -v S="$2" '
		/procd_set_param[ \t]+command/ && !d {
			d = 1; o = ""; ind = $0; sub(/[^ \t].*$/, "", ind)
			for (i = 1; i <= NF; i++) {
				u = $i; gsub(/^["\047]|["\047]$/, "", u)
				if (u ~ /^--socks-(host|port)$/) { i++; continue }
				if (u ~ /^--socks-(host|port)=/ || u ~ /^--socks-enabled(=.*)?$/) continue
				o = o (o == "" ? "" : " ") $i
			}
			if (S != "") o = o " " S
			print ind o; next
		}
		{ print }' "$init" > "$t" && [ -s "$t" ] && cat "$t" > "$init"
	rm -f "$t"
}

tg_socks_set() {
	local v="$1" init="$TG_INIT_RS" mode port host="" st was="" c out want
	[ -f "$init" ] || { echo '{"error":"Rust не установлен"}'; return 1; }
	_tg_rs_uci && { echo '{"error":"Rust установлен пакетом luci-app-tg-ws-proxy-rs — SOCKS5 включается в его настройках (Enable SOCKS5 input)"}'; return 1; }
	_tg_auto_busy rust && { echo '{"error":"Идёт установка или удаление Rust — дождитесь окончания"}'; return 1; }
	_tg_rs_socks_ok "$(cat "$TG_VER_RS_FILE" 2>/dev/null)" || { echo '{"error":"SOCKS5 есть в Rust начиная с версии 2.6.0 — обновите прокси"}'; return 1; }
	grep -q 'procd_set_param[[:space:]]\{1,\}command' "$init" || { echo '{"error":"в init-скрипте Rust нет строки запуска — переустановите прокси"}'; return 1; }
	case "$v" in
		off) mode=off ;;
		lan:*|local:*) mode="${v%%:*}"; port="$(printf '%s' "${v#*:}" | sed 's/^0*//')" ;;
		*) echo '{"error":"неизвестный режим SOCKS5"}'; return 1 ;;
	esac
	if [ "$mode" != off ]; then
		st="$(_tg_port_state rust "$port" socks)"
		case "$st" in
			free|self) ;;
			bad) echo '{"error":"Порт — число от 1 до 65535"}'; return 1 ;;
			"tg rust") printf '{"error":"Порт %s уже у MTProto этого прокси — нужен другой"}\n' "$port"; return 1 ;;
			"tg "*) printf '{"error":"Порт %s уже у %s — выберите другой"}\n' "$port" "$(esc "$(_tg_title_of "${st#tg }")")"; return 1 ;;
			*) printf '{"error":"Порт %s уже занят программой %s — выберите другой"}\n' "$port" "$(esc "${st#busy }")"; return 1 ;;
		esac
		if [ "$mode" = lan ]; then
			host="$(_zm_lan_ip)"
			_tg_ip4_ok "$host" || { echo '{"error":"Не удалось узнать адрес роутера в домашней сети — выберите «Только этот роутер» или проверьте интерфейс lan"}'; return 1; }
		else host=127.0.0.1; fi
		want="--socks-enabled --socks-host $host --socks-port $port"
	else want=""; fi
	c="$(_tg_rs_socks_cfg)"
	if [ "$mode" = off ]; then [ "${c%% *}" = 0 ] && { printf '{"ok":true,"same":true}\n'; return 0; }
	else [ "$c" = "1 $host $port" ] && { printf '{"ok":true,"same":true,"host":"%s"}\n' "$(esc "$host")"; return 0; }; fi
	pidof tg-ws-proxy-rs >/dev/null 2>&1 && was=1
	_tg_bk save
	_tg_socks_write "$init" "$want"
	c="$(_tg_rs_socks_cfg)"
	if { [ "$mode" = off ] && [ "${c%% *}" != 0 ]; } || { [ "$mode" != off ] && [ "$c" != "1 $host $port" ]; }; then
		_tg_bk restore
		echo '{"error":"не удалось записать настройку в init-скрипт Rust — оставили как было"}'
		return 1
	fi
	"$init" restart >/dev/null 2>&1
	if _tg_listening rust "${port:-$(_tg_port_of rust)}"; then
		_tg_bk drop
		if [ "$mode" = off ]; then logger -t zapret-manager "TG WS Proxy (rust): SOCKS5 выключен"
		else logger -t zapret-manager "TG WS Proxy (rust): SOCKS5 на $host:$port"; fi
		printf '{"ok":true,"running":true,"host":"%s"}\n' "$(esc "$host")"
		return 0
	fi
	if [ -z "$was" ]; then
		_tg_bk drop
		printf '{"ok":true,"running":false,"host":"%s"}\n' "$(esc "$host")"
		return 0
	fi
	"$init" stop >/dev/null 2>&1
	out="$(_tg_args_probe rust)"
	_tg_bk restore
	"$init" restart >/dev/null 2>&1
	printf '{"error":"С включённым SOCKS5 Rust не запустился — вернули как было, прокси работает как раньше","log":"%s"}\n' "$(esc_ml "$out")"
	return 1
}

_tg_rs_socks_fix() {
	local c h p ip
	[ -f "$TG_INIT_RS" ] || return 0
	grep -q -- '--socks-enabled' "$TG_INIT_RS" || return 0
	_tg_rs_uci && return 0
	_tg_auto_busy rust && return 0
	c="$(_tg_rs_socks_cfg)"; set -- $c; h="$2"; p="$3"
	case "$h" in 127.*|::1|0.0.0.0|'') return 0 ;; esac
	ip="$(_zm_lan_ip)"
	_tg_ip4_ok "$ip" && [ "$ip" != "$h" ] || return 0
	_tg_socks_write "$TG_INIT_RS" "--socks-enabled --socks-host $ip --socks-port $p"
	logger -t zapret-manager "TG WS Proxy (rust): адрес роутера в домашней сети сменился ($h → $ip) — перенесли на него SOCKS5"
	"$TG_INIT_RS" enabled >/dev/null 2>&1 && "$TG_INIT_RS" restart >/dev/null 2>&1
	return 0
}

_tg_dom_ok() { [ "${#1}" -le 253 ] && printf '%s' "$1" | grep -qE '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$'; }

_tg_ip4_ok() { printf '%s' "$1" | grep -qE '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'; }

_tg_ext_get() {
	[ -f "$TG_EXT_FILE" ] || return 0
	awk -v k="$1.$2=" 'index($0, k) == 1 { v = substr($0, length(k) + 1) } END { printf "%s", v }' "$TG_EXT_FILE"
}

_tg_ext_put() {
	local t="$TG_EXT_FILE.$$"
	mkdir -p "$ZM_STATE_DIR"
	{
		[ -f "$TG_EXT_FILE" ] && awk -v k="$1.$2=" 'index($0, k) != 1' "$TG_EXT_FILE"
		[ -n "$3" ] && printf '%s.%s=%s\n' "$1" "$2" "$3"
	} > "$t"
	if [ -s "$t" ]; then mv -f "$t" "$TG_EXT_FILE"; else rm -f "$t" "$TG_EXT_FILE"; fi
	return 0
}

_tg_kv_set() {
	if grep -q "^$2=" "$1" 2>/dev/null; then sed -i "s|^$2=.*|$2=\"$3\"|" "$1"
	else
		[ -s "$1" ] && [ -n "$(tail -c 1 "$1")" ] && echo >> "$1"
		printf '%s="%s"\n' "$2" "$3" >> "$1"
	fi
}

_tg_fw_name() { case "$1" in mtproto) echo "Allow-TG-WS-Proxy-Go" ;; *) echo "Allow-TG-WS-Proxy-Rust" ;; esac; }

_tg_fw_set() {
	local s="zm_tg_$1" z
	z="$(_zm_wan_zone)"
	if [ -n "$2" ]; then
		[ "$(uci -q get "firewall.$s")" = rule ] && [ "$(uci -q get "firewall.$s.dest_port")" = "$2" ] && [ "$(uci -q get "firewall.$s.src")" = "$z" ] && return 1
		uci -q delete "firewall.$s"
		uci set "firewall.$s=rule"
		uci set "firewall.$s.name=$(_tg_fw_name "$1")"
		uci set "firewall.$s.src=$z"
		uci set "firewall.$s.proto=tcp"
		uci set "firewall.$s.dest_port=$2"
		uci set "firewall.$s.target=ACCEPT"
	else
		uci -q get "firewall.$s" >/dev/null || return 1
		uci delete "firewall.$s"
	fi
	uci commit firewall
	/etc/init.d/firewall reload >/dev/null 2>&1
	return 0
}

_tg_fw_sync() {
	local p n
	p="$(_tg_fw_port "$1")"; [ -n "$p" ] || return 0
	n="$(_tg_port_of "$1")"
	[ "$p" = "$n" ] || _tg_fw_set "$1" "$n"
	return 0
}

_tg_fw_live() {
	command -v nft >/dev/null 2>&1 || return 0
	nft list chain inet fw4 "input_$(_zm_wan_zone)" 2>/dev/null | grep -qF "$(_tg_fw_name "$1")"
}

_tg_ftls_ok() {
	local b c k r
	case "$1" in
		mtproto) b=/usr/bin/tg-ws-proxy; grep -q FAKE_TLS_DOMAIN /etc/init.d/tg-ws-proxy 2>/dev/null || return 1 ;;
		rust) b="$TG_BIN_RS" ;;
		*) return 1 ;;
	esac
	[ -x "$b" ] || return 1
	k="$(ls -ln "$b" 2>/dev/null | awk '{ print $5 }') $(date -r "$b" +%s 2>/dev/null)"
	c="$JOBS_DIR/tg.ftls.$1"
	if [ -f "$c" ] && [ "$(sed -n 1p "$c")" = "$k" ]; then
		r="$(sed -n 2p "$c")"
	else
		r=0
		case "$1" in
			mtproto) "$b" --print-link --host 127.0.0.1 --port 1443 --secret 00000000000000000000000000000000 --fake-tls-domain example.com 2>/dev/null | grep -q 'secret=ee' && r=1 ;;
			rust) "$b" --help 2>&1 | grep -q 'listen-faketls-domain' && r=1 ;;
		esac
		mkdir -p "$JOBS_DIR"
		printf '%s\n%s\n' "$k" "$r" > "$c"
	fi
	[ "$r" = 1 ]
}

_tg_tls_write() {
	local s init="$TG_INIT_RS"
	case "$1" in
		mtproto)
			mkdir -p "$(dirname "$TG_CONF_MT")"
			[ -f "$TG_CONF_MT" ] || printf 'HOST=0.0.0.0\nPORT=1443\n' > "$TG_CONF_MT"
			_tg_kv_set "$TG_CONF_MT" FAKE_TLS_DOMAIN "$2" ;;
		rust)
			sed -i "s/[[:space:]]--listen-faketls-domain[[:space:]=]\{1,\}[\"']\{0,1\}[A-Za-z0-9.-]*[\"']\{0,1\}//g" "$init"
			s="$(_tg_rs_init_secret)"
			case "$s" in
				dd*|ee*)
					if [ "${#s}" -ge 34 ]; then
						s="$(printf '%s' "$s" | cut -c3-34)"
						sed -i "s/--secret\([[:space:]=]\{1,\}[\"']\{0,1\}\)[0-9a-fA-F,]\{1,\}/--secret\1$s/" "$init"
						printf '%s\n' "$s" > "$TG_SECRET_RS_FILE"
					fi ;;
			esac
			[ -n "$2" ] && sed -i "/procd_set_param[[:space:]]\{1,\}command/ s#\($TG_BIN_RS\)#\1 --listen-faketls-domain $2#" "$init" ;;
	esac
	return 0
}

_tg_tls_live() {
	local p c
	p="$(pidof "$(_tg_bin_of "$1")" 2>/dev/null | awk '{ print $1 }')"
	[ -n "$p" ] || return 1
	c=" $(tr '\000' ' ' 2>/dev/null < "/proc/$p/cmdline") "
	if [ -n "$2" ]; then
		case "$c" in *"-domain $2 "*|*"-domain=$2 "*) return 0 ;; esac
		return 1
	fi
	case "$c" in *fake-tls-domain*|*listen-faketls-domain*) return 1 ;; esac
	return 0
}

_tg_tls_apply() {
	local id="$1" d="$2" init port was=""
	init="$(_tg_auto_init "$id")"; port="$(_tg_port_of "$id")"
	pidof "$(_tg_bin_of "$id")" >/dev/null 2>&1 && was=1
	_tg_bk save
	_tg_tls_write "$id" "$d"
	"$init" restart >/dev/null 2>&1
	if _tg_listening "$id" "$port" && _tg_tls_live "$id" "$d"; then _tg_bk drop; return 0; fi
	[ -z "$was" ] && { _tg_bk drop; return 0; }
	_tg_bk restore
	"$init" restart >/dev/null 2>&1
	return 1
}

_tg_resolve() {
	local t=""
	command -v timeout >/dev/null 2>&1 && t="timeout 5"
	$t nslookup "$1" $2 2>/dev/null | awk '/^Name:/ { n = 1; next } n && /^Address/ { for (i = 2; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i }' | awk '!s[$0]++' | head -n 4
}

tg_ext_check() {
	local id="$1" h wan grey=false ips="" first="" x m=false listen=false fp live=false
	h="$(printf '%s' "$2" | tr 'A-Z' 'a-z' | tr -d ' \t\r\n')"
	[ -f "$(_tg_auto_init "$id")" ] || { echo '{"error":"прокси не установлен"}'; return 1; }
	wan="$(_zm_wan_ip)"
	[ -n "$wan" ] && _zm_ip_grey "$wan" && grey=true
	if [ -n "$h" ]; then
		if _tg_ip4_ok "$h"; then
			ips="$h"
		elif _tg_dom_ok "$h"; then
			for x in - 77.88.8.8 1.1.1.1; do
				[ "$x" = - ] && x=""
				ips="$(_tg_resolve "$h" $x)"
				[ -n "$ips" ] || continue
				[ -n "$first" ] || first="$ips"
				[ -n "$wan" ] && printf '%s\n' "$ips" | grep -qxF "$wan" && break
				ips=""
			done
			[ -n "$ips" ] || ips="$first"
		else
			echo '{"error":"Адрес не похож на домен или IPv4"}'; return 1
		fi
		[ -n "$wan" ] && printf '%s\n' "$ips" | grep -qxF "$wan" && m=true
	fi
	_zm_tcp_listen "$(_tg_port_of "$id")" && pidof "$(_tg_bin_of "$id")" >/dev/null 2>&1 && listen=true
	fp="$(_tg_fw_port "$id")"
	[ -n "$fp" ] && _tg_fw_live "$id" && live=true
	printf '{"ok":true,"host":"%s","ips":[%s],"match":%s,"wan":"%s","grey":%s,"listen":%s,"open":%s,"fw_port":"%s","fw_live":%s,"port":"%s"}\n' \
		"$(esc "$h")" "$(printf '%s\n' "$ips" | awk 'NF { printf "%s\"%s\"", (n++ ? "," : ""), $0 }')" "$m" "$(esc "$wan")" "$grey" "$listen" \
		"$([ -n "$fp" ] && echo true || echo false)" "$(esc "$fp")" "$live" "$(esc "$(_tg_port_of "$id")")"
}

tg_site_check() {
	local d c
	d="$(printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d ' \t\r\n')"
	{ _tg_dom_ok "$d" && ! _tg_ip4_ok "$d"; } || { echo '{"error":"Нужно имя сайта, например www.google.com"}'; return 1; }
	c="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 4 --max-time 8 "https://$d/" 2>/dev/null)"
	case "$c" in ''|000) printf '{"ok":true,"up":false}\n' ;; *) printf '{"ok":true,"up":true,"code":"%s"}\n' "$(esc "$c")" ;; esac
}

tg_ext_set() {
	local id="$1" spec="$2" tls open hmode host cur fw=same tch=false pkg=0
	case "$id" in mtproto|rust) ;; *) echo '{"error":"у этого прокси нет доступа из интернета"}'; return 1 ;; esac
	[ -f "$(_tg_auto_init "$id")" ] || { echo '{"error":"прокси не установлен"}'; return 1; }
	_tg_auto_busy "$id" && { echo '{"error":"Идёт установка или удаление этого прокси — дождитесь окончания"}'; return 1; }
	case "$spec" in *:*:*:*) ;; *) echo '{"error":"неверные настройки"}'; return 1 ;; esac
	tls="$(printf '%s' "${spec%%:*}" | tr 'A-Z' 'a-z')"; spec="${spec#*:}"
	open="${spec%%:*}"; spec="${spec#*:}"
	hmode="${spec%%:*}"; host="$(printf '%s' "${spec#*:}" | tr 'A-Z' 'a-z')"
	case "$open" in 0|1) ;; *) echo '{"error":"неверные настройки"}'; return 1 ;; esac
	case "$hmode" in ddns|ip|'') ;; *) echo '{"error":"неверные настройки"}'; return 1 ;; esac
	if [ -n "$tls" ]; then
		{ _tg_dom_ok "$tls" && ! _tg_ip4_ok "$tls"; } || { echo '{"error":"Сайт для маскировки — имя сайта, например www.google.com"}'; return 1; }
	fi
	[ -z "$host" ] || _tg_ip4_ok "$host" || _tg_dom_ok "$host" || { echo '{"error":"Адрес для ссылки — домен (например, myhome.ddns.net) или IPv4"}'; return 1; }
	[ "$open" = 1 ] && [ -z "$host" ] && { echo '{"error":"Укажите домен или внешний IP — без него ссылку из интернета не собрать"}'; return 1; }
	[ "$id" = rust ] && _tg_rs_uci && pkg=1
	cur="$(_tg_tls_of "$id")"
	if [ "$tls" != "$cur" ]; then
		[ "$pkg" = 1 ] && { echo '{"error":"Rust установлен пакетом — маскировка FakeTLS меняется в его настройках (Inbound FakeTLS domain)"}'; return 1; }
		[ -z "$tls" ] || _tg_ftls_ok "$id" || { printf '{"error":"Эта версия %s не умеет FakeTLS — обновите прокси"}\n' "$(esc "$(_tg_title_of "$id")")"; return 1; }
		_tg_tls_apply "$id" "$tls" || { printf '{"error":"С новой маскировкой %s не запустился — вернули прежние настройки, прокси работает как раньше"}\n' "$(esc "$(_tg_title_of "$id")")"; return 1; }
		tch=true
		logger -t zapret-manager "TG WS Proxy ($id): ${tls:+FakeTLS, сайт $tls}${tls:-обычный ключ (dd)}"
	fi
	_tg_ext_put "$id" host "$host"
	_tg_ext_put "$id" hmode "$hmode"
	if [ "$open" = 1 ]; then
		_tg_fw_set "$id" "$(_tg_port_of "$id")" && { fw=opened; logger -t zapret-manager "TG WS Proxy ($id): порт $(_tg_port_of "$id") открыт из интернета"; }
	else
		_tg_fw_set "$id" "" && { fw=closed; logger -t zapret-manager "TG WS Proxy ($id): порт закрыт для интернета"; }
	fi
	printf '{"ok":true,"tls":%s,"fw":"%s","running":%s}\n' "$tch" "$fw" "$(pidof "$(_tg_bin_of "$id")" >/dev/null 2>&1 && echo true || echo false)"
}

_tg_ext_clear() {
	_tg_fw_set "$1" "" && echo "   ✓ Порт прокси закрыт для интернета"
	_tg_ext_put "$1" host ""
	_tg_ext_put "$1" hmode ""
	return 0
}

_tg_auto_alive() {
	case "$1" in
		mtproto) pidof tg-ws-proxy >/dev/null 2>&1 ;;
		socks5) pidof tg-ws-proxy-go >/dev/null 2>&1 ;;
		rust) pidof tg-ws-proxy-rs >/dev/null 2>&1 ;;
		tgws) [ -n "$(tgws status 2>/dev/null)" ] ;;
	esac
}

_tg_auto_busy() {
	case "$1" in
		tgws) _job_running tgws_install || _job_running tgws_remove || _job_running tgws_restart || _job_running tgws_reconfigure ;;
		*) _job_running "tg_install_$1" || _job_running "tg_remove_$1" ;;
	esac
}

_tg_auto_drop() {
	grep -qF "$TG_AUTO_TAG-$1=" "$CRON_FILE" 2>/dev/null || return 0
	sed -i "\\|$TG_AUTO_TAG-$1=|d" "$CRON_FILE"
	/etc/init.d/cron restart >/dev/null 2>&1
}

tg_auto_set() {
	local id="$1" v="$2" spec init off
	init="$(_tg_auto_init "$id")" || { echo '{"error":"неизвестный прокси"}'; return 1; }
	off=$(( $(printf '%s' "$id" | wc -c) % 5 ))
	case "$v" in
		off) spec="" ;;
		h1) spec="$((7 + off)) * * * *" ;;
		h2|h3|h6|h12) spec="$((7 + off)) */${v#h} * * *" ;;
		*) echo '{"error":"неизвестный интервал"}'; return 1 ;;
	esac
	[ -z "$spec" ] || [ -f "$init" ] || { echo '{"error":"этот прокси не установлен"}'; return 1; }
	mkdir -p "$(dirname "$CRON_FILE")"
	touch "$CRON_FILE"
	sed -i "\\|$TG_AUTO_TAG-$id=|d" "$CRON_FILE"
	[ -n "$spec" ] && echo "$spec /opt/zapret-manager-luci/backend.sh tg_auto_tick $id >/dev/null 2>&1 $TG_AUTO_TAG-$id=$v" >> "$CRON_FILE"
	/etc/init.d/cron enable >/dev/null 2>&1
	/etc/init.d/cron restart >/dev/null 2>&1
	printf '{"ok":true,"auto":%s}\n' "$(_tg_auto_json)"
}

tg_watch_set() {
	mkdir -p "$ZM_STATE_DIR"
	case "$1" in
		on) : > "$TG_WATCH_FLAG" ;;
		off) rm -f "$TG_WATCH_FLAG" ;;
		*) echo '{"error":"неизвестное значение"}'; return 1 ;;
	esac
	printf '{"ok":true,"auto":%s}\n' "$(_tg_auto_json)"
}

tg_auto_tick() {
	local init
	init="$(_tg_auto_init "$1")" || return 0
	[ -x "$init" ] || return 0
	"$init" enabled >/dev/null 2>&1 || return 0
	[ "$1" = rust ] && _tg_rs_off && return 0
	_tg_auto_busy "$1" && return 0
	"$init" restart >/dev/null 2>&1
	return 0
}

_tg_watch() {
	local id init
	_tg_rs_socks_fix
	[ -f "$TG_WATCH_FLAG" ] || return 0
	for id in mtproto socks5 rust tgws; do
		init="$(_tg_auto_init "$id")"
		[ -x "$init" ] || continue
		"$init" enabled >/dev/null 2>&1 || continue
		[ "$id" = rust ] && _tg_rs_off && continue
		_tg_auto_busy "$id" && continue
		_tg_auto_alive "$id" && continue
		sleep 3
		_tg_auto_alive "$id" && continue
		logger -t zapret-manager "TG-прокси ($id) не работает — запускаем заново"
		"$init" restart >/dev/null 2>&1
	done
	return 0
}

do_tg_install_mtproto() {
	_ensure_deps
	echo "==> Устанавливаем TG WS Proxy MTProto"
	local raz url tmp tag ver cur rev fb="" ZM_ARCH_FB=1
	raz="ipk"; [ "$PKG" = "apk" ] && raz="apk"
	echo "==> Узнаём последнюю версию на GitHub ($TG_REPO_MT)"
	tag="$(ZM_VER_FORCE=1 _zm_cached tg_mt _tg_tag_mt)"
	if [ -z "$tag" ]; then
		[ -n "$ZM_AU" ] && { echo "ОШИБКА: GitHub не ответил — обновление отложено, стоящая версия не тронута"; return 1; }
		tag="$TG_MTPROTO_TAG $TG_MTPROTO_REV"; fb=1
	fi
	rev="${tag#* }"; tag="${tag%% *}"; [ "$rev" = "$tag" ] && rev="$(_tg_mt_rev "$tag")"
	ver="$(_tg_mt_base "$tag")"
	cur="$(tg_status | sed -n 's/.*"mtproto_version":"\([^"]*\)".*/\1/p')"
	if [ -n "$fb" ]; then echo "   ! GitHub не ответил или для этой архитектуры нет пакета — ставим проверенную $(_tg_mt_show "$ver" "$rev")${cur:+, сейчас стоит $cur}"
	else echo "   ✓ Последняя версия: $(_tg_mt_show "$ver" "$rev")${cur:+, сейчас стоит $cur}"; fi
	tmp="/tmp/tg-ws-proxy.$raz"
	rm -f /etc/tg-ws-proxy.conf /etc/tg-ws-proxy.conf-opkg
	$UPDATE >&2
	url="$(_tg_mt_url "$tag" "$ver" "$rev")"
	echo "==> Скачиваем $(basename "$url")"
	if ! _zm_fetch "$url" "$tmp" 120; then
		echo "   · не скачалось: $ZM_FETCH_ERR"
		if [ "$tag" != "$TG_MTPROTO_TAG" ]; then
			[ -n "$ZM_AU" ] && { rm -f "$tmp"; echo "ОШИБКА: пакет новой версии не скачался — обновление отложено, стоящая версия не тронута"; return 1; }
			echo "!! Для версии $(_tg_mt_show "$ver" "$rev") нет пакета под эту архитектуру — ставим проверенную $(_tg_mt_show "$TG_MTPROTO_VER" "$TG_MTPROTO_REV")"
			ver="$TG_MTPROTO_VER"; rev="$TG_MTPROTO_REV"
			url="$(_tg_mt_url "$TG_MTPROTO_TAG" "$ver" "$rev")"
			_zm_fetch "$url" "$tmp" 120 || { rm -f "$tmp"; echo "ОШИБКА скачивания $url — $ZM_FETCH_ERR"; return 1; }
		else
			rm -f "$tmp"; echo "ОШИБКА скачивания $url"; return 1
		fi
	fi
	if _pkg_is_installed tg-ws-proxy && [ ! -f /etc/init.d/tg-ws-proxy ]; then
		echo "==> Пакет числится установленным, но файлов нет — ставим поверх"
		if [ "$PKG" = apk ]; then _zm_run 180 apk del --force-broken-world tg-ws-proxy >/dev/null 2>&1; $INSTALL "$tmp" >&2
		else $INSTALL --force-reinstall "$tmp" >&2; fi
	elif [ "$PKG" = opkg ] && _pkg_is_installed tg-ws-proxy; then
		$INSTALL --force-reinstall "$tmp" >&2
	else
		$INSTALL "$tmp" >&2
	fi
	[ -f /etc/init.d/tg-ws-proxy ] || { echo "ОШИБКА установки: менеджер пакетов не поставил tg-ws-proxy"; rm -f "$tmp"; return 1; }
	rm -f "$tmp"
	mkdir -p "$(dirname "$TG_SECRET_MT_FILE")"
	if ! grep -q '^SECRET=.' "$TG_SECRET_MT_FILE" 2>/dev/null; then
		echo "SECRET=$(head -c16 /dev/urandom | hexdump -e '16/1 "%02x"')" > "$TG_SECRET_MT_FILE"
	fi
	rm -f /etc/tg-ws-proxy.conf /etc/tg-ws-proxy.conf-opkg
	/etc/init.d/tg-ws-proxy enable >/dev/null 2>&1
	/etc/init.d/tg-ws-proxy restart >/dev/null 2>&1
	cur="$(tg_status | sed -n 's/.*"mtproto_version":"\([^"]*\)".*/\1/p')"
	echo "==> Готово: TG WS Proxy MTProto ${cur:-$(_tg_mt_show "$ver" "$rev")}"
}

do_tg_remove_mtproto() {
	local rc=0
	echo "==> Останавливаем TG WS Proxy MTProto"
	_zm_stop_svc tg-ws-proxy tg-ws-proxy
	_tg_ext_clear mtproto
	_zm_pkg_purge tg-ws-proxy || rc=1
	echo "==> Чистим файлы и настройки"
	_zm_wipe /etc/init.d/tg-ws-proxy /usr/bin/tg-ws-proxy /etc/tg-ws-proxy /etc/tg-ws-proxy.conf /etc/tg-ws-proxy.conf-opkg /etc/config/tg-ws-proxy /etc/config/tg-ws-proxy-opkg /etc/rc.d/*tg-ws-proxy || rc=1
	_zm_cron_drop 'tg-ws-proxy([^-]|$)' "TG WS Proxy"
	_zm_rm_done "$rc" "TG WS Proxy MTProto"
}

do_tg_install_socks5() {
	_ensure_deps
	echo "==> Устанавливаем TG WS Proxy SOCKS5"
	local file url tag tmp="$JOBS_DIR/tg-ws-proxy-go.new"
	mkdir -p "$JOBS_DIR"
	rm -f "$TG_BIN_GO.new"
	_tg_arch_init
	file="$(_tg_arch_go)" || { echo "ОШИБКА: архитектура не поддерживается ($TG_ARCH)"; return 1; }
	echo "==> Узнаём последнюю версию на GitHub ($TG_REPO_GO)"
	tag="$(_tg_fresh_tag go)"
	echo "   ✓ Последняя версия: $(_ver_norm "$tag")$([ -s "$TG_VER_GO_FILE" ] && echo ", сейчас стоит $(cat "$TG_VER_GO_FILE")")"
	url="${GH_MAIN}/$TG_REPO_GO/releases/download/${tag}/${file}"
	echo "==> Скачиваем $file"
	if ! _zm_fetch "$url" "$tmp" 120; then
		rm -f "$tmp"
		echo "   · не скачалось: $ZM_FETCH_ERR"
		[ "$(_ver_norm "$tag")" = "$TG_GO_VER" ] && { echo "ОШИБКА скачивания"; return 1; }
		[ -n "$ZM_AU" ] && { echo "ОШИБКА: файл новой версии не скачался — обновление отложено, стоящая версия не тронута"; return 1; }
		echo "!! Для версии $(_ver_norm "$tag") нет файла под эту архитектуру — ставим проверенную $TG_GO_VER"
		tag="v$TG_GO_VER"
		_zm_fetch "${GH_MAIN}/$TG_REPO_GO/releases/download/${tag}/${file}" "$tmp" 120 || { rm -f "$tmp"; echo "ОШИБКА скачивания: $ZM_FETCH_ERR"; return 1; }
	fi
	chmod +x "$tmp"
	[ -x "$TG_INIT_GO" ] && "$TG_INIT_GO" stop >/dev/null 2>&1
	_zm_bin_put "$tmp" "$TG_BIN_GO" || { rm -f "$tmp"; [ -x "$TG_INIT_GO" ] && [ -x "$TG_BIN_GO" ] && "$TG_INIT_GO" start >/dev/null 2>&1; return 1; }
	rm -f "$tmp"
	if [ ! -f "$TG_INIT_GO" ]; then
		printf '#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\n\nstart_service() {\n\tprocd_open_instance\n\tprocd_set_param command /usr/bin/tg-ws-proxy-go --host 0.0.0.0 --port 2080 --cf-proxy --cf-proxy-first --cf-balance\n\tprocd_set_param respawn\n\tprocd_close_instance\n}\n' > "$TG_INIT_GO"
		_zm_gml_patch "$TG_INIT_GO"
		chmod +x "$TG_INIT_GO"
		"$TG_INIT_GO" enable >/dev/null 2>&1
	fi
	"$TG_INIT_GO" restart >/dev/null 2>&1
	_ver_norm "$tag" > "$TG_VER_GO_FILE"
	echo "==> Готово: TG WS Proxy SOCKS5 $(cat "$TG_VER_GO_FILE")"
}

do_tg_remove_socks5() {
	echo "==> Удаляем TG WS Proxy SOCKS5"
	_zm_stop_svc tg-ws-proxy-go tg-ws-proxy-go
	echo "==> Удаляем программу, службу и настройки"
	local rc=0
	_zm_wipe "$TG_BIN_GO" "$TG_BIN_GO.new" "$TG_INIT_GO" "$TG_VER_GO_FILE" /etc/rc.d/*tg-ws-proxy-go || rc=1
	_zm_cron_drop 'tg-ws-proxy-go' "TG WS Proxy SOCKS5"
	_zm_rm_done "$rc" "TG WS Proxy SOCKS5"
}

do_tg_install_rust() {
	_ensure_deps
	echo "==> Устанавливаем TG WS Proxy Rust"
	local file url tmp_archive tmp_dir secret tag
	_tg_arch_init
	file="$(_tg_arch_rs)" || { echo "ОШИБКА: архитектура не поддерживается ($TG_ARCH)"; return 1; }
	echo "==> Узнаём последнюю версию на GitHub ($TG_REPO_RS)"
	tag="$(_tg_fresh_tag rs)"
	echo "   ✓ Последняя версия: $(_ver_norm "$tag")$([ -s "$TG_VER_RS_FILE" ] && echo ", сейчас стоит $(cat "$TG_VER_RS_FILE")")"
	tmp_archive="$JOBS_DIR/tg-ws-proxy-rs.tar.gz"; tmp_dir="$JOBS_DIR/tg-ws-proxy-rs"
	url="${GH_MAIN}/$TG_REPO_RS/releases/download/${tag}/${file}.tar.gz"
	echo "==> Скачиваем $file"
	if ! _zm_fetch "$url" "$tmp_archive" 120; then
		rm -f "$tmp_archive"
		echo "   · не скачалось: $ZM_FETCH_ERR"
		[ "$(_ver_norm "$tag")" = "$TG_RS_VER" ] && { echo "ОШИБКА скачивания"; return 1; }
		echo "!! Для версии $(_ver_norm "$tag") нет архива под эту архитектуру — ставим проверенную $TG_RS_VER"
		tag="v$TG_RS_VER"
		_zm_fetch "${GH_MAIN}/$TG_REPO_RS/releases/download/${tag}/${file}.tar.gz" "$tmp_archive" 120 || { rm -f "$tmp_archive"; echo "ОШИБКА скачивания: $ZM_FETCH_ERR"; return 1; }
	fi
	rm -rf "$tmp_dir"; mkdir -p "$tmp_dir"
	tar -xzf "$tmp_archive" -C "$tmp_dir" || { echo "ОШИБКА распаковки"; rm -rf "$tmp_dir" "$tmp_archive"; return 1; }
	set -- $(find "$tmp_dir" -type f -name 'tg-ws-proxy*' 2>/dev/null)
	[ -n "$1" ] || { echo "ОШИБКА: в архиве нет программы"; rm -rf "$tmp_dir" "$tmp_archive"; return 1; }
	[ -x "$TG_INIT_RS" ] && "$TG_INIT_RS" stop >/dev/null 2>&1
	_zm_bin_put "$1" "$TG_BIN_RS" || { rm -rf "$tmp_dir" "$tmp_archive"; [ -x "$TG_INIT_RS" ] && [ -x "$TG_BIN_RS" ] && "$TG_INIT_RS" start >/dev/null 2>&1; return 1; }
	rm -rf "$tmp_dir" "$tmp_archive"

	if [ ! -f "$TG_SECRET_RS_FILE" ]; then
		head -c16 /dev/urandom | hexdump -e '16/1 "%02x"' > "$TG_SECRET_RS_FILE"
	fi
	secret=$(cat "$TG_SECRET_RS_FILE")

	if [ ! -f "$TG_INIT_RS" ]; then
		printf '#!/bin/sh /etc/rc.common\nSTART=99\nUSE_PROCD=1\n\nstart_service() {\n\tprocd_open_instance\n\tprocd_set_param command /usr/bin/tg-ws-proxy-rs --host 0.0.0.0 --port 2443 --secret %s --default-domains --cf-balance --cf-priority\n\tprocd_set_param respawn\n\tprocd_close_instance\n}\n' "$secret" > "$TG_INIT_RS"
		chmod +x "$TG_INIT_RS"
		"$TG_INIT_RS" enable >/dev/null 2>&1
	fi
	"$TG_INIT_RS" restart >/dev/null 2>&1
	_ver_norm "$tag" > "$TG_VER_RS_FILE"
	echo "==> Готово: TG WS Proxy Rust $(cat "$TG_VER_RS_FILE")"
}

do_tg_remove_rust() {
	echo "==> Удаляем TG WS Proxy Rust"
	_zm_stop_svc tg-ws-proxy-rs tg-ws-proxy-rs
	_tg_ext_clear rust
	echo "==> Удаляем программу, службу и настройки"
	local rc=0
	_zm_wipe "$TG_BIN_RS" "$TG_INIT_RS" "$TG_SECRET_RS_FILE" "$TG_VER_RS_FILE" /etc/rc.d/*tg-ws-proxy-rs || rc=1
	_zm_cron_drop 'tg-ws-proxy-rs' "TG WS Proxy Rust"
	_zm_rm_done "$rc" "TG WS Proxy Rust"
}

tg_action() {
	local variant="$1" action="$2"
	case "$variant:$action" in
		watch:on|watch:off) tg_watch_set "$action"; return ;;
		*:auto=*) tg_auto_set "$variant" "${action#auto=}"; return ;;
		*:port=*) tg_port_check "$variant" "${action#port=}"; return ;;
		rust:sport=*) tg_port_check rust "${action#sport=}" socks; return ;;
		rust:socks=*) tg_socks_set "${action#socks=}"; return ;;
		*:conf=*) tg_conf_set "$variant" "${action#conf=}"; return ;;
		*:args=*) tg_args_set "$variant" "${action#args=}"; return ;;
		*:ext=*) tg_ext_set "$variant" "${action#ext=}"; return ;;
		*:chk=*) tg_ext_check "$variant" "${action#chk=}"; return ;;
		*:site=*) tg_site_check "${action#site=}"; return ;;
		mtproto:restart|socks5:restart|rust:restart) _tg_restart_one "$variant"; return ;;
		rust:install|rust:update|rust:reinstall|rust:reinstall_clean|rust:remove)
			_tg_rs_uci && { echo '{"error":"TG WS Proxy (Rust) установлен пакетом luci-app-tg-ws-proxy-rs — обновляйте и удаляйте его через менеджер пакетов, настройки — в Службы → Telegram WS Proxy (Rust)"}'; return 1; } ;;
	esac
	case "$variant:$action" in
		mtproto:remove|socks5:remove|rust:remove) _tg_auto_drop "$variant" ;;
	esac
	case "$variant:$action" in
		mtproto:install|mtproto:update) job_start tg_install_mtproto do_tg_install_mtproto ;;
		mtproto:reinstall)              job_start tg_install_mtproto _tg_reinstall_keep mtproto do_tg_remove_mtproto do_tg_install_mtproto ;;
		socks5:reinstall)               job_start tg_install_socks5 _tg_reinstall_keep socks5 do_tg_remove_socks5 do_tg_install_socks5 ;;
		rust:reinstall)                 job_start tg_install_rust _tg_reinstall_keep rust do_tg_remove_rust do_tg_install_rust ;;
		mtproto:reinstall_clean)        job_start tg_install_mtproto _zm_reinstall do_tg_remove_mtproto do_tg_install_mtproto ;;
		socks5:reinstall_clean)         job_start tg_install_socks5 _zm_reinstall do_tg_remove_socks5 do_tg_install_socks5 ;;
		rust:reinstall_clean)           job_start tg_install_rust _zm_reinstall do_tg_remove_rust do_tg_install_rust ;;
		mtproto:remove)                 job_start tg_remove_mtproto do_tg_remove_mtproto ;;
		socks5:install|socks5:update)   job_start tg_install_socks5 do_tg_install_socks5 ;;
		socks5:remove)                  job_start tg_remove_socks5 do_tg_remove_socks5 ;;
		rust:install|rust:update)       job_start tg_install_rust do_tg_install_rust ;;
		rust:remove)                    job_start tg_remove_rust do_tg_remove_rust ;;
		*) echo '{"error":"неизвестный вариант/действие"}' ;;
	esac
}

_tg_keep_files() {
	case "$1" in
		mtproto) echo "$TG_CONF_MT $TG_SECRET_MT_FILE" ;;
		socks5) echo "$TG_INIT_GO" ;;
		rust) echo "$TG_INIT_RS $TG_SECRET_RS_FILE" ;;
	esac
}
_tg_key_files() { case "$1" in mtproto) echo "$TG_SECRET_MT_FILE" ;; rust) echo "$TG_SECRET_RS_FILE" ;; esac; }

_tg_reinstall_keep() {
	local v="$1" k="$JOBS_DIR/tg_keep.$1" f b n=0 rc=0 fw host hmode init
	rm -rf "$k"; mkdir -p "$k" || return 1
	for f in $(_tg_keep_files "$v"); do
		[ -f "$f" ] || continue
		cp -p "$f" "$k/$(printf '%s' "$f" | tr '/' '_')" && n=$((n + 1))
	done
	fw="$(_tg_fw_port "$v")"; host="$(_tg_ext_get "$v" host)"; hmode="$(_tg_ext_get "$v" hmode)"
	[ "$n" -gt 0 ] && echo "==> Запоминаем порт, ключ и параметры — после переустановки они вернутся"
	_zm_reinstall "$2" "$3" || rc=1
	for f in $(if [ "$rc" = 0 ]; then _tg_keep_files "$v"; else _tg_key_files "$v"; fi); do
		b="$k/$(printf '%s' "$f" | tr '/' '_')"
		[ -f "$b" ] || continue
		mkdir -p "$(dirname "$f")" && cp -p "$b" "$f"
	done
	if [ "$rc" = 0 ]; then
		[ -n "$host" ] && _tg_ext_put "$v" host "$host"
		[ -n "$hmode" ] && _tg_ext_put "$v" hmode "$hmode"
		[ -n "$fw" ] && _tg_fw_set "$v" "$(_tg_port_of "$v")" && echo "   ✓ Порт прокси снова открыт для интернета"
		init="$(_tg_auto_init "$v")"
		[ -x "$init" ] && "$init" restart >/dev/null 2>&1
		[ "$n" -gt 0 ] && echo "   ✓ Порт, ключ и параметры прежние — ссылку для Telegram менять не нужно"
	elif [ -n "$(_tg_key_files "$v")" ]; then
		echo "   · Ключ сохранён — при следующей установке он вернётся"
	fi
	rm -rf "$k"
	return "$rc"
}

_tg_restart_one() {
	local init i=0
	init="$(_tg_auto_init "$1")"
	[ -x "$init" ] || { echo '{"error":"Прокси не установлен"}'; return 1; }
	"$init" restart >/dev/null 2>&1
	while [ "$i" -lt 5 ] && ! _tg_auto_alive "$1"; do i=$((i + 1)); sleep 1; done
	tg_status
}

tg_restart_all() {
	[ -x /etc/init.d/tg-ws-proxy ] && /etc/init.d/tg-ws-proxy restart >/dev/null 2>&1
	[ -x "$TG_INIT_GO" ] && "$TG_INIT_GO" restart >/dev/null 2>&1
	[ -x "$TG_INIT_RS" ] && "$TG_INIT_RS" restart >/dev/null 2>&1
	[ -x /etc/init.d/tgws ] && /etc/init.d/tgws restart >/dev/null 2>&1
	printf '{"ok":true}\n'
}

do_tgws_install() {
	_ensure_deps
	echo "==> Устанавливаем sTGWS"
	local ver arch file tmp ZM_ARCH_FB=1
	echo "==> Узнаём последнюю версию sTGWS"
	ver="$(ZM_VER_FORCE=1 _zm_cached tgws _tgws_latest)"
	[ -n "$ver" ] || { [ -n "$ZM_AU" ] && { echo "ОШИБКА: не удалось узнать последнюю версию — обновление отложено, стоящая версия не тронута"; return 1; }; ver="$TGWS_VERSION"; }
	echo "   ✓ Последняя версия: $ver"
	arch="$(awk -F\' '/DISTRIB_ARCH/ {print $2}' /etc/openwrt_release)"
	[ -n "$arch" ] || arch="$(opkg print-architecture 2>/dev/null | awk '$2!="all"&&$2!="noarch"{print $2}' | tail -1)"
	if [ -z "$arch" ]; then
		echo "ОШИБКА: не удалось определить архитектуру роутера"
		return 1
	fi
	file="tgws-${ver}-1_${arch}.${RAZ}"
	tmp="$JOBS_DIR/tgws_install.$RAZ"
	echo "==> Роутер: $arch, формат пакетов: $PKG"
	echo "==> Скачиваем $file"
	local attempt=1 max_attempts=3
	while [ "$attempt" -le "$max_attempts" ]; do
		rm -f "$tmp"
		_zm_fetch "$TGWS_BASE_URL/$file" "$tmp" 180 || echo "!! Попытка $attempt из $max_attempts: не скачалось — $ZM_FETCH_ERR"
		if [ -s "$tmp" ]; then
			if [ "$RAZ" = "ipk" ]; then
				tar -tzf "$tmp" 2>/dev/null | grep -q 'debian-binary' && break
			else
				head -c 512 "$tmp" | grep -qiE '<html|<!doctype' || break
			fi
		fi
		attempt=$((attempt + 1))
	done
	if [ "$attempt" -gt "$max_attempts" ]; then
		echo "ОШИБКА: не удалось скачать пакет sTGWS ($TGWS_BASE_URL/$file)"
		rm -f "$tmp"
		return 1
	fi
	echo "==> Обновляем список пакетов"
	$UPDATE >&2
	if [ "$PKG" = "apk" ]; then
		if apk info -e kmod-nft-queue >/dev/null 2>&1; then
			$INSTALL kmod-nft-queue >&2
		fi
	elif opkg list-installed kmod-nft-queue 2>/dev/null | grep -q .; then
		opkg flag user kmod-nft-queue >/dev/null 2>&1
	fi
	echo "==> Устанавливаем пакет"
	$INSTALL "$tmp" || { echo "ОШИБКА: менеджер пакетов отказался ставить sTGWS"; rm -f "$tmp"; return 1; }
	rm -f "$tmp"
	if [ ! -x /etc/init.d/tgws ]; then
		echo "ОШИБКА: установка sTGWS не удалась"
		return 1
	fi
	echo "==> Запускаем sTGWS"
	/etc/init.d/tgws enable >/dev/null 2>&1
	/etc/init.d/tgws restart >/dev/null 2>&1
	local i started=0
	for i in $(seq 1 20); do
		if [ -n "$(tgws status 2>/dev/null)" ]; then
			started=1
			break
		fi
		sleep 5
	done
	if [ "$started" != "1" ]; then
		echo "ОШИБКА: sTGWS не запустился"
		return 1
	fi
	echo "==> Подбираем домен — как кнопка «Подобрать новый домен»"
	_tgws_pick || echo "!! Домен пока не подобрался — sTGWS установлен, нажмите «Подобрать новый домен» через минуту"
	local domain
	domain=$(_tgws_domain)
	echo "==> Используем домен: ${domain:-не определён}"
	_tsc_tg_ensure >/dev/null 2>&1
	_ab_dns_bg
	echo "==> Готово, sTGWS установлен и запущен"
}

do_tgws_remove() {
	local rc=0
	echo "==> Останавливаем sTGWS"
	_zm_stop_svc tgws tgws
	killall stgws >/dev/null 2>&1
	/usr/sbin/stgws apply --spec /dev/null --state-dir /var/lib/stgws >/dev/null 2>&1
	/usr/sbin/tgws apply --spec /dev/null --state-dir /var/lib/tgws >/dev/null 2>&1
	nft delete table inet stgws >/dev/null 2>&1
	nft delete table inet tgws >/dev/null 2>&1
	_zm_pkg_purge tgws || rc=1
	echo "==> Чистим файлы"
	_zm_wipe /etc/*tgws* /var/lib/*tgws* /var/lock/*tgws* /etc/rc.d/*tgws* /etc/init.d/*tgws* /usr/sbin/*tgws* /usr/bin/*tgws* /etc/config/*tgws* &&
		echo "   ✓ Файлы, правила файрвола и настройки удалены" || rc=1
	_zm_cron_drop 'tgws' "sTGWS"
	_zm_rm_listed stgws || rc=1
	_zm_rm_done "$rc" "sTGWS"
}

do_tgws_restart() {
	[ -x /etc/init.d/tgws ] || { echo "ОШИБКА: sTGWS не установлен"; return 1; }
	echo "==> Перезапускаем sTGWS"
	/etc/init.d/tgws restart >/dev/null 2>&1
	sleep 5
	if [ -z "$(tgws status 2>/dev/null)" ]; then
		echo "ОШИБКА: sTGWS не запущен после перезапуска"
		return 1
	fi
	echo "==> Готово, sTGWS перезапущен"
}

_tgws_pick() {
	local n=0
	while [ "$n" -lt 2 ]; do
		tgws pick >/dev/null 2>&1
		sleep 6
		/etc/init.d/tgws restart >/dev/null 2>&1
		sleep 3
		[ -n "$(tgws status 2>/dev/null)" ] && [ -n "$(_tgws_domain)" ] && return 0
		n=$((n + 1))
		[ "$n" -lt 2 ] && echo "   · Домен не подобрался — пробуем ещё раз"
	done
	return 1
}

do_tgws_reconfigure() {
	[ -x /etc/init.d/tgws ] || { echo "ОШИБКА: sTGWS не установлен"; return 1; }
	echo "==> Подбираем новый домен"
	local domain
	if ! _tgws_pick; then
		echo "ОШИБКА: не удалось подобрать домен"
		return 1
	fi
	domain=$(_tgws_domain)
	echo "==> Новый домен: $domain"
	if [ -f /etc/stgws/smart-map ] && [ -x /etc/stgws/route-smart.sh ]; then
		echo "==> Умная карта: перестраиваю по стабильным диапазонам"
		ash /etc/stgws/route-smart.sh || echo "ОШИБКА: умная карта не применилась — оставлена карта подбора"
	fi
	echo "==> Готово, домен перенастроен"
}

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

tgws_action() {
	local action="$1"
	case "$action" in
		install|update) job_start tgws_install do_tgws_install ;;
		reinstall)      job_start tgws_install _zm_reinstall do_tgws_remove do_tgws_install ;;
		remove)         _tg_auto_drop tgws; job_start tgws_remove do_tgws_remove ;;
		restart)        job_start tgws_restart do_tgws_restart ;;
		reconfigure)    job_start tgws_reconfigure do_tgws_reconfigure ;;
		route_smart)    job_start tgws_route_smart do_route_smart ;;
		route_save)     do_route_save ;;
		route_restore)  do_route_restore ;;
		route_auto_on)  : > /etc/stgws/smart-map; echo '{"ok":true}' ;;
		route_auto_off) rm -f /etc/stgws/smart-map; echo '{"ok":true}' ;;
		*) echo '{"error":"неизвестное действие"}' ;;
	esac
}
