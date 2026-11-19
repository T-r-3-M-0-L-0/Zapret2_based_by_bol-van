#!/bin/sh
umask 022
ZSKIP_FILE="/opt/zapret-manager-luci/zapret_vpn_skip"
ZSKIP_NFT="/usr/share/nftables.d/ruleset-post/90-zm-zskip.nft"
ZSKIP_FP="/tmp/zapret-manager-luci/zskip.fp"
ZSKIP_SVC="steer sing-box netshift netshift-naive mihomo xray v2ray tailscale podkop podkop-plus podkop-engine passwall passwall2"
_zm_zskip_fp() (
	set +f
	echo "zskip 1"
	while read -r n d g f r u x m t; do [ "$d" = 00000000 ] && [ "$m" = 00000000 ] && { echo "wan $n"; break; }; done < /proc/net/route 2>/dev/null
	for n in /sys/class/net/*; do { read -r t < "$n/type"; } 2>/dev/null && [ "$t" = 65534 ] && echo "if ${n##*/}"; done
	for n in $ZSKIP_SVC; do [ -d "/sys/fs/cgroup/services/$n" ] && set -- $(ls -id "/sys/fs/cgroup/services/$n" 2>/dev/null) && echo "svc $n $1"; done
)
if [ "$1" = zm_watch ]; then
	[ -z "$ZM_WATCH_FORCE" ] && [ -f /opt/zapret-manager-luci/state/watch.off ] && exit 0
	mkdir -p /tmp/zapret-manager-luci 2>/dev/null; : > /tmp/zapret-manager-luci/watch.last 2>/dev/null
	_zw_idle() {
		local d=/tmp/zapret-manager-luci s=/opt/zapret-manager-luci/state e=/etc/zm-steer
		local pl=/usr/libexec/rpcd/zapret-manager want have t v st=0
		pidof rpcd >/dev/null 2>&1 || return 1
		ubus -t 5 list session >/dev/null 2>&1 || return 1
		ubus -t 15 call session access '{"ubus_rpc_session":"00000000000000000000000000000000","scope":"ubus","object":"session","function":"access"}' >/dev/null 2>&1
		[ "$?" = 7 ] && return 1
		if [ -x "$pl" ]; then
			ubus -t 5 list zapret-manager >/dev/null 2>&1 || return 1
			want="$(grep -c 'json_add_object' "$pl" 2>/dev/null)"
			have="$(ubus -v list zapret-manager 2>/dev/null | grep -c '^[[:space:]]*"')"
			if [ "${want:-0}" -gt 0 ] 2>/dev/null && [ "${have:-0}" -gt 0 ] 2>/dev/null && [ "$have" != "$want" ]; then return 1; fi
		fi
		[ -s "$s/strategy_test.backup" ] && return 1
		[ -f "$s/alloff/on" ] && return 1
		t="$(awk '$1 == "oom_kill" { print $2; exit }' /proc/vmstat 2>/dev/null)"
		[ -n "$t" ] && [ "$t" != "$(cat "$d/oom.seen" 2>/dev/null || echo 0)" ] && return 1
		[ -f "$d/resolv.conf.zm-bak" ] && return 1
		[ -f "$s/tg.watch" ] && return 1
		if grep -qx 'ru=isp' /opt/zapret-manager-luci/dns_net 2>/dev/null; then
			for t in /tmp/resolv.conf.d/resolv.conf.auto /tmp/resolv.conf.auto; do
				[ -s "$t" ] || continue
				v="$(awk '$1 == "nameserver" && ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || ($2 ~ /^[0-9A-Fa-f:]+$/ && $2 ~ /:.*:/)) && $2 !~ /^(127\.|0\.0\.0\.0$|::1$|[Ff][Ee]80:)/ && !u[$2]++ { print $2 }' "$t" | head -n 4 | tr '\n' ',' | sed 's/,$//')"
				[ -n "$v" ] && ! grep -qxF "ispips=$v" /opt/zapret-manager-luci/dns_net 2>/dev/null && return 1
				break
			done
		fi
		{ [ -e /usr/bin/netshift ] || [ -e /usr/lib/netshift ]; } && return 1
		if command -v steer >/dev/null 2>&1 && grep -qxF -e engine -e 'pkg steer' -e 'net zmwarp' -e 'net zmwarp4' "$e/owned" 2>/dev/null; then
			[ ! -f "$e/stopped" ] && [ -s "$e/sub.txt" ] && grep -qxF steer-spec "$e/owned" 2>/dev/null && return 1
			if [ ! -f "$e/stopped" ] && [ -s "$e/warp.up" ]; then
				[ -f "$d/steer/colo.last" ] || return 1
				t="$(date -r "$d/steer/colo.last" +%s 2>/dev/null || echo 0)"
				[ $(( $(date +%s) - t )) -lt 300 ] || return 1
			fi
		fi
		if grep -qx 'on=1' "$s/adblock/settings" 2>/dev/null; then
			t="$(awk -F= -v now="$(date +%s)" '$1 == "auto" { a = $2 } $1 == "updated" { u = $2 } END { print (a != "0" && u + 0 > 0 && now - u > 93600) ? 1 : 0 }' "$s/adblock/settings" 2>/dev/null)"
			if [ -f "$d/adblock.auto" ] || [ "$t" = 1 ]; then [ -n "$(find "$d/adblock.auto.try" -mmin -180 2>/dev/null)" ] || return 1; fi
			for t in $(sed -n 's/^conf-dir=\([^,]*\).*/\1/p' /var/etc/dnsmasq.conf.* 2>/dev/null | sort -u); do
				[ -s "$t/zm-adblock.conf" ] || return 1
				grep -qx 'stats=1' "$s/adblock/settings" 2>/dev/null && { [ -s "$t/zm-adblock-stats.conf" ] || return 1; }
			done
			if [ -s "$s/adblock/free.txt" ]; then
				t="$(cat /var/run/zm-adblock-free.pid 2>/dev/null)"
				[ -n "$t" ] && kill -0 "$t" 2>/dev/null || return 1
				nft list table inet zm_adblock_free >/dev/null 2>&1 || return 1
				for v in /var/etc/dnsmasq.conf.*; do [ "$v" -nt /var/etc/zm-adblock-free.conf ] && return 1; done
			fi
			if grep -q '^tch=.*\(et_spamhaus_block\|hagezi_tif_ip_block\|botnet_attackers_ip_block\)' "$s/adblock/settings" 2>/dev/null; then
				nft list table inet zm_adblock_ip >/dev/null 2>&1 || return 1
			fi
		elif [ -e /var/run/zm-adblock-free.pid ]; then return 1
		fi
		t=/opt/zapret/init.d/openwrt/zapret
		if [ -f "$t" ] && ! grep -qxF '	procd_set_param respawn 300 5 5 # zm-respawn' "$t" 2>/dev/null; then
			[ -f "$d/zp.respawn.skip" ] && [ ! "$t" -nt "$d/zp.respawn.skip" ] || return 1
		fi
		[ -f "$d/zp.respawn" ] && return 1
		if { read -r t < "$ZSKIP_FILE"; } 2>/dev/null && [ "$t" = on ] && { [ -x /etc/init.d/zapret ] || [ -x /etc/init.d/zapret2 ]; } && [ -d /usr/share/nftables.d ]; then
			[ "$(_zm_zskip_fp)" = "$(cat "$ZSKIP_FP" 2>/dev/null)" ] || return 1
			[ -f "$ZSKIP_FP.cg" ] && { nft list table inet zm_zskip_cg >/dev/null 2>&1 || return 1; }
		elif [ -f "$ZSKIP_FP" ] || [ -f "$ZSKIP_NFT" ]; then return 1
		fi
		rm -f /tmp/zm-rpcd-slow /tmp/zm-rpcd-plugin.stamp "$s/fk.watch" "$d/steer.vpnwatch"
		return 0
	}
	_zw_idle && exit 0
fi

CONF="/etc/config/zapret"
ZM_VERSION="5.083"
ZM_SCRIPT_URL="https://raw.githubusercontent.com/StressOzz/Zapret-Manager/refs/heads/main/ZapretManager_LuCI.sh"
ZM_STATS_URL="http://89.191.225.101:8787"
ZM_STATS_OFF="/etc/zapret-manager.nostats"
ZM_STATS_IDF="/etc/zapret-manager.id"
ZM_TERMS_FILE="/etc/zapret-manager.terms"
ZM_TERMS_VER=1
GH_RAW="https://raw.githubusercontent.com"
GH_MAIN="https://github.com"
MT_URL_ITDOG="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/files/MagiTrickle/configAD.yaml"
MT_URL_IH1="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/files/MagiTrickle/config.yaml"
MT_URL_IH2="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/files/MagiTrickle/configOLD.yaml"
EXCLUDE_URL="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/zapret-hosts-user-exclude.txt"
FLOWSEAL_ZIP="${GH_MAIN}/Flowseal/zapret-discord-youtube/archive/refs/heads/main.zip"
FLOWSEAL_FAKE_RAW="${GH_MAIN}/Flowseal/zapret-discord-youtube/raw/refs/heads/main/bin"
STR_URL="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/files/StrYoutube"
ZAPRET_VER="72.20260307"
JOBS_DIR="/tmp/zapret-manager-luci"
ZM_STATE_DIR="/opt/zapret-manager-luci/state"
CRON_FILE="/etc/crontabs/root"
ZM_EV_FILE="$ZM_STATE_DIR/events.log"
ZM_EV_MAX=300
ZM_OOM_FILE="$ZM_STATE_DIR/oom.last"
_zm_ev_lvl() {
	case "$1" in
		*"не отвеча"*|*"не работа"*|*"недоступ"*|*"не запуст"*|*"не заработал"*|*"не скача"*|*"завис"*|*"не хватило памяти"*|*"не получ"*|*"пропал"*|*"перезапуска"*|*"не удалось"*|*"не видит"*|*"не принял"*|*"запускаем заново"*|*"восстанавливаем"*) echo warn ;;
		*"снова "*|*"вернул"*|*"возвращ"*|*"применена"*|*"применён"*|*"применены"*|*"обновлён"*|*"обновлены"*|*"выбрала"*|*"заменён"*) echo ok ;;
		*) echo info ;;
	esac
}
_zm_ev() {
	local m now f="$ZM_EV_FILE" lk="/tmp/zapret-manager-luci/ev.lock" n=0 lv
	m="$(printf '%s' "$1" | tr '\t\r\n\\' '    ' | sed 's/  */ /g; s/^ //; s/ $//')"
	[ -n "$m" ] || return 0
	now="$(date +%s)"; lv="$(_zm_ev_lvl "$m")"
	mkdir -p /tmp/zapret-manager-luci "${f%/*}" 2>/dev/null || return 0
	until mkdir "$lk" 2>/dev/null; do
		n=$((n + 1))
		if [ "$n" -ge 6 ]; then rm -rf "$lk"; mkdir "$lk" 2>/dev/null || return 0; break; fi
		sleep 1
	done
	[ -f "$f" ] || : > "$f"
	awk -F '\t' -v OFS='\t' -v t="$now" -v m="$m" -v l="$lv" -v max="$ZM_EV_MAX" '
		NF >= 4 { a[++n] = $0 }
		END {
			if (n > 0) { split(a[n], p, "\t") }
			if (n > 0 && p[4] == m && t >= p[1] && t - p[1] < 900) a[n] = t OFS (p[2] + 1) OFS p[3] OFS m
			else a[++n] = t OFS 1 OFS l OFS m
			for (i = (n > max ? n - max + 1 : 1); i <= n; i++) print a[i]
		}' "$f" > "$f.zmtmp" 2>/dev/null && mv -f "$f.zmtmp" "$f"
	rm -f "$f.zmtmp"
	rmdir "$lk" 2>/dev/null
	return 0
}
logger() {
	command logger "$@" 2>/dev/null
	case "$1 $2" in
		"-t zapret-manager") shift 2; [ "$1" = -- ] && shift; _zm_ev "$*" ;;
		"-t zm-steer") shift 2; [ "$1" = -- ] && shift; _zm_ev "Steer: $*" ;;
	esac
	return 0
}
zm_events() {
	local f="$ZM_EV_FILE" lim="$1" tot=0
	case "$lim" in ''|*[!0-9]*) lim=100 ;; esac
	[ "$lim" -gt "$ZM_EV_MAX" ] && lim="$ZM_EV_MAX"
	[ "$lim" -lt 1 ] && lim=1
	[ -s "$f" ] && tot="$(grep -c . "$f" 2>/dev/null)"
	printf '{"items":['
	[ -s "$f" ] && tail -n "$lim" "$f" | awk -F '\t' '
		function j(v) { gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v); gsub(/[\001-\037]/, " ", v); return v }
		NF >= 4 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { r[++n] = sprintf("{\"t\":%s,\"n\":%s,\"l\":\"%s\",\"m\":\"%s\"}", $1, $2, j($3), j($4)) }
		END { for (i = n; i >= 1; i--) printf "%s%s", (i < n ? "," : ""), r[i] }'
	printf '],"total":%s,"now":%s}\n' "${tot:-0}" "$(date +%s)"
}
zm_events_clear() {
	: > "$ZM_EV_FILE" 2>/dev/null
	rm -f "$ZM_OOM_FILE"
	echo '{"ok":true}'
}
_zm_oom_watch() {
	local n seen f=/tmp/zapret-manager-luci/oom.seen k d
	n="$(awk '$1 == "oom_kill" { print $2; exit }' /proc/vmstat 2>/dev/null)"
	case "$n" in ''|*[!0-9]*) return 0 ;; esac
	seen="$(cat "$f" 2>/dev/null)"
	case "$seen" in ''|*[!0-9]*) seen=0 ;; esac
	mkdir -p /tmp/zapret-manager-luci 2>/dev/null
	echo "$n" > "$f"
	[ "$n" -gt "$seen" ] || return 0
	d=$((n - seen))
	k="$(dmesg 2>/dev/null | sed -n 's/.*[Kk]illed process [0-9][0-9]* (\([^)]*\)).*/\1/p' | tail -n "$d" | awk 'NF && !s[$0]++' | head -n 4 | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
	mkdir -p "${ZM_OOM_FILE%/*}" 2>/dev/null
	printf '%s\t%s\t%s\n' "$(date +%s)" "$d" "$k" > "$ZM_OOM_FILE"
	logger -t zapret-manager "Роутеру не хватило памяти — система закрыла ${k:-процесс}$([ "$d" -gt 1 ] && echo " (случаев: $d)")"
}
_zm_oom_json() {
	local at n k
	[ -s "$ZM_OOM_FILE" ] || { echo null; return; }
	IFS='	' read -r at n k < "$ZM_OOM_FILE"
	case "$at" in ''|*[!0-9]*) echo null; return ;; esac
	[ $(( $(date +%s) - at )) -lt 259200 ] || { echo null; return; }
	case "$n" in ''|*[!0-9]*) n=1 ;; esac
	printf '{"at":%s,"n":%s,"procs":"%s","ram_mb":%s,"zram":%s}' "$at" "$n" "$(esc "$k")" "$(awk '/^MemTotal:/ { print int($2 / 1024); exit }' /proc/meminfo 2>/dev/null || echo 0)" "$(_zram_on && echo true || echo false)"
}
ZM_GML_LINE='	ZM_GML="$(awk '\''$1 == "MemTotal:" { if ($2 > 0 && $2 <= 524288) printf "%dMiB", $2 / 2048; exit }'\'' /proc/meminfo 2>/dev/null)"; [ -n "$ZM_GML" ] && procd_set_param env GOMEMLIMIT="$ZM_GML"'
_zm_gml() {
	[ -n "$ZM_GML_ONE" ] || ZM_GML_ONE="$(awk '$1 == "MemTotal:" { m = int($2 / 8192); if (m < 16) m = 16; if (m > 128) m = 128; print m "MiB"; exit }' /proc/meminfo 2>/dev/null)"
	echo "${ZM_GML_ONE:-64MiB}"
}
_zm_gml_patch() {
	local f="$1" t
	[ -f "$f" ] || return 0
	grep -q 'GOMEMLIMIT\|procd_set_param env' "$f" && return 0
	[ "$(grep -c 'procd_set_param command' "$f")" = 1 ] || return 0
	t="$f.zmgml.$$"
	awk -v L="$ZM_GML_LINE" '{ print } !d && /procd_set_param command/ { print L; d = 1 }' "$f" > "$t" && [ -s "$t" ] && cat "$t" > "$f"
	rm -f "$t"
}
ZM_GHP_FILE="$ZM_STATE_DIR/ghproxy"
ZM_GHP_FAIL="$JOBS_DIR/ghproxy.fail"
ZM_GHP_LOG="$JOBS_DIR/ghproxy.log"
ZM_GHP_NET="$JOBS_DIR/ghnet"
ZM_GHP_GOOD="$JOBS_DIR/ghproxy.good"
ZM_GHP_LIST="gh-proxy.org ghfast.top gh.llkk.cc ghproxy.net"
ZM_GHP_HOSTS="github.com raw.githubusercontent.com"
ZM_GHP_TRY=3
_zm_ghp_load() {
	[ -n "$ZM_GHP_MODE" ] && return 0
	ZM_GHP_MODE=off
	grep -qE '^mode=(auto|always)$' "$ZM_GHP_FILE" 2>/dev/null && ZM_GHP_MODE=auto
	return 0
}
_zm_gh_host() {
	case "$1" in
		https://raw.githubusercontent.com/*|https://github.com/*|https://codeload.github.com/*|https://objects.githubusercontent.com/*|https://release-assets.githubusercontent.com/*|https://gist.githubusercontent.com/*|https://gist.github.com/*) return 0 ;;
	esac
	return 1
}
_zm_ghp_hn() { local h="${1#https://}"; printf '%s' "${h%%/*}"; }
_zm_ghp_say() {
	[ -n "$ZM_JOB_LOG" ] && printf '%s\n' "$1" >> "$ZM_JOB_LOG" 2>/dev/null
	mkdir -p "$JOBS_DIR" 2>/dev/null
	{ tail -n 39 "$ZM_GHP_LOG" 2>/dev/null; printf '%s|%s\n' "$(date +%s)" "$(printf '%s' "$1" | sed 's/^[[:space:]]*//')"; } > "$ZM_GHP_LOG.$$" 2>/dev/null && mv -f "$ZM_GHP_LOG.$$" "$ZM_GHP_LOG" 2>/dev/null
	return 0
}
_zm_ghp_why() {
	case "$1:$2" in
		curl:5|curl:6) echo "не нашёлся адрес (DNS)" ;;
		curl:7) echo "не удалось подключиться" ;;
		curl:28) echo "не ответил вовремя" ;;
		curl:35|wget:5) echo "ошибка защищённого соединения" ;;
		curl:60) echo "чужой сертификат — похоже, адрес подменён" ;;
		curl:52|curl:56|curl:18|curl:55|curl:16|curl:92|curl:8) echo "соединение оборвалось" ;;
		wget:4) echo "ошибка сети" ;;
		wget:1) echo "не скачалось" ;;
		*:211) echo "вместо файла пришла веб-страница" ;;
		*:212) echo "файл пришёл повреждённым" ;;
		*) return 1 ;;
	esac
}
_zm_ghp_clean() { case "$1:$2" in curl:5|curl:6|curl:7|curl:22|curl:35|curl:60) return 0 ;; esac; return 1; }
_zm_ghp_out() {
	local t="$1" a nx=""
	shift
	for a; do
		if [ -n "$nx" ]; then [ "$a" = - ] || printf '%s' "$a"; return 0; fi
		case "$t:$a" in
			curl:-o|curl:--output|wget:-O|wget:-qO|wget:--output-document) nx=1 ;;
			curl:-o?*) [ "${a#-o}" = - ] || printf '%s' "${a#-o}"; return 0 ;;
			wget:-qO?*) [ "${a#-qO}" = - ] || printf '%s' "${a#-qO}"; return 0 ;;
			wget:-O?*) [ "${a#-O}" = - ] || printf '%s' "${a#-O}"; return 0 ;;
		esac
	done
	return 0
}
_zm_ghp_half() {
	local n="$1"
	case "$n" in ''|*[!0-9]*) printf '%s' "$n"; return 0 ;; esac
	n=$(( (n + 1) / 2 ))
	[ "$n" -lt "$2" ] && n="$2"
	[ "$n" -gt "$1" ] && n="$1"
	printf '%s' "$n"
}
_zm_ghp_exec() {
	local t="$1" pre="$2" d="$3" a x=0 hv="" sp=""
	shift 3
	for a; do
		[ "$x" = 0 ] && { set --; x=1; }
		if [ -n "$hv" ]; then set -- "$@" "$(_zm_ghp_half "$a" "$hv")"; hv=""; continue; fi
		case "$t:$a" in
			curl:--connect-timeout) hv=3 ;;
			curl:-m|curl:--max-time|wget:-T) hv=5 ;;
			curl:-y|curl:--speed-time) sp=1 ;;
		esac
		if _zm_gh_host "$a"; then set -- "$@" "$pre$a"; else set -- "$@" "$a"; fi
	done
	if [ "$t" = curl ] && [ -n "$d" ] && [ -z "$sp" ]; then command curl --speed-limit 512 --speed-time 20 "$@"
	else command "$t" "$@"; fi
}
_zm_ghp_try() {
	local t="$1" pre="$2" d="$3" o="$4" rc
	shift 4
	_zm_ghp_exec "$t" "$pre" "$d" "$@"; rc=$?
	[ "$rc" = 0 ] || return "$rc"
	[ -n "$o" ] && [ "$o" != /dev/null ] && [ -s "$o" ] || return 0
	[ -n "$ZM_FETCH_ANY" ] || ! head -c 1024 "$o" 2>/dev/null | grep -qiE '<(!doctype|html|head|body)' || return 211
	[ -z "$ZM_GHP_CHECK" ] || "$ZM_GHP_CHECK" "$o" || return 212
	return 0
}
_zm_ghp_mark() {
	mkdir -p "$JOBS_DIR" 2>/dev/null
	printf '%s %s\n' "$2" "$(date +%s)" > "$ZM_GHP_NET.$1.$$" 2>/dev/null && mv -f "$ZM_GHP_NET.$1.$$" "$ZM_GHP_NET.$1" 2>/dev/null
	return 0
}
_zm_ghp_probe() {
	if _zm_has curl; then command curl -s -o /dev/null -I --connect-timeout 3 --max-time 5 "https://$1/" 2>/dev/null; return; fi
	_zm_has wget && command wget -q -T 5 --spider "https://$1/" >/dev/null 2>&1
}
_zm_ghp_st() {
	local s="" t="" now
	now="$(date +%s)"
	if [ -z "$2" ] && [ -f "$ZM_GHP_NET.$1" ] && read -r s t < "$ZM_GHP_NET.$1"; then
		case "$t" in ''|*[!0-9]*) ;; *)
			case "$s" in
				up) [ $((now - t)) -lt 300 ] && { echo up; return 0; } ;;
				down) [ $((now - t)) -lt 600 ] && { echo down; return 0; } ;;
			esac ;;
		esac
	fi
	if _zm_ghp_probe "$1"; then s=up; else s=down; fi
	_zm_ghp_mark "$1" "$s"
	echo "$s"
}
_zm_ghp_order() {
	local g="" m
	[ -f "$ZM_GHP_GOOD" ] && read -r g < "$ZM_GHP_GOOD"
	case " $ZM_GHP_LIST " in *" $g "*) [ -n "$g" ] && printf '%s' "$g" ;; *) g="" ;; esac
	for m in $ZM_GHP_LIST; do [ "$m" = "$g" ] || printf ' %s' "$m"; done
}
_zm_ghp_run() {
	local t="$1" a gh="" h rc why out nm m n=0
	shift
	for a; do _zm_gh_host "$a" && { gh="$a"; break; }; done
	[ -n "$gh" ] || { command "$t" "$@"; return; }
	_zm_ghp_load
	out="$(_zm_ghp_out "$t" "$@")"
	if [ -n "$ZM_GHP_NOMIR" ]; then _zm_ghp_try "$t" "" 1 "$out" "$@"; return; fi
	h="$(_zm_ghp_hn "$gh")"
	nm="${gh%%\?*}"; nm="${nm##*/}"; [ -n "$nm" ] || nm="$gh"
	if [ "$ZM_GHP_MODE" != auto ]; then
		while :; do
			n=$((n + 1))
			[ "$n" -gt 1 ] && [ -n "$out" ] && [ "$out" != /dev/null ] && rm -f "$out" 2>/dev/null
			_zm_ghp_try "$t" "" 1 "$out" "$@"; rc=$?
			[ "$rc" = 0 ] && { rm -f "$ZM_GHP_FAIL" 2>/dev/null; return 0; }
			_zm_ghp_why "$t" "$rc" >/dev/null || return "$rc"
			[ "$n" -lt "$ZM_GHP_TRY" ] || break
			[ -n "$out" ] || _zm_ghp_clean "$t" "$rc" || break
			[ "$rc" = 211 ] && break
		done
		mkdir -p "$JOBS_DIR" 2>/dev/null; date +%s > "$ZM_GHP_FAIL" 2>/dev/null
		return "$rc"
	fi
	if [ "$(_zm_ghp_st "$h")" = down ]; then
		_zm_ghp_say "   · $h сейчас недоступен — $nm качаем сразу через зеркало"
	else
		n=1
		_zm_ghp_try "$t" "" 1 "$out" "$@"; rc=$?
		[ "$rc" = 0 ] && { _zm_ghp_mark "$h" up; return 0; }
		why="$(_zm_ghp_why "$t" "$rc")" || return "$rc"
		if [ -z "$out" ] && ! _zm_ghp_clean "$t" "$rc"; then
			_zm_ghp_say "   · GitHub: $nm — $why. Через зеркало не повторяем: часть ответа уже получена"
			return "$rc"
		fi
		_zm_ghp_mark "$h" down
		_zm_ghp_say "   · GitHub: $nm не скачался напрямую — $why. Следующие 10 минут $h качаем сразу через зеркала"
	fi
	rc=1
	for m in $(_zm_ghp_order); do
		[ "$n" -lt "$ZM_GHP_TRY" ] || break
		n=$((n + 1))
		[ -n "$out" ] && [ "$out" != /dev/null ] && rm -f "$out" 2>/dev/null
		_zm_ghp_try "$t" "https://$m/" "" "$out" "$@"; rc=$?
		if [ "$rc" = 0 ]; then
			printf '%s\n' "$m" > "$ZM_GHP_GOOD" 2>/dev/null
			_zm_ghp_say "   ✓ $nm скачан через зеркало $m"
			return 0
		fi
		why="$(_zm_ghp_why "$t" "$rc")" || why="ошибка $rc"
		[ "$rc" = 22 ] && why="зеркало ответило ошибкой"
		_zm_ghp_say "   · $m: не скачалось — $why"
		[ -n "$out" ] || _zm_ghp_clean "$t" "$rc" || break
	done
	rm -f "$ZM_GHP_GOOD" 2>/dev/null
	_zm_ghp_say "   !! $nm не скачался ни напрямую, ни через зеркала (попыток: $n)"
	[ "$rc" = 0 ] && rc=1
	return "$rc"
}
_zm_has() { local d IFS=:; for d in ${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}; do [ -n "$d" ] && [ -x "$d/$1" ] && [ ! -d "$d/$1" ] && return 0; done; return 1; }
curl() { _zm_ghp_run curl "$@"; }
wget() { _zm_ghp_run wget "$@"; }
_zm_fetch_ok() {
	[ -s "$1" ] || return 1
	[ -n "$ZM_FETCH_ANY" ] || ! head -c 1024 "$1" | grep -qiE '<(!doctype|html|head|body)' || return 1
	ZM_FETCH_SIZE="$(wc -c 2>/dev/null < "$1" | tr -d ' ')"
	return 0
}
_zm_fetch() {
	_zm_fetch_one "$@" && return 0
	[ -n "$ZM_ARCH_FB" ] || return 1
	case "$1" in *"$ZM_A73"*) ;; *) return 1 ;; esac
	case "$1" in *kmod*|*amneziawg*) return 1 ;; esac
	case "$ZM_FETCH_ERR" in *"(HTTP 404)"*|*"(HTTP 410)"*) ;; *) return 1 ;; esac
	[ "$(_zm_arch)" = "$ZM_A73" ] || return 1
	local a u e="$ZM_FETCH_ERR"
	for a in $ZM_A73_ALTS; do
		u="$(printf '%s' "$1" | sed "s/$ZM_A73/$a/g")"
		if _zm_fetch_one "$u" "$2" "$3" "$4"; then
			echo "   · Сборки для $ZM_A73 нет — взята совместимая $a" >&2
			_zm_arch_accept "$a"
			return 0
		fi
		case "$ZM_FETCH_ERR" in *"(HTTP 404)"*|*"(HTTP 410)"*) ;; *) return 1 ;; esac
	done
	ZM_FETCH_ERR="$e"
	return 1
}
_zm_fetch_one() {
	local u="$1" o="$2" tm="${3:-120}" rg="$4" ef code rc e i cr=""
	ZM_FETCH_ERR=""; ZM_FETCH_SIZE=0
	ef="$o.zmerr"
	rm -f "$o"
	if _zm_has curl; then
		code="$(curl -fsSL --connect-timeout 10 --max-time "$tm" ${rg:+-r "$rg"} -A "Mozilla/5.0" -o "$o" -w '%{http_code}' "$u" 2>"$ef")"; rc=$?; cr="$rc"
		code="$(printf '%s' "$code" | tail -c 3)"
		e="$(tail -n 1 "$ef" 2>/dev/null | sed 's/^curl: ([0-9]*) //')"; rm -f "$ef"
		if [ "$rc" = 0 ] && _zm_fetch_ok "$o"; then return 0; fi
		rm -f "$o"
		if [ "$rc" = 22 ]; then
			case "$code" in
				404|410) ZM_FETCH_ERR="файла нет на сервере (HTTP $code)"; return 1 ;;
				403) ZM_FETCH_ERR="сервер отказал в доступе (HTTP 403)" ;;
				429) ZM_FETCH_ERR="сервер просит подождать — слишком много запросов (HTTP 429)" ;;
				5??) ZM_FETCH_ERR="сервер временно не работает (HTTP $code)" ;;
				*) ZM_FETCH_ERR="сервер ответил ошибкой HTTP ${code:-?}" ;;
			esac
		elif [ "$rc" = 0 ]; then ZM_FETCH_ERR="вместо файла пришла веб-страница"
		else ZM_FETCH_ERR="$(_zm_ghp_why curl "$rc" || echo "${e:-curl: ошибка $rc}")"; fi
	fi
	if [ -n "$cr" ] && _zm_gh_host "$u" && { [ "$cr" = 0 ] || [ "$cr" = 22 ] || _zm_ghp_why curl "$cr" >/dev/null; }; then :
	elif [ -z "$rg" ] && _zm_has wget; then
		e="$(ZM_GHP_NOMIR="${cr:+1}"; wget -T 20 -U "Mozilla/5.0" -O "$o" "$u" 2>&1)"; rc=$?
		if [ "$rc" = 0 ] && _zm_fetch_ok "$o"; then ZM_FETCH_ERR=""; return 0; fi
		rm -f "$o"
		if [ "$rc" = 0 ]; then e="вместо файла пришла веб-страница"
		else e="$( { [ "$rc" != 1 ] && _zm_ghp_why wget "$rc"; } || printf '%s\n' "$e" | grep -v '^Downloading\|^Connecting\|^Writing\|^Download completed\|^$' | tail -n 1)"; fi
		ZM_FETCH_ERR="${ZM_FETCH_ERR:+$ZM_FETCH_ERR; }wget: ${e:-не скачалось}"
	fi
	[ -n "$ZM_FETCH_ERR" ] || ZM_FETCH_ERR="на роутере нет ни curl, ни wget"
	if _zm_has curl && command -v _st_warp_first >/dev/null 2>&1; then
		i="$(_st_warp_first 2>/dev/null)"
		if [ -n "$i" ] && [ -d "/sys/class/net/$i" ]; then
			if ( ZM_GHP_NOMIR=1; curl -fsSL --interface "$i" --connect-timeout 10 --max-time "$tm" ${rg:+-r "$rg"} -A "Mozilla/5.0" -o "$o" "$u" 2>/dev/null ) && _zm_fetch_ok "$o"; then
				ZM_FETCH_ERR=""
				return 0
			fi
			rm -f "$o"
			ZM_FETCH_ERR="$ZM_FETCH_ERR; через WARP тоже не вышло"
		fi
	fi
	return 1
}
_zm_size_txt() { local b="${1:-0}"; if [ "$b" -lt 1024 ]; then echo "$b Б"; elif [ "$b" -lt 1048576 ]; then echo "$(( (b + 512) / 1024 )) КБ"; else awk -v b="$b" 'BEGIN { printf "%.1f МБ\n", b / 1048576 }'; fi; }
_zm_get() {
	local nm="${3:-${1##*/}}"
	if _zm_fetch "$1" "$2" "${4:-120}"; then echo "   ✓ $nm — $(_zm_size_txt "$ZM_FETCH_SIZE")"; return 0; fi
	echo "   !! $nm — не скачался: $ZM_FETCH_ERR"
	return 1
}
gh_mirrors() { _zm_ghp_load; [ "$ZM_GHP_MODE" = auto ] && echo $(_zm_ghp_order); return 0; }
gh_net() {
	_zm_ghp_load
	[ "$ZM_GHP_MODE" = auto ] || { echo up; return 0; }
	case " $ZM_GHP_HOSTS codeload.github.com objects.githubusercontent.com release-assets.githubusercontent.com " in *" $1 "*) ;; *) echo up; return 0 ;; esac
	if [ "$2" = down ]; then _zm_ghp_mark "$1" down; echo down; else _zm_ghp_st "$1"; fi
}
gh_get() {
	_zm_gh_host "$1" && [ -n "$2" ] || return 1
	_zm_fetch "$1" "$2" "${3:-120}" && return 0
	echo "$ZM_FETCH_ERR" >&2
	return 1
}
MIHOMO_DIR="/etc/mihomo"
MIHOMO_BIN="/usr/bin/mihomo"
MIHOMO_CONF="/etc/mihomo/config.yaml"
MAGITRICKLE_CONF="/etc/magitrickle/state/config.yaml"
MIXOMO_CRON_CMD="/etc/init.d/mihomo restart"
HOSTS_FILE="/etc/hosts"
EXPERT_MODE_FILE="/opt/zapret-manager-luci/expert_mode"
PORTS_UDP="88,1024-2407,2409-4499,4502-19293,19345-49999,50101-65535"
PORTS_TCP="2099,2802,2302,2502,3478-3480,3724,6000-8000,8085,8090,8100,8903,8904,25565,27015-27030,27036-27037,35500-35600,50001,60442"
{ [ -d "$JOBS_DIR" ] && [ -d "$ZM_STATE_DIR" ]; } || mkdir -p "$JOBS_DIR" "$ZM_STATE_DIR" 2>/dev/null

if command -v opkg >/dev/null 2>&1; then
	PKG="opkg"; PKG_ADD="opkg install"; PKG_DEL="opkg remove"; PKG_UPD="opkg update"
	RAZ="ipk"
else
	PKG="apk"; PKG_ADD="apk add --allow-untrusted"; PKG_DEL="apk del"; PKG_UPD="apk update"
	RAZ="apk"
fi

esc() {
	case "$1" in *[!A-Za-z0-9\ ._:/@+=,%-]*) ;; *) printf '%s' "$1"; return 0 ;; esac
	printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr '\n' ' '
}

esc_ml() {
	printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed 's/\r$//; s/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

_job_running() {
	local pid="$JOBS_DIR/$1.pid"
	[ -f "$pid" ] && kill -0 "$(cat "$pid" 2>/dev/null)" 2>/dev/null || return 1
	! grep -q '^__DONE__' "$JOBS_DIR/$1.log" 2>/dev/null
}

job_status() {
	local name="$1"
	case "$name" in ''|*[!A-Za-z0-9_.-]*) echo '{"running":false,"done":false,"rc":""}'; return ;; esac
	local pid="$JOBS_DIR/$name.pid"
	local log="$JOBS_DIR/$name.log"
	local running="false" done="false" rc=""
	_job_running "$name" && running="true"
	if [ -f "$log" ] && grep -q '^__DONE__' "$log"; then
		done="true"
		rc=$(grep '^__DONE__' "$log" | tail -1 | awk '{print $2}')
	fi
	printf '{"running":%s,"done":%s,"rc":"%s"}\n' "$running" "$done" "$rc"
}

log_tail() {
	local name="$1"
	case "$name" in ''|*[!A-Za-z0-9_.-]*) echo '{"lines":""}'; return ;; esac
	local log="$JOBS_DIR/$name.log"
	[ -f "$log" ] || { echo '{"lines":""}'; return; }
	printf '{"lines":"%s"}\n' "$(esc_ml "$(tail -n 300 "$log" | grep -v '^__DONE__')")"
}

_confz() {
	if [ "$PKG" = "apk" ]; then echo "/etc/apk/repositories.d/distfeeds.list"
	else echo "/etc/opkg/distfeeds.conf"; fi
}

ZM_MIRROR_STATE="$ZM_STATE_DIR/mirror.state"
_mirror_host() {
	grep -v '^[[:space:]]*#' "$(_confz)" 2>/dev/null | grep -oE 'https?://[^ ]+/(releases|snapshots)/' | head -n1 | sed -E 's#^https?://##; s#/(releases|snapshots)/$##'
}

_mirror_name() {
	local f url
	f="$(_confz)"
	[ -f "$f" ] || { echo "файл не найден"; return; }
	url="$(_mirror_host)"
	[ -n "$url" ] || url=$(head -n1 "$f")
	case "$url" in
		*mirror-03.infra.openwrt.org*) echo "Infra OpenWrt" ;;
		*c3sl.ufpr.br*) echo "Brazil" ;;
		*ustc.edu.cn*) echo "China" ;;
		*tetaneutral.net*) echo "France" ;;
		*garr.it*) echo "Italy" ;;
		*marwan.ma*) echo "Morocco" ;;
		*pixeldeck.net*) echo "USA" ;;
		*rwth-aachen.de*) echo "Germany" ;;
		*downloads.openwrt.org*) echo "default / OpenWrt" ;;
		'') echo "неизвестное" ;;
		*) echo "$url" ;;
	esac
}

_mirror_info() {
	local h how="" ts=""
	h="$(_mirror_host)"
	if [ -s "$ZM_MIRROR_STATE" ] && [ "$(cut -f1 "$ZM_MIRROR_STATE")" = "$h" ]; then
		how="$(cut -f3 "$ZM_MIRROR_STATE")"; ts="$(cut -f2 "$ZM_MIRROR_STATE")"
	fi
	[ "$h" = downloads.openwrt.org ] && how=""
	printf '"mirror":"%s","mirror_host":"%s","mirror_how":"%s","mirror_at":%s' "$(esc "$(_mirror_name)")" "$(esc "$h")" "$(esc "$how")" "${ts:-0}"
}

_cpu_stat() { awk '/^cpu / { t = 0; for (i = 2; i <= NF; i++) t += $i; print t, $5 + $6; exit }' /proc/stat 2>/dev/null; }

_cpu_load() {
	local f="$JOBS_DIR/cpu.stat" now prev="" t1 i1 t2 i2 p
	now="$(_cpu_stat)"
	[ -n "$now" ] || return 0
	if [ -s "$f" ] && [ -z "$(find "$f" -mmin +1 2>/dev/null)" ]; then
		read -r prev 2>/dev/null < "$f"
	fi
	if [ -z "$prev" ]; then
		prev="$now"
		sleep 1
		now="$(_cpu_stat)"
	fi
	set -- $prev $now
	t1=$1; i1=$2; t2=$3; i2=$4
	if [ $((t2 - t1)) -lt 50 ] 2>/dev/null && [ -s "$f.pct" ]; then
		p=""; read -r p 2>/dev/null < "$f.pct"
		[ -n "$p" ] && { echo "$p"; return 0; }
	fi
	[ "$t2" -gt "$t1" ] 2>/dev/null || { echo 0; return 0; }
	echo "$now" > "$f"
	p=$(( (100 * ((t2 - t1) - (i2 - i1)) + (t2 - t1) / 2) / (t2 - t1) ))
	echo "$p" > "$f.pct"
	echo "$p"
}

_cpu_temp() {
	local z t typ best="" v
	for z in /sys/class/thermal/thermal_zone*; do
		[ -r "$z/temp" ] || continue
		t=""; read -r t 2>/dev/null < "$z/temp"
		case "$t" in ''|*[!0-9-]*) continue ;; esac
		typ=""; read -r typ 2>/dev/null < "$z/type"
		case "$typ" in *cpu*|*CPU*|*soc*|*SOC*) best="$t"; break ;; esac
		{ [ -z "$best" ] || [ "$t" -gt "$best" ]; } && best="$t"
	done
	if [ -z "$best" ]; then
		for z in /sys/class/hwmon/hwmon*/temp1_input; do
			[ -r "$z" ] || continue
			t=""; read -r t 2>/dev/null < "$z"
			case "$t" in ''|*[!0-9-]*) continue ;; esac
			best="$t"; break
		done
	fi
	[ -n "$best" ] || return 0
	if [ "$best" -gt 1000 ] 2>/dev/null; then v=$(( (best + 50) / 100 )); echo "$((v / 10)).$((v % 10))"
	else echo "$best"; fi
}

_inet_ping() {
	local h out ms
	for h in ya.ru vk.ru; do
		out=$(ping -4 -c 1 -W 2 "$h" 2>/dev/null)
		ms=$(echo "$out" | sed -n 's/.*time=\([0-9.]*\).*/\1/p' | head -n1)
		[ -n "$ms" ] && { echo "$(date +%s) ok ${ms%%.*}"; return 0; }
	done
	for h in ya.ru vk.ru; do
		ms=$(curl -s -o /dev/null --connect-timeout 4 --max-time 6 -w '%{time_namelookup} %{time_connect}' "http://$h/" 2>/dev/null) || continue
		echo "$(date +%s) ok $(echo "$ms" | awk '{ v = ($2 - $1) * 1000; if (v < 1) v = 1; printf "%d", v }')"
		return 0
	done
	for h in 77.88.8.8 1.1.1.1; do
		ping -4 -c 1 -W 2 "$h" >/dev/null 2>&1 && { echo "$(date +%s) nodns"; return 0; }
	done
	for h in 1.1.1.1 8.8.8.8; do
		curl -s -o /dev/null --connect-timeout 4 --max-time 6 "http://$h/" >/dev/null 2>&1 && { echo "$(date +%s) nodns"; return 0; }
	done
	echo "$(date +%s) fail"
}
_inet_state() {
	local f="$JOBS_DIR/inet" t r ms age
	read -r t r ms 2>/dev/null < "$f"
	age=$(( $(date +%s) - ${t:-0} ))
	if [ "$age" -ge 10 ] || [ "$age" -lt 0 ]; then
		mkdir -p "$JOBS_DIR"
		if mkdir "$f.lock" 2>/dev/null; then
			( _inet_ping > "$f.new" 2>/dev/null && mv -f "$f.new" "$f"; rmdir "$f.lock" ) >/dev/null 2>&1 &
		elif [ -n "$(find "$f.lock" -mmin +1 2>/dev/null)" ]; then
			rmdir "$f.lock" 2>/dev/null
		fi
	fi
	[ -n "$r" ] && [ "$age" -lt 120 ] && echo "$r $ms"
}

ZM_SI_STATIC="$JOBS_DIR/si.static"
_si_static() {
	local f="$ZM_SI_STATIC" line="" model arch owrt target
	if [ -s "$f" ] && [ ! "$(_confz)" -nt "$f" ] && [ ! "$ZM_MIRROR_STATE" -nt "$f" ] && [ -z "$(find "$f" -mmin +10 2>/dev/null)" ]; then
		IFS= read -r line 2>/dev/null < "$f"
		[ -n "$line" ] && { printf '%s\n' "$line"; return 0; }
	fi
	model=$(cat /tmp/sysinfo/model 2>/dev/null)
	arch=$(grep DISTRIB_ARCH /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
	owrt=$(grep '^DISTRIB_RELEASE=' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
	target=$(grep '^DISTRIB_TARGET=' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
	line="$(printf '%s,"model":"%s","arch":"%s","openwrt":"%s","target":"%s","hostname":"%s","kernel":"%s"' "$(_mirror_info)" \
		"$(esc "$model")" "$(esc "$arch")" "$(esc "$owrt")" "$(esc "$target")" "$(esc "$(cat /proc/sys/kernel/hostname 2>/dev/null)")" "$(esc "$(uname -r 2>/dev/null)")")"
	printf '%s\n' "$line" > "$f.$$" 2>/dev/null && mv -f "$f.$$" "$f" 2>/dev/null || rm -f "$f.$$"
	printf '%s\n' "$line"
}

system_info() {
	local df_j inet inet_ms
	df_j=$(df -h /tmp / 2>/dev/null | awk 'function c(x) { gsub(/["\\]/, "", x); return x }
		NR == 2 { a = $3; b = $4; t = $2 } NR == 3 { u = $3; v = $4; r = $2 }
		END { printf "\"tmp_used\":\"%s\",\"tmp_free\":\"%s\",\"tmp_total\":\"%s\",\"root_used\":\"%s\",\"root_free\":\"%s\",\"root_total\":\"%s\"", c(a), c(b), c(t), c(u), c(v), c(r) }')
	[ -n "$df_j" ] || df_j='"tmp_used":"","tmp_free":"","tmp_total":"","root_used":"","root_free":"","root_total":""'
	set -- $(_inet_state)
	inet="$1"; inet_ms="$2"
	printf '{%s,%s,"cpu_temp":"%s","cpu_load":"%s","inet":"%s","inet_ms":"%s"}\n' "$(_si_static)" "$df_j" "$(_cpu_temp)" "$(_cpu_load)" "$inet" "$inet_ms"
}

_mon_dev() {
	local f="$JOBS_DIR/mon.dev.$1" d=""
	if [ -s "$f" ] && [ -z "$(find "$f" -mmin +1 2>/dev/null)" ]; then read -r d 2>/dev/null < "$f"; printf '%s' "$d"; return 0; fi
	d="$(ubus -t 2 call "network.interface.$1" status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null)"
	[ -n "$d" ] || d="$(uci -q get "network.$1.device" 2>/dev/null)"
	case "$d" in *[!A-Za-z0-9_.@-]*) d="" ;; esac
	printf '%s\n' "$d" > "$f" 2>/dev/null
	printf '%s' "$d"
}

_mon_ifs() {
	local f="$JOBS_DIR/mon.ifs" dr o n d
	if [ -s "$f" ] && [ -z "$(find "$f" -mmin +1 2>/dev/null)" ]; then cat "$f"; return 0; fi
	dr="$(awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" { print $7 + 0, $1 }' /proc/net/route 2>/dev/null | sort -n | awk 'NR == 1 { print $2 }')"
	{
		ubus -t 2 call network.interface dump 2>/dev/null | jsonfilter -e '@.interface[@.up=true]' 2>/dev/null | while IFS= read -r o; do
			n="$(jsonfilter -s "$o" -e '@.interface' 2>/dev/null)"
			d="$(jsonfilter -s "$o" -e '@.l3_device' 2>/dev/null)"
			[ -n "$n" ] && [ -n "$d" ] && [ "$n" != loopback ] && [ -d "/sys/class/net/$d" ] || continue
			case "$n$d" in *[!A-Za-z0-9_.@-]*) continue ;; esac
			echo "$n $d"
		done
		[ -n "$dr" ] && echo "$dr $dr"
	} | awk -v dr="$dr" '
		{ l[NR] = $0; nm[NR] = $1; dv[NR] = $2 }
		END {
			for (p = 0; p < 2; p++) for (i = 1; i <= NR; i++) {
				six = (nm[i] ~ /6$/) ? 1 : 0
				if (six != p || seen[dv[i]]++) continue
				print nm[i], dv[i], (dv[i] == dr ? 1 : 0)
			}
		}' > "$f.$$" 2>/dev/null && mv -f "$f.$$" "$f" 2>/dev/null
	cat "$f" 2>/dev/null
}

_mon_fan() {
	local h n v rpm=-1 pwm=-1 st=-1 mx=-1 c t y="${ZM_SYSFS:-/sys}"
	for h in "$y"/class/hwmon/hwmon*; do
		[ -d "$h" ] || continue
		n=""; read -r n 2>/dev/null < "$h/name"
		for v in "$h"/fan[0-9]_input; do
			[ -r "$v" ] || continue
			t=""; read -r t 2>/dev/null < "$v"; case "$t" in ''|*[!0-9]*) ;; *) [ "$rpm" -lt 0 ] && rpm="$t" ;; esac
		done
		case "$n" in *fan*|*FAN*) ;; *) [ -e "$h/fan1_input" ] || continue ;; esac
		for v in "$h"/pwm[0-9]; do
			[ -r "$v" ] || continue
			t=""; read -r t 2>/dev/null < "$v"; case "$t" in ''|*[!0-9]*) ;; *) [ "$pwm" -lt 0 ] && pwm=$(( (t * 100 + 127) / 255 )) ;; esac
		done
	done
	for c in "$y"/class/thermal/cooling_device*; do
		[ -r "$c/type" ] || continue
		t=""; read -r t 2>/dev/null < "$c/type"
		case "$t" in *fan*|*Fan*|*FAN*) ;; *) continue ;; esac
		read -r st 2>/dev/null < "$c/cur_state"; read -r mx 2>/dev/null < "$c/max_state"
		case "$st$mx" in *[!0-9]*|'') st=-1; mx=-1 ;; *) break ;; esac
	done
	[ "$rpm" -ge 0 ] || [ "$pwm" -ge 0 ] || [ "$st" -ge 0 ] || return 0
	printf '{"rpm":%s,"pwm":%s,"st":%s,"mx":%s}' "$rpm" "$pwm" "$st" "$mx"
}

_zm_ncore() {
	local c
	c="$(sed -n 's/^core[[:space:]]*:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' /proc/cpuinfo 2>/dev/null | sort -u | wc -l | tr -d ' ')"
	[ "${c:-0}" -gt 0 ] 2>/dev/null || c="$(cat /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list 2>/dev/null | sort -u | wc -l | tr -d ' ')"
	{ [ "${c:-0}" -gt 0 ] && [ "$c" -le "$1" ]; } 2>/dev/null || c="$1"
	echo "$c"
}
_mon_static() {
	local f="$JOBS_DIR/mon.static" soc="" v c n part cpu="" mx="" line
	if [ -s "$f" ] && [ -z "$(find "$f" -mmin +10 2>/dev/null)" ] && grep -q '"ncore":' "$f"; then cat "$f"; return 0; fi
	soc="$( { tr '\000' '\n' < /proc/device-tree/compatible; } 2>/dev/null | tail -n1)"
	case "$soc" in
		*,*)
			v="${soc%%,*}"; c="$(printf '%s' "${soc#*,}" | tr 'a-z' 'A-Z')"
			case "$v" in
				mediatek) v=MediaTek ;; qcom) v=Qualcomm ;; brcm) v=Broadcom ;; ralink) v=Ralink ;; realtek) v=Realtek ;;
				rockchip) v=Rockchip ;; allwinner) v=Allwinner ;; marvell) v=Marvell ;; airoha|econet) v=Airoha ;; amlogic) v=Amlogic ;; nxp|fsl) v=NXP ;;
			esac
			soc="$v $c" ;;
		*) soc="" ;;
	esac
	n="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
	part="$(sed -n 's/^CPU part[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo 2>/dev/null | head -n1)"
	case "$part" in
		0xd03) cpu=Cortex-A53 ;; 0xd04) cpu=Cortex-A35 ;; 0xd05) cpu=Cortex-A55 ;; 0xd07) cpu=Cortex-A57 ;; 0xd08) cpu=Cortex-A72 ;;
		0xd09) cpu=Cortex-A73 ;; 0xd0b) cpu=Cortex-A76 ;; 0xc05) cpu=Cortex-A5 ;; 0xc07) cpu=Cortex-A7 ;; 0xc09) cpu=Cortex-A9 ;; 0xc0f) cpu=Cortex-A15 ;;
	esac
	[ -n "$cpu" ] || cpu="$(sed -En 's/^(cpu model|model name)[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo 2>/dev/null | head -n1)"
	read -r mx 2>/dev/null < /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
	case "$mx" in ''|*[!0-9]*) mx=0 ;; esac
	line="$(printf '"soc":"%s","cpu_model":"%s","ncpu":%s,"ncore":%s,"fmax":%s,"model":"%s","kernel":"%s","openwrt":"%s"' "$(esc "$soc")" "$(esc "$cpu")" "${n:-1}" "$(_zm_ncore "${n:-1}")" "$((mx / 1000))" \
		"$(esc "$(cat /tmp/sysinfo/model 2>/dev/null)")" "$(esc "$(uname -r 2>/dev/null)")" \
		"$(esc "$(sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" /etc/openwrt_release 2>/dev/null)")")"
	printf '%s\n' "$line" > "$f.$$" 2>/dev/null && mv -f "$f.$$" "$f" 2>/dev/null
	printf '%s\n' "$line"
}

_mon_c() { local t="$1" v; if [ "$t" -gt 1000 ] 2>/dev/null; then v=$(( (t + 50) / 100 )); echo "$((v / 10)).$((v % 10))"; else echo "$t"; fi; }

_mon_tlabel() {
	local n="$1" l="$2" i b
	case "$n" in
		*phy[0-9]*)
			i="$(printf '%s' "$n" | sed 's/.*phy\([0-9]*\).*/\1/')"; b="$(uci -q get "wireless.radio$i.band" 2>/dev/null)"
			case "$b" in 2g) echo "Wi-Fi 2,4 ГГц" ;; 5g) echo "Wi-Fi 5 ГГц" ;; 6g) echo "Wi-Fi 6 ГГц" ;; *) echo "Wi-Fi (phy$i)" ;; esac ;;
		*cpu*|*CPU*|*soc*|*SOC*|*tsens*) echo "Процессор" ;;
		*ddr*|*DDR*) echo "Память" ;;
		*nvme*|*mmc*) echo "Накопитель" ;;
		*ath*|*mt76*|*mt79*|*wifi*|*wlan*) echo "Wi-Fi" ;;
		*) if [ -n "$l" ]; then echo "$n · $l"; else echo "$n"; fi ;;
	esac
}

_mon_temps() {
	local z t typ sep="" h n i lbl seen=" "
	for z in /sys/class/thermal/thermal_zone*; do
		[ -r "$z/temp" ] || continue
		t=""; read -r t 2>/dev/null < "$z/temp"
		case "$t" in ''|*[!0-9-]*) continue ;; esac
		typ=""; read -r typ 2>/dev/null < "$z/type"
		seen="$seen$(printf '%s' "$typ" | tr '-' '_') "
		printf '%s{"id":"%s","label":"%s","c":%s}' "$sep" "$(esc "$typ")" "$(esc "$(_mon_tlabel "$typ")")" "$(_mon_c "$t")"; sep=","
	done
	for h in /sys/class/hwmon/hwmon*; do
		n=""; read -r n 2>/dev/null < "$h/name"
		case "$seen" in *" $(printf '%s' "$n" | tr '-' '_') "*) continue ;; esac
		for i in "$h"/temp*_input; do
			[ -r "$i" ] || continue
			t=""; read -r t 2>/dev/null < "$i"
			case "$t" in ''|*[!0-9-]*) continue ;; esac
			lbl=""; read -r lbl 2>/dev/null < "${i%_input}_label"
			printf '%s{"id":"%s","label":"%s","c":%s}' "$sep" "$(esc "$n")" "$(esc "$(_mon_tlabel "$n" "$lbl")")" "$(_mon_c "$t")"; sep=","
		done
	done
}

monitor_snapshot() {
	local wan lan fl f t ifs fan
	wan="$(_mon_dev wan)"; lan="$(_mon_dev lan)"
	ifs="$(_mon_ifs | tr '\n' ';')"
	fan="$(_mon_fan)"
	fl="/proc/uptime /proc/loadavg /proc/stat /proc/meminfo /proc/net/dev"
	for f in /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max; do [ -r "$f" ] && fl="$fl $f"; done
	t=""; read -r t 2>/dev/null < /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq
	case "$t" in ''|*[!0-9]*) t=0 ;; esac
	printf '{'
	awk -v wan="$wan" -v lan="$lan" -v ifs="$ifs" '
		BEGIN { k = split(ifs, il, ";"); for (i = 1; i <= k; i++) if (split(il[i], q, " ") >= 2) { ifn[q[2]] = q[1]; ifi[q[2]] = q[3] + 0; ifo[++ifc] = q[2] } }
		FILENAME == "/proc/uptime" { up = $1 + 0 }
		FILENAME == "/proc/loadavg" { ld = ($1 + 0) "," ($2 + 0) "," ($3 + 0); split($4, pr, "/"); run = pr[1] + 0; tot = pr[2] + 0 }
		FILENAME == "/proc/stat" && $1 ~ /^cpu/ {
			s = ""; for (i = 2; i <= 9; i++) s = s (i > 2 ? "," : "") ($i + 0)
			if ($1 == "cpu") all = s; else cores = cores (cores != "" ? "," : "") "[" s "]"
		}
		FILENAME == "/proc/meminfo" { k = $1; sub(/:$/, "", k); m[k] = $2 + 0 }
		FILENAME == "/proc/net/dev" && index($0, ":") {
			l = $0; sub(/^[ \t]+/, "", l); n = substr(l, 1, index(l, ":") - 1); split(substr(l, index(l, ":") + 1), v, " ")
			if (n == wan) w = (v[1] + 0) "," (v[9] + 0)
			if (n == lan) la = (v[1] + 0) "," (v[9] + 0)
			if (n in ifn) ifc_v[n] = (v[1] + 0) "," (v[9] + 0)
		}
		FILENAME ~ /_count$/ { cc = $1 + 0 }
		FILENAME ~ /_max$/ { cm = $1 + 0 }
		END {
			av = ("MemAvailable" in m) ? m["MemAvailable"] : m["MemFree"] + m["Cached"] + m["Buffers"]
			printf "\"t\":%s,\"load\":[%s],\"run\":%d,\"tasks\":%d,\"cpu\":[%s],\"cores\":[%s],", up + 0, (ld != "" ? ld : "0,0,0"), run, tot, all, cores
			printf "\"mem\":{\"total\":%d,\"free\":%d,\"avail\":%d,\"buffers\":%d,\"cached\":%d,\"shmem\":%d,\"sreclaim\":%d,\"swap\":%d,\"swapfree\":%d},", m["MemTotal"], m["MemFree"], av, m["Buffers"], m["Cached"], m["Shmem"], m["SReclaimable"], m["SwapTotal"], m["SwapFree"]
			printf "\"net\":{\"wan\":[%s],\"lan\":[%s],\"wan_dev\":\"%s\",\"lan_dev\":\"%s\",\"ifs\":[", w, la, wan, lan
			for (i = 1; i <= ifc; i++) { d = ifo[i]; if (!(d in ifc_v)) continue; printf "%s{\"n\":\"%s\",\"d\":\"%s\",\"i\":%d,\"c\":[%s]}", (o++ ? "," : ""), ifn[d], d, ifi[d], ifc_v[d] }
			printf "]},\"conn\":[%d,%d]", cc, cm
		}' $fl 2>/dev/null
	df -k / /tmp 2>/dev/null | awk 'NR == 2 { a = $2 + 0; b = $3 + 0 } NR == 3 { c = $2 + 0; d = $3 + 0 } END { printf ",\"flash\":[%d,%d],\"tmp\":[%d,%d]", a, b, c, d }'
	printf ',"fan":%s' "${fan:-null}"
	printf ',"freq":%s,"leases":%s,"temps":[%s],"htop":{"inst":%s,"ttyd":%s,"open":%s},%s}\n' \
		"$((t / 1000))" "$(cat /tmp/dhcp.leases 2>/dev/null | grep -c .)" "$(_mon_temps)" \
		"$([ -x /usr/bin/htop ] && echo true || echo false)" "$([ -x /usr/bin/ttyd ] && echo true || echo false)" \
		"$([ -s "$JOBS_DIR/htop.pid" ] && kill -0 "$(cat "$JOBS_DIR/htop.pid" 2>/dev/null)" 2>/dev/null && echo true || echo false)" "$(_mon_static)"
}

monitor_procs() {
	local tot
	tot="$(awk '$1 == "cpu" { t = 0; for (i = 2; i <= NF; i++) t += $i; printf "%.0f", t; exit }' /proc/stat 2>/dev/null)"
	printf '{"total":%s,"p":[' "${tot:-0}"
	{ ps w 2>/dev/null; echo '@@ZM@@'; cat /proc/[0-9]*/stat 2>/dev/null; } | awk '
		function j(s,    o, i, c, n) { o = ""; n = length(s); for (i = 1; i <= n; i++) { c = substr(s, i, 1); if (c == "\\") o = o "\\\\"; else if (c == "\"") o = o "\\\""; else if (c < " ") o = o " "; else o = o c } return o }
		!body && $0 == "@@ZM@@" { body = 1; next }
		!body && !hdr { hdr = 1; ci = index($0, "COMMAND"); next }
		!body { if ($1 ~ /^[0-9]+$/) { u[$1] = $2; c = ci ? substr($0, ci) : ""; sub(/^\{[^}]*\} /, "", c); cmd[$1] = c }; next }
		{
			l = $0; a = index(l, "("); b = 0
			for (i = length(l); i > a; i--) if (substr(l, i, 1) == ")") { b = i; break }
			if (!a || !b) next
			p = substr(l, 1, a - 2) + 0; nm = substr(l, a + 1, b - a - 1)
			split(substr(l, b + 2), f, " ")
			printf "%s[%d,%d,\"%s\",\"%s\",%.0f,%.0f,%d,\"%s\",\"%s\"]", (n++ ? "," : ""), p, f[2], j(nm), f[1], f[12] + f[13], f[22] * 4, f[18], j(u[p]), j(substr(cmd[p], 1, 240))
		}'
	printf ']}\n'
}

ui_net_get() {
	local d=""
	case "$1" in ''|*[!A-Za-z0-9._@-]*) ;; *) grep -q "^[[:space:]]*$1:" /proc/net/dev 2>/dev/null && d="$1" ;; esac
	[ -n "$d" ] || d="$(_mon_dev wan)"
	[ -n "$d" ] || d="$(awk 'NR > 1 && $2 == "00000000" { print $1; exit }' /proc/net/route 2>/dev/null)"
	awk -v d="$d" '
		FILENAME == "/proc/uptime" { t = $1 + 0 }
		FILENAME == "/proc/net/dev" && index($0, ":") {
			l = $0; sub(/^[ \t]+/, "", l); n = substr(l, 1, index(l, ":") - 1)
			if (n == d) { split(substr(l, index(l, ":") + 1), v, " "); rx = v[1]; tx = v[9] }
		}
		END { printf "{\"dev\":\"%s\",\"rx\":%.0f,\"tx\":%.0f,\"t\":%.2f}\n", d, rx + 0, tx + 0, t }' /proc/uptime /proc/net/dev 2>/dev/null
}

case "$1" in
	system_info) system_info; exit ;;
	ui_net_get)  ui_net_get "$2"; exit ;;
	monitor)       monitor_snapshot; exit ;;
	monitor_procs) monitor_procs; exit ;;
	job_status)  job_status "$2"; exit ;;
	log_tail)    log_tail "$2"; exit ;;
esac
_ZM_ML=""
_zmL() {
	case " $_ZM_ML " in *" $1 "*) echo "Zapret Manager: в модуле $1 нет нужной функции — переустановите панель" >&2; return 127 ;; esac
	[ -r "/opt/zapret-manager-luci/mod/$1.sh" ] || { echo "Zapret Manager: нет файла модуля $1 — переустановите панель" >&2; return 127; }
	_ZM_ML="$_ZM_ML $1"
	. "/opt/zapret-manager-luci/mod/$1.sh" || return 127
	case "$1" in
		steer2) _zmE steer1 ;;
	esac
	return 0
}
_zmE() { local m; for m in "$@"; do case " $_ZM_ML " in *" $m "*) ;; *) _zmL "$m" || return $? ;; esac; done; }
_tg_arch_init() { _zmL tg && _tg_arch_init "$@"; }
_zm_pkg_fmt() { _zmL tg && _zm_pkg_fmt "$@"; }
_zm_pkg_update() { _zmL tg && _zm_pkg_update "$@"; }
_zm_pkg_add() { _zmL tg && _zm_pkg_add "$@"; }
_zm_pkg_del() { _zmL tg && _zm_pkg_del "$@"; }
_zm_ca_keep() { _zmL tg && _zm_ca_keep "$@"; }
_zm_clean_job() { _zmL tg && _zm_clean_job "$@"; }
_zm_dns_scrub() { _zmL tg && _zm_dns_scrub "$@"; }
_zm_net_recover() { _zmL tg && _zm_net_recover "$@"; }
reboot_hint_clear() { _zmL tg && reboot_hint_clear "$@"; }
system_reboot() { _zmL system && system_reboot "$@"; }
_zm_net_restore() { _zmL system && _zm_net_restore "$@"; }
_zm_net_prepare() { _zmL system && _zm_net_prepare "$@"; }
_fk_guard() { _zmL forkozz && _fk_guard "$@"; }
_fk_watch() { _zmL forkozz && _fk_watch "$@"; }
_fk_ping_burst() { _zmL forkozz && _fk_ping_burst "$@"; }
zram_status() { _zmL openwrt && zram_status "$@"; }
zram_action() { _zmL openwrt && zram_action "$@"; }
mem_heal() { _zmL openwrt && mem_heal "$@"; }
zm_watch() { _zmL openwrt && zm_watch "$@"; }
zm_alloff() { _zmL openwrt && zm_alloff "$@"; }
do_zm_alloff() { _zmL openwrt && do_zm_alloff "$@"; }
zm_uiram() { _zmL openwrt && zm_uiram "$@"; }
_zui_on() { _zmL openwrt && _zui_on "$@"; }
_zui_off() { _zmL openwrt && _zui_off "$@"; }
_zui_sync() { _zmL openwrt && _zui_sync "$@"; }
jobs_cancel() { _zmL openwrt && jobs_cancel "$@"; }
terms_accept() { _zmL remote && terms_accept "$@"; }
_pend_cancel() { _zmL remote && _pend_cancel "$@"; }
zapret_pending() { _zmL zapret && zapret_pending "$@"; }
do_install_zapret() { _zmL zapret && do_install_zapret "$@"; }
do_install_zapret2() { _zmL zapret && do_install_zapret2 "$@"; }
do_install_zapret_full() { _zmL zapret && do_install_zapret_full "$@"; }
do_remove_zapret() { _zmL zapret && do_remove_zapret "$@"; }
zapret_action() { _zmL zapret && zapret_action "$@"; }
do_remove_zapret2() { _zmL zapret && do_remove_zapret2 "$@"; }
zapret2_action() { _zmL zapret && zapret2_action "$@"; }
do_str_refresh() { _zmL zapret && do_str_refresh "$@"; }
str_refresh() { _zmL zapret && str_refresh "$@"; }
_v_ok() { _zmL zapret && _v_ok "$@"; }
strategy_vall() { _zmL zapret && strategy_vall "$@"; }
_refresh_exclude_file() { _zmL zapret && _refresh_exclude_file "$@"; }
_nfq_normalize() { _zmL zapret && _nfq_normalize "$@"; }
_dc_body() { _zmL zapret && _dc_body "$@"; }
_dc_safe() { _zmL zapret && _dc_safe "$@"; }
_udp443_add() { _zmL zapret && _udp443_add "$@"; }
_discord_str_add() { _zmL zapret && _discord_str_add "$@"; }
ts_check() { _zmL remote && ts_check "$@"; }
strategy_list_v() { _zmL zapret && strategy_list_v "$@"; }
strategy_set_v() { _zmL zapret && strategy_set_v "$@"; }
strategy_main_off() { _zmL zapret && strategy_main_off "$@"; }
do_flowseal_download() { _zmL zapret && do_flowseal_download "$@"; }
strategy_list_flowseal() { _zmL zapret && strategy_list_flowseal "$@"; }
strategy_list_youtube() { _zmL zapret && strategy_list_youtube "$@"; }
strategy_set_youtube() { _zmL zapret && strategy_set_youtube "$@"; }
_dc_has_udp() { _zmL zapret && _dc_has_udp "$@"; }
discord_status() { _zmL zapret && discord_status "$@"; }
discord_off() { _zmL zapret && discord_off "$@"; }
discord_set_fake() { _zmL zapret && discord_set_fake "$@"; }
hosts_auto() { _zmL zapret && hosts_auto "$@"; }
hosts_auto_tick() { _zmL zapret && hosts_auto_tick "$@"; }
hosts_toggle() { _zmL zapret && hosts_toggle "$@"; }
hosts_replace_geohide() { _zmL zapret && hosts_replace_geohide "$@"; }
hosts_reset() { _zmL zapret && hosts_reset "$@"; }
hosts_file_get() { _zmL zapret && hosts_file_get "$@"; }
hosts_file_set() { _zmL zapret && hosts_file_set "$@"; }
_remove_ports_if_present() { _zmL zapret && _remove_ports_if_present "$@"; }
_add_ports_if_missing() { _zmL zapret && _add_ports_if_missing "$@"; }
zapret_ports_get() { _zmL zapret && zapret_ports_get "$@"; }
zapret_ports_set() { _zmL zapret && zapret_ports_set "$@"; }
zapret_ports_migrate() { _zmL zapret && zapret_ports_migrate "$@"; }
_game_active() { _zmL zapret && _game_active "$@"; }
_game_xtreme_undo_opts() { _zmL zapret && _game_xtreme_undo_opts "$@"; }
game_status() { _zmL zapret && game_status "$@"; }
game_toggle_xtreme() { _zmL zapret && game_toggle_xtreme "$@"; }
_zapret_v6_set() { _zmL zapret && _zapret_v6_set "$@"; }
_fw4_offload_set() { _zmL zapret && _fw4_offload_set "$@"; }
_ft_zapret_sync() { _zmL zapret && _ft_zapret_sync "$@"; }
system_toggle_steer_offload_fix() { _zmL system && system_toggle_steer_offload_fix "$@"; }
system_check_connectivity() { _zmL system && system_check_connectivity "$@"; }
system_toggle_quic() { _zmL system && system_toggle_quic "$@"; }
system_toggle_ipv6() { _zmL system && system_toggle_ipv6 "$@"; }
system_toggle_flow_offloading_fix() { _zmL system && system_toggle_flow_offloading_fix "$@"; }
_zm_junk_raw() { _zmL system && _zm_junk_raw "$@"; }
zm_refs_heal() { _zmL system && zm_refs_heal "$@"; }
_zm_bin_put() { _zmL system && _zm_bin_put "$@"; }
_zpg_known() { _zmL system && _zpg_known "$@"; }
_zpg_is_off() { _zmL system && _zpg_is_off "$@"; }
_zpg_used() { _zmL system && _zpg_used "$@"; }
_zpg_pruned() { _zmL system && _zpg_pruned "$@"; }
_zpg_size_put() { _zmL system && _zpg_size_put "$@"; }
_zpg_stub() { _zmL system && _zpg_stub "$@"; }
_zpg_menu_filter() { _zmL system && _zpg_menu_filter "$@"; }
_zpg_rebuild() { _zmL system && _zpg_rebuild "$@"; }
do_zpg_restore() { _zmL system && do_zpg_restore "$@"; }
zm_pages() { _zmL zapret && zm_pages "$@"; }
zm_cleanup() { _zmL system && zm_cleanup "$@"; }
gh_proxy() { _zmL system && gh_proxy "$@"; }
webui() { _zmL system && webui "$@"; }
zm_autoclean() { _zmL system && zm_autoclean "$@"; }
system_uninstall_panel() { _zmL system && system_uninstall_panel "$@"; }
_pg_trace() { _zmL system && _pg_trace "$@"; }
purge_scan() { _zmL system && purge_scan "$@"; }
do_purge() { _zmL system && do_purge "$@"; }
purge_run() { _zmL zapret && purge_run "$@"; }
_bk_lock() { _zmL system && _bk_lock "$@"; }
_bk_unlock() { _zmL system && _bk_unlock "$@"; }
_bk_make() { _zmL system && _bk_make "$@"; }
_bk_auto() { _zmL system && _bk_auto "$@"; }
backup_list() { _zmL system && backup_list "$@"; }
backup_action() { _zmL system && backup_action "$@"; }
_mirror_swap() { _zmL system && _mirror_swap "$@"; }
_mirror_upd_bad() { _zmL system && _mirror_upd_bad "$@"; }
_mirror_auto() { _zmL system && _mirror_auto "$@"; }
mirror_status() { _zmL system && mirror_status "$@"; }
mirror_set() { _zmL system && mirror_set "$@"; }
exclusions_status() { _zmL system && exclusions_status "$@"; }
exclusions_set() { _zmL system && exclusions_set "$@"; }
zsec2_status() { _zmL zapret2 && zsec2_status "$@"; }
_zs2_stage() { _zmL zapret2 && _zs2_stage "$@"; }
zsec2_action() { _zmL zapret2 && zsec2_action "$@"; }
zsec2_sync() { _zmL zapret2 && zsec2_sync "$@"; }
zapret_excl_tick() { _zmL zapret && zapret_excl_tick "$@"; }
zapret_lists_status() { _zmL zapret && zapret_lists_status "$@"; }
zapret_list_get() { _zmL zapret && zapret_list_get "$@"; }
zapret_list_set() { _zmL zapret && zapret_list_set "$@"; }
zapret_list_restore() { _zmL zapret && zapret_list_restore "$@"; }
nfqws_opt_get() { _zmL zapret && nfqws_opt_get "$@"; }
_tg_mt_base() { _zmL tg && _tg_mt_base "$@"; }
_tg_tag_mt() { _zmL tg && _tg_tag_mt "$@"; }
_tg_tag_go() { _zmL tg && _tg_tag_go "$@"; }
_tg_tag_rs() { _zmL tg && _tg_tag_rs "$@"; }
_zm_pkg_reg_drop() { _zmL tg && _zm_pkg_reg_drop "$@"; }
_tg_rs_off() { _zmL tg && _tg_rs_off "$@"; }
_tg_dom_ok() { _zmL tg && _tg_dom_ok "$@"; }
_tg_ext_get() { _zmL tg && _tg_ext_get "$@"; }
_tg_fw_live() { _zmL tg && _tg_fw_live "$@"; }
_tg_ftls_ok() { _zmL tg && _tg_ftls_ok "$@"; }
tg_auto_tick() { _zmL tg && tg_auto_tick "$@"; }
_tg_watch() { _zmL tg && _tg_watch "$@"; }
do_tg_install_mtproto() { _zmL tg && do_tg_install_mtproto "$@"; }
do_tg_remove_mtproto() { _zmL tg && do_tg_remove_mtproto "$@"; }
do_tg_install_socks5() { _zmL tg && do_tg_install_socks5 "$@"; }
do_tg_remove_socks5() { _zmL tg && do_tg_remove_socks5 "$@"; }
do_tg_install_rust() { _zmL tg && do_tg_install_rust "$@"; }
do_tg_remove_rust() { _zmL tg && do_tg_remove_rust "$@"; }
tg_action() { _zmL tg && tg_action "$@"; }
tg_restart_all() { _zmL tg && tg_restart_all "$@"; }
do_tgws_install() { _zmL tg && do_tgws_install "$@"; }
do_tgws_remove() { _zmL tg && do_tgws_remove "$@"; }
tgws_action() { _zmL tg && tgws_action "$@"; }
_test_unstale() { _zmL test && _test_unstale "$@"; }
_test_prepare_urls() { _zmL test && _test_prepare_urls "$@"; }
test_action() { _zmL test && test_action "$@"; }
test_status() { _zmL test && test_status "$@"; }
test_results() { _zmL test && test_results "$@"; }
_zo_rkn_fetch() { _zmL zapret && _zo_rkn_fetch "$@"; }
_zo_reapply() { _zmL zapret && _zo_reapply "$@"; }
zapret_opt_set() { _zmL zapret && zapret_opt_set "$@"; }
_za_last_write() { _zmL test && _za_last_write "$@"; }
do_autobest() { _zmL autoupd && do_autobest "$@"; }
_za_youtube() { _zmL test && _za_youtube "$@"; }
_za_main() { _zmL test && _za_main "$@"; }
_zt_detect() { _zmL test && _zt_detect "$@"; }
_zt_sync() { _zmL test && _zt_sync "$@"; }
system_time_set() { _zmL system && system_time_set "$@"; }
zm_stats_hit() { _zmL system && zm_stats_hit "$@"; }
zm_stats_get() { _zmL system && zm_stats_get "$@"; }
_zm_job_label() { _zmL system && _zm_job_label "$@"; }
zm_update_action() { _zmL system && zm_update_action "$@"; }
do_mixomo_install() { _zmL mixomo && do_mixomo_install "$@"; }
do_mixomo_remove() { _zmL mixomo && do_mixomo_remove "$@"; }
mixomo_action() { _zmL mixomo && mixomo_action "$@"; }
mixomo_config_get() { _zmL mixomo && mixomo_config_get "$@"; }
mixomo_config_set() { _zmL mixomo && mixomo_config_set "$@"; }
mixomo_secure() { _zmL mixomo && mixomo_secure "$@"; }
mixomo_filter_set() { _zmL mixomo && mixomo_filter_set "$@"; }
_mx_has_sub() { _zmL mixomo && _mx_has_sub "$@"; }
mixomo_subscription_set() { _zmL mixomo && mixomo_subscription_set "$@"; }
mixomo_magitrickle_list_set() { _zmL mixomo && mixomo_magitrickle_list_set "$@"; }
mixomo_autorestart_set() { _zmL mixomo && mixomo_autorestart_set "$@"; }
mixomo_ui_action() { _zmL mixomo && mixomo_ui_action "$@"; }
mixomo_warp_status() { _zmL mixomo && mixomo_warp_status "$@"; }
mixomo_warp_config_set() { _zmL mixomo && mixomo_warp_config_set "$@"; }
mixomo_warp_action() { _zmL mixomo && mixomo_warp_action "$@"; }
mixomo_warp_integrate_action() { _zmL mixomo && mixomo_warp_integrate_action "$@"; }
_ver_hm() { _zmL autoupd && _ver_hm "$@"; }
_ver_cron_sync() { _zmL autoupd && _ver_cron_sync "$@"; }
versions_cron() { _zmL autoupd && versions_cron "$@"; }
versions_mode_set() { _zmL autoupd && versions_mode_set "$@"; }
versions_status() { _zmL autoupd && versions_status "$@"; }
_au_on() { _zmL autoupd && _au_on "$@"; }
autoupd_run() { _zmL autoupd && autoupd_run "$@"; }
_au_spawn() { _zmL autoupd && _au_spawn "$@"; }
autoupd_status() { _zmL autoupd && autoupd_status "$@"; }
bytetube_installed() { _zmL bytetube && bytetube_installed "$@"; }
_bytetube_install_byedpi() { _zmL bytetube && _bytetube_install_byedpi "$@"; }
bytetube_sync() { _zmL bytetube && bytetube_sync "$@"; }
do_bytetube_install() { _zmL bytetube && do_bytetube_install "$@"; }
do_bytetube_purge() { _zmL bytetube && do_bytetube_purge "$@"; }
bytetube_action() { _zmL bytetube && bytetube_action "$@"; }
_doh_pkg() { _zmL doh && _doh_pkg "$@"; }
doh_force_set() { _zmL doh && doh_force_set "$@"; }
do_doh_install() { _zmL doh && do_doh_install "$@"; }
do_doh_remove() { _zmL doh && do_doh_remove "$@"; }
doh_remove() { _zmL doh && doh_remove "$@"; }
doh_install() { _zmL doh && doh_install "$@"; }
doh_power() { _zmL doh && doh_power "$@"; }
_doh_boot_auto() { _zmL doh && _doh_boot_auto "$@"; }
_doh_boot_fill() { _zmL doh && _doh_boot_fill "$@"; }
doh_bootstrap_set() { _zmL doh && doh_bootstrap_set "$@"; }
doh_probe() { _zmL doh && doh_probe "$@"; }
doh_check() { _zmL doh && doh_check "$@"; }
doh_set() { _zmL doh && doh_set "$@"; }
_doh_locked() { _zmL doh && _doh_locked "$@"; }
doh_watch() { _zmL doh && doh_watch "$@"; }
_doh_fo_cron() { _zmL doh && _doh_fo_cron "$@"; }
doh_failover_set() { _zmL doh && doh_failover_set "$@"; }
_doh_own_title() { _zmL doh && _doh_own_title "$@"; }
_fk_dns_migrate() { _zmL forkozz && _fk_dns_migrate "$@"; }
_hosts_geo_migrate() { _zmL zapret && _hosts_geo_migrate "$@"; }
dns_presets_migrate() { _zmL doh && dns_presets_migrate "$@"; }
_doh_legacy_fix() { _zmL doh && _doh_legacy_fix "$@"; }
doh_own_set() { _zmL doh && doh_own_set "$@"; }
_dn_ru_ips() { _zmL doh && _dn_ru_ips "$@"; }
dns_net_set() { _zmL doh && dns_net_set "$@"; }
_dn_watch() { _zmL doh && _dn_watch "$@"; }
dns_net_gone() { _zmL doh && dns_net_gone "$@"; }
_rb_list_norm() { _zmL doh && _rb_list_norm "$@"; }
_rb_in() { _zmL doh && _rb_in "$@"; }
_kill_match() { _zmL doh && _kill_match "$@"; }
_st_dnsopt_save() { _zmL steer1 && _st_dnsopt_save "$@"; }
stl_engine_remove() { _zmL steer1 && stl_engine_remove "$@"; }
stl_reload() { _zmL steer1 && stl_reload "$@"; }
_st_diag_human() { _zmL steer1 && _st_diag_human "$@"; }
stl_sub_norm() { _zmL steer1 && stl_sub_norm "$@"; }
stl_sub_nodes() { _zmL steer1 && stl_sub_nodes "$@"; }
stl_sub_check() { _zmL steer1 && stl_sub_check "$@"; }
_st_warp_ownconf() { _zmL steer1 && _st_warp_ownconf "$@"; }
_st_wnet() { _zmL steer1 && _st_wnet "$@"; }
_st_work_main() { _zmL steer1 && _st_work_main "$@"; }
do_steer_excl() { _zmL steer1 && do_steer_excl "$@"; }
steer_devices() { _zmL steer1 && steer_devices "$@"; }
_st_devs_save() { _zmL steer1 && _st_devs_save "$@"; }
_st_splify2() { _zmL steer1 && _st_splify2 "$@"; }
_st_spec_foreign() { _zmL steer1 && _st_spec_foreign "$@"; }
_st_install_steer() { _zmL steer1 && _st_install_steer "$@"; }
_awg_legacy_feeds() { _zmL awg && _awg_legacy_feeds "$@"; }
_awg_kmod_pin_bad() { _zmL awg && _awg_kmod_pin_bad "$@"; }
_awg_kmod_manual() { _zmL awg && _awg_kmod_manual "$@"; }
_awg_kmod_load() { _zmL awg && _awg_kmod_load "$@"; }
_st_install_awg() { _zmL steer1 && _st_install_awg "$@"; }
_st_warp_register() { _zmL steer1 && _st_warp_register "$@"; }
_st_warp_iface_write() { _zmL steer1 && _st_warp_iface_write "$@"; }
_st_fwd_has() { _zmL steer1 && _st_fwd_has "$@"; }
_st_ext_release_fwd() { _zmL steer1 && _st_ext_release_fwd "$@"; }
_st_if_ru() { _zmL steer1 && _st_if_ru "$@"; }
_st_wifs_auto() { _zmL steer1 && _st_wifs_auto "$@"; }
_st_warp_pre_clean() { _zmL steer1 && _st_warp_pre_clean "$@"; }
_st_warp_scan() { _zmL steer1 && _st_warp_scan "$@"; }
_st_warp_alive_if() { _zmL steer1 && _st_warp_alive_if "$@"; }
_st_colo_guard() { _zmL steer1 && _st_colo_guard "$@"; }
do_steer_warp_pick() { _zmL steer1 && do_steer_warp_pick "$@"; }
_st_own_conf_ok() { _zmL steer1 && _st_own_conf_ok "$@"; }
_st_warp_own_iface() { _zmL steer1 && _st_warp_own_iface "$@"; }
_st_warp_park() { _zmL steer1 && _st_warp_park "$@"; }
_st_warp_up() { _zmL steer1 && _st_warp_up "$@"; }
_st_via_ok() { _zmL steer1 && _st_via_ok "$@"; }
_st_via_pick() { _zmL steer1 && _st_via_pick "$@"; }
_st_fetch() { _zmL steer1 && _st_fetch "$@"; }
_st_cdn_url() { _zmL steer1 && _st_cdn_url "$@"; }
_st_cat_build() { _zmL steer1 && _st_cat_build "$@"; }
_st_owncat_build() { _zmL steer1 && _st_owncat_build "$@"; }
_st_tch_build() { _zmL steer1 && _st_tch_build "$@"; }
_st_cat_dl() { _zmL steer1 && _st_cat_dl "$@"; }
_st_set_have() { _zmL steer1 && _st_set_have "$@"; }
_st_srs_get() { _zmL steer1 && _st_srs_get "$@"; }
_st_lists_par() { _zmL steer1 && _st_lists_par "$@"; }
_st_spec_apply() { _zmL steer1 && _st_spec_apply "$@"; }
_st_spec_clear() { _zmL steer1 && _st_spec_clear "$@"; }
_st_kick0() { _zmL steer1 && _st_kick0 "$@"; }
_st_dns_conflict() { _zmL steer1 && _st_dns_conflict "$@"; }
do_steer_dns_fix() { _zmL steer1 && do_steer_dns_fix "$@"; }
_st_cron_restart() { _zmL steer1 && _st_cron_restart "$@"; }
_st_cron_refresh() { _zmL steer1 && _st_cron_refresh "$@"; }
_st_cron_set() { _zmL steer1 && _st_cron_set "$@"; }
_st_down() { _zmL steer1 && _st_down "$@"; }
_st_apply() { _zmL steer1 && _st_apply "$@"; }
_st_selfcheck() { _zmL steer1 && _st_selfcheck "$@"; }
do_steer_install() { _zmL steer1 && do_steer_install "$@"; }
do_steer_warp_setup() { _zmL steer1 && do_steer_warp_setup "$@"; }
_st_own_keep() { _zmL steer1 && _st_own_keep "$@"; }
do_steer_warp_own() { _zmL steer1 && do_steer_warp_own "$@"; }
do_steer_warp_iface() { _zmL steer1 && do_steer_warp_iface "$@"; }
do_steer_warp_remove() { _zmL steer1 && do_steer_warp_remove "$@"; }
do_steer_ext_pick() { _zmL steer1 && do_steer_ext_pick "$@"; }
do_steer_warp_auto() { _zmL steer1 && do_steer_warp_auto "$@"; }
_st_warp_fix() { _zmL steer1 && _st_warp_fix "$@"; }
do_steer_warp_fix() { _zmL steer1 && do_steer_warp_fix "$@"; }
_st_wfix_set() { _zmL steer1 && _st_wfix_set "$@"; }
_st_wfix_cron() { _zmL steer1 && _st_wfix_cron "$@"; }
_st_wfix_tick() { _zmL steer1 && _st_wfix_tick "$@"; }
_st_spec_quick() { _zmL steer1 && _st_spec_quick "$@"; }
_st_spec_quick_warp() { _zmL steer1 && _st_spec_quick_warp "$@"; }
do_steer_dnsopt() { _zmL steer1 && do_steer_dnsopt "$@"; }
do_steer_onfail() { _zmL steer2 && do_steer_onfail "$@"; }
_st_lists_cron_sync() { _zmL steer2 && _st_lists_cron_sync "$@"; }
do_steer_lists() { _zmL steer2 && do_steer_lists "$@"; }
do_steer_stop() { _zmL steer2 && do_steer_stop "$@"; }
_st_need_warp() { _zmL steer2 && _st_need_warp "$@"; }
do_steer_warp_restart() { _zmL steer2 && do_steer_warp_restart "$@"; }
do_steer_warp_endpoint() { _zmL steer2 && do_steer_warp_endpoint "$@"; }
do_steer_warp_recreate() { _zmL steer2 && do_steer_warp_recreate "$@"; }
do_steer_remove() { _zmL steer2 && do_steer_remove "$@"; }
steer_status() { _zmL steer2 && steer_status "$@"; }
_st_cust_split() { _zmL steer2 && _st_cust_split "$@"; }
steer_svc_domflags() { _zmL steer2 && steer_svc_domflags "$@"; }
steer_svc_dom() { _zmL steer2 && steer_svc_dom "$@"; }
steer_svc_find() { _zmL steer2 && steer_svc_find "$@"; }
steer_list_get() { _zmL steer2 && steer_list_get "$@"; }
steer_list_set() { _zmL steer2 && steer_list_set "$@"; }
steer_list_reset() { _zmL steer2 && steer_list_reset "$@"; }
_st_sel_set() { _zmL steer2 && _st_sel_set "$@"; }
_st_sub_filter() { _zmL steer2 && _st_sub_filter "$@"; }
_st_vpn_zone() { _zmL steer2 && _st_vpn_zone "$@"; }
_st_node_down() { _zmL steer2 && _st_node_down "$@"; }
_st_node_failover() { _zmL steer2 && _st_node_failover "$@"; }
_st_vpn_watch() { _zmL steer2 && _st_vpn_watch "$@"; }
do_steer_sub_remove() { _zmL steer2 && do_steer_sub_remove "$@"; }
steer_sub_action() { _zmL steer2 && steer_sub_action "$@"; }
_st_sub_auto_set() { _zmL steer2 && _st_sub_auto_set "$@"; }
do_steer_engine() { _zmL steer2 && do_steer_engine "$@"; }
do_steer_engine_ver() { _zmL steer2 && do_steer_engine_ver "$@"; }
steer_sub_status() { _zmL steer2 && steer_sub_status "$@"; }
steer_sub_tcp() { _zmL steer2 && steer_sub_tcp "$@"; }
_st_bind() { _zmL steer2 && _st_bind "$@"; }
_st_sec_ok() { _zmL steer2 && _st_sec_ok "$@"; }
steer_tun_list() { _zmL steer2 && steer_tun_list "$@"; }
_st_main_tun() { _zmL steer2 && _st_main_tun "$@"; }
_st_tun_check() { _zmL steer2 && _st_tun_check "$@"; }
_st_tun_hook() { _zmL steer2 && _st_tun_hook "$@"; }
do_steer_tunup() { _zmL steer2 && do_steer_tunup "$@"; }
_st_sec_work() { _zmL steer2 && _st_sec_work "$@"; }
_st_secs_ifaces() { _zmL steer2 && _st_secs_ifaces "$@"; }
_st_vpn_any() { _zmL steer2 && _st_vpn_any "$@"; }
do_steer_sub_update_all() { _zmL steer2 && do_steer_sub_update_all "$@"; }
_st_secs_ping_tick() { _zmL steer2 && _st_secs_ping_tick "$@"; }
_st_secs_vpn_watch() { _zmL steer2 && _st_secs_vpn_watch "$@"; }
_st_ping_cron() { _zmL steer2 && _st_ping_cron "$@"; }
steer_ping_tick() { _zmL steer2 && steer_ping_tick "$@"; }
steer_sub_probe() { _zmL steer2 && steer_sub_probe "$@"; }
_st_report() { _zmL steer2 && _st_report "$@"; }
steer_sec_action() { _zmL steer2 && steer_sec_action "$@"; }
_awg_proto_ok() { _zmL awg && _awg_proto_ok "$@"; }
_awg_down() { _zmL awg && _awg_down "$@"; }
awg_status() { _zmL awg && awg_status "$@"; }
do_awg_install() { _zmL awg && do_awg_install "$@"; }
do_awg_remove() { _zmL awg && do_awg_remove "$@"; }
_awg_steer_sync() { _zmL awg && _awg_steer_sync "$@"; }
_awf_ifaces() { _zmL awg && _awf_ifaces "$@"; }
_i1_dns() { _zmL awg && _i1_dns "$@"; }
_i1_stun() { _zmL awg && _i1_stun "$@"; }
_i1_sip() { _zmL awg && _i1_sip "$@"; }
_awg_keys_get() { _zmL awg && _awg_keys_get "$@"; }
do_awg_gen() { _zmL awg && do_awg_gen "$@"; }
_awg_iface_set() { _zmL awg && _awg_iface_set "$@"; }
_awg_conf_kv() { _zmL awg && _awg_conf_kv "$@"; }
do_awg_pick() { _zmL awg && do_awg_pick "$@"; }
_awg_delete() { _zmL awg && _awg_delete "$@"; }
awg_action() { _zmL awg && awg_action "$@"; }
_term_say() { _zmL remote && _term_say "$@"; }
_term_mode() { _zmL remote && _term_mode "$@"; }
_term_stop() { _zmL remote && _term_stop "$@"; }
term_status() { _zmL remote && term_status "$@"; }
do_term_install() { _zmL remote && do_term_install "$@"; }
term_action() { _zmL remote && term_action "$@"; }
_tsc_ver() { _zmL remote && _tsc_ver "$@"; }
_tsc_wan_closed() { _zmL remote && _tsc_wan_closed "$@"; }
_tsc_tg_ensure() { _zmL remote && _tsc_tg_ensure "$@"; }
_st_lan_fw() { _zmL steer2 && _st_lan_fw "$@"; }
steer_lan_list() { _zmL steer2 && steer_lan_list "$@"; }
do_steer_lanset() { _zmL steer2 && do_steer_lanset "$@"; }
_tsc_nft_left() { _zmL remote && _tsc_nft_left "$@"; }
tsc_watch() { _zmL remote && tsc_watch "$@"; }
tsc_status() { _zmL remote && tsc_status "$@"; }
do_tsc_install() { _zmL remote && do_tsc_install "$@"; }
do_tsc_update() { _zmL remote && do_tsc_update "$@"; }
do_tsc_remove() { _zmL remote && do_tsc_remove "$@"; }
tsc_action() { _zmL remote && tsc_action "$@"; }
_mon_htop_close() { _zmL monitor && _mon_htop_close "$@"; }
do_htop_install() { _zmL monitor && do_htop_install "$@"; }
do_htop_remove() { _zmL monitor && do_htop_remove "$@"; }
htop_gone() { _zmL zapret && htop_gone "$@"; }
monitor_action() { _zmL monitor && monitor_action "$@"; }
_watch_line() { _zmL monitor && _watch_line "$@"; }
watch_status() { _zmL monitor && watch_status "$@"; }
watch_set() { _zmL monitor && watch_set "$@"; }
_fk_zash_ensure() { _zmL forkozz && _fk_zash_ensure "$@"; }
_fk_engine_busy() { _zmL forkozz && _fk_engine_busy "$@"; }
_fk_ready() { _zmL forkozz && _fk_ready "$@"; }
_fk_settle() { _zmL forkozz && _fk_settle "$@"; }
_fk_lite_engine() { _zmL forkozz && _fk_lite_engine "$@"; }
_fk_lite_arch() { _zmL forkozz && _fk_lite_arch "$@"; }
_fk_device_setup() { _zmL forkozz && _fk_device_setup "$@"; }
_fk_latest_fetch() { _zmL forkozz && _fk_latest_fetch "$@"; }
_fk_fwd_sync() { _zmL forkozz && _fk_fwd_sync "$@"; }
_fk_naive_auto() { _zmL forkozz && _fk_naive_auto "$@"; }
_fk_restore_old() { _zmL forkozz && _fk_restore_old "$@"; }
_fk_sb_pkg_switch() { _zmL forkozz && _fk_sb_pkg_switch "$@"; }
_fk_sb_init_write() { _zmL forkozz && _fk_sb_init_write "$@"; }
_fk_dnsmasq_clean() { _zmL forkozz && _fk_dnsmasq_clean "$@"; }
_fk_fast_patch() { _zmL forkozz && _fk_fast_patch "$@"; }
_fk_b4_watch() { _zmL forkozz && _fk_b4_watch "$@"; }
_fk_ghdl_patch() { _zmL forkozz && _fk_ghdl_patch "$@"; }
_fk_subck_patch() { _zmL forkozz && _fk_subck_patch "$@"; }
_fk_hdr_patch() { _zmL forkozz && _fk_hdr_patch "$@"; }
_fk_autogrp_watch() { _zmL forkozz && _fk_autogrp_watch "$@"; }
_fk_autogrp_sync() { _zmL forkozz && _fk_autogrp_sync "$@"; }
_fk_listsvia_patch() { _zmL forkozz && _fk_listsvia_patch "$@"; }
_fk_subvia_patch() { _zmL forkozz && _fk_subvia_patch "$@"; }
_fk_reality_patch() { _zmL forkozz && _fk_reality_patch "$@"; }
_fk_rsinit_patch() { _zmL forkozz && _fk_rsinit_patch "$@"; }
_fk_dnslan_patch() { _zmL forkozz && _fk_dnslan_patch "$@"; }
_fk_dnsloop_patch() { _zmL forkozz && _fk_dnsloop_patch "$@"; }
_fk_dnsloop_off() { _zmL forkozz && _fk_dnsloop_off "$@"; }
_fk_rs_watch() { _zmL forkozz && _fk_rs_watch "$@"; }
_fk_fakeip_patch() { _zmL forkozz && _fk_fakeip_patch "$@"; }
_fk_ru_watch() { _zmL forkozz && _fk_ru_watch "$@"; }
_fk_desync_patch() { _zmL forkozz && _fk_desync_patch "$@"; }
_fk_ksgap_patch() { _zmL forkozz && _fk_ksgap_patch "$@"; }
_fk_naivesni_patch() { _zmL forkozz && _fk_naivesni_patch "$@"; }
_fk_ksgap_watch() { _zmL forkozz && _fk_ksgap_watch "$@"; }
_fk_serial_patch() { _zmL forkozz && _fk_serial_patch "$@"; }
_fk_mlkem_patch() { _zmL forkozz && _fk_mlkem_patch "$@"; }
_fk_log_mark() { _zmL forkozz && _fk_log_mark "$@"; }
_fk_lists_wait() { _zmL forkozz && _fk_lists_wait "$@"; }
_fk_lists_report() { _zmL forkozz && _fk_lists_report "$@"; }
_fk_dlc_note() { _zmL forkozz && _fk_dlc_note "$@"; }
_fk_clash_ok() { _zmL forkozz && _fk_clash_ok "$@"; }
_fk_sb_settle() { _zmL forkozz && _fk_sb_settle "$@"; }
_fk_rs_check() { _zmL forkozz && _fk_rs_check "$@"; }
_fk_lists_errors() { _zmL forkozz && _fk_lists_errors "$@"; }
_fk_sub_wait() { _zmL forkozz && _fk_sub_wait "$@"; }
_fk_servers_report() { _zmL forkozz && _fk_servers_report "$@"; }
_fk_check_live() { _zmL forkozz && _fk_check_live "$@"; }
do_fk_install() { _zmL forkozz && do_fk_install "$@"; }
do_fk_remove() { _zmL forkozz && do_fk_remove "$@"; }
_fk_start_once() { _zmL forkozz && _fk_start_once "$@"; }
_fk_reset_runtime() { _zmL forkozz && _fk_reset_runtime "$@"; }
_fk_svc_report() { _zmL forkozz && _fk_svc_report "$@"; }
_fk_rl_learn_run() { _zmL forkozz && _fk_rl_learn_run "$@"; }
_fk_rl_watch() { _zmL forkozz && _fk_rl_watch "$@"; }
_fk_rl_report() { _zmL forkozz && _fk_rl_report "$@"; }
_fk_sub_fmt_auto() { _zmL forkozz && _fk_sub_fmt_auto "$@"; }
_fk_sub_update() { _zmL forkozz && _fk_sub_update "$@"; }
_fk_log_default() { _zmL forkozz && _fk_log_default "$@"; }
_fk_ext_auto() { _zmL forkozz && _fk_ext_auto "$@"; }
do_fk_singbox() { _zmL forkozz && do_fk_singbox "$@"; }
forkop_config_get() { _zmL forkozz && forkop_config_get "$@"; }
forkop_config_set() { _zmL forkozz && forkop_config_set "$@"; }
_st_dnslog_fix() { _zmL steer2 && _st_dnslog_fix "$@"; }
steer_explain() { _zmL steer2 && steer_explain "$@"; }
forkop_action() { _zmL forkozz && forkop_action "$@"; }
_tsc_ip_rules_left() { _zmL remote && _tsc_ip_rules_left "$@"; }
do_tsc_leftovers_clean() { _zmL remote && do_tsc_leftovers_clean "$@"; }
sysinfo_run() { _zmL sysinfo && sysinfo_run "$@"; }
sysinfo_get() { _zmL sysinfo && sysinfo_get "$@"; }
_ab_dns_sync() { _zmL adblock && _ab_dns_sync "$@"; }
_ab_kw_in() { _zmL adblock && _ab_kw_in "$@"; }
adblock_stats_tick() { _zmL adblock && adblock_stats_tick "$@"; }
_ab_free_sync() { _zmL adblock && _ab_free_sync "$@"; }
adblock_status() { _zmL adblock && adblock_status "$@"; }
adblock_action() { _zmL adblock && adblock_action "$@"; }
adblock_cron() { _zmL adblock && adblock_cron "$@"; }
_ab_watch() { _zmL adblock && _ab_watch "$@"; }
_ab_ids() { _zmL adblock && _ab_ids "$@"; }
_ab_src() { _zmL adblock && _ab_src "$@"; }
do_ab_apply() { _zmL adblock && do_ab_apply "$@"; }
owrt_reboot_run() { _zmL openwrt && owrt_reboot_run "$@"; }
owrt_status() { _zmL openwrt && owrt_status "$@"; }
owrt_set() { _zmL openwrt && owrt_set "$@"; }
_pc_sync() { _zmL openwrt && _pc_sync "$@"; }

INSTALL="_zm_pkg_add"; DELETE="_zm_pkg_del"; UPDATE="_zm_pkg_update"
TG_ARCH=""

ZM_A73="aarch64_cortex-a73"
ZM_A73_ALTS="aarch64_cortex-a53 aarch64_generic"
_zm_arch() { awk -F\' '/DISTRIB_ARCH/ {print $2}' /etc/openwrt_release 2>/dev/null; }
_zm_arch_alts() {
	echo "$1"
	[ "$1" = "$ZM_A73" ] && printf '%s\n' $ZM_A73_ALTS
	return 0
}
_zm_arch_accept() {
	local a="$1" c="${ZM_OPKG_CONF:-/etc/opkg.conf}" f="${ZM_APK_ARCH:-/etc/apk/arch}" n cur
	case " $ZM_A73_ALTS " in *" $a "*) ;; *) return 0 ;; esac
	cur="$(_zm_arch)"
	[ "$cur" = "$a" ] && return 0
	case "$cur" in aarch64_*) ;; *) return 0 ;; esac
	if [ "$PKG" = apk ]; then
		[ -d "${f%/*}" ] || return 0
		if [ ! -s "$f" ]; then
			n="$(apk --print-arch 2>/dev/null)"
			[ -n "$n" ] || return 0
			echo "$n" > "$f" || return 1
		fi
		grep -qx "$a" "$f" && return 0
		{ [ -z "$(tail -c 1 "$f")" ] || echo; echo "$a"; } >> "$f" || return 1
	else
		[ -f "$c" ] || return 0
		if ! grep -q '^[[:space:]]*arch[[:space:]]' "$c"; then
			n="$(opkg print-architecture 2>/dev/null | awk '$1 == "arch" && NF >= 3 { print "arch " $2 " " $3 }')"
			case "$n" in *aarch64*) ;; *) return 0 ;; esac
			{ [ -z "$(tail -c 1 "$c")" ] || echo; printf '%s\n' "$n"; } >> "$c" || return 1
		fi
		grep -qE "^[[:space:]]*arch[[:space:]]+$a([[:space:]]|\$)" "$c" && return 0
		{ [ -z "$(tail -c 1 "$c")" ] || echo; echo "arch $a 5"; } >> "$c" || return 1
	fi
	echo "   · Разрешили ставить пакеты $a — на $cur они работают (тот же набор команд ARMv8.0)" >&2
	logger -t zapret-manager "Разрешены пакеты $a (совместимы с $cur)"
	return 0
}

ZM_NL='
'
_zm_re() { case "$1" in *"$ZM_NL"*) return 1 ;; esac; printf '%s\n' "$1" | grep -qE -- "$2"; }

ZM_TMO=""
_zm_tmo_ok() {
	[ -n "$ZM_TMO" ] || { if timeout 1 true >/dev/null 2>&1; then ZM_TMO=1; else ZM_TMO=0; fi; }
	[ "$ZM_TMO" = 1 ]
}
_zm_tmo() {
	local s="$1" p w rc
	shift
	case "$(type "$1" 2>/dev/null)" in *function*) ;; *) if _zm_tmo_ok; then timeout "$s" "$@"; return; fi ;; esac
	case "$s" in ''|*[!0-9]*) s=60 ;; esac
	{ "$@" <&3 3<&- & } 3<&0
	p=$!
	( i=0
	  while [ "$i" -lt "$s" ] && kill -0 "$p" 2>/dev/null; do sleep 1; i=$((i + 1)); done
	  if kill -0 "$p" 2>/dev/null; then kill "$p" 2>/dev/null; sleep 1; kill -9 "$p" 2>/dev/null; fi ) >/dev/null 2>&1 </dev/null &
	w=$!
	wait "$p" 2>/dev/null; rc=$?
	wait "$w" 2>/dev/null
	case "$rc" in 137|143) rc=124 ;; esac
	return $rc
}

ZM_JESC_AWK='function jesc(s,    o, i, c, n) {
	o = ""; n = length(s)
	for (i = 1; i <= n; i++) {
		c = substr(s, i, 1)
		if (c == "\\") o = o "\\\\"
		else if (c == "\"") o = o "\\\""
		else if (c == "\t") o = o "\\t"
		else if (c != "\r") o = o c
	}
	return o
}
'

_zm_zone_sec() {
	local z
	for z in $(uci -q -X show firewall | sed -n "s/^firewall\.\([^.=]*\)=zone\$/\1/p"); do
		[ "$(uci -q get "firewall.$z.name")" = "$1" ] && { echo "$z"; return 0; }
	done
	return 1
}
_zm_zone_of_net() {
	local z
	for z in $(uci -q -X show firewall | sed -n "s/^firewall\.\([^.=]*\)=zone\$/\1/p"); do
		case " $(uci -q get "firewall.$z.network") " in *" $1 "*) uci -q get "firewall.$z.name"; return 0 ;; esac
	done
	return 1
}
_zm_zone_of_tun() {
	local n z
	_zm_zone_of_net "$1" && return 0
	case "$(uci -q get "network.$1.proto")" in gre|grev6) ;; *) return 1 ;; esac
	z="$(uci -q get "network.$1.zone")"
	[ -n "$z" ] && { echo "$z"; return 0; }
	for n in $(uci -q -X show network | sed -n "s/^network\.\([^.=]*\)\.device='@$1'\$/\1/p"); do
		_zm_zone_of_net "$n" && return 0
	done
	return 1
}
_zm_lan_zone() {
	local c="$JOBS_DIR/lanzone" v=""
	if [ -s "$c" ] && { [ ! -e /etc/config/firewall ] || [ "$c" -nt /etc/config/firewall ]; }; then read -r v < "$c"; [ -n "$v" ] && { echo "$v"; return 0; }; fi
	v="$(_zm_lan_zone_find)"
	[ -n "$v" ] && { printf '%s\n' "$v" > "$c.$$" 2>/dev/null && mv -f "$c.$$" "$c" 2>/dev/null; }
	echo "${v:-lan}"
}
_zm_lan_zone_find() {
	local f w
	_zm_zone_of_net lan && return 0
	_zm_zone_sec lan >/dev/null && { echo lan; return 0; }
	w="$(_zm_wan_zone)"
	for f in $(uci -q -X show firewall | sed -n "s/^firewall\.\([^.=]*\)=forwarding\$/\1/p"); do
		[ "$(uci -q get "firewall.$f.dest")" = "$w" ] && { uci -q get "firewall.$f.src"; return 0; }
	done
	echo lan
}
_zm_wan_zone() { _zm_zone_of_net wan || echo wan; }
_zm_lan_nets() {
	local s n=""
	s="$(_zm_zone_sec "$(_zm_lan_zone)")" && n="$(uci -q get "firewall.$s.network")"
	echo "${n:-lan}"
}
_zm_lan_devs() {
	local s n d out=""
	for n in $(_zm_lan_nets); do
		d="$(ifstatus "$n" 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null)"
		[ -n "$d" ] || d="$(ifstatus "$n" 2>/dev/null | jsonfilter -e '@.device' 2>/dev/null)"
		[ -n "$d" ] || d="$(uci -q get "network.$n.device")"
		[ -n "$d" ] && [ -d "/sys/class/net/$d" ] || continue
		case " $out " in *" $d "*) ;; *) out="$out $d" ;; esac
	done
	if s="$(_zm_zone_sec "$(_zm_lan_zone)")"; then
		for d in $(uci -q get "firewall.$s.device"); do
			[ -d "/sys/class/net/$d" ] || continue
			case " $out " in *" $d "*) ;; *) out="$out $d" ;; esac
		done
	fi
	[ -n "$out" ] || out="br-lan"
	echo $out
}
ZMW_STATE="$ZM_STATE_DIR/webui"
_zmw_port() {
	local p
	p="$(uci -q get uhttpd.zmweb.listen_http 2>/dev/null | tr ' ' '\n' | sed -n '1s/.*://p')"
	case "$p" in ''|*[!0-9]*) return 1 ;; esac
	echo "$p"
}
_zm_lan_ip() {
	local n ip d
	ip="$(ifstatus lan 2>/dev/null | jsonfilter -e "@['ipv4-address'][0].address" 2>/dev/null)"
	[ -n "$ip" ] && { echo "$ip"; return 0; }
	for n in $(_zm_lan_nets); do
		[ "$n" = lan ] && continue
		ip="$(ifstatus "$n" 2>/dev/null | jsonfilter -e "@['ipv4-address'][0].address" 2>/dev/null)"
		[ -n "$ip" ] && { echo "$ip"; return 0; }
	done
	ip="$(uci -q get network.lan.ipaddr 2>/dev/null | awk '{ print $1 }' | cut -d/ -f1)"
	[ -n "$ip" ] && { echo "$ip"; return 0; }
	for d in $(_zm_lan_devs); do
		ip="$(ip -4 -o addr show dev "$d" 2>/dev/null | awk '{ print $4; exit }' | cut -d/ -f1)"
		[ -n "$ip" ] && { echo "$ip"; return 0; }
	done
	return 1
}

_pkg_is_installed() {
	if [ "$PKG" = "apk" ]; then apk info -e "$1" >/dev/null 2>&1
	elif [ -f /usr/lib/opkg/status ]; then awk -v p="$1" '$1 == "Package:" { x = ($2 == p) } x && $1 == "Status:" && / (installed|unpacked)$/ { f = 1; exit } END { exit !f }' /usr/lib/opkg/status
	else opkg list-installed 2>/dev/null | grep -q "^$1 "; fi
}
_zm_px_foreign() {
	if [ -x /etc/init.d/tachyon ] || _pkg_is_installed tachyon || _pkg_is_installed luci-app-tachyon; then echo "Tachyon"; return 0; fi
	if [ -x /etc/init.d/forkop ] || _pkg_is_installed forkop || _pkg_is_installed luci-app-forkop; then
		if [ -e /etc/init.d/forkop-support ] || [ -e /usr/share/forkop/mirror-migration.sh ]; then echo "Forkop X"; else echo "Forkop"; fi
		return 0
	fi
	return 1
}
_apk_ver() {
	local v=""
	if [ -s /lib/apk/db/installed ]; then v="$(awk -v p="$1" '/^P:/ { x = (substr($0, 3) == p) } x && /^V:/ { print substr($0, 3); exit }' /lib/apk/db/installed)"
	else v="$(apk info -v 2>/dev/null | sed -n "s/^$1-\([0-9][^ ]*\)\$/\1/p" | head -n1)"; fi
	[ -n "$v" ] && printf '%s\n' "$v"
}
_kv_last() {
	local l v=""
	[ -f "$1" ] || return 0
	while IFS= read -r l || [ -n "$l" ]; do case "$l" in "$2="*) v="${l#"$2="}" ;; esac; done < "$1"
	printf '%s' "$v"
}
_opkg_ver() {
	if [ -f /usr/lib/opkg/status ]; then
		awk -v p="$1" 'function out() { if (x && ok && v != "" && !d) { print v; d = 1 } }
			$1 == "Package:" { out(); if (d) exit; x = ($2 == p); v = ""; ok = 0; next }
			x && $1 == "Version:" { v = $2 } x && $1 == "Status:" && / (installed|unpacked)$/ { ok = 1 } END { out() }' /usr/lib/opkg/status
	else opkg list-installed 2>/dev/null | awk -v p="$1" '$1 == p { print $3; exit }'; fi
}

_ensure_deps() {
	local need=""
	_zm_has curl || need="$need curl"
	command -v unzip >/dev/null 2>&1 || need="$need unzip"
	[ -z "$need" ] && return 0
	echo "==> Не хватает программ:$need — устанавливаем"
	$UPDATE
	$INSTALL $need
}

_zm_kids() {
	local f a b c d r
	for f in /proc/[0-9]*/stat; do
		{ read -r a b c d r < "$f"; } 2>/dev/null || continue
		[ "$d" = "$1" ] && echo "$a"
	done
}

_zm_kill_tree() {
	local c
	[ -n "$1" ] || return 0
	kill -STOP "$1" 2>/dev/null
	for c in $(_zm_kids "$1"); do _zm_kill_tree "$c"; done
	kill -9 "$1" 2>/dev/null
}

_zm_pkg_unlock() {
	pidof opkg >/dev/null 2>&1 || rm -f /var/lock/opkg.lock 2>/dev/null
	return 0
}

_zm_dots() {
	local p="$1" tmo="${2:-900}" i=0 o="${ZM_JOB_LOG:-/dev/null}" shown=0
	[ -n "$ZM_IN_WAIT" ] && o=/dev/null
	while kill -0 "$p" 2>/dev/null; do
		sleep 1
		i=$((i + 1))
		if [ "$i" -ge "$tmo" ]; then
			_zm_kill_tree "$p"
			[ "$shown" = 1 ] && echo >> "$o"
			shown=0
			echo "!! Шаг не завершился за $tmo с — прерываем его, чтобы ничего не зависло" >> "${ZM_JOB_LOG:-/dev/null}"
			[ -n "${ZM_TMO_FLAG:-}" ] && : > "$ZM_TMO_FLAG"
			_zm_pkg_unlock
			break
		fi
		if [ "$i" -ge 20 ]; then
			[ "$shown" = 0 ] && { printf 'Подождите ' >> "$o"; shown=1; }
			[ $((i % 5)) = 0 ] && printf '.' >> "$o"
		fi
	done
	[ "$shown" = 1 ] && echo >> "$o"
	return 0
}

_zm_run() {
	local tmo="$1" p rc t="/tmp/zm-run.$$.$RANDOM"
	shift
	( ZM_IN_WAIT=1; export ZM_IN_WAIT; "$@" ) > "$t" 2>&1 &
	p=$!
	_zm_dots "$p" "$tmo"
	wait "$p" 2>/dev/null
	rc=$?
	cat "$t" 2>/dev/null
	rm -f "$t"
	return $rc
}

_zm_pkg_names() {
	local a out=""
	for a; do
		case "$a" in -*) continue ;; esac
		a="${a##*/}"
		out="$out${out:+, }$a"
	done
	echo "$out"
}

_zm_ca_have() { ls /etc/ssl/certs/*.crt >/dev/null 2>&1; }

job_start() {
	local name="$1"; shift
	local log="$JOBS_DIR/$name.log"
	local pid="$JOBS_DIR/$name.pid"
	if _job_running "$name"; then
		printf '{"started":true,"job":"%s","already_running":true}\n' "$name"
		return 0
	fi
	: > "$log"
	( ZM_JOB_LOG="$log"; export ZM_JOB_LOG; _bk_auto "$@" >>"$log" 2>&1; "$@" >>"$log" 2>&1; rc=$?; _zm_net_restore >>"$log" 2>&1; [ -n "$(tail -c 1 "$log" 2>/dev/null)" ] && echo >>"$log"
		[ "$rc" = 0 ] && _zm_rm_job "$1" && _zm_clean_job "$name" >>"$log" 2>&1
		echo "__DONE__ $rc" >>"$log" ) &
	echo $! > "$pid"
	printf '{"started":true,"job":"%s"}\n' "$name"
}

_zm_rm_job() {
	case "$1" in
		do_steer_sub_remove) return 1 ;;
		do_remove_*|do_*_remove|do_*_remove_*|do_*_uninstall|do_*_purge|do_purge) return 0 ;;
	esac
	return 1
}

_zm_wait() {
	local p rc t="/tmp/zm-wait.$$.$RANDOM" tmo=600
	shift
	( ZM_IN_WAIT=1; export ZM_IN_WAIT; "$@" ) > "$t.o" 2> "$t.e" &
	p=$!
	_zm_dots "$p" "$tmo"
	wait "$p" 2>/dev/null
	rc=$?
	cat "$t.o"
	[ "$rc" = 0 ] || cat "$t.e" >&2
	rm -f "$t.o" "$t.e"
	return $rc
}

_zm_quiet() {
	local p rc t="/tmp/zm-quiet.$$.$RANDOM" tmo=600
	shift
	( ZM_IN_WAIT=1; export ZM_IN_WAIT; "$@" ) > "$t" 2>&1 &
	p=$!
	_zm_dots "$p" "$tmo"
	wait "$p" 2>/dev/null
	rc=$?
	[ "$rc" = 0 ] || tail -n 8 "$t" | sed 's/^/   /'
	rm -f "$t"
	return $rc
}

_zm_sleep() {
	sleep "$1" &
	_zm_dots $! "$(( $1 + 5 ))"
	wait $! 2>/dev/null
	return 0
}

_zm_cron_drop() {
	local pat="$1" what="$2"
	grep -qiE "$pat" "$CRON_FILE" 2>/dev/null || return 0
	echo "   → Убираем задания $what из расписания (cron)"
	grep -viE "$pat" "$CRON_FILE" > "$CRON_FILE.zm" 2>/dev/null
	if [ $? -le 1 ] && [ -f "$CRON_FILE.zm" ]; then cat "$CRON_FILE.zm" > "$CRON_FILE"; fi
	rm -f "$CRON_FILE.zm"
	/etc/init.d/cron restart >/dev/null 2>&1
	echo "   ✓ Расписание очищено"
}

_zm_svc_off() {
	[ -x "/etc/init.d/$1" ] || return 0
	echo "   → Останавливаем службу $1 и убираем её из автозапуска"
	_zm_run 60 "/etc/init.d/$1" stop >/dev/null 2>&1
	"/etc/init.d/$1" disable >/dev/null 2>&1
	return 0
}

ZM_RESOLV_BAK="$JOBS_DIR/resolv.conf.zm-bak"

_zm_dns_ok() { nslookup "$1" >/dev/null 2>&1; }

_zm_host_ok() {
	curl -s -o /dev/null --connect-timeout 6 --max-time 12 "https://$1/" >/dev/null 2>&1
	case $? in 0|22|35|47|52|56|60) return 0 ;; esac
	return 1
}

ZM_REBOOT_HINT="$JOBS_DIR/reboot.hint"

_zm_reboot_hint() {
	mkdir -p "$JOBS_DIR"
	printf '%s\n%s\n' "$1" "$(date +%s)" > "$ZM_REBOOT_HINT"
}

_zm_reboot_hint_get() {
	local ts now
	[ -s "$ZM_REBOOT_HINT" ] || return 0
	ts="$(sed -n 2p "$ZM_REBOOT_HINT" 2>/dev/null)"
	now="$(date +%s)"
	case "$ts" in
		''|*[!0-9]*) rm -f "$ZM_REBOOT_HINT"; return 0 ;;
		*) [ $((now - ts)) -gt 120 ] && { rm -f "$ZM_REBOOT_HINT"; return 0; } ;;
	esac
	head -n1 "$ZM_REBOOT_HINT"
}

_zm_inet_ok() {
	nslookup ya.ru 127.0.0.1 >/dev/null 2>&1 || nslookup cloudflare.com 127.0.0.1 >/dev/null 2>&1 || return 1
	_zm_host_ok ya.ru || _zm_host_ok www.cloudflare.com || _zm_host_ok www.google.com
}

_zm_inet_wait() {
	local t=0
	while [ "$t" -lt "$1" ]; do
		_zm_inet_ok && return 0
		sleep 3; t=$((t + 3))
	done
	return 1
}

_zm_ip_ok() {
	ping -4 -c 1 -W 2 77.88.8.8 >/dev/null 2>&1 || ping -4 -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 ||
		curl -s -o /dev/null --connect-timeout 4 --max-time 6 http://1.1.1.1/ >/dev/null 2>&1
}
_zm_net_why() {
	if _zm_ip_ok; then
		echo "   · Связь по IP есть, а имена сайтов роутер не находит — не работает DNS роутера. Откройте вкладку «DNS over HTTPS» (другой сервер или выключить), не поможет — перезагрузите роутер"
	else
		echo "   · Роутер не достаёт до интернета даже по IP-адресу — перезагрузите роутер; не поможет — проверьте кабель и настройки провайдера (Сеть → Интерфейсы → WAN)"
	fi
}

_zm_after_remove() {
	if _zm_net_recover; then
		_zm_reboot_hint "$1 удалён. Желательно перезагрузить роутер."
		ZM_RB_NOTE="   Желательно перезагрузить роутер — кнопка «Перезагрузить» появилась внизу страницы на 2 минуты"
	else
		_zm_reboot_hint "$1 удалён, но интернет на роутере не отвечает. Перезагрузите роутер."
		ZM_RB_NOTE="!! Перезагрузите роутер — кнопка «Перезагрузить» появилась внизу страницы на 2 минуты"
	fi
}
_zm_rb_note() {
	[ -n "$ZM_RB_NOTE" ] && echo "$ZM_RB_NOTE"
	ZM_RB_NOTE=""
	return 0
}

_zm_if_web() {
	local u
	for u in https://1.1.1.1/cdn-cgi/trace https://www.google.com/generate_204 https://www.cloudflare.com/cdn-cgi/trace; do
		curl -s -o /dev/null --interface "$1" --connect-timeout 4 --max-time 7 "$u" 2>/dev/null && return 0
	done
	return 1
}

_zm_net_own() {
	[ -n "$ZM_JOB_LOG" ] || return 0
	grep -qxF "$ZM_JOB_LOG" "$ZM_RESOLV_BAK.owners" 2>/dev/null || echo "$ZM_JOB_LOG" >> "$ZM_RESOLV_BAK.owners"
}

_zm_net_others() {
	local o
	[ -f "$ZM_RESOLV_BAK.owners" ] || return 1
	while read -r o; do
		[ -n "$o" ] && [ "$o" != "$ZM_JOB_LOG" ] || continue
		_job_running "$(basename "$o" .log)" && return 0
	done < "$ZM_RESOLV_BAK.owners"
	return 1
}

_zm_net_orphan() {
	[ -f "$ZM_RESOLV_BAK" ] || return 1
	if [ -s "$ZM_RESOLV_BAK.owners" ]; then
		_zm_net_others && return 1
		return 0
	fi
	[ -z "$(_zm_busy_job)" ]
}

_zm_net_heal() {
	if [ -f "$ZM_RESOLV_BAK" ]; then _zm_net_own; return 0; fi
	local src=/tmp/resolv.conf
	[ -s "$src" ] || src=/etc/resolv.conf
	[ -s "$src" ] || return 1
	cat "$src" > "$ZM_RESOLV_BAK.new" 2>/dev/null && [ -s "$ZM_RESOLV_BAK.new" ] || { rm -f "$ZM_RESOLV_BAK.new"; return 1; }
	mv -f "$ZM_RESOLV_BAK.new" "$ZM_RESOLV_BAK"
	rm -f "$ZM_RESOLV_BAK.owners"
	_zm_net_own
	printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /tmp/resolv.conf 2>/dev/null || printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
	echo "   → DNS роутера не отвечает — на время операции берём 1.1.1.1 и 9.9.9.9"
}

_zm_local_dns_up() {
	pidof dnsmasq >/dev/null 2>&1 && return 0
	netstat -lnu 2>/dev/null | grep -qE '[[:space:]](127\.0\.0\.1|0\.0\.0\.0|::1?|:::?):53[[:space:]]'
}

_zm_feed_host() {
	local h
	h="$(_mirror_host)"
	h="${h%%/*}"
	echo "${h:-downloads.openwrt.org}"
}

FK_GUARD_PID="$JOBS_DIR/fk-guard.pid"

_fk_fallback_sec() (
	local sec="$1" lock="/tmp/zm-fk-fallback.$1.lock" at=0 now pid r to priority
	case "$sec" in *[!A-Za-z0-9_]*|'') exit 1 ;; esac
	now="$(date +%s)"
	if [ -d "$lock" ]; then
		pid="$(cat "$lock/pid" 2>/dev/null)"
		case "$pid" in ''|*[!0-9]*) ;; *) kill -0 "$pid" 2>/dev/null && exit 0 ;; esac
		at="$(cat "$lock/at" 2>/dev/null)"
		case "$at" in ''|*[!0-9]*) at="$(stat -c %Y "$lock" 2>/dev/null)"; at="${at:-$now}" ;; esac
		[ $((now - at)) -gt 600 ] && rm -rf "$lock"
	fi
	mkdir "$lock" 2>/dev/null || exit 0
	echo "$now" > "$lock/at"
	trap 'rm -rf "$lock"' EXIT
	r="$(_fk_uc fallwatch "$sec" 2>/dev/null)"
	if [ "$(printf '%s' "$r" | jsonfilter -e '@.manual' 2>/dev/null)" = true ]; then _fk_heal_sec "$sec" ".$sec"; exit 0; fi
	[ "$(printf '%s' "$r" | jsonfilter -e '@.changed' 2>/dev/null)" = true ] || exit 0
	to="$(printf '%s' "$r" | jsonfilter -e '@.direct' 2>/dev/null)"
	priority="$(printf '%s' "$r" | jsonfilter -e '@.priority' 2>/dev/null)"
	if [ "$to" = true ]; then logger -t zapret-manager "Forkozz: VPN секции $sec недоступны — её правила временно идут напрямую"
	elif [ "$priority" = true ]; then logger -t zapret-manager "Forkozz: секция $sec выбрала первую доступную подписку по заданному порядку"
	else logger -t zapret-manager "Forkozz: VPN секции $sec снова доступен — возвращаем её правила через VPN"; fi
)

_fk_home_sec() (
	local sec="$1" lock="/tmp/zm-fk-home.$1"
	case "$sec" in *[!A-Za-z0-9_]*|'') exit 1 ;; esac
	if [ -d "$lock" ]; then
		[ -n "$(find "$lock" -maxdepth 0 -mmin +5 2>/dev/null)" ] && rm -rf "$lock"
	fi
	mkdir "$lock" 2>/dev/null || exit 0
	trap 'rm -rf "$lock"' EXIT
	_fk_uc home "$sec" >/dev/null 2>&1
)

_fk_heal_sec() {
	local sec="$1" f="$JOBS_DIR/fk.heal$2" r n=0 name to
	_fk_warm && { rm -f "$f"; return 0; }
	r="$(_fk_uc heal "$sec" 2>/dev/null)"
	[ "$(printf '%s' "$r" | jsonfilter -e '@.dead' 2>/dev/null)" = true ] || { rm -f "$f" "$f.hold"; return 0; }
	if [ "$(printf '%s' "$r" | jsonfilter -e '@.hold' 2>/dev/null)" = true ]; then
		name="$(printf '%s' "$r" | jsonfilter -e '@.name' 2>/dev/null)"
		if [ "$(cat "$f.hold" 2>/dev/null)" != "$name" ]; then
			printf '%s\n' "$name" > "$f.hold"
			logger -t zapret-manager "Forkozz: выбранный сервер «$name» не отвечает — держим его, как задано в настройке"
		fi
		return 0
	fi
	_zm_inet_ok || return 0
	n="$(cat "$f" 2>/dev/null)"; n=$(( ${n:-0} + 1 ))
	echo "$n" > "$f"
	[ "$n" -ge 2 ] || return 0
	[ "$n" -gt 2 ] && [ $((n % 15)) -ne 0 ] && return 0
	r="$(_fk_uc heal "$sec" switch 2>/dev/null)"
	if [ "$(printf '%s' "$r" | jsonfilter -e '@.changed' 2>/dev/null)" = true ]; then
		name="$(printf '%s' "$r" | jsonfilter -e '@.name' 2>/dev/null)"
		to="$(printf '%s' "$r" | jsonfilter -e '@.to' 2>/dev/null)"
		if [ "$(printf '%s' "$r" | jsonfilter -e '@.back' 2>/dev/null)" = true ]; then
			logger -t zapret-manager "Forkozz: сервер «$name» не отвечает — переключились на ${to:-автовыбор}, вернёмся на него, когда он ответит"
		else logger -t zapret-manager "Forkozz: сервер «$name» не отвечает — переключились на ${to:-автовыбор}"; fi
		rm -f "$f"
	fi
	return 0
}

ZRAM_OWN="$ZM_STATE_DIR/zram.own"
_zram_on() { grep -q '^/dev/zram' /proc/swaps 2>/dev/null; }

_zm_job_skip() { case "$1" in versions|sysinfo|*_download|fk-guard) return 0 ;; esac; return 1; }

_zm_rpcd_kick() {
	local i=0
	/etc/init.d/rpcd reload >/dev/null 2>&1
	while [ "$i" -lt 8 ]; do
		sleep 1; i=$((i + 1))
		if [ -n "$1" ]; then eval "$1" >/dev/null 2>&1 && return 0
		else ubus -t 3 list zapret-manager >/dev/null 2>&1 && return 0; fi
	done
	/etc/init.d/rpcd restart >/dev/null 2>&1
	return 1
}

ui_theme_set() {
	[ "$1" = blocks ] && set -- contrast
	[ "$1" = minimal ] && set -- micro
	case "$1" in micro|light|dark|ink|bento|retro|depth|graphite|oled|matrix|neon|synth|noir|contrast|metro|custom|auto) ;; *) echo '{"error":"неизвестная тема"}'; return 1 ;; esac
	mkdir -p "$ZM_STATE_DIR" /www/zm
	printf '%s\n' "$1" > "$ZM_STATE_DIR/ui.theme"
	printf '%s\n' "$1" > /www/zm/theme.txt
	chmod 0644 /www/zm/theme.txt 2>/dev/null
	printf '{"ok":true}\n'
}

ui_look_set() {
	local v="$1"
	[ "${#v}" -le 4000 ] || { echo '{"error":"слишком длинные настройки оформления"}'; return 1; }
	printf '%s' "$v" | grep -qE '^\{[A-Za-z0-9 ":,#._{}-]*\}$' || { echo '{"error":"неверные настройки оформления"}'; return 1; }
	printf '%s' "$v" | jsonfilter -e '@' >/dev/null 2>&1 || { echo '{"error":"неверные настройки оформления"}'; return 1; }
	mkdir -p "$ZM_STATE_DIR" /www/zm
	printf '%s\n' "$v" > "$ZM_STATE_DIR/ui.look"
	printf '%s\n' "$v" > /www/zm/look.json
	chmod 0644 /www/zm/look.json 2>/dev/null
	printf '{"ok":true}\n'
}

UI_NAV_FILE="$ZM_STATE_DIR/ui.nav.hidden"
ui_nav_get() { [ -s "$UI_NAV_FILE" ] || return 0; tr '\n' ' ' < "$UI_NAV_FILE" | sed 's/  */ /g; s/^ //; s/ $//'; }
ui_nav_set() {
	local id out="" n=0
	for id in $(printf '%s' "$1" | tr ',' ' '); do
		printf '%s' "$id" | grep -qE '^[a-z0-9_]{1,32}$' || { echo '{"error":"неверный раздел"}'; return 1; }
		case "$id" in dashboard|thanks) continue ;; esac
		case " $out " in *" $id "*) continue ;; esac
		out="$out $id"; n=$((n + 1))
		[ "$n" -le 64 ] || { echo '{"error":"слишком много разделов"}'; return 1; }
	done
	mkdir -p "$ZM_STATE_DIR"
	if [ -n "$out" ]; then printf '%s\n' $out > "$UI_NAV_FILE"; else rm -f "$UI_NAV_FILE"; fi
	printf '{"ok":true,"hidden":"%s"}\n' "$(ui_nav_get)"
}

terms_get() {
	local v="" t=""
	[ -s "$ZM_TERMS_FILE" ] && read -r v t _ < "$ZM_TERMS_FILE"
	case "$t" in ''|*[!0-9]*) t=0 ;; esac
	printf '{"accepted":%s,"ver":%s,"at":%s}\n' "$([ "$v" = "$ZM_TERMS_VER" ] && echo true || echo false)" "$ZM_TERMS_VER" "$t"
}
ui_flags_get() {
	local f="$ZM_STATE_DIR/ui.flags" out="" sep="" k
	if [ -s "$f" ]; then
		for k in $(grep -E '^[a-z0-9_]{1,48}$' "$f" | sort -u); do out="$out$sep\"$k\":1"; sep=","; done
	fi
	printf '{"flags":{%s}}\n' "$out"
}

ui_flag_set() {
	local f="$ZM_STATE_DIR/ui.flags" k="${1#-}"
	printf '%s' "$k" | grep -qE '^[a-z0-9_]{1,48}$' || { echo '{"error":"неверное имя"}'; return 1; }
	mkdir -p "$ZM_STATE_DIR"
	if [ "$k" != "$1" ]; then
		if grep -qx "$k" "$f" 2>/dev/null; then grep -vx "$k" "$f" > "$f.zm"; mv -f "$f.zm" "$f"; fi
	else
		grep -qx "$k" "$f" 2>/dev/null || echo "$k" >> "$f"
	fi
	printf '{"ok":true}\n'
}

UI_RADIO_FILE="$ZM_STATE_DIR/ui.radio"
_ui_radio_id() { printf '%s' "$1" | grep -qxE '[a-z0-9_]{1,32}'; }
_ui_radio_fav() { [ "${#1}" -le 2000 ] && printf '%s' "$1" | grep -qxE '[a-z0-9_]{1,32}(,[a-z0-9_]{1,32})*'; }
ui_radio_get() {
	local st="" vol="" show="" prev="" fav=""
	[ -s "$UI_RADIO_FILE" ] && read -r st vol show prev fav < "$UI_RADIO_FILE"
	_ui_radio_id "$st" || st=""
	case "$vol" in ''|*[!0-9]*) vol=70 ;; esac
	[ "$vol" -le 100 ] 2>/dev/null || vol=100
	[ "$show" = 0 ] || show=1
	_ui_radio_id "$prev" || prev=""
	_ui_radio_fav "$fav" && fav="\"$(printf '%s' "$fav" | sed 's/,/","/g')\"" || fav=""
	printf '{"station":"%s","volume":%s,"show":%s,"prev":"%s","fav":[%s]}\n' "$st" "$vol" "$([ "$show" = 1 ] && echo true || echo false)" "$prev" "$fav"
}
ui_radio_set() {
	local st vol show prev fav x ost ovol oshow oprev ofav
	read -r st vol show prev fav x <<EOF_ZMR
$1
EOF_ZMR
	_ui_radio_id "$st" || { echo '{"error":"неверная станция"}'; return 1; }
	case "$vol" in ''|*[!0-9]*) echo '{"error":"неверная громкость"}'; return 1 ;; esac
	[ "$vol" -le 100 ] || { echo '{"error":"неверная громкость"}'; return 1; }
	case "$show" in 0|1) ;; *) echo '{"error":"неверный параметр"}'; return 1 ;; esac
	if [ -z "$prev" ]; then
		[ -s "$UI_RADIO_FILE" ] && read -r ost ovol oshow oprev ofav < "$UI_RADIO_FILE"
		prev="${oprev:--}"; fav="${ofav:--}"
	fi
	[ "$prev" = - ] || _ui_radio_id "$prev" || prev=-
	[ -n "$fav" ] || fav=-
	[ "$fav" = - ] || _ui_radio_fav "$fav" || { echo '{"error":"неверный список избранного"}'; return 1; }
	mkdir -p "$ZM_STATE_DIR"
	printf '%s %s %s %s %s\n' "$st" "$vol" "$show" "$prev" "$fav" > "$UI_RADIO_FILE.zm" && mv -f "$UI_RADIO_FILE.zm" "$UI_RADIO_FILE"
	ui_radio_get
}

UI_ICY_DIR="/tmp/.zm-radio-icy"
_ui_icy_age() { local t; t="$(date -r "$1" +%s 2>/dev/null)" || { echo 99999; return; }; echo $(( $(date +%s) - t )); }
_ui_icy_byte() { if _zm_has hexdump; then hexdump -v -e '1/1 "%u"'; else od -An -v -tu1 | tr -d ' \n'; fi; }
_ui_icy_hex() { if _zm_has hexdump; then hexdump -v -e '1/1 "%02x"'; else od -An -v -tx1 | tr -d ' \n'; fi; }
_ui_icy_url() {
	case "$1" in
		o_europa) echo "https://ep256.hostingradio.ru:8052/europaplus256.mp3" ;;
		o_rusradio) echo "https://rusradio.hostingradio.ru/rusradio96.aacp" ;;
		o_hitfm) echo "https://hitfm.hostingradio.ru/hitfm96.aacp" ;;
		o_novoe) echo "http://icecast.newradio.cdnvideo.ru/newradio3" ;;
		o_dfm) echo "https://dfm.hostingradio.ru/dfm96.aacp" ;;
		o_dfmclub) echo "https://dfm-dfmclub.hostingradio.ru/dfmclub96.aacp" ;;
		o_dfmrus) echo "https://dfm-dfmrusdance.hostingradio.ru/dfmrusdance96.aacp" ;;
		o_clubcz) echo "http://radio.ipip.cz:7996/" ;;
		o_retro) echo "https://retro128.streamr.ru/" ;;
		o_avto) echo "http://ic4.101.ru:8000/stream/air/aac/64/100" ;;
		o_nashe) echo "http://nashe128.streamr.ru" ;;
		o_maximum) echo "http://nashe2.hostingradio.ru/rock-128.mp3" ;;
		o_rockarsenal) echo "https://online.rockarsenal.ru/rockarsenal_aacplus" ;;
		o_shokolad) echo "https://choco.hostingradio.ru:10010/fm" ;;
		o_jazz24) echo "https://knkx-live-a.edge.audiocdn.com/6285_256k" ;;
		z_pop|z_club|z_rock|z_disco|z_shanson|z_rus|z_rnb|z_relax|z_zaychata|z_kpop|z_rap|z_metal|z_bass|z_love|z_rurock|z_folk|z_classic) echo "https://abs.zaycev.fm/${1#z_}256k" ;;
		o_*) return 1 ;;
		*) echo "https://radiorecord.hostingradio.ru/$1.aacp" ;;
	esac
}
_ui_icy_dl() {
	local p="$1" f="$UI_ICY_DIR/$1" b="$UI_ICY_DIR/$1.$$" n l k sz off u
	if ! mkdir "$f.lock" 2>/dev/null; then
		[ "$(_ui_icy_age "$f.lock")" -ge 30 ] || return 0
		rm -rf "$f.lock"; mkdir "$f.lock" 2>/dev/null || return 0
	fi
	: > "$f.try"
	u="$(_ui_icy_url "$p")" || u=""
	if [ -z "$u" ]; then : > "$f"
	elif _zm_has curl; then
		command curl -sSL --max-redirs 3 --connect-timeout 5 --max-time 8 -A 'Mozilla/5.0' -H 'Icy-MetaData: 1' -D "$b.h" \
			"$u" 2>/dev/null | head -c 40000 > "$b.bin"
		n="$(grep -i '^icy-metaint:' "$b.h" 2>/dev/null | head -n 1 | tr -dc '0-9' | head -c 6)"
		sz="$(wc -c 2>/dev/null < "$b.bin" | tr -d ' ')"
		if [ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null; then
			off=0
			for k in 1 2; do
				off=$((off + n))
				[ "${sz:-0}" -gt "$off" ] || break
				l="$(tail -c +$((off + 1)) "$b.bin" | head -c 1 | _ui_icy_byte)"
				case "$l" in ''|*[!0-9]*) break ;; esac
				if [ "$l" -gt 0 ]; then
					[ "$sz" -ge $((off + 1 + l * 16)) ] || break
					tail -c +$((off + 2)) "$b.bin" | head -c $((l * 16)) | tr -d '\000' | _ui_icy_hex > "$b.t"
					mv -f "$b.t" "$f"
					break
				fi
				off=$((off + 1))
			done
		elif [ -s "$b.h" ] && [ "${sz:-0}" -gt 0 ]; then
			: > "$f"
		fi
	fi
	rm -f "$b.h" "$b.bin" "$b.t"
	rmdir "$f.lock" 2>/dev/null
	return 0
}
ui_radio_now() {
	local p="$1" f t
	printf '%s' "$p" | grep -qE '^[a-z0-9_]{1,32}$' || { echo '{"error":"неверная станция"}'; return 1; }
	f="$UI_ICY_DIR/$p"
	mkdir -p "$UI_ICY_DIR"
	if [ "$(_ui_icy_age "$f")" -ge 12 ] && [ "$(_ui_icy_age "$f.try")" -ge 12 ]; then _ui_icy_dl "$p"; fi
	if [ ! -f "$f" ] || [ "$(_ui_icy_age "$f")" -ge 120 ]; then printf '{"ok":false,"title":""}\n'; return 0; fi
	t="$(head -c 8200 "$f" | tr -dc '0-9a-f')"
	printf '{"ok":true,"title":"%s"}\n' "$t"
}

ZM_PEND_DIR="$JOBS_DIR/pend"
ZM_PEND_RKN="/opt/zapret/ipset/.zm-pend-rkn"
_pend_list() {
	printf '%s\n' "$CONF" "$ZO_RKN_FLAG" "$ZO_USER_FLAG" "$ZO_IPID_FLAG" "$ZO_DOH_FLAG" "$ZO_GV_FLAG" "$ZC_FILE" "$ZC_BAK" "$ZC_AFTER" \
		"$YV_OFF_FLAG" "$DV_OFF_FLAG" "$ZP_OWN" "$ZP_MANUAL" "$ZO_SCRIPT" "$MAIN_OFF_FLAG" "$ZG_FAKE_FILE"
}
_pend_on() { [ -f "$ZM_PEND_DIR/on" ]; }
_pend_clear() { rm -rf "$ZM_PEND_DIR"; rm -f "$ZM_PEND_RKN"; }
_pend_begin() {
	local d="$ZM_PEND_DIR"
	_pend_on && return 0
	_pend_clear
	mkdir -p "$d/f" || return 1
	_pend_list | awk '{ print NR "\t" $0 }' | while IFS="$(printf '\t')" read -r i f; do
		[ -e "$f" ] || continue
		cp -p "$f" "$d/f/$i" || exit 1
	done || { _pend_clear; return 1; }
	[ -e "$ZO_RKN_FILE" ] && { ln -f "$ZO_RKN_FILE" "$ZM_PEND_RKN" 2>/dev/null || cp -p "$ZO_RKN_FILE" "$ZM_PEND_RKN" 2>/dev/null; }
	: > "$d/on"
}
_pend_same() {
	local d="$ZM_PEND_DIR"
	_pend_on || return 1
	_pend_list | awk '{ print NR "\t" $0 }' | while IFS="$(printf '\t')" read -r i f; do
		if [ -e "$d/f/$i" ]; then cmp -s "$d/f/$i" "$f" || exit 1
		elif [ -e "$f" ]; then exit 1; fi
	done
}
_pend_was() {
	[ -s "$ZM_PEND_DIR/f/1" ] || return 0
	( CONF="$ZM_PEND_DIR/f/1"; ZM_NFQ_BODY=""; ZM_YS=""; ZM_UDP=""; ZM_DOH=""; ZM_RKN=""; ZM_FITS=""; _strat_label ) 2>/dev/null
}

ZM_ALLOFF="$ZM_STATE_DIR/alloff"
_zm_alloff_on() { [ -f "$ZM_ALLOFF/on" ]; }
ZUI_DIR="/tmp/.zm-ui"
ZUI_ARC="/opt/zapret-manager-luci/ui.tgz"
ZUI_INIT="/etc/init.d/zm-ui"
ZUI_FLAG="$ZM_STATE_DIR/ui.ram"
ZUI_PATHS="/www/luci-static/resources/view/zapret-manager /www/luci-static/resources/zapret-manager /www/luci-static/resources/view/bytetube /www/luci-static/resources/bytetube /www/zm /opt/zapret-manager-luci/mod"

zapret_restart() {
	[ -n "$ZM_NO_RESTART" ] && return 0
	if [ -n "$ZM_DEFER" ]; then : > "$ZM_PEND_DIR/dirty" 2>/dev/null; return 0; fi
	_pend_clear
	[ -s "$ZC_FILE" ] && _zc_drop
	_zp_sync
	_yv_ipid_sync
	_zo_gv_sync
	_zo_doh_sync
	if [ -n "$(_fake_missing)" ]; then
		if [ -n "$ZM_JOB_LOG" ]; then _fake_ensure; else _zm_run 25 _fake_ensure >/dev/null 2>&1; fi
	fi
	if _zs2_on && [ -n "$(_fake_missing "$ZS2_OPT")" ]; then
		if [ -n "$ZM_JOB_LOG" ]; then _fake_ensure "$ZS2_OPT"; else _zm_run 25 _fake_ensure "$ZS2_OPT" >/dev/null 2>&1; fi
	fi
	_zs2_sync
	chmod -R a+rX /opt/zapret/ipset /opt/zapret/files 2>/dev/null
	[ -x /opt/zapret/sync_config.sh ] && /opt/zapret/sync_config.sh >/dev/null 2>&1
	_zm_alloff_on && ! pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1 && return 0
	_zp_rsp_fix; rm -f "$ZP_RSP_WAIT"
	/etc/init.d/zapret restart >/dev/null 2>&1
}

# Автоперезапуск nfqws/tpws: procd поднимает упавший процесс через 5 с. Строка живёт в init-скрипте
# пакета Zapret, обновление Zapret её стирает — панель возвращает её при установке, перезапуске и в стороже.
# 300 — сколько секунд процесс должен проработать, чтобы счётчик сбоев обнулился; 5 — пауза перед подъёмом;
# 5 — сколько раз подряд поднимать, если процесс падает быстрее: при битой стратегии procd не крутит его вечно.
ZP_RSP_INIT="/opt/zapret/init.d/openwrt/zapret"
ZP_RSP_LINE='	procd_set_param respawn 300 5 5 # zm-respawn'
ZP_RSP_WAIT="$JOBS_DIR/zp.respawn"
ZP_RSP_SKIP="$JOBS_DIR/zp.respawn.skip"

_zp_rsp_ok() {
	awk -v add="$ZP_RSP_LINE" '/^run_daemon\(\)/ { fn = 1 } fn && /^}/ { fn = 0 }
		fn && /procd_set_param[[:space:]]+respawn/ { n++; if ($0 == add) m++ } END { exit !(n == 1 && m == 1) }' "$ZP_RSP_INIT" 2>/dev/null
}

# 0 — строка вписана сейчас; 1 — уже стоит или Zapret нет; 2 — init-скрипт непривычного вида, его не трогаем
_zp_rsp_fix() {
	local f="$ZP_RSP_INIT" t
	[ -f "$f" ] || return 1
	_zp_rsp_ok && return 1
	[ -f "$ZP_RSP_SKIP" ] && [ ! "$f" -nt "$ZP_RSP_SKIP" ] && return 2
	t="$f.zm.$$"
	if awk -v add="$ZP_RSP_LINE" '/^run_daemon\(\)/ { fn = 1 } fn && /^}/ { fn = 0 }
		fn && /procd_set_param[[:space:]]+respawn/ { next } { print }
		fn && !done && /^[[:space:]]*procd_open_instance[[:space:]]*$/ { print add; done = 1 }
		END { exit !done }' "$f" > "$t" 2>/dev/null && sh -n "$t" 2>/dev/null; then
		if [ -x "$f" ]; then chmod 755 "$t"; else chmod 644 "$t"; fi
		if mv -f "$t" "$f"; then
			rm -f "$ZP_RSP_SKIP"
			logger -t zapret-manager "Zapret: включён автоперезапуск nfqws при сбое"
			return 0
		fi
	fi
	rm -f "$t"
	mkdir -p "$JOBS_DIR"; : > "$ZP_RSP_SKIP"
	logger -t zapret-manager "Zapret: init-скрипт непривычного вида — автоперезапуск nfqws не включён, файл не тронут"
	return 2
}

# 0 — у запущенного Zapret автоперезапуск уже действует (или Zapret не запущен)
_zp_rsp_live() {
	local j r a
	pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1 || return 0
	j="$(ubus -t 5 call service list '{"name":"zapret"}' 2>/dev/null)"
	[ -n "$j" ] || return 0
	r="$(printf '%s' "$j" | jsonfilter -e '@.zapret.instances[*].running' 2>/dev/null | grep -c true)"
	a="$(printf '%s' "$j" | jsonfilter -e '@.zapret.instances[*].respawn.retry' 2>/dev/null | grep -c .)"
	[ "${r:-0}" -le "${a:-0}" ] 2>/dev/null
}

# Вписывает строку и, если Zapret сейчас работает без автоперезапуска, перезапускает его —
# но не во время операций панели, теста стратегий и неприменённых изменений: тогда откладывает до сторожа.
# now — без этих проверок: так зовёт сама установка Zapret, пакет уже запустил его со старым init-скриптом
_zp_rsp_sync() {
	local ch=false rs=false
	if [ ! -f "$ZP_RSP_INIT" ]; then rm -f "$ZP_RSP_WAIT"
	else
		_zp_rsp_fix && ch=true
		if _zp_rsp_ok && ! _zp_rsp_live; then
			if [ "$1" != now ] && { _zm_busy_job >/dev/null 2>&1 || _pend_on || [ -s "$TEST_BACKUP" ]; }; then
				mkdir -p "$JOBS_DIR"; : > "$ZP_RSP_WAIT"
			else
				rm -f "$ZP_RSP_WAIT"
				/etc/init.d/zapret restart >/dev/null 2>&1
				logger -t zapret-manager "Zapret перезапущен, чтобы включился автоперезапуск nfqws"
				rs=true
			fi
		else rm -f "$ZP_RSP_WAIT"; fi
	fi
	printf '{"changed":%s,"restarted":%s}\n' "$ch" "$rs"
}

_strat_label() {
	local s g
	s=$(_nfq_names | sed 's/^#[[:space:]]*//; s/[[:space:]]*$//; /^udp443$/d; /^DoH$/d; /^gvideo[0-9][0-9]*$/d; /^[Nn][Oo][Cc][Hh][Aa][Nn][Gg][Ee]$/d' | tr '\n' ' ' | sed 's/ $//')
	_yv_ipid_on && s="$(printf '%s' "$s" | sed -E 's/(^| )(Yv[0-9]+)( |$)/\1\2z\3/')"
	_udp443_on && s="${s:+$s }QUIC"
	_zo_doh_on && s="${s:+$s }DoH"
	g="$(_zo_gv_cur)"
	[ -n "$g" ] && s="${s:+$s }gVideo$g"
	{ _zc_has || [ -s "$ZC_FILE" ]; } && s="${s:+$s }Custom"
	[ -z "$s" ] && _nfq_opt_body | grep -q -- '^[[:space:]]*--' && s="своя"
	_zo_wss_on && s="${s:+$s }wssize"
	printf '%s' "$s"
}

_zo_rkn_count() {
	local k c n f="$JOBS_DIR/rkn.count"
	[ -s "$ZO_RKN_FILE" ] || { echo 0; return 0; }
	k="$(date -r "$ZO_RKN_FILE" +%s 2>/dev/null)-$(wc -c < "$ZO_RKN_FILE" 2>/dev/null)"
	if [ -s "$f" ]; then
		{ read -r c n; } < "$f" 2>/dev/null
		[ "$c" = "$k" ] && case "$n" in ''|*[!0-9]*) ;; *) echo "$n"; return 0 ;; esac
	fi
	n="$(awk 'NF { n++ } END { print n + 0 }' "$ZO_RKN_FILE" 2>/dev/null)"
	mkdir -p "$JOBS_DIR" 2>/dev/null && echo "$k ${n:-0}" > "$f" 2>/dev/null
	echo "${n:-0}"
}
status() {
	local zr="not_installed" zr_running="false" zr_ver=""
	_test_recover
	_pend_on || [ ! -e "$ZM_PEND_RKN" ] || rm -f "$ZM_PEND_RKN"
	if [ -f /etc/init.d/zapret ]; then
		zr="installed"
		zr_ver="$ZAPRET_VER"
		pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1 && zr_running="true"
	fi

	local zr2="not_installed" zr2_running="false" zr2_luci=""
	if [ -f /etc/init.d/zapret2 ]; then
		zr2="installed"
		/etc/init.d/zapret2 status >/dev/null 2>&1 && zr2_running="true"
		zr2_luci="$(_z2_luci_path)"
	fi

	local strat="" fs_marker="" testing=false test_now="" ZM_NFQ_BODY="" zdd="" zdo=false ZM_YS="" ZM_UDP="" ZM_DOH="" ZM_RKN="" ZM_FITS=""
	if [ "$zr" = installed ]; then
		zdd="$(_zo_doh_hosts)"
		[ -n "$zdd" ] && zdo=true
		zdd="${zdd:-$ZO_DOH_DEF}"
	fi
	if [ -f "$CONF" ]; then
		ZM_NFQ_BODY="$(_nfq_opt_body)"
		ZM_YS="$(_yv_ipid_scan)"
		if _udp443_on; then ZM_UDP=1; else ZM_UDP=0; fi
		if _zo_doh_on; then ZM_DOH=1; else ZM_DOH=0; fi
		if _zo_rkn_on; then ZM_RKN=1; else ZM_RKN=0; fi
		if _zo_rkn_fits; then ZM_FITS=1; else ZM_FITS=0; fi
		strat=$(_strat_label)
		fs_marker=$(sed -n '/^# ZMFS:/{s/^# ZMFS://p;q}' "$CONF")
		if [ -s "$TEST_BACKUP" ] && _test_running; then
			testing=true; test_now="$strat"
			strat=$(CONF="$TEST_BACKUP"; ZM_NFQ_BODY=""; ZM_YS=""; ZM_UDP=""; ZM_DOH=""; ZM_RKN=""; ZM_FITS=""; _strat_label)
			fs_marker=$(sed -n '/^# ZMFS:/{s/^# ZMFS://p;q}' "$TEST_BACKUP")
			[ "$test_now" = "$strat" ] && test_now=""
		fi
	fi

	local zs_yv=false zs_qy=false zs_ex=false zs_rk=false zs_rko=false zs_rkf=false zs_ws=false zs_ul=false zs_ulo=false zs_ip=false zs_yt=false zs_zd=false zs_zdon=false zs_s2=false zs_pd=false zs_pw="" zs_hz=false zs_hzu=false zs_gv=""
	[ -f /opt/zapret-manager-luci/yv_off ] && zs_yv=true
	local zs_mo=false zs_mf=""
	if [ -f "$MAIN_OFF_FLAG" ]; then
		if [ -f "$CONF" ] && [ ! -s "$TEST_BACKUP" ] && _nfq_opt_body | grep -qxF -e "$ZO_EXCL_HL" -e "--hostlist=$ZO_RKN_FILE" -e "$ZO_USER_HL"; then rm -f "$MAIN_OFF_FLAG"
		else zs_mo=true; read -r zs_mf < "$MAIN_OFF_FLAG"; case "$zs_mf" in fs) ;; *) zs_mf=v ;; esac; fi
	fi
	[ -f "$EXPERT_MODE_FILE" ] && zs_ex=true
	[ -f "$ZO_RKN_FLAG" ] && zs_rk=true
	[ -f "$ZO_USER_FLAG" ] && zs_ul=true
	[ -f "$ZO_DOH_FLAG" ] && zs_zd=true
	_zs2_on && zs_s2=true
	_pend_on && { zs_pd=true; zs_pw="$(esc "$(_pend_was)")"; }
	_zx_hdr_on && zs_hz=true
	if [ -f "$CONF" ]; then
		_udp443_on && zs_qy=true
		_zo_rkn_on && zs_rko=true
		{ _zo_rkn_fits || _zo_rkn_on; } && zs_rkf=true
		_zo_wss_on && zs_ws=true
		_zo_user_on && zs_ulo=true
		_yv_ipid_on && zs_ip=true
		[ "${ZM_YS%% *}" -gt 0 ] 2>/dev/null && zs_yt=true
		_zo_doh_on && zs_zdon=true
		_zl_used exclude && zs_hzu=true
		zs_gv="$(_zo_gv_cur)"
	fi
	printf '{"pkg":"%s","zapret":"%s","zapret_running":%s,"zapret_version":"%s","zapret2":"%s","zapret2_running":%s,"strategy":"%s","flowseal":"%s","yv_off":%s,"quic_yt":%s,"expert":%s,"rkn":%s,"rkn_on":%s,"rkn_fits":%s,"rkn_count":%s,"rkn_src":"%s","wssize":%s,"ulist":%s,"ulist_on":%s,"ulist_count":%s,"testing":%s,"test_now":"%s","ipid":%s,"ipid_want":"%s","gv":"%s","gv_want":"%s","gv_list":"%s","yt_tcp":%s,"z2_luci":"%s","zdoh":%s,"zdoh_on":%s,"zdoh_doms":"%s","zdoh_own":%s,"s2":%s,"pending":%s,"pending_was":"%s","hdrezka":%s,"hdrezka_used":%s,"main_off":%s,"main_fam":"%s","vpnskip":%s,"vpnskip_ifs":"%s"}\n' \
		"$PKG" "$zr" "$zr_running" "$(esc "$zr_ver")" "$zr2" "$zr2_running" "$(esc "$strat")" "$(esc "$fs_marker")" \
		"$zs_yv" "$zs_qy" "$zs_ex" "$zs_rk" "$zs_rko" "$zs_rkf" \
		"$(_zo_rkn_count)" "$(_zo_rkn_src)" \
		"$zs_ws" "$zs_ul" "$zs_ulo" "$(_zo_user_count)" "$testing" "$(esc "$test_now")" \
		"$zs_ip" "$(_yv_ipid_want)" "$zs_gv" "$(_zo_gv_want)" "$(_gv_ids | tr '\n' ' ' | sed 's/ $//')" \
		"$zs_yt" "$(esc "$zr2_luci")" "$zs_zd" "$zs_zdon" "$(esc "$zdd")" "$zdo" "$zs_s2" "$zs_pd" "$zs_pw" "$zs_hz" "$zs_hzu" "$zs_mo" "$zs_mf" \
		"$(_zm_zskip_on && echo true || echo false)" "$(_zm_zskip_on && [ -f "$ZSKIP_NFT" ] && sed -n 's/^.*oifname "\([^"]*\)".*$/\1/p' "$ZSKIP_NFT" | tr '\n' ' ' | sed 's/ $//')"
}
_z2_luci_path() {
	grep -ho '"admin/[A-Za-z0-9_/-]*zapret2[A-Za-z0-9_/-]*"' /usr/share/luci/menu.d/*.json 2>/dev/null | tr -d '"' | grep -v 'zapret-manager' |
		awk '{ print length($0) "\t" $0 }' | sort -n | head -n 1 | cut -f 2
}

_z2_arch() { awk -F\' '/DISTRIB_ARCH/ {print $2}' /etc/openwrt_release 2>/dev/null; }
_z2_arch_ok() { case "$(_z2_arch)" in aarch64_*) return 0 ;; esac; return 1; }

ZM_STR_DIR="$ZM_STATE_DIR/str"
ZM_STR_URL="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/files"
ZM_STR_NAMES="StrV StrDiscord StrGVideo"
_str_fetch() {
	local n="$1" f t
	f="$ZM_STR_DIR/$n"; t="$f.dl"
	mkdir -p "$ZM_STR_DIR" || return 1
	rm -f "$t" "$t.c"
	_zm_fetch "$ZM_STR_URL/$n" "$t" 20 || { rm -f "$t"; return 1; }
	tr -d '\r' < "$t" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' > "$t.c"
	rm -f "$t"
	if grep -q '^#' "$t.c" && grep -q '^--' "$t.c" && ! grep -qiE '<(!doctype|html)' "$t.c" && ! grep -q "'" "$t.c"; then
		cmp -s "$t.c" "$f" || cat "$t.c" > "$f"
		rm -f "$t.c"
		return 0
	fi
	rm -f "$t.c"
	ZM_FETCH_ERR="файл $n скачался неполным или битым"
	return 1
}
_str_cached() { [ -s "$ZM_STR_DIR/$1" ] && echo "$ZM_STR_DIR/$1"; }
_str_path() {
	[ -s "$ZM_STR_DIR/$1" ] || _str_fetch "$1" >/dev/null 2>&1
	_str_cached "$1"
}
_str_ids() { local f; f="$(_str_cached "$1")" || return 0; sed -n "s/^#\\($2[0-9][0-9]*\\)\$/\\1/p" "$f"; }
_str_has() { local f; f="$(_str_path "$1")" || return 1; grep -qxF "#$2" "$f"; }
_str_body() { local f; f="$(_str_path "$1")" || return 1; awk -v N="#$2" '/^#/ { p = ($0 == N); next } p' "$f"; }
_dv_ok() { _zm_re "$1" '^[0-9]+$' && _str_has StrDiscord "Dv$1"; }
_gv_ok() { _zm_re "$1" '^[0-9]+$' && _str_has StrGVideo "gVideo$1"; }
_gv_ids() { _str_ids StrGVideo gVideo | sed 's/^gVideo//'; }
_gv_range() { _gv_ids | awk 'NR == 1 { f = $0 } { l = $0 } END { if (NR == 1) printf "gVideo%s", f; else if (NR) printf "gVideo%s–gVideo%s", f, l }'; }
_str_miss() { echo "список стратегий $1 не загружен — проверьте интернет и нажмите «Обновить список» на вкладке YouTube"; }
strategy_vx() { _v_ok "$1" || return 1; echo "#$1"; _str_body StrV "$1"; }
Dv() { _dv_ok "$1" && _str_body StrDiscord "Dv$1"; }

NOCHANGE_RX='#[[:space:]]*nochange'
NOCHANGE_MSG="включено «Не изменять стратегию» (#nochange) — панель её не меняет. Выключите этот переключатель в «Редактировать текущую стратегию», чтобы разрешить изменения"

_nochange_in() { [ -f "$1" ] && grep -qiE "$NOCHANGE_RX" "$1"; }
_nochange_strategy() { _nfq_opt_body | grep -qiE "$NOCHANGE_RX"; }
_nochange_guard() {
	_nochange_strategy || return 0
	printf '{"error":"%s","nochange":true}\n' "$(esc "$NOCHANGE_MSG")"
	return 1
}

_zm_dl_sane() { [ -s "$1" ] && ! head -c 1024 "$1" | grep -qiE '<(!doctype|html|head|body)'; }
_zm_zip_ok() { command -v unzip >/dev/null 2>&1 || return 0; unzip -tq "$1" >/dev/null 2>&1; }
_zm_tgz_ok() { tar -tzf "$1" >/dev/null 2>&1; }

_nochange_restore() {
	local keep="$ZM_STATE_DIR/nochange.$1" f dst
	[ -d "$keep" ] || return 0
	for f in "$keep"/*; do
		[ -f "$f" ] || continue
		dst="$(basename "$f" | sed 's#%#/#g')"
		mkdir -p "$(dirname "$dst")"
		cp -p "$f" "$dst" && echo "   ✓ $(basename "$dst") оставлен как был (#nochange)"
	done
	rm -rf "$keep"
}

_add_gp_domains() {
	_nochange_in /opt/zapret/ipset/zapret-hosts-google.txt && return 0
	local f="/opt/zapret/ipset/zapret-hosts-google.txt" tmp
	mkdir -p "$(dirname "$f")"
	tmp="$f.tmp"
	{
		[ -f "$f" ] && cat "$f"
		printf '%s\n' "gvt1.com" "googleplay.com" "play.google.com" "beacons.gvt2.com" \
			"play.googleapis.com" "play-fe.googleapis.com" "lh3.googleusercontent.com" \
			"android.clients.google.com" "connectivitycheck.gstatic.com" \
			"play-lh.googleusercontent.com" "play-games.googleusercontent.com" \
			"prod-lt-playstoregatewayadapter-pa.googleapis.com" "youtubei.youtube.com" \
			"cloudfunctions.net"
	} | sort -u > "$tmp"
	mv "$tmp" "$f"
}

YV_OFF_FLAG="/opt/zapret-manager-luci/yv_off"
DV_OFF_FLAG="/opt/zapret-manager-luci/dv_off"
MAIN_OFF_FLAG="/opt/zapret-manager-luci/main_off"
ZM_MAIN_RX='^--hostlist-exclude=/opt/zapret/ipset/zapret-hosts-user-exclude[.]txt$|^--hostlist=/opt/zapret/ipset/zapret-hosts-rkn[.]txt$|^--hostlist=/opt/zapret/ipset/zapret-hosts-user[.]txt$'
ZM_MAIN_KEEP='^[ \t]*#|^--hostlist=/opt/zapret/ipset/zapret-hosts-google[.]txt$'
ZM_MAIN_LAST="без неё в стратегии не останется ни одного блока и Zapret ничего не будет делать. Если обход не нужен, остановите Zapret кнопкой «Остановить»"
_nfq_has_prof() { [ -s "$ZC_FILE" ] || _nfq_opt_body | sed '1d;$d' | grep -q '^--'; }
DISCORD_RX='^--filter-l7=discord,stun$|^--filter-udp=19294-19344,50000-50100$|^--filter-tcp=2053,2083,2087,2096,8443$|^--hostlist-domains=discord[.]media$|^#[ \t]*Dv[0-9]+$'

YV_RX='^#[ \t]*Yv[0-9]+$|^--hostlist=/opt/zapret/ipset/zapret-hosts-google[.]txt$'
NFQ_MARK_RX='^[ \t]*#[ \t]*((Yv|Dv|Gv)[0-9]|udp443[ \t]*$|DoH[ \t]*$|gvideo[0-9]+[ \t]*$)'
UDP443_MARK_RX='^[ \t]*#[ \t]*udp443[ \t]*$'

_nfq_drop_profiles() {
	local rc zl=""
	if [ ! -s "$ZC_FILE" ] && _zc_has; then _zc_lift; zl=1; fi
	_nfq_drop_profiles_raw "$@"; rc=$?
	[ -n "$zl" ] && _zc_drop
	return $rc
}
_nfq_drop_profiles_raw() {
	local rx="$1" force="$2" keep="$3" old="$JOBS_DIR/nfq_drop_old" new="$JOBS_DIR/nfq_drop_new" rc
	mkdir -p "$JOBS_DIR"
	awk "/^[[:space:]]*option NFQWS_OPT '\$/ { f = 1 } f" "$CONF" > "$old"
	[ -s "$old" ] || { rm -f "$old"; return 1; }
	grep -q "^[[:space:]]*'[[:space:]]*\$" "$old" || { rm -f "$old"; return 1; }
	awk -v RX="$rx" -v KP="$keep" -v MK="$NFQ_MARK_RX" -v UQ="$UDP443_MARK_RX" -v q="'" '
		function emit(l) { o[++no] = l }
		function flush(   i, drop, real, udp) {
			if (n == 0 && np == 0) return
			drop = 0; real = 0; udp = 0
			for (i = 1; i <= np; i++) if (pc[i] ~ RX) drop = 1
			for (i = 1; i <= n; i++) {
				if (b[i] ~ RX) drop = 1
				if (b[i] !~ /^[ \t]*#/) real++
				if (b[i] == "--filter-udp=443") udp = 1
			}
			if (drop && KP != "") {
				for (i = 1; i <= np; i++) if (pc[i] ~ KP) drop = 0
				for (i = 1; i <= n; i++) if (b[i] ~ KP) drop = 0
			}
			if (drop) removed = 1
			else if (real > 0) {
				for (i = 1; i <= np; i++) if (udp || pc[i] !~ UQ) emit(pc[i])
				if (printed) emit("--new")
				for (i = 1; i <= n; i++) if (udp || b[i] !~ UQ) emit(b[i])
				printed = 1
			}
			n = 0; np = 0
		}
		function hold_in(   i) { for (i = 1; i <= nh; i++) b[++n] = h[i]; nh = 0 }
		NR == 1 { head = $0; next }
		done { tail[++nt] = $0; next }
		$0 ~ ("^[ \t]*" q "[ \t]*$") {
			hold_in(); flush()
			print head
			for (i = 1; i <= nn; i++) print nm[i]
			for (i = 1; i <= no; i++) print o[i]
			print
			done = 1; next
		}
		/^[ \t]*$/ { next }
		$0 == "--new" { flush(); for (k = 1; k <= nh; k++) pc[++np] = h[k]; nh = 0; next }
		/^[ \t]*#/ {
			if ($0 ~ MK) h[++nh] = $0
			else if (!(($0) in seen)) { seen[$0] = 1; nm[++nn] = $0 }
			next
		}
		{ hold_in(); b[++n] = $0 }
		END {
			if (!done) exit 1
			for (i = 1; i <= nt; i++) print tail[i]
			exit (removed ? 0 : 3)
		}' "$old" > "$new"
	rc=$?
	if [ "$rc" = 0 ] || { [ "$rc" = 3 ] && [ -n "$force" ]; }; then
		sed -i "/^[[:space:]]*option NFQWS_OPT '/,\$d" "$CONF"
		cat "$new" >> "$CONF"
	fi
	rm -f "$old" "$new"
	return $rc
}

_nfq_canon() {
	local t="$CONF.zmcanon"
	[ -f "$CONF" ] || return 0
	grep -q "^[[:space:]]*option[[:space:]][[:space:]]*NFQWS_OPT[[:space:]][[:space:]]*'" "$CONF" || return 0
	awk -v q="'" '
		function put(l,   n, i, p) {
			sub(/^[ \t]+/, "", l); sub(/[ \t]+$/, "", l)
			if (l == "") return
			if (l !~ /^--/) { print l; return }
			n = split(l, p, /[ \t]+--/)
			print p[1]
			for (i = 2; i <= n; i++) print "--" p[i]
		}
		{ gsub(/\r/, "") }
		st == 2 || (st == 0 && $0 !~ /^[ \t]*option[ \t]+NFQWS_OPT[ \t]+\047/) { print; next }
		{
			l = $0
			if (st == 0) { sub(/^[ \t]*option[ \t]+NFQWS_OPT[ \t]+\047/, "", l); print "\toption NFQWS_OPT \047"; st = 1 }
			if (l ~ /\047[ \t]*$/) { sub(/\047[ \t]*$/, "", l); e = 1 }
			if (index(l, q)) bad = 1
			put(l)
			if (e) { print q; st = 2 }
		}
		END { exit (bad || st != 2) ? 1 : 0 }' "$CONF" > "$t" 2>/dev/null || { rm -f "$t"; return 1; }
	[ -s "$t" ] || { rm -f "$t"; return 1; }
	cmp -s "$t" "$CONF" || cat "$t" > "$CONF"
	rm -f "$t"
	return 0
}

_nfq_opt_body() {
	if [ -n "$ZM_NFQ_BODY" ]; then printf '%s\n' "$ZM_NFQ_BODY"; return 0; fi
	sed -n "/^[[:space:]]*option NFQWS_OPT '\$/,/^[[:space:]]*'\$/p" "$CONF" 2>/dev/null
}

ZC_FILE="$ZM_STATE_DIR/zapret.custom.lift"
ZC_BAK="$ZM_STATE_DIR/zapret.custom.conf"
ZC_AFTER="$ZM_STATE_DIR/zapret.custom.after"
ZC_START_RX='^[ \t]*#[ \t]*customstart[ \t]*$'
ZC_END_RX='^[ \t]*#[ \t]*customend[ \t]*$'
_zc_has() { _nfq_opt_body | awk -v S="$ZC_START_RX" -v E="$ZC_END_RX" 'tolower($0) ~ S { s = 1 } s && tolower($0) ~ E { f = 1 } END { exit !f }'; }
_zc_norm() {
	awk -v q="'" '
		function flush(   i) { while (nb > 0 && b[nb] == "--new") nb--; for (i = 1; i <= nb; i++) print b[i]; nb = 0 }
		!inb && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { print; inb = 1; nb = 0; next }
		inb && $0 ~ ("^[ \t]*" q "[ \t]*$") { flush(); print; inb = 0; next }
		inb { if ($0 == "--new" && (nb == 0 || b[nb] == "--new")) next; b[++nb] = $0; next }
		{ print }
		END { if (inb) flush() }' "$CONF" > "$CONF.zc" && [ -s "$CONF.zc" ] && cat "$CONF.zc" > "$CONF"
	rm -f "$CONF.zc"
}
_zc_lift() {
	[ -f "$CONF" ] || return 0
	[ -s "$ZC_FILE" ] && _zc_drop
	_zc_has || return 0
	mkdir -p "$ZM_STATE_DIR"
	cp -f "$CONF" "$ZC_BAK"
	awk -v F="$ZC_FILE" -v q="'" -v S="$ZC_START_RX" -v E="$ZC_END_RX" '
		!inb && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { inb = 1; print; next }
		inb && $0 ~ ("^[ \t]*" q "[ \t]*$") { inb = 0; print; next }
		inb && !c && tolower($0) ~ S { c = 1 }
		c { print > F; if (tolower($0) ~ E) c = 0; next }
		{ print }' "$CONF" > "$CONF.zc" || { rm -f "$CONF.zc" "$ZC_FILE" "$ZC_BAK"; return 0; }
	if [ ! -s "$ZC_FILE" ] || [ ! -s "$CONF.zc" ]; then rm -f "$CONF.zc" "$ZC_FILE" "$ZC_BAK"; return 0; fi
	cat "$CONF.zc" > "$CONF"; rm -f "$CONF.zc"
	awk -v S="$ZC_START_RX" -v E="$ZC_END_RX" '{ a[NR] = $0 } END { for (i = 1; i <= NR; i++) { if (a[i] == "--new" && (i == 1 || i == NR || tolower(a[i - 1]) ~ S || tolower(a[i + 1]) ~ E)) continue; print a[i] } }' 		"$ZC_FILE" > "$ZC_FILE.n" && [ -s "$ZC_FILE.n" ] && mv -f "$ZC_FILE.n" "$ZC_FILE"
	rm -f "$ZC_FILE.n"
	_zc_norm
	cp -f "$CONF" "$ZC_AFTER"
	ZC_LIFTED=1
}
_zc_drop() {
	[ -s "$ZC_FILE" ] || { rm -f "$ZC_FILE" "$ZC_BAK" "$ZC_AFTER"; ZC_LIFTED=""; return 0; }
	[ -f "$CONF" ] && grep -q "^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$" "$CONF" || return 0
	if _zc_has; then rm -f "$ZC_FILE" "$ZC_BAK" "$ZC_AFTER"; ZC_LIFTED=""; return 0; fi
	if [ -s "$ZC_BAK" ] && [ -f "$ZC_AFTER" ] && cmp -s "$CONF" "$ZC_AFTER"; then
		cat "$ZC_BAK" > "$CONF"
	else
		awk -v F="$ZC_FILE" '
			!d && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { print; while ((getline l < F) > 0) print l; print "--new"; d = 1; next }
			{ print }' "$CONF" > "$CONF.zc" && [ -s "$CONF.zc" ] && cat "$CONF.zc" > "$CONF"
		rm -f "$CONF.zc"
		_zc_norm
	fi
	rm -f "$ZC_FILE" "$ZC_BAK" "$ZC_AFTER"
	ZC_LIFTED=""
}
_nfq_names() {
	_nfq_opt_body | awk -v S="$ZC_START_RX" -v E="$ZC_END_RX" 'tolower($0) ~ S { c = 1; next } c { if (tolower($0) ~ E) c = 0; next } /^#/ { print }'
}
_udp443_on() { case "$ZM_UDP" in 1) return 0 ;; 0) return 1 ;; esac; _nfq_opt_body | grep -qx -- '--filter-udp=443'; }

youtube_quic_set() {
	local mode="$1"
	[ -f "$CONF" ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	case "$mode" in
		on)
			_udp443_on && { printf '{"ok":true,"quic":true}\n'; return 0; }
			_add_gp_domains
			_udp443_add
			_nfq_normalize ;;
		off)
			_udp443_on || { sed -i '/^[[:space:]]*#[[:space:]]*udp443[[:space:]]*$/d' "$CONF"; printf '{"ok":true,"quic":false}\n'; return 0; }
			_nfq_drop_profiles '^--filter-udp=443$'
			case $? in 0|3) ;; *) echo '{"error":"блок стратегий Zapret (NFQWS_OPT) записан не так, как его пишет панель, — блок QUIC не тронут"}'; return 1 ;; esac
			sed -i '/^[[:space:]]*#[[:space:]]*udp443[[:space:]]*$/d' "$CONF" ;;
		*) echo '{"error":"неизвестное действие"}'; return 1 ;;
	esac
	zapret_restart
	printf '{"ok":true,"quic":%s}\n' "$(_udp443_on && echo true || echo false)"
}

_ts_warning() { grep -q "=ts" "$CONF" 2>/dev/null && echo true || echo false; }

ZM_TS_RX='fooling=([a-z0-9]+,)*ts(,|$)'
_ts_has() { grep -qE -- "$ZM_TS_RX"; }
_ts_parts() {
	awk -v pu="--filter-udp=$PORTS_UDP" -v pt="--filter-tcp=$PORTS_TCP" -v rx="$ZM_TS_RX" '
		function flush(   lab) {
			if (has) {
				seen[g ? "YouTube" : dc ? "Discord" : gm ? "игры" : "основная"] = 1
			}
			has = 0; g = 0; dc = 0; gm = 0
		}
		{ sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, "") }
		$0 == "--new" { flush(); next }
		/^#/ || $0 == "" || $0 == "'"'"'" { next }
		$0 ~ rx { has = 1 }
		/zapret-hosts-google|^--filter-udp=443$/ { g = 1 }
		/discord|19294-19344|2053,2083/ { dc = 1 }
		$0 == pu || $0 == pt || /^--filter-(udp|tcp)=80,88,444-65535$/ { gm = 1 }
		END { flush(); n = split("основная YouTube Discord игры", O, " "); for (i = 1; i <= n; i++) if (O[i] in seen) print O[i] }'
}
_ts_yv_text() { [ -s "$(_yv_file)" ] && awk -v n="#$1" '$0 == n { f = 1; next } /^#Yv[0-9]/ { f = 0 } f' "$(_yv_file)"; }

_flowseal_file() { echo "$JOBS_DIR/flowseal_strategies.txt"; }

FLOWSEAL_FAKES="stun2.bin quic_initial_4pda_to.bin quic_initial_5ka_ru.bin quic_initial_lemana_pro.bin \
quic_initial_rutube_ru.bin quic_initial_steam_chat_com.bin quic_initial_steamcommunity_com.bin \
quic_initial_steamstatic_com.bin quic_initial_tencent_com.bin tls_clienthello_4pda_to.bin \
tls_clienthello_5ka_ru.bin tls_clienthello_awswaf_com.bin tls_clienthello_max_ru.bin \
tls_clienthello_sochi_park.bin tls_clienthello_steam_chat_com.bin tls_clienthello_steamstatic_com.bin \
tls_clienthello_teamspeak_com.bin tls_clienthello_www_sferum_ru.bin tls_clienthello_www_google_com_2.bin"

ZAPRET_FAKE_RAW="${GH_MAIN}/bol-van/zapret/raw/refs/heads/master/files/fake"
ZM_FAKE_RAW="${GH_MAIN}/StressOzz/Zapret-Manager/raw/refs/heads/main/files"
FAKE_FAIL="$JOBS_DIR/fake_fail"
_fake_missing() {
	local f d=/opt/zapret/files/fake
	grep -oE "$d/[A-Za-z0-9_.-]+\.bin" "${1:-$CONF}" 2>/dev/null | sort -u | while read -r f; do
		case "${f##*/}" in ACTIVE_*) continue ;; esac
		[ -s "$f" ] || echo "${f##*/}"
	done
}
ZM_FAKE_OWN="tls_clienthello_www_google_com_2.bin"
_fake_fetch() {
	local d=/opt/zapret/files/fake u srcs err=""
	mkdir -p "$d"
	ZM_FAKE_SRC=""
	srcs="$FLOWSEAL_FAKE_RAW $ZAPRET_FAKE_RAW $ZM_FAKE_RAW"
	case " $ZM_FAKE_OWN " in *" $1 "*) srcs="$ZM_FAKE_RAW $FLOWSEAL_FAKE_RAW" ;; esac
	for u in $srcs; do
		rm -f "$d/$1.zmdl"
		if _zm_fetch "$u/$1" "$d/$1.zmdl" 30; then
			mv -f "$d/$1.zmdl" "$d/$1"; chmod a+r "$d/$1" 2>/dev/null
			case "$u" in "$FLOWSEAL_FAKE_RAW") ZM_FAKE_SRC=Flowseal ;; "$ZAPRET_FAKE_RAW") ZM_FAKE_SRC=zapret ;; *) ZM_FAKE_SRC="Zapret Manager" ;; esac
			return 0
		fi
		case "$u" in "$FLOWSEAL_FAKE_RAW") u=Flowseal ;; "$ZAPRET_FAKE_RAW") u=zapret ;; *) u="Zapret Manager" ;; esac
		err="${err:+$err; }$u — $ZM_FETCH_ERR"
	done
	rm -f "$d/$1.zmdl"
	ZM_FETCH_ERR="$err"
	return 1
}
_fake_get_many() {
	local d=/opt/zapret/files/fake r="$JOBS_DIR/fakes.$$" f n=0 tot=$# batch="" pids="" st src sz why
	ZM_FAKE_OK=0; ZM_FAKE_BAD=0; ZM_FAKE_FAILED=""
	mkdir -p "$d" "$r"
	for f; do
		( if _fake_fetch "$f"; then printf 'ok|%s|%s\n' "$ZM_FAKE_SRC" "$(wc -c < "$d/$f" | tr -d ' ')"; else printf 'bad|%s\n' "$ZM_FETCH_ERR"; fi ) > "$r/$f" 2>/dev/null &
		pids="$pids $!"; batch="$batch $f"; n=$((n + 1))
		[ $((n % 4)) = 0 ] || [ "$n" = "$tot" ] || continue
		wait $pids 2>/dev/null
		for f in $batch; do
			IFS='|' read -r st src sz 2>/dev/null < "$r/$f"
			if [ "$st" = ok ]; then
				ZM_FAKE_OK=$((ZM_FAKE_OK + 1))
				echo "   ✓ $f — $(_zm_size_txt "$sz")$([ "$src" != Flowseal ] && echo " · из $src")"
			else
				why="$(sed -n 's/^bad|//p' "$r/$f" 2>/dev/null)"
				ZM_FAKE_BAD=$((ZM_FAKE_BAD + 1)); ZM_FAKE_FAILED="$ZM_FAKE_FAILED $f"
				echo "   !! $f — не скачался: ${why:-нет ответа}"
			fi
		done
		pids=""; batch=""
	done
	rm -rf "$r"
	return 0
}
_fake_ensure() {
	local f t now miss
	[ -d /opt/zapret ] || return 0
	miss="$(_fake_missing "$1")"
	[ -n "$miss" ] || return 0
	now="$(date +%s)"
	mkdir -p "$JOBS_DIR"
	local want=""
	for f in $miss; do
		t="$(awk -v f="$f" '$1 == f { t = $2 } END { print t }' "$FAKE_FAIL" 2>/dev/null)"
		if [ -n "$t" ] && [ $((now - t)) -lt 600 ]; then echo "!! Нет fake-файла $f (недавно не скачался) — стратегия с ним может не работать"; continue; fi
		want="$want $f"
	done
	[ -n "$want" ] || return 0
	echo "==> Докачиваем fake-файлы для стратегии: $(echo $want | wc -w)"
	_fake_get_many $want
	for f in $want; do
		case " $ZM_FAKE_FAILED " in
			*" $f "*) echo "$f $now" >> "$FAKE_FAIL" ;;
			*) [ -f "$FAKE_FAIL" ] && awk -v f="$f" '$1 != f' "$FAKE_FAIL" > "$FAKE_FAIL.t" && mv -f "$FAKE_FAIL.t" "$FAKE_FAIL" ;;
		esac
	done
	[ "$ZM_FAKE_BAD" = 0 ] || echo "!! Стратегия с недостающими fake-файлами может не работать"
	return 0
}

strategy_set_flowseal() {
	local name="$1" f block q w
	[ "$name" = off ] && { strategy_main_off fs; return; }
	f="$(_flowseal_file)"
	[ -s "$f" ] || { echo '{"error":"список не загружен — сначала обновите"}'; return 1; }
	[ -f "$CONF" ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	case "$name" in *"$ZM_NL"*|*\\*) echo '{"error":"стратегия не найдена"}'; return 1 ;; esac
	block=$(awk -v n="#$name" '$0==n{flag=1; print; next} /^#/ && flag{exit} flag{print}' "$f")
	[ -z "$block" ] && { echo '{"error":"стратегия не найдена"}'; return 1; }
	_udp443_on && q=1
	_zo_wss_on && w=1
	rm -f "$YV_OFF_FLAG" "$DV_OFF_FLAG" "$MAIN_OFF_FLAG"
	_game_xtreme_undo_opts
	_remove_ports_if_present NFQWS_PORTS_UDP "$PORTS_UDP"
	_remove_ports_if_present NFQWS_PORTS_TCP "$PORTS_TCP"
	sed -i '/^# ZMFS:/d' "$CONF"
	{ printf '# ZMFS:%s\n' "$name"; cat "$CONF"; } > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
	sed -i "/option NFQWS_OPT '/,\$d" "$CONF"
	{ echo "	option NFQWS_OPT '"; echo "$block"; echo "'"; } >> "$CONF"
	if ! grep -q "option NFQWS_PORTS_UDP.*19294-19344,50000-50100" "$CONF"; then
		sed -i "/^[[:space:]]*option NFQWS_PORTS_UDP '/s/'\$/,19294-19344,50000-50100'/" "$CONF"
	fi
	if ! grep -q "option NFQWS_PORTS_TCP.*2053,2083,2087,2096,8443" "$CONF"; then
		sed -i "/^[[:space:]]*option NFQWS_PORTS_TCP '/s/'\$/,2053,2083,2087,2096,8443'/" "$CONF"
	fi
	_add_gp_domains
	_refresh_exclude_file
	sed -i '/--new/{N;/--filter-tcp=2802/{s/--new/#Gv0\n--new/;};}' "$CONF"
	if printf '%s\n' "$block" | grep -qxF -e "--filter-udp=$PORTS_UDP" -e "--filter-tcp=$PORTS_TCP"; then
		_add_ports_if_missing NFQWS_PORTS_UDP "$PORTS_UDP"
		_add_ports_if_missing NFQWS_PORTS_TCP "$PORTS_TCP"
	fi
	[ -n "$q" ] && _udp443_add
	_zo_reapply "$w"
	zapret_restart
	printf '{"ok":true,"strategy":"%s","ts_warning":%s}\n' "$(esc "$name")" "$(_ts_warning)"
}

_yv_file() { echo "${ZM_YV_FILE:-$JOBS_DIR/youtube_strategies.txt}"; }

do_yv_download() {
	_ensure_deps
	local out; out="$(_yv_file)"
	echo "==> Скачиваем список стратегий для YouTube"
	_zm_fetch "$STR_URL" "$out" 20 || { echo "ОШИБКА скачивания: $ZM_FETCH_ERR"; return 1; }
	[ -d /opt/zapret ] && [ -n "$(_fake_missing "$out")" ] && _fake_ensure "$out"
	echo "==> Готово, стратегий: $(grep -c '^#Yv' "$out")"
	do_str_refresh || true
}

_dc_has_tcp() { _dc_body | grep -qx -- '--filter-tcp=2053,2083,2087,2096,8443'; }
_dc_tcp_now() {
	_dc_body | awk '
		go && ($0 == "--new" || /^[ \t]*#/) { exit }
		go { print; next }
		$0 == "--filter-tcp=2053,2083,2087,2096,8443" { go = 1; print }'
}
_dc_fail() {
	cat "$1" > "$CONF"; rm -f "$1"
	[ -n "$2" ] && { mkdir -p "$(dirname "$DV_OFF_FLAG")"; touch "$DV_OFF_FLAG"; }
	printf '{"error":"%s"}\n' "$(esc "$3")"
	return 1
}
ZM_DC_BAD="блок стратегий Zapret (NFQWS_OPT) записан не так, как его пишет панель, — Discord-часть не тронута"
ZM_DC_GUARD="правка стратегии Discord повредила бы блок NFQWS_OPT — изменения отменены, конфигурация Zapret осталась прежней"

discord_set_dv() {
	local num="$1" bak wasoff="" t
	[ "$num" = off ] && { discord_off; return; }
	_zm_re "$num" '^[0-9]+$' || { echo '{"error":"некорректный номер Dv"}'; return 1; }
	_dv_ok "$num" || { printf '{"error":"%s"}\n' "$(esc "$([ -n "$(_str_cached StrDiscord)" ] && echo "стратегии Dv$num нет в списке" || _str_miss Discord)")"; return 1; }
	[ -f "$CONF" ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	_nfq_canon || { printf '{"error":"%s"}\n' "$ZM_DC_BAD"; return 1; }
	[ -f "$DV_OFF_FLAG" ] && wasoff=1
	mkdir -p "$JOBS_DIR"; bak="$JOBS_DIR/discord.conf.bak"; t="$JOBS_DIR/discord.dv"
	cp -f "$CONF" "$bak"
	rm -f "$DV_OFF_FLAG"
	if ! _dc_has_udp || ! _dc_has_tcp; then
		_nfq_drop_profiles "$DISCORD_RX"
		case $? in 0|3) ;; *) _dc_fail "$bak" "$wasoff" "$ZM_DC_BAD"; return 1 ;; esac
		_discord_str_add
		_dc_has_tcp || { _dc_fail "$bak" "$wasoff" "не удалось добавить блок Discord — сначала выберите основную стратегию"; return 1; }
	fi
	Dv "$num" > "$t"
	awk -v F="$t" -v N="#Dv$num" -v q="'" -v CS="$ZC_START_RX" -v CE="$ZC_END_RX" '
		!inb && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { inb = 1; print; next }
		inb && $0 ~ ("^[ \t]*" q "[ \t]*$") { inb = 0; sk = 0; print; next }
		!inb { print; next }
		cs { print; if (tolower($0) ~ CE) cs = 0; next }
		tolower($0) ~ CS { sk = 0; cs = 1; print; next }
		sk { if ($0 == "--new" || $0 ~ /^[ \t]*#/) sk = 0; else next }
		/^[ \t]*#[ \t]*Dv[0-9]+[ \t]*$/ { if (!mk) print N; mk = 1; next }
		!dn && $0 == "--filter-tcp=2053,2083,2087,2096,8443" {
			if (!mk) { print N; mk = 1 }
			while ((getline l < F) > 0) print l
			close(F); dn = 1; sk = 1; next
		}
		{ print }
		END { exit dn ? 0 : 1 }' "$CONF" > "$CONF.zmd" && [ -s "$CONF.zmd" ] && cat "$CONF.zmd" > "$CONF"
	rm -f "$CONF.zmd" "$t"
	_dc_safe "$bak" && [ "$(_dc_tcp_now)" = "$(Dv "$num")" ] || { _dc_fail "$bak" "$wasoff" "$ZM_DC_GUARD"; return 1; }
	rm -f "$bak"
	zapret_restart
	printf '{"ok":true,"dv":"Dv%s"}\n' "$num"
}

_hosts_block() {
	case "$1" in
		nalog) printf '%s\n' \
			"#Nalog" \
			"213.24.64.175 lkfl2.nalog.ru" \
			"213.24.64.181 lknpd.nalog.ru" ;;
		ntc) printf '%s\n' \
			"#ntc.party" \
			"130.255.77.28 ntc.party" ;;
		instagram) printf '%s\n' \
			"#Instagram&Facebook" \
			"57.144.222.34 instagram.com www.instagram.com" \
			"157.240.9.174 instagram.com www.instagram.com" \
			"157.240.245.174 instagram.com www.instagram.com b.i.instagram.com z-p42-chat-e2ee-ig.facebook.com help.instagram.com" \
			"157.240.205.174 instagram.com www.instagram.com" \
			"57.144.244.192 static.cdninstagram.com graph.instagram.com i.instagram.com api.instagram.com edge-chat.instagram.com" \
			"31.13.66.63 scontent.cdninstagram.com scontent-hel3-1.cdninstagram.com" \
			"57.144.244.1 facebook.com www.facebook.com fb.com fbsbx.com" \
			"57.144.244.128 static.xx.fbcdn.net scontent.xx.fbcdn.net" \
			"31.13.67.20 scontent-hel3-1.xx.fbcdn.net" ;;
		librusec) printf '%s\n' \
			"#lib.rus.ec" \
			"185.39.18.98 lib.rus.ec www.lib.rus.ec" ;;
		ai_openai) printf '%s\n' \
			"#OpenAI" \
			"45.155.204.190 chatgpt.com ab.chatgpt.com auth.openai.com auth0.openai.com platform.openai.com cdn.oaistatic.com" \
			"45.155.204.190 tcr9i.chat.openai.com webrtc.chatgpt.com android.chat.openai.com api.openai.com operator.chatgpt.com" \
			"45.155.204.190 sora.chatgpt.com sora.com videos.openai.com ios.chat.openai.com cdn.auth0.com files.oaiusercontent.com" ;;
		ai_claude) printf '%s\n' \
			"#Claude" \
			"45.155.204.190 claude.ai console.anthropic.com api.anthropic.com" ;;
		ai_gemini) printf '%s\n' \
			"#Gemini" \
			"45.155.204.190 gemini.google.com" ;;
		ai_aistudio) printf '%s\n' \
			"#AIStudio" \
			"45.155.204.190 aistudio.google.com generativelanguage.googleapis.com aitestkitchen.withgoogle.com aisandbox-pa.googleapis.com" \
			"45.155.204.190 webchannel-alkalimakersuite-pa.clients6.google.com alkalimakersuite-pa.clients6.google.com assistant-s3-pa.googleapis.com" \
			"45.155.204.190 proactivebackend-pa.googleapis.com robinfrontend-pa.googleapis.com o.pki.goog labs.google labs.google.com notebooklm.google" \
			"45.155.204.190 notebooklm.google.com jules.google.com stitch.withgoogle.com" ;;
		ai_grok) printf '%s\n' \
			"#Grok" \
			"45.155.204.190 grok.com accounts.x.ai assets.grok.com" ;;
		ai_copilot) printf '%s\n' \
			"#Microsoft" \
			"45.155.204.190 copilot.microsoft.com sydney.bing.com edgeservices.bing.com rewards.bing.com" \
			"45.155.204.190 xsts.auth.xboxlive.com xgpuwebf2p.gssv-play-prod.xboxlive.com xgpuweb.gssv-play-prod.xboxlive.com" \
			"45.155.204.190 xboxdesignlab.xbox.com" ;;
		ai_deepl) printf '%s\n' \
			"#DeepL" \
			"45.155.204.190 deepl.com www.deepl.com www2.deepl.com login-wall.deepl.com w.deepl.com dict.deepl.com ita-free.www.deepl.com" \
			"45.155.204.190 write-free.www.deepl.com experimentation.deepl.com experimentation-grpc.deepl.com ita-free.app.deepl.com" \
			"45.155.204.190 ott.deepl.com api-free.deepl.com backend.deepl.com clearance.deepl.com errortracking.deepl.com" \
			"45.155.204.190 oneshot-free.www.deepl.com checkout.www.deepl.com gtm.deepl.com auth.deepl.com shield.deepl.com" ;;
		ai_elevenlabs) printf '%s\n' \
			"#ElevenLabs" \
			"45.155.204.190 elevenlabs.io api.us.elevenlabs.io elevenreader.io api.elevenlabs.io help.elevenlabs.io" ;;
		ai_windsurf) printf '%s\n' \
			"#Windsurf" \
			"45.155.204.190 windsurf.com codeium.com server.codeium.com web-backend.codeium.com marketplace.windsurf.com" \
			"45.155.204.190 unleash.codeium.com inference.codeium.com windsurf-stable.codeium.com" \
			"144.31.14.104 windsurf-telemetry.codeium.com" ;;
		ai_trae) printf '%s\n' \
			"#Trae.ai" \
			"45.155.204.190 trae-api-sg.mchost.guru api.trae.ai api-sg-central.trae.ai api16-normal-alisg.mchost.guru" ;;
		ai_manus) printf '%s\n' \
			"#Manus" \
			"45.155.204.190 manus.im api.manus.im" ;;
		ai_notion) printf '%s\n' \
			"#Notion" \
			"45.155.204.190 www.notion.so calendar.notion.so" ;;
		twitch) printf '%s\n' \
			"#Twitch" \
			"45.155.204.190 usher.ttvnw.net gql.twitch.tv" ;;
		telegram) printf '%s\n' \
			"#TelegramWeb" \
			"149.154.167.220 core.telegram.org api.telegram.org flora.web.telegram.org kws1-1.web.telegram.org kws1.web.telegram.org kws2-1.web.telegram.org kws2.web.telegram.org kws4-1.web.telegram.org" \
			"149.154.167.220 kws4.web.telegram.org kws5-1.web.telegram.org kws5.web.telegram.org pluto-1.web.telegram.org pluto.web.telegram.org td.telegram.org telegram.dog" \
			"149.154.167.220 telegram.me telegram.org telegram.space telesco.pe venus.web.telegram.org web.telegram.org zws1-1.web.telegram.org zws1.web.telegram.org" \
			"149.154.167.220 tg.dev t.me zws2-1.web.telegram.org zws2.web.telegram.org zws4-1.web.telegram.org zws5-1.web.telegram.org zws5.web.telegram.org" ;;
		spotify) printf '%s\n' \
			"#Spotify" \
			"45.155.204.190 api.spotify.com login5.spotify.com encore.scdn.co gew1-spclient.spotify.com spclient.wg.spotify.com" \
			"45.155.204.190 api-partner.spotify.com aet.spotify.com www.spotify.com accounts.spotify.com open.spotify.com" \
			"45.155.204.190 accounts.scdn.co gew1-dealer.spotify.com open-exp.spotifycdn.com www-growth.scdn.co" ;;
		rutor) printf '%s\n' \
			"#rutor" \
			"172.66.159.63 rutor.info d.rutor.info" ;;
		scell) printf '%s\n' \
			"#Supercell" \
			"103.27.157.38 accounts.supercell.com cdn.id.supercell.com clashofclans.inbox.supercell.com game-assets.brawlstarsgame.com" \
			"103.27.157.38 game-assets.clashofclans.com game-assets.clashroyaleapp.com security.id.supercell.com store.supercell.com" \
			"31.25.239.132 accounts.supercell.com cdn.id.supercell.com clashofclans.inbox.supercell.com game-assets.brawlstarsgame.com" \
			"31.25.239.132 game-assets.clashofclans.com game-assets.clashroyaleapp.com game.boombeachgame.com game.mocogame.com security.id.supercell.com store.supercell.com" \
			"185.246.223.127 game.brawlstarsgame.com" \
			"62.133.62.97 game.clashroyaleapp.com" \
			"193.23.209.189 gamea.clashofclans.com" \
			"108.61.167.26 game.squadbustersgame.com" ;;
		githubraw) printf '%s\n' \
			"#githubusercontent.com" \
			"146.75.22.132 objects.githubusercontent.com release-assets.githubusercontent.com raw.githubusercontent.com private-user-images.githubusercontent.com gist.githubusercontent.com" \
			"146.75.22.132 camo.githubusercontent.com avatars.githubusercontent.com avatars0.githubusercontent.com avatars1.githubusercontent.com avatars2.githubusercontent.com avatars3.githubusercontent.com avatars4.githubusercontent.com avatars5.githubusercontent.com" ;;
		github) printf '%s\n' \
			"#github.com" \
			"140.82.114.3 github.com" \
			"185.199.110.154 github.githubassets.com" \
			"185.199.110.133 camo.githubassets.com" ;;
		spotifyext) printf '%s\n' \
			"#SpotifyEXT" \
			"45.155.204.190 spotify.com www.spotify.com accounts.spotify.com login.spotify.com login5.spotify.com login.app.spotify.com auth.spotify.com account.spotify.com api.spotify.com api-partner.spotify.com spclient.wg.spotify.com gew1-spclient.spotify.com" \
			"45.155.204.190 guc3-spclient.spotify.com gae2-spclient.spotify.com gue1-spclient.spotify.com gnl-spclient.spotify.com spclient.spotify.com ap-gew1.spotify.com ap-gue1.spotify.com ap-gae2.spotify.com ap-gew4.spotify.com ap-sto3.spotify.com" \
			"45.155.204.190 ap-guc3.spotify.com ap.spotify.com apresolve.spotify.com aet.spotify.com gew1-dealer.g2.spotify.com guc3-dealer.g2.spotify.com gue1-dealer.g2.spotify.com dealer.spotify.com dealer-wg.spotify.com edge-web.dual-gslb.spotify.com" \
			"45.155.204.190 client.spotify.com web-partner.spotify.com connect.spotify.com gce.spotify.com clienttoken.spotify.com exp.wg.spotify.com pixel.spotify.com pixel-static.spotify.com image-upload.spotify.com content.spotify.com analytics.spotify.com" \
			"45.155.204.190 crashdump.spotify.com log.spotify.com logger.spotify.com metrics.spotify.com desktop.spotify.com audio-fa-tls13.spotifycdn.com heads-fa-tls13.spotifycdn.com heads4-fa-tls13.spotifycdn.com image-cdn-fa.spotifycdn.com" \
			"45.155.204.190 concerts.spotifycdn.com mrkt.spotifycdn.com pickasso.spotifycdn.com podz-content.spotifycdn.com seed-mix-image.spotifycdn.com thisis-images.spotifycdn.com wap.spotifycdn.com web-sdk-assets.spotifycdn.com spotifycdn.com spotifycdn.net" \
			"35.186.224.24 open.spotify.com" \
			"162.159.141.124 audio4-fa-tls13.spotifycdn.com audio-cf.spotifycdn.com open-exp.spotifycdn.com" \
			"23.36.163.34 audio-ak-spotify-com.akamaized.net" \
			"2.16.168.44 audio4-ak-spotify-com.akamaized.net" \
			"199.232.210.248 scdn.co i.scdn.co line-up.scdn.co mosaic.scdn.co daily-mix.scdn.co lineup-images.scdn.co encore.scdn.co image-cdn-fa.scdn.co accounts.scdn.co www.scdn.co www-growth.scdn.co av.scdn.co seafoam.scdn.co" \
			"23.48.23.145 heads-ak-spotify-com.akamaized.net" \
			"45.155.204.190 xpui.app.spotify.com" ;;
		roblox) printf '%s\n' \
			"#tr.rbxcdn.com" \
			"108.156.22.8 tr.rbxcdn.com" \
			"108.157.32.114 tr.rbxcdn.com" \
			"18.65.147.108 tr.rbxcdn.com" \
			"18.65.147.112 tr.rbxcdn.com" \
			"13.224.181.18 tr.rbxcdn.com" \
			"13.224.181.74 tr.rbxcdn.com" \
			"54.230.253.22 tr.rbxcdn.com" \
			"54.230.253.81 tr.rbxcdn.com" \
			"54.230.253.48 tr.rbxcdn.com" \
			"54.230.253.59 tr.rbxcdn.com" \
			"143.204.214.34 tr.rbxcdn.com" \
			"143.204.214.67 tr.rbxcdn.com" \
			"143.204.214.92 tr.rbxcdn.com" \
			"99.84.181.25 tr.rbxcdn.com" \
			"99.84.181.63 tr.rbxcdn.com" \
			"65.8.158.45 tr.rbxcdn.com" \
			"65.8.158.112 tr.rbxcdn.com" ;;
		rutracker) printf '%s\n' \
			"#Rutracker" \
			"172.67.182.196 rutracker.org" ;;
		tapeop) printf '%s\n' \
			"#tapeop.dev" \
			"216.24.57.251 www.tapeop.dev tapeop.dev" \
			"216.24.57.3 www.tapeop.dev tapeop.dev" ;;
		finland) echo "#Discord Finland"; awk 'BEGIN { for (i = 10000; i <= 10199; i++) print "104.25.158.178 finland" i ".discord.media" }' ;;
		*) return 1 ;;
	esac
}

_hosts_drop_lines() {
	local tmp="$HOSTS_FILE.zmtmp" list="$HOSTS_FILE.zmdrop"
	cat > "$list"
	awk -v list="$list" 'function n(s) { gsub(/\r/, "", s); gsub(/[ \t]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }
		BEGIN { while ((getline l < list) > 0) { k = n(l); if (k != "") drop[k] = 1 } close(list) }
		!(n($0) in drop)' "$HOSTS_FILE" > "$tmp" && cat "$tmp" > "$HOSTS_FILE"
	rm -f "$tmp" "$list"
}

HOSTS_BLOCKS="nalog ntc instagram librusec ai_openai ai_claude ai_gemini ai_aistudio ai_grok ai_copilot ai_deepl ai_elevenlabs ai_windsurf ai_trae ai_manus ai_notion twitch telegram spotify spotifyext rutor rutracker scell roblox githubraw github tapeop finland"
_hosts_src() {
	if grep -q '^### dns.malw.link: hosts file' "${1:-$HOSTS_FILE}" 2>/dev/null; then echo malw
	elif grep -q '^### geohide.ru: hosts file' "${1:-$HOSTS_FILE}" 2>/dev/null; then
		if grep -q '^# Регион серверов: US$' "${1:-$HOSTS_FILE}" 2>/dev/null; then echo us
		elif grep -q '^# Регион серверов: EU$' "${1:-$HOSTS_FILE}" 2>/dev/null; then echo eu
		elif grep -q '^# Регион серверов: RU$' "${1:-$HOSTS_FILE}" 2>/dev/null; then echo ru
		else echo unknown; fi
	fi
}
HOSTS_AUTO="$ZM_STATE_DIR/hosts.auto"
HOSTS_BASE="$ZM_STATE_DIR/hosts.base.gz"
HOSTS_ON="$ZM_STATE_DIR/hosts.on"
HOSTS_AUTO_TAG="# zm-hosts-auto"
_hosts_auto_get() { [ -s "$HOSTS_AUTO" ] && sed -n "s/^$1=//p" "$HOSTS_AUTO" | head -n 1; }
hosts_status() {
	local blocks="$HOSTS_BLOCKS" b
	local geohide
	geohide="$(_hosts_src)"
	printf '{"geohide":"%s","auto":"%s","auto_last":%s,"auto_err":"%s","items":[' "$(esc "$geohide")" "$(esc "$(_hosts_auto_get src)")" "$(_hosts_auto_get last | grep -E '^[0-9]+$' || echo 0)" "$(esc "$(_hosts_auto_get err)")"
	for b in $blocks; do echo "@@ZMB $b"; _hosts_block "$b"; done | awk -v hf="$HOSTS_FILE" 'function n(s) { gsub(/\r/, "", s); gsub(/[ \t]+/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }
		function flush() { if (id == "") return; printf "%s{\"id\":\"%s\",\"enabled\":%s}", (cnt++ ? "," : ""), id, (total > 0 && found == total) ? "true" : "false" }
		BEGIN { while ((getline l < hf) > 0) have[n(l)] = 1; close(hf) }
		/^@@ZMB / { flush(); id = substr($0, 7); total = 0; found = 0; split("", seen); next }
		{ k = n($0); if (k == "" || (k in seen)) next; seen[k] = 1; total++; if (k in have) found++ }
		END { flush() }'
	printf '],"extra":%s}\n' "$(_hosts_extra)"
}

HOSTS_EDIT_MAX=262144

ZM_UP_FILE="$JOBS_DIR/upload.part"
ZM_UP_MAX=4194304
upload_part() {
	local part="$1" sz
	mkdir -p "$JOBS_DIR"
	case "$part" in
		first) : > "$ZM_UP_FILE" ;;
		next) [ -f "$ZM_UP_FILE" ] || { echo '{"error":"загрузка прервалась — сохраните ещё раз"}'; return 1; } ;;
		*) echo '{"error":"неверная часть файла"}'; return 1 ;;
	esac
	printf '%s' "$2" >> "$ZM_UP_FILE"
	sz="$(wc -c < "$ZM_UP_FILE" | tr -d ' ')"
	[ "${sz:-0}" -gt "$ZM_UP_MAX" ] && { rm -f "$ZM_UP_FILE"; echo '{"error":"текст слишком большой"}'; return 1; }
	printf '{"ok":true,"size":%s}\n' "${sz:-0}"
}

_ports_get() { sed -n "s/^[[:space:]]*option $1 '\([^']*\)'.*/\1/p" "$CONF" | head -n1; }
_ports_put() { sed -i "s|^\([[:space:]]*option $1 '\)[^']*'|\1$2'|" "$CONF"; }

ZP_OWN="$ZM_STATE_DIR/zapret.ports.own"
ZP_MANUAL="$ZM_STATE_DIR/zapret.ports.manual"
ZP_DEF_TCP="80,443"
ZP_DEF_UDP="443"
ZP_MAX=300
ZP_AWK='
function zp_parse(s, lo, hi,   n, m, i, j, k, t, ab, a, b, x, y) {
	n = 0; m = split(s, t, ",")
	for (i = 1; i <= m; i++) {
		k = t[i]; gsub(/[ \t\r\n]/, "", k)
		if (k ~ /^[0-9]+$/) { a = k + 0; b = a }
		else if (k ~ /^[0-9]+-[0-9]+$/) { split(k, ab, "-"); a = ab[1] + 0; b = ab[2] + 0 }
		else continue
		if (a < 1 || b > 65535 || a > b) continue
		n++; lo[n] = a; hi[n] = b
	}
	for (i = 2; i <= n; i++) {
		x = lo[i]; y = hi[i]; j = i - 1
		while (j >= 1 && lo[j] > x) { lo[j + 1] = lo[j]; hi[j + 1] = hi[j]; j-- }
		lo[j + 1] = x; hi[j + 1] = y
	}
	if (n == 0) return 0
	j = 1
	for (i = 2; i <= n; i++) {
		if (lo[i] <= hi[j] + 1) { if (hi[i] > hi[j]) hi[j] = hi[i] }
		else { j++; lo[j] = lo[i]; hi[j] = hi[i] }
	}
	return j
}
function zp_str(lo, hi, n,   i, o) {
	o = ""
	for (i = 1; i <= n; i++) o = o (o == "" ? "" : ",") (lo[i] == hi[i] ? lo[i] : lo[i] "-" hi[i])
	return o
}
function zp_norm(s,   lo, hi, n) { n = zp_parse(s, lo, hi); return zp_str(lo, hi, n) }
function zp_diff(a, b,   al, ah, an, bl, bh, bn, ol, oh, on, i, j, c) {
	an = zp_parse(a, al, ah); bn = zp_parse(b, bl, bh); on = 0
	for (i = 1; i <= an; i++) {
		c = al[i]
		for (j = 1; j <= bn && c <= ah[i]; j++) {
			if (bh[j] < c) continue
			if (bl[j] > ah[i]) break
			if (bl[j] > c) { on++; ol[on] = c; oh[on] = bl[j] - 1 }
			c = bh[j] + 1
		}
		if (c <= ah[i]) { on++; ol[on] = c; oh[on] = ah[i] }
	}
	return zp_str(ol, oh, on)
}
'
_zp_calc() {
	awk -v op="$1" -v a="$2" -v b="$3" "$ZP_AWK"'
		BEGIN { if (op == "norm") print zp_norm(a); else if (op == "diff") print zp_diff(a, b); else print zp_norm(a "," b) }' < /dev/null
}
_zp_scan() {
	{
		sed -n "/^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$/,/^[[:space:]]*'[[:space:]]*\$/p" "$CONF" 2>/dev/null
		[ -s "$ZC_FILE" ] && { echo "--new"; cat "$ZC_FILE"; }
		_zs2_on && [ -n "$(_zs2_ips)" ] && { echo "--new"; _zs2_opt; }
	} | awk '
		function fl() { if (des && !ht && !hu) { wt = 1; wu = 1 } des = 0; ht = 0; hu = 0 }
		function addp(p, v,   n, i, t) {
			if (v == "" || v ~ /[~*]/) { if (p == "t") wt = 1; else wu = 1; return }
			n = split(v, t, ",")
			for (i = 1; i <= n; i++) {
				if (t[i] == "") continue
				if (p == "t") { if (!(t[i] in st)) { st[t[i]] = 1; ts = ts (ts == "" ? "" : ",") t[i] } }
				else if (!(t[i] in su)) { su[t[i]] = 1; us = us (us == "" ? "" : ",") t[i] }
			}
		}
		{
			l = $0; sub(/^[ \t]+/, "", l); sub(/[ \t\r]+$/, "", l)
			if (l ~ /^option[ \t]+NFQWS_OPT/) { ok = 1; next }
			if (l == "\047" || l == "" || l ~ /^#/) next
			sub(/\047$/, "", l)
			n = split(l, w, /[ \t]+/)
			for (i = 1; i <= n; i++) {
				x = w[i]
				if (pend != "") { addp(pend, x); pend = ""; continue }
				if (x == "--new") fl()
				else if (x ~ /^--filter-tcp=/) { ht = 1; addp("t", substr(x, 14)) }
				else if (x == "--filter-tcp") { ht = 1; pend = "t" }
				else if (x ~ /^--filter-udp=/) { hu = 1; addp("u", substr(x, 14)) }
				else if (x == "--filter-udp") { hu = 1; pend = "u" }
				else if (x ~ /^--dpi-desync/) des = 1
			}
		}
		END { fl(); print ok + 0; print ts; print us; print wt + 0; print wu + 0 }'
}
_zp_load() {
	local r
	r="$(_zp_scan; echo .)"
	ZP_OK="$(printf '%s' "$r" | sed -n 1p)"
	ZP_ST="$(printf '%s' "$r" | sed -n 2p)"
	ZP_SU="$(printf '%s' "$r" | sed -n 3p)"
	ZP_WT="$(printf '%s' "$r" | sed -n 4p)"
	ZP_WU="$(printf '%s' "$r" | sed -n 5p)"
	ZP_CT="$(_ports_get NFQWS_PORTS_TCP)"
	ZP_CU="$(_ports_get NFQWS_PORTS_UDP)"
	[ "$ZP_OK" = 1 ]
}
_zp_own_load() {
	if [ -f "$ZP_OWN" ] && [ ! -f "$ZP_MANUAL" ]; then
		ZP_OT="$(sed -n 's/^tcp=//p' "$ZP_OWN" | head -n1)"
		ZP_OU="$(sed -n 's/^udp=//p' "$ZP_OWN" | head -n1)"
	else
		ZP_OT="$(_zp_calc diff "$ZP_CT" "$ZP_ST")"
		ZP_OU="$(_zp_calc diff "$ZP_CU" "$ZP_SU")"
	fi
}
_zp_own_put() {
	mkdir -p "$ZM_STATE_DIR" || return 1
	printf 'tcp=%s\nudp=%s\n' "$(_zp_calc norm "$1")" "$(_zp_calc norm "$2")" > "$ZP_OWN.t" && mv -f "$ZP_OWN.t" "$ZP_OWN"
}
_zp_put() {
	if grep -q "^[[:space:]]*option $1 '" "$CONF"; then
		_ports_put "$1" "$2"
	else
		awk -v l="	option $1 '$2'" '!d && /^[ \t]*option NFQWS_OPT \047/ { print l; d = 1 } { print }' "$CONF" > "$CONF.zp" && [ -s "$CONF.zp" ] && cat "$CONF.zp" > "$CONF"
		rm -f "$CONF.zp"
	fi
}
_zp_sync() {
	local t u
	ZP_CHANGED=""
	[ -f "$CONF" ] || return 0
	[ -f "$ZP_MANUAL" ] && return 0
	[ -s "$TEST_BACKUP" ] && return 0
	_zp_load || return 0
	if [ ! -f "$ZP_OWN" ]; then
		_zp_own_load
		_zp_own_put "$ZP_OT" "$ZP_OU" || return 0
	fi
	_zp_own_load
	if [ "$ZP_WT" = 0 ]; then
		t="$(_zp_calc union "$ZP_ST" "$ZP_OT")"
		[ -n "$t" ] && [ "$t" != "$(_zp_calc norm "$ZP_CT")" ] && { _zp_put NFQWS_PORTS_TCP "$t"; ZP_CHANGED=1; }
	fi
	if [ "$ZP_WU" = 0 ]; then
		u="$(_zp_calc union "$ZP_SU" "$ZP_OU")"
		[ -n "$u" ] && [ "$u" != "$(_zp_calc norm "$ZP_CU")" ] && { _zp_put NFQWS_PORTS_UDP "$u"; ZP_CHANGED=1; }
	fi
	[ -n "$ZP_CHANGED" ] && logger -t zapret-manager "Zapret: порты сверены со стратегией — TCP ${t:-$ZP_CT}, UDP ${u:-$ZP_CU}"
	return 0
}

strategy_TCP_common() {
	printf '%s\n' "--new" "--filter-tcp=$PORTS_TCP" "--dpi-desync-any-protocol=1" "--dpi-desync-cutoff=n5" \
		"--dpi-desync=multisplit" "--dpi-desync-split-seqovl=582" "--dpi-desync-split-pos=1" \
		"--dpi-desync-split-seqovl-pattern=/opt/zapret/files/fake/stun.bin"
}

strategy_Gv1() {
	printf '%s\n' "#Gv1" "--new" "--filter-udp=$PORTS_UDP" "--dpi-desync=fake" "--dpi-desync-cutoff=d2" \
		"--dpi-desync-any-protocol=1" "--dpi-desync-fake-unknown-udp=/opt/zapret/files/fake/${1:-stun.bin}"
}

strategy_Gv() {
	local n="$1"
	printf '%s\n' "#Gv$n" "--new" "--filter-udp=$PORTS_UDP" "--dpi-desync=fake" "--dpi-desync-repeats=10" \
		"--dpi-desync-any-protocol=1" "--dpi-desync-fake-unknown-udp=/opt/zapret/files/fake/${2:-stun.bin}" "--dpi-desync-cutoff=n$n"
}

ZG_FAKE_FILE="$ZM_STATE_DIR/zapret_gfake"
_gv_fake_of() {
	awk '{ l = $0; gsub(/^[ \t]+|[ \t\r]+$/, "", l) }
		l ~ /^#Gv[1-4](Xtreme)?$/ { g = 1; next }
		g && l ~ /^#/ { exit }
		g && l ~ /^--dpi-desync-fake-unknown-udp=/ { sub(/.*\//, "", l); print l; exit }'
}
_gv_fake_put() {
	awk -v n="$1" '{ l = $0; gsub(/^[ \t]+|[ \t\r]+$/, "", l) }
		l ~ /^#Gv[1-4](Xtreme)?$/ { g = 1 }
		g && !d && l ~ /^--dpi-desync-fake-unknown-udp=/ { sub(/--dpi-desync-fake-unknown-udp=[^ \t\r]*/, "--dpi-desync-fake-unknown-udp=/opt/zapret/files/fake/" n); d = 1 }
		{ print }'
}
_game_fake_ok() { [ -n "$1" ] || return 1; case " $ZS2_FAKES " in *" $1 "*) return 0 ;; esac; return 1; }
_game_fake_safe() { _game_fake_ok "$1" && return 0; _zm_re "$1" '^[A-Za-z0-9_][A-Za-z0-9_.-]*[.]bin$' && [ -f "/opt/zapret/files/fake/$1" ]; }
_game_fake_cur() { [ -f "$CONF" ] && sed -n "/^[[:space:]]*option NFQWS_OPT '/,\$p" "$CONF" | _gv_fake_of; }
_game_fake() {
	local f
	f="$(_game_fake_cur)"
	_game_fake_safe "$f" && { echo "$f"; return 0; }
	f=""
	[ -s "$ZG_FAKE_FILE" ] && read -r f < "$ZG_FAKE_FILE"
	_game_fake_safe "$f" || f=stun.bin
	echo "$f"
}
_game_fake_save() {
	if [ "$1" = stun.bin ]; then rm -f "$ZG_FAKE_FILE"
	else mkdir -p "$ZM_STATE_DIR" && printf '%s\n' "$1" > "$ZG_FAKE_FILE"; fi
}

_game_rx() {
	printf '%s' "^#Gv[0-9]+(Xtreme)?\$|^--filter-(udp|tcp)=($PORTS_UDP|$PORTS_TCP|80,88,444-65535)\$"
}

game_set() {
	local choice="$1" current="" rc gf="$2"
	_zm_re "$choice" '^([1-4]|off)$' || { echo '{"error":"некорректный номер Gv"}'; return 1; }
	[ -f "$CONF" ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	current=$(grep -oE '^#Gv[1-4](Xtreme)?$' "$CONF" | head -n1 | sed 's/^#//; s/Xtreme$//')

	if [ "$choice" = off ]; then
		_game_active || { printf '{"ok":true,"game":"none","removed":false}\n'; return 0; }
		cp "$CONF" "$CONF.gvbak"
		_game_xtreme_undo_opts
		_nfq_drop_profiles "$(_game_rx)"
		rc=$?
		if [ "$rc" = 0 ] && [ -f "$MAIN_OFF_FLAG" ] && ! _nfq_has_prof; then
			mv -f "$CONF.gvbak" "$CONF"
			printf '{"error":"%s"}\n' "$(esc "Основная стратегия выключена, а игровой блок — последний: $ZM_MAIN_LAST")"
			return 1
		fi
		case $rc in
			0|3)
				rm -f "$CONF.gvbak"
				_remove_ports_if_present NFQWS_PORTS_UDP "$PORTS_UDP"
				_remove_ports_if_present NFQWS_PORTS_TCP "$PORTS_TCP"
				zapret_restart
				printf '{"ok":true,"game":"none","removed":true}\n' ;;
			*)
				mv -f "$CONF.gvbak" "$CONF"
				echo '{"error":"блок стратегий Zapret (NFQWS_OPT) записан не так, как его пишет панель, — игровая часть не тронута"}'; return 1 ;;
		esac
		return 0
	fi

	[ "$current" = "Gv$choice" ] && { printf '{"ok":true,"game":"Gv%s"}\n' "$choice"; return 0; }
	_game_fake_safe "$gf" || gf="$(_game_fake)"

	cp "$CONF" "$CONF.gvbak"
	_game_xtreme_undo_opts
	_nfq_drop_profiles "$(_game_rx)"
	case $? in
		0|3) rm -f "$CONF.gvbak" ;;
		*) mv -f "$CONF.gvbak" "$CONF"
			echo '{"error":"блок стратегий Zapret (NFQWS_OPT) записан не так, как его пишет панель, — игровая часть не тронута"}'; return 1 ;;
	esac

	local last_quote strat
	last_quote=$(grep -n "^[[:space:]]*'[[:space:]]*\$" "$CONF" | tail -n1 | cut -d: -f1)
	[ -n "$last_quote" ] && sed -i "${last_quote},\$d" "$CONF"
	if [ "$choice" = "1" ]; then strat="$(strategy_Gv1 "$gf"; strategy_TCP_common)"; else strat="$(strategy_Gv "$choice" "$gf"; strategy_TCP_common)"; fi
	echo "$strat" | sed '/^$/d' >> "$CONF"
	echo "'" >> "$CONF"
	_game_fake_save "$gf"
	_add_ports_if_missing NFQWS_PORTS_UDP "$PORTS_UDP"
	_add_ports_if_missing NFQWS_PORTS_TCP "$PORTS_TCP"
	zapret_restart
	printf '{"ok":true,"game":"Gv%s"}\n' "$choice"
}

game_set_fake() {
	local file="$1"
	_game_fake_ok "$file" || { echo '{"error":"неизвестный fake-файл"}'; return 1; }
	[ -f "$CONF" ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	if [ -z "$(_game_fake_cur)" ]; then
		_game_fake_save "$file"
		printf '{"ok":true,"fake":"%s","saved":true}\n' "$(esc "$file")"
		return 0
	fi
	_gv_fake_put "$file" < "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF" || { rm -f "$CONF.tmp"; echo '{"error":"не удалось записать конфиг Zapret"}'; return 1; }
	[ "$(_game_fake_cur)" = "$file" ] || { echo '{"error":"не удалось поменять fake-файл в игровой стратегии"}'; return 1; }
	_game_fake_save "$file"
	zapret_restart
	printf '{"ok":true,"fake":"%s"}\n' "$(esc "$file")"
}

_quic_blocked() {
	uci show firewall 2>/dev/null | grep -q "name='Block_UDP_80'" \
		&& uci show firewall 2>/dev/null | grep -q "name='Block_UDP_443'" \
		&& echo true || echo false
}

ZM_V6_OPT_RX="^[[:space:]]*option[[:space:]]+DISABLE_IPV6[[:space:]]+['\"]?"
_ipv6_enabled_in_zapret() {
	[ -f "$CONF" ] && grep -Eq "${ZM_V6_OPT_RX}0['\"]?[[:space:]]*\$" "$CONF" && echo true || echo false
}

FW4_TPL="/usr/share/firewall4/templates/ruleset.uc"

_fw4_offload_on() { [ "$(uci -q get firewall.@defaults[0].flow_offloading)" = 1 ]; }
_fw4_offload_mode() {
	if [ "$(uci -q get firewall.@defaults[0].flow_offloading_hw)" = 1 ] && [ "$(uci -q get firewall.@defaults[0].flow_offloading)" = 1 ]; then echo hw
	elif [ "$(uci -q get firewall.@defaults[0].flow_offloading)" = 1 ]; then echo sw
	else echo off; fi
}
FT_STEER_OFF="$ZM_STATE_DIR/ft.steer.off"
_ft_steer_applied() { grep -q 'ct mark and 0x0ff00000 == 0x0 .*flow offload @ft;' "$FW4_TPL" 2>/dev/null; }

FT_ZAPRET_OFF="$ZM_STATE_DIR/ft.zapret.off"
_ft_steer_sync() {
	local want=0
	[ -f "$FW4_TPL" ] || return 0
	if stl_present && [ ! -f "$FT_STEER_OFF" ]; then
		_ft_steer_applied && return 0
		_fw4_offload_on || return 0
		want=1
	else
		_ft_steer_applied || return 0
	fi
	_fw4_offload_set "$want" keep || return 0
	logger -t zapret-manager "Flow Offloading: соединения Steer $([ "$want" = 1 ] && echo "исключены из выгрузки потоков" || echo "снова выгружаются")"
	_fw4_offload_on && /etc/init.d/firewall reload >/dev/null 2>&1
	return 0
}

_flow_offloading_fix_applied() {
	grep -q 'ct original packets ge 30 flow offload @ft;' /usr/share/firewall4/templates/ruleset.uc 2>/dev/null \
		&& echo true || echo false
}

_expert_mode() { [ -f "$EXPERT_MODE_FILE" ] && echo true || echo false; }

system_status() {
	printf '{"quic_blocked":%s,"ipv6_enabled":%s,"flow_offloading_fix":%s,"flow_mode":"%s","fw4_tpl":%s,"steer_installed":%s,"steer_offload_fix":%s,"steer_offload_off":%s,"zapret_fix_off":%s,"zapret_installed":%s,"watch_off":%s,"expert_mode":%s,"pkg":"%s",%s,"zm_total":%s}\n' \
		"$(_quic_blocked)" "$(_ipv6_enabled_in_zapret)" "$(_flow_offloading_fix_applied)" "$(_fw4_offload_mode)" "$([ -f "$FW4_TPL" ] && echo true || echo false)" \
		"$(stl_present && echo true || echo false)" "$(_ft_steer_applied && echo true || echo false)" "$([ -f "$FT_STEER_OFF" ] && echo true || echo false)" \
		"$([ -f "$FT_ZAPRET_OFF" ] && echo true || echo false)" "$([ -x /etc/init.d/zapret ] || [ -x /etc/init.d/zapret2 ] && echo true || echo false)" "$([ -f "$WATCH_OFF" ] && echo true || echo false)" \
		"$(_expert_mode)" "$PKG" "$(_zt_json)" "$(_zm_stats_cached)"
}

ZM_V6_ADDRS="2001:4860:4860::8888 2606:4700:4700::1111 2a02:6b8::feed:0ff"
ZM_V6_STATE="$JOBS_DIR/v6.state"
_zm_v6_ms() {
	local a t
	for a in "$@"; do
		t="$(ping -6 -c1 -W2 "$a" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\).*/\1/p' | head -n1)"
		[ -n "$t" ] && { echo "$t"; return 0; }
	done
	return 1
}
_zm_v6_dns() {
	nslookup google.com 127.0.0.1 2>/dev/null | awk '/^Name:/ { f = 1 } f && /^Address/ && /:[0-9A-Fa-f]*:/ { ok = 1 } END { exit !ok }'
}
_zm_v6_reach() {
	local a t
	for a in google.com $ZM_V6_ADDRS; do
		t="$(_zm_v6_ms "$a")" && { echo "$t $a"; return 0; }
	done
	return 1
}
_zm_v6_state_of() {
	[ -n "$1" ] || { echo dead; return; }
	if [ "${1#* }" = google.com ] || _zm_v6_dns; then echo live; else echo nodns; fi
}
_zm_v6_save() { mkdir -p "$JOBS_DIR"; echo "$1" > "$ZM_V6_STATE"; }
_zm_v6_probe() {
	_zm_v6_state_of "$(_zm_v6_reach)"
}
_zm_v6_cached() {
	local f="$ZM_V6_STATE"
	if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +10 2>/dev/null)" ]; then
		if mkdir "$f.lock" 2>/dev/null; then
			( _zm_v6_probe > "$f.new" 2>/dev/null; [ -s "$f.new" ] && mv -f "$f.new" "$f"; rmdir "$f.lock" ) >/dev/null 2>&1 </dev/null &
		elif [ -n "$(find "$f.lock" -mmin +2 2>/dev/null)" ]; then
			rmdir "$f.lock" 2>/dev/null
		fi
	fi
	cat "$f" 2>/dev/null
}

_zm_want() { case "$1" in on) echo true ;; off) echo false ;; *) echo "" ;; esac; }

ZM_FLASH_PATHS="/opt/zapret-manager-luci /usr/libexec/rpcd/zapret-manager /usr/share/rpcd/acl.d/luci-app-zapret-manager.json /usr/share/luci/menu.d/luci-app-zapret-manager.json /www/luci-static/resources/view/zapret-manager /www/luci-static/resources/zapret-manager /www/luci-static/resources/bytetube /www/luci-static/resources/view/bytetube /www/zm /www/zm-webui.html /usr/share/zm-redbtn"

_zm_kb() {
	[ $# -gt 0 ] || { echo 0; return 0; }
	du -sk "$@" 2>/dev/null | awk '{ s += $1 } END { print s + 0 }'
}

_zm_aged() {
	[ -e "$1" ] || [ -L "$1" ] || return 1
	[ "${2:-0}" -gt 0 ] || return 0
	[ -n "$(find "$1" -maxdepth 0 -mmin +"$2" 2>/dev/null)" ]
}

_zm_engine_refs() {
	local f
	for f in "$STL_ETC"/*.json "$STL_ETC"/*.yaml "$STL_ETC"/*.yml $( [ "$1" = engine ] || echo "$STL_KEEP $ST_DIR/model.svc $STL_TMP/spec.prev $ST_RUN/model" ); do
		[ -s "$f" ] && sed 's|\\/|/|g' "$f"
	done | tr '",[]{} \t\r' '\n\n\n\n\n\n\n\n\n' | sed "s/^'//; s/'\$//" | grep '^/' | sort -u
}

_zm_junk() {
	local refs="$JOBS_DIR/cleanup.refs.$$"
	mkdir -p "$JOBS_DIR"
	_zm_engine_refs > "$refs" 2>/dev/null
	if [ -s "$refs" ]; then
		_zm_junk_raw "$1" | awk -v refs="$refs" 'BEGIN { while ((getline l < refs) > 0) r[++n] = l; close(refs) } { for (i = 1; i <= n; i++) if (r[i] == $0 || index(r[i], $0 "/") == 1) next; print }'
	else
		_zm_junk_raw "$1"
	fi
	rm -f "$refs"
	return 0
}

_zm_tmp_live() {
	local p="${1##*/}"
	p="${p#*.}"; p="${p%%.*}"
	case "$p" in ''|*[!0-9]*) return 1 ;; esac
	[ "$p" != "$$" ] && [ -d "/proc/$p" ]
}

_zm_refs_missing() {
	local f
	stl_present || return 0
	_zm_engine_refs engine 2>/dev/null | grep -E "^($ZM_LISTS_DIR|$ST_DIR/lists)/" | while IFS= read -r f; do
		[ -e "$f" ] || echo "$f"
	done
}

_zm_mem_kb() { awk '/^MemAvailable:/ { print $2; f = 1; exit } /^MemFree:/ { m = $2 } END { if (!f) print m + 0 }' /proc/meminfo 2>/dev/null; }
_zm_df_kb() { df -kP "$1" 2>/dev/null | awk 'NR == 2 { print $4 + 0; f = 1 } END { if (!f) print 0 }'; }

_zm_fs_packs() {
	case "$(awk '$2 == "/overlay" { t = $3 } END { print t }' /proc/mounts 2>/dev/null)" in jffs2|ubifs) return 0 ;; esac
	return 1
}
_zm_mb() { awk -v k="$1" 'BEGIN { v = k / 1024; if (v < 10) printf "%.1f", v; else printf "%d", v + 0.5 }' | sed 's/\.0$//; s/\./,/'; }

ZPG_V="/www/luci-static/resources/view/zapret-manager"
ZPG_OFF="$ZM_STATE_DIR/pages.off"
ZPG_SIZE="$ZM_STATE_DIR/pages.size"
ZPG_MENU="/usr/share/luci/menu.d/luci-app-zapret-manager.json"
ZPG_IDS="strategy zapret2 steer forkozz bytetube tgproxy mixomo hosts adblock doh awg tailscale terminal monitor openwrt"
ZPG_LIST='strategy|Zapret|Обход блокировок|Стратегии, тесты, YouTube, Discord, игры и списки
zapret2|Zapret2|Обход блокировок|Установка и управление Zapret2
steer|Steer|Обход блокировок|Выбранные сервисы через WARP или VPN
forkozz|Forkozz|Обход блокировок|Выбранные сервисы через ваш сервер, подписку или туннель
bytetube|ByeTube|Обход блокировок|YouTube через ByeDPI
tgproxy|TG WS Proxy|Обход блокировок|Прокси для Telegram
mixomo|Mixomo|Обход блокировок|Mihomo, MagiTrickle и WARP
hosts|Hosts|Сеть|Домены в hosts и списки GeoHide
adblock|Блокировка рекламы|Сеть|Реклама, трекеры и фишинг для всей сети
doh|DNS over HTTPS|Сеть|Шифрованный DNS для всей сети
awg|AmneziaWG|Сеть|Туннели AmneziaWG и WARP
tailscale|Удалённый доступ|Сеть|Роутер и домашняя сеть из любой сети
terminal|Терминал|Сеть|Командная строка роутера в браузере
monitor|Монитор ресурсов|Сервис|Процессор, память, температура и процессы
openwrt|Настройка OpenWrt|Сервис|Время, ускорение, Wi-Fi, перезагрузка и зеркало'
_zpg_f() { printf '%s\n' "$ZPG_LIST" | awk -F'|' -v id="$1" -v n="$2" '$1 == id { print $n; exit }'; }
_zpg_files() {
	case "$1" in
		forkozz) echo "$ZPG_V/forkozz.js /opt/zapret-manager-luci/netshift.uc" ;;
		bytetube) echo "$ZPG_V/bytetube.js /www/luci-static/resources/bytetube/common.js /www/luci-static/resources/bytetube/presets.js /www/luci-static/resources/view/bytetube/style.css" ;;
		*) echo "$ZPG_V/$1.js" ;;
	esac
}
_zpg_offlist() { [ -s "$ZPG_OFF" ] && tr -s ' \n' '  ' < "$ZPG_OFF" | sed 's/^ //; s/ $//'; return 0; }
_zpg_lock() {
	_zpg_used "$1" 2>/dev/null && { echo "компонент установлен на роутере"; return 0; }
	return 1
}
_zpg_have() {
	local f
	[ -f "$ZM_STATE_DIR/ui.pc" ] && return 0
	for f in $(_zpg_files "$1"); do [ -s "$f" ] || return 1; done
	grep -q 'zmPageOff' "$ZPG_V/$1.js" 2>/dev/null && return 1
	return 0
}
_zpg_bytes() {
	local f n=0 s
	for f in $(_zpg_files "$1"); do
		[ -s "$f" ] || continue
		grep -q 'zmPageOff' "$f" 2>/dev/null && continue
		s="$(wc -c 2>/dev/null < "$f")"; n=$((n + ${s:-0}))
	done
	echo "$n"
}
_zpg_size() {
	local n
	if _zpg_have "$1"; then _zpg_bytes "$1"; return 0; fi
	n="$(awk -v id="$1" '$1 == id { print $2 + 0; exit }' "$ZPG_SIZE" 2>/dev/null)"
	echo "${n:-0}"
}
_zpg_core_bytes() {
	local f n=0 s
	for f in /opt/zapret-manager-luci/backend.sh /opt/zapret-manager-luci/mod/*.sh /opt/zapret-manager-luci/b64.uc /usr/libexec/rpcd/zapret-manager \
		/usr/share/rpcd/acl.d/luci-app-zapret-manager.json "$ZPG_MENU" /www/luci-static/resources/zapret-manager/common.js \
		"$ZPG_V/style.css" "$ZPG_V/dashboard.js" "$ZPG_V/system.js" "$ZPG_V/thanks.js" /www/zm/app.js /www/zm/app.css /www/zm-webui.html; do
		[ -f "$f" ] || continue
		s="$(wc -c 2>/dev/null < "$f")"; n=$((n + ${s:-0}))
	done
	for f in $(find /usr/share/zm-redbtn -type f 2>/dev/null); do s="$(wc -c 2>/dev/null < "$f")"; n=$((n + ${s:-0})); done
	echo "$n"
}
_zpg_prune() {
	local id="$1" f n
	n="$(_zpg_bytes "$id")"
	[ "${n:-0}" -gt 0 ] && _zpg_size_put "$id" "$n"
	for f in $(_zpg_files "$id"); do rm -f "$f"; done
	[ "$id" = bytetube ] && rmdir /www/luci-static/resources/bytetube /www/luci-static/resources/view/bytetube 2>/dev/null
	_zpg_stub "$id"
	logger -t zapret-manager "Компоненты панели: страница «$(_zpg_f "$id" 2)» убрана"
	return 0
}
_zpg_enforce() {
	local id keep="" ch=""
	[ -s "$ZPG_OFF" ] || return 0
	for id in $(_zpg_offlist); do
		_zpg_known "$id" || { ch=1; continue; }
		if _zpg_lock "$id" >/dev/null; then ch=1; continue; fi
		keep="$keep $id"
		_zpg_pruned "$id" || { _zpg_prune "$id"; ch=1; }
	done
	keep="${keep# }"
	if [ -n "$keep" ]; then
		[ "$keep" = "$(_zpg_offlist)" ] || printf '%s\n' "$keep" > "$ZPG_OFF"
	else
		rm -f "$ZPG_OFF"
	fi
	_zpg_menu_filter
	[ -n "$ch" ] && _zpg_rebuild
	return 0
}
_zpg_status() {
	local id out="" sep="" lk on have
	for id in $ZPG_IDS; do
		lk="$(_zpg_lock "$id")" || lk=""
		on=true; _zpg_is_off "$id" && on=false
		have=false; _zpg_have "$id" && have=true
		out="$out$sep{\"id\":\"$id\",\"title\":\"$(esc "$(_zpg_f "$id" 2)")\",\"group\":\"$(esc "$(_zpg_f "$id" 3)")\",\"sub\":\"$(esc "$(_zpg_f "$id" 4)")\",\"on\":$on,\"have\":$have,\"lock\":\"$(esc "$lk")\",\"size\":$(_zpg_size "$id")}"
		sep=","
	done
	printf '{"ver":"%s","core":%s,"free":%s,"job":%s,"pages":[%s]}\n' "$(esc "$ZM_VERSION")" "$(_zpg_core_bytes)" \
		"$(df -kP /overlay 2>/dev/null | awk 'NR == 2 { print $4 + 0; f = 1 } END { if (!f) print 0 }')" \
		"$(_job_running pages && echo true || echo false)" "$out"
}

ZM_AC_FILE="$ZM_STATE_DIR/autoclean"
ZM_AC_UPD="$ZM_STATE_DIR/autoclean.upd"
ZM_AC_LAST="$ZM_STATE_DIR/autoclean.last"
ZM_AC_TAG="# zm-autoclean"
ZM_AC_CMD="/opt/zapret-manager-luci/backend.sh zm_cleanup auto >/dev/null 2>&1"
_zm_ac_hours() { case "$(cat "$ZM_AC_FILE" 2>/dev/null)" in 3) echo 3 ;; 6) echo 6 ;; 12) echo 12 ;; 24) echo 24 ;; *) echo 0 ;; esac; }
_zm_ac_spec() { case "$(_zm_ac_hours)" in 3|6|12) echo "41 */$(_zm_ac_hours) * * *" ;; 24) echo "41 4 * * *" ;; esac; }
_zm_ghp_warn() {
	local f=0
	_zm_ghp_load
	[ "$ZM_GHP_MODE" = off ] && [ -s "$ZM_GHP_FAIL" ] || return 1
	read -r f < "$ZM_GHP_FAIL"
	case "$f" in ''|*[!0-9]*) return 1 ;; esac
	[ $(( $(date +%s) - f )) -lt 1800 ]
}

PG_ORDER="steer forkozz mixomo awg bytetube zapret zapret2 tgproxy stgws tailscale terminal htop adblock doh dnsnet hosts panel"

BK_DIR="/opt/zapret-manager-luci/backups"
BK_KEEPD="/lib/upgrade/keep.d/zapret-manager"
BK_AUTO_OFF="$BK_DIR/auto.off"
BK_AUTO_N=5
BK_KEEPD_KB=8192
BK_ORDER="zapret zapret2 bytetube awg steer forkozz mixomo tgproxy stgws tailscale terminal htop doh adblock dnsnet hosts"
BK_NET="network firewall dhcp"
BK_UP="$JOBS_DIR/bk.upload"
BK_RUN="$JOBS_DIR/bk"

BK_UC="/opt/zapret-manager-luci/b64.uc"

ZM_MIRRORS="downloads.openwrt.org mirror-03.infra.openwrt.org openwrt.tetaneutral.net ftp.halifax.rwth-aachen.de/openwrt openwrt.mirror.garr.it/mirrors/openwrt mirrors.ustc.edu.cn/openwrt openwrt.c3sl.ufpr.br mirror.marwan.ma/openwrt openwrt.pixeldeck.net"
_mirror_feed1() {
	local l
	l="$(grep -v '^[[:space:]]*#' "$(_confz)" 2>/dev/null | grep -oE 'https?://[^ ]+/(releases|snapshots)/[^ ]+' | head -n1)"
	[ -n "$l" ] || return 1
	case "$l" in *.adb|*/Packages.gz) ;; *) [ "$PKG" = apk ] || l="${l%/}/Packages.gz" ;; esac
	echo "$l"
}
_mirror_probe() {
	local r code t
	r="$(curl -s -o /dev/null -L -r 0-1023 --connect-timeout 4 --max-time 10 -w '%{http_code} %{time_total}' "$(_mirror_swap "$2" "$1")" 2>/dev/null)"
	code="${r%% *}"; t="${r##* }"
	case "$code" in 200|206) ;; *) return 1 ;; esac
	awk -v t="$t" -v h="$1" 'BEGIN { printf "%d %s\n", t * 1000 + 0.5, h }'
}

_excl_dir() { echo "/opt/zapret/init.d/openwrt/custom.d"; }
_excl_file() { echo "$(_excl_dir)/20-script.sh"; }

_excl_current() {
	local f; f="$(_excl_file)"
	[ -f "$f" ] || return 0
	grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$f" | sort -u
}

_excl_enable_custom() {
	[ -f "$CONF" ] || return 0
	if grep -q "^[[:space:]]*option DISABLE_CUSTOM " "$CONF"; then
		sed -i "s/^\([[:space:]]*option DISABLE_CUSTOM \).*/\1'0'/" "$CONF"
	else
		sed -i "/^config main/a\\	option DISABLE_CUSTOM '0'" "$CONF"
	fi
}

ZS2_DIR="$ZM_STATE_DIR/zsec2"
ZS2_ON="$ZS2_DIR/on"
ZS2_OPT="$ZS2_DIR/opt"
ZS2_DEVS="$ZS2_DIR/devs"
ZS2_SRC="$ZS2_DIR/src"
ZS2_SCRIPT="/opt/zapret/init.d/openwrt/custom.d/30-zm-section2.sh"
ZS2_MAX=32
_zs2_on() { [ -f "$ZS2_ON" ]; }
_zs2_devs() { [ -s "$ZS2_DEVS" ] && awk -F'|' '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && !s[$1]++ { print $1 }' "$ZS2_DEVS"; }
_zs2_ips() {
	local ex ip
	ex="$(_excl_current)"
	_zs2_devs | while read -r ip; do printf '%s\n' "$ex" | grep -qxF "$ip" || echo "$ip"; done
}
_zs2_opt() { [ -s "$ZS2_OPT" ] && tr -d '\r' < "$ZS2_OPT" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^#' | grep -v '^$'; }
_zs2_script() {
	local ips
	ips="$(_zs2_ips | tr '\n' ' ' | sed 's/ *$//; s/ /, /g')"
	cat <<ZS2_SCRIPT_EOF
# Zapret Manager: дополнительная секция Zapret. Файл пишет панель — меняйте настройки во вкладке «Доп. секция»
ZMS2_SRC="$ips"
ZMS2_OPT="\$(cat <<'ZMS2_OPT_EOF'
$(_zs2_opt)
ZMS2_OPT_EOF
)"

alloc_dnum DNUM_ZMS2
alloc_qnum QNUM_ZMS2

zapret_custom_daemons()
{
	local opt="--qnum=\$QNUM_ZMS2 \$ZMS2_OPT"
	[ -n "\$ZMS2_SRC" ] || return 0
	filter_apply_hostlist_target opt
	do_nfqws \$1 \$DNUM_ZMS2 "\$opt"
}

zms2_nft_in_out()
{
	local f
	[ -n "\$2" ] || return 0
	[ -n "\$3" ] && [ "\$3" != 0 ] && {
		f="\$1 dport {\$2} \$(nft_first_packets \$3)"
		nft_filter_apply_ipset_target4 f
		nft_fw_nfqws_post4 "\$f ct original ip saddr { \$ZMS2_SRC }" \$QNUM_ZMS2
	}
	[ -n "\$4" ] && [ "\$4" != 0 ] && {
		f="\$1 dport {\$2} \$(nft_first_packets \$4)"
		nft_filter_apply_ipset_target4 f
		nft_fw_nfqws_pre4 "\$(nft_reverse_nfqws_rule "\$f") ct original ip saddr { \$ZMS2_SRC }" \$QNUM_ZMS2
	}
	return 0
}

zapret_custom_firewall_nft()
{
	[ -n "\$ZMS2_SRC" ] || return 0
	zms2_nft_in_out tcp "\$NFQWS_PORTS_TCP" "\$NFQWS_TCP_PKT_OUT" "\$NFQWS_TCP_PKT_IN"
	zms2_nft_in_out tcp "\$NFQWS_PORTS_TCP_KEEPALIVE" keepalive "\$NFQWS_TCP_PKT_IN"
	zms2_nft_in_out udp "\$NFQWS_PORTS_UDP" "\$NFQWS_UDP_PKT_OUT" "\$NFQWS_UDP_PKT_IN"
	zms2_nft_in_out udp "\$NFQWS_PORTS_UDP_KEEPALIVE" keepalive "\$NFQWS_UDP_PKT_IN"
}
ZS2_SCRIPT_EOF
}
_zs2_sync() {
	local d="${ZS2_SCRIPT%/*}"
	[ -d /opt/zapret/init.d/openwrt ] || return 0
	_zs2_refresh
	if _zs2_on && [ -n "$(_zs2_ips)" ] && [ -n "$(_zs2_opt)" ]; then
		_excl_enable_custom
		mkdir -p "$d" || return 1
		_zs2_script > "$ZS2_SCRIPT.zm.$$" || { rm -f "$ZS2_SCRIPT.zm.$$"; return 1; }
		if cmp -s "$ZS2_SCRIPT.zm.$$" "$ZS2_SCRIPT"; then rm -f "$ZS2_SCRIPT.zm.$$"
		else mv -f "$ZS2_SCRIPT.zm.$$" "$ZS2_SCRIPT"; fi
		chmod 644 "$ZS2_SCRIPT" 2>/dev/null
	else
		rm -f "$ZS2_SCRIPT"
	fi
	return 0
}
_zs2_opt_check() {
	local t="$1" bad
	[ -n "$(printf '%s' "$t" | tr -d '[:space:]')" ] || { echo "стратегия пустая"; return 1; }
	[ "$(printf '%s' "$t" | wc -c)" -le 32768 ] || { echo "стратегия слишком большая — не больше 32 КБ"; return 1; }
	case "$t" in *"'"*) echo "одинарные кавычки ' в стратегии нельзя — они ломают запуск Zapret"; return 1 ;; esac
	case "$t" in *'"'*|*'`'*|*'$'*|*'\'*) echo 'символы " ` $ \ в стратегии нельзя'; return 1 ;; esac
	bad="$(printf '%s\n' "$t" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' | grep -v '^#' | grep -v '^--' | head -n 1)"
	[ -z "$bad" ] || { echo "строка не похожа на параметр nfqws (должна начинаться с --): $bad"; return 1; }
	printf '%s\n' "$t" | grep -q '^[[:space:]]*--' || { echo "в стратегии нет ни одного параметра --…"; return 1; }
	printf '%s\n' "$t" | grep -qE -- '--(qnum|user|uid|daemon|pidfile|dpi-desync-fwmark)([= ]|$)' && { echo "параметры --qnum, --user, --uid, --daemon, --pidfile и --dpi-desync-fwmark панель задаёт сама — уберите их"; return 1; }
	printf '%s\n' "$t" | grep -qx 'ZMS2_OPT_EOF' && { echo "в стратегии есть служебная строка"; return 1; }
	return 0
}
ZS2_FAKES="stun.bin stun2.bin quic_initial_4pda_to.bin quic_initial_tencent_com.bin tls_clienthello_sochi_park.bin quic_initial_www_google_com.bin quic_initial_steamcommunity_com.bin quic_initial_5ka_ru.bin quic_initial_rutube_ru.bin"
_zs2_kv() { sed -n "s/^$2=//p" "$1/sel" 2>/dev/null | head -n1; }
_zs2_kset() {
	{ grep -v "^$2=" "$1/sel" 2>/dev/null; [ -z "$3" ] || printf '%s=%s\n' "$2" "$3"; } > "$1/sel.t" && mv -f "$1/sel.t" "$1/sel"
}
_zs2_kind() {
	local k
	k="$(_zs2_kv "$ZS2_DIR" kind)"
	[ -n "$k" ] && [ -f "$ZS2_DIR/base" ] && { echo "$k"; return 0; }
	case "$(cat "$ZS2_SRC" 2>/dev/null)" in
		v[0-9]*) echo v ;;
		Flowseal\ *) echo fs ;;
		"копия основной") echo main ;;
		*) echo own ;;
	esac
}
_zs2_stage_dir() {
	local t f
	t="$(mktemp -d /tmp/zm-zs2.XXXXXX)" || return 1
	for f in sel base yvb src; do [ -f "$ZS2_DIR/$f" ] && cp -f "$ZS2_DIR/$f" "$t/$f"; done
	if [ ! -f "$t/base" ] && [ -s "$ZS2_OPT" ]; then
		tr -d '\r' < "$ZS2_OPT" > "$t/base"
		rm -f "$t/sel" "$t/yvb"
		_zs2_kset "$t" kind "$(_zs2_kind)"
		[ "$(_zs2_kind)" = v ] && { _zs2_kset "$t" yv off; _zs2_kset "$t" dv off; }
	fi
	echo "$t"
}
_zs2_commit() {
	local f
	for f in sel base yvb src opt; do
		if [ -f "$1/$f" ]; then
			cp -f "$1/$f" "$ZS2_DIR/$f.zm.$$" && mv -f "$ZS2_DIR/$f.zm.$$" "$ZS2_DIR/$f" || { rm -f "$ZS2_DIR/$f.zm.$$"; return 1; }
		else
			rm -f "$ZS2_DIR/$f"
		fi
	done
	return 0
}
_zs2_drop() {
	local t rc
	t="$(mktemp -d /tmp/zm-zs2.XXXXXX)" || return 1
	{ echo "	option NFQWS_OPT '"; cat; echo "'"; } > "$t/c"
	( CONF="$t/c"; JOBS_DIR="$t"; _nfq_drop_profiles_raw "$1" force "$2" ) >/dev/null 2>&1
	rc=$?
	if [ "$rc" = 0 ] || [ "$rc" = 3 ]; then sed '1d;$d' "$t/c"; rm -rf "$t"; return 0; fi
	rm -rf "$t"
	return 1
}
_zs2_yv08() { printf '%s\n' "#Yv08" "--filter-tcp=443" "--hostlist=/opt/zapret/ipset/zapret-hosts-google.txt" "--dpi-desync=hostfakesplit" "--dpi-desync-hostfakesplit-mod=host=google.com" "--dpi-desync-fooling=ts"; }
_zs2_dvblk() {
	printf '%s\n' "--new" "--filter-udp=19294-19344,50000-50100" "--filter-l7=discord,stun" "--dpi-desync=fake" \
		"--dpi-desync-fake-discord=/opt/zapret/files/fake/stun.bin" "--dpi-desync-fake-stun=/opt/zapret/files/fake/stun.bin" \
		"--dpi-desync-repeats=6" "#Dv$1" "--new"
	Dv "$1"
}
_zs2_gvblk() { if [ "$1" = 1 ]; then strategy_Gv1; else strategy_Gv "$1"; fi; strategy_TCP_common; }
_zs2_build() {
	local D="$1" k y d g
	k="$(_zs2_kv "$D" kind)"; y="$(_zs2_kv "$D" yv)"; d="$(_zs2_kv "$D" dv)"; g="$(_zs2_kv "$D" gv)"
	[ -s "$D/base" ] || return 1
	case "$y" in ''|off) ;; *) [ -s "$D/yvb" ] || return 1 ;; esac
	if [ "$k" = v ]; then
		{
			case "$y" in off) ;; '') _zs2_yv08; echo "--new" ;; *) cat "$D/yvb"; echo "--new" ;; esac
			cat "$D/base"
			[ "$d" = off ] || _zs2_dvblk "${d:-1}"
			case "$g" in [1-4]) _zs2_gvblk "$g" ;; esac
		} > "$D/w"
	else
		cp -f "$D/base" "$D/w" || return 1
		if [ -n "$y" ]; then
			_zs2_drop "$YV_RX" '^--filter-udp=443$' < "$D/w" > "$D/w2" || return 1
			if [ "$y" = off ]; then mv -f "$D/w2" "$D/w"; else { cat "$D/yvb"; echo "--new"; cat "$D/w2"; } > "$D/w"; fi
		fi
		if [ -n "$d" ]; then
			_zs2_drop "$DISCORD_RX" < "$D/w" > "$D/w2" || return 1
			{ cat "$D/w2"; [ "$d" = off ] || _zs2_dvblk "$d"; } > "$D/w"
		fi
		if [ -n "$g" ]; then
			_zs2_drop "$(_game_rx)" < "$D/w" > "$D/w2" || return 1
			{ cat "$D/w2"; case "$g" in [1-4]) _zs2_gvblk "$g" ;; esac; } > "$D/w"
		fi
	fi
	_zs2_drop '^#ZM_NEVER_MATCHES$' < "$D/w" > "$D/w2" || return 1
	awk -v df="$(_zs2_kv "$D" df)" -v gf="$(_zs2_kv "$D" gf)" -v F=/opt/zapret/files/fake/ '
		/^#Gv[1-4](Xtreme)?$/ { gb = 1 }
		$0 == "--new" { ds = 0 }
		$0 == "--filter-l7=discord,stun" { ds = 1 }
		df != "" && ds && /^--dpi-desync-fake-discord=/ { $0 = "--dpi-desync-fake-discord=" F df }
		df != "" && ds && /^--dpi-desync-fake-stun=/ { $0 = "--dpi-desync-fake-stun=" F df }
		gf != "" && gb && !gd && /^--dpi-desync-fake-unknown-udp=/ { $0 = "--dpi-desync-fake-unknown-udp=" F gf; gd = 1 }
		{ print }' "$D/w2" > "$D/w3" || return 1
	_zs2_x "$D" "$D/w3" || return 1
	cat "$D/w3"
	rm -f "$D/w" "$D/w2" "$D/w3"
}

ZS2_XKEYS="doh rkn ul wss quic ipid xt"
_zs2_tx() {
	local f="$1" t
	shift
	t="$(mktemp -d /tmp/zm-zs2x.XXXXXX)" || return 1
	{ echo "	option NFQWS_OPT '"; cat "$f"; echo "'"; } > "$t/c"
	( CONF="$t/c"; JOBS_DIR="$t"; ZM_NFQ_BODY=""; ZM_RKN=""; ZM_FITS=""; ZM_DOH=""; ZM_UDP=""; ZM_YS=""; "$@" ) >/dev/null 2>&1
	if grep -q "^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$" "$t/c" && grep -q "^[[:space:]]*'[[:space:]]*\$" "$t/c"; then
		sed -n "/^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$/,/^[[:space:]]*'[[:space:]]*\$/p" "$t/c" | sed '1d;$d' > "$f"
		rm -rf "$t"
		return 0
	fi
	rm -rf "$t"
	return 1
}
_zs2_xdrop() { _zs2_drop "$2" < "$1" > "$1.n" && mv -f "$1.n" "$1"; }
_zs2_doh_conf() { _zo_doh_cut; _zo_doh_put "$1"; }
_zs2_ul_apply() {
	grep -qxF -- "--hostlist=$ZO_RKN_FILE" "$1" && return 0
	awk -v EX="$ZO_EXCL_HL" -v U="$ZO_USER_HL" '!d && $0 == EX { print U; d = 1; next } { print }' "$1" > "$1.n" && mv -f "$1.n" "$1"
}
_zs2_xt() {
	local f="$1" w="$2" n u t
	if [ "$w" = on ]; then
		grep -q '^#Gv[0-9]\+$' "$f" || return 0
		awk '
			/^#Gv[0-9]+$/ { print $0 "Xtreme"; g = 1; next }
			g && /^--filter-udp=/ { print "--filter-udp=80,88,444-65535"; next }
			g && /^--filter-tcp=/ { print "--filter-tcp=80,88,444-65535"; g = 0; next }
			{ print }' "$f" > "$f.n" && mv -f "$f.n" "$f"
	else
		n="$(sed -n 's/^#Gv\([1-4]\)Xtreme$/\1/p' "$f" | head -n1)"
		[ -n "$n" ] || return 0
		u="$(_zs2_gvblk "$n" | grep -m1 '^--filter-udp=')"; t="$(_zs2_gvblk "$n" | grep -m1 '^--filter-tcp=')"
		awk -v U="$u" -v T="$t" '
			/^#Gv[0-9]+Xtreme$/ { sub(/Xtreme$/, ""); print; g = 1; next }
			g && /^--filter-udp=/ { print U; next }
			g && /^--filter-tcp=/ { print T; g = 0; next }
			{ print }' "$f" > "$f.n" && mv -f "$f.n" "$f"
	fi
}
_zs2_x() {
	local D="$1" f="$2" v
	case "$(_zs2_kv "$D" rkn)" in
		on) [ -s "$ZO_RKN_FILE" ] && _zs2_tx "$f" _zo_rkn_patch ;;
		off) _zs2_tx "$f" _zo_rkn_unpatch ;;
	esac
	[ "$(_zs2_kv "$D" ul)" = on ] && _zs2_ul_apply "$f"
	case "$(_zs2_kv "$D" wss)" in
		on) _zs2_tx "$f" _zo_wss_add ;;
		off) _zs2_xdrop "$f" '^--wssize 1:6$' || return 1 ;;
	esac
	v="$(_zs2_kv "$D" ipid)"
	[ -n "$v" ] && _zs2_tx "$f" _yv_ipid_apply "$v"
	case "$(_zs2_kv "$D" quic)" in
		on)
			grep -qx -- '--filter-udp=443' "$f" || {
				printf '%s\n' '#udp443' '--filter-udp=443' "$ZO_YT_HL" '--dpi-desync=fake' '--dpi-desync-repeats=11' \
					'--dpi-desync-fake-quic=/opt/zapret/files/fake/quic_initial_www_google_com.bin' '--new' > "$f.n"
				cat "$f" >> "$f.n" && mv -f "$f.n" "$f"
			} ;;
		off)
			_zs2_xdrop "$f" '^--filter-udp=443$' || return 1
			sed -i '/^[[:space:]]*#[[:space:]]*udp443[[:space:]]*$/d' "$f" ;;
	esac
	v="$(_zs2_kv "$D" xt)"
	[ -n "$v" ] && _zs2_xt "$f" "$v"
	case "$(_zs2_kv "$D" doh)" in
		on)
			v="$(_zo_doh_doms)"
			_zs2_tx "$f" _zs2_doh_conf "$v" || return 1
			_zs2_kset "$D" dohd "$v" ;;
		off) _zs2_tx "$f" _zo_doh_cut || return 1 ;;
	esac
	return 0
}
_zs2_refresh() {
	local t out
	[ "$(_zs2_kv "$ZS2_DIR" doh)" = on ] && [ -s "$ZS2_DIR/base" ] || return 0
	[ "$(_zs2_kv "$ZS2_DIR" dohd)" = "$(_zo_doh_doms)" ] && return 0
	t="$(_zs2_stage_dir)" || return 0
	if out="$(_zs2_build "$t")" && _zs2_opt_check "$out" >/dev/null; then
		printf '%s\n' "$out" > "$t/opt"
		_zs2_commit "$t"
	fi
	rm -rf "$t"
	return 0
}

_zl_path() {
	case "$1" in
		exclude) echo /opt/zapret/ipset/zapret-hosts-user-exclude.txt ;;
		user)    echo /opt/zapret/ipset/zapret-hosts-user.txt ;;
		google)  echo /opt/zapret/ipset/zapret-hosts-google.txt ;;
		*) return 1 ;;
	esac
}
_zl_json_text() {
	[ -f "$1" ] || return 0
	local tab; tab="$(printf '\t')"
	tr -d '\r\000-\010\013\014\016-\037' < "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" | awk '{ printf "%s%s", (NR > 1 ? "\\n" : ""), $0 }'
}
_zl_count() { local n; [ -f "$1" ] && n=$(grep -cvE '^[[:space:]]*(#.*)?$' "$1"); echo "${n:-0}"; }
_zl_used() {
	local f; f="$(_zl_path "$1")" || return 1
	case "$1" in exclude) _nfq_opt_body | grep -qF -- "--hostlist-exclude=$f" ;; *) _nfq_opt_body | grep -qF -- "--hostlist=$f" ;; esac
}
_zl_info() {
	local f; f="$(_zl_path "$1")"
	printf '{"id":"%s","path":"%s","used":%s,"exists":%s,"count":%s,"size":%s,"mtime":%s,"auto":"%s","nochange":%s}' "$1" "$f" "$([ -f "$CONF" ] && _zl_used "$1" && echo true || echo false)" \
		"$([ -f "$f" ] && echo true || echo false)" "$(_zl_count "$f")" \
		"$([ -f "$f" ] && wc -c < "$f" | tr -d ' ' || echo 0)" "$([ -f "$f" ] && date -r "$f" +%s 2>/dev/null || echo 0)" \
		"$([ "$1" = exclude ] && _zx_auto_get)" "$(_nochange_in "$f" && echo true || echo false)"
}

ZX_AUTO_TAG="# zm-excl-auto"

_zx_auto_get() {
	local v
	v="$(grep -F "$ZX_AUTO_TAG=" "$CRON_FILE" 2>/dev/null | head -n1 | sed 's/.*=//')"
	case "$v" in h2|h4|h6|h12) echo "$v" ;; *) echo off ;; esac
}

ZL_EDIT_MAX=262144

ZX_HDR_FLAG="$ZM_STATE_DIR/zapret_hdrezka"
ZX_HDR_FILE="/opt/zapret/ipset/zapret-hosts-user-exclude.txt"
ZX_HDR_DOMS="rezka.ag hdrezka.ag hdrezka.ac hdrezka.la hdrezka.me hdrezka.org flypink.org"
ZX_HDR_B="#zm-hdrezka"
ZX_HDR_E="#zm-hdrezka-end"
_zx_hdr_on() { [ -f "$ZX_HDR_FLAG" ]; }
_zx_hdr_sync() {
	local f="${1:-$ZX_HDR_FILE}" tmp
	if [ ! -f "$f" ]; then
		_zx_hdr_on && [ -d "$(dirname "$f")" ] || return 1
		: > "$f"
	fi
	tmp="$f.zmhdr"
	awk -v B="$ZX_HDR_B" -v E="$ZX_HDR_E" -v D="$ZX_HDR_DOMS" '
		BEGIN { n = split(D, a, " "); for (i = 1; i <= n; i++) d[a[i]] = 1 }
		{ l = $0; sub(/\r$/, "", l); t = tolower(l); gsub(/^[ \t]+|[ \t]+$/, "", t) }
		t == B { s = 1; next }
		t == E { s = 0; next }
		s && (t in d || t == "") { next }
		{ print }' "$f" > "$tmp" || { rm -f "$tmp"; return 1; }
	if _zx_hdr_on; then
		[ -s "$tmp" ] && [ -n "$(tail -c 1 "$tmp")" ] && echo >> "$tmp"
		{ echo "$ZX_HDR_B"; printf '%s\n' $ZX_HDR_DOMS; echo "$ZX_HDR_E"; } >> "$tmp"
	fi
	if cmp -s "$tmp" "$f"; then rm -f "$tmp"; return 1; fi
	cat "$tmp" > "$f"; rm -f "$tmp"; chmod 644 "$f"
	return 0
}
_zx_hdr_set() {
	_pend_on && { echo '{"error":"сначала примените или отмените выбранную стратегию"}'; return 1; }
	case "$1" in
		on) mkdir -p "$ZM_STATE_DIR"; : > "$ZX_HDR_FLAG" ;;
		off) rm -f "$ZX_HDR_FLAG" ;;
		*) echo '{"error":"неизвестное значение"}'; return 1 ;;
	esac
	mkdir -p "$(dirname "$ZX_HDR_FILE")"
	_zx_hdr_sync && zapret_restart
	status
}

nfqws_opt_set() {
	local content="$1"
	[ -x /etc/init.d/zapret ] || { echo '{"error":"Zapret не установлен"}'; return 1; }
	[ -f "$CONF" ] || { echo '{"error":"конфигурация Zapret не найдена"}'; return 1; }
	grep -q "^[[:space:]]*option NFQWS_OPT '\$" "$CONF" || { echo '{"error":"в конфигурации не найден блок NFQWS_OPT"}'; return 1; }
	case "$content" in *"'"*) echo '{"error":"одинарные кавычки \u0027 в стратегии нельзя — они ломают конфиг Zapret"}'; return 1 ;; esac
	printf '%s' "$content" | grep -q -- '--' || { echo '{"error":"в стратегии нет ни одного параметра --… — сохранение отменено"}'; return 1; }
	sed -i "/^[[:space:]]*option NFQWS_OPT '/,\$d" "$CONF"
	{ echo "	option NFQWS_OPT '"; printf '%s\n' "$content"; echo "'"; } >> "$CONF"
	if _zo_doh_on; then [ -f "$ZO_DOH_FLAG" ] || { mkdir -p "$ZM_STATE_DIR"; _zo_doh_tpl > "$ZO_DOH_FLAG"; }
	else rm -f "$ZO_DOH_FLAG"; fi
	[ -f /opt/zapret/sync_config.sh ] && chmod +x /opt/zapret/sync_config.sh
	zapret_restart
	sleep 1
	printf '{"ok":true}\n'
}

TG_MTPROTO_VER="0.11"
TG_MTPROTO_TAG="0.11-rev3"
TG_MTPROTO_REV=3
TGWS_VERSION="0.3.1"
TGWS_BASE_URL="https://gitlab.com/xyzmean/brb/-/raw/main/dist"
TGWS_VERSION_URL="https://gitlab.com/xyzmean/brb/-/raw/main/VERSION"
TG_GO_VER="1.4.1"
TG_RS_VER="2.6.1"
TG_BIN_GO="/usr/bin/tg-ws-proxy-go"
TG_INIT_GO="/etc/init.d/tg-ws-proxy-go"
TG_BIN_RS="/usr/bin/tg-ws-proxy-rs"
TG_INIT_RS="/etc/init.d/tg-ws-proxy-rs"
TG_SECRET_RS_FILE="/etc/tg-ws-proxy-rs.secret"
TG_SECRET_MT_FILE="/etc/tg-ws-proxy/secret.conf"
TG_VER_GO_FILE="/etc/tg-ws-proxy-go.ver"
TG_VER_RS_FILE="/etc/tg-ws-proxy-rs.ver"
TG_REPO_MT="spatiumstas/tg-ws-proxy-go"
TG_REPO_GO="d0mhate/-tg-ws-proxy-Manager-go"
TG_REPO_RS="valnesfjord/tg-ws-proxy-rs"

_gh_latest_tag() {
	curl -Ls --connect-timeout 5 --max-time 12 -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" 2>/dev/null |
		sed -n 's#.*/releases/tag/##p' | head -n1 | grep -E '^[vV]?[0-9]+(\.[0-9]+)+(-rev[0-9]+)?$'
}

_tg_mt_show() { if [ "${2:-1}" -gt 1 ] 2>/dev/null; then echo "$1-$2"; else echo "$1"; fi; }

_tg_latest() {
	local t
	t="$(_zm_cached "tg_$1" "_tg_tag_$1")"
	[ -n "$t" ] || case "$1" in mt) t="$TG_MTPROTO_TAG $TG_MTPROTO_REV" ;; go) t="v$TG_GO_VER" ;; rs) t="v$TG_RS_VER" ;; esac
	echo "$t"
}

_tg_newer() { [ -n "$1" ] && [ -n "$2" ] && _st_ver_lt "$(_ver_norm "$1" | tr - .)" "$(_ver_norm "$2" | tr - .)"; }

_zm_pkg_files() {
	if [ "$PKG" = apk ]; then apk info -L "$1" 2>/dev/null | grep -v 'contains:$' | grep -v '^$' | sed 's#^/*#/#'
	else opkg files "$1" 2>/dev/null | grep '^/'; fi
}

_zm_pkg_purge() {
	local p="$1" files f try=1 left reg ca=0
	_pkg_is_installed "$p" || return 0
	_zm_ca_have && ca=1
	files="$(_zm_pkg_files "$p")"
	echo "   → Удаляем пакет $p"
	while [ "$try" -le 4 ]; do
		if [ "$try" = 1 ]; then
			_zm_run 180 $PKG_DEL "$p" >/dev/null 2>&1
		else
			[ "$try" = 4 ] && _zm_pkg_reg_drop "$p"
			if [ "$PKG" = apk ]; then
				_zm_run 180 apk del --force-broken-world "$p" >/dev/null 2>&1 || _zm_run 180 apk del --force "$p" >/dev/null 2>&1
			else
				_zm_run 180 opkg remove --force-depends --force-remove "$p" >/dev/null 2>&1
			fi
		fi
		_zm_pkg_unlock
		left=""
		for f in $files; do
			[ -f "$f" ] || [ -L "$f" ] || continue
			rm -f "$f" 2>/dev/null
			[ -f "$f" ] || [ -L "$f" ] && left="$left $f"
		done
		reg=0; _pkg_is_installed "$p" && reg=1
		if [ "$reg" = 0 ] && [ -z "$left" ]; then
			if [ -n "$ZM_PKG_QUIET" ]; then :
			elif [ "$try" = 1 ]; then echo "   ✓ Пакет $p удалён, остатков нет"
			else echo "   ✓ Пакет $p удалён с попытки $try, остатков нет"; fi
			[ "$ca" = 1 ] && _zm_ca_keep
			return 0
		fi
		[ "$try" -lt 4 ] && echo "   ↻ Пакет $p удалился не полностью — попытка $((try + 1)) из 4"
		try=$((try + 1))
		sleep 2
	done
	[ "$ca" = 1 ] && _zm_ca_keep
	[ "$reg" = 1 ] && echo "!! Пакет $p не удалился за 4 попытки — он всё ещё числится в системе"
	[ -n "$left" ] && echo "!! От пакета $p остались файлы:$left"
	return 1
}

_zm_luci_files() {
	local n
	for n in "$@"; do
		printf '%s ' "/www/luci-static/resources/view/$n" "/www/luci-static/resources/$n" "/www/luci-static/resources/protocol/$n.js" \
			"/usr/share/luci/menu.d/luci-app-$n.json" "/usr/share/luci/menu.d/luci-proto-$n.json" \
			"/usr/share/rpcd/acl.d/luci-app-$n.json" "/usr/share/rpcd/acl.d/luci-proto-$n.json" \
			"/usr/libexec/rpcd/luci.$n" "/usr/share/rpcd/ucode/luci.$n" "/usr/lib/lua/luci/i18n/$n.*.lmo"
	done
}
_zm_rm_listed() {
	local t l=""
	for t in $(_pg_trace "$1"); do case "$t" in /*) l="$l $t" ;; esac; done
	_zm_wipe $l
}

_zm_pkg_wipe() {
	local p rc=0
	for p; do _zm_pkg_purge "$p" || rc=1; done
	return $rc
}

_zm_wipe() {
	local f try=1 left
	while [ "$try" -le 4 ]; do
		left=""
		for f in "$@"; do
			[ -e "$f" ] || [ -L "$f" ] || continue
			rm -rf "$f" 2>/dev/null
			[ -e "$f" ] || [ -L "$f" ] && left="$left $f"
		done
		[ -z "$left" ] && return 0
		try=$((try + 1))
		sleep 1
	done
	echo "!! Не удалось удалить за 4 попытки:$left"
	return 1
}

_zm_rm_done() {
	if [ "$1" = 0 ] && [ -n "$ZM_RM_INNER" ]; then
		ZM_RB_NOTE=""
		echo "   ✓ Прежний $2 удалён — ставим заново"
		return 0
	fi
	if [ "$1" = 0 ]; then
		echo "==> Готово: $2 удалён полностью, остатков нет"
		_zm_rb_note
		return 0
	fi
	ZM_RB_NOTE=""
	echo "ОШИБКА: $2 удалён не полностью — что осталось, написано выше. Перезагрузите роутер и нажмите «Удалить» ещё раз"
	return 1
}

_zm_stop_svc() {
	local s="$1" b="$2"
	[ -x "/etc/init.d/$s" ] && { "/etc/init.d/$s" stop >/dev/null 2>&1; "/etc/init.d/$s" disable >/dev/null 2>&1; }
	[ -n "$b" ] && killall "$b" >/dev/null 2>&1
	rm -f /etc/rc.d/[SK][0-9][0-9]"$s"
}

_zm_reinstall() {
	ZM_RM_INNER=1
	"$1" || { ZM_RM_INNER=""; echo "ОШИБКА: не удалось удалить — переустановка остановлена"; return 1; }
	ZM_RM_INNER=""
	"$2"
}

_tg_rs_uci() {
	[ -f /etc/config/tg-ws-proxy-rs ] && [ -f "$TG_INIT_RS" ] && ! grep -q -- '--secret' "$TG_INIT_RS"
}
_tg_hex() {
	if command -v hexdump >/dev/null 2>&1; then printf '%s' "$1" | hexdump -v -e '1/1 "%02x"'
	else printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; fi
}
_tg_rs_link_secret() {
	local secret="$1" domain="$2" key="$1"
	[ -n "$secret" ] || return 0
	case "$secret" in dd*|ee*) [ "${#secret}" -gt 32 ] && key="$(printf '%s' "$secret" | cut -c3-34)" ;; esac
	if [ -n "$domain" ]; then
		printf 'ee%s%s' "$key" "$(_tg_hex "$domain")"
	elif [ "$key" != "$secret" ]; then
		printf '%s' "$secret"
	else
		printf 'dd%s' "$secret"
	fi
}

tg_status() {
	local mt="not_installed" mt_running="false" mt_ver=""
	local go="not_installed" go_running="false" go_ver=""
	local rs="not_installed" rs_running="false" rs_ver=""
	local secret_mt="" secret_rs="" lan_ip
	local rs_uci="false" rs_enabled="true" rs_port=2443 rs_host="" rs_domain="" v

	if [ -f /etc/init.d/tg-ws-proxy ]; then
		mt="installed"; pidof tg-ws-proxy >/dev/null 2>&1 && mt_running="true"
		if [ "$PKG" = "apk" ]; then
			v=$(apk info -v 2>/dev/null | grep '^tg-ws-proxy-[0-9]' | head -n1 | sed -E 's/^tg-ws-proxy-([0-9.]+)(-r([0-9]+))?.*/\1 \3/')
		else
			v=$(_opkg_ver tg-ws-proxy | sed -E 's/^([0-9.]+)(-r?([0-9]+))?.*/\1 \3/')
		fi
		set -- $v
		mt_ver="$(_tg_mt_show "$1" "$2")"
	fi
	if [ -f "$TG_INIT_GO" ]; then
		go="installed"; pidof tg-ws-proxy-go >/dev/null 2>&1 && go_running="true"
		[ -f "$TG_VER_GO_FILE" ] && go_ver=$(cat "$TG_VER_GO_FILE")
	fi
	if [ -f "$TG_INIT_RS" ]; then
		rs="installed"; pidof tg-ws-proxy-rs >/dev/null 2>&1 && rs_running="true"
		[ -f "$TG_VER_RS_FILE" ] && rs_ver=$(cat "$TG_VER_RS_FILE")
	fi

	secret_mt="$(_tg_mt_secret)"
	if _tg_rs_uci; then
		rs_uci="true"
		_tg_rs_off && rs_enabled="false"
		rs_port="$(uci -q get tg-ws-proxy-rs.main.port)"; [ -n "$rs_port" ] || rs_port=1443
		secret_rs="$(uci -q get tg-ws-proxy-rs.main.secret)"; secret_rs="${secret_rs%%,*}"
		rs_host="$(uci -q get tg-ws-proxy-rs.main.link_ip)"
		rs_domain="$(uci -q get tg-ws-proxy-rs.main.listen_faketls_domain)"
	elif [ -f "$TG_INIT_RS" ]; then
		secret_rs="$(_tg_rs_init_secret)"
		[ -z "$secret_rs" ] && [ -f "$TG_SECRET_RS_FILE" ] && secret_rs="$(head -n1 "$TG_SECRET_RS_FILE" | tr -cd '0-9a-fA-F')"
		rs_port="$(_tg_port_of rust)"
		rs_domain="$(_tg_init_arg "$TG_INIT_RS" --listen-faketls-domain '[A-Za-z0-9.-]')"
		v="$(_tg_init_arg "$TG_INIT_RS" --host '[0-9.]')"
		case "$v" in ''|0.0.0.0|127.*) ;; *) rs_host="$v" ;; esac
	fi
	if [ "$rs" = installed ] && { [ "$rs_uci" = true ] || [ -z "$rs_ver" ]; }; then
		v="$("$TG_BIN_RS" --version 2>/dev/null | awk '{print $2}')"; [ -n "$v" ] && rs_ver="$(_ver_norm "$v")"
	fi
	secret_rs="$(_tg_rs_link_secret "$secret_rs" "$rs_domain")"
	lan_ip="$(_zm_lan_ip)"
	local mt_port mt_host="" mt_link="" go_port
	mt_port="$(_tg_port_of mtproto)"; go_port="$(_tg_port_of socks5)"
	v="$(_tg_kv "$TG_CONF_MT" HOST)"
	case "$v" in ''|0.0.0.0|127.*) ;; *) mt_host="$v" ;; esac
	if [ -n "$secret_mt" ]; then
		v="$(_tg_kv "$TG_CONF_MT" FAKE_TLS_DOMAIN)"
		if [ -n "$v" ]; then mt_link="ee$secret_mt$(_tg_hex "$v")"; else mt_link="dd$secret_mt"; fi
	fi

	local mt_l go_l rs_l rs_sok=false rs_son=false rs_shost="" rs_sport="" rs_slan=false
	if [ "$rs" = installed ]; then
		_tg_rs_socks_ok "$rs_ver" && rs_sok=true
		set -- $(_tg_rs_socks_cfg)
		[ "$1" = 1 ] && rs_son=true
		rs_shost="$2"; rs_sport="$3"
		case "$rs_shost" in 127.*|::1|localhost) ;; *) rs_slan=true ;; esac
	fi
	mt_l="$(_tg_latest mt)"; mt_l="$(_tg_mt_show "$(_tg_mt_base "${mt_l%% *}")" "${mt_l##* }")"; go_l="$(_ver_norm "$(_tg_latest go)")"; rs_l="$(_ver_norm "$(_tg_latest rs)")"
	printf '{"mtproto":"%s","mtproto_running":%s,"mtproto_version":"%s","mtproto_latest":"%s","mtproto_newer":%s,"socks5":"%s","socks5_running":%s,"socks5_version":"%s","socks5_latest":"%s","socks5_newer":%s,"rust":"%s","rust_running":%s,"rust_version":"%s","rust_latest":"%s","rust_newer":%s,"rust_uci":%s,"rust_enabled":%s,"rust_port":"%s","rust_host":"%s","lan_ip":"%s","secret_mtproto":"%s","secret_rust":"%s","mtproto_port":"%s","mtproto_host":"%s","link_mtproto":"%s","socks5_port":"%s","rust_key":"%s","socks5_args":"%s","rust_args":"%s","args_def":{"socks5":"%s","rust":"%s"},"rust_socks":{"ok":%s,"on":%s,"host":"%s","port":"%s","lan":%s},"auto":%s,"ext":%s}\n' \
		"$mt" "$mt_running" "$(esc "$mt_ver")" "$(esc "$mt_l")" "$(_tg_newer "$mt_ver" "$mt_l" && echo true || echo false)" \
		"$go" "$go_running" "$(esc "$go_ver")" "$(esc "$go_l")" "$(_tg_newer "$go_ver" "$go_l" && echo true || echo false)" \
		"$rs" "$rs_running" "$(esc "$rs_ver")" "$(esc "$rs_l")" "$(_tg_newer "$rs_ver" "$rs_l" && echo true || echo false)" \
		"$rs_uci" "$rs_enabled" "$(esc "$rs_port")" "$(esc "$rs_host")" \
		"$(esc "$lan_ip")" "$(esc "$secret_mt")" "$(esc "$secret_rs")" \
		"$(esc "$mt_port")" "$(esc "$mt_host")" "$(esc "$mt_link")" "$(esc "$go_port")" "$(_tg_rs_uci || esc "$(_tg_rs_init_secret)")" \
		"$(esc "$(_tg_args_of socks5)")" "$(_tg_rs_uci || esc "$(_tg_args_of rust)")" "$(esc "$TG_ARGS_DEF_GO")" "$(esc "$TG_ARGS_DEF_RS")" \
		"$rs_sok" "$rs_son" "$(esc "$rs_shost")" "$(esc "$rs_sport")" "$rs_slan" \
		"$(_tg_auto_json)" "$(_tg_ext_json)"
}

TG_CONF_MT="/etc/tg-ws-proxy/config.conf"
_tg_kv() {
	[ -f "$1" ] || return 0
	awk -v k="$2" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2); sub(/[ \t]*(#.*)?\r?$/, "", v); if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2) } END { printf "%s", v }' "$1"
}
_tg_mt_secret() { _tg_kv "$TG_SECRET_MT_FILE" SECRET | tr -cd '0-9a-fA-F' | tr 'A-F' 'a-f'; }
_tg_init_arg() {
	[ -f "$1" ] || return 0
	sed -n "s/.*$2[[:space:]=]\{1,\}[\"']\{0,1\}\($3\{1,\}\).*/\1/p" "$1" | head -n1
}
_tg_rs_init_secret() { _tg_init_arg "$TG_INIT_RS" --secret '[0-9a-fA-F]' | tr 'A-F' 'a-f'; }
_tg_port_of() {
	local v=""
	case "$1" in
		mtproto) v="$(_tg_kv "$TG_CONF_MT" PORT | tr -cd 0-9)"; echo "${v:-1443}" ;;
		socks5) v="$(_tg_init_arg "$TG_INIT_GO" --port '[0-9]')"; echo "${v:-2080}" ;;
		rust)
			if _tg_rs_uci; then v="$(uci -q get tg-ws-proxy-rs.main.port)"; echo "${v:-1443}"
			else v="$(_tg_init_arg "$TG_INIT_RS" --port '[0-9]')"; echo "${v:-2443}"; fi ;;
	esac
}
_tg_title_of() { case "$1" in mtproto) echo "Go (MTProto)" ;; socks5) echo "SOCKS5" ;; rust) echo "Rust (MTProto)" ;; rsocks) echo "SOCKS5 в Rust" ;; esac; }
_tg_rs_socks_cfg() {
	local on=0 host="" port=""
	if _tg_rs_uci; then
		[ "$(uci -q get tg-ws-proxy-rs.main.socks_enabled)" = 1 ] && on=1
		host="$(uci -q get tg-ws-proxy-rs.main.socks_host)"; port="$(uci -q get tg-ws-proxy-rs.main.socks_port)"
	elif [ -f "$TG_INIT_RS" ]; then
		grep -q -- '--socks-enabled' "$TG_INIT_RS" && on=1
		host="$(_tg_init_arg "$TG_INIT_RS" --socks-host '[0-9a-fA-F.:]')"; port="$(_tg_init_arg "$TG_INIT_RS" --socks-port '[0-9]')"
	fi
	echo "$on ${host:-127.0.0.1} ${port:-1080}"
}
_tg_rs_socks_ok() {
	local v="$1"
	[ -x "$TG_BIN_RS" ] || return 1
	[ -n "$v" ] && { ! _st_ver_lt "$(_ver_norm "$v")" 2.6.0; return; }
	"$TG_BIN_RS" --help 2>/dev/null | grep -q -- '--socks-enabled'
}
_zm_tcp_listen() {
	awk -v P="$(printf '%04X' "$1")" '$4 == "0A" { n = split($2, a, ":"); if (toupper(a[n]) == P) { f = 1; exit } } END { exit !f }' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}
_zm_port_owner() {
	local ino d
	ino="$(awk -v P="$(printf '%04X' "$1")" '$4 == "0A" { n = split($2, a, ":"); if (toupper(a[n]) == P) { print $10; exit } }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)"
	[ -n "$ino" ] || return 0
	for d in /proc/[0-9]*; do
		ls -l "$d/fd" 2>/dev/null | grep -qF "socket:[$ino]" || continue
		cat "$d/comm" 2>/dev/null || echo "?"
		return 0
	done
	echo "?"
}

TG_ARGS_DEF_GO="--cf-proxy --cf-proxy-first --cf-balance"
TG_ARGS_DEF_RS="--default-domains --cf-balance --cf-priority"
_tg_args_of() {
	local init
	init="$(_tg_auto_init "$1")" || return 0
	[ -f "$init" ] || return 0
	awk '
		/procd_set_param[ \t]+command/ && !d {
			d = 1; o = ""; seen = 0
			for (i = 1; i <= NF; i++) {
				t = $i; gsub(/^["\047]|["\047]$/, "", t)
				if (!seen) { if (t ~ /tg-ws-proxy-(go|rs)$/) seen = 1; continue }
				if (t ~ /^--?(host|port|secret|listen-faketls-domain|socks-host|socks-port)$/) { i++; continue }
				if (t ~ /^--?(host|port|secret|listen-faketls-domain|socks-host|socks-port)=/ || t == "--socks-enabled") continue
				o = o (o == "" ? "" : " ") t
			}
			print o
		}' "$init"
}

TG_EXT_FILE="$ZM_STATE_DIR/tg.ext"
_tg_unhex() { printf '%s' "$1" | awk '{ h = "0123456789abcdef"; o = ""; for (i = 1; i < length($0); i += 2) o = o sprintf("%c", (index(h, substr($0, i, 1)) - 1) * 16 + index(h, substr($0, i + 1, 1)) - 1); printf "%s", o }'; }
_tg_fw_port() { [ "$(uci -q get "firewall.zm_tg_$1")" = rule ] && uci -q get "firewall.zm_tg_$1.dest_port"; }
_zm_wan_ip() {
	local s n ip
	for n in wan $(s="$(_zm_zone_sec "$(_zm_wan_zone)")" && uci -q get "firewall.$s.network"); do
		ip="$(ifstatus "$n" 2>/dev/null | jsonfilter -e "@['ipv4-address'][0].address" 2>/dev/null)"
		[ -n "$ip" ] && { echo "$ip"; return 0; }
	done
	return 1
}
_zm_ip_grey() {
	case "$1" in
		10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
	esac
	return 1
}
_tg_tls_of() {
	local d s
	case "$1" in
		mtproto) _tg_kv "$TG_CONF_MT" FAKE_TLS_DOMAIN ;;
		rust)
			if _tg_rs_uci; then uci -q get tg-ws-proxy-rs.main.listen_faketls_domain; return 0; fi
			d="$(_tg_init_arg "$TG_INIT_RS" --listen-faketls-domain '[A-Za-z0-9.-]')"
			if [ -z "$d" ]; then
				s="$(_tg_rs_init_secret)"
				case "$s" in ee*) [ "${#s}" -gt 34 ] && d="$(_tg_unhex "$(printf '%s' "$s" | cut -c35-)")" ;; esac
			fi
			printf '%s' "$d" ;;
	esac
}
_tg_ddns_hosts() {
	local s h
	for s in $(uci -q -X show ddns 2>/dev/null | sed -n 's/^ddns\.\([^.=]*\)=service$/\1/p'); do
		[ "$(uci -q get "ddns.$s.enabled")" = 1 ] || continue
		[ "$(uci -q get "ddns.$s.use_ipv6")" = 1 ] && continue
		h="$(uci -q get "ddns.$s.lookup_host")"; [ -n "$h" ] || h="$(uci -q get "ddns.$s.domain")"
		h="$(printf '%s' "${h##*@}" | tr 'A-Z' 'a-z')"
		_tg_dom_ok "$h" && echo "$h"
	done | awk '!s[$0]++'
}
_tg_ext_one() {
	local id="$1" tls port fp live=false ft=false pkg=false
	[ -f "$(_tg_auto_init "$id")" ] || { printf '"%s":null' "$id"; return 0; }
	tls="$(_tg_tls_of "$id")"; fp="$(_tg_fw_port "$id")"; port="$(_tg_port_of "$id")"
	[ -n "$fp" ] && _tg_fw_live "$id" && live=true
	if [ "$id" = rust ] && _tg_rs_uci; then pkg=true; else _tg_ftls_ok "$id" && ft=true; fi
	printf '"%s":{"ftls":%s,"tls":"%s","open":%s,"fw_port":"%s","fw_live":%s,"port":"%s","host":"%s","hmode":"%s","pkg":%s}' "$id" \
		"$ft" "$(esc "$tls")" "$([ -n "$fp" ] && echo true || echo false)" "$(esc "$fp")" "$live" "$(esc "$port")" \
		"$(esc "$(_tg_ext_get "$id" host)")" "$(esc "$(_tg_ext_get "$id" hmode)")" "$pkg"
}
_tg_ext_json() {
	local wan grey=false dd=""
	wan="$(_zm_wan_ip)"
	[ -n "$wan" ] && _zm_ip_grey "$wan" && grey=true
	dd="$(_tg_ddns_hosts | awk '{ printf "%s\"%s\"", (NR > 1 ? "," : ""), $0 }')"
	printf '{%s,%s,"wan":"%s","grey":%s,"ddns":[%s]}' "$(_tg_ext_one mtproto)" "$(_tg_ext_one rust)" "$(esc "$wan")" "$grey" "$dd"
}
TG_AUTO_TAG="# zm-tg-auto"
TG_WATCH_FLAG="$ZM_STATE_DIR/tg.watch"

_tg_auto_init() {
	case "$1" in
		mtproto) echo /etc/init.d/tg-ws-proxy ;;
		socks5) echo "$TG_INIT_GO" ;;
		rust) echo "$TG_INIT_RS" ;;
		tgws) echo /etc/init.d/tgws ;;
		*) return 1 ;;
	esac
}

_tg_auto_get() {
	local v
	v="$(grep -F "$TG_AUTO_TAG-$1=" "$CRON_FILE" 2>/dev/null | head -n1 | sed 's/.*=//')"
	case "$v" in m5|m10|m15|m30|h1|h2|h3|h6|h12|d[0-9]|d1[0-9]|d2[0-3]) echo "$v" ;; *) echo off ;; esac
}

_tg_auto_json() {
	printf '{"mtproto":"%s","socks5":"%s","rust":"%s","tgws":"%s","watch":%s}' \
		"$(_tg_auto_get mtproto)" "$(_tg_auto_get socks5)" "$(_tg_auto_get rust)" "$(_tg_auto_get tgws)" \
		"$([ -f "$TG_WATCH_FLAG" ] && echo true || echo false)"
}

_tg_any_installed() {
	local id
	for id in mtproto socks5 rust tgws; do
		[ -x "$(_tg_auto_init "$id")" ] && return 0
	done
	return 1
}

_tgws_domain() {
	tgws status 2>/dev/null | sed -n 's/^[[:space:]]*домен:[[:space:]]*//p' | head -n1
}

tgws_status() {
	local installed="not_installed" ver="" domain="" running="false" latest=""
	if [ "$PKG" = "apk" ]; then
		ver=$(apk info -v 2>/dev/null | grep '^tgws-' | sed -E 's/^tgws-([0-9.]+).*/\1/')
	else
		ver=$(_opkg_ver tgws | sed 's/-r[0-9]\+$//')
	fi
	if [ -x /etc/init.d/tgws ]; then
		installed="installed"
		[ -n "$(tgws status 2>/dev/null)" ] && running="true"
		domain=$(_tgws_domain)
	fi
	latest="$(_zm_cached tgws _tgws_latest)"
	[ -n "$latest" ] || latest="$TGWS_VERSION"
	local saved=false smart=false
	[ -s /etc/stgws/route.conf.custom ] && saved=true
	[ -f /etc/stgws/smart-map ] && smart=true
	printf '{"installed":"%s","running":%s,"version":"%s","latest":"%s","newer":%s,"domain":"%s","route_saved":%s,"smart_auto":%s}\n' "$installed" "$running" "$(esc "$ver")" "$(esc "$latest")" "$(_tg_newer "$ver" "$latest" && echo true || echo false)" "$(esc "$domain")" "$saved" "$smart"
}

TEST_DIR="$JOBS_DIR/strategy_test"
_test_running() { _job_running strategy_test; }
TEST_KEEP="$ZM_STATE_DIR/tests"

_test_recover() {
	[ -s "$ZM_STATE_DIR/strategy_test.backup" ] || return 0
	_test_running && return 0
	[ -d /opt/zapret ] && cp -f "$ZM_STATE_DIR/strategy_test.backup" "$CONF" && zapret_restart
	rm -f "$ZM_STATE_DIR/strategy_test.backup"
}
TEST_BACKUP="$ZM_STATE_DIR/strategy_test.backup"
TEST_STOP_FLAG="$TEST_DIR/stop"
TEST_MODE_FILE="$TEST_DIR/mode"
TEST_DOMAINS_JSON="${GH_RAW}/hyperion-cs/dpi-checkers/refs/heads/main/ru/tcp-16-20/suite.v2.json"
TEST_YT_DOMAINS="youtu.be youtube.com i.ytimg.com i9.ytimg.com yt3.ggpht.com yt4.ggpht.com googleapis.com jnn-pa.googleapis.com googleusercontent.com signaler-pa.youtube.com youtubei.googleapis.com manifest.googlevideo.com yt3.googleusercontent.com rr4---sn-q4flrnsl.googlevideo.com rr5---sn-n8v7knez.googlevideo.com rr2---sn-q4fl6ndl.googlevideo.com rr1---sn-q4fl6n6y.googlevideo.com rr1---sn-4axm-n8vs.googlevideo.com rr2---sn-hgn7ynek.googlevideo.com rr14---sn-n8v7kn7r.googlevideo.com rr16---sn-axq7sn76.googlevideo.com rr4---sn-jvhnu5g-c35d.googlevideo.com rr1---sn-8ph2xajvh-5xge.googlevideo.com rr1---sn-xguxaxjvh-gufl.googlevideo.com rr1---sn-gvnuxaxjvh-5gie.googlevideo.com rr1---sn-gvnuxaxjvh-o8ge.googlevideo.com rr5---sn-gvnuxaxjvh-n8vk.googlevideo.com rr10---sn-gvnuxaxjvh-304z.googlevideo.com rr12---sn-gvnuxaxjvh-bvwz.googlevideo.com rr1---sn-ug5onuxaxjvh-p3ul.googlevideo.com rr1---sn-ug5onuxaxjvh-n8v6.googlevideo.com rr1---sn-u5uuxaxjvhg0-ocje.googlevideo.com"
TEST_PARALLEL=8

ZO_RKN_URL="${GH_RAW}/IndeecFOX/zapret4rocket/refs/heads/master/extra_strats/TCP/RKN/List.txt"
ZO_RKN_FILE="/opt/zapret/ipset/zapret-hosts-rkn.txt"
ZO_RKN_FLAG="$ZM_STATE_DIR/zapret_rkn"
ZO_RKN_SRC_FILE="$ZM_STATE_DIR/zapret_rkn_src"
_zo_rkn_src() { [ "$(cat "$ZO_RKN_SRC_FILE" 2>/dev/null)" = tachyon ] && echo tachyon || echo z4r; }
ZO_USER_HL="--hostlist=/opt/zapret/ipset/zapret-hosts-user.txt"
ZO_EXCL_HL="--hostlist-exclude=/opt/zapret/ipset/zapret-hosts-user-exclude.txt"
ZO_WSS="--wssize 1:6"
ZO_IPID="--ip-id=zero"
ZO_IPID_FLAG="$ZM_STATE_DIR/zapret_ipid"
ZO_YT_HL="--hostlist=/opt/zapret/ipset/zapret-hosts-google.txt"
ZO_SCRIPT="/opt/zapret/init.d/openwrt/custom.d/50-script.sh"

_zo_rkn_on() { case "$ZM_RKN" in 1) return 0 ;; 0) return 1 ;; esac; _nfq_opt_body | grep -qxF -- "--hostlist=$ZO_RKN_FILE"; }
_zo_rkn_fits() { case "$ZM_FITS" in 1) return 0 ;; 0) return 1 ;; esac; _nfq_opt_body | grep -qxF -- "$ZO_EXCL_HL"; }

_zo_rkn_patch() {
	[ -s "$ZO_RKN_FILE" ] || return 1
	_zo_rkn_on && return 0
	_zo_rkn_fits || return 1
	[ -f /opt/zapret/ipset/zapret-hosts-user.txt ] || : > /opt/zapret/ipset/zapret-hosts-user.txt
	awk -v EX="$ZO_EXCL_HL" -v U="$ZO_USER_HL" -v R="--hostlist=$ZO_RKN_FILE" '
		/^[[:space:]]*option NFQWS_OPT \047[[:space:]]*$/ { inb = 1; print; next }
		inb && /^[[:space:]]*\047[[:space:]]*$/ { inb = 0 }
		inb && $0 == EX { print U; print R; next }
		{ print }' "$CONF" > "$CONF.zo" && mv -f "$CONF.zo" "$CONF"
	_zo_rkn_on
}

_zo_rkn_unpatch() {
	awk -v EX="$ZO_EXCL_HL" -v U="$ZO_USER_HL" -v R="--hostlist=$ZO_RKN_FILE" '
		/^[[:space:]]*option NFQWS_OPT \047[[:space:]]*$/ { inb = 1; print; next }
		inb && /^[[:space:]]*\047[[:space:]]*$/ { if (held) print U; held = 0; inb = 0; print; next }
		inb && $0 == U && !held { held = 1; next }
		inb && $0 == R { if (held) { print EX; held = 0 } next }
		inb && held { print U; held = 0 }
		{ print }' "$CONF" > "$CONF.zo" && mv -f "$CONF.zo" "$CONF"
}

ZO_USER_FLAG="$ZM_STATE_DIR/zapret_userlist"
ZO_USER_FILE="/opt/zapret/ipset/zapret-hosts-user.txt"
_zo_user_on() { [ -f "$ZO_USER_FLAG" ] && ! _zo_rkn_on && ! _zo_rkn_fits && _nfq_opt_body | grep -qxF -- "$ZO_USER_HL"; }
_zo_user_count() { sed 's/#.*//' "$ZO_USER_FILE" 2>/dev/null | awk 'NF { n++ } END { print n + 0 }'; }

_zo_wss_on() { _nfq_opt_body | grep -qxF -- "$ZO_WSS"; }

ZO_DOH_FLAG="$ZM_STATE_DIR/zapret_doh"
ZO_DOH_DEF="cloudflare-dns.com,dns.google,dns.comss.one,dns.quad9.net"
ZO_DOH_MK='^[ \t]*#[ \t]*DoH[ \t]*$'
_zo_doh_on() { case "$ZM_DOH" in 1) return 0 ;; 0) return 1 ;; esac; _nfq_opt_body | awk -v M="$ZO_DOH_MK" '$0 ~ M { f = 1 } END { exit !f }'; }
_zo_doh_hosts() {
	local x="" id c
	if _doh_fo_on; then
		c="$(_doh_fo_get chain "")"
		set -f
		for id in $([ -n "$ZO_DOH_PLAN" ] || _doh_fo_get pref "") $(IFS=,; echo $c); do x="$x $(_doh_url_of "$id")"; done
		set +f
	fi
	{ [ -n "$ZO_DOH_PLAN" ] || uci -q show https-dns-proxy 2>/dev/null; } | awk -v P="$ZO_DOH_PLAN" -v X="$x" '
		function add(u,   h) {
			if (u !~ /^https:\/\//) return
			h = tolower(u); sub(/^https:\/\//, "", h); sub(/[\/:?].*$/, "", h)
			if (h !~ /^[a-z0-9.-]*[a-z][a-z0-9.-]*$/ || (h in s)) return
			s[h] = 1; d[++n] = h
		}
		P == "" && /\.resolver_url=/ { v = $0; sub(/^[^=]*=/, "", v); gsub(/\047/, "", v); add(v); r++ }
		END {
			if (P != "") { add(P); r = 1 }
			if (!r) exit
			m = split(X, a, " ")
			for (i = 1; i <= m; i++) add(a[i])
			for (i = 1; i <= n; i++) {
				k = 0
				for (j = 1; j <= n; j++) if (j != i && length(d[i]) > length(d[j]) && substr(d[i], length(d[i]) - length(d[j])) == "." d[j]) k = 1
				if (!k) o = o (o == "" ? "" : ",") d[i]
			}
			print o
		}'
}
_zo_doh_doms() { local d; d="$(_zo_doh_hosts)"; echo "${d:-$ZO_DOH_DEF}"; }
ZO_DOH_OLD="--filter-tcp=443 --dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=ya.ru --dpi-desync-hostfakesplit-midhost=host-2 --dpi-desync-split-seqovl=726 --dpi-desync-fooling=badsum,badseq --dpi-desync-badseq-increment=0"
ZO_DOH_NEW="--filter-tcp=443 --dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=common.dot.dns.yandex.net --dpi-desync-hostfakesplit-midhost=host-2 --dpi-desync-split-seqovl=726 --dpi-desync-fooling=badsum,badseq --dpi-desync-badseq-increment=0"
_zo_doh_tpl() {
	local t
	t="$(grep '^--' "$ZO_DOH_FLAG" 2>/dev/null | grep -v '^--hostlist-domains=' | grep -vx -- '--new')"
	if ! printf '%s\n' "$t" | grep -q '^--filter-tcp=' || ! printf '%s\n' "$t" | grep -q '^--dpi-desync=' || [ "$(echo $t)" = "$ZO_DOH_OLD" ]; then
		t="$(printf '%s\n' $ZO_DOH_NEW)"
	fi
	printf '%s\n' "$t"
}
_zo_doh_stale() {
	[ "$(_nfq_opt_body | awk -v M="$ZO_DOH_MK" '
		$0 ~ M { c++; d = (c == 1); next }
		d && $0 == "--new" { d = 0 }
		d && /^[ \t]*--/ && !/^[ \t]*--hostlist-domains=/ { l = $0; gsub(/^[ \t]+|[ \t\r]+$/, "", l); o = o (o == "" ? "" : " ") l }
		END { print o }')" = "$ZO_DOH_OLD" ]
}
_zo_doh_scan() {
	_nfq_opt_body | awk -v M="$ZO_DOH_MK" '
		NR == 1 { next }
		$0 ~ M { c++; if (!opt) top = 1; d = (c == 1); next }
		d && $0 == "--new" { d = 0 }
		d && dom == "" && /^[ \t]*--hostlist-domains=/ { dom = $0; sub(/^[ \t]*--hostlist-domains=/, "", dom); sub(/[ \t\r]+$/, "", dom) }
		/^[ \t]*--/ && $0 != "--new" { opt = 1 }
		END { print (c == 0 ? "none" : (c == 1 && top) ? "top" : "mid") " " dom }'
}
_zo_doh_cut() {
	local f="$CONF.zdoh"
	awk -v M="$ZO_DOH_MK" -v C="${1:-/dev/null}" -v q="'" '
		!inb && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { inb = 1; n = 0; print; next }
		inb && $0 ~ ("^[ \t]*" q "[ \t]*$") {
			while (n > 0 && b[n] == "--new") n--
			for (i = 1; i <= n; i++) print b[i]
			inb = 0; d = 0; print; next
		}
		inb && $0 ~ M { d = 1; c++; next }
		inb && d && $0 == "--new" { d = 0; next }
		inb && d && /^[ \t]*#/ { b[++n] = $0; next }
		inb && d { if (c == 1) print > C; next }
		inb { if ($0 == "--new" && (n == 0 || b[n] == "--new")) next; b[++n] = $0; next }
		{ print }
		END { exit (inb ? 1 : 0) }' "$CONF" > "$f" && [ -s "$f" ] && cat "$f" > "$CONF"
	rm -f "$f"
}
_zo_doh_put() {
	local f="$CONF.zdoh"
	{ echo "#DoH"; _zo_doh_tpl | awk -v D="--hostlist-domains=$1" '!p && !/^--filter-/ { print D; p = 1 } { print } END { if (!p) print D }'; echo "--new"; } > "$f.b"
	awk -v F="$f.b" '!d && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { print; while ((getline l < F) > 0) print l; d = 1; next } { print } END { exit !d }' "$CONF" > "$f" && [ -s "$f" ] && cat "$f" > "$CONF"
	rm -f "$f" "$f.b"
}
_zo_doh_sync() {
	local doms cap
	[ -f "$ZO_DOH_FLAG" ] && [ -f "$CONF" ] || return 1
	grep -q "^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$" "$CONF" || return 1
	_nochange_strategy && return 1
	doms="$(_zo_doh_doms)"
	[ "$(ZM_NFQ_BODY=""; _zo_doh_scan)" = "top $doms" ] && ! (ZM_NFQ_BODY=""; _zo_doh_stale) && return 1
	cap="$ZO_DOH_FLAG.cap"
	rm -f "$cap"
	_zo_doh_cut "$cap"
	grep -q '^--dpi-desync=' "$cap" 2>/dev/null && mv -f "$cap" "$ZO_DOH_FLAG"
	rm -f "$cap"
	_zo_doh_put "$doms"
	return 0
}
_zo_doh_follow() {
	local s2="" a
	[ -x /etc/init.d/zapret ] && [ -f "$CONF" ] || return 0
	_test_running && return 0
	[ -s "$TEST_BACKUP" ] && return 0
	if [ "$(_zs2_kv "$ZS2_DIR" doh)" = on ]; then
		a="$(md5sum "$ZS2_OPT" 2>/dev/null)"
		_zs2_refresh
		[ "$a" = "$(md5sum "$ZS2_OPT" 2>/dev/null)" ] || s2=1
	fi
	if [ -f "$ZO_DOH_FLAG" ] && _zo_doh_sync; then :
	elif [ -z "$s2" ]; then return 0; fi
	[ -n "$s2" ] && _zs2_sync
	pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1 || return 0
	chmod -R a+rX /opt/zapret/ipset /opt/zapret/files 2>/dev/null
	[ -x /opt/zapret/sync_config.sh ] && /opt/zapret/sync_config.sh >/dev/null 2>&1
	/etc/init.d/zapret restart >/dev/null 2>&1
	return 0
}

_yv_ipid_scan() {
	_nfq_opt_body | awk -v H="$ZO_YT_HL" -v Z="$ZO_IPID" -v S="$ZC_START_RX" -v E="$ZC_END_RX" '
		function flush() { if (yt && tcp) { n++; if (z) k++ } yt = 0; tcp = 0; z = 0 }
		{ l = $0; sub(/^[ \t]+/, "", l); sub(/[ \t\r]+$/, "", l) }
		tolower(l) ~ S { flush(); c = 1; next }
		c { if (tolower(l) ~ E) c = 0; next }
		l == "--new" { flush(); next }
		l == H { yt = 1 }
		l ~ /^--filter-tcp=/ { tcp = 1 }
		l == Z { z = 1 }
		END { flush(); print n + 0, k + 0 }'
}
_yv_ipid_on() { set -- ${ZM_YS:-$(_yv_ipid_scan)}; [ "${2:-0}" -gt 0 ]; }
_yv_ipid_want() {
	local w=""
	case "$ZT_IPID" in on) echo on; return 0 ;; none) return 0 ;; esac
	[ -s "$ZO_IPID_FLAG" ] && read -r w < "$ZO_IPID_FLAG"
	case "$w" in on|off) echo "$w" ;; esac
}
_yv_ipid_apply() {
	[ -f "$CONF" ] || return 1
	case "$1" in on|off) ;; *) return 1 ;; esac
	awk -v W="$1" -v H="$ZO_YT_HL" -v Z="$ZO_IPID" -v S="$ZC_START_RX" -v E="$ZC_END_RX" -v q="'" '
		function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
		function flush(   i, l, yt, tcp, put) {
			yt = 0; tcp = 0; put = 0
			for (i = 1; i <= nb; i++) { l = trim(b[i]); if (l == H) yt = 1; if (l ~ /^--filter-tcp=/) tcp = 1 }
			for (i = 1; i <= nb; i++) {
				l = trim(b[i])
				if (yt && tcp && ((W == "on" && l ~ /^--ip-id=/) || (W == "off" && l == Z))) continue
				print b[i]
				if (yt && tcp && W == "on" && l == H && !put) { print Z; put = 1 }
			}
			nb = 0
		}
		!inb && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { inb = 1; print; next }
		inb && $0 ~ ("^[ \t]*" q "[ \t]*$") { flush(); inb = 0; print; next }
		inb && !c && tolower(trim($0)) ~ S { flush(); c = 1; print; next }
		inb && c { print; if (tolower(trim($0)) ~ E) c = 0; next }
		inb && trim($0) == "--new" { flush(); print; next }
		inb { b[++nb] = $0; next }
		{ print }
		END { if (inb) exit 1 }' "$CONF" > "$CONF.ipid" && [ -s "$CONF.ipid" ] && { cmp -s "$CONF" "$CONF.ipid" || cat "$CONF.ipid" > "$CONF"; }
	rm -f "$CONF.ipid"
}

_yv_ipid_sync() {
	local w
	w="$(_yv_ipid_want)"
	[ -n "$w" ] && [ -f "$CONF" ] || return 0
	_nochange_strategy && return 0
	_yv_ipid_apply "$w"
	return 0
}
ZO_GV_FLAG="$ZM_STATE_DIR/zapret_gv"
ZO_GV_RX='^[ \t]*#[ \t]*gvideo[0-9]+[ \t]*$'
_zo_gv_want() { local w=""; [ -s "$ZO_GV_FLAG" ] && read -r w < "$ZO_GV_FLAG"; _zm_re "$w" '^[0-9]+$' && echo "$w"; return 0; }
_zo_gv_blk() { _gv_ok "$1" || return 1; echo "#gvideo$1"; _str_body StrGVideo "gVideo$1"; }
_zo_gv_cur() { _nfq_opt_body | sed -n 's/^[ \t]*#[ \t]*gvideo\([0-9][0-9]*\)[ \t]*$/\1/p' | head -n 1; }
_zo_gv_count() { _nfq_opt_body | grep -cE "$ZO_GV_RX"; }
_zo_gv_first() {
	_nfq_opt_body | sed '1d;$d' | awk -v D="$ZO_DOH_MK" -v G="$ZO_GV_RX" -v CS="$ZC_START_RX" '
		tolower($0) ~ CS { exit }
		!n && !g && $0 ~ D { dh = 1; next }
		dh { if ($0 == "--new") dh = 0; next }
		$0 == "--new" { if (n) exit; next }
		$0 ~ G { g = 1; print; next }
		/^[ \t]*#/ { next }
		/^[ \t]*$/ { next }
		{ print; n++ }'
}
_zo_gv_ok() { [ "$(_zo_gv_count)" = 1 ] && [ "$(_zo_gv_first)" = "$(_zo_gv_blk "$1")" ]; }
_zo_gv_drop() {
	[ "$(_zo_gv_count)" -gt 0 ] 2>/dev/null || return 0
	_nfq_drop_profiles "$ZO_GV_RX"
	case $? in 0|3) return 0 ;; esac
	return 1
}
_zo_gv_put() {
	local f="$CONF.zgv"
	_zo_gv_blk "$1" > "$f.b"
	awk -v F="$f.b" -v D="$ZO_DOH_MK" -v MK="$NFQ_MARK_RX" -v CS="$ZC_START_RX" -v q="'" '
		function put(   l) { while ((getline l < F) > 0) print l; close(F); d = 1 }
		!inb && !d && /^[ \t]*option NFQWS_OPT \047[ \t]*$/ { inb = 1; print; next }
		inb && !d && $0 ~ ("^[ \t]*" q "[ \t]*$") { if (dh) print "--new"; put(); print; inb = 0; next }
		inb && !d && dh { print; if ($0 == "--new") { put(); print "--new" } next }
		inb && !d && tolower($0) ~ CS { put(); print "--new"; print; next }
		inb && !d && $0 ~ D { dh = 1; print; next }
		inb && !d && $0 !~ MK && (/^[ \t]*#/ || /^[ \t]*$/) { print; next }
		inb && !d { put(); print "--new"; print; next }
		{ print }
		END { exit !d }' "$CONF" > "$f" && [ -s "$f" ] && cat "$f" > "$CONF"
	rm -f "$f" "$f.b"
	_zc_norm
	return 0
}
_zo_gv_sync() {
	local w
	[ -f "$CONF" ] || return 0
	grep -q "^[[:space:]]*option NFQWS_OPT '[[:space:]]*\$" "$CONF" || return 0
	_nochange_strategy && return 0
	[ -s "$TEST_BACKUP" ] && return 0
	w="$(_zo_gv_want)"
	if [ -z "$w" ]; then _zo_gv_drop; return 0; fi
	_gv_ok "$w" || return 0
	_zo_gv_ok "$w" && return 0
	_zo_gv_drop || return 1
	_zo_gv_put "$w"
	return 0
}

_zo_wss_add() {
	_zo_wss_on && return 0
	_nfq_opt_body | sed '1d;$d' | grep -q '^--' || return 1
	awk -v W="$ZO_WSS" '
		/^[[:space:]]*option NFQWS_OPT \047[[:space:]]*$/ { inb = 1; print; next }
		inb && /^[[:space:]]*\047[[:space:]]*$/ { print "--new"; print "--filter-tcp=443"; print W; inb = 0 }
		{ print }' "$CONF" > "$CONF.zo" && mv -f "$CONF.zo" "$CONF"
	_zo_wss_on
}

TEST_CUSTOM_FILE="/root/custom_test.txt"

ZA_TAG="# zm-autobest"
ZA_MODE_FILE="$ZM_STATE_DIR/autobest.mode"
ZA_LAST="$ZM_STATE_DIR/autobest.last"
ZA_RUN="$TEST_DIR/autobest"
ZA_TS="$ZM_STATE_DIR/autobest.ts"

ZA_YT_FILE="$ZM_STATE_DIR/autobest.yt"
ZA_LAST_YT="$ZM_STATE_DIR/autobest.last_yt"
_za_mode() { case "$(cat "$ZA_MODE_FILE" 2>/dev/null)" in v) echo v ;; flowseal) echo flowseal ;; youtube) echo youtube ;; *) echo v_flowseal ;; esac; }
_za_yt() { [ -f "$ZA_YT_FILE" ]; }
ZA_TIME_FILE="$ZM_STATE_DIR/autobest.time"
_za_time() { grep -F "$ZA_TAG" "$CRON_FILE" 2>/dev/null | head -n 1 | awk '{ printf "%02d:%02d\n", $2, $1 }'; }

ZA_LOG="$ZM_STATE_DIR/autobest.log"

_zt_tz() {
	case "$1" in
		Europe/Kaliningrad) echo "EET-2" ;;
		Europe/Moscow) echo "MSK-3" ;;
		Europe/Samara) echo "<+04>-4" ;;
		Asia/Yekaterinburg) echo "<+05>-5" ;;
		Asia/Omsk) echo "<+06>-6" ;;
		Asia/Krasnoyarsk) echo "<+07>-7" ;;
		Asia/Irkutsk) echo "<+08>-8" ;;
		Asia/Yakutsk) echo "<+09>-9" ;;
		Asia/Vladivostok) echo "<+10>-10" ;;
		Asia/Magadan) echo "<+11>-11" ;;
		Asia/Kamchatka) echo "<+12>-12" ;;
		UTC) echo "UTC" ;;
		*) return 1 ;;
	esac
}

ZT_NTP_STD="0.openwrt.pool.ntp.org 1.openwrt.pool.ntp.org 2.openwrt.pool.ntp.org 3.openwrt.pool.ntp.org"
ZT_NTP_IP="89.109.251.21 89.109.251.22 162.159.200.1 162.159.200.123 216.239.35.0 216.239.35.4"
_zt_ntp_list() { uci -q get system.ntp.server 2>/dev/null | tr -s ' \t' '  ' | sed 's/^ //; s/ $//'; }
_zt_ntp_preset() {
	local l="$1"
	[ -n "$l" ] || { echo none; return 0; }
	[ "$l" = "$ZT_NTP_IP" ] && { echo ip; return 0; }
	printf '%s\n' $l | grep -qv 'pool\.ntp\.org$' && echo own || echo std
}

_zt_json() {
	local l
	set -- $(date '+%s %z %d.%m.%Y %H:%M:%S')
	l="$(_zt_ntp_list)"
	printf '"time":%s,"time_text":"%s","zone":"%s","utc_offset":"%s","ntp":%s,"ntp_preset":"%s","ntp_servers":"%s","dnsm":%s' \
		"$1" "$3 $4" "$(esc "$(uci -q get system.@system[0].zonename)")" "$2" \
		"$([ "$(uci -q get system.ntp.enabled)" = 0 ] && echo false || echo true)" \
		"$(_zt_ntp_preset "$l")" "$(esc "$l")" "$(_dnsm_present && echo true || echo false)"
}

_zt_posix() {
	local z="$1" p f
	p="$(_zt_tz "$z")" && { echo "$p"; return 0; }
	for f in /usr/share/ucode/luci/zoneinfo.uc /usr/lib/lua/luci/sys/zoneinfo/tzdata.lua; do
		[ -f "$f" ] || continue
		p="$(grep -F "'$z'" "$f" 2>/dev/null | head -n 1 | sed -n "s/.*'$(printf '%s' "$z" | sed 's#/#\\/#g')'[^']*'\([^']*\)'.*/\1/p")"
		[ -n "$p" ] && { echo "$p"; return 0; }
	done
	[ -n "$2" ] || return 1
	printf '%s' "$2" | awk '{ s = substr($0, 1, 1); h = substr($0, 2, 2) + 0; m = substr($0, 5, 2) + 0;
		if (s != "+" && s != "-") exit 1
		n = sprintf("%s%02d", s, h); if (m) n = n sprintf("%02d", m)
		printf "<%s>%s%d%s\n", n, (s == "+" ? "-" : ""), h, (m ? ":" m : "") }'
}

_zm_gh_get() { _zm_fetch "$1" "$2" "${4:-120}" "$3"; }

_zm_panel_latest() {
	local f="$JOBS_DIR/zm_head.$$" v
	mkdir -p "$JOBS_DIR"
	_zm_gh_get "$ZM_SCRIPT_URL" "$f" 0-400 8 || { rm -f "$f"; return 1; }
	v="$(grep -m1 '^# Version:' "$f" | sed 's/^# Version:[[:space:]]*//' | tr -d '\r ')"
	rm -f "$f"
	echo "$v" | grep -qE '^[0-9]+(\.[0-9]+)*$' && echo "$v"
}

_zm_newer() { [ -n "$1" ] && _st_ver_lt "$ZM_VERSION" "$1"; }

_zm_stats_on() { [ -n "$ZM_STATS_URL" ] && [ ! -e "$ZM_STATS_OFF" ] && [ -z "$ZM_NO_STATS" ]; }
_zm_stats_age() { local t; t="$(date -r "$1" +%s 2>/dev/null)" || { echo 999999; return; }; echo $(( $(date +%s) - t )); }
_zm_stats_fetch() {
	mkdir -p "$JOBS_DIR"
	rm -f "$2.t.$$"
	if _zm_has curl; then command curl -fsS --connect-timeout 4 --max-time 6 -A "zapret-manager/$ZM_VERSION" -o "$2.t.$$" "$1" 2>/dev/null
	else command wget -q -T 6 -U "zapret-manager/$ZM_VERSION" -O "$2.t.$$" "$1" 2>/dev/null; fi
	if grep -q '"total":[0-9]' "$2.t.$$" 2>/dev/null; then mv -f "$2.t.$$" "$2"; rm -f "$2.fail"; return 0; fi
	rm -f "$2.t.$$"
	: > "$2.fail"
	return 1
}
_zm_stats_due() { [ "$(_zm_stats_age "$1")" -ge "$2" ] && [ "$(_zm_stats_age "$1.fail")" -ge 120 ]; }
_zm_stats_total() { sed -n 's/.*"total":\([0-9]*\).*/\1/p' "$1" 2>/dev/null | head -n1; }
_zm_stats_cached() {
	_zm_stats_on || { echo null; return 0; }
	local f="$JOBS_DIR/stats.json" t
	t="$(_zm_stats_total "$f")"
	_zm_stats_due "$f" 60 && ( _zm_stats_fetch "$ZM_STATS_URL/count" "$f" ) >/dev/null 2>&1 </dev/null &
	echo "${t:-null}"
}

zm_update_status() {
	local latest
	if [ -z "$ZM_VER_FORCE" ] && [ "$(_ver_mode)" != open ]; then latest="$(ZM_VER_LOCAL=1 _zm_cached_first panel _zm_panel_latest)"
	else latest="$(_zm_cached_first panel _zm_panel_latest)"; fi
	printf '{"current":"%s","latest":"%s","newer":%s}\n' "$(esc "$ZM_VERSION")" "$(esc "$latest")" "$(_zm_newer "$latest" && echo true || echo false)"
}

ZM_CL_FILE="/opt/zapret-manager-luci/CHANGELOG.md"
ZM_CL_PENDING="$ZM_STATE_DIR/cl.pending"
ZM_CL_URLS="${GH_RAW}/StressOzz/Zapret-Manager/refs/heads/main/CHANGELOG.md https://cdn.jsdelivr.net/gh/StressOzz/Zapret-Manager@main/CHANGELOG.md"

_zm_cl_get() {
	local out="$1" u
	for u in $ZM_CL_URLS; do
		rm -f "$out"
		_zm_gh_get "$u" "$out" "" 12 && _zm_dl_sane "$out" && [ "$(wc -c < "$out")" -le 262144 ] && return 0
	done
	rm -f "$out"
	return 1
}

_zm_cl_top() {
	if grep -q '^## ' "$1" 2>/dev/null; then
		awk '/^## / { if (s) exit; s = 1 } s && !/^---[[:space:]]*$/' "$1"
	else
		grep -v '^---[[:space:]]*$' "$1"
	fi | tr -d '\r' | head -n 80
}

_zm_cl_sync() {
	local t="$ZM_CL_FILE.dl"
	mkdir -p "$(dirname "$ZM_CL_FILE")"
	if _zm_cl_get "$t"; then mv -f "$t" "$ZM_CL_FILE"; chmod 644 "$ZM_CL_FILE"; echo '{"ok":true}'
	else rm -f "$t"; echo '{"ok":false}'; fi
}

zm_changelog() {
	local mode="$1" f blk="" ver="" date="" from="" pending=false
	case "$mode" in
		local)
			[ -f "$ZM_CL_PENDING" ] || { printf '{"pending":false,"current":"%s"}\n' "$(esc "$ZM_VERSION")"; return 0; }
			pending=true
			from="$(head -n 1 "$ZM_CL_PENDING" | tr -cd '0-9.')"
			f="$ZM_CL_FILE" ;;
		remote)
			f="$JOBS_DIR/changelog.md"
			if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +10 2>/dev/null)" ]; then
				mkdir -p "$JOBS_DIR"
				if _zm_cl_get "$f.dl"; then mv -f "$f.dl" "$f"; else rm -f "$f.dl"; fi
			fi
			[ -s "$f" ] || { echo '{"error":"не удалось скачать список изменений с GitHub"}'; return 1; } ;;
		all)
			f="$JOBS_DIR/changelog.md"
			if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +10 2>/dev/null)" ]; then
				mkdir -p "$JOBS_DIR"
				if _zm_cl_get "$f.dl"; then mv -f "$f.dl" "$f"; else rm -f "$f.dl"; fi
			fi
			blk=github
			[ -s "$f" ] || { f="$ZM_CL_FILE"; blk=local; }
			[ -s "$f" ] || { echo '{"error":"список изменений не загрузился: нет связи с GitHub, а сохранённой копии на роутере пока нет"}'; return 1; }
			printf '{"current":"%s","source":"%s","text":"%s"}\n' "$(esc "$ZM_VERSION")" "$blk" \
				"$(esc_ml "$(grep -v '^---[[:space:]]*$' "$f" | tr -d '\r' | head -n 600)")"
			return 0 ;;
		seen) rm -f "$ZM_CL_PENDING"; echo '{"ok":true}'; return 0 ;;
		*) echo '{"error":"неизвестный режим"}'; return 1 ;;
	esac
	[ -s "$f" ] && blk="$(_zm_cl_top "$f")"
	ver="$(printf '%s\n' "$blk" | sed -n '/[^[:space:]]/{p;q;}' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)"
	date="$(printf '%s\n' "$blk" | sed -n '/[^[:space:]]/{p;q;}' | grep -oE '[0-9]{2}\.[0-9]{2}\.[0-9]{4}' | head -n 1)"
	printf '{"pending":%s,"from":"%s","current":"%s","version":"%s","date":"%s","text":"%s"}\n' \
		"$pending" "$(esc "$from")" "$(esc "$ZM_VERSION")" "$(esc "$ver")" "$(esc "$date")" "$(esc_ml "$blk")"
}

_zm_busy_job() {
	local f j
	for f in "$JOBS_DIR"/*.pid; do
		[ -f "$f" ] || continue
		j="$(basename "$f" .pid)"
		case "$j" in versions|sysinfo|*_download|fk-guard|"$ZM_CLEAN_SELF") continue ;; esac
		_job_running "$j" && { _zm_job_label "$j"; return 0; }
	done
	return 1
}

_mixomo_lan_ip() { _zm_lan_ip; }

_zm_cached() {
	local f="$ZM_STATE_DIR/latest.$1" v age=360
	[ "$1" = panel ] && age=60
	shift
	if [ -n "$ZM_VER_LOCAL" ]; then cat "$f" 2>/dev/null; return 0; fi
	mkdir -p "$ZM_STATE_DIR"
	if [ -n "$ZM_VER_FORCE" ]; then
		v="$("$@")"
		[ -n "$v" ] && echo "$v" > "$f"
	elif [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +$age 2>/dev/null)" ]; then
		if mkdir "$f.lock" 2>/dev/null; then
			( v="$("$@")"; [ -n "$v" ] && echo "$v" > "$f"; rmdir "$f.lock" ) >/dev/null 2>&1 &
		elif [ -n "$(find "$f.lock" -mmin +2 2>/dev/null)" ]; then
			rmdir "$f.lock" 2>/dev/null
		fi
	fi
	cat "$f" 2>/dev/null
}
_zm_cached_first() {
	local f="$ZM_STATE_DIR/latest.$1"
	[ -n "$ZM_VER_LOCAL" ] && { cat "$f" 2>/dev/null; return 0; }
	if [ -s "$f" ] || { [ -f "$f.try" ] && [ -z "$(find "$f.try" -mmin +10 2>/dev/null)" ]; }; then
		_zm_cached "$@"
	else
		mkdir -p "$ZM_STATE_DIR"; : > "$f.try"
		ZM_VER_FORCE=1 _zm_cached "$@"
	fi
}
_mihomo_latest() { curl -Ls --connect-timeout 4 --max-time 6 -o /dev/null -w '%{url_effective}' "https://github.com/MetaCubeX/mihomo/releases/latest" 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

_mt_latest() { curl -fsSL --connect-timeout 4 --max-time 6 -o /dev/null -w '%{url_effective}' "https://github.com/MagiTrickle/MagiTrickle/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+(-rev[0-9]+)?$' | head -1; }
_mt_installed_ver() {
	local v
	if [ "$PKG" = "apk" ]; then
		v=$(apk info -v 2>/dev/null | sed -n 's/^magitrickle-\([0-9].*\)$/\1/p' | head -n1)
	else
		v=$(opkg status magitrickle 2>/dev/null | awk '/^Version:/ {print $2; exit}')
	fi
	printf '%s' "$v" | sed -E 's/-r?1$//; s/-r?([0-9]+)$/-rev\1/'
}
_tgws_latest() { curl -fsSL --connect-timeout 4 --max-time 6 "$TGWS_VERSION_URL" 2>/dev/null | tr -d '[:space:]' | grep -E '^[vV]?[0-9]+(\.[0-9]+)+$'; }

mixomo_status() {
	local mihomo="not_installed" mihomo_running="false" mihomo_ver="" mihomo_latest=""
	local magitrickle="not_installed" magitrickle_running="false" mt_ver="" mt_latest=""
	local hev="not_installed" hev_running="false" hev_ver=""
	local lan_ip subscription="false" mt_list="" autorestart="" ui_panel=""

	if [ -x "$MIHOMO_BIN" ]; then
		mihomo="installed"
		pidof mihomo >/dev/null 2>&1 && mihomo_running="true"
		mihomo_ver=$("$MIHOMO_BIN" -v 2>/dev/null | head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
		mihomo_latest="$(_zm_cached mihomo _mihomo_latest)"
		[ -f "$MIHOMO_DIR/.ui_panel" ] && ui_panel=$(cat "$MIHOMO_DIR/.ui_panel")
	fi
	if [ -x /etc/init.d/magitrickle ]; then
		magitrickle="installed"
		/etc/init.d/magitrickle status >/dev/null 2>&1 && magitrickle_running="true"
		mt_ver="$(_mt_installed_ver)"
		mt_latest="$(_zm_cached magitrickle2 _mt_latest)"
	fi
	if [ -x /etc/init.d/hev-socks5-tunnel ]; then
		hev="installed"
		/etc/init.d/hev-socks5-tunnel status >/dev/null 2>&1 && hev_running="true"
		if [ "$PKG" = "apk" ]; then
			hev_ver=$(apk info -v 2>/dev/null | grep '^hev-socks5-tunnel-' | cut -d- -f4-)
		else
			hev_ver=$(opkg status hev-socks5-tunnel 2>/dev/null | awk '/^Version:/ {print $2}')
		fi
	fi

	lan_ip=$(_mixomo_lan_ip)
	_mx_has_sub && subscription="true"

	if [ -f "$MAGITRICKLE_CONF" ]; then
		if grep -Fq 'name: Google_ai' "$MAGITRICKLE_CONF"; then mt_list="itdog"
		elif grep -Fq 'name: Meta (WA+FB+Instagram)' "$MAGITRICKLE_CONF"; then mt_list="ih2"
		elif grep -Fq 'url: https://sw.ext.io/ipset/ipset_cf.list' "$MAGITRICKLE_CONF"; then mt_list="ih1"
		fi
	fi

	local cronline hourm
	cronline=$(grep -F "$MIXOMO_CRON_CMD" "$CRON_FILE" 2>/dev/null | head -n1)
	if [ -n "$cronline" ]; then
		hourm=$(echo "$cronline" | awk '{print $2}')
		case "$hourm" in
			*/*) autorestart="every:$(echo "$hourm" | cut -d'/' -f2)" ;;
			*) autorestart="daily:$hourm" ;;
		esac
	fi

	printf '{"mihomo":"%s","mihomo_running":%s,"mihomo_version":"%s","mihomo_latest":"%s","magitrickle":"%s","magitrickle_running":%s,"magitrickle_version":"%s","magitrickle_latest":"%s","hev":"%s","hev_running":%s,"hev_version":"%s","lan_ip":"%s","subscription":%s,"magitrickle_list":"%s","autorestart":"%s","ui_panel":"%s","forkozz":%s,"fk_name":"%s","bytetube":%s,"exclude":"%s","mt_all":%s,"api_port":%s,"api_secret":"%s","api_open":%s}\n' \
		"$mihomo" "$mihomo_running" "$(esc "$mihomo_ver")" "$(esc "$mihomo_latest")" \
		"$magitrickle" "$magitrickle_running" "$(esc "$mt_ver")" "$(esc "$mt_latest")" \
		"$hev" "$hev_running" "$(esc "$hev_ver")" \
		"$(esc "$lan_ip")" "$subscription" "$mt_list" "$(esc "$autorestart")" "$(esc "$ui_panel")" \
		"$(_fk_installed && echo true || echo false)" "$(_fk_name)" "$(_bt_installed && echo true || echo false)" "$(esc "$(cat "$MIXOMO_EXCL" 2>/dev/null)")" \
		"$(_mt_all_on && echo true || echo false)" "$(_mx_api_port)" "$(esc "$(_mx_secret_get)")" "$([ -f "$MX_OPEN" ] && echo true || echo false)"
}

_bt_installed() { [ -x /usr/bin/bytetube ] || [ -x /etc/init.d/bytetube ]; }
_mx_installed() { [ -x "$MIHOMO_BIN" ] || [ -x /etc/init.d/mihomo ]; }

MT_ALL_GID="2a11c0de"
MT_ALL_RID="2a11c0d1"
_mt_all_on() {
	[ -f "$MAGITRICKLE_CONF" ] && awk -v g="$MT_ALL_GID" '
		/^- id:/ { v = $0; sub(/^- id:[ \t]*/, "", v); gsub(/["\047 \t\r]/, "", v); ing = (v == g); if (ing) found = 1; next }
		/^[^ -]/ { ing = 0 }
		ing && /^  enable:[ \t]*["\047]?false/ { goff = 1 }
		ing && /^    enable:/ { rany = 1; if ($0 ~ /^    enable:[ \t]*["\047]?true/) ron = 1 }
		END { exit !(found && !goff && (ron || !rany)) }' "$MAGITRICKLE_CONF"
}

_mx_secret_get() {
	local sec
	sec="$(sed -n 's/^secret:[[:space:]]*//p' "${1:-$MIHOMO_CONF}" 2>/dev/null | head -n1)"
	case "$sec" in
		\"*) sec="${sec#\"}"; sec="${sec%%\"*}" ;;
		\'*) sec="${sec#\'}"; sec="${sec%%\'*}" ;;
		*) sec="$(printf '%s' "$sec" | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//')" ;;
	esac
	printf '%s' "$sec"
}
_mx_api_port() {
	local ec port
	ec="$(sed -n 's/^external-controller:[[:space:]]*//p' "$MIHOMO_CONF" 2>/dev/null | head -n1 | sed 's/[[:space:]]*#.*$//; s/^["'\'']//; s/["'\''][[:space:]]*$//; s/[[:space:]]*$//')"
	port="${ec##*:}"
	case "$port" in ''|*[!0-9]*) port=9090 ;; esac
	echo "$port"
}
MX_OPEN="$ZM_STATE_DIR/mx.open"
_mx_api() {
	local ec host port sec
	ec="$(sed -n 's/^external-controller:[[:space:]]*//p' "$MIHOMO_CONF" 2>/dev/null | head -n1 | sed 's/[[:space:]]*#.*$//; s/^["'\'']//; s/["'\''][[:space:]]*$//; s/[[:space:]]*$//')"
	port="$(_mx_api_port)"
	host="${ec%:*}"; host="${host#[}"; host="${host%]}"
	case "$host" in ''|0.0.0.0|::|'*'|localhost) host=127.0.0.1 ;; esac
	case "$host" in *:*) host="[$host]" ;; esac
	sec="$(_mx_secret_get)"
	curl -s --connect-timeout 3 --max-time 8 ${sec:+-H "Authorization: Bearer $sec"} "http://$host:$port$1" 2>/dev/null
}

_mx_names_tail() {
	printf ',"hide_names":[%s],"exclude":"%s","all_names":[%s],"own_filter":"%s"}\n' \
		"$(_zm_json_lines "$MIXOMO_HIDE")" "$(esc "$(cat "$MIXOMO_EXCL" 2>/dev/null)")" \
		"$(_zm_json_lines "$MIHOMO_DIR/.zm_names_all")" "$(esc "$(head -n1 "$MIHOMO_DIR/.zm_filter_user" 2>/dev/null)")"
}

mixomo_proxies() {
	local j nf="$MIHOMO_DIR/.zm_names" af="$MIHOMO_DIR/.zm_names_all"
	[ -x /etc/init.d/mihomo ] || { echo '{"error":"Mixomo не установлен"}'; return 1; }
	pidof mihomo >/dev/null 2>&1 || { printf '{"error":"Mihomo не запущен"'; _mx_names_tail; return 0; }
	j="$(_mx_api /providers/proxies | tr '\n' ' ')"
	case "$j" in
		*'"providers"'*)
			if printf '%s' "$j" | jsonfilter -e '@.providers' >/dev/null 2>&1; then
				printf '%s' "$j" | jsonfilter -e '@.providers[@.vehicleType!="Compatible"].proxies[*].name' 2>/dev/null | grep -v '^$' > "$nf.new"
				if [ -s "$nf.new" ]; then
					mv -f "$nf.new" "$nf"
					cat "$af" "$nf" 2>/dev/null | awk 'NF && !s[$0]++' | tail -n 1000 > "$af.new" && mv -f "$af.new" "$af"
				fi
				rm -f "$nf.new"
			else
				printf '{"error":"Mihomo отдал неполный список серверов — нажмите «Обновить список»"'; _mx_names_tail; return 0
			fi
			;;
		'{'*'"message"'*) printf '{"error":"Mihomo не пустил к списку серверов — проверьте secret в конфигурации"'; _mx_names_tail; return 0 ;;
		*) j=null ;;
	esac
	printf '{"data":%s' "$j"; _mx_names_tail
}

MIXOMO_SUB_PREV="$MIHOMO_DIR/.zm_sub_prev"

MIXOMO_WARP_CONF="/root/WARP.conf"
MIXOMO_EXCL="$MIHOMO_DIR/.zm_exclude"
MIXOMO_HIDE="$MIHOMO_DIR/.zm_hide"
MIXOMO_WARP_PRIMARY="https://santa-atmo.ru/warp/warp.php"
MIXOMO_AWG_JC=4
MIXOMO_AWG_JMIN=40
MIXOMO_AWG_JMAX=70
MIXOMO_AWG_H1=1
MIXOMO_AWG_H2=2
MIXOMO_AWG_H3=3
MIXOMO_AWG_H4=4
MIXOMO_AWG_S1=0
MIXOMO_AWG_S2=0
MIXOMO_AWG_I1="<b 0xce000000010897a297ecc34cd6dd000044d0ec2e2e1ea2991f467ace4222129b5a098823784694b4897b9986ae0b7280135fa85e196d9ad980b150122129ce2a9379531b0fd3e871ca5fdb883c369832f730e272d7b8b74f393f9f0fa43f11e510ecb2219a52984410c204cf875585340c62238e14ad04dff382f2c200e0ee22fe743b9c6b8b043121c5710ec289f471c91ee414fca8b8be8419ae8ce7ffc53837f6ade262891895f3f4cecd31bc93ac5599e18e4f01b472362b8056c3172b513051f8322d1062997ef4a383b01706598d08d48c221d30e74c7ce000cdad36b706b1bf9b0607c32ec4b3203a4ee21ab64df336212b9758280803fcab14933b0e7ee1e04a7becce3e2633f4852585c567894a5f9efe9706a151b615856647e8b7dba69ab357b3982f554549bef9256111b2d67afde0b496f16962d4957ff654232aa9e845b61463908309cfd9de0a6abf5f425f577d7e5f6440652aa8da5f73588e82e9470f3b21b27b28c649506ae1a7f5f15b876f56abc4615f49911549b9bb39dd804fde182bd2dcec0c33bad9b138ca07d4a4a1650a2c2686acea05727e2a78962a840ae428f55627516e73c83dd8893b02358e81b524b4d99fda6df52b3a8d7a5291326e7ac9d773c5b43b8444554ef5aea104a738ed650aa979674bbed38da58ac29d87c29d387d80b526065baeb073ce65f075ccb56e47533aef357dceaa8293a523c5f6f790be90e4731123d3c6152a70576e90b4ab5bc5ead01576c68ab633ff7d36dcde2a0b2c68897e1acfc4d6483aaaeb635dd63c96b2b6a7a2bfe042f6aed82e5363aa850aace12ee3b1a93f30d8ab9537df483152a5527faca21efc9981b304f11fc95336f5b9637b174c5a0659e2b22e159a9fed4b8e93047371175b1d6d9cc8ab745f3b2281537d1c75fb9451871864efa5d184c38c185fd203de206751b92620f7c369e031d2041e152040920ac2c5ab5340bfc9d0561176abf10a147287ea90758575ac6a9f5ac9f390d0d5b23ee12af583383d994e22c0cf42383834bcd3ada1b3825a0664d8f3fb678261d57601ddf94a8a68a7c273a18c08aa99c7ad8c6c42eab67718843597ec9930457359dfdfbce024afc2dcf9348579a57d8d3490b2fa99f278f1c37d87dad9b221acd575192ffae1784f8e60ec7cee4068b6b988f0433d96d6a1b1865f4e155e9fe020279f434f3bf1bd117b717b92f6cd1cc9bea7d45978bcc3f24bda631a36910110a6ec06da35f8966c9279d130347594f13e9e07514fa370754d1424c0a1545c5070ef9fb2acd14233e8a50bfc5978b5bdf8bc1714731f798d21e2004117c61f2989dd44f0cf027b27d4019e81ed4b5c31db347c4a3a4d85048d7093cf16753d7b0d15e078f5c7a5205dc2f87e330a1f716738dce1c6180e9d02869b5546f1c4d2748f8c90d9693cba4e0079297d22fd61402dea32ff0eb69ebd65a5d0b687d87e3a8b2c42b648aa723c7c7daf37abcc4bb85caea2ee8f55bec20e913b3324ab8f5c3304f820d42ad1b9f2ffc1a3af9927136b4419e1e579ab4c2ae3c776d293d397d575df181e6cae0a4ada5d67ecea171cca3288d57c7bbdaee3befe745fb7d634f70386d873b90c4d6c6596bb65af68f9e5121e67ebf0d89d3c909ceedfb32ce9575a7758ff080724e1ab5d5f43074ecb53a479af21ed03d7b6899c36631c0166f9d47e5e1d4528a5d3d3f744029c4b1c190cbfbad06f5f83f7ad0429fa9a2719c56ffe3783460e166de2d8>"

AWG_SIP_I1="<b 0x494e56495445207369703a626f624062696c6f78692e636f6d205349502f322e300d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a4d61782d466f7277617264733a2037300d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e746163743a203c7369703a616c69636540706333332e61746c616e74612e636f6d3e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f7364700d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>"
AWG_SIP_I2="<b 0x5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>"

_mixomo_warp_best_endpoint() {
	local warp_tmp="$JOBS_DIR/mixomo_warp" pings count=0 ip
	pings="$warp_tmp/pings"
	mkdir -p "$warp_tmp"
	rm -f "$pings" "$warp_tmp/pick.info"
	for ip in $(_awg_rand_hosts 4 | head -n 60); do
		(
			trace_data=$(curl -s --connect-timeout 2 --max-time 4 -w "\n%{time_total}" -H "Host: trace.cloudflare.com" "http://${ip}/cdn-cgi/trace" 2>/dev/null)
			[ -n "$trace_data" ] || exit 0
			colo=$(echo "$trace_data" | awk -F'=' '$1=="colo"{print $2}')
			[ -n "$colo" ] || exit 0
			_st_warp_is_ru "$colo" && exit 0
			ping_ms=$(echo "$trace_data" | tail -n1 | awk '{printf "%d", $1 * 1000}')
			[ -n "$ping_ms" ] && echo "$ping_ms $ip $colo" >> "$pings"
		) &
		count=$((count + 1))
		[ $((count % 20)) -eq 0 ] && wait
	done
	wait
	if [ -s "$pings" ]; then
		sort -n "$pings" | head -n1 | awk '{ print $2 ":4500" }'
		sort -n "$pings" | head -n1 | awk '{ print "   ближайший зарубежный узел: " $3 ", " $1 " мс (оценка по HTTP, без туннеля)" }' > "$warp_tmp/pick.info"
	else
		echo "engage.cloudflareclient.com:4500"
	fi
	rm -f "$pings"
}

BYEDPI_REPO="DPITrickster/ByeDPI-OpenWrt"

_fk_dash_info() {
	local sec="" x t v
	[ -f /etc/config/netshift ] || return 0
	for x in main $(uci -q show netshift 2>/dev/null | sed -n 's/^netshift\.\([A-Za-z0-9_]*\)=section$/\1/p'); do
		case "$(uci -q get "netshift.$x.connection_type")" in proxy|vpn) sec="$x"; break ;; esac
	done
	[ -n "$sec" ] || return 0
	if [ "$(uci -q get "netshift.$sec.connection_type")" = vpn ]; then
		v="$(uci -q get "netshift.$sec.interface")"
		[ -n "$v" ] && echo "через $v"
		return 0
	fi
	t="$(uci -q get "netshift.$sec.proxy_config_type")"
	case "$t" in
		subscription)
			v="$(jsonfilter -i "$ZM_STATE_DIR/fk.sub.$sec.json" -e '@.title' 2>/dev/null | tr -d '\000-\037' | cut -c 1-40)"
			echo "${v:-по подписке}" ;;
		outbound) echo "свой конфиг" ;;
		*) echo "свои серверы" ;;
	esac
}
_fk_dash_secs() {
	local f="$JOBS_DIR/fk.dash" now t=""
	now="$(date +%s)"
	[ -f "$f" ] && read -r t < "$f"
	case "$t" in ''|*[!0-9]*) t=0 ;; esac
	if [ $((now - t)) -ge 20 ] || [ "$now" -lt "$t" ]; then
		mkdir -p "$JOBS_DIR"
		{ echo "$now"; _fk_uc secdash 2>/dev/null | grep "$(printf '\t')"; } > "$f.$$" && mv -f "$f.$$" "$f"
	fi
	tail -n +2 "$f" 2>/dev/null
}
_fk_dash_sum() {
	_fk_dash_secs | awk -F'\t' '$2 != "" { n++; nm = nm (n > 1 ? ", " : "") $2; if ($1 == "bad" || $1 == "stopped" || $1 == "direct") { b++; bn = bn (b > 1 ? ", " : "") $2 } }
		END {
			if (!n) exit
			if (!b) { if (n > 1) print 1 "\t" (n <= 3 ? "через " nm : n " " (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? "секции" : "секций")); exit }
			w = (b > 1 ? "не отвечают " : "не отвечает ") bn
			if (b == n) print 2 "\t" (n == 1 ? "через " bn " — не отвечает" : w); else print 3 "\t" (n - b) " из " n " · " w
		}'
}
_tg_dash_info() {
	local l=""
	[ -f /etc/init.d/tg-ws-proxy ] && l="Go"
	[ -f "$TG_INIT_GO" ] && l="${l:+$l, }SOCKS5"
	[ -f "$TG_INIT_RS" ] && l="${l:+$l, }Rust"
	[ -x /etc/init.d/tgws ] && l="${l:+$l, }sTGWS"
	echo "$l"
}
health() {
	local zr=0 zr2=0 bt=0 tg=0 mx=0 doh=0 hs=0 inst=0 bad=0 out=""
	if [ -f /etc/init.d/zapret ]; then zr=2; pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1 && zr=1; fi
	if [ -f /etc/init.d/zapret2 ]; then zr2=2; /etc/init.d/zapret2 status >/dev/null 2>&1 && zr2=1; fi
	if [ -x /usr/bin/bytetube ]; then
		bt=2
		out=$(/usr/bin/bytetube status 2>/dev/null)
		case "$out" in *'"enabled":true'*'"byedpi":true'*'"hev":true'*) bt=1 ;; esac
	fi
	if [ -f /etc/init.d/tg-ws-proxy ]; then inst=1; pidof tg-ws-proxy >/dev/null 2>&1 || bad=1; fi
	if [ -f "$TG_INIT_GO" ]; then inst=1; pidof tg-ws-proxy-go >/dev/null 2>&1 || bad=1; fi
	if [ -f "$TG_INIT_RS" ]; then inst=1; pidof tg-ws-proxy-rs >/dev/null 2>&1 || bad=1; fi
	if [ -x /etc/init.d/tgws ]; then inst=1; [ -n "$(tgws status 2>/dev/null)" ] || bad=1; fi
	if [ "$inst" = "1" ]; then tg=1; [ "$bad" = "1" ] && tg=2; fi
	if [ -x "$MIHOMO_BIN" ]; then
		mx=1
		pidof mihomo >/dev/null 2>&1 || mx=2
		if [ -x /etc/init.d/magitrickle ]; then /etc/init.d/magitrickle status >/dev/null 2>&1 || mx=2; fi
		if [ -x /etc/init.d/hev-socks5-tunnel ]; then /etc/init.d/hev-socks5-tunnel status >/dev/null 2>&1 || mx=2; fi
	fi
	if [ "$PKG" = "apk" ]; then apk info -e https-dns-proxy >/dev/null 2>&1 && doh=2
	elif [ -d /usr/lib/opkg/info ]; then { [ -f /usr/lib/opkg/info/https-dns-proxy.control ] || [ -f /usr/lib/opkg/info/https-dns-proxy.list ]; } && doh=2
	else _pkg_is_installed https-dns-proxy && doh=2; fi
	if [ "$doh" = "2" ]; then pidof https-dns-proxy >/dev/null 2>&1 && doh=1; fi
	out=$(hosts_status 2>/dev/null)
	case "$out" in *'"enabled":true'*|*'"geohide":"'[a-z]*) hs=1 ;; esac
	local sr=0 w
	if _st_installed; then
		if [ -f /etc/zm-steer/stopped ] || ! grep -qx 'steer-spec' /etc/zm-steer/owned 2>/dev/null || [ "$(_st_exit)" = none ]; then
			sr=5
		else
			sr=2
			if stl_running; then
				if [ "$(_st_exit)" = vpn ]; then
					_st_vpn_dev >/dev/null && { _st_vpn_live; [ $? -ne 1 ] && sr=1; }
				elif [ "$(_st_exit)" = iface ]; then
					_zm_tun_up "$(_st_main_iface)" && sr=1
				else
					for w in $(awk '{print $1}' /etc/zm-steer/warp.up 2>/dev/null) zmwarp; do
						[ -d "/sys/class/net/$w" ] && { sr=1; break; }
					done
				fi
			fi
		fi
	fi
	local sx="" sf=false
	if [ "$sr" = 1 ] && stl_state "$(_st_exit)" && [ "$STL_FAILED" = true ]; then sr=2; sf=true; fi
	if _st_installed; then sx="$(_st_exit)"; [ "$sx" = warp ] && _st_warp_own && sx=own; [ "$sx" = own ] && _st_warp_ext && sx="iface:$(_st_ext_if)"; [ "$sx" = iface ] && sx="iface:$(_st_main_iface)"; fi
	local fw=false v6=false
	_fw4_offload_on && [ -f "$FW4_TPL" ] && [ ! -f "$FT_ZAPRET_OFF" ] && { [ -x /etc/init.d/zapret ] || [ -x /etc/init.d/zapret2 ]; } && [ "$(_flow_offloading_fix_applied)" = false ] && fw=true
	local fws=false
	_fw4_offload_on && [ -f "$FW4_TPL" ] && stl_present && [ ! -f "$FT_STEER_OFF" ] && ! _ft_steer_applied && fws=true
	[ -f "$CONF" ] && [ "$(_ipv6_enabled_in_zapret)" = false ] && [ "$(_zm_v6_cached)" = live ] && v6=true
	local d_zr="$zr" d_zr2="$zr2" d_bt="$bt" d_tg="$tg" d_mx="$mx" d_doh="$doh" d_sr="$sr" d_fk d_awg d_term=0 awgj fkh
	[ "$zr" = 2 ] && d_zr=4
	[ "$zr2" = 2 ] && d_zr2=4
	if [ "$bt" = 2 ]; then case "$(/usr/bin/bytetube status 2>/dev/null)" in *'"enabled":true'*) ;; *) d_bt=4 ;; esac; fi
	[ "$tg" = 2 ] && ! ls /etc/rc.d/S*tg-ws-proxy* >/dev/null 2>&1 && ! ls /etc/rc.d/S*tgws >/dev/null 2>&1 && d_tg=4
	[ "$mx" = 2 ] && ! ls /etc/rc.d/S*mihomo >/dev/null 2>&1 && d_mx=4
	if [ "$doh" = 2 ]; then ls /etc/rc.d/S*https-dns-proxy >/dev/null 2>&1 || d_doh=4; fi
	[ "$sr" = 5 ] && d_sr=4
	local fki="" fks
	fkh="$(_fk_health)"
	if [ "$fkh" = 1 ] || [ "$fkh" = 2 ]; then
		fki="$(_fk_dash_info)"
		if [ "$fkh" = 1 ] && fks="$(_fk_dash_sum)" && [ -n "$fks" ]; then
			fkh="${fks%%	*}"
			fki="${fks#*	}"
		fi
	fi
	d_fk="$fkh"; [ "$d_fk" = 5 ] && d_fk=4
	awgj="$(_awg_health)"; d_awg="${awgj%%,*}"
	case "$awgj" in *'"awg_total":0') [ "$d_awg" = 1 ] && d_awg=4; [ "$d_awg" = 3 ] && d_awg=2 ;; esac
	if _term_installed; then
		if _term_running; then d_term=1; elif _term_enabled; then d_term=2; else d_term=4; fi
	fi
	local d_ab=0 tss=0
	if _ab_on; then if _ab_applied; then d_ab=1; else d_ab=2; fi; fi
	if _tsc_installed; then
		if _tsc_running; then if [ "$(cat "$TSC_STATE" 2>/dev/null)" = Running ]; then tss=1; else tss=3; fi
		elif _tsc_enabled; then tss=2; else tss=5; fi
	fi
	printf '{"dots":{"zapret":%s,"zapret2":%s,"bytetube":%s,"tg":%s,"mixomo":%s,"doh":%s,"hosts":%s,"adblock":%s,"steer":%s,"forkop":%s,"awg":%s,"term":%s,"ts":%s},' \
		"$d_zr" "$d_zr2" "$d_bt" "$d_tg" "$d_mx" "$d_doh" "$hs" "$d_ab" "$d_sr" "${d_fk:-0}" "${d_awg:-0}" "$d_term" "$(_tsc_dot)"
	printf '"zapret":%s,"zapret2":%s,"bytetube":%s,"tg":%s,"mixomo":%s,"doh":%s,"hosts":%s,"steer":%s,"steer_off":%s,"steer_fail":%s,"steer_exit":"%s","awg":%s,"forkop":%s,"flow_warn":%s,"steer_flow_warn":%s,"ipv6_warn":%s,"gh_warn":%s,"reboot_hint":"%s","nav_hidden":"%s","pages_off":"%s","tsc":%s,"htop":%s,"fk_info":"%s","tg_info":"%s","oom":%s,"zmw":%s}\n' \
		"$zr" "$zr2" "$bt" "$tg" "$mx" "$doh" "$hs" "$sr" \
		"$([ -f /etc/zm-steer/stopped ] && echo true || echo false)" "$sf" "$sx" "$awgj" "$fkh" "$fw" "$fws" "$v6" "$(_zm_ghp_warn && echo true || echo false)" "$(esc "$(_zm_reboot_hint_get)")" "$(esc "$(ui_nav_get)")" "$(esc "$(_zpg_offlist)")" "$tss" "$([ -x /usr/bin/htop ] && echo true || echo false)" \
		"$(esc "$fki")" "$([ "$tg" != 0 ] && esc "$(_tg_dash_info)")" "$(_zm_oom_json)" "$(_zmw_port || echo 0)"
}

VERSIONS_CACHE="$ZM_STATE_DIR/versions.json"

_ver_norm() { printf '%s' "$1" | sed 's/^[vV]//; s/-r[0-9]*$//; s/[[:space:]]//g'; }
_ver_gh_latest() {
	curl -Ls --connect-timeout 5 --max-time 10 -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" 2>/dev/null |
		sed -n 's#.*/tag/##p' | grep -oE '[0-9]+(\.[0-9]+)+' | head -n1
}

VER_MODE_FILE="$ZM_STATE_DIR/ver.mode"
VER_CRON_TAG="# zm-versions"
_ver_mode() { case "$(cat "$VER_MODE_FILE" 2>/dev/null)" in open) echo open ;; button) echo button ;; *) echo day ;; esac; }
_ver_bg() { [ ! -f "$ZM_STATE_DIR/watch.off" ]; }
VER_EVERY_FILE="$ZM_STATE_DIR/ver.every"
VER_TIME_FILE="$ZM_STATE_DIR/ver.time"
AU_WHEN_FILE="$ZM_STATE_DIR/au.when"
_ver_every() { case "$(cat "$VER_EVERY_FILE" 2>/dev/null)" in 2) echo 2 ;; 6) echo 6 ;; 12) echo 12 ;; *) echo 24 ;; esac; }
_ver_time() { _ver_hm | awk '{ printf "%02d:%02d\n", $1, $2 }'; }
_au_when() { [ "$(cat "$AU_WHEN_FILE" 2>/dev/null)" = now ] && echo now || echo night; }

AU_LOG="$ZM_STATE_DIR/autoupd.log"
AU_LOCK="$JOBS_DIR/autoupd.lock"
_au_live() { [ -d "$AU_LOCK" ] && kill -0 "$(cat "$AU_LOCK/pid" 2>/dev/null)" 2>/dev/null; }
AU_SKIP="$ZM_STATE_DIR/autoupd.skip"
autoupd() {
	local j
	case "$1" in
		status) ;;
		panel_on|comp_on) mkdir -p "$ZM_STATE_DIR"; : > "$ZM_STATE_DIR/au.${1%_on}" ;;
		panel_off|comp_off) rm -f "$ZM_STATE_DIR/au.${1%_off}" ;;
		run)
			_au_live && { echo '{"error":"обновление уже идёт"}'; return 1; }
			if j="$(_zm_busy_job)"; then printf '{"error":"%s"}\n' "$(esc "идёт операция «$j» — дождитесь её окончания")"; return 1; fi
			_au_spawn now
			sleep 1 ;;
		clear) _au_live && { echo '{"error":"дождитесь окончания обновления"}'; return 1; }; rm -f "$AU_LOG" ;;
		*) echo '{"error":"неизвестное действие"}'; return 1 ;;
	esac
	autoupd_status
}

_zm_dnsmasq_variant() {
	local p
	for p in dnsmasq-full dnsmasq-dhcpv6 dnsmasq; do _pkg_is_installed "$p" && { echo "$p"; return 0; }; done
	return 1
}

_zm_pkg_got() {
	local f
	for f in "$2/$1"_*.ipk "$2/$1"-[0-9]*.apk; do [ -s "$f" ] && { echo "$f"; return 0; }; done
	return 1
}

_zm_pkg_get() {
	mkdir -p "$2"
	if [ "$PKG" = apk ]; then _zm_run 120 apk fetch -o "$2" "$1" >/dev/null 2>&1
	else ( cd "$2" && _zm_run 120 opkg download "$1" ) >/dev/null 2>&1; fi
	_zm_pkg_got "$1" "$2" >/dev/null
}

_zm_pkg_deps() {
	if [ "$PKG" = apk ]; then
		apk info -R "$1" 2>/dev/null | grep -v 'depends on:$' | sed 's/[<>=~].*//; s/[[:space:]]//g' | grep -v '^$'
	else
		opkg info "$1" 2>/dev/null | sed -n 's/^Depends: //p' | head -n 1 | tr ',' '\n' | sed 's/([^)]*)//g; s/^[[:space:]]*//; s/[[:space:]].*$//' | grep -v '^$'
	fi
}

_zm_resolv_upstream() {
	rm -f /tmp/resolv.conf
	if grep -qs '^nameserver' /tmp/resolv.conf.d/resolv.conf.auto; then
		grep '^nameserver' /tmp/resolv.conf.d/resolv.conf.auto > /tmp/resolv.conf
	else
		printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /tmp/resolv.conf
	fi
}

_zm_dhcp_back() {
	[ -s "$1/dhcp" ] && cat "$1/dhcp" > /etc/config/dhcp
	[ -f "$1/had-opkg" ] || rm -f /etc/config/dhcp-opkg
	[ -f "$1/had-apknew" ] || rm -f /etc/config/dhcp.apk-new
	return 0
}

_zm_dnsmasq_start() {
	/etc/init.d/dnsmasq enable >/dev/null 2>&1
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	sleep 2
	pidof dnsmasq >/dev/null 2>&1
}

do_bytetube_uninstall() {
	echo "==> Останавливаем ByeTube"
	[ -x /usr/bin/bytetube ] && /usr/bin/bytetube test stop >/dev/null 2>&1
	_zm_svc_off bytetube
	echo "==> Снимаем правила файрвола и DNS ByeTube"
	if [ -x /usr/libexec/bytetube/net.sh ]; then
		/usr/libexec/bytetube/net.sh purge >/dev/null 2>&1
		. /usr/libexec/bytetube/common.sh
		for d in $(dnsmasq_confdirs 2>/dev/null || dnsmasq_confdir); do rm -f "$d/bytetube.conf"; done
	fi
	echo "==> Удаляем файлы и настройки ByeTube"
	local rc=0
	_zm_wipe /etc/config/bytetube /etc/init.d/bytetube /etc/rc.d/*bytetube /etc/hotplug.d/firewall/90-bytetube \
		/usr/bin/bytetube /usr/libexec/bytetube /usr/share/bytetube \
		/usr/share/nftables.d/chain-pre/forward/50-bytetube.nft \
		/var/etc/bytetube /var/run/bytetube.started /tmp/bytetube-test \
		/etc/bytetube /lib/upgrade/keep.d/bytetube || rc=1
	_zm_cron_drop 'bytetube' "ByeTube"
	/etc/init.d/dnsmasq restart >/dev/null 2>&1
	/etc/init.d/firewall reload >/dev/null 2>&1
	rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache
	/etc/init.d/rpcd reload >/dev/null 2>&1
	[ "$ZM_NO_AFTER" = 1 ] && return "$rc"
	_zm_after_remove "ByeTube"
	_zm_rm_done "$rc" "ByeTube"
}

_doh_file="/etc/config/https-dns-proxy"

_doh_steer_active() { grep -qx 'steer-spec' /etc/zm-steer/owned 2>/dev/null && [ ! -f /etc/zm-steer/stopped ]; }

DOH_FORCE_MODE_FILE="/opt/zapret-manager-luci/doh_force"
_doh_force_mode() {
	local m
	m="$(cat "$DOH_FORCE_MODE_FILE" 2>/dev/null)"
	case "$m" in off) echo off ;; *) echo auto ;; esac
}
_doh_force_want() {
	if [ "$(_doh_force_mode)" = off ]; then echo 0; else echo 1; fi
}
_doh_main_text() {
	local n
	echo "config main 'config'"
	echo "	option dnsmasq_config_update '*'"
	echo "	option force_dns '$1'"
	echo "	option notrack_dns '1'"
	echo "	list force_dns_port '53'"
	echo "	list force_dns_port '853'"
	for n in $(_zm_lan_nets); do echo "	list force_dns_src_interface '$n'"; done
	echo "	option procd_trigger_wan6 '0'"
	echo "	option heartbeat_domain 'heartbeat.mossdef.org'"
	echo "	option heartbeat_sleep_timeout '10'"
	echo "	option heartbeat_wait_timeout '10'"
	echo "	option user 'nobody'"
	echo "	option group 'nogroup'"
	echo "	option listen_addr '127.0.0.1'"
	echo "	option force_ip_family 'auto'"
	# Подсказка браузерам — вместе с перехватом, если её не выключили в «Браузеры и российские сайты»
	n="$1"; [ "$(_kv_last "$DN_FILE" canary_off)" = 1 ] && n=0
	echo "	option canary_domains_icloud '$n'"
	echo "	option canary_domains_mozilla '$n'"
}
_doh_other_sections() {
	awk '/^config[ \t]/ { skip = ($2 == "main") } !skip' "$_doh_file" 2>/dev/null | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' | sed '/./,$!d'
}
_doh_force_apply() {
	local want new cur rest
	[ -f "$_doh_file" ] || return 0
	want="$(_doh_force_want)"
	new="$(_doh_main_text "$want")"
	cur="$(awk '/^config[ \t]/ { on = ($2 == "main") } on' "$_doh_file" | sed '/^[[:space:]]*$/d')"
	[ "$cur" = "$new" ] && return 0
	rest="$(_doh_other_sections)"
	{ printf '%s\n' "$new"; [ -n "$rest" ] && printf '\n%s\n' "$rest"; } > "$_doh_file.zmtmp" && mv -f "$_doh_file.zmtmp" "$_doh_file"
	/etc/init.d/https-dns-proxy running >/dev/null 2>&1 && /etc/init.d/https-dns-proxy restart >/dev/null 2>&1
	[ "$want" = 0 ] && _dn_canary_fix
	return 0
}

_dnsm_present() { [ -x /usr/bin/dns-manager ] || [ -x /usr/libexec/rpcd/dns_manager ]; }

ZSKIP_PAT="zm_vpn* zmv* zm_warp* zmwarp* awg* wg* tun* tailscale* utun* mihomo* Meta"
_zm_zskip_on() { local v; { read -r v < "$ZSKIP_FILE"; } 2>/dev/null; [ "$v" = on ]; }
_zm_zskip_need() { [ -x /etc/init.d/zapret ] || [ -x /etc/init.d/zapret2 ]; }
_zm_zskip_mark() {
	local m=0 v f
	for f in /etc/config/zapret /etc/config/zapret2; do
		for v in $(sed -n "s/^[[:space:]]*option[[:space:]][[:space:]]*DESYNC_MARK[[:space:]][[:space:]]*'\{0,1\}\(0x[0-9a-fA-F]\{1,8\}\)'\{0,1\}[[:space:]]*$/\1/p" "$f" 2>/dev/null); do
			m=$((m | v))
		done
	done
	[ "$m" -gt 0 ] 2>/dev/null || m=$((0x40000000))
	printf '0x%08x\n' "$m"
}
_zm_zskip_ifs() {
	local wan p n pats
	set -f
	wan="$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
	pats=""
	for p in $ZSKIP_PAT; do case "$wan" in $p) ;; *) pats="$pats $p" ;; esac; done
	{
		for p in $pats; do echo "$p"; done
		ip -d link show 2>/dev/null | awk '/^[0-9]+: / { n = $2; sub(/:$/, "", n); sub(/@.*/, "", n); next } n != "" && $1 ~ /^(tun|wireguard|amneziawg)$/ { print n; n = "" }'
	} | while read -r n; do
		[ -n "$n" ] && [ "$n" != "$wan" ] || continue
		case "$n" in *[!A-Za-z0-9_.*-]*) continue ;; esac
		for p in $pats; do case "$n" in $p) [ "$n" != "$p" ] && continue 2 ;; esac; done
		echo "$n"
	done | awk '!s[$0]++'
	set +f
}
_zm_zskip_cgs() {
	local n
	for n in $ZSKIP_SVC; do [ -d "/sys/fs/cgroup/services/$n" ] && echo "$n"; done
}
_zm_zskip_render() {
	local m n
	set -f
	m="$(_zm_zskip_mark)"
	echo "# Zapret Manager: Zapret и Zapret2 не трогают трафик, который уходит в туннели VPN"
	echo "table inet zm_zskip"
	echo "delete table inet zm_zskip"
	echo "table inet zm_zskip {"
	echo "	chain post {"
	echo "		type filter hook postrouting priority 50; policy accept;"
	for n in $(_zm_zskip_ifs); do echo "		oifname \"$n\" meta mark set meta mark | $m"; done
	echo "	}"
	echo "}"
	set +f
}
_zm_zskip_render_cg() {
	local m n
	m="$(_zm_zskip_mark)"
	echo "table inet zm_zskip_cg"
	echo "delete table inet zm_zskip_cg"
	echo "table inet zm_zskip_cg {"
	echo "	chain out {"
	echo "		type filter hook output priority 50; policy accept;"
	for n; do
		echo "		# $n $(ls -id "/sys/fs/cgroup/services/$n" 2>/dev/null | awk '{ print $1 }')"
		echo "		socket cgroupv2 level 2 \"services/$n\" meta mark set meta mark | $m"
	done
	echo "	}"
	echo "}"
}
_zm_zskip_drop() { command -v nft >/dev/null 2>&1 && nft list table inet "$1" >/dev/null 2>&1 && nft delete table inet "$1" >/dev/null 2>&1; return 0; }
_zm_zskip_sync() {
	local t c
	if _zm_zskip_on && _zm_zskip_need && command -v nft >/dev/null 2>&1 && [ -d /usr/share/nftables.d ]; then
		mkdir -p "${ZSKIP_NFT%/*}" "${ZSKIP_FP%/*}" || return 1
		t="$ZSKIP_NFT.zm.$$"
		_zm_zskip_render > "$t" || { rm -f "$t"; return 1; }
		if cmp -s "$t" "$ZSKIP_NFT" && nft list table inet zm_zskip >/dev/null 2>&1; then
			rm -f "$t"
		elif nft -c -f "$t" >/dev/null 2>&1; then
			mv -f "$t" "$ZSKIP_NFT" && chmod 0644 "$ZSKIP_NFT" && nft -f "$ZSKIP_NFT" >/dev/null 2>&1 || return 1
		else
			rm -f "$t"; return 1
		fi
		c="$(_zm_zskip_cgs)"
		t="$ZSKIP_FP.cg.$$"
		if [ -z "$c" ]; then
			rm -f "$ZSKIP_FP.cg"; _zm_zskip_drop zm_zskip_cg
		elif ! _zm_zskip_render_cg $c > "$t"; then
			:
		elif cmp -s "$t" "$ZSKIP_FP.cg" && nft list table inet zm_zskip_cg >/dev/null 2>&1; then
			:
		elif nft -c -f "$t" >/dev/null 2>&1 && nft -f "$t" >/dev/null 2>&1; then
			mv -f "$t" "$ZSKIP_FP.cg"
		else
			rm -f "$ZSKIP_FP.cg"; _zm_zskip_drop zm_zskip_cg
		fi
		rm -f "$t"
		_zm_zskip_fp > "$ZSKIP_FP"
	elif [ -f "$ZSKIP_NFT" ] || [ -f "$ZSKIP_FP" ] || [ -f "$ZSKIP_FP.cg" ]; then
		rm -f "$ZSKIP_NFT" "$ZSKIP_FP" "$ZSKIP_FP.cg"
		_zm_zskip_drop zm_zskip
		_zm_zskip_drop zm_zskip_cg
	fi
	return 0
}

_doh_provider_of() {
	case "$1" in
		https://cloudflare-dns.com/*|https://1.1.1.1/*|https://1.0.0.1/*) echo cloudflare ;;
		https://dns.google/*|https://8.8.8.8/*|https://8.8.4.4/*) echo google ;;
		https://security.cloudflare-dns.com/*) echo cloudflare_sec ;;
		https://family.cloudflare-dns.com/*) echo cloudflare_fam ;;
		https://dns.quad9.net/*) echo quad9 ;;
		https://dns10.quad9.net/*) echo quad9_open ;;
		https://xbox-dns.ru/*) echo xbox ;;
		https://dns.comss.one/*) echo comss ;;
		https://dns.dns-ai.ru/*) echo dnsai ;;
		https://sync.bezmezhau.com/*) echo bezmezhau ;;
		https://common.dot.dns.yandex.net/*) echo yandex ;;
		https://family.dot.dns.yandex.net/*) echo yandex_family ;;
		https://safe.dot.dns.yandex.net/*) echo yandex_safe ;;
		https://eu.geohide.ru/*) echo geohide_eu ;;
		https://us.geohide.ru/*) echo geohide_us ;;
		https://dns.malw.link/*) echo malw ;;
		https://d.webshiftvpn.ru/*) echo webshift ;;
		https://dns.dagami.ru/*) echo dagami ;;
		https://dns.magicdns.ru/*|https://api.magicdns.ru/*) echo magicdns ;;
		https://tamaev-gifts.xyz/*) echo tamaev ;;
		https://dns.zombiez.ru/*) echo zombiez ;;
		https://dns.wlrus.cfd/*) echo wlrus ;;
		https://api.magicinfo.art/*) echo magicinfo ;;
		https://w.quic.best/*) echo quicbest ;;
		https://freedns.controld.com/p0) echo controld ;;
		https://freedns.controld.com/p1) echo controld_sec ;;
		https://freedns.controld.com/family) echo controld_fam ;;
		https://unfiltered.joindns4.eu/*) echo dns4eu ;;
		https://protective.joindns4.eu/*) echo dns4eu_sec ;;
		https://child.joindns4.eu/*) echo dns4eu_fam ;;
		*) echo "" ;;
	esac
}

_hosts_extra() {
	[ -s "$HOSTS_FILE" ] || { echo false; return; }
	awk -v me="$(uci -q get system.@system[0].hostname 2>/dev/null)" '
		BEGIN { split("localhost localhost.localdomain ip6-localhost ip6-loopback ip6-localnet ip6-mcastprefix ip6-allnodes ip6-allrouters ip6-allhosts broadcasthost", a, " "); for (i in a) ok[a[i]] = 1; r = "false" }
		{ sub(/#.*/, ""); if (NF < 2) next
		  for (i = 2; i <= NF; i++) { n = tolower($i); if (n in ok || n == tolower(me) || n ~ /\.lan$/) continue; r = "true"; exit } }
		END { print r }' "$HOSTS_FILE" 2>/dev/null || echo false
}

doh_status() {
	local installed="false" current="" running=false force=false list="" sep="" i url port prov n=0 provs=""
	_doh_legacy_fix
	_doh_pkg && installed="true"
	[ "$installed" = true ] && _doh_boot_fill
	[ "$installed" = true ] && _doh_fo_on && ! grep -qF "$DOH_FO_CRON" "$CRON_FILE" 2>/dev/null && _doh_fo_cron on
	if [ -f "$_doh_file" ]; then
		i=0
		while url="$(uci -q get "https-dns-proxy.@https-dns-proxy[$i].resolver_url")"; do
			port="$(uci -q get "https-dns-proxy.@https-dns-proxy[$i].listen_port")"
			[ -n "$port" ] || port=$((5053 + i))
			prov="$(_doh_provider_of "$url")"
			list="$list$sep{\"url\":\"$(esc "$url")\",\"port\":\"$(esc "$port")\",\"provider\":\"$prov\",\"bootstrap\":\"$(esc "$(uci -q get "https-dns-proxy.@https-dns-proxy[$i].bootstrap_dns")")\",\"boot_auto\":\"$(esc "$(_doh_boot_auto "$prov" "$url")")\",\"boot_dead\":$(grep -qxF "$url" "$DOH_BOOT_SKIP" 2>/dev/null && echo true || echo false)}"
			sep=","; n=$((n + 1)); provs="$prov"
			i=$((i + 1))
			[ "$i" -gt 16 ] && break
		done
		[ "$n" = 1 ] && current="$provs"
		if [ "$(uci -q get https-dns-proxy.config.force_dns)" != "0" ]; then force=true
		elif [ "$(uci -q get https-dns-proxy.config.canary_domains_mozilla)" != "0" ] && ! _dnsm_present; then _doh_force_apply; fi
	fi
	/etc/init.d/https-dns-proxy running >/dev/null 2>&1 && running=true
	[ -f "$DOH_STOP" ] && ! _doh_pkg && rm -f "$DOH_STOP"
	_dn_canary_fix
	printf '{"name":"%s","installed":%s,"stopped":%s,"current":"%s","running":%s,"force_dns":%s,"force_mode":"%s","resolvers":[%s],"steer_active":%s,"steer_installed":%s,"forkozz":%s,"fk_name":"%s","bootstrap_custom":"%s","luci_boots":[%s],"hosts_extra":%s,"failover":%s,"dnsm":%s,"net":%s,"own":[%s],"zapret_doh":"%s"}\n' \
		"$(c="$(_doh_cur_id)"; [ -n "$c" ] && esc "$(_doh_name "$c")")" "$installed" "$([ -f "$DOH_STOP" ] && echo true || echo false)" "$(esc "$current")" "$running" "$force" "$(_doh_force_mode)" "$list" \
		"$(_doh_steer_active && echo true || echo false)" \
		"$(grep -qx 'engine' /etc/zm-steer/owned 2>/dev/null && stl_present && echo true || echo false)" \
		"$(_fk_installed && echo true || echo false)" "$(_fk_name)" "$(esc "$(cat "$DOH_BOOT_FILE" 2>/dev/null)")" "$(_doh_luci_list | awk -F'\t' '{ printf "%s{\"t\":\"%s\",\"b\":\"%s\"}", (NR > 1 ? "," : ""), $1, $2 }')" "$(_hosts_extra)" "$(_doh_fo_json)" \
		"$(_dnsm_present && echo true || echo false)" "$(_dn_json)" "$(_doh_own_json)" \
		"$(if [ ! -x /etc/init.d/zapret ] || [ ! -f "$CONF" ]; then echo none; elif [ -f "$ZO_DOH_FLAG" ]; then echo on; else echo off; fi)"
}

DOH_BOOT_FILE="/opt/zapret-manager-luci/doh_bootstrap"
DOH_BOOT_DEF="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4"
DOH_LUCI_PROV="/usr/share/https-dns-proxy/providers"

DOH_LUCI_JSON="/usr/share/https-dns-proxy/providers.json"
_doh_luci_list() {
	local c=/tmp/zm-doh-luciprov.tsv src
	if [ -s "$DOH_LUCI_JSON" ]; then src="$DOH_LUCI_JSON"
	elif ls "$DOH_LUCI_PROV"/*.json >/dev/null 2>&1; then src="$DOH_LUCI_PROV"
	else return 0; fi
	if [ -f "$c" ] && [ "$c" -nt "$src" ] && [ -n "$(find "$c" -mmin -60 2>/dev/null)" ]; then cat "$c"; return 0; fi
	if [ "$src" = "$DOH_LUCI_JSON" ]; then set -- "$src"; else set -- "$src"/*.json; fi
	awk '
		function flush() {
			gsub(/[ \t]/, "", b)
			if (t ~ /^https:\/\/[^ \t\\]*$/ && b ~ /^[0-9A-Fa-f.:,]+$/) print t "\t" b
			t = ""; b = ""
		}
		FNR == 1 { d = 0; key = ""; want = 0 }
		{
			ln = $0; n = length(ln); i = 1
			while (i <= n) {
				c = substr(ln, i, 1)
				if (c == "\"") {
					r = substr(ln, i + 1)
					if (!match(r, /^([^"\\]|\\.)*"/)) break
					v = substr(r, 1, RLENGTH - 1); i += RLENGTH + 1
					if (d != 1) continue
					if (want) { if (key == "template") t = v; else b = v; want = 0; key = ""; continue }
					r = substr(ln, i)
					if (match(r, /^[ \t\r]*:/)) { key = v; i += RLENGTH; want = (key == "template" || key == "bootstrap_dns") }
					continue
				}
				if (c == "{") { d++; if (d == 1) { t = ""; b = "" } }
				else if (c == "}") { d--; if (d == 0) flush() }
				if (c != " " && c != "\t" && c != "\r") want = 0
				i++
			}
		}
	' "$@" 2>/dev/null > "$c.$$" && mv -f "$c.$$" "$c"
	cat "$c" 2>/dev/null
}

DOH_BOOT_449="1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001,8.8.8.8,8.8.4.4,2001:4860:4860::8888,2001:4860:4860::8844"
DOH_BOOT_SKIP="/tmp/zm-doh-bootfill.skip"
DOH_BOOT_KEEP="/tmp/zm-doh-bootfill.keep"

_doh_url_of() {
	case "$1" in
		cloudflare)    echo "https://cloudflare-dns.com/dns-query" ;;
		google)        echo "https://dns.google/dns-query" ;;
		cloudflare_sec) echo "https://security.cloudflare-dns.com/dns-query" ;;
		cloudflare_fam) echo "https://family.cloudflare-dns.com/dns-query" ;;
		quad9)         echo "https://dns.quad9.net/dns-query" ;;
		quad9_open)    echo "https://dns10.quad9.net/dns-query" ;;
		yandex)        echo "https://common.dot.dns.yandex.net/dns-query" ;;
		xbox)          echo "https://xbox-dns.ru/dns-query" ;;
		comss)         echo "https://dns.comss.one/dns-query" ;;
		dnsai)         echo "https://dns.dns-ai.ru/dns-query" ;;
		bezmezhau)     echo "https://sync.bezmezhau.com/dns-query" ;;
		yandex_family) echo "https://family.dot.dns.yandex.net/dns-query" ;;
		yandex_safe)   echo "https://safe.dot.dns.yandex.net/dns-query" ;;
		geohide_eu)    echo "https://eu.geohide.ru/dns-query" ;;
		geohide_us)    echo "https://us.geohide.ru/dns-query" ;;
		malw)          echo "https://dns.malw.link/dns-query" ;;
		webshift)      echo "https://d.webshiftvpn.ru/dns-query" ;;
		dagami)        echo "https://dns.dagami.ru/dns-query" ;;
		magicdns)      echo "https://dns.magicdns.ru/dns-query" ;;
		tamaev)       echo "https://tamaev-gifts.xyz/dns-query" ;;
		zombiez)      echo "https://dns.zombiez.ru/dns-query" ;;
		wlrus)        echo "https://dns.wlrus.cfd/dns-query" ;;
		magicinfo)    echo "https://api.magicinfo.art/dns-query" ;;
		quicbest)     echo "https://w.quic.best/dns-query" ;;
		controld)      echo "https://freedns.controld.com/p0" ;;
		controld_sec)  echo "https://freedns.controld.com/p1" ;;
		controld_fam)  echo "https://freedns.controld.com/family" ;;
		dns4eu)        echo "https://unfiltered.joindns4.eu/dns-query" ;;
		dns4eu_sec)    echo "https://protective.joindns4.eu/dns-query" ;;
		dns4eu_fam)    echo "https://child.joindns4.eu/dns-query" ;;
		https://*)
			printf '%s' "$1" | grep -qE '^https://[A-Za-z0-9.-]+\.[A-Za-z0-9-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+=&?-]*)?$' || return 1
			[ "${#1}" -le 200 ] || return 1
			echo "$1" ;;
		*) return 1 ;;
	esac
}

DOH_FO_FILE="/opt/zapret-manager-luci/doh_failover"
DOH_STOP="/opt/zapret-manager-luci/state/doh.stopped"
DOH_FO_STATE="/tmp/zm-doh-failover.state"
DOH_FO_EVENTS="/tmp/zm-doh-failover.events"
DOH_FO_CRON="# zm-dohwatch"
_doh_fo_get() { local v; v="$(_kv_last "$DOH_FO_FILE" "$1")"; echo "${v:-$2}"; }
_doh_st_get() { local v; v="$(_kv_last "$DOH_FO_STATE" "$1")"; echo "${v:-$2}"; }
DOH_LK="/tmp/zm-doh-failover.lock"
_doh_fo_on() { [ "$(_doh_fo_get fo 0)" = 1 ] || [ "$(_doh_fo_get direct 0)" = 1 ]; }
_zm_clock_ok() { [ "$(date +%Y)" -ge 2025 ] 2>/dev/null; }
_doh_name() {
	case "$1" in
		google) echo Google ;; cloudflare) echo Cloudflare ;; quad9) echo "Quad9 · Защита от угроз" ;; xbox) echo XBOX ;; comss) echo Comss ;; dnsai) echo DNS-AI ;; bezmezhau) echo Bezmezhau ;;
		cloudflare_sec) echo "Cloudflare · Защита от угроз" ;; cloudflare_fam) echo "Cloudflare · Семейный фильтр" ;; quad9_open) echo "Quad9 · Без фильтрации" ;;
		controld_sec) echo "Control D · Защита от угроз" ;; controld_fam) echo "Control D · Семейный фильтр" ;; dns4eu_sec) echo "DNS4EU · Защита от угроз" ;; dns4eu_fam) echo "DNS4EU · Семейный фильтр" ;;
		yandex) echo "Яндекс" ;; yandex_family) echo "Яндекс · Семейный фильтр" ;; yandex_safe) echo "Яндекс · Защита от угроз" ;; geohide_eu) echo "GeoHide EU" ;;
		geohide_us) echo "GeoHide US" ;; malw) echo MALW ;; webshift) echo WebShift ;; dagami) echo Dagami ;; magicdns) echo MagicDNS ;;
		tamaev) echo tamaev-gifts.xyz ;; zombiez) echo zombiez.ru ;; wlrus) echo wlrus.cfd ;; magicinfo) echo magicinfo.art ;; quicbest) echo quic.best ;;
		controld) echo "Control D" ;; dns4eu) echo DNS4EU ;;
		https://*) _doh_own_title "$1" | grep . || printf '%s' "$1" | sed 's#^https://\([^/]*\).*#\1#' ;; *) echo "$1" ;;
	esac
}
_doh_cur_id() {
	local u p
	[ -n "$(uci -q get 'https-dns-proxy.@https-dns-proxy[1].resolver_url')" ] && return 0
	u="$(uci -q get 'https-dns-proxy.@https-dns-proxy[0].resolver_url')"
	[ -n "$u" ] || return 0
	p="$(_doh_provider_of "$u")"
	echo "${p:-$u}"
}
_doh_fo_chain() {
	local id
	_doh_fo_get chain "" | tr ',' '\n' | while IFS= read -r id; do
		[ -n "$id" ] && _doh_url_of "$id" >/dev/null && echo "$id"
	done
	return 0
}
_doh_fo_json() {
	local ev ch="" id sep="" pref
	pref="$(_doh_fo_get pref "")"; [ -n "$pref" ] || pref="$(_doh_cur_id)"
	for id in $(_doh_fo_chain "$pref"); do ch="$ch$sep\"$(esc "$id")\""; sep=","; done
	ev="$(awk -F'|' 'BEGIN { s = "" } NF >= 2 { m = $0; sub(/^[^|]*\|/, "", m); gsub(/["\\]/, "", m); printf "%s{\"at\":%d,\"text\":\"%s\"}", s, $1, m; s = "," }' "$DOH_FO_EVENTS" 2>/dev/null)"
	printf '{"fo":%s,"direct":%s,"pref":"%s","chain":[%s],"mode":"%s","since":%s,"fails":%s,"events":[%s]}' \
		"$([ "$(_doh_fo_get fo 0)" = 1 ] && echo true || echo false)" "$([ "$(_doh_fo_get direct 0)" = 1 ] && echo true || echo false)" \
		"$(esc "$(_doh_fo_get pref "")")" "$ch" \
		"$(esc "$(_doh_st_get mode normal)")" "$(_doh_st_get since 0)" "$(_doh_st_get fails 0 | tr -cd 0-9)" "$ev"
}

DOH_OWN_FILE="/opt/zapret-manager-luci/doh_own"
DOH_OWN_MAX=12
_doh_own_json() {
	[ -s "$DOH_OWN_FILE" ] || return 0
	awk -F'\t' '$1 ~ /^https:\/\// { n2 = $2; gsub(/["\\]/, "", n2); printf "%s{\"url\":\"%s\",\"name\":\"%s\"}", (n++ ? "," : ""), $1, n2 }' "$DOH_OWN_FILE"
}
_dns_preset_map() {
	case "$1" in
		https://dns.bezmezhau.com/*) echo "https://sync.bezmezhau.com/dns-query" ;;
		dns.bezmezhau.com) echo "sync.bezmezhau.com" ;;
		https://geohide.ru/*|https://dns.geohide.ru/*) echo "https://dns.comss.one/dns-query" ;;
		https://api.magicdns.ru/*) echo "https://dns.magicdns.ru/dns-query" ;;
		https://dns.zapret.moe/*) echo "https://dns.comss.one/dns-query" ;;
		*) echo "$1" ;;
	esac
}

DN_FILE="/opt/zapret-manager-luci/dns_net"
DN_OWN="/opt/zapret-manager-luci/dns_net.owned"
DN_CANARY="use-application-dns.net mask.icloud.com mask-h2.icloud.com"
DN_RU_ZONES="ru su xn--p1ai"
DN_YANDEX="77.88.8.8 77.88.8.1"
_dn_get() { local v; v="$(_kv_last "$DN_FILE" "$1")"; echo "${v:-$2}"; }
_dn_secs() { uci -q -X show dhcp 2>/dev/null | sed -n "s/^dhcp\.\([A-Za-z0-9_]*\)=dnsmasq\$/\1/p"; }
_dn_isp() {
	local f
	for f in /tmp/resolv.conf.d/resolv.conf.auto /tmp/resolv.conf.auto; do
		[ -s "$f" ] || continue
		awk '$1 == "nameserver" && ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ || ($2 ~ /^[0-9A-Fa-f:]+$/ && $2 ~ /:.*:/)) && $2 !~ /^(127\.|0\.0\.0\.0$|::1$|[Ff][Ee]80:)/ && !u[$2]++ { print $2 }' "$f" | head -n 4 | tr '\n' ',' | sed 's/,$//'
		return 0
	done
}
# https-dns-proxy сам закрывает браузерам свой DNS (записи server=/use-application-dns.net/ и т. п.), только
# пока он установлен, не остановлен кнопкой и перехват включён. После удаления DoH, остановки или «Не перехватывать» такие записи —
# остаток: Firefox и Частный узел iCloud остаются выключены, а выключить это в панели нечем
DN_CANARY_DOH="use-application-dns.net mask.icloud.com mask-h2.icloud.com"
_dn_canary_doh_on() {
	[ -x /etc/init.d/https-dns-proxy ] && [ -f /etc/config/https-dns-proxy ] && [ ! -f "$DOH_STOP" ] &&
		[ "$(uci -q get https-dns-proxy.config.force_dns)" != 0 ] && [ "$(uci -q get https-dns-proxy.config.canary_domains_mozilla)" != 0 ]
}
_dn_canary_fix() {
	local s o d ch=""
	_dnsm_present && return 0
	_dn_canary_doh_on && return 0
	for s in $(_dn_secs); do
		for o in server doh_backup_server doh_server; do
			for d in $DN_CANARY_DOH; do
				uci -q get "dhcp.$s.$o" 2>/dev/null | tr ' ' '\n' | grep -qxF "/$d/" || continue
				uci -q del_list "dhcp.$s.$o=/$d/"; ch=1
			done
		done
	done
	[ -n "$ch" ] || return 0
	uci -q commit dhcp
	[ "$1" = norestart ] || /etc/init.d/dnsmasq restart >/dev/null 2>&1
	logger -t zapret-manager "DNS: убраны оставшиеся записи DoH, закрывавшие браузерам свой DNS"
	return 0
}
_dn_json() {
	local doh=false
	_dn_canary_doh_on && uci -q -X show dhcp 2>/dev/null | grep -E '^dhcp\.[^.]*\.server=' | grep -qF "'/use-application-dns.net/'" && doh=true
	printf '{"canary":%s,"canary_doh":%s,"ru":"%s","ru_ips":"%s","isp":"%s"}' \
		"$([ "$(_dn_get canary 0)" = 1 ] && echo true || echo false)" "$doh" "$(esc "$(_dn_get ru off)")" \
		"$(esc "$(_dn_ru_ips | tr ' ' ',')")" "$(esc "$(_dn_isp)")"
}

RB_SHARE="/usr/share/zm-redbtn"
ZM_LISTS_DIR="/opt/zapret-manager-luci/lists"
ZM_LISTS_ITD="${GH_RAW}/itdoginfo/allow-domains/main"
ZM_LISTS_V2F="${GH_RAW}/v2fly/domain-list-community/master/data"

_rb_list_src() {
	case "$1" in
		svc_youtube.lst) echo "$ZM_LISTS_ITD/Services/youtube.lst" ;;
		svc_telegram.lst) echo "$ZM_LISTS_ITD/Services/telegram.lst" ;;
		svc_discord.lst) echo "$ZM_LISTS_ITD/Services/discord.lst" ;;
		svc_instagram.lst) echo "$ZM_LISTS_V2F/instagram" ;;
		svc_instagram_extra.lst) echo "$RB_SHARE/svc/instagram_extra.lst" ;;
		svc_facebook.lst) echo "$ZM_LISTS_V2F/facebook" ;;
		svc_messenger.lst) echo "$ZM_LISTS_V2F/messenger" ;;
		svc_whatsapp.lst) echo "$ZM_LISTS_V2F/whatsapp" ;;
		svc_whatsapp_extra.lst) echo "$RB_SHARE/svc/whatsapp_extra.lst" ;;
		svc_google_ai_extra.lst) echo "$RB_SHARE/svc/google_ai_extra.lst" ;;
		svc_tiktok_extra.lst) echo "$RB_SHARE/svc/tiktok_extra.lst" ;;
		svc_v2meta.lst) echo "$ZM_LISTS_V2F/meta" ;;
		svc_threads.lst) echo "$ZM_LISTS_V2F/threads" ;;
		svc_oculus.lst) echo "$ZM_LISTS_V2F/oculus" ;;
		svc_twitter.lst) echo "$ZM_LISTS_ITD/Services/twitter.lst" ;;
		telegram.lst) echo "$ZM_LISTS_ITD/Subnets/IPv4/telegram.lst" ;;
		discord.lst) echo "$ZM_LISTS_ITD/Subnets/IPv4/discord.lst" ;;
		twitter_x.lst) echo "$ZM_LISTS_ITD/Subnets/IPv4/twitter.lst" ;;
		meta.lst) echo "$ZM_LISTS_ITD/Subnets/IPv4/meta.lst" ;;
		own_github.lst) echo "${GH_RAW}/v2fly/domain-list-community/master/data/github" ;;
		*) return 1 ;;
	esac
}

_rb_list_get() {
	local f="$1" p="$ZM_LISTS_DIR/$1" u tmp
	u="$(_rb_list_src "$f")" || return 1
	case "$u" in /*)
		[ -s "$u" ] || { echo "     !! $f: нет встроенного списка" >&2; return 1; }
		mkdir -p "$ZM_LISTS_DIR" 2>/dev/null
		tmp="$ZM_LISTS_DIR/.$f.$$"
		cp -f "$u" "$tmp" 2>/dev/null && _rb_list_norm "$f" "$tmp" > "$tmp.ok"
		rm -f "$tmp"
		if [ -s "$tmp.ok" ]; then
			if cmp -s "$tmp.ok" "$p"; then rm -f "$tmp.ok"; else mv -f "$tmp.ok" "$p"; fi
			echo "     ✓ $f: встроенный, строк $(wc -l < "$p" | tr -d ' ')" >&2
			return 0
		fi
		rm -f "$tmp.ok"
		return 1 ;;
	esac
	if [ -s "$p" ] && [ -z "$(find "$p" -mtime +6 2>/dev/null)" ]; then return 0; fi
	if [ -s "$p" ] && [ -n "$(find "$ZM_LISTS_DIR/.$f.fail" -mmin -60 2>/dev/null)" ]; then return 0; fi
	mkdir -p "$ZM_LISTS_DIR" 2>/dev/null
	tmp="$ZM_LISTS_DIR/.$f.$$"
	if _st_fetch "$u" "$tmp" || { _st_cdn_url "$u" >/dev/null 2>&1 && _st_fetch "$(_st_cdn_url "$u")" "$tmp"; }; then
		_rb_list_norm "$f" "$tmp" > "$tmp.ok"
		if [ -s "$tmp.ok" ]; then
			mv -f "$tmp.ok" "$p"
			rm -f "$tmp" "$ZM_LISTS_DIR/.$f.fail"
			echo "     ✓ $f: скачан, строк $(wc -l < "$p" | tr -d ' ')" >&2
			return 0
		fi
	fi
	rm -f "$tmp" "$tmp.ok"
	: > "$ZM_LISTS_DIR/.$f.fail" 2>/dev/null
	if [ -s "$p" ]; then
		echo "     !! $f не обновился — беру прошлую копию" >&2
		return 0
	fi
	echo "     !! $f не скачался" >&2
	return 1
}

_rb_say() { echo "==> $*"; }
_rb_warn() { echo "!! $*"; }
_rb_conf_plus() {
	if [ -f "$ST_TCH_OFF" ] || [ ! -s "$ST_TCH_PLUS" ]; then grep -hv '^#' "$RB_SHARE/services.conf" 2>/dev/null; return 0; fi
	awk -F'|' -v OFS='|' -v pf="$ST_TCH_PLUS" '
		BEGIN { while ((getline l < pf) > 0) { i = index(l, "|"); if (i > 1) P[substr(l, 1, i - 1)] = substr(l, i + 1) } close(pf) }
		/^#/ { next }
		($1 in P) && P[$1] != "" && $8 != "" { n = split($8, c, ","); for (i = 1; i <= n; i++) h[c[i]] = 1; m = split(P[$1], a, ","); for (i = 1; i <= m; i++) if (a[i] != "" && !(a[i] in h)) $8 = $8 ($8 != "" ? "," : "") a[i]; delete h }
		{ print }' "$RB_SHARE/services.conf" 2>/dev/null
}
_rb_svc_src() { _rb_conf_plus; cat "$ST_OWN_SVC" "$ST_OWN_CSVC" 2>/dev/null; [ -f "$ST_CAT_OFF" ] || awk -F'|' -v skip="$ST_CAT_SKIP" -v conf="$RB_SHARE/services.conf" 'BEGIN { while ((getline l < conf) > 0) { if (l ~ /^#/) continue; split(l, a, "|"); if (a[1] == "") continue; b[a[1]] = 1; m = split(a[8], c, ","); for (i = 1; i <= m; i++) if (c[i] != "") b[c[i]] = 1 } } $9 != "" && $9 != "Свои списки каталога" { k = $1; sub(/^c_/, "", k); if (index(skip, " " k " ")) next; if (k ~ /^itdoginfo_/ && (substr(k, 11) in b)) next; print }' "$ST_CAT_SVC" 2>/dev/null; [ -f "$ST_TCH_OFF" ] || cat "$ST_TCH_SVC" 2>/dev/null; }
_rb_svc_field() { _rb_svc_src | awk -F'|' -v k="$1" -v n="$2" '$1 == k { print $n; exit }'; }
_rb_svc_row() { _rb_svc_src | awk -F'|' -v k="$1" '$1 == k { print; exit }'; }
_rb_svc_names() { local id; for id in $1; do printf '%s, ' "$(_rb_svc_field "$id" 2)"; done | sed 's/, $//'; }
_rb_routable() { _rb_svc_src | awk -F'|' -v k="$1" '$1 == k { r = k == "custom" || $3 $4 $8 != ""; exit } END { exit !r }'; }
_job_alive() { _job_running "$1"; }

_rb_rpcd_ensure() {
	local i=0
	while [ "$i" -lt 3 ]; do
		ubus list zapret-manager >/dev/null 2>&1 && return 0
		/etc/init.d/rpcd reload >/dev/null 2>&1
		sleep 3
		i=$((i + 1))
	done
	ubus list zapret-manager >/dev/null 2>&1
}

ST_DIR="/etc/zm-steer"
ST_OWNED="$ST_DIR/owned"
ST_SEL="$ST_DIR/services"
ST_CAT_SVC="$ST_DIR/services.remote"
ST_CAT_IDX="$ST_DIR/catalog.idx"
ST_CAT_META="$ST_DIR/catalog.meta"
ST_CAT_URL="$ST_DIR/catalog.url"
ST_CAT_OFF="$ST_DIR/catalog.off"
ST_TCH_SVC="$ST_DIR/tachyon.svc"
ST_TCH_DIRECT="$ST_DIR/tachyon.direct"
ST_TCH_PLUS="$ST_DIR/tachyon.plus"
ST_TCH_IDX="$ST_DIR/tachyon.idx"
ST_TCH_META="$ST_DIR/tachyon.meta"
ST_TCH_OFF="$ST_DIR/tachyon.off"
ST_TCH_ERR="$ST_DIR/tachyon.err"
ST_TCH_XSETS="$ST_DIR/user/exclude.sets"
ST_TCH_REPO="https://github.com/Dushnilin/tachyon-lists"
ST_OWN_SVC="$ST_DIR/own.svc"
ST_OWN_IDX="$ST_DIR/own.idx"
ST_OWN_GRP="Мои списки (добавлены вами)"
ST_OWN_MAX=30
ST_OWN_CATS="$ST_DIR/own.cats"
ST_OWN_CSVC="$ST_DIR/own.cat.svc"
ST_OWN_CIDX="$ST_DIR/own.cat.idx"
ST_OWN_CMAX=5
ST_TCH_RAW="https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main"
ST_TCH_CDN="https://cdn.jsdelivr.net/gh/Dushnilin/tachyon-lists@main"
ST_SKIP="$ST_DIR/skip"
ST_OFF="$ST_DIR/stopped"
ST_WARP_CONF="$ST_DIR/warp.conf"
ST_RUN="$JOBS_DIR/steer"
ST_STOP_FLAG="$ST_RUN/stop"
ST_PHASE_FILE="$ST_RUN/phase"
ST_WARP_IF="zmwarp"
ST_WARP_ZONE="zmwarp"
ST_AWG_MIRRORS="${GH_MAIN}/2Grey/awg-openwrt/releases/download ${GH_MAIN}/Slava-Shchipunov/awg-openwrt/releases/download"
ST_AWG_MIRROR_FLAT="https://gitlab.com/xyzmean/brb/-/raw/main/deps/awg"
ST_CRON_TAG="# zm-steer"
ST_CRON_CMD="/opt/zapret-manager-luci/backend.sh steer_action cron_restart x >/dev/null 2>&1"
ST_WARP_N=3
ST_WARP_MAX=3
ST_OWN_IF="zmwarp4"
ST_WARP_MODE="$ST_DIR/warp.mode"
ST_WARP_OWN="$ST_DIR/warp.own.conf"
ST_WARP_OWN_KEEP="/etc/zm-warp-own.conf"
ST_WARP_UP_AUTO="$ST_DIR/warp.up.auto"
ST_WIF1="zmwarp"; ST_WCONF1="$ST_WARP_CONF"
_st_mode_vars() {
	ST_MODE_RAW=""
	[ -f "$ST_WARP_MODE" ] && { read -r ST_MODE_RAW < "$ST_WARP_MODE" || :; } 2>/dev/null
	case "$ST_MODE_RAW" in
		own) ST_WARP_N=1; ST_WIF1="$ST_OWN_IF"; ST_WCONF1="$ST_WARP_OWN" ;;
		iface:?*) ST_WARP_N=1; ST_WIF1="${ST_MODE_RAW#iface:}"; ST_WCONF1="$ST_DIR/warp.ext.none" ;;
		*) ST_WARP_N="$ST_WARP_MAX"; ST_WIF1="zmwarp"; ST_WCONF1="$ST_DIR/warp.conf" ;;
	esac
	ST_WARP_IF="$ST_WIF1"; ST_WARP_CONF="$ST_WCONF1"
}
_st_mode_vars
ST_WARP_UP="$ST_DIR/warp.up"
ST_WARP_GEO="$ST_DIR/warp.geo"
ST_RU_COLOS="DME SVX LED KJA REN OVB KZN AER VVO"

STL_TMP="$ST_RUN"
STL_KEEP="$ST_DIR/spec.before"
STL_CACHE="$ZM_STATE_DIR/steer.latest"
STL_ETC="${STL_ETC:-/etc/steer}"
STL_SPEC="$STL_ETC/spec.json"
STL_YAML="$STL_ETC/spec.yaml"
STL_SOCK="$STL_ETC/steer.sock"
STL_INIT="${STL_INIT:-/etc/init.d/steer}"
STL_SBIN="${STL_SBIN:-/usr/sbin}"
STL_STATE="${STL_STATE:-/var/lib/steer}"
STL_PLUG="${STL_PLUG:-/usr/lib/steer/plugins}"
STL_SEED_SPEC='{"version":2,"outputs":{"direct":{"kind":"direct"}}}'
STL_MIN="2.0.0"
# Ядро steer 2.0.5 — версия до перехода на плагины. Выбрана при установке — закреплена: обновлений не ищем
STL_LEGACY="2.0.5"
STL_PIN="$ST_DIR/engine.pin"
STL_MODS="vless xsteer obfs tgws hysteria2 proxy"
STL_REL_URLS="${STL_REL_URLS:-https://raw.githubusercontent.com/splify2/releases/main/version.json https://cdn.jsdelivr.net/gh/splify2/releases@main/version.json https://splify2.github.io/releases/version.json}"
STL_PKG_URLS="${STL_PKG_URLS:-https://github.com/splify2/releases/releases/download/steer-v@V@ https://github.com/splify2/steer/releases/download/v@V@ https://gitlab.com/xyzmean/steer/-/raw/dist}"
STL_WARP_OUT="zm_warp"
STL_VPN_OUT="zm_vpn"
STL_VPN_DEV="zm_vpn"
STL_VPN_PFX="zmv"
ST_SEC=""

_st_onfail() { [ "$(cat /etc/zm-steer/onfail 2>/dev/null)" = drop ] && echo drop || echo direct; }
_st_dnsmode() { [ "$(cat /etc/zm-steer/dns.mode 2>/dev/null)" = router ] && echo router || echo tun; }
_st_realip() { [ "$(cat /etc/zm-steer/realip.mode 2>/dev/null)" = off ] && echo off || echo on; }
_st_torrent() { case "$(cat /etc/zm-steer/torrent.mode 2>/dev/null)" in direct) echo direct ;; block) echo block ;; *) echo allow ;; esac; }
_st_quic() { [ "$(cat /etc/zm-steer/quic.mode 2>/dev/null)" = block ] && echo block || echo allow; }
# «Торренты» и «QUIC» у правила. $1 — списки srs правила, $2 — выход. Ядро отвергает эти ключи у правила со
# списком srs (пока только domains_file и prefixes_file) и torrent: direct у выхода «напрямую» — раньше из-за
# одного такого правила они снимались со всех правил с ложной подсказкой «обновите ядро»
_stl_tq() {
	[ -n "$ZM_STL_NOTQ" ] && return 0
	[ -n "$1" ] && return 0
	case "$(_st_torrent)" in
		allow) ;;
		direct) case "$2" in "$ST_DIRECT_OUT"|direct) ;; *) printf ',"torrent":"direct"' ;; esac ;;
		*) printf ',"torrent":"%s"' "$(_st_torrent)" ;;
	esac
	[ "$(_st_quic)" = block ] && printf ',"quic":"block"'
	return 0
}
_st_cttl() { local v; v="$(cat /etc/zm-steer/dns.ttlmin 2>/dev/null)"; case "$v" in 300|900|3600) echo "$v" ;; *) echo 0 ;; esac; }
_stl_t() { _zm_tmo "$@"; }
_stl_out() { case "$1" in vpn) echo "$STL_VPN_OUT" ;; iface) echo "zm_if${ST_SEC#s}" ;; *) echo "$STL_WARP_OUT" ;; esac; }
_stl_ver_ok() { _zm_re "$1" '^[0-9]+\.[0-9]+\.[0-9]+$' && [ "${1%%.*}" -ge 2 ]; }

# Оболочка запоминает, где лежала команда: после удаления пакета «command -v» в том же процессе ещё находит
# её — поэтому проверяем сам файл
stl_present() { local p; p="$(command -v steer 2>/dev/null)" && [ -x "$p" ]; }
stl_version() { steer --version 2>/dev/null | awk 'NR == 1 { print $2 }'; }
stl_v2() { _stl_ver_ok "$(stl_version)"; }
_stl_mod_x() { [ -x "$STL_SBIN/steer-$1" ] || [ -s "$STL_PLUG/$1/plugin.json" ]; }
stl_has() {
	stl_v2 || return 1
	case "$1" in
		vpn|vless) _stl_mod_x vless ;;
		hy2|hysteria2) _stl_mod_x hysteria2 ;;
		proxy) _stl_mod_x proxy ;;
		*) return 1 ;;
	esac
}
stl_busy_by() {
	local i=/etc/init.d/sing-box b by=""
	grep -q steer-box-connector "$i" 2>/dev/null || return 1
	for b in podkop; do [ -e "${i%/*}/$b" ] && by="${by:+$by, }$b"; done
	echo "${by:-steer-box-connector}"
}
_stl_mods_present() { local m; for m in $STL_MODS; do _stl_mod_x "$m" && printf '%s ' "$m"; done; }

_stl_rel() {
	local f="$STL_TMP/version.json" u
	mkdir -p "$STL_TMP"
	[ -s "$f" ] && [ -z "$(find "$f" -mmin +60 2>/dev/null)" ] && { echo "$f"; return 0; }
	for u in $STL_REL_URLS; do
		_zm_fetch "$u" "$f.tmp" 20 || continue
		[ "$(jsonfilter -i "$f.tmp" -e '@.schema' 2>/dev/null)" = 1 ] || continue
		mv -f "$f.tmp" "$f"; echo "$f"; return 0
	done
	rm -f "$f.tmp"
	[ -s "$f" ] && { echo "$f"; return 0; }
	return 1
}

_stl_pin() { local v; v="$(head -n1 "$STL_PIN" 2>/dev/null)"; _stl_ver_ok "$v" && echo "$v"; }

# Версия, до которой панель обновляет ядро: закреплённая или последняя
stl_latest() {
	local p
	p="$(_stl_pin)" && { echo "$p"; return 0; }
	stl_latest_real
}

stl_latest_real() {
	local v="" f u
	if [ -z "$ZM_VER_FORCE" ] && [ -s "$STL_CACHE" ] && [ -z "$(find "$STL_CACHE" -mmin +360 2>/dev/null)" ]; then cat "$STL_CACHE"; return 0; fi
	f="$(_stl_rel)" && v="$(jsonfilter -i "$f" -e '@.products.steer.stable' 2>/dev/null)"
	if ! _stl_ver_ok "$v"; then
		for u in $STL_PKG_URLS; do
			case "$u" in *@V@*) continue ;; esac
			v="$(curl -fsSL --connect-timeout 6 --max-time 12 "$u/VERSION" 2>/dev/null | tr -d '[:space:]')"
			_stl_ver_ok "$v" && break
			v=""
		done
	fi
	if _stl_ver_ok "$v"; then
		mkdir -p "$(dirname "$STL_CACHE")"; echo "$v" > "$STL_CACHE"; echo "$v"
	elif [ -s "$STL_CACHE" ]; then cat "$STL_CACHE"
	else echo "$STL_MIN"; fi
}

stl_pkgs_installed() {
	local p m
	_st_ver_lt "$(stl_version)" 2.1.0 || { _pkg_is_installed steer-core && printf 'steer-core '; return 0; }
	for p in $(for m in $STL_MODS; do echo "steer-$m"; done) steer-extended steer-core steer libsteer libsteer-wolfssl; do
		_pkg_is_installed "$p" && printf '%s ' "$p"
	done
}

stl_leftovers() {
	stl_present && return 0
	local t m n=0
	for t in "inet steer" "ip steer" "ip6 steer" "inet steer_obfs"; do nft delete table $t >/dev/null 2>&1 && n=$((n + 1)); done
	for t in $(awk '{print $3}' "$STL_STATE/registry" 2>/dev/null); do ip route flush table "$t" >/dev/null 2>&1; done
	for m in $(awk '{print $2}' "$STL_STATE/registry" 2>/dev/null); do
		while ip rule del fwmark "0x$m/0x0ff00000" >/dev/null 2>&1; do n=$((n + 1)); done
		while ip rule del fwmark "0x$m" >/dev/null 2>&1; do n=$((n + 1)); done
	done
	killall steerd >/dev/null 2>&1
	rm -rf "$STL_STATE"
	rm -f "$STL_SOCK"
	if [ -d "$STL_PLUG" ] || [ -d "$STL_ETC/plugins" ]; then
		rm -rf "$STL_PLUG" "$STL_ETC/plugins"
		rm -f /lib/upgrade/keep.d/steer-plugins
		rmdir "${STL_PLUG%/*}" 2>/dev/null
		echo "   ✓ Плагины ядра steer убраны"
	fi
	rmdir "$STL_ETC" 2>/dev/null
	[ "$n" -gt 0 ] && echo "   ✓ Убраны оставшиеся правила ядра steer: $n"
	return 0
}

stl_spec_whose() {
	[ -s "$STL_YAML" ] && { echo foreign; return; }
	[ -s "$STL_SPEC" ] || { echo none; return; }
	grep -qE '"(zm_(warp[0-9]*|vpn[0-9]*|if[0-9]*|direct)|zmv[0-9]*_[A-Za-z0-9]+)"' "$STL_SPEC" && { echo zm; return; }
	tr '\n\r' '  ' < "$STL_SPEC" | grep -q '"\(channels\|rules\)"[[:space:]]*:[[:space:]]*\[[[:space:]]*{' && { echo foreign; return; }
	echo none
}
stl_rules() { grep -o '"out":' "$STL_SPEC" 2>/dev/null | wc -l | tr -d ' '; }

stl_running() { [ -x "$STL_INIT" ] && "$STL_INIT" running >/dev/null 2>&1; }
stl_enabled() { [ -x "$STL_INIT" ] && "$STL_INIT" enabled >/dev/null 2>&1; }
stl_restart() {
	[ -x "$STL_INIT" ] || return 1
	"$STL_INIT" enable >/dev/null 2>&1
	"$STL_INIT" restart >/dev/null 2>&1
	sleep 1
	stl_running
}
stl_stop() { [ -x "$STL_INIT" ] || return 0; "$STL_INIT" stop >/dev/null 2>&1; "$STL_INIT" disable >/dev/null 2>&1; return 0; }

stl_state() {
	local o j m
	o="$(_stl_out "$1")"
	STL_UP=false; STL_FAILED=false; STL_DEV=""; STL_PSTATE=""; STL_PNODE=""; STL_PTOTAL=""; STL_NODE=""; STL_NWHY=""
	STL_KIND=""; STL_SEL=""; STL_PROTO=""; STL_PIDX=""
	stl_present || return 1
	if [ -n "$ZM_STL_CACHE" ] && [ -n "$STL_ST_J" ]; then j="$STL_ST_J"; else j="$(_stl_t 10 steer status 2>/dev/null)"; fi
	case "$j" in '{'*) ;; *) return 1 ;; esac
	eval "$(printf '%s' "$j" | jsonfilter -e "STL_KIND=@.outputs.$o.kind" -e "STL_SEL=@.outputs.$o.group.selected" \
		-e "STL_UP=@.outputs.$o.up" -e "STL_FAILED=@.outputs.$o.failed" -e "STL_DEV=@.outputs.$o.device" \
		-e "STL_PSTATE=@.outputs.$o.probe.state" -e "STL_PNODE=@.outputs.$o.probe.node" -e "STL_PTOTAL=@.outputs.$o.probe.total" \
		-e "STL_NWHY=@.outputs.$o.node_down.why" 2>/dev/null)"
	case "$STL_UP" in 1|true) STL_UP=true ;; *) STL_UP=false ;; esac
	case "$STL_FAILED" in 1|true) STL_FAILED=true ;; *) STL_FAILED=false ;; esac
	if [ "$1" = vpn ]; then
		m="$o"
		[ "$STL_KIND" = group ] && printf '%s' "$STL_SEL" | grep -qE "^${STL_VPN_PFX}_[a-z0-9]+\$" && m="$STL_SEL"
		local n1="" n2="" n3="" i1="" i2="" w2=""
		eval "$(printf '%s' "$j" | jsonfilter -e "STL_PROTO=@.outputs.$m.kind" -e "n1=@.outputs.$m.vless.node" -e "n2=@.outputs.$m.proxy.node" \
			-e "n3=@.outputs.$m.hysteria2.node" -e "i1=@.outputs.$m.vless.active[0].index" -e "i2=@.outputs.$m.proxy.active[0].index" \
			-e "w2=@.outputs.$m.node_down.why" 2>/dev/null)"
		STL_NODE="${n1:-${n2:-$n3}}"; STL_PIDX="${i1:-$i2}"
		[ -z "$STL_NWHY" ] && [ "$m" != "$o" ] && STL_NWHY="$w2"
		[ "$STL_KIND" = group ] && [ "$STL_FAILED" = true ] && [ -z "$STL_PSTATE" ] && { STL_PSTATE=failed; STL_PTOTAL=0; }
	fi
	[ "$STL_UP" = true ] && STL_NWHY=""
	# Ядро обрезает причину по байтам, посреди слова: «…соединения не открыва»
	case "$STL_NWHY" in "проверка проходит, а соединения не "*) STL_NWHY="проверка проходит, а соединения не открываются" ;; esac
	printf '%s' "$STL_DEV" | grep -qE '^[A-Za-z0-9_.-]+$' || STL_DEV=""
	case "$STL_PSTATE" in probing|failed|no_such_node|excluded) ;; *) STL_PSTATE="" ;; esac
	case "$STL_PNODE" in ''|*[!0-9]*) STL_PNODE=0 ;; esac
	case "$STL_PTOTAL" in ''|*[!0-9]*) STL_PTOTAL=0 ;; esac
	case "$STL_PIDX" in *[!0-9]*) STL_PIDX="" ;; esac
	return 0
}

stl_diag() {
	local d
	d="$(_stl_t 30 steer diag 2>/dev/null | tr '\n' ' ')"
	case "$d" in '{'*'}'*) printf '%s' "$d" ;; *) echo null ;; esac
}
_stl_diag_tsv() {
	local n i=0
	n="$(jsonfilter -i "$1" -e '@.checks[*].id' 2>/dev/null | wc -l)"
	while [ "$i" -lt "$n" ]; do
		printf '%s\t%s\t%s\n' "$(jsonfilter -i "$1" -e "@.checks[$i].verdict" 2>/dev/null)" \
			"$(jsonfilter -i "$1" -e "@.checks[$i].what" 2>/dev/null)" "$(jsonfilter -i "$1" -e "@.checks[$i].why" 2>/dev/null)"
		i=$((i + 1))
	done
}

ZM_ST_DIAG_AWK='
function secof(o) {
	if (o == "zm_vpn" || o == "zm_if" || o ~ /^zmv_/) return "main"
	if (o ~ /^zm_(vpn|if)[2-9]$/) return "s" substr(o, length(o), 1)
	if (o ~ /^zmv[2-9]_/) return "s" substr(o, 4, 1)
	return ""
}
function tipof(r,   c) {
	if (r ~ /вместо 101/) {
		c = r; sub(/^[^0-9]*/, "", c); c = substr(c, 1, 3) + 0
		if (c == 400 || c == 404) return "Сервер не знает такого адреса подключения — в ссылке неверный path или host"
		if (c == 403) return "Сервер или CDN перед ним не пускает — проверьте host и sni в ссылке или возьмите другой узел"
		if (c >= 500) return "Сервер узла (или CDN перед ним) не смог принять подключение — обычно в ссылке неверный path или host, реже сбой у поставщика"
		return "Сервер не принял подключение WebSocket — проверьте path и host в ссылке"
	}
	if (r ~ /Upgrade|Sec-WebSocket|кадр WebSocket/) return "По ссылке отвечает не VPN-сервер, а что-то другое (сайт-заглушка, прокси) — проверьте path, host и порт"
	if (r ~ /не разрешил/) return "Адрес сервера из ссылки не находится — проверьте адрес в ссылке и DNS роутера"
	if (r ~ /TCP не соединился|нет сокета/) return "До сервера не достучаться: он выключен, сменил порт или его блокирует провайдер"
	if (r ~ /ClientHello|таймаут|не ответил за|узел не ответил/) return "Сервер молчит — так выглядит блокировка по имени сайта (SNI) или лежащий узел; попробуйте другой узел"
	if (r ~ /не признал ключ|UUID|отверг авторизацию|отказал в авторизации|авторизации негоден|pbk или sid/) return "Сервер не принял ключ или пароль из ссылки — ссылка устарела: обновите подписку или ссылку"
	if (r ~ /подлинност|сертификат|pinSHA256/) return "Сертификат сервера не прошёл проверку — в ссылке неверный sni, или соединение подменяют"
	if (r ~ /ECH/) return "Ключ ECH в ссылке устарел — обновите ссылку или подписку"
	if (r ~ /VLESS encryption/) return "Строка encryption в ссылке не совпадает с сервером — обновите ссылку"
	if (r ~ /HTTP\/2|HTTP\/1\.1|gRPC/) return "Сервер не поддерживает транспорт из ссылки (ws, grpc, xhttp) — проверьте тип транспорта"
	if (r ~ /QUIC не открылся/) return "Подключение по QUIC (UDP) не открылось — проверьте порт и sni в ссылке; иногда провайдер режет UDP"
	if (r ~ /соединения не открываются/) return "Узел отвечает на проверку, но настоящие соединения не держит — выберите другой узел"
	if (r ~ /закрыл соединение|TLS закрыт|обрыв|поток закрыт|GOAWAY|не прислал данных|ответа нет|ответ не по протоколу|соединение закрыто/) return "Сервер обрывает соединение — узел перегружен или не пускает с этого адреса; попробуйте другой узел"
	return "Узел не отвечает — выберите другой узел или проверьте ссылку"
}
BEGIN {
	FS = "\t"; OFS = U
	while ((getline l < M) > 0) { split(l, a, "\t"); LB[a[1]] = a[2]; ST[a[1]] = a[3]; IF[a[1]] = a[4] }
	close(M)
	T = "(zm_vpn[2-9]?|zmv[2-9]?_[A-Za-z0-9]+|zm_warp[0-9]*|zmwarp[0-9]*)"
}
{
	v = $1; w = $2; y = $3; v0 = v; tip = ""; note = ""; s = ""; lab = ""
	if (w ~ /^выход [A-Za-z0-9_.-]+/) {
		o = w; sub(/^выход /, "", o); rest = o; sub(/[: ].*$/, "", o)
		rest = substr(rest, length(o) + 1); sub(/^:? */, "", rest)
		s = secof(o)
		if (s != "") {
			k = (o ~ /^zm_if/) ? "туннель" (IF[s] != "" ? " " IF[s] : "") : "VPN"
			lab = (LB[s] != "" ? LB[s] " · " : "") k
		} else if (o ~ /^zm_warp/) lab = "WARP"
		else if (o ~ /^zmwarp[0-9]*$/) lab = (o == "zmwarp" ? "WARP" : "WARP " substr(o, 7))
		else if (o == "zm_direct") lab = "Мимо Steer"
		else if (o ~ /^zm_fo[0-9]+$/) lab = "Запасной путь секций"
		if (lab != "") {
			sub("^устройство " T " в зоне, NAT есть$", "туннель подключён, NAT есть", rest)
			sub("^устройство " T " в зоне$", "туннель подключён", rest)
			sub("^устройства " T " нет$", "туннель не поднят", rest)
			sub("^устройство " T " выключено$", "туннель выключен", rest)
			sub("^" T " вне зоны фаервола$", "туннель вне зоны фаервола", rest)
			sub("^у " T " нет masquerade", "у туннеля нет masquerade", rest)
			sub("^" T " не отвечает", "туннель не отвечает", rest)
			cl = ""
			if (match(rest, /, трафик канала /)) {
				cl = substr(rest, RSTART + RLENGTH); rest = substr(rest, 1, RSTART - 1)
				if (cl == "идёт напрямую") cl = "сервисы идут напрямую"
				else if (cl == "остановлен") cl = "сервисы остановлены"
				else if (cl == "идёт через обход") cl = "сервисы идут через обход блокировок"
			}
			if (rest ~ /^узел перестал отвечать/) {
				rest = "узел не отвечает"
				r = y; sub(/; выход вернётся сам, когда узел ответит$/, "", r); sub(/ \(проверьте path и host\)$/, "", r)
				if (r == "узел не отвечает") r = ""
				y = r; tip = tipof(r)
			} else if (rest ~ /^туннель не отвечает/) {
				y = "проверьте туннель и его сервер"
				tip = "Туннель есть, но трафик через него не проходит — обычно не отвечает сервер туннеля"
			} else if (rest == "туннель не поднят") sub(/^туннель не поднят — /, "", y)
			if (s != "" && ST[s] != "" && ST[s] != "work") cl = ""
			w = lab ": " rest (cl != "" ? ", " cl : "")
		}
	} else if (w ~ /^канал s[2-9]_/) {
		c = w; sub(/^канал /, "", c); s = substr(c, 1, 2); sub(/^s[2-9]_/, "", c); sub(/:.*$/, "", c)
		t = w; sub(/^канал s[2-9]_[^:]*/, "", t)
		if (LB[s] != "") w = LB[s] " · список «" c "»" t
		s = ""
	}
	if (v == "fail" && s != "" && ST[s] != "" && ST[s] != "work") {
		v = "warn"
		note = ST[s] == "off" ? "Секция выключена — на работу это сейчас не влияет" : "В секции ничего не выбрано — на работу это сейчас не влияет"
		if (LB[s] == "") note = ST[s] == "off" ? "Steer выключен — на работу это сейчас не влияет" : "Сервисы не выбраны — на работу это сейчас не влияет"
	} else if (v == "fail" && tip != "" && s != "") tip = tip ". Как только он ответит, всё заработает само"
	print v, w, y, tip, note, v0, $2
}'
_st_diag_hjson() {
	_st_diag_human | awk -F"$(printf '\037')" "$ZM_JESC_AWK"'
		$1 ~ /^(ok|warn|fail)$/ { printf "%s{\"v\":\"%s\",\"what\":\"%s\",\"why\":\"%s\",\"tip\":\"%s\",\"note\":\"%s\"}", (n++ ? "," : ""), $1, jesc($2), jesc($3), jesc($4), jesc($5) }'
}

_stl_explain_run() {
	local t="" x="$STL_ETC/.zm-explain.$$.json"
	if [ -s "$STL_SPEC" ] && grep -q '"scope":"device"' "$STL_SPEC" 2>/dev/null; then
		sed 's/"scope":"device"/"scope":"device","enabled":false/g' "$STL_SPEC" > "$x" 2>/dev/null && t="$(_stl_t 20 steer explain --spec "$x" "$1" 2>&1)"
		rm -f "$x"
		case "$t" in *' -> '*) printf '%s\n' "$t"; return 0 ;; esac
	fi
	_stl_t 20 steer explain "$1" 2>&1
}

stl_explain() {
	local t line
	STL_X_VERDICT=unknown; STL_X_OUT=""; STL_X_DEV=""; STL_X_SET=""; STL_X_ADDR=""; STL_X_FAKE=false
	t="$(_stl_explain_run "$1")"
	STL_X_TEXT="$t"
	line="$(printf '%s\n' "$t" | grep -m1 -- '-> output "')"
	STL_X_ADDR="$(printf '%s\n' "$t" | head -n1 | sed -n 's/^[^ ]* -> \([0-9a-fA-F.:]*\) (.*/\1/p')"
	printf '%s\n' "$t" | head -n1 | grep -q 'fake-IP' && STL_X_FAKE=true
	if [ -n "$line" ]; then
		STL_X_OUT="$(printf '%s' "$line" | sed -n 's/.*-> output "\([^"]*\)".*/\1/p')"
		STL_X_SET="$(printf '%s' "$line" | sed -n 's/.*"\([^"]*\)" -> output ".*/\1/p')"
		STL_X_DEV="$(printf '%s' "$line" | sed -n 's/.*-> dev \([^ ]*\).*/\1/p')"
		case "$STL_X_OUT" in "$STL_WARP_OUT") STL_X_VERDICT=warp ;; zm_vpn|zm_vpn[2-9]|zmv_*|zmv[2-9]_*) STL_X_VERDICT=vpn ;; zm_if|zm_if[2-9]) STL_X_VERDICT=iface ;; "$ST_DIRECT_OUT") STL_X_VERDICT=direct ;;
			zm_fo[0-9]*) case "$STL_X_DEV" in zmwarp*) STL_X_VERDICT=warp ;; zm_vpn*|zmv*) STL_X_VERDICT=vpn ;; '') STL_X_VERDICT=other ;; *) STL_X_VERDICT=iface ;; esac ;;
			*) STL_X_VERDICT=other ;; esac
		[ -z "$STL_X_DEV" ] && printf '%s' "$line" | grep -q -- '-> direct' && STL_X_VERDICT=direct
	elif printf '%s' "$t" | grep -q 'no channel matches'; then STL_X_VERDICT=direct
	elif printf '%s' "$t" | grep -q 'резолвер ответил, но адреса не дал'; then STL_X_VERDICT=noaddr
	elif printf '%s' "$t" | grep -q 'резолвер steer не ответил'; then STL_X_VERDICT=nodns
	elif printf '%s' "$t" | grep -q 'нет ни одного правила по доменам'; then STL_X_VERDICT=nodomains; fi
}
ZM_ROUTE_PROBES='www static cdn api m' 

stl_sub_fetch() {
	local r
	STL_SUB_URL=""; STL_SUB_TITLE=""; STL_SUB_WARN=""; STL_SUB_ERR=""
	rm -f "$2"
	r="$(steer sub-fetch "$1" --out "$2" --info "$3" 2>/dev/null)"
	if [ "$(printf '%s' "$r" | jsonfilter -e '@.ok' 2>/dev/null)" != true ] || [ ! -s "$2" ]; then
		rm -f "$2"
		STL_SUB_ERR="$(printf '%s' "$r" | jsonfilter -e '@.error' 2>/dev/null)"
		return 1
	fi
	STL_SUB_URL="$(printf '%s' "$r" | jsonfilter -e '@.url' 2>/dev/null)"
	STL_SUB_TITLE="$(printf '%s' "$r" | jsonfilter -e '@.title' 2>/dev/null)"
	STL_SUB_WARN="$(printf '%s' "$r" | jsonfilter -e '@.warn' 2>/dev/null)"
	return 0
}
STL_VPN_PROTOS="vless hysteria2 trojan shadowsocks socks http vmess"
STL_VPN_DEVS="zm_vpn zmv_vless zmv_hy2 zmv_trojan zmv_ss zmv_socks zmv_http zmv_vmess"
STL_LINK_RE='^(vless|vmess|trojan|ss|socks|socks4|socks4a|socks5|http|https|hysteria2|hy2)://'
_stl_mod_of() { case "$1" in vless) echo vless ;; hysteria2) echo hysteria2 ;; *) echo proxy ;; esac; }

stl_sub_mods() {
	local m="vpn" t
	if head -c 256 "$1" 2>/dev/null | tr -d ' \t\r\n' | grep -q '^[[{]'; then
		# Протокол — только у узлов (outbounds): inbounds socks/http полного конфига Xray модулей не требуют
		t="$(jsonfilter -i "$1" -e '@.outbounds[*].type' -e '@.outbounds[*].protocol' -e '@[*].outbounds[*].type' -e '@[*].outbounds[*].protocol' 2>/dev/null | tr 'A-Z' 'a-z')"
		[ -n "$t" ] || t="$(grep -oiE '"(protocol|type)"[[:space:]]*:[[:space:]]*"[A-Za-z0-9]+"' "$1" 2>/dev/null | sed 's/.*"\([^"]*\)"$/\1/' | tr 'A-Z' 'a-z')"
		printf '%s\n' "$t" | grep -qxE 'hysteria2?|hy2' && m="$m hy2"
		printf '%s\n' "$t" | grep -qxE 'trojan|shadowsocks|socks|http|vmess' && m="$m proxy"
	elif grep -qE '^proxies:[[:space:]]*(\[|$)' "$1"; then
		# Только раздел proxies: у rule-providers и proxy-providers тоже бывает «type: http»
		t="$(awk '/^proxies:/ { p = 1; sub(/^proxies:/, ""); print; next } /^[^[:space:]#-]/ { p = 0 } p' "$1" 2>/dev/null)"
		printf '%s\n' "$t" | grep -qiE '(^|[{,[:space:]-])type:[[:space:]]*["'"'"']?(hysteria2?|hy2)["'"'"']?([,}[:space:]]|$)' && m="$m hy2"
		printf '%s\n' "$t" | grep -qiE '(^|[{,[:space:]-])type:[[:space:]]*["'"'"']?(trojan|ss|shadowsocks|socks5?|http|vmess)["'"'"']?([,}[:space:]]|$)' && m="$m proxy"
	else
		grep -qiE '^(hysteria2|hy2)://' "$1" && m="$m hy2"
		grep -qiE '^(trojan|ss|socks4a?|socks5?|https?|vmess)://' "$1" && m="$m proxy"
	fi
	echo "$m"
}

_stl_insec() { [ -f "${1%/*}/sub.insecure" ]; }
_stl_insec_arg() { _stl_insec "$1" && echo --insecure; }

stl_probe() {
	local j
	j="$([ -f "$ST_NOPQ_ON" ] && export STEER_NOPQ=1; _stl_t "${4:-40}" steer "$2-probe" "$1" --node "$3" --timeout 8 $(_stl_insec_arg "$1") 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
	case "$j" in '{'*'}') printf '%s' "$j" ;; *) return 1 ;; esac
}

_st_phase() { printf '%s\n' "$1" > "$ST_PHASE_FILE"; }
_st_own() { mkdir -p "$ST_DIR"; grep -qxF "$1" "$ST_OWNED" 2>/dev/null || echo "$1" >> "$ST_OWNED"; }
_st_owns() { grep -qxF "$1" "$ST_OWNED" 2>/dev/null; }
_st_running() { _job_alive steer; }
_st_installed() { stl_present && { _st_owns "engine" || _st_owns "pkg steer" || _st_owns "net zmwarp" || _st_owns "net $ST_OWN_IF"; }; }
_st_warp_on() {
	if _st_warp_ext; then [ "$(uci -q get "network.$ST_WARP_IF.proto")" = amneziawg ]; else _st_owns "net $ST_WARP_IF" && [ -s "$ST_WARP_CONF" ]; fi
}
_st_warp_own() { case "$ST_MODE_RAW" in own|iface:?*) return 0 ;; esac; return 1; }
_st_warp_ext() { case "$ST_MODE_RAW" in iface:?*) return 0 ;; esac; return 1; }
_st_ext_if() { case "$ST_MODE_RAW" in iface:?*) printf '%s\n' "${ST_MODE_RAW#iface:}" ;; esac; }
_st_uses_if() { [ -n "$1" ] && _st_installed || return 1; { _st_warp_ext && [ "$(_st_ext_if)" = "$1" ]; } || { [ "$(cat "$ST_DIR/exit" 2>/dev/null)" = iface ] && [ "$(_st_main_iface)" = "$1" ]; } || _st_sec_has_if "$1"; }
_st_sec_has_if() { local s; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = iface ] && [ "$(_st_sec_iface "$s")" = "$1" ] && return 0; done; return 1; }
# Через интерфейс прямо сейчас идут сервисы Steer (Steer включён): выключенному Steer интерфейс не нужен
_st_live_if() { _st_uses_if "$1" && [ ! -f "$ST_OFF" ]; }
_st_used_ifs() {
	local s
	{ _st_warp_ext && _st_ext_if
	  [ "$(cat "$ST_DIR/exit" 2>/dev/null)" = iface ] && _st_main_iface && echo
	  for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = iface ] && _st_sec_iface "$s" && echo; done; } | grep . | awk '!s[$0]++'
}
# Включённый Steer поднимает туннели, которые выключили, пока он стоял
_st_ifs_up() {
	local i n=""
	for i in $(_st_used_ifs); do
		[ "$(uci -q get "network.$i.auto")" = 0 ] || continue
		case "$(uci -q get "network.$i.proto")" in amneziawg|wireguard) ;; *) continue ;; esac
		uci -q delete "network.$i.auto"; n="$n $i"
	done
	[ -n "$n" ] || return 0
	uci -q commit network
	for i in $n; do ifup "$i" >/dev/null 2>&1; _rb_say "Включаем туннель $i — через него идут сервисы Steer"; done
	sleep 3
}
_st_warp_modename() { if _st_warp_ext; then echo iface; elif _st_warp_ownconf; then echo own; else echo auto; fi; }
_st_wpeer() { if [ -n "$(uci -q get "network.${1}_peer")" ]; then echo "${1}_peer"; else _awg_peer_sec "$1"; fi; }
_st_sec_off() {
	case "${1:-main}" in
		main) [ -f "$ST_SEC_DIR/main.off" ] && [ -s "$ST_SEC_LIST" ] ;;
		*) [ -f "$ST_SEC_DIR/$1/off" ] ;;
	esac
}
_st_sel() { _st_sec_off "$ST_SEC" && return 0; _st_sel_raw; }
_st_sel_raw() { [ -s "$ST_SEL" ] || return 0; local id; for id in $(cat "$ST_SEL"); do _rb_routable "$id" || continue; [ "$id" = custom ] && [ ! -s "$ST_CUSTOM.lst" ] && [ ! -s "$ST_CUSTOM.pfx" ] && continue; echo "$id"; done; }

ST_DEVS="$ST_DIR/devices"
ST_DIRECT_OUT="zm_direct"
_st_devs_all() { _st_sec_off "$ST_SEC" && return 1; grep -q "^all	" "$ST_DEVS" 2>/dev/null; }
_st_devs_n() { local n; n="$(grep -c "^$1	" "$ST_DEVS" 2>/dev/null)"; echo "${n:-0}"; }
_st_work() { [ -n "$(_st_sel)" ] || _st_devs_all || { [ -z "$ST_SEC" ] && _st_secs_work; }; }
ST_EXCL_LIST="zm_excl"
_st_devs_json() {
	[ -s "$ST_DEVS" ] || return 0
	awk -F'\t' -v q='"' -v nf="$OW_NAMES" -v lf=/tmp/dhcp.leases 'function j(v,  o, i, c) { o = ""; for (i = 1; i <= length(v); i++) { c = substr(v, i, 1); if (c == "\\" || c == q) o = o "\\" c; else if (c ~ /[\t\r\n]/) o = o " "; else o = o c } return o }
		BEGIN { while ((getline l < nf) > 0) { split(l, a, "\t"); if (a[2] != "") lb[tolower(a[1])] = a[2] } while ((getline l < lf) > 0) { split(l, a, " "); if (a[3] != "") im[a[3]] = tolower(a[2]) } }
		($1 == "all" || $1 == "byp" || $1 == "only") && $2 != "" { k = tolower($2); m = (k in im) ? im[k] : k; printf "%s{\"mode\":\"%s\",\"key\":\"%s\",\"name\":\"%s\"}", (n++ ? "," : ""), $1, j($2), j(m in lb ? lb[m] : $3) }' "$ST_DEVS"
}
do_steer_devs() {
	local rc
	_st_phase rules
	rm -f "$ST_STOP_FLAG"
	if [ -n "$ST_SEC" ]; then _rb_say "Секция «$(_st_sec_name "$ST_SEC")», устройства: весь трафик через секцию — $(_st_devs_n all), правила секции только для — $(_st_devs_n only)"
	else _rb_say "Устройства: весь трафик через туннель — $(_st_devs_n all), сервисы только для — $(_st_devs_n only), мимо Steer — $(_st_devs_n byp)"; fi
	if _st_owns "steer-spec" && _st_work; then
		if _st_use_vpn; then _st_spec_quick; else _st_spec_quick_warp; fi
		rc=$?
		if [ "$rc" = 0 ]; then _rb_say "Готово: правила устройств применены, списки сервисов не перекачивались"; return 0; fi
		[ "$rc" = 1 ] && return 1
	fi
	do_steer_apply
}

[ -d "$ST_RUN" ] || mkdir -p "$ST_RUN" 2>/dev/null

_st_blocker() {
	local b
	if _st_splify2 && [ "$(stl_spec_whose)" != zm ]; then echo splify2; return; fi
	if b="$(stl_busy_by)"; then echo "Ядро steer ведёт $b — Zapret Manager его не трогает."; return; fi
	if _st_spec_foreign; then echo steer; return; fi
	echo ""
}

_rb_arch() { awk -F\' '/DISTRIB_ARCH/ {print $2}' /etc/openwrt_release; }
_rb_release() { awk -F\' '/DISTRIB_RELEASE/ {print $2}' /etc/openwrt_release; }

_rb_fetch_pkg() {
	_zm_fetch "$1" "$2" 120 && return 0
	echo "   не скачалось: $1 — $ZM_FETCH_ERR"
	rm -f "$2"; return 1
}

_st_ver_lt() {
	awk -v a="$1" -v b="$2" 'BEGIN { n = split(a, x, "."); m = split(b, y, "."); k = n > m ? n : m
		for (i = 1; i <= k; i++) { if (x[i] + 0 < y[i] + 0) exit 0; if (x[i] + 0 > y[i] + 0) exit 1 }
		exit 1 }'
}

_st_vpn_ok() { stl_has vpn || { stl_present && ! stl_v2; }; }

_st_sub_feats() { if [ -s "$ST_SUB" ]; then stl_sub_mods "$ST_SUB"; else echo vpn; fi; }
_st_feats_ok() { local f; for f; do stl_has "$f" || return 1; done; return 0; }

_st_awg_loaded() { grep -q '^amneziawg ' /proc/modules 2>/dev/null || [ -d /sys/module/amneziawg ]; }

_awg_board() { ubus call system board 2>/dev/null | jsonfilter -e "$1" 2>/dev/null; }
_awg_rel_ver() { local v; v="$(_awg_board '@.release.version')"; [ -n "$v" ] || v="$(_rb_release)"; echo "$v"; }
_awg_rel_arch() {
	local a; a="$(_awg_board '@.release.arch')"
	[ -n "$a" ] || a="$(_rb_arch)"
	[ -n "$a" ] || a="$(opkg print-architecture 2>/dev/null | awk 'BEGIN { m = 0 } $3 > m { m = $3; a = $2 } END { print a }')"
	[ -n "$a" ] || a="$(apk --print-arch 2>/dev/null)"
	echo "$a"
}
_awg_rel_target() { local t; t="$(_awg_board '@.release.target')"; [ -n "$t" ] || t="$(awk -F\' '/DISTRIB_TARGET/ {print $2}' /etc/openwrt_release)"; echo "$t"; }
_awg_luci_pkg() {
	local v="$1" ma mi pa
	ma="$(echo "$v" | cut -d. -f1)"; mi="$(echo "$v" | cut -d. -f2)"; pa="$(echo "$v" | cut -d. -f3 | sed 's/[^0-9].*//')"
	case "$ma.$mi.$pa" in *[!0-9.]*|*..*|.*|*.) echo luci-app-amneziawg; return ;; esac
	if [ "$ma" -gt 24 ] || { [ "$ma" -eq 24 ] && [ "$mi" -gt 10 ]; } || { [ "$ma" -eq 24 ] && [ "$mi" -eq 10 ] && [ "$pa" -ge 3 ]; } ||
	   { [ "$ma" -eq 23 ] && [ "$mi" -eq 5 ] && [ "$pa" -ge 6 ]; }; then
		echo luci-proto-amneziawg
	else
		echo luci-app-amneziawg
	fi
}
_awg_fetch() {
	local e
	for e in "$RAZ" "$([ "$RAZ" = apk ] && echo ipk || echo apk)"; do
		if _rb_fetch_pkg "$1/$2$3.$e" "$ST_RUN/$2.$e" >&2; then echo "$ST_RUN/$2.$e"; return 0; fi
	done
	return 1
}

AWG_KMOD_MANUAL="/etc/zm-awg/kmod-manual"
_awg_kmod_have() {
	_pkg_is_installed kmod-amneziawg && return 0
	[ -s "$AWG_KMOD_MANUAL" ] && [ -f "/lib/modules/$(uname -r)/amneziawg.ko" ]
}
_awg_kmod_ver() {
	if [ -s "$AWG_KMOD_MANUAL" ] && [ -f "/lib/modules/$(uname -r)/amneziawg.ko" ]; then
		awk '{ print $1; exit }' "$AWG_KMOD_MANUAL"
	else
		_awg_pkg_ver kmod-amneziawg
	fi
}
_awg_kmod_manual_rm() {
	[ -f "$AWG_KMOD_MANUAL" ] || return 0
	rm -f "/lib/modules/$(uname -r)/amneziawg.ko" "$AWG_KMOD_MANUAL"
}

ST_WARP_API="https://api.cloudflareclient.com/v0a2158/reg https://api.cloudflareclient.com/v0a1922/reg"

_st_warp_zone() {
	local want i
	want="$({ for i in $(_st_wifs_every); do { _st_owns "net $i" || _st_wifs_all | grep -qx "$i"; } && echo "$i"; done; _st_ext_zoneless && echo "$ST_WIF1"; _st_secs_zoneless; } | awk '!x[$0]++' | tr '\n' ' ' | sed 's/ $//')"
	if [ "$(uci -q get "firewall.$ST_WARP_ZONE")" = "zone" ] && [ "$(uci -q get "firewall.$ST_WARP_ZONE.network")" != "$want" ]; then
		uci -q delete "firewall.$ST_WARP_ZONE.network"
		for i in $want; do uci add_list "firewall.$ST_WARP_ZONE.network=$i"; done
		uci commit firewall
		/etc/init.d/firewall reload >/dev/null 2>&1
	fi
	if [ "$(uci -q get "firewall.$ST_WARP_ZONE")" != "zone" ]; then
		uci set "firewall.$ST_WARP_ZONE=zone"
		uci set "firewall.$ST_WARP_ZONE.name=$ST_WARP_ZONE"
		for i in $want; do uci add_list "firewall.$ST_WARP_ZONE.network=$i"; done
		uci set "firewall.$ST_WARP_ZONE.input=REJECT"
		uci set "firewall.$ST_WARP_ZONE.output=ACCEPT"
		uci set "firewall.$ST_WARP_ZONE.forward=REJECT"
		uci set "firewall.$ST_WARP_ZONE.masq=1"
		uci set "firewall.$ST_WARP_ZONE.mtu_fix=1"
		uci set "firewall.${ST_WARP_ZONE}_fwd=forwarding"
		uci set "firewall.${ST_WARP_ZONE}_fwd.src=$(_zm_lan_zone)"
		uci set "firewall.${ST_WARP_ZONE}_fwd.dest=$ST_WARP_ZONE"
		uci commit firewall
		_st_own "fw $ST_WARP_ZONE"
		/etc/init.d/firewall reload >/dev/null 2>&1
	fi
	_zm_fwd_fix "${ST_WARP_ZONE}_fwd"
}

ST_EXT_FWD="zmwarp_ext"
_st_secs_zoneless() { local i z; for i in $(_st_tun_ifaces); do z="$(_zm_zone_of_tun "$i")"; { [ -z "$z" ] || [ "$z" = "$ST_WARP_ZONE" ]; } && echo "$i"; done; }
_st_secs_fw() {
	local i z lz s r keep="" ch=0 zl=""
	lz="$(_zm_lan_zone)"
	_st_tun_hook
	for i in $(_st_tun_ifaces); do
		z="$(_zm_zone_of_tun "$i")"
		if [ -z "$z" ] || [ "$z" = "$ST_WARP_ZONE" ]; then zl=1; continue; fi
		s="$(_st_zone_sec "$z")"
		if [ "$z" = "$lz" ]; then
			[ -n "$s" ] && [ "$(uci -q get "firewall.$s.masq")" != 1 ] && _rb_warn "$i стоит в зоне локальной сети «$z» без маскарадинга (NAT) — сайты через него не откроются. Уберите $i из этой зоны (Сеть → Межсетевой экран)"
			continue
		fi
		r="zmsec_$i"
		if ! _st_fwd_has "$lz" "$z" "$r"; then
			keep="$keep $r"
			if [ "$(uci -q get "firewall.$r.dest")" != "$z" ] || [ "$(uci -q get "firewall.$r.src")" != "$lz" ]; then
				uci -q delete "firewall.$r"
				uci set "firewall.$r=forwarding"
				uci set "firewall.$r.src=$lz"
				uci set "firewall.$r.dest=$z"
				_st_own "fw $r"
				ch=1
				_rb_say "Разрешаем устройствам сети ходить в зону «$z» интерфейса $i"
			fi
		fi
		[ -n "$s" ] && [ "$(uci -q get "firewall.$s.masq")" != 1 ] && _rb_warn "В зоне «$z» выключен маскарадинг (NAT) — без него сайты через $i не откроются. Включите его в Сеть → Межсетевой экран"
	done
	for r in $(sed -n 's/^fw \(zmsec_[A-Za-z0-9_]*\)$/\1/p' "$ST_OWNED" 2>/dev/null); do
		case " $keep " in *" $r "*) continue ;; esac
		uci -q delete "firewall.$r"
		sed -i "\\|^fw $r\$|d" "$ST_OWNED" 2>/dev/null
		ch=1
	done
	[ "$ch" = 1 ] && { uci commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1; }
	if [ -n "$zl" ] || [ "$(uci -q get "firewall.$ST_WARP_ZONE")" = zone ]; then _st_warp_zone; fi
	_st_lan_fw
	return 0
}
_st_ext_zoneless() {
	local z
	_st_warp_ext || return 1
	z="$(_zm_zone_of_net "$ST_WIF1")"
	[ -z "$z" ] || [ "$z" = "$ST_WARP_ZONE" ]
}
_st_zone_sec() { local z; for z in $(uci -q -X show firewall | sed -n "s/^firewall\.\([^.=]*\)=zone\$/\1/p"); do [ "$(uci -q get "firewall.$z.name")" = "$1" ] && { echo "$z"; return 0; }; done; return 1; }

_zm_fwd_fix() {
	local lz
	[ "$(uci -q get "firewall.$1")" = forwarding ] || return 0
	lz="$(_zm_lan_zone)"
	[ "$(uci -q get "firewall.$1.src")" = "$lz" ] && return 0
	uci set "firewall.$1.src=$lz"
	uci commit firewall
	/etc/init.d/firewall reload >/dev/null 2>&1
}

_st_warp_is_ru() { case " $ST_RU_COLOS " in *" $1 "*) return 0 ;; esac; [ "$2" = RU ] && return 0; return 1; }

_st_wif() { [ "$1" = 1 ] && echo "$ST_WIF1" || echo "zmwarp$1"; }
_st_wconf() { [ "$1" = 1 ] && echo "$ST_WCONF1" || echo "$ST_DIR/warp$1.conf"; }
_st_with() {
	local n="$1" oi="$ST_WARP_IF" oc="$ST_WARP_CONF" rc
	shift
	ST_WARP_IF="$(_st_wif "$n")"; ST_WARP_CONF="$(_st_wconf "$n")"
	"$@"; rc=$?
	ST_WARP_IF="$oi"; ST_WARP_CONF="$oc"
	return $rc
}
_st_wifs_all() { local n=1; while [ "$n" -le "$ST_WARP_N" ]; do _st_wif "$n"; n=$((n + 1)); done; }
_st_wifs_every() { _st_wifs_auto; echo "$ST_OWN_IF"; }
_st_warp_first() {
	local i
	[ -s "$ST_WARP_UP" ] && while read -r i _; do [ -d "/sys/class/net/$i" ] && { echo "$i"; return 0; }; done < "$ST_WARP_UP"
	echo "$ST_WARP_IF"
}

ST_WARP_POOLS="188.114.96. 188.114.97. 188.114.98. 188.114.99. 162.159.192. 162.159.193. 162.159.195. 8.34.70. 8.34.146. 8.39.214. 8.39.204. 8.6.112. 8.35.211. 8.39.125. 8.47.69."
ST_WARP_PORTS="2408 500 1701 4500"
ST_WARP_PORTS_EXT="854 859 864 878 880 890 891 894 903 908 928 934 939 942 943 945 946 955 968 987 988 1002 1010 1014 1018 1070 1074 1180 1387 1843 2371 2506 3138 3476 3581 3854 4177 4198 4233 5279 5956 7103 7152 7156 7281 7559 8319 8742 8854 8886"
ST_WARP_RAND=10
ST_WARP_HS_WAIT=8
ST_WARP_BURST=10
ST_WARP_TORN=3

_st_warp_link() {
	local dev="$1" peer="$2" push w=0 hs
	awg set "$dev" peer "$peer" remove 2>/dev/null
	awg set "$dev" peer "$peer" endpoint "$3:$4" allowed-ips 0.0.0.0/0 persistent-keepalive 25 2>/dev/null || return 1
	ping -I "$dev" -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 &
	push=$!
	while [ "$w" -lt $((ST_WARP_HS_WAIT * 4)) ]; do
		hs=$(awg show "$dev" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
		if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then wait "$push" 2>/dev/null; return 0; fi
		w=$((w + 1))
		sleep 0.25 2>/dev/null || sleep 1
	done
	kill "$push" 2>/dev/null; wait "$push" 2>/dev/null
	return 1
}

_st_warp_probe() {
	local out
	out=$(ping -I "$1" -c "$ST_WARP_BURST" -i 0.2 -W 2 -w 8 1.1.1.1 2>/dev/null)
	case "$out" in *"packet loss"*) ;; *) out=$(ping -I "$1" -c 5 -W 2 -w 10 1.1.1.1 2>/dev/null) ;; esac
	case "$out" in *" 100% packet loss"*|'') out=$(ping -I "$1" -c "$ST_WARP_BURST" -i 0.2 -W 2 -w 8 8.8.8.8 2>/dev/null) ;; esac
	printf '%s\n' "$out" | awk -v t="$ST_WARP_TORN" '
		/seq=[0-9]/ { s = $0; sub(/.*seq=/, "", s); sub(/[^0-9].*/, "", s); s += 0; if (!got++ || s > hi) hi = s }
		/packets transmitted/ { tx = $1 + 0 }
		/packet loss/ { l = $0; sub(/%.*/, "", l); sub(/.*[^0-9]/, "", l); loss = l + 0; have = 1 }
		/min\/avg/ { v = $0; sub(/.*= */, "", v); split(v, a, "/"); rtt = int(a[2]) }
		END {
			if (!have) loss = 100
			torn = (got > 0 && tx > 0 && tx - 1 - hi >= t) ? 1 : 0
			printf "%d %d %d\n", loss, (got > 0 && rtt > 0 ? rtt : (got > 0 ? 1 : 99999)), torn
		}'
}

_cf_meta() {
	local j c s k t
	j=$(curl -s ${1:+--interface "$1"} --connect-timeout 4 --max-time 8 -H 'Referer: https://speed.cloudflare.com' https://speed.cloudflare.com/meta 2>/dev/null)
	case "$j" in *'"colo"'*) ;; *) return 1 ;; esac
	c="$(jsonfilter -s "$j" -e '@.colo.iata' 2>/dev/null)"
	[ -n "$c" ] || c="$(jsonfilter -s "$j" -e '@.colo' 2>/dev/null | grep -E '^[A-Z]{3}$')"
	[ -n "$c" ] || return 1
	s="$(jsonfilter -s "$j" -e '@.country' 2>/dev/null)"
	k="$(jsonfilter -s "$j" -e '@.colo.cca2' 2>/dev/null)"
	t="$(jsonfilter -s "$j" -e '@.colo.city' 2>/dev/null | tr -d '"\\\t\r\n')"
	echo "$c ${s:--} ${k:--} ${t:--}"
}

_st_warp_geo() {
	local i m
	mkdir -p "$ST_DIR"
	for i in "$@"; do
		[ -d "/sys/class/net/$i" ] || continue
		m="$(_cf_meta "$i")" || continue
		{ grep -v "^$i " "$ST_WARP_GEO" 2>/dev/null; echo "$i $m"; } > "$ST_WARP_GEO.tmp" && mv "$ST_WARP_GEO.tmp" "$ST_WARP_GEO"
	done
	return 0
}
_st_geo_get() { awk -v i="$1" '$1 == i { $1 = ""; sub(/^ /, ""); print; exit }' "$ST_WARP_GEO" 2>/dev/null; }

_st_colo_of() {
	local c
	c=$(curl -sI --interface "$1" --max-time 8 -H 'Host: www.cloudflare.com' http://104.16.132.229/ 2>/dev/null |
		sed -n 's/^[Cc][Ff]-[Rr][Aa][Yy]: *[0-9a-f]*-\([A-Z][A-Z][A-Z]\).*/\1/p' | head -n1)
	[ -n "$c" ] || c=$(curl -s --interface "$1" --connect-timeout 5 --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null |
		sed -n 's/^colo=//p' | head -n1)
	[ -n "$c" ] && echo "$c"
}

ST_WARP_PORTS_TTL=43200

ST_WARP_PAR=8
ST_WARP_PRE_WAIT=6

ST_WARP_PICK="$ST_DIR/warp.pick"
ST_WARP_ORDER="$ST_DIR/warp.order"
_st_warp_pick() { [ "$(cat "$ST_WARP_PICK" 2>/dev/null)" = order ] && echo order || echo latency; }

ST_TGWS_WARP="/etc/stgws/warp.lst"

ST_LISTS_MANIFEST="https://github.com/xyzmean/splify2-lists/releases/latest/download/lists.json"
ST_LISTS_MANIFEST_RAW="https://raw.githubusercontent.com/xyzmean/splify2-lists/main/lists.json"
ST_CAT_SKIP=" mydyson itdoginfo_meta "
ST_SRS_FALLBACK="https://github.com/itdoginfo/allow-domains/releases/latest/download"

_st_cat_src() { [ -s "$ST_CAT_URL" ] && head -n1 "$ST_CAT_URL" || echo "$ST_LISTS_MANIFEST"; }

_st_cat_refresh() {
	local m="$ST_RUN/lists.json" lk="$ST_RUN/cat.lock" rc=0 t
	[ -f "$ST_CAT_OFF" ] && return 0
	mkdir -p "$ST_DIR" "$ST_RUN"
	if [ "$1" != force ] && [ -s "$ST_CAT_SVC" ]; then
		t="$(date -r "$ST_CAT_SVC" +%s 2>/dev/null || echo 0)"
		[ $(( $(date +%s) - t )) -lt 21600 ] && return 0
	fi
	if ! mkdir "$lk" 2>/dev/null; then
		if [ "$1" = force ]; then
			t=0
			while [ "$t" -lt 10 ] && [ -d "$lk" ]; do sleep 1; t=$((t + 1)); done
		fi
		if ! mkdir "$lk" 2>/dev/null; then
			[ -n "$(find "$lk" -maxdepth 0 -mmin +5 2>/dev/null)" ] || return 0
			rmdir "$lk" 2>/dev/null; mkdir "$lk" 2>/dev/null || return 0
		fi
	fi
	if _st_cat_dl "$m.tmp"; then
		mv -f "$m.tmp" "$m"
		touch "$ST_CAT_SVC"
		rm -f "$ST_DIR/catalog.err"
	else
		rm -f "$m.tmp"
		echo "$(date +%s)" > "$ST_DIR/catalog.err"
		rc=1
	fi
	rmdir "$lk" 2>/dev/null
	return $rc
}

_st_tch_on() { [ ! -f "$ST_TCH_OFF" ]; }

_st_age() { echo $(( $(date +%s) - $(date -r "$1" +%s 2>/dev/null || echo 0) )); }

_st_tch_idx_merge() {
	mkdir -p "$ST_DIR"
	{ grep -vE '^(t|zmu|zmc[0-9]+)_' "$ST_CAT_IDX" 2>/dev/null; _st_tch_on && cat "$ST_TCH_IDX" 2>/dev/null; cat "$ST_OWN_IDX" "$ST_OWN_CIDX" 2>/dev/null; } > "$ST_CAT_IDX.t$$"
	if [ -s "$ST_CAT_IDX.t$$" ] || [ -f "$ST_CAT_IDX" ]; then mv -f "$ST_CAT_IDX.t$$" "$ST_CAT_IDX"; else rm -f "$ST_CAT_IDX.t$$"; fi
}

_st_tch_refresh() {
	local m="$ST_RUN/tachyon.json" lk="$ST_RUN/tch.lock" rc=0 t
	_st_tch_on || return 0
	mkdir -p "$ST_DIR" "$ST_RUN"
	[ "$1" != force ] && [ -s "$ST_TCH_META" ] && [ "$(_st_age "$ST_TCH_META")" -lt 21600 ] && return 0
	if ! mkdir "$lk" 2>/dev/null; then
		t=0
		while [ "$1" = force ] && [ "$t" -lt 10 ] && [ -d "$lk" ]; do sleep 1; t=$((t + 1)); done
		if ! mkdir "$lk" 2>/dev/null; then
			[ -n "$(find "$lk" -maxdepth 0 -mmin +5 2>/dev/null)" ] || return 0
			rmdir "$lk" 2>/dev/null; mkdir "$lk" 2>/dev/null || return 0
		fi
	fi
	if { _st_fetch "$ST_TCH_RAW/release/catalog.json" "$m" || _st_fetch "$ST_TCH_CDN/release/catalog.json" "$m"; } && _st_tch_build "$m"; then
		rm -f "$ST_TCH_ERR"
		_st_tch_idx_merge
	else
		date +%s > "$ST_TCH_ERR"
		rc=1
	fi
	rm -f "$m"
	rmdir "$lk" 2>/dev/null
	return $rc
}

_st_tch_bg() {
	_st_tch_on || return 0
	[ -d "$ST_RUN/tch.lock" ] && [ -z "$(find "$ST_RUN/tch.lock" -maxdepth 0 -mmin +5 2>/dev/null)" ] && return 0
	[ -f "$ST_TCH_ERR" ] && [ "$(_st_age "$ST_TCH_ERR")" -lt 1800 ] && return 0
	[ -s "$ST_TCH_META" ] && [ "$(_st_age "$ST_TCH_META")" -lt 21600 ] && [ "$RB_SHARE/services.conf" -ot "$ST_TCH_META" ] && return 0
	( _st_tch_refresh force >/dev/null 2>&1 & )
}

_st_tch_busy() {
	[ -d "$ST_RUN/tch.lock" ] && [ -z "$(find "$ST_RUN/tch.lock" -maxdepth 0 -mmin +5 2>/dev/null)" ] && return 0
	[ -f "$ST_RUN/tch.pending" ] && [ -z "$(find "$ST_RUN/tch.pending" -maxdepth 0 -mmin +5 2>/dev/null)" ]
}

_st_tch_json() {
	local d="" n=0 x=0 p=0 k=0 t=0 g=0
	[ -s "$ST_TCH_META" ] && { d="$(sed -n 's/^version=//p' "$ST_TCH_META")"; n="$(sed -n 's/^lists=//p' "$ST_TCH_META")"; x="$(sed -n 's/^direct=//p' "$ST_TCH_META")"; p="$(sed -n 's/^plus=//p' "$ST_TCH_META")"
		k="$(sed -n 's/^block=//p' "$ST_TCH_META")"; t="$(sed -n 's/^total=//p' "$ST_TCH_META")"; g="$(sed -n 's/^big=//p' "$ST_TCH_META")"; }
	printf '{"on":%s,"version":"%s","lists":%s,"direct":%s,"plus":%s,"block":%s,"big":%s,"total":%s,"age":%s,"error":%s,"busy":%s,"url":"%s"}' \
		"$(_st_tch_on && echo true || echo false)" "$(esc "$d")" "${n:-0}" "${x:-0}" "${p:-0}" "${k:-0}" "${g:-0}" "${t:-0}" "$([ -s "$ST_TCH_META" ] && _st_age "$ST_TCH_META" || echo -1)" \
		"$([ -f "$ST_TCH_ERR" ] && echo true || echo false)" "$(_st_tch_busy && echo true || echo false)" "$ST_TCH_REPO"
}

_st_cat_bg() {
	_st_tch_bg
	_st_owncat_bg
	[ -f "$ST_CAT_OFF" ] && return 0
	[ -d "$ST_RUN/cat.lock" ] && [ -z "$(find "$ST_RUN/cat.lock" -maxdepth 0 -mmin +5 2>/dev/null)" ] && return 0
	if grep -q '|Свои списки каталога$' "$ST_CAT_SVC" 2>/dev/null; then ( _st_cat_refresh force >/dev/null 2>&1 & ); return 0; fi
	[ -f "$ST_DIR/catalog.err" ] && [ $(( $(date +%s) - $(awk '{ print $1 + 0; exit }' "$ST_DIR/catalog.err" 2>/dev/null | grep . || echo 0) )) -lt 1800 ] && return 0
	if [ -s "$ST_CAT_SVC" ] && [ "$RB_SHARE/services.conf" -nt "$ST_CAT_SVC" ]; then
		if [ -s "$ST_RUN/lists.json" ] && mkdir "$ST_RUN/cat.lock" 2>/dev/null; then
			_st_cat_build "$ST_RUN/lists.json"; local rc=$?
			rmdir "$ST_RUN/cat.lock" 2>/dev/null
			[ "$rc" = 0 ] && return 0
		fi
		( _st_cat_refresh force >/dev/null 2>&1 & )
		return 0
	fi
	[ -s "$ST_CAT_SVC" ] && [ $(( $(date +%s) - $(date -r "$ST_CAT_SVC" +%s 2>/dev/null || echo 0) )) -lt 21600 ] && return 0
	( _st_cat_refresh >/dev/null 2>&1 & )
}

_st_cat_json() {
	local ver="" sets=0 svcs=0 err=false off=false src
	[ -s "$ST_CAT_META" ] && { ver="$(sed -n 's/^version=//p' "$ST_CAT_META")"; sets="$(sed -n 's/^sets=//p' "$ST_CAT_META")"; svcs="$(sed -n 's/^services=//p' "$ST_CAT_META")"; }
	[ -f "$ST_DIR/catalog.err" ] && err=true
	[ -f "$ST_CAT_OFF" ] && off=true
	src="$(_st_cat_src)"
	printf '{"url":"%s","custom":%s,"version":"%s","sets":%s,"services":%s,"error":%s,"off":%s,"busy":%s,"tachyon":%s,"own":%s,"own_max":%s}' \
		"$(esc "$src")" "$([ -s "$ST_CAT_URL" ] && echo true || echo false)" "$(esc "$ver")" "${sets:-0}" "${svcs:-0}" "$err" "$off" \
		"$([ -d "$ST_RUN/cat.lock" ] && echo true || echo false)" "$(_st_tch_json)" "$(_st_own_json)" "$ST_OWN_MAX"
}

_st_own_used() {
	local id="$1" u w=""
	case "$id" in
		zmc[0-9]*)
			grep -qs "^${id}_" "$ST_DIR/services" "$ST_SEC_DIR"/*/services && w="Steer"
			for u in $(awk -F'|' -v k="${id}_" 'index($1, k) == 1 { print $3 }' "$ST_OWN_CIDX" 2>/dev/null); do
				grep -qsF "$u" /etc/config/netshift && { w="${w:+$w, }Forkozz"; break; }
			done ;;
		*)
			grep -qsx "$id" "$ST_DIR/services" "$ST_SEC_DIR"/*/services && w="Steer"
			u="$(awk -F'|' -v k="$id" '$1 == k { print $3; exit }' "$ST_OWN_IDX" 2>/dev/null)"
			[ -n "$u" ] && grep -qsF "$u" /etc/config/netshift && w="${w:+$w, }Forkozz" ;;
	esac
	printf '%s' "$w"
}

_st_own_json() {
	local id fmt url kind n dom pfx name sep="" w
	printf '['
	while IFS='|' read -r id fmt url kind n dom pfx; do
		[ -n "$id" ] || continue
		name="$(awk -F'|' -v k="$id" '$1 == k { print $2; exit }' "$ST_OWN_SVC" 2>/dev/null)"
		w="$(_st_own_used "$id")"
		printf '%s{"id":"%s","kind":"list","name":"%s","url":"%s","fmt":"%s","dom":%s,"pfx":%s,"used":"%s"}' "$sep" "$id" "$(esc "${name:-$id}")" "$(esc "$url")" "$fmt" "${dom:-0}" "${pfx:-0}" "$(esc "$w")"
		sep=","
	done 2>/dev/null < "$ST_OWN_IDX"
	local sets svcs ver ts
	while IFS='|' read -r id name url sets svcs ver ts; do
		[ -n "$id" ] || continue
		w="$(_st_own_used "$id")"
		printf '%s{"id":"%s","kind":"catalog","name":"%s","url":"%s","sets":%s,"svcs":%s,"version":"%s","age":%s,"used":"%s"}' "$sep" "$id" "$(esc "$name")" "$(esc "$url")" "${sets:-0}" "${svcs:-0}" "$(esc "$ver")" "$(( $(date +%s) - ${ts:-0} ))" "$(esc "$w")"
		sep=","
	done 2>/dev/null < "$ST_OWN_CATS"
	printf ']'
}

_st_own_desc() {
	local d="$1" p="$2" o=""
	[ "$d" -gt 0 ] && o="$d $(_zm_plural "$d" домен домена доменов)"
	[ "$p" -gt 0 ] && o="${o:+$o · }$p $(_zm_plural "$p" подсеть подсети подсетей)"
	[ -n "$o" ] || o="набор правил sing-box (.srs)"
	printf '%s' "$o"
}

_st_own_url() {
	printf '%s' "$1" | sed 's#^https://github\.com/\([^/]*\)/\([^/]*\)/\(blob\|raw\)/#https://raw.githubusercontent.com/\1/\2/#'
}

_st_own_probe() {
	local u="$1" f="$ST_RUN/own.probe.$$" d p h
	mkdir -p "$ST_RUN"
	rm -f "$f" "$f.n"
	if ! _st_fetch "$u" "$f" && ! { _st_cdn_url "$u" >/dev/null && _st_fetch "$(_st_cdn_url "$u")" "$f"; }; then
		rm -f "$f"; echo "ERR:список по этой ссылке не скачался — проверьте ссылку и доступ к сайту"; return 1
	fi
	if [ "$(wc -c < "$f")" -gt 16777216 ]; then rm -f "$f"; echo "ERR:файл больше 16 МБ — для роутера это слишком много"; return 1; fi
	h="$(head -c 3 "$f")"
	case "${u%%[?#]*}" in
		*.srs)
			rm -f "$f"
			[ "$h" = SRS ] || { echo "ERR:по ссылке не набор правил sing-box (.srs)"; return 1; }
			echo "srs 0 0"; return 0 ;;
	esac
	[ "$h" = SRS ] && { rm -f "$f"; echo "srs 0 0"; return 0; }
	tr -d '\r' < "$f" | sed 's/[[:space:]]*#.*$//; s/^[[:space:]]*//; s/[[:space:]]*$//' | tr 'A-Z' 'a-z' > "$f.n"
	p="$(grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$f.n" | awk '!s[$0]++' | wc -l | tr -d ' ')"
	d="$(sed 's/^domain://; s/^full://; s/^suffix://; s/^\*\.//; s/^\.//' "$f.n" |
		grep -E '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$' | grep -vE '^[0-9.]+$' | awk '!s[$0]++' | wc -l | tr -d ' ')"
	if [ "$d" = 0 ] && [ "$p" = 0 ]; then
		if grep -qiE '<html|<!doctype' "$f"; then echo "ERR:по ссылке открылась веб-страница, а не список — нужна прямая ссылка на файл (на GitHub — кнопка «Raw»)"
		elif grep -qE '^[[:space:]]*[{[]' "$f"; then
			if grep -q '"domain_lists"\|"categories"' "$f" && cp -f "$f" "$ST_RUN/own.cat.new" && _st_owncat_build "$ST_RUN/own.cat.new" zmc0 x; then
				rm -f "$f" "$f.n" "$ST_RUN"/owncat.*
				echo "cat 0 0"; return 0
			fi
			rm -f "$ST_RUN/own.cat.new" "$ST_RUN"/owncat.*
			echo "ERR:это файл JSON, но не каталог списков — нужен каталог в формате splify2-lists (lists.json) или текстовый список: один домен или подсеть на строке"
		elif grep -qE '^(0\.0\.0\.0|127\.0\.0\.1)[[:space:]]+[a-z0-9]' "$f.n"; then echo "ERR:это файл hosts — нужен список, где на строке только домен или подсеть"
		elif grep -qE '^\|\|' "$f.n"; then echo "ERR:это фильтр блокировщика рекламы — нужен список, где на строке только домен или подсеть"
		else echo "ERR:в файле не нашлось ни доменов, ни подсетей IPv4 — на строке должен быть один домен или подсеть"; fi
		rm -f "$f" "$f.n"; return 1
	fi
	rm -f "$f" "$f.n"
	[ $((d + p)) -gt 150000 ] && { echo "ERR:в списке $((d + p)) записей — больше 150 тыс. роутеру не по силам"; return 1; }
	echo "lst $d $p"
}

_st_own_taken() {
	awk -F'|' -v nm="$1" -v k="$2" '
		function lc(x,    i) { x = tolower(x); for (i = 1; i <= 33; i++) gsub(U[i], L[i], x); return x }
		BEGIN { n = split("А Б В Г Д Е Ё Ж З И Й К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ъ Ы Ь Э Ю Я", U, " "); split("а б в г д е ё ж з и й к л м н о п р с т у ф х ц ч ш щ ъ ы ь э ю я", L, " "); nm = lc(nm) }
		$1 != k && lc($2) == nm { f = 1 } END { exit !f }' $(for f in "$ST_OWN_SVC" "$ST_OWN_CATS"; do [ -f "$f" ] && echo "$f"; done) /dev/null 2>/dev/null
}

_st_own_dname() {
	local n
	n="$(printf '%s' "$1" | sed -n 's#^https://raw\.githubusercontent\.com/\([^/]*\)/\([^/]*\)/.*#\1/\2#p; s#^https://github\.com/\([^/]*\)/\([^/]*\)/.*#\1/\2#p' | head -n1)"
	[ -n "$n" ] && [ "$2" = cat ] && { printf '%s' "$n"; return; }
	n="${1%%[?#]*}"; n="${n##*/}"; n="${n%.*}"
	printf '%s' "${n:-Мой список}"
}

_st_owncat_put() {
	local id="$1" name="$2" url="$3" svcs sets ver
	_st_owncat_build "$ST_RUN/own.cat.new" "$id" "$name" || return 1
	svcs="$(grep -c . "$ST_RUN/owncat.svc")"; sets="$(grep -c . "$ST_RUN/owncat.idx")"
	ver="$(sed -n 's/^version=//p' "$ST_RUN/owncat.meta" | tr -d '|')"
	mkdir -p "$ST_DIR"
	{ grep -v "^${id}_" "$ST_OWN_CSVC" 2>/dev/null; cat "$ST_RUN/owncat.svc"; } > "$ST_OWN_CSVC.t" && mv -f "$ST_OWN_CSVC.t" "$ST_OWN_CSVC"
	{ grep -v "^${id}_" "$ST_OWN_CIDX" 2>/dev/null; cat "$ST_RUN/owncat.idx"; } > "$ST_OWN_CIDX.t" && mv -f "$ST_OWN_CIDX.t" "$ST_OWN_CIDX"
	{ grep -v "^$id|" "$ST_OWN_CATS" 2>/dev/null; printf '%s|%s|%s|%s|%s|%s|%s\n' "$id" "$name" "$url" "$sets" "$svcs" "$ver" "$(date +%s)"; } > "$ST_OWN_CATS.t" && mv -f "$ST_OWN_CATS.t" "$ST_OWN_CATS"
	rm -f "$ST_RUN"/owncat.* "$ST_RUN/own.cat.new"
	_st_tch_idx_merge
	OWNCAT_SVCS="$svcs"
	return 0
}

_st_owncat_refresh() {
	local id name url rest r rc=0
	[ -s "$ST_OWN_CATS" ] || return 0
	while IFS='|' read -r id name url rest; do
		[ -n "$id" ] || continue
		[ -n "$1" ] && [ "$1" != "$id" ] && continue
		r="$ST_RUN/own.cat.new"
		if _st_fetch "$url" "$r" || { _st_cdn_url "$url" >/dev/null && _st_fetch "$(_st_cdn_url "$url")" "$r"; }; then
			_st_owncat_put "$id" "$name" "$url" || { rm -f "$r"; rc=1; }
		else rm -f "$r"; rc=1; fi
	done < "$ST_OWN_CATS"
	return $rc
}

_st_owncat_bg() {
	[ -s "$ST_OWN_CATS" ] || return 0
	[ -d "$ST_RUN/owncat.lock" ] && [ -z "$(find "$ST_RUN/owncat.lock" -maxdepth 0 -mmin +5 2>/dev/null)" ] && return 0
	[ "$(_st_age "$ST_OWN_CATS")" -lt 86400 ] && return 0
	mkdir -p "$ST_RUN"; rmdir "$ST_RUN/owncat.lock" 2>/dev/null; mkdir "$ST_RUN/owncat.lock" 2>/dev/null || return 0
	( _st_owncat_refresh; touch "$ST_OWN_CATS"; rmdir "$ST_RUN/owncat.lock" ) >/dev/null 2>&1 &
}

_st_own_add() {
	local in="$1" u name r fmt d p n id kind x
	u="$(printf '%s' "$in" | jsonfilter -e '@.url' 2>/dev/null | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
	name="$(printf '%s' "$in" | jsonfilter -e '@.name' 2>/dev/null | tr -d '\000-\037|"\\' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
	case "$u" in https://?*) ;; http://*) echo '{"error":"нужна ссылка https:// — по http список могут подменить по дороге"}'; return 1 ;; *) echo '{"error":"нужна ссылка вида https://…/список.txt"}'; return 1 ;; esac
	case "$u" in *[[:space:]\"\'\\\`\$\;\|\<\>]*) echo '{"error":"недопустимые символы в ссылке"}'; return 1 ;; esac
	[ "${#u}" -le 500 ] || { echo '{"error":"слишком длинная ссылка"}'; return 1; }
	u="$(_st_own_url "$u")"
	[ "${#name}" -le 120 ] || { echo '{"error":"слишком длинное название"}'; return 1; }
	case "${u%%[?#]*}" in *.json) [ -n "$name" ] || name="$(_st_own_dname "$u" cat)" ;; *) [ -n "$name" ] || name="$(_st_own_dname "$u")" ;; esac
	x="$(awk -F'|' -v u="$u" '$3 == u { print $1; exit }' "$ST_OWN_IDX" 2>/dev/null)"
	[ -n "$x" ] && { printf '{"error":"этот список уже добавлен — «%s»"}\n' "$(esc "$(awk -F'|' -v k="$x" '$1 == k { print $2; exit }' "$ST_OWN_SVC")")"; return 1; }
	x="$(awk -F'|' -v u="$u" '$3 == u { print $2; exit }' "$ST_OWN_CATS" 2>/dev/null)"
	[ -n "$x" ] && { printf '{"error":"этот каталог уже добавлен — «%s»"}\n' "$(esc "$x")"; return 1; }
	_st_own_taken "$name" "" && { echo '{"error":"список с таким названием уже есть — назовите его иначе"}'; return 1; }
	r="$(_zm_run 17 _st_own_probe "$u")"
	case $? in
		0) ;;
		137|143) rm -f "$ST_RUN"/own.probe.*; echo '{"error":"список не успел скачаться за 17 секунд — проверьте ссылку или попробуйте позже"}'; return 1 ;;
		*) r="$(printf '%s\n' "$r" | sed -n 's/^ERR://p' | head -n1)"; printf '{"error":"%s"}\n' "$(esc "${r:-список не скачался}")"; return 1 ;;
	esac
	set -- $(printf '%s\n' "$r" | tail -n1); fmt="$1"; d="${2:-0}"; p="${3:-0}"
	[ "$fmt" = cat ] || [ "$(grep -c . "$ST_OWN_IDX" 2>/dev/null || echo 0)" -lt "$ST_OWN_MAX" ] || { echo "{\"error\":\"своих списков уже $ST_OWN_MAX — удалите ненужный\"}"; return 1; }
	if [ "$fmt" = cat ]; then
		[ "$(grep -c . "$ST_OWN_CATS" 2>/dev/null || echo 0)" -lt "$ST_OWN_CMAX" ] || { rm -f "$ST_RUN/own.cat.new"; echo "{\"error\":\"своих каталогов уже $ST_OWN_CMAX — удалите ненужный\"}"; return 1; }
		name="$(printf '%s' "$name" | tr -d '()')"
		n="$(awk -F'|' '{ sub(/^zmc/, "", $1); if ($1 + 0 > m) m = $1 + 0 } END { print m + 1 }' "$ST_OWN_CATS" 2>/dev/null)"
		id="zmc${n:-1}"
		_st_owncat_put "$id" "$name" "$u" || { rm -f "$ST_RUN/own.cat.new"; echo '{"error":"в каталоге не нашлось ни одного списка"}'; return 1; }
		printf '{"ok":true,"id":"%s","kind":"catalog","name":"%s","svcs":%s}\n' "$id" "$(esc "$name")" "${OWNCAT_SVCS:-0}"
		return 0
	fi
	case "$fmt" in lst|srs) ;; *) echo '{"error":"список не скачался"}'; return 1 ;; esac
	n="$(awk -F'|' '{ sub(/^zmu_/, "", $1); if ($1 + 0 > m) m = $1 + 0 } END { print m + 1 }' "$ST_OWN_IDX" 2>/dev/null)"
	id="zmu_${n:-1}"
	kind=d; [ "$d" = 0 ] && kind=s
	[ "$fmt" = srs ] && kind=s
	mkdir -p "$ST_DIR"
	printf '%s|%s|%s|%s|%s|%s|%s\n' "$id" "$fmt" "$u" "$kind" "$((d + p))" "$d" "$p" >> "$ST_OWN_IDX"
	printf '%s|%s||||||%s|%s|%s\n' "$id" "$name" "$id" "$ST_OWN_GRP" "$(_st_own_desc "$d" "$p")" >> "$ST_OWN_SVC"
	rm -f "$ST_DIR/lists/$id".*
	_st_tch_idx_merge
	printf '{"ok":true,"id":"%s","name":"%s","dom":%s,"pfx":%s,"fmt":"%s"}\n' "$id" "$(esc "$name")" "$d" "$p" "$fmt"
}

_st_own_del() {
	local id="$1" w
	case "$id" in
		zmc[0-9]*)
			grep -q "^$id|" "$ST_OWN_CATS" 2>/dev/null || { echo '{"error":"нет такого каталога — обновите страницу"}'; return 1; }
			w="$(_st_own_used "$id")"
			[ -n "$w" ] && { printf '{"error":"списки этого каталога включены в %s — снимите с них отметки, сохраните и удалите снова"}\n' "$w"; return 1; }
			grep -v "^$id|" "$ST_OWN_CATS" > "$ST_OWN_CATS.t"; mv -f "$ST_OWN_CATS.t" "$ST_OWN_CATS"
			grep -v "^${id}_" "$ST_OWN_CSVC" > "$ST_OWN_CSVC.t" 2>/dev/null; mv -f "$ST_OWN_CSVC.t" "$ST_OWN_CSVC"
			grep -v "^${id}_" "$ST_OWN_CIDX" > "$ST_OWN_CIDX.t" 2>/dev/null; mv -f "$ST_OWN_CIDX.t" "$ST_OWN_CIDX"
			[ -s "$ST_OWN_CATS" ] || rm -f "$ST_OWN_CATS" "$ST_OWN_CSVC" "$ST_OWN_CIDX"
			rm -f "$ST_DIR/lists/${id}_"* "$ST_RUN/dom/${id}_"*
			grep -v "^${id}_" "$ST_DOMCNT" > "$ST_DOMCNT.t" 2>/dev/null && mv -f "$ST_DOMCNT.t" "$ST_DOMCNT"
			_st_tch_idx_merge
			printf '{"ok":true}\n'; return 0 ;;
		zmu_[0-9]*) ;;
		*) echo '{"error":"нет такого списка"}'; return 1 ;;
	esac
	grep -q "^$id|" "$ST_OWN_IDX" 2>/dev/null || { echo '{"error":"нет такого списка — обновите страницу"}'; return 1; }
	w="$(_st_own_used "$id")"
	[ -n "$w" ] && { printf '{"error":"список включён в %s — снимите с него отметку, сохраните и удалите снова"}\n' "$w"; return 1; }
	grep -v "^$id|" "$ST_OWN_IDX" > "$ST_OWN_IDX.t" ; mv -f "$ST_OWN_IDX.t" "$ST_OWN_IDX"
	grep -v "^$id|" "$ST_OWN_SVC" > "$ST_OWN_SVC.t" 2>/dev/null; mv -f "$ST_OWN_SVC.t" "$ST_OWN_SVC"
	[ -s "$ST_OWN_IDX" ] || rm -f "$ST_OWN_IDX" "$ST_OWN_SVC"
	rm -f "$ST_DIR/lists/$id".* "$ST_RUN/dom/$id".*
	grep -v "^$id " "$ST_DOMCNT" > "$ST_DOMCNT.t" 2>/dev/null && mv -f "$ST_DOMCNT.t" "$ST_DOMCNT"
	_st_tch_idx_merge
	printf '{"ok":true}\n'
}

_st_own_ren() {
	local id name
	id="$(printf '%s' "$1" | jsonfilter -e '@.id' 2>/dev/null)"
	name="$(printf '%s' "$1" | jsonfilter -e '@.name' 2>/dev/null | tr -d '\000-\037|"\\' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
	case "$id" in zmu_[0-9]*|zmc[0-9]*) ;; *) echo '{"error":"нет такого списка"}'; return 1 ;; esac
	case "$id" in zmc*) name="$(printf '%s' "$name" | tr -d '()')"; grep -q "^$id|" "$ST_OWN_CATS" 2>/dev/null ;; *) grep -q "^$id|" "$ST_OWN_SVC" 2>/dev/null ;; esac || { echo '{"error":"нет такого списка — обновите страницу"}'; return 1; }
	[ -n "$name" ] || { echo '{"error":"название не может быть пустым"}'; return 1; }
	[ "${#name}" -le 120 ] || { echo '{"error":"слишком длинное название"}'; return 1; }
	_st_own_taken "$name" "$id" && { echo '{"error":"список с таким названием уже есть"}'; return 1; }
	case "$id" in
		zmc*)
			local old
			old="$(awk -F'|' -v k="$id" '$1 == k { print $2; exit }' "$ST_OWN_CATS")"
			awk -F'|' -v OFS='|' -v nm="$name" -v k="$id" '$1 == k { $2 = nm } { print }' "$ST_OWN_CATS" > "$ST_OWN_CATS.t" && mv -f "$ST_OWN_CATS.t" "$ST_OWN_CATS"
			awk -F'|' -v OFS='|' -v nm="$name" -v o="$old (" -v k="${id}_" 'index($1, k) == 1 && index($9, o) == 1 { $9 = nm " (" substr($9, length(o) + 1) } { print }' "$ST_OWN_CSVC" > "$ST_OWN_CSVC.t" && mv -f "$ST_OWN_CSVC.t" "$ST_OWN_CSVC" ;;
		*) awk -F'|' -v OFS='|' -v nm="$name" -v k="$id" '$1 == k { $2 = nm } { print }' "$ST_OWN_SVC" > "$ST_OWN_SVC.t" && mv -f "$ST_OWN_SVC.t" "$ST_OWN_SVC" ;;
	esac
	printf '{"ok":true}\n'
}

ST_LISTS_TAG="# zm-stlists"
ST_LISTS_OFF="$ST_DIR/lists.auto.off"
ST_LISTS_LAST="$ST_DIR/lists.last"
ST_LISTS_CMD="/opt/zapret-manager-luci/backend.sh steer_action lists_bg all >/dev/null 2>&1"

_st_set_count() { local f n=0; for f in "$ST_RUN"/$1.*; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }

_st_lists_used() {
	local how="$1" ids s
	shift
	ids="$*"
	for s in $(_st_secs); do
		if [ "$how" = live ]; then _st_sec_live "$s" || continue; else _st_sec_off "$s" && continue; fi
		ids="$ids $(_st_sec_with "$s" _st_sel | tr '\n' ' ')"
	done
	[ -n "$(echo $ids)" ] || return 0
	{ _rb_svc_src | awk -F'|' -v ids=" $(echo $ids) " 'index(ids, " " $1 " ") && !seen[$1]++ { print $8 }'
	  [ -f "$ST_TCH_OFF" ] || awk -F'|' -v ids=" $(echo $ids) " 'index(ids, " " $1 " ") { print $2 }' "$ST_TCH_PLUS" 2>/dev/null; } |
		tr ',' '\n' | grep -E '^[A-Za-z0-9_-]+$' | awk '!s[$0]++'
}

_st_kick() { _st_sec_with main _st_kick0; }

ST_CRON_KEEP="$ST_DIR/autorestart"

_st_cron_get() {
	local line hour min
	line=$(grep -F "$ST_CRON_TAG" "$CRON_FILE" 2>/dev/null | head -n1)
	[ -n "$line" ] || return 0
	min=$(echo "$line" | awk '{print $1}')
	hour=$(echo "$line" | awk '{print $2}')
	case "$min" in */*) echo "everym:${min#*/}"; return 0 ;; esac
	case "$hour" in
		*/*) echo "every:${hour#*/}" ;;
		*)
			case "$min" in ''|0|00|*[!0-9]*) echo "daily:$hour" ;; ?) echo "daily:$hour:0$min" ;; *) echo "daily:$hour:$min" ;; esac ;;
	esac
}

ST_HEAL_STAMP="$ST_DIR/heal.reinstall"
ST_HEAL_CAUSE="$ST_DIR/heal.cause"

_st_own_saved() { [ -s "$ST_WARP_OWN" ] || [ -s "$ST_WARP_OWN_KEEP" ]; }

ST_WFIX="$ST_DIR/wfix"
ST_WFIX_STATE="$ST_DIR/wfix.state"
ST_WFIX_LOG="$ST_DIR/wfix.log"
ST_WFIX_TAG="# zm-wfix"
ST_WFIX_TRIES=4

_st_wfix_say() {
	mkdir -p "$ST_DIR"
	{ tail -n 19 "$ST_WFIX_LOG" 2>/dev/null; echo "$(date +%s)|$1"; } > "$ST_WFIX_LOG.tmp" && mv -f "$ST_WFIX_LOG.tmp" "$ST_WFIX_LOG"
	logger -t zm-steer "автоподбор: $1" 2>/dev/null
}

_st_wfix_get() { awk -v i="$1" -v f="$2" '$1 == i { print $f; exit }' "$ST_WFIX_STATE" 2>/dev/null; }

_st_wfix_hs() { awg show "$1" latest-handshakes 2>/dev/null | awk '{ print $2 + 0; exit }'; }

_st_wfix_net_ok() {
	ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 || ping -c 2 -W 3 8.8.8.8 >/dev/null 2>&1 ||
		curl -s -o /dev/null --connect-timeout 5 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
}

_st_wfix_min() { local m; m="$(cat "$ST_WFIX" 2>/dev/null)"; case "$m" in 30|60|180) echo "$m" ;; *) echo "" ;; esac; }

_st_wfix_json() {
	local m out="" sep="" i since tries last t txt n fixing=""
	m="$(_st_wfix_min)"
	if [ -s "$ST_WFIX_STATE" ]; then
		while read -r i since tries last; do
			[ -n "$i" ] || continue
			case "$i" in zmwarp) n=1 ;; *) n="${i#zmwarp}" ;; esac
			out="$out$sep{\"n\":${n:-0},\"since\":${since:-0},\"tries\":${tries:-0},\"last\":${last:-0}}"; sep=","
		done < "$ST_WFIX_STATE"
	fi
	_st_running && [ -s "$ST_RUN/wfix.busy" ] && fixing="$(cat "$ST_RUN/wfix.busy")"
	printf '{"mode":"%s","max":%s,"now":%s,"last_check":%s,"fixing":"%s","dead":[%s],"log":[' "${m:-off}" "$ST_WFIX_TRIES" "$(date +%s)" \
		"$(awk '{ print $1 + 0; exit }' "$ST_RUN/wfix.last" 2>/dev/null | grep . || echo 0)" "$fixing" "$out"
	sep=""
	[ -s "$ST_WFIX_LOG" ] && tail -n 5 "$ST_WFIX_LOG" | while IFS='|' read -r t txt; do
		printf '%s{"t":%s,"text":"%s"}' "$sep" "${t:-0}" "$(esc "$txt")"; sep=","
	done
	printf ']}'
}

_st_respec() {
	local rc
	if _st_use_vpn; then _st_spec_quick; else _st_spec_quick_warp; fi
	rc=$?
	[ "$rc" = 0 ] && { echo "   ✓ Правила обновлены, списки сервисов не перекачивались"; return 0; }
	_st_kick
}

do_steer_apply() {
	_st_phase rules
	rm -f "$ST_STOP_FLAG"
	_st_installed || { echo "ОШИБКА: Steer ещё не установлен"; return 1; }
	[ -n "$(_st_blocker)" ] && { echo "ОШИБКА: настройку ядра steer сейчас ведёт не Zapret Manager"; return 1; }
	rm -f "$ST_OFF"
	_st_nopq_sync
	_st_ifs_up
	_st_apply || return 1
	_st_lists_cron_sync >/dev/null 2>&1
	_st_phase check
	sleep 2
	_st_selfcheck
	_rb_say "Готово"
}

_st_active_if() {
	[ "$(_st_exit)" = vpn ] && return 0
	_st_owns "steer-spec" && stl_running && stl_state warp || return 0
	[ "$STL_FAILED" = true ] || printf '%s' "$STL_DEV"
}

ST_USER_DIR="$ST_DIR/user"
ST_CUSTOM="$ST_USER_DIR/custom"

ST_DOMCNT="$ST_DIR/domcount"

ST_VPN_ZONE="zmvpn"
ST_VDIR="$ST_DIR"
ST_SUB="$ST_DIR/sub.txt"
ST_SUB_INFO="$ST_DIR/sub.userinfo"
ST_SUB_URL="$ST_DIR/sub.url"
ST_SUB_TITLE="$ST_DIR/sub.title"
ST_SUB_NODE="$ST_DIR/sub.node"
ST_SUB_GRP="$ST_DIR/sub.group"
ST_SUB_GRPS="$ST_DIR/sub.autogrp"
ST_SUB_EXCL="$ST_DIR/sub.exclude"
ST_SUB_HIDE="$ST_DIR/sub.hidden"
ST_SUB_NOAUTO="$ST_DIR/sub.noauto"; ST_SUB_NOAUTO_MK="$ST_DIR/sub.noauto.mk"
ST_EXIT="$ST_DIR/exit"

_st_exit() {
	local e
	if [ -n "$ST_SEC" ]; then
		case "$(_st_sec_kind "$ST_SEC")" in
			vpn) if [ -s "$ST_SUB" ] && _st_vpn_ok; then echo vpn; else echo none; fi ;;
			iface) if _st_sec_live "$ST_SEC"; then echo iface; else echo none; fi ;;
			*) if _st_warp_on; then echo warp; else echo none; fi ;;
		esac
		return
	fi
	e="$(cat "$ST_EXIT" 2>/dev/null)"
	if [ "$e" = iface ] && _st_tun_live "$(_st_main_iface)"; then echo iface; return; fi
	if [ "$e" = vpn ] && [ -s "$ST_SUB" ] && _st_vpn_ok; then echo vpn; return; fi
	if _st_warp_on; then echo warp; return; fi
	if [ -s "$ST_SUB" ] && _st_vpn_ok; then echo vpn; return; fi
	echo none
}
_st_use_vpn() { [ "$(_st_exit)" = vpn ]; }

ST_VPN_PROBE="$JOBS_DIR/steer.vpnprobe"
_st_vpn_probe() {
	local trace ip="" loc="" r=fail dev
	ST_VPN_STUCK=""
	if dev="$(_st_vpn_dev)"; then
		trace="$(_st_vpn_trace "$dev")"
		ip="$(echo "$trace" | sed -n 's/^ip=//p')"; loc="$(echo "$trace" | sed -n 's/^loc=//p')"
		{ [ -n "$ip" ] || [ "$trace" = alive=1 ] || [ "${trace#probe=}" != "$trace" ]; } && r=ok
		if [ "$r" = ok ] && stl_running && stl_state vpn >/dev/null 2>&1 && [ -n "$STL_KIND" ] && [ "$STL_UP" != true ]; then
			# Ответил не тот путь: устройство другого протокола подписки или запасной узел пула. Ядро же
			# говорит, что узел выхода упал, — значит, VPN не работает, и сторожу пора переходить на рабочий
			if [ -n "$STL_NWHY" ] || [ "$STL_PSTATE" = failed ] || [ "$STL_PSTATE" = no_such_node ]; then r=fail
			else r=stuck; ST_VPN_STUCK=1; fi
		fi
	fi
	mkdir -p "$ZM_STATE_DIR"
	echo "$(date +%s) $r $ip $loc" > "$ST_VPN_PROBE"
	[ "$r" = ok ]
}
_st_vpn_live() {
	local t r age
	read -r t r _ 2>/dev/null < "$ST_VPN_PROBE"
	age=$(( $(date +%s) - ${t:-0} ))
	if [ "$age" -gt 120 ] || [ "$age" -lt 0 ]; then
		if mkdir "$ST_VPN_PROBE.lock" 2>/dev/null; then
			( _st_vpn_probe >/dev/null 2>&1; rmdir "$ST_VPN_PROBE.lock" ) >/dev/null 2>&1 &
		elif [ -n "$(find "$ST_VPN_PROBE.lock" -mmin +1 2>/dev/null)" ]; then
			rmdir "$ST_VPN_PROBE.lock" 2>/dev/null
		fi
	fi
	[ -z "$r" ] && return 2
	[ "$age" -gt 600 ] && return 2
	[ "$r" = ok ]
}

_st_sub_label() {
	[ -s "$ST_SUB" ] || return 0
	if [ -s "$ST_SUB_TITLE" ]; then
		case "$(head -n1 "$ST_SUB_TITLE")" in
			*🌨*VPN*) echo "StressKVN" ;;
			*) head -n1 "$ST_SUB_TITLE" ;;
		esac
	elif [ -s "$ST_SUB_URL" ]; then sed -n 's#^[a-z]*://\([^/:?]*\).*#\1#p' "$ST_SUB_URL" | head -n1
	else echo "свои ссылки"; fi
}

ZM_FOLD_AWK='function fold(x,  k) { x = tolower(x); for (k = 1; k <= nU; k++) gsub(U[k], L[k], x); return x }
BEGIN { nU = split("А Б В Г Д Е Ё Ж З И Й К Л М Н О П Р С Т У Ф Х Ц Ч Ш Щ Ъ Ы Ь Э Ю Я", U, " "); split("а б в г д е ё ж з и й к л м н о п р с т у ф х ц ч ш щ ъ ы ь э ю я", L, " ") }'

_zm_json_lines() {
	local l sep=""
	[ -s "$1" ] || return 0
	while IFS= read -r l || [ -n "$l" ]; do
		[ -n "$l" ] || continue
		printf '%s"%s"' "$sep" "$(esc "$l")"; sep=","
	done < "$1"
}

_zm_names_save() {
	local src="$1" dst="$2"
	awk 'length($0) > 0 && length($0) <= 400 && !s[$0]++' "$src" 2>/dev/null | head -n 300 > "$dst.tmp"
	if [ -s "$dst.tmp" ]; then mv -f "$dst.tmp" "$dst"; else rm -f "$dst.tmp" "$dst"; fi
}

_zm_excl_save() {
	local m="$2" f="$1"
	case "$m" in *"
"*|*"$(printf '\r')"*) echo "маркеры — одной строкой через |"; return 1 ;; esac
	[ "${#m}" -le 1600 ] || { echo "слишком длинный список маркеров"; return 1; }
	mkdir -p "$(dirname "$f")"
	rm -f "$f.v"
	if [ -z "$(printf '%s' "$m" | tr -d ' |,')" ]; then rm -f "$f"; return 0; fi
	printf '%s\n' "$m" > "$f"
}

ST_SUB_NODES="$ST_DIR/sub.nodes"

_st_vpn_dev() {
	local d
	stl_state vpn >/dev/null 2>&1 && [ -n "$STL_DEV" ] && [ -d "/sys/class/net/$STL_DEV" ] && { echo "$STL_DEV"; return 0; }
	for d in $STL_VPN_DEVS; do [ -d "/sys/class/net/$d" ] && { echo "$d"; return 0; }; done
	return 1
}
_stl_redir_dev() {
	case "$1" in zm_vpn|zm_vpn[2-9]|zmv_*|zmv[2-9]_*) ;; *) return 1 ;; esac
	[ -n "$STL_VER_C" ] || STL_VER_C="$(stl_version)"
	_stl_ver_ok "$STL_VER_C" && ! _st_ver_lt "$STL_VER_C" 2.1.0
}

_st_vpn_node_probe() {
	local o="$1" p m j idx i2 try ok ms
	p="$(sed -n "s/.*\"$o\":{\([^}]*\)}.*/\1/p" "$STL_SPEC" 2>/dev/null | head -n 1 | sed -n 's/.*"protocol":"\([a-z0-9]*\)".*/\1/p')"
	[ -n "$p" ] || return 1
	m="$(_stl_mod_of "$p")"
	_stl_mod_x "$m" || return 1
	j="$(_stl_t 10 steer status 2>/dev/null)"
	idx="$(printf '%s' "$j" | jsonfilter -e "@.outputs.$o.$m.active[0].index" 2>/dev/null)"
	i2="$(printf '%s' "$j" | jsonfilter -e "@.outputs.$o.$m.active[1].index" 2>/dev/null)"
	case "$idx" in ''|*[!0-9]*) idx=-1 ;; esac
	case "$i2" in ''|*[!0-9]*) i2="$idx" ;; esac
	for try in 1 2; do
		j="$(_stl_t 60 steer "$m-probe" "$o" --node "$idx" --timeout 8 2>/dev/null | tr '\n' ' ')"
		ok="$(printf '%s' "$j" | jsonfilter -e '@.working' 2>/dev/null)"
		case "$ok" in ''|-*|*[!0-9]*) ;; *) break ;; esac
		[ "$try" = 1 ] || return 1
		[ "$idx" = -1 ] && return 1
		[ "$i2" = "$idx" ] && sleep 3
		idx="$i2"
	done
	ms=0
	if [ "$idx" != -1 ]; then
		ms="$(printf '%s' "$j" | jsonfilter -e '@.results[0].ttfb_ms' 2>/dev/null)"
		case "$ms" in ''|*[!0-9]*|0) ms="$(printf '%s' "$j" | jsonfilter -e '@.results[0].handshake_ms' 2>/dev/null)" ;; esac
		case "$ms" in ''|*[!0-9]*) ms=0 ;; esac
	fi
	echo "probe=$ms"
}

_st_vpn_trace() {
	local u t
	if _stl_redir_dev "$1"; then _st_vpn_node_probe "$1"; return; fi
	[ -w "/proc/sys/net/ipv4/conf/$1/rp_filter" ] && echo 2 > "/proc/sys/net/ipv4/conf/$1/rp_filter" 2>/dev/null
	for u in https://1.1.1.1/cdn-cgi/trace https://www.cloudflare.com/cdn-cgi/trace; do
		t="$(curl -4 -s --interface "$1" --connect-timeout 5 --max-time 10 "$u" 2>/dev/null)"
		case "$t" in *ip=*) printf '%s\n' "$t"; return 0 ;; esac
	done
	t="$(curl -4 -s -o /dev/null -w '%{http_code}' --interface "$1" --connect-timeout 12 --max-time 18 http://cp.cloudflare.com/generate_204 2>/dev/null)"
	case "$t" in 204|200) echo alive=1; return 0 ;; esac
	return 1
}

_st_vpn_check() {
	local w=0 tr ip loc max="${1:-90}"
	while [ "$w" -lt "$max" ]; do
		stl_state vpn >/dev/null 2>&1
		[ "$STL_UP" = true ] && [ -n "$STL_DEV" ] && [ -d "/sys/class/net/$STL_DEV" ] && break
		[ "$w" -ge 6 ] && { [ "$STL_PSTATE" = no_such_node ] || [ "$STL_PSTATE" = excluded ]; } && break
		[ "$w" -ge 20 ] && [ "$STL_PSTATE" != probing ] && { [ -n "$STL_NWHY" ] || [ "$STL_PSTATE" = failed ]; } && break
		sleep 2; w=$((w + 2))
	done
	if [ "$STL_UP" = true ] && [ -n "$STL_DEV" ]; then
		w=0
		while [ "$w" -lt 3 ]; do
			tr="$(_st_vpn_trace "$STL_DEV")"
			ip="$(echo "$tr" | sed -n 's/^ip=//p')"; loc="$(echo "$tr" | sed -n 's/^loc=//p')"
			if [ -n "$ip" ]; then
				echo "[ OK ] VPN: трафик идёт через узел${STL_NODE:+ «$STL_NODE»} (выход $ip${loc:+, $loc})"
				return 0
			fi
			if [ "$tr" = alive=1 ]; then
				echo "[ OK ] VPN: трафик идёт через узел${STL_NODE:+ «$STL_NODE»} — туннель медленный, адрес выхода не узнали"
				return 0
			fi
			case "$tr" in probe=*)
				tr="${tr#probe=}"
				echo "[ OK ] VPN: туннель поднят, узел${STL_NODE:+ «$STL_NODE»} отвечает$([ "${tr:-0}" -gt 0 ] && echo " (задержка $tr мс)")"
				return 0 ;;
			esac
			w=$((w + 1)); [ "$w" -lt 3 ] && { sleep 5; stl_state vpn >/dev/null 2>&1; }
		done
	fi
	stl_state vpn >/dev/null 2>&1
	if [ "$STL_FAILED" = true ] && [ -n "$STL_NWHY" ]; then
		echo "[FAIL] VPN: узел$( [ -s "$ST_SUB_NODE" ] && printf ' «%s»' "$(head -n1 "$ST_SUB_NODE")") не отвечает — $STL_NWHY; $(_st_fail_text)"
	elif [ "$STL_PSTATE" = no_such_node ]; then
		echo "[FAIL] VPN: выбранного узла больше нет в подписке — выберите «Авто» или другой узел"
	elif [ "$STL_PSTATE" = excluded ]; then
		echo "[FAIL] VPN: все узлы подписки скрыты или убраны из «Авто» — верните хотя бы один узел"
	elif [ "$STL_PSTATE" = failed ] || [ "$STL_UP" != true ]; then
		echo "[FAIL] VPN: ни один выбранный узел не ответил за $max с — проверьте задержку узлов на вкладке «Подписка»"
	elif _stl_redir_dev "$STL_DEV"; then
		echo "[FAIL] VPN: туннель поднят${STL_NODE:+ (узел «$STL_NODE»)}, но узел не ответил на проверку — запрос через него не прошёл"
	else
		echo "[FAIL] VPN: туннель поднят${STL_NODE:+ (узел «$STL_NODE»)}, но трафик через него не идёт"
	fi
	return 1
}

ST_SUB_VIA="$ST_DIR/sub.via"
_zm_bin() { local d IFS=:; for d in ${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}; do [ -n "$d" ] && [ -x "$d/$1" ] && [ ! -d "$d/$1" ] && { echo "$d/$1"; return 0; }; done; return 1; }

ST_SUB_FELL="$ST_DIR/sub.node.fell"
ST_VPN_WATCH="$JOBS_DIR/steer.vpnwatch"
ST_NODE_POL="$ST_DIR/node.pol"
ST_SUB_HOME="$ST_DIR/sub.node.home"
_st_node_pol() { case "$(cat "$ST_NODE_POL" 2>/dev/null)" in switch) echo switch ;; hold) echo hold ;; *) echo back ;; esac; }
_st_fail_text() { [ "$(_st_onfail)" = drop ] && echo "выбранные сервисы остановлены" || echo "выбранные сервисы идут напрямую"; }
# Короткий ClientHello (без постквантового обмена) для всего ядра: переменная STEER_NOPQ=1 демона steerd.
# Режим: auto (по умолчанию — включается, когда проверка узла показала, что он пускает только с коротким), on, off.
# Файл запуска steer читает флаг ST_NOPQ_ON строкой с меткой zm-nopq; после обновления steer строка ставится снова
ST_NOPQ_MODE="$ST_DIR/nopq.mode"
ST_NOPQ_AUTO="$ST_DIR/nopq.auto"
ST_NOPQ_ON="$ST_DIR/nopq.on"
_st_nopq_mode() { case "$(cat "$ST_NOPQ_MODE" 2>/dev/null)" in on) echo on ;; off) echo off ;; *) echo auto ;; esac; }
_st_nopq_want() { case "$(_st_nopq_mode)" in on) return 0 ;; off) return 1 ;; esac; [ -s "$ST_NOPQ_AUTO" ]; }
_st_nopq_pid() {
	local p
	p="$(ubus call service list '{"name":"steer"}' 2>/dev/null | jsonfilter -e '@.steer.instances.*.pid' 2>/dev/null | head -n1)"
	[ -n "$p" ] || p="$(pidof steerd 2>/dev/null | awk '{ print $1 }')"
	case "$p" in ''|*[!0-9]*) return 1 ;; esac
	[ -r "/proc/$p/environ" ] && echo "$p"
}
_st_nopq_have() {
	local p
	# Без строки панели в файле запуска STEER_NOPQ у ядра взяться неоткуда — ubus и /proc не спрашиваем
	grep -q 'zm-nopq' "$STL_INIT" 2>/dev/null || return 1
	p="$(_st_nopq_pid)" && tr '\000' '\n' < "/proc/$p/environ" 2>/dev/null | grep -qx 'STEER_NOPQ=1'
}
_st_nopq_patch() {
	local f="$STL_INIT" t
	[ -f "$f" ] || return 1
	grep -q 'zm-nopq' "$f" && return 0
	[ "$(grep -c 'procd_set_param command' "$f")" = 1 ] || return 1
	grep -q 'procd_set_param env' "$f" && return 1
	t="$f.zmnq.$$"
	awk -v L="	[ -f '$ST_NOPQ_ON' ] && procd_set_param env STEER_NOPQ=1 # zm-nopq" '{ print } !d && /procd_set_param command/ { print L; d = 1 }' "$f" > "$t" && [ -s "$t" ] && cat "$t" > "$f"
	rm -f "$t"
	grep -q 'zm-nopq' "$f"
}
_st_nopq_sync() {
	local want=0
	_st_nopq_want && want=1
	if [ "$want" = 1 ]; then
		if ! _st_nopq_patch; then
			rm -f "$ST_NOPQ_ON"
			[ -n "$1" ] || _rb_warn "Короткий ClientHello включить не удалось: файл запуска ядра steer не такой, как ожидали"
			return 1
		fi
		mkdir -p "$ST_DIR"; : > "$ST_NOPQ_ON"
	else
		rm -f "$ST_NOPQ_ON"
		grep -q 'zm-nopq' "$STL_INIT" 2>/dev/null || return 0
	fi
	stl_running && _st_nopq_pid >/dev/null || return 0
	if [ "$want" = 1 ]; then _st_nopq_have && { rm -f "$ST_DIR/nopq.fail"; return 0; }; else _st_nopq_have || return 0; fi
	# Перезапуск уже не помог — не перезапускаем ядро на каждом переключении, пробуем снова через час
	[ -n "$(find "$ST_DIR/nopq.fail" -mmin -60 2>/dev/null)" ] && return 1
	if [ "$want" = 1 ]; then
		[ -n "$1" ] || _rb_say "Включаем короткий ClientHello — перезапускаем ядро steer"
		logger -t zapret-manager "Steer: включаем короткий ClientHello (без постквантового обмена)"
	else
		[ -n "$1" ] || _rb_say "Возвращаем обычный ClientHello — перезапускаем ядро steer"
		logger -t zapret-manager "Steer: возвращаем обычный ClientHello"
	fi
	stl_restart >/dev/null 2>&1
	sleep 1
	if [ "$want" = 1 ] && ! _st_nopq_have; then
		: > "$ST_DIR/nopq.fail"
		[ -n "$1" ] || _rb_warn "Ядро steer перезапустилось без короткого ClientHello — файл запуска steer не принял настройку"
		logger -t zapret-manager "Steer: короткий ClientHello не включился после перезапуска"
		return 1
	fi
	rm -f "$ST_DIR/nopq.fail"
	return 0
}
do_steer_nopq() {
	rm -f "$ST_STOP_FLAG"
	_st_installed || { _rb_say "Сохранено — включится вместе со Steer"; return 0; }
	_st_nopq_sync || return 1
	_st_vpn_check 30 >/dev/null 2>&1
	_rb_say "Готово"
	return 0
}
_st_diag_node() {
	case "$1" in
		"выход "*": узел перестал отвечать"*|"выход "*": соединение с узлом "*" не поднято"*|"выход "*": ни один узел подписки не ответил"*|\
		"выход "*": выбран узел "*|"выход "*": все узлы-кандидаты"*|"выход "*": в подписке нет пригодных узлов"*|"выход "*" не отвечает, трафик канала"*) return 0 ;;
	esac
	return 1
}

ST_SUB_TAG="# zm-subupd"
ST_SUB_AUTO_OFF="$ZM_STATE_DIR/st.subauto.off"

ST_SUB_PICK="$ST_DIR/sub.pick"
ST_LAT_MODE="$ST_DIR/lat.mode"
_st_lat_mode() { [ "$(cat "$ST_LAT_MODE" 2>/dev/null)" = real ] && echo real || echo fast; }
ST_SUB_PING="$ST_DIR/sub.ping"
ST_SUB_ORDER="$ST_DIR/sub.order"
ST_PING_TAG="# zm-subping"

ST_SEC_DIR="$ST_DIR/sec"
ST_SEC_LIST="$ST_SEC_DIR/list"
ST_SEC_MAX=6
ST_SEC_VPN_MAX=3
_st_sec_with() {
	local _sw_was="$ST_SEC" _sw_rc
	_st_bind "$1"; shift
	"$@"; _sw_rc=$?
	_st_bind "$_sw_was"
	return $_sw_rc
}
_st_secs() { local s; for s in $(_st_list); do [ "$s" = main ] || echo "$s"; done; }
_st_sec_kind() { local k=""; [ -f "$ST_SEC_DIR/$1/kind" ] && read -r k < "$ST_SEC_DIR/$1/kind"; case "$k" in vpn|iface) echo "$k" ;; *) echo warp ;; esac; }
_st_sec_iface() { local k=""; [ -f "$ST_SEC_DIR/$1/iface" ] && read -r k < "$ST_SEC_DIR/$1/iface"; printf '%s' "$k"; }
_st_sec_over() { local k="" f="$ST_SEC_DIR/$1/over"; [ "$1" = main ] && f="$ST_DIR/over"; [ -f "$f" ] && read -r k < "$f"; case "$k" in warp|main) printf '%s' "$k" ;; s[2-9]) [ -d "$ST_SEC_DIR/$k" ] && printf '%s' "$k" ;; esac; }
_st_over_drop() {
	local i n=0
	for i in $(_st_secs); do [ "$(_st_sec_over "$i")" = "$1" ] && { rm -f "$ST_SEC_DIR/$i/over"; n=1; }; done
	[ "$(_st_sec_over main)" = "$1" ] && { rm -f "$ST_DIR/over"; n=1; }
	return $((1 - n))
}
_st_secs_overmain() { local s; for s in $(_st_secs); do [ "$(_st_sec_over "$s")" = main ] && _st_sec_live "$s" && _st_sec_work "$s" && return 0; done; return 1; }
_st_warp_used() { _st_warp_on && { _st_secs_warp || _st_secs_overwarp; }; }
_st_list() {
	local l s
	l="$([ -s "$ST_SEC_LIST" ] && grep -E '^(main|s[2-9])$' "$ST_SEC_LIST" | awk '!x[$0]++')"
	for s in $l; do
		[ "$s" = main ] || [ -d "$ST_SEC_DIR/$s" ] || continue
		printf '%s\n' "$s"
	done
}
_st_heal_list() {
	local l s
	l="$(_st_list)"
	for s in s2 s3 s4 s5 s6 s7 s8 s9; do
		[ -f "$ST_SEC_DIR/$s/kind" ] || continue
		printf '%s\n' "$l" | grep -qx "$s" || l="${l:+$l
}$s"
	done
	if ! printf '%s\n' "$l" | grep -qE '^s[2-9]$'; then
		rm -f "$ST_SEC_LIST" "$ST_SEC_DIR/main.off"
		return 0
	fi
	[ "$l" = "$(cat "$ST_SEC_LIST" 2>/dev/null)" ] && return 0
	printf '%s\n' "$l" > "$ST_SEC_LIST.heal.$$" && mv -f "$ST_SEC_LIST.heal.$$" "$ST_SEC_LIST" || rm -f "$ST_SEC_LIST.heal.$$"
}
_st_order_all() {
	local l
	l="$(_st_list)"
	if [ -z "$l" ] || ! printf '%s\n' "$l" | grep -qx main; then
		printf 'main\n'
		[ -n "$l" ] && printf '%s\n' "$l"
		return 0
	fi
	printf '%s\n' "$l"
}
_st_order_json() { _st_order_all | awk 'BEGIN { o = "" } { printf "%s\"%s\"", o, $0; o = "," }'; }
_st_secs_overwarp() { local s; _st_sec_with main _st_use_vpn && { _st_sec_with main _st_work_main || _st_secs_overmain; } && [ "$(_st_sec_over main)" = warp ] && return 0; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = vpn ] && _st_sec_live "$s" && _st_sec_work "$s" && [ "$(_st_sec_over "$s")" = warp ] && return 0; done; return 1; }
_st_sec_name() {
	local f="$ST_SEC_DIR/$1/name" v=""
	case "$1" in ''|main) f="$ST_SEC_DIR/main.name" ;; esac
	[ -f "$f" ] && read -r v < "$f"
	[ -n "$v" ] || case "$1" in ''|main) v="Основная" ;; *) v="Секция ${1#s}" ;; esac
	printf '%s' "$v"
}
_zm_tun_kind() {
	local d
	[ -n "$1" ] && [ "$1" != loopback ] && [ "$1" != "$TSC_NET" ] || return 1
	_awg_is_steer "$1" && return 1
	case "$(uci -q get "network.$1.proto")" in
		amneziawg) echo awg ;;
		wireguard) echo wg ;;
		pptp) echo pptp ;;
		l2tp) echo l2tp ;;
		sstp) echo sstp ;;
		openvpn) echo ovpn ;;
		gre) echo gre ;;
		grev6) echo gre6 ;;
		none)
			d="$(uci -q get "network.$1.device")"
			case "$d" in ''|@*|br-*|lo|tailscale*|zm*|eth*|lan*|wan*|wlan*|phy*|bond*|veth*) return 1 ;; esac
			case "$d" in tun*|tap*|wg*|awg*|ovpn*|ppp*) echo tun; return 0 ;; esac
			case "$(cat "/sys/class/net/$d/type" 2>/dev/null)" in 65534|512|776) echo tun ;; *) return 1 ;; esac ;;
		*) return 1 ;;
	esac
}
_zm_tun_label() { case "$1" in awg) echo AmneziaWG ;; wg) echo WireGuard ;; pptp) echo PPTP ;; l2tp) echo L2TP ;; sstp) echo SSTP ;; ovpn) echo OpenVPN ;; gre) echo GRE ;; gre6) echo "GRE (IPv6)" ;; *) echo "туннель" ;; esac; }
_zm_tun_dev() {
	local d p
	d="$(ifstatus "$1" 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null)"
	if [ -z "$d" ]; then
		p="$(uci -q get "network.$1.proto")"
		case "$p" in
			pptp|l2tp|sstp) d="$p-$1" ;;
			amneziawg|wireguard) d="$1" ;;
			gre) d="gre4-$1" ;;
			grev6) d="gre6-$1" ;;
			*) d="$(uci -q get "network.$1.device")"; case "$d" in @*) d="" ;; esac ;;
		esac
	fi
	printf '%s' "$d" | grep -E '^[A-Za-z0-9_.-]{1,15}$'
}
_zm_tun_up() { local d; d="$(_zm_tun_dev "$1")" && [ -d "/sys/class/net/$d" ] && [ "$(cat "/sys/class/net/$d/operstate" 2>/dev/null)" != down ]; }
_zm_tun_age() {
	local t
	t="$({ awg show "$1" latest-handshakes || wg show "$1" latest-handshakes; } 2>/dev/null | awk '$2 > mx { mx = $2 } END { if (mx > 0) print mx }')"
	[ -n "$t" ] && echo $(( $(date +%s) - t ))
}
_zm_tun_peer() { uci -q -X show network | sed -n -e "s/^network\.\([^.=]*\)=amneziawg_$1\$/\1/p" -e "s/^network\.\([^.=]*\)=wireguard_$1\$/\1/p" | head -n1; }
_st_tun_live() { _zm_tun_kind "$1" >/dev/null && _zm_tun_dev "$1" >/dev/null; }
_st_main_iface() { local k=""; [ -f "$ST_DIR/exit.iface" ] && read -r k < "$ST_DIR/exit.iface"; printf '%s' "$k"; }
_st_tun_ifaces() { { _st_main_tun && echo; _st_secs_ifaces; } | grep . | awk '!x[$0]++'; }
ST_TUN_HOOK="/etc/hotplug.d/iface/95-zm-steer"
_st_sec_live() {
	_st_sec_off "$1" && return 1
	case "$(_st_sec_kind "$1")" in
		vpn) [ -s "$ST_SEC_DIR/$1/sub.txt" ] && _st_vpn_ok ;;
		iface) _st_tun_live "$(_st_sec_iface "$1")" ;;
		*) _st_warp_on ;;
	esac
}
_st_secs_work() { local s; for s in $(_st_secs); do _st_sec_live "$s" && _st_sec_work "$s" && return 0; done; return 1; }
_st_secs_vpn() { local s; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = vpn ] && _st_sec_live "$s" && _st_sec_work "$s" && echo "$s"; done; }
_st_secs_warp() { local s; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = warp ] && _st_sec_work "$s" && return 0; done; return 1; }
_st_secs_url() { local s; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = vpn ] && [ -s "$ST_SEC_DIR/$s/sub.url" ] && echo "$s"; done; }
_st_vpn_devs_all() { local s; _st_sec_with main eval 'echo $STL_VPN_DEVS'; for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = vpn ] && _st_sec_with "$s" eval 'echo $STL_VPN_DEVS'; done; }
_st_feats_all() { local s; { _st_sec_with main _st_use_vpn && _st_sec_with main _st_sub_feats; for s in $(_st_secs_vpn); do _st_sec_with "$s" _st_sub_feats; done; } | tr ' ' '\n' | grep . | awk '!x[$0]++' | tr '\n' ' '; }

steer_action() {
	local action="$1" mode="$2" w d
	case "$action" in sec_add|sec_name|sec_kind|sec_del|sec_off|sec_over|sec_order) steer_sec_action "$action" "$mode"; return ;; esac
	case "$mode" in
		"~s"[2-9]"~"*)
			w="${mode#?}"; w="${w%%\~*}"; mode="${mode#?$w?}"
			_st_sec_ok "$w" || { echo '{"error":"нет такой секции — обновите страницу"}'; return 1; }
			case "$action" in
				lists|devs_set|list_set|list_get|list_reset|svc_find|svc_dom|sub_status|sub_probe|sub_tcp|lat_mode|node_pol|sub_home|sub_links_get|sub_set|sub_links|sub_update|sub_remove|sub_node|sub_group|sub_filter|sub_hide|sub_noauto|sub_pick|sub_ping|sub_insecure|sub_happ) ;;
				*) echo '{"error":"это действие общее для всех секций"}'; return 1 ;;
			esac
			( _st_bind "$w"; steer_action "$action" "$mode" ); return $? ;;
	esac
	case "$action" in diag|wfix_tick|explain|lists_bg|lists_cron) ;; *) rm -f "$ST_VPN_PROBE" ;; esac
	case "$action" in
		install|engine_ver|apply|start|stop|remove|warp_restart|warp_endpoint|warp_recreate|lists|engine|warp_setup|warp_fix|warp_fixkeys|warp_own|warp_mode|warp_iface|ext_pick|warp_pick|warp_remove|onfail|dnsmode|realip|cttl|torrent|quic|lan_set)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			case "$action" in warp_iface|ext_pick|warp_restart|warp_mode|warp_own) _job_alive awg && { echo '{"error":"на вкладке AmneziaWG идёт операция — дождитесь её окончания"}'; return 1; } ;; esac
			[ "$action" = remove ] || [ -z "$(_st_blocker)" ] || { echo '{"error":"ядро steer сейчас настраивает не Zapret Manager — панель его не трогает"}'; return 1; }
			case "$action" in
				warp_endpoint|warp_recreate|warp_fix|warp_fixkeys|warp_pick)
					_st_warp_ext && { echo '{"error":"в режиме «Интерфейс AmneziaWG» туннель чинится на вкладке AmneziaWG или кнопкой «Подобрать точку входа»"}'; return 1; }
					_st_warp_own && { echo '{"error":"в режиме «Свой конфиг» ключи и точку входа задаёт ваш конфиг — замените его или вернитесь к автоматическому WARP"}'; return 1; } ;;
			esac
			case "$action" in
				warp_own)
					if [ -n "$mode" ]; then
						printf '%s\n' "$mode" | grep -qi '^[[:space:]]*\[interface\]' || { echo '{"error":"в конфиге нет секции [Interface]"}'; return 1; }
						printf '%s\n' "$mode" | grep -qi '^[[:space:]]*\[peer\]' || { echo '{"error":"в конфиге нет секции [Peer]"}'; return 1; }
						printf '%s\n' "$mode" | grep -qi '^[[:space:]]*endpoint[[:space:]]*=' || { echo '{"error":"в конфиге нет Endpoint — адреса сервера"}'; return 1; }
						mkdir -p "$ST_DIR"
						( umask 077; printf '%s\n' "$mode" | tr -d '\r' > "$ST_DIR/warp.pending" )
						chmod 600 "$ST_DIR/warp.pending"
						if ! _st_own_conf_ok "$ST_DIR/warp.pending"; then
							rm -f "$ST_DIR/warp.pending"
							echo '{"error":"в конфиге нет PrivateKey, Address, PublicKey или Endpoint (адрес:порт) — прежний туннель не тронут"}'
							return 1
						fi
					else
						_st_own_saved || { echo '{"error":"вставьте конфиг WARP"}'; return 1; }
					fi
					job_start steer do_steer_warp_own ;;
				warp_mode)
					[ "$mode" = auto ] || { echo '{"error":"неизвестный режим"}'; return 1; }
					job_start steer do_steer_warp_auto ;;
				warp_remove)
					_st_installed || { echo '{"error":"Steer не установлен"}'; return 1; }
					_job_alive awg && { echo '{"error":"на вкладке AmneziaWG идёт операция — дождитесь её окончания"}'; return 1; }
					_st_warp_on || _st_warp_ext || [ -s "$ST_WARP_OWN" ] || grep -q '^net zmwarp' "$ST_OWNED" 2>/dev/null || { echo '{"error":"WARP в Steer не подключён — убирать нечего"}'; return 1; }
					case "$mode" in ''|awg) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					job_start steer do_steer_warp_remove "$mode" ;;
				warp_iface)
					printf '%s' "$mode" | grep -qE '^[A-Za-z0-9_]{1,15}$' || { echo '{"error":"неверное имя интерфейса"}'; return 1; }
					_awg_is_steer "$mode" && { echo '{"error":"это туннель самого Steer — выберите интерфейс, созданный на вкладке AmneziaWG"}'; return 1; }
					[ "$(uci -q get "network.$mode.proto")" = amneziawg ] || { echo '{"error":"такого интерфейса AmneziaWG нет"}'; return 1; }
					job_start steer do_steer_warp_iface "$mode" ;;
				ext_pick)
					_st_warp_ext || { echo '{"error":"Steer сейчас работает не через интерфейс AmneziaWG"}'; return 1; }
					[ "$(uci -q get "network.$(_awg_peer_sec "$(_st_ext_if)").public_key")" = "$AWG_WARP_PEER" ] || { echo '{"error":"подбор точки входа есть только для туннелей WARP"}'; return 1; }
					job_start steer do_steer_ext_pick ;;
				dnsmode|realip|cttl|torrent|quic)
					if [ "$action" = dnsmode ]; then
						case "$mode" in tun|router) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					elif [ "$action" = cttl ]; then
						case "$mode" in 0|300|900|3600) ;; *) echo '{"error":"неизвестный срок"}'; return 1 ;; esac
					elif [ "$action" = torrent ]; then
						case "$mode" in allow|direct|block) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					elif [ "$action" = quic ]; then
						case "$mode" in allow|block) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					else
						case "$mode" in on|off) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					fi
					if _st_installed && [ ! -f "$ST_OFF" ] && _st_owns "steer-spec"; then job_start steer do_steer_dnsopt "$action" "$mode"
					else _st_dnsopt_save "$action" "$mode"; printf '{"ok":true,"saved":true}\n'
					fi ;;
				lan_set)
					w=""
					for d in $(printf '%s' "$mode" | tr ',;' '  '); do
						printf '%s' "$d" | grep -qE '^([A-Za-z0-9._-]{1,15}|ppp\+)$' || { printf '{"error":"%s"}\n' "$(esc "неверное имя сети: $d")"; return 1; }
						case " $(_st_out_tun_devs | tr '\n' ' ') " in *" $d "*) printf '{"error":"%s"}\n' "$(esc "через $d уже идут сервисы Steer — одна и та же сеть не может быть и выходом, и источником")"; return 1 ;; esac
						case " $(_zm_lan_devs) " in *" $d "*) continue ;; esac
						case " $w " in *" $d "*) ;; *) w="$w $d" ;; esac
					done
					[ "$(echo $w | wc -w)" -le "$ST_LAN_MAX" ] || { echo "{\"error\":\"не больше $ST_LAN_MAX дополнительных сетей\"}"; return 1; }
					mkdir -p "$ST_DIR"
					if [ -n "$w" ]; then printf '%s\n' $w > "$ST_LAN_EXTRA"; else rm -f "$ST_LAN_EXTRA"; fi
					if _st_installed && [ ! -f "$ST_OFF" ] && _st_owns "steer-spec"; then job_start steer do_steer_lanset
					else
						[ -n "$w" ] || _st_lan_fw_drop
						printf '{"ok":true,"saved":true}\n'
					fi ;;
				onfail)
					case "$mode" in drop|direct) ;; *) echo '{"error":"неизвестный режим"}'; return 1 ;; esac
					if _st_installed && [ ! -f "$ST_OFF" ] && _st_owns "steer-spec"; then job_start steer do_steer_onfail "$mode"
					else
						mkdir -p "$ST_DIR"
						if [ "$mode" = drop ]; then echo drop > "$ST_DIR/onfail"; else rm -f "$ST_DIR/onfail"; fi
						printf '{"ok":true,"saved":true}\n'
					fi ;;
				warp_pick)
					_st_warp_on || { echo '{"error":"WARP ещё не подключён"}'; return 1; }
					case "$mode" in
						latency) job_start steer do_steer_warp_pick latency ;;
						order:*)
							mode="$(printf '%s' "${mode#order:}" | tr ',' ' ')"
							for w in $mode; do printf '%s' "$w" | grep -qE '^zmwarp[0-9]?$' || { echo '{"error":"неверное имя туннеля"}'; return 1; }; done
							[ -n "$(echo $mode)" ] || { echo '{"error":"пустой порядок туннелей"}'; return 1; }
							job_start steer do_steer_warp_pick order "$mode" ;;
						*) echo '{"error":"неизвестный режим"}'; return 1 ;;
					esac ;;
				install)
					case "$mode" in ''|latest|legacy) ;; *) echo '{"error":"неизвестная версия ядра"}'; return 1 ;; esac
					job_start steer do_steer_install "$mode" ;;
				engine_ver)
					case "$mode" in latest|legacy) ;; *) echo '{"error":"неизвестная версия ядра"}'; return 1 ;; esac
					_st_installed || { echo '{"error":"Steer ещё не установлен"}'; return 1; }
					job_start steer do_steer_engine_ver "$mode" ;;
				apply|start)   job_start steer do_steer_apply ;;
				stop)          job_start steer do_steer_stop ;;
				remove)        job_start steer do_steer_remove ;;
				warp_restart)  job_start steer do_steer_warp_restart ;;
				engine)        job_start steer do_steer_engine ;;
				warp_setup)    job_start steer do_steer_warp_setup ;;
				warp_fix|warp_fixkeys)
					case "$mode" in [1-9]) ;; *) echo '{"error":"неверный номер туннеля"}'; return 1 ;; esac
					[ "$mode" -le "$ST_WARP_N" ] || { echo '{"error":"неверный номер туннеля"}'; return 1; }
					if [ "$action" = warp_fixkeys ]; then job_start steer do_steer_warp_fix "$mode" keys
					else job_start steer do_steer_warp_fix "$mode"; fi ;;
				warp_endpoint) job_start steer do_steer_warp_endpoint ;;
				warp_recreate) job_start steer do_steer_warp_recreate ;;
				lists)
					_st_sel_set "$mode" || return 1
					if _st_installed && [ ! -f "$ST_OFF" ]; then job_start steer do_steer_apply
					else printf '{"ok":true,"saved":true}\n'; fi ;;
			esac
			;;
		sub_status) steer_sub_status ;;
		explain) steer_explain "$mode" ;;
		sub_auto)
			_st_sub_auto_set "$mode" || return 1
			if [ "$mode" = off ]; then mkdir -p "$ZM_STATE_DIR"; : > "$ST_SUB_AUTO_OFF"; else rm -f "$ST_SUB_AUTO_OFF"; fi ;;
		sub_refresh)
			_st_running && return 0
			[ -s "$ST_SUB_URL" ] || [ -n "$(_st_secs_url)" ] || return 0
			job_start steer do_steer_sub_update_all >/dev/null
			;;
		sub_probe) steer_sub_probe "$mode" ;;
		sub_tcp) steer_sub_tcp "$mode" ;;
		lat_mode)
			case "$mode" in
				real) mkdir -p "$ST_DIR"; echo real > "$ST_LAT_MODE" ;;
				fast) rm -f "$ST_LAT_MODE" ;;
				'') ;;
				*) echo '{"error":"неизвестный способ проверки"}'; return 1 ;;
			esac
			printf '{"ok":true,"mode":"%s"}\n' "$(_st_lat_mode)" ;;
		nopq)
			case "$mode" in
				auto) rm -f "$ST_NOPQ_MODE" ;;
				on|off) mkdir -p "$ST_DIR"; echo "$mode" > "$ST_NOPQ_MODE" ;;
				*) echo '{"error":"неизвестная настройка"}'; return 1 ;;
			esac
			[ "$mode" = off ] && rm -f "$ST_NOPQ_AUTO"
			rm -f "$ST_DIR/nopq.fail"
			if _st_installed && stl_running && { { _st_nopq_want && ! _st_nopq_have; } || { ! _st_nopq_want && _st_nopq_have; }; }; then
				job_start steer do_steer_nopq
			else
				_st_nopq_want && _st_nopq_patch && { mkdir -p "$ST_DIR"; : > "$ST_NOPQ_ON"; }
				_st_nopq_want || rm -f "$ST_NOPQ_ON"
				printf '{"ok":true,"saved":true}\n'
			fi ;;
		nopq_auto)
			[ "$(_st_nopq_mode)" = auto ] || { printf '{"ok":true,"skip":true}\n'; return 0; }
			mkdir -p "$ST_DIR"; printf '%s\n' "$mode" | head -c 200 > "$ST_NOPQ_AUTO"
			printf '{"ok":true}\n' ;;
		node_pol)
			case "$mode" in
				back) rm -f "$ST_NODE_POL" ;;
				switch|hold) mkdir -p "$ST_DIR"; echo "$mode" > "$ST_NODE_POL"; rm -f "$ST_SUB_HOME" ;;
				'') ;;
				*) echo '{"error":"неизвестная настройка"}'; return 1 ;;
			esac
			printf '{"ok":true,"pol":"%s"}\n' "$(_st_node_pol)" ;;
		sub_home)
			rm -f "$ST_SUB_HOME" "$ST_SUB_FELL"
			printf '{"ok":true}\n' ;;
		sub_links_get)
			[ -s "$ST_SUB" ] || { echo '{"error":"подписки нет"}'; return 1; }
			[ -s "$ST_SUB_URL" ] && { echo '{"error":"это подписка по ссылке — её серверы задаёт сервис, а не вы"}'; return 1; }
			printf '{"links":"%s"}\n' "$(esc_ml "$(grep -iE "$STL_LINK_RE" "$ST_SUB")")"
			;;
		sub_ping_tick) steer_ping_tick; _st_secs_ping_tick; printf '{"ok":true}\n' ;;
		sub_set|sub_links|sub_update|sub_remove|sub_exit|sub_node|sub_group|sub_filter|sub_hide|sub_noauto|sub_pick|sub_ping|sub_insecure|sub_happ|iface_forget)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			[ -z "$(_st_blocker)" ] || { echo '{"error":"ядро steer сейчас настраивает не Zapret Manager — панель его не трогает"}'; return 1; }
			steer_sub_action "$action" "$mode"
			;;
		list_get) steer_list_get "$mode" ;;
		svc_dom) steer_svc_dom "$mode" ;;
		svc_find) steer_svc_find "$mode" ;;
		svc_domflags) steer_svc_domflags ;;
		devices) steer_devices ;;
		devs_set)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			[ -z "$(_st_blocker)" ] || { echo '{"error":"ядро steer сейчас настраивает не Zapret Manager — панель его не трогает"}'; return 1; }
			_st_devs_save "$mode"
			if _st_installed && [ ! -f "$ST_OFF" ] && [ "$(_st_exit)" != none ] && { _st_work || _st_owns "steer-spec"; }; then job_start steer do_steer_devs
			else printf '{"ok":true,"saved":true}\n'; fi
			;;
		catalog_refresh)
			[ -f "$ST_CAT_OFF" ] && { echo '{"error":"каталог списков выключен"}'; return 1; }
			rm -f "$ST_DIR/catalog.err"
			( _st_cat_refresh force >/dev/null 2>&1 & )
			printf '{"ok":true}\n'
			;;
		tachyon)
			mkdir -p "$ST_DIR"
			case "$mode" in
				off) touch "$ST_TCH_OFF"; _st_tch_idx_merge; printf '{"ok":true}\n' ;;
				state) _st_tch_json; echo ;;
				on|refresh)
					[ "$mode" = refresh ] && ! _st_tch_on && { echo '{"error":"Tachyon Lists выключен"}'; return 1; }
					rm -f "$ST_TCH_OFF" "$ST_TCH_ERR"
					_st_tch_idx_merge
					mkdir -p "$ST_RUN"; : > "$ST_RUN/tch.pending"
					if [ "$mode" = on ] && [ -s "$ST_TCH_SVC" ]; then ( _st_tch_refresh; rm -f "$ST_RUN/tch.pending" ) >/dev/null 2>&1 &
					else ( _st_tch_refresh force; rm -f "$ST_RUN/tch.pending" ) >/dev/null 2>&1 &
					fi
					printf '{"ok":true,"started":true}\n' ;;
				*) echo '{"error":"неизвестное действие"}'; return 1 ;;
			esac
			;;
		own_add|own_del|own_ren|own_refresh)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			mkdir -p "$ST_DIR" "$ST_RUN"
			case "$action" in
				own_add) _st_own_add "$mode" ;;
				own_del) _st_own_del "$mode" ;;
				own_ren) _st_own_ren "$mode" ;;
				own_refresh)
					case "$mode" in zmc[0-9]*) grep -q "^$mode|" "$ST_OWN_CATS" 2>/dev/null ;; *) false ;; esac || { echo '{"error":"нет такого каталога — обновите страницу"}'; return 1; }
					_zm_run 17 _st_owncat_refresh "$mode" >/dev/null 2>&1
					case $? in
						0) printf '{"ok":true,%s}\n' "$(awk -F'|' -v k="$mode" '$1 == k { printf "\"svcs\":%d,\"version\":\"%s\"", $5, $6; exit }' "$ST_OWN_CATS")" ;;
						137|143) rm -f "$ST_RUN/own.cat.new" "$ST_RUN"/owncat.*; echo '{"error":"каталог не успел скачаться за 17 секунд — прежний оставлен, попробуйте позже"}'; return 1 ;;
						*) echo '{"error":"каталог не скачался или в нём нет списков — прежний оставлен"}'; return 1 ;;
					esac ;;
			esac
			;;
		xsets)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			mkdir -p "$ST_USER_DIR"
			printf '%s\n' $(printf '%s' "$mode" | tr ',' ' ') | grep -E '^t_[a-z0-9_]+$' | while IFS= read -r x; do
				grep -q "^$x|" "$ST_TCH_DIRECT" 2>/dev/null && echo "$x"
			done | awk '!s[$0]++' > "$ST_TCH_XSETS.t"
			if cmp -s "$ST_TCH_XSETS.t" "$ST_TCH_XSETS" 2>/dev/null || { [ ! -s "$ST_TCH_XSETS.t" ] && [ ! -s "$ST_TCH_XSETS" ]; }; then rm -f "$ST_TCH_XSETS.t"; printf '{"ok":true,"saved":true}\n'; return 0; fi
			mv -f "$ST_TCH_XSETS.t" "$ST_TCH_XSETS"
			[ -s "$ST_TCH_XSETS" ] || rm -f "$ST_TCH_XSETS"
			if _st_installed && [ ! -f "$ST_OFF" ] && [ "$(_st_exit)" != none ] && { _st_work || _st_owns "steer-spec"; }; then job_start steer do_steer_excl
			else printf '{"ok":true,"saved":true}\n'; fi
			;;
		catalog_src)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			mkdir -p "$ST_DIR"
			case "$mode" in
				off) touch "$ST_CAT_OFF"; printf '{"ok":true}\n'; return 0 ;;
				on) rm -f "$ST_CAT_OFF" ;;
				'') rm -f "$ST_CAT_URL" ;;
				https://*)
					case "$mode" in *[[:space:]\"\'\\\`\$\;\|\<\>]*) echo '{"error":"недопустимые символы в ссылке"}'; return 1 ;; esac
					printf '%s\n' "$mode" > "$ST_CAT_URL" ;;
				*) echo '{"error":"нужна ссылка https://…/lists.json"}'; return 1 ;;
			esac
			rm -f "$ST_DIR/catalog.err"
			_zm_run 17 _st_cat_refresh force >/dev/null 2>&1
			case $? in
				0) printf '{"ok":true}\n' ;;
				137|143) rmdir "$ST_RUN/cat.lock" 2>/dev/null; rm -f "$ST_RUN/lists.json.tmp"; echo '{"error":"каталог не успел скачаться за 17 секунд — прежний список сервисов оставлен, попробуйте позже"}'; return 1 ;;
				*) echo '{"error":"каталог по этой ссылке не скачался или в нём нет списков — прежний список сервисов оставлен"}'; return 1 ;;
			esac
			;;
		list_set|list_reset)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			if [ "$action" = list_set ]; then steer_list_set "$mode"; else steer_list_reset "$mode"; fi
			;;
		halt)
			_st_running || { echo '{"error":"ничего не выполняется"}'; return 1; }
			touch "$ST_STOP_FLAG"
			printf '{"ok":true}\n'
			;;
		restart)
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			_st_owns "steer-spec" || { echo '{"error":"правил для Steer нет — выберите сервисы"}'; return 1; }
			[ -z "$(_st_blocker)" ] || { echo '{"error":"ядро steer сейчас настраивает не Zapret Manager — панель его не трогает"}'; return 1; }
			stl_restart || { echo '{"error":"Steer не запустился — загляните в системный журнал"}'; return 1; }
			printf '{"ok":true}\n'
			;;
		autorestart) _st_cron_set "$mode" ;;
		lan_list) steer_lan_list ;;
		tun_list) steer_tun_list ;;
		tun_up)
			printf '%s' "$mode" | grep -qE '^[A-Za-z0-9_]{1,15}$' || { echo '{"error":"неверное имя туннеля"}'; return 1; }
			_st_installed && [ ! -f "$ST_OFF" ] && [ -z "$(_st_blocker)" ] || { printf '{"ok":true}\n'; return 0; }
			_st_uses_if "$mode" || { printf '{"ok":true}\n'; return 0; }
			d="$(_zm_tun_dev "$mode")" || { printf '{"ok":true}\n'; return 0; }
			grep -qF "\"device\":\"$d\"" "$STL_SPEC" 2>/dev/null && { printf '{"ok":true,"same":true}\n'; return 0; }
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			job_start steer do_steer_tunup "$mode" ;;
		lists_via)
			mkdir -p "$ST_DIR"
			if [ "$mode" = on ]; then touch "$ST_DIR/lists.via"; else rm -f "$ST_DIR/lists.via"; fi
			printf '{"ok":true}\n' ;;
		lists_auto)
			_st_installed || { echo '{"error":"Steer ещё не установлен"}'; return 1; }
			mkdir -p "$ST_DIR"
			if [ "$mode" = off ]; then : > "$ST_LISTS_OFF"; else rm -f "$ST_LISTS_OFF"; fi
			_st_lists_cron_sync
			printf '{"ok":true}\n' ;;
		lists_cron)
			_st_lists_cron_sync
			printf '{"ok":true}\n' ;;
		lists_refresh)
			_st_installed || { echo '{"error":"Steer ещё не установлен"}'; return 1; }
			[ -z "$(_st_blocker)" ] || { echo '{"error":"ядро steer сейчас настраивает не Zapret Manager — панель его не трогает"}'; return 1; }
			_st_running && { echo '{"error":"дождитесь окончания текущей операции"}'; return 1; }
			job_start steer_lists do_steer_lists all ;;
		lists_bg)
			_st_installed && [ ! -f "$ST_OFF" ] && [ -z "$(_st_blocker)" ] || return 0
			[ "$mode" = missing ] || [ ! -f "$ST_LISTS_OFF" ] || return 0
			_st_running && return 0
			_job_running steer_lists && return 0
			job_start steer_lists do_steer_lists "$([ "$mode" = missing ] && echo missing || echo all)" >/dev/null ;;
		sub_via)
			mkdir -p "$ST_DIR"
			if [ "$mode" = on ]; then touch "$ST_SUB_VIA"; else rm -f "$ST_SUB_VIA"; fi
			printf '{"ok":true}\n' ;;
		wfix) _st_wfix_set "$mode" ;;
		wfix_tick) _st_wfix_tick; printf '{"ok":true}\n' ;;
		conns)
			stl_present && stl_running || { echo '{"error":"Steer не запущен"}'; return 1; }
			w="$(_stl_t 15 steer conns 2>/dev/null | tr -d '\n\r')"
			case "$w" in '{'*'"conns"'*) ;; *) echo '{"error":"ядро Steer не отдало список соединений — нужна версия 2.0 или новее"}'; return 1 ;; esac
			if [ "$(printf '%s' "$w" | sed 's/}, *{/}\n{/g' | wc -l)" -gt 400 ]; then
				printf '%s' "$w" | sed 's/}, *{/}\n{/g' | head -n 400 | tr '\n' ',' | sed 's/,$//'
				w="$(printf '%s' "$w" | sed -n 's/.*"total": *\([0-9][0-9]*\).*/\1/p')"
				printf '],"shown":400,"total":%s,"truncated":true}\n' "${w:-400}"
			else printf '%s\n' "$w"; fi ;;
		dnslog)
			stl_present && stl_running || { echo '{"error":"Steer не запущен"}'; return 1; }
			w="$(_stl_t 15 steer dns-log 2>/dev/null | tr -d '\n\r')"
			case "$w" in '{'*'"names"'*) ;; *) echo '{"error":"ядро Steer не отдало журнал имён — нужна версия 2.0 или новее"}'; return 1 ;; esac
			mkdir -p "$ST_RUN"
			printf '%s\n' "$w" > "$ST_RUN/dnslog.$$"
			_st_dnslog_fix "$ST_RUN/dnslog.$$" 2>/dev/null | grep . || printf '%s\n' "$w"
			rm -f "$ST_RUN/dnslog.$$" ;;
		wfix_reset)
			rm -f "$ST_WFIX_STATE"; printf '{"ok":true}\n' ;;
		warp_own_get)
			local of="$ST_WARP_OWN"
			[ -s "$of" ] || of="$ST_WARP_OWN_KEEP"
			if [ -s "$of" ]; then printf '{"content":"%s"}\n' "$(esc_ml "$(tr -d '\r' < "$of" | tr '\t' ' ')")"
			else printf '{"content":""}\n'; fi
			;;
		diag)
			local trace warp="none" colo="" tun="" tsep="" wi wn wv wc vpn="none" vip="" vloc="" gs gt
			if _st_installed && _st_work && [ ! -f "$ST_OFF" ] && _st_use_vpn; then
				vpn=off
				_st_vpn_probe && vpn=on
				read -r _ _ vip vloc 2>/dev/null < "$ST_VPN_PROBE"
			elif _st_installed && _st_warp_on && _st_work && [ ! -f "$ST_OFF" ] && { [ "$(_st_exit)" != iface ] || _st_secs_warp; }; then
				warp=off
				wn=1
				while [ "$wn" -le "$ST_WARP_N" ]; do
					wi="$(_st_wif "$wn")"
					if _st_wnet "$wi" && [ -d "/sys/class/net/$wi" ]; then
						trace="$(curl -s --interface "$wi" --connect-timeout 4 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)"
						wc="$(echo "$trace" | sed -n 's/^colo=//p')"
						wv=""
						case "$trace" in
							*warp=on*|*warp=plus*) wv=on ;;
							*ip=*) _st_warp_own && wv=on ;;
						esac
						gs=""; gt=""
						if [ "$wv" = on ]; then
							warp=on; [ -n "$colo" ] || colo="$wc"
							_st_warp_geo "$wi"
							set -- $(_st_geo_get "$wi")
							if [ $# -ge 4 ]; then
								[ -n "$wc" ] || wc="$1"
								gs="$2"; shift 3; gt="$*"
								[ "$gs" = - ] && gs=""; [ "$gt" = - ] && gt=""
							fi
						else wc="$(_st_colo_of "$wi")"; [ -n "$wc" ] && wv=notls || wv=off; fi
						tun="$tun$tsep{\"n\":$wn,\"warp\":\"$wv\",\"colo\":\"$(esc "$wc")\",\"city\":\"$(esc "$gt")\",\"seen\":\"$(esc "$gs")\"}"
						tsep=","
					fi
					wn=$((wn + 1))
				done
			fi
			local d="" itj="" isep="" ti td tip tup
			if _st_installed && _st_work && [ ! -f "$ST_OFF" ]; then
				for ti in $(_st_tun_ifaces); do
					td="$(_zm_tun_dev "$ti")"; tip=""; tup=false
					if [ -n "$td" ] && [ -d "/sys/class/net/$td" ]; then
						tup=true
						tip="$(curl -s --interface "$td" --connect-timeout 4 --max-time 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p')"
					fi
					itj="$itj$isep{\"name\":\"$(esc "$ti")\",\"label\":\"$(esc "$(_zm_tun_label "$(_zm_tun_kind "$ti")")")\",\"kind\":\"$(_zm_tun_kind "$ti")\",\"up\":$tup,\"ip\":\"$(esc "$tip")\"}"
					isep=","
				done
			fi
			local hj=""
			if stl_present && _st_owns "steer-spec"; then
				d="$(stl_diag)"
				if [ "$d" != null ]; then
					mkdir -p "$ST_RUN"
					printf '%s\n' "$d" > "$ST_RUN/diag.ui.$$"
					hj="$(_stl_diag_tsv "$ST_RUN/diag.ui.$$" | _st_diag_hjson)"
					rm -f "$ST_RUN/diag.ui.$$"
				fi
			fi
			printf '{"warp":"%s","colo":"%s","vpn":"%s","vpn_ip":"%s","vpn_loc":"%s","tunnels":[%s],"ifs":[%s],"diag":%s,"human":[%s]}\n' "$warp" "$(esc "$colo")" "$vpn" "$(esc "$vip")" "$(esc "$vloc")" "$tun" "$itj" "${d:-null}" "$hj"
			;;
		dns_fix)
			do_steer_dns_fix
			printf '{"ok":true}\n'
			;;
		cron_restart) _st_cron_restart ;;
		sync)
			_st_cron_refresh
			_st_ping_cron
			_st_owns "steer-spec" && [ ! -f "$ST_OFF" ] && [ -z "$(_st_blocker)" ] && stl_reload
			printf '{"ok":true}\n'
			;;
		*) echo '{"error":"неизвестное действие"}' ;;
	esac
}

AWG_DIR="/etc/zm-awg"
AWG_RUN="$JOBS_DIR/awg"
AWG_WARP_PEER="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
AWG_ENDPOINTS="engage.cloudflareclient.com:4500 engage.cloudflareclient.com:2408 162.159.192.1:2408 162.159.193.1:2408 162.159.195.1:2408 188.114.97.1:2408 188.114.98.1:500 188.114.99.1:4500"

[ -d "$AWG_RUN" ] || mkdir -p "$AWG_RUN" 2>/dev/null

_awg_pkg_ver() {
	if [ "$PKG" = "apk" ]; then
		_apk_ver "$1"
	else
		_opkg_ver "$1"
	fi
}
_awg_installed() { command -v awg >/dev/null 2>&1 && { _awg_kmod_have || _st_awg_loaded; }; }
_awg_ifaces() { uci -q show network | sed -n "s/^network\.\([A-Za-z0-9_]*\)\.proto='amneziawg'\$/\1/p"; }
_awg_is_steer() { case "$1" in zmwarp|zmwarp[0-9]) return 0 ;; esac; return 1; }
_awg_peer_sec() { uci -q -X show network | sed -n "s/^network\.\([^.=]*\)=amneziawg_$1\$/\1/p" | head -n1; }
_awg_owned() { grep -qxF "$1" "$AWG_DIR/owned" 2>/dev/null; }
_awg_fk_secs() {
	local s
	[ -s /etc/config/netshift ] || return 0
	for s in $(uci -q show netshift 2>/dev/null | sed -n "s/^netshift\.\([^.=]*\)\.interface='$1'\$/\1/p"); do
		[ "$(uci -q get "netshift.$s.connection_type")" = vpn ] && echo "$s"
	done
	return 0
}
_awg_fk_live() { _fk_installed && _fk_enabled && [ -n "$(_awg_fk_secs "$1")" ]; }
_awg_hs_age() {
	local hs
	hs=$(awg show "$1" latest-handshakes 2>/dev/null | awk '$2 > 0 { print $2; exit }')
	[ -n "$hs" ] && echo $(( $(date +%s) - hs ))
}

_awg_health() {
	local i n=0 up=0 a st=0
	if _awg_installed; then
		for i in $(_awg_ifaces); do
			[ "$(uci -q get "network.$i.auto")" = 0 ] && [ ! -d "/sys/class/net/$i" ] && continue
			n=$((n + 1))
			a="$(_awg_hs_age "$i")"
			[ -n "$a" ] && [ "$a" -lt 180 ] && up=$((up + 1))
		done
		if [ "$n" = 0 ]; then
			if [ -f /lib/netifd/proto/amneziawg.sh ]; then st=1; else st=3; fi
		elif [ "$up" = "$n" ]; then st=1
		elif [ "$up" = 0 ]; then st=2
		else st=3; fi
	fi
	printf '%s,"awg_up":%s,"awg_total":%s' "$st" "$up" "$n"
}

AWF_MODE="$ZM_STATE_DIR/awgfix"
AWF_SKIP="$ZM_STATE_DIR/awgfix.skip"
AWF_STATE="$ZM_STATE_DIR/awgfix.state"
AWF_LOG="$ZM_STATE_DIR/awgfix.log"
AWF_TAG="# zm-awgfix"
AWF_TRIES=4

_awf_min() { case "$(cat "$AWF_MODE" 2>/dev/null)" in 5) echo 5 ;; 15) echo 15 ;; 30|60|180) echo 30 ;; esac; }

AWG_API1="https://api.cloudflareclient.com/v0a4005/reg"
AWG_API2="https://api.cloudflareclient.com/v0i1909051800/reg"
AWG_RELAY="https://edge-client-api.vercel.app/v0a4005/reg"
AWG_CF_VER="a-6.11-2223"
AWG_BOOT_PRIV="4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg="
AWG_BOOT_IP="172.16.0.3"
AWG_TEST_IF="zmawgtest"
AWG_TEST_HOSTS="162.159.192.1 188.114.97.1 188.114.96.3 162.159.193.2 162.159.195.2 188.114.98.2 188.114.99.2 8.6.112.2 8.34.70.2 8.34.146.2 8.39.125.2"
AWG_TEST_PORTS="2408 500 4500 1701"
AWG_I1_ICLOUD="<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"
AWG_I1_QUIC1="<b 0xc10000000114367096bb0fb3f58f3a3fb8aaacd61d63a1c8a40e14f7374b8a62dccba6431716c3abf6f5afbcfb39bd008000047c32e268567c652e6f4db58bff759bc8c5aaca183b87cb4d22938fe7d8dca22a679a79e4d9ee62e4bbb3a380dd78d4e8e48f26b38a1d42d76b371a5a9a0444827a69d1ab5872a85749f65a4104e931740b4dc1e2dd77733fc7fac4f93011cd622f2bb47e85f71992e2d585f8dc765a7a12ddeb879746a267393ad023d267c4bd79f258703e27345155268bd3cc0506ebd72e2e3c6b5b0f005299cd94b67ddabe30389c4f9b5c2d512dcc298c14f14e9b7f931e1dc397926c31fbb7cebfc668349c218672501031ecce151d4cb03c4c660b6c6fe7754e75446cd7de09a8c81030c5f6fb377203f551864f3d83e27de7b86499736cbbb549b2f37f436db1cae0a4ea39930f0534aacdd1e3534bc87877e2afabe959ced261f228d6362e6fd277c88c312d966c8b9f67e4a92e757773db0b0862fb8108d1d8fa262a40a1b4171961f0704c8ba314da2482ac8ed9bd28d4b50f7432d89fd800c25a50c5e2f5c0710544fef5273401116aa0572366d8e49ad758fcb29e6a92912e644dbe227c247cb3417eabfab2db16796b2fba420de3b1dc94e8361f1f324a331ddaf1e626553138860757fd0bf687566108b77b70fb9f8f8962eca599c4a70ed373666961a8cb506b96756d9e28b94122b20f16b54f118c0e603ce0b831efea614ad836df6cf9affbdd09596412547496967da758cec9080295d853b0861670b71d9abde0d562b1a6de82782a5b0c14d297f27283a895abc889a5f6703f0e6eb95f67b2da45f150d0d8ab805612d570c2d5cb6997ac3a7756226c2f5c8982ffbd480c5004b0660a3c9468945efde90864019a2b519458724b55d766e16b0da25c0557c01f3c11ddeb024b62e303640e17fdd57dedb3aeb4a2c1b7c93059f9c1d7118d77caac1cd0f6556e46cbc991c1bb16970273dea833d01e5090d061a0c6d25af2415cd2878af97f6d0e7f1f936247b394ecb9bd484da6be936dee9b0b92dc90101a1b4295e97a9772f2263eb09431995aa173df4ca2abd687d87706f0f93eaa5e13cbe3b574fa3cfe94502ace25265778da6960d561381769c24e0cbd7aac73c16f95ae74ff7ec38124f7c722b9cb151d4b6841343f29be8f35145e1b27021056820fed77003df8554b4155716c8cf6049ef5e318481460a8ce3be7c7bfac695255be84dc491c19e9dedc449dd3471728cd2a3ee51324ccb3eef121e3e08f8e18f0006ea8957371d9f2f739f0b89e4db11e5c6430ada61572e589519fbad4498b460ce6e4407fc2d8f2dd4293a50a0cb8fcaaf35cd9a8cc097e3603fbfa08d9036f52b3e7fcce11b83ad28a4ac12dba0395a0cc871cefd1a2856fffb3f28d82ce35cf80579974778bab13d9b3578d8c75a2d196087a2cd439aff2bb33f2db24ac175fff4ed91d36a4cdbfaf3f83074f03894ea40f17034629890da3efdbb41141b38368ab532209b69f057ddc559c19bc8ae62bf3fd564c9a35d9a83d14a95834a92bae6d9a29ae5e8ece07910d16433e4c6230c9bd7d68b47de0de9843988af6dc88b5301820443bd4d0537778bf6b4c1dd067fcf14b81015f2a67c7f2a28f9cb7e0684d3cb4b1c24d9b343122a086611b489532f1c3a26779da1706c6759d96d8ab>"

AWG_I1_SET="quic2 dns stun icloud sip quic"
AWG_I1_HOSTS="www.apple.com www.google.com www.microsoft.com cdn.jsdelivr.net"

_awg_i1() {
	case "$1" in
		quic) echo "$MIXOMO_AWG_I1" ;;
		quic2) echo "$AWG_I1_QUIC1" ;;
		icloud) echo "$AWG_I1_ICLOUD" ;;
		dns) _i1_dns ;;
		stun) _i1_stun ;;
		sip) _i1_sip ;;
	esac
}

AWG_NO_I1=0
AWG_TRY_WAIT=8
_awg_mask_name() {
	case "$1" in
		"$AWG_I1_ICLOUD") echo "iCloud-DNS" ;;
		"$AWG_I1_QUIC1") echo "QUIC-2" ;;
		"<r 2><b 0x01000001000000000001"*) echo "DNS" ;;
		"<b 0x0001"*) echo "STUN" ;;
		"<b 0x4f5054494f4e53"*|"<b 0x494e56495445"*) echo "SIP" ;;
		*) echo "QUIC" ;;
	esac
}

_zm_rand32() {
	local v=""
	if command -v hexdump >/dev/null 2>&1; then v="$(head -c 4 /dev/urandom 2>/dev/null | hexdump -e '1/4 "%u"' 2>/dev/null)"
	elif command -v od >/dev/null 2>&1; then v="$(head -c 4 /dev/urandom 2>/dev/null | od -An -tu4 2>/dev/null | tr -d ' \n')"; fi
	case "$v" in ''|*[!0-9]*) v="$(( $(date +%s) % 100000 * 1000 + $$ % 1000 ))" ;; esac
	echo "$v"
}

_awg_rand_hosts() {
	awk -v n="$1" -v pools="$ST_WARP_POOLS" -v seed="$(_zm_rand32)" 'BEGIN {
		srand(seed + 0); c = split(pools, p, " ")
		for (i = 1; i <= c; i++) for (k = 0; k < n; k++) printf "%s%d\n", p[i], 2 + int(rand() * 253)
	}' | awk 'BEGIN { srand() } { print rand() "\t" $0 }' | sort -n | cut -f2
}

_awg_cv() { awk -v s="$2" -v k="$3" '$1 == s && $2 == k { $1 = ""; $2 = ""; sub(/^  /, ""); print; exit }' "$1"; }

_term_installed() { [ -x /usr/bin/ttyd ]; }
_term_running() { pidof ttyd >/dev/null 2>&1; }
_term_enabled() { ls /etc/rc.d/S*ttyd >/dev/null 2>&1; }
_term_version() { ttyd --version 2>/dev/null | head -n1 | awk '{ print $NF }'; }
_term_port() {
	local p
	p="$(uci -q get 'ttyd.@ttyd[0].port' 2>/dev/null)"
	case "$p" in ''|*[!0-9]*) p=7681 ;; esac
	echo "$p"
}

TERM_ALL="$ZM_STATE_DIR/ttyd.all"
_term_iface() { uci -q get 'ttyd.@ttyd[0].interface'; }

do_term_remove() {
	_term_say "Останавливаем терминал"
	_term_stop
	echo "   ✓ Терминал остановлен и убран из автозапуска"
	_term_say "Удаляем ttyd"
	local rc=0
	_zm_pkg_wipe luci-i18n-ttyd-ru luci-app-ttyd ttyd || rc=1
	_zm_wipe /etc/config/ttyd /etc/config/ttyd-opkg /etc/config/ttyd.apk-new /etc/init.d/ttyd /etc/rc.d/*ttyd || rc=1
	rm -f "$TERM_ALL"
	_zm_rm_listed terminal || rc=1
	rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null
	_term_installed && rc=1
	_zm_rm_done "$rc" "Терминал"
}

TSC_DIR="$ZM_STATE_DIR/tailscale"
TSC_ON="$TSC_DIR/on"
TSC_STOP="$TSC_DIR/stopped"
TSC_NOEXIT="$TSC_DIR/noexit"
TSC_LAN="$TSC_DIR/lan"
TSC_LS_PREV="$TSC_DIR/localservice"
TSC_ZR_OWN="$TSC_DIR/zapret.own"
TSC_STATE="$TSC_DIR/state"
TSC_SRV="$TSC_DIR/server"
TSC_KEY="$TSC_DIR/authkey"
TSC_DEV="tailscale0"
TSC_NET="tailscale"
TSC_FW_RULE="zm_tailscale"
TSC_NFT="/usr/share/nftables.d/chain-pre/forward/30-zm-tailscale.nft"
TSC_HOOK="/usr/libexec/zm-tailscale-tgws"
TSC_SYSCTL="/etc/sysctl.d/90-zm-tailscale.conf"
TSC_UPLOG="$JOBS_DIR/tsc.up.log"
TSC_NEED_KB=10240

_tsc_installed() { [ -x /usr/sbin/tailscaled ] && [ -e /usr/sbin/tailscale ]; }
_tsc_running() { pidof tailscaled >/dev/null 2>&1; }
_tsc_enabled() { ls /etc/rc.d/S*tailscale >/dev/null 2>&1; }
TSC_SOCK="/var/run/tailscale/tailscaled.sock"

TSC_GH_BASES="https://raw.githubusercontent.com/gunanovo/openwrt-tailscale/refs/heads/feed https://cdn.jsdelivr.net/gh/gunanovo/openwrt-tailscale@feed"
TSC_LUCI_BASES="https://raw.githubusercontent.com/Tokisaki-Galaxy/luci-app-tailscale-community/gh-pages/all https://tokisaki-galaxy.github.io/luci-app-tailscale-community/all https://cdn.jsdelivr.net/gh/Tokisaki-Galaxy/luci-app-tailscale-community@gh-pages/all"
TSC_SRC="$TSC_DIR/source"

_tsc_vnum() { printf '%s' "$1" | sed 's/-r[0-9]*$//; s/[^0-9.].*$//'; }

_st_lan_devs() {
	local out d i outd
	out="$(_zm_lan_devs)"
	if [ -f "$TSC_ON" ]; then case " $out " in *" $TSC_DEV "*) ;; *) out="$out $TSC_DEV" ;; esac; fi
	outd=" $(_st_out_tun_devs | tr '\n' ' ') "
	for d in $(_st_lan_extra); do
		case "$outd" in *" $d "*) continue ;; esac
		if [ "$d" = "$ST_PPP_SRV" ]; then
			i=0
			while [ "$i" -lt "$ST_PPP_N" ]; do case " $out " in *" ppp$i "*) ;; *) out="$out ppp$i" ;; esac; i=$((i + 1)); done
			continue
		fi
		[ -d "/sys/class/net/$d" ] || _st_tun_srcdev "$d" >/dev/null || continue
		case " $out " in *" $d "*) ;; *) out="$out $d" ;; esac
	done
	echo $out
}
ST_PPP_SRV="ppp+"
ST_PPP_N=16
_st_tun_srcdev() {
	local n
	for n in $(uci -q -X show network | sed -n 's/^network\.\([^.=]*\)=interface$/\1/p'); do
		_zm_tun_kind "$n" >/dev/null && [ "$(_zm_tun_dev "$n")" = "$1" ] && { echo "$n"; return 0; }
	done
	return 1
}
_st_out_tun_devs() {
	local i s
	{ [ "$(cat "$ST_DIR/exit" 2>/dev/null)" = iface ] && _st_main_iface && echo
	  for s in $(_st_secs); do [ "$(_st_sec_kind "$s")" = iface ] && _st_sec_iface "$s" && echo; done; } 2>/dev/null | grep . | awk '!x[$0]++' | while read -r i; do
		_zm_tun_dev "$i"
	done
	_st_warp_ext && _st_ext_if
	return 0
}

ST_LAN_EXTRA="$ST_DIR/lan.extra"
ST_LAN_MAX=8
_st_lan_extra() { [ -s "$ST_LAN_EXTRA" ] || return 0; tr -s ' \t\r' '\n\n\n' 2>/dev/null < "$ST_LAN_EXTRA" | grep -E '^([A-Za-z0-9._-]{1,15}|ppp\+)$' | awk '!x[$0]++'; }
_st_lan_fw_drop() {
	local r ch=0
	for r in $(sed -n 's/^fw \(zmlan_[A-Za-z0-9_]*\)$/\1/p' "$ST_OWNED" 2>/dev/null); do
		uci -q delete "firewall.$r"; sed -i "\\|^fw $r\$|d" "$ST_OWNED" 2>/dev/null; ch=1
	done
	[ "$ch" = 1 ] && { uci commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1; }
	return 0
}

TSC_CRON_TAG="# zm-tailscale"

TSC_MANUAL="$TSC_DIR/approved.manual"

_tsc_dot() {
	_tsc_installed || { echo 0; return; }
	if _tsc_running; then
		[ "$(cat "$TSC_STATE" 2>/dev/null)" = Running ] && echo 1 || echo 4
	elif _tsc_enabled; then echo 2; else echo 4; fi
}

MON_HTOP_PID="$JOBS_DIR/htop.pid"
MON_TTYD_OWN="$ZM_STATE_DIR/ttyd.htop"

WATCH_OFF="$ZM_STATE_DIR/watch.off"
WATCH_EVERY="$ZM_STATE_DIR/watch.every"

_watch_kv() { sed -n "s/^$1=//p" "$WATCH_EVERY" 2>/dev/null | head -n1; }
_watch_every() {
	local v
	v="$(_watch_kv every)"
	case "$v" in
		[1-9]m|[1-5][0-9]m|[1-9]h|1[0-9]h|2[0-3]h|[1-9]d|[12][0-9]d|30d) echo "$v" ;;
		*) echo 2m ;;
	esac
}
_watch_at() {
	local v
	v="$(_watch_kv at)"
	_zm_re "$v" '^([01][0-9]|2[0-3]):[0-5][0-9]$' && echo "$v" || echo "04:20"
}
_watch_label() {
	local v n u
	v="$(_watch_every)"; n="${v%?}"; u="${v#"$n"}"
	case "$u" in
		m) [ "$n" = 1 ] && echo "каждую минуту" || echo "раз в $n $(_zm_plural "$n" минуту минуты минут)" ;;
		h) [ "$n" = 1 ] && echo "раз в час" || echo "раз в $n $(_zm_plural "$n" час часа часов)" ;;
		d) [ "$n" = 1 ] && echo "раз в сутки, в $(_watch_at)" || echo "раз в $n $(_zm_plural "$n" день дня дней), в $(_watch_at)" ;;
	esac
}
_zm_plural() {
	local n="$1" a b
	a=$((n % 10)); b=$((n % 100))
	if [ "$a" = 1 ] && [ "$b" != 11 ]; then echo "$2"
	elif [ "$a" -ge 2 ] && [ "$a" -le 4 ] && { [ "$b" -lt 12 ] || [ "$b" -gt 14 ]; }; then echo "$3"
	else echo "$4"; fi
}

FK_ZASH_MARK=".zm-zashboard"

FK_REPO="yandexru45/netshift"
FK_PIN="0.9.12"
FK_MARK="/usr/lib/netshift/zm-managed"
FK_UC="/opt/zapret-manager-luci/netshift.uc"
ZM_AG_JQ="/opt/zapret-manager-luci/autogrp.jq"
ZM_AG_FK_JQ="/opt/zapret-manager-luci/autogrp-fk.jq"
FK_AG_FILE="$ZM_STATE_DIR/fk.autogrp.json"
FK_SB_OWN="$ZM_STATE_DIR/netshift.singbox"
FK_DEPS="ca-bundle kmod-inet-diag kmod-tun curl jq ucode ucode-mod-fs ucode-mod-uci kmod-nft-tproxy coreutils-base64 bind-dig ip-full"
FK_NFT="NetShiftTable"
FK_NFT_GUARD="NetShiftGuard"
FK_REL="env NETSHIFT_BLOCK_LEAKS_RELEASE=1"
FK_SB_PKGS="sing-box sing-box-tiny sing-box-extended podkop-engine podkop-engine-full"
FK_DEPS_OWN="$ZM_STATE_DIR/netshift.deps"
FK_DL_NFT="/usr/share/nftables.d/table-post/90-zm-dnsloop.nft"
FK_DL_CHAIN="zm_dnsloop"
FK_FILES="/usr/lib/netshift /usr/lib/netshift.zm-old /etc/netshift /usr/bin/netshift /etc/init.d/netshift /etc/rc.d/*netshift /etc/config/netshift /etc/config/netshift-opkg /etc/config/netshift-070 /etc/config/netshift.apk-new \
/etc/init.d/netshift-naive /etc/rc.d/*netshift-naive /var/run/netshift* /var/lock/netshift* /tmp/netshift* /tmp/local-ruleset.json /tmp/local-ruleset.srs /tmp/sing-box-config.json /tmp/sing-box/rulesets /tmp/sing-box/subscription* \
/www/luci-static/resources/view/netshift /usr/share/luci/menu.d/luci-app-netshift.json /usr/share/rpcd/acl.d/luci-app-netshift.json \
/tmp/zm-fk-* /tmp/zm-zash /tmp/zm-zash.zip /opt/zapret-manager-luci/fk-rs $FK_DL_NFT"

_fk_say() { echo "==> $*"; }
_fk_installed() { [ -x /usr/bin/netshift ] && [ -f /usr/lib/netshift/constants.sh ]; }
_fk_version() { sed -n 's/^NETSHIFT_VERSION="\([^"]*\)".*/\1/p' /usr/lib/netshift/constants.sh 2>/dev/null | head -n1; }
_fk_enabled() { ls /etc/rc.d/S*netshift >/dev/null 2>&1; }
FK_SB_PROCS="sing-box sing-box-core"
_fk_sb_alive() { pidof $FK_SB_PROCS >/dev/null 2>&1; }
# После (пере)запуска sing-box пару минут серверы могут не отвечать на проверку, пока качаются наборы правил:
# в это окно сторож не уводит выбранный сервер на «Авто», а выбор пользователя возвращается без проверки
FK_WARM="/tmp/zm-fk-warm"
_fk_warm_mark() { echo $(( $(date +%s) + ${1:-300} )) > "$FK_WARM"; }
_fk_warm() { local t; t="$(cat "$FK_WARM" 2>/dev/null)"; case "$t" in ''|*[!0-9]*) return 1 ;; esac; [ "$t" -gt "$(date +%s)" ]; }
_fk_sb_newpid() {
	local p o f="$JOBS_DIR/fk.sbpid"
	p="$(pidof $FK_SB_PROCS 2>/dev/null | awk '{ print $1 }')"
	[ -n "$p" ] || return 0
	o="$(cat "$f" 2>/dev/null)"
	[ "$p" = "$o" ] && return 0
	mkdir -p "$JOBS_DIR"; echo "$p" > "$f"
	[ -n "$o" ] && _fk_warm_mark 300
	return 0
}
_fk_nft_on() { nft list chain inet "$FK_NFT" mangle >/dev/null 2>&1 || nft list table inet "$FK_NFT" >/dev/null 2>&1; }
_fk_up() { _fk_sb_alive && _fk_nft_on; }
FK_SERIAL_DIR="/var/run/netshift-zm-serial"
_fk_sb_ver() { command -v sing-box >/dev/null 2>&1 && sing-box version 2>/dev/null | head -n1 | awk '{print $NF}'; }
_fk_sb_pkg() { local p; for p in sing-box-tiny sing-box sing-box-extended podkop-engine podkop-engine-full; do _pkg_is_installed "$p" && { echo "$p"; return 0; }; done; return 1; }
_fk_sb_var() {
	local v
	v="$(_fk_sb_ver)"
	[ -n "$v" ] || { echo ""; return 0; }
	case "$v" in *-lite*) echo lite; return 0 ;; *extended*) echo extended; return 0 ;; esac
	[ "$(head -c 2 /usr/bin/sing-box 2>/dev/null)" = "#!" ] && [ -f /usr/libexec/sing-box-core ] && { echo lite; return 0; }
	case "$(_fk_sb_pkg)" in
		sing-box-tiny) echo tiny ;;
		sing-box) echo stable ;;
		sing-box-extended) echo extended ;;
		*) echo manual ;;
	esac
}
_fk_sb_name() { case "$1" in tiny) echo Облегчённый ;; stable) echo Обычный ;; extended) echo Расширенный ;; lite|compact) echo "Расширенный облегчённый" ;; manual) echo "установлен вручную" ;; *) echo "$1" ;; esac; }
FK_SBL_REPO="yandexru45/sing-box-extended-lite"
_fk_sbl_latest() {
	curl -Ls --connect-timeout 5 --max-time 10 -o /dev/null -w '%{url_effective}' "https://github.com/$FK_SBL_REPO/releases/latest" 2>/dev/null |
		sed -n 's#.*/tag/[vV]\{0,1\}##p' | head -n1
}
_fk_lite_state() {
	_fk_lite_arch >/dev/null || { echo arch; return 0; }
	_fk_installed && ! _fk_lite_engine && { echo engine; return 0; }
	echo ok
}
_fk_sbx_latest() {
	curl -Ls --connect-timeout 5 --max-time 10 -o /dev/null -w '%{url_effective}' "https://github.com/shtorm-7/sing-box-extended/releases/latest" 2>/dev/null |
		sed -n 's#.*/tag/[vV]\{0,1\}##p' | head -n1
}
_fk_foreign() {
	if [ "$PKG" = apk ]; then apk info -e netshift >/dev/null 2>&1 || apk info -e luci-app-netshift >/dev/null 2>&1
	else [ -f /usr/lib/opkg/info/netshift.control ] || [ -f /usr/lib/opkg/info/luci-app-netshift.control ]; fi
}
_fk_ours() { _fk_installed && ! _fk_foreign; }
_fk_name() { if _fk_foreign; then echo NetShift; else echo Forkozz; fi; }
_fk_uc() { command -v ucode >/dev/null 2>&1 && [ -f "$FK_UC" ] || { echo '{"error":"Forkozz не установлен"}'; return 1; }; ucode "$FK_UC" "$@"; }
_fk_grp_keep() { ls "$ZM_STATE_DIR"/fk.grp.* "$ZM_STATE_DIR"/fk.pin.* >/dev/null 2>&1 || return 0; _fk_uc grpkeep >/dev/null 2>&1; return 0; }

_fk_latest() { _zm_cached netshift _fk_latest_fetch; }

_fk_blocker() {
	_pkg_is_installed https-dns-proxy && { echo doh; return; }
	{ _pkg_is_installed podkop || _pkg_is_installed podkop-plus || [ -x /etc/init.d/podkop ] || [ -x /etc/init.d/podkop-plus ]; } && { echo podkop; return; }
	[ -n "$(_zm_px_foreign)" ] && { echo foreign; return; }
	{ _pkg_is_installed luci-app-passwall || _pkg_is_installed luci-app-passwall2 || [ -x /etc/init.d/passwall ] || [ -x /etc/init.d/passwall2 ]; } && { echo passwall; return; }
	{ _pkg_is_installed nextdns || [ -x /etc/init.d/nextdns ]; } && { echo nextdns; return; }
	[ -x "$MIHOMO_BIN" ] && { echo mixomo; return; }
	_st_installed 2>/dev/null && { echo steer; return; }
	echo ""
}

_fk_blocker_text() {
	case "$1" in
		doh) echo "Стоит DNS over HTTPS — Forkozz шифрует DNS сам. Удалите DoH на его вкладке." ;;
		podkop) echo "Стоит Podkop — он тоже перехватывает трафик. Удалите его." ;;
		foreign) echo "Стоит $(_zm_px_foreign) — он работает на том же sing-box и тоже перехватывает трафик и DNS. Вместе с Forkozz они сломают друг друга: удалите $(_zm_px_foreign) или не ставьте Forkozz." ;;
		passwall) echo "Стоит PassWall — он тоже перехватывает трафик. Удалите его." ;;
		nextdns) echo "Стоит NextDNS — он тоже перехватывает DNS. Удалите его." ;;
		mixomo) echo "Стоит Mixomo — он тоже перехватывает трафик и DNS. Удалите его на вкладке Mixomo." ;;
		steer) echo "Стоит Steer — он тоже направляет сервисы в туннель. Удалите его на вкладке Steer." ;;
		*) echo "$1" ;;
	esac
}

_fk_warn() {
	local w=""
	[ -x /usr/bin/bytetube ] && /etc/init.d/bytetube enabled 2>/dev/null && w="$w bytetube"
	[ "$(uci -q get netshift.settings.block_leaks)" = 1 ] && [ -f /usr/lib/netshift/kill_switch.sh ] && ! _fk_up && ! _job_running forkop && w="$w leaks"
	echo $w
}

_fk_health() {
	_fk_ours || { echo 0; return; }
	_fk_enabled || { echo 5; return; }
	_fk_up && echo 1 || echo 2
}

forkop_status() {
	local inst=false ver="" latest="" newer=false en=false up=false sb sbp="" blk busy=false warn="" x sbu=""
	_fk_installed && { inst=true; ver="$(_fk_version)"; }
	latest="$(_fk_latest)"
	[ -n "$ver" ] && [ -n "$latest" ] && _st_ver_lt "$ver" "$latest" && newer=true
	_fk_enabled && en=true
	_fk_up && up=true
	sb="$(_fk_sb_ver)"
	sbp="$(_fk_sb_var)"
	[ "$inst" = false ] && [ -n "$sb" ] && sbu="$(_fk_sb_users)"
	blk="$(_fk_blocker)"
	_job_running forkop && busy=true
	for x in $(_fk_warn); do warn="$warn${warn:+,}\"$x\""; done
	printf '{"installed":%s,"version":"%s","latest":"%s","newer":%s,"enabled":%s,"running":%s,"managed":%s,"foreign":%s,"singbox":"%s","singbox_pkg":"%s","singbox_users":"%s","blocker":"%s","blocker_text":"%s","warn":[%s],"busy":%s,"lan_ip":"%s","watch":%s,"hosts_extra":%s,"sb_lite":"%s"}\n' \
		"$inst" "$(esc "$ver")" "$(esc "$latest")" "$newer" "$en" "$up" \
		"$([ -f "$FK_MARK" ] && echo true || echo false)" "$(_fk_foreign && echo true || echo false)" \
		"$(esc "$sb")" "$(esc "$sbp")" "$(esc "$sbu")" "$(esc "$blk")" "$(esc "$(_fk_blocker_text "$blk")")" "$warn" "$busy" \
		"$(esc "$(_zm_lan_ip)")" \
		"$(awk '{print $1 + 0; exit}' "$ZM_STATE_DIR/fk.watch" 2>/dev/null | grep . || echo 0)" "$(_hosts_extra)" "$(_fk_lite_state)"
}

_fk_sb_install() {
	local v up=0 own=""
	rm -f /tmp/zm-fk-rlcore
	v="$(_fk_sb_ver)"
	if [ -n "$v" ] && ! _st_ver_lt "$v" 1.12.0 && [ -x /etc/init.d/sing-box ]; then
		_fk_say "sing-box $v уже установлен ($(_fk_sb_name "$(_fk_sb_var)")) — оставляем его"
		return 0
	fi
	if [ -n "$v" ] && _st_ver_lt "$v" 1.12.0; then _fk_say "sing-box $v слишком старый для Forkozz (нужен 1.12 и новее) — заменяем"
	elif [ -n "$v" ]; then _fk_say "У sing-box $v нет службы запуска — ставим заново"; fi
	if [ "$1" != stable ] && _fk_lite_arch >/dev/null && _fk_lite_engine; then
		/etc/init.d/netshift running >/dev/null 2>&1 && up=1
		_fk_sb_init_write && own=1
		ZM_FK_SB_NESTED=1; ZM_FK_SB_FRESH=1
		do_fk_singbox lite norestart; v=$?
		ZM_FK_SB_NESTED=""; ZM_FK_SB_FRESH=""
		[ "$up" = 0 ] && /etc/init.d/netshift running >/dev/null 2>&1 && _zm_run 60 $FK_REL /etc/init.d/netshift stop >/dev/null 2>&1
		if [ "$v" = 0 ] && [ "$(_fk_sb_var)" = lite ]; then
			mkdir -p "$ZM_STATE_DIR"; echo sing-box > "$FK_SB_OWN"
			return 0
		fi
		[ -n "$own" ] && [ -z "$(_fk_sb_pkg)" ] && rm -f /etc/init.d/sing-box /etc/config/sing-box
		_fk_say "Расширенный облегчённый sing-box не встал — ставим облегчённый из репозитория OpenWrt. Перейти на расширенный облегчённый можно позже в «Настройках» → sing-box"
	elif [ "$1" != stable ] && ! _fk_lite_arch >/dev/null; then
		_fk_say "Расширенного облегчённого sing-box для этого роутера ($TG_ARCH) нет — ставим облегчённый из репозитория OpenWrt"
	fi
	if [ "$1" != stable ] && _fk_sb_pkg_switch tiny; then :
	else
		[ "$1" != stable ] && _fk_say "Облегчённого sing-box для этого роутера нет — ставим обычный"
		_fk_sb_pkg_switch stable || { echo "ОШИБКА: sing-box не установился"; return 1; }
	fi
	_fk_sb_pkg > "$FK_SB_OWN"
	_fk_say "sing-box $(_fk_sb_ver) установлен ($(_fk_sb_name "$(_fk_sb_var)"))"
	return 0
}

_fk_sb_users() {
	local p u=""
	for p in podkop podkop-plus forkop luci-app-forkop tachyon luci-app-tachyon luci-app-passwall luci-app-passwall2 luci-app-homeproxy homeproxy luci-app-ssr-plus luci-app-momo momo; do
		_pkg_is_installed "$p" && u="$u${u:+, }$p"
	done
	for p in podkop podkop-plus forkop tachyon passwall passwall2 homeproxy momo; do
		[ -x "/etc/init.d/$p" ] && ! echo ", $u," | grep -q ", $p," && u="$u${u:+, }$p"
	done
	echo "$u"
}

FK_RS_DIR="/opt/zapret-manager-luci/fk-rs"
FK_RS_MAXF=2097152
FK_RS_MAXT=4194304
FK_RS_FREE=2048

FK_FIP_DEF="198.18.0.0/15"
_fk_fip_live() {
	nft list chain inet "$FK_NFT" mangle 2>/dev/null | sed -n 's/.*ip daddr \(198\.\(1[89]\|2[0-3]\)\.[0-9.]*\/[0-9]*\) meta mark set.*/\1/p' | head -n1
}
_fk_fip_file() { sed -n 's/^SB_FAKEIP_INET4_RANGE="\([0-9./]*\)"$/\1/p' /usr/lib/netshift/constants.sh 2>/dev/null | head -n1; }
_fk_fip_stale() {
	local l f
	l="$(_fk_fip_live)"; f="$(_fk_fip_file)"
	[ -n "$l" ] && [ -n "$f" ] && [ "$l" != "$f" ]
}

_fk_rs_fatal() {
	local m="$FK_LOGMARK"
	if [ -z "$m" ]; then [ "$1" = recent ] || return 0; fi
	logread 2>/dev/null | { if [ -n "$m" ]; then cat; else tail -n 400; fi; } |
		awk -v m="$m" 'm != "" && !f { if (index($0, m)) f = 1; next } /sing-box/ && /initial rule-set/ { l = $0 } END { if (l != "") print l }' |
		sed 's/\x1b\[[0-9;]*m//g' | awk '
		function rsw(r) {
			if (r ~ /deadline exceeded|i\/o timeout|[Tt]imeout|timed out/) return "сервер не ответил вовремя"
			if (r ~ /connection reset|EOF|broken pipe|forcibly closed/) return "соединение оборвалось"
			if (r ~ /connection refused/) return "сервер отказал в соединении"
			if (r ~ /network is unreachable|no route to host|host is unreachable/) return "нет связи с сервером"
			if (r ~ /no such host|lookup |server misbehaving/) return "не удалось узнать адрес сервера (DNS)"
			if (r ~ /x509|certificate|tls: /) return "не установилось защищённое соединение"
			if (r ~ /operation not permitted/) return "запрос заблокировал сам роутер: правила или туннель ещё не были готовы"
			if (match(r, /(status|code)[: ]+[0-9][0-9][0-9]/)) return "сервер ответил ошибкой " substr(r, RSTART + RLENGTH - 3, 3)
			return substr(r, 1, 160)
		}
		function rsbase(u) { sub(/[?#].*$/, "", u); sub(/^.*\//, "", u); return u }
		{
			t = ""; u = ""; r = ""
			if (match($0, /initial rule-set: [^:]+:/)) t = substr($0, RSTART + 18, RLENGTH - 19)
			if (match($0, /"https?:\/\/[^"]+"/)) { u = substr($0, RSTART + 1, RLENGTH - 2); r = substr($0, RSTART + RLENGTH); sub(/^:[ ]*/, "", r) }
			else if (match($0, /initial rule-set: [^:]+: /)) r = substr($0, RSTART + RLENGTH)
			print t "\t" u "\t" rsw(r)
		}'
}

_fk_naive_own() {
	[ -e /usr/bin/naive ] || return 0
	_pkg_is_installed naiveproxy && return 0
	echo /usr/bin/naive
}

_fk_wait_up() {
	local i=0 max="$1"
	while [ "$i" -lt "$max" ]; do
		_fk_ready && break
		sleep 1
		i=$((i + 1))
		[ "$i" = 20 ] && printf 'Подождите '
		[ "$i" -gt 20 ] && [ $((i % 5)) = 0 ] && printf '.'
		[ "$i" = "$max" ] && [ "$max" = "$1" ] && _fk_engine_busy && max=$((max + 150))
	done
	[ "$i" -ge 20 ] && echo
	_fk_ready
}

_fk_why() {
	local l
	if [ -n "$FK_LOGMARK" ]; then
		l="$(logread 2>/dev/null | awk -v m="$FK_LOGMARK" 'f { print } index($0, m) { f = 1 }' | grep -E 'netshift|sing-box' | grep -E 'fatal|FATAL|Aborted|error|is not started: no section' | tail -n 1)"
	else
		l="$(logread 2>/dev/null | tail -n 200 | grep -E 'netshift|sing-box' | grep -E 'fatal|FATAL|Aborted|error|is not started: no section' | tail -n 1)"
	fi
	case "$l" in
		*"initial rule-set"*) echo "sing-box не смог скачать набор правил при запуске (подробности выше)" ;;
		*"no section has a connection yet"*) echo "ни в одной секции нет подключения — добавьте ссылку на сервер или подписку" ;;
		*"Outbound section not found"*) echo "ни в одной секции нет настроенного подключения" ;;
		*"Invalid service in community lists"*) echo "в секции выбран список, которого Forkozz не знает — сохраните сервисы заново" ;;
		*"configuration"*"is invalid"*) echo "sing-box не принял собранный конфиг — посмотрите журнал" ;;
		*"version"*"lower than the required"*) echo "sing-box слишком старый — замените его в «Настройках»" ;;
		*"Service 'sing-box' is missing"*) echo "нет службы sing-box — переустановите sing-box в «Настройках»" ;;
		*"Proxy string is not set"*|*"links is not set"*) echo "в секции нет ни одного сервера" ;;
		*"VPN interface is not set"*) echo "в секции не выбран туннель" ;;
	esac
}

_fk_rl_si() {
	local fp mk n
	fp="$(uci -q get "netshift.$1.zm_rl_fp")"; mk="$(uci -q get "netshift.$1.zm_rl_mk")"
	n="$(uci -q get "netshift.$1.zm_rl_node" | wc -w)"; n=$((n / 3))
	[ -n "$fp$mk" ] || [ "$n" -gt 0 ] || return 0
	printf ' · REALITY: отпечаток %s, ключ %s' "$(case "${fp:-auto}" in auto) echo авто ;; sub) echo как в подписке ;; *) echo "$fp" ;; esac)" \
		"$(case "${mk:-auto}" in on) echo включён ;; off) echo выключен ;; *) echo авто ;; esac)"
	[ "$n" -gt 0 ] && printf ', свои настройки у серверов: %s' "$n"
	return 0
}

_fk_engine_state() {
	local j p x n q k=0
	j="$(ubus call service list '{"name":"netshift"}' 2>/dev/null)"
	p="$(printf '%s' "$j" | jsonfilter -e '@.netshift.instances[*].pid' 2>/dev/null | head -n 1)"
	if printf '%s' "$j" | grep -q '"running": *true' && [ -n "$p" ] && [ -d "/proc/$p" ]; then
		q="$p"; n=""
		while [ -n "$q" ] && [ "$k" -lt 4 ]; do
			x=""
			for p in $q; do x="$x $(cat "/proc/$p/task/$p/children" 2>/dev/null)"; done
			q="$(echo $x)"; k=$((k + 1))
			for p in $q; do n="$n $(sed -n 's/^Name:[[:space:]]*//p' "/proc/$p/status" 2>/dev/null)"; done
		done
		n="$(printf '%s\n' $n | grep -vxE 'sh|ash|sleep|logger' | awk '!s[$0]++' | head -n 4 | tr '\n' ' ' | sed 's/ $//; s/ /, /g')"
		echo "движок NetShift ещё не закончил запуск${n:+ (сейчас работает: $n)}"
	else
		x="$(printf '%s' "$j" | jsonfilter -e '@.netshift.instances[*].exit_code' 2>/dev/null | head -n 1)"
		case "$x" in ''|0) ;; *) echo "движок NetShift завершился с ошибкой (код $x)" ;; esac
	fi
}

FK_DLC_ON=/tmp/zm-fk-dlcache.on
do_fk_service() {
	local rc
	[ "$1" = stop ] && { _fk_service0 "$@"; return; }
	: > "$FK_DLC_ON" 2>/dev/null
	_fk_service0 "$@"; rc=$?
	rm -f "$FK_DLC_ON"
	return $rc
}

_fk_service0() {
	local a="$1" b
	_fk_installed || { echo "ОШИБКА: Forkozz не установлен"; return 1; }
	case "$a" in
		stop)
			_fk_say "Выключаем Forkozz — трафик пойдёт напрямую"
			/etc/init.d/netshift disable >/dev/null 2>&1
			echo "   ✓ Убран из автозапуска"
			_zm_run 90 $FK_REL /etc/init.d/netshift stop >/dev/null 2>&1
			nft delete table inet "$FK_NFT" >/dev/null 2>&1
			nft delete table inet "$FK_NFT_GUARD" >/dev/null 2>&1
			if nft list table inet "$FK_NFT" >/dev/null 2>&1; then echo "!! Служба остановлена, но её правила в firewall остались — перезагрузите роутер"
			else echo "   ✓ Служба остановлена, правила сняты"; fi
			_ab_free_sync >/dev/null 2>&1
			_fk_say "Готово: Forkozz выключен"
			return 0 ;;
	esac
	_fk_dns_migrate >/dev/null 2>&1
	_fk_device_setup || return 1
	b="$(_fk_blocker)"
	[ -n "$b" ] && { echo "ОШИБКА: $(_fk_blocker_text "$b")"; return 1; }
	[ -n "$(_fk_sb_ver)" ] || _fk_sb_install || return 1
	_fk_ext_auto config "" norestart
	_fk_naive_auto
	_fk_log_default
	if _fk_sub_fmt_auto; then
		_fk_say "Скачиваем подписку в новом формате"
		if _fk_sub_update; then echo "   ✓ Подписка обновлена"
		else echo "!! Подписка в новом формате не обновилась — Forkozz возьмёт её при следующем обновлении"; fi
	fi
	local lx; lx="$(_fk_log_ext)"
	/etc/init.d/netshift enable >/dev/null 2>&1
	_fk_fast_patch
	_fk_mlkem_patch
	_fk_serial_patch
	_fk_listsvia_patch
	_fk_subvia_patch
	_fk_reality_patch
	_fk_rsinit_patch
	_fk_desync_patch
	_fk_ksgap_patch
	_fk_naivesni_patch
	_fk_fakeip_patch
	_fk_ghdl_patch
	_fk_subck_patch
	_fk_hdr_patch
	_fk_dnslan_patch noreload
	_fk_dnsloop_patch noreload
	_fk_autogrp_sync quiet cached
	mkdir -p /etc/sing-box
	_fk_log_mark
	: > "$JOBS_DIR/forkop-svc.out"
	_fk_settle 180 "Forkozz ещё заканчивает прошлую операцию (запуск или применение подписки) — ждём её" ||
		_rb_warn "Прошлая операция Forkozz не закончилась за 3 минуты — продолжаем, движок выполнит нашу следом"
	_fk_warm_mark 900
	if [ "$a" = apply ] && _fk_up && _fk_fip_stale; then
		_fk_say "Пул Fake IP теперь $(_fk_fip_file) — перезапускаем Forkozz полностью"
		a=start
	fi
	if [ "$a" = apply ] && _fk_up; then
		_fk_say "Применяем настройки: Forkozz пересобирает конфиг sing-box и подхватывает списки"
		_zm_run 240 /usr/bin/netshift reload >> "$JOBS_DIR/forkop-svc.out" 2>&1 || echo "!! Перезагрузка настроек завершилась с ошибкой"
	else
		_fk_say "Запускаем Forkozz: собираем конфиг sing-box, скачиваем списки, ставим правила"
		if _fk_up || _fk_sb_alive || nft list table inet "$FK_NFT" >/dev/null 2>&1; then
			_zm_run 90 /etc/init.d/netshift stop >> "$JOBS_DIR/forkop-svc.out" 2>&1
		fi
		_fk_start_once || echo "!! Запуск завершился с ошибкой"
	fi
	_fk_svc_report
	if ! _fk_ready; then
		_fk_say "Ждём, пока поднимутся sing-box и правила (до 90 с)"
		_fk_wait_up 90
	fi
	if ! _fk_up; then
		_fk_rs_check
		if [ "$?" = 1 ]; then
			b="$(_fk_why)"
			_rb_warn "Forkozz не поднялся${b:+: $b}"
		fi
		_fk_say "Пробуем ещё раз: снимаем остатки прошлого запуска и запускаем заново"
		_fk_log_mark
		_fk_reset_runtime
		: > "$JOBS_DIR/forkop-svc.out"
		_fk_start_once || echo "!! Повторный запуск завершился с ошибкой"
		_fk_svc_report
		_fk_ready || _fk_wait_up 90
	fi
	rm -f "$JOBS_DIR/forkop-svc.out"
	if _fk_up; then
		_fk_say "Проверяем, что всё работает"
		_fk_check_live
		_fk_warm_mark 300
		_fk_sb_newpid
		_fk_grp_keep
		_fk_sub_wait 90
		_fk_ext_auto all "$lx"
		_fk_lists_wait 240 || _rb_warn "Списки ещё скачиваются — числа ниже могут быть неполными. Они догрузятся сами; позже нажмите «Обновить списки сейчас», чтобы увидеть итог"
		_fk_dlc_note
		_fk_lists_report
		_fk_lists_errors
		if _fk_sb_settle 60; then b=1; else _fk_rs_check; b=$?; fi
		if [ "$b" = 0 ]; then
			_fk_say "Перезапускаем Forkozz с новой настройкой"
			_fk_log_mark
			_fk_reset_runtime
			: > "$JOBS_DIR/forkop-svc.out"
			_fk_start_once || echo "!! Запуск завершился с ошибкой"
			_fk_svc_report
			rm -f "$JOBS_DIR/forkop-svc.out"
			_fk_ready || _fk_wait_up 90
			if _fk_sb_settle 90; then b=1; else _fk_rs_check; b=$?; fi
			if [ "$b" = 1 ] && _fk_up; then
				echo "   ✓ sing-box запустился — наборы правил скачались через VPN"
				_fk_lists_wait 240 || _rb_warn "Списки ещё скачиваются — они догрузятся сами"
				_fk_lists_errors
			fi
		fi
		if [ "$b" != 1 ] || ! _fk_up; then
			echo "ОШИБКА: Forkozz не работает — sing-box не запустился. Если GitHub у провайдера не открывается, проверьте сервер подключения и включите «Авто» в Система → Доступ к GitHub."
			_zm_reboot_hint "Forkozz не запустился: sing-box не смог скачать наборы правил с GitHub."
			return 1
		fi
		_fk_clash_ok || echo "!! sing-box пока не отвечает — он ещё запускается; если так и останется, нажмите «Перезапустить»"
		_fk_servers_report
		_fk_rl_report
		if [ -s /tmp/zm-fk-rlalt.json ]; then
			_fk_say "Проверяем новые серверы REALITY с ключом X25519MLKEM768 и без"
			_fk_rl_learn_run '{"max":60}'
		fi
		_ab_free_sync >/dev/null 2>&1
		_fk_zash_ensure
		local ps
		for ps in $(_fk_uc secnames 2>/dev/null); do
			[ "$(uci -q get netshift."$ps".zm_sub_priority)" = 1 ] && _fk_fallback_sec "$ps" >/dev/null 2>&1 &
		done
		_fk_fwd_sync
		_fk_warm_mark 300
		_fk_sb_newpid
		_fk_grp_keep
		_fk_say "Готово: Forkozz работает"
		_fk_guard
		grep -q '^Forkozz не запустился' "$ZM_REBOOT_HINT" 2>/dev/null && rm -f "$ZM_REBOOT_HINT"
		return 0
	fi
	[ -n "$(_fk_rs_fatal)" ] && _fk_rs_check
	b="$(_fk_why)"
	echo "ОШИБКА: Forkozz не запустился${b:+: $b}. Если ошибка повторяется, перезагрузите роутер — это сбросит всё, что осталось от прошлых запусков."
	_zm_reboot_hint "Forkozz не запустился. Перезагрузите роутер — это сбросит всё, что осталось от прошлых запусков, — и включите Forkozz снова."
	b="$(_fk_engine_state)"
	[ -n "$b" ] && echo "Состояние: $b"
	echo "Последние записи журнала:"
	logread 2>/dev/null | { if [ -n "$FK_LOGMARK" ]; then awk -v m="$FK_LOGMARK" 'f { print } index($0, m) { f = 1 }'; else cat; fi; } |
		grep -E 'netshift|sing-box' | grep -v 'DEBUG\|\[debug\]\|udhcpc\|is deprecated\|deprecated in sing-box' |
		sed 's/\x1b\[[0-9;]*m//g; s/\[[0-9;]*m//g' | tail -n 10 | sed 's/^[^]]*\]: //; s/^/   /'
	return 1
}

FK_EXT_FAIL="$ZM_STATE_DIR/fk.ext.fail"
FK_NAIVE_FAIL="$ZM_STATE_DIR/fk.naive.fail"
_fk_log_ext() { logread 2>/dev/null | grep -ci 'requires sing-box-extended'; }

FK_DNS_Q="AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

_zm_route_target() {
	local q
	q="$(printf '%s' "$1" | tr -d ' \t\r\n' | tr 'A-Z' 'a-z' | sed 's#^[a-z0-9+.-]*://##; s#^[^/@]*@##; s#[/?\#].*$##')"
	case "$q" in
		\[*\]*) q="${q#\[}"; q="${q%%\]*}" ;;
		*:*:*) ;;
		*:*) q="${q%%:*}" ;;
	esac
	printf '%s' "$q" | grep -Eq '^([a-z0-9]([a-z0-9_-]{0,62}\.)+[a-z0-9-]{1,63}|[0-9a-f:]{2,39})$' || return 1
	printf '%s' "$q"
}

_zm_resolve4() {
	nslookup "$1" 127.0.0.1 2>/dev/null | awk '/^Name:/ { f = 1; next } f && /^Address/ { a = $0; sub(/^Address[ 0-9]*:[ \t]*/, "", a); if (a ~ /^[0-9.]+$/) { print a; exit }}' | head -n1
}

_zm_resolve_any() {
	local a
	a="$(_zm_resolve4 "$1")"
	[ -n "$a" ] || a="$(nslookup "$1" 127.0.0.1 2>/dev/null | awk '/^Name:/ { f = 1; next } f && /^Address/ { a = $0; sub(/^Address[ 0-9]*:[ \t]*/, "", a); print a; exit }')"
	printf '%s' "$a"
}

_tsc_leftovers() {
	local z lz
	_tsc_installed && return 0
	uci -q get netshift.settings.source_network_interfaces | tr ' ' '\n' | grep -qx "$TSC_DEV" && echo "Forkozz ждёт трафик с $TSC_DEV"
	[ -f "$TSC_ON" ] && echo "панель считает удалённый доступ включённым"
	uci -q get "network.$TSC_NET" >/dev/null && echo "интерфейс «$TSC_NET» в сети"
	lz="$(_zm_lan_zone)"
	z="$(_zm_zone_sec "$lz" 2>/dev/null)" && case " $(uci -q get "firewall.$z.network") " in *" $TSC_NET "*) echo "«$TSC_NET» в зоне «$lz»" ;; esac
	uci -q get "firewall.$TSC_FW_RULE" >/dev/null && echo "правило firewall Allow-Tailscale"
	_tsc_nft_left && echo "правила Tailscale в firewall (ts-*)"
	_tsc_ip_rules_left && echo "правила маршрутизации Tailscale (таблица 52)"
	[ -f "$TSC_LS_PREV" ] && echo "изменённая настройка DNS роутера (localservice)"
	grep -qF "$TSC_CRON_TAG" "$CRON_FILE" 2>/dev/null && echo "сторож Tailscale в cron"
	return 0
}

SI_OUT="$JOBS_DIR/sysinfo.json"

SI_DOH_INIT="/etc/init.d/https-dns-proxy"

AB_DIR="$ZM_STATE_DIR/adblock"
AB_SET="$AB_DIR/settings"
AB_ALLOW="$AB_DIR/allow.txt"
AB_BLOCK="$AB_DIR/block.txt"
AB_NAME="zm-adblock.conf"
AB_CRON_TAG="# zm-adblock"
AB_FREE="$AB_DIR/free.txt"
AB_FREE_PORT=53535
AB_FREE_CONF="/var/etc/zm-adblock-free.conf"
AB_FREE_PID="/var/run/zm-adblock-free.pid"
AB_FREE_NFT="zm_adblock_free"
AB_STATS_CONF="zm-adblock-stats.conf"
AB_STATS_LOG="/var/run/dnsmasq/zm-queries.log"
AB_STATS_DIR="/tmp/zm-adblock-stats"
AB_STATS_CRON="# zm-abstats"
AB_STATS_ALL="$AB_DIR/stats-all.txt"
AB_KEY_AWK='
function abmap(f,   l, a) { while ((getline l < f) > 0) { split(l, a, "\t"); if (a[1] == "R") R[a[2]] = 1; else if (a[1] == "M") M[a[2]] = a[3]; else if (a[1] == "F") F4[a[2]] = a[3]; else if (a[1] == "N") N[a[2]] = a[3]; else if (a[1] == "H") H[a[2]] = a[3] } close(f) }
function abkey(k) { if (k == "r" || k == "s" || k ~ /^[mn]:/) return k; if (k in R) return "r"; if (k in M) return "m:" M[k]; if (k in H) return "n:" H[k]; return k }
'
AB_URL_GH="${GH_RAW}/hagezi/dns-blocklists/main/dnsmasq"
AB_URL_CDN="https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/dnsmasq"
AB_ALLOW_DEFAULT='# Переходы по рекламе в поиске Яндекса
yabs.yandex.ru
redirect.appmetrica.yandex.com
trk.mail.ru
s.click.aliexpress.com'

_ab_get() {
	local v
	v="$(_kv_last "$AB_SET" "$1")"
	echo "${v:-$2}"
}
_ab_on() { [ "$(_ab_get on 0)" = 1 ]; }
_ab_dirs() {
	local d
	d="$(sed -n 's/^conf-dir=\([^,]*\).*/\1/p' /var/etc/dnsmasq.conf.* 2>/dev/null | sort -u)"
	echo "${d:-/tmp/dnsmasq.d}"
}
_ab_applied() {
	local d n=0
	for d in $(_ab_dirs); do [ -s "$d/$AB_NAME" ] || return 1; n=1; done
	[ "$n" = 1 ]
}

AB_TG_LIST="$AB_DIR/tg.domains"
AB_TG_URL="${GH_RAW}/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt"
AB_TCH_DOM="android_ads_block telemetry_mobile_block win_spy xiaomi_smarttv_ads gambling_block"
AB_TCH_IP="et_spamhaus_block hagezi_tif_ip_block botnet_attackers_ip_block"
AB_IP_NFT="zm_adblock_ip"
AB_IP_DIR="$AB_DIR/ip"
AB_DNS_STAMP="$AB_DIR/dns.hosts"
_ab_dns_bg() { ( sleep "${1:-20}"; _ab_dns_sync ) >/dev/null 2>&1 </dev/null & }

AB_LF="$AB_DIR/logfacility.saved"
_ab_stats_block() {
	local d f
	for d in $(_ab_dirs); do
		_ab_kw_in log-facility /etc/dnsmasq.conf && { echo "/etc/dnsmasq.conf"; return 0; }
		for f in "$d"/*; do _ab_kw_in log-facility "$f" && { echo "$f"; return 0; }; done
	done
	return 1
}
_ab_lf_files() { [ -s "$AB_LF" ] && cut -d'|' -f2- "$AB_LF" | grep '/' | sort -u; }
_ab_stats_applied() {
	local d n=0
	for d in $(_ab_dirs); do [ -s "$d/$AB_STATS_CONF" ] || return 1; n=1; done
	[ "$n" = 1 ]
}

ZM_MULTI_OK=' status system_info health versions zm_update_status lan_ip bytetube_installed '
_zm_multi_ok() {
	case "$1" in *[!a-z0-9_]*|'') return 1 ;; multi) return 1 ;; *_status|*_get|strategy_list_*|mixomo_proxies) return 0 ;; esac
	case "$ZM_MULTI_OK" in *" $1 "*) return 0 ;; esac
	return 1
}
_zm_multi() {
	local d="$JOBS_DIR/multi.$$" i=0 n line m a f sep=""
	mkdir -p "$d" || { echo '{"error":"нет места в /tmp"}'; return 1; }
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		[ "$i" -ge 16 ] && break
		m="${line%%	*}"; a=""
		case "$line" in *"	"*) a="${line#*	}" ;; esac
		if _zm_multi_ok "$m" && { [ -z "$a" ] || _zm_re "$a" '^[A-Za-z0-9_.:@-]{1,64}$'; }; then
			if [ -n "$a" ]; then ( cmd="$m"; _zm_run_cmd "$a" ) < /dev/null > "$d/$i" 2>/dev/null &
			else ( cmd="$m"; _zm_run_cmd ) < /dev/null > "$d/$i" 2>/dev/null &
			fi
		else
			: > "$d/$i"
		fi
		i=$((i + 1))
	done << ZM_MULTI_EOF
$1
ZM_MULTI_EOF
	wait
	printf '{"r":['
	n=0
	while [ "$n" -lt "$i" ]; do
		f="$d/$n"
		if [ -s "$f" ] && [ "$(head -c 1 "$f")" = "{" ] && case "$(tail -c 8 "$f" | tr -d '\n\r\t ')" in *"}") true ;; *) false ;; esac; then
			printf '%s' "$sep"; cat "$f"
		else
			printf '%s{"__fail":true}' "$sep"
		fi
		sep=","
		n=$((n + 1))
	done
	printf ']}\n'
	rm -rf "$d"
}

OW_LEASES="${ZM_OW_LEASES:-/tmp/dhcp.leases}"
OW_NAMES="$ZM_STATE_DIR/ow.names"
_zm_dname() { [ -n "$1" ] && [ -s "$OW_NAMES" ] && awk -F'\t' -v m="$(printf '%s' "$1" | tr 'A-F' 'a-f')" 'tolower($1) == m && $2 != "" { print $2; f = 1; exit } END { exit !f }' "$OW_NAMES"; }
OW_V6_BAK="$ZM_STATE_DIR/ipv6.off"
OW_RB_TAG="# zm-sched-reboot"
PC_FILE="$ZM_STATE_DIR/parental"
PC_NFT="zm_parental"
PC_TAG="# zm-parental"
PC_MAX=32
OW_V6_KEYS="network.wan6.disabled network.wan.ipv6 dhcp.lan.ra dhcp.lan.dhcpv6 dhcp.lan.ndp dhcp.lan.ra_default network.lan.ip6assign"

OW_WCONF="${ZM_OW_WCONF:-/etc/config/wireless}"
OW_WGUARD="$ZM_STATE_DIR/wifi.guard"
OW_WROLL="$ZM_STATE_DIR/wifi.rollback"

cmd="$1"; shift
_zm_in() {
	ZM_IN="$(cat; echo .)"
	if [ "$ZM_IN" = "@zmupload." ] && [ "$cmd" != upload_part ] && [ -f "$ZM_UP_FILE" ]; then
		ZM_IN="$(cat "$ZM_UP_FILE"; echo .)"
		rm -f "$ZM_UP_FILE"
	fi
}
if [ "$2" = @stdin ]; then _zm_in; set -- "$1" "${ZM_IN%.}"
elif [ "$1" = @stdin ]; then _zm_in; set -- "${ZM_IN%.}"; fi
case "$cmd" in
	strategy_set_v|strategy_set_flowseal|strategy_set_youtube|youtube_quic_set|discord_set_dv|discord_set_fake|game_set|game_set_fake|game_toggle_xtreme)
		[ -f "$CONF" ] && { _nochange_guard || exit 1; } ;;
	test_action)
		[ "$1" = start ] && [ "$2" != current ] && [ -f "$CONF" ] && { _nochange_guard || exit 1; }
		[ "$1" = apply ] && [ -f "$CONF" ] && { _nochange_guard || exit 1; }
		[ "$1" = auto_run ] && [ -f "$CONF" ] && { _nochange_guard || exit 1; } ;;
	zapret_opt_set)
		case "$1" in rkn:*|wssize:*|ipid:*) [ -f "$CONF" ] && { _nochange_guard || exit 1; } ;; esac ;;
esac
case "$cmd:$1" in
	zapret_opt_set:hdrezka:*|zapret_opt_set:vpnskip:*) ;;
	*)
case "$cmd" in
	strategy_set_v|strategy_set_flowseal|strategy_set_youtube|youtube_quic_set|discord_set_dv|discord_set_fake|game_set|game_set_fake|game_toggle_xtreme|zapret_opt_set)
		if [ -n "$ZM_UI_DEFER" ] && [ -f "$CONF" ] && [ ! -s "$TEST_BACKUP" ] && pgrep -f "/opt/zapre[t]/" >/dev/null 2>&1; then
			_pend_begin && ZM_DEFER=1
		fi
		rm -f "$ZM_PEND_DIR/dirty" ;;
esac
case "$cmd" in
	strategy_set_v|strategy_set_flowseal|strategy_set_youtube|youtube_quic_set|discord_set_dv|discord_set_fake|game_set|game_set_fake|game_toggle_xtreme|zapret_opt_set)
		_nfq_canon
		_zc_lift ;;
esac ;;
esac
_zm_run_cmd() {
case "$cmd" in
	status)                  status ;;
	system_info)             system_info ;;
	job_status)               job_status "$1" ;;
	log_tail)                  log_tail "$1" ;;
	zapret_action)              zapret_action "$1" ;;
	zapret2_action)              zapret2_action "$1" ;;
	strategy_list_v)            strategy_list_v ;;
	strategy_set_v)              strategy_set_v "$1" ;;
	strategy_list_flowseal)       strategy_list_flowseal "$1" ;;
	strategy_set_flowseal)         strategy_set_flowseal "$1" ;;
	strategy_list_youtube)          strategy_list_youtube "$1" ;;
	strategy_set_youtube)            strategy_set_youtube "$1" ;;
	youtube_quic_set)                youtube_quic_set "$1" ;;
	discord_status)                 discord_status ;;
	discord_set_dv)                  discord_set_dv "$1" ;;
	discord_set_fake)                 discord_set_fake "$1" ;;
	game_status)                        game_status ;;
	game_set)                            game_set "$1" ;;
	game_set_fake)                        game_set_fake "$1" ;;
	game_toggle_xtreme)                    game_toggle_xtreme ;;
	system_status)                           system_status ;;
	system_check_connectivity)                system_check_connectivity ;;
	system_toggle_quic)                        system_toggle_quic "$1" ;;
	system_toggle_ipv6)                         system_toggle_ipv6 "$1" ;;
	system_toggle_flow_offloading_fix)           system_toggle_flow_offloading_fix "$1" ;;
	system_toggle_steer_offload_fix)             system_toggle_steer_offload_fix "$1" ;;
	system_uninstall_panel)                        system_uninstall_panel "$1" ;;
	purge_scan)                                    purge_scan ;;
	purge_run)                                     purge_run "$1" ;;
	backup_list)                                   backup_list ;;
	backup_action)                                 backup_action "$1" "$2" ;;
	zm_cleanup)                                    zm_cleanup "$1" ;;
	zm_autoclean)                                  zm_autoclean "$1" ;;
	gh_proxy)                                      gh_proxy "$1" "$2" ;;
	webui)                                         webui "$1" "$2" ;;
	gh_mirrors)                                    gh_mirrors ;;
	gh_net)                                        gh_net "$1" "$2" ;;
	gh_get)                                        gh_get "$1" "$2" "$3" ;;
	zm_refs_heal)                                  zm_refs_heal "$1" ;;
	sysinfo_run)                                   sysinfo_run ;;
	sysinfo_get)                                   sysinfo_get ;;
	mirror_status)                                     mirror_status ;;
	mirror_set)                                          mirror_set "$1" ;;
	exclusions_status)                                     exclusions_status ;;
	exclusions_set)                                          exclusions_set "$1" ;;
	zapret_pending)                                          zapret_pending "$1" ;;
	nfqws_opt_get)                                   nfqws_opt_get ;;
	zapret_lists_status)                             zapret_lists_status ;;
	zapret_list_get)                                 zapret_list_get "$1" ;;
	zapret_list_set)                                 zapret_list_set "$1" "$2" ;;
	zapret_list_restore)                             zapret_list_restore "$1" ;;
	nfqws_opt_set)                                   nfqws_opt_set "$1" ;;
	tg_status)                                                   tg_status ;;
	tg_action)                                                    tg_action "$1" "$2" ;;
	tg_auto_tick)                                                 tg_auto_tick "$1" ;;
	zapret_excl_tick)                                             zapret_excl_tick ;;
	tg_restart_all)                                                tg_restart_all ;;
	tgws_status)                                                    tgws_status ;;
	tgws_action)                                                     tgws_action "$1" ;;
	hosts_status)                      hosts_status ;;
	hosts_toggle)                       hosts_toggle "$1" ;;
	hosts_replace_geohide)              hosts_replace_geohide "$1" ;;
	hosts_auto)                         hosts_auto "$1" ;;
	hosts_auto_tick)                    hosts_auto_tick ;;
	hosts_reset)                        hosts_reset ;;
	hosts_file_get)                     hosts_file_get ;;
	hosts_file_set)                     hosts_file_set "$1" ;;
	upload_part)                        upload_part "$1" "$2" ;;
	doh_install)                         doh_install ;;
	doh_remove)                          doh_remove ;;
	doh_status)                          doh_status ;;
	doh_set)                              _doh_locked doh_set "$1" ;;
	doh_probe)                            doh_probe "$1" ;;
	doh_check)                            doh_check ;;
	doh_bootstrap_set)                    _doh_locked doh_bootstrap_set "$1" ;;
	doh_force_set)                        _doh_locked doh_force_set "$1" ;;
	doh_failover_set)                     _doh_locked doh_failover_set "$1" ;;
	doh_own_set)                          doh_own_set "$1" ;;
	doh_power)                            _doh_locked doh_power "$1" ;;
	doh_watch)                            doh_watch ;;
	dns_net_set)                          dns_net_set "$1" ;;
	dns_net_gone)                         dns_net_gone ;;
	test_status)                          test_status ;;
	test_action)                          test_action "$1" "$2" ;;
	test_results)                         test_results "$1" ;;
	zapret_opt_set)                       zapret_opt_set "$1" ;;
	zapret_ports_get)                     zapret_ports_get ;;
	zapret_ports_set)                     zapret_ports_set "$1" "$2" "$3" ;;
	zapret_ports_migrate)                 zapret_ports_migrate ;;
	system_time_set)                      system_time_set "$1" ;;
	zm_update_status)                     zm_update_status ;;
	zm_update_action)                     zm_update_action ;;
	zm_stats_get)                         zm_stats_get ;;
	zm_stats_hit)                         zm_stats_hit ;;
	zm_changelog)                         case "$1" in local|remote|all) zm_changelog "$1" ;; *) echo '{"error":"неизвестный режим"}' ;; esac ;;
	zm_changelog_seen)                    zm_changelog seen ;;
	zm_changelog_sync)                    _zm_cl_sync ;;
	str_refresh)                          str_refresh ;;
	mixomo_status)                        mixomo_status ;;
	mixomo_action)                        mixomo_action "$1" ;;
	mixomo_config_get)                    mixomo_config_get ;;
	mixomo_config_set)                    mixomo_config_set "$1" ;;
	mixomo_subscription_set)              mixomo_subscription_set "$1" ;;
	mixomo_filter_set)                    mixomo_filter_set "$1" ;;
	mixomo_proxies)                       mixomo_proxies ;;
	mixomo_magitrickle_list_set)          mixomo_magitrickle_list_set "$1" ;;
	mixomo_autorestart_set)               mixomo_autorestart_set "$1" "$2" ;;
	mixomo_ui_action)                     mixomo_ui_action "$1" ;;
	mixomo_warp_status)                   mixomo_warp_status ;;
	mixomo_warp_action)                   mixomo_warp_action "$1" ;;
	mixomo_warp_integrate_action)         mixomo_warp_integrate_action ;;
	mixomo_warp_config_set)               mixomo_warp_config_set "$1" ;;
	bytetube_installed)                   bytetube_installed ;;
	health)                               health ;;
	versions)                             versions_status "$1" ;;
	versions_mode)                        versions_mode_set "$1" ;;
	versions_cron)                        versions_cron ;;
	versions_cron_sync)                   _ver_cron_sync ;;
	autoupd)                              autoupd "$1" ;;
	autoupd_run)                          autoupd_run "$1" ;;
	awg_status)                           awg_status ;;
	awg_action)                           awg_action "$1" "$2" ;;
	term_status)                          term_status ;;
	term_action)                          term_action "$1" "$2" ;;
	tsc_status)                           tsc_status ;;
	tsc_action)                           tsc_action "$1" "$2" ;;
	tsc_watch)                            tsc_watch ;;
	tsc_lan_ip)                           _zm_lan_ip ;;
	monitor)                              monitor_snapshot ;;
	ui_net_get)                           ui_net_get "$2" ;;
	monitor_procs)                        monitor_procs ;;
	monitor_action)                       monitor_action "$1" "$2" ;;
	htop_gone)                            htop_gone ;;
	watch_status)                         watch_status ;;
	watch_set)                            watch_set "$1" ;;
	zm_alloff)                            zm_alloff "$1" ;;
	zm_uiram)                             zm_uiram "$1" ;;
	watch_cron_line)                      _watch_line ;;
	adblock_status)                       adblock_status ;;
	adblock_action)                       adblock_action "$1" "$2" ;;
	adblock_cron)                         adblock_cron ;;
	adblock_stats_tick)                   adblock_stats_tick ;;
	steer_status)                         steer_status ;;
	steer_action)                         steer_action "$1" "$2" ;;
	bytetube_action)                      bytetube_action "$1" ;;
	bytetube_sync)                        bytetube_sync ;;
	pc_tick)                              _pc_sync ;;
	forkop_status)                        forkop_status ;;
	forkop_config_get)                    forkop_config_get ;;
	forkop_config_set)                    forkop_config_set "$1" ;;
	forkop_device_setup)                  _fk_device_setup "$1" ;;
	forkop_priority_watch)                _fk_fallback_sec "$1" ;;
	forkop_ping_burst)                    _fk_ping_burst "$1" ;;
	forkop_action)                        forkop_action "$1" "$2" ;;
	lan_ip)                               _zm_lan_ip ;;
	jobs_cancel)                          jobs_cancel "$1" ;;
	system_reboot)                        system_reboot ;;
	reboot_hint_clear)                    reboot_hint_clear ;;
	zm_watch)                             zm_watch ;;
	mem_heal)                             mem_heal ;;
	mixomo_secure)                        mixomo_secure ;;
	zram_status)                          zram_status ;;
	owrt_status)                          owrt_status ;;
	owrt_set)                             owrt_set "$1" "$2" ;;
	owrt_reboot_run)                      owrt_reboot_run ;;
	zsec2_status)                         zsec2_status ;;
	zsec2_action)                         zsec2_action "$1" "$2" ;;
	zsec2_sync)                           zsec2_sync ;;
	zapret_respawn_sync)                  _zp_rsp_sync ;;
	zram_action)                          zram_action "$1" ;;
	events)                               zm_events "$1" ;;
	events_clear)                         zm_events_clear ;;
	ui_theme_set)                         ui_theme_set "$1" ;;
	ui_look_set)                          ui_look_set "$1" ;;
	ui_nav_set)                           ui_nav_set "$1" ;;
	zm_pages)                             zm_pages "$1" "$2" ;;
	ui_flags_get)                         ui_flags_get ;;
	terms_get)                            terms_get ;;
	terms_accept)                         terms_accept ;;
	ui_flag_set)                          ui_flag_set "$1" ;;
	ui_radio_get)                         ui_radio_get ;;
	ui_radio_set)                         ui_radio_set "$1" ;;
	ui_radio_now)                         ui_radio_now "$1" ;;
	adblock_dns_sync)                     _ab_dns_sync ;;
	dns_presets_migrate)                  dns_presets_migrate ;;
	zapret_doh_migrate)                   [ -f "$ZO_DOH_FLAG" ] && [ -f "$CONF" ] && _zo_doh_stale && { _zo_doh_follow; echo '{"changed":true}'; } || echo '{"changed":false}' ;;
	multi)                                _zm_multi "$1" ;;
	*) echo '{"error":"неизвестная команда"}'; exit 1 ;;
esac
}
if [ -n "$ZM_DEFER" ]; then
	zm_out="$(_zm_run_cmd "$@")"
	zm_rc=$?
	[ -n "$ZC_LIFTED" ] && _zc_drop
	if _pend_same; then
		_pend_clear
		printf '%s\n' "$zm_out" | sed '$ s/"pending":true/"pending":false/'
	elif [ -f "$ZM_PEND_DIR/dirty" ]; then
		printf '%s\n' "$zm_out" | sed '$ s/}[[:space:]]*$/,"pending":true}/'
	else
		printf '%s\n' "$zm_out"
	fi
	exit $zm_rc
fi
_zm_run_cmd "$@"
zm_rc=$?
[ -n "$ZC_LIFTED" ] && _zc_drop
exit $zm_rc
