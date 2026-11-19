#!/bin/ash
# plugin-manager backend — управление манифест-плагинами через zm-pluginctl.
# Контракт: действие = $1, аргументы формы = $2.., ответ = JSON в stdout.

PLUG_DIR="/etc/zm-plugins"
LOG=/tmp/zm-plugin-manager.log
CTL=/usr/sbin/zm-pluginctl

jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
jlog() { # многострочный текст со stdin → json-строка
	sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a; N; $!ba; s/\n/\\n/g'
}
stamp() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }
run_ctl() { # $1=команда, $2=аргумент → печатает JSON результата
	local out rc
	out="$("$CTL" "$1" "$2" 2>&1)"; rc=$?
	stamp "$1 $2 → rc=$rc $(echo "$out" | head -n 1)"
	if [ $rc = 0 ]; then
		printf '{"ok":true,"message":"%s","log":"%s"}' "$(jesc "$(echo "$out" | head -n 1)")" "$(echo "$out" | jlog)"
	else
		printf '{"ok":false,"error":"%s"}' "$(jesc "$(echo "$out" | tail -n 1)")"
	fi
}

do_list() {
	printf '['
	local first=1 m id title group ver nw
	for m in "$PLUG_DIR"/*/manifest.json; do
		[ -f "$m" ] || continue
		id="$(jsonfilter -i "$m" -e '$.id' 2>/dev/null)"
		title="$(jsonfilter -i "$m" -e '$.title' 2>/dev/null)"
		group="$(jsonfilter -i "$m" -e '$.group' 2>/dev/null)"
		ver="$(jsonfilter -i "$m" -e '$.version' 2>/dev/null)"
		nw="$(jsonfilter -i "$m" -e '$.widgets[*]' 2>/dev/null | wc -l)"
		[ "$first" = 1 ] || printf ','
		first=0
		printf '["%s","%s","%s","%s","%s"]' "$(jesc "$id")" "$(jesc "$title")" "$(jesc "${group:-Плагины}")" "$(jesc "${ver:-—}")" "$nw"
	done
	printf ']'
}

do_summary() {
	local n=0 m
	for m in "$PLUG_DIR"/*/manifest.json; do [ -f "$m" ] && n=$((n+1)); done
	local idx="есть"
	[ -s /www/zm-plugins/index.json ] || idx="ОТСУТСТВУЕТ (нужна пересборка)"
	printf '{"ok":true,"data":{"Плагинов установлено":"%s","Реестр меню":"%s","Каталог":"%s"}}' "$n" "$idx" "$PLUG_DIR"
}

case "${1:-}" in
	list)    printf '{"ok":true,"rows":%s}' "$(do_list)" ;;
	summary) do_summary ;;
	install) run_ctl install "${2:-}" ;;
	remove)
		[ "${2:-}" = "plugin-manager" ] && { printf '{"ok":false,"error":"нельзя удалить сам менеджер плагинов"}'; exit 0; }
		run_ctl remove "${2:-}" ;;
	reindex) run_ctl reindex ;;
	log)
		if [ -s "$LOG" ]; then printf '{"ok":true,"log":"%s"}' "$(tail -n 30 "$LOG" | jlog)";
		else printf '{"ok":true,"log":"операций ещё не было"}'; fi ;;
	*) printf '{"ok":false,"error":"неизвестное действие: %s"}' "$(jesc "$1")" ;;
esac
