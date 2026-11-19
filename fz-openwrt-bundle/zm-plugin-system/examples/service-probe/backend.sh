#!/bin/ash
# service-probe backend — пример контракта backend.sh для манифест-плагина.
# Каждое действие = $1, ответ = JSON в stdout.
#   table:  {"ok":true,"rows":[["кол1","кол2"],...]}
#   status: {"ok":true,"data":{"Ключ":"Значение"}}
#   log:    {"ok":true,"log":"текст"}
#   button: {"ok":true,"message":"Готово","log":"детали"}
# Ошибка:  {"ok":false,"error":"текст"}

LAST=/tmp/zm-service-probe.log
SUM=/tmp/zm-service-probe.summary
CALLS=/tmp/zm-probe-calls.log

mark() { echo "$(date '+%H:%M:%S') call:$1" >> "$CALLS"; }

do_probe() {
	printf '[' > "$LAST.rows"
	first=1
	okn=0; failn=0
	probe() {
		r=$(curl -s -o /dev/null -m 6 -w '%{http_code} %{time_total}' "$2" 2>/dev/null) || r="000 0"
		code="${r%% *}"; tm="${r##* }"
		if [ "$code" != "000" ]; then st="OK"; okn=$((okn+1)); else st="FAIL"; failn=$((failn+1)); fi
		[ "$first" = 1 ] || printf ',' >> "$LAST.rows"
		first=0
		printf '["%s","%s","%s","%s"]' "$1" "$code" "$tm" "$st" >> "$LAST.rows"
		printf '%s %s %s %ss %s\n' "$(date '+%H:%M:%S')" "$1" "$code" "$tm" "$st" >> "$LAST.new"
	}
	: > "$LAST.new"
	probe "YouTube"  "https://www.youtube.com/generate_204"
	probe "Google"   "https://www.google.com/generate_204"
	probe "Discord"  "https://discord.com/api/v9/gateway"
	probe "GitHub"   "https://github.com/"
	printf ']' >> "$LAST.rows"
	# атомарная фиксация: журнал и сводка появляются только после конца прогона
	mv "$LAST.new" "$LAST"
	printf '{"ok":true,"data":{"Всего проб":"%s","Успешно":"%s","Ошибок":"%s","Последний прогон":"%s"}}' \
		"$((okn+failn))" "$okn" "$failn" "$(date '+%H:%M:%S')" > "$SUM"
	rows="$(cat "$LAST.rows")"; rm -f "$LAST.rows"
	printf '{"ok":true,"message":"Пробы завершены","rows":%s}' "$rows"
}

do_summary() {
	if [ -s "$SUM" ]; then
		cat "$SUM"
	else
		printf '{"ok":true,"data":{"Всего проб":"0","Успешно":"0","Ошибок":"0","Последний прогон":"ещё не было"}}'
	fi
}

case "${1:-}" in
	probe)   mark probe;   do_probe ;;
	summary) mark summary; do_summary ;;
	lastlog) mark lastlog
		if [ -s "$LAST" ]; then
			log="$(sed 's/\\/\\\\/g; s/"/\\"/g' "$LAST" | sed ':a; N; $!ba; s/\n/\\n/g')"
			printf '{"ok":true,"log":"%s"}' "$log"
		else
			printf '{"ok":true,"log":"прогонов ещё не было — нажмите «Проверить сейчас»"}'
		fi
		;;
	*) printf '{"ok":false,"error":"неизвестное действие: %s"}' "$1" ;;
esac
