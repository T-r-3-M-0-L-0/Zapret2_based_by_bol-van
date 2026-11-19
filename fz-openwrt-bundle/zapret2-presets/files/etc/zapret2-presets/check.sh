#!/bin/ash
# zapret2-presets check helper: пробы ключевых сервисов, вывод в JSON.
# Вызывается из LuCI-страницы «Zapret2 пресеты». Никаких изменений не вносит.
printf '['
first=1
probe() {
	name="$1"; url="$2"
	r=$(curl -s -o /dev/null -m 6 -w '%{http_code} %{time_total}' "$url" 2>/dev/null) || r="000 0"
	code="${r%% *}"; tm="${r##* }"
	if [ "$code" != "000" ]; then ok=true; else ok=false; fi
	[ "$first" = 1 ] || printf ','
	first=0
	printf '{"name":"%s","code":"%s","time":"%s","ok":%s}' "$name" "$code" "$tm" "$ok"
}
probe "YouTube"    "https://www.youtube.com/generate_204"
probe "Google"     "https://www.google.com/generate_204"
probe "GV-redirector" "https://redirector.googlevideo.com/"
probe "Discord"    "https://discord.com/api/v9/gateway"
probe "GitHub"     "https://github.com/"
probe "Telegram"   "https://web.telegram.org/"
printf ']'
