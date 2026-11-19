#!/bin/sh
# install-zapret2-config.sh — перенос конфигурации zapret2 (UCI + ipset/*.txt + lua/*.lua + files/fake/*)
# на другой роутер с уже установленным zapret2 из Zapret-Manager.
# Запуск на роутере: sh install-zapret2-config.sh [--check]
set -eu
umask 022
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC=$SOURCE/src
MODE=${1:-install}
case "$MODE" in install|--check) ;; *) echo 'Usage: sh install-zapret2-config.sh [--check]' >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }

ok=0
# Зависимости: сам zapret2 (ставится из Zapret-Manager) — до любых записей.
[ -f /etc/init.d/zapret2 ] || { echo 'MISSING /etc/init.d/zapret2 (установите Zapret2 из панели)'; ok=1; }
[ -d /opt/zapret2/ipset ] || { echo 'MISSING /opt/zapret2/ipset'; ok=1; }
[ -d /opt/zapret2/lua ] || { echo 'MISSING /opt/zapret2/lua'; ok=1; }
[ -f /etc/config/zapret2 ] || { echo 'MISSING /etc/config/zapret2'; ok=1; }
# Источник.
[ -f "$SRC/etc/config/zapret2" ] || { echo "MISSING $SRC/etc/config/zapret2"; ok=1; }
[ -d "$SRC/opt/zapret2/ipset" ] || { echo "MISSING $SRC/opt/zapret2/ipset"; ok=1; }
[ -d "$SRC/opt/zapret2/lua" ] || { echo "MISSING $SRC/opt/zapret2/lua"; ok=1; }
[ -d "$SRC/opt/zapret2/files/fake" ] || { echo "MISSING $SRC/opt/zapret2/files/fake"; ok=1; }
# UCI-конфиг источника должен парситься.
if [ "$ok" = 0 ] && ! uci -c "$SRC/etc/config" show zapret2 >/dev/null 2>&1; then
    echo 'BAD UCI: src/etc/config/zapret2 не разбирается'
    ok=1
fi
[ "$ok" = 0 ] || { echo 'PREFLIGHT_FAIL: исходные файлы не тронуты'; exit 1; }
echo 'PREFLIGHT_OK'
[ "$MODE" != --check ] || exit 0

BK=/root/zapret2-config-backup-$(date +%Y%m%d%H%M%S)
mkdir -p "$BK/ipset" "$BK/lua"
cp -p /etc/config/zapret2 "$BK/zapret2"
# Бэкапим только то, что будет перезаписано.
for f in "$SRC"/opt/zapret2/ipset/*.txt; do
    b=$(basename "$f")
    [ ! -f "/opt/zapret2/ipset/$b" ] || cp -p "/opt/zapret2/ipset/$b" "$BK/ipset/"
done
for f in "$SRC"/opt/zapret2/lua/*.lua; do
    b=$(basename "$f")
    [ ! -f "/opt/zapret2/lua/$b" ] || cp -p "/opt/zapret2/lua/$b" "$BK/lua/"
done
mkdir -p "$BK/fake"
for f in "$SRC"/opt/zapret2/files/fake/*; do
    b=$(basename "$f")
    [ ! -f "/opt/zapret2/files/fake/$b" ] || cp -p "/opt/zapret2/files/fake/$b" "$BK/fake/"
done

rollback() {
    cp -p "$BK/zapret2" /etc/config/zapret2 2>/dev/null || true
    cp -p "$BK/ipset/"*.txt /opt/zapret2/ipset/ 2>/dev/null || true
    cp -p "$BK/lua/"*.lua /opt/zapret2/lua/ 2>/dev/null || true
    [ ! -d "$BK/fake" ] || cp -p "$BK/fake/"* /opt/zapret2/files/fake/ 2>/dev/null || true
    /etc/init.d/zapret2 restart >/dev/null 2>&1 || true
    echo 'INSTALL_FAIL: выполнен откат к прежней конфигурации' >&2
    exit 1
}

cp "$SRC"/opt/zapret2/ipset/*.txt /opt/zapret2/ipset/ || rollback
cp "$SRC"/opt/zapret2/lua/*.lua /opt/zapret2/lua/ || rollback
mkdir -p /opt/zapret2/files/fake
cp "$SRC"/opt/zapret2/files/fake/* /opt/zapret2/files/fake/ || rollback
cp "$SRC/etc/config/zapret2" /etc/config/zapret2.new || rollback
mv -f /etc/config/zapret2.new /etc/config/zapret2 || rollback

/etc/init.d/zapret2 restart >/dev/null 2>&1 || rollback
sleep 3
/etc/init.d/zapret2 status >/dev/null 2>&1 || rollback
pgrep -f nfqws2 >/dev/null 2>&1 || rollback

echo "INSTALLED. Backup: $BK"
echo 'Профили и списки применены, служба zapret2 перезапущена.'
