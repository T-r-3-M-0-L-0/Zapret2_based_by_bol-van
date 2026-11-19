#!/bin/sh
set -eu
umask 077
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS=/root/zapret2-tools
VIEW=/www/luci-static/resources/view/zapret2
ACL=/usr/share/rpcd/acl.d/luci-app-zapret2.json
MODE=${1:-install}
case "$MODE" in install|--check) ;; *) echo 'Usage: sh install-strategy-compare.sh [--check]' >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
command -v ucode >/dev/null
test -f "$VIEW/app.js"
test -f "$ACL"
test -f /opt/zapret2/init.d/openwrt/uci2config
for file in strategy-check-openwrt.sh strategy-check-control.sh strategy-compare.js; do test -f "$SOURCE/$file"; done
sh -n "$SOURCE/strategy-check-openwrt.sh"
sh -n "$SOURCE/strategy-check-control.sh"
STAGE=$(mktemp -d /tmp/zapret2-ui-install-XXXXXX)
APPLIED=0
SUCCESS=0
finish() {
    code=$?
    trap - 0
    if [ "$APPLIED" = 1 ] && [ "$SUCCESS" = 0 ]; then
        cp -p "$BACKUP/app.js" "$VIEW/app.js"
        cp -p "$BACKUP/version.json" "$VIEW/version.json"
        cp -p "$BACKUP/acl.json" "$ACL"
        for file in strategy-check-openwrt.sh strategy-check-control.sh; do
            if test -f "$BACKUP/$file"; then cp -p "$BACKUP/$file" "$TOOLS/$file"; else rm -f "$TOOLS/$file"; fi
        done
        if test -f "$BACKUP/strategy-compare.js"; then cp -p "$BACKUP/strategy-compare.js" "$VIEW/strategy-compare.js"; else rm -f "$VIEW/strategy-compare.js"; fi
        /etc/init.d/rpcd restart || true
    fi
    rm -rf "$STAGE"
    exit "$code"
}
trap finish 0
ucode - "$VIEW" "$ACL" "$STAGE" <<'UCODE'
import { readfile, writefile } from 'fs';
let view = ARGV[0], aclpath = ARGV[1], stage = ARGV[2];
let app = readfile(view + '/app.js');
let anchor = "'require view.zapret2.blockcheck as blockcheckTab';";
let call = 'blockcheckTab.createBlockcheckTab(m);';
if (index(app, anchor) < 0 || index(app, call) < 0)
    die('Unsupported LuCI app layout. No files were replaced.\n');
if (index(app, "'require view.zapret2.strategy-compare as compareTab';") < 0)
    app = replace(app, anchor, anchor + "\n'require view.zapret2.strategy-compare as compareTab';");
if (index(app, 'compareTab.createCompareTab(m);') < 0)
    app = replace(app, call, call + '\n\t\tcompareTab.createCompareTab(m);');
let acl = json(readfile(aclpath));
let role = acl['luci-app-zapret2'];
if (!role?.read?.file || !role?.write?.file)
    die('Unsupported ACL layout. No files were replaced.\n');
role.read.file['/root/zapret2-tools/strategy-check-control.sh'] = ['exec'];
role.write.file['/root/zapret2-tools/strategy-check-control.sh'] = ['exec'];
let version = json(readfile(view + '/version.json')) || {};
let base = replace(version.luci_app_version || 'local', /\.strategy-compare\..*$/, '');
version.luci_app_version = base + '.strategy-compare.8';
writefile(stage + '/app.js', app);
writefile(stage + '/acl.json', sprintf('%.J\n', acl));
writefile(stage + '/version.json', sprintf('%J\n', version));
UCODE
if [ "$MODE" = --check ]; then echo 'INSTALL_PREFLIGHT_OK'; exit 0; fi
if test -f /tmp/zapret2-strategy-ui/latest; then
    current=$(cat /tmp/zapret2-strategy-ui/latest)
    case "$current" in /tmp/zapret2-strategy-ui/job-*)
        if test -f "$current/checker.pid"; then
            pid=$(cat "$current/checker.pid")
            case "$pid" in ''|*[!0-9]*) ;; *)
                if kill -0 "$pid" 2>/dev/null; then echo 'Stop the active strategy test before installing' >&2; exit 1; fi ;;
            esac
        fi ;;
    esac
fi
BACKUP=$TOOLS/backups/ui-$(date +%Y%m%d%H%M%S)-$$
mkdir -p "$BACKUP"
cp -p "$VIEW/app.js" "$BACKUP/app.js"
cp -p "$VIEW/version.json" "$BACKUP/version.json"
cp -p "$ACL" "$BACKUP/acl.json"
test ! -f "$VIEW/strategy-compare.js" || cp -p "$VIEW/strategy-compare.js" "$BACKUP/strategy-compare.js"
for file in strategy-check-openwrt.sh strategy-check-control.sh; do
    test ! -f "$TOOLS/$file" || cp -p "$TOOLS/$file" "$BACKUP/$file"
done
APPLIED=1
for file in strategy-check-openwrt.sh strategy-check-control.sh; do
    cp "$SOURCE/$file" "$TOOLS/$file.new"
    chmod 700 "$TOOLS/$file.new"
    mv "$TOOLS/$file.new" "$TOOLS/$file"
done
cp "$SOURCE/strategy-compare.js" "$VIEW/strategy-compare.js.new"
chmod 644 "$VIEW/strategy-compare.js.new"
mv "$VIEW/strategy-compare.js.new" "$VIEW/strategy-compare.js"
cp "$STAGE/app.js" "$VIEW/app.js.new"
cp "$STAGE/version.json" "$VIEW/version.json.new"
cp "$STAGE/acl.json" "$ACL.new"
chmod 644 "$VIEW/app.js.new" "$VIEW/version.json.new" "$ACL.new"
mv "$VIEW/app.js.new" "$VIEW/app.js"
mv "$VIEW/version.json.new" "$VIEW/version.json"
mv "$ACL.new" "$ACL"
/etc/init.d/rpcd restart
SUCCESS=1
echo "Installed: Services -> Zapret2 -> Сравнение стратегий"
echo "Backup: $BACKUP"

# Optional bundle parts: healthcheck (autotest + autopromote) and HTTP3 curl.
if [ -f "$SOURCE/healthcheck.sh" ] && [ -d /opt/zapret2 ]; then
    first_install=1
    if [ -f /opt/zapret2/healthcheck.sh ]; then
        first_install=0
        cp -p /opt/zapret2/healthcheck.sh "$BACKUP/healthcheck.sh"
        # Preserve user-tuned settings across upgrades.
        OLD_AP=$(sed -n 's/^AUTOPROMOTE=\([01]\).*/\1/p' /opt/zapret2/healthcheck.sh)
        OLD_CD=$(sed -n 's/^COOLDOWN=\([0-9]*\).*/\1/p' /opt/zapret2/healthcheck.sh)
        OLD_CAP=$(sed -n 's/^PROMOTE_CAP=\([0-9]*\).*/\1/p' /opt/zapret2/healthcheck.sh)
    fi
    cp "$SOURCE/healthcheck.sh" /opt/zapret2/healthcheck.sh.new
    [ -z "${OLD_AP:-}" ] || sed -i "s/^AUTOPROMOTE=.*/AUTOPROMOTE=$OLD_AP/" /opt/zapret2/healthcheck.sh.new
    [ -z "${OLD_CD:-}" ] || sed -i "s/^COOLDOWN=.*/COOLDOWN=$OLD_CD/" /opt/zapret2/healthcheck.sh.new
    [ -z "${OLD_CAP:-}" ] || sed -i "s/^PROMOTE_CAP=.*/PROMOTE_CAP=$OLD_CAP/" /opt/zapret2/healthcheck.sh.new
    chmod 755 /opt/zapret2/healthcheck.sh.new
    mv /opt/zapret2/healthcheck.sh.new /opt/zapret2/healthcheck.sh
    [ "$first_install" = 0 ] || crontab -l 2>/dev/null | grep -qF '/opt/zapret2/healthcheck.sh' || {
        ( crontab -l 2>/dev/null; echo '17 * * * * /opt/zapret2/healthcheck.sh >/dev/null 2>&1 # zhealth' ) | crontab -
    }
    grep -q '^/opt/zapret2/healthcheck\.sh' /etc/sysupgrade.conf 2>/dev/null || echo '/opt/zapret2/healthcheck.sh' >> /etc/sysupgrade.conf
    echo 'Installed: /opt/zapret2/healthcheck.sh (healthcheck + autotest + autopromote)'
fi

if [ -d /opt/zapret2 ] && [ ! -x /opt/zapret2/curl-h3 ]; then
    if [ -f "$SOURCE/curl-h3" ]; then
        cp "$SOURCE/curl-h3" /opt/zapret2/curl-h3
        chmod 755 /opt/zapret2/curl-h3
    else
        H3URL=
        case "$(uname -m)" in
            aarch64) H3URL='https://github.com/stunnel/static-curl/releases/download/8.23.0-1/curl-linux-aarch64-musl-8.23.0-1.tar.xz' ;;
            x86_64) H3URL='https://github.com/stunnel/static-curl/releases/download/8.23.0-1/curl-linux-x86_64-musl-8.23.0-1.tar.xz' ;;
        esac
        if [ -n "$H3URL" ] && command -v uclient-fetch >/dev/null 2>&1; then
            echo 'Downloading static curl with HTTP3...'
            rm -rf /tmp/curl-h3-dl
            mkdir -p /tmp/curl-h3-dl
            if uclient-fetch -q -O /tmp/curl-h3-dl/curl.tar.xz "$H3URL" && tar -xJf /tmp/curl-h3-dl/curl.tar.xz -C /tmp/curl-h3-dl 2>/dev/null; then
                cp /tmp/curl-h3-dl/curl /opt/zapret2/curl-h3
                chmod 755 /opt/zapret2/curl-h3
            fi
            rm -rf /tmp/curl-h3-dl
        fi
    fi
fi
if [ -x /opt/zapret2/curl-h3 ]; then
    mkdir -p /opt/zapret2/h3bin
    ln -sf ../curl-h3 /opt/zapret2/h3bin/curl
    grep -q '^/opt/zapret2/curl-h3' /etc/sysupgrade.conf 2>/dev/null || echo '/opt/zapret2/curl-h3' >> /etc/sysupgrade.conf
    echo 'HTTP3 curl: /opt/zapret2/curl-h3 (QUIC mode available)'
else
    echo 'NOTE: no HTTP3 curl found; quic mode stays hidden. Put curl-h3 next to the installer or install it manually.'
fi
