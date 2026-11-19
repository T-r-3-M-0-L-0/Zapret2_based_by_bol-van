#!/bin/ash
# Hourly service checks. Only a repeatable improvement on the same route
# and pinned address can change the live configuration.
umask 077
set -f
COOLDOWN=21600
AUTOPROMOTE=1
PROMOTE_CAP=3
CHECKER=/root/zapret2-tools/strategy-check-openwrt.sh
SERVICE=/etc/init.d/zapret2
CONFIG=/etc/config/zapret2
TOOLS=/root/zapret2-tools
LOCK=/var/lock/zapret2-strategy-check.lock
LOG=/tmp/zhealth.log
AUTOLOG=/tmp/zhealth-autotest.log
FAILS=/tmp/zhealth-fails
REPORTS=/tmp/zhealth-reports
PENDING=$TOOLS/health-pending
COUNT=$TOOLS/health-switch-count

exec 8>/var/lock/zapret2-health.lock
flock -n 8 || exit 0
mkdir -p "$REPORTS" || exit 1
WORK=$(mktemp -d "$REPORTS/run.XXXXXX") || exit 1
note() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M')" "$*" >> "$AUTOLOG"; }
checksum() { sha256sum "$1" | cut -d' ' -f1; }
restore_pending() {
    [ -f "$PENDING" ] || return 0
    local backup expected current
    read -r backup expected < "$PENDING" || return 1
    [ -s "$backup" ] || { note "Rollback backup unavailable: $backup"; return 1; }
    current=$(checksum "$CONFIG")
    if [ "$current" != "$expected" ] && [ "$current" != "$(checksum "$backup")" ]; then
        note "Config changed externally; rollback needs review: $backup"; return 1
    fi
    cp -p "$backup" "$CONFIG.health-new" && mv -f "$CONFIG.health-new" "$CONFIG" &&
        "$SERVICE" restart 7>&- 8>&- && "$SERVICE" status >/dev/null || { note "Rollback failed: $backup"; return 1; }
    rm -f "$PENDING"
    note "Rolled back and restarted zapret2: $backup"
}
cleanup() {
    rm -rf "$WORK"
    for f in "$LOG" "$AUTOLOG"; do
        [ ! -f "$f" ] || { tail -n 500 "$f" > "$f.trim" && mv -f "$f.trim" "$f"; }
    done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Keep live probes out of an isolated test that uses the same target and ports.
exec 7>"$LOCK"
flock -n 7 || { note "Tester busy; leaving counters and reports intact"; exit 0; }
if [ -f "$PENDING" ]; then restore_pending || exit 1; fi
cat > "$WORK/targets" <<'TARGETS'
www.youtube.com page https://www.youtube.com/
i.ytimg.com image https://i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg
discord.com page https://discord.com/
instagram.com redirect https://instagram.com/
web.whatsapp.com page https://web.whatsapp.com/
alloha.tv redirect https://alloha.tv/
filmix.watch redirect https://filmix.watch/
www.google.com page https://www.google.com/
TARGETS
# A video CDN needs a live signed URL. Expired links must not trigger promotion.
if [ -s /etc/zapret2-health-media.url ]; then
    IFS= read -r media < /etc/zapret2-health-media.url || :
    expires=$(printf '%s\n' "$media" | sed -n 's/.*[?&]expire=\([0-9]*\).*/\1/p')
    case "$media" in https://*.googlevideo.com/videoplayback\?*)
        if [ "${expires:-0}" -gt "$(($(date +%s) + 600))" ] 2>/dev/null; then
            printf 'youtube-media media %s\n' "$media" >> "$WORK/targets"
        else note "YouTube media: expired or missing expiry"; fi ;;
    *) note "YouTube media: expected a signed googlevideo.com URL";; esac
fi

live() { "$CHECKER" --health-probe "$@"; }
batch=0
while read -r key kind url; do
    live "$kind" "$url" > "$WORK/$key.live" &
    batch=$((batch+1))
    if [ "$batch" = 3 ]; then wait; batch=0; fi
done < "$WORK/targets"
wait
exec 7>&-
touch "$FAILS"
: > "$WORK/fails"
: > "$WORK/triggers"
line=$(date '+%Y-%m-%d %H:%M')
while read -r key kind url; do
    read -r state code route addr < "$WORK/$key.live" || state=error
    line="$line $key:${code:-000}/${state}/${route:-unknown}"
    n=0
    if [ "$state" = fail ]; then
        n=$(awk -v k="$key" -v r="$route" '$1==k && $3==r {print $2+0;exit}' "$FAILS")
        n=$((${n:-0}+1))
        case "$route" in dev/lo) ;; dev/*)
            stamp=/tmp/zhealth-autotest-$(printf '%s' "$key" | tr -cd 'a-z0-9')
            last=$(cat "$stamp" 2>/dev/null)
            [ "$n" -lt 2 ] || [ "$(($(date +%s) - ${last:-0}))" -lt "$COOLDOWN" ] || printf '%s %s %s %s %s\n' "$key" "$kind" "$url" "$route" "$addr" >> "$WORK/triggers" ;;
        esac
    fi
    printf '%s %s %s\n' "$key" "$n" "${route:-unknown}" >> "$WORK/fails"
done < "$WORK/targets"
mv -f "$WORK/fails" "$FAILS" || exit 1
printf '%s\n' "$line" >> "$LOG"
[ -s "$WORK/triggers" ] || exit 0
"$SERVICE" status >/dev/null 2>&1 || { note "zapret2 inactive; skipping comparison"; exit 0; }
alive=0
for ref in ya.ru mail.ru vk.com; do
    code=$(curl -4 --noproxy '*' -s -o /dev/null --range 0-1023 -m 6 -w '%{http_code}' "https://$ref/") || continue
    case "$code" in 2??|3??) alive=$((alive+1));; esac
    [ "$alive" -lt 2 ] || break
done
[ "$alive" -ge 2 ] || { note "Reference sites unavailable; no strategy change"; exit 0; }

# Discard only provably incompatible UCI profiles. Unknown port forms remain candidates.
candidates() {
    uci -q show zapret2 | awk -F= '
    $1 ~ /^zapret2\.[^.]+$/ && $2=="strategy" {split($1,p,"."); names[++n]=p[2]; next}
    $1 ~ /\.(protocol|port)$/ {split($1,p,"."); v=$2; gsub(/\047/,"",v); a[p[2],p[3]]=v}
    END {for(i=1;i<=n;i++) {
        k=names[i]; if(a[k,"protocol"]=="udp") continue
        ports=a[k,"port"]; if(ports=="" || ports ~ /[^0-9 ,:-]/) {print k;continue}
        count=split(ports,parts,/[, ]+/)
        for(j=1;j<=count;j++) {
            m=split(parts[j],bounds,/[-:]/)
            if((m==1 && bounds[1]+0==443) || (m==2 && bounds[1]+0<=443 && bounds[2]+0>=443)) {print k;break}
        }
    }}'
}
# Require every baseline attempt to fail and every winning attempt to pass on
# the same observed path. Exclude skipped/errored/missing rows and old TSVs.
winners() {
    awk -F '\t' -v route="$2" -v need="$3" '
        NR>1 && $1=="baseline" {base++; if($3!="FAIL" || $10!=route) invalid=1; next}
        NR>1 {p=$1; total[p]++; if($3=="PASS" && $10==route) ok[p]++; if(!seen[p]++) order[++n]=p}
        END {if(base!=need || invalid) exit; for(i=1;i<=n;i++) {p=order[i]; if(total[p]==need && ok[p]==need) print p}}' "$1/results.tsv"
}
compare() {
    local dest=$1 repeats=$2
    shift 2
    "$CHECKER" --run --no-stop --mode tls13 --repeats "$repeats" --timeout 8 --health-kind "$kind" \
        --url "$url" --ip "$addr" --keep-logs last-error --report "$dest" "$@" > "$WORK/check.log" 2>&1 &&
        [ "$(cut -f1 "$dest/progress.tsv" 2>/dev/null)" = finished ] && awk -F '\t' '
            $1=="baseline" && ($3=="HTTP_OK" || $3=="FAIL") {baseline=1}
            $1!="baseline" && $3 ~ /^(PASS|FAIL|NO_ACTION|SKIP_HOSTLIST|SKIP_PROTOCOL)$/ {evaluated=1}
            END {exit !(baseline && evaluated)}' "$dest/results.tsv"
}
# Pointer is replaced only after a complete run; one previous bundle per target is retained until then.
publish() {
    local dir=$1 pointer="$REPORTS/latest-$key" old
    old=$(cat "$pointer" 2>/dev/null)
    mv "$dir" "$REPORTS/$bundle" && printf '%s\n' "$bundle" > "$pointer.new" && mv -f "$pointer.new" "$pointer" || return 1
    case "$old" in *[!a-zA-Z0-9.-]*) ;; "$key".*) [ "$old" = "$bundle" ] || rm -rf "$REPORTS/$old";; esac
}
same_live() {
    local output
    output=$(live "$kind" "$url" "$addr") || return 1
    set -- $output
    [ "$1/$3/$4" = "$expected/$route/$addr" ]
}
promote() (
    exec 7>"$LOCK"; flock -n 7 || { note "$key: tester busy before apply"; return 1; }
    [ "$fingerprint" = "$(checksum "$CONFIG")" ] && [ -z "$(uci -q changes zapret2)" ] || { note "$key: configuration changed"; return 1; }
    [ "$(uci -q get "zapret2.$winner.enabled")" != 1 ] || return 1
    local expected=fail
    same_live || { note "$key: active route or service changed"; return 1; }
    day=$(date +%Y%m%d); count=0
    if [ -f "$COUNT" ]; then read -r prev used < "$COUNT"; [ "$prev" != "$day" ] || count=$used
    elif [ -f "/tmp/zhealth-promote-$day" ]; then read -r count < "/tmp/zhealth-promote-$day"; fi
    [ "$count" -lt "$PROMOTE_CAP" ] || { note "$key: daily switch limit reached"; return 0; }
    mkdir -p "$TOOLS/backups" "$WORK/config" "$WORK/delta" || return 1
    backup="$TOOLS/backups/config-before-health-$(date +%Y%m%d%H%M%S)-$$"
    cp -p "$CONFIG" "$backup" && cp -p "$CONFIG" "$WORK/config/zapret2" &&
        uci -c "$WORK/config" -t "$WORK/delta" set "zapret2.$winner.enabled=1" &&
        uci -c "$WORK/config" -t "$WORK/delta" commit zapret2 || return 1
    hash=$(checksum "$WORK/config/zapret2")
    [ -n "$hash" ] && printf '%s %s\n' "$backup" "$hash" > "$PENDING.new" && mv -f "$PENDING.new" "$PENDING" || return 1
    trap 'if [ -f "$PENDING" ]; then restore_pending; fi' EXIT
    trap 'exit 1' HUP INT TERM
    printf '%s %s\n' "$day" "$((count+1))" > "$COUNT.new" && mv -f "$COUNT.new" "$COUNT" || return 1
    cp -p "$WORK/config/zapret2" "$CONFIG.health-new" && mv -f "$CONFIG.health-new" "$CONFIG" &&
        "$SERVICE" restart 7>&- 8>&- && "$SERVICE" status >/dev/null || return 1
    expected=ok
    same_live && same_live || { note "$key: active verification failed for $winner"; return 1; }
    # Broad profiles may also affect services that were healthy before the change.
    while read -r peer peer_kind peer_url; do
        [ "$peer" != "$key" ] || continue
        read -r before _ peer_route peer_addr < "$WORK/$peer.live" || continue
        [ "$before" = ok ] || continue
        local verified=0
        for retry in 1 2; do
            set -- $(live "$peer_kind" "$peer_url" "$peer_addr")
            if [ "$1" = ok ] && [ "$3" = "$peer_route" ]; then verified=1; break; fi
        done
        [ "$verified" = 1 ] || { note "$key: regression on $peer after enabling $winner"; return 1; }
    done < "$WORK/targets"
    rm -f "$PENDING" || return 1
    note "$key: enabled $winner, verified twice on $route; backup $backup"
)

candidates > "$WORK/candidates"
while read -r key kind url route addr; do
    stamp=/tmp/zhealth-autotest-$(printf '%s' "$key" | tr -cd 'a-z0-9')
    [ ! -f "$PENDING" ] || exit 1
    set --
    while read -r name; do set -- "$@" --strategy "$name"; done < "$WORK/candidates"
    [ "$#" -gt 0 ] || continue
    fingerprint=$(checksum "$CONFIG")
    bundle="$key.$(date +%s).$$"
    job="$WORK/$bundle"
    mkdir "$job" || exit 1
    if ! compare "$job/screen" 1 "$@"; then
        note "$key: comparison incomplete or busy; retry next run ($(tail -1 "$WORK/check.log"))"; continue
    fi
    winner=
    for candidate in $(winners "$job/screen" "$route" 1); do
        if [ "$(uci -q get "zapret2.$candidate.enabled")" = 1 ]; then
            note "$key: $candidate works in isolation but is already enabled; inspect active profile order and host filters"
            continue
        fi
        if ! compare "$job/confirm-$candidate" 2 --strategy "$candidate"; then
            note "$key: confirmation incomplete; retry next run"; continue 2
        fi
        if [ "$(winners "$job/confirm-$candidate" "$route" 2)" = "$candidate" ]; then winner=$candidate; break; fi
    done
    publish "$job" || exit 1
    if [ -n "$winner" ]; then
        note "$key: confirmed $winner on $route"
        [ "$AUTOPROMOTE" != 1 ] || promote || continue
    else note "$key: no confirmed improvement"; fi
    date +%s > "$stamp"
done < "$WORK/triggers"
