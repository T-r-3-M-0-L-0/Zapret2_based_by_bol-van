#!/bin/sh
# Check named Zapret Manager UCI strategies using isolated nfqws2 + curl probes.
set -f
umask 077

BASE=${ZAPRET_BASE:-/opt/zapret2}
# Prefer static curl with HTTP3 if present (for --mode quic).
if [ -x "$BASE/curl-h3" ]; then PATH="$BASE/h3bin:$PATH"; export PATH; fi
CONFIG_DIR=/etc/config
MODE=tls13
ACTION=
SELECTED=
URL=
PIN_IP=
REPEATS=3
TIMEOUT=12
MIN_BYTES=1024
REPORT=
WORK=
TABLE=
NFQ_PID=
CURL_PID=
GUARD_PID=
LOCK=/var/lock/zapret2-strategy-check.lock
INIT=/etc/init.d/zapret2
MARK=0x10000000
DESYNC_MARK=0x40000000
QNUM=0
NOSTOP=0
SCAN_LISTS=0
ONLY_LISTS=
MAX_DOMAINS=0
DNS_PID=
DNS_TIMER=
REQUEST=head
KEEP_LOGS=all
THROUGHPUT=0
THROUGHPUT_URL=
MIN_SPEED=0
TP_MAXTIME=60

usage() {
    cat <<'EOF'
Usage:
  sh strategy-check-openwrt.sh --list
  sh strategy-check-openwrt.sh --check --strategy Yv02 [--strategy Yv08]
  sh strategy-check-openwrt.sh --run --strategy Yv02 --url 'https://i.ytimg.com/vi/VIDEO_ID/hqdefault.jpg'
  sh strategy-check-openwrt.sh --list-hostlists
  sh strategy-check-openwrt.sh --run --strategy Yv02 --scan-lists
Options:
  --all                  Select all configured strategies instead of --strategy.
  --mode tls13|tls12|http|quic   Default tls13. QUIC requires curl HTTP3 support.
  --ip IPv4              Pin the target IP; otherwise resolve once with mdig.
  --repeats N            Attempts per profile (1..10), default 3.
  --timeout SECONDS      Per-request timeout (2..60), default 12.
  --min-bytes N          Minimum received bytes for success, default 1024.
  --report DIRECTORY     New output directory. Default /tmp/strategy-check-XXXXXX.
  --base DIRECTORY       Existing zapret2 installation, default /opt/zapret2.
  --config-dir DIRECTORY UCI source directory, default /etc/config.
  --scan-lists           Test the strategy technique on all referenced domain lists.
                         Replace host/IP include and exclude filters in test copies.
  --only-list NAME       Limit --scan-lists to a listed hostlist (repeatable).
  --max-domains-per-list N  Optional sample limit; default 0 tests every domain.
  --request head|get     List probe method; get uses a 64 KiB range like Zapret Manager.
  --keep-logs all|last-error  Last-error keeps metrics in TSV and only the latest error log per profile.
  --no-stop            With --run: keep zapret2 running; test flows are marked with the
                       desync mark so the live service skips them (requires zapret2 running).
  --throughput N       After a reachable probe, download N MiB and measure speed
                       (first attempt only). Distinguishes 'opens' from 'video plays'.
  --throughput-url URL Download this URL for the throughput probe; defaults to --url.
                       Use a media/segment URL (e.g. googlevideo) for realistic numbers.
  --min-speed KBps     Speed threshold; below it the result is TP_SLOW. Default 0 (report only).
  --tp-maxtime SEC     Throughput download time cap, default 60.
--check only compiles profiles and runs nfqws2 --dry-run.
--run temporarily stops zapret2, tests a direct baseline and one profile at a time,
then restores the service if it was running. HUP/INT/TERM and a watchdog restore it.
With --no-stop the service is left running instead.
Tests use IPv4 and a ranged GET. Redirects are reported without following them.
Results distinguish a received response from a matched, executed Lua strategy.
EOF
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
need_value() { [ "$#" -ge 2 ] && [ -n "$2" ] || die "Missing value for $1"; }
# Record the source ports of matching packets. Read only curl's actual port
# after the request, so traffic from other clients cannot count as this probe.
observe_path() {
    local addr=$1 port=$2
    if [ "$PATH_ACTIVE" = 1 ]; then
        nft delete table inet "$PATH_TABLE" 2>/dev/null || { PATH_ACTIVE=0; return; }
    fi
    PATH_ACTIVE=0
    PATH_DEV=$(ip -4 route get "$addr" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1);exit}}')
    case "$PATH_DEV" in ''|*[!a-zA-Z0-9_.-]*) return ;; esac
    local match="ip daddr $addr $TRANSPORT dport $port $TRANSPORT sport 61000-61099"
    {
        echo "add table inet $PATH_TABLE"
        for name in egress netshift; do
            echo "add set inet $PATH_TABLE $name { type inet_service; flags dynamic; size 128; }"
        done
        echo "add chain inet $PATH_TABLE out { type filter hook postrouting priority 110; policy accept; }"
        echo "add rule inet $PATH_TABLE out oifname \"$PATH_DEV\" $match add @egress { $TRANSPORT sport }"
        if nft list chain inet NetShiftTable proxy 2>/dev/null | grep -Eq "meta mark & 0x00100000 == 0x00100000 meta l4proto $TRANSPORT tproxy ip to "; then
            echo "add chain inet $PATH_TABLE input_probe { type filter hook prerouting priority -99; policy accept; }"
            echo "add rule inet $PATH_TABLE input_probe iifname lo meta mark & 0x00100000 == 0x00100000 $match add @netshift { $TRANSPORT sport }"
        fi
    } | nft -f - 2>/dev/null && PATH_ACTIVE=1
}

observed_route() {
    local source_port=$1 via_proxy=0 via_dev=0
    number "$source_port" && [ "$source_port" -gt 0 ] && [ "$PATH_ACTIVE" = 1 ] || { echo unknown; return; }
    nft get element inet "$PATH_TABLE" netshift "{ $source_port }" >/dev/null 2>&1 && via_proxy=1
    nft get element inet "$PATH_TABLE" egress "{ $source_port }" >/dev/null 2>&1 && via_dev=1
    if [ "$via_proxy" = 1 ] && { [ "$via_dev" = 0 ] || [ "$PATH_DEV" = lo ]; }; then echo NetShift
    elif [ "$via_proxy" = 0 ] && [ "$via_dev" = 1 ]; then echo "dev/$PATH_DEV"
    else echo unknown; fi
}


# Both the active service probe and isolated profiles use the same success criteria.
health_response() {
    awk -F '\t' -v kind="$1" -v host="$2" '
        {
            if (kind=="redirect" && $1 ~ /^30[12378]$/) {
                h=host; sub(/^www\./,"",h)
                dest=tolower($7); sub(/^https:\/\//,"",dest); sub(/[\/?#].*/,"",dest)
                ok=($7 ~ /^https:\/\// && (dest==h || substr(dest,length(dest)-length(h))=="." h))
            } else if ($1=="200" || $1=="206") {
                ok=($2>=1024 && $6 ~ /^text\/html/)
                if(kind=="image") ok=($2>=1024 && $6 ~ /^image\//)
                if(kind=="media") ok=($2>=16384 && $6 ~ /^(video\/|audio\/|application\/octet-stream)/)
            }
        } END {exit !ok}'
}

HEALTH_FORMAT='%{http_code}\t%{size_download}\t%{time_total}\t%{speed_download}\t%{local_port}\t%{content_type}\t%{redirect_url}\n'
HEALTH_KIND=
if [ "$1" = --health-probe ]; then
    kind=$2; url=$3; host=$(printf '%s\n' "$url" | sed -n 's@^https://\([A-Za-z0-9.-]*\)/.*@\1@p')
    [ -n "$host" ] || exit 2
    case "$kind" in page|redirect|image|media) ;; *) exit 2 ;; esac
    addr=${4:-$(resolveip -4 -t 4 "$host" 2>/dev/null | head -1)}
    if ! printf '%s\n' "$addr" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}'; then
        printf 'dns_error 000 unknown -\n'; exit 0
    fi
    PATH_TABLE=zhealthpath_$$; PATH_ACTIVE=0; TRANSPORT=tcp
    trap 'nft delete table inet "$PATH_TABLE" 2>/dev/null || :' EXIT
    trap 'exit 1' HUP INT TERM
    observe_path "$addr" 443
    metrics=$(curl -4 --noproxy '*' -s --tlsv1.3 --tls-max 1.3 --http1.1 --range 0-262143 --max-time 8 --max-filesize 8388608 \
        --resolve "$host:443:$addr" --local-port 61000-61099 -o /dev/null -w "$HEALTH_FORMAT" "$url")
    rc=$?; status=fail
    [ "$rc" = 0 ] && printf '%s\n' "$metrics" | health_response "$kind" "$host" && status=ok
    route=$(observed_route "$(printf '%s' "$metrics" | cut -f5)")
    printf '%s %s %s %s\n' "$status" "$(printf '%s' "$metrics" | cut -f1)" "$route" "$addr"
    exit 0
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --list|--check|--run|--list-hostlists) [ -z "$ACTION" ] || die 'Choose one action'; ACTION=${1#--}; shift ;;
        --strategy) need_value "$@"; SELECTED="$SELECTED $2"; shift 2 ;;
        --all) SELECTED='*'; shift ;;
        --url) need_value "$@"; URL=$2; shift 2 ;;
        --mode) need_value "$@"; MODE=$2; shift 2 ;;
        --health-kind) need_value "$@"; HEALTH_KIND=$2; case "$2" in page|redirect|image|media) ;; *) die "Invalid service probe";; esac; shift 2 ;;
        --ip) need_value "$@"; PIN_IP=$2; shift 2 ;;
        --repeats) need_value "$@"; REPEATS=$2; shift 2 ;;
        --timeout) need_value "$@"; TIMEOUT=$2; shift 2 ;;
        --min-bytes) need_value "$@"; MIN_BYTES=$2; shift 2 ;;
        --report) need_value "$@"; REPORT=$2; shift 2 ;;
        --base) need_value "$@"; BASE=$2; shift 2 ;;
        --config-dir) need_value "$@"; CONFIG_DIR=$2; shift 2 ;;
        --scan-lists) SCAN_LISTS=1; shift ;;
        --only-list) need_value "$@"; ONLY_LISTS="$ONLY_LISTS $2"; shift 2 ;;
        --max-domains-per-list) need_value "$@"; MAX_DOMAINS=$2; shift 2 ;;
        --request) need_value "$@"; REQUEST=$2; shift 2 ;;
        --keep-logs) need_value "$@"; KEEP_LOGS=$2; shift 2 ;;
        --no-stop) NOSTOP=1; shift ;;
        --throughput) need_value "$@"; THROUGHPUT=$2; shift 2 ;;
        --throughput-url) need_value "$@"; THROUGHPUT_URL=$2; shift 2 ;;
        --min-speed) need_value "$@"; MIN_SPEED=$2; shift 2 ;;
        --tp-maxtime) need_value "$@"; TP_MAXTIME=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done
[ -n "$ACTION" ] || { usage; exit 2; }
case "$MODE" in tls13|tls12|http|quic) ;; *) die 'Unsupported mode' ;; esac
number "$REPEATS" && [ "$REPEATS" -ge 1 ] && [ "$REPEATS" -le 10 ] || die 'Invalid repeats'
number "$TIMEOUT" && [ "$TIMEOUT" -ge 2 ] && [ "$TIMEOUT" -le 60 ] || die 'Invalid timeout'
number "$MIN_BYTES" && [ "$MIN_BYTES" -le 1073741824 ] || die 'Invalid minimum bytes'
number "$MAX_DOMAINS" || die 'Invalid domain limit'
case "$REQUEST" in head|get) ;; *) die 'Invalid request method' ;; esac
case "$KEEP_LOGS" in all|last-error) ;; *) die 'Invalid log policy' ;; esac
number "$THROUGHPUT" && [ "$THROUGHPUT" -le 1024 ] || die 'Invalid throughput MiB'
number "$MIN_SPEED" || die 'Invalid min speed'
number "$TP_MAXTIME" && [ "$TP_MAXTIME" -ge 5 ] && [ "$TP_MAXTIME" -le 600 ] || die 'Invalid tp max time'
if [ "$SCAN_LISTS" = 1 ]; then
    [ -z "$URL" ] && [ -z "$PIN_IP" ] || die '--scan-lists chooses domain URLs and IPs automatically'
fi
[ "$(id -u)" = 0 ] || die 'Run as root on OpenWrt'
command -v uci >/dev/null || die 'uci is required'
[ -f "$CONFIG_DIR/zapret2" ] || die 'UCI config not found'

# Named and anonymous sections are both represented using uci's own selectors.
ALL=$(uci -c "$CONFIG_DIR" -s show zapret2 | sed -n 's/^zapret2\.\([^.=]*\)=strategy$/\1/p')
[ -n "$ALL" ] || die 'No UCI strategy sections'
if [ "$ACTION" = list ]; then
    printf 'PROFILE\tENABLED\tPROTOCOL\tPORTS\n'
    for profile in $ALL; do
        printf '%s\t%s\t%s\t%s\n' "$profile" \
            "$(uci -c "$CONFIG_DIR" -q get "zapret2.$profile.enabled")" \
            "$(uci -c "$CONFIG_DIR" -q get "zapret2.$profile.protocol")" \
            "$(uci -c "$CONFIG_DIR" -q get "zapret2.$profile.port")"
    done
    exit 0
fi
[ -n "$SELECTED" ] || [ "$ACTION" = list-hostlists ] || die 'Specify --strategy NAME or --all'
[ "$SELECTED" != '*' ] || SELECTED=$ALL
for profile in $SELECTED; do
    printf '%s\n' "$ALL" | grep -Fxq -- "$profile" || die "Unknown strategy: $profile"
done
[ -x "$BASE/nfq2/nfqws2" ] || die 'nfqws2 not found'
[ -f "$BASE/init.d/openwrt/uci2config" ] || die 'Zapret Manager uci2config is required'
command -v flock >/dev/null || die 'flock is required'
exec 9>"$LOCK"
flock -n 9 || die 'Another strategy check is running'

# Keep the output, including compiled options, for reproducing any failure.
if [ -n "$REPORT" ]; then
    [ ! -e "$REPORT" ] || die 'Report directory already exists'
    mkdir -p "$REPORT" || die 'Cannot create report directory'
    WORK=$(cd "$REPORT" && pwd)
else
    WORK=$(mktemp -d /tmp/strategy-check-XXXXXX) || die 'mktemp failed'
fi
TABLE=strategycheck_$$
PATH_TABLE=strategypath_$$
PATH_ACTIVE=0
printf '%s\n' "$WORK" > "$WORK/report-path.txt"

stop_test() {
    for child in "$DNS_PID" "$DNS_TIMER"; do
        [ -z "$child" ] || { kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; }
    done
    DNS_PID=
    DNS_TIMER=
    if [ -n "$CURL_PID" ]; then
        kill "$CURL_PID" 2>/dev/null
        wait "$CURL_PID" 2>/dev/null
        CURL_PID=
    fi
    if [ -n "$NFQ_PID" ]; then
        kill "$NFQ_PID" 2>/dev/null
        wait "$NFQ_PID" 2>/dev/null
        NFQ_PID=
    fi
    [ -z "$TABLE" ] || nft delete table inet "$TABLE" 2>/dev/null
    return 0
}

restore_service() {
    # Only one of the parent and watchdog may own restoration.
    [ -f "$WORK/restore-needed" ] || return 0
    local tries=0 owner rest self_pid
    read -r self_pid rest < /proc/self/stat
    while ! mkdir "$WORK/restoring" 2>/dev/null; do
        [ -f "$WORK/restore-needed" ] || return 0
        owner=
        [ ! -r "$WORK/restoring/owner" ] || read -r owner < "$WORK/restoring/owner"
        case "$owner" in ''|*[!0-9]*) owner= ;; esac
        if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
            rm -f "$WORK/restoring/owner"
            rmdir "$WORK/restoring" 2>/dev/null
            continue
        fi
        tries=$((tries + 1))
        [ "$tries" -lt 35 ] || return 1
        sleep 1
    done
    printf '%s\n' "$self_pid" > "$WORK/restoring/owner"
    if "$INIT" start >> "$WORK/service-restore.log" 2>&1 && "$INIT" status >> "$WORK/service-restore.log" 2>&1; then
        rm -f "$WORK/restore-needed"
    else
        printf 'ERROR: service restore failed. Run %s start. See %s/service-restore.log\n' "$INIT" "$WORK" >&2
        rm -f "$WORK/restoring/owner"
        rmdir "$WORK/restoring"
        return 1
    fi
}

cleanup() {
    code=$?
    trap - 0
    trap '' HUP INT TERM
    stop_test
    nft delete table inet "$PATH_TABLE" 2>/dev/null
    if ! restore_service; then code=1; fi
    [ -z "$GUARD_PID" ] || { kill "$GUARD_PID" 2>/dev/null; wait "$GUARD_PID" 2>/dev/null; }
    if [ "$SCAN_LISTS" = 1 ] && [ "$ACTION" = run ] && command -v summarize_lists >/dev/null 2>&1; then
        summarize_lists
    fi
    printf 'Report: %s\n' "$WORK"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -p "$WORK/uci" "$WORK/base" "$WORK/delta" "$WORK/profiles" || die 'Cannot prepare staging'
uci -c "$CONFIG_DIR" -s export zapret2 > "$WORK/source.uci" || die 'Cannot snapshot UCI'
printf 'profile\tattempt\tresult\tcurl_rc\thttp_code\tbytes\tseconds\tbytes_per_second\tdomain\troute\n' > "$WORK/results.tsv"
"$BASE/nfq2/nfqws2" --version > "$WORK/version.txt" 2>&1

progress() {
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "${2:-}" "${HOST:-}" "${target_index:-0}" "${target_count:-0}" > "$WORK/progress.tsv.new"
    mv "$WORK/progress.tsv.new" "$WORK/progress.tsv"
}

discover_hostlists() {
    mkdir -p "$WORK/lists" || return 1
    (
        . /lib/functions.sh
        . "$WORK/source.uci"
        hostlist_sources() {
            local section=$1 refs ref path script token domains auto
            config_get refs "$section" hostlist ''
            for ref in $refs; do
                config_get path "$ref" path ''
                [ -z "$path" ] || printf '%s\tfile\t%s\n' "$ref" "$path"
            done
            config_get_bool auto "$section" autohostlist 0
            if [ "$auto" = 1 ]; then
                config_get path list_hosts_auto path "$BASE/ipset/zapret_hosts_auto.txt"
                printf 'list_hosts_auto\tfile\t%s\n' "$path"
            fi
            config_get script "$section" script ''
            for token in $script; do
                case "$token" in
                    --hostlist=*|--hostlist-auto=*)
                        path=${token#*=}
                        path=$(printf '%s' "$path" | tr -d "\"'")
                        printf '%s\tfile\t%s\n' "$(basename "$path")" "$path"
                        ;;
                    --hostlist-domains=*)
                        domains=${token#*=}
                        domains=$(printf '%s' "$domains" | tr -d "\"'")
                        printf '%s.domains\tinline\t%s\n' "$section" "$domains"
                        ;;
                esac
            done
        }
        config_foreach hostlist_sources strategy
    ) > "$WORK/lists/sources.raw.tsv" || return 1
    # The same file referenced by many profiles is one list.
    awk -F '\t' '!seen[$2 FS $3]++' "$WORK/lists/sources.raw.tsv" > "$WORK/lists/sources.tsv"
    printf 'id\tlist\tsource\tvalid_domains\tselected_domains\tstate\n' > "$WORK/lists.tsv"
    : > "$WORK/membership.tsv"
    list_id=0
    tab=$(printf '\t')
    while IFS="$tab" read -r label kind source; do
        [ -n "$label" ] || continue
        if [ -n "$ONLY_LISTS" ]; then
            found=0
            for wanted in $ONLY_LISTS; do [ "$wanted" != "$label" ] || found=1; done
            [ "$found" = 1 ] || continue
        fi
        list_id=$((list_id + 1))
        raw=$WORK/lists/$list_id.raw
        domains=$WORK/lists/$list_id.domains
        state=OK
        if [ "$kind" = inline ]; then
            printf '%s\n' "$source" | tr ',' '\n' > "$raw"
        else
            path=$source
            [ ! -f "$path.gz" ] || path=$path.gz
            if [ ! -f "$path" ]; then
                state=MISSING
                : > "$raw"
            else
                case "$path" in
                    *.gz) gzip -dc "$path" > "$raw" 2> "$WORK/lists/$list_id.error" || state=READ_ERROR ;;
                    *) cat "$path" > "$raw" || state=READ_ERROR ;;
                esac
            fi
        fi
        awk '
            {gsub(/\r/, ""); sub(/#.*/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); sub(/^\^/, ""); sub(/\.$/, ""); $0=tolower($0)}
            /^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+$/ {
                if ($0 !~ /^[0-9.]+$/ && $0 !~ /\.\./ && !seen[$0]++) print
            }
        ' "$raw" > "$domains"
        total=$(wc -l < "$domains")
        [ "$state" != OK ] || [ "$total" -gt 0 ] || state=EMPTY
        if [ "$MAX_DOMAINS" -gt 0 ]; then
            head -n "$MAX_DOMAINS" "$domains" > "$domains.selected"
        else
            cp "$domains" "$domains.selected"
        fi
        selected=$(wc -l < "$domains.selected")
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$list_id" "$label" "$source" "$total" "$selected" "$state" >> "$WORK/lists.tsv"
        while IFS= read -r domain; do
            printf '%s\t%s\n' "$list_id" "$domain"
        done < "$domains.selected" >> "$WORK/membership.tsv"
    done < "$WORK/lists/sources.tsv"
    for wanted in $ONLY_LISTS; do
        awk -F '\t' -v wanted="$wanted" 'NR>1 && $2==wanted {found=1} END {exit !found}' "$WORK/lists.tsv" || die "Unknown inclusion hostlist: $wanted"
    done
    cut -f2 "$WORK/membership.tsv" | sort -u > "$WORK/domains.txt"
    cat "$WORK/lists.tsv"
}

summarize_lists() {
    [ -s "$WORK/membership.tsv" ] || return 0
    awk -F '\t' -v out="$WORK/domain-results.tsv.new" -v requested="$SELECTED" '
        BEGIN {
            profiles["baseline"]=1
            requested_count=split(requested, names, " ")
            for(i=1;i<=requested_count;i++) if(names[i]!="") profiles[names[i]]=1
        }
        FILENAME==ARGV[1] {members[$2]=members[$2] " " $1; next}
        FILENAME==ARGV[2] {
            if(FNR>1) {label[$1]=$2; available[$1]=$4; selected[$1]=$5; state[$1]=$6}
            next
        }
        FNR==1 {next}
        {
            profiles[$1]=1
            if($3=="CHECK_ERROR") {compile_error[$1]=1; next}
            if($9=="-" || $9=="") next
            key=$1 SUBSEP $9
            tries[key]++
            tally[key SUBSEP $3]++
        }
        END {
            print "profile\tdomain\tresult\tattempts\tpassed" > out
            for(key in tries) {
                split(key, item, SUBSEP)
                profile=item[1]; domain=item[2]; n=tries[key]
                passed=tally[key SUBSEP "PASS"]+tally[key SUBSEP "HTTP_OK"]
                result="FAIL"
                if(passed==n) result="PASS"
                else if(passed>0) result="UNSTABLE"
                else if(tally[key SUBSEP "NO_ACTION"]==n) result="NO_ACTION"
                else if(tally[key SUBSEP "DNS_ERROR"]==n) result="DNS_ERROR"
                else if(tally[key SUBSEP "SKIP_PROTOCOL"]==n) result="SKIP_PROTOCOL"
                else if(tally[key SUBSEP "STRATEGY_ERROR"]+tally[key SUBSEP "START_ERROR"]>0) result="ERROR"
                else if(tally[key SUBSEP "HTTP_RESPONSE"]>0) result="HTTP_RESPONSE"
                print profile "\t" domain "\t" result "\t" n "\t" passed > out
                count=split(members[domain], ids, " ")
                for(i=1;i<=count;i++) if(ids[i]!="") {
                    group=profile SUBSEP ids[i]
                    totals[group SUBSEP result]++
                    visited[group]++
                }
            }
            close(out)
            print "profile\tlist\tcoverage\tpass\tunstable\tfail\tno_action\tdns_error\thttp_response\terrors\tskipped\tverdict"
            for(profile in profiles) for(id in label) {
                group=profile SUBSEP id
                pass=totals[group SUBSEP "PASS"]+0
                unstable=totals[group SUBSEP "UNSTABLE"]+0
                fail=totals[group SUBSEP "FAIL"]+0
                noaction=totals[group SUBSEP "NO_ACTION"]+0
                dns=totals[group SUBSEP "DNS_ERROR"]+0
                http=totals[group SUBSEP "HTTP_RESPONSE"]+0
                errors=totals[group SUBSEP "ERROR"]+0
                skipped=totals[group SUBSEP "SKIP_PROTOCOL"]+0
                verdict="INCONCLUSIVE"
                if(state[id]!="OK") verdict=state[id]
                else if(compile_error[profile]) verdict="CHECK_ERROR"
                else if(visited[group]<selected[id]) verdict="INCOMPLETE"
                else if(pass==selected[id]) verdict=(selected[id]<available[id] ? "ALL_PASS_SAMPLE" : "ALL_PASS")
                else if(pass+unstable>0) verdict="PARTIAL"
                else if(skipped==selected[id]) verdict="SKIP_PROTOCOL"
                else if(noaction==selected[id]) verdict="NO_ACTION"
                else if(errors>0) verdict="ERROR"
                else if(fail==selected[id]) verdict="FAIL"
                print profile "\t" label[id] "\t" (visited[group]+0) "/" selected[id] "/" available[id] "\t" pass "\t" unstable "\t" fail "\t" noaction "\t" dns "\t" http "\t" errors "\t" skipped "\t" verdict
            }
        }
    ' "$WORK/membership.tsv" "$WORK/lists.tsv" "$WORK/results.tsv" > "$WORK/list-results.tsv.new"
    mv "$WORK/domain-results.tsv.new" "$WORK/domain-results.tsv"
    mv "$WORK/list-results.tsv.new" "$WORK/list-results.tsv"
    [ "${1:-}" != quiet ] || return 0
    printf '\nList results (root HTTP reachability)\n'
    cat "$WORK/list-results.tsv"
}

if [ "$ACTION" = list-hostlists ] || [ "$SCAN_LISTS" = 1 ]; then
    discover_hostlists || die 'Cannot discover domain lists'
    [ "$ACTION" != list-hostlists ] || exit 0
    [ -s "$WORK/domains.txt" ] || die 'No domains found in referenced hostlists'
fi

compile_profile() {
    profile=$1
    current=$2
    mkdir -p "$current" || return 1
    cp "$WORK/source.uci" "$WORK/uci/zapret2" || return 1
    # Disable all other profiles only in a private copy.
    for item in $ALL; do
        printf 'set zapret2.%s.enabled=0\n' "$item"
    done > "$WORK/select.batch"
    printf 'set zapret2.%s.enabled=1\n' "$profile" >> "$WORK/select.batch"
    printf 'commit zapret2\n' >> "$WORK/select.batch"
    uci -c "$WORK/uci" -t "$WORK/delta" -s batch < "$WORK/select.batch" || return 1
    cp "$BASE/config" "$WORK/base/config" || return 1
    UCI_CONFIG_DIR="$WORK/uci" ZAPRET_BASE="$WORK/base" \
        sh "$BASE/init.d/openwrt/uci2config" > "$current/generator.log" 2>&1 || return 1
    (
        . "$WORK/base/config"
        printf '%s\n' "$NFQWS2_OPT"
    ) > "$current/options.txt" || return 1
    # Refuse a generator that silently loaded the live configuration.
    name_count=$(grep -o -- '--name=[^[:space:]]*' "$current/options.txt" | wc -l)
    if [ "$name_count" -ne 1 ]; then
        printf 'Expected exactly one compiled profile, got %s.\n' "$name_count" > "$current/error.txt"
        return 1
    fi
    case "$profile" in
        @*) ;; # Anonymous UCI selectors are exported under generated names.
        *) grep -Fq -- "--name=$profile " "$current/options.txt" || return 1 ;;
    esac
    # Autohostlists could modify live lists during a test. Require an explicit
    # ordinary hostlist strategy instead, preserving its original matching rules.
    if [ "$SCAN_LISTS" = 0 ] && grep -q -- '--hostlist-auto=' "$current/options.txt"; then
        printf 'Autohostlist strategies need a fixed-hostlist copy for testing.\n' > "$current/error.txt"
        return 1
    fi
    options=$(cat "$current/options.txt")
    if [ "$SCAN_LISTS" = 1 ]; then
        # Measure the technique against the target under test, independently of
        # its original domain/IP scope. Transport, L7 and Lua remain unchanged.
        cp "$current/options.txt" "$current/original-options.txt" || return 1
        awk '{for(i=1;i<=NF;i++) if ($i !~ /^--(hostlist(|-domains|-exclude|-exclude-domains)|ipset(|-ip|-exclude|-exclude-ip))=/ && $i !~ /^--hostlist-auto([=-]|$)/) printf "%s ", $i; print ""}' \
            "$current/options.txt" > "$current/technique-options.txt"
        mv "$current/technique-options.txt" "$current/options.txt"
        options=$(cat "$current/options.txt")
    fi
    "$BASE/nfq2/nfqws2" --qnum=399 --dry-run \
        "--lua-init=@$BASE/lua/zapret-lib.lua" \
        "--lua-init=@$BASE/lua/zapret-antidpi.lua" \
        "--lua-init=@$BASE/lua/zapret-auto.lua" \
        $options > "$current/dry-run.log" 2>&1
}

index=0
READY=
CHECK_FAILED=0
for profile in $SELECTED; do
    index=$((index + 1))
    current=$WORK/profiles/$index
    printf '%s\n' "$profile" > "$WORK/profile-$index.txt"
    progress compile "$profile"
    if compile_profile "$profile" "$current"; then
        printf 'CHECK_OK %s\n' "$profile"
        READY="$READY $index"
    else
        printf 'CHECK_ERROR %s (see %s)\n' "$profile" "$current"
        printf '%s\t0\tCHECK_ERROR\t-\t-\t-\t-\t-\t-\t-\n' "$profile" >> "$WORK/results.tsv"
        CHECK_FAILED=1
    fi
done
[ "$ACTION" != check ] || exit "$CHECK_FAILED"
[ -n "$READY" ] || die 'No profiles passed compilation'

parse_target() {
    case "$URL" in
        http://*) [ "$MODE" = http ] || die 'Use --mode http with an http URL'; authority=${URL#http://}; PORT=80 ;;
        https://*) [ "$MODE" != http ] || die 'Use an https test mode'; authority=${URL#https://}; PORT=443 ;;
        *) die 'A complete --url http(s)://host/path is required' ;;
    esac
    authority=${authority%%/*}
    authority=${authority%%\?*}
    case "$authority" in *:*) HOST=${authority%:*}; PORT=${authority##*:} ;; *) HOST=$authority ;; esac
    case "$HOST" in ''|*[!a-zA-Z0-9.-]*) die 'Only DNS names or IPv4 URLs are supported' ;; esac
    number "$PORT" && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die 'Invalid URL port'
}

resolve_target() {
    if [ -z "$PIN_IP" ]; then
        printf '%s\n' "$HOST" > "$WORK/dns-input.txt"
        "$BASE/mdig/mdig" --family=4 --eagain=1 < "$WORK/dns-input.txt" \
            > "$target_dir/dns.txt" 2> "$target_dir/dns-error.log" &
        DNS_PID=$!
        printf '%s\n' "$DNS_PID" > "$WORK/dns.pid"
        (sleep "$TIMEOUT"; kill "$DNS_PID" 2>/dev/null) 9>&- &
        DNS_TIMER=$!
        wait "$DNS_PID" 2>/dev/null
        kill "$DNS_TIMER" 2>/dev/null
        wait "$DNS_TIMER" 2>/dev/null
        DNS_PID=
        DNS_TIMER=
        rm -f "$WORK/dns.pid"
        PIN_IP=$(tr -d '\r' < "$target_dir/dns.txt" | head -n 1)
    fi
    printf '%s\n' "$PIN_IP" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}'
}

command -v curl >/dev/null || die 'curl is required'
command -v nft >/dev/null || die 'nft is required'
[ -x "$INIT" ] || die 'OpenWrt zapret2 service not found'
curl --version > "$WORK/curl-version.txt"
if [ "$MODE" = quic ] && ! grep -q 'HTTP3' "$WORK/curl-version.txt"; then
    printf 'SKIP_UNSUPPORTED: curl has no HTTP3 support.\n'
    printf 'quic\t0\tSKIP_UNSUPPORTED\t-\t-\t-\t-\t-\t-\t-\n' >> "$WORK/results.tsv"
    exit 2
fi
if [ "$SCAN_LISTS" = 1 ]; then
    scheme=https
    [ "$MODE" != http ] || scheme=http
    sed "s|^|$scheme://|; s|$|/|" "$WORK/domains.txt" > "$WORK/urls.txt"
else
    parse_target
    printf '%s\n' "$URL" > "$WORK/urls.txt"
fi
printf '%s\n' "$SELECTED" > "$WORK/selected.txt"
printf '%s\n' "$MODE" > "$WORK/mode.txt"
printf '%s\n' "$REQUEST" > "$WORK/request.txt"
FIXED_IP=$PIN_IP
case "$MODE" in quic) TRANSPORT=udp ;; *) TRANSPORT=tcp ;; esac

# Throughput probe target: resolved once and added to the test firewall so the
# candidate strategy (not the live service in --no-stop mode) shapes it.
TP_IP= TP_HOST= TP_PORT= TP_URL=$THROUGHPUT_URL
if [ "$THROUGHPUT" -gt 0 ]; then
    [ "$SCAN_LISTS" = 0 ] || die '--throughput is not supported with --scan-lists'
    [ -n "$TP_URL" ] || TP_URL=$URL
    case "$TP_URL" in
        http://*) tp_authority=${TP_URL#http://}; TP_PORT=80 ;;
        https://*) tp_authority=${TP_URL#https://}; TP_PORT=443 ;;
        *) die 'A complete --throughput-url http(s)://host/path is required' ;;
    esac
    tp_authority=${tp_authority%%/*}
    tp_authority=${tp_authority%%\?*}
    case "$tp_authority" in *:*) TP_HOST=${tp_authority%:*}; TP_PORT=${tp_authority##*:} ;; *) TP_HOST=$tp_authority ;; esac
    case "$TP_HOST" in ''|*[!a-zA-Z0-9.-]*) die 'Only DNS names or IPv4 throughput URLs are supported' ;; esac
    number "$TP_PORT" && [ "$TP_PORT" -ge 1 ] && [ "$TP_PORT" -le 65535 ] || die 'Invalid throughput URL port'
    if [ "$TP_HOST" = "$HOST" ] && [ -n "$FIXED_IP" ]; then TP_IP=$FIXED_IP; fi
    if [ -z "$TP_IP" ]; then
        printf '%s\n' "$TP_HOST" > "$WORK/dns-tp-input.txt"
        "$BASE/mdig/mdig" --family=4 --eagain=1 < "$WORK/dns-tp-input.txt" > "$WORK/dns-tp.txt" 2> "$WORK/dns-tp-error.log"
        TP_IP=$(tr -d '\r' < "$WORK/dns-tp.txt" | head -n 1)
    fi
    printf '%s\n' "$TP_IP" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}' \
        || die 'Cannot resolve throughput host'
    printf 'Throughput target: %s (%s), %s MiB, min speed %s KB/s\n' "$TP_HOST" "$TP_IP" "$THROUGHPUT" "$MIN_SPEED"
fi
QNUM=$((20000 + $$ % 20000))
while awk -v q="$QNUM" '$1==q {found=1} END {exit !found}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null; do
    QNUM=$((QNUM + 1))
    [ "$QNUM" -lt 60000 ] || die 'No test queue available'
done

watchdog() {
    # This child survives a killed/disconnected parent and performs recovery.
    trap '' HUP INT
    trap 'exit 0' TERM
    elapsed=0
    while kill -0 "$parent_pid" 2>/dev/null && [ "$elapsed" -lt "$deadline" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
    done
    if [ "$elapsed" -ge "$deadline" ]; then
        kill -TERM "$parent_pid" 2>/dev/null
        sleep 3
    fi
    if [ -f "$WORK/nfq.pid" ]; then
        read -r child_pid < "$WORK/nfq.pid"
        case "$child_pid" in ''|*[!0-9]*) ;; *) kill "$child_pid" 2>/dev/null ;; esac
    fi
    for child_file in curl.pid dns.pid; do
        if [ -f "$WORK/$child_file" ]; then
            read -r child_pid < "$WORK/$child_file"
            case "$child_pid" in ''|*[!0-9]*) ;; *) kill "$child_pid" 2>/dev/null ;; esac
        fi
    done
    nft delete table inet "$TABLE" 2>/dev/null
    nft delete table inet "$PATH_TABLE" 2>/dev/null
    restore_service
}

# Arm recovery before stopping the service, including the stop/start failure case.
parent_pid=$$
target_count=$(wc -l < "$WORK/urls.txt")
deadline=$((120 + target_count * (TIMEOUT + (index + 1) * REPEATS * (TIMEOUT + 3))))
[ "$THROUGHPUT" -eq 0 ] || deadline=$((deadline + (index + 1) * TP_MAXTIME))
if [ "$NOSTOP" = 1 ]; then
    "$INIT" status > "$WORK/service-before.log" 2>&1 || die '--no-stop requires zapret2 service running'
    if ! nft list table inet zapret2 2>/dev/null | grep -q 'queue'; then
        die 'zapret2 queue rules not found; service seems inactive'
    fi
else
    if "$INIT" status > "$WORK/service-before.log" 2>&1; then
        : > "$WORK/restore-needed"
    fi
fi
(watchdog) > "$WORK/watchdog.log" 2>&1 &
GUARD_PID=$!
if [ "$NOSTOP" = 1 ]; then
    printf 'Live test: %s target(s) via %s. zapret2 keeps running; test flows are marked for it to skip.\n' "$target_count" "$MODE"
else
    printf 'Live test: %s target(s) via %s. zapret2 is paused during testing.\n' "$target_count" "$MODE"
    "$INIT" stop > "$WORK/service-stop.log" 2>&1 || die 'Cannot stop zapret2'
    if "$INIT" status >/dev/null 2>&1; then die 'zapret2 is still running'; fi
    if nft list table inet zapret2 2>/dev/null | grep -q 'queue'; then
        die 'zapret2 queue rules remain; isolated testing would be inaccurate'
    fi
fi

wait_for_queue() {
    local queue_file=/proc/net/netfilter/nfnetlink_queue polls=0
    if [ ! -r "$queue_file" ] || ! command -v ucode >/dev/null; then
        sleep 1
        kill -0 "$NFQ_PID" 2>/dev/null
        return
    fi
    while kill -0 "$NFQ_PID" 2>/dev/null; do
        awk -v q="$QNUM" -v pid="$NFQ_PID" '$1==q && $2==pid {ready=1} END {exit !ready}' "$queue_file" && return 0
        [ "$polls" -lt 20 ] || break
        ucode -e 'sleep(50)' || break
        polls=$((polls + 1))
    done
    return 1
}

probe() {
    profile=$1
    attempt=$2
    log=$3
    local metric_format='%{http_code}\t%{size_download}\t%{time_total}\t%{speed_download}\t%{local_port}\n'
    set -- -4 --noproxy '*' --silent --show-error --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
        --resolve "$HOST:$PORT:$PIN_IP" --local-port 61000-61099 \
        --output /dev/null \
        --write-out "$metric_format"
    if [ "$SCAN_LISTS" = 1 ]; then
        # A list scan measures root HTTP reachability, keeping logs bounded even
        # for hundreds of domains. Full content probes remain in --url mode.
        if [ "$REQUEST" = get ]; then
            set -- "$@" --range 0-65535 --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/8.0'
        else
            set -- "$@" --head
        fi
    else
        set -- "$@" --range 0-262143
    fi
    case "$MODE" in
        tls13) set -- "$@" --tlsv1.3 --tls-max 1.3 --http1.1 ;;
        tls12) set -- "$@" --tlsv1.2 --tls-max 1.2 --http1.1 ;;
        quic) set -- "$@" --http3-only ;;
        http) set -- "$@" --http1.1 ;;
    esac
    [ -z "$HEALTH_KIND" ] || set -- "$@" --max-filesize 8388608 --write-out "$HEALTH_FORMAT"
    observe_path "$PIN_IP" "$PORT"
    curl "$@" "$URL" 9>&- > "$log.metrics" 2> "$log.curl.log" &
    CURL_PID=$!
    printf '%s\n' "$CURL_PID" > "$WORK/curl.pid"
    wait "$CURL_PID"
    curl_rc=$?
    CURL_PID=
    rm -f "$WORK/curl.pid"
    metrics=$(cut -f1-4 "$log.metrics")
    route=$(observed_route "$(cut -f5 "$log.metrics")")
    result=FAIL
    [ "$curl_rc" -ne 0 ] || {
        if awk -v min="$MIN_BYTES" '$1 ~ /^2[0-9][0-9]$/ && $2>=min {ok=1} END {exit !ok}' "$log.metrics"; then result=HTTP_OK; fi
        if [ "$SCAN_LISTS" = 1 ]; then
            result=HTTP_RESPONSE
            if awk '$1 ~ /^[23][0-9][0-9]$/ {ok=1} END {exit !ok}' "$log.metrics"; then result=HTTP_OK; fi
        fi
    }
    if [ -n "$HEALTH_KIND" ]; then
        result=FAIL
        [ "$curl_rc" = 0 ] && health_response "$HEALTH_KIND" "$HOST" < "$log.metrics" && result=HTTP_OK
    fi
    if [ "$THROUGHPUT" -gt 0 ] && [ "$attempt" = 1 ] && [ "$result" = HTTP_OK ]; then
        set -- -4 --noproxy '*' --silent --show-error --connect-timeout "$TIMEOUT" --max-time "$TP_MAXTIME" \
            --resolve "$TP_HOST:$TP_PORT:$TP_IP" --local-port 61000-61099 \
            --output /dev/null --range "0-$((THROUGHPUT * 1048576 - 1))" --max-filesize "$((THROUGHPUT * 1048576))" \
            --user-agent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/8.0' \
            --write-out "$metric_format"
        case "$MODE" in
            tls13) set -- "$@" --tlsv1.3 --tls-max 1.3 --http1.1 ;;
            tls12) set -- "$@" --tlsv1.2 --tls-max 1.2 --http1.1 ;;
            quic) set -- "$@" --http3-only ;;
            http) set -- "$@" --http1.1 ;;
        esac
        observe_path "$TP_IP" "$TP_PORT"
        curl "$@" "$TP_URL" 9>&- > "$log.tp.metrics" 2> "$log.tp.curl.log" &
        CURL_PID=$!
        printf '%s\n' "$CURL_PID" > "$WORK/curl.pid"
        wait "$CURL_PID"
        tp_rc=$?
        CURL_PID=
        rm -f "$WORK/curl.pid"
        tp_metrics=$(cut -f1-4 "$log.tp.metrics")
        tp_route=$(observed_route "$(cut -f5 "$log.tp.metrics")")
        tp_result=$(awk -v rc="$tp_rc" -v mib="$THROUGHPUT" -v kbps="$MIN_SPEED" '
            $1 ~ /^(200|206)$/ && $2 ~ /^[0-9]+$/ && $2 == mib*1048576 && $4 ~ /^[0-9]+([.][0-9]+)?$/ {
                valid=1; speed=$4+0
            }
            END { print (rc || !valid ? "TP_FAIL" : speed < kbps*1024 ? "TP_SLOW" : "TP_OK") }
        ' "$log.tp.metrics")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$profile" "$attempt" "$tp_result" "$tp_rc" "$tp_metrics" "$TP_HOST" "$tp_route" >> "$WORK/results.tsv"
        printf '%s %s throughput: %s curl=%s %s\n' "$HOST" "$profile" "$tp_result" "$tp_rc" "$tp_metrics"
    fi
    if [ "$profile" != baseline ]; then
        nft list table inet "$TABLE" > "$log.firewall.txt"
        stop_test
        rm -f "$WORK/nfq.pid"
        if grep -Eq 'desync ERROR|stack traceback|not found[.] skipped|unavailable|not found[.] using zero pattern' "$log.nfq.log"; then
            result=STRATEGY_ERROR
        elif ! grep -Eq "\\* lua .*: desync" "$log.nfq.log"; then
            result=NO_ACTION
        elif [ "$result" = HTTP_OK ]; then
            result=PASS
        fi
        if [ "$SCAN_LISTS" = 1 ]; then
            grep -E 'github version|desync profile|hostname=|\* lua.*: desync|ERROR|not found|unavailable|stack traceback' "$log.nfq.log" | tail -n 100 > "$log.nfq.log.compact"
            mv "$log.nfq.log.compact" "$log.nfq.log"
        fi
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$profile" "$attempt" "$result" "$curl_rc" "$metrics" "$HOST" "$route" >> "$WORK/results.tsv"
    printf '%s %s attempt %s: %s curl=%s %s\n' "$HOST" "$profile" "$attempt" "$result" "$curl_rc" "$metrics"
    if [ "$KEEP_LOGS" = last-error ]; then
        case "$result" in
            FAIL|STRATEGY_ERROR)
                if [ "$profile" != baseline ]; then
                    { printf '%s %s\n' "$HOST" "$result"; cat "$log.curl.log" "$log.nfq.log"; } > "$current/last-error.log"
                fi
                ;;
        esac
        rm -f "$log.metrics" "$log.curl.log" "$log.nfq.log" "$log.firewall.txt"
    fi
}

setup_firewall() {
    nft delete table inet "$TABLE" 2>/dev/null
    nft -f - <<EOF
add table inet $TABLE
add chain inet $TABLE postnat { type filter hook postrouting priority 102; policy accept; }
add rule inet $TABLE postnat ip daddr { $DESTS } $TRANSPORT dport { $DPORTS } $TRANSPORT sport 61000-61099 meta mark & $MARK == 0 ct mark set ct mark | $MARK counter queue num $QNUM bypass
add chain inet $TABLE prenat { type filter hook prerouting priority -102; policy accept; }
add rule inet $TABLE prenat ip saddr { $DESTS } $TRANSPORT sport { $DPORTS } $TRANSPORT dport 61000-61099 counter queue num $QNUM bypass
add rule inet $TABLE prenat icmp type time-exceeded ct mark & $MARK != 0 drop
add chain inet $TABLE predefrag { type filter hook output priority -402; policy accept; }
add rule inet $TABLE predefrag meta mark & $MARK != 0 notrack
EOF
    if [ "$NOSTOP" = 1 ]; then
        # Mark test flows with the zapret2 desync mark BEFORE the live service hooks
        # (postrouting srcnat-1=99, prerouting dstnat+1=-99) so they are never queued
        # to the live nfqws2. The tester's own rules at 102/-102 still queue them
        # to the isolated test queue.
        nft -f - <<EOF
add chain inet $TABLE premarkout { type filter hook postrouting priority 98; policy accept; }
add rule inet $TABLE premarkout ip daddr { $DESTS } $TRANSPORT dport { $DPORTS } $TRANSPORT sport 61000-61099 ct mark & $MARK == 0 ct mark set ct mark | $MARK meta mark set meta mark | $DESYNC_MARK
add chain inet $TABLE premarkin { type filter hook prerouting priority -103; policy accept; }
add rule inet $TABLE premarkin ct mark & $MARK != 0 meta mark set meta mark | $DESYNC_MARK
EOF
    fi
}


# Only skip when every plain inclusion file is readable and definitively excludes
# this host. Unknown syntax, automatic lists and additional inclusions stay eligible.
host_scope_misses() {
    local opt path hits=0 tmp="$WORK/host-scope.txt"
    for opt in $options; do
        case "$opt" in
            --hostlist-domains=*|--hostlist-auto=*|--new) return 1 ;;
            --hostlist=*)
                path=${opt#*=}
                [ -r "$path" ] || return 1
                case "$path" in *.gz) gzip -dc "$path" > "$tmp" || return 1;; *) tmp=$path;; esac
                awk -v h="$HOST" '
                    {sub(/#.*/,"");gsub(/^[ \t]+|[ \t\r]+$/,""); if(!length) next
                     v=tolower($0); exact=sub(/^\^/,"",v); if(v !~ /^[a-z0-9.-]+$/ || v==h || (!exact && substr(h,length(h)-length(v))=="."v)) keep=1}
                    END {exit !keep}' "$tmp" && return 1
                hits=1; tmp="$WORK/host-scope.txt";;
        esac
    done
    [ "$hits" = 1 ]
}

run_profiles() {
for selected_index in $READY; do
    current=$WORK/profiles/$selected_index
    profile=$(cat "$WORK/profile-$selected_index.txt")
    options=$(cat "$current/options.txt")
    if [ -n "$HEALTH_KIND" ] && host_scope_misses; then
        printf '%s\t0\tSKIP_HOSTLIST\t-\t-\t-\t-\t-\t%s\t-\n' "$profile" "$HOST" >> "$WORK/results.tsv"
        continue
    fi
    if ! grep -q -- "--filter-$TRANSPORT=" "$current/options.txt"; then
        printf 'SKIP_PROTOCOL %s (test uses %s)\n' "$profile" "$TRANSPORT"
        printf '%s\t0\tSKIP_PROTOCOL\t-\t-\t-\t-\t-\t%s\t-\n' "$profile" "$HOST" >> "$WORK/results.tsv"
        continue
    fi
    attempt=1
    while [ "$attempt" -le "$REPEATS" ]; do
        # Start a fresh process per attempt to reset circular/orchestrator state.
        log=$target_dir/profile-$selected_index-attempt-$attempt
        progress test "$profile"
        "$BASE/nfq2/nfqws2" "--qnum=$QNUM" "--fwmark=$MARK" --debug=1 \
            "--lua-init=@$BASE/lua/zapret-lib.lua" \
            "--lua-init=@$BASE/lua/zapret-antidpi.lua" \
            "--lua-init=@$BASE/lua/zapret-auto.lua" $options > "$log.nfq.log" 2>&1 &
        NFQ_PID=$!
        printf '%s\n' "$NFQ_PID" > "$WORK/nfq.pid"
        if ! wait_for_queue; then
            printf '%s\t%s\tSTART_ERROR\t-\t-\t-\t-\t-\t%s\t-\n' "$profile" "$attempt" "$HOST" >> "$WORK/results.tsv"
            printf 'START_ERROR %s (see %s.nfq.log)\n' "$profile" "$log"
            if [ "$KEEP_LOGS" = last-error ]; then
                mv "$log.nfq.log" "$current/last-error.log"
            fi
            stop_test
            break
        fi
        setup_firewall || die 'Cannot create test firewall'
        probe "$profile" "$attempt" "$log"
        attempt=$((attempt + 1))
    done
done
}

target_index=0
mkdir -p "$WORK/targets"
while IFS= read -r URL; do
    free_kb=$(df -k "$WORK" | awk 'NR==2 {print $4}')
    if number "$free_kb" && [ "$free_kb" -lt 4096 ]; then
        die 'Low report filesystem space; partial results were saved'
    fi
    target_index=$((target_index + 1))
    target_dir=$WORK/targets/$target_index
    mkdir -p "$target_dir" || die 'Cannot create target report'
    PIN_IP=$FIXED_IP
    parse_target
    progress dns
    printf '%s\n' "$URL" > "$target_dir/url.txt"
    printf 'Target %s/%s: %s\n' "$target_index" "$target_count" "$HOST"
    if ! resolve_target; then
        printf 'DNS_ERROR %s\n' "$HOST"
        for profile in baseline $SELECTED; do
            printf '%s\t0\tDNS_ERROR\t-\t-\t-\t-\t-\t%s\t-\n' "$profile" "$HOST" >> "$WORK/results.tsv"
        done
        [ "$SCAN_LISTS" != 1 ] || summarize_lists quiet
        continue
    fi
    printf 'host=%s\nip=%s\nport=%s\nmode=%s\n' "$HOST" "$PIN_IP" "$PORT" "$MODE" > "$target_dir/target.txt"
    DESTS=$PIN_IP
    DPORTS=$PORT
    if [ "$THROUGHPUT" -gt 0 ]; then
        [ "$TP_IP" = "$PIN_IP" ] || DESTS="$PIN_IP, $TP_IP"
        [ "$TP_PORT" = "$PORT" ] || DPORTS="$PORT, $TP_PORT"
    fi
    attempt=1
    if [ "$NOSTOP" = 1 ]; then
        # Mark baseline flows too so the live service skips them: baseline stays direct.
        setup_firewall || die 'Cannot create test firewall'
    fi
    while [ "$attempt" -le "$REPEATS" ]; do
        progress baseline baseline
        probe baseline "$attempt" "$target_dir/baseline-$attempt"
        attempt=$((attempt + 1))
    done
    run_profiles
    [ "$SCAN_LISTS" != 1 ] || summarize_lists quiet
done < "$WORK/urls.txt"
progress finished
awk -F '\t' 'NR>1 {counts[$1 " " $3]++} END {for (key in counts) print key, counts[key]}' "$WORK/results.tsv" > "$WORK/summary.txt"
printf '\nSummary\n'
cat "$WORK/summary.txt"
exit 0
