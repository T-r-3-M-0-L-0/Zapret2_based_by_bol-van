#!/bin/sh
# Fixed-command bridge for the LuCI strategy comparison tab.
set -f
umask 077
TOOLS=/root/zapret2-tools
# Prefer static curl with HTTP3 (same as the checker) so quic mode is offered.
if [ -x /opt/zapret2/curl-h3 ]; then PATH="/opt/zapret2/h3bin:$PATH"; export PATH; fi
CHECKER=$TOOLS/strategy-check-openwrt.sh
SELF=$TOOLS/strategy-check-control.sh
STATE=/tmp/zapret2-strategy-ui
mkdir -p "$STATE"
. /usr/share/libubox/jshn.sh

error() { json_init; json_add_string error "$*"; json_dump; exit 1; }
read_text() { [ ! -f "$1" ] || cat "$1"; }
valid_number() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
live_pid() {
    local pid=$1 pattern=$2
    valid_number "$pid" && [ "$pid" -gt 1 ] && kill -0 "$pid" 2>/dev/null &&
        tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -Fq -- "$pattern"
}
latest() {
    JOB=$(read_text "$STATE/latest")
    case "$JOB" in "$STATE"/job-*) [ -d "$JOB" ] || JOB= ;; *) JOB= ;; esac
}
is_running() {
    [ -n "$JOB" ] || return 1
    live_pid "$(read_text "$JOB/worker.pid")" "$SELF" ||
        live_pid "$(read_text "$JOB/checker.pid")" "$CHECKER"
}
catalog_files() {
    if [ -f "$STATE/catalog.lists.tsv" ] && is_running; then return 0; fi
    local dir code
    dir=$(mktemp -d /tmp/zapret2-catalog-XXXXXX) || return 1
    "$CHECKER" --list > "$dir/profiles.tsv" || return 1
    "$CHECKER" --list-hostlists --report "$dir/report" > "$dir/output.log" 2>&1
    code=$?
    if [ "$code" = 0 ]; then
        cp "$dir/report/lists.tsv" "$STATE/catalog.lists.tsv"
        cp "$dir/profiles.tsv" "$STATE/catalog.profiles.tsv"
    fi
    rm -rf "$dir"
    return "$code"
}

worker() {
    JOB=$1
    shift
    read -r worker_pid rest < /proc/self/stat
    printf '%s\n' "$worker_pid" > "$JOB/worker.pid"
    trap '' HUP INT
    [ ! -f "$JOB/stop" ] || { echo stopped > "$JOB/state"; exit 0; }
    "$CHECKER" "$@" --report "$JOB/report" > "$JOB/run.log" 2>&1 &
    checker_pid=$!
    printf '%s\n' "$checker_pid" > "$JOB/checker.pid"
    [ ! -f "$JOB/stop" ] || kill -TERM "$checker_pid" 2>/dev/null
    echo running > "$JOB/state"
    wait "$checker_pid"
    code=$?
    printf '%s\n' "$code" > "$JOB/exit-code"
    # The checker watchdog may still be restoring after a forced termination.
    n=0
    while [ -f "$JOB/report/restore-needed" ] && [ "$n" -lt 40 ]; do
        echo restoring > "$JOB/state"
        sleep 1
        n=$((n + 1))
    done
    if [ -f "$JOB/report/restore-needed" ]; then
        echo recovery_required > "$JOB/state"
    elif [ -f "$JOB/stop" ]; then
        echo stopped > "$JOB/state"
    elif [ "$code" = 0 ]; then
        echo finished > "$JOB/state"
    else
        echo failed > "$JOB/state"
    fi
    date +%s > "$JOB/finished"
}

case "${1:-}" in
    _worker) shift; worker "$@"; exit ;;
    catalog)
        latest
        catalog_files || error 'Не удалось прочитать списки. Возможно, идёт проверка из SSH.'
        json_init
        json_add_string profiles "$(cat "$STATE/catalog.profiles.tsv")"
        json_add_string lists "$(cat "$STATE/catalog.lists.tsv")"
        http3=0
        curl --version | grep -q HTTP3 && http3=1
        json_add_boolean http3 "$http3"
        json_dump
        ;;
    start)
        [ "$#" = 8 ] || error 'Неверное число параметров запуска'
        shift
        profiles=$1; lists=$2; mode=$3; repeats=$4; limit=$5; timeout=$6; request=$7
        case "$mode" in tls13|tls12|http|quic) ;; *) error 'Неизвестный протокол' ;; esac
        case "$request" in head|get) ;; *) error 'Неизвестный метод запроса' ;; esac
        valid_number "$repeats" && [ "$repeats" -ge 1 ] && [ "$repeats" -le 5 ] || error 'Повторы должны быть от 1 до 5'
        valid_number "$limit" && [ "$limit" -le 10000 ] || error 'Неверный лимит доменов'
        valid_number "$timeout" && [ "$timeout" -ge 2 ] && [ "$timeout" -le 30 ] || error 'Тайм-аут должен быть от 2 до 30 секунд'
        if [ "$mode" = quic ]; then curl --version | grep -q HTTP3 || error 'В установленном curl нет HTTP/3'; fi
        [ -n "$profiles" ] && [ -n "$lists" ] || error 'Выберите стратегии и списки'
        exec 8>/var/lock/zapret2-strategy-ui.lock
        flock -n 8 || error 'Другой запрос запуска уже обрабатывается'
        latest
        is_running && error 'Проверка уже запущена'
        exec 7>/var/lock/zapret2-strategy-check.lock
        flock -n 7 || error 'Идёт проверка из SSH. Дождитесь её завершения.'
        flock -u 7
        exec 7>&-
        catalog_files || error 'Не удалось получить каталог профилей'
        /etc/init.d/zapret2 status >/dev/null 2>&1 || error 'Служба zapret2 не запущена — сначала запустите её'
        set -- --run --no-stop --scan-lists --mode "$mode" --repeats "$repeats" \
            --max-domains-per-list "$limit" --timeout "$timeout" --request "$request" --keep-logs last-error
        if [ "$profiles" = all ]; then
            set -- "$@" --all
        else
            for profile in $(printf '%s' "$profiles" | tr ',' ' '); do
                awk -F '\t' -v name="$profile" 'NR>1 && $1==name {found=1} END {exit !found}' "$STATE/catalog.profiles.tsv" || error 'Неизвестная стратегия'
                set -- "$@" --strategy "$profile"
            done
        fi
        if [ "$lists" != all ]; then
            for name in $(printf '%s' "$lists" | tr ',' ' '); do
                awk -F '\t' -v name="$name" 'NR>1 && $2==name {found=1} END {exit !found}' "$STATE/catalog.lists.tsv" || error 'Неизвестный список'
                set -- "$@" --only-list "$name"
            done
        fi
        JOB=$STATE/job-$(date +%s)-$$
        mkdir "$JOB" || error 'Не удалось создать каталог проверки'
        date +%s > "$JOB/started"
        printf '%s\n' "$mode" > "$JOB/mode"
        printf '%s\n' "$request" > "$JOB/request"
        printf '%s\n' "$limit" > "$JOB/limit"
        echo preparing > "$JOB/state"
        printf '%s\n' "$JOB" > "$STATE/latest.new"
        mv "$STATE/latest.new" "$STATE/latest"
        setsid "$SELF" _worker "$JOB" "$@" 8>&- </dev/null > "$JOB/worker.log" 2>&1 &
        printf '%s\n' "$!" > "$JOB/worker.pid"
        json_init; json_add_boolean started 1; json_add_string report "$JOB/report"; json_dump
        ;;
    stop)
        latest
        [ -n "$JOB" ] || error 'Нет запущенной проверки'
        is_running || error 'Нет выполняющейся проверки'
        : > "$JOB/stop"
        pid=$(read_text "$JOB/checker.pid")
        if live_pid "$pid" "$CHECKER"; then kill -TERM "$pid"; fi
        json_init; json_add_boolean stopping 1; json_dump
        ;;
    status)
        latest
        json_init
        if [ -z "$JOB" ]; then json_add_string state idle; json_add_boolean running 0; json_dump; exit; fi
        running=0
        is_running && running=1
        state=$(read_text "$JOB/state")
        if [ "$running" = 0 ]; then
            case "$state" in preparing|running|restoring)
                if [ -f "$JOB/report/restore-needed" ]; then state=recovery_required; else state=interrupted; fi
                ;;
            esac
        fi
        json_add_string state "$state"
        json_add_boolean running "$running"
        json_add_string mode "$(read_text "$JOB/mode")"
        json_add_string request "$(read_text "$JOB/request")"
        json_add_string report "$JOB/report"
        json_add_string progress "$(read_text "$JOB/report/progress.tsv")"
        json_add_string lists "$(read_text "$JOB/report/lists.tsv")"
        json_add_string results "$(read_text "$JOB/report/list-results.tsv")"
        json_add_string scores "$(awk -F '\t' 'NR>1 {total[$1]++; if($3=="PASS") ok[$1]++} END {print "profile\tpass\ttested"; for(p in total) print p "\t" (ok[p]+0) "\t" total[p]}' "$JOB/report/domain-results.tsv" 2>/dev/null)"
        json_add_string selected "$(read_text "$JOB/report/selected.txt")"
        json_add_string exit_code "$(read_text "$JOB/exit-code")"
        json_add_string started "$(read_text "$JOB/started")"
        json_add_string finished "$(read_text "$JOB/finished")"
        json_add_string log "$(tail -n 35 "$JOB/run.log" 2>/dev/null)"
        json_dump
        ;;
    recover)
        latest
        [ -n "$JOB" ] && [ -f "$JOB/report/restore-needed" ] || error 'Нет ожидающего восстановления'
        is_running && error 'Сначала остановите проверку'
        /etc/init.d/zapret2 start > "$JOB/recover.log" 2>&1 && /etc/init.d/zapret2 status >> "$JOB/recover.log" 2>&1 || error 'Не удалось восстановить службу'
        rm -f "$JOB/report/restore-needed"
        echo interrupted > "$JOB/state"
        json_init; json_add_boolean recovered 1; json_dump
        ;;
    promote)
        [ "$#" = 2 ] || error 'Укажите стратегию: promote NAME'
        profile=$2
        [ "$(uci -q -c /etc/config get "zapret2.$profile" 2>/dev/null)" = strategy ] || error 'Неизвестная стратегия'
        latest
        is_running && error 'Идёт проверка. Дождитесь её завершения.'
        exec 7>/var/lock/zapret2-strategy-check.lock
        flock -n 7 || error 'Идёт проверка из SSH. Дождитесь её завершения.'
        backup=/root/zapret2-tools/backups/config-before-promote-$(date +%Y%m%d%H%M%S)
        mkdir -p /root/zapret2-tools/backups
        cp /etc/config/zapret2 "$backup" || error 'Не удалось сохранить резервную копию'
        uci -c /etc/config set "zapret2.$profile.enabled=1" || error 'Не удалось включить стратегию'
        uci -c /etc/config commit zapret2 || error 'Не удалось применить конфигурацию'
        /etc/init.d/zapret2 restart > /tmp/zapret2-promote.log 2>&1 || error 'Служба не перезапустилась; копия в $backup'
        sleep 2
        /etc/init.d/zapret2 status >> /tmp/zapret2-promote.log 2>&1
        running=0
        /etc/init.d/zapret2 status >/dev/null 2>&1 && running=1
        flock -u 7
        exec 7>&-
        json_init
        json_add_boolean promoted 1
        json_add_string profile "$profile"
        json_add_string backup "$backup"
        json_add_boolean running "$running"
        json_dump
        ;;
    cronstatus)
        HC=/opt/zapret2/healthcheck.sh
        cron_on=0
        crontab -l 2>/dev/null | grep -Eq '^[^#].*[[:space:]]/opt/zapret2/healthcheck[.]sh([[:space:]]|$)' && cron_on=1
        ap=$(sed -n 's/^AUTOPROMOTE=\([01]\).*/\1/p' "$HC" 2>/dev/null)
        cd=$(sed -n 's/^COOLDOWN=\([0-9]*\).*/\1/p' "$HC" 2>/dev/null)
        cap=$(sed -n 's/^PROMOTE_CAP=\([0-9]*\).*/\1/p' "$HC" 2>/dev/null)
        hc_running=0
        ( flock -n 6 ) 6>/var/lock/zapret2-health.lock || hc_running=1
        json_init
        json_add_boolean cron_enabled "$cron_on"
        json_add_boolean autopromote "${ap:-0}"
        json_add_int cooldown "${cd:-21600}"
        json_add_int promote_cap "${cap:-3}"
        json_add_boolean installed "$([ -f "$HC" ] && echo 1 || echo 0)"
        json_add_boolean running "$hc_running"
        json_add_string health_log "$(tail -n 15 /tmp/zhealth.log 2>/dev/null)"
        json_add_string autotest_log "$(tail -n 40 /tmp/zhealth-autotest.log 2>/dev/null)"
        json_dump
        ;;
    cronset)
        [ "$#" = 5 ] || error 'cronset: enabled autopromote cooldown_hours cap'
        en=$2; ap=$3; cdh=$4; cap=$5
        case "$en" in 0|1) ;; *) error 'enabled: 0 или 1' ;; esac
        case "$ap" in 0|1) ;; *) error 'autopromote: 0 или 1' ;; esac
        valid_number "$cdh" && [ "$cdh" -ge 1 ] && [ "$cdh" -le 168 ] || error 'Кулдаун: от 1 до 168 часов'
        valid_number "$cap" && [ "$cap" -le 20 ] || error 'Лимит промоутов: от 0 до 20'
        HC=/opt/zapret2/healthcheck.sh
        [ -f "$HC" ] || error 'healthcheck.sh не установлен'
        exec 6>/var/lock/zapret2-health.lock
        flock -n 6 || error 'Дождитесь окончания проверки'
        cp -p "$HC" "$HC.uibak" || error 'Не удалось сохранить настройки'
        sed -i "s/^AUTOPROMOTE=.*/AUTOPROMOTE=$ap/; s/^COOLDOWN=.*/COOLDOWN=$((cdh * 3600))/; s/^PROMOTE_CAP=.*/PROMOTE_CAP=$cap/" "$HC" || error 'Не удалось записать параметры'
        if ! ash -n "$HC" 2>/dev/null; then
            cp -p "$HC.uibak" "$HC"
            error 'Ошибка синтаксиса после правки, изменения откачены'
        fi
        if [ "$en" = 1 ]; then
            crontab -l 2>/dev/null | grep -Eq '^[^#].*[[:space:]]/opt/zapret2/healthcheck[.]sh([[:space:]]|$)' ||
                ( crontab -l 2>/dev/null; echo '17 * * * * /opt/zapret2/healthcheck.sh >/dev/null 2>&1 # zhealth' ) | crontab -
        else
            crontab -l 2>/dev/null | grep -Ev '^[^#].*[[:space:]]/opt/zapret2/healthcheck[.]sh([[:space:]]|$)' | crontab -
        fi || { mv -f "$HC.uibak" "$HC"; error 'Не удалось обновить crontab'; }
        rm -f "$HC.uibak"
        json_init; json_add_boolean saved 1; json_dump
        ;;
    cronrun)
        [ -x /opt/zapret2/healthcheck.sh ] || error 'healthcheck.sh не установлен'
        ( flock -n 6 ) 6>/var/lock/zapret2-health.lock || error 'Проверка уже выполняется'
        setsid /opt/zapret2/healthcheck.sh </dev/null >/dev/null 2>&1 &
        json_init; json_add_boolean started 1; json_dump
        ;;
    details)
        [ "$#" = 3 ] || error 'Не указаны стратегия и список'
        profile=$2; name=$3
        latest
        [ -n "$JOB" ] || error 'Отчёт ещё не создан'
        list_id=$(awk -F '\t' -v name="$name" 'NR>1 && $2==name {print $1; exit}' "$JOB/report/lists.tsv")
        [ -n "$list_id" ] || error 'Список не найден в отчёте'
        data=$(awk -F '\t' -v id="$list_id" -v profile="$profile" '
            FILENAME==ARGV[1] {if($1==id) domains[$2]=1; next}
            FNR==1 {print; next}
            $1==profile && domains[$9] {print}
        ' "$JOB/report/membership.tsv" "$JOB/report/results.tsv")
        json_init; json_add_string rows "$data"; json_dump
        ;;
    *) error 'Неизвестное действие' ;;
esac
