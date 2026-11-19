#!/bin/ash
# route-smart.sh v2 — rebuild tgws route.conf preferring fronts on stable CF ranges.
#
# Principles (post-review):
# - 'direct' entries and any non-ws lines are preserved verbatim; only ws entries
#   whose current domain is unhealthy get a replacement.
# - All A-records of kws1.<domain> are measured; a healthy IP passes 3/3 TLS
#   handshakes with HTTP < 400. The health quorum counts unique IPs, not domains.
# - Normalized comparison of route tuples: header/date drift never causes a restart.
# - Atomic write in the same filesystem, flock serialization, post-restart
#   verification of the bridge with automatic rollback on failure.
DIR=/etc/stgws
DOMAINS=$DIR/tgws-domains.lst
ROUTE=$DIR/route.conf
LOCK=/var/lock/tgws-route-smart.lock

exec 9>"$LOCK" 2>/dev/null || { echo '{"error":"no lock file"}'; exit 1; }
flock -n 9 || { echo '{"error":"route-smart уже выполняется"}'; exit 1; }

WORK=$(mktemp -d /tmp/routesmart-XXXXXX) || exit 1
trap 'rm -rf "$WORK"' 0

# --- 1. Resolve kws1.<domain> -> all A-records via dns.google -----------------
: > "$WORK/ipmap"     # "domain ip" per line
: > "$WORK/dnsfail"
for D in $(cat "$DOMAINS"); do
  IPS=$(curl -s -m 6 "https://dns.google/resolve?name=kws1.$D&type=A" | jsonfilter -e '@.Answer[@.type=1].data' 2>/dev/null)
  if [ -z "$IPS" ]; then
    echo "$D" >> "$WORK/dnsfail"
    continue
  fi
  for IP in $IPS; do
    case "$IP" in ''|*[!0-9.]*) continue ;; esac
    echo "$D $IP" >> "$WORK/ipmap"
  done
done
[ -s "$WORK/ipmap" ] || { echo '{"error":"не удалось резолвить kws-поддомены"}'; exit 1; }

# --- 2. Measure each unique IP: 3 handshakes, HTTP < 400 every time -----------
: > "$WORK/badips"
for IP in $(awk '{print $2}' "$WORK/ipmap" | sort -u); do
  OK=1
  i=1
  while [ "$i" -le 3 ]; do
    CODE=$(curl -s -o /dev/null --connect-timeout 5 -m 8 -w '%{http_code}' \
      --resolve "www.cloudflare.com:443:$IP" https://www.cloudflare.com/ 2>/dev/null)
    case "$CODE" in
      2*|3*) ;;
      *) OK=0; break ;;
    esac
    i=$((i+1))
  done
  [ "$OK" = 0 ] && echo "$IP" >> "$WORK/badips"
done

# --- 3. Healthy domains; quorum by unique healthy IPs --------------------------
if [ -s "$WORK/badips" ]; then
  awk 'NR==FNR {bad[$1]=1; next} !($2 in bad) {print $1}' "$WORK/badips" "$WORK/ipmap" | sort -u > "$WORK/healthy"
  HIP_N=$(awk 'NR==FNR {bad[$1]=1; next} !($2 in bad) {print $2}' "$WORK/badips" "$WORK/ipmap" | sort -u | wc -l | tr -d ' ')
else
  awk '{print $1}' "$WORK/ipmap" | sort -u > "$WORK/healthy"
  HIP_N=$(awk '{print $2}' "$WORK/ipmap" | sort -u | wc -l | tr -d ' ')
fi
HEALTHY_N=$(wc -l < "$WORK/healthy" | tr -d ' ')
if [ "$HIP_N" -lt 3 ]; then
  printf '{"error":"здоровых диапазонов мало (%s уникальных IP) — карту не трогаю","healthy_ips":%s}\n' "$HIP_N" "$HIP_N"
  exit 1
fi

# --- 4. New map: keep direct/non-ws verbatim; reassign only unhealthy ws ------
awk '!/^#/ && NF >= 2 {print}' "$ROUTE" > "$WORK/oldentries"
: > "$WORK/new"
USED=" "
while read -r DC MODE DOMAIN REST; do
  [ -n "$DC" ] || continue
  if [ "$MODE" != "ws" ] || [ -z "$DOMAIN" ]; then
    # direct entries, media keys, unknown formats — keep byte-identical
    echo "$DC $MODE $DOMAIN $REST" | sed 's/ *$//' >> "$WORK/new"
    continue
  fi
  PICK=""
  if grep -qx "$DOMAIN" "$WORK/healthy"; then
    PICK=$DOMAIN
  else
    while read -r H; do
      case "$USED" in *" $H "*) continue ;; esac
      PICK=$H
      break
    done < "$WORK/healthy"
    [ -n "$PICK" ] || PICK=$(head -1 "$WORK/healthy")
  fi
  USED="$USED$PICK "
  echo "$DC ws $PICK" >> "$WORK/new"
done < "$WORK/oldentries"

# --- 5. Normalized compare: tuples only, no comments/date ---------------------
NORM() { awk '{print $1, $2, $3}' "$1" | sort; }
CHANGED=0
NORM "$WORK/oldentries" > "$WORK/old.norm"
NORM "$WORK/new" > "$WORK/new.norm"
cmp -s "$WORK/old.norm" "$WORK/new.norm" || CHANGED=1

APPLIED=0
if [ "$CHANGED" = 1 ]; then
  # --- 6. Validate, then atomic write in the same FS --------------------------
  # Every DC key from the old map must be present exactly once in the new map.
  VALID=1
  for DC in $(awk '{print $1}' "$WORK/oldentries" | sort -u); do
    [ "$(awk -v d="$DC" '$1==d' "$WORK/new" | wc -l)" = 1 ] || { VALID=0; break; }
  done
  [ -s "$WORK/new" ] || VALID=0
  if [ "$VALID" != 1 ]; then
    echo '{"error":"новая карта неполная — старая сохранена"}'
    exit 1
  fi
  {
    echo '# Карта «дата-центр → путь». Пишет её подбор, читает мост.'
    echo '# Править руками можно, но следующий `tgws pick` перепишет файл целиком.'
    echo "# $(date '+%Y-%m-%d %H:%M') route-smart: домены на нестабильных CF-диапазонах заменены."
    cat "$WORK/new"
  } > "$DIR/.route.conf.new"
  cp -p "$ROUTE" "$ROUTE.auto-bak"
  mv -f "$DIR/.route.conf.new" "$ROUTE"

  # --- 7. Restart and verify the bridge; rollback on failure ------------------
  /etc/init.d/tgws restart >/dev/null 2>&1
  OK=0
  i=0
  while [ "$i" -lt 8 ]; do
    if pgrep -f 'stgws tgws' >/dev/null 2>&1 && \
       stgws tgws-instances --spec "$DIR/spec.json" --state-dir /var/lib/stgws 2>/dev/null | grep -q .; then
      OK=1
      break
    fi
    sleep 1
    i=$((i+1))
  done
  if [ "$OK" != 1 ]; then
    cp -p "$ROUTE.auto-bak" "$ROUTE"
    /etc/init.d/tgws restart >/dev/null 2>&1
    echo '{"error":"мост не поднялся после смены карты — выполнен откат"}'
    exit 1
  fi
  APPLIED=1
fi

MAP=$(awk '$2=="ws" {printf "%s->%s ", $1, $3} $2!="ws" {printf "%s->%s ", $1, $2}' "$WORK/new" | sed 's/ $//')
FLAKY_N=$(wc -l < "$WORK/badips" | tr -d ' ')
DNSFAIL_N=$(wc -l < "$WORK/dnsfail" | tr -d ' ')
printf '{"ok":true,"changed":%s,"applied":%s,"healthy":%s,"healthy_ips":%s,"flaky_ips":%s,"dns_failed":%s,"map":"%s"}\n' \
  "$CHANGED" "$APPLIED" "$HEALTHY_N" "$HIP_N" "$FLAKY_N" "$DNSFAIL_N" "$MAP"
