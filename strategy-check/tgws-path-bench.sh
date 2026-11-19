#!/bin/ash
# Real WS-path latency: TLS handshake + TTFB to the actual apiws endpoints.
for U in \
  https://web.telegram.org/apiws \
  https://kws1.onedaychamp.co.uk/apiws \
  https://kws1.offshor.co.uk/apiws \
  https://kws1.pyatdesyatodin.co.uk/apiws \
  https://kws1.stopblocking.co.uk/apiws \
  https://kws1.lovetrue.co.uk/apiws ; do
  R=$(curl -s -o /dev/null -w '%{time_appconnect} %{time_starttransfer} %{http_code}' --connect-timeout 5 -m 10 "$U" 2>/dev/null)
  echo "$R  $U"
done
echo '--- CPU of stgws:'
top -b -n1 | grep -E 'stgws|CPU:' | head -4
