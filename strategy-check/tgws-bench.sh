#!/bin/ash
# Latency benchmark for tg-ws domains: TLS handshake time, best of 2.
for D in $(cat /etc/stgws/tgws-domains.lst) web.telegram.org; do
  T1=$(curl -s -o /dev/null -w '%{time_appconnect}' --connect-timeout 5 -m 8 "https://$D/" 2>/dev/null)
  T2=$(curl -s -o /dev/null -w '%{time_appconnect}' --connect-timeout 5 -m 8 "https://$D/" 2>/dev/null)
  BEST=$(awk -v a="$T1" -v b="$T2" 'BEGIN{if(a==0||a=="")a=99; if(b==0||b=="")b=99; print (a<b)?a:b}')
  echo "$BEST $D"
done | sort -n
