#!/bin/ash
# Map each tgws front domain to its kws1 IP range via dns.google.
for D in $(cat /etc/stgws/tgws-domains.lst); do
  IP=$(curl -s -m 6 "https://dns.google/resolve?name=kws1.$D&type=A" | grep -o '"data":"[0-9.]*"' | head -1 | cut -d'"' -f4)
  echo "$IP $D"
done | sort
