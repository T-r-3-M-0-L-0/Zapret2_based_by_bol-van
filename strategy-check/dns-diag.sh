#!/bin/ash
echo '--- logread https-dns-proxy:'
logread -e https-dns-proxy 2>/dev/null | tail -8
echo '--- DoH endpoints:'
curl -s -o /dev/null -w 'cloudflare-dns.com: %{http_code} %{time_total}s\n' -m 10 \
  'https://cloudflare-dns.com/dns-query?name=google.com&type=A' -H 'accept: application/dns-json'
curl -s -o /dev/null -w 'mozilla.cloudflare-dns.com: %{http_code} %{time_total}s\n' -m 10 \
  'https://mozilla.cloudflare-dns.com/dns-query?name=google.com&type=A' -H 'accept: application/dns-json'
curl -s -o /dev/null -w 'dns.google: %{http_code} %{time_total}s\n' -m 10 \
  'https://dns.google/resolve?name=google.com&type=A'
curl -s -o /dev/null -w 'dns.quad9: %{http_code} %{time_total}s\n' -m 10 \
  'https://dns.quad9.net:5053/dns-query?name=google.com&type=A' -H 'accept: application/dns-json'
echo '--- https-dns-proxy config:'
uci -q show https-dns-proxy | head -20
