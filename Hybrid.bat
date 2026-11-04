@echo off
chcp 65001 > nul
:: New2.bat v2 - порт Hybrid_v2 (zapret1) на winws2 / zapret2
:: Discord-профили: seqovl-перекрытие + fake sni=ozon.ru + badseq (приёмы Hybrid).
:: Провайдеры: Ростелеком, ЕСК, МГТС. Windows 10/11.
:: Требования: bin\winws2.exe, lua\zapret-lib.lua, lua\zapret-antidpi.lua
:: Запуск от администратора. Перед запуском остановить zapret1 (sc stop zapret).

cd /d "%~dp0"

set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
set "LUA=%~dp0lua\"

start "zapret2: %~n0" /min "%BIN%winws2.exe" ^
--wf-tcp-out=80,443,2053,2083,2087,2096,8443 --wf-udp-out=443,1024-65535 ^
--lua-init=@"%LUA%zapret-lib.lua" --lua-init=@"%LUA%zapret-antidpi.lua" ^
--lua-init="fake_default_tls = tls_mod(fake_default_tls,'rnd,rndsni')" ^
--blob=tls_google:@"%BIN%tls_clienthello_www_google_com.bin" ^
--blob=tls_max:@"%BIN%tls_clienthello_max_ru.bin" ^
--blob=quic_google:@"%BIN%quic_initial_www_google_com.bin" ^
--blob=quic_vk:@"%BIN%quic_initial_vk_com.bin" ^
--blob=quic_ru:@"%BIN%quic_initial_dbankcloud_ru.bin" ^
--lua-init="tls_ozon = tls_mod(tls_google,'sni=ozon.ru')" ^
--lua-init="tls_max_ozon = tls_mod(tls_max,'sni=ozon.ru')" ^
--lua-init="tls_def_ozon = tls_mod(fake_default_tls,'sni=ozon.ru')" ^
--filter-udp=443 --filter-l7=quic --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" ^
  --payload=quic_initial ^
  --lua-desync=fake:blob=quic_google:repeats=6 ^
--new ^
--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun ^
  --payload=all ^
  --lua-desync=fake:blob=quic_vk:repeats=6:payload=all ^
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist-domains=updates.discord.com ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8 ^
  --lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_ozon ^
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist-domains=media.discordapp.net,images-ext-1.discordapp.net,images-ext-2.discordapp.net ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_max_ozon:tcp_ts=-600000:repeats=8 ^
  --lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000 ^
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist-domains=cdn.discordapp.com,stable.dl2.discordapp.net ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8 ^
  --lua-desync=multidisorder:pos=1,midsld:seqovl=652:seqovl_pattern=tls_ozon ^
--new ^
--filter-tcp=443,2053,2083,2087,2096,8443 --filter-l7=tls --hostlist-domains=discord.com,discord.gg,gateway.discord.gg,discordapp.com,discordapp.net,discordcdn.com,discord.media,discordstatus.com ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_def_ozon:tcp_seq=-10000:tcp_ack=-66000:repeats=8 ^
  --lua-desync=multidisorder:pos=1,sniext+1,midsld ^
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist="%LISTS%list-google.txt" ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6:ip_id=zero ^
  --lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:ip_id=zero ^
--new ^
--filter-tcp=443 --filter-l7=tls --hostlist="%LISTS%list-github.txt" ^
  --payload=tls_client_hello --out-range=-d10 ^
  --lua-desync=fake:blob=tls_google:tcp_ts=-600000:repeats=6:ip_id=zero ^
  --lua-desync=fakedsplit:pattern=0x00:tcp_ts=-600000:ip_id=zero ^
--new ^
--filter-tcp=80,443 --filter-l7=http,tls --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" ^
  --payload=tls_client_hello,http_req --out-range=-d10 ^
  --lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-600000:tcp_md5:repeats=4 ^
--new ^
--filter-udp=443 --filter-l7=quic --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" ^
  --payload=quic_initial ^
  --lua-desync=fake:blob=quic_google:repeats=6 ^
--new ^
--filter-tcp=80,443,8443 --filter-l7=http,tls --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" ^
  --payload=tls_client_hello,http_req --out-range=-d10 ^
  --lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-600000:repeats=4 ^
--new ^
--filter-udp=7711,12000 ^
  --payload=all ^
  --lua-desync=fake:blob=quic_ru:repeats=1:ip_autottl=6,1-20:payload=all ^
--new ^
--filter-udp=1024-3477,3481-19293,19345-49999,50101-65535 ^
  --payload=all --out-range=-n2 ^
  --lua-desync=fake:blob=quic_ru:repeats=8:ip_autottl=6,1-20:payload=all
