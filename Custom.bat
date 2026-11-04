@echo off
chcp 65001 > nul
:: Custom.bat - built by service.ps1 from profiles: 10_quic_general.conf, 20_discord_voice_udp.conf, 30_discord_updates.conf, 40_discord_media_images.conf, 50_discord_cdn.conf, 60_discord_main.conf, 70_google.conf, 71_github.conf, 81_ipset_quic.conf, 82_ipset_tcp.conf, 90_game_udp.conf, 91_udp_catchall.conf, 97_fs_fta_multidisorder.conf
cd /d "%~dp0"
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
set "LUA=%~dp0lua\"

start "zapret2: custom" /min "%BIN%winws2.exe" ^
--wf-tcp-out=80,443,2053,2083,2087,2096,8443 --wf-udp-out=443,1024-65535 ^
--lua-init=@"%LUA%zapret-lib.lua" --lua-init=@"%LUA%zapret-antidpi.lua" ^
--lua-init="fake_default_tls=tls_mod(fake_default_tls,'rnd,rndsni')" ^
--blob=tls_google:@"%BIN%tls_clienthello_www_google_com.bin" ^
--blob=tls_max:@"%BIN%tls_clienthello_max_ru.bin" ^
--blob=tls_4pda:@"%BIN%tls_clienthello_4pda_to.bin" ^
--blob=tls_sferum:@"%BIN%tls_clienthello_www_sferum_ru.bin" ^
--blob=tls_sochi:@"%BIN%tls_clienthello_sochi_park.bin" ^
--blob=stun:@"%BIN%stun.bin" ^
--blob=stun2:@"%BIN%stun2.bin" ^
--blob=quic_google:@"%BIN%quic_initial_www_google_com.bin" ^
--blob=quic_vk:@"%BIN%quic_initial_vk_com.bin" ^
--blob=quic_ru:@"%BIN%quic_initial_dbankcloud_ru.bin" ^
--lua-init="tls_ozon=tls_mod(tls_google,'sni=ozon.ru')" ^
--lua-init="tls_max_ozon=tls_mod(tls_max,'sni=ozon.ru')" ^
--lua-init="tls_def_ozon=tls_mod(fake_default_tls,'sni=ozon.ru')" ^
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
--lua-desync=fake:blob=quic_ru:repeats=8:ip_autottl=6,1-20:payload=all ^
--new ^
--filter-tcp=80,443 --filter-l7=http,tls --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" ^
--payload=tls_client_hello,http_req --out-range=-d10 ^
--lua-desync=fake:blob=0x00000000:tcp_seq=-10000:tcp_ack=-66000:repeats=11:payload=tls_client_hello ^
--lua-desync=fake:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:tcp_seq=-10000:tcp_ack=-66000:repeats=11:payload=tls_client_hello ^
--lua-desync=fake:blob=tls_sferum:tcp_seq=-10000:tcp_ack=-66000:repeats=11:payload=http_req ^
--lua-desync=multidisorder:pos=1,midsld
