@echo off
cd /d C:\fZapret2
bin\winws2.exe --debug=1 --wf-tcp-out=853 --wf-udp-out=853 --lua-init=@"C:\fZapret2\lua\zapret-lib.lua" --lua-init=@"C:\fZapret2\lua\zapret-antidpi.lua" --lua-init=@"C:\fZapret2\lua\zapret-testlib.lua" --filter-tcp=853 --filter-l7=tls --payload=tls_client_hello --lua-desync=myinfo --lua-desync=myfake:blob=fake_default_tls:pad=32:ip_ttl=3:repeats=2 --lua-desync=mysplit:pos=midsld > C:\fZapret2\logs\testlib_debug.txt 2>&1
