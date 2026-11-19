import paramiko, sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.1.1', username='root', password='0130_1117_0411', timeout=20)

def run(cmd, timeout=60):
    i, o, e = c.exec_command(cmd, timeout=timeout)
    return o.read().decode(), e.read().decode()

def download(path):
    i, o, e = c.exec_command('cat "%s"' % path, timeout=60)
    return o.read().decode('utf-8', 'replace')

def upload(path, content):
    i, o, e = c.exec_command('cat > "%s"' % path, timeout=120)
    i.write(content.encode('utf-8'))
    i.channel.shutdown_write()
    return o.read().decode(), e.read().decode()

TS = '20261118-routesmart'

# ---------- 1. mod/tg.sh ----------
p = '/opt/zapret-manager-luci/mod/tg.sh'
src = download(p)
run('cp -p %s %s.bak-%s' % (p, p, TS))

old_action = """tgws_action() {
	local action="$1"
	case "$action" in
		install|update) job_start tgws_install do_tgws_install ;;
		reinstall)      job_start tgws_install _zm_reinstall do_tgws_remove do_tgws_install ;;
		remove)         _tg_auto_drop tgws; job_start tgws_remove do_tgws_remove ;;
		restart)        job_start tgws_restart do_tgws_restart ;;
		reconfigure)    job_start tgws_reconfigure do_tgws_reconfigure ;;
		*) echo '{"error":"неизвестное действие"}' ;;
	esac
}"""
new_action = """do_route_smart() {
	[ -x /etc/stgws/route-smart.sh ] || { echo "ОШИБКА: нет /etc/stgws/route-smart.sh"; return 1; }
	ash /etc/stgws/route-smart.sh || return 1
	echo "==> Карта перестроена по стабильным диапазонам"
}

do_route_save() {
	[ -s /etc/stgws/route.conf ] || { echo '{"error":"карта пуста"}'; return 1; }
	cp -p /etc/stgws/route.conf /etc/stgws/route.conf.custom || { echo '{"error":"не удалось сохранить карту"}'; return 1; }
	echo '{"ok":true}'
}

do_route_restore() {
	[ -s /etc/stgws/route.conf.custom ] || { echo '{"error":"нет сохранённой карты"}'; return 1; }
	cp -p /etc/stgws/route.conf.custom /etc/stgws/route.conf || { echo '{"error":"не удалось восстановить карту"}'; return 1; }
	/etc/init.d/tgws restart >/dev/null 2>&1
	echo '{"ok":true}'
}

tgws_action() {
	local action="$1"
	case "$action" in
		install|update) job_start tgws_install do_tgws_install ;;
		reinstall)      job_start tgws_install _zm_reinstall do_tgws_remove do_tgws_install ;;
		remove)         _tg_auto_drop tgws; job_start tgws_remove do_tgws_remove ;;
		restart)        job_start tgws_restart do_tgws_restart ;;
		reconfigure)    job_start tgws_reconfigure do_tgws_reconfigure ;;
		route_smart)    job_start tgws_route_smart do_route_smart ;;
		route_save)     do_route_save ;;
		route_restore)  do_route_restore ;;
		route_auto_on)  : > /etc/stgws/smart-map; echo '{"ok":true}' ;;
		route_auto_off) rm -f /etc/stgws/smart-map; echo '{"ok":true}' ;;
		*) echo '{"error":"неизвестное действие"}' ;;
	esac
}"""
assert old_action in src, 'tgws_action block not found'
src = src.replace(old_action, new_action)

old_rec = """	domain=$(_tgws_domain)
	echo "==> Новый домен: $domain"
	echo "==> Готово, домен перенастроен"
}"""
new_rec = """	domain=$(_tgws_domain)
	echo "==> Новый домен: $domain"
	if [ -f /etc/stgws/smart-map ] && [ -x /etc/stgws/route-smart.sh ]; then
		echo "==> Умная карта: перестраиваю по стабильным диапазонам"
		ash /etc/stgws/route-smart.sh || echo "ОШИБКА: умная карта не применилась — оставлена карта подбора"
	fi
	echo "==> Готово, домен перенастроен"
}"""
assert old_rec in src, 'do_tgws_reconfigure tail not found'
src = src.replace(old_rec, new_rec)
upload(p, src)
print('tg.sh patched')

# ---------- 2. backend.sh tgws_status ----------
p = '/opt/zapret-manager-luci/backend.sh'
src = download(p)
run('cp -p %s %s.bak-%s' % (p, p, TS))

old_st = """	printf '{"installed":"%s","running":%s,"version":"%s","latest":"%s","newer":%s,"domain":"%s"}\\n' "$installed" "$running" "$(esc "$ver")" "$(esc "$latest")" "$(_tg_newer "$ver" "$latest" && echo true || echo false)" "$(esc "$domain")"
}"""
new_st = """	local saved=false smart=false
	[ -s /etc/stgws/route.conf.custom ] && saved=true
	[ -f /etc/stgws/smart-map ] && smart=true
	printf '{"installed":"%s","running":%s,"version":"%s","latest":"%s","newer":%s,"domain":"%s","route_saved":%s,"smart_auto":%s}\\n' "$installed" "$running" "$(esc "$ver")" "$(esc "$latest")" "$(_tg_newer "$ver" "$latest" && echo true || echo false)" "$(esc "$domain")" "$saved" "$smart"
}"""
assert old_st in src, 'tgws_status printf not found'
src = src.replace(old_st, new_st)
upload(p, src)
print('backend.sh patched')

# ---------- 3. route-smart.sh ----------
data = open('strategy-check/route-smart.sh', 'rb').read().replace(b'\r\n', b'\n')
i, o, e = c.exec_command('cat > /etc/stgws/route-smart.sh && chmod 755 /etc/stgws/route-smart.sh && ash -n /etc/stgws/route-smart.sh && echo ROUTESMART_OK', timeout=60)
i.write(data); i.channel.shutdown_write()
print(o.read().decode(), e.read().decode())

# ---------- 4. tgproxy.js ----------
p = '/www/luci-static/resources/view/zapret-manager/tgproxy.js'
src = download(p)
run('cp -p %s %s.bak-%s' % (p, p, TS))

old_btn = """				actions.push(E('button', {
					'class': 'cbi-button',
					'click': function() { doTgwsAction('reconfigure'); }
				}, 'Подобрать новый домен'));"""
new_btn = old_btn + """
				actions.push(E('button', {
					'class': 'cbi-button',
					'title': 'Перестроить карту дата-центров по стабильным диапазонам Cloudflare',
					'click': function() { doTgwsAction('route_smart'); }
				}, 'Умная карта'));
				actions.push(E('button', {
					'class': 'cbi-button',
					'title': 'Сохранить текущую карту как эталон',
					'click': function() { doTgwsAction('route_save'); }
				}, 'Сохранить карту'));
				if (d.route_saved) {
					actions.push(E('button', {
						'class': 'cbi-button',
						'title': 'Вернуть сохранённую карту и перезапустить',
						'click': function() { doTgwsAction('route_restore'); }
					}, 'Восстановить карту'));
				}
				actions.push(E('button', {
					'class': 'cbi-button' + (d.smart_auto ? ' cbi-button-positive' : ''),
					'title': 'После подбора домена автоматически перестраивать карту по стабильным диапазонам',
					'click': function() { doTgwsAction(d.smart_auto ? 'route_auto_off' : 'route_auto_on'); }
				}, d.smart_auto ? 'Авто-карта: вкл' : 'Авто-карта: выкл'));"""
assert old_btn in src, 'reconfigure button not found'
src = src.replace(old_btn, new_btn)

old_map = """			var job = action === 'remove' ? 'tgws_remove'
				: action === 'restart' ? 'tgws_restart'
				: action === 'reconfigure' ? 'tgws_reconfigure' : 'tgws_install';
			var label = action === 'remove' ? 'Удаляем sTGWS'
				: action === 'restart' ? 'Перезапускаем sTGWS'
				: action === 'reconfigure' ? 'Подбираем новый домен sTGWS'
				: action === 'reinstall' ? 'Переустанавливаем sTGWS'
				: action === 'update' ? 'Обновляем sTGWS' : 'Устанавливаем sTGWS';"""
new_map = """			var job = action === 'remove' ? 'tgws_remove'
				: action === 'restart' ? 'tgws_restart'
				: action === 'route_smart' ? 'tgws_route_smart'
				: action === 'reconfigure' ? 'tgws_reconfigure' : 'tgws_install';
			var label = action === 'remove' ? 'Удаляем sTGWS'
				: action === 'restart' ? 'Перезапускаем sTGWS'
				: action === 'route_smart' ? 'Перестраиваем карту sTGWS'
				: action === 'reconfigure' ? 'Подбираем новый домен sTGWS'
				: action === 'reinstall' ? 'Переустанавливаем sTGWS'
				: action === 'update' ? 'Обновляем sTGWS' : 'Устанавливаем sTGWS';"""
assert old_map in src, 'job map not found'
src = src.replace(old_map, new_map)

old_else = """				} else {
					tgwsBusy = false;
				}
			}).catch(function() { tgwsBusy = false; });"""
new_else = """				} else {
					tgwsBusy = false;
					if (res.ok) {
						zm.toast('Готово', 'info');
						zm.tgwsStatus().then(function(d) { tgwsData = d; renderTgws(d); });
					}
				}
			}).catch(function() { tgwsBusy = false; });"""
assert old_else in src, 'else branch not found'
src = src.replace(old_else, new_else)
upload(p, src)
print('tgproxy.js patched')

c.close()
print('ALL_PATCHED')
