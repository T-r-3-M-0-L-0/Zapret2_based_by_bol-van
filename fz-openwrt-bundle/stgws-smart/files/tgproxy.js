'use strict';
'require view';
'require zapret-manager.common as zm';
var E = (function(raw) { return function() { var a = Array.prototype.slice.call(arguments), i = a.length - 1; if (i >= 1 && (typeof a[i] === 'string' || typeof a[i] === 'number')) a[i] = [ String(a[i]) ]; return raw.apply(null, a); }; })(window.E);

var VARIANTS = [
	{ id: 'mtproto', title: 'Go (MTProto)', port: 1443, kind: 'proto' },
	{ id: 'socks5', title: 'SOCKS5', port: 2080, kind: 'socks' },
	{ id: 'rust', title: 'Rust (MTProto)', port: 2443, kind: 'proto' }
];

var AUTO_OPTS = [
	[ 'off', 'Выкл' ], [ 'h1', '1 ч' ], [ 'h2', '2 ч' ], [ 'h3', '3 ч' ], [ 'h6', '6 ч' ], [ 'h12', '12 ч' ]
];

var TG_SITES = [ 'www.google.com', 'ya.ru', 'vk.com', 'www.microsoft.com', 'www.apple.com', 'www.cloudflare.com' ];
var TG_DOM_RE = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$/;
var TG_IP_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function tgHex(s) {
	var out = '', i;
	for (i = 0; i < s.length; i++) out += ('0' + s.charCodeAt(i).toString(16)).slice(-2);
	return out;
}

function tgCore(k) {
	k = String(k || '');
	return k.length >= 34 && /^(dd|ee)/.test(k) ? k.slice(2, 34) : k;
}

function linkBlock(link, label) {
	var qrLink = link.replace(/^tg:\/\//, 'https://t.me/');
	var qrBox = E('div', { 'class': 'zm-tg-qr-box', 'style': 'display:none' });
	var shown = false;
	return E('div', { 'class': 'zm-tg-link-item' }, [
		label ? E('div', { 'class': 'zm-tg-link-label' }, label) : E([]),
		E('div', { 'class': 'zm-tg-link-row' }, [
			E('div', { 'class': 'zm-tg-link-box' }, [ zm.secret(link) ]),
			E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() { copyToClipboard(link); } }, 'Скопировать'),
			E('button', { 'class': 'cbi-button zm-tg-qr-btn', 'title': 'Показать QR-код', 'aria-expanded': 'false', 'click': function(ev) {
				shown = !shown;
				qrBox.style.display = shown ? '' : 'none';
				ev.currentTarget.setAttribute('aria-expanded', shown ? 'true' : 'false');
				if (shown && !qrBox.firstChild) {
					var svg = zm.qrSvg(qrLink);
					if (svg) {
						var pic = E('div', { 'class': 'zm-tg-qr-pic' });
						pic.innerHTML = svg;
						qrBox.appendChild(pic);
						qrBox.appendChild(E('div', { 'class': 'zm-hint' }, 'Наведите камеру телефона — Telegram предложит подключить прокси'));
					} else qrBox.appendChild(E('div', { 'class': 'zm-hint' }, 'Ссылка слишком длинная для QR-кода — скопируйте её'));
				}
			} }, 'QR-код')
		]),
		qrBox
	]);
}

function copyToClipboard(text) {
	if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
		navigator.clipboard.writeText(text).then(function() {
			zm.toast('Ссылка скопирована', 'info');
		}).catch(function() {
			fallbackCopy(text);
		});
	} else {
		fallbackCopy(text);
	}
}

function fallbackCopy(text) {
	var ta = document.createElement('textarea');
	ta.value = text;
	ta.setAttribute('readonly', '');
	ta.style.position = 'fixed';
	ta.style.top = '0';
	ta.style.left = '0';
	ta.style.opacity = '0';
	document.body.appendChild(ta);
	ta.focus();
	ta.select();
	ta.setSelectionRange(0, text.length);
	var ok = false;
	try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
	document.body.removeChild(ta);
	zm.toast(ok ? 'Ссылка скопирована' : 'Не удалось скопировать — выделите ссылку вручную', ok ? 'info' : 'warning');
}

return view.extend({
	load: function() {
		zm.injectCss();
		return Promise.all([ zm.tgStatus(), zm.tgwsStatus().catch(function() { return {}; }) ]);
	},

	render: function(all) {
		var data = all[0];
		var tgwsData = all[1] || {};
		var wrap = E('div', { 'class': 'zm-wrap' });
		var cards = E('div', { 'class': 'zm-tg-board' });
		var linksWrap = E('div', {});
		var logEl = E('pre', { 'class': 'zm-log' });

		function statusOf(d, id) {
			if (id === 'mtproto') return { installed: d.mtproto === 'installed', running: d.mtproto_running === true, secret: d.link_mtproto || (d.secret_mtproto ? 'dd' + d.secret_mtproto : ''), version: d.mtproto_version, latest: d.mtproto_latest, newer: d.mtproto_newer === true,
				port: d.mtproto_port, host: d.mtproto_host, key: d.secret_mtproto || '', edit: true, ext: (d.ext || {}).mtproto || null };
			if (id === 'socks5') return { installed: d.socks5 === 'installed', running: d.socks5_running === true, secret: '', version: d.socks5_version, latest: d.socks5_latest, newer: d.socks5_newer === true,
				port: d.socks5_port, edit: true, args: d.socks5_args || '', argsDef: (d.args_def || {}).socks5 || '' };
			return { installed: d.rust === 'installed', running: d.rust_running === true, secret: d.secret_rust, version: d.rust_version, latest: d.rust_latest, newer: d.rust_newer === true,
				uci: d.rust_uci === true, enabled: d.rust_enabled !== false, port: d.rust_port, host: d.rust_host, key: d.rust_key || '', edit: d.rust_uci !== true, ext: (d.ext || {}).rust || null, args: d.rust_args || '', argsDef: (d.args_def || {}).rust || '', socks: d.rust_socks || null };
		}

		var editOpen = {}, editDraft = {}, portSeq = 0;
		function genKey() {
			var b = new Uint8Array(16), i, out = '';
			try { (window.crypto || window.msCrypto).getRandomValues(b); } catch (e) { for (i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256); }
			for (i = 0; i < 16; i++) out += ('0' + b[i].toString(16)).slice(-2);
			return out;
		}
		function hexHost(h) {
			var out = '', i;
			for (i = 0; i + 1 < h.length; i += 2) out += String.fromCharCode(parseInt(h.substr(i, 2), 16));
			return out;
		}
		function keyCheck(v, s) {
			s = String(s || '').replace(/\s+/g, '').toLowerCase();
			if (!s) return { ok: false, text: 'Введите ключ или нажмите «Новый ключ»' };
			if (/[^0-9a-f]/.test(s)) return { ok: false, text: 'Только цифры 0–9 и буквы a–f' };
			var ex = statusOf(data, v.id).ext;
			if (s.slice(0, 2) === 'ee' && s.length > 34) {
				var h = s.length % 2 === 0 ? hexHost(s.slice(34)).toLowerCase() : '';
				if (!TG_DOM_RE.test(h) || TG_IP_RE.test(h)) return { ok: false, text: 'После ee и 32 знаков должно идти имя сайта в hex' };
				if (ex && !ex.ftls) return { ok: false, text: 'Ключ ee… — это FakeTLS, а эта версия ' + v.title + ' его не умеет. Обновите прокси или введите ключ из 32 знаков' };
				return { ok: true, key: s, text: 'Ключ ee… — ' + (ex && ex.tls ? 'FakeTLS' : 'включится FakeTLS') + ', сайт для маскировки: ' + h };
			}
			var tlsNow = ex && ex.tls ? ' (сейчас FakeTLS — в ссылке будет ee…)' : '';
			if (v.id === 'mtproto') {
				if (s.length === 34 && s.slice(0, 2) === 'dd') s = s.slice(2);
				return s.length === 32 ? { ok: true, key: s, text: '32 знака — подходит' + tlsNow } : { ok: false, text: 'Нужно ровно 32 знака, сейчас ' + s.length };
			}
			if (s.length === 32) return { ok: true, key: s, text: '32 знака — подходит' + (tlsNow || ', в ссылке будет dd…') };
			if (s.length === 34 && s.slice(0, 2) === 'dd') return { ok: true, key: s, text: 'Ключ dd… — подходит' + tlsNow };
			return { ok: false, text: 'Нужно 32 знака (или dd + 32, или ee + 32 + сайт в hex), сейчас ' + s.length };
		}
		function portCheck(v, st, p) {
			p = String(p || '').trim();
			if (!/^\d{1,5}$/.test(p) || +p < 1 || +p > 65535) return { ok: false, text: 'Число от 1 до 65535' };
			if (+p < 1024) return { ok: true, warn: true, text: 'Порт ниже 1024 часто занят службами роутера — проверим' };
			return { ok: true, text: String(+p) === String(st.port) ? 'Текущий порт' : '' };
		}
		function chip(cls, text) { return E('span', { 'class': 'zm-tg-chip ' + cls }, text); }
		function hasArgs(v, st) { return (v.id === 'socks5' || v.id === 'rust') && !st.uci; }
		function argsNorm(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }
		function argsCheck(s) {
			var a = argsNorm(s), toks = a ? a.split(' ') : [], i, t;
			if (a.length > 512) return { ok: false, text: 'Слишком длинно — не больше 512 знаков', args: a };
			for (i = 0; i < toks.length; i++) {
				t = toks[i];
				if (!/^[A-Za-z0-9._:\/,=@+%-]+$/.test(t)) return { ok: false, text: '«' + t + '» — недопустимые символы', args: a };
				if (/^--?(host|port|secret|listen-faketls-domain)(=|$)/.test(t)) return { ok: false, text: t.split('=')[0] + ' задаётся выше — уберите его', args: a };
			}
			var n = toks.length;
			return { ok: true, args: a, text: n ? n + ' ' + (n % 10 === 1 && n % 100 !== 11 ? 'параметр' : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14) ? 'параметра' : 'параметров') : 'без параметров' };
		}
		function editPanel(v, st) {
			var dr = editDraft[v.id] || (editDraft[v.id] = { port: String(st.port || v.port), key: st.key || '', args: st.args || '', busy: false, net: null });
			var withArgs = hasArgs(v, st);
			var argsIn = withArgs ? E('input', { 'type': 'text', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-args-in', 'value': dr.args, 'spellcheck': 'false', 'autocapitalize': 'off', 'autocomplete': 'off', 'aria-label': 'Параметры после порта' }) : null;
			var argsPre = E('span', { 'class': 'zm-tg-args-pre' }), argsMsg = E('div', { 'class': 'zm-tg-edit-msg' });
			var portIn = E('input', { 'type': 'text', 'inputmode': 'numeric', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-edit-port', 'value': dr.port, 'maxlength': '5', 'aria-label': 'Порт' });
			var keyIn = v.kind === 'proto' ? E('input', { 'type': 'text', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-edit-key', 'value': dr.key, 'spellcheck': 'false', 'autocapitalize': 'off', 'autocomplete': 'off', 'aria-label': 'Ключ' }) : null;
			if (keyIn) zm.secretIn(keyIn);
			var portMsg = E('div', { 'class': 'zm-tg-edit-msg' }), keyMsg = E('div', { 'class': 'zm-tg-edit-msg' });
			var preview = E('div', { 'class': 'zm-tg-link-box zm-tg-edit-preview' });
			var saveBtn = E('button', { 'class': 'cbi-button cbi-button-positive' }, 'Сохранить и перезапустить');
			var host = st.host || data.lan_ip || '192.168.1.1';
			var netT = null;
			function linkFor(k) {
				var p = String(+dr.port || dr.port);
				if (v.kind === 'socks') return 'tg://socks?server=' + host + '&port=' + p;
				if (!k) return '';
				var sec = 'dd' + k;
				if (k.length >= 34 && /^(dd|ee)/.test(k)) sec = k;
				else if (st.secret && st.secret.length > 34 && st.secret.slice(0, 2) === 'ee') sec = 'ee' + k + st.secret.slice(34);
				return 'tg://proxy?server=' + host + '&port=' + p + '&secret=' + sec;
			}
			function paint() {
				var pc = portCheck(v, st, dr.port), kc = keyIn ? keyCheck(v, dr.key) : { ok: true };
				portMsg.innerHTML = '';
				if (!pc.ok) portMsg.appendChild(chip('zm-tg-chip-bad', '✕ ' + pc.text));
				else if (dr.net === 'wait') portMsg.appendChild(chip('zm-tg-chip-wait', 'проверяем, свободен ли порт…'));
				else if (dr.net && dr.net.free === false) portMsg.appendChild(chip('zm-tg-chip-bad', '✕ ' + (dr.net.why || 'порт занят')));
				else if (dr.net && dr.net.free) portMsg.appendChild(chip('zm-tg-chip-ok', '✓ ' + (dr.net.self ? 'сейчас этот порт у самого прокси' : 'порт свободен')));
				else if (pc.text) portMsg.appendChild(chip(pc.warn ? 'zm-tg-chip-wait' : 'zm-tg-chip-ok', pc.text));
				if (keyIn) {
					keyMsg.innerHTML = '';
					keyMsg.appendChild(chip(kc.ok ? 'zm-tg-chip-ok' : 'zm-tg-chip-bad', (kc.ok ? '✓ ' : '✕ ') + kc.text));
				}
				var ac = withArgs ? argsCheck(dr.args) : { ok: true, args: '' };
				if (withArgs) {
					argsPre.textContent = '…--port ' + (String(+dr.port || dr.port) || st.port || v.port);
					argsMsg.innerHTML = '';
					argsMsg.appendChild(chip(ac.ok ? 'zm-tg-chip-ok' : 'zm-tg-chip-bad', (ac.ok ? '✓ ' : '✕ ') + ac.text));
				}
				var confSame = String(+dr.port) === String(st.port) && (!keyIn || (kc.key || '') === (st.key || ''));
				var argsSame = !withArgs || ac.args === argsNorm(st.args);
				var same = confSame && argsSame;
				var ok = pc.ok && kc.ok && ac.ok && !(dr.net && dr.net.free === false) && dr.net !== 'wait';
				preview.innerHTML = '';
				preview.appendChild(ok ? zm.secret(linkFor(kc.key)) : document.createTextNode('Ссылка появится, когда порт' + (keyIn ? ' и ключ' : '') + ' будут в порядке'));
				preview.classList.toggle('zm-tg-edit-preview-off', !ok);
				saveBtn.disabled = !ok || same || dr.busy;
				saveBtn.textContent = dr.busy ? 'Применяем…' : same ? 'Без изменений' : 'Сохранить и перезапустить';
			}
			function netCheck() {
				clearTimeout(netT);
				var pc = portCheck(v, st, dr.port);
				if (!pc.ok) { dr.net = null; paint(); return; }
				if (String(+dr.port) === String(st.port)) { dr.net = { free: true, self: true }; paint(); return; }
				dr.net = 'wait'; paint();
				var mine = ++portSeq, p = String(+dr.port);
				netT = setTimeout(function() {
					zm.tgAction(v.id, 'port=' + p).then(function(r) {
						if (mine !== portSeq) return;
						dr.net = r && !r.error ? r : { free: false, why: (r && r.error) || 'роутер не ответил' };
						paint();
					}, function() { if (mine === portSeq) { dr.net = { free: false, why: 'роутер не ответил' }; paint(); } });
				}, 450);
			}
			portIn.addEventListener('input', function() { var c = portIn.value.replace(/\D+/g, ''); if (c !== portIn.value) portIn.value = c; dr.port = c; netCheck(); });
			if (keyIn) keyIn.addEventListener('input', function() { dr.key = keyIn.value.trim(); paint(); });
			if (argsIn) argsIn.addEventListener('input', function() { dr.args = argsIn.value; paint(); });
			saveBtn.addEventListener('click', function() {
				if (dr.busy) return;
				if (busyMap[v.id]) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
				var kc = keyIn ? keyCheck(v, dr.key) : { key: '' };
				var ac = withArgs ? argsCheck(dr.args) : { args: '' };
				var confSame = String(+dr.port) === String(st.port) && (!keyIn || (kc.key || '') === (st.key || ''));
				var argsSame = !withArgs || ac.args === argsNorm(st.args);
				dr.busy = true; busyMap[v.id] = true; paint();
				zm.toast('Применяем настройки ' + v.title + ' и перезапускаем его', 'warning');
				var stop = function(msg, log) {
					dr.busy = false; busyMap[v.id] = false;
					zm.toast(msg + (log ? ' · ' + String(log).split('\n')[0] : ''), 'error', 12000);
					zm.tgStatus().then(function(d) { data = d; st = statusOf(d, v.id); paint(); });
				};
				var step1 = confSame ? Promise.resolve({ ok: true, same: true }) : zm.tgAction(v.id, 'conf=' + (+dr.port) + ':' + (kc.key || ''));
				step1.then(function(r) {
					if (!r || r.error) { stop((r && r.error) || 'Роутер не ответил'); return; }
					var step2 = argsSame ? Promise.resolve({ ok: true, same: true }) : zm.tgAction(v.id, 'args=' + ac.args);
					return step2.then(function(r2) {
						if (!r2 || r2.error) { stop((r2 && r2.error) || 'Роутер не ответил', r2 && r2.log); return; }
						dr.busy = false; busyMap[v.id] = false;
						var running = !(r.running === false || r2.running === false);
						zm.toast(confSame && argsSame ? 'Ничего не изменилось'
							: !running ? 'Сохранено. ' + v.title + ' сейчас не запущен' + (confSame ? '' : ' — ссылка появится, когда он заработает')
							: confSame ? v.title + ': параметры применены, ссылка прежняя'
							: v.title + ': ' + (keyIn ? 'порт и ключ' : 'порт') + (argsSame ? '' : ' и параметры') + ' применены — обновите прокси в Telegram по новой ссылке', 'info', 8000);
						editOpen[v.id] = false; delete editDraft[v.id];
						zm.tgStatus().then(function(d) { data = d; renderCards(d); renderLinks(d); });
					});
				}).catch(function() { dr.busy = false; busyMap[v.id] = false; zm.toast('Роутер не ответил', 'error'); paint(); });
			});
			var rows = [
				E('div', { 'class': 'zm-tg-edit-row' }, [
					E('label', { 'class': 'zm-tg-edit-label' }, 'Порт'),
					E('div', { 'class': 'zm-tg-edit-field' }, [ portIn, portMsg ])
				])
			];
			if (keyIn) rows.push(E('div', { 'class': 'zm-tg-edit-row' }, [
				E('label', { 'class': 'zm-tg-edit-label' }, 'Ключ'),
				E('div', { 'class': 'zm-tg-edit-field' }, [
					E('div', { 'class': 'zm-tg-edit-keyline' }, [ keyIn, E('button', { 'class': 'cbi-button', 'type': 'button', 'title': 'Случайный ключ из 32 знаков', 'click': function() { dr.key = genKey(); keyIn.value = dr.key; paint(); } }, 'Новый ключ') ]),
					keyMsg
				])
			]));
			if (argsIn) rows.push(E('div', { 'class': 'zm-tg-edit-row zm-tg-args-row' }, [
				E('label', { 'class': 'zm-tg-edit-label' }, 'Параметры после порта'),
				E('div', { 'class': 'zm-tg-edit-field' }, [
					E('div', { 'class': 'zm-tg-args-line' }, [ argsPre, argsIn,
						E('button', { 'class': 'cbi-button', 'type': 'button', 'title': st.argsDef, 'click': function() { dr.args = st.argsDef || ''; argsIn.value = dr.args; paint(); } }, 'По умолчанию') ]),
					E('p', { 'class': 'zm-hint zm-tg-args-hint' }, keyIn ? 'Через пробел. Порт и ключ подставятся сами.' : 'Через пробел. Порт подставится сам.'),
					argsMsg
				])
			]));
			var box = E('div', { 'class': 'zm-tg-edit' }, rows.concat([
				E('div', { 'class': 'zm-tg-edit-label zm-tg-edit-plabel' }, 'Ссылка после сохранения'),
				preview,
				E('p', { 'class': 'zm-hint', 'style': 'margin:6px 0 0' }, v.kind === 'socks'
					? 'После сохранения прокси перезапустится. В Telegram поменяйте порт у прокси или откройте новую ссылку.'
					: 'После сохранения прокси перезапустится, а старая ссылка перестанет работать — откройте в Telegram новую. Не запустится с новыми настройками — вернём прежние.'),
				E('div', { 'class': 'zm-actions' }, [
					saveBtn,
					E('button', { 'class': 'cbi-button', 'click': function() { editOpen[v.id] = false; delete editDraft[v.id]; renderCards(data); } }, 'Отмена')
				])
			]));
			if (String(+dr.port) === String(st.port)) dr.net = { free: true, self: true };
			paint();
			return box;
		}

		var extOpen = {}, extDraft = {}, extPaint = {}, socksOpen = false, socksDraft = null, socksBusy = null;
		function socksHost(st, s) { return s && s.lan ? (s.host && s.host !== '0.0.0.0' ? s.host : data.lan_ip || '192.168.1.1') : '127.0.0.1'; }
		function socksAddr(st, s) { return socksHost(st, s) + ':' + s.port; }
		function socksFind(st, done) {
			var list = [], p;
			for (p = 1080; p <= 1099; p++) if (String(p) !== String(st.port)) list.push(p);
			(function next(i) {
				if (i >= list.length) { done(null); return; }
				zm.tgAction('rust', 'sport=' + list[i]).then(function(r) {
					if (r && !r.error && r.free) done(list[i]); else next(i + 1);
				}, function() { done(null); });
			})(0);
		}
		function socksEnable(st) {
			if (socksBusy || busyMap.rust) return;
			socksBusy = 'pick'; renderCards(data);
			socksFind(st, function(port) {
				if (port) { socksApply(st, { on: true, lan: true, port: String(port) }); return; }
				socksBusy = null; socksOpen = true; socksDraft = null; renderCards(data);
				zm.toast('Порты 1080–1099 заняты — укажите свой порт для SOCKS5', 'warning', 8000);
			});
		}
		function socksApply(st, dr, done) {
			if (busyMap.rust) { zm.toast('Дождитесь завершения текущей операции', 'warning'); if (done) done(false); return; }
			busyMap.rust = true; socksBusy = dr.on ? 'on' : 'off'; renderCards(data);
			var host = dr.lan ? ((st.socks || {}).on && (st.socks || {}).lan ? socksHost(st, st.socks) : (data.lan_ip || '192.168.1.1')) : '127.0.0.1';
			zm.tgAction('rust', 'socks=' + (dr.on ? (dr.lan ? 'lan' : 'local') + ':' + (+dr.port) : 'off')).then(function(r) {
				busyMap.rust = false; socksBusy = null;
				if (!r || r.error) { renderCards(data); zm.toast((r && r.error) || 'Роутер не ответил', 'error', 12000); if (done) done(false); return; }
				if (r.host) host = r.host;
				zm.toast(!dr.on ? 'SOCKS5 выключен' : r.running === false ? 'Сохранено. Rust сейчас не запущен' : dr.lan ? 'SOCKS5 работает: ' + host + ':' + (+dr.port) + ' — ссылка для Telegram вверху страницы' : 'SOCKS5 работает на 127.0.0.1:' + (+dr.port), 'info', 8000);
				socksOpen = false; socksDraft = null;
				if (done) done(true);
				zm.tgStatus().then(function(d) { data = d; renderCards(d); renderLinks(d); });
			}, function() { busyMap.rust = false; socksBusy = null; renderCards(data); zm.toast('Роутер не ответил', 'error'); if (done) done(false); });
		}
		function socksPanel(v, st, cls) {
			var s = st.socks || {}, body = E('div', { 'class': 'zm-tg-x-body zm-tg-socks-body ' + (cls || '') });
			var dr = socksDraft || (socksDraft = { on: true, port: String(s.port || 1080), lan: true, busy: false, net: null });
			var netT = null;
			function netCheck() {
				clearTimeout(netT);
				var p = +dr.port;
				if (!/^\d{2,5}$/.test(dr.port) || p < 1 || p > 65535 || String(p) === String(st.port)) { dr.net = null; paint(); return; }
				if (s.on && String(p) === String(s.port)) { dr.net = { free: true, self: true }; paint(); return; }
				dr.net = 'wait'; paint();
				var mine = ++portSeq;
				netT = setTimeout(function() {
					zm.tgAction('rust', 'sport=' + p).then(function(r) {
						if (mine !== portSeq) return;
						dr.net = r && !r.error ? r : { free: false, why: (r && r.error) || 'роутер не ответил' };
						paint();
					}, function() { if (mine === portSeq) { dr.net = { free: false, why: 'роутер не ответил' }; paint(); } });
				}, 450);
			}
			var portIn = E('input', { 'type': 'text', 'inputmode': 'numeric', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-edit-port', 'value': dr.port, 'maxlength': '5', 'aria-label': 'Порт SOCKS5' });
			var portMsg = E('div', { 'class': 'zm-tg-chips' });
			var applyBtn = E('button', { 'class': 'cbi-button cbi-button-positive' }, 'Применить');
			var note = E('p', { 'class': 'zm-hint zm-tg-x-note zm-tg-socks-note' }, s.on ? 'После смены порта добавьте в Telegram новую ссылку сверху — старая перестанет работать.' : 'Подключаться смогут только устройства вашей домашней сети — пароля у SOCKS5 нет.');
			var acts = E('div', { 'class': 'zm-actions' }, [ applyBtn, E('button', { 'class': 'cbi-button', 'click': function() {
				if (dr.busy) return;
				if (s.on) { dr.port = String(s.port); portIn.value = dr.port; dr.net = { free: true, self: true }; ++portSeq; clearTimeout(netT); paint(); return; }
				socksOpen = false; socksDraft = null; renderCards(data);
			} }, s.on ? 'Вернуть' : 'Отмена') ]);
			function portOk() { var p = +dr.port; return /^\d{2,5}$/.test(dr.port) && p >= 1 && p <= 65535 && String(p) !== String(st.port); }
			function same() { return !!s.on && String(+dr.port) === String(s.port) && !!s.lan; }
			function paint() {
				portMsg.innerHTML = '';
				var p = +dr.port;
				if (!/^\d{2,5}$/.test(dr.port) || p < 1 || p > 65535) portMsg.appendChild(chip('zm-tg-chip-bad', '✕ порт — число от 1 до 65535'));
				else if (String(p) === String(st.port)) portMsg.appendChild(chip('zm-tg-chip-bad', '✕ это порт MTProto этого прокси — нужен другой'));
				else if (dr.net === 'wait') portMsg.appendChild(chip('zm-tg-chip-wait', 'проверяем, свободен ли порт…'));
				else if (dr.net && dr.net.free === false) portMsg.appendChild(chip('zm-tg-chip-bad', '✕ ' + (dr.net.why || 'порт занят')));
				else if (dr.net && dr.net.free && !same()) portMsg.appendChild(chip('zm-tg-chip-ok', '✓ порт свободен'));
				var show = !s.on || !same() || dr.busy;
				acts.style.display = note.style.display = show ? '' : 'none';
				portMsg.style.display = portMsg.firstChild ? '' : 'none';
				var bad = !portOk() || dr.net === 'wait' || !dr.net || dr.net.free === false;
				applyBtn.disabled = bad || same() || dr.busy;
				applyBtn.textContent = dr.busy ? 'Сохраняем…' : same() ? 'Без изменений' : s.on ? 'Сохранить и перезапустить' : 'Включить';
			}
			portIn.addEventListener('input', function() { var c = portIn.value.replace(/\D+/g, ''); if (c !== portIn.value) portIn.value = c; dr.port = c; netCheck(); });
			applyBtn.addEventListener('click', function() {
				if (dr.busy || applyBtn.disabled) return;
				dr.busy = true; paint();
				socksApply(st, dr, function() { dr.busy = false; paint(); });
			});
			body.appendChild(E('div', { 'class': 'zm-tg-socks-port' }, [ E('span', { 'class': 'zm-tg-socks-port-l' }, 'Порт'), portIn, portMsg ]));
			if (s.on && !s.lan) body.appendChild(E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Сейчас SOCKS5 доступен только самому роутеру. После сохранения к нему смогут подключаться устройства вашей домашней сети.'));
			body.appendChild(note);
			body.appendChild(acts);
			if (dr.net === null) netCheck(); else paint();
			return body;
		}
		function socksUci(st) {
			var s = st.socks || {};
			return E('p', { 'class': 'zm-hint zm-tg-x-note' }, (s.on ? 'SOCKS5 включён: ' + socksAddr(st, s) + '. ' : 'SOCKS5 выключен. ') + 'Rust установлен пакетом — SOCKS5 включается в его настройках: Enable SOCKS5 input, адрес и порт.');
		}

		function socksBlock(v, st) {
			var s = st.socks || {}, on = !!(s.ok && s.on), open = !!s.ok && !st.uci && !socksBusy && (on || !!socksOpen);
			var box = E('div', { 'class': 'zm-tg-socks-strip' + (open ? ' zm-tg-socks-strip-open' : '') });
			var hint = !s.ok ? 'Есть в Rust с версии 2.6.0 — обновите прокси, чтобы включить.'
				: socksBusy === 'off' ? 'Выключаем — Rust перезапускается…'
				: socksBusy ? 'Включаем — Rust перезапускается…'
				: on ? [ zm.secret(socksAddr(st, s)), s.lan ? ' · для устройств дома' : ' · только для этого роутера' ]
				: 'Ещё один способ подключиться к этому прокси: в Telegram добавляется как обычный SOCKS5, без ключа. MTProto продолжит работать.';
			box.appendChild(E('div', { 'class': 'zm-tg-socks-line' }, [
				zm.swRow(socksBusy ? socksBusy !== 'off' : on, 'SOCKS5', hint, function() {
					if (!s.ok) { zm.toast('Сначала обновите Rust до 2.6.0 или новее', 'warning'); return; }
					if (st.uci) { zm.toast('Rust установлен пакетом — SOCKS5 включается в его настройках', 'warning'); return; }
					if (socksBusy || busyMap.rust) return;
					if (on) socksApply(st, { on: false }); else socksEnable(st);
				}, !s.ok || !!socksBusy)
			]));
			if (open) box.appendChild(socksPanel(v, st));
			if (st.uci && s.ok) box.appendChild(socksUci(st));
			return box;
		}
		function extSummary(st) {
			var x = st.ext, parts = [];
			if (x.tls) parts.push('FakeTLS · ' + x.tls);
			if (x.open) parts.push(x.host ? [ 'из интернета: ', zm.secret(x.host + ':' + st.port) ] : 'из интернета');
			if (x.open && String(x.fw_port) !== String(st.port)) parts.push('⚠ в правиле старый порт');
			if (!parts.length) return 'выключено · прокси работает только дома';
			var out = [];
			parts.forEach(function(p, i) { if (i) out.push(' · '); out = out.concat(p); });
			return out;
		}
		function extFold(v, st) {
			var open = !!extOpen[v.id];
			function toggle() { extOpen[v.id] = !open; if (open) { delete extDraft[v.id]; delete extPaint[v.id]; } renderCards(data); }
			var box = E('div', { 'class': 'zm-fold zm-tg-x' + (open ? ' zm-fold-open' : '') });
			box.appendChild(E('div', { 'class': 'zm-fold-head', 'role': 'button', 'tabindex': '0', 'aria-expanded': open ? 'true' : 'false', 'click': toggle,
				'keydown': function(ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); } } }, [
				E('span', { 'class': 'zm-svc-chev' }, '›'), E('span', {}, 'Доступ из интернета и маскировка'), E('span', { 'class': 'zm-fold-sum' }, extSummary(st))
			]));
			if (open) box.appendChild(extPanel(v, st));
			return box;
		}
		function extPanel(v, st) {
			var x = st.ext, ex = data.ext || {}, ddns = ex.ddns || [], port = String(st.port || v.port);
			var wanPub = ex.wan && !ex.grey ? ex.wan : '';
			var dr = extDraft[v.id];
			if (!dr) {
				var hm = x.hmode || (x.host && TG_IP_RE.test(x.host) ? 'ip' : 'ddns');
				dr = extDraft[v.id] = { tls: !!x.tls, site: x.tls || TG_SITES[0], own: !!x.tls && TG_SITES.indexOf(x.tls) < 0, open: !!x.open, hmode: hm,
					host: x.host || (hm === 'ip' ? wanPub : ddns[0] || ''), busy: false, chk: null, siteChk: null };
			}
			var body = E('div', { 'class': 'zm-fold-body zm-tg-x-body' });
			var siteMsg = E('div', { 'class': 'zm-tg-chips' }), tlsMsg = E('div', { 'class': 'zm-tg-chips' }), hostMsg = E('div', { 'class': 'zm-tg-chips' });
			var linkWrap = E('div', {}), lastLink = null;
			var applyBtn = E('button', { 'class': 'cbi-button cbi-button-positive' }, 'Применить');
			var siteT = null, hostT = null, pickWrap = null, pickFill = null;
			function site() { return String(dr.site || '').trim().toLowerCase(); }
			function host() { return String(dr.host || '').trim().toLowerCase(); }
			function siteOk() { return TG_DOM_RE.test(site()) && !TG_IP_RE.test(site()); }
			function hostOk() { var h = host(); return TG_IP_RE.test(h) || TG_DOM_RE.test(h); }
			function wantTls() { return x.pkg ? (x.tls || '') : dr.tls ? site() : ''; }
			function valid() { return (x.pkg || !dr.tls || siteOk()) && (!dr.open || hostOk()); }
			function same() {
				return wantTls() === (x.tls || '') && dr.open === !!x.open && (!dr.open || host() === (x.host || '')) && !(x.open && String(x.fw_port) !== port);
			}
			function rebuild() { delete extPaint[v.id]; var nb = extPanel(v, st); body.parentNode && body.parentNode.replaceChild(nb, body); }
			function row(label, kids) {
				return E('div', { 'class': 'zm-tg-x-row' }, [ E('div', { 'class': 'zm-tg-edit-label' }, label), E('div', { 'class': 'zm-tg-x-field' }, kids) ]);
			}
			function seg(items, cur, pick, dis) {
				return E('div', { 'class': 'zm-seg zm-tg-x-seg' }, items.map(function(it) {
					var off = dis && dis[it[0]];
					function go() { if (!off && !dr.busy && it[0] !== cur) pick(it[0]); }
					return E('div', { 'class': 'zm-seg-item' + (it[0] === cur ? ' zm-active' : '') + (off ? ' zm-tg-seg-off' : ''), 'role': 'button', 'tabindex': off ? '-1' : '0',
						'aria-pressed': it[0] === cur ? 'true' : 'false', 'title': off || null, 'click': go,
						'keydown': function(ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } } }, it[1]);
				}));
			}
			function siteCheck() {
				clearTimeout(siteT);
				if (!dr.tls || x.pkg || !siteOk() || (dr.siteChk && dr.siteChk.site === site())) { paint(); return; }
				var want = site();
				dr.siteChk = 'wait'; paint();
				siteT = setTimeout(function() {
					zm.tgAction(v.id, 'site=' + want).then(function(r) {
						if (site() !== want) return;
						dr.siteChk = r && !r.error ? { site: want, up: !!r.up } : null;
						if (extPaint[v.id]) extPaint[v.id]();
					}, function() { if (site() === want) { dr.siteChk = null; if (extPaint[v.id]) extPaint[v.id](); } });
				}, 600);
			}
			function hostCheck(delay) {
				clearTimeout(hostT);
				if (!dr.open || !hostOk()) { paint(); return; }
				var want = host();
				dr.chk = 'wait'; paint();
				hostT = setTimeout(function() {
					zm.tgAction(v.id, 'chk=' + want).then(function(r) {
						if (host() !== want) return;
						if (r && !r.error) r.host = want;
						dr.chk = r && !r.error ? r : null;
						if (extPaint[v.id]) extPaint[v.id]();
					}, function() { if (host() === want) { dr.chk = null; if (extPaint[v.id]) extPaint[v.id](); } });
				}, delay || 0);
			}
			function paint() {
				var c = dr.chk, ip = TG_IP_RE.test(host());
				siteMsg.innerHTML = '';
				if (dr.tls && !x.pkg) {
					if (!siteOk()) siteMsg.appendChild(chip('zm-tg-chip-bad', '✕ Нужно имя сайта, например www.google.com'));
					else if (dr.siteChk === 'wait') siteMsg.appendChild(chip('zm-tg-chip-wait', 'проверяем сайт…'));
					else if (dr.siteChk && dr.siteChk.site === site()) siteMsg.appendChild(dr.siteChk.up ? chip('zm-tg-chip-ok', '✓ сайт открывается по HTTPS') : chip('zm-tg-chip-wait', '⚠ сайт не открылся с роутера — лучше выбрать другой'));
				}
				tlsMsg.innerHTML = '';
				if (!x.pkg && valid() && wantTls() !== (x.tls || '')) tlsMsg.appendChild(chip('zm-tg-chip-wait', '⚠ Ключ в ссылках станет ' + (wantTls() ? 'ee…' : 'dd…') + ' — после «Применить» откройте новую ссылку на всех устройствах, и дома тоже'));
				if (pickFill) pickFill();
				hostMsg.innerHTML = '';
				if (dr.open) {
					var grey = c && c !== 'wait' && c.host === host() ? c.grey && c.wan : ex.grey && ex.wan;
					if (grey) hostMsg.appendChild(chip('zm-tg-chip-bad', [ '✕ У роутера серый адрес ', zm.secret(grey), ' — из интернета к нему не подключиться: нужен белый IP от провайдера или проброс порта на модеме' ]));
					if (!host()) hostMsg.appendChild(chip('zm-tg-chip-bad', dr.hmode === 'ip' ? '✕ Впишите внешний IP роутера' : '✕ Впишите домен, например myhome.ddns.net'));
					else if (!hostOk()) hostMsg.appendChild(chip('zm-tg-chip-bad', '✕ Это не домен и не IPv4-адрес'));
					else if (c === 'wait') hostMsg.appendChild(chip('zm-tg-chip-wait', 'проверяем адрес…'));
					else if (c && c.host === host()) {
						if (!c.grey) hostMsg.appendChild(!c.wan ? chip('zm-tg-chip-wait', '⚠ Не удалось узнать адрес роутера в интернете')
							: c.match ? chip('zm-tg-chip-ok', ip ? '✓ это адрес роутера в интернете' : [ '✓ домен указывает на роутер · ', zm.secret(c.wan) ])
							: ip ? chip('zm-tg-chip-bad', [ '✕ У роутера сейчас адрес ', zm.secret(c.wan) ])
							: !(c.ips || []).length ? chip('zm-tg-chip-bad', '✕ Домен не найден в DNS')
							: chip('zm-tg-chip-bad', [ '✕ Домен указывает на ', zm.secret(c.ips.join(', ')), ', а у роутера ', zm.secret(c.wan) ]));
						if (x.open) {
							if (String(x.fw_port) !== port) hostMsg.appendChild(chip('zm-tg-chip-wait', '⚠ В правиле старый порт ' + x.fw_port + ' — нажмите «Применить»'));
							else if (c.fw_live) hostMsg.appendChild(chip('zm-tg-chip-ok', '✓ порт ' + port + ' открыт в межсетевом экране'));
							else hostMsg.appendChild(chip('zm-tg-chip-wait', '⚠ Правило есть, но межсетевой экран его не загрузил'));
						}
						if (!c.listen) hostMsg.appendChild(chip('zm-tg-chip-wait', '⚠ Прокси сейчас не запущен'));
						hostMsg.appendChild(E('button', { 'type': 'button', 'class': 'zm-tg-pick zm-tg-recheck', 'click': function() { dr.chk = null; hostCheck(); } }, 'Проверить ещё раз'));
					}
				}
				var lk = '', k = tgCore(st.key || st.secret);
				if (dr.open && hostOk() && (x.pkg ? st.secret : k)) lk = 'tg://proxy?server=' + host() + '&port=' + port + '&secret=' + (x.pkg ? st.secret : wantTls() ? 'ee' + k + tgHex(wantTls()) : 'dd' + k);
				var sm = same(), key = lk + '|' + sm;
				if (key !== lastLink) {
					lastLink = key;
					linkWrap.innerHTML = '';
					if (lk) linkWrap.appendChild(row('Ссылка из интернета', [
						sm ? linkBlock(lk, '') : E('div', { 'class': 'zm-tg-link-box zm-tg-edit-preview' }, [ zm.secret(lk) ]),
						sm ? E([]) : E('div', { 'class': 'zm-tg-chips' }, [ chip('zm-tg-chip-wait', 'заработает после «Применить»') ]),
						E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Не публикуйте эту ссылку: с ней прокси сможет пользоваться любой. Утекла — смените ключ в «Порт и ключ».')
					]));
				}
				applyBtn.disabled = !valid() || sm || dr.busy;
				applyBtn.textContent = dr.busy ? 'Применяем…' : sm ? 'Без изменений' : 'Применить';
			}
			extPaint[v.id] = paint;

			var mask;
			if (x.pkg) {
				mask = [ E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Rust установлен пакетом — FakeTLS включается в его настройках (Inbound FakeTLS domain). Сейчас: ' + (x.tls ? 'FakeTLS, сайт ' + x.tls : 'обычный ключ (dd)') + '.') ];
			} else {
				mask = [ seg([ [ 'dd', 'Обычный ключ (dd)' ], [ 'ee', 'FakeTLS (ee)' ] ], dr.tls ? 'ee' : 'dd', function(m) { dr.tls = m === 'ee'; rebuild(); },
					x.ftls || x.tls ? null : { ee: 'Эта версия прокси не умеет FakeTLS' }) ];
				if (!x.ftls && !x.tls) mask.push(E('div', { 'class': 'zm-tg-chips' }, [ chip('zm-tg-chip-wait', '⚠ Эта версия ' + v.title + ' не умеет FakeTLS — ' + (st.newer ? 'обновите прокси кнопкой «Обновить до ' + st.latest + '»' : 'нужна версия новее')) ]));
				if (dr.tls) {
					var siteSel = E('select', { 'class': 'cbi-input-select zm-tg-x-site', 'aria-label': 'Сайт для маскировки' },
						TG_SITES.map(function(d) { return E('option', { 'value': d, 'selected': !dr.own && d === site() ? 'selected' : null }, d); })
							.concat([ E('option', { 'value': '', 'selected': dr.own ? 'selected' : null }, 'Свой сайт…') ]));
					siteSel.addEventListener('change', function() {
						if (siteSel.value) { dr.own = false; dr.site = siteSel.value; siteCheck(); }
						else { dr.own = true; dr.site = ''; rebuild(); }
					});
					var line = [ siteSel ];
					if (dr.own) {
						var ownIn = E('input', { 'type': 'text', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-x-own', 'value': dr.site, 'placeholder': 'example.com', 'spellcheck': 'false', 'autocapitalize': 'off', 'autocomplete': 'off', 'aria-label': 'Свой сайт для маскировки' });
						ownIn.addEventListener('input', function() { dr.site = ownIn.value.trim(); clearTimeout(siteT); siteT = setTimeout(siteCheck, 500); paint(); });
						line.push(ownIn);
					}
					mask.push(E('div', { 'class': 'zm-tg-x-line' }, line), siteMsg,
						E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Для провайдера подключение к прокси выглядит как обычный HTTPS к этому сайту. Лучше выбрать сайт, который у вас открывается без VPN.'));
				} else mask.push(E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Обычный ключ работает везде, но провайдеру проще распознать в нём прокси.'));
				mask.push(tlsMsg);
			}

			var net = [ zm.swRow(dr.open, 'Открыть порт ' + port + ' для интернета', 'Правило «' + (v.id === 'rust' ? 'Allow-TG-WS-Proxy-Rust' : 'Allow-TG-WS-Proxy-Go') + '» в межсетевом экране (зона WAN). Выключите — правило уберётся.',
				function() { dr.open = !dr.open; rebuild(); }, dr.busy) ];
			if (dr.open) {
				net.push(seg([ [ 'ddns', 'DDNS / свой домен' ], [ 'ip', 'Внешний IP' ] ], dr.hmode, function(m) {
					dr.hmode = m;
					if (m === 'ip' && !TG_IP_RE.test(host())) dr.host = wanPub;
					if (m === 'ddns' && TG_IP_RE.test(host())) dr.host = ddns[0] || '';
					dr.chk = null; rebuild();
				}));
				var hostIn = E('input', { 'type': 'text', 'class': 'cbi-input-text zm-tg-edit-in zm-tg-x-host', 'value': dr.host, 'placeholder': dr.hmode === 'ip' ? 'например, 203.0.113.10' : 'например, myhome.ddns.net',
					'spellcheck': 'false', 'autocapitalize': 'off', 'autocomplete': 'off', 'aria-label': dr.hmode === 'ip' ? 'Внешний IP роутера' : 'Домен роутера' });
				zm.secretIn(hostIn);
				hostIn.addEventListener('input', function() { dr.host = hostIn.value.trim(); hostCheck(700); });
				pickWrap = E('div', { 'class': 'zm-tg-chips' });
				pickFill = function() {
					pickWrap.innerHTML = '';
					function pick(val, why) { return E('button', { 'type': 'button', 'class': 'zm-tg-pick', 'click': function() { dr.host = val; hostIn.value = val; hostCheck(); } }, [ E('b', { 'class': 'zm-blur' }, val), E('span', {}, ' · ' + why) ]); }
					if (dr.hmode === 'ddns') ddns.forEach(function(h) { if (h !== host()) pickWrap.appendChild(pick(h, 'из «Динамического DNS»')); });
					else if (wanPub && wanPub !== host()) pickWrap.appendChild(pick(wanPub, 'адрес роутера сейчас'));
				};
				net.push(E('div', { 'class': 'zm-tg-x-line' }, [ hostIn ]), pickWrap, hostMsg);
				net.push(E('p', { 'class': 'zm-hint zm-tg-x-note' }, dr.hmode === 'ip'
					? 'Внешний IP может смениться — тогда ссылка перестанет работать. Надёжнее домен из «Динамического DNS».'
					: ddns.length ? 'Домен из «Динамического DNS» всегда указывает на роутер, даже когда провайдер меняет IP.'
						: 'Нет своего домена? Настройте «Динамический DNS» (пакет luci-app-ddns) — тогда ссылка не сломается, когда провайдер сменит IP.'));
				net.push(E('p', { 'class': 'zm-hint zm-tg-x-note' }, 'Проверяйте с телефона через мобильный интернет: из домашней сети прокси откроется, даже если снаружи порт закрыт.'));
			}

			applyBtn.addEventListener('click', function() {
				if (dr.busy || applyBtn.disabled) return;
				if (busyMap[v.id]) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
				var tls = wantTls(), tlsCh = tls !== (x.tls || ''), opening = dr.open && !x.open;
				function go() {
					dr.busy = true; busyMap[v.id] = true; paint();
					zm.toast(tlsCh ? 'Перезапускаем ' + v.title + ' с новой маскировкой' : 'Применяем настройки ' + v.title, 'warning');
					zm.tgAction(v.id, 'ext=' + tls + ':' + (dr.open ? 1 : 0) + ':' + dr.hmode + ':' + (hostOk() ? host() : '')).then(function(r) {
						dr.busy = false; busyMap[v.id] = false;
						if (!r || r.error) { zm.toast((r && r.error) || 'Роутер не ответил', 'error', 10000); paint(); return; }
						var msg = [];
						if (r.tls) msg.push(tls ? 'FakeTLS включён, сайт ' + tls : 'FakeTLS выключен');
						if (r.fw === 'opened') msg.push('порт ' + port + ' открыт для интернета');
						if (r.fw === 'closed') msg.push('порт закрыт для интернета');
						zm.toast(v.title + ': ' + (msg.length ? msg.join(', ') : 'сохранено') + (r.tls ? ' — откройте в Telegram новую ссылку на всех устройствах' : ''), 'info', r.tls ? 9000 : 5000);
						delete extDraft[v.id]; delete extPaint[v.id];
						zm.tgStatus().then(function(d) { data = d; renderCards(d); renderLinks(d); });
					}, function() { dr.busy = false; busyMap[v.id] = false; zm.toast('Роутер не ответил', 'error'); paint(); });
				}
				if (!opening) { go(); return; }
				zm.dialog({ title: 'Открыть ' + v.title + ' для интернета?', okText: 'Открыть порт ' + port,
					blocks: [ { type: 'list', title: 'Что произойдёт', items: [
						'Порт ' + port + ' (TCP) откроется в межсетевом экране со стороны интернета',
						'Подключиться смогут только те, у кого есть ссылка с ключом',
						tls ? 'Для провайдера подключения выглядят как HTTPS к ' + tls : 'Совет: включите FakeTLS — так прокси сложнее распознать',
						'Закрыть порт можно здесь же одним переключателем'
					] } ] }).then(function(ok) { if (ok) go(); });
			});

			body.appendChild(E('p', { 'class': 'zm-hint zm-tg-x-intro' }, 'Нужно, только если подключаться к прокси не из дома — с телефона в мобильной сети или с работы. Дома всё работает и без этого.'));
			body.appendChild(row('Маскировка', mask));
			body.appendChild(row('Из интернета', net));
			body.appendChild(linkWrap);
			body.appendChild(E('div', { 'class': 'zm-actions' }, [
				applyBtn,
				E('button', { 'class': 'cbi-button', 'click': function() { extOpen[v.id] = false; delete extDraft[v.id]; delete extPaint[v.id]; renderCards(data); } }, 'Отмена')
			]));
			paint();
			if (dr.open && hostOk() && !dr.chk) hostCheck();
			if (dr.tls && !x.pkg && siteOk() && !dr.siteChk) siteCheck();
			return body;
		}

		function extLink(st, x) {
			if (!x || !x.open || !x.host || !st.secret) return '';
			return 'tg://proxy?server=' + x.host + '&port=' + (st.port || '') + '&secret=' + st.secret;
		}

		function renderLinks(d) {
			linksWrap.innerHTML = '';
			VARIANTS.forEach(function(v) {
				var st = statusOf(d, v.id);
				var host = st.host || d.lan_ip, port = st.port || v.port;
				if (!st.installed || !st.running || !host) return;

				var link, extra, outLink = '';
				if (v.kind === 'socks') {
					link = 'tg://socks?server=' + host + '&port=' + port;
					extra = [ 'SOCKS5-адрес: ', zm.secret(host + ':' + port) ];
				} else {
					if (!st.secret) return;
					link = 'tg://proxy?server=' + host + '&port=' + port + '&secret=' + st.secret;
					extra = [ 'Хост: ', zm.secret(host), '   Порт: ' + port + '   Ключ: ', zm.secret(st.secret) ];
					outLink = extLink(st, st.ext);
				}

				linksWrap.appendChild(E('div', { 'class': 'zm-tg-link-card' }, [
					E('h4', {}, v.title),
					E('p', { 'class': 'zm-tg-link-hint' }, outLink
						? 'Дома подключайтесь по первой ссылке, вне дома — по второй. Откройте ссылку на телефоне или компьютере с Telegram — прокси подключится сам.'
						: 'Откройте эту ссылку на телефоне/компьютере с Telegram — прокси подключится автоматически. Либо скопируйте и вставьте её в браузер/Telegram вручную.'),
					linkBlock(link, outLink ? 'Дома' : ''),
					E('p', { 'class': 'zm-hint' }, extra),
					outLink ? linkBlock(outLink, 'Из интернета') : E([])
				]));
			});
			var rst = statusOf(d, 'rust'), rs = rst.socks;
			if (rst.installed && rst.running && rs && rs.ok && rs.on && rs.lan) {
				var sl = 'tg://socks?server=' + socksHost(rst, rs) + '&port=' + rs.port;
				linksWrap.appendChild(E('div', { 'class': 'zm-tg-link-card' }, [
					E('h4', {}, 'Rust (SOCKS5)'),
					E('p', { 'class': 'zm-tg-link-hint' }, 'Откройте ссылку на телефоне или компьютере с Telegram — прокси добавится как SOCKS5. Работает только дома, ключ не нужен.'),
					linkBlock(sl, ''),
					E('p', { 'class': 'zm-hint' }, 'SOCKS5-адрес: ' + socksHost(rst, rs) + ':' + rs.port)
				]));
			}
		}

		var busyMap = {};

		function restartBtn(v) {
			return E('button', {
				'class': 'cbi-button',
				'disabled': busyMap[v.id] ? '' : null,
				'click': function() {
					if (busyMap[v.id]) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
					busyMap[v.id] = true;
					renderCards(data);
					zm.toast('Перезапускаем ' + v.title, 'warning');
					zm.tgAction(v.id, 'restart').then(function(res) {
						busyMap[v.id] = false;
						if (!res || res.error) { zm.toast((res && res.error) || 'Роутер не ответил', 'error'); renderCards(data); return; }
						data = res;
						renderCards(res);
						renderLinks(res);
						var ok = statusOf(res, v.id).running;
						zm.toast(ok ? v.title + ' перезапущен' : v.title + ' не запустился — проверьте порт и параметры', ok ? 'info' : 'error');
					}).catch(function() { busyMap[v.id] = false; renderCards(data); zm.toast('Роутер не ответил', 'error'); });
				}
			}, 'Перезапустить');
		}

		function reinstallAsk(v) {
			var proto = v.kind !== 'socks';
			zm.dialog({
				title: 'Переустановить ' + v.title + '?',
				intro: 'Программа скачается и встанет заново. Пока идёт переустановка, Telegram через этот прокси не подключится. Если нужен просто перезапуск — нажмите «Перезапустить».',
				blocks: [ { type: 'choice', id: 'how', value: 'keep', title: 'Настройки', options: [
					{ id: 'keep', label: 'Сохранить', hint: proto ? 'Порт, ключ и параметры останутся — ссылка для Telegram не изменится' : 'Порт и параметры останутся прежними' },
					{ id: 'clean', label: 'С нуля', warn: true, hint: proto ? 'Новый ключ и настройки по умолчанию — старая ссылка перестанет работать на всех устройствах' : 'Порт и параметры вернутся к настройкам по умолчанию' }
				] } ],
				okText: 'Переустановить'
			}).then(function(r) {
				if (!r) return;
				if (r.how !== 'clean') { doAction(v.id, 'reinstall'); return; }
				if (!proto) { doAction(v.id, 'reinstall_clean'); return; }
				zm.dialog({ title: 'Сбросить ключ ' + v.title + '?', danger: true, okText: 'Сбросить и переустановить',
					blocks: [ { type: 'note', kind: 'warn', text: 'Старая ссылка перестанет работать. Новую придётся заново отправить на все телефоны и компьютеры, где настроен этот прокси.' } ]
				}).then(function(ok) { if (ok) doAction(v.id, 'reinstall_clean'); });
			});
		}

		function renderCards(d) {
			cards.innerHTML = '';
			VARIANTS.forEach(function(v) {
				var st = statusOf(d, v.id);
				var actions = [], pkgNote = null;
				if (st.uci) {
					var web = document.body.classList.contains('zmw-body');
					actions.push(E('a', { 'class': 'cbi-button', 'href': L.url('admin/services/tg-ws-proxy-rs'), 'target': web ? '_blank' : null, 'rel': web ? 'noopener' : null }, 'Настройки пакета'));
					if (st.enabled) actions.push(restartBtn(v));
					pkgNote = E('p', { 'class': 'zm-hint' }, st.enabled
						? 'Установлен пакетом luci-app-tg-ws-proxy-rs: порт, ключ и остальное меняются в его настройках, обновление и удаление — через менеджер пакетов.'
						: 'Установлен пакетом luci-app-tg-ws-proxy-rs и выключен в его настройках — включите там «Enabled» и сохраните.');
					if (String(st.port) === '1443' && d.mtproto === 'installed')
						pkgNote = E([ pkgNote, E('p', { 'class': 'zm-hint' }, '⚠ Порт 1443 занят и Go (MTProto) — оба прокси на одном порту не заработают. Смените порт в настройках пакета.') ]);
				} else if (st.installed) {
					if (st.edit) actions.push(E('button', {
						'class': 'cbi-button' + (editOpen[v.id] ? ' zm-active' : ''),
						'aria-expanded': editOpen[v.id] ? 'true' : 'false',
						'click': function() { editOpen[v.id] = !editOpen[v.id]; if (!editOpen[v.id]) delete editDraft[v.id]; renderCards(data); }
					}, v.kind === 'socks' ? (hasArgs(v, st) ? 'Порт и параметры' : 'Изменить порт') : hasArgs(v, st) ? 'Порт, ключ и параметры' : 'Порт и ключ'));
					actions.push(restartBtn(v));
					actions.push(E('button', {
						'class': 'cbi-button cbi-button-remove',
						'click': function() {
							zm.dialog({ title: 'Удалить ' + v.title + '?', danger: true, okText: 'Удалить',
								blocks: [ { type: 'list', title: 'Что произойдёт', items: [
									v.title + ' остановится',
									'Пакет и все файлы удалятся — даже если менеджер пакетов откажется',
									'Telegram через этот прокси перестанет подключаться'
								] } ]
							}).then(function(r) { if (r) doAction(v.id, 'remove'); });
						}
					}, 'Удалить'));
					actions.push(E('button', {
						'class': 'cbi-button',
						'click': function() { reinstallAsk(v); }
					}, 'Переустановить'));
					if (st.installed && st.newer) {
						actions.push(E('button', {
							'class': 'cbi-button',
							'click': function() { doAction(v.id, 'update'); }
						}, 'Обновить до ' + st.latest));
					}
				} else {
					actions.push(E('button', {
						'class': 'cbi-button cbi-button-positive',
						'click': function() { doAction(v.id, 'install'); }
					}, 'Установить'));
				}
				cards.appendChild(E('div', { 'class': 'zm-card' + (extOpen[v.id] && v.kind === 'proto' && st.installed ? ' zm-tg-wide' : '') + (st.installed && st.edit && editOpen[v.id] ? ' zm-tg-open' : ''), 'data-k': v.id }, [
					E('h3', {}, v.id === 'rust' && st.socks && st.socks.ok && st.socks.on ? 'Rust (MTProto + SOCKS5)' : v.title),
					E('div', { 'class': 'zm-row' }, [
						E('span', { 'class': 'zm-label' }, 'Статус'),
						st.installed ? zm.badge(st.running, 'запущен', st.uci && !st.enabled ? 'выключен в пакете' : 'остановлен') : zm.badge(false, '', 'не установлен')
					]),
					st.installed && st.version ? E('div', { 'class': 'zm-row' }, [
						E('span', { 'class': 'zm-label' }, 'Версия'), E('span', {}, [ st.version + (st.newer ? ' · доступна ' + st.latest : st.latest ? ' · последняя' : '') ])
					]) : E([]),
					st.installed ? E('div', { 'class': 'zm-row' }, [ E('span', { 'class': 'zm-label' }, 'Порт'), E('span', {}, [ String(st.port || v.port) ]) ]) : E([]),
					st.installed && hasArgs(v, st) && argsNorm(st.args) !== argsNorm(st.argsDef) ? E('div', { 'class': 'zm-row' }, [ E('span', { 'class': 'zm-label' }, 'Параметры'),
						E('span', { 'class': 'zm-tg-key', 'title': st.args || 'без параметров' }, [ st.args ? 'свои' : 'без параметров' ]) ]) : E([]),
					st.installed && st.secret ? E('div', { 'class': 'zm-row' }, [ E('span', { 'class': 'zm-label' }, 'Ключ'),
						zm.secretBox(E('span', { 'class': 'zm-tg-key' }, [ st.secret.length > 22 ? st.secret.slice(0, 10) + '…' + st.secret.slice(-8) : st.secret ]), st.secret) ]) : E([]),
					pkgNote || E([]),
					E('div', { 'class': 'zm-actions' }, actions),
					st.installed && st.edit && editOpen[v.id] ? editPanel(v, st) : E([]),
					st.installed && v.id === 'rust' && st.socks ? socksBlock(v, st) : E([]),
					st.installed && v.kind === 'proto' && st.ext ? extFold(v, st) : E([])
				]));
			});
			if (tgwsCard) cards.appendChild(tgwsCard);
			layoutCards();
		}

		function layoutCards() {
			var els = [], block = null, col = 0, n = 0;
			Array.prototype.forEach.call(cards.children, function(ch) {
				if (!ch.classList.contains('zm-tg-cols')) { els.push(ch); return; }
				var L = ch.children[0].children, R = ch.children[1].children, i;
				for (i = 0; i < Math.max(L.length, R.length); i++) { if (L[i]) els.push(L[i]); if (R[i]) els.push(R[i]); }
			});
			cards.innerHTML = '';
			els.forEach(function(el) {
				el.classList.remove('zm-tg-n1', 'zm-tg-n2', 'zm-tg-n3', 'zm-tg-n4');
				el.classList.add('zm-tg-n' + (n % 4 + 1));
				el.style.order = ''; el.style.minHeight = '';
				n++;
				if (el.classList.contains('zm-tg-wide')) { cards.appendChild(el); block = null; return; }
				if (!block) { block = E('div', { 'class': 'zm-tg-cols' }, [ E('div', { 'class': 'zm-tg-col' }), E('div', { 'class': 'zm-tg-col' }) ]); cards.appendChild(block); col = 0; }
				el.style.order = String(col);
				block.children[col % 2].appendChild(el);
				col++;
			});
		}

		function doAction(variantId, action) {
			if (busyMap[variantId]) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
			busyMap[variantId] = true;
			var job = action === 'remove' ? ('tg_remove_' + (variantId === 'mtproto' ? 'mtproto' : variantId))
				: ('tg_install_' + (variantId === 'mtproto' ? 'mtproto' : variantId));
			zm.toast((action === 'remove' ? 'Удаляем…' : /^reinstall/.test(action) ? 'Переустанавливаем…' : action === 'update' ? 'Обновляем…' : 'Устанавливаем…'), 'warning');
			zm.tgAction(variantId, action).then(function(res) {
				if (res.error) { busyMap[variantId] = false; zm.toast(res.error, 'error'); return; }
				if (res.started) {
					zm.pollJob(job, logEl, function(ok) {
						busyMap[variantId] = false;
						zm.toast(ok ? 'Готово' : 'Не получилось — причина в журнале ниже', ok ? 'info' : 'error');
						zm.tgStatus().then(function(d) { data = d; renderCards(d); renderLinks(d); renderAuto(); });
					});
				} else {
					busyMap[variantId] = false;
				}
			}).catch(function() { busyMap[variantId] = false; });
		}

		renderLinks(data);
		renderCards(data);
		wrap.appendChild(linksWrap);
		wrap.appendChild(cards);
		wrap.appendChild(logEl);

		var tgwsCard = E('div', { 'class': 'zm-card', 'data-k': 'tgws' });
		var tgwsBusy = false;

		function renderTgws(d) {
			var installed = d.installed === 'installed';
			var actions = [];
			if (installed) {
				actions.push(E('button', {
					'class': 'cbi-button cbi-button-remove',
					'click': function() {
						zm.dialog({ title: 'Удалить sTGWS?', danger: true, okText: 'Удалить sTGWS',
							blocks: [ { type: 'list', title: 'Что произойдёт', items: [
								'sTGWS остановится',
								'Пакет и все файлы удалятся — даже если менеджер пакетов откажется',
								'Telegram через этот прокси перестанет подключаться'
							] } ]
						}).then(function(v) { if (v) doTgwsAction('remove'); });
					}
				}, 'Удалить'));
				actions.push(E('button', {
					'class': 'cbi-button',
					'click': function() {
						zm.dialog({ title: 'Переустановить sTGWS?', okText: 'Переустановить',
							intro: 'Программа удалится и встанет заново с начальными настройками. Пока идёт переустановка, Telegram через sTGWS не подключится.',
							blocks: [ { type: 'note', text: 'Если нужен просто перезапуск — нажмите «Перезапустить».' } ]
						}).then(function(v) { if (v) doTgwsAction('reinstall'); });
					}
				}, 'Переустановить'));
				if (d.version && d.newer) {
					actions.push(E('button', {
						'class': 'cbi-button',
						'click': function() { doTgwsAction('update'); }
					}, 'Обновить до ' + d.latest));
				}
				actions.push(E('button', {
					'class': 'cbi-button',
					'click': function() { doTgwsAction('restart'); }
				}, 'Перезапустить'));
				actions.push(E('button', {
					'class': 'cbi-button',
					'click': function() { doTgwsAction('reconfigure'); }
				}, 'Подобрать новый домен'));
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
				}, d.smart_auto ? 'Авто-карта: вкл' : 'Авто-карта: выкл'));
			} else {
				actions.push(E('button', {
					'class': 'cbi-button cbi-button-positive',
					'click': function() { doTgwsAction('install'); }
				}, 'Установить'));
			}
			tgwsCard.innerHTML = '';
			tgwsCard.appendChild(E('h3', {}, 'sTGWS'));
			tgwsCard.appendChild(E('div', { 'class': 'zm-row' }, [
				E('span', { 'class': 'zm-label' }, 'Статус'),
				installed ? zm.badge(d.running === true, 'запущен', 'остановлен') : zm.badge(false, '', 'не установлен')
			]));
			if (installed && d.version) {
				tgwsCard.appendChild(E('div', { 'class': 'zm-row' }, [
					E('span', { 'class': 'zm-label' }, 'Версия'), E('span', {}, [ String(d.version) ])
				]));
			}
			if (installed && d.domain) {
				tgwsCard.appendChild(E('div', { 'class': 'zm-row' }, [
					E('span', { 'class': 'zm-label' }, 'Домен'), E('span', {}, [ String(d.domain) ])
				]));
			}
			tgwsCard.appendChild(E('div', { 'class': 'zm-actions' }, actions));
		}

		function doTgwsAction(action) {
			if (tgwsBusy) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
			tgwsBusy = true;
			var job = action === 'remove' ? 'tgws_remove'
				: action === 'restart' ? 'tgws_restart'
				: action === 'route_smart' ? 'tgws_route_smart'
				: action === 'reconfigure' ? 'tgws_reconfigure' : 'tgws_install';
			var label = action === 'remove' ? 'Удаляем sTGWS'
				: action === 'restart' ? 'Перезапускаем sTGWS'
				: action === 'route_smart' ? 'Перестраиваем карту sTGWS'
				: action === 'reconfigure' ? 'Подбираем новый домен sTGWS'
				: action === 'reinstall' ? 'Переустанавливаем sTGWS'
				: action === 'update' ? 'Обновляем sTGWS' : 'Устанавливаем sTGWS';
			zm.toast(label, 'warning');
			zm.tgwsAction(action).then(function(res) {
				if (res.error) { tgwsBusy = false; zm.toast(res.error, 'error'); return; }
				if (res.started) {
					zm.pollJob(job, logEl, function(ok) {
						tgwsBusy = false;
						zm.toast(ok ? 'Готово' : 'Не получилось — причина в журнале ниже', ok ? 'info' : 'error');
						zm.tgwsStatus().then(function(d) { tgwsData = d; renderTgws(d); return zm.tgStatus(); }).then(function(d) { if (d && !d.error) data = d; renderAuto(); });
					});
				} else {
					tgwsBusy = false;
					if (res.ok) {
						zm.toast('Готово', 'info');
						zm.tgwsStatus().then(function(d) { tgwsData = d; renderTgws(d); });
					}
				}
			}).catch(function() { tgwsBusy = false; });
		}

		renderTgws(tgwsData);
		cards.appendChild(tgwsCard);
		layoutCards();

		var autoCard = E('div', { 'class': 'zm-card' }), autoBusy = false;

		function autoSet(id, value, okText) {
			if (autoBusy) { zm.toast('Дождитесь окончания текущей операции', 'warning'); renderAuto(); return; }
			autoBusy = true;
			renderAuto();
			zm.tgAction(id, value).then(function(res) {
				autoBusy = false;
				if (!res || res.error) { zm.toast((res && res.error) || 'Роутер не ответил', 'error'); renderAuto(); return; }
				if (res.auto) data.auto = res.auto;
				zm.toast(okText, 'info');
				renderAuto();
			}).catch(function() { autoBusy = false; zm.toast('Роутер не ответил', 'error'); renderAuto(); });
		}

		function renderAuto() {
			var a = data.auto || {}, rows = [];
			var list = VARIANTS.map(function(v) { return { id: v.id, title: v.title, on: statusOf(data, v.id).installed }; });
			list.push({ id: 'tgws', title: 'sTGWS', on: tgwsData.installed === 'installed' });
			autoCard.innerHTML = '';
			autoCard.appendChild(E('h3', {}, 'Автоперезапуск'));
			list.filter(function(x) { return x.on; }).forEach(function(x) {
				var cur = a[x.id] || 'off', opts = AUTO_OPTS.slice();
				if (!opts.some(function(o) { return o[0] === cur; })) opts.push([ cur, /^d\d+$/.test(cur) ? 'в ' + ('0' + cur.slice(1)).slice(-2) + ':00' : /^m\d+$/.test(cur) ? cur.slice(1) + ' мин' : /^h\d+$/.test(cur) ? cur.slice(1) + ' ч' : cur ]);
				rows.push(E('div', { 'class': 'zm-row zm-tg-auto-row' }, [
					E('span', { 'class': 'zm-label' }, x.title),
					E('div', { 'class': 'zm-seg' + (autoBusy ? ' zm-seg-busy' : '') }, opts.map(function(o) {
						return E('div', { 'class': 'zm-seg-item' + (o[0] === cur ? ' zm-active' : ''), 'click': function() {
							if (o[0] === cur || autoBusy) return;
							autoSet(x.id, 'auto=' + o[0], o[0] === 'off' ? x.title + ': автоперезапуск выключен' : x.title + ': перезапуск каждые ' + o[1]);
						} }, o[1]);
					}))
				]));
			});
			if (!rows.length) {
				autoCard.appendChild(E('p', { 'class': 'zm-hint' }, 'Установите хотя бы один прокси — здесь можно будет настроить его перезапуск по расписанию.'));
				return;
			}
			autoCard.appendChild(E('p', { 'class': 'zm-hint' }, 'Для каждого прокси можно задать свой интервал. Перезапуск занимает пару секунд — Telegram переподключится сам.'));
			rows.forEach(function(r) { autoCard.appendChild(r); });
			autoCard.appendChild(zm.swRow(!!a.watch, 'Поднимать упавший прокси', 'Раз в 2 минуты панель проверяет установленные прокси и запускает заново тот, чей процесс перестал работать.', function() {
				autoSet('watch', a.watch ? 'off' : 'on', a.watch ? 'Проверка прокси выключена' : 'Упавший прокси будет запущен заново в течение 2 минут');
			}, autoBusy));
		}

		renderAuto();
		wrap.appendChild(autoCard);

		var restartBusy = false;
		wrap.appendChild(E('div', { 'class': 'zm-card' }, [
			E('h3', {}, 'Общие действия'),
			E('div', { 'class': 'zm-actions' }, [
				E('button', {
					'class': 'cbi-button',
					'click': function() {
						if (restartBusy) { zm.toast('Дождитесь завершения текущей операции', 'warning'); return; }
						restartBusy = true;
						zm.toast('Перезапускаем TG WS Proxy', 'warning');
						zm.tgRestartAll().then(function() {
							restartBusy = false;
							zm.toast('Все запущенные TG WS Proxy перезапущены', 'info');
							zm.tgwsStatus().then(function(d) { renderTgws(d); });
						}).catch(function() { restartBusy = false; });
					}
				}, 'Перезапустить все')
			])
		]));

		return wrap;
	}
});
