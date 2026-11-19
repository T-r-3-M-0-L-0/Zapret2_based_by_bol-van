'use strict';
'require view';
'require fs';
'require ui';
'require zapret-manager.common as zm';

/*
 * Универсальный рендерер манифест-плагинов Zapret Manager (SPA :7788).
 *
 * Маршрут плагина: view 'plugin', part = <id плагина>.
 * Манифест: /etc/zm-plugins/<id>/manifest.json
 * Backend:   /etc/zm-plugins/<id>/backend.sh <action> [args...] → JSON в stdout.
 *
 * Виджеты v1.1: status, table, button, log, form. См. PLUGIN_DEV.md.
 * После успешного button/form все auto-виджеты страницы обновляются сразу.
 */

var PLUG_DIR = '/etc/zm-plugins';

return view.extend({
	load: function() {
		zm.injectCss();
		var id = this.zmPart || '';
		if (!/^[a-z0-9-]+$/.test(id))
			return Promise.resolve({ error: 'Неизвестный идентификатор плагина' });
		return L.resolveDefault(fs.read(PLUG_DIR + '/' + id + '/manifest.json'), null).then(function(text) {
			if (!text) return { error: 'Манифест не найден: ' + id + ' (плагин не установлен?)' };
			try { return { id: id, manifest: JSON.parse(text) }; }
			catch (e) { return { error: 'Манифест повреждён: ' + e.message }; }
		});
	},

	render: function(data) {
		var view = this;
		var wrap = E('div', { 'class': 'zm-wrap' });
		if (!data || data.error) {
			wrap.appendChild(E('div', { 'class': 'zm-card' }, [
				E('h3', {}, 'Плагин'),
				E('p', {}, (data && data.error) || 'Ошибка загрузки')
			]));
			return wrap;
		}

		var id = data.id, m = data.manifest || {};
		var timers = [];
		var refreshers = []; // auto-виджеты; кнопки и формы дёргают их после действия

		function refreshAll() {
			refreshers.forEach(function(fn) {
				try { fn(); } catch (e) { /* виджет сам покажет ошибку */ }
			});
		}

		function runAction(action, args) {
			return fs.exec(PLUG_DIR + '/' + id + '/backend.sh', [ action ].concat(args || [])).then(function(res) {
				var j;
				try { j = JSON.parse(res.stdout || '{}'); }
				catch (e) { throw new Error('невалидный ответ backend: ' + String(res.stdout || res.stderr || '').slice(0, 200)); }
				if (j.error || j.ok === false) throw new Error(j.error || 'действие завершилось с ошибкой');
				return j;
			});
		}

		function auto(widget, el, fn) {
			fn();
			refreshers.push(fn);
			var sec = parseInt(widget.refresh, 10);
			if (sec > 0) {
				var t = setInterval(function() {
					if (!el.isConnected) { clearInterval(t); return; }
					fn();
				}, sec * 1000);
				timers.push(t);
			}
		}

		function wStatus(wd) {
			var body = E('div', {}, 'Загрузка…');
			auto(wd, body, function() {
				runAction(wd.action).then(function(j) {
					body.innerHTML = '';
					var d = j.data || {};
					var keys = Object.keys(d);
					if (!keys.length) { body.textContent = 'Нет данных'; return; }
					var t = E('table', { 'class': 'table' });
					keys.forEach(function(k) {
						t.appendChild(E('tr', {}, [ E('td', { 'style': 'font-weight:600' }, k), E('td', {}, String(d[k])) ]));
					});
					body.appendChild(t);
				}).catch(function(e) { body.textContent = 'Ошибка: ' + e.message; });
			});
			return E('div', { 'class': 'zm-card' }, [ E('h3', {}, wd.title || 'Статус'), body ]);
		}

		function wTable(wd) {
			var body = E('div', {}, 'Загрузка…');
			var cols = wd.columns || [];
			auto(wd, body, function() {
				runAction(wd.action).then(function(j) {
					body.innerHTML = '';
					var rows = j.rows || [];
					if (!rows.length) { body.textContent = 'Нет данных'; return; }
					var t = E('table', { 'class': 'table' });
					if (cols.length)
						t.appendChild(E('tr', { 'class': 'tr table-titles' }, cols.map(function(c) { return E('th', { 'class': 'th' }, c); })));
					rows.forEach(function(r) {
						t.appendChild(E('tr', {}, (Array.isArray(r) ? r : [ r ]).map(function(c) { return E('td', {}, String(c)); })));
					});
					body.appendChild(t);
				}).catch(function(e) { body.textContent = 'Ошибка: ' + e.message; });
			});
			return E('div', { 'class': 'zm-card' }, [ E('h3', {}, wd.title || 'Таблица'), body ]);
		}

		function wButton(wd) {
			var out = E('pre', { 'class': 'zp-log', 'style': 'max-height:180px;overflow:auto;display:none' });
			var label0 = wd.label || wd.action;
			var btn = E('button', { 'class': 'cbi-button ' + (wd.danger ? 'cbi-button-remove' : 'cbi-button-action'),
				'click': function() {
					btn.disabled = true; btn.textContent = 'Выполняется…';
					runAction(wd.action).then(function(j) {
						zm.toast(j.message || 'Готово', 'info');
						if (wd.output) { out.style.display = ''; out.textContent = j.log || JSON.stringify(j, null, 2); }
						refreshAll();
					}).catch(function(e) {
						zm.toast(e.message, 'error');
						if (wd.output) { out.style.display = ''; out.textContent = 'Ошибка: ' + e.message; }
					}).finally(function() { btn.disabled = false; btn.textContent = label0; });
				} }, label0);
			return E('div', { 'class': 'zm-card' }, [
				wd.title ? E('h3', {}, wd.title) : '',
				E('div', { 'class': 'zp-toolbar' }, [ btn ]),
				wd.desc ? E('div', { 'class': 'cbi-section-descr' }, wd.desc) : '',
				out
			]);
		}

		function wLog(wd) {
			var pre = E('pre', { 'class': 'zp-log', 'style': 'max-height:240px;overflow:auto' }, 'Загрузка…');
			auto(wd, pre, function() {
				runAction(wd.action).then(function(j) {
					pre.textContent = j.log || '(пусто)';
				}).catch(function(e) { pre.textContent = 'Ошибка: ' + e.message; });
			});
			return E('div', { 'class': 'zm-card' }, [ E('h3', {}, wd.title || 'Журнал'), pre ]);
		}

		/* Форма: поля → backend.sh <action> <знач1> <знач2> ...
		 * Поля: [{name, label, placeholder, password, required}] */
		function wForm(wd) {
			var out = E('pre', { 'class': 'zp-log', 'style': 'max-height:180px;overflow:auto;display:none' });
			var label0 = wd.label || 'Выполнить';
			var inputs = [];
			var grid = E('div', { 'style': 'display:grid;gap:8px;max-width:520px' });
			(wd.fields || []).forEach(function(f) {
				var inp = E('input', {
					'type': f.password ? 'password' : 'text',
					'class': 'cbi-input-text',
					'placeholder': f.placeholder || '',
					'style': 'width:100%'
				});
				inp.zmName = f.name || '';
				inp.zmRequired = !!f.required;
				inputs.push(inp);
				grid.appendChild(E('label', { 'style': 'display:grid;gap:4px' }, [
					E('span', { 'style': 'font-weight:600' }, (f.label || f.name || '?') + (f.required ? ' *' : '')),
					inp
				]));
			});
			var btn = E('button', { 'class': 'cbi-button ' + (wd.danger ? 'cbi-button-remove' : 'cbi-button-action'),
				'click': function() {
					var args = [];
					for (var i = 0; i < inputs.length; i++) {
						var v = String(inputs[i].value || '').trim();
						if (inputs[i].zmRequired && !v) { zm.toast('Заполните поле: ' + (inputs[i].zmName || inputs[i].placeholder), 'error'); return; }
						args.push(v);
					}
					btn.disabled = true; btn.textContent = 'Выполняется…';
					runAction(wd.action, args).then(function(j) {
						zm.toast(j.message || 'Готово', 'info');
						if (wd.output !== false) { out.style.display = ''; out.textContent = j.log || j.message || 'OK'; }
						inputs.forEach(function(inp) { inp.value = ''; });
						refreshAll();
					}).catch(function(e) {
						zm.toast(e.message, 'error');
						out.style.display = ''; out.textContent = 'Ошибка: ' + e.message;
					}).finally(function() { btn.disabled = false; btn.textContent = label0; });
				} }, label0);
			return E('div', { 'class': 'zm-card' }, [
				wd.title ? E('h3', {}, wd.title) : '',
				grid,
				E('div', { 'class': 'zp-toolbar', 'style': 'margin-top:8px' }, [ btn ]),
				wd.desc ? E('div', { 'class': 'cbi-section-descr' }, wd.desc) : '',
				out
			]);
		}

		var kinds = { status: wStatus, table: wTable, button: wButton, log: wLog, form: wForm };

		wrap.appendChild(E('h2', {}, (m.title || id) + (m.version ? ' · v' + m.version : '')));
		if (m.description)
			wrap.appendChild(E('div', { 'class': 'cbi-section-descr' }, m.description));

		var widgets = Array.isArray(m.widgets) ? m.widgets : [];
		if (!widgets.length)
			wrap.appendChild(E('div', { 'class': 'zm-card' }, 'В манифесте нет виджетов.'));
		widgets.forEach(function(wd) {
			var fn = kinds[wd.type];
			if (fn) wrap.appendChild(fn(wd));
			else wrap.appendChild(E('div', { 'class': 'zm-card' }, 'Неизвестный тип виджета: ' + wd.type));
		});

		return wrap;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
