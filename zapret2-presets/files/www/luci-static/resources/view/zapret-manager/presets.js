'use strict';
'require view';
'require uci';
'require fs';
'require rpc';
'require ui';
'require zapret-manager.common as zm';

/*
 * Zapret2 — конструктор стратегий и пресеты (страница Zapret-Manager).
 *
 * Конструктор: карточки стратегий из /etc/config/zapret2 (секции strategy),
 * клик — вкл/выкл в рабочем наборе, «Применить набор» пишет enabled в UCI
 * и перезапускает zapret2. «Проверить» запускает /etc/zapret2-presets/check.sh
 * (curl-пробы ключевых сервисов) и показывает результат чипами.
 *
 * Пресет = /etc/zapret2-presets/<имя>.txt: строки — имена стратегий,
 * строки с '# ' — описание.
 */

var PRESETS_DIR = '/etc/zapret2-presets';
var CHECK_SCRIPT = PRESETS_DIR + '/check.sh';
var SC_CTL = '/root/zapret2-tools/strategy-check-control.sh';

function scExec(args) {
	return fs.exec(SC_CTL, args).then(function(res) {
		var j;
		try { j = JSON.parse(res.stdout || '{}'); } catch (e) { j = null; }
		if (!j) throw new Error(res.stderr || 'пустой ответ от control-скрипта');
		if (j.error) throw new Error(j.error);
		return j;
	});
}

function parseTsv(text) {
	return (text || '').split('\n').filter(function(l) { return l.trim(); }).map(function(l) { return l.split('\t'); });
}

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

/* В SPA-режиме (панель :7788) shim uci.save() не коммитит на flash — коммитим явно. */
var callUciCommit = rpc.declare({
	object: 'uci',
	method: 'commit',
	params: [ 'config' ],
	expect: { result: false }
});

var CSS = `
.zp-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin:10px 0}
.zp-item{border:1px solid #555;border-radius:10px;padding:10px 12px;cursor:pointer;position:relative;transition:border-color .15s,background .15s}
.zp-item:hover{border-color:#999}
.zp-item.on{border-color:#2ea043;background:rgba(46,160,67,.12)}
.zp-item.dirty::after{content:'●';color:#e3b341;position:absolute;top:6px;right:10px}
.zp-item h4{margin:0 0 6px 0;font-size:13px;word-break:break-all}
.zp-badge{display:inline-block;font-size:11px;padding:1px 7px;border-radius:8px;background:#444;color:#ddd;margin:0 4px 4px 0}
.zp-badge.proto{background:#1f6feb33;color:#79c0ff}
.zp-group{margin:14px 0 4px 0;font-weight:600}
.zp-chip{display:inline-block;padding:4px 10px;border-radius:10px;margin:0 6px 6px 0;font-size:12px}
.zp-chip.ok{background:rgba(46,160,67,.18);color:#56d364}
.zp-chip.bad{background:rgba(248,81,73,.18);color:#ff7b72}
.zp-preset{border:1px solid #555;border-radius:10px;padding:12px;cursor:default}
.zp-preset.active{border-color:#2ea043}
.zp-toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}
.zp-chipz{max-height:180px;overflow:auto;border:1px solid #555;border-radius:8px;padding:8px;margin:8px 0}
.zp-chipz label{display:inline-flex;gap:4px;align-items:center;margin:0 10px 4px 0;font-size:12px;cursor:pointer}
.zp-score{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}
.zp-score td,.zp-score th{border-bottom:1px solid #444;padding:4px 8px;text-align:left}
.zp-log{max-height:160px;overflow:auto;font-size:11px;background:rgba(0,0,0,.25);border-radius:8px;padding:8px;margin-top:8px;white-space:pre-wrap;word-break:break-all}
.zp-sel{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:6px 0}
.zp-sel select,.zp-sel input{max-width:140px}
`;

function asList(v) {
	if (v == null) return [];
	return Array.isArray(v) ? v : [ String(v) ];
}

function parsePreset(text) {
	var desc = '', names = [];
	(text || '').split('\n').forEach(function(line) {
		line = line.trim();
		if (!line) return;
		if (line.charAt(0) === '#') {
			if (!desc) desc = line.replace(/^#+\s*/, '');
			return;
		}
		names.push(line);
	});
	return { desc: desc, names: names };
}

function familyOf(name) {
	if (/^fz/i.test(name)) return 'FZ — основной набор';
	if (/^Yv/i.test(name)) return 'YouTube — варианты';
	if (/^Youtube/i.test(name)) return 'YouTube';
	if (/^v\d+$/i.test(name)) return 'V-серия';
	if (/^games/i.test(name)) return 'Игры';
	if (/^discord/i.test(name)) return 'Discord';
	if (/^DoH/i.test(name)) return 'DoH';
	if (/circular/i.test(name)) return 'Circular';
	if (/^alt/i.test(name)) return 'ALT';
	return 'Прочие';
}

var FAMILY_ORDER = [ 'FZ — основной набор', 'YouTube', 'YouTube — варианты', 'Discord', 'Игры', 'DoH', 'V-серия', 'ALT', 'Circular', 'Прочие' ];

return view.extend({
	load: function() {
		zm.injectCss();
		return Promise.all([
			uci.load('zapret2'),
			L.resolveDefault(fs.list(PRESETS_DIR), [])
		]);
	},

	getStrategies: function() {
		return uci.sections('zapret2', 'strategy').map(function(s) {
			return {
				name: s['.name'],
				enabled: s.enabled === '1',
				protocol: asList(s.protocol).join(' ').toUpperCase(),
				port: asList(s.port).join(','),
				l7: asList(s.filter_l7).join(' '),
				hostlist: asList(s.hostlist).join(' ')
			};
		});
	},

	loadPresets: function(files) {
		var jobs = [];
		files.filter(function(f) { return f.type === 'file' && /\.txt$/.test(f.name); })
			.forEach(function(f) {
				jobs.push(L.resolveDefault(fs.read(PRESETS_DIR + '/' + f.name), '').then(function(text) {
					var p = parsePreset(text);
					p.id = f.name.replace(/\.txt$/, '');
					p.file = f.name;
					return p;
				}));
			});
		return Promise.all(jobs);
	},

	render: function(data) {
		var view = this;
		var strategies = this.getStrategies();
		var selected = {};
		strategies.forEach(function(s) { selected[s.name] = s.enabled; });
		var filterText = '';

		var wrap = E('div', { 'class': 'zm-wrap' });
		wrap.appendChild(E('style', {}, CSS));
		wrap.appendChild(E('h2', {}, 'Zapret2 — конструктор стратегий'));

		var statusEl = E('div', { 'class': 'cbi-section-descr', 'style': 'font-weight:600' });
		var checkEl = E('div', {});
		var cardsEl = E('div', {});
		var presetsEl = E('div', {});

		function sameSet(a, b) {
			if (a.length !== b.length) return false;
			var sa = a.slice().sort(), sb = b.slice().sort();
			for (var i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
			return true;
		}
		function selectedNames() {
			return strategies.filter(function(s) { return selected[s.name]; }).map(function(s) { return s.name; });
		}
		function enabledNames() {
			return strategies.filter(function(s) { return s.enabled; }).map(function(s) { return s.name; });
		}
		function updateStatus() {
			var sel = selectedNames().length;
			var dirty = strategies.some(function(s) { return selected[s.name] !== s.enabled; });
			statusEl.textContent = 'В наборе: ' + sel + ' из ' + strategies.length +
				' стратегий' + (dirty ? ' — есть неприменённые изменения' : ' (совпадает с активными)');
		}

		function renderCards() {
			cardsEl.innerHTML = '';
			var groups = {};
			strategies.forEach(function(s) {
				if (filterText && s.name.toLowerCase().indexOf(filterText) === -1) return;
				var g = familyOf(s.name);
				(groups[g] = groups[g] || []).push(s);
			});
			FAMILY_ORDER.forEach(function(g) {
				var list = groups[g];
				if (!list || !list.length) return;
				cardsEl.appendChild(E('div', { 'class': 'zp-group' }, g + ' (' + list.length + ')'));
				var grid = E('div', { 'class': 'zp-cards' });
				list.forEach(function(s) {
					var badges = [];
					if (s.protocol) badges.push(E('span', { 'class': 'zp-badge proto' }, s.protocol));
					if (s.port) badges.push(E('span', { 'class': 'zp-badge' }, ':' + s.port));
					if (s.l7) badges.push(E('span', { 'class': 'zp-badge' }, s.l7));
					if (s.hostlist) badges.push(E('span', { 'class': 'zp-badge' }, 'hostlist'));
					grid.appendChild(E('div', {
						'class': 'zp-item' + (selected[s.name] ? ' on' : '') + (selected[s.name] !== s.enabled ? ' dirty' : ''),
						'click': function() {
							selected[s.name] = !selected[s.name];
							renderCards();
							updateStatus();
						}
					}, [ E('h4', {}, s.name), E('div', {}, badges) ]));
				});
				cardsEl.appendChild(grid);
			});
		}

		function applySelection(names, label) {
			ui.showModal('Применяю…', [ E('p', { 'class': 'spinning' }, label || 'Записываю набор и перезапускаю zapret2') ]);
			strategies.forEach(function(s) {
				uci.set('zapret2', s.name, 'enabled', names.indexOf(s.name) !== -1 ? '1' : '0');
			});
			return uci.save()
				.then(function() { return uci.changes(); })
				.then(function() { return callUciCommit('zapret2'); })
				.then(function() { return callInitAction('zapret2', 'restart'); })
				.then(function() { uci.unload('zapret2'); return uci.load('zapret2'); })
				.then(function() {
					strategies = view.getStrategies();
					strategies.forEach(function(s) { selected[s.name] = s.enabled; });
					ui.hideModal();
					zm.toast('Набор применён, zapret2 перезапущен', 'info');
					renderCards(); updateStatus(); renderPresets();
				})
				.catch(function(e) {
					ui.hideModal();
					zm.toast('Ошибка: ' + (e && e.message ? e.message : e), 'error');
				});
		}

		function runCheck() {
			checkEl.innerHTML = '';
			checkEl.appendChild(E('p', { 'class': 'spinning' }, 'Проверяю сервисы (до ~10 секунд)…'));
			fs.exec(CHECK_SCRIPT).then(function(res) {
				checkEl.innerHTML = '';
				var arr;
				try { arr = JSON.parse(res.stdout || '[]'); } catch (e) { arr = null; }
				if (!arr) {
					checkEl.appendChild(E('p', {}, 'Не удалось разобрать ответ проверки: ' + (res.stdout || res.stderr || 'пусто')));
					return;
				}
				var box = E('div', { 'style': 'margin:8px 0' });
				arr.forEach(function(r) {
					box.appendChild(E('span', { 'class': 'zp-chip ' + (r.ok ? 'ok' : 'bad') },
						r.name + ': ' + (r.ok ? 'OK (' + r.code + ', ' + Number(r.time).toFixed(1) + 's)' : 'недоступен')));
				});
				checkEl.appendChild(box);
			}).catch(function(e) {
				checkEl.innerHTML = '';
				checkEl.appendChild(E('p', {}, 'Проверка не запустилась: ' + e));
			});
		}

		function renderPresets() {
			presetsEl.innerHTML = '';
			L.resolveDefault(fs.list(PRESETS_DIR), []).then(function(fl) {
				return view.loadPresets(Array.isArray(fl) ? fl : []);
			}).then(function(presets) {
				var grid = E('div', { 'class': 'zp-cards' });
				var cur = enabledNames();
				if (!presets.length)
					grid.appendChild(E('div', {}, 'Пресетов нет — сохраните текущий набор ниже.'));
				presets.forEach(function(p) {
					var active = sameSet(cur, p.names);
					grid.appendChild(E('div', { 'class': 'zp-preset' + (active ? ' active' : '') }, [
						E('h4', { 'style': 'margin:0 0 4px 0' }, p.id + (active ? '  ✓ активен' : '')),
						E('div', { 'class': 'cbi-section-descr' }, p.desc || '—'),
						E('div', { 'style': 'margin:6px 0' }, 'Стратегий: ' + p.names.length),
						E('div', {}, [
							E('button', { 'class': 'cbi-button cbi-button-apply', 'click': function() {
								zm.dialog({ title: 'Применить пресет?', okText: 'Применить',
									blocks: [ { type: 'note', text: '«' + p.id + '»: ' + p.names.length + ' стратегий, остальные будут выключены, zapret2 перезапустится.' } ]
								}).then(function(v) { if (v) applySelection(p.names, 'Применяю пресет «' + p.id + '»…'); });
							} }, 'Применить'),
							' ',
							E('button', { 'class': 'cbi-button cbi-button-remove', 'click': function() {
								zm.dialog({ title: 'Удалить пресет?', danger: true, okText: 'Удалить',
									blocks: [ { type: 'note', text: '«' + p.id + '» будет удалён безвозвратно.' } ]
								}).then(function(v) {
									if (!v) return;
									fs.remove(PRESETS_DIR + '/' + p.file).then(renderPresets).catch(function(e) {
										zm.toast('Не удалось удалить: ' + e, 'error');
									});
								});
							} }, 'Удалить')
						])
					]));
				});
				presetsEl.appendChild(grid);
			});
		}

		// --- панель инструментов ---
		var search = E('input', { 'type': 'text', 'placeholder': 'поиск по имени…', 'style': 'width:200px',
			'input': function() { filterText = search.value.trim().toLowerCase(); renderCards(); } });
		var applyBtn = E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() {
			var n = selectedNames();
			zm.dialog({ title: 'Применить набор?', okText: 'Применить',
				blocks: [ { type: 'note', text: n.length + ' стратегий будет включено, остальные выключены, zapret2 перезапустится.' } ]
			}).then(function(v) { if (v) applySelection(n); });
		} }, 'Применить набор');
		var resetBtn = E('button', { 'class': 'cbi-button', 'click': function() {
			strategies.forEach(function(s) { selected[s.name] = s.enabled; });
			renderCards(); updateStatus();
		} }, 'Сбросить');
		var checkBtn = E('button', { 'class': 'cbi-button cbi-button-action', 'click': runCheck }, 'Проверить');

		// --- сохранение пресета ---
		var nameInput = E('input', { 'type': 'text', 'placeholder': 'имя-пресета', 'style': 'width:180px' });
		var descInput = E('input', { 'type': 'text', 'placeholder': 'описание (необязательно)', 'style': 'width:260px' });
		var saveBtn = E('button', { 'class': 'cbi-button cbi-button-add', 'click': function() {
			var id = nameInput.value.trim().replace(/[^a-zA-Z0-9_-]/g, '-');
			if (!id) { zm.toast('Укажите имя пресета (латиница, цифры, - и _)', 'warning'); return; }
			var names = selectedNames();
			var body = (descInput.value.trim() ? '# ' + descInput.value.trim() + '\n' : '') + names.join('\n') + '\n';
			fs.write(PRESETS_DIR + '/' + id + '.txt', body).then(function() {
				zm.toast('Пресет «' + id + '» сохранён (' + names.length + ' стратегий)', 'info');
				nameInput.value = ''; descInput.value = '';
				renderPresets();
			}).catch(function(e) {
				zm.toast('Не удалось сохранить: ' + e, 'error');
			});
		} }, 'Сохранить набор как пресет');

		// --- сравнение стратегий ---
		var scCatalog = null, scTimer = null, scBusy = false;
		var scStatusEl = E('div', {});
		var scChipsEl = E('div', { 'class': 'zp-chipz' }, 'Загружаю каталог стратегий…');
		var scChecked = {};

		function scRenderScores(st) {
			var rows = parseTsv(st.scores);
			if (rows.length < 2) return null;
			var table = E('table', { 'class': 'zp-score' }, [
				E('tr', {}, [ E('th', {}, 'Стратегия'), E('th', {}, 'Прошло'), E('th', {}, 'Всего'), E('th', {}, ''), ])
			]);
			rows.slice(1).sort(function(a, b) { return (b[1] / (b[2] || 1)) - (a[1] / (a[2] || 1)); }).forEach(function(r) {
				var name = r[0], ok = r[1], total = r[2];
				table.appendChild(E('tr', {}, [
					E('td', {}, name),
					E('td', { 'style': 'color:' + (ok === total && total !== '0' ? '#56d364' : ok === '0' ? '#ff7b72' : '#e3b341') }, ok),
					E('td', {}, total),
					E('td', {}, E('button', { 'class': 'cbi-button cbi-button-neutral', 'style': 'padding:1px 8px;font-size:11px',
						'click': function() {
							if (strategies.some(function(s) { return s.name === name; })) {
								selected[name] = true;
								renderCards(); updateStatus();
								zm.toast('«' + name + '» добавлена в набор (не забудьте «Применить набор»)', 'info');
							} else {
								zm.toast('Стратегии «' + name + '» нет в конфиге', 'warning');
							}
						} }, '+ В набор'))
				]));
			});
			return table;
		}

		function scStateText(st) {
			var map = { idle: 'простаивает', preparing: 'подготовка…', running: 'идёт проверка…', restoring: 'восстановление службы…',
				finished: 'завершено', failed: 'ошибка', stopped: 'остановлено', interrupted: 'прервано', recovery_required: 'требуется восстановление службы' };
			return map[st.state] || st.state || 'нет данных';
		}

		function scPoll() {
			scExec([ 'status' ]).then(function(st) {
				scStatusEl.innerHTML = '';
				scStatusEl.appendChild(E('div', {}, 'Состояние: ' + scStateText(st) + (st.exit_code ? ' (код ' + st.exit_code + ')' : '')));
				var table = scRenderScores(st);
				if (table) scStatusEl.appendChild(table);
				if (st.log) scStatusEl.appendChild(E('pre', { 'class': 'zp-log' }, st.log));
				if (st.state === 'recovery_required') {
					scStatusEl.appendChild(E('button', { 'class': 'cbi-button cbi-button-negative', 'style': 'margin-top:8px',
						'click': function() { scExec([ 'recover' ]).then(scPoll).catch(function(e) { zm.toast(e.message, 'error'); }); }
					}, 'Восстановить zapret2'));
				}
				if (String(st.running) === '1' || st.running === true || st.state === 'running' || st.state === 'preparing' || st.state === 'restoring') {
					scBusy = true;
					scTimer = setTimeout(scPoll, 2000);
				} else {
					scBusy = false;
					scTimer = null;
				}
			}).catch(function(e) {
				scStatusEl.innerHTML = '';
				scStatusEl.appendChild(E('p', {}, 'Статус недоступен: ' + e.message));
				scBusy = false;
			});
		}

		function scLoadCatalog() {
			scExec([ 'catalog' ]).then(function(cat) {
				scCatalog = cat;
				scChipsEl.innerHTML = '';
				var sel = selectedNames();
				parseTsv(cat.profiles).slice(1).forEach(function(row) {
					var name = row[0];
					if (!name) return;
					if (scChecked[name] === undefined) scChecked[name] = sel.indexOf(name) !== -1;
					var cb = E('input', { 'type': 'checkbox', 'change': function() { scChecked[name] = cb.checked; } });
					if (scChecked[name]) cb.setAttribute('checked', '');
					cb.checked = !!scChecked[name];
					scChipsEl.appendChild(E('label', {}, [ cb, name ]));
				});
				var lists = parseTsv(cat.lists).slice(1).map(function(r) { return r[1]; }).filter(Boolean);
				listSel.innerHTML = '';
				listSel.appendChild(E('option', { 'value': 'all' }, 'Все списки'));
				lists.forEach(function(n) { listSel.appendChild(E('option', { 'value': n }, n)); });
				if (cat.http3) modeSel.appendChild(E('option', { 'value': 'quic' }, 'QUIC/HTTP3'));
			}).catch(function(e) {
				scChipsEl.textContent = 'Каталог недоступен: ' + e.message;
			});
		}

		var modeSel = E('select', {}, [
			E('option', { 'value': 'tls13' }, 'TLS 1.3'),
			E('option', { 'value': 'tls12' }, 'TLS 1.2'),
			E('option', { 'value': 'http' }, 'HTTP')
		]);
		var listSel = E('select', {}, [ E('option', { 'value': 'all' }, 'Все списки') ]);
		var repeatsIn = E('input', { 'type': 'number', 'min': '1', 'max': '5', 'value': '1', 'title': 'Повторы' });
		var timeoutIn = E('input', { 'type': 'number', 'min': '2', 'max': '30', 'value': '8', 'title': 'Тайм-аут, сек' });
		var limitIn = E('input', { 'type': 'number', 'min': '1', 'max': '10000', 'value': '50', 'title': 'Доменов на список' });
		var reqSel = E('select', {}, [ E('option', { 'value': 'head' }, 'HEAD'), E('option', { 'value': 'get' }, 'GET') ]);

		var startBtn = E('button', { 'class': 'cbi-button cbi-button-positive', 'click': function() {
			var chosen = Object.keys(scChecked).filter(function(k) { return scChecked[k]; });
			if (!scCatalog) { zm.toast('Каталог ещё не загружен', 'warning'); return; }
			if (!chosen.length) { zm.toast('Отметьте хотя бы одну стратегию для сравнения', 'warning'); return; }
			zm.dialog({ title: 'Запустить сравнение?', okText: 'Запустить',
				blocks: [ { type: 'note', text: 'Стратегий: ' + chosen.length + '. На время прогона основной zapret2 приостанавливается.' } ]
			}).then(function(v) {
				if (!v) return;
				scExec([ 'start', chosen.join(','), listSel.value, modeSel.value,
					repeatsIn.value || '1', limitIn.value || '50', timeoutIn.value || '8', reqSel.value ])
					.then(function() { zm.toast('Проверка запущена', 'info'); scPoll(); })
					.catch(function(e) { zm.toast(e.message, 'error'); scPoll(); });
			});
		} }, 'Запустить сравнение');
		var stopBtn = E('button', { 'class': 'cbi-button cbi-button-remove', 'click': function() {
			scExec([ 'stop' ]).then(function() { zm.toast('Останавливаю…', 'info'); setTimeout(scPoll, 1500); })
				.catch(function(e) { zm.toast(e.message, 'error'); });
		} }, 'Остановить');
		var refreshBtn = E('button', { 'class': 'cbi-button', 'click': scPoll }, 'Обновить статус');

		var compareCard = E('div', { 'class': 'zm-card' }, [
			E('h3', {}, 'Сравнение стратегий'),
			E('div', { 'class': 'cbi-section-descr' },
				'Прогон выбранных стратегий по спискам доменов с замером доступности (движок strategy-check). Отмеченные по умолчанию — стратегии из рабочего набора конструктора. По итогам каждую стратегию можно добавить в набор кнопкой «+ В набор».'),
			E('div', { 'class': 'zp-sel' }, [
				E('span', {}, 'Протокол:'), modeSel,
				E('span', {}, 'Списки:'), listSel,
				E('span', {}, 'Повторы:'), repeatsIn,
				E('span', {}, 'Тайм-аут:'), timeoutIn,
				E('span', {}, 'Доменов:'), limitIn,
				E('span', {}, 'Метод:'), reqSel
			]),
			scChipsEl,
			E('div', { 'class': 'zp-toolbar' }, [ startBtn, stopBtn, refreshBtn ]),
			scStatusEl
		]);

		// --- автопроверка по расписанию (cron healthcheck) ---
		var cronStatusEl = E('div', {});
		var cronOnCb = E('input', { 'type': 'checkbox' });
		var cronApCb = E('input', { 'type': 'checkbox' });
		var cronCdIn = E('input', { 'type': 'number', 'min': '1', 'max': '168', 'style': 'width:80px' });
		var cronCapIn = E('input', { 'type': 'number', 'min': '0', 'max': '20', 'style': 'width:80px' });

		function cronLoad() {
			scExec([ 'cronstatus' ]).then(function(st) {
				cronStatusEl.innerHTML = '';
				if (!st.installed) {
					cronStatusEl.appendChild(E('p', {}, 'healthcheck.sh не установлен (пакет strategy-check) — автопроверка недоступна.'));
					return;
				}
				cronOnCb.checked = !!st.cron_enabled;
				cronApCb.checked = !!st.autopromote;
				cronCdIn.value = String(Math.round((st.cooldown || 21600) / 3600));
				cronCapIn.value = String(st.promote_cap != null ? st.promote_cap : 3);
				cronStatusEl.appendChild(E('div', {},
					'Сейчас: расписание ' + (st.cron_enabled ? 'включено (каждый час)' : 'ВЫКЛЮЧЕНО') +
					', автоприменение ' + (st.autopromote ? 'включено' : 'выключено') +
					', кулдаун ' + Math.round((st.cooldown || 0) / 3600) + ' ч' +
					', лимит ' + (st.promote_cap != null ? st.promote_cap : 3) +
					(st.running ? ' — прямо сейчас идёт проверка' : '')));
				if (st.health_log) cronStatusEl.appendChild(E('pre', { 'class': 'zp-log' }, '— журнал проверок —\n' + st.health_log));
				if (st.autotest_log) cronStatusEl.appendChild(E('pre', { 'class': 'zp-log' }, '— журнал автоподбора —\n' + st.autotest_log));
			}).catch(function(e) {
				cronStatusEl.innerHTML = '';
				cronStatusEl.appendChild(E('p', {}, 'Статус расписания недоступен: ' + e.message));
			});
		}

		var cronSaveBtn = E('button', { 'class': 'cbi-button cbi-button-apply', 'click': function() {
			var cdh = parseInt(cronCdIn.value, 10), cap = parseInt(cronCapIn.value, 10);
			if (!(cdh >= 1 && cdh <= 168)) { zm.toast('Кулдаун: от 1 до 168 часов', 'warning'); return; }
			if (!(cap >= 0 && cap <= 20)) { zm.toast('Лимит автоприменений: от 0 до 20', 'warning'); return; }
			scExec([ 'cronset', cronOnCb.checked ? '1' : '0', cronApCb.checked ? '1' : '0', String(cdh), String(cap) ])
				.then(function() { zm.toast('Настройки расписания сохранены', 'info'); cronLoad(); })
				.catch(function(e) { zm.toast(e.message, 'error'); });
		} }, 'Сохранить');
		var cronRunBtn = E('button', { 'class': 'cbi-button cbi-button-action', 'click': function() {
			scExec([ 'cronrun' ])
				.then(function() { zm.toast('Проверка запущена в фоне', 'info'); setTimeout(cronLoad, 3000); })
				.catch(function(e) { zm.toast(e.message, 'error'); });
		} }, 'Проверить сейчас');

		var cronCard = E('div', { 'class': 'zm-card' }, [
			E('h3', {}, 'Автопроверка по расписанию'),
			E('div', { 'class': 'cbi-section-descr' }, [
				E('p', {}, 'Фоновая проверка healthcheck: раз в час (в :17) с роутера проверяются ключевые сайты. Если текущая стратегия перестала работать — запускается автоподбор по кандидатам.'),
				E('p', {}, [
					E('b', {}, 'Автоприменение'), ' — найденная лучшая стратегия применяется сама, без вас. ',
					E('b', {}, 'Кулдаун'), ' — минимальный перерыв между автоприменениями (часы), чтобы не дёргать службу зря. ',
					E('b', {}, 'Лимит'), ' — максимум автоприменений подряд, защита от бесконечных переключений.'
				])
			]),
			E('div', { 'class': 'zp-sel' }, [
				E('label', {}, [ cronOnCb, ' Проверка по расписанию' ]),
				E('label', {}, [ cronApCb, ' Автоприменение' ]),
				E('span', {}, 'Кулдаун, ч:'), cronCdIn,
				E('span', {}, 'Лимит:'), cronCapIn,
				cronSaveBtn, cronRunBtn
			]),
			cronStatusEl
		]);

		wrap.appendChild(E('div', { 'class': 'zm-card' }, [
			E('h3', {}, 'Конструктор'),
			E('div', { 'class': 'cbi-section-descr' },
				'Клик по карточке включает/выключает стратегию в рабочем наборе. «Применить набор» записывает его и перезапускает zapret2. «Проверить» прогоняет пробы ключевых сервисов с роутера.'),
			statusEl,
			E('div', { 'class': 'zp-toolbar' }, [ search, applyBtn, resetBtn, checkBtn ]),
			checkEl,
			cardsEl
		]));
		wrap.appendChild(compareCard);
		wrap.appendChild(cronCard);
		wrap.appendChild(E('div', { 'class': 'zm-card' }, [
			E('h3', {}, 'Пресеты'),
			presetsEl,
			E('div', { 'class': 'zp-toolbar', 'style': 'margin-top:10px' }, [ nameInput, descInput, saveBtn ])
		]));

		renderCards();
		updateStatus();
		renderPresets();
		scLoadCatalog();
		scPoll();
		cronLoad();
		return wrap;
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
