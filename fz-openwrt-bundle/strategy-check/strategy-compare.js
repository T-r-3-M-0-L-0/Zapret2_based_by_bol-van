'use strict';
'require baseclass';
'require form';
'require fs';
'require ui';
'require poll';

var CONTROL = '/root/zapret2-tools/strategy-check-control.sh';
var activePoll = null;
var labels = {
    PASS: 'Доступен, Lua сработал', HTTP_OK: 'Доступен без обхода',
    FAIL: 'Ошибка запроса', HTTP_RESPONSE: 'HTTP 4xx/5xx — нужен конкретный URL',
    NO_ACTION: 'Lua-действие не выполнялось', DNS_ERROR: 'Ошибка DNS',
    STRATEGY_ERROR: 'Ошибка стратегии', START_ERROR: 'Ошибка запуска',
    SKIP_PROTOCOL: 'Другой транспорт', ALL_PASS: 'Все домены прошли',
    ALL_PASS_SAMPLE: 'Вся выборка прошла', PARTIAL: 'Частичный результат',
    INCONCLUSIVE: 'Неопределённый результат', INCOMPLETE: 'Проверка не завершена',
    CHECK_ERROR: 'Ошибка компиляции', ERROR: 'Ошибка стратегии',
    EMPTY: 'Пустой список', MISSING: 'Файл списка отсутствует', READ_ERROR: 'Ошибка чтения'
};

function parseTSV(text) {
    var lines = String(text || '').trim().split('\n');
    if (!lines[0]) return [];
    var headers = lines.shift().replace(/\r$/, '').split('\t');
    return lines.filter(Boolean).map(function(line) {
        var cells = line.replace(/\r$/, '').split('\t');
        var row = {};
        headers.forEach(function(key, index) { row[key] = cells[index] || ''; });
        return row;
    });
}

function call(action, args) {
    return fs.exec(CONTROL, [action].concat(args || [])).then(function(result) {
        var data;
        try { data = JSON.parse(result.stdout || '{}'); }
        catch (error) { throw new Error(result.stderr || 'Не удалось прочитать ответ проверяющего скрипта'); }
        if (data.error || result.code !== 0)
            throw new Error(data.error || result.stderr || 'Ошибка проверки');
        return data;
    });
}

function download(name, text) {
    var url = URL.createObjectURL(new Blob([text], { type: 'text/tab-separated-values;charset=utf-8' }));
    var link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
}

function selectedValues(select) {
    return Array.prototype.filter.call(select.options, function(option) {
        return option.selected;
    }).map(function(option) { return option.value; });
}

function replace(node, children) {
    while (node.firstChild) node.removeChild(node.firstChild);
    children.forEach(function(child) { node.appendChild(child); });
}

function field(title, input, description) {
    return E('div', { style: 'margin:0 0 14px;min-width:210px;flex:1' }, [
        E('label', { 'for': input.id || '', style: 'display:block;font-weight:600;margin-bottom:6px' }, title),
        input,
        description ? E('small', { style: 'display:block;opacity:.75;margin-top:4px' }, description) : E('span')
    ]);
}

function renderPanel() {
    var root = E('div');
    var status = E('p', { id: 'sc-status' }, 'Загрузка проверки стратегий…');
    var resultsNode = E('div');
    var progressNode = E('div', { id: 'sc-progress', style: 'margin:12px 0' });
    var logNode = E('pre', { style: 'white-space:pre-wrap;max-height:220px;overflow:auto;font-size:11px' });
    var lastStatus = {};
    var busy = false;
    var launching = false;
    var requestEpoch = 0;
    var expectedReport = '';
    var startButton, stopButton, recoverButton, refreshButton, exportButton;
    var profilesSelect = E('select', { id: 'sc-profiles', multiple: true, size: 7, style: 'width:100%' });
    var listsSelect = E('select', { id: 'sc-lists', multiple: true, size: 7, style: 'width:100%' });
    var allProfiles = E('input', { id: 'sc-all-profiles', type: 'checkbox', checked: true });
    var allLists = E('input', { id: 'sc-all-lists', type: 'checkbox' });
    var protocol = E('select', { id: 'sc-mode', style: 'width:100%' }, [
        E('option', { value: 'tls13' }, 'TLS 1.3 / TCP'),
        E('option', { value: 'tls12' }, 'TLS 1.2 / TCP'),
        E('option', { value: 'http' }, 'HTTP / TCP'),
        E('option', { value: 'quic' }, 'QUIC / HTTP3')
    ]);
    var request = E('select', { id: 'sc-request', style: 'width:100%' }, [
        E('option', { value: 'get' }, 'GET, до 64 КиБ — как в Zapret Manager'),
        E('option', { value: 'head' }, 'HEAD — короткая проверка HTTP/TLS')
    ]);
    var limit = E('input', { id: 'sc-limit', type: 'number', min: 0, max: 10000, value: 5, style: 'width:100%' });
    var repeats = E('input', { id: 'sc-repeats', type: 'number', min: 1, max: 5, value: 1, style: 'width:100%' });
    var timeout = E('input', { id: 'sc-timeout', type: 'number', min: 2, max: 30, value: 6, style: 'width:100%' });

    function fail(error) {
        ui.addNotification(null, E('p', {}, error.message || String(error)), 'error');
    }

    function setButtons(running) {
        running = running || launching;
        busy = running;
        startButton.disabled = running;
        stopButton.disabled = launching || !running;
        refreshButton.disabled = running;
        profilesSelect.disabled = running || allProfiles.checked;
        listsSelect.disabled = running || allLists.checked;
        [allProfiles, allLists, protocol, request, limit, repeats, timeout].forEach(function(node) {
            node.disabled = running;
        });
        exportButton.disabled = !lastStatus.results;
        recoverButton.style.display = lastStatus.state === 'recovery_required' ? '' : 'none';
    }

    allProfiles.onchange = function() { setButtons(busy); };
    allLists.onchange = function() { setButtons(busy); };

    function showDetails(profile, list) {
        return call('details', [profile, list]).then(function(data) {
            var rows = parseTSV(data.rows);
            var body = E('tbody');
            rows.forEach(function(row) {
                body.appendChild(E('tr', {}, [
                    E('td', {}, row.domain), E('td', {}, row.attempt),
                    E('td', {}, labels[row.result] || row.result),
                    E('td', {}, row.curl_rc), E('td', {}, row.http_code),
                    E('td', {}, row.bytes), E('td', {}, row.seconds),
                    E('td', {}, !row.route || row.route === 'unknown' ? 'Не подтверждён' :
                        row.route === '-' ? '—' : row.route.replace(/^dev\//, 'Через '))
                ]));
            });
            ui.showModal(profile === 'baseline' ? 'Контрольный тест' : profile, [
                E('p', {}, list),
                E('div', { style: 'overflow:auto;max-height:60vh' }, [
                    E('table', { class: 'table' }, [
                        E('thead', {}, [E('tr', {}, ['Домен', 'Попытка', 'Результат', 'curl', 'HTTP', 'Байты', 'Секунды', 'Маршрут'].map(function(text) {
                            return E('th', {}, text);
                        }))]), body
                    ])
                ]),
                rows.length ? E('span') : E('p', {}, 'Для этой пары ещё нет завершённых запросов.'),
                E('div', { class: 'right' }, [
                    E('button', { type: 'button', class: 'btn', click: function() { download('zapret2-domains.tsv', data.rows); } }, 'Скачать TSV'),
                    ' ', E('button', { type: 'button', class: 'btn cbi-button-neutral', click: ui.hideModal }, 'Закрыть')
                ])
            ]);
        }).catch(fail);
    }

    function promote(name) {
        if (!confirm('Включить стратегию «' + name + '» в активной конфигурации и перезапустить zapret2?')) return;
        return call('promote', [name]).then(function(res) {
            if (res.error) throw new Error(res.error);
            ui.addNotification(null, E('p', {}, 'Стратегия «' + name + '» включена. Служба: ' +
                (res.running ? 'работает' : 'НЕ РАБОТАЕТ') + '. Резервная копия: ' + res.backup),
                res.running ? 'info' : 'warning');
            return refreshStatus();
        }).catch(fail);
    }

    function renderResults(data) {
        var listRows = parseTSV(data.results);
        var scores = {};
        parseTSV(data.scores).forEach(function(row) { scores[row.profile] = row; });
        var listNames = parseTSV(data.lists).map(function(row) { return row.list; });
        var grouped = {};
        listRows.forEach(function(row) {
            if (!grouped[row.profile]) grouped[row.profile] = {};
            grouped[row.profile][row.list] = row;
        });
        if (!listRows.length) {
            replace(resultsNode, [E('p', {}, data.running ? 'Сводная таблица появится после первого обработанного домена.' : 'Запустите проверку, чтобы получить сводную таблицу.')]);
            return;
        }
        var names = Object.keys(grouped).filter(function(name) { return name !== 'baseline'; });
        names.sort(function(a, b) {
            var diff = +((scores[b] || {}).pass || 0) - +((scores[a] || {}).pass || 0);
            return diff || a.localeCompare(b);
        });
        if (grouped.baseline) names.unshift('baseline');
        var head = E('tr', {}, ['Стратегия', 'Итого по уникальным доменам', 'К контролю'].concat(listNames).map(function(name) {
            return E('th', {}, name);
        }));
        var body = E('tbody');
        names.forEach(function(name) {
            var score = scores[name] || { pass: 0, tested: 0 };
            var controlScore = scores.baseline || { pass: 0 };
            var delta = +score.pass - +controlScore.pass;
            var row = E('tr', { style: name === 'baseline' ? 'background:rgba(60,140,200,.12)' : '' }, [
                E('td', { style: 'font-weight:600;white-space:nowrap' }, name === 'baseline' ? 'Контрольный тест — без обхода' : [
                    name, ' ',
                    E('button', { type: 'button', class: 'btn',
                        style: 'padding:0 6px;font-size:11px',
                        title: 'Включить в активной конфигурации и перезапустить службу',
                        click: function() { return promote(name); }
                    }, 'Применить')
                ]),
                E('td', {}, score.pass + '/' + score.tested),
                E('td', {}, name === 'baseline' ? '—' :
                    (+score.tested === +controlScore.tested && +score.tested > 0 ? (delta > 0 ? '+' : '') + delta : '…'))
            ]);
            listNames.forEach(function(list) {
                var cell = grouped[name][list];
                if (!cell) { row.appendChild(E('td', {}, '…')); return; }
                var coverage = cell.coverage.split('/');
                var total = +coverage[1];
                var control = (grouped.baseline || {})[list];
                var color = '#6b7280';
                if (/^ALL_PASS/.test(cell.verdict)) color = '#16803b';
                else if (control && +cell.pass > +control.pass) color = '#b77900';
                else if (cell.verdict === 'FAIL' || cell.verdict === 'ERROR' || cell.verdict === 'CHECK_ERROR') color = '#c62f3c';
                var title = (labels[cell.verdict] || cell.verdict) + '\nПокрытие: ' + cell.coverage +
                    '\nНестабильные: ' + cell.unstable + ', DNS: ' + cell.dns_error + ', HTTP 4xx/5xx: ' + cell.http_response;
                row.appendChild(E('td', {}, [E('button', { type: 'button',
                    class: 'btn', title: title,
                    style: 'color:' + color + ';font-weight:700;white-space:nowrap',
                    click: function() { return showDetails(name, list); }
                }, cell.pass + '/' + total + (cell.verdict === 'INCOMPLETE' ? ' …' : ''))]));
            });
            body.appendChild(row);
        });
        replace(resultsNode, [
            E('p', {}, 'Зелёный — вся выборка прошла, жёлтый — успешных доменов больше, чем без обхода. Нажмите ячейку для результатов по доменам. «Итого» учитывает каждый домен один раз.'),
            E('div', { style: 'overflow:auto;max-height:70vh' }, [E('table', { class: 'table' }, [E('thead', {}, [head]), body])])
        ]);
    }

    function refreshStatus() {
        var epoch = requestEpoch;
        return call('status').then(function(data) {
            if (launching || epoch !== requestEpoch) return;
            if (expectedReport && data.report !== expectedReport) return;
            expectedReport = '';
            lastStatus = data;
            var phases = { compile: 'Подготовка стратегии', dns: 'Разрешение домена', baseline: 'Контрольный тест', test: 'Проверка стратегии', finished: 'Запросы завершены' };
            var states = { idle: 'Ожидание запуска', preparing: 'Подготовка', running: 'Идёт проверка', restoring: 'Восстановление службы', finished: 'Завершено', stopped: 'Остановлено', failed: 'Завершилось с ошибкой', interrupted: 'Прервано', recovery_required: 'Требуется восстановить службу' };
            var progress = String(data.progress || '').trim().split('\t');
            status.textContent = (states[data.state] || data.state) + (data.mode ? ' · ' + data.mode.toUpperCase() + ' · ' + String(data.request || '').toUpperCase() : '');
            var description = [];
            if (data.running && progress[0]) description.push((phases[progress[0]] || progress[0]) + ': ' + (progress[1] || progress[2] || ''));
            if (+progress[4] > 0) description.push('Домен ' + progress[3] + '/' + progress[4] + (progress[2] ? ' — ' + progress[2] : ''));
            if (data.started) description.push('Прошло ' + Math.max(0, Math.floor(((+data.finished || Date.now() / 1000) - +data.started) / 60)) + ' мин.');
            progressNode.textContent = description.join(' · ');
            logNode.textContent = data.log || '';
            setButtons(data.running === true);
            renderResults(data);
        }).catch(function(error) { status.textContent = error.message; });
    }

    function loadCatalog() {
        refreshButton.disabled = true;
        return call('catalog').then(function(data) {
            replace(profilesSelect, parseTSV(data.profiles).map(function(row) {
                return E('option', { value: row.PROFILE, selected: row.ENABLED === '1' }, row.PROFILE + ' · ' + row.PROTOCOL + '/' + row.PORTS);
            }));
            replace(listsSelect, parseTSV(data.lists).map(function(row) {
                return E('option', { value: row.list, selected: row.list === 'list_hosts_youtube' || row.list === 'list-google.txt' }, row.list + ' · ' + row.valid_domains + ' доменов');
            }));
            protocol.querySelector('option[value="quic"]').disabled = !data.http3;
            setButtons(busy);
        }).catch(fail).finally(function() { refreshButton.disabled = busy; });
    }

    startButton = E('button', { type: 'button', class: 'btn cbi-button-apply', click: function() {
        var profiles = allProfiles.checked ? 'all' : selectedValues(profilesSelect).join(',');
        var lists = allLists.checked ? 'all' : selectedValues(listsSelect).join(',');
        if (!profiles || !lists) { fail(new Error('Выберите хотя бы одну стратегию и один список')); return; }
        launching = true;
        requestEpoch++;
        status.textContent = 'Подготовка запуска…';
        progressNode.textContent = '';
        setButtons(true);
        return call('start', [profiles, lists, protocol.value, repeats.value, limit.value, timeout.value, request.value])
            .then(function(data) {
                launching = false;
                requestEpoch++;
                expectedReport = data.report || '';
                return refreshStatus();
            }).catch(function(error) { launching = false; fail(error); return refreshStatus(); });
    } }, 'Начать проверку');
    stopButton = E('button', { type: 'button', class: 'btn cbi-button-negative', disabled: true, click: function() {
        stopButton.disabled = true;
        return call('stop').then(refreshStatus).catch(fail);
    } }, 'Остановить и восстановить службу');
    recoverButton = E('button', { type: 'button', class: 'btn cbi-button-apply', style: 'display:none', click: function() {
        return call('recover').then(refreshStatus).catch(fail);
    } }, 'Восстановить службу');
    refreshButton = E('button', { type: 'button', class: 'btn', click: loadCatalog }, 'Обновить списки');
    exportButton = E('button', { type: 'button', class: 'btn', disabled: true, click: function() {
        download('zapret2-strategy-summary.tsv', lastStatus.results || '');
    } }, 'Скачать сводную TSV');

    // --- Автоподбор стратегий (cron) ---
    var cronEnabled = E('input', { type: 'checkbox' });
    var cronAuto = E('input', { type: 'checkbox' });
    var cronCooldown = E('input', { type: 'number', min: 1, max: 168, style: 'width:90px' });
    var cronCap = E('input', { type: 'number', min: 0, max: 20, style: 'width:90px' });
    var cronStatusLine = E('p');
    var cronHealthLog = E('pre', { style: 'white-space:pre-wrap;max-height:160px;overflow:auto;font-size:11px' });
    var cronAutoLog = E('pre', { style: 'white-space:pre-wrap;max-height:160px;overflow:auto;font-size:11px' });

    function loadCron() {
        return call('cronstatus').then(function(d) {
            cronEnabled.checked = !!d.cron_enabled;
            cronAuto.checked = !!d.autopromote;
            cronCooldown.value = Math.round((d.cooldown || 21600) / 3600);
            cronCap.value = d.promote_cap != null ? d.promote_cap : 3;
            cronStatusLine.textContent = d.installed
                ? (d.cron_enabled ? 'Автоподбор активен: мониторинг каждый час.' : 'Автоподбор выключен (cron-запись удалена, мониторинг не работает).') +
                    (d.running ? ' Сейчас выполняется проверка.' : '')
                : 'healthcheck.sh не установлен на роутере.';
            cronHealthLog.textContent = d.health_log || 'пусто';
            cronAutoLog.textContent = d.autotest_log || 'пусто';
        }).catch(function(e) { cronStatusLine.textContent = e.message; });
    }

    var cronSaveButton = E('button', { type: 'button', class: 'btn cbi-button-apply', click: function() {
        cronSaveButton.disabled = true;
        return call('cronset', [cronEnabled.checked ? '1' : '0', cronAuto.checked ? '1' : '0',
                String(cronCooldown.value || 6), String(cronCap.value != null ? cronCap.value : 3)])
            .then(function() { ui.addNotification(null, E('p', {}, 'Настройки автоподбора сохранены')); return loadCron(); })
            .catch(fail)
            .finally(function() { cronSaveButton.disabled = false; });
    } }, 'Сохранить настройки');
    var cronRunButton = E('button', { type: 'button', class: 'btn', click: function() {
        cronRunButton.disabled = true;
        return call('cronrun')
            .then(function() {
                ui.addNotification(null, E('p', {}, 'Проверка запущена, журналы обновятся через пару минут'));
                setTimeout(loadCron, 5000);
            })
            .catch(fail)
            .finally(function() { cronRunButton.disabled = false; });
    } }, 'Проверить сейчас');

    replace(root, [
        E('p', {}, 'Сравнение сохранённых стратегий zapret2 по схеме Zapret Manager: контрольный тест без обхода, проверка каждой стратегии и сводная таблица с деталями по доменам.'),
        E('p', { style: 'padding:10px;border-left:3px solid #16803b;background:rgba(22,128,59,.08)' }, 'Проверка идёт без остановки zapret2: тестовые потоки помечаются, и основная служба их пропускает, продолжая работать. В тестовой копии снимаются исходные ограничения стратегии по доменам и IP. Закрытие страницы не останавливает прогон.'),
        E('div', { style: 'display:flex;flex-wrap:wrap;gap:18px' }, [
            field('Стратегии', E('div', {}, [E('label', {}, [allProfiles, ' Все сохранённые стратегии']), profilesSelect])),
            field('Доменные списки', E('div', {}, [E('label', {}, [allLists, ' Все используемые списки']), listsSelect]), 'Можно выбрать несколько списков. По умолчанию выбраны списки YouTube/Google.')
        ]),
        E('div', { style: 'display:flex;flex-wrap:wrap;gap:18px' }, [
            field('Протокол', protocol, 'UDP-профили пропускаются в TCP-тестах. QUIC требует curl с HTTP3.'),
            field('Запрос', request, 'Проверяется корень домена. Превью и видео YouTube требуют отдельных URL.'),
            field('Доменов из каждого списка', limit, '0 — все домены. Общие домены проверяются один раз.'),
            field('Повторов', repeats), field('Тайм-аут, секунд', timeout)
        ]),
        E('div', { style: 'display:flex;gap:8px;flex-wrap:wrap' }, [startButton, stopButton, recoverButton, refreshButton, exportButton]),
        status, progressNode, resultsNode,
        E('details', {}, [E('summary', {}, 'Журнал проверки'), logNode]),
        E('h3', {}, 'Автоподбор стратегий (cron)'),
        cronStatusLine,
        E('div', { style: 'display:flex;flex-wrap:wrap;gap:18px' }, [
            field('Автоподбор по расписанию', E('label', {}, [cronEnabled, ' каждый час']),
                'После двух сбоев на одном интерфейсе проверяются совместимые профили. Запросы через NetShift видны в журнале.'),
            field('Автоприменение победителя', E('label', {}, [cronAuto, ' включать найденную стратегию']),
                'Новый профиль подтверждается дважды на том же маршруте. Если после включения проверка не проходит, прежняя конфигурация восстанавливается.'),
            field('Кулдаун, часов', cronCooldown, 'Как часто можно повторять автотест одного домена.'),
            field('Промоутов в сутки', cronCap, 'Защита от частых переключений, 0 — запретить.')
        ]),
        E('div', { style: 'display:flex;gap:8px;flex-wrap:wrap' }, [cronSaveButton, cronRunButton]),
        E('details', {}, [E('summary', {}, 'Журнал мониторинга'), cronHealthLog]),
        E('details', {}, [E('summary', {}, 'Журнал автоподбора'), cronAutoLog])
    ]);
    loadCatalog().then(refreshStatus);
    loadCron();
    if (activePoll) poll.remove(activePoll);
    activePoll = function() { if (document.contains(root)) return refreshStatus(); };
    poll.add(activePoll, 3);
    return root;
}

return baseclass.extend({
    createCompareTab: function(map) {
        var section = map.section(form.TypedSection, '_strategy_compare_tab', 'Сравнение стратегий',
            'Контрольный тест, результаты по спискам и доменам, сравнение с доступностью без обхода.');
        section.anonymous = true;
        section.addremove = false;
        section.cfgsections = function() { return ['_strategy_compare']; };
        var option = section.option(form.DummyValue, '_strategy_compare_panel');
        option.cfgvalue = function() { return ''; };
        option.renderWidget = renderPanel;
        option.write = function() {};
        option.remove = function() {};
    }
});
