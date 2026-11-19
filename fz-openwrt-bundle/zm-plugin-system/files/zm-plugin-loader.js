
// zm-plugin-loader v1: маршруты плагинов из /zm-plugins/index.json
var zmPluginsReady = false;
function zmLoadPlugins(next) {
	fetch('/zm-plugins/index.json?v=' + BUILD).then(function (r) { return r.ok ? r.json() : null; }).then(function (idx) {
		(idx && idx.plugins || []).forEach(function (p) {
			if (!p || !p.id || ROUTE_BY_ID[p.id]) return;
			var r = { id: p.id, title: p.title || p.id, sub: p.sub || '', icon: p.icon || 'layers', group: p.group || 'Плагины' };
			if (p.view) r.view = p.view;
			if (p.part) r.part = p.part;
			ROUTES.push(r); ROUTE_BY_ID[r.id] = r;
		});
	}).catch(function () {}).then(function () { zmPluginsReady = true; if (typeof next === 'function') next(); });
}
