'use strict';
'require view';
'require view.zapret-manager.plugin as zmPlugin';

/*
 * LuCI-обёртка над универсальным рендерером манифест-плагинов.
 * Показывает плагин plugin-manager в разделе «Службы» классической панели LuCI.
 * Сама логика — в /etc/zm-plugins/plugin-manager/ (manifest.json + backend.sh).
 */

/* Объект view из 'require view.zapret-manager.plugin' — в зависимости от
 * версии LuCI это класс или уже инстанс; берём методы с того, что есть. */
var impl = zmPlugin.prototype || zmPlugin;

return view.extend({
	load: function() {
		this.zmPart = 'plugin-manager';
		return impl.load.call(this);
	},
	render: function(data) {
		return impl.render.call(this, data);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
