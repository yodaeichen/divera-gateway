// Benutzerformular: Rollenvorlage füllt die Einzelrechte aus; die Kundenliste wird bei "alle Kunden" ausgegraut.
(function () {
  var preset = document.getElementById('preset');
  var form = document.getElementById('user-form');
  if (!preset || !form) return;
  var presets = JSON.parse(preset.getAttribute('data-presets'));
  var all = document.getElementById('all-tenants');
  var list = document.getElementById('tenant-list');

  function current() {
    var out = { send: form.elements.p_send.checked };
    Object.keys(presets.admin).forEach(function (key) {
      if (key !== 'send') out[key] = parseInt(form.elements['p_' + key].value, 10);
    });
    return out;
  }
  function matching() {
    var now = current();
    return Object.keys(presets).filter(function (name) {
      return Object.keys(presets[name]).every(function (key) { return presets[name][key] === now[key]; });
    })[0] || '';
  }
  function tenants() {
    var locked = all.checked || form.elements.p_users.value === '2';
    if (form.elements.p_users.value === '2') all.checked = true;
    list.style.opacity = locked ? '0.45' : '';
  }
  preset.addEventListener('change', function () {
    var chosen = presets[preset.value];
    if (!chosen) return;
    Object.keys(chosen).forEach(function (key) {
      if (key === 'send') form.elements.p_send.checked = chosen.send;
      else form.elements['p_' + key].value = String(chosen[key]);
    });
    tenants();
  });
  Array.prototype.forEach.call(form.querySelectorAll('.perm'), function (el) {
    el.addEventListener('change', function () { preset.value = matching(); tenants(); });
  });
  all.addEventListener('change', tenants);
  tenants();
})();
