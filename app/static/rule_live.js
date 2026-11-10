// Live-Ansicht der Regel: schickt die aktuellen Formularwerte an /rules/preview und zeigt das Ergebnis.
// Es wird dabei nichts gespeichert und nichts an DIVERA gesendet.
(function () {
  var form = document.getElementById('rule-form');
  var out = document.getElementById('live');
  if (!form || !out || !window.fetch) return;
  var fallback = document.getElementById('static-result');
  if (fallback) fallback.style.display = 'none';
  var timer = null, seq = 0;

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function ph(name) { return '<code>{' + esc(name) + '}</code>'; }

  function render(d) {
    var h = '<h2>Live-Ansicht</h2>';
    if (d.state === 'nosample') {
      out.innerHTML = h + '<p>Trage unten eine Beispielnachricht ein (oder übernimm eine über „Verbindung testen" bei der Quelle). ' +
        'Dann siehst du hier bei jeder Änderung sofort, was an DIVERA gehen würde.</p>';
      return;
    }
    h += '<div class="state ' + (d.match ? 'ok' : '') + '">' +
      (d.match ? 'Regel greift bei der Beispielnachricht' : 'Regel greift nicht bei der Beispielnachricht') + '</div>';
    if (d.form_error) h += '<div class="warn">' + esc(d.form_error) + '</div>';
    if (!d.active) h += '<div class="warn">Die Regel ist nicht aktiv und wird im Betrieb übersprungen.</div>';

    h += '<h3>Bedingungen</h3><ul>';
    if (!d.conditions.length) h += '<li>Keine Bedingung gesetzt: die Regel greift bei jeder Nachricht der Quelle.</li>';
    d.conditions.forEach(function (c) {
      var terms = c.terms.map(function (t) {
        return t === c.hit ? '<strong>„' + esc(t) + '“</strong>' : '„' + esc(t) + '“';
      }).join(' oder ');
      h += '<li class="' + (c.ok ? 'yes' : 'no') + '">' + esc(c.label) + ' enthält ' + terms + '</li>';
    });
    h += '</ul>';

    if (d.expressions.length) {
      h += '<h3>Ausdrücke' + (d.require_regex ? ' (alle müssen etwas finden)' : '') + '</h3><ul>';
      d.expressions.forEach(function (e, i) {
        var names = Object.keys(e.groups);
        var text = 'Zeile ' + (i + 1) + ': ';
        if (e.error) text += 'fehlerhaft (' + esc(e.error) + ')';
        else if (!e.ok) text += 'nichts gefunden';
        else if (!names.length) text += 'gefunden, aber ohne benannte Gruppe';
        else text += names.map(function (n) { return ph(n) + ' = ' + esc(e.groups[n]); }).join(', ');
        h += '<li class="' + (e.ok ? 'yes' : 'no') + '">' + text + '</li>';
      });
      h += '</ul>';
    }

    var f = {};
    d.fields.forEach(function (x) { f[x.key] = x; });
    function count(x) {
      return '<span class="count ' + (x.length > x.limit ? 'over' : '') + '">' + x.length + ' / ' + x.limit + ' Zeichen' +
        (x.length > x.limit ? ', wird abgeschnitten' : '') + '</span>';
    }
    h += '<h3>So geht es an DIVERA' + (d.match ? '' : ' (wenn die Regel greifen würde)') + '</h3>';
    h += '<div class="msg ' + (d.kind === 'news' ? 'news ' : '') + (d.match ? '' : 'off') + '">' +
      '<div class="count">' + (d.kind === 'news' ? 'Mitteilung' + (d.plan.push ? ' (leise)' : ' ohne Push') : 'Alarm') + (d.priority && d.kind !== 'news' ? ' · Sonderrechte' : '') + '</div>' +
      '<div class="t">' + (esc(f.title.value) || '<em>kein Stichwort</em>') + '</div>' +
      '<div class="a">' + (esc(f.address.value) || '<em>keine Adresse</em>') + '</div>' +
      '<div class="x">' + (esc(f.text.value) || '<em>kein Text</em>') + '</div></div>';
    h += '<ul><li>Stichwort: ' + count(f.title) + '</li><li>Text: ' + count(f.text) + '</li>' +
      (f.address.length ? '<li>Adresse: ' + count(f.address) + '</li>' : '') +
      (d.plan.route === 'v2'
        ? '<li><strong>Geht an: ' + esc(d.plan.audience) + '</strong></li>' +
          (d.plan.ntype === 3 ? '<li>Gruppen: ' + esc(d.groups.join(', ')) + '</li>' : '') +
          (d.plan.ntype === 4 ? '<li>Personen: ' + esc(d.persons.join(', ')) + '</li>' : '') +
          '<li>Push: ' + (d.plan.push ? 'ja' : 'nein') + '</li>'
        : '<li>Empfänger (RIC): ' + (d.payload.ric ? esc(d.payload.ric) : '<em>keine</em>') + '</li>' +
          '<li>Gruppen: ' + (d.groups.length ? esc(d.groups.join(', ')) : '<em>keine</em>') + '</li>' +
          '<li>Personen: ' + (d.persons.length ? esc(d.persons.join(', ')) : '<em>keine</em>') + '</li>') + '</ul>';
    if (d.plan.route === 'v2' && !d.user_key) h += '<div class="warn">Dieser Weg braucht den persönlichen Accesskey eines DIVERA-Benutzers. Beim Kunden ist noch keiner hinterlegt, DIVERA wird die Mitteilung ablehnen.</div>';
    d.plan.notes.forEach(function (n) { h += '<div class="warn">' + esc(n) + '</div>'; });
    if (d.plan.route === 'v2' && d.plan.ntype === 2) h += '<div class="warn">Keine Gruppe und keine Person angekreuzt: die Mitteilung geht an alle Mitglieder der Einheit.</div>';

    if (d.kind !== 'news') h += '<div class="warn"><strong>Achtung, Alarm:</strong> Diese Regel löst bei den Empfängern einen echten Alarm mit Alarmton aus. Für reine Informationen „Mitteilung (leise)" wählen.</div>';
    if (!f.title.value) h += '<div class="warn">Das Stichwort ist leer.</div>';
    if (!d.has_recipient)
      h += '<div class="warn">Kein Empfänger angegeben. Trage eine RIC ein oder kreuze Gruppen oder Personen an.</div>';
    if (d.unknown.length) h += '<div class="warn">Unbekannte Platzhalter (bleiben leer): ' + d.unknown.map(ph).join(', ') + '</div>';
    if (d.empty.length) h += '<div class="warn">Platzhalter ohne Inhalt bei dieser Nachricht: ' + d.empty.map(ph).join(', ') + '</div>';

    var names = Object.keys(d.placeholders);
    h += '<details><summary>Verfügbare Platzhalter (' + (names.length + 1) + ')</summary><ul>' +
      names.map(function (n) { return '<li>' + ph(n) + ' = ' + esc(d.placeholders[n]) + '</li>'; }).join('') +
      '<li>' + ph('body') + ' = ganzer Text</li></ul></details>';
    h += '<details><summary>Daten an die DIVERA-API</summary><pre>' + esc(JSON.stringify(d.payload, null, 2)) + '</pre></details>';
    h += '<p class="hint">Es wird nichts gespeichert und nichts gesendet.</p>';
    out.innerHTML = h;
  }

  function update() {
    var mine = ++seq;
    fetch('/rules/preview', { method: 'POST', body: new FormData(form), credentials: 'same-origin' })
      .then(function (resp) {
        if (!resp.ok || (resp.headers.get('content-type') || '').indexOf('json') < 0) throw new Error('status ' + resp.status);
        return resp.json();
      })
      .then(function (data) { if (mine === seq) render(data); })
      .catch(function () {
        if (mine === seq) out.innerHTML = '<h2>Live-Ansicht</h2><div class="warn">Keine Antwort vom Server. Vielleicht ist die Anmeldung abgelaufen: Seite neu laden.</div>';
      });
  }
  function schedule() { clearTimeout(timer); timer = setTimeout(update, 250); }
  // Auswahllisten: Zähler und Filter
  function counts() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-count]'), function (el) {
      var n = form.querySelectorAll('input[name="' + el.getAttribute('data-count') + '"]:checked').length;
      el.textContent = n ? '(' + n + ' ausgewählt)' : '';
    });
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-filter]'), function (box) {
    box.addEventListener('input', function (ev) {
      ev.stopPropagation();
      var needle = box.value.toLowerCase();
      var rows = document.querySelectorAll('[data-list="' + box.getAttribute('data-filter') + '"] label');
      Array.prototype.forEach.call(rows, function (row) {
        row.style.display = row.textContent.toLowerCase().indexOf(needle) >= 0 || row.querySelector('input').checked ? '' : 'none';
      });
    });
  });
  form.addEventListener('change', counts);
  counts();
  form.addEventListener('input', schedule);
  form.addEventListener('change', schedule);
  update();
})();
