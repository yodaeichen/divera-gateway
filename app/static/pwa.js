// App-Funktionen: Service Worker anmelden, Installation anbieten, Push-Meldungen auf diesem Gerät ein- und ausschalten.
(function () {
  var hasWorker = 'serviceWorker' in navigator && window.isSecureContext;
  var standalone = (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || window.navigator.standalone === true;
  var ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  var ready = hasWorker ? navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(function () { return null; }) : Promise.resolve(null);

  function show(id, on) { var el = document.getElementById(id); if (el) el.hidden = !on; }
  function say(el, text, bad) { if (el) { el.textContent = text; el.className = 'hint' + (bad ? ' bad' : ''); } }

  // ---------- Installation ----------
  var installCard = document.getElementById('app-install');
  var prompt = null;
  if (installCard) {
    show('app-installed', standalone);
    show('app-insecure', !standalone && !window.isSecureContext);
    show('app-ios', !standalone && window.isSecureContext && ios);
    show('app-other', !standalone && window.isSecureContext && !ios);
    var button = document.getElementById('app-install-button');
    window.addEventListener('beforeinstallprompt', function (event) {
      event.preventDefault();
      prompt = event;
      show('app-other', false);
      show('app-prompt', true);
    });
    if (button) button.addEventListener('click', function () {
      if (!prompt) return;
      prompt.prompt();
      prompt.userChoice.then(function () { prompt = null; show('app-prompt', false); });
    });
    window.addEventListener('appinstalled', function () { show('app-prompt', false); show('app-other', false); show('app-installed', true); });
  }

  // ---------- Push-Meldungen ----------
  var card = document.getElementById('push-card');
  if (!card) return;
  var status = document.getElementById('push-status');
  var on = document.getElementById('push-on');
  var off = document.getElementById('push-off');
  var test = document.getElementById('push-test');
  var subscription = null;

  function keyBytes(text) {
    var raw = window.atob((text + '==='.slice((text.length + 3) % 4)).replace(/-/g, '+').replace(/_/g, '/'));
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function post(path, sub) {
    var data = new FormData();
    var json = sub.toJSON();
    data.append('csrf', card.getAttribute('data-csrf'));
    data.append('endpoint', sub.endpoint);
    data.append('p256dh', (json.keys && json.keys.p256dh) || '');
    data.append('auth', (json.keys && json.keys.auth) || '');
    return fetch(path, { method: 'POST', body: data, credentials: 'same-origin' }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) throw new Error(body.detail || 'Der Server hat die Anfrage abgelehnt.');
        return body;
      });
    });
  }
  function render() {
    on.hidden = !!subscription;
    off.hidden = test.hidden = !subscription;
    on.disabled = off.disabled = test.disabled = false;
  }
  function unsupported(text) { on.hidden = off.hidden = test.hidden = true; say(status, text); }

  if (!window.isSecureContext) return unsupported('Push-Meldungen gehen nur, wenn das Gateway über HTTPS geöffnet ist.');
  if (ios && !standalone) return unsupported('Auf iPhone und iPad zuerst die App zum Home-Bildschirm hinzufügen (siehe oben) und von dort öffnen. Danach lässt sich Push hier einschalten.');
  if (!hasWorker || !('PushManager' in window) || !('Notification' in window)) return unsupported('Dieser Browser kann keine Push-Meldungen empfangen.');

  ready.then(function (registration) {
    if (!registration) return unsupported('Die App-Funktionen ließen sich in diesem Browser nicht starten.');
    return navigator.serviceWorker.ready.then(function (active) {
      return active.pushManager.getSubscription().then(function (found) {
        subscription = found;
        render();
        if (Notification.permission === 'denied') say(status, 'Benachrichtigungen sind für diese Seite im Browser gesperrt. Bitte in den Einstellungen des Browsers erlauben.', true);
        else say(status, found ? 'Auf diesem Gerät eingeschaltet.' : 'Auf diesem Gerät ausgeschaltet.');
        if (found) post('/push/subscribe', found).catch(function () {});   // Eintrag auffrischen, falls er auf dem Server fehlt

        on.addEventListener('click', function () {
          on.disabled = true;
          Notification.requestPermission().then(function (answer) {
            if (answer !== 'granted') throw new Error('Ohne die Erlaubnis für Benachrichtigungen geht es nicht.');
            return active.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(card.getAttribute('data-key')) });
          }).then(function (created) {
            subscription = created;
            return post('/push/subscribe', created);
          }).then(function () { window.location.reload(); }).catch(function (error) {
            render();
            say(status, 'Einschalten hat nicht geklappt: ' + error.message, true);
          });
        });
        off.addEventListener('click', function () {
          off.disabled = true;
          var old = subscription;
          post('/push/unsubscribe', old).catch(function () {}).then(function () { return old.unsubscribe(); }).then(function () { window.location.reload(); });
        });
        test.addEventListener('click', function () {
          test.disabled = true;
          post('/push/test', subscription).then(function () {
            say(status, 'Probemeldung verschickt. Sie sollte in wenigen Sekunden erscheinen.');
          }).catch(function (error) { say(status, 'Probemeldung ging nicht raus: ' + error.message, true); }).then(function () { test.disabled = false; });
        });
      });
    });
  });
})();
