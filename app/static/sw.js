// Service Worker des DIVERA Gateway: macht die Oberfläche als App installierbar, zeigt Push-Meldungen an
// und liefert eine Hinweisseite, wenn der Server nicht erreichbar ist.
// Seiten mit Daten werden nie zwischengespeichert, nur Stil, Skripte und Symbole.
var VERSION = "__VERSION__";
var CACHE = "gateway-" + VERSION;
var PRECACHE = ["/offline", "/static/icons/icon-192.png"];

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (cache) { return cache.addAll(PRECACHE); }).then(function () { return self.skipWaiting(); }));
});

self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (key) { return key.indexOf("gateway-") === 0 && key !== CACHE; }).map(function (key) { return caches.delete(key); }));
  }).then(function () { return self.clients.claim(); }));
});

self.addEventListener("fetch", function (event) {
  var request = event.request;
  if (request.method !== "GET") return;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf("/static/") === 0) {
    // Erst aus dem Zwischenspeicher antworten, im Hintergrund auffrischen
    event.respondWith(caches.open(CACHE).then(function (cache) {
      return cache.match(request).then(function (hit) {
        var fresh = fetch(request).then(function (response) {
          if (response.ok) cache.put(request, response.clone());
          return response;
        });
        if (hit) { fresh.catch(function () {}); return hit; }
        return fresh;
      });
    }));
    return;
  }
  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(function () { return caches.match("/offline"); }));
  }
});

self.addEventListener("push", function (event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = {}; }
  var target = typeof data.url === "string" && data.url.charAt(0) === "/" && data.url.charAt(1) !== "/" ? data.url : "/";
  event.waitUntil(self.registration.showNotification(data.title || "DIVERA Gateway", {
    body: data.body || "",
    icon: "/static/icons/icon-192.png",
    badge: "/static/icons/badge-96.png",
    tag: data.tag || undefined,
    data: { url: target }
  }));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
    for (var i = 0; i < list.length; i++) {
      if ("focus" in list[i]) {
        if ("navigate" in list[i]) list[i].navigate(target).catch(function () {});
        return list[i].focus();
      }
    }
    return self.clients.openWindow(target);
  }));
});
