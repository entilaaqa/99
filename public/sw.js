const CACHE = "entilaaqa-v3";
const CORE = ["/", "/manifest.webmanifest", "/icons/icon.svg"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", e => {
  const r = e.request;
  if (r.method !== "GET") return;
  const u = new URL(r.url);
  // Pages: network first so visitors always get the latest version, cached copy when offline.
  if (r.mode === "navigate") {
    e.respondWith(fetch(r).then(res => {
      if (res.ok && u.pathname === "/") { const copy = res.clone(); caches.open(CACHE).then(c => c.put("/", copy)); }
      return res;
    }).catch(() => caches.match("/")));
    return;
  }
  // Never touch API calls.
  if (u.pathname.startsWith("/api/")) return;
  // Same-origin static files and Google Fonts: serve from cache, refresh in the background.
  if (u.origin === location.origin || u.hostname.endsWith("fonts.googleapis.com") || u.hostname.endsWith("fonts.gstatic.com")) {
    e.respondWith(caches.match(r).then(hit => {
      const net = fetch(r).then(res => {
        if (res && (res.ok || res.type === "opaque")) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(r, copy)); }
        return res;
      }).catch(() => hit);
      return hit || net;
    }));
  }
});
