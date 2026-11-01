/* AegisVault Zero-Knowledge Offline Service Worker */
const SW_VERSION = '__AEGIS_SW_VERSION__';
const CACHE_PREFIX = 'aegisvault-shell-';
const CACHE_NAME = `${CACHE_PREFIX}${SW_VERSION}`;

// Populated at build time by Vite plugin; falls back to core shell entries in dev
const PRECACHE_ASSETS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon.svg',
  './pwa-192x192.png',
  './pwa-512x512.png',
  './pwa-maskable-512x512.png',
  './apple-touch-icon.png',
  /* __AEGIS_PRECACHE_MANIFEST__ */
];

function isSensitiveOrApiRequest(request, url) {
  if (request.method !== 'GET') return true;
  if (request.headers && request.headers.has('Authorization')) return true;
  if (url.origin !== self.location.origin) return true;
  if (url.pathname.includes('/api/')) return true;
  return false;
}

function isStaticSameOriginAsset(url) {
  if (url.origin !== self.location.origin) return false;
  return /\.(?:js|mjs|css|woff2?|ttf|svg|png|ico|webmanifest|json)$/i.test(
    url.pathname
  );
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      const baseScope = self.registration.scope || self.location.href;
      const uniqueUrls = Array.from(
        new Set(
          PRECACHE_ASSETS.map((relPath) => new URL(relPath, baseScope).href)
        )
      );

      await Promise.allSettled(
        uniqueUrls.map(async (targetUrl) => {
          try {
            const response = await fetch(targetUrl, { cache: 'reload' });
            if (response && response.ok) {
              await cache.put(targetUrl, response.clone());
            }
          } catch {
            // Ignore individual asset failure during install in dev mode
          }
        })
      );

      // If no controller is active yet (first install), activate immediately so offline works on next reload.
      // If a controller already exists (version upgrade), wait for explicit user confirmation via SKIP_WAITING message
      // so unlocked vaults or unsaved edits are never disrupted.
      if (!self.registration.active) {
        await self.skipWaiting();
      }
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(
        keys
          .filter(
            (key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME
          )
          .map((oldKey) => caches.delete(oldKey))
      );
      await self.clients.claim();
    })()
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }

  // Strictly bypass Cache Storage for all API/Worker/authenticated/cross-origin requests
  if (isSensitiveOrApiRequest(request, url)) {
    return;
  }

  // Navigation requests (HTML App Shell): Network-first with fast offline fallback to cached index.html
  if (request.mode === 'navigate') {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE_NAME);
        const scopeIndexUrl = new URL('./index.html', self.registration.scope).href;
        const scopeRootUrl = new URL('./', self.registration.scope).href;

        try {
          const networkResponse = await fetch(request);
          if (networkResponse && networkResponse.ok) {
            await cache.put(scopeIndexUrl, networkResponse.clone());
          }
          return networkResponse;
        } catch {
          const cachedIndex =
            (await cache.match(request)) ||
            (await cache.match(scopeIndexUrl)) ||
            (await cache.match(scopeRootUrl));
          if (cachedIndex) {
            return cachedIndex;
          }
          throw new Error('Offline and no cached App Shell available');
        }
      })()
    );
    return;
  }

  // Static same-origin assets (JS, CSS, WOFF2 fonts, SVG, PNG, manifest): Cache-first, then network + cache
  if (isStaticSameOriginAsset(url)) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match(request, { ignoreSearch: false });
        if (cached) {
          return cached;
        }
        const networkResponse = await fetch(request);
        if (
          networkResponse &&
          networkResponse.ok &&
          networkResponse.status === 200
        ) {
          await cache.put(request, networkResponse.clone());
        }
        return networkResponse;
      })()
    );
  }
});
