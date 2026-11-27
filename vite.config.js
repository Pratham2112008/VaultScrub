import { defineConfig } from 'vite';
import fs from 'node:fs';
import path from 'node:path';

function collectDistFiles(dir, baseDir = dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectDistFiles(full, baseDir));
    } else if (entry.name !== 'sw.js') {
      const rel = `./${path.relative(baseDir, full).replace(/\\/g, '/')}`;
      results.push(rel);
    }
  }
  return results;
}

function vaultScrubOfflinePwaPlugin() {
  return {
    name: 'vaultscrub-offline-pwa',
    closeBundle() {
      const outDir = path.resolve(import.meta.dirname, 'dist');
      if (!fs.existsSync(outDir)) return;

      const files = ['./', ...collectDistFiles(outDir)];
      const cacheVersion = `vaultscrub-offline-${Date.now()}`;
      const swContent = `const CACHE_NAME = ${JSON.stringify(cacheVersion)};
const PRECACHE_URLS = ${JSON.stringify(files, null, 2)};

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))),
    ).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const reqUrl = new URL(event.request.url);
  if (reqUrl.origin !== self.location.origin) return;

  if (event.request.mode === 'navigate' || reqUrl.pathname.endsWith('.html')) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request)),
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (!response || response.status !== 200 || response.type !== 'basic') {
          return response;
        }
        const clone = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
        return response;
      });
    }),
  );
});
`;
      fs.writeFileSync(path.join(outDir, 'sw.js'), swContent, 'utf8');
    },
  };
}

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: path.resolve(import.meta.dirname, 'index.html'),
        workbench: path.resolve(import.meta.dirname, 'workbench.html'),
      },
    },
  },
  plugins: [vaultScrubOfflinePwaPlugin()],
});
