import init, { init_service_worker } from "/pkg/client_wasm.js";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

async function start() {
  await init();
  init_service_worker();
}

start().catch((err) => {
  console.error("service worker bootstrap failed", err);
});

