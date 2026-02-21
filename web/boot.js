import init, { init_client_runtime } from "/pkg/client_wasm.js";

async function start() {
  await init();
  await init_client_runtime();
}

start().catch((err) => {
  console.error("client runtime bootstrap failed", err);
});

