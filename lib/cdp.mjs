// Minimal CDP client for the user's own running browser (Brave/Chrome started with
// --remote-debugging-port). Pages open as background targets, so the user's tabs
// and focus are never touched.
const CDP = process.env.SECURIZAME_CDP || "http://127.0.0.1:9222";
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function connect() {
  const v = await (await fetch(`${CDP}/json/version`)).json();
  const ws = new WebSocket(v.webSocketDebuggerUrl);
  await new Promise((r, e) => { ws.onopen = r; ws.onerror = e; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const j = JSON.parse(m.data);
    if (j.id && pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); }
  };
  const send = (method, params = {}, sessionId) => new Promise((res) => {
    const i = ++id;
    pending.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

  // Opens url, polls `expr` every 500 ms until ready(value) or tries run out, closes the page.
  async function evalAt(url, expr, ready = Boolean, tries = 30) {
    const { result: { targetId } } = await send("Target.createTarget", { url, background: true });
    const { result: { sessionId } } = await send("Target.attachToTarget", { targetId, flatten: true });
    await send("Runtime.enable", {}, sessionId);
    await send("Emulation.setFocusEmulationEnabled", { enabled: true }, sessionId);
    let val = null;
    try {
      for (let i = 0; i < tries; i++) {
        await sleep(500);
        const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true }, sessionId);
        val = r.result?.result?.value;
        if (val && ready(val)) break;
      }
    } finally {
      await send("Target.closeTarget", { targetId });
    }
    return val;
  }

  return { evalAt, close: () => ws.close() };
}
