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
  const pending = new Map(), listeners = new Set();
  ws.onmessage = (m) => {
    const j = JSON.parse(m.data);
    if (j.id && pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); }
    else if (j.method) listeners.forEach((fn) => fn(j));
  };
  const send = (method, params = {}, sessionId) => new Promise((res) => {
    const i = ++id;
    pending.set(i, res);
    ws.send(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

  // Opens url in a background target, hands fn a page object, closes the target afterwards.
  // setup(page), if given, runs before navigating: the place to subscribe to network events.
  //   page.evaluate(expr)               -> value of expr (returnByValue)
  //   page.waitFor(expr, ready, tries)  -> polls expr every 500 ms until ready(value) or tries run out
  //   page.send(method, params)         -> raw CDP command on this page (e.g. "Network.enable")
  //   page.on(method, fn)               -> CDP events of this page (e.g. "Network.responseReceived")
  async function withPage(url, fn, setup) {
    const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank", background: true });
    const own = [];
    try {
      const { result: { sessionId } } = await send("Target.attachToTarget", { targetId, flatten: true });
      await send("Runtime.enable", {}, sessionId);
      await send("Emulation.setFocusEmulationEnabled", { enabled: true }, sessionId);
      const evaluate = async (expression) =>
        (await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, sessionId)).result?.result?.value;
      const waitFor = async (expr, ready = Boolean, tries = 30) => {
        let val = null;
        for (let i = 0; i < tries; i++) {
          await sleep(500);
          val = await evaluate(expr);
          if (val && ready(val)) break;
        }
        return val;
      };
      const on = (method, cb) => { const l = (j) => j.sessionId === sessionId && j.method === method && cb(j.params); listeners.add(l); own.push(l); };
      const page = { evaluate, waitFor, on, send: (method, params) => send(method, params, sessionId) };
      if (setup) await setup(page);
      await send("Page.navigate", { url }, sessionId);
      return await fn(page);
    } finally {
      own.forEach((l) => listeners.delete(l));
      await send("Target.closeTarget", { targetId });
    }
  }

  // Opens url, polls `expr` every 500 ms until ready(value) or tries run out, closes the page.
  const evalAt = (url, expr, ready, tries) =>
    withPage(url, (page) => page.waitFor(expr, ready, tries));

  return { evalAt, withPage, close: () => ws.close() };
}
