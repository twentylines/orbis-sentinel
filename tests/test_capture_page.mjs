import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../web/capture.js', import.meta.url));
const { captureView, boundedJSON, mainHealthReady, dashboardDestination, startCapturePage } = await import(
  `data:text/javascript;base64,${source.toString('base64')}`
);
const point = '12345678-1234-4123-8123-123456789abc';
const progress = { version: 1, id: point, state: 'running', phase: 'saving-orbis', completedBytes: 50, totalBytes: 100, restartVerified: false };
const envelope = (p = progress) => ({
  schema: 'orbis-sentinel.capture-progress.v1',
  id: point,
  available: true,
  progress: p,
  ageMs: 0,
  sourceState: 'ready',
});
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const health = { status: 'ok', info: { queue: { status: 'up' } }, details: { queue: { status: 'up' } }, error: {} };
const build = { version: '0.8.0-beta.2', commit: null, imageDigest: null, runtipiCompatibility: null };

test('capture stages and sizes come only from a fresh exact observation', () => {
  assert.equal(captureView(envelope(), point).percent, 50);
  assert.deepEqual(captureView(envelope(), point).counts, [50, 100]);
  assert.equal(captureView(envelope({ ...progress, completedBytes: 100 }), point).percent, 99);
  assert.equal(captureView(envelope({ ...progress, totalBytes: null }), point).percent, null);
  for (const patch of [{ ageMs: 5001 }, { available: false }, { sourceState: 'stale' }, { id: 'other' }, { path: 'private' }, { ageMs: -1 }]) {
    const view = captureView({ ...envelope(), ...patch }, point);
    assert.equal(view.mode, 'waiting');
    assert.equal(view.percent, null);
    assert.equal(view.complete, false);
  }
  for (const patch of [
    { version: true },
    { completedBytes: true },
    { completedBytes: 101 },
    { totalBytes: -1 },
    { restartVerified: true },
    { phase: 'complete' },
    { phase: '__proto__' },
    { id: 'other' },
  ]) {
    assert.equal(captureView(envelope({ ...progress, ...patch }), point).mode, 'waiting');
  }
  const stopped = captureView(envelope({ ...progress, state: 'recovery-required' }), point);
  assert.equal(stopped.mode, 'failed');
  assert.equal(stopped.complete, false);
  assert.equal(stopped.percent, null);
});

test('restart is a separate view and bytes alone never complete a capture', () => {
  assert.equal(captureView(envelope({ ...progress, phase: 'starting-orbis' }), point).mode, 'boot');
  const complete = captureView(envelope({ ...progress, state: 'complete', phase: 'complete', restartVerified: true }), point);
  assert.equal(complete.mode, 'boot');
  assert.equal(complete.complete, true);
  assert.equal(complete.percent, null);
});

test('maintenance health cannot substitute for a real Orbis readiness response', async () => {
  assert.equal(mainHealthReady({ status: 'ok', maintenance: false }), false);
  assert.equal(mainHealthReady({ ...health, maintenance: false }), false);
  assert.equal(mainHealthReady({ status: 'ok' }), false);
  assert.equal(mainHealthReady(health), true);
  const calls = [];
  assert.equal(
    await dashboardDestination(async (path) => {
      calls.push(path);
      return json({ status: 'ok', maintenance: false });
    }),
    null,
  );
  assert.deepEqual(calls, ['/api/health']);
  assert.equal(await dashboardDestination(async (path) => json(path === '/api/health' ? health : build)), '/dashboard');
  assert.equal(
    await dashboardDestination(async (path) => json(path === '/api/health' ? health : { ...build, sentinelVersion: '0.1.0-dev.10' })),
    '/dashboard',
  );
  assert.equal(await dashboardDestination(async (path) => (path === '/api/health' ? json(health) : json({}, 401))), '/login');
  assert.equal(await dashboardDestination(async (path) => json(path === '/api/health' ? health : { version: '0.8.0' })), null);
});

test('JSON reads reject oversized, wrong-type and malformed responses', async () => {
  await assert.rejects(() => boundedJSON(json({ data: 'x'.repeat(17000) })));
  await assert.rejects(() => boundedJSON(new Response('{}', { headers: { 'content-type': 'text/html' } })));
  await assert.rejects(() => boundedJSON(new Response(new Uint8Array([255]), { headers: { 'content-type': 'application/json' } })));
});

function fixture() {
  const elements = Object.fromEntries(
    ['main', 'h1', '.stage', 'progress', '.scan', '.counts', '.notice'].map((key) => [key, { dataset: {}, textContent: '', hidden: false }]),
  );
  const listeners = new Map();
  const doc = {
    hidden: false,
    documentElement: { toggleAttribute: () => undefined },
    querySelector: (key) => elements[key],
    addEventListener: (event, handler) => listeners.set(event, handler),
    removeEventListener: (event) => listeners.delete(event),
  };
  const jobs = new Map();
  let serial = 0;
  const timers = {
    setTimeout: (run, delay) => {
      jobs.set(++serial, { run, delay });
      return serial;
    },
    clearTimeout: (id) => jobs.delete(id),
  };
  const next = () => {
    const [id, job] = [...jobs].sort((a, b) => a[1].delay - b[1].delay)[0];
    jobs.delete(id);
    return job.run();
  };
  const location = {
    pathname: `/sentinel/captures/${point}`,
    replace: (destination) => {
      location.destination = destination;
    },
  };
  return { doc, elements, listeners, jobs, timers, next, location };
}

test('one request at a time, visibility abort and late results cannot redirect', async () => {
  const f = fixture();
  let resolve;
  let calls = 0;
  let signal;
  const stop = startCapturePage(
    f.doc,
    f.location,
    async (_, options) => {
      calls++;
      signal = options.signal;
      return new Promise((done) => {
        resolve = done;
      });
    },
    f.timers,
  );
  const run = f.next();
  assert.equal(calls, 1);
  f.doc.hidden = true;
  f.listeners.get('visibilitychange')();
  assert.equal(signal.aborted, true);
  f.doc.hidden = false;
  f.listeners.get('visibilitychange')();
  assert.equal(calls, 1);
  resolve(json(envelope({ ...progress, state: 'complete', phase: 'complete', restartVerified: true })));
  await run;
  assert.equal(f.location.destination, undefined);
  assert.equal(f.jobs.size, 1);
  stop();
  assert.equal(f.jobs.size, 0);
  assert.equal(f.listeners.size, 0);
});

test('native browser timer methods retain their global receiver', () => {
  const f = fixture();
  const before = { setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout };
  globalThis.setTimeout = function (run, delay) {
    assert.equal(this, globalThis);
    return f.timers.setTimeout(run, delay);
  };
  globalThis.clearTimeout = function (id) {
    assert.equal(this, globalThis);
    return f.timers.clearTimeout(id);
  };
  try {
    const stop = startCapturePage(f.doc, f.location, async () => json(envelope()));
    assert.equal(f.jobs.size, 1);
    stop();
    assert.equal(f.jobs.size, 0);
  } finally {
    globalThis.setTimeout = before.setTimeout;
    globalThis.clearTimeout = before.clearTimeout;
  }
});

test('successful capture automatically opens dashboard after genuine health and build', async () => {
  const f = fixture();
  const calls = [];
  const stop = startCapturePage(
    f.doc,
    f.location,
    async (path) => {
      calls.push(path);
      return json(
        path.startsWith('/sentinel/')
          ? envelope({ ...progress, state: 'complete', phase: 'complete', restartVerified: true })
          : path === '/api/health'
            ? health
            : build,
      );
    },
    f.timers,
  );
  await f.next();
  assert.equal(f.location.destination, '/dashboard');
  assert.equal(f.jobs.size, 0);
  assert.deepEqual(calls, [`/sentinel/api/v1/captures/${point}/progress`, '/api/health', '/api/system/build']);
  assert.equal(f.elements.main.dataset.mode, 'boot');
  assert.equal(f.elements['.notice'].hidden, false);
  stop();
});

test('a failed Main readiness check keeps the starting view without a flash back', async () => {
  const f = fixture();
  const stop = startCapturePage(
    f.doc,
    f.location,
    async (path) => {
      if (path.startsWith('/sentinel/')) return json(envelope({ ...progress, state: 'complete', phase: 'complete', restartVerified: true }));
      throw Error('Main is not ready');
    },
    f.timers,
  );
  await f.next();
  assert.equal(f.elements.main.dataset.mode, 'boot');
  assert.equal(f.location.destination, undefined);
  assert.equal(f.jobs.size, 1);
  stop();
});
