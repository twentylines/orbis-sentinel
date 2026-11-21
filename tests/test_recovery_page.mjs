import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { decodeBase64url, encodeBase64url, handoffView, passkeyResponse, progressView, start } from '../web/recovery.js';

const buffer = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
const updateJob = (changes = {}) => ({ id: '12345678-1234-4123-8123-123456789abc', state: 'running', targetTag: 'v0.8.8', phase: 'restarting', ...changes });
const progressEnvelope = (job = updateJob()) => ({ schema: 'orbis-sentinel.progress.v1', available: true, progress: { version: 1, job }, ageMs: 0, sourceState: 'ready' });

test('update view uses reported phases and byte progress without inventing a phase percentage', () => {
  const restarting = progressView(progressEnvelope());
  assert.equal(restarting.phase, 'Restarting Orbis');
  assert.equal(restarting.ongoing, true);
  assert.equal(restarting.percent, null);
  const download = { phase: 'downloading', currentBytes: 1024, totalBytes: 2048 };
  const known = progressView(progressEnvelope(updateJob({ phase: 'downloading', download })));
  assert.equal(known.percent, 50);
  assert.match(known.detail, /1 KB of 2 KB/);
  const unknown = progressView(progressEnvelope(updateJob({ phase: 'downloading', download: { ...download, totalBytes: null } })));
  assert.equal(unknown.percent, null);
  assert.match(unknown.detail, /1 KB received/);
  const verifying = progressView(progressEnvelope(updateJob({ phase: 'verifying', download: { ...download, phase: 'extracting' } })));
  assert.equal(verifying.phase, 'Verifying');
  assert.equal(verifying.percent, null);
  const extracting = progressView(progressEnvelope(updateJob({ phase: 'installing', download: { phase: 'extracting', currentBytes: 2048, totalBytes: 2048, layersComplete: 0, layersTotal: 1 } })));
  assert.equal(extracting.phase, 'Extracting');
  assert.equal(extracting.percent, null);
  assert.equal(extracting.detail, '0 of 1 layers ready');
});

test('idle, terminal, cached and unavailable observations remain distinct', () => {
  assert.equal(progressView(progressEnvelope(null)).phase, 'No update in progress');
  const complete = progressView(progressEnvelope(updateJob({ state: 'complete', phase: null })));
  assert.equal(complete.phase, 'Complete');
  assert.equal(complete.ongoing, false);
  assert.match(complete.detail, /Controller health is shown above/);
  for (const state of ['failed', 'interrupted']) {
    const value = progressView(progressEnvelope(updateJob({ state })));
    assert.equal(value.attention, true);
    assert.equal(value.ongoing, false);
    assert.equal(value.percent, null);
  }
  const cached = progressView(progressEnvelope(updateJob({ phase: 'installing', download: { phase: 'complete', currentBytes: 0, totalBytes: 0, alreadyCached: true } })));
  assert.equal(cached.percent, null);
  assert.match(cached.detail, /already cached/);
  const missing = progressView({ schema: 'orbis-sentinel.progress.v1', available: false });
  assert.equal(missing.phase, 'Unavailable');
  assert.equal(missing.record, null);
  for (const bad of [progressEnvelope(updateJob({ id: 'invalid' })), progressEnvelope(updateJob({ targetTag: '<script>' })),
                      progressEnvelope(updateJob({ phase: 'unknown' })), progressEnvelope(updateJob({ phase: 'downloading', download: { currentBytes: 2, totalBytes: 1 } }))])
    assert.throws(() => progressView(bad));
});

test('browser binary conversion preserves canonical base64url bytes', () => {
  for (const size of [0, 1, 2, 3, 31, 32, 33, 256, 8192]) {
    const bytes = randomBytes(size);
    const encoded = encodeBase64url(buffer(bytes));
    assert.equal(encoded, bytes.toString('base64url'));
    assert.deepEqual(Buffer.from(decodeBase64url(encoded)), bytes);
    assert.doesNotMatch(encoded, /[+/=]/);
  }
});

test('serialized browser assertion retains a genuine ES256 signature and account handle', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const id = randomBytes(24);
  const handle = randomBytes(24);
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: randomBytes(32).toString('base64url'), origin: 'https://orbis.example', crossOrigin: false }));
  const auth = Buffer.alloc(37);
  createHash('sha256').update('orbis.example').digest().copy(auth);
  auth[32] = 5;
  auth.writeUInt32BE(4, 33);
  const signed = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
  const signature = sign('sha256', signed, privateKey);
  const result = passkeyResponse({ id: id.toString('base64url'), rawId: buffer(id), authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}), response: { clientDataJSON: buffer(client), authenticatorData: buffer(auth), signature: buffer(signature), userHandle: buffer(handle) } });
  assert.equal(result.id, result.rawId);
  assert.equal(result.type, 'public-key');
  assert.equal(result.authenticatorAttachment, 'platform');
  assert.equal(result.response.userHandle, handle.toString('base64url'));
  const delivered = Buffer.concat([Buffer.from(result.response.authenticatorData, 'base64url'), createHash('sha256').update(Buffer.from(result.response.clientDataJSON, 'base64url')).digest()]);
  assert.equal(verify('sha256', delivered, publicKey, Buffer.from(result.response.signature, 'base64url')), true);
});

test('nullable browser user handle does not create a fabricated identity or attachment', () => {
  const bytes = randomBytes(16);
  const result = passkeyResponse({ id: bytes.toString('base64url'), rawId: buffer(bytes), authenticatorAttachment: null,
    getClientExtensionResults: () => ({}), response: { clientDataJSON: buffer(bytes), authenticatorData: buffer(bytes), signature: buffer(bytes), userHandle: null } });
  assert.equal(result.response.userHandle, null);
  assert.equal(Object.hasOwn(result, 'authenticatorAttachment'), false);
  assert.deepEqual(Object.keys(result).sort(), ['clientExtensionResults', 'id', 'rawId', 'response', 'type']);
});

const plan = '12345678-1234-4123-8123-123456789abc';
const scope = { planId: plan, installationId: 'a'.repeat(64), handoffSha256: 'b'.repeat(64) };
const handoffEnvelope = (state = 'held') => ({
  schema: 'orbis-sentinel.handoff-status.v1', ageMs: 20,
  status: { version: 1, handoff: state === null ? null : { planId: plan, state, ...(state === 'held' ? { returnScope: scope } : {}) } },
});
const unavailableHandoff = { schema: 'orbis-sentinel.handoff-status.v1', status: null, ageMs: null };

async function page(t, { keyOnly = false, savedSession = false, failedLogin = false, loginError, optionsError,
  setupPending = false, firstOptionsError = false, holdReconnect = false, holdProgress = false, progressCode = 200,
  progressValue = { schema: 'orbis-sentinel.progress.v1', available: false, progress: null, ageMs: null, sourceState: 'unavailable' },
  holdHandoff = false, holdHandoffAt = 1, handoffValue = unavailableHandoff, handoffCode = 200,
  approvalValue, approvalCode = 200, holdApproval = false, returnValue, returnCode = 200, holdReturn = false,
  origin = 'https://sentinel.example.test' } = {}) {
  // A DOM port exercises the shipped controller; rendered layout is checked separately.
  const html = await readFile(new URL('../web/recovery.html', import.meta.url), 'utf8');
  const elements = new Map();
  const listeners = new Map();
  let focused;
  for (const match of html.matchAll(/id="([^"]+)"/g)) {
    const events = new Map();
    const classes = new Set();
    const attributes = new Map();
    elements.set(match[1], { value: '', textContent: '', hidden: false, disabled: false, required: false, dataset: {},
      classList: { add: (value) => classes.add(value), remove: (value) => classes.delete(value) },
      setAttribute: (name, value) => attributes.set(name, value), getAttribute: (name) => attributes.get(name), removeAttribute: (name) => attributes.delete(name),
      addEventListener: (name, action) => events.set(name, action),
      focus: () => { focused = match[1]; },
      fire: (name) => events.get(name)?.({ preventDefault() {} }),
    });
  }
  const element = (id) => { assert.ok(elements.has(id), `Missing real HTML element: ${id}`); return elements.get(id); };
  const calls = [];
  const storage = [];
  const timers = new Map();
  let nextTimer = 0;
  let elapsed = 0;
  let releaseStatus;
  let releaseOptions;
  let releaseProgress;
  let releaseHandoff;
  let releaseApproval;
  let releaseReturn;
  const heldStatus = new Promise((resolve) => { releaseStatus = resolve; });
  const status = { components: { orbis: { installedVersion: null, state: 'unavailable' }, sentinel: { installedVersion: '0.1.0-dev.13', state: 'healthy' } } };
  const reply = (value, code = 200) => ({ ok: code === 200, status: code, json: async () => value });
  const globals = {
    performance: { now: () => elapsed },
    document: { cookie: 'orbis-sentinel-local-csrf=synthetic-csrf', hidden: false,
      get activeElement() { return elements.get(focused); },
      documentElement: { dataset: {} }, getElementById: element, addEventListener: (name, action) => listeners.set(name, action) },
    window: { location: new URL(origin), addEventListener: (name, action) => listeners.set(name, action) },
    localStorage: { getItem: () => null, setItem: (name, value) => storage.push([name, value]) },
    fetch: async (url, init) => {
      const route = url.split('/').at(-1);
      const body = init.body ? JSON.parse(init.body) : undefined;
      calls.push({ route, body, ...(body === undefined ? {} : { headers: init.headers }) });
      if (route === 'options') {
        if (calls.length === 1 && setupPending) return reply({ error: 'Sign-in could not be completed. Try again.' }, 401);
        if (calls.length === 1 && firstOptionsError) return reply({ error: 'Recovery is temporarily unavailable.' }, 503);
        if (optionsError && calls.filter((call) => call.route === 'options').length > 1) throw optionsError;
        const options = { password: !keyOnly, recoveryKey: true, passkey: false, totp: { password: !keyOnly, passkey: false } };
        if (holdReconnect && calls.filter((call) => call.route === 'options').length > 1)
          return new Promise((resolve) => { releaseOptions = () => resolve(reply(options)); });
        return reply(options);
      }
      if (route === 'session') return reply({ authenticated: savedSession });
      if (route === 'challenge') return reply({ challenge: randomBytes(32).toString('base64url') });
      if (route === 'login') {
        if (loginError) throw loginError;
        return failedLogin ? reply({ error: 'Sign-in could not be completed.' }, 401) : reply({ authenticated: true });
      }
      if (route === 'status') return heldStatus;
      if (route === 'progress') {
        if (holdProgress && calls.filter((call) => call.route === 'progress').length === 1)
          return new Promise((resolve) => { releaseProgress = (value) => resolve(reply(value)); });
        return reply(progressValue, progressCode);
      }
      if (route === 'handoff-status') {
        assert.equal(init.method, 'GET');
        assert.equal(init.cache, 'no-store');
        if (holdHandoff && calls.filter((call) => call.route === 'handoff-status').length === holdHandoffAt)
          return new Promise((resolve) => { releaseHandoff = (value) => resolve(reply(value)); });
        return reply(typeof handoffValue === 'function' ? handoffValue() : handoffValue, handoffCode);
      }
      if (route === 'controller-return-approval') {
        const value = approvalValue === undefined
          ? { approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000 } : approvalValue;
        if (holdApproval) return new Promise((resolve) => { releaseApproval = (value) => resolve(reply(value)); });
        return reply(value, approvalCode);
      }
      if (route === 'controller-return') {
        const value = returnValue === undefined ? { planId: plan, state: 'return-accepted', phase: 'return-accepted' } : returnValue;
        if (holdReturn) return new Promise((resolve) => { releaseReturn = (value) => resolve(reply(value)); });
        return reply(value, returnCode);
      }
      if (route === 'logout') return reply({ authenticated: false });
      throw new Error(`Unexpected controller route: ${route}`);
    },
    setTimeout: (action, delay) => {
      assert.ok(Number.isFinite(delay) && delay >= 0 && delay <= 60000);
      const id = ++nextTimer;
      timers.set(id, { action, delay });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
  };
  const descriptors = new Map(Object.keys(globals).map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  t.after(() => {
    listeners.get('pagehide')?.();
    for (const [name, descriptor] of descriptors) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
  });
  for (const [name, value] of Object.entries(globals)) Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  const settle = async () => {
    for (let attempt = 0; attempt < 100; attempt++) {
      await new Promise(setImmediate);
      if (element('recovery-panel').getAttribute('aria-busy') !== 'true') return;
    }
    assert.fail('Authentication remained busy while only status metadata was pending');
  };
  await start();
  return { element, calls, storage, listeners, timers, document: globals.document, focus: () => focused, settle,
    advance: (milliseconds) => { elapsed += milliseconds; },
    releaseProgress: async (value) => { assert.equal(typeof releaseProgress, 'function'); releaseProgress(value); await new Promise(setImmediate); },
    releaseHandoff: async (value) => { assert.equal(typeof releaseHandoff, 'function'); releaseHandoff(value); await new Promise(setImmediate); },
    releaseApproval: async (value) => { assert.equal(typeof releaseApproval, 'function'); releaseApproval(value); await new Promise(setImmediate); },
    releaseReturn: async (value) => { assert.equal(typeof releaseReturn, 'function'); releaseReturn(value); await new Promise(setImmediate); },
    releaseOptions: () => { assert.equal(typeof releaseOptions, 'function'); releaseOptions(); },
    tick: async (delay) => {
      const next = [...timers].find(([, timer]) => delay === undefined || timer.delay === delay);
      assert.ok(next, 'No pending readiness check');
      timers.delete(next[0]);
      await next[1].action();
    },
    release: async () => { releaseStatus(reply(status)); await new Promise(setImmediate); } };
}

test('authenticated progress renders without waiting for component status and pauses when hidden', async (t) => {
  const ui = await page(t, { savedSession: true, progressValue: progressEnvelope() });
  await ui.settle();
  assert.equal(ui.element('orbis-state').textContent, 'Checking…');
  assert.equal(ui.element('update-phase').textContent, 'Restarting Orbis');
  assert.equal(ui.element('update-target').textContent, '0.8.8');
  assert.equal(ui.element('update-spinner').hidden, false);
  assert.equal(ui.element('update-bar').getAttribute('value'), undefined);
  assert.equal([...ui.timers.values()].filter(({ delay }) => delay === 1000).length, 1);
  assert.ok(ui.calls.filter(({ route }) => route === 'progress').every(({ body }) => body === undefined));
  assert.equal(ui.calls.some(({ route }) => route === 'active'), false);
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  assert.equal(ui.timers.size, 0);
  await ui.release();
});

test('progress requests do not overlap and a late result cannot restore signed-out content', async (t) => {
  const ui = await page(t, { savedSession: true, holdProgress: true });
  ui.listeners.get('online')();
  ui.listeners.get('visibilitychange')();
  assert.equal(ui.calls.filter(({ route }) => route === 'progress').length, 1);
  await ui.element('sign-out').fire('click');
  await ui.releaseProgress(progressEnvelope());
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.element('update-phase').textContent, 'Checking…');
  assert.equal(ui.timers.size, 0);
  await ui.release();
});

test('progress session expiry clears the view without silently renewing authentication', async (t) => {
  const ui = await page(t, { savedSession: true, progressCode: 401 });
  await ui.settle();
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.element('sign-in').hidden, false);
  assert.equal(ui.element('notice').textContent, 'Your recovery session expired. Sign in again.');
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.calls.some(({ route }) => ['active', 'challenge', 'login'].includes(route)), false);
  await ui.release();
});

test('cached-page return retries fresh progress after an old in-flight observation finishes', async (t) => {
  const ui = await page(t, { savedSession: true, holdProgress: true, progressValue: progressEnvelope(updateJob({ phase: 'verifying' })) });
  ui.listeners.get('pagehide')();
  ui.listeners.get('pageshow')();
  await ui.releaseProgress(progressEnvelope());
  assert.equal(ui.element('update-phase').textContent, 'Checking…');
  await ui.tick(1000);
  assert.equal(ui.element('update-phase').textContent, 'Verifying');
  assert.equal(ui.calls.filter(({ route }) => route === 'progress').length, 2);
  await ui.release();
});

test('a pending listener guides enrollment and automatically rechecks only existing read endpoints', async (t) => {
  const ui = await page(t, { setupPending: true });
  assert.equal(ui.element('sign-in').hidden, true);
  assert.equal(ui.element('recovery-setup').hidden, false);
  assert.equal(ui.element('enrollment-steps').hidden, false);
  assert.deepEqual(ui.calls, [{ route: 'options', body: undefined }]);
  const html = await readFile(new URL('../web/recovery.html', import.meta.url), 'utf8');
  assert.match(html, /--bootstrap save-key[\s\S]+--bootstrap acknowledge-key[\s\S]+enter the key from that copy/);
  assert.doesNotMatch(html, /retry-options|Check sign-in again/);
  assert.equal([...ui.timers.values()][0]?.delay, 5000);
  await ui.tick();
  assert.equal(ui.element('recovery-setup').hidden, true);
  assert.equal(ui.element('sign-in').hidden, false);
  assert.equal(ui.focus(), undefined);
  assert.equal(ui.timers.size, 0);
  assert.deepEqual(ui.calls.map(({ route }) => route), ['options', 'options', 'session']);
  assert.ok(ui.calls.every(({ body }) => body === undefined));
});

test('an unavailable listener automatically reconnects without asserting enrollment state', async (t) => {
  const ui = await page(t, { firstOptionsError: true });
  assert.equal(ui.element('recovery-setup').hidden, false);
  assert.equal(ui.element('enrollment-steps').hidden, true);
  assert.equal(ui.element('notice').dataset.error, 'true');
  await ui.tick();
  assert.equal(ui.element('sign-in').hidden, false);
});

test('readiness checks pause while hidden and resume automatically when visible', async (t) => {
  const ui = await page(t, { setupPending: true });
  assert.equal(ui.timers.size, 1);
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  ui.listeners.get('online')();
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.calls.length, 1);
  ui.document.hidden = false;
  ui.listeners.get('visibilitychange')();
  await ui.settle();
  assert.equal(ui.element('sign-in').hidden, false);
  assert.equal(ui.timers.size, 0);
  assert.deepEqual(ui.calls.map(({ route }) => route), ['options', 'options', 'session']);
});

test('overlapping readiness events share one check and never reset ready sign-in fields', async (t) => {
  const ui = await page(t, { setupPending: true });
  ui.listeners.get('online')();
  ui.listeners.get('visibilitychange')();
  await ui.settle();
  assert.deepEqual(ui.calls.map(({ route }) => route), ['options', 'options', 'session']);
  ui.element('username').value = 'operator';
  ui.element('password').value = 'pending-entry';
  ui.listeners.get('online')();
  ui.listeners.get('visibilitychange')();
  await ui.settle();
  assert.equal(ui.calls.length, 3);
  assert.equal(ui.element('username').value, 'operator');
  assert.equal(ui.element('password').value, 'pending-entry');
  assert.equal(ui.focus(), undefined);
  assert.equal(ui.timers.size, 0);
});

test('pagehide cancels readiness checks and cached-page return resumes them', async (t) => {
  const ui = await page(t, { setupPending: true });
  ui.listeners.get('pagehide')();
  ui.listeners.get('online')();
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.calls.length, 1);
  ui.listeners.get('pageshow')();
  await ui.settle();
  assert.equal(ui.element('sign-in').hidden, false);
  assert.deepEqual(ui.calls.map(({ route }) => route), ['options', 'options', 'session']);
});

test('a readiness response arriving after pagehide cannot reveal sign-in or resume polling', async (t) => {
  const ui = await page(t, { setupPending: true, holdReconnect: true });
  const pending = ui.tick();
  await new Promise(setImmediate);
  ui.listeners.get('pagehide')();
  ui.releaseOptions();
  await pending;
  assert.equal(ui.element('sign-in').hidden, true);
  assert.equal(ui.element('recovery-setup').hidden, false);
  assert.equal(ui.timers.size, 0);
  assert.deepEqual(ui.calls.map(({ route }) => route), ['options', 'options']);
});

test('signed-in readiness presents observed methods and the current HTTPS recovery entry', async (t) => {
  const ui = await page(t, { keyOnly: true, savedSession: true, origin: 'https://sentinel.example.test:8443' });
  assert.equal(ui.element('account-readiness').textContent, 'Orbis operator sign-in is not enrolled.');
  assert.equal(ui.element('key-readiness').textContent, 'Emergency key sign-in is available.');
  assert.equal(ui.element('recovery-address-row').hidden, false);
  assert.equal(ui.element('recovery-address').textContent, 'https://sentinel.example.test:8443/sentinel/recovery/');
  assert.deepEqual(ui.storage, []);
  await ui.release();
});

test('the local HTTP listener is not advertised as the independent recovery address', async (t) => {
  const ui = await page(t, { savedSession: true, origin: 'http://localhost:8080' });
  assert.equal(ui.element('recovery-address-row').hidden, true);
  assert.equal(ui.element('recovery-address').textContent, '');
  await ui.release();
});

test('successful sign-in stays responsive while observed status is pending, and ignores its late result after sign-out', async (t) => {
  const ui = await page(t);
  ui.element('username').value = 'test';
  ui.element('password').value = 'test12345';
  ui.element('totp').value = '123456';
  ui.element('sign-in').fire('submit');
  await ui.settle();
  assert.equal(ui.element('overview').hidden, false);
  assert.equal(ui.element('sign-out').disabled, false);
  assert.equal(ui.element('notice').textContent, '');
  assert.equal(ui.element('orbis-state').textContent, 'Checking…');
  assert.equal(ui.element('sentinel-state').textContent, 'Checking…');
  assert.equal(ui.focus(), 'page-title');
  assert.equal(ui.element('password').value, '');
  assert.equal(ui.element('totp').value, '');
  await ui.element('sign-out').fire('click');
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.focus(), 'username');
  await ui.release();
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.element('orbis-state').textContent, 'Checking…');
});

test('key-only recovery hides and removes required account factors and sends only the selected key', async (t) => {
  const ui = await page(t, { keyOnly: true });
  assert.equal(ui.element('account-fields').hidden, true);
  for (const name of ['username', 'password', 'totp']) assert.equal(ui.element(name).required, false);
  assert.equal(ui.element('recovery-key').required, true);
  assert.equal(ui.element('use-recovery-key').hidden, true);
  const key = 'orbis-recovery-' + randomBytes(32).toString('base64url');
  ui.element('recovery-key').value = key;
  ui.element('sign-in').fire('submit');
  await ui.settle();
  assert.equal(ui.element('overview').hidden, false);
  assert.equal(ui.element('recovery-key').value, '');
  assert.deepEqual(ui.calls.find((call) => call.route === 'challenge').body, { method: 'recovery-key' });
  assert.deepEqual(ui.calls.find((call) => call.route === 'login').body.credentials, { method: 'recovery-key', recoveryKey: key });
  assert.deepEqual(ui.storage, []);
  await ui.element('sign-out').fire('click');
  assert.equal(ui.focus(), 'recovery-key');
  await ui.release();
});

test('switching sign-in methods clears secrets, changes native validation and restores the relevant focus', async (t) => {
  const ui = await page(t);
  ui.element('password').value = 'test12345';
  ui.element('totp').value = '123456';
  ui.element('use-recovery-key').fire('click');
  assert.equal(ui.element('password').value, '');
  assert.equal(ui.element('totp').value, '');
  assert.equal(ui.element('password').required, false);
  assert.equal(ui.element('totp').required, false);
  assert.equal(ui.focus(), 'recovery-key');
  ui.element('recovery-key').value = 'do-not-retain';
  ui.element('use-recovery-key').fire('click');
  assert.equal(ui.element('recovery-key').value, '');
  assert.equal(ui.element('password').required, true);
  assert.equal(ui.element('totp').required, true);
  assert.equal(ui.element('recovery-key').required, false);
  assert.equal(ui.focus(), 'username');
  ui.element('appearance').value = 'dark';
  ui.element('appearance').fire('change');
  assert.deepEqual(ui.storage, [['orbis-sentinel.appearance', 'dark']]);
  await ui.release();
});

test('failed emergency authentication clears the key and focuses its field', async (t) => {
  const ui = await page(t, { keyOnly: true, failedLogin: true });
  ui.element('recovery-key').value = 'invalid-key';
  ui.element('sign-in').fire('submit');
  await ui.settle();
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.element('recovery-key').value, '');
  assert.equal(ui.focus(), 'recovery-key');
  assert.equal(ui.element('notice').dataset.error, 'true');
  assert.equal(ui.calls.some((call) => call.route === 'status'), false);
  await ui.release();
});

test('a restored session does not block initialization on observed status metadata', async (t) => {
  const ui = await page(t, { keyOnly: true, savedSession: true });
  assert.equal(ui.element('overview').hidden, false);
  assert.equal(ui.element('sign-out').disabled, false);
  assert.equal(ui.element('orbis-state').textContent, 'Checking…');
  await ui.release();
  assert.equal(ui.element('orbis-state').textContent, 'Unavailable');
  assert.equal(ui.element('sentinel-state').textContent, 'Healthy');
});

for (const [name, loginError, message] of [
  ['timeout', new DOMException('signal timed out', 'TimeoutError'), 'Sentinel did not respond in time. Try again.'],
  ['network failure', new TypeError('Failed to fetch'), 'Sentinel could not be reached. Check your connection and try again.'],
]) {
  test(`sign-in ${name} restores password focus and explains how to retry`, async (t) => {
    const ui = await page(t, { loginError });
    ui.element('username').value = 'test';
    ui.element('password').value = 'test12345';
    ui.element('totp').value = '123456';
    ui.element('sign-in').fire('submit');
    await ui.settle();
    assert.equal(ui.element('overview').hidden, true);
    assert.equal(ui.element('credentials').disabled, false);
    assert.equal(ui.element('notice').textContent, message);
    assert.equal(ui.element('notice').dataset.error, 'true');
    assert.equal(ui.focus(), 'password');
    assert.equal(ui.calls.some((call) => call.route === 'status'), false);
    await ui.release();
  });
}

test('losing the service before a key challenge restores key focus without submitting credentials', async (t) => {
  const ui = await page(t, { keyOnly: true, optionsError: new TypeError('Failed to fetch') });
  ui.element('recovery-key').value = 'synthetic-recovery-key';
  ui.element('sign-in').fire('submit');
  await ui.settle();
  assert.equal(ui.element('credentials').disabled, false);
  assert.equal(ui.element('recovery-key').value, '');
  assert.equal(ui.focus(), 'recovery-key');
  assert.equal(ui.element('notice').textContent, 'Sentinel could not be reached. Check your connection and try again.');
  assert.equal(ui.calls.some((call) => call.route === 'challenge' || call.route === 'login'), false);
  await ui.release();
});


test('handoff view distinguishes verified phases, idle, unavailable, and invalid held scope', () => {
  const states = {
    accepted: 'Accepted', stopping: 'Stopping Orbis', held: 'Controller held',
    returning: 'Returning to Orbis', complete: 'Return verified', attention: 'Needs attention',
  };
  for (const [state, label] of Object.entries(states)) {
    assert.equal(handoffView(handoffEnvelope(state)).phase, label);
    assert.equal(handoffView(handoffEnvelope(state)).id, plan);
  }
  assert.equal(handoffView(handoffEnvelope(null)).phase, 'No controller handoff');
  assert.equal(handoffView(unavailableHandoff).phase, 'Unavailable');
  assert.equal(handoffView({ ...handoffEnvelope(), ageMs: 5001 }).id, null);
  const wrongScope = handoffEnvelope();
  wrongScope.status.handoff.returnScope = { ...scope, planId: '12345678-1234-4123-8123-123456789abd' };
  assert.equal(handoffView(wrongScope).id, null);
});

test('held handoff renders its plan while Main is off without automatically dispatching an operation', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope() });
  await ui.release();
  assert.equal(ui.element('orbis-state').textContent, 'Unavailable');
  assert.equal(ui.element('handoff-phase').textContent, 'Controller held');
  assert.equal(ui.element('handoff-plan').textContent, plan);
  assert.equal(ui.element('handoff-record').hidden, false);
  assert.equal(ui.calls.some(({ route, body }) => body !== undefined || route === 'active'), false);
  const html = await readFile(new URL('../web/recovery.html', import.meta.url), 'utf8');
  const section = html.match(/<section id="handoff-status"[\s\S]*?<\/section>/)[0];
  assert.match(section, /id="review-return"/);
  assert.doesNotMatch(section, /installationId|handoffSha256/);
  assert.match(section, /role="status"/);
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.equal(ui.timers.size, 0);
});

test('handoff polling is one-inflight and clears cached or late content on hide, navigation, and sign-out', async (t) => {
  const ui = await page(t, { savedSession: true, holdHandoff: true, handoffValue: handoffEnvelope('complete') });
  const count = () => ui.calls.filter(({ route }) => route === 'handoff-status').length;
  ui.listeners.get('online')();
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  ui.document.hidden = false;
  ui.listeners.get('visibilitychange')();
  ui.listeners.get('pagehide')();
  ui.listeners.get('pageshow')();
  assert.equal(count(), 1);
  await ui.releaseHandoff(handoffEnvelope());
  assert.equal(ui.element('handoff-plan').textContent, '');
  await ui.tick(2000);
  assert.equal(count(), 2);
  assert.equal(ui.element('handoff-phase').textContent, 'Return verified');
  await ui.element('sign-out').fire('click');
  assert.equal(ui.element('handoff-record').hidden, true);
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.equal(ui.timers.size, 0);
  await ui.release();
});

test('late handoff response cannot restore a plan after sign-out', async (t) => {
  const ui = await page(t, { savedSession: true, holdHandoff: true });
  await ui.element('sign-out').fire('click');
  await ui.releaseHandoff(handoffEnvelope());
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.timers.size, 0);
  await ui.release();
});

test('handoff 401 clears the signed-in view without issuing activity or a login', async (t) => {
  const ui = await page(t, { savedSession: true, handoffCode: 401 });
  await ui.settle();
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.equal(ui.element('overview').hidden, true);
  assert.equal(ui.element('notice').textContent, 'Your recovery session expired. Sign in again.');
  assert.ok(ui.calls.every(({ body }) => body === undefined));
  assert.equal(ui.timers.size, 0);
  await ui.release();
});

test('verified handoff expires while the next poll remains pending', async (t) => {
  const value = { ...handoffEnvelope('complete'), ageMs: 4999 };
  const ui = await page(t, { savedSession: true, holdHandoff: true, holdHandoffAt: 2, handoffValue: value });
  await ui.release();
  assert.equal(ui.element('handoff-phase').textContent, 'Return verified');
  const poll = [...ui.timers].find(([, timer]) => timer.delay === 2000);
  ui.timers.delete(poll[0]);
  const pending = poll[1].action();
  assert.equal(ui.calls.filter(({ route }) => route === 'handoff-status').length, 2);
  ui.advance(1);
  await ui.tick(1);
  assert.equal(ui.element('handoff-phase').textContent, 'Unavailable');
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.equal(ui.element('handoff-record').hidden, true);
  await ui.releaseHandoff(value);
  await pending;
});

test('request latency consumes the sample lifetime before it can be displayed', async (t) => {
  const ui = await page(t, { savedSession: true, holdHandoff: true });
  ui.advance(5001);
  await ui.releaseHandoff({ ...handoffEnvelope('complete'), ageMs: 0 });
  assert.equal(ui.element('handoff-phase').textContent, 'Unavailable');
  assert.equal(ui.element('handoff-plan').textContent, '');
  assert.ok([...ui.timers.values()].every(({ delay }) => delay === 1000 || delay === 2000 || delay === 5000));
  await ui.release();
});

test('a retired display timer cannot erase a newer generation', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope('complete') });
  await ui.release();
  const retired = [...ui.timers.values()].find(({ delay }) => delay === 4980);
  assert.ok(retired);
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  ui.document.hidden = false;
  ui.listeners.get('visibilitychange')();
  await new Promise(setImmediate);
  assert.equal(ui.element('handoff-phase').textContent, 'Return verified');
  retired.action();
  assert.equal(ui.element('handoff-phase').textContent, 'Return verified');
});

test('return requires a separate confirmation and only fixed status can verify completion', async (t) => {
  let status = handoffEnvelope();
  const ui = await page(t, { savedSession: true, handoffValue: () => status });
  await ui.release();
  assert.equal(ui.element('review-return').hidden, false);
  await ui.element('review-return').fire('click');
  const approval = ui.calls.filter(({ route }) => route === 'controller-return-approval');
  assert.equal(approval.length, 1);
  assert.deepEqual(approval[0].body, { scope });
  assert.equal(approval[0].headers['X-Orbis-Sentinel-CSRF'], 'synthetic-csrf');
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
  assert.equal(ui.element('confirm-return').hidden, false);
  assert.equal(ui.focus(), 'return-title');
  await ui.tick(2000);
  assert.equal(ui.element('confirm-return').hidden, false, 'same fresh scope retains the review');
  await ui.element('confirm-return').fire('submit');
  await new Promise(setImmediate);
  const dispatch = ui.calls.filter(({ route }) => route === 'controller-return');
  assert.equal(dispatch.length, 1);
  assert.deepEqual(dispatch[0].body, { scope, approvalId: 'c'.repeat(64) });
  assert.equal(dispatch[0].headers['X-Orbis-Sentinel-CSRF'], 'synthetic-csrf');
  assert.notEqual(ui.element('handoff-phase').textContent, 'Return verified');
  assert.equal(ui.element('review-return').hidden, true);
  status = handoffEnvelope('complete');
  await ui.tick(2000);
  assert.equal(ui.element('handoff-phase').textContent, 'Return verified');
  assert.equal(ui.element('controller-return').hidden, true);
});

test('cancel returns focus without dispatch and elapsed expiry prevents a start', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(),
    approvalValue: { approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 2000 } });
  await ui.release();
  await ui.element('review-return').fire('click');
  ui.element('cancel-return').fire('click');
  assert.equal(ui.focus(), 'review-return');
  assert.equal(ui.element('confirm-return').hidden, true);
  await ui.element('confirm-return').fire('submit');
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
  await ui.element('review-return').fire('click');
  ui.advance(3000);
  await ui.element('confirm-return').fire('submit');
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
  assert.match(ui.element('return-notice').textContent, /expired/);
});

test('stale status immediately retires a confirmation even if its grant has time left', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope() });
  await ui.release();
  await ui.element('review-return').fire('click');
  await ui.tick(4980);
  assert.equal(ui.element('confirm-return').hidden, true);
  assert.equal(ui.element('controller-return').hidden, true);
  assert.equal(ui.focus(), 'handoff-title');
  await ui.element('confirm-return').fire('submit');
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
});

test('late approval after sign-out cannot reveal or dispatch a confirmation', async (t) => {
  const ui = await page(t, { savedSession: true, holdApproval: true, handoffValue: handoffEnvelope() });
  await ui.release();
  const pending = ui.element('review-return').fire('click');
  await ui.element('sign-out').fire('click');
  await ui.releaseApproval({ approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000 });
  await pending;
  assert.equal(ui.element('confirm-return').hidden, true);
  assert.equal(ui.element('controller-return').hidden, true);
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
});

test('a changed held scope discards an outstanding approval response', async (t) => {
  let status = handoffEnvelope();
  const ui = await page(t, { savedSession: true, holdApproval: true, handoffValue: () => status });
  await ui.release();
  const pending = ui.element('review-return').fire('click');
  status = handoffEnvelope();
  status.status.handoff.returnScope = { ...scope, handoffSha256: 'e'.repeat(64) };
  await ui.tick(2000);
  await ui.releaseApproval({ approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000 });
  await pending;
  assert.equal(ui.element('confirm-return').hidden, true);
  assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
});

test('uncertain dispatch is never retried and a fresh held observation permits a new review', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), returnValue: { error: 'Unavailable' }, returnCode: 503 });
  await ui.release();
  await ui.element('review-return').fire('click');
  await ui.element('confirm-return').fire('submit');
  await new Promise(setImmediate);
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return').length, 1);
  assert.equal(ui.element('review-return').hidden, true);
  ui.advance(2000);
  await ui.tick(2000);
  assert.equal(ui.element('review-return').hidden, false);
  assert.match(ui.element('return-notice').textContent, /still held/);
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return').length, 1);
});

test('duplicate clicks share one approval and one dispatch, and direct reply cannot supply completion', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), holdApproval: true, holdReturn: true });
  await ui.release();
  const preparing = ui.element('review-return').fire('click');
  await ui.element('review-return').fire('click');
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return-approval').length, 1);
  await ui.releaseApproval({ approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000 });
  await preparing;
  const dispatch = ui.element('confirm-return').fire('submit');
  await ui.element('confirm-return').fire('submit');
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return').length, 1);
  await ui.releaseReturn({ planId: plan, state: 'complete', phase: 'complete' });
  await dispatch;
  await new Promise(setImmediate);
  assert.equal(ui.element('handoff-phase').textContent, 'Controller held');
});

for (const endpoint of ['approval', 'dispatch']) {
  test(`return ${endpoint} session expiry clears confirmation and all timers`, async (t) => {
    const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(),
      ...(endpoint === 'approval' ? { approvalCode: 401, approvalValue: { error: 'Expired' } }
        : { returnCode: 401, returnValue: { error: 'Expired' } }) });
    await ui.release();
    await ui.element('review-return').fire('click');
    if (endpoint === 'dispatch') await ui.element('confirm-return').fire('submit');
    assert.equal(ui.element('overview').hidden, true);
    assert.equal(ui.element('confirm-return').hidden, true);
    assert.equal(ui.timers.size, 0);
    assert.equal(ui.element('notice').textContent, 'Your recovery session expired. Sign in again.');
  });
}

for (const [name, change] of Object.entries({
  'extra authority': { private: 'unexpected' },
  'foreign scope': { scope: { ...scope, installationId: 'd'.repeat(64) } },
  'invalid identifier': { approvalId: 'invalid' },
  'expired grant': { expiresAtMs: 1 },
  'unbounded grant': { expiresAtMs: Number.MAX_SAFE_INTEGER },
})) {
  test(`return rejects ${name} without showing confirmation`, async (t) => {
    const value = { approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000, ...change };
    const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), approvalValue: value });
    await ui.release();
    await ui.element('review-return').fire('click');
    assert.equal(ui.element('confirm-return').hidden, true);
    assert.equal(ui.calls.some(({ route }) => route === 'controller-return'), false);
    assert.match(ui.element('return-notice').textContent, /could not be verified/);
  });
}

test('independent review: approval initiation checks held freshness before a delayed timer runs', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope() });
  await ui.release();
  ui.advance(4981);
  await ui.element('review-return').fire('click');
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return-approval').length, 0);
});

test('independent review: late approval cannot expose confirmation using expired held status', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), holdApproval: true });
  await ui.release();
  const preparing = ui.element('review-return').fire('click');
  ui.advance(4981);
  await ui.releaseApproval({ approvalId: 'c'.repeat(64), scope, expiresAtMs: Date.now() + 30000 });
  await preparing;
  assert.equal(ui.element('confirm-return').hidden, true);
});

test('independent review: dispatch checks held freshness independently of a valid grant', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope() });
  await ui.release();
  await ui.element('review-return').fire('click');
  ui.advance(4981);
  await ui.element('confirm-return').fire('submit');
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return').length, 0);
});

test('independent review: expired held scope moves focus away from the hidden review opener', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope() });
  await ui.release();
  ui.element('review-return').focus();
  await ui.tick(4980);
  assert.equal(ui.element('controller-return').hidden, true);
  assert.equal(ui.focus(), 'handoff-title');
});

for (const endpoint of ['approval', 'dispatch']) {
  test(`independent review: ${endpoint} session expiry focuses a surviving sign-in field`, async (t) => {
    const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(),
      ...(endpoint === 'approval' ? { approvalCode: 401, approvalValue: { error: 'Expired' } }
        : { returnCode: 401, returnValue: { error: 'Expired' } }) });
    await ui.release();
    ui.element('review-return').focus();
    await ui.element('review-return').fire('click');
    if (endpoint === 'dispatch') {
      ui.element('start-return').focus();
      await ui.element('confirm-return').fire('submit');
    }
    assert.equal(ui.element('sign-in').hidden, false);
    assert.equal(ui.focus(), 'username');
  });
}

test('independent review: tab visibility does not erase uncertain dispatch before a post-response observation', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), returnCode: 503, returnValue: { error: 'Unavailable' } });
  await ui.release();
  await ui.element('review-return').fire('click');
  await ui.element('confirm-return').fire('submit');
  await new Promise(setImmediate);
  assert.equal(ui.element('review-return').hidden, true);
  ui.document.hidden = true;
  ui.listeners.get('visibilitychange')();
  ui.document.hidden = false;
  ui.listeners.get('visibilitychange')();
  await new Promise(setImmediate);
  assert.equal(ui.element('review-return').hidden, true);
});

test('independent review: authoritative attention retires the pending startup copy', async (t) => {
  let status = handoffEnvelope();
  const ui = await page(t, { savedSession: true, handoffValue: () => status, holdReturn: true });
  await ui.release();
  await ui.element('review-return').fire('click');
  const dispatch = ui.element('confirm-return').fire('submit');
  status = handoffEnvelope('attention');
  await ui.tick(2000);
  await ui.releaseReturn({ planId: plan, state: 'return-accepted', phase: 'return-accepted' });
  await dispatch;
  assert.equal(ui.element('handoff-phase').textContent, 'Needs attention');
  assert.equal(ui.element('controller-return').hidden, true);
});

test('foreign terminal status cannot settle a pending controller return', async (t) => {
  let status = handoffEnvelope();
  const ui = await page(t, { savedSession: true, handoffValue: () => status, holdReturn: true });
  await ui.release();
  await ui.element('review-return').fire('click');
  const pending = ui.element('confirm-return').fire('submit');
  status = handoffEnvelope('complete');
  status.status.handoff.planId = '12345678-1234-4123-8123-123456789abd';
  await ui.tick(2000);
  assert.equal(ui.element('controller-return').hidden, false);
  assert.equal(ui.element('review-return').hidden, true);
  await ui.releaseReturn({ planId: plan, state: 'return-accepted', phase: 'return-accepted' });
  await pending;
  assert.equal(ui.element('controller-return').hidden, false);
});

test('page navigation preserves pending reconciliation through a late dispatch reply', async (t) => {
  const ui = await page(t, { savedSession: true, handoffValue: handoffEnvelope(), holdReturn: true });
  await ui.release();
  await ui.element('review-return').fire('click');
  const pending = ui.element('confirm-return').fire('submit');
  ui.listeners.get('pagehide')();
  await ui.releaseReturn({ planId: plan, state: 'return-accepted', phase: 'return-accepted' });
  await pending;
  ui.listeners.get('pageshow')();
  await new Promise(setImmediate);
  assert.equal(ui.element('review-return').hidden, true);
  assert.equal(ui.calls.filter(({ route }) => route === 'controller-return').length, 1);
});
