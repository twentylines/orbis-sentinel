const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const stages = {
  preparing: 'Preparing the capture',
  'stopping-orbis': 'Pausing Orbis',
  'saving-orbis': 'Saving Orbis',
  'starting-orbis': 'Starting Orbis',
  'stopping-apps': 'Pausing selected apps',
  'saving-apps': 'Saving selected app data',
  'starting-apps': 'Starting selected apps',
  sealing: 'Finishing the capture',
  complete: 'Starting Orbis',
};
const exact = (value, fields) =>
  value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join() === [...fields].sort().join();
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const validPoint = (value) => typeof value === 'string' && value.length === 36 && uuid.test(value);

export function captureView(envelope, point) {
  const waiting = {
    title: 'Capturing Orbis',
    text: 'Waiting for the server to respond.',
    mode: 'waiting',
    phase: 'preparing',
    percent: null,
    counts: null,
    complete: false,
  };
  if (
    !validPoint(point) ||
    !exact(envelope, ['schema', 'id', 'available', 'progress', 'ageMs', 'sourceState']) ||
    envelope.schema !== 'orbis-sentinel.capture-progress.v1' ||
    envelope.id !== point ||
    envelope.available !== true ||
    envelope.sourceState !== 'ready' ||
    !count(envelope.ageMs) ||
    envelope.ageMs > 5000
  )
    return waiting;
  const p = envelope.progress;
  if (
    !exact(p, ['version', 'id', 'state', 'phase', 'completedBytes', 'totalBytes', 'restartVerified']) ||
    p.version !== 1 ||
    p.id !== point ||
    !['waiting', 'running', 'recovery-required', 'complete'].includes(p.state) ||
    !Object.hasOwn(stages, p.phase) ||
    !count(p.completedBytes) ||
    !(p.totalBytes === null || count(p.totalBytes)) ||
    (p.totalBytes !== null && p.completedBytes > p.totalBytes) ||
    typeof p.restartVerified !== 'boolean' ||
    (p.state === 'complete') !== (p.phase === 'complete') ||
    p.restartVerified !== (p.state === 'complete')
  )
    return waiting;
  if (p.state === 'recovery-required')
    return { ...waiting, title: 'Capture stopped', text: 'Recovery details are saved.', mode: 'failed', phase: p.phase };
  const boot = p.phase === 'starting-orbis' || p.state === 'complete';
  return {
    title: boot ? 'Starting Orbis' : 'Capturing Orbis',
    text: stages[p.phase],
    mode: boot ? 'boot' : 'capturing',
    phase: p.phase,
    percent: !boot && p.totalBytes > 0 ? Math.min(99, Math.floor((p.completedBytes / p.totalBytes) * 100)) : null,
    counts: !boot && p.totalBytes > 0 ? [p.completedBytes, p.totalBytes] : null,
    complete: p.state === 'complete' && p.restartVerified,
  };
}

export function mainHealthReady(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Object.hasOwn(value, 'maintenance') &&
    value.status === 'ok' &&
    value.info?.queue?.status === 'up' &&
    value.details?.queue?.status === 'up'
  );
}

export async function boundedJSON(response) {
  if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) throw Error('Unavailable');
  const reader = response.body?.getReader();
  if (!reader) throw Error('Unavailable');
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16384) throw Error('Unavailable');
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function dashboardDestination(fetcher, signal) {
  const options = { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal };
  const health = await fetcher('/api/health', options);
  if (!health.ok || !mainHealthReady(await boundedJSON(health))) return null;
  const build = await fetcher('/api/system/build', options);
  if (build.status === 401) return '/login';
  if (!build.ok) return null;
  const value = await boundedJSON(build);
  return value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    ['version', 'commit', 'imageDigest', 'runtipiCompatibility'].every((key) => Object.hasOwn(value, key)) &&
    ['commit', 'imageDigest', 'runtipiCompatibility'].every(
      (key) => value[key] === null || (typeof value[key] === 'string' && value[key].length <= 256),
    ) &&
    typeof value.version === 'string' &&
    /^(?:v?\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?|development)$/.test(value.version)
    ? '/dashboard'
    : null;
}

function bytes(value) {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index++;
  }
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(amount)} ${units[index]}`;
}

export function startCapturePage(
  doc,
  location,
  fetcher = fetch,
  timers = { setTimeout: (run, delay) => globalThis.setTimeout(run, delay), clearTimeout: (id) => globalThis.clearTimeout(id) },
) {
  const point = /^\/sentinel\/captures\/([^/]+)$/.exec(location.pathname)?.[1];
  if (!validPoint(point)) return () => undefined;
  const main = doc.querySelector('main');
  const title = doc.querySelector('h1');
  const stage = doc.querySelector('.stage');
  const meter = doc.querySelector('progress');
  const scan = doc.querySelector('.scan');
  const counts = doc.querySelector('.counts');
  const notice = doc.querySelector('.notice');
  if (![main, title, stage, meter, scan, counts, notice].every(Boolean)) return () => undefined;
  let epoch = 0;
  let pending = false;
  let timer = null;
  let controller = null;
  let disposed = false;
  let finished = false;
  let last = '';
  const render = (view) => {
    const signature = JSON.stringify(view);
    if (signature === last) return;
    last = signature;
    main.dataset.mode = view.mode;
    main.dataset.phase = view.phase;
    title.textContent = view.title;
    stage.textContent = view.mode === 'boot' ? 'Orbis will open automatically.' : view.text;
    meter.hidden = view.percent === null;
    if (!meter.hidden) meter.value = view.percent;
    scan.hidden = view.mode !== 'capturing' || view.percent !== null;
    counts.hidden = view.counts === null;
    counts.textContent = view.counts ? `${bytes(view.counts[0])} of ${bytes(view.counts[1])}` : '';
  };
  const schedule = (delay) => {
    timers.clearTimeout(timer);
    if (!disposed && !finished && !doc.hidden) timer = timers.setTimeout(run, delay);
  };
  const run = async () => {
    if (pending || disposed || finished || doc.hidden) return;
    pending = true;
    const current = epoch;
    controller = new AbortController();
    const timeout = timers.setTimeout(() => controller?.abort(), 5000);
    try {
      const response = await fetcher(`/sentinel/api/v1/captures/${point}/progress`, {
        cache: 'no-store',
        credentials: 'same-origin',
        redirect: 'error',
        signal: controller.signal,
      });
      const view = captureView(response.ok ? await boundedJSON(response) : null, point);
      if (current !== epoch || disposed) return;
      render(view);
      if (view.complete) {
        let destination = null;
        try {
          destination = await dashboardDestination(fetcher, controller.signal);
        } catch {
          destination = null;
        }
        if (destination && current === epoch && !disposed) {
          finished = true;
          location.replace(destination);
        }
      }
    } catch {
      if (current === epoch && !disposed) render(captureView(null, point));
    } finally {
      timers.clearTimeout(timeout);
      controller = null;
      pending = false;
      schedule(current === epoch ? 1000 : 0);
    }
  };
  const visibility = () => {
    epoch++;
    doc.documentElement.toggleAttribute('data-paused', doc.hidden);
    timers.clearTimeout(timer);
    if (doc.hidden) controller?.abort();
    else if (!pending) schedule(0);
  };
  doc.addEventListener('visibilitychange', visibility);
  doc.documentElement.toggleAttribute('data-paused', doc.hidden);
  schedule(0);
  return () => {
    disposed = true;
    epoch++;
    timers.clearTimeout(timer);
    controller?.abort();
    doc.removeEventListener('visibilitychange', visibility);
  };
}

if (typeof document !== 'undefined') startCapturePage(document, window.location);
