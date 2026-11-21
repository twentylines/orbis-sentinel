const portal = '/sentinel/recovery/';
const api = portal + 'api/v1';

export function decodeBase64url(value) {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (character) => character.charCodeAt(0));
}

export function encodeBase64url(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function passkeyResponse(credential) {
  const response = credential.response;
  return {
    id: credential.id, rawId: encodeBase64url(credential.rawId), type: 'public-key',
    clientExtensionResults: credential.getClientExtensionResults(),
    ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}),
    response: {
      clientDataJSON: encodeBase64url(response.clientDataJSON), authenticatorData: encodeBase64url(response.authenticatorData),
      signature: encodeBase64url(response.signature), userHandle: response.userHandle ? encodeBase64url(response.userHandle) : null,
    },
  };
}

const bytesText = (bytes) => {
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const unit = Math.min(Math.floor(Math.log2(Math.max(1, bytes)) / 10), units.length - 1);
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(bytes / 1024 ** unit)} ${units[unit]}`;
};

export function progressView(value) {
  const unavailable = { phase: 'Unavailable', detail: 'Update progress is unavailable. Retrying automatically.', ongoing: false, attention: false, percent: null, record: null };
  if (value?.schema !== 'orbis-sentinel.progress.v1' || typeof value.available !== 'boolean') throw new Error('Invalid update progress');
  if (!value.available) return unavailable;
  const job = value.progress?.job;
  if (value.progress?.version !== 1 || job === undefined) throw new Error('Invalid update progress');
  if (job === null) return { ...unavailable, phase: 'No update in progress', detail: 'No Orbis update operation is reported.', record: null };
  const states = { queued: 'Queued', running: 'Updating', recovering: 'Recovering', complete: 'Complete', failed: 'Failed', interrupted: 'Interrupted' };
  const phases = { downloading: 'Downloading', installing: 'Installing', restarting: 'Restarting Orbis', verifying: 'Verifying', recovering: 'Recovering' };
  if (!Object.hasOwn(states, job.state) || typeof job.id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(job.id)
      || typeof job.targetTag !== 'string' || job.targetTag.length > 100 || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$/.test(job.targetTag)
      || job.phase !== null && !Object.hasOwn(phases, job.phase)) throw new Error('Invalid update progress');
  const ongoing = ['queued', 'running', 'recovering'].includes(job.state);
  let phase = ongoing ? phases[job.phase] || states[job.state] : states[job.state];
  let detail = job.state === 'complete' ? 'The update operation completed. Controller health is shown above.'
    : ['failed', 'interrupted'].includes(job.state) ? 'This update needs attention. Its recorded operation is shown below.'
    : 'Sentinel will keep this progress visible while Orbis restarts.';
  let percent = job.state === 'complete' ? 100 : null;
  if (ongoing && job.download && ['downloading', 'installing'].includes(job.phase)) {
    const d = job.download;
    if (!Number.isSafeInteger(d.currentBytes) || d.currentBytes < 0 || d.totalBytes !== null && (!Number.isSafeInteger(d.totalBytes) || d.totalBytes < d.currentBytes))
      throw new Error('Invalid download progress');
    if (d.phase === 'extracting') {
      phase = 'Extracting';
      detail = d.layersTotal > 0 ? `${d.layersComplete} of ${d.layersTotal} layers ready` : 'Extracting the downloaded image.';
    } else if (d.phase !== 'complete') {
      detail = d.totalBytes === null ? `${bytesText(d.currentBytes)} received` : `${bytesText(d.currentBytes)} of ${bytesText(d.totalBytes)} received`;
      if (d.totalBytes > 0) percent = d.currentBytes / d.totalBytes * 100;
    } else detail = d.alreadyCached ? 'The required image is already cached. Preparing the next phase.' : 'Image download complete. Preparing the next phase.';
  }
  return { phase, detail, ongoing, attention: ['failed', 'interrupted'].includes(job.state), percent, record: { target: job.targetTag.slice(1), id: job.id } };
}

const handoffSchema = 'orbis-sentinel.handoff-status.v1';
const handoffUnavailable = { phase: 'Unavailable', detail: 'Sentinel could not verify the controller handoff status.', id: null };
const handoffChecking = { phase: 'Checking…', detail: '', id: null };
const handoffStates = {
  accepted: ['Accepted', 'The host accepted the controller handoff.'],
  stopping: ['Stopping Orbis', 'The host is stopping the Orbis controller.'],
  held: ['Controller held', 'The host verified that the Orbis controller is stopped.'],
  returning: ['Returning to Orbis', 'The host is restoring the controller and checking its startup.'],
  complete: ['Return verified', 'The host verified a fresh, healthy startup for this handoff.'],
  attention: ['Needs attention', 'Review this handoff on the host.'],
};
const planId = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const scopeHash = /^[a-f0-9]{64}$/;
const hasKeys = (value, keys) => value !== null && typeof value === 'object'
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

export function handoffView(value) {
  if (!hasKeys(value, ['schema', 'status', 'ageMs']) || value.schema !== handoffSchema)
    return handoffUnavailable;
  if (value.status === null) return handoffUnavailable;
  if (!Number.isInteger(value.ageMs) || value.ageMs < 0 || value.ageMs > 5000
      || !hasKeys(value.status, ['version', 'handoff']) || value.status.version !== 1)
    return handoffUnavailable;
  const { handoff } = value.status;
  if (handoff === null) return { phase: 'No controller handoff', detail: '', id: null };
  if (typeof handoff?.state !== 'string' || !Object.hasOwn(handoffStates, handoff.state)
      || typeof handoff.planId !== 'string' || handoff.planId.length !== 36 || !planId.test(handoff.planId))
    return handoffUnavailable;
  const held = handoff.state === 'held';
  if (!hasKeys(handoff, held ? ['planId', 'state', 'returnScope'] : ['planId', 'state']))
    return handoffUnavailable;
  if (held) {
    const scope = handoff.returnScope;
    if (!hasKeys(scope, ['planId', 'installationId', 'handoffSha256']) || scope.planId !== handoff.planId
        || ![scope.installationId, scope.handoffSha256].every((value) => typeof value === 'string'
          && value.length === 64 && scopeHash.test(value)))
      return handoffUnavailable;
  }
  const [phase, detail] = handoffStates[handoff.state];
  return { phase, detail, id: handoff.planId, attention: handoff.state === 'attention' };
}

export async function start() {
  const element = (id) => document.getElementById(id);
  let authenticated = false;
  let busy = false;
  let usingRecoveryKey = false;
  let options = { password: false, recoveryKey: false, passkey: false, totp: { password: false, passkey: false } };
  let poll;
  let lastActivity = 0;
  let generation = 0;
  let statusSequence = 0;
  let progressPoll;
  let progressBusy = false;
  let handoffPoll;
  let handoffExpiry;
  let handoffDisplay = 0;
  let handoffBusy = false;
  let handoffGeneration = 0;
  let heldScope = null;
  let heldDeadline = 0;
  let returnApproval = null;
  let returnExpiry;
  let returnBusy = false;
  let returnPending = null;
  let returnObservedAfter = Infinity;
  let returnSequence = 0;
  let returnFocusLost = false;
  let connecting = false;
  let connectionNeeded = true;
  let leaving = false;
  const notice = (text, error = false) => {
    element('notice').textContent = text;
    element('notice').dataset.error = String(error);
  };
  const cookie = (suffix) => {
    for (const prefix of ['__Host-orbis-sentinel-', 'orbis-sentinel-local-']) {
      const name = prefix + suffix + '=';
      const item = document.cookie.split(';').map((value) => value.trim()).find((value) => value.startsWith(name));
      if (item) return item.slice(name.length);
    }
    return '';
  };
  const request = async (path, body, csrf = false) => {
    let reply;
    try {
      reply = await fetch(api + path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(csrf ? { 'X-Orbis-Sentinel-CSRF': cookie('csrf') } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(18000),
      });
    } catch (error) {
      if (error.name === 'TimeoutError') throw new Error('Sentinel did not respond in time. Try again.');
      if (error instanceof TypeError) throw new Error('Sentinel could not be reached. Check your connection and try again.');
      throw error;
    }
    const result = await reply.json();
    if (!reply.ok) {
      const error = new Error(result.error || 'Sentinel could not complete the request.');
      error.status = reply.status;
      throw error;
    }
    return result;
  };
  const setBusy = (value, message = 'Signing in…') => {
    busy = value;
    element('credentials').disabled = value;
    element('sign-out').disabled = value;
    element('recovery-panel').setAttribute('aria-busy', String(value));
    element('submit').textContent = value ? message : 'Sign in';
  };
  const updateMethod = () => {
    if (!options.password) usingRecoveryKey = true;
    if (!options.recoveryKey) usingRecoveryKey = false;
    element('account-fields').hidden = usingRecoveryKey;
    element('recovery-key-field').hidden = !usingRecoveryKey;
    element('recovery-key').required = usingRecoveryKey;
    element('username').required = !usingRecoveryKey;
    element('password').required = !usingRecoveryKey;
    element('passkey').hidden = usingRecoveryKey || !options.passkey || !window.PublicKeyCredential;
    element('totp-field').hidden = usingRecoveryKey || (!options.totp.password && !options.totp.passkey);
    element('totp').required = !usingRecoveryKey && options.totp.password;
    element('use-recovery-key').hidden = !options.recoveryKey || !options.password;
    element('use-recovery-key').textContent = usingRecoveryKey ? 'Use Orbis sign-in' : 'Use a recovery key';
    if (!authenticated) element('page-description').textContent = usingRecoveryKey
      ? 'Sign in with your saved recovery key.' : 'Sign in with your Orbis operator account.';
  };
  const loadOptions = async () => {
    const current = generation;
    const result = await request('/options');
    if (leaving || current !== generation) return false;
    options = result;
    updateMethod();
    return true;
  };
  const signedOut = (message = '') => {
    authenticated = false;
    generation++;
    clearTimeout(poll);
    clearTimeout(progressPoll);
    clearHandoff({ resetReturn: true });
    element('overview').hidden = true;
    element('recovery-setup').hidden = true;
    element('sign-out').hidden = true;
    element('sign-in').hidden = false;
    element('recovery-panel').classList.remove('authenticated');
    element('password').value = '';
    element('totp').value = '';
    element('recovery-key').value = '';
    updateMethod();
    notice(message);
  };
  const refresh = async () => {
    clearTimeout(poll);
    if (!authenticated || document.hidden || leaving) return;
    const current = generation;
    const sequence = ++statusSequence;
    try {
      const result = await request('/status');
      if (current !== generation || sequence !== statusSequence || !authenticated) return;
      const labels = { unknown: 'Unknown', healthy: 'Healthy', unavailable: 'Unavailable', updating: 'Updating', recovering: 'Recovering' };
      for (const name of ['orbis', 'sentinel']) {
        const component = result.components[name];
        element(name + '-version').textContent = component.installedVersion || 'Unavailable';
        element(name + '-state').textContent = labels[component.state] || 'Unknown';
      }
      notice('');
    } catch (error) {
      if (current !== generation || sequence !== statusSequence || !authenticated) return;
      if (error.status === 401) {
        signedOut('Your recovery session expired. Sign in again.');
        element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
        return;
      }
      for (const name of ['orbis', 'sentinel']) element(name + '-state').textContent = 'Unavailable';
      notice('Sentinel status could not be refreshed. It will retry automatically.', true);
    }
    if (authenticated && sequence === statusSequence) poll = setTimeout(refresh, 5000);
  };
  const renderProgress = (view) => {
    const text = (id, value) => {
      const target = element(id);
      if (target.textContent !== value) target.textContent = value;
    };
    text('update-phase', view.phase);
    text('update-detail', view.detail);
    element('update-progress').dataset.attention = String(view.attention);
    element('update-spinner').hidden = !view.ongoing;
    element('update-record').hidden = !view.record;
    text('update-target', view.record?.target || '');
    text('update-operation', view.record?.id || '');
    const bar = element('update-bar');
    bar.hidden = !view.ongoing && view.percent === null;
    bar.setAttribute('aria-valuetext', view.phase);
    if (view.percent === null) bar.removeAttribute('value');
    else bar.setAttribute('value', String(view.percent));
  };
  const refreshProgress = async () => {
    clearTimeout(progressPoll);
    if (!authenticated || document.hidden || leaving || progressBusy) return;
    progressBusy = true;
    const current = generation;
    try {
      const result = await request('/progress');
      if (current !== generation || !authenticated || leaving) return;
      renderProgress(progressView(result));
    } catch (error) {
      if (current !== generation || !authenticated || leaving) return;
      if (error.status === 401) {
        signedOut('Your recovery session expired. Sign in again.');
        element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
        return;
      }
      renderProgress(progressView({ schema: 'orbis-sentinel.progress.v1', available: false }));
    } finally {
      progressBusy = false;
      if (authenticated && !document.hidden && !leaving) progressPoll = setTimeout(refreshProgress, 1000);
    }
  };
  const sameScope = (left, right) => left !== null && right !== null
    && ['planId', 'installationId', 'handoffSha256'].every((key) => left[key] === right[key]);
  const returnNotice = (message = '') => {
    element('return-notice').textContent = message;
    element('return-notice').hidden = !message;
  };
  const clearReturnApproval = () => {
    returnFocusLost ||= ['review-return', 'return-title', 'start-return', 'cancel-return']
      .some((id) => element(id) === document.activeElement);
    returnApproval = null;
    clearTimeout(returnExpiry);
    element('confirm-return').hidden = true;
  };
  const renderReturn = () => {
    element('controller-return').hidden = !heldScope && !returnPending;
    element('review-return').hidden = !heldScope || !!returnApproval || !!returnPending;
    element('review-return').disabled = returnBusy;
    element('start-return').disabled = returnBusy;
    element('cancel-return').disabled = returnBusy;
    if (returnFocusLost && canPollHandoff()) {
      element(element('review-return').hidden ? 'handoff-title' : 'review-return').focus();
    }
    returnFocusLost = false;
  };
  const renderHandoff = (view, scope = null) => {
    for (const [id, value] of [['handoff-phase', view.phase], ['handoff-detail', view.detail], ['handoff-plan', view.id || '']]) {
      const target = element(id);
      if (target.textContent !== value) target.textContent = value;
    }
    element('handoff-detail').hidden = !view.detail;
    element('handoff-record').hidden = !view.id;
    element('handoff-status').dataset.attention = String(!!view.attention);
    if (!scope) heldDeadline = 0;
    if (!sameScope(heldScope, scope)) {
      heldScope = scope;
      returnSequence++;
      clearReturnApproval();
    }
    if (returnPending && view.id === returnPending.scope.planId
        && [handoffStates.complete[0], handoffStates.attention[0]].includes(view.phase)) {
      returnPending = null;
      returnNotice();
    }
    renderReturn();
  };
  const expireHandoff = () => {
    handoffDisplay++;
    clearTimeout(handoffExpiry);
    renderHandoff(handoffUnavailable);
  };
  const clearHandoff = ({ resetReturn = false } = {}) => {
    handoffGeneration++;
    clearTimeout(handoffPoll);
    handoffDisplay++;
    clearTimeout(handoffExpiry);
    if (resetReturn) {
      returnPending = null;
      returnObservedAfter = Infinity;
      returnNotice();
    }
    renderHandoff(handoffChecking);
  };
  const canPollHandoff = () => authenticated && !document.hidden && !leaving;
  const freshHeld = () => {
    if (!heldScope) return false;
    if (performance.now() < heldDeadline) return true;
    expireHandoff();
    return false;
  };
  const refreshHandoff = async () => {
    clearTimeout(handoffPoll);
    if (!canPollHandoff() || handoffBusy) return;
    handoffBusy = true;
    const current = handoffGeneration;
    const started = performance.now();
    try {
      const result = await request('/handoff-status');
      if (current !== handoffGeneration || !canPollHandoff()) return;
      handoffDisplay++;
      clearTimeout(handoffExpiry);
      // Account for all request time conservatively: the sample may have been
      // taken before the request, and a pending poll must not extend its life.
      const elapsed = Math.ceil(Math.max(0, performance.now() - started));
      const age = result?.ageMs;
      const adjusted = Number.isInteger(age) && age >= 0 ? age + elapsed : NaN;
      const remaining = 5000 - adjusted;
      if (!Number.isFinite(remaining) || remaining <= 0) { expireHandoff(); return; }
      const view = handoffView({ ...result, ageMs: adjusted });
      const scope = view !== handoffUnavailable && result.status?.handoff?.state === 'held'
        ? { ...result.status.handoff.returnScope } : null;
      if (returnPending && !returnBusy && scope && sameScope(scope, returnPending.scope)
          && performance.now() - adjusted >= returnObservedAfter) {
        returnPending = null;
        returnNotice('Orbis is still held. You can review the return again.');
      }
      heldDeadline = scope ? performance.now() + remaining : 0;
      renderHandoff(view, scope);
      if (view === handoffUnavailable) return;
      const display = handoffDisplay;
      handoffExpiry = setTimeout(() => {
        if (current === handoffGeneration && display === handoffDisplay) expireHandoff();
      }, remaining);
    } catch (error) {
      if (current !== handoffGeneration || !canPollHandoff()) return;
      if (error.status === 401) {
        signedOut('Your recovery session expired. Sign in again.');
        element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
      } else expireHandoff();
    } finally {
      handoffBusy = false;
      if (canPollHandoff()) handoffPoll = setTimeout(refreshHandoff, 2000);
    }
  };
  element('review-return').addEventListener('click', async () => {
    if (returnBusy || returnPending || !canPollHandoff() || !freshHeld()) return;
    const scope = { ...heldScope };
    const current = ++returnSequence;
    const started = performance.now();
    const wallStarted = Date.now();
    returnBusy = true;
    returnNotice('Preparing confirmation…');
    renderReturn();
    try {
      const result = await request('/controller-return-approval', { scope }, true);
      if (current !== returnSequence || !canPollHandoff() || !freshHeld() || !sameScope(heldScope, scope)) return;
      const elapsed = Math.ceil(Math.max(0, performance.now() - started));
      const remaining = Math.min(result?.expiresAtMs - Date.now(), result?.expiresAtMs - wallStarted - elapsed);
      if (!hasKeys(result, ['approvalId', 'scope', 'expiresAtMs'])
          || typeof result.approvalId !== 'string' || !scopeHash.test(result.approvalId)
          || !hasKeys(result.scope, ['planId', 'installationId', 'handoffSha256']) || !sameScope(result.scope, scope)
          || !Number.isInteger(result.expiresAtMs) || !Number.isFinite(remaining) || remaining <= 0 || remaining > 60000)
        throw new Error('Confirmation could not be verified. Try again.');
      returnApproval = { ...result, deadline: performance.now() + remaining };
      element('confirm-return').hidden = false;
      returnNotice();
      returnExpiry = setTimeout(() => {
        if (current !== returnSequence) return;
        clearReturnApproval();
        returnNotice('Confirmation expired. Review the return again.');
        renderReturn();
      }, remaining);
      element('return-title').focus();
    } catch (error) {
      if (current !== returnSequence || !canPollHandoff()) return;
      if (error.status === 401) {
        signedOut('Your recovery session expired. Sign in again.');
        element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
      }
      else returnNotice(error.message);
    } finally {
      returnBusy = false;
      renderReturn();
    }
  });
  element('cancel-return').addEventListener('click', () => {
    if (returnBusy) return;
    returnSequence++;
    clearReturnApproval();
    returnNotice();
    renderReturn();
    if (heldScope) element('review-return').focus();
  });
  element('confirm-return').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (returnBusy || !returnApproval || !canPollHandoff() || !freshHeld()) return;
    const approval = returnApproval;
    if (!sameScope(approval.scope, heldScope) || Date.now() >= approval.expiresAtMs
        || performance.now() >= approval.deadline) {
      clearReturnApproval();
      returnNotice('Confirmation expired. Review the return again.');
      renderReturn();
      element('review-return').focus();
      return;
    }
    const current = ++returnSequence;
    returnBusy = true;
    returnPending = { scope: approval.scope };
    returnObservedAfter = Infinity;
    clearReturnApproval();
    returnNotice('Starting Orbis and checking its startup…');
    renderReturn();
    try {
      const result = await request('/controller-return', { scope: approval.scope, approvalId: approval.approvalId }, true);
      if (current !== returnSequence || !canPollHandoff()) return;
      if (!hasKeys(result, ['planId', 'state', 'phase']) || result.planId !== approval.scope.planId
          || !['return-accepted', 'returning', 'complete'].includes(result.phase) || result.state !== result.phase)
        throw new Error('The return response could not be verified.');
      // The fixed status read is the authority for verified completion.
      returnNotice('Return requested. Checking the controller status…');
    } catch (error) {
      if (current !== returnSequence || !canPollHandoff()) return;
      if (error.status === 401) {
        signedOut('Your recovery session expired. Sign in again.');
        element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
      }
      else returnNotice('The return could not be confirmed. Checking the controller status…');
    } finally {
      returnBusy = false;
      returnObservedAfter = performance.now();
      renderReturn();
      if (canPollHandoff()) void refreshHandoff();
    }
  });
  const signedIn = () => {
    authenticated = true;
    generation++;
    element('sign-in').hidden = true;
    element('recovery-setup').hidden = true;
    element('overview').hidden = false;
    element('sign-out').hidden = false;
    element('recovery-panel').classList.add('authenticated');
    element('page-description').textContent = 'Installation status';
    element('password').value = '';
    element('totp').value = '';
    element('recovery-key').value = '';
    element('account-readiness').textContent = options.password ? 'Orbis operator sign-in is available.' : 'Orbis operator sign-in is not enrolled.';
    element('key-readiness').textContent = options.recoveryKey ? 'Emergency key sign-in is available.' : 'Emergency key sign-in is not enrolled.';
    const address = window.location?.protocol === 'https:' ? new URL(portal, window.location.origin).href : null;
    element('recovery-address-row').hidden = address === null;
    if (address !== null) element('recovery-address').textContent = address;
    for (const name of ['orbis', 'sentinel']) {
      element(name + '-version').textContent = 'Checking…';
      element(name + '-state').textContent = 'Checking…';
    }
    notice('');
    element('page-title').focus();
    renderProgress({ phase: 'Checking…', detail: 'Checking update progress…', ongoing: false, attention: false, percent: null, record: null });
    void refresh();
    void refreshProgress();
    clearHandoff({ resetReturn: true });
    void refreshHandoff();
  };
  const signIn = async (method) => {
    if (busy || leaving) return;
    if (method !== 'passkey') method = usingRecoveryKey ? 'recovery-key' : 'password';
    let focusAfter;
    setBusy(true);
    notice(method === 'passkey' ? 'Waiting for your passkey…' : 'Signing in…');
    try {
      if (!await loadOptions()) return;
      if (method !== 'passkey') method = usingRecoveryKey ? 'recovery-key' : 'password';
      const totp = element('totp').value.trim();
      if (options.totp[method] && !/^[0-9]{6}$/.test(totp)) {
        notice('Enter your current six-digit authenticator code.', true);
        focusAfter = 'totp';
        return;
      }
      const issued = await request('/challenge', { method });
      let credentials;
      if (method === 'passkey') {
        const publicKey = { ...issued.publicKey, challenge: decodeBase64url(issued.publicKey.challenge),
          allowCredentials: issued.publicKey.allowCredentials.map((item) => ({ ...item, id: decodeBase64url(item.id) })) };
        const credential = await navigator.credentials.get({ publicKey });
        if (!credential) throw new Error('The passkey request was cancelled.');
        credentials = { method, response: passkeyResponse(credential) };
      } else if (method === 'recovery-key') {
        credentials = { method, recoveryKey: element('recovery-key').value.trim() };
      } else {
        credentials = { method, username: element('username').value, password: element('password').value };
      }
      if (options.totp[method]) credentials.totpCode = totp;
      await request('/login', { challenge: issued.challenge, credentials });
      signedIn();
    } catch (error) {
      element('recovery-key').value = '';
      notice(error.name === 'NotAllowedError' ? 'The passkey request was cancelled. You can try again or use your password.' : error.message, true);
      if (method === 'passkey') focusAfter = 'passkey';
      if (method === 'recovery-key') focusAfter = 'recovery-key';
      if (method === 'password') focusAfter = 'password';
    } finally {
      setBusy(false);
      if (!authenticated && focusAfter) element(focusAfter).focus();
    }
  };
  element('sign-in').addEventListener('submit', (event) => { event.preventDefault(); void signIn('password'); });
  element('passkey').addEventListener('click', () => { void signIn('passkey'); });
  element('use-recovery-key').addEventListener('click', () => {
    if (busy) return;
    usingRecoveryKey = !usingRecoveryKey;
    for (const name of ['password', 'totp', 'recovery-key']) element(name).value = '';
    updateMethod();
    notice('');
    element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
  });
  element('sign-out').addEventListener('click', async () => {
    if (busy) return;
    setBusy(true);
    try {
      await request('/logout', {}, true);
      signedOut();
      setBusy(false);
      element(usingRecoveryKey ? 'recovery-key' : 'username').focus();
    } catch (error) {
      notice(error.message, true);
    } finally { setBusy(false); }
  });
  const appearance = element('appearance');
  const applyAppearance = (value) => {
    appearance.value = ['light', 'dark'].includes(value) ? value : 'system';
    if (appearance.value === 'system') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = appearance.value;
  };
  try { applyAppearance(localStorage.getItem('orbis-sentinel.appearance')); } catch { applyAppearance('system'); }
  appearance.addEventListener('change', () => {
    applyAppearance(appearance.value);
    try { localStorage.setItem('orbis-sentinel.appearance', appearance.value); } catch {}
  });
  const activity = () => {
    if (!authenticated || busy || Date.now() - lastActivity < 60000) return;
    lastActivity = Date.now();
    void request('/active', {}, true).catch(() => {});
  };
  document.addEventListener('pointerdown', activity, { passive: true });
  document.addEventListener('keydown', activity, { passive: true });
  const sync = () => {
    clearTimeout(poll);
    clearTimeout(progressPoll);
    if (document.hidden || leaving) {
      clearHandoff();
      return;
    }
    if (authenticated) { void refresh(); void refreshProgress(); void refreshHandoff(); }
    else if (connectionNeeded) void connect();
  };
  document.addEventListener('visibilitychange', sync);
  window.addEventListener('online', sync);
  window.addEventListener('pagehide', () => {
    leaving = true;
    generation++;
    clearTimeout(poll);
    clearTimeout(progressPoll);
    clearHandoff();
  });
  window.addEventListener('pageshow', () => { leaving = false; sync(); });
  const connect = async () => {
    clearTimeout(poll);
    if (connecting || busy || authenticated || document.hidden || leaving) return;
    connecting = true;
    const current = generation;
    try {
      if (!await loadOptions()) return;
      const session = await request('/session').catch((error) => {
        if (error.status === 401) return { authenticated: false };
        throw error;
      });
      if (leaving || current !== generation) return;
      connectionNeeded = false;
      if (session.authenticated === true) signedIn();
      else signedOut();
    } catch (error) {
      if (leaving || current !== generation) return;
      element('sign-in').hidden = true;
      element('recovery-setup').hidden = false;
      element('enrollment-steps').hidden = error.status !== 401;
      element('page-description').textContent = 'Recovery sign-in is unavailable.';
      notice(error.status === 401
        ? 'Sentinel is reachable. Sign-in will appear when recovery access is active.'
        : 'Sentinel sign-in could not be checked. Reconnecting automatically.', error.status !== 401);
    } finally {
      connecting = false;
      if (connectionNeeded && !authenticated && !document.hidden && !leaving) poll = setTimeout(connect, 5000);
    }
  };
  await connect();
}

if (typeof document !== 'undefined') void start();
