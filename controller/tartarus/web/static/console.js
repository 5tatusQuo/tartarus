const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
const toast = document.querySelector('#toast');

function notify(message, error = false) {
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast show${error ? ' error' : ''}`;
  window.setTimeout(() => { toast.className = 'toast'; }, 4200);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.method && options.method !== 'GET') headers.set('X-CSRF-Token', csrf);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const response = await fetch(path, {...options, headers});
  if (!response.ok) {
    const body = await response.json().catch(() => ({detail: 'Request failed'}));
    throw new Error(body.detail || 'Request failed');
  }
  return response.json();
}

const ludusStatus = document.querySelector('[data-ludus-status]');
if (ludusStatus) {
  const identity = document.querySelector('[data-ludus-identity]');
  api('/api/ludus').then((status) => {
    ludusStatus.textContent = status.ludus_connected ? 'Connected' : 'Offline';
    ludusStatus.classList.remove('neutral');
    ludusStatus.classList.add(status.ludus_connected ? 'success' : 'danger');
    if (identity) identity.textContent = status.ludus_user || status.detail || 'Ludus authentication is unavailable.';
  }).catch((error) => {
    ludusStatus.textContent = 'Unavailable';
    ludusStatus.classList.remove('neutral');
    ludusStatus.classList.add('danger');
    if (identity) identity.textContent = error.message;
  });
}

const fileInput = document.querySelector('#sample-file');
fileInput?.addEventListener('change', () => {
  const zone = document.querySelector('.dropzone');
  if (fileInput.files.length) {
    zone.classList.add('has-file');
    zone.querySelector('strong').textContent = fileInput.files[0].name;
  }
});

let pendingApproval = null;
document.querySelector('[data-prepare-analysis]')?.addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const caseId = document.querySelector('#case-id').value.trim();
  const rangeId = document.querySelector('#range-id').value;
  const sample = fileInput?.files[0];
  if (!caseId || !rangeId || !sample) return notify('Choose a case ID, ELF or ZIP sample, and managed range.', true);
  button.disabled = true;
  button.textContent = 'Staging safely…';
  try {
    let caseRecord;
    try { caseRecord = await api('/api/cases', {method: 'POST', body: JSON.stringify({case_id: caseId})}); }
    catch (error) {
      const cases = await api('/api/cases');
      caseRecord = cases.find((item) => item.case_id === caseId);
      if (!caseRecord) throw error;
    }
    const upload = new FormData();
    upload.append('sample', sample, sample.name);
    const zipPassword = document.querySelector('#zip-password');
    const sampleRecord = await api(`/api/cases/${encodeURIComponent(caseRecord.case_id)}/samples`, {method: 'POST', body: upload});
    pendingApproval = await api('/api/workflows', {method: 'POST', body: JSON.stringify({
      range_id: rangeId, case_id: caseRecord.case_id, sample_id: sampleRecord.sample_id,
      telemetry_profile: document.querySelector('#profile').value,
      duration: Number(document.querySelector('#duration').value),
      archive_password: zipPassword?.value || null
    })});
    const scope = document.querySelector('#approval-scope');
    scope.replaceChildren(...Object.entries(pendingApproval.job.approval.scope).filter(([key]) => !['operation','post_run_action'].includes(key)).map(([key, value]) => {
      const row = document.createElement('div');
      const dt = document.createElement('dt'); dt.textContent = key.replaceAll('_', ' ');
      const dd = document.createElement('dd'); dd.textContent = String(value);
      row.append(dt, dd); return row;
    }));
    document.querySelector('#approval-dialog').showModal();
  } catch (error) { notify(error.message, true); }
  finally { button.disabled = false; button.innerHTML = 'Review execution <span>→</span>'; }
});

document.querySelector('#approval-check')?.addEventListener('change', (event) => {
  document.querySelector('[data-approve-analysis]').disabled = !event.target.checked;
});

document.querySelector('[data-approve-analysis]')?.addEventListener('click', async (event) => {
  if (!pendingApproval) return;
  event.currentTarget.disabled = true;
  event.currentTarget.textContent = 'Starting verified workflow…';
  try {
    await api(`/api/workflows/${pendingApproval.job.job_id}/approve`, {method: 'POST', body: JSON.stringify({token: pendingApproval.approval_token})});
    window.location.assign(`/jobs/${encodeURIComponent(pendingApproval.job.job_id)}`);
  } catch (error) { notify(error.message, true); event.currentTarget.disabled = false; }
});

document.querySelector('[data-run-search]')?.addEventListener('input', (event) => {
  const query = event.target.value.toLowerCase();
  document.querySelectorAll('[data-search]').forEach((row) => { row.hidden = !row.dataset.search.toLowerCase().includes(query); });
});

document.querySelectorAll('[data-report-tab]').forEach((tab) => tab.addEventListener('click', () => {
  document.querySelectorAll('[data-report-tab]').forEach((item) => item.classList.toggle('active', item === tab));
  document.querySelectorAll('[data-report-panel]').forEach((panel) => panel.classList.toggle('hidden', panel.dataset.reportPanel !== tab.dataset.reportTab));
}));

document.querySelectorAll('[data-verify-range]').forEach((button) => button.addEventListener('click', async () => {
  const card = button.closest('[data-range-id]');
  const result = card.querySelector('.range-result');
  button.disabled = true; result.textContent = 'Running complete readiness checks…';
  try { const report = await api(`/api/ranges/${encodeURIComponent(card.dataset.rangeId)}/verify`, {method: 'POST'}); result.textContent = report.passed ? `Passed all ${report.checks.length} checks.` : `Verification failed. ${report.checks.filter((item) => item.status !== 'pass').length} checks need attention.`; }
  catch (error) { result.textContent = error.message; notify(error.message, true); }
  finally { button.disabled = false; }
}));

document.querySelectorAll('[data-rebuild-range]').forEach((button) => button.addEventListener('click', async () => {
  const card = button.closest('[data-range-id]');
  const rangeId = card.dataset.rangeId;
  const confirmation = window.prompt(`Type ${rangeId} to destroy and rebuild only the disposable sandbox.`);
  if (confirmation !== rangeId) return;
  button.disabled = true;
  try { const report = await api(`/api/ranges/${encodeURIComponent(rangeId)}/rebuild`, {method: 'POST', body: JSON.stringify({confirmation})}); notify(report.passed ? 'Sandbox rebuilt and verified.' : 'Sandbox rebuild requires attention.', !report.passed); }
  catch (error) { notify(error.message, true); }
  finally { button.disabled = false; }
}));

document.querySelector('[data-connect-chatgpt]')?.addEventListener('click', () => window.location.assign('/auth/chatgpt/start'));

document.querySelector('[data-disconnect-chatgpt]')?.addEventListener('click', async () => {
  try { await api('/auth/chatgpt/disconnect', {method: 'POST'}); window.location.reload(); }
  catch (error) { notify(error.message, true); }
});

document.querySelector('[data-run-diagnostics]')?.addEventListener('click', async (event) => {
  const result = document.querySelector('[data-diagnostics-result]');
  event.currentTarget.disabled = true; result.textContent = 'Running controller and Ludus checks…';
  try { const report = await api('/api/diagnostics', {method: 'POST'}); const failed = report.checks.filter((item) => !['pass','not_prepared'].includes(item.status)); result.textContent = report.ready ? `Controller ready · ${report.checks.length} checks passed.` : `${failed.length} checks require attention.`; }
  catch (error) { result.textContent = error.message; notify(error.message, true); }
  finally { event.currentTarget.disabled = false; }
});

const eventLog = document.querySelector('[data-job-events]');
if (eventLog) {
  const runId = eventLog.dataset.runId;
  api('/api/status').then((status) => {
    if (!status.active_job || status.active_job.run_id !== runId) return;
    eventLog.replaceChildren();
    const source = new EventSource(`/api/workflows/${status.active_job.job_id}/events`);
    source.addEventListener('progress', (event) => {
      const data = JSON.parse(event.data); const row = document.createElement('p');
      const time = document.createElement('time'); time.textContent = data.timestamp.slice(11, 19);
      row.append(time, document.createTextNode(`${data.phase.toUpperCase()}  ${data.message}`)); eventLog.append(row); eventLog.scrollTop = eventLog.scrollHeight;
    });
    source.addEventListener('done', () => { source.close(); window.setTimeout(() => window.location.reload(), 800); });
  }).catch(() => {});
}

const liveJob = document.querySelector('[data-live-job]');
if (liveJob) {
  const source = new EventSource(`/api/workflows/${encodeURIComponent(liveJob.dataset.liveJob)}/events`);
  const log = liveJob.querySelector('[data-live-events]');
  const heartbeat = liveJob.querySelector('[data-job-heartbeat]');
  const phases = ['verification','preparing','starting','analyzing','collecting','recovering','reporting','complete'];
  const updateHeartbeat = (phase) => {
    heartbeat.textContent = `Connected · ${phase.replaceAll('_', ' ')} · ${new Date().toLocaleTimeString()}`;
  };
  const updateTimeline = (data) => {
    const phaseItems = [...document.querySelectorAll('[data-phase]')];
    const prior = phaseItems.findIndex((item) => item.classList.contains('current'));
    const current = phases.indexOf(data.phase);
    const failed = data.level === 'error' || data.phase === 'failed';
    phaseItems.forEach((item) => {
      const own = phases.indexOf(item.dataset.phase);
      const active = current >= 0 ? own === current : failed && own === prior;
      if (current >= 0) item.classList.toggle('done', own < current);
      item.classList.toggle('current', active);
      item.classList.toggle('failed', failed && active);
      if (active && data.message) item.querySelector('small').textContent = data.message;
      else if (current >= 0 && own < current) item.querySelector('small').textContent = 'Completed';
    });
  };
  source.addEventListener('progress', (event) => {
    const data = JSON.parse(event.data);
    document.querySelector('[data-job-phase]').textContent = data.phase.replaceAll('_', ' ');
    updateHeartbeat(data.phase);
    const row = document.createElement('p'); const time = document.createElement('time');
    time.textContent = data.timestamp.slice(11, 19); row.append(time, document.createTextNode(`${data.phase.toUpperCase()}  ${data.message}`));
    log.append(row); log.scrollTop = log.scrollHeight;
    updateTimeline(data);
  });
  source.addEventListener('heartbeat', (event) => {
    const job = JSON.parse(event.data);
    updateHeartbeat(job.phase);
  });
  source.addEventListener('done', (event) => {
    const job = JSON.parse(event.data); source.close();
    if (job.status === 'completed') window.location.assign(`/reports/${encodeURIComponent(job.case_id)}/${encodeURIComponent(job.run_id)}`);
    else {
      document.querySelector('[data-job-status]').textContent = job.status.replaceAll('_', ' ');
      heartbeat.textContent = `Stopped · ${job.phase.replaceAll('_', ' ')}`;
      const failure = document.querySelector('[data-job-failure]');
      failure.querySelector('[data-job-failure-message]').textContent = job.failure || 'Workflow needs attention.';
      const action = failure.querySelector('[data-job-failure-action]');
      const reconnect = (job.failure || '').includes('ChatGPT');
      action.href = reconnect ? '/settings' : '/analysis/new';
      action.textContent = reconnect ? 'Reconnect ChatGPT' : 'Start a new analysis';
      action.classList.remove('hidden');
      failure.classList.remove('hidden');
      notify(job.failure || 'Workflow needs attention.', true);
    }
  });
  source.onerror = () => { heartbeat.textContent = 'Connection interrupted · retrying…'; };
}

document.querySelector('[data-emergency-stop]')?.addEventListener('click', async (event) => {
  if (!window.confirm('Stop execution, collect available evidence, and recover the sandbox?')) return;
  event.currentTarget.disabled = true;
  try { await api(`/api/workflows/${encodeURIComponent(event.currentTarget.dataset.jobId)}/emergency-stop`, {method: 'POST'}); notify('Emergency stop and recovery started.'); }
  catch (error) { notify(error.message, true); event.currentTarget.disabled = false; }
});
