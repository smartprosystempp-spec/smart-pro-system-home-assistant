"use strict";
(() => {
  const probe = document.getElementById('origin-probe-form');
  const probeTarget = document.getElementById('probe-result');
  if (probe && probeTarget) probe.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = probe.querySelector('button');
    button.disabled = true;
    probeTarget.textContent = 'Έλεγχος υποβολής...';
    try {
      const response = await fetch(probe.action, {
        method: 'POST', mode: 'same-origin', credentials: 'same-origin',
        cache: 'no-store', redirect: 'error',
        headers: {'Content-Type':'application/json','X-Smart-Pro-QA-Probe':'v1'},
        body: '{"probe":"metadata-v1"}'
      });
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json'))
        throw Error('probe_http_rejected');
      const data = await response.json();
      if (data.code !== 'request_metadata_observed_no_write') throw Error('probe_invalid_result');
      const fields = ['code','origin','fetch_site','origin_host','custom_header'];
      probeTarget.textContent = fields.map(k => k + ': ' + String(data[k] || 'unknown')).join('\n');
    } catch (_error) {
      probeTarget.textContent = 'browser_fetch_failed_no_write (χωρίς αλλαγές χρήστη)';
    } finally { button.disabled = false; }
  });
  for (const [id, targetId] of [
    ['retained-create-form', 'retained-create-result'],
    ['retained-revoke-form', 'retained-revoke-result'],
  ]) {
    const form = document.getElementById(id);
    const result = document.getElementById(targetId);
    if (!form || !result) continue;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button');
      button.disabled = true;
      result.textContent = 'Εκτέλεση μίας ενέργειας. Μην επαναλάβετε.';
      try {
        const csrf = form.querySelector('input[name="csrf"]').value;
        const confirm = form.querySelector('input[name="confirm"]').value;
        const response = await fetch(form.action, {
          method: 'POST', mode: 'same-origin', credentials: 'same-origin',
          cache: 'no-store', redirect: 'error',
          headers: {'Content-Type':'application/json','X-Smart-Pro-QA-Action':'v1'},
          body: JSON.stringify({csrf, confirm})
        });
        if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json'))
          throw Error('qa_action_rejected_or_uncertain');
        const data = await response.json();
        if (typeof data.code !== 'string' || !/^[a-z0-9_]{3,100}$/.test(data.code))
          throw Error('invalid_response');
        result.textContent = 'Αποτέλεσμα: ' + data.code +
          '\nΕλέγξτε την καρτέλα Χρήστες του Home Assistant. Μην επαναλάβετε.';
      } catch (_error) {
        result.textContent = 'result_unknown_check_HA_users_no_retry — Ελέγξτε τη λίστα χρηστών.';
      }
    });
  }
})();
