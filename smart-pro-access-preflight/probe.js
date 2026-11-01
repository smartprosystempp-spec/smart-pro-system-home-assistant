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
  const form = document.getElementById('account-roundtrip-form');
  const result = document.getElementById('roundtrip-result');
  if (!form || !result) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    result.textContent = 'Η εφάπαξ δοκιμή εκτελείται. Μην επαναλάβετε.';
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
        throw Error('qa_write_rejected_or_uncertain');
      const data = await response.json();
      if (typeof data.code !== 'string' || !/^[a-z0-9_]{3,90}$/.test(data.code))
        throw Error('invalid_response');
      result.textContent = 'Αποτέλεσμα: ' + data.code +
        '\nΕλέγξτε την καρτέλα Χρήστες του Home Assistant. Μην επαναλάβετε.';
    } catch (_error) {
      // After a failed or interrupted request, do NOT claim no write.
      result.textContent = 'result_unknown_check_HA_users_no_retry — Ελέγξτε τη λίστα Χρηστών, μην επαναλάβετε.';
    }
  });
})();
