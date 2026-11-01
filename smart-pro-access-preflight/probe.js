"use strict";
(() => {
  const form = document.getElementById('origin-probe-form');
  const target = document.getElementById('probe-result');
  if (!form || !target) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    target.textContent = 'Έλεγχος υποβολής...';
    try {
      const response = await fetch(form.action, {
        method: 'POST',
        mode: 'same-origin',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { 'Content-Type': 'application/json', 'X-Smart-Pro-QA-Probe': 'v1' },
        body: '{"probe":"metadata-v1"}'
      });
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json')) {
        throw Error('probe_http_rejected_no_write');
      }
      const data = await response.json();
      if (data.code !== 'request_metadata_observed_no_write') throw Error('probe_invalid_result_no_write');
      const fields = ['code','origin','fetch_site','origin_host','custom_header'];
      target.textContent = fields.map(k => k + ': ' + String(data[k] || 'unknown')).join('\n');
    } catch(_error) {
      target.textContent = 'browser_fetch_failed_no_write (χωρίς αλλαγές χρήστη)';
    } finally {
      button.disabled = false;
    }
  });
})();
