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
  // Read-only ticket preflight. Returns fixed status only; no secrets, no HA writes.
  const preForm = document.getElementById('lab-handoff-preflight-form');
  const preResult = document.getElementById('handoff-preflight-result');
  if (preForm && preResult) preForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = preForm.querySelector('button[type="submit"]');
    button.disabled = true;
    preResult.textContent = 'Έλεγχος επικοινωνίας... Χωρίς δημιουργία χρήστη.';
    try {
      const response = await fetch(preForm.action, {
        method:'POST', mode:'same-origin', credentials:'same-origin',
        cache:'no-store', redirect:'error',
        headers:{'Content-Type':'application/json','X-Smart-Pro-QA-Action':'v1'},
        body:JSON.stringify({csrf:preForm.querySelector('input[name="csrf"]').value,
          ticket:preForm.querySelector('input[name="ticket"]').value.trim()})
      });
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json'))
        throw Error('handoff_preflight_http_' + response.status);
      const data=await response.json();
      if (!/^[a-z0-9_]{3,110}$/.test(data.code||'')) throw Error('handoff_preflight_bad_response');
      preResult.textContent='Αποτέλεσμα: '+data.code;
    } catch (error) {
      const reason=String(error.message || 'failed');
      preResult.textContent=/^handoff_preflight_http_[0-9]{3}$/.test(reason)
        ? 'Αποτέλεσμα: '+reason : 'handoff_preflight_network_or_browser_failure';
    } finally {
      preForm.querySelector('input[name="ticket"]').value='';
    }
  });
  // Real credentials NEVER enter browser JS. Only a one-time Portal ticket is posted.
  const handoffForm = document.getElementById('lab-handoff-create-form');
  const handoffResult = document.getElementById('handoff-create-result');
  if (handoffForm && handoffResult) handoffForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = handoffForm.querySelector('button[type="submit"]');
    button.disabled = true;
    handoffResult.textContent = 'Εκτέλεση μίας ελεγχόμενης ενέργειας. Μην επαναλάβεις.';
    try {
      const body = {
        csrf: handoffForm.querySelector('input[name="csrf"]').value,
        ticket: handoffForm.querySelector('input[name="ticket"]').value.trim(),
        confirm: handoffForm.querySelector('input[name="confirm"]').value
      };
      const response = await fetch(handoffForm.action, {
        method:'POST', mode:'same-origin', credentials:'same-origin',
        cache:'no-store', redirect:'error',
        headers:{'Content-Type':'application/json','X-Smart-Pro-QA-Action':'v1'},
        body:JSON.stringify(body)
      });
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json'))
        throw Error('handoff_http_uncertain');
      const data = await response.json();
      if (!/^[a-z0-9_]{3,110}$/.test(data.code || '')) throw Error('handoff_invalid_response');
      handoffResult.textContent = 'Αποτέλεσμα: '+data.code+'\nΈλεγξε το Portal και τη λίστα χρηστών. Μην επαναλάβεις.';
    } catch (_error) {
      handoffResult.textContent = 'handoff_outcome_uncertain_check_portal_and_ha_users — Μην επαναλάβεις.';
    } finally { handoffForm.querySelector('input[name="ticket"]').value=''; }
  });
  const revokeForm = document.getElementById('lab-login-revoke-form');
  const revokeResult = document.getElementById('lab-login-result');
  if (revokeForm && revokeResult) revokeForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = revokeForm.querySelector('button[type="submit"]');
    button.disabled = true;
    revokeResult.textContent = 'Εκτέλεση ελεγχόμενης ανάκλησης. Μην επαναλάβεις.';
    try {
      const payload={csrf:revokeForm.querySelector('input[name="csrf"]').value,
                     confirm:revokeForm.querySelector('input[name="confirm"]').value};
      const response=await fetch(revokeForm.action,{method:'POST',mode:'same-origin',
        credentials:'same-origin',cache:'no-store',redirect:'error',
        headers:{'Content-Type':'application/json','X-Smart-Pro-QA-Action':'v1'},
        body:JSON.stringify(payload)});
      if (!response.ok || !response.headers.get('Content-Type')?.includes('application/json')) throw Error('uncertain');
      const data=await response.json();
      if (!/^[a-z0-9_]{3,110}$/.test(data.code||'')) throw Error('invalid');
      revokeResult.textContent='Αποτέλεσμα: '+data.code+'\nΈλεγξε την καρτέλα Χρήστες. Μην επαναλάβεις.';
    } catch (_error) { revokeResult.textContent='result_unknown_check_HA_users_no_retry'; }
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
