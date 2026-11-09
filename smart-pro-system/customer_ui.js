/* Smart Pro System 3.0.31 — additive customer UI only.
   Reuses existing Portal state, Guardian state and owner-consent handlers;
   does NOT authorize requests, mutate settings or alter technician PIN access. */
(() => {
  'use strict';
  const init = () => {
    const body = document.body;
    const headerActions = document.querySelector('.sps-header-actions');
    const strip = document.querySelector('.sps-state-strip');
    const portalCard = document.getElementById('portalConnectionCard');
    const adminCard = document.getElementById('sps-customer-admin-access');
    if (!body || !headerActions || !strip || !portalCard || !adminCard) return;
    body.classList.add('sps-customer-v1');

    // Navigation via Home Assistant's parent UI (Ingress); plain link outside it.
    const back = document.createElement('a');
    back.className = 'sps-action sps-back-apps';
    back.textContent = '← Εφαρμογές';
    back.href = '/config/apps/installed';
    back.target = '_top';
    back.setAttribute('aria-label', 'Επιστροφή στις εγκατεστημένες εφαρμογές Home Assistant');
    back.addEventListener('click', (ev) => {
      if (window.parent !== window) {
        try {
          window.parent.postMessage({type:'home-assistant/navigate', path:'/config/apps/installed'}, '*');
          ev.preventDefault();
        } catch (_) { /* fallback is the valid top-level link */ }
      }
    });
    headerActions.prepend(back);

    // The existing admin consent card is moved, not reimplemented. Its listeners,
    // exact confirmation, server-side authority and no-retry behavior remain.
    const adminButton = document.createElement('button');
    adminButton.type = 'button';
    adminButton.className = 'sps-action';
    adminButton.textContent = 'Πρόσβαση Smart Pro';
    adminButton.setAttribute('aria-haspopup','dialog');
    adminButton.setAttribute('aria-controls','sps-admin-overlay');
    back.after(adminButton);

    const overlay = document.createElement('div');
    overlay.className = 'sps-admin-overlay';
    overlay.id = 'sps-admin-overlay';
    overlay.setAttribute('role','dialog');
    overlay.setAttribute('aria-modal','true');
    overlay.setAttribute('aria-labelledby','sps-admin-title');
    overlay.setAttribute('aria-hidden','true');
    const dialog = document.createElement('div');
    dialog.className = 'sps-admin-dialog';
    dialog.innerHTML = '<div class="sps-admin-head"><div><span class="sps-eyebrow">Ρητή έγκριση ιδιοκτήτη</span><h2 id="sps-admin-title">Πρόσβαση Smart Pro</h2><p>Ξεχωριστός λογαριασμός διαχειριστή, μόνο με την έγκρισή σας.</p></div><button type="button" class="sps-modal-close" aria-label="Κλείσιμο">✕</button></div><div class="sps-admin-content"><p class="sps-admin-explainer">Ο προσωπικός σας λογαριασμός Home Assistant δεν αλλάζει. Η υπάρχουσα διαδικασία ελέγχει την έγκριση και την παράδοση των στοιχείων με ασφάλεια.</p><div id="sps-admin-mount"></div></div>';
    overlay.append(dialog);
    body.append(overlay);
    dialog.querySelector('#sps-admin-mount').append(adminCard);
    const modalClose = dialog.querySelector('.sps-modal-close');
    let lastFocus = null;
    function isBusy() {
      const state = adminCard.querySelector('[role="status"]');
      const txt = state ? (state.textContent || '') : '';
      return txt.includes('Έλεγχος έγκρισης και ασφαλής εκτέλεση');
    }
    function closeAdmin() {
      if (isBusy()) return; // Do not obscure an in-flight one-shot action.
      overlay.classList.remove('is-open');
      overlay.setAttribute('aria-hidden','true');
      body.classList.remove('sps-modal-open');
      if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
    }
    adminButton.addEventListener('click', () => {
      lastFocus = document.activeElement;
      overlay.classList.add('is-open');
      overlay.setAttribute('aria-hidden','false');
      body.classList.add('sps-modal-open');
      modalClose.focus();
    });
    modalClose.addEventListener('click',closeAdmin);
    overlay.addEventListener('click',(e) => { if (e.target === overlay) closeAdmin(); });
    document.addEventListener('keydown',(e) => {
      if (e.key !== 'Escape' || !overlay.classList.contains('is-open')) return;
      e.preventDefault(); closeAdmin();
    });

    // Preserve Portal pairing, subscription verification and Disconnect.
    // The full information stays in a details panel instead of being repeated.
    const details = document.createElement('details');
    details.className = 'sps-connection-details';
    details.id = 'sps-connection-details';
    const summary = document.createElement('summary');
    summary.textContent = 'Στοιχεία σύνδεσης Portal, συνδρομής & αποσύνδεση';
    details.append(summary,portalCard);
    strip.after(details);
    const sync = document.createElement('div');
    sync.className = 'sps-sync-mini';
    sync.innerHTML = '<span>Σύνδεση Portal</span><strong id="sps-sync-state" data-tone="muted">Έλεγχος...</strong><small id="sps-sync-time">Αναμονή ενημέρωσης</small>';
    strip.append(sync);
    const badge = document.getElementById('portalConnectionBadge');
    const heartbeat = document.getElementById('portalLastHeartbeat');
    const syncState = sync.querySelector('#sps-sync-state');
    const syncTime = sync.querySelector('#sps-sync-time');
    let wasConnected = null;
    function paintConnection() {
      const connected = !!badge && badge.classList.contains('connected');
      const checking = !!badge && String(badge.textContent || '').includes('Έλεγχος');
      const error = !!badge && badge.classList.contains('error');
      if (connected) {
        syncState.textContent = '✓ Συνδεδεμένο';
        syncState.dataset.tone = 'good';
      } else if (error) {
        syncState.textContent = 'Χρειάζεται έλεγχος';
        syncState.dataset.tone = 'attention';
      } else {
        syncState.textContent = checking ? 'Έλεγχος...' : 'Δεν έχει συνδεθεί';
        syncState.dataset.tone = 'muted';
      }
      const last = heartbeat ? String(heartbeat.textContent || '').trim() : '';
      syncTime.textContent = connected && last && last !== '--' ? 'Συγχρονισμός: ' + last : 'Στοιχεία από το Portal';
      if (connected !== wasConnected) {
        // Reset the connection panel only when its authoritative state changes.
        details.open = !connected;
        wasConnected = connected;
      }
      body.classList.toggle('sps-is-connected',connected);
    }
    paintConnection();
    if (badge) new MutationObserver(paintConnection).observe(badge,{attributes:true,childList:true,characterData:true,subtree:true});
    if (heartbeat) new MutationObserver(paintConnection).observe(heartbeat,{childList:true,characterData:true,subtree:true});

    // Keep the original computed Guardian warning as the customer authority.
    // Only surface concrete device/battery/update warnings, not system internals.
    const health = document.querySelector('.sps-health');
    if (health) {
      const title = health.querySelector('.sps-section-heading h2');
      if (title) title.textContent = 'Κατάσταση συστήματος';
      const alerts = document.createElement('div');
      alerts.className = 'sps-customer-alerts';
      alerts.setAttribute('aria-live','polite');
      const stateMsg = document.getElementById('statusMessage');
      if (stateMsg) stateMsg.after(alerts);
      else health.append(alerts);
      const watch = ['deviceHealth','batteryHealth','updateHealth'].map(id => document.getElementById(id)).filter(Boolean);
      const renderAlerts = () => {
        alerts.replaceChildren();
        for (const node of watch) {
          if (!node.classList.contains('warning') && !node.classList.contains('error')) continue;
          const label = (node.innerText || node.textContent || '').replace(/^[●✔✓⚠️\s]+/u,'').trim();
          if (!label) continue;
          const badge = document.createElement('span');
          badge.textContent = label.length > 110 ? label.slice(0,108)+'…' : label;
          alerts.append(badge);
        }
      };
      for (const node of watch) new MutationObserver(renderAlerts).observe(node,{attributes:true,characterData:true,childList:true,subtree:true});
      renderAlerts();
    }
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init,{once:true});
  else init();
})();
