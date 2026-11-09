/* Smart Pro System 3.0.32 — additive customer UI only.
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


    // 3.0.32 — Layout-only tablet consolidation. Existing live service rows,
    // Guardian/status nodes and activity are RE-PARENTED, never copied or
    // replaced. Their upstream authors, entitlements and handlers stay intact.
    const serviceSection = document.querySelector('.sps-services');
    const activitySection = document.getElementById('customerActivityPanel');
    const statusMessage = document.getElementById('statusMessage');
    const watchdogState = document.getElementById('watchdogStateRow');
    const servicesList = serviceSection && serviceSection.querySelector('.sps-service-list');

    function makeModal(id,title,kicker) {
      const shade = document.createElement('div');
      shade.className = 'sps-detail-overlay';
      shade.id = id;
      shade.setAttribute('role','dialog');
      shade.setAttribute('aria-modal','true');
      shade.setAttribute('aria-hidden','true');
      shade.setAttribute('aria-label',title);
      shade.innerHTML = '<div class="sps-detail-dialog"><div class="sps-detail-head"><div><span class="sps-eyebrow"></span><h2></h2></div><button type="button" class="sps-detail-close" aria-label="Κλείσιμο">✕</button></div><div class="sps-detail-content"></div></div>';
      shade.querySelector('.sps-eyebrow').textContent=kicker;
      shade.querySelector('h2').textContent=title;
      body.append(shade);
      const panel = shade.querySelector('.sps-detail-dialog');
      const closeButton = shade.querySelector('.sps-detail-close');
      let returnFocus = null;
      function close(){
        shade.classList.remove('is-open');
        shade.setAttribute('aria-hidden','true');
        if (!document.querySelector('.sps-detail-overlay.is-open') && !document.querySelector('.sps-admin-overlay.is-open')) body.classList.remove('sps-modal-open');
        if (returnFocus && typeof returnFocus.focus === 'function') returnFocus.focus();
      }
      function open(){
        // Never obscure the existing one-shot owner authorization process.
        if (document.querySelector('.sps-admin-overlay.is-open')) return;
        for(const other of document.querySelectorAll('.sps-detail-overlay.is-open')) {
          if (other !== shade) other.querySelector('.sps-detail-close').click();
        }
        returnFocus=document.activeElement;
        shade.classList.add('is-open');
        shade.setAttribute('aria-hidden','false');
        body.classList.add('sps-modal-open');
        closeButton.focus();
      }
      closeButton.addEventListener('click',close);
      shade.addEventListener('click',e=>{if(e.target===shade)close();});
      shade.addEventListener('keydown',e=>{
        if(e.key==='Escape'){e.preventDefault();close();return;}
        if(e.key!=='Tab')return;
        const focusables=Array.from(panel.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex="0"]')).filter(el=>el.getClientRects().length);
        if (!focusables.length)return;
        const first=focusables[0],last=focusables[focusables.length-1];
        if (e.shiftKey && document.activeElement===first){e.preventDefault();last.focus();}
        if (!e.shiftKey && document.activeElement===last){e.preventDefault();first.focus();}
      });
      return {content:shade.querySelector('.sps-detail-content'),open,close};
    }
    const serviceModal=makeModal('sps-services-overlay','Υπηρεσίες Smart Pro','Κατάσταση εγκατάστασης');
    const monitoringModal=makeModal('sps-monitor-overlay','Παρακολούθηση & συμβάντα','Κατάσταση συστήματος');

    if (serviceSection && servicesList) {
      const serviceMini=document.createElement('button');
      serviceMini.type='button';
      serviceMini.id='sps-service-mini';
      serviceMini.className='sps-compact-card sps-service-mini';
      serviceMini.setAttribute('aria-haspopup','dialog');
      serviceMini.setAttribute('aria-controls','sps-services-overlay');
      serviceMini.innerHTML='<span class="sps-compact-icon" aria-hidden="true">◈</span><span class="sps-compact-copy"><strong>Κατάσταση Smart Pro</strong><small id="sps-service-brief">Έλεγχος υπηρεσιών…</small></span><span class="sps-compact-status" id="sps-service-overall" data-tone="muted">Έλεγχος…</span><span class="sps-compact-more" aria-hidden="true">Λεπτομέρειες ›</span>';
      serviceSection.before(serviceMini);
      serviceModal.content.append(serviceSection);
      serviceMini.addEventListener('click',serviceModal.open);
      const outcome=serviceMini.querySelector('#sps-service-overall');
      const brief=serviceMini.querySelector('#sps-service-brief');
      function updateServiceMini(){
        let good=0,amber=0,red=0;
        const rows=Array.from(servicesList.querySelectorAll('.sps-service-row'));
        for(const row of rows){
          const tones=Array.from(row.querySelectorAll('.sps-service-status b')).map(el=>({tone:el.dataset.tone||'muted',label:(el.textContent||'').trim()}));
          if(tones.some(t=>t.tone==='bad')){red++;continue;}
          if(tones.some(t=>t.tone==='attention')){amber++;continue;}
          // Entitled Managed Support / External URL without working runtime is
          // not called healthy, even if the runtime source reports 'muted'.
          const entitled=tones.length>1 && tones[0].tone==='good';
          const runtime=tones.length>1 ? tones[tones.length-1]:null;
          if(entitled && runtime && runtime.tone!=='good') {amber++;continue;}
          if(tones.some(t=>t.tone==='good'))good++;
        }
        // The customer Portal connection is a separate, existing authority.
        const portalOK=body.classList.contains('sps-is-connected');
        const portalBadge=document.getElementById('portalConnectionBadge');
        const hasSyncError=!!portalBadge && portalBadge.classList.contains('error');
        if(hasSyncError) amber++;
        if(red){outcome.textContent='Πρόβλημα';outcome.dataset.tone='bad';brief.textContent='Απαιτείται έλεγχος υπηρεσίας';}
        else if(amber){outcome.textContent='Προσοχή';outcome.dataset.tone='attention';brief.textContent='Μία ή περισσότερες υπηρεσίες χρειάζονται έλεγχο';}
        else if(!portalOK){outcome.textContent='Αναμονή';outcome.dataset.tone='muted';brief.textContent='Αναμονή σύνδεσης με το Portal';}
        else if(good){outcome.textContent='Σε λειτουργία';outcome.dataset.tone='good';brief.textContent='Οι ενεργές υπηρεσίες λειτουργούν';}
        else{outcome.textContent='Χωρίς ενεργή';outcome.dataset.tone='muted';brief.textContent='Δεν επιβεβαιώθηκε ενεργή υπηρεσία';}
      }
      new MutationObserver(updateServiceMini).observe(servicesList,{attributes:true,subtree:true,characterData:true,childList:true,attributeFilter:['data-tone']});
      const portalBadge=document.getElementById('portalConnectionBadge');
      if(portalBadge)new MutationObserver(updateServiceMini).observe(portalBadge,{attributes:true,childList:true,characterData:true,subtree:true});
      updateServiceMini();
    }

    if (health && statusMessage){
      const brandText=document.querySelector('.sps-brand > div:last-child');
      const monitorMini=document.createElement('button');
      monitorMini.type='button';
      monitorMini.id='sps-monitor-mini';
      monitorMini.className='sps-monitor-mini';
      monitorMini.setAttribute('aria-haspopup','dialog');
      monitorMini.setAttribute('aria-controls','sps-monitor-overlay');
      monitorMini.innerHTML='<span class="sps-monitor-dot" aria-hidden="true">✓</span><span id="sps-monitor-text">Έλεγχος παρακολούθησης…</span><span class="sps-monitor-chevron" aria-hidden="true">›</span>';
      if(brandText) brandText.append(monitorMini);
      monitorMini.addEventListener('click',monitoringModal.open);
      const monitorText=monitorMini.querySelector('#sps-monitor-text');
      const monitorDot=monitorMini.querySelector('.sps-monitor-dot');
      function updateMonitorMini(){
        const status=String(statusMessage.textContent||'').toLowerCase();
        const guardian=String(watchdogState?.textContent||'').toLowerCase();
        const remoteBanner=document.getElementById('remoteBanner');
      const remoteVisible=!!remoteBanner && remoteBanner.style.display!=='none' && remoteBanner.style.visibility!=='hidden';
      const tamperAlert=/συναγερμ|παραβίασ|tamper|alarm/i.test(status);
      const hasDeviceAlerts=['deviceHealth','batteryHealth','updateHealth'].some(id=>{
          const el=document.getElementById(id);
          return !!el && (el.classList.contains('warning')||el.classList.contains('error'));
        });
        const alert=hasDeviceAlerts||statusMessage.classList.contains('pending')||statusMessage.classList.contains('error');
        if (tamperAlert||statusMessage.classList.contains('error')||[...['deviceHealth','batteryHealth','updateHealth'].map(id=>document.getElementById(id))].some(x=>x?.classList.contains('error'))){
          monitorText.textContent='Πρόβλημα εγκατάστασης · προβολή';monitorMini.dataset.tone='bad';monitorDot.textContent='!';
        } else if(remoteVisible){
          monitorText.textContent='Τεχνικός συνδεδεμένος · προβολή';monitorMini.dataset.tone='attention';monitorDot.textContent='i';
        } else if(alert){
          monitorText.textContent='Απαιτείται προσοχή · προβολή';monitorMini.dataset.tone='attention';monitorDot.textContent='!';
        } else if(statusMessage.classList.contains('neutral')){
          monitorText.textContent='Κατάσταση εγκατάστασης · προβολή';monitorMini.dataset.tone='muted';monitorDot.textContent='i';
        } else if(guardian.includes('ενεργός (cloud)')||status.includes('παρακολουθείται ενεργά')){
          monitorText.textContent='Παρακολούθηση ενεργή';monitorMini.dataset.tone='good';monitorDot.textContent='✓';
        } else {
          monitorText.textContent='Κατάσταση παρακολούθησης';monitorMini.dataset.tone='muted';monitorDot.textContent='i';
        }
      }
      const obs=new MutationObserver(updateMonitorMini);
      obs.observe(statusMessage,{attributes:true,childList:true,characterData:true,subtree:true,attributeFilter:['class','style']});
      if(watchdogState)obs.observe(watchdogState,{attributes:true,childList:true,characterData:true,subtree:true});
      const remoteBanner=document.getElementById('remoteBanner');
      if(remoteBanner)obs.observe(remoteBanner,{attributes:true,childList:true,characterData:true,subtree:true,attributeFilter:['style','class']});
      for (const id of ['deviceHealth','batteryHealth','updateHealth']){
        const node=document.getElementById(id);
        if (node)obs.observe(node,{attributes:true,childList:true,characterData:true,subtree:true,attributeFilter:['class']});
      }
      monitoringModal.content.append(health);
      if(activitySection){
        const activityLink=document.createElement('button');
        activityLink.className='sps-activity-shortcut';
        activityLink.type='button';
        activityLink.textContent='Πρόσφατη δραστηριότητα · αιτήματα και συντήρηση  ›';
        const place=document.getElementById('sps-service-mini');
        if(place)place.after(activityLink);
        activityLink.addEventListener('click',()=>{monitoringModal.open();activitySection.open=true;});
        monitoringModal.content.append(activitySection);
      }
      updateMonitorMini();
    }
    body.classList.add('sps-customer-compact');
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded',init,{once:true});
  else init();
})();
