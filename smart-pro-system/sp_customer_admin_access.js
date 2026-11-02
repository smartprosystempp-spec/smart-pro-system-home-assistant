"use strict";
(() => {
  // Customer-facing operational flow: no transfer code, no installation token,
  // no raw secret, no local storage, no dependency on the Access QA add-on.
  const root = document.getElementById('portalConnectedView');
  if (!root) return;
  const card = document.createElement('section');
  card.id = 'sps-customer-admin-access';
  card.style.cssText = 'margin:16px 0;padding:18px;border:1px solid #405573;border-radius:14px;background:rgba(17,28,48,.94);color:#ecf4ff';
  card.setAttribute('aria-label','Πρόσβαση διαχειριστή Smart Pro');
  const title = document.createElement('h3'); title.textContent='Πρόσβαση διαχειριστή Smart Pro'; title.style.margin='0 0 8px';
  const info = document.createElement('p'); info.textContent='Δημιουργία ξεχωριστού λογαριασμού διαχειριστή μόνο με τη ρητή έγκρισή σας. Ο προσωπικός λογαριασμός σας δεν αλλάζει. Η παράδοση στοιχείων στη Smart Pro γίνεται κρυπτογραφημένα.';
  const state = document.createElement('p'); state.setAttribute('role','status'); state.textContent='Έλεγχος διαθεσιμότητας…';
  const note = document.createElement('p'); note.style.cssText='font-size:13px;opacity:.8'; note.textContent='Η δημιουργία λογαριασμού δεν ανοίγει αυτόματα τεχνική συνεδρία ούτε αλλάζει τη συνεχή παρακολούθηση.';
  const controls = document.createElement('div');controls.style.display='none';
  const explanation=document.createElement('p'); explanation.textContent='Η ενέργεια παραχωρεί πλήρη δικαιώματα διαχειριστή σε ξεχωριστό λογαριασμό Smart Pro. Επιβεβαιώστε μόνο εάν το επιθυμείτε.';
  const prompt=document.createElement('label');prompt.style.cssText='display:block;margin:12px 0';
  const input=document.createElement('input');input.type='checkbox';input.style.marginRight='8px';prompt.appendChild(input);
  const consentText=document.createElement('span');consentText.textContent='Επιβεβαιώνω ότι επιτρέπω στη Smart Pro να δημιουργήσει ξεχωριστό λογαριασμό με πλήρη δικαιώματα διαχειριστή.';prompt.appendChild(consentText);
  const submit=document.createElement('button');submit.type='button';submit.textContent='Ενεργοποίηση πρόσβασης Smart Pro'; submit.style.cssText='padding:10px 14px;background:#2d88c7;color:#fff;border-radius:9px;border:0;cursor:pointer';
  const retry=document.createElement('button');retry.type='button';retry.textContent='Ανανέωση κατάστασης';retry.style.cssText='margin-left:8px;padding:10px 14px;border:1px solid #5b8cb1;border-radius:9px;background:transparent;color:#e7f1ff;cursor:pointer';
  controls.append(explanation,prompt,submit,retry);card.append(title,info,state,controls,note);
  root.appendChild(card);
  let current=null, busy=false;
  const url=(typeof portalCurrentPath==='function'?portalCurrentPath():(window.location.pathname.endsWith('/')?window.location.pathname:window.location.pathname+'/'))+'api/sp-customer-admin/';
  const labels={absent:'Η πρόσβαση δεν έχει ενεργοποιηθεί.',active:'Ο ξεχωριστός διαχειριστής Smart Pro είναι ενεργός και τα στοιχεία του παραδόθηκαν.',incomplete:'Η δημιουργία λογαριασμού δεν ολοκληρώθηκε. Απαιτείται ελεγχόμενη ανάκληση.',undelivered_revoke_only:'Η παράδοση δεν επιβεβαιώθηκε. Ο λογαριασμός υπάρχει και πρέπει να ανακληθεί πριν από νέα προσπάθεια.',review_required:'Απαιτείται έλεγχος διαχειριστή πριν από οποιαδήποτε αλλαγή.',portal_unpaired:'Συνδέστε πρώτα το Smart Pro System με το Portal.',untrusted_ingress:'Η διαχειριστική φόρμα διατίθεται μόνο μέσω της ασφαλούς διεπαφής Home Assistant.',ha_admin_required:'Μόνο επαληθευμένος διαχειριστής Home Assistant μπορεί να εγκρίνει πρόσβαση.'};
  async function refresh() {
    if (busy) return;
    state.textContent='Έλεγχος κατάστασης…';controls.style.display='none';input.checked=false;
    try {
      const response=await fetch(url+'status',{credentials:'same-origin',cache:'no-store',redirect:'error'});
      if (!response.ok) throw Error('readback_failed');
      const d=await response.json();
      current=d;
      state.textContent=labels[d.status]||'Η κατάσταση δεν επιβεβαιώθηκε. Δεν εκτελέστηκε ενέργεια.';
      if (d.operation==='activate' && d.consent_token) {
        consentText.textContent='Επιβεβαιώνω ότι επιτρέπω τη δημιουργία ξεχωριστού λογαριασμού με πλήρη δικαιώματα διαχειριστή.';submit.textContent='Ενεργοποίηση πρόσβασης Smart Pro';controls.style.display='block';
      } else if(d.operation==='revoke' && d.consent_token) {
        consentText.textContent='Επιβεβαιώνω ότι θέλω να ανακαλέσω τον ξεχωριστό λογαριασμό διαχειριστή Smart Pro.';submit.textContent='Ανάκληση πρόσβασης Smart Pro';controls.style.display='block';
      }
    } catch(_) { current=null; state.textContent='Ο έλεγχος δεν είναι διαθέσιμος. Δεν δημιουργήθηκε λογαριασμός.'; }
  }
  submit.addEventListener('click',async()=>{
    if(busy||!current||!current.consent_token)return;
    const expected=current.operation==='activate'?'ΕΓΚΡΙΝΩ':'ΑΝΑΚΛΗΣΗ';
    if(!input.checked){state.textContent='Επιβεβαιώστε πρώτα την επιλογή σας.';return;}
    busy=true;submit.disabled=true;retry.disabled=true;state.textContent='Έλεγχος έγκρισης και ασφαλής εκτέλεση. Μην επαναλάβετε την ενέργεια.';
    const payload={operation:current.operation,consent_token:current.consent_token,confirmation:expected};
    current=null;
    try {
      const response=await fetch(url+'action',{method:'POST',mode:'same-origin',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'Content-Type':'application/json','X-Smart-Pro-Admin-Action':'v1'},body:JSON.stringify(payload)});
      const result=await response.json();
      if(!response.ok){state.textContent='Η ενέργεια δεν επιβεβαιώθηκε ('+String(result.code||'έλεγχος')+'). Ελέγξτε την κατάσταση και μην επαναλάβετε τη δημιουργία.';}
      else if(result.code==='enrolled_pending_portal_receipt')state.textContent='Η πρόσβαση ενεργοποιήθηκε και τα στοιχεία παραδόθηκαν κρυπτογραφημένα στη Smart Pro.';
      else if(result.code==='revoked_verified')state.textContent='Η πρόσβαση ανακλήθηκε επιτυχώς.';
      else state.textContent='Αποτέλεσμα: '+String(result.code||'μη επιβεβαιωμένο');
    } catch(_) {state.textContent='Το αποτέλεσμα είναι αβέβαιο. Μην επαναλάβετε τη δημιουργία. Ελέγξτε τους χρήστες Home Assistant και το Admin Portal.';}
    finally {busy=false;controls.style.display='none';submit.disabled=false;retry.disabled=false;input.checked=false;}
  });
  retry.addEventListener('click',refresh);
  refresh();
})();
