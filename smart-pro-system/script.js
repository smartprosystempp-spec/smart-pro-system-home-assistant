
let portalStatusTimer = null;
let currentPortalStatus = null;
let portalRequestsCache = [];
let portalRequestsLoading = false;

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function portalRequestIsOpen(request) {
    return Boolean(request && ['new', 'in_progress'].includes(String(request.status || '')));
}

function portalRequestTimestamp(request) {
    return Number(request && (request.updated_at || request.created_at) ? (request.updated_at || request.created_at) : 0);
}

function portalRequestIsManual(request) {
    if (!request) return false;
    if (request.channel) return String(request.channel) === 'manual_request';
    return String(request.source || '') !== 'automatic';
}

function portalManualOpenCount(status) {
    if (!status) return 0;
    if (status.manual_open_request_count !== undefined && status.manual_open_request_count !== null) {
        return Number(status.manual_open_request_count || 0);
    }
    return Number(status.open_request_count || 0);
}

function portalActiveRequest() {
    const active = portalRequestsCache.filter(request => portalRequestIsOpen(request) && portalRequestIsManual(request));
    active.sort((a, b) => portalRequestTimestamp(b) - portalRequestTimestamp(a));
    if (active.length > 0) return active[0];
    const latest = currentPortalStatus && currentPortalStatus.latest_request;
    return portalRequestIsOpen(latest) && portalRequestIsManual(latest) ? latest : null;
}

function portalRequestStatusClass(status) {
    const value = String(status || '');
    if (value === 'new') return 'portal-request-new';
    if (value === 'in_progress') return 'portal-request-progress';
    if (value === 'completed') return 'portal-request-completed';
    if (value === 'cancelled') return 'portal-request-cancelled';
    return 'portal-request-neutral';
}

function portalSubscriptionAccessState(subscription) {
    if (!subscription || !subscription.available) return '';
    const access = subscription.service_access || {};
    return String(access.state || subscription.status || '').trim().toLowerCase();
}

function portalTrialActive(subscription) {
    if (!subscription || !subscription.available) return false;
    const access = subscription.service_access || {};
    return portalSubscriptionAccessState(subscription) === 'trial' && access.trial_active !== false;
}

function portalTrialEndAt(subscription) {
    if (!portalTrialActive(subscription)) return null;
    const access = subscription.service_access || {};
    const value = Number(access.trial_end_at || 0);
    return Number.isFinite(value) && value > 0 ? value : null;
}

function portalTrialDaysRemaining(subscription) {
    const endAt = portalTrialEndAt(subscription);
    if (!endAt) return null;
    return Math.max(0, Math.ceil((endAt - (Date.now() / 1000)) / 86400));
}

function portalServiceAllowed(entitlement) {
    const subscription = currentPortalStatus && currentPortalStatus.subscription;
    // Once the Portal status endpoint is available, fail closed until pairing and
    // an authoritative paid service-access contract are present. Trial is an
    // onboarding state only and never unlocks paid Tools capabilities.
    if (currentPortalStatus && !currentPortalStatus.connected) return false;
    if (!subscription || !subscription.available) return currentPortalStatus ? false : true;
    if (subscription.verification_valid === false) return false;
    if (portalTrialActive(subscription)) return false;
    const access = subscription.service_access || {};
    const platformActive = access.platform_services_active !== undefined
        ? !!access.platform_services_active
        : !!subscription.services_active;
    if (!platformActive) return false;
    if (!entitlement) return true;
    const entitlements = subscription.entitlements || {};
    return !!entitlements[entitlement];
}

function setSubscriptionLockedControls(elements, locked) {
    (elements || []).forEach((el) => {
        if (!el) return;
        if (locked) {
            if (el.dataset.subscriptionPrevDisabled === undefined) {
                el.dataset.subscriptionPrevDisabled = el.disabled ? '1' : '0';
            }
            el.disabled = true;
            el.setAttribute('aria-disabled', 'true');
        } else if (el.dataset.subscriptionPrevDisabled !== undefined) {
            el.disabled = el.dataset.subscriptionPrevDisabled === '1';
            el.removeAttribute('aria-disabled');
            delete el.dataset.subscriptionPrevDisabled;
        }
    });
}

function ensureServiceGateNotice(container, noticeId, visible, message) {
    if (!container) return;
    let notice = document.getElementById(noticeId);
    if (!notice) {
        notice = document.createElement('div');
        notice.id = noticeId;
        notice.style.margin = '0 0 12px';
        notice.style.padding = '10px 12px';
        notice.style.borderRadius = '6px';
        notice.style.border = '1px solid #ff9800';
        notice.style.background = 'rgba(255, 152, 0, 0.10)';
        notice.style.color = '#ffcc80';
        notice.style.fontWeight = '600';
        container.prepend(notice);
    }
    notice.textContent = message;
    notice.style.display = visible ? 'block' : 'none';
}

function applySubscriptionServiceUiGates() {
    const guardianAllowed = portalServiceAllowed('guardian_monitoring');
    const updatesAllowed = portalServiceAllowed('update_guidance');

    const guardianTab = document.getElementById('tab_security');
    if (guardianTab) {
        ensureServiceGateNotice(
            guardianTab,
            'guardianSubscriptionGateNotice',
            !guardianAllowed,
            '🔒 Ο Φρουρός δεν είναι διαθέσιμος στην τρέχουσα κατάσταση υπηρεσιών. Οι αποθηκευμένες ρυθμίσεις διατηρούνται και θα επανέλθουν όταν υπάρχει ενεργό δικαίωμα.'
        );
        setSubscriptionLockedControls(Array.from(guardianTab.querySelectorAll('input, select, textarea, button')), !guardianAllowed);
    }

    const updatesCard = document.getElementById('cardUpdates');
    if (updatesCard) {
        ensureServiceGateNotice(
            updatesCard.querySelector('.auto-card-content') || updatesCard,
            'updatesSubscriptionGateNotice',
            !updatesAllowed,
            '🔒 Τα Smart Updates δεν είναι διαθέσιμα στην τρέχουσα κατάσταση υπηρεσιών. Η υπάρχουσα πολιτική διατηρείται χωρίς να εκτελείται.'
        );
        const ids = [
            'ts_auto_update_enabled', 'upd_core', 'upd_os', 'upd_addons',
            'upd_wait_days', 'upd_backup_wait', 'upd_eval_wait', 'upd_offline_limit',
            'upd_notify_all', 'smartUpdatesTestScenario', 'smartUpdatesTestRunBtn'
        ];
        setSubscriptionLockedControls(ids.map((id) => document.getElementById(id)), !updatesAllowed);
    }
}

function portalRequestDisplayTime(request) {
    const timestamp = portalRequestTimestamp(request);
    if (!timestamp) return '';
    return new Date(timestamp * 1000).toLocaleString('el-GR', {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}


function portalCurrentPath() {
    return window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
}

function portalFormatTime(timestamp) {
    if (!timestamp) return 'Καμία ακόμη';
    return new Date(timestamp * 1000).toLocaleString('el-GR');
}

function portalFormatDate(timestamp) {
    if (!timestamp) return '--';
    return new Date(Number(timestamp) * 1000).toLocaleDateString('el-GR', {
        day: '2-digit', month: '2-digit', year: 'numeric'
    });
}

function portalSubscriptionStatusClass(status) {
    const value = String(status || '');
    return ['active', 'grace', 'expired', 'suspended', 'pending_activation'].includes(value)
        ? value
        : '';
}

function portalSubscriptionRelevantDate(subscription) {
    if (!subscription) return '--';
    if (portalTrialActive(subscription)) {
        const endAt = portalTrialEndAt(subscription);
        return endAt ? `Trial έως ${portalFormatDate(endAt)}` : '--';
    }
    if (subscription.status === 'grace') {
        return subscription.grace_until ? `Χάρη έως ${portalFormatDate(subscription.grace_until)}` : '--';
    }
    if (subscription.status === 'pending_activation') {
        return subscription.start_at ? `Έναρξη ${portalFormatDate(subscription.start_at)}` : '--';
    }
    return subscription.expires_at ? `Λήξη ${portalFormatDate(subscription.expires_at)}` : '--';
}

function portalSubscriptionDaysText(subscription) {
    if (portalTrialActive(subscription)) {
        const days = portalTrialDaysRemaining(subscription);
        if (days === null) return '--';
        return `${days} ${days === 1 ? 'ημέρα' : 'ημέρες'}`;
    }
    if (!subscription || subscription.days_remaining === null || subscription.days_remaining === undefined) return '--';
    const days = Number(subscription.days_remaining || 0);
    return `${days} ${days === 1 ? 'ημέρα' : 'ημέρες'}`;
}

function updateCompactSubscription(subscription) {
    const uiPlan = document.getElementById('uiCompactPlan');
    const uiDays = document.getElementById('uiCompactDays');
    const uiMetaTitle = document.getElementById('uiCompactMetaTitle');
    const compactBox = document.getElementById('compactSubInfo');
    if (!uiPlan || !uiDays || !compactBox || !subscription || !subscription.available) return false;
    if (uiMetaTitle) uiMetaTitle.innerText = 'Υπόλοιπο ημερών';

    const isTrial = portalTrialActive(subscription);
    const planLabel = subscription.plan_label || (subscription.plan === 'advanced' ? 'Smart Pro System Advanced' : 'Smart Pro System Care');
    if (isTrial) {
        uiPlan.innerText = '🧪 ΔΟΚΙΜΑΣΤΙΚΗ ΠΕΡΙΟΔΟΣ';
    } else {
        uiPlan.innerText = subscription.plan === 'advanced' ? `◆ ${planLabel.toUpperCase()}` : `🛡️ ${planLabel.toUpperCase()}`;
    }

    let borderColor = isTrial ? '#f0b94b' : '#4caf50';
    let daysColor = isTrial ? '#ffd27a' : 'var(--success-text)';
    if (!isTrial && subscription.status === 'grace') { borderColor = '#ff9800'; daysColor = '#ffb74d'; }
    if (!isTrial && ['expired', 'suspended'].includes(subscription.status)) { borderColor = '#f44336'; daysColor = 'var(--error-text)'; }
    if (!isTrial && subscription.status === 'pending_activation') { borderColor = '#78909c'; daysColor = '#cbd5e1'; }

    compactBox.style.borderLeftColor = borderColor;
    uiPlan.style.color = borderColor;
    uiDays.style.color = daysColor;
    if (isTrial) {
        const trialDays = portalTrialDaysRemaining(subscription);
        uiDays.innerText = trialDays === null ? '--' : trialDays;
    } else {
        uiDays.innerText = subscription.status === 'expired'
            ? 'ΕΛΗΞΕ'
            : (subscription.status === 'suspended' ? 'ΑΝΑΣΤΟΛΗ' : (subscription.days_remaining ?? '--'));
    }
    return true;
}

function renderPortalSubscription(subscription) {
    const panel = document.getElementById('portalSubscriptionPanel');
    const plan = document.getElementById('portalSubscriptionPlan');
    const status = document.getElementById('portalSubscriptionStatus');
    const days = document.getElementById('portalSubscriptionDays');
    const date = document.getElementById('portalSubscriptionDate');
    const verification = document.getElementById('portalSubscriptionVerification');
    const managedPolicy = document.getElementById('portalManagedPolicy');
    const managedRuntime = document.getElementById('portalManagedRuntime');
    const tunnelRuntime = document.getElementById('portalTunnelRuntime');
    const note = document.getElementById('portalSubscriptionNote');
    const techSummary = document.getElementById('portalSubscriptionTechSummary');
    const legacyFields = document.getElementById('legacySubscriptionFields');

    if (!subscription || !subscription.available) {
        if (panel) panel.style.display = 'none';
        if (techSummary) techSummary.style.display = 'none';
        if (legacyFields) legacyFields.style.display = 'block';
        return;
    }

    if (panel) panel.style.display = 'block';
    if (plan) plan.textContent = portalTrialActive(subscription) ? 'Δεν έχει επιλεγεί πληρωμένο πακέτο' : (subscription.plan_label || subscription.plan || '--');
    if (status) {
        const access = subscription.service_access || {};
        status.textContent = access.state === 'trial'
            ? (access.state_label || 'Trial ενεργό')
            : (subscription.status_label || subscription.status || '--');
        status.className = `portal-subscription-status ${portalSubscriptionStatusClass(subscription.status)}`.trim();
    }
    if (days) days.textContent = portalSubscriptionDaysText(subscription);
    if (date) date.textContent = portalSubscriptionRelevantDate(subscription);
    if (verification) {
        verification.textContent = subscription.verification_label || '--';
        verification.className = subscription.verification_state || '';
    }
    if (managedPolicy) {
        const access = subscription.service_access || {};
        const entitlements = (subscription.entitlements && typeof subscription.entitlements === 'object') ? subscription.entitlements : {};
        const entitled = entitlements.managed_remote_support === true;
        if (access.state === 'trial') {
            managedPolicy.textContent = 'Δεν ενεργοποιείται στο Trial';
            managedPolicy.className = 'managed-denied';
            managedPolicy.title = 'Η δοκιμαστική περίοδος δεν ενεργοποιεί paid Managed Support entitlement.';
        } else if (entitled) {
            managedPolicy.textContent = 'Περιλαμβάνεται στο πακέτο';
            managedPolicy.className = 'managed-allowed';
            managedPolicy.title = 'Το ενεργό πακέτο περιλαμβάνει δικαίωμα Managed Support.';
        } else {
            managedPolicy.textContent = 'Δεν περιλαμβάνεται';
            managedPolicy.className = 'managed-denied';
            managedPolicy.title = 'Το ενεργό πακέτο δεν περιλαμβάνει Managed Support.';
        }
    }
    if (managedRuntime) {
        const runtime = (currentPortalStatus && currentPortalStatus.managed_support_runtime) || {};
        const runtimeLabels = {
            running: 'Εκτελείται',
            stopped: 'Εγκατεστημένο · Σταματημένο',
            error: 'Σφάλμα runtime',
            installed_unknown: 'Εγκατεστημένο · Άγνωστη κατάσταση',
            not_installed: 'Δεν έχει εγκατασταθεί',
            unavailable: 'Δεν ήταν δυνατός ο έλεγχος'
        };
        managedRuntime.textContent = runtimeLabels[runtime.state] || 'Άγνωστη κατάσταση';
        managedRuntime.className = runtime.state === 'running' ? 'managed-allowed' : 'managed-runtime-muted';
        managedRuntime.title = runtime.version ? `Smart Pro Managed Support ${runtime.version}` : '';
    }
    if (tunnelRuntime) {
        const runtime = (currentPortalStatus && currentPortalStatus.smart_pro_tunnel_runtime) || {};
        const runtimeLabels = {
            running: 'Εκτελείται',
            stopped: 'Εγκατεστημένο · Σταματημένο',
            error: 'Σφάλμα runtime',
            installed_unknown: 'Εγκατεστημένο · Άγνωστη κατάσταση',
            not_installed: 'Δεν έχει εγκατασταθεί',
            unavailable: 'Δεν ήταν δυνατός ο έλεγχος'
        };
        tunnelRuntime.textContent = runtimeLabels[runtime.state] || 'Άγνωστη κατάσταση';
        tunnelRuntime.className = runtime.state === 'running' ? 'managed-allowed' : 'managed-runtime-muted';
        tunnelRuntime.title = runtime.version ? `Smart Pro Tunnel ${runtime.version}` : '';
    }
    if (note) {
        if (subscription.verification_state === 'cached') {
            note.textContent = 'Προσωρινό πρόβλημα επικοινωνίας: χρησιμοποιείται η τελευταία έγκυρη κατάσταση μέσα στην ανοχή των 72 ωρών.';
        } else if (subscription.verification_state === 'verification_required') {
            note.textContent = 'Δεν ήταν δυνατή νέα επαλήθευση για περισσότερες από 72 ώρες. Απαιτείται έλεγχος σύνδεσης με το Portal.';
        } else {
            note.textContent = 'Η κατάσταση συγχρονίζεται από το Smart Pro Portal. Σε προσωρινή διακοπή διατηρείται η τελευταία έγκυρη επαλήθευση για έως 72 ώρες.';
        }
    }

    if (techSummary) {
        techSummary.style.display = 'block';
        const summaryPlan = portalTrialActive(subscription) ? 'Δοκιμαστική περίοδος' : (subscription.plan_label || '--');
        const summaryStatus = portalTrialActive(subscription)
            ? ((subscription.service_access || {}).state_label || 'Trial ενεργό')
            : (subscription.status_label || '--');
        techSummary.innerHTML = `<strong>${escapeHtml(summaryPlan)} · ${escapeHtml(summaryStatus)}</strong>`
            + `<span>${escapeHtml(portalSubscriptionDaysText(subscription))} · ${escapeHtml(portalSubscriptionRelevantDate(subscription))}</span>`
            + `<span>${escapeHtml(subscription.verification_label || '--')} · Πηγή: Smart Pro Portal</span>`;
    }
    if (legacyFields) legacyFields.style.display = 'none';
    updateCompactSubscription(subscription);
}

function spsSetText(id, text, tone = '') {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text || '--';
    el.dataset.tone = tone || 'neutral';
}

function spsRuntimeLabel(runtime) {
    const state = String((runtime || {}).state || 'unavailable');
    const labels = {
        running: ['Εκτελείται', 'good'],
        stopped: ['Εγκατεστημένο · Σταματημένο', 'attention'],
        error: ['Σφάλμα runtime', 'bad'],
        installed_unknown: ['Εγκατεστημένο · Άγνωστο', 'attention'],
        not_installed: ['Δεν έχει εγκατασταθεί', 'muted'],
        unavailable: ['Δεν ήταν δυνατός ο έλεγχος', 'muted']
    };
    return labels[state] || ['Άγνωστη κατάσταση', 'muted'];
}

function spsTunnelRuntimeLabel(runtime) {
    runtime = runtime || {};
    const processState = String(runtime.state || 'unavailable');
    const transportState = String(runtime.transport_state || 'off');
    const proxyState = String(runtime.private_proxy_state || 'off');
    if (processState === 'not_installed') return ['Δεν έχει εγκατασταθεί', 'muted'];
    if (processState === 'stopped') return ['Εγκατεστημένο · Σταματημένο', 'attention'];
    if (processState === 'error') return ['Σφάλμα add-on', 'bad'];
    if (processState === 'unavailable') return ['Δεν ήταν δυνατός ο έλεγχος', 'muted'];
    if (processState !== 'running') return ['Εγκατεστημένο · Άγνωστη κατάσταση', 'attention'];
    if (transportState === 'connected' && proxyState === 'listening') return ['Tunnel συνδεδεμένο · Proxy ενεργό', 'good'];
    if (transportState === 'connected') return ['Tunnel συνδεδεμένο · Proxy σε αναμονή', 'attention'];
    if (transportState === 'starting' || transportState === 'up_no_handshake') return ['Tunnel εκκινεί · Αναμονή σύνδεσης', 'attention'];
    if (transportState === 'handshake_stale') return ['Tunnel χρειάζεται έλεγχο', 'bad'];
    if (transportState === 'failed') return ['Tunnel runtime σφάλμα', 'bad'];
    if (transportState === 'identity_ready' || transportState === 'off' || transportState === 'stopped') return ['Add-on ενεργό · Tunnel ανενεργό', 'attention'];
    return ['Add-on ενεργό · Runtime άγνωστο', 'attention'];
}

function renderVNextOverview(status) {
    status = status || {};
    const subscription = status.subscription || {};
    const access = subscription.service_access || {};
    const external = status.external_access_summary || {};
    const standalone = external.standalone_entitlement || {};
    const mode = document.getElementById('customerModeBadge');
    const installationName = document.getElementById('uiInstallationName');
    const servicesNote = document.getElementById('servicesContextNote');
    const isTrial = portalTrialActive(subscription);
    const paidPlan = subscription && subscription.available && ['care', 'advanced', 'complete'].includes(String(subscription.plan || ''));
    const standaloneActive = standalone.eligible === true || (external.entitlement_eligible === true && ['standalone', 'package_and_standalone'].includes(String(external.eligibility_source || '')));

    if (!status.connected) {
        if (mode) { mode.textContent = 'Μη συνδεδεμένο'; mode.dataset.tone = 'muted'; }
        if (installationName) installationName.textContent = 'Δεν έχει συνδεθεί';
        if (servicesNote) servicesNote.textContent = 'Συνδέστε την εγκατάσταση με προσωρινό κωδικό από το Portal για να εμφανιστούν οι υπηρεσίες της.';
    } else if (isTrial) {
        if (mode) { mode.textContent = 'Δοκιμαστική εγκατάσταση'; mode.dataset.tone = 'attention'; }
        if (installationName) installationName.textContent = status.installation_name || status.installation_id || 'Συνδεδεμένη εγκατάσταση';
        if (servicesNote) servicesNote.textContent = standaloneActive
            ? 'Η δοκιμαστική περίοδος παραμένει ενεργή. Οι αγορασμένες standalone υπηρεσίες εμφανίζονται και λειτουργούν ανεξάρτητα από τα Trial benefits.'
            : 'Η δοκιμαστική περίοδος είναι onboarding κατάσταση και δεν ισοδυναμεί με πληρωμένο πακέτο.';
    } else if (paidPlan) {
        if (mode) { mode.textContent = 'Συνδρομητική εγκατάσταση'; mode.dataset.tone = access.paid_services_active ? 'good' : 'attention'; }
        if (installationName) installationName.textContent = status.installation_name || status.installation_id || 'Συνδεδεμένη εγκατάσταση';
        if (servicesNote) servicesNote.textContent = 'Οι παρακάτω καταστάσεις ξεχωρίζουν το πακέτο, την τρέχουσα πρόσβαση και το πραγματικό τοπικό runtime.';
    } else if (standaloneActive) {
        if (mode) { mode.textContent = 'Standalone / εφάπαξ υπηρεσία'; mode.dataset.tone = 'info'; }
        if (installationName) installationName.textContent = status.installation_name || status.installation_id || 'Συνδεδεμένη εγκατάσταση';
        if (servicesNote) servicesNote.textContent = 'Δεν υπάρχει συνδρομητικό πακέτο. Εμφανίζονται μόνο οι standalone υπηρεσίες και τα πραγματικά τοπικά runtimes αυτής της εγκατάστασης.';
    } else {
        if (mode) { mode.textContent = 'Χωρίς ενεργό πακέτο'; mode.dataset.tone = 'info'; }
        if (installationName) installationName.textContent = status.installation_name || status.installation_id || 'Συνδεδεμένη εγκατάσταση';
        if (servicesNote) servicesNote.textContent = 'Η εγκατάσταση είναι συνδεδεμένη, αλλά δεν υπάρχει ενεργό πληρωμένο πακέτο ή standalone υπηρεσία.';
    }

    const managedRuntime = spsRuntimeLabel(status.managed_support_runtime || {});
    const tunnelRuntime = spsTunnelRuntimeLabel(status.smart_pro_tunnel_runtime || {});
    const entitlements = (subscription && subscription.entitlements) || {};
    const packageEntitlements = (subscription && subscription.package_entitlements) || {};
    let managedEntitlement = ['Δεν περιλαμβάνεται', 'muted'];
    if (!status.connected) managedEntitlement = ['Μετά τη σύνδεση', 'muted'];
    else if (isTrial) managedEntitlement = ['Δεν ενεργοποιείται στο Trial', 'muted'];
    else if (paidPlan && packageEntitlements.managed_remote_support === true) {
        if (entitlements.managed_remote_support === true) managedEntitlement = ['Περιλαμβάνεται · Ενεργό', 'good'];
        else if (String(access.state || '') === 'expired') managedEntitlement = ['Περιλαμβάνεται · Ανενεργό λόγω λήξης', 'attention'];
        else if (String(access.state || '') === 'suspended') managedEntitlement = ['Περιλαμβάνεται · Σε αναστολή', 'attention'];
        else managedEntitlement = ['Περιλαμβάνεται · Αναμονή πρόσβασης', 'attention'];
    } else if (paidPlan) managedEntitlement = ['Δεν περιλαμβάνεται στο πακέτο', 'muted'];
    else managedEntitlement = ['Δεν περιλαμβάνεται', 'muted'];
    spsSetText('serviceManagedEntitlement', managedEntitlement[0], managedEntitlement[1]);
    spsSetText('serviceManagedRuntime', managedRuntime[0], managedRuntime[1]);
    spsSetText('serviceTunnelRuntime', tunnelRuntime[0], tunnelRuntime[1]);

    const backup = status.managed_backup_summary || {};
    let backupLabel = 'Δεν έχει ρυθμιστεί';
    let backupTone = 'muted';
    if (backup.storage_configured && backup.policy_state) { backupLabel = 'Ρυθμισμένο · ' + (backup.retention_days ? `${backup.retention_days} ημέρες` : 'πολιτική ενεργή'); backupTone = 'good'; }
    else if (backup.policy_state && backup.policy_state !== 'none') { backupLabel = 'Πολιτική διαθέσιμη · αναμονή ρύθμισης'; backupTone = 'attention'; }
    if (backup.upload_result_state && ['failed','error'].includes(String(backup.upload_result_state).toLowerCase())) { backupLabel = 'Απαιτεί έλεγχο'; backupTone = 'bad'; }
    spsSetText('serviceBackupState', backupLabel, backupTone);

    const externalLink = document.getElementById('serviceExternalUrlLink');
    const cycleLabel = String(standalone.cycle || '') === 'annual' ? 'Ετήσιο' : (String(standalone.cycle || '') === 'monthly' ? 'Μηνιαίο' : '');
    let externalEntitlementLabel = 'Δεν υπάρχει ενεργό δικαίωμα';
    let externalEntitlementTone = 'muted';
    if (external.package_eligible === true && standalone.eligible === true) { externalEntitlementLabel = 'Πακέτο + Standalone'; externalEntitlementTone = 'good'; }
    else if (external.package_eligible === true) { externalEntitlementLabel = 'Περιλαμβάνεται στο πακέτο'; externalEntitlementTone = 'good'; }
    else if (standalone.eligible === true) { externalEntitlementLabel = cycleLabel ? `Standalone ενεργό · ${cycleLabel}` : 'Standalone ενεργό'; externalEntitlementTone = 'good'; }
    else if (['expired','suspended','revoked'].includes(String(standalone.status || ''))) { externalEntitlementLabel = `Standalone · ${String(standalone.status).replaceAll('_',' ')}`; externalEntitlementTone = 'attention'; }
    spsSetText('serviceExternalUrlEntitlement', externalEntitlementLabel, externalEntitlementTone);

    let externalLabel = 'Δεν έχει ρυθμιστεί';
    let externalTone = 'muted';
    const registryState = String(external.registry_state || '');
    const tunnelState = String(external.tunnel_runtime || 'off');
    const gatewayState = String(external.gateway_state || 'not_configured');
    const portalPublicReady = external.portal_public_ready === true;
    if ((portalPublicReady || registryState === 'active') && external.hostname) { externalLabel = 'Online · Public URL ενεργό'; externalTone = 'good'; }
    else if (registryState && registryState !== 'unknown') { externalLabel = 'Provisioning · ' + registryState.replaceAll('_', ' '); externalTone = 'attention'; }
    else if (tunnelState === 'connected' && gatewayState === 'private_ready') { externalLabel = 'Private tunnel έτοιμο · αναμονή public URL'; externalTone = 'attention'; }
    else if (['starting','up_no_handshake','handshake_stale'].includes(tunnelState)) { externalLabel = 'Tunnel σε ρύθμιση · αναμονή provisioning'; externalTone = 'attention'; }
    else if (external.entitlement_eligible === true) { externalLabel = 'Αγορασμένο · αναμονή provisioning'; externalTone = 'attention'; }
    spsSetText('serviceExternalUrlState', externalLabel, externalTone);
    if (externalLink) {
        if ((portalPublicReady || registryState === 'active') && external.hostname) {
            externalLink.href = 'https://' + external.hostname;
            externalLink.style.display = 'inline-flex';
        } else {
            externalLink.removeAttribute('href');
            externalLink.style.display = 'none';
        }
    }
}

function renderPortalStatus(status) {
    currentPortalStatus = status || {};
    renderVNextOverview(currentPortalStatus);
    const badge = document.getElementById('portalConnectionBadge');
    const disconnected = document.getElementById('portalDisconnectedView');
    const connected = document.getElementById('portalConnectedView');
    const installationId = document.getElementById('portalInstallationId');
    const heartbeat = document.getElementById('portalLastHeartbeat');
    const message = document.getElementById('portalConnectionMessage');
    const folderLink = document.getElementById('portalFolderLink');

    if (folderLink && status.portal_url) {
        folderLink.href = status.portal_url.replace(/\/$/, '') + '/smart-pro-portal-preview/';
    }

    const headerInstallation = document.getElementById('uiCustomerNameDisplay');
    if (status.connected) {
        if (badge) { badge.textContent = status.last_error ? 'Σφάλμα συγχρονισμού' : 'Συνδεδεμένο'; badge.className = status.last_error ? 'portal-link-status error' : 'portal-link-status connected'; }
        if (disconnected) disconnected.style.display = 'none';
        if (connected) connected.style.display = 'block';
        if (installationId) installationId.textContent = status.installation_id || '--';
        if (heartbeat) heartbeat.textContent = portalFormatTime(status.last_heartbeat);
        if (headerInstallation) headerInstallation.innerText = status.installation_id ? `| ${status.installation_id}` : '';
        if (message) { message.textContent = status.last_error || 'Η εγκατάσταση συγχρονίζεται αυτόματα με το Smart Pro Portal.'; message.className = status.last_error ? 'portal-link-message error' : 'portal-link-message success'; }
    } else {
        portalRequestsCache = [];
        if (badge) { badge.textContent = 'Δεν έχει συνδεθεί'; badge.className = 'portal-link-status'; }
        if (disconnected) disconnected.style.display = 'block';
        if (connected) connected.style.display = 'none';
        if (headerInstallation) headerInstallation.innerText = '';
        if (message) { message.textContent = ''; message.className = 'portal-link-message'; }
        const uiPlan = document.getElementById('uiCompactPlan');
        const uiDays = document.getElementById('uiCompactDays');
        const uiMetaTitle = document.getElementById('uiCompactMetaTitle');
        const compactBox = document.getElementById('compactSubInfo');
        if (uiPlan) { uiPlan.innerText = 'SMART PRO PORTAL'; uiPlan.style.color = '#78909c'; }
        if (uiMetaTitle) uiMetaTitle.innerText = 'Κατάσταση';
        if (uiDays) { uiDays.innerText = 'Αναμονή σύνδεσης'; uiDays.style.color = '#cbd5e1'; }
        if (compactBox) compactBox.style.borderLeftColor = '#78909c';
        renderPortalSubscription(null);
    }
    renderPortalSubscription(currentPortalStatus.subscription);
    applySubscriptionServiceUiGates();
    checkSubscriptionLockout();
    updatePortalRequestUi(currentPortalStatus);
    reconcilePendingRequestFromPortal(currentPortalStatus);
    renderHistory();
}

function updatePortalRequestUi(status) {
    const button = document.getElementById('supportBtn');
    if (!button) return;
    const openCount = portalManualOpenCount(status);
    const active = portalActiveRequest();
    const supportAllowed = portalServiceAllowed('support_requests');
    if (status && status.connected && openCount > 0) {
        const code = active && active.code ? active.code : (openCount === 1 ? '1 ενεργό αίτημα' : `${openCount} ενεργά αιτήματα`);
        const label = active && active.status_label ? ` · ${active.status_label}` : '';
        button.innerText = `⏳ ${code}${label}`;
        button.classList.add('sent');
        button.style.pointerEvents = 'none';
        button.title = active && active.category_label
            ? `${active.category_label}${active.message ? ' — ' + active.message : ''}`
            : 'Υπάρχει ενεργό αίτημα στο Smart Pro Portal.';
    } else if (!status || !status.connected) {
        button.innerText = '🔗 Υποστήριξη μετά τη σύνδεση';
        button.classList.add('sent');
        button.style.pointerEvents = 'none';
        button.title = 'Συνδέστε πρώτα την εγκατάσταση με το Smart Pro Portal.';
    } else if (!supportAllowed) {
        button.innerText = '🔒 Υποστήριξη μη ενεργή';
        button.classList.add('sent');
        button.style.pointerEvents = 'none';
        button.title = 'Τα κανονικά αιτήματα υποστήριξης απαιτούν ενεργή συνδρομητική κάλυψη.';
    } else {
        button.innerText = '👨‍🔧 Αίτημα Υποστήριξης';
        button.classList.remove('sent');
        button.style.pointerEvents = 'auto';
        button.title = '';
    }
}

function portalHasOpenRequest() {
    if (currentPortalStatus && currentPortalStatus.connected) {
        return portalManualOpenCount(currentPortalStatus) > 0;
    }
    const reqTime = globalConfig ? Number(globalConfig.pending_request_time || 0) : 0;
    return reqTime > 0 && (Date.now() - reqTime < TIMEOUT_MS);
}

function refreshHealthFromSnapshot() {
    if (!lastHealthSnapshot) return;
    updateHealthUI(
        lastHealthSnapshot.offline,
        lastHealthSnapshot.batteries,
        lastHealthSnapshot.watchdogEnabled,
        lastHealthSnapshot.offlineList,
        lastHealthSnapshot.batteryList,
        lastHealthSnapshot.tamperList
    );
}

async function reconcilePendingRequestFromPortal(status) {
    if (!status || !status.connected || !globalConfig) return;
    const openCount = portalManualOpenCount(status);
    if (openCount === 0 && Number(globalConfig.pending_request_time || 0) > 0) {
        globalConfig.pending_request_time = 0;
        await saveConfig({ pending_request_time: 0 });
    }
    refreshHealthFromSnapshot();
}

async function loadPortalRequests() {
    if (portalRequestsLoading) return;
    if (!currentPortalStatus || !currentPortalStatus.connected) {
        portalRequestsCache = [];
        renderHistory();
        return;
    }

    portalRequestsLoading = true;
    try {
        const response = await fetch(portalCurrentPath() + 'api/portal_requests', { cache: 'no-store' });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.message || 'Αποτυχία συγχρονισμού αιτημάτων.');
        portalRequestsCache = Array.isArray(data.requests) ? data.requests : [];
        currentPortalStatus = Object.assign({}, currentPortalStatus, {
            open_request_count: Number(data.open_request_count || 0),
            manual_open_request_count: Number(data.manual_open_request_count !== undefined ? data.manual_open_request_count : (data.open_request_count || 0)),
            automatic_alert_count: Number(data.automatic_alert_count || 0),
            latest_request: data.latest_request || null
        });
        updatePortalRequestUi(currentPortalStatus);
        renderHistory();
        refreshHealthFromSnapshot();
    } catch (error) {
        console.warn('Portal requests sync:', error.message);
    } finally {
        portalRequestsLoading = false;
    }
}

async function loadPortalStatus() {
    try {
        const response = await fetch(portalCurrentPath() + 'api/portal_status', { cache: 'no-store' });
        if (!response.ok) throw new Error('Αποτυχία ελέγχου σύνδεσης.');
        renderPortalStatus(await response.json());
        await loadPortalRequests();
    } catch (error) {
        const message = document.getElementById('portalConnectionMessage');
        if (message) { message.textContent = error.message; message.className = 'portal-link-message error'; }
    }
}

async function pairWithPortal() {
    const input = document.getElementById('portalPairingCode');
    const button = document.getElementById('portalPairButton');
    const message = document.getElementById('portalConnectionMessage');
    const code = input ? input.value.trim().toUpperCase().replace(/\s+/g, '') : '';
    if (!/^SP-[A-HJ-NP-Z2-9]{6}$/.test(code)) {
        if (message) { message.textContent = 'Ο κωδικός πρέπει να έχει μορφή SP-XXXXXX.'; message.className = 'portal-link-message error'; }
        return;
    }
    if (button) { button.disabled = true; button.textContent = 'Σύνδεση...'; }
    if (message) { message.textContent = 'Γίνεται ασφαλής σύνδεση με το Smart Pro Portal...'; message.className = 'portal-link-message'; }
    try {
        const response = await fetch(portalCurrentPath() + 'api/portal_pair', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Η σύνδεση απέτυχε.');
        if (input) input.value = '';
        renderPortalStatus(data.connection || {});
        showToast('✅ Η εγκατάσταση συνδέθηκε με το Portal!');
    } catch (error) {
        if (message) { message.textContent = error.message; message.className = 'portal-link-message error'; }
    } finally {
        if (button) { button.disabled = false; button.textContent = 'Σύνδεση'; }
    }
}

async function disconnectPortal() {
    if (!window.confirm('Να αποσυνδεθεί αυτή η εγκατάσταση από το Smart Pro Portal;')) return;
    try {
        const response = await fetch(portalCurrentPath() + 'api/portal_disconnect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        if (!response.ok) throw new Error('Η αποσύνδεση απέτυχε.');
        await loadPortalStatus();
        showToast('Η τοπική σύνδεση διαγράφηκε.');
    } catch (error) {
        const message = document.getElementById('portalConnectionMessage');
        if (message) { message.textContent = error.message; message.className = 'portal-link-message error'; }
    }
}

function startPortalStatusPolling() {
    loadPortalStatus();
    if (portalStatusTimer) clearInterval(portalStatusTimer);
    portalStatusTimer = setInterval(loadPortalStatus, 15000);
}

const TIMEOUT_MS = 2 * 60 * 60 * 1000; 
let globalConfig = null;
let lastHealthSnapshot = null;
let integrationHealthTimer = null;

let pendingAutomationToggle = null;

function toggleCard(cardId) {
    const card = document.getElementById(cardId);
    if (!card) return;
    card.classList.toggle('open');
    const expanded = card.classList.contains('open');
    const button = card.querySelector('.automation-card-main');
    if (button) button.setAttribute('aria-expanded', String(expanded));
}

function automationNumber(id, fallback) {
    const value = Number(document.getElementById(id)?.value);
    return Number.isFinite(value) ? value : fallback;
}

function setAutomationStatus(prefix, status, text) {
    const pill = document.getElementById(prefix + 'StatusPill');
    const label = document.getElementById(prefix + 'ToggleLabel');
    const card = document.getElementById(prefix === 'updates' ? 'cardUpdates' : 'cardVacation');
    if (pill) {
        pill.dataset.status = status;
        pill.textContent = text;
    }
    if (label) label.textContent = text;
    if (card) card.dataset.automationState = status;
}

function updateAutomationPresentation() {
    const updatesEnabled = document.getElementById('ts_auto_update_enabled')?.checked === true;
    const notifyOnly = document.getElementById('upd_notify_all')?.checked === true;
    const waitDays = automationNumber('upd_wait_days', 3);
    const offlineLimit = automationNumber('upd_offline_limit', 2);
    const updateScopes = [
        document.getElementById('upd_core')?.checked,
        document.getElementById('upd_os')?.checked,
        document.getElementById('upd_addons')?.checked
    ].filter(Boolean).length;

    const updatesMode = notifyOnly ? 'Μόνο ειδοποίηση' : 'Αυτόματη εγκατάσταση';
    const updatesStatus = updatesEnabled ? (notifyOnly ? 'monitoring' : 'active') : 'inactive';
    const updatesStatusText = updatesEnabled ? (notifyOnly ? 'Παρακολούθηση' : 'Ενεργό') : 'Ανενεργό';
    setAutomationStatus('updates', updatesStatus, updatesStatusText);

    const updatesSummary = document.getElementById('updatesCardSummary');
    if (updatesSummary) {
        updatesSummary.textContent = `${updatesStatusText} · ${updatesMode} · ${updateScopes}/3 κατηγορίες · Ωρίμανση ${waitDays} ημ. · Rollback στις ${offlineLimit} συσκευές`;
    }
    const notifyLabel = document.getElementById('updatesNotifyLabel');
    if (notifyLabel) notifyLabel.textContent = notifyOnly ? 'Ενεργό' : 'Ανενεργό';

    const updatesBanner = document.getElementById('updatesStateNarrative');
    if (updatesBanner) {
        updatesBanner.dataset.status = updatesStatus;
        if (!updatesEnabled) {
            updatesBanner.textContent = 'Ο αυτοματισμός είναι κλειστός. Δεν γίνεται έλεγχος, ειδοποίηση, backup, εγκατάσταση ή rollback.';
        } else if (notifyOnly) {
            updatesBanner.textContent = 'Ενεργή παρακολούθηση ενημερώσεων. Αποστέλλεται μία ειδοποίηση ανά ώριμο update, χωρίς καμία πραγματική εγκατάσταση.';
        } else {
            updatesBanner.textContent = 'Ενεργή αυτόματη ροή: έλεγχος → ωρίμανση → backup → εγκατάσταση → health check → επιτυχία ή rollback.';
        }
    }

    const vacationEnabled = document.getElementById('ts_auto_vacation_enabled')?.checked === true;
    setAutomationStatus('vacation', vacationEnabled ? 'active' : 'inactive', vacationEnabled ? 'Ενεργό' : 'Ανενεργό');
    const vacationStart = document.getElementById('ts_vacation_start')?.value || '20:00';
    const vacationEnd = document.getElementById('ts_vacation_end')?.value || '23:59';
    const selectedLights = document.querySelectorAll('.vac-light-cb:checked').length;
    const selectedCovers = document.querySelectorAll('.vac-cover-cb:checked').length;
    const selectedAudio = document.querySelectorAll('.vac-audio-cb:checked').length;
    const vacationSummary = document.getElementById('vacationCardSummary');
    if (vacationSummary) {
        vacationSummary.textContent = `${vacationEnabled ? 'Ενεργό' : 'Ανενεργό'} · Παρουσία ${vacationStart}–${vacationEnd} · ${selectedLights + selectedCovers + selectedAudio} επιλογές`;
    }
    const vacationDeviceSummary = document.getElementById('vacationDeviceSummary');
    if (vacationDeviceSummary) {
        vacationDeviceSummary.textContent = `${selectedLights} φωτισμός · ${selectedCovers} ρολά · ${selectedAudio} ήχος/TV`;
    }
    const vacationBanner = document.getElementById('vacationStateNarrative');
    if (vacationBanner) {
        vacationBanner.dataset.status = vacationEnabled ? 'active' : 'inactive';
        vacationBanner.textContent = vacationEnabled
            ? 'Ο αυτοματισμός είναι διαθέσιμος και εκτελείται μόνο όταν το input_boolean.smart_pro_vacation είναι ενεργό στο Home Assistant.'
            : 'Ο αυτοματισμός είναι κλειστός. Δεν αλλάζει φώτα, ρολά, πρίζες ή συσκευές πολυμέσων.';
    }
}

function handleNotifyOnlyToggle() {
    updateAutomationPresentation();
}

function handleAutoUpdateToggle(event) {
    const checkbox = event?.target;
    if (!checkbox) return;
    if (!checkbox.checked) {
        updateAutomationPresentation();
        return;
    }
    checkbox.checked = false;
    updateAutomationPresentation();
    openAutomationActivationConfirm();
}

function openAutomationActivationConfirm() {
    const notifyOnly = document.getElementById('upd_notify_all')?.checked === true;
    pendingAutomationToggle = { id: 'ts_auto_update_enabled', checked: true };
    const modal = document.getElementById('automationConfirmModal');
    const card = document.getElementById('automationConfirmCard');
    const title = document.getElementById('automationConfirmTitle');
    const message = document.getElementById('automationConfirmMessage');
    const mode = document.getElementById('automationConfirmMode');
    const checklist = document.getElementById('automationConfirmChecklist');
    const button = document.getElementById('automationConfirmButton');

    if (title) title.textContent = notifyOnly
        ? 'Ενεργοποίηση παρακολούθησης ενημερώσεων'
        : 'Ενεργοποίηση πραγματικών αυτόματων ενημερώσεων';
    if (message) message.textContent = notifyOnly
        ? 'Ο Smart Updates θα ελέγχει διαθέσιμες ενημερώσεις και θα στέλνει ειδοποίηση όταν ολοκληρωθεί η περίοδος ωρίμανσης.'
        : 'Μετά την αποθήκευση, ο Smart Updates θα μπορεί να εκτελεί πραγματικές επεμβατικές ενέργειες στο Home Assistant.';
    if (mode) {
        mode.dataset.mode = notifyOnly ? 'notify' : 'automatic';
        mode.textContent = notifyOnly ? 'Λειτουργία: Μόνο ειδοποίηση' : 'Λειτουργία: Αυτόματη εγκατάσταση';
    }
    if (checklist) {
        checklist.innerHTML = notifyOnly
            ? '<li>Ωριαίος έλεγχος διαθέσιμων ενημερώσεων</li><li>Περίοδος ωρίμανσης πριν από την ειδοποίηση</li><li>Κανένα backup, update ή rollback</li>'
            : '<li>Δημιουργία πλήρους backup</li><li>Εγκατάσταση ώριμων ενημερώσεων</li><li>Έλεγχος υγείας μετά την εγκατάσταση</li><li>Πιθανό rollback στο συγκεκριμένο backup</li>';
    }
    if (card) card.dataset.level = notifyOnly ? 'info' : 'critical';
    if (button) {
        button.textContent = notifyOnly ? 'Ενεργοποίηση παρακολούθησης' : 'Ενεργοποίηση αυτοματισμού';
        button.dataset.level = notifyOnly ? 'info' : 'critical';
    }
    if (modal) modal.style.display = 'flex';
}

function closeAutomationConfirm() {
    const modal = document.getElementById('automationConfirmModal');
    if (modal) modal.style.display = 'none';
    pendingAutomationToggle = null;
}

function confirmAutomationActivation() {
    if (pendingAutomationToggle) {
        const checkbox = document.getElementById(pendingAutomationToggle.id);
        if (checkbox) checkbox.checked = pendingAutomationToggle.checked;
    }
    closeAutomationConfirm();
    updateAutomationPresentation();
    showToast('Ο αυτοματισμός ενεργοποιήθηκε τοπικά. Πάτησε «Εφαρμογή» ή «Αποθήκευση» για να ισχύσει.');
}

const AUTOMATION_GUIDES = {
    updates: {
        title: 'Smart Updates & Rollback — Οδηγός λειτουργίας',
        html: `
            <section><h4>Πριν από την ενεργοποίηση</h4><p>Επιβεβαίωσε ότι λειτουργούν το Home Assistant token, το email τεχνικών ειδοποιήσεων και η δημιουργία backup. Εκτέλεσε πρώτα την ασφαλή δοκιμή.</p></section>
            <section><h4>Δύο τρόποι λειτουργίας</h4><p><strong>Μόνο ειδοποίηση:</strong> εντοπίζει ώριμα updates και στέλνει μία ενημέρωση χωρίς πραγματική επέμβαση.</p><p><strong>Αυτόματη εγκατάσταση:</strong> backup → update → health check → επιτυχία ή rollback.</p></section>
            <section><h4>Κρίσιμες ρυθμίσεις</h4><p><strong>Ημέρες ωρίμανσης:</strong> μειώνουν τον κίνδυνο εγκατάστασης πολύ νέας έκδοσης.</p><p><strong>Όριο offline συσκευών:</strong> rollback όταν οι νέες offline συσκευές είναι ίσες ή περισσότερες από το όριο.</p></section>
            <section><h4>Σε αποτυχία</h4><p>Αποτυχία backup ή εγκατάστασης σταματά τη ροή. Αποτυχία rollback απαιτεί άμεσο χειροκίνητο έλεγχο.</p></section>
            <section><h4>Ασφαλής δοκιμή</h4><p>Ο κεντρικός διακόπτης πρέπει να είναι κλειστός. Η δοκιμή προσομοιώνει όλα τα στάδια χωρίς πραγματικό backup, update ή restore.</p></section>`
    },
    vacation: {
        title: 'Smart Vacation Mode — Οδηγός λειτουργίας',
        html: `
            <section><h4>Σκοπός</h4><p>Δημιουργεί ρεαλιστική εικόνα παρουσίας με τυχαίο φωτισμό/ήχο και προγραμματισμένη κίνηση ρολών.</p></section>
            <section><h4>Δύο επίπεδα ενεργοποίησης</h4><p>Ο διακόπτης της κάρτας επιτρέπει τη λειτουργία. Η πραγματική εκτέλεση ξεκινά μόνο όταν το <strong>input_boolean.smart_pro_vacation</strong> είναι ενεργό στο Home Assistant.</p></section>
            <section><h4>Ωράρια</h4><p>Φώτα και ήχος λειτουργούν τυχαία μέσα στο παράθυρο παρουσίας. Τα ρολά ακολουθούν τις σταθερές ώρες ανοίγματος και κλεισίματος.</p></section>
            <section><h4>Επιλογή συσκευών</h4><p>Χρησιμοποίησε μόνο συσκευές που είναι ασφαλές να ενεργοποιούνται χωρίς ανθρώπινη παρουσία. Απόφυγε θερμαντικά σώματα, συσκευές μαγειρέματος και άλλες επικίνδυνες καταναλώσεις.</p></section>
            <section><h4>Απενεργοποίηση</h4><p>Με κλειστό τον διακόπτη δεν εκτελείται καμία ενέργεια Vacation Mode, ανεξάρτητα από την κατάσταση του helper.</p></section>`
    }
};

function openAutomationGuide(type) {
    const guide = AUTOMATION_GUIDES[type];
    if (!guide) return;
    const modal = document.getElementById('automationGuideModal');
    const title = document.getElementById('automationGuideTitle');
    const body = document.getElementById('automationGuideBody');
    if (title) title.textContent = guide.title;
    if (body) body.innerHTML = guide.html;
    if (modal) modal.style.display = 'flex';
}

function closeAutomationGuide() {
    const modal = document.getElementById('automationGuideModal');
    if (modal) modal.style.display = 'none';
}

document.addEventListener('change', (event) => {
    if (event.target && event.target.matches('.vac-light-cb, .vac-cover-cb, .vac-audio-cb')) {
        updateAutomationPresentation();
    }
});

async function loadConfig() {
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const headers = {};
        if (techSessionToken) headers['Authorization'] = 'Bearer ' + techSessionToken;
        const res = await fetch(currentPath + 'api/tech_settings', { headers });
        globalConfig = await res.json();
    } catch (e) { console.error("Σφάλμα φόρτωσης ρυθμίσεων."); }
}

async function saveConfig(data) {
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const headers = { 'Content-Type': 'application/json' };
        if (techSessionToken) headers['Authorization'] = 'Bearer ' + techSessionToken;
        const response = await fetch(currentPath + 'api/tech_settings', {
            method: 'POST', headers,
            body: JSON.stringify(data || {})
        });
        if (!response.ok) return false;
        const payload = await response.json().catch(() => ({}));
        globalConfig = Object.assign({}, globalConfig || {}, payload.settings || data || {});
        return true;
    } catch (e) {
        console.error("Σφάλμα αποθήκευσης.", e);
        return false;
    }
}

function checkSubscription() {
    if (currentPortalStatus) {
        if (currentPortalStatus.connected && updateCompactSubscription(currentPortalStatus.subscription)) return;
        if (!currentPortalStatus.connected) {
            const uiPlan = document.getElementById('uiCompactPlan');
            const uiDays = document.getElementById('uiCompactDays');
            const compactBox = document.getElementById('compactSubInfo');
            if (uiPlan) { uiPlan.innerText = '🔗 ΧΩΡΙΣ ΣΥΝΔΕΣΗ'; uiPlan.style.color = '#78909c'; }
            if (uiDays) { uiDays.innerText = '--'; uiDays.style.color = '#cbd5e1'; }
            if (compactBox) compactBox.style.borderLeftColor = '#78909c';
            return;
        }
    }
    if(!globalConfig) return;
    const plan = globalConfig.active_plan || 'smartcare';
    const startDateStr = globalConfig.sub_start || new Date().toISOString().split('T')[0];
    const durationMonths = parseInt(globalConfig.sub_months || '12');
    const endDate = new Date(startDateStr); endDate.setMonth(endDate.getMonth() + durationMonths);
    const diffDays = Math.ceil((endDate - new Date()) / (1000 * 60 * 60 * 24));
    
    const uiPlan = document.getElementById('uiCompactPlan'); const uiDays = document.getElementById('uiCompactDays');
    const compactBox = document.getElementById('compactSubInfo');
    let planName = "🛡️ SMART CARE", planColor = "#1976d2";
    if (plan === 'homeplus') { planName = "⭐ HOME PLUS"; planColor = "#ff9800"; }
    if (plan === 'businesspro') { planName = "💼 BUSINESS PRO"; planColor = "#9c27b0"; }
    
    if(uiPlan) { uiPlan.innerText = planName; uiPlan.style.color = planColor; }
    if (compactBox && uiDays) {
        compactBox.style.borderLeftColor = planColor;
        if (diffDays > 30) { uiDays.innerText = diffDays; uiDays.style.color = 'var(--success-text)'; } 
        else if (diffDays > 0) { uiDays.innerText = diffDays; uiDays.style.color = '#ff9800'; } 
        else { uiDays.innerText = "ΕΛΗΞΕ"; uiDays.style.color = 'var(--error-text)'; }
    }
}

function applyLogic() {
    if(!globalConfig) return;
    const remoteBanner = document.getElementById('remoteBanner'); 
    // Αν έχεις ενεργοποιήσει χειροκίνητα το Banner από τις ρυθμίσεις
    if(remoteBanner) remoteBanner.style.display = globalConfig.remote_session ? 'block' : 'none';
    
    const custName = currentPortalStatus && currentPortalStatus.connected
        ? (currentPortalStatus.installation_id || '')
        : '';
    const uiCust = document.getElementById('uiCustomerNameDisplay');
    if (uiCust) uiCust.innerText = custName ? `| ${custName}` : '';
}

// --- ΑΣΦΑΛΗΣ ΕΛΕΓΧΟΣ ΑΥΤΟΜΑΤΟΥ BANNER (MESHCENTRAL) ---
let meshBannerTimer = null;
let meshBannerCheckRunning = false;

async function checkMeshBanner() {
    if (meshBannerCheckRunning || !globalConfig) return;

    const remoteBanner = document.getElementById('remoteBanner');

    if (!globalConfig.mesh_banner_enabled) {
        if (remoteBanner && !globalConfig.remote_session) {
            remoteBanner.style.display = 'none';
        }
        return;
    }

    const currentPath = window.location.pathname.endsWith('/')
        ? window.location.pathname
        : window.location.pathname + '/';

    meshBannerCheckRunning = true;

    try {
        const requestUrl = currentPath
            + 'api/mesh_status?_='
            + Date.now();

        const res = await fetch(requestUrl, {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        });

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();

        if (remoteBanner && !globalConfig.remote_session) {
            remoteBanner.style.display = data.active
                ? 'block'
                : 'none';
        }
    } catch (error) {
        console.error(
            'MeshCentral Banner Check Failed',
            error
        );
    } finally {
        meshBannerCheckRunning = false;
    }
}

function startMeshBannerPolling() {
    if (meshBannerTimer) {
        clearInterval(meshBannerTimer);
    }

    checkMeshBanner();
    meshBannerTimer = setInterval(
        checkMeshBanner,
        5000
    );
}

window.addEventListener('focus', checkMeshBanner);
window.addEventListener('pageshow', checkMeshBanner);

document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        checkMeshBanner();
    }
});
// --------------------------------------------------

function showToast(message) {
    const toast = document.getElementById("toast"); if (!toast) return;
    toast.innerText = message; toast.className = "toast show";
    setTimeout(() => { toast.className = toast.className.replace("show", ""); }, 3000);
}

function setInputValue(id, value) {
    const element = document.getElementById(id);
    if (element) element.value = value ?? '';
}

function setCheckboxValue(id, checked) {
    const element = document.getElementById(id);
    if (element) element.checked = Boolean(checked);
}

async function addReqHistory(type, message) {
    if(!globalConfig) return;
    const hist = globalConfig.req_history || [];
    const now = new Date(); const dateStr = now.toLocaleDateString('el-GR') + ', ' + now.toLocaleTimeString('el-GR', {hour: '2-digit', minute:'2-digit'});
    hist.unshift({ type: type, msg: message, time: dateStr }); 
    globalConfig.req_history = hist.slice(0, 10);
    await saveConfig({ req_history: globalConfig.req_history });
    renderHistory();
}

async function addMainHistory(message) {
    if(!globalConfig) return;
    const hist = globalConfig.main_history || [];
    const now = new Date(); const dateStr = now.toLocaleDateString('el-GR') + ', ' + now.toLocaleTimeString('el-GR', {hour: '2-digit', minute:'2-digit'});
    hist.unshift({ msg: message, time: dateStr }); 
    globalConfig.main_history = hist.slice(0, 10);
    await saveConfig({ main_history: globalConfig.main_history });
    renderHistory();
}

function renderHistory() {
    if(!globalConfig) return;
    const reqHist = Array.isArray(globalConfig.req_history) ? globalConfig.req_history : [];
    const mainHist = Array.isArray(globalConfig.main_history) ? globalConfig.main_history : [];
    const reqList = document.getElementById('reqHistoryList');
    const mainList = document.getElementById('mainHistoryList');
    const logsGrid = document.getElementById('logsGrid');
    if(!reqList || !mainList || !logsGrid) return;

    const portalItems = portalRequestsCache.slice().sort((a, b) => {
        const openDiff = Number(portalRequestIsOpen(b)) - Number(portalRequestIsOpen(a));
        return openDiff || (portalRequestTimestamp(b) - portalRequestTimestamp(a));
    });
    const portalCodes = new Set(portalItems.map(item => String(item.code || '').toUpperCase()).filter(Boolean));
    const localRequests = reqHist.filter(item => {
        const match = String(item && item.msg ? item.msg : '').match(/\bSP-\d{5}\b/i);
        return !match || !portalCodes.has(match[0].toUpperCase());
    });

    reqList.innerHTML = '';
    mainList.innerHTML = '';
    if (portalItems.length === 0 && localRequests.length === 0 && mainHist.length === 0) {
        logsGrid.style.display = 'none';
        return;
    }
    logsGrid.style.display = 'grid';

    portalItems.forEach(request => {
        const isOpen = portalRequestIsOpen(request);
        const code = escapeHtml(request.code || 'Αίτημα');
        const category = escapeHtml(request.category_label || request.category || 'Αίτημα υποστήριξης');
        const status = escapeHtml(request.status_label || request.status || 'Καταχωρισμένο');
        const source = escapeHtml(request.source_label || '');
        const message = escapeHtml(request.message || '');
        const date = escapeHtml(portalRequestDisplayTime(request));
        const statusClass = portalRequestStatusClass(request.status);
        reqList.insertAdjacentHTML('beforeend', `
            <div class="history-item portal-request-item${isOpen ? ' is-open' : ''}">
                <span class="hist-msg portal-request-content">
                    <span class="portal-request-heading">
                        <strong>${isOpen ? '🟠' : '🟢'} ${code}</strong>
                        <span class="portal-request-status ${statusClass}">${status}</span>
                    </span>
                    <span class="portal-request-category">${category}${source ? ` · ${source}` : ''}</span>
                    ${message ? `<small class="portal-request-message">${message}</small>` : ''}
                </span>
                <span class="hist-date">${date}</span>
            </div>`);
    });

    localRequests.forEach(item => {
        const isRequest = item.type === 'req';
        const icon = isRequest ? '🟠' : '🟢';
        const cssClass = isRequest ? 'req' : 'res';
        reqList.insertAdjacentHTML('beforeend', `<div class="history-item"><span class="hist-msg ${cssClass}">${icon} ${escapeHtml(item.msg || '')}</span><span class="hist-date">${escapeHtml(item.time || '')}</span></div>`);
    });

    mainHist.forEach(item => {
        mainList.insertAdjacentHTML('beforeend', `<div class="history-item"><span class="hist-msg main">🔵 ${escapeHtml(item.msg || '')}</span><span class="hist-date">${escapeHtml(item.time || '')}</span></div>`);
    });
}

async function fetchRealHomeData() {
    let watchdogEnabled = true; let importantDomains = ['light.', 'switch.', 'climate.', 'cover.', 'lock.', 'camera.', 'water_heater.', 'binary_sensor.']; let batteryLimit = 15.0;
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const wdRes = await fetch(currentPath + 'status');
        if (wdRes.ok) { const wdData = await wdRes.json(); watchdogEnabled = wdData.watchdog_enabled; batteryLimit = wdData.battery_limit || 15.0; if (wdData.domains && wdData.domains.length > 0) importantDomains = wdData.domains; }
    } catch (error) {}
    
    try {
        const response = await fetch(currentPath + 'api/ha_states', { cache: 'no-store' });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            const devText = document.getElementById('deviceHealthText');
            if (devText) devText.innerText = payload.message || "Σφάλμα API";
            return;
        }
        const data = Array.isArray(payload.states) ? payload.states : [];
        let offlineCount = 0; let lowBatteryCount = 0; let updatesPending = 0;
        let realCpu = '--', realRam = '--', realDisk = '--', realCpuTemp = '--', realIp = '--', realDb = '--', realOs = '--', realUptime = '--';
        let backupDates = [], offlineDevicesNames = [], lowBatteryNames = [], tamperDetected = [];

        data.forEach(entity => {
            const id = entity.entity_id; const state = entity.state; const isImportant = importantDomains.some(domain => id.startsWith(domain));
            let friendlyName = (entity.attributes && entity.attributes.friendly_name) ? entity.attributes.friendly_name : id;
            if ((state === 'unavailable' || state === 'unknown') && isImportant) { offlineCount++; offlineDevicesNames.push(friendlyName); }
            if (entity.attributes && entity.attributes.device_class === 'battery') { const batLevel = parseFloat(state); if (!isNaN(batLevel) && batLevel < batteryLimit) { lowBatteryCount++; lowBatteryNames.push(`${friendlyName} (${batLevel}%)`); } }
            if (entity.attributes && entity.attributes.device_class === 'tamper' && state === 'on') tamperDetected.push(friendlyName);

            if (id === 'sensor.system_monitor_processor_use' || id === 'sensor.processor_use') realCpu = Math.round(parseFloat(state)) + '%';
            if (id === 'sensor.system_monitor_memory_use_percent' || id === 'sensor.memory_use_percent') realRam = Math.round(parseFloat(state)) + '%'; 
            else if ((id === 'sensor.system_monitor_memory_use' || id === 'sensor.memory_use') && realRam === '--') realRam = Math.round(parseFloat(state)) + ' MB';
            if (id === 'sensor.system_monitor_disk_usage_share' || id === 'sensor.disk_use_percent') realDisk = Math.round(parseFloat(state)) + '%';
            if (id.includes('processor_temperature')) realCpuTemp = parseFloat(state).toFixed(1) + ' °C';
            if (id.includes('ipv4_address') && state !== 'unknown') realIp = state;
            if (id.includes('database_size')) realDb = parseFloat(state).toFixed(1) + ' MB';
            if (id === 'update.home_assistant_operating_system_update') realOs = 'HA OS ' + (entity.attributes.installed_version || ''); 
            else if (id === 'update.home_assistant_core_update' && realOs === '--') realOs = 'HA Core ' + (entity.attributes.installed_version || '');
            if (id.includes('last_boot') && state !== 'unknown') { const diffDays = Math.floor((new Date() - new Date(state)) / (1000 * 60 * 60 * 24)); realUptime = `${diffDays} ημέρες`; }
            if (id.includes('backup_state') || id.includes('samba_backup')) {
                if(entity.attributes.last_backup) backupDates.push(new Date(entity.attributes.last_backup).toLocaleString('el-GR', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'})); 
                else if (entity.attributes.last_backup_time) backupDates.push(new Date(entity.attributes.last_backup_time).toLocaleString('el-GR', {day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'}));
            }
            if (id.startsWith('update.') && state === 'on') updatesPending++;
        });

        lastHealthSnapshot = {
            offline: offlineCount,
            batteries: lowBatteryCount,
            watchdogEnabled,
            offlineList: offlineDevicesNames,
            batteryList: lowBatteryNames,
            tamperList: tamperDetected
        };
        updateHealthUI(offlineCount, lowBatteryCount, watchdogEnabled, offlineDevicesNames, lowBatteryNames, tamperDetected);
        const safeText = (id, val) => { const el = document.getElementById(id); if (el && val !== '--') el.innerHTML = (id==='uptimeText') ? `Συνεχής Λειτουργία: <strong>${val}</strong>` : val; };
        safeText('cpuValue', realCpu); safeText('ramValue', realRam); safeText('diskValue', realDisk); safeText('cpuTempValue', realCpuTemp);
        safeText('ipValue', realIp); safeText('dbValue', realDb); safeText('osValue', realOs); safeText('uptimeText', realUptime);

        const backupList = document.getElementById('backupList');
        if (backupList) { if (backupDates.length > 0) backupList.innerHTML = backupDates.map(d => `<div>${d}</div>`).join(''); else backupList.innerHTML = `<span style="color:var(--text-muted);">Δεν βρέθηκε αισθητήρας</span>`; }
        const updateBox = document.getElementById('updateHealth'); const updateIcon = document.getElementById('updateIcon'); const updateText = document.getElementById('updateText');
        if (updateBox && updatesPending > 0) { updateBox.className = 'health-row warning'; updateIcon.innerText = '⚠️'; updateText.innerText = 'Εκκρεμούν ' + updatesPending + ' Ενημερώσεις'; } 
        else if (updateBox) { updateBox.className = 'health-row'; updateIcon.innerText = '✔️'; updateText.innerText = 'Λογισμικό Ενημερωμένο'; }
    } catch (error) { console.error(error); }
}

function updateHealthUI(offline, batteries, watchdogEnabled, offlineList = [], batteryList = [], tamperList = []) {
    const devBox = document.getElementById('deviceHealth'); const devText = document.getElementById('deviceHealthText');
    const statusMsg = document.getElementById('statusMessage'); const supportBtn = document.getElementById('supportBtn');
    const wdBox = document.getElementById('watchdogStateRow'); const wdIcon = document.getElementById('wdIcon'); const wdText = document.getElementById('wdText');
    
    const portalConnected = !!(currentPortalStatus && currentPortalStatus.connected);

    if (wdBox && wdIcon && wdText) {
        const guardianAllowed = portalServiceAllowed('guardian_monitoring');
        if (!portalConnected) {
            wdBox.className = 'health-row';
            wdIcon.innerText = '🔗';
            wdText.innerHTML = 'Φρουρός: <strong>Μετά τη σύνδεση με το Portal</strong>';
        } else if (!guardianAllowed) {
            wdBox.className = 'health-row warning';
            wdIcon.innerText = '🔒';
            wdText.innerHTML = 'Φρουρός: <strong>Μη ενεργός από τη συνδρομή</strong>';
        } else if (watchdogEnabled) {
            wdBox.className = 'health-row'; wdIcon.innerText = '🛡️'; wdText.innerHTML = 'Φρουρός: <strong>Ενεργός (Cloud)</strong>';
        } else {
            wdBox.className = 'health-row warning'; wdIcon.innerText = '🏠'; wdText.innerHTML = 'Φρουρός: <strong>Τοπικός (Ανενεργός)</strong>';
        }
    }
    if (!devBox || !devText || !statusMsg || !supportBtn) return;
    
    const guardianAllowed = portalServiceAllowed('guardian_monitoring');
    const hasPendingRequest = portalHasOpenRequest();

    if (tamperList.length > 0) {
        statusMsg.innerHTML = `🚨 <strong>ΣΥΝΑΓΕΡΜΟΣ ΠΑΡΑΒΙΑΣΗΣ</strong><br>Εντοπίστηκε σε: ${tamperList.join(', ')}`;
        statusMsg.style.background = 'var(--error-bg)'; statusMsg.style.color = 'var(--error-text)'; statusMsg.style.display = 'block';
    } else { statusMsg.style.background = ''; statusMsg.style.color = ''; }

    if (offline > 0) { 
        devBox.className = 'health-row error'; 
        let listHTML = `<details style="margin-top: 5px; cursor: pointer; text-align: left; background: rgba(0,0,0,0.05); padding: 5px; border-radius: 4px; font-size: 0.9em;"><summary style="font-weight: bold;">Συσκευές (${offline})</summary><ul style="margin-top: 5px; margin-bottom: 0; padding-left: 20px;">`;
        offlineList.forEach(dev => { listHTML += `<li style="padding: 2px 0;">${dev}</li>`; }); listHTML += `</ul></details>`;
        devText.innerHTML = `<strong>${offline} συσκευές εκτός σύνδεσης</strong><br>${listHTML}`;
        
        if (guardianAllowed && watchdogEnabled && tamperList.length === 0) { statusMsg.innerHTML = "⚠️ <strong>Εντοπίστηκε απώλεια.</strong> Ο Φρουρός τη διαχειρίζεται αυτόματα. Μπορείτε παράλληλα να ανοίξετε ξεχωριστό αίτημα υποστήριξης."; statusMsg.className = 'status pending'; if (!hasPendingRequest) { supportBtn.innerText = "👨‍🔧 Αίτημα Υποστήριξης"; supportBtn.classList.remove('sent'); supportBtn.style.pointerEvents = 'auto'; } } 
        else if (tamperList.length === 0) { statusMsg.innerHTML = "⚠️ <strong>Εντοπίστηκε σφάλμα.</strong> Πατήστε το κουμπί."; statusMsg.className = 'status pending'; if (!hasPendingRequest) { supportBtn.innerText = "👨‍🔧 Αίτημα Υποστήριξης"; supportBtn.classList.remove('sent'); supportBtn.style.pointerEvents = 'auto'; } }
    } else { 
        devBox.className = 'health-row'; devText.innerHTML = "Δεν εντοπίστηκαν offline συσκευές"; 
        if (hasPendingRequest && tamperList.length === 0) {
            const activeRequest = portalActiveRequest();
            const activeCode = activeRequest && activeRequest.code ? activeRequest.code : 'Ενεργό αίτημα';
            const activeStatus = activeRequest && activeRequest.status_label ? ` · ${activeRequest.status_label}` : '';
            statusMsg.innerHTML = `⏳ <strong>${escapeHtml(activeCode)}${escapeHtml(activeStatus)}</strong>`;
            statusMsg.className = 'status pending';
        } else if (tamperList.length === 0) {
            const subscription = currentPortalStatus && currentPortalStatus.subscription;
            if (!portalConnected) {
                statusMsg.innerHTML = "ℹ️ Η εγκατάσταση δεν έχει συνδεθεί ακόμη με το Smart Pro Portal. Συνδέστε την για να εμφανιστεί η πραγματική κατάσταση συνδρομής, Φρουρού και υπηρεσιών.";
                statusMsg.className = 'status neutral';
            } else if (portalTrialActive(subscription)) {
                statusMsg.innerHTML = "ℹ️ Η εγκατάσταση είναι συνδεδεμένη και συγχρονίζεται με το Smart Pro Portal. Η δοκιμαστική περίοδος δεν ενεργοποιεί πληρωμένες λειτουργίες.";
                statusMsg.className = 'status pending';
            } else {
                statusMsg.innerHTML = !guardianAllowed
                    ? "ℹ️ Η εγκατάσταση παραμένει συνδεδεμένη, αλλά η ενεργή παρακολούθηση Φρουρού είναι ανενεργή λόγω συνδρομής."
                    : (watchdogEnabled ? "✅ Το σύστημά σας παρακολουθείται ενεργά." : "✅ Το σύστημά σας είναι ασφαλές τοπικά.");
                statusMsg.className = guardianAllowed ? 'status' : 'status pending';
            }
            supportBtn.innerText = "👨‍🔧 Αίτημα Υποστήριξης"; supportBtn.classList.remove('sent'); supportBtn.style.pointerEvents = 'auto';
        }
    }
    const batBox = document.getElementById('batteryHealth'); const batText = document.getElementById('batteryHealthText');
    if(batBox && batText) {
        if (batteries > 0) { 
            batBox.className = 'health-row warning'; 
            let batHTML = `<details style="margin-top: 5px; cursor: pointer; text-align: left; background: rgba(0,0,0,0.05); padding: 5px; border-radius: 4px; font-size: 0.9em;"><summary style="font-weight: bold;">Μπαταρίες (${batteries})</summary><ul style="margin-top: 5px; margin-bottom: 0; padding-left: 20px;">`;
            batteryList.forEach(dev => { batHTML += `<li style="padding: 2px 0;">${dev}</li>`; }); batHTML += `</ul></details>`;
            batText.innerHTML = `<strong>${batteries} μπαταρίες χαμηλές</strong><br>${batHTML}`;
        } else { batBox.className = 'health-row'; batText.innerText = "Δεν εντοπίστηκαν χαμηλές μπαταρίες"; }
    }
    // Health rendering must never re-enable support when the Portal contract blocks it.
    updatePortalRequestUi(currentPortalStatus);
}

function switchTab(tabId) {
    document.querySelectorAll('.tech-tab-content').forEach(el => el.classList.remove('is-active'));
    document.querySelectorAll('.tech-tab-btn').forEach(el => {
        el.classList.remove('is-active');
        el.setAttribute('aria-selected', 'false');
    });
    const content = document.getElementById(tabId);
    const btn = document.getElementById('btn_' + tabId);
    if (content) content.classList.add('is-active');
    if (btn) {
        btn.classList.add('is-active');
        btn.setAttribute('aria-selected', 'true');
    }
    const body = document.getElementById('techModalBody');
    if (body) body.scrollTop = 0;
}

let techSessionToken = '';
let watchdogTestPollTimer = null;
let pendingWatchdogTestOptions = null;
let lastWatchdogTestState = { status: 'idle', message: 'Δεν εκτελείται δοκιμή.' };
let watchdogTerminalDisplayUntil = 0;
let watchdogTerminalResetTimer = null;
let watchdogTerminalKey = '';
let clickCount = 0; let clickTimer;
function checkTechAccess() {
    clickCount++; clearTimeout(clickTimer); clickTimer = setTimeout(() => { clickCount = 0; }, 1200);
    if (clickCount === 5) { clickCount = 0; const pinModal = document.getElementById('pinModal'); if(pinModal) pinModal.style.display = 'flex'; const pinInput = document.getElementById('techPinInput'); if(pinInput) { pinInput.value = ''; pinInput.focus(); } }
}
function closePinModal() { const pm = document.getElementById('pinModal'); if(pm) pm.style.display = 'none'; }
async function verifyPin() {
    const pinInput = document.getElementById('techPinInput'); if (!pinInput || !pinInput.value) return;
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const response = await fetch(currentPath + 'api/verify_pin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pin: pinInput.value }) });
        const data = await response.json();
        if (response.ok && data.status === 'success' && data.tech_session_token) {
            techSessionToken = data.tech_session_token;
            closePinModal();
            openTechModal();
        } else {
            showToast("Λάθος PIN.");
            pinInput.value = '';
        }
    } catch (e) { showToast("Σφάλμα σύνδεσης."); pinInput.value = ''; }
}
const techInput = document.getElementById("techPinInput"); if (techInput) { techInput.addEventListener("keypress", function(event) { if (event.key === "Enter") { event.preventDefault(); verifyPin(); } }); }
function closeTechModal() {
    closeAutomationConfirm();
    closeAutomationGuide();
    const tm = document.getElementById('techModal'); if(tm) tm.style.display = 'none';
    if (watchdogTestPollTimer) { clearInterval(watchdogTestPollTimer); watchdogTestPollTimer = null; }
    if (integrationHealthTimer) { clearInterval(integrationHealthTimer); integrationHealthTimer = null; }
    if (watchdogTerminalResetTimer) { clearTimeout(watchdogTerminalResetTimer); watchdogTerminalResetTimer = null; }
    watchdogTerminalDisplayUntil = 0;
    watchdogTerminalKey = '';
    techSessionToken = '';
}

async function openTechModal() {
    const modal = document.getElementById('techModal'); if(modal) modal.style.display = 'flex'; switchTab('tab_general'); 
    
    await loadConfig(); 
    const data = globalConfig || {};
    
    
    setInputValue('ts_customer_name', data.installation_id || (currentPortalStatus && currentPortalStatus.installation_id) || data.customer_name || '');
    setInputValue('planSelect', data.active_plan || 'smartcare');
    setInputValue('ts_sub_start', data.sub_start || new Date().toISOString().split('T')[0]);
    setInputValue('ts_sub_months', data.sub_months || '12');
    setCheckboxValue('remoteSessionToggle', data.remote_session === true);
    
    // Ρυθμίσεις Mesh Banner
    setCheckboxValue('ts_mesh_banner_enabled', data.mesh_banner_enabled === true);
    setInputValue(
        'ts_mesh_server_ip',
        data.mesh_server_ip && data.mesh_server_ip !== '100.70.104.64'
            ? data.mesh_server_ip
            : 'support.smart-pro-system.com'
    );
    
    setCheckboxValue('ts_watchdog_enabled', data.watchdog_enabled !== false);
    setInputValue('ts_check_interval', data.check_interval_min); setInputValue('ts_alert_delay', data.alert_delay_min);
    setInputValue('ts_battery_limit', data.battery_limit || 15.0); setInputValue('ts_email_password', '');
    const emailPasswordInput = document.getElementById('ts_email_password');
    if (emailPasswordInput) emailPasswordInput.placeholder = data.email_password_configured ? 'Ρυθμισμένο — αφήστε κενό για διατήρηση' : 'Δεν έχει ρυθμιστεί';
    const alertAddress = document.getElementById('ts_alert_email_address');
    if (alertAddress) alertAddress.textContent = 'alert@smart-pro-system.gr';
    setInputValue('ts_watchdog_test_delay', data.watchdog_test_delay_sec || 10);
    setInputValue('ts_watchdog_test_clear', data.watchdog_test_clear_sec || 30);
    setInputValue('ts_watchdog_test_device_name', data.watchdog_test_device_name || 'Δοκιμαστική συσκευή Φρουρού');
    setCheckboxValue('ts_watchdog_test_send_email', data.watchdog_test_send_email === true);
    
    setCheckboxValue('ts_domain_light', data.domain_light); setCheckboxValue('ts_domain_switch', data.domain_switch);
    setCheckboxValue('ts_domain_binary_sensor', data.domain_binary_sensor); setCheckboxValue('ts_domain_climate', data.domain_climate);
    setCheckboxValue('ts_domain_cover', data.domain_cover); setCheckboxValue('ts_domain_camera', data.domain_camera);
    setCheckboxValue('ts_domain_lock', data.domain_lock); setCheckboxValue('ts_domain_water_heater', data.domain_water_heater);
    setCheckboxValue('ts_domain_sensor', data.domain_sensor);

    // Updates Settings
    setCheckboxValue('ts_auto_update_enabled', data.auto_update_enabled === true);
    setCheckboxValue('upd_core', data.update_core !== false);
    setCheckboxValue('upd_os', data.update_os !== false);
    setCheckboxValue('upd_addons', data.update_addons !== false);
    setInputValue('upd_wait_days', data.update_wait_days || 3);
    setInputValue('upd_backup_wait', data.update_backup_wait_min || 15);
    setInputValue('upd_eval_wait', data.update_eval_min || 20);
    setInputValue('upd_offline_limit', data.update_rollback_offline_count || 2);
    setCheckboxValue('upd_notify_all', data.update_notify_only === true);

    setCheckboxValue('ts_auto_vacation_enabled', data.auto_vacation_enabled !== false);
    setInputValue('ts_vacation_start', data.vacation_start || "20:00"); setInputValue('ts_vacation_end', data.vacation_end || "23:59");
    setInputValue('ts_cover_open', data.cover_open_time || "08:00"); setInputValue('ts_cover_close', data.cover_close_time || "20:00");
    updateAutomationPresentation();
    renderPortalSubscription(currentPortalStatus && currentPortalStatus.subscription);
    applySubscriptionServiceUiGates();

    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const entRes = await fetch(currentPath + 'api/entities'); 
        if (entRes.ok) {
            const entData = await entRes.json();
            let htmlA = '', htmlB = '', htmlC = '';
            entData.forEach(ent => {
                let isLight = (data.vacation_lights || []).includes(ent.id) ? 'checked' : '';
                let isCover = (data.vacation_covers || []).includes(ent.id) ? 'checked' : '';
                let isAudio = (data.vacation_audio || []).includes(ent.id) ? 'checked' : '';
                let str = (cls, chk) => `<label style="display:block; margin-bottom:5px; padding:3px; cursor:pointer;"><input type="checkbox" class="${cls}" value="${ent.id}" ${chk} style="transform:scale(1.1); margin-right:5px;"> ${ent.name} <span style="color:#666; font-size:0.8em;">(${ent.id.split('.')[0]})</span></label>`;
                if(ent.id.startsWith('light.')) htmlA += str('vac-light-cb', isLight);
                if(ent.id.startsWith('cover.')) htmlB += str('vac-cover-cb', isCover);
                if(ent.id.startsWith('switch.') || ent.id.startsWith('media_player.')) { htmlC += str('vac-audio-cb', isAudio); htmlA += str('vac-light-cb', isLight); }
            });
            document.getElementById('vacationLightsContainer').innerHTML = htmlA || 'Δεν βρέθηκαν φώτα/πρίζες';
            document.getElementById('vacationCoversContainer').innerHTML = htmlB || 'Δεν βρέθηκαν ρολά/τέντες (cover)';
            document.getElementById('vacationAudioContainer').innerHTML = htmlC || 'Δεν βρέθηκαν πρίζες/TVs';
            updateAutomationPresentation();
        }
    } catch (e) { console.error("Σφάλμα φόρτωσης", e); }

    await loadIntegrationHealth();
    if (integrationHealthTimer) clearInterval(integrationHealthTimer);
    integrationHealthTimer = setInterval(loadIntegrationHealth, 5000);

    await loadSmartUpdatesTestStatus();
    await loadWatchdogTestStatus();
    if (watchdogTestPollTimer) clearInterval(watchdogTestPollTimer);
    watchdogTestPollTimer = setInterval(loadWatchdogTestStatus, 2000);
}

let techSettingsSaveInProgress = false;

function setTechSettingsSaveState(isSaving) {
    const applyButton = document.getElementById('techApplyBtn');
    const saveButton = document.getElementById('techSaveBtn');

    if (applyButton) {
        applyButton.disabled = isSaving;
        applyButton.textContent = isSaving ? 'Εφαρμογή…' : 'Εφαρμογή';
    }
    if (saveButton) {
        saveButton.disabled = isSaving;
        saveButton.textContent = isSaving ? 'Αποθήκευση…' : 'Αποθήκευση';
    }
}

async function saveTechSettings(closeModalAfter = true) {
    if (techSettingsSaveInProgress) return false;

    const safeGetVal = (id) => { const el = document.getElementById(id); return el ? el.value : ''; };
    const safeGetCheck = (id) => { const el = document.getElementById(id); return el ? el.checked : false; };
    const parseNum = (val, def) => { const n = parseFloat(val); return isNaN(n) ? def : n; };

    let selLights = []; document.querySelectorAll('.vac-light-cb:checked').forEach(cb => selLights.push(cb.value));
    let selCovers = []; document.querySelectorAll('.vac-cover-cb:checked').forEach(cb => selCovers.push(cb.value));
    let selAudio = []; document.querySelectorAll('.vac-audio-cb:checked').forEach(cb => selAudio.push(cb.value));

    const existingReqHist = globalConfig ? (globalConfig.req_history || []) : [];
    const existingMainHist = globalConfig ? (globalConfig.main_history || []) : [];
    const existingReqTime = globalConfig ? (globalConfig.pending_request_time || 0) : 0;

    const techData = {
        active_plan: safeGetVal('planSelect'),
        sub_start: safeGetVal('ts_sub_start'),
        sub_months: parseInt(safeGetVal('ts_sub_months') || 12),
        remote_session: safeGetCheck('remoteSessionToggle'),

        mesh_banner_enabled: safeGetCheck('ts_mesh_banner_enabled'),
        mesh_server_ip: safeGetVal('ts_mesh_server_ip') || 'support.smart-pro-system.com',

        req_history: existingReqHist,
        main_history: existingMainHist,
        pending_request_time: existingReqTime,

        auto_update_enabled: safeGetCheck('ts_auto_update_enabled'),
        update_core: safeGetCheck('upd_core'),
        update_os: safeGetCheck('upd_os'),
        update_addons: safeGetCheck('upd_addons'),
        update_wait_days: parseNum(safeGetVal('upd_wait_days'), 3),
        update_backup_wait_min: parseNum(safeGetVal('upd_backup_wait'), 15),
        update_eval_min: parseNum(safeGetVal('upd_eval_wait'), 20),
        update_rollback_offline_count: parseNum(safeGetVal('upd_offline_limit'), 2),
        update_notify_only: safeGetCheck('upd_notify_all'),

        watchdog_enabled: safeGetCheck('ts_watchdog_enabled'),
        check_interval_min: parseNum(safeGetVal('ts_check_interval'), 5.0),
        alert_delay_min: parseNum(safeGetVal('ts_alert_delay'), 15.0),
        battery_limit: parseNum(safeGetVal('ts_battery_limit'), 15.0),
        watchdog_test_delay_sec: parseNum(safeGetVal('ts_watchdog_test_delay'), 10),
        watchdog_test_clear_sec: parseNum(safeGetVal('ts_watchdog_test_clear'), 30),
        watchdog_test_device_name: safeGetVal('ts_watchdog_test_device_name') || 'Δοκιμαστική συσκευή Φρουρού',
        watchdog_test_send_email: safeGetCheck('ts_watchdog_test_send_email'),
        auto_vacation_enabled: safeGetCheck('ts_auto_vacation_enabled'),
        vacation_start: safeGetVal('ts_vacation_start') || '20:00',
        vacation_end: safeGetVal('ts_vacation_end') || '23:59',
        cover_open_time: safeGetVal('ts_cover_open') || '08:00',
        cover_close_time: safeGetVal('ts_cover_close') || '20:00',
        vacation_lights: selLights,
        vacation_covers: selCovers,
        vacation_audio: selAudio,
        domain_light: safeGetCheck('ts_domain_light'),
        domain_switch: safeGetCheck('ts_domain_switch'),
        domain_binary_sensor: safeGetCheck('ts_domain_binary_sensor'),
        domain_climate: safeGetCheck('ts_domain_climate'),
        domain_cover: safeGetCheck('ts_domain_cover'),
        domain_camera: safeGetCheck('ts_domain_camera'),
        domain_lock: safeGetCheck('ts_domain_lock'),
        domain_water_heater: safeGetCheck('ts_domain_water_heater'),
        domain_sensor: safeGetCheck('ts_domain_sensor')
    };
    const newEmailPassword = safeGetVal('ts_email_password').trim();
    if (newEmailPassword) techData.email_password = newEmailPassword;

    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    techSettingsSaveInProgress = true;
    setTechSettingsSaveState(true);

    try {
        const response = await fetch(currentPath + 'api/tech_settings', {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify(techData)
        });

        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload.status === 'error') {
            throw new Error(payload.message || `HTTP ${response.status}`);
        }

        // From this point onward the backend has confirmed the save. UI refresh
        // errors must never be reported as a failed save.
        globalConfig = Object.assign({}, globalConfig || {}, payload.settings || techData);
        setInputValue('ts_customer_name', globalConfig.installation_id || globalConfig.customer_name || '');
        updateAutomationPresentation();
        showToast('✅ Οι ρυθμίσεις αποθηκεύτηκαν!');

        try {
            applyLogic();
            checkSubscription();
            checkSubscriptionLockout();
            await loadIntegrationHealth();
        } catch (refreshError) {
            console.error('Οι ρυθμίσεις αποθηκεύτηκαν, αλλά η ανανέωση του UI απέτυχε.', refreshError);
        }

        if (closeModalAfter) closeTechModal();
        return true;
    } catch (error) {
        console.error('Αποτυχία αποθήκευσης τεχνικών ρυθμίσεων.', error);
        const message = error && error.message && !String(error.message).startsWith('HTTP ')
            ? error.message
            : 'Αποτυχία επικοινωνίας κατά την αποθήκευση των ρυθμίσεων.';
        showToast('❌ ' + message);
        return false;
    } finally {
        techSettingsSaveInProgress = false;
        setTechSettingsSaveState(false);
    }
}

function setIntegrationHealthRow(id, label, ok, message) {
    const row = document.getElementById(id);
    if (!row) return;
    row.textContent = `${ok ? '✅' : '⚠️'} ${label}: ${message}`;
    row.style.background = ok ? 'rgba(46,125,50,0.24)' : 'rgba(239,108,0,0.20)';
    row.style.color = ok ? '#b9f6ca' : '#ffe0b2';
    row.style.border = `1px solid ${ok ? '#2e7d32' : '#ef6c00'}`;
}

async function loadIntegrationHealth() {
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const response = await fetch(currentPath + 'api/integration_health?_=' + Date.now(), { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        setIntegrationHealthRow('integrationHealthPortal', 'Portal', Boolean(data.portal && data.portal.healthy), data.portal && data.portal.message ? data.portal.message : 'Άγνωστη κατάσταση');
        setIntegrationHealthRow('integrationHealthMesh', 'MeshCentral', Boolean(data.meshcentral && data.meshcentral.configured), data.meshcentral && data.meshcentral.message ? data.meshcentral.message : 'Άγνωστη κατάσταση');
        setIntegrationHealthRow('integrationHealthEmail', 'Email ειδοποιήσεων', Boolean(data.email && data.email.configured), data.email && data.email.message ? data.email.message : 'Άγνωστη κατάσταση');
        const installationInput = document.getElementById('ts_customer_name');
        if (installationInput && data.installation && data.installation.installation_id) {
            installationInput.value = data.installation.installation_id;
        }
    } catch (error) {
        setIntegrationHealthRow('integrationHealthPortal', 'Portal', false, 'Αποτυχία ελέγχου');
        setIntegrationHealthRow('integrationHealthMesh', 'MeshCentral', false, 'Αποτυχία ελέγχου');
        setIntegrationHealthRow('integrationHealthEmail', 'Email ειδοποιήσεων', false, 'Αποτυχία ελέγχου');
    }
}

function closeEmailTestResult() {
    const modal = document.getElementById('emailTestResultModal');
    if (modal) modal.style.display = 'none';
}

function showEmailTestResult(success, message) {
    const modal = document.getElementById('emailTestResultModal');
    const title = document.getElementById('emailTestResultTitle');
    const body = document.getElementById('emailTestResultMessage');
    const card = document.getElementById('emailTestResultCard');
    if (title) {
        title.textContent = success ? '✅ Δοκιμή email επιτυχής' : '❌ Αποτυχία δοκιμής email';
        title.style.color = success ? '#81c784' : '#ef9a9a';
    }
    if (body) body.textContent = message || (success ? 'Το email στάλθηκε.' : 'Η αποστολή απέτυχε.');
    if (card) card.style.borderColor = success ? '#4caf50' : '#f44336';
    if (modal) modal.style.display = 'flex';
}

async function sendTestAlertEmail() {
    if (!techSessionToken) {
        showEmailTestResult(false, 'Η τεχνική συνεδρία έληξε. Άνοιξε ξανά τον πίνακα με PIN.');
        return;
    }
    const button = document.getElementById('testAlertEmailBtn');
    const password = document.getElementById('ts_email_password')?.value || '';
    const configured = Boolean(globalConfig && globalConfig.email_password_configured);
    if (!password && !configured) {
        showEmailTestResult(false, 'Συμπλήρωσε πρώτα τον κωδικό του alert@smart-pro-system.gr.');
        return;
    }
    if (button) { button.disabled = true; button.textContent = 'Αποστολή…'; }
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    try {
        const response = await fetch(currentPath + 'api/test_alert_email', {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify({ email_password: password })
        });
        const data = await response.json();
        showEmailTestResult(response.ok && data.success === true, data.message);
    } catch (error) {
        showEmailTestResult(false, 'Δεν ήταν δυνατή η επικοινωνία με την υπηρεσία email: ' + error.message);
    } finally {
        if (button) { button.disabled = false; button.textContent = '✉️ Αποστολή δοκιμαστικού email'; }
    }
}


function smartUpdatesTestPath(suffix) {
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    return currentPath + 'api/smart_updates_test/' + suffix;
}

function smartUpdatesTestStatusMeta(status) {
    const map = {
        passed: { icon: '✅', label: 'Επιτυχία' },
        expected_stop: { icon: '🛑', label: 'Ασφαλής διακοπή' },
        critical: { icon: '🚨', label: 'Κρίσιμη προσομοίωση' },
        running: { icon: '⏳', label: 'Εκτέλεση' },
        idle: { icon: 'ℹ️', label: 'Αναμονή' },
        simulated_failure: { icon: '⚠️', label: 'Προσομοιωμένη αποτυχία' },
        blocked: { icon: '🛡️', label: 'Μπλοκαρίστηκε' },
        skipped: { icon: '⏭️', label: 'Παραλείφθηκε' }
    };
    return map[status] || { icon: '•', label: status || 'Άγνωστο' };
}

function renderSmartUpdatesTest(test) {
    const statusBox = document.getElementById('smartUpdatesTestStatus');
    const stepsBox = document.getElementById('smartUpdatesTestSteps');
    const safetyBox = document.getElementById('smartUpdatesTestSafety');
    const runButton = document.getElementById('smartUpdatesTestRunBtn');
    if (!statusBox || !stepsBox) return;

    const state = test || {
        status: 'idle',
        message: 'Δεν έχει εκτελεστεί ασφαλής δοκιμή.',
        steps: [],
        real_actions_executed: false
    };
    const meta = smartUpdatesTestStatusMeta(state.status);
    statusBox.textContent = `${meta.icon} ${state.scenario_label ? state.scenario_label + ': ' : ''}${state.message || ''}`;
    statusBox.dataset.status = state.status || 'idle';

    if (safetyBox) {
        const switchText = state.auto_update_enabled === true ? 'ΑΝΟΙΧΤΟΣ' : 'κλειστός';
        safetyBox.textContent = state.status === 'idle'
            ? 'Πραγματικές ενέργειες: μπλοκαρισμένες.'
            : `Κεντρικός διακόπτης: ${switchText} · Πραγματικές ενέργειες: ${state.real_actions_executed ? 'ΝΑΙ' : 'ΟΧΙ'} · Καμία ρύθμιση δεν άλλαξε.`;
    }

    stepsBox.replaceChildren();
    (state.steps || []).forEach((step) => {
        const row = document.createElement('div');
        row.className = 'smart-updates-test-step';
        row.dataset.status = step.status || 'idle';

        const icon = document.createElement('span');
        icon.className = 'smart-updates-test-step-icon';
        icon.textContent = smartUpdatesTestStatusMeta(step.status).icon;

        const copy = document.createElement('div');
        copy.className = 'smart-updates-test-step-copy';

        const title = document.createElement('strong');
        title.textContent = step.label || step.key || 'Βήμα';

        const detail = document.createElement('span');
        detail.textContent = step.detail || '';

        copy.appendChild(title);
        copy.appendChild(detail);
        row.appendChild(icon);
        row.appendChild(copy);
        stepsBox.appendChild(row);
    });

    if (runButton) {
        runButton.disabled = state.status === 'running';
        runButton.textContent = state.status === 'running'
            ? 'Εκτέλεση…'
            : '▶ Εκτέλεση ασφαλούς δοκιμής';
    }
}

async function loadSmartUpdatesTestStatus() {
    if (!techSessionToken) return;
    try {
        const response = await fetch(smartUpdatesTestPath('state') + '?_=' + Date.now(), {
            headers: watchdogTestHeaders(false),
            cache: 'no-store'
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Αποτυχία ανάγνωσης δοκιμής.');
        renderSmartUpdatesTest(data.test);
    } catch (error) {
        renderSmartUpdatesTest({
            status: 'critical',
            message: 'Δεν ήταν δυνατή η ανάγνωση της δοκιμής: ' + error.message,
            steps: [],
            real_actions_executed: false
        });
    }
}

async function runSmartUpdatesSafeTest() {
    if (!techSessionToken) {
        showToast('Άνοιξε ξανά τον τεχνικό πίνακα με PIN.');
        return;
    }
    const scenario = document.getElementById('smartUpdatesTestScenario')?.value || 'notify_only';
    renderSmartUpdatesTest({
        status: 'running',
        scenario_label: 'Ασφαλής δοκιμή',
        message: 'Εκτελείται εσωτερική προσομοίωση…',
        steps: [],
        real_actions_executed: false,
        auto_update_enabled: false
    });
    try {
        const response = await fetch(smartUpdatesTestPath('run'), {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify({ scenario })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Η ασφαλής δοκιμή απέτυχε.');
        renderSmartUpdatesTest(data.test);
        showToast('🧪 Η ασφαλής δοκιμή ολοκληρώθηκε.');
    } catch (error) {
        renderSmartUpdatesTest({
            status: 'critical',
            message: error.message,
            steps: [],
            real_actions_executed: false
        });
        showToast('❌ ' + error.message);
    }
}

function watchdogTestPath(suffix) {
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    return currentPath + 'api/watchdog_test/' + suffix;
}

function watchdogTestHeaders(includeJson = false) {
    const headers = { 'Authorization': 'Bearer ' + techSessionToken };
    if (includeJson) headers['Content-Type'] = 'application/json';
    return headers;
}

function watchdogTerminalStateKey(state) {
    return [state.test_id || '', state.status || '', state.finished_at || state.cancelled_at || '', state.request_code || ''].join('|');
}

async function acknowledgeWatchdogTerminalState() {
    if (!techSessionToken) return;
    try {
        await fetch(watchdogTestPath('ack'), {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify({})
        });
    } catch (error) {
        console.error('Watchdog test acknowledge failed', error);
    }
}

function holdWatchdogTerminalMessage(state) {
    const key = watchdogTerminalStateKey(state);
    if (!key || key === watchdogTerminalKey) return;
    watchdogTerminalKey = key;
    watchdogTerminalDisplayUntil = Date.now() + 10000;
    acknowledgeWatchdogTerminalState();
    if (watchdogTerminalResetTimer) clearTimeout(watchdogTerminalResetTimer);
    watchdogTerminalResetTimer = setTimeout(() => {
        watchdogTerminalDisplayUntil = 0;
        watchdogTerminalKey = '';
        watchdogTerminalResetTimer = null;
        renderWatchdogTestStatus({ status: 'idle', message: 'Δεν εκτελείται δοκιμή.' }, true);
    }, 10000);
}

function renderWatchdogTestStatus(test, force = false) {
    const box = document.getElementById('watchdogTestStatus');
    const startBtn = document.getElementById('watchdogTestStartBtn');
    const cancelBtn = document.getElementById('watchdogTestCancelBtn');
    if (!box) return;

    const state = test || { status: 'idle', message: 'Δεν εκτελείται δοκιμή.' };
    const terminal = ['completed', 'cancelled', 'failed', 'expired'].includes(state.status);
    const active = ['scheduled', 'running', 'request_created'].includes(state.status);
    if (!force && state.status === 'idle' && Date.now() < watchdogTerminalDisplayUntil) return;
    if (active && watchdogTerminalDisplayUntil) {
        if (watchdogTerminalResetTimer) clearTimeout(watchdogTerminalResetTimer);
        watchdogTerminalResetTimer = null;
        watchdogTerminalDisplayUntil = 0;
        watchdogTerminalKey = '';
    }

    lastWatchdogTestState = state;
    let extra = '';
    if ((state.status === 'scheduled' || state.status === 'running') && state.seconds_until_request > 0) {
        extra = ` Αίτημα σε περίπου ${state.seconds_until_request} δευτ.`;
    } else if (state.status === 'request_created' && state.seconds_until_clear > 0) {
        extra = ` Αυτόματος καθαρισμός σε περίπου ${state.seconds_until_clear} δευτ.`;
    }
    if (state.request_code) extra += ` Κωδικός: ${state.request_code}.`;
    if (state.email_sent === true) extra += ' Το δοκιμαστικό email στάλθηκε.';
    if (state.email_sent === false && state.email_message) extra += ` Το email δεν στάλθηκε: ${state.email_message}`;
    if (state.error) extra += ` Σφάλμα: ${state.error}`;

    box.textContent = (state.message || 'Δεν εκτελείται δοκιμή.') + extra;
    box.dataset.status = state.status || 'idle';
    if (startBtn) startBtn.disabled = active;
    if (cancelBtn) {
        cancelBtn.disabled = !active;
        cancelBtn.textContent = state.status === 'request_created'
            ? 'Καθαρισμός προσομοίωσης'
            : 'Ακύρωση δοκιμής';
    }
    if (terminal) holdWatchdogTerminalMessage(state);
}

async function loadWatchdogTestStatus() {
    if (!techSessionToken) return;
    try {
        const response = await fetch(watchdogTestPath('state') + '?_=' + Date.now(), {
            headers: watchdogTestHeaders(false),
            cache: 'no-store'
        });
        const data = await response.json();
        if (response.status === 401) {
            renderWatchdogTestStatus({ status: 'failed', message: 'Η τεχνική συνεδρία έληξε. Άνοιξε ξανά τον πίνακα με PIN.' });
            return;
        }
        if (!response.ok) throw new Error(data.message || 'Αποτυχία ανάγνωσης κατάστασης.');
        renderWatchdogTestStatus(data.test);
    } catch (e) {
        renderWatchdogTestStatus({
            status: 'failed',
            message: 'Δεν ήταν δυνατή η ανάγνωση της δοκιμής: ' + e.message
        });
    }
}

function closeWatchdogTestConfirm() {
    const modal = document.getElementById('watchdogTestConfirmModal');
    if (modal) modal.style.display = 'none';
    pendingWatchdogTestOptions = null;
}

function startWatchdogTest() {
    if (!techSessionToken) { showToast('Άνοιξε ξανά τον τεχνικό πίνακα με PIN.'); return; }
    const delay = Number(document.getElementById('ts_watchdog_test_delay')?.value || 10);
    const clearAfter = Number(document.getElementById('ts_watchdog_test_clear')?.value || 30);
    const deviceName = document.getElementById('ts_watchdog_test_device_name')?.value || 'Δοκιμαστική συσκευή Φρουρού';
    const sendEmail = document.getElementById('ts_watchdog_test_send_email')?.checked === true;

    pendingWatchdogTestOptions = {
        delay_seconds: delay,
        clear_seconds: clearAfter,
        device_name: deviceName,
        send_email: sendEmail
    };
    const details = document.getElementById('watchdogTestConfirmDetails');
    if (details) {
        details.textContent =
            `${deviceName}
` +
            `Δημιουργία αιτήματος μετά από ${delay} δευτ.
` +
            `Αυτόματος καθαρισμός ${clearAfter} δευτ. αργότερα.`;
    }
    const modal = document.getElementById('watchdogTestConfirmModal');
    if (modal) modal.style.display = 'flex';
}

async function confirmWatchdogTestStart() {
    if (!pendingWatchdogTestOptions) return;
    const options = { ...pendingWatchdogTestOptions };
    const modal = document.getElementById('watchdogTestConfirmModal');
    if (modal) modal.style.display = 'none';
    pendingWatchdogTestOptions = null;

    renderWatchdogTestStatus({ status: 'scheduled', message: 'Γίνεται έναρξη της ασφαλούς δοκιμής…' });
    try {
        const response = await fetch(watchdogTestPath('start'), {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify(options)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Η δοκιμή δεν ξεκίνησε.');
        renderWatchdogTestStatus(data.test);
        showToast('🧪 Η ασφαλής δοκιμή ξεκίνησε.');
    } catch (e) {
        renderWatchdogTestStatus({ status: 'failed', message: 'Η δοκιμή δεν ξεκίνησε: ' + e.message });
        showToast('❌ ' + e.message);
    }
}

async function cancelWatchdogTest() {
    if (!techSessionToken) return;
    const previousStatus = lastWatchdogTestState?.status || 'idle';
    renderWatchdogTestStatus({ status: 'running', message: 'Γίνεται καθαρισμός της προσομοίωσης…' });
    try {
        const response = await fetch(watchdogTestPath('cancel'), {
            method: 'POST',
            headers: watchdogTestHeaders(true),
            body: JSON.stringify({})
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Η δοκιμή δεν ακυρώθηκε.');
        const message = data.test?.action_message || data.test?.message || 'Η δοκιμή ακυρώθηκε.';
        renderWatchdogTestStatus({ ...data.test, message });
        showToast(previousStatus === 'request_created'
            ? 'Η προσομοίωση καθαρίστηκε. Το αίτημα παραμένει στο Portal.'
            : 'Η δοκιμή ακυρώθηκε πριν δημιουργηθεί αίτημα.');
    } catch (e) {
        renderWatchdogTestStatus({ status: 'failed', message: 'Η ακύρωση απέτυχε: ' + e.message });
        showToast('❌ ' + e.message);
    }
}

async function resolveRequest() {
    const base = currentPortalStatus && currentPortalStatus.portal_url ? currentPortalStatus.portal_url.replace(/\/$/, '') : 'https://smart-pro-system.gr';
    window.open(base + '/smart-pro-portal-preview/?spp_view=requests', '_blank');
    showToast('Η κατάσταση του αιτήματος διαχειρίζεται πλέον από το Smart Pro Portal.');
}

function addMaintenance() { const input = document.getElementById('maintenanceInput'); if(!input) return; const text = input.value.trim(); if (text === "") { showToast("Γράψτε σημείωση."); return; } addMainHistory(text); input.value = ''; showToast("Καταγράφηκε!"); }

function checkSubscriptionLockout() {
    if(!globalConfig) return;
    const lockoutScreen = document.getElementById('lockoutScreen');
    // 2.4.35: Portal-connected installations follow the central service-access
    // contract. Keep the legacy full-screen lockout hidden because pairing and
    // Managed enrollment remain available; individual subscription services are
    // gated in their own UI/runtime paths.
    if (currentPortalStatus) {
        if (lockoutScreen) lockoutScreen.style.display = 'none';
        return;
    }
    const plan = globalConfig.active_plan || 'smartcare'; const startDateStr = globalConfig.sub_start || new Date().toISOString().split('T')[0];
    const durationMonths = parseInt(globalConfig.sub_months || 12); const startDate = new Date(startDateStr); const endDate = new Date(startDate);
    endDate.setMonth(endDate.getMonth() + durationMonths); const diffDays = Math.ceil((endDate - new Date()) / (1000 * 60 * 60 * 24));
    const currentPath = window.location.pathname.endsWith('/') ? window.location.pathname : window.location.pathname + '/';
    if (diffDays <= 0) { if(lockoutScreen) lockoutScreen.style.display = 'flex'; fetch(currentPath + 'api/set_subscription_status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: false }) }).catch(e=>e); } 
    else { if(lockoutScreen) lockoutScreen.style.display = 'none'; fetch(currentPath + 'api/set_subscription_status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ active: true }) }).catch(e=>e); }
}

window.onload = async function() {
    const scanner = document.getElementById('scanner'); if(scanner) scanner.style.display = 'block';
    await loadPortalStatus();
    startPortalStatusPolling();
    
    await loadConfig();
    if(!globalConfig) globalConfig = {}; 
    
    checkSubscription(); checkSubscriptionLockout(); applyLogic(); renderHistory(); checkPendingRequest();
    
    let progress = 0; const fill = document.getElementById('progressFill'); const text = document.getElementById('scannerText');
    const messages = ["Έλεγχος Δικτύου...", "Ανάγνωση Αισθητήρων...", "Συγχρονισμός...", "Ολοκλήρωση..."];
    const interval = setInterval(() => {
        progress += 2; if(fill) fill.style.width = progress + '%';
        let msgIndex = Math.floor(progress / 25); if (msgIndex >= messages.length) msgIndex = messages.length - 1;
        if(text) text.innerText = messages[msgIndex] + " (" + progress + "%)";
        if(progress >= 100) {
            clearInterval(interval);
            setTimeout(() => {
                if(scanner) scanner.style.display = 'none';
                const sm = document.getElementById('statusMessage'); if(sm) sm.style.display = 'block';
                const md = document.getElementById('mainDashboard'); if(md) md.style.display = 'grid';
                const lg = document.getElementById('logsGrid'); if(lg) lg.style.display = 'grid';
                fetchRealHomeData(); setInterval(fetchRealHomeData, 10000);
                
                // Εκκίνηση του ασφαλούς ελέγχου για το Banner
                startMeshBannerPolling();
                
            }, 500);
        }
    }, 30);
};

function openModal() {
    if (!portalServiceAllowed('support_requests')) {
        showToast('Τα κανονικά αιτήματα υποστήριξης δεν είναι ενεργά για αυτή την εγκατάσταση.');
        return;
    }
    const portalOpen = portalManualOpenCount(currentPortalStatus);
    if (currentPortalStatus && currentPortalStatus.connected && portalOpen > 0) { showToast('Υπάρχει ήδη ενεργό αίτημα πελάτη στο Portal.'); return; }
    const reqTime = globalConfig ? (globalConfig.pending_request_time || 0) : 0;
    if ((!currentPortalStatus || !currentPortalStatus.connected) && reqTime > 0 && (Date.now() - reqTime < TIMEOUT_MS)) { showToast("Υπάρχει ήδη εκκρεμές αίτημα!"); return; }
    const sm = document.getElementById('supportModal'); if(sm) sm.style.display = 'flex';
    document.querySelectorAll('.checkbox-group input[type="checkbox"]').forEach(cb => cb.checked = false);
    const customIssueTxt = document.getElementById('customIssueText'); if (customIssueTxt) customIssueTxt.value = '';
    const plan = (globalConfig && globalConfig.active_plan) ? globalConfig.active_plan : 'smartcare';
    const handleLocks = (selector, txtId, originalText, requiresProOnly) => {
        const isPro = plan === 'businesspro'; const isPlus = plan === 'homeplus' || isPro;
        const isAllowed = requiresProOnly ? isPro : isPlus;
        const cb = document.querySelector(selector); const txt = document.getElementById(txtId);
        if (cb && txt) {
            if (!isAllowed) { txt.innerText = "🔒 " + originalText; cb.onclick = (e) => { e.preventDefault(); const alertModal = document.getElementById('customAlertModal'); if (alertModal) alertModal.style.display = 'flex'; }; } 
            else { txt.innerText = originalText; cb.onclick = null; }
        }
    };
    handleLocks('.opt-plus[value="Προσθήκη Συσκευής"]', 'txt_plus1', '➕ Προσθήκη νέας συσκευής', false);
    handleLocks('.opt-plus[value="Αλλαγή Σεναρίου"]', 'txt_plus2', '⚙️ Αλλαγή σε υπάρχον σενάριο', false);
    handleLocks('.opt-pro[value="Νέο Σενάριο"]', 'txt_pro1', '🚀 Δημιουργία πολύπλοκου σεναρίου', true);
    handleLocks('.opt-pro[value="Live Συνεδρία"]', 'txt_pro2', '👨‍💻 Live Απομακρυσμένη Συνεδρία', true);
}

function closeModal() { const sm = document.getElementById('supportModal'); if(sm) sm.style.display = 'none'; }

async function submitRequest() {
    const selected = Array.from(document.querySelectorAll('.checkbox-group input[type="checkbox"]:checked'));
    const selectedIssues = selected.map(cb => cb.value);
    const customIssueTxt = document.getElementById('customIssueText');
    const customText = customIssueTxt && customIssueTxt.value.trim() !== '' ? customIssueTxt.value.trim() : '';
    let finalMessage = selectedIssues.length > 0 ? selectedIssues.join(', ') : '';
    if (customText) finalMessage += (finalMessage ? ' | Σχόλιο: ' : '') + customText;
    if (!finalMessage) finalMessage = 'Γενικό αίτημα';

    const categoryMap = {
        'Πρόβλημα Δικτύου': 'network',
        'Βλάβη Συσκευής': 'device',
        'Σφάλμα Αυτοματισμού': 'automation',
        'Προσθήκη Συσκευής': 'add_device',
        'Αλλαγή Σεναρίου': 'modify_scene',
        'Νέο Σενάριο': 'new_scene',
        'Live Συνεδρία': 'live_session'
    };
    const category = selected.length > 0 ? (categoryMap[selected[0].value] || 'general') : 'general';
    const submitButton = document.getElementById('supportSubmitButton');
    if (submitButton) { submitButton.disabled = true; submitButton.textContent = 'Αποστολή...'; }

    try {
        const response = await fetch(portalCurrentPath() + 'api/portal_request', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ category, message: finalMessage, severity: 'normal' })
        });
        const rawResponse = await response.text();
        let data = {};
        try {
            data = rawResponse ? JSON.parse(rawResponse) : {};
        } catch (parseError) {
            const plainMessage = rawResponse
                .replace(/<[^>]*>/g, ' ')
                .replace(/&[^;]+;/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
            throw new Error(
                response.ok
                    ? 'Το Portal επέστρεψε μη έγκυρη απάντηση.'
                    : (plainMessage || `Σφάλμα Portal (${response.status}).`)
            );
        }
        if (!response.ok) throw new Error(data.message || `Το αίτημα δεν αποθηκεύτηκε (${response.status}).`);
        const requestData = data.request || {};
        await addReqHistory('req', `${requestData.code || 'Νέο αίτημα'} · ${finalMessage}`);
        if (globalConfig) {
            globalConfig.pending_request_time = Date.now();
            await saveConfig({ pending_request_time: globalConfig.pending_request_time });
        }
        currentPortalStatus = Object.assign({}, currentPortalStatus || {}, {
            connected: true,
            open_request_count: Number(data.open_request_count || 1),
            manual_open_request_count: Number(data.manual_open_request_count !== undefined ? data.manual_open_request_count : 1),
            automatic_alert_count: Number(data.automatic_alert_count || 0),
            latest_request: requestData
        });
        if (requestData && requestData.code) {
            portalRequestsCache = [requestData].concat(
                portalRequestsCache.filter(item => String(item.code || '') !== String(requestData.code || ''))
            );
        }
        updatePortalRequestUi(currentPortalStatus);
        renderHistory();
        closeModal();
        showToast(`✅ Δημιουργήθηκε το ${requestData.code || 'αίτημα'}`);
        window.setTimeout(loadPortalStatus, 1200);
    } catch (error) {
        showToast('❌ ' + error.message);
    } finally {
        if (submitButton) { submitButton.disabled = false; submitButton.textContent = 'Αποστολή'; }
    }
}

function checkPendingRequest() {
    if (currentPortalStatus && currentPortalStatus.connected) {
        updatePortalRequestUi(currentPortalStatus);
        reconcilePendingRequestFromPortal(currentPortalStatus);
        return;
    }
    if(!globalConfig) return;
    const requestTime = Number(globalConfig.pending_request_time || 0);
    if (requestTime > 0 && (Date.now() - requestTime < TIMEOUT_MS)) {
        setUIPending();
    } else if (requestTime > 0) {
        globalConfig.pending_request_time = 0;
        saveConfig({ pending_request_time: 0 });
        const btn = document.getElementById('supportBtn');
        if(btn) { btn.innerText = "👨‍🔧 Αίτημα Υποστήριξης"; btn.classList.remove('sent'); btn.style.pointerEvents = 'auto'; }
    }
}

function setUIPending() { 
    const btn = document.getElementById('supportBtn'); 
    if(btn) { btn.innerText = "⏳ Εκκρεμεί"; btn.classList.add('sent'); btn.style.pointerEvents = 'none'; } 
    const statusMsg = document.getElementById('statusMessage'); 
    if(statusMsg) {
        const activeRequest = portalActiveRequest();
        const label = activeRequest && activeRequest.code
            ? `${activeRequest.code}${activeRequest.status_label ? ' · ' + activeRequest.status_label : ''}`
            : 'Υπάρχει ενεργό αίτημα.';
        statusMsg.innerHTML = `⏳ ${escapeHtml(label)}`;
        statusMsg.classList.add('pending');
    } 
}
