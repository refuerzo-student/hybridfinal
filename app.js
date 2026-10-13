/**
 * HYBRID-RECOVER Application Controller (Enhanced)
 *
 * State management, role-based access control, Four-Eyes approval flow,
 * integrity verification, and audit logging — all client-side only.
 */

/* ================================================================
 * GLOBAL STATE
 * ================================================================ */

// Current signed-in user — tied to the Account Profile role switcher.
// In this prototype we simulate identity purely on the client.
let currentUser = {
    email: 'ralph.it_spec@corp.internal',
    role: 'RALPH',          // 'RALPH' | 'NICOLAS' | 'GABRIEL'
    displayName: 'Ralph (IT Specialist)'
};

// Pending Four-Eyes request created when Ralph selects a PRODUCTION target.
let pendingRequest = null;

// Approver identity captured at approval time (so later logging never
// misattributes the approval to whoever is signed in when the run finishes).
let lastApproval = null;

// Snapshot integrity model — re-evaluated whenever the exception switch toggles.
const snapshots = [
    { id: 'SNAP-2026-0911-01', timestamp: '2026-09-11 21:30:00 UTC', size: '42.8 GB', hash: 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef', verified: true },
    { id: 'SNAP-2026-0911-02', timestamp: '2026-09-11 22:45:00 UTC', size: '38.5 GB', hash: 'b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12', verified: false },
    { id: 'SNAP-2026-0911-03', timestamp: '2026-09-11 23:00:00 UTC', size: '41.2 GB', hash: 'c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234', verified: true }
];

// Integrity Exception Switch state.
let integrityException = {
    armed: false,
    reason: null,
    toggledBy: null,     // email of user who armed
    timestamp: null
};

// In-memory audit log (persisted to sessionStorage so it survives tab switches).
let auditLogs = [];

// Restore persisted state on script load.
(function restoreSession() {
    const saved = sessionStorage.getItem('hybridRecoverState');
    if (saved) {
        try {
            const v = JSON.parse(saved);
            if (v.currentUser) currentUser = v.currentUser;
            if (v.pendingRequest) pendingRequest = v.pendingRequest ?? null;
            if (Array.isArray(v.auditLogs)) auditLogs = v.auditLogs;
            if (v.integrityException) integrityException = {
                armed: v.integrityException.armed,
                reason: v.integrityException.reason,
                toggledBy: v.integrityException.toggledBy,
                timestamp: v.integrityException.timestamp
            };
        } catch { /* ignore corrupt data */ }
    }
})();

/* ================================================================
 * UTILITY HELPERS
 * ================================================================ */

function persistState() {
    sessionStorage.setItem('hybridRecoverState', JSON.stringify({
        currentUser,
        pendingRequest,
        auditLogs,
        integrityException
    }));
}

// Derive a log ID from a real timestamp: LOG-YYYYMMDD-NNN
function generateLogId(ts) {
    const d = new Date(ts);
    const ymd = d.getFullYear().toString() + String(d.getMonth() + 1).padStart(2, '0') + String(d.getDate()).padStart(2, '0');
    const seq = auditLogs.filter(e => e.id.startsWith('LOG-' + ymd + '-')).length + 1;
    return 'LOG-' + ymd + '-' + String(seq).padStart(3, '0');
}

// Simulated signature hash. No backend and no async crypto API here, so this
// is a deterministic 64-hex-character digest (the same shape as a SHA-256
// value) derived from the payload. Identical inputs always produce identical
// output, which is what the tamper-evidence demo relies on.
function generateSignatureHash(data) {
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    let h1 = 0x811c9dc5, h2 = 0x01000193, h3 = 0x9e3779b9;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
        h2 = Math.imul(h2 + c + i, 2246822519) >>> 0;
        h3 = Math.imul(h3 ^ (c * (i + 1)), 3266489917) >>> 0;
    }
    let out = '';
    let x = (h1 ^ h2 ^ h3) >>> 0;
    while (out.length < 64) {
        x = (Math.imul(x ^ (x >>> 15), 2246822519) + 374761393) >>> 0;
        out += (x >>> 0).toString(16).padStart(8, '0');
    }
    return out.slice(0, 64);
}

// Absolute wall-clock timestamp: "2026-10-11 10:09:53 UTC"
function absoluteTimestamp(ts) {
    return new Date(ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

// Optional human-readable label: "just now", "5 min ago", "2 hr ago" or ""
function relativeTimestampLabel(ts) {
    const diffMin = Math.floor((Date.now() - new Date(ts).getTime()) / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return diffMin + ' min ago';
    if (diffMin < 1440) return Math.floor(diffMin / 60) + ' hr ago';
    return '';
}

function formatTimestamp(ts) {
    const rel = relativeTimestampLabel(ts);
    return absoluteTimestamp(ts) + (rel ? ' (' + rel + ')' : '');
}

// Truncate hash for display: first 10 chars + ellipsis
function truncateHash(h) {
    return h.slice(0, 10) + '…';
}

/* ================================================================
 * AUDIT LOG
 * ================================================================ */

function addAuditLog(entry) {
    const ts = entry.timestamp || Date.now();
    const logEntry = {
        id: entry.id || generateLogId(ts),
        timestamp: ts,
        requester: entry.requester || '—',
        approver: entry.approver || '—',
        status: entry.status,
        signatureHash: entry.signatureHash || generateSignatureHash(entry),
        detail: entry.detail || null,
        _fullHash: entry.signatureHash   // kept for expand-to-full
    };
    auditLogs.unshift(logEntry);
    persistState();
    renderAuditLog();
}

function renderAuditLog() {
    const tbody = document.getElementById('auditLogBody');
    if (!tbody) return;

    if (auditLogs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="p-3 text-center text-slate-400">No audit entries yet.</td></tr>';
        return;
    }

    tbody.innerHTML = auditLogs.map(e => `
        <tr class="audit-row" data-id="${e.id}" data-fullhash="${e.signatureHash}">
            <td class="p-2.5 text-slate-600">${e.id}</td>
            <td class="p-2.5 text-slate-500 align-top">
                <span class="block whitespace-nowrap">${absoluteTimestamp(e.timestamp)}</span>
                <span class="block text-[10px] text-slate-400">${relativeTimestampLabel(e.timestamp)}</span>
            </td>
            <td class="p-2.5 text-slate-800 font-mono align-top truncate" title="${e.requester}">${e.requester}</td>
            <td class="p-2.5 text-slate-800 font-mono align-top truncate" title="${e.approver === '—' ? 'No approver on this entry' : e.approver}">${e.approver}</td>
            <td class="p-2.5 align-top">${statusBadge(e.status)}</td>
            <td class="p-2.5 text-slate-500 font-mono truncate cursor-pointer hover:text-slate-800 align-top" title="Click to show the full signature hash">${truncateHash(e.signatureHash)}</td>
        </tr>
    `).join('');

    // Re-attach click listener for hash expansion
    tbody.querySelectorAll('.audit-row').forEach(row => {
        row.addEventListener('click', function(ev) {
            const cell = ev.target.closest('td:last-child, td:nth-child(6)');
            if (cell && ev.target === cell) {
                const full = this.getAttribute('data-fullhash');
                showFullHashModal(this.getAttribute('data-id'), full);
            }
        });
    });
}

function statusBadge(status) {
    switch (status) {
        case 'APPROVED':
            return '<span class="text-emerald-700 font-bold">APPROVED</span>';
        case 'COMPLETED':
        case 'SUCCESS':
            return '<span class="text-emerald-700 font-bold">COMPLETED</span>';
        case 'REJECTED':
            return '<span class="text-red-700 font-bold">REJECTED</span>';
        case 'WITHDRAWN':
            return '<span class="text-slate-500 font-bold">WITHDRAWN</span>';
        case 'SELF-APPROVED / EXCEPTION':
            return '<span class="text-red-700 font-bold">SELF-APPROVED / EXCEPTION</span>';
        case 'REQUESTED':
            return '<span class="text-amber-700 font-bold">PENDING</span>';
        case 'FAILED':
            return '<span class="text-red-700 font-bold">FAILED</span>';
        case 'EXCEPTION_SWITCH':
            return '<span class="text-amber-700 font-bold">EXCEPTION</span>';
        default:
            return `<span class="text-slate-600 font-bold">${status}</span>`;
    }
}

function showFullHashModal(logId, fullHash) {
    let modal = document.getElementById('hashDetailModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'hashDetailModal';
        modal.className = 'fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4';
        modal.innerHTML = `
            <div class="bg-white rounded-lg max-w-lg w-full p-5 space-y-4 shadow-xl">
                <h4 class="text-sm font-bold text-slate-900">Signature Hash — <span id="hashLogId" class="font-mono text-xs text-slate-600"></span></h4>
                <div class="bg-slate-50 border border-slate-200 rounded p-3 font-mono text-xs text-slate-800 break-all select-all"></div>
                <div class="flex justify-end">
                    <button onclick="closeHashModal()" class="bg-slate-900 hover:bg-slate-800 text-white text-xs px-3 py-1.5 rounded font-medium">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    modal.querySelector('div.bg-slate-50').innerText = fullHash;
    modal.querySelector('#hashLogId').innerText = logId;
    modal.classList.remove('hidden');
}

// Declare closeHashModal at global scope
window.closeHashModal = function closeHashModal() {
    const modal = document.getElementById('hashDetailModal');
    if (modal) modal.classList.add('hidden');
};

/* ================================================================
 * ROLE-BASED ACCESS CONTROL
 * ================================================================ */

// Role definitions: who can do what
const ROLE_PERMISSIONS = {
    RALPH: { canRequest: true, canApprove: false, canToggleException: false, canConfigure: true, description: 'IT Specialist — can request recovery, configure nodes' },
    NICOLAS: { canRequest: false, canApprove: false, canToggleException: false, canConfigure: false, description: 'Help Desk Agent — view-only access' },
    GABRIEL: { canRequest: true, canApprove: true, canToggleException: true, canConfigure: true, description: 'Cloud Manager — full authorization and exception override' }
};

function switchRole(role) {
    const roleMap = {
        RALPH: { email: 'ralph.it_spec@corp.internal', role: 'RALPH', displayName: 'Ralph (IT Specialist)' },
        NICOLAS: { email: 'nicolas.helpdesk@corp.internal', role: 'NICOLAS', displayName: 'Nicolas (Help Desk Agent)' },
        GABRIEL: { email: 'gabriel.cloud_mgr@corp.internal', role: 'GABRIEL', displayName: 'Gabriel (Cloud Manager)' }
    };

    const info = roleMap[role];
    currentUser = info;

    // Update header display
    document.getElementById('currentUserDisplay').innerText = info.email;
    const roleBadge = document.getElementById('currentRoleBadge');
    const badgeText = info.displayName.match(/\(([^)]+)\)/)?.[1] || info.role;
    roleBadge.innerText = badgeText;

    persistState();
    renderRoleScopedBanner();
    applyRoleRestrictions();

    // Re-render approver button state to match new role
    renderApproveButton();
    // Re-render the snapshot table and integrity tiles with the live state
    renderSnapshotTable();
    updateIntegrityStatusBanner();
}

function renderRoleScopedBanner() {
    const banner = document.getElementById('roleScopedBanner');
    const bannerText = document.getElementById('roleScopedBannerText');
    const perms = ROLE_PERMISSIONS[currentUser.role];

    if (currentUser.role === 'NICOLAS') {
        banner.classList.remove('hidden');
        bannerText.innerHTML = '<strong>Help Desk Role Restricted:</strong> Read-only view. To configure or approve recovery, switch to an IT Specialist or Cloud Manager profile.';
    } else if (currentUser.role === 'GABRIEL') {
        banner.classList.remove('hidden');
        bannerText.innerHTML = '<strong>Cloud Manager Role Active:</strong> You can approve Four-Eyes requests and toggle the Integrity Exception Switch.';
    } else {
        banner.classList.add('hidden');
    }
}

// Plain-language explanation shown next to any control the signed-in role
// cannot use. Says who can do it and how to get access.
function restrictionReason(kind) {
    const u = currentUser;
    if (kind === 'request') {
        if (u.role === 'NICOLAS') {
            return 'Restricted: IT Specialists only. Help Desk agents can view recovery settings but cannot start one. Ask an IT Specialist (ralph.it_spec@corp.internal) to configure it, or request access from your Cloud Manager.';
        }
        return '';
    }
    return '';
}

function applyRoleRestrictions() {
    const perms = ROLE_PERMISSIONS[currentUser.role];
    const requestReason = restrictionReason('request');

    document.querySelectorAll('.action-btn').forEach(b => {
        const restricted = !perms.canRequest;
        b.classList.toggle('disabled-action', restricted);
        if (restricted) {
            b.setAttribute('disabled', 'true');
            b.setAttribute('aria-disabled', 'true');
            if (requestReason) b.title = requestReason;
        } else {
            b.removeAttribute('disabled');
            b.setAttribute('aria-disabled', 'false');
            b.removeAttribute('title');
        }
    });

    // Inline explanation (a disabled button cannot show a tooltip in some
    // browsers, so the text is also written out in the page).
    document.querySelectorAll('.restriction-note[data-restriction-for="request"]').forEach(note => {
        note.textContent = requestReason;
        note.classList.toggle('hidden', !requestReason);
    });

    // Show/hide exception switch
    updateExceptionSwitchDisplay();

    // Update approvals section visibility
    renderApproveButton();
}

/* ================================================================
 * DASHBOARD: NODE CARD BUTTONS
 * ================================================================ */

// Dashboard "Configure Recovery" quick action: pick the node, then jump to
// the configurator with the matching target pre-selected.
function quickSelectAndRecover(dbName) {
    const select = document.getElementById('targetDestination');
    if (select) {
        select.value = (dbName === 'DB-PAYMENTS-AWS') ? 'PROD_LIVE' : 'STAGING';
    }

    switchTab('recovery', document.querySelectorAll('.nav-btn')[1]);
    updateTargetSafetyUI();
}

/* ================================================================
 * RECOVERY CONFIGURATOR
 * ================================================================ */

function updateTargetSafetyUI() {
    const dest = document.getElementById('targetDestination').value;
    const warning = document.getElementById('targetSafetyWarning');

    if (dest === 'PROD_LIVE') {
        warning.innerHTML = 'Overwriting live PRODUCTION databases requires Four-Eyes authorization approval from a Cloud Manager who is not the requester.';
        warning.className = 'text-xs text-amber-800 bg-amber-50/60 border border-amber-200/80 p-3 rounded font-serif italic';
    } else {
        warning.innerHTML = 'Non-Production target selected. Automatic execution enabled.';
        warning.className = 'text-xs text-slate-700 bg-slate-50/60 border border-slate-200/80 p-3 rounded font-serif italic';
    }

    updateIntegrityStatusBanner();
}

// Snapshot integrity verification — re-evaluated every time it is called so
// the UI can never show a stale "SHA-256 Validated" after a state change.
//
//  - armed           : emergency override. Selection is allowed (that is the
//                      whole point of an exception) but the display warns that
//                      integrity is not guaranteed, and the run is logged as
//                      SELF-APPROVED / EXCEPTION.
//  - not armed + ok  : verified, selection allowed.
//  - not armed + bad : blocked, with a plain-language reason.
function getSnapshotIntegrityStatus(snapshot) {
    if (integrityException.armed) {
        return {
            verified: false,
            selectable: true,
            label: 'Verification bypassed — integrity not guaranteed',
            color: 'text-amber-700 font-bold',
            reason: 'Integrity verification is bypassed — any run now is recorded as SELF-APPROVED / EXCEPTION.'
        };
    }
    if (snapshot.verified) {
        return { verified: true, selectable: true, label: 'SHA-256 Validated', color: 'text-emerald-700 font-bold', reason: '' };
    }
    return {
        verified: false,
        selectable: false,
        label: 'Checksum mismatch — not verified',
        color: 'text-red-700 font-bold',
        reason: 'This snapshot failed its SHA-256 checksum check, so it cannot be selected. Choose a verified checkpoint, or ask your Cloud Manager to arm the Integrity Exception Switch.'
    };
}

// Currently highlighted snapshot in the configurator.
let selectedSnapshotId = 'SNAP-2026-0911-01';

function renderSnapshotTable() {
    const tbody = document.getElementById('snapshotTableBody');
    if (!tbody) return;

    // Drop a selection that is no longer allowed.
    const current = snapshots.find(s => s.id === selectedSnapshotId);
    if (!current || !getSnapshotIntegrityStatus(current).selectable) {
        const fallback = snapshots.find(s => getSnapshotIntegrityStatus(s).selectable);
        selectedSnapshotId = fallback ? fallback.id : null;
    }

    tbody.innerHTML = snapshots.map(snap => {
        const status = getSnapshotIntegrityStatus(snap);
        const checked = snap.id === selectedSnapshotId;
        const selectCell = status.selectable
            ? `<input type="radio" name="snapshot" value="${snap.id}" ${checked ? 'checked' : ''} class="accent-slate-900" onchange="onSnapshotSelected('${snap.id}')" aria-label="Select ${snap.id}">`
            : `<span class="text-slate-400" aria-disabled="true" title="${status.reason}">—</span>`;

        const note = status.reason
            ? `<span class="block text-[10px] font-sans font-normal mt-0.5 ${status.selectable ? 'text-amber-700' : 'text-red-600'}">${status.reason}</span>`
            : '';

        return `
            <tr>
                <td class="p-2.5 align-top">${selectCell}${note}</td>
                <td class="p-2.5 text-slate-900 font-bold align-top">${snap.id}</td>
                <td class="p-2.5 text-slate-600 whitespace-nowrap align-top">${snap.timestamp}</td>
                <td class="p-2.5 text-slate-600 align-top">${snap.size}</td>
                <td class="p-2.5 font-semibold ${status.color} align-top">${status.label}</td>
            </tr>
        `;
    }).join('');
}

function onSnapshotSelected(id) {
    selectedSnapshotId = id;
}

// Re-verify integrity on configurator load
function onConfiguratorLoad() {
    renderSnapshotTable();
    updateExceptionSwitchDisplay();
    updateIntegrityStatusBanner();
}

// Re-verify right before the "Initiate Automated Recovery" confirmation.
function preInitiateVerification() {
    renderSnapshotTable();               // re-check + re-render first
    updateIntegrityStatusBanner();

    const snap = snapshots.find(s => s.id === selectedSnapshotId);
    if (!snap) {
        alert('No snapshot is selectable right now. If the Integrity Exception Switch is armed, disarm it to restore verification, or ask your Cloud Manager for an approved exception.');
        return false;
    }

    const status = getSnapshotIntegrityStatus(snap);
    if (!status.selectable) {
        alert(`This snapshot cannot be used: ${status.reason}`);
        return false;
    }

    return true;
}

/* ================================================================
 * TRIGGER RECOVERY — creates the Four-Eyes request
 * ================================================================ */

function triggerRecoveryProcess() {
    // Runtime enforcement — Help Desk agents cannot create requests.
    if (!ROLE_PERMISSIONS[currentUser.role].canRequest) {
        alert(`Restricted: IT Specialists only. You are signed in as ${currentUser.displayName} and cannot start a recovery. Request access from your Cloud Manager.`);
        return;
    }

    // Re-verify snapshot integrity immediately before the confirmation (F-03).
    if (!preInitiateVerification()) return;

    const dest = document.getElementById('targetDestination').value;
    const snapshotId = selectedSnapshotId;
    const direction = document.getElementById('recoveryDirection').value;
    const targetLabel = dest === 'PROD_LIVE'
        ? 'DB-PAYMENTS-AWS (PRODUCTION)'
        : 'DB-STAGE-LOCAL (STAGING)';

    // Plain-language confirmation of what is about to happen.
    const confirmed = confirm(
        (dest === 'PROD_LIVE'
            ? 'Initiate Automated Recovery?\n\nThis targets a LIVE PRODUCTION database and will create a Four-Eyes authorization request that a second Cloud Manager must approve before anything runs.'
            : 'Initiate Automated Recovery?\n\nThis targets a non-production STAGING instance and the pipeline will run immediately without Four-Eyes approval.') +
        `\n\nSnapshot: ${snapshotId}\nDirection: ${direction}\nTarget: ${targetLabel}`
    );
    if (!confirmed) return;

    if (dest === 'PROD_LIVE') {
        // Create the Four-Eyes request record with requester identity
        lastApproval = null;   // reset so a stale approver is never carried over
        const reqSeq = String(Date.now() % 100000).padStart(5, '0');
        pendingRequest = {
            id: 'REQ-' + reqSeq + '-FOUR-EYES',
            requester: currentUser.email,
            requesterRole: currentUser.role,
            requesterDisplayName: currentUser.displayName,
            target: targetLabel,
            targetEnv: dest,
            snapshotId: snapshotId,
            direction: direction,
            timestamp: Date.now(),
            payloadHash: truncateHash(generateSignatureHash({ snapshotId, direction, target: dest }))
        };

        persistState();

        // Log the request creation
        addAuditLog({
            timestamp: pendingRequest.timestamp,
            requester: pendingRequest.requester,
            approver: '—',
            status: 'REQUESTED',
            signatureHash: generateSignatureHash(pendingRequest),
            detail: 'Four-Eyes recovery request created for PRODUCTION target'
        });

        renderApprovalsQueue();
        switchTab('approvals', document.querySelectorAll('.nav-btn')[2]);
    } else {
        // Non-production: no approval is required, so no approver may be
        // carried over from an earlier request.
        lastApproval = null;
        runAutomatedExecution();
    }
}

/* ================================================================
 * FOUR-EYES APPROVAL QUEUE
 * ================================================================ */

function renderApprovalsQueue() {
    const queueDiv = document.getElementById('approvalsContainer');
    if (!queueDiv) return;

    if (!pendingRequest) {
        queueDiv.innerHTML = `
            <div class="bg-white border border-slate-200/80 rounded p-6 text-center text-slate-400 text-xs">
                No pending Four-Eyes authorization requests.
            </div>
        `;
        return;
    }

    const perms = ROLE_PERMISSIONS[currentUser.role];
    const isRequester = currentUser.email === pendingRequest.requester;
    const canApprove = perms.canApprove && !isRequester;

    queueDiv.innerHTML = `
        <div class="bg-white border border-slate-200/80 rounded p-6 space-y-5">
            <div class="border-b border-slate-100 pb-3">
                <h3 class="text-base font-bold text-slate-900">Four-Eyes Authorization Required</h3>
                <p class="text-xs text-slate-500 mt-0.5">High-risk recovery requests require secondary authorization from a Cloud Manager.</p>
            </div>

            <div class="bg-[#FAF9F6] border border-slate-200 rounded p-4 text-xs space-y-2 font-mono">
                <div class="flex justify-between"><span class="text-slate-400">Request ID:</span> <span class="text-slate-800 font-bold">${pendingRequest.id}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Requester:</span> <span class="text-slate-800 text-right">${pendingRequest.requester} <span class="text-slate-500">(${pendingRequest.requesterDisplayName})</span></span></div>
                <div class="flex justify-between"><span class="text-slate-400">Your Role:</span> <span class="text-slate-800 font-bold">${currentUser.displayName}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Request Status:</span> <span class="${isRequester ? 'text-amber-700' : 'text-slate-800'} font-bold">${isRequester ? 'Awaiting second approver' : 'Awaiting your approval'}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Target Environment:</span> <span class="text-slate-900 font-bold">${pendingRequest.target}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Snapshot:</span> <span class="text-slate-700">${pendingRequest.snapshotId}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Payload Hash:</span> <span class="text-slate-600">${pendingRequest.payloadHash}</span></div>
                <div class="flex justify-between"><span class="text-slate-400">Submitted:</span> <span class="text-slate-500">${formatTimestamp(pendingRequest.timestamp)}</span></div>
            </div>

            ${!canApprove ? `
            <div class="bg-amber-50/70 border border-amber-200/80 text-amber-800 p-3 rounded text-xs flex items-start gap-2">
                <i class="fa-solid fa-lock text-amber-600 mt-0.5"></i>
                <span>${isRequester
                    ? 'You cannot approve your own request — awaiting a second authorized approver. Switch to a Cloud Manager account to approve.'
                    : 'Only a Cloud Manager can approve recovery requests. You are signed in as ' + currentUser.displayName + '.'}</span>
            </div>` : ''}

            <div class="flex justify-end space-x-2">
                <button onclick="rejectFourEyesRequest()" ${canApprove || isRequester ? '' : 'disabled aria-disabled="true"'} class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs px-4 py-2 rounded font-medium transition-all ${canApprove || isRequester ? '' : 'disabled-action'}" ${canApprove || isRequester ? '' : 'title="Restricted: only the requester or a Cloud Manager can act on this request."'}>
                    ${isRequester ? 'Withdraw Request' : 'Reject Action'}
                </button>
                <button id="approveBtn" onclick="approveFourEyesRequest()" class="text-xs px-4 py-2 rounded font-medium transition-all">
                    ${renderApproveButtonLabel(canApprove, isRequester, perms)}
                </button>
            </div>
        </div>
    `;

    // Apply the correct disabled/label state to the freshly rendered approve button.
    renderApproveButton();
}

function renderApproveButtonLabel(canApprove, isRequester, perms) {
    if (isRequester) {
        return 'You cannot approve your own request — awaiting a second authorized approver.';
    }
    if (!perms.canApprove) {
        return 'Restricted: Cloud Manager approval required.';
    }
    return `Approve as ${currentUser.displayName}`;
}

function renderApproveButton() {
    const btn = document.getElementById('approveBtn');
    if (!btn) return;

    if (!pendingRequest) return;

    const perms = ROLE_PERMISSIONS[currentUser.role];
    const isRequester = currentUser.email === pendingRequest.requester;
    const canApprove = perms.canApprove && !isRequester;

    btn.classList.add('text-right', 'whitespace-normal', 'leading-snug');

    if (!canApprove) {
        const msg = isRequester
            ? 'You cannot approve your own request — awaiting a second authorized approver.'
            : 'Restricted: only a Cloud Manager can approve. Switch profiles in Account Profile (bottom of the sidebar).';
        btn.disabled = true;
        btn.setAttribute('aria-disabled', 'true');
        btn.classList.add('bg-slate-200', 'text-slate-500', 'cursor-not-allowed');
        btn.classList.remove('bg-slate-900', 'hover:bg-slate-800', 'text-white', 'bg-slate-300', 'text-slate-600');
        btn.innerText = isRequester
            ? 'You cannot approve your own request — awaiting a second authorized approver.'
            : 'Restricted: Cloud Manager approval required.';
        btn.title = msg;
    } else {
        btn.disabled = false;
        btn.setAttribute('aria-disabled', 'false');
        btn.classList.remove('bg-slate-200', 'text-slate-500', 'cursor-not-allowed', 'bg-slate-300', 'text-slate-600');
        btn.classList.add('bg-slate-900', 'hover:bg-slate-800', 'text-white');
        btn.innerText = `Approve as ${currentUser.displayName}`;
        btn.title = `Approve request ${pendingRequest.id} as ${currentUser.displayName} (${currentUser.email})`;
    }
}

/* ================================================================
 * APPROVAL HANDLER — with runtime enforcement
 * ================================================================ */

function approveFourEyesRequest() {
    if (!pendingRequest) {
        alert('No pending request found.');
        return false;
    }

    const perms = ROLE_PERMISSIONS[currentUser.role];
    const isRequester = currentUser.email === pendingRequest.requester;

    // Runtime enforcement — cannot be bypassed via DevTools
    if (isRequester) {
        addAuditLog({
            timestamp: Date.now(),
            requester: pendingRequest.requester,
            approver: '—',
            status: 'SELF-APPROVED / EXCEPTION',
            signatureHash: generateSignatureHash({ event: 'self_approval_attempt', by: currentUser.email }),
            detail: 'Self-approval attempt blocked — requester cannot approve own request'
        });
        alert('You cannot approve your own request. Please switch to a Cloud Manager account to provide the secondary authorization.');
        return false;
    }

    if (!perms.canApprove) {
        addAuditLog({
            timestamp: Date.now(),
            requester: pendingRequest.requester,
            approver: '—',   // no approval occurred
            status: 'REJECTED',
            signatureHash: generateSignatureHash({ event: 'unauthorized_approval_attempt', by: currentUser.email }),
            detail: `${currentUser.displayName} (${currentUser.email}) attempted to approve without Cloud Manager privileges — blocked`
        });
        alert(`Only a Cloud Manager can approve Four-Eyes requests. You are signed in as ${currentUser.displayName}. Please switch profiles in Account Profile (bottom of the sidebar).`);
        return false;
    }

    // Approved — record the actually authenticated approver for the audit trail.
    lastApproval = {
        approverEmail: currentUser.email,
        approverRole: currentUser.role,
        approverDisplayName: currentUser.displayName,
        approvedAt: Date.now(),
        requestId: pendingRequest.id
    };
    pendingRequest.approvedBy = currentUser.email;
    persistState();

    if (integrityException.armed) {
        // Exception path: integrity verification is bypassed, so the run that
        // follows is classified as SELF-APPROVED / EXCEPTION. Do not attribute
        // an approver on an exception entry — log the action without a name.
        addAuditLog({
            timestamp: lastApproval.approvedAt,
            requester: pendingRequest.requester,
            approver: '—',
            status: 'SELF-APPROVED / EXCEPTION',
            signatureHash: generateSignatureHash({ ...pendingRequest, exception: true }),
            detail: 'Approval submitted while the Integrity Exception Switch was armed — recorded on the exception path, no approver attributed. See the exception switch entry for who armed it and why.'
        });
    } else {
        addAuditLog({
            timestamp: lastApproval.approvedAt,
            requester: pendingRequest.requester,
            approver: currentUser.email,   // The actually authenticated approver
            status: 'APPROVED',
            signatureHash: generateSignatureHash({ ...pendingRequest, approver: currentUser.email }),
            detail: `Four-Eyes request approved by ${currentUser.displayName}`
        });
    }

    runAutomatedExecution();
    return true;
}

function rejectFourEyesRequest() {
    if (!pendingRequest) {
        alert('No pending request found.');
        return;
    }

    // Runtime enforcement — mirrors the disabled state on the button.
    const isRequester = currentUser.email === pendingRequest.requester;
    const canAct = isRequester || (ROLE_PERMISSIONS[currentUser.role].canApprove && !isRequester);
    if (!canAct) {
        alert(`Restricted: only the requester or a Cloud Manager can act on this request. You are signed in as ${currentUser.displayName}.`);
        return;
    }

    addAuditLog({
        timestamp: Date.now(),
        requester: pendingRequest.requester,
        approver: isRequester ? '—' : currentUser.email,
        status: isRequester ? 'WITHDRAWN' : 'REJECTED',
        signatureHash: generateSignatureHash({ event: 'rejected', by: currentUser.email }),
        detail: `${isRequester ? 'Request withdrawn by requester' : 'Request rejected by'} ${currentUser.displayName}`
    });

    pendingRequest = null;
    persistState();
    alert('Action Aborted: Four-Eyes authorization request declined.');
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active-nav'));
    document.querySelectorAll('.nav-btn')[0].classList.add('active-nav');
    switchTab('dashboard', document.querySelectorAll('.nav-btn')[0]);
}

/* ================================================================
 * INTEGRITY EXCEPTION SWITCH
 * ================================================================ */

function updateExceptionSwitchDisplay() {
    const switchContainer = document.getElementById('exceptionSwitchContainer');
    const switchCheckbox = document.getElementById('simulateIntegrityFailure');
    const hint = document.getElementById('exceptionSwitchHint');

    if (!switchContainer || !switchCheckbox) return;

    const perms = ROLE_PERMISSIONS[currentUser.role];
    const restrictedMsg = `Restricted: Cloud Managers only. You are signed in as ${currentUser.displayName}. The Integrity Exception Switch bypasses integrity verification, so it requires the Cloud Manager role plus a written reason. Ask Gabriel (gabriel.cloud_mgr@corp.internal) to arm it.`;

    if (!perms.canToggleException) {
        switchCheckbox.disabled = true;
        switchCheckbox.setAttribute('aria-disabled', 'true');
        switchContainer.setAttribute('data-restricted', 'true');
        switchContainer.title = restrictedMsg;
        switchContainer.classList.add('opacity-50', 'cursor-not-allowed');
        switchContainer.classList.remove('cursor-pointer');
        if (hint) {
            hint.innerText = 'Restricted';
            hint.title = restrictedMsg;
            hint.classList.add('text-amber-600', 'font-semibold');
        }
    } else {
        switchCheckbox.disabled = false;
        switchCheckbox.setAttribute('aria-disabled', 'false');
        switchContainer.setAttribute('data-restricted', 'false');
        switchContainer.classList.remove('opacity-50', 'cursor-not-allowed');
        switchContainer.classList.add('cursor-pointer');
        switchContainer.title = 'Arm or disarm the Integrity Exception Switch. A confirmation dialog with a required reason is shown, and every toggle is written to the audit log.';
        if (hint) {
            hint.innerText = integrityException.armed ? 'Armed' : 'Off';
            hint.title = switchContainer.title;
            hint.classList.toggle('text-amber-600', integrityException.armed);
            hint.classList.toggle('font-semibold', integrityException.armed);
        }

        // Reflect the armed state
        switchCheckbox.checked = integrityException.armed;
    }
}

function confirmExceptionToggle() {
    const checkbox = document.getElementById('simulateIntegrityFailure');

    // Runtime enforcement — checks state, not just the DOM attribute.
    if (!ROLE_PERMISSIONS[currentUser.role].canToggleException) {
        if (checkbox) checkbox.checked = integrityException.armed;
        alert('Restricted: only a Cloud Manager can toggle the Integrity Exception Switch. You are signed in as ' + currentUser.displayName + '.');
        return;
    }

    if (checkbox.checked) {
        // Attempting to arm — show confirmation dialog
        showExceptionDialog();
    } else {
        // Un-arming — just record it
        const prevArmed = integrityException.armed;
        integrityException = { armed: false, reason: null, toggledBy: currentUser.email, timestamp: Date.now() };
        persistState();

        addAuditLog({
            timestamp: Date.now(),
            requester: currentUser.email,
            approver: '—',
            status: 'EXCEPTION_SWITCH',
            signatureHash: generateSignatureHash({ event: 'exception_switch_unarmed', by: currentUser.email }),
            detail: `${currentUser.displayName} disarmed the Integrity Exception Switch`
        });

        renderSnapshotTable();
        updateIntegrityStatusBanner();
        updateExceptionSwitchDisplay();
    }
}

function showExceptionDialog() {
    let dialog = document.getElementById('exceptionDialog');
    if (!dialog) {
        dialog = document.createElement('div');
        dialog.id = 'exceptionDialog';
        dialog.className = 'fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4';
        dialog.innerHTML = `
            <div class="bg-white rounded-lg max-w-lg w-full p-5 space-y-4 shadow-xl">
                <h4 class="text-sm font-bold text-slate-900">Integrity Exception Switch — Confirmation Required</h4>
                <div class="bg-red-50 border border-red-200 rounded p-3 text-xs text-red-800 space-y-1">
                    <div class="font-bold">⚠ Warning</div>
                    <div>This switch should only be used when the primary SHA-256 verification path is unavailable and business continuity requires immediate recovery.</div>
                    <div>Using this switch bypasses all integrity checks. The recovered payload may be tampered with or corrupted.</div>
                </div>
                <div class="space-y-1.5">
                    <label for="exceptionReason" class="text-[11px] font-bold text-slate-600 uppercase tracking-wider font-mono">Reason for Use <span class="text-red-600">*</span></label>
                    <textarea id="exceptionReason" rows="3" class="w-full bg-white border border-slate-200 rounded p-2 text-xs text-slate-800 focus:outline-none focus:border-slate-400 resize-y" placeholder="Describe why integrity verification cannot be performed..."></textarea>
                </div>
                <div class="flex justify-end space-x-2 pt-2">
                    <button onclick="cancelExceptionToggle()" class="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 text-xs px-4 py-2 rounded font-medium transition-all">Cancel</button>
                    <button onclick="armExceptionSwitch()" class="bg-red-700 hover:bg-red-800 text-white text-xs px-4 py-2 rounded font-medium transition-all">Arm Exception Switch</button>
                </div>
            </div>
        `;
        document.body.appendChild(dialog);
    }
    dialog.classList.remove('hidden');
    document.getElementById('exceptionReason').focus();
}

window.cancelExceptionToggle = function cancelExceptionToggle() {
    const checkbox = document.getElementById('simulateIntegrityFailure');
    checkbox.checked = false;  // Reset the checkbox
    const dialog = document.getElementById('exceptionDialog');
    if (dialog) dialog.classList.add('hidden');
};

window.armExceptionSwitch = function armExceptionSwitch() {
    // Runtime enforcement inside the handler itself.
    if (!ROLE_PERMISSIONS[currentUser.role].canToggleException) {
        alert('Restricted: only a Cloud Manager can arm the Integrity Exception Switch. You are signed in as ' + currentUser.displayName + '.');
        return;
    }

    const reason = document.getElementById('exceptionReason').value.trim();
    if (!reason) {
        alert('A reason is required to arm the Integrity Exception Switch.');
        return;
    }

    integrityException = {
        armed: true,
        reason: reason,
        toggledBy: currentUser.email,
        timestamp: Date.now()
    };

    persistState();

    // Close dialog
    const dialog = document.getElementById('exceptionDialog');
    if (dialog) dialog.classList.add('hidden');

    // Log the toggle
    addAuditLog({
        timestamp: integrityException.timestamp,
        requester: currentUser.email,
        approver: '—',
        status: 'EXCEPTION_SWITCH',
        signatureHash: generateSignatureHash(integrityException),
        detail: `${currentUser.displayName} armed Integrity Exception Switch: "${reason}"`
    });

    // Re-verify snapshots
    renderSnapshotTable();
    updateIntegrityStatusBanner();
    updateExceptionSwitchDisplay();
};

// Keep the dashboard node-card integrity tiles in sync with the live state.
function updateDashboardIntegrity() {
    const armed = integrityException.armed;
    ['integrityAWS', 'integrityStage'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (armed) {
            el.innerText = 'Bypassed';
            el.className = 'text-amber-700 font-semibold';
        } else {
            el.innerText = 'Valid';
            el.className = 'text-emerald-700 font-semibold';
        }
    });
}

function updateIntegrityStatusBanner() {
    const banner = document.getElementById('integrityStatusBanner');
    updateDashboardIntegrity();
    if (!banner) return;

    if (integrityException.armed) {
        const snap = snapshots.find(s => s.id === selectedSnapshotId) || snapshots[0];
        const status = getSnapshotIntegrityStatus(snap);
        banner.innerHTML = `
            <div class="flex items-start gap-2">
                <i class="fa-solid fa-triangle-exclamation text-amber-600 text-sm mt-0.5"></i>
                <div>
                    <strong>${status.label}</strong>
                    <div class="mt-1">Integrity verification is bypassed, so the restored data is not guaranteed to match the vault copy. Only use this during an approved exception — any run started now is recorded as SELF-APPROVED / EXCEPTION.</div>
                    <div class="mt-1 text-[11px]">Armed by ${integrityException.toggledBy} at ${formatTimestamp(integrityException.timestamp)}${integrityException.reason ? '. Reason: "' + integrityException.reason + '"' : ''}</div>
                </div>
            </div>
        `;
        banner.className = 'bg-amber-50 border border-amber-300 text-amber-900 p-3 rounded text-xs';
        banner.classList.remove('hidden');
    } else {
        banner.className = 'hidden';
        banner.classList.add('hidden');
    }
}

/* ================================================================
 * PIPELINE MODAL
 * ================================================================ */

function closeExecutionOverlay() {
    document.getElementById('executionOverlay').classList.add('hidden');
    switchTab('recovery', document.querySelectorAll('.nav-btn')[1]);
}

// Pipeline status enum — never allow EXECUTING + STOPPED simultaneously
let pipelineState = 'IDLE'; // 'IDLE' | 'EXECUTING' | 'STOPPED' | 'COMPLETED'

// Log the outcome of a pipeline run. The approver comes from the approval
// record (lastApproval), never from whoever happens to be signed in now.
function logPipelineOutcome(outcome) {
    const requester = pendingRequest
        ? pendingRequest.requester
        : currentUser.email;

    // Emergency/self-approved path: integrity verification was bypassed.
    if (integrityException.armed) {
        addAuditLog({
            timestamp: Date.now(),
            requester: requester,
            approver: '—',   // never name another person on an exception path
            status: 'SELF-APPROVED / EXCEPTION',
            signatureHash: generateSignatureHash({ event: 'pipeline', outcome, requester, exception: true }),
            detail: `${outcome} — integrity verification bypassed because the Integrity Exception Switch was armed. See the exception switch entry for who armed it and why.`
        });
        lastApproval = null;   // one approval authorises exactly one run
        return;
    }

    // Normal path: record the approver authenticated at approval time, or "—".
    const approver = lastApproval ? lastApproval.approverEmail : '—';
    addAuditLog({
        timestamp: Date.now(),
        requester: requester,
        approver: approver,
        status: outcome,
        signatureHash: generateSignatureHash({ event: 'pipeline', outcome, requester, approver }),
        detail: lastApproval
            ? `${outcome} — Four-Eyes approved by ${lastApproval.approverDisplayName}`
            : `${outcome} — non-production target, no approval required`
    });
    lastApproval = null;       // never leak an approver into a later run
}

function runAutomatedExecution() {
    const overlay = document.getElementById('executionOverlay');
    const isFailureSimulated = integrityException.armed;

    overlay.classList.remove('hidden');
    document.getElementById('exceptionAlert').classList.add('hidden');

    pipelineState = 'EXECUTING';

    // Step States — reset all
    document.getElementById('badgeStep1').innerText = "Processing...";
    document.getElementById('badgeStep1').className = "text-slate-600 font-bold";

    document.getElementById('badgeStep2').innerText = "Pending";
    document.getElementById('badgeStep2').className = "text-slate-400";

    document.getElementById('badgeStep3').innerText = "Pending";
    document.getElementById('badgeStep3').className = "text-slate-400";

    // Header badge — always consistent with state
    updatePipelineBadge();

    // Step 1: KMS Retrieval
    setTimeout(() => {
        if (pipelineState === 'STOPPED') return;

        document.getElementById('badgeStep1').innerText = "Done";
        document.getElementById('badgeStep1').className = "text-emerald-700 font-bold";

        document.getElementById('badgeStep2').innerText = "Verifying Hash...";
        document.getElementById('badgeStep2').className = "text-slate-600 font-bold";

        // Step 2: Integrity Verification
        setTimeout(() => {
            if (pipelineState === 'STOPPED') return;

            if (isFailureSimulated) {
                // Failure path — consistent STOPPED state
                pipelineState = 'STOPPED';

                document.getElementById('badgeStep2').innerText = "FAILED";
                document.getElementById('badgeStep2').className = "text-red-700 font-bold";

                // Step 3 marked as "Not run" — never "Pending"
                document.getElementById('badgeStep3').innerText = "Not run";
                document.getElementById('badgeStep3').className = "text-slate-400 italic";

                updatePipelineBadge();

                document.getElementById('exceptionAlert').classList.remove('hidden');
                document.getElementById('exceptionMessage').innerText = "Checksum mismatch detected during Step 2 validation. Payload signature does not match vault registry key. Recovery halted automatically.";

                logPipelineOutcome('FAILED');
            } else {
                // Success path
                document.getElementById('badgeStep2').innerText = "Done";
                document.getElementById('badgeStep2').className = "text-emerald-700 font-bold";

                document.getElementById('badgeStep3').innerText = "Mounting...";
                document.getElementById('badgeStep3').className = "text-slate-600 font-bold";

                // Step 3: Target Restore
                setTimeout(() => {
                    if (pipelineState === 'STOPPED') return;

                    document.getElementById('badgeStep3').innerText = "Done";
                    document.getElementById('badgeStep3').className = "text-emerald-700 font-bold";

                    pipelineState = 'COMPLETED';
                    updatePipelineBadge();

                    logPipelineOutcome('COMPLETED');

                    setTimeout(() => {
                        overlay.classList.add('hidden');
                        switchTab('audit', document.querySelectorAll('.nav-btn')[3]);
                    }, 800);
                }, 1000);
            }
        }, 1000);
    }, 1000);
}

function updatePipelineBadge() {
    const badge = document.getElementById('overallStatusBadge');
    if (!badge) return;

    switch (pipelineState) {
        case 'EXECUTING':
            badge.innerText = "EXECUTING";
            badge.className = "bg-slate-100 text-slate-700 text-[10px] font-mono px-2 py-0.5 rounded border border-slate-200";
            break;
        case 'STOPPED':
            badge.innerText = "STOPPED";
            badge.className = "bg-red-50 text-red-700 text-[10px] font-mono px-2 py-0.5 rounded border border-red-200";
            break;
        case 'COMPLETED':
            badge.innerText = "COMPLETED";
            badge.className = "bg-emerald-50 text-emerald-700 text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-200";
            break;
        default:
            badge.innerText = "IDLE";
            badge.className = "bg-slate-100 text-slate-500 text-[10px] font-mono px-2 py-0.5 rounded border border-slate-200";
    }
}

/* ================================================================
 * TAB SWITCHING
 * ================================================================ */

function switchTab(tabId, element) {
    const panels = document.querySelectorAll('.tab-panel');
    panels.forEach(sec => sec.classList.remove('active-panel', 'hidden'));

    const targetPanel = document.getElementById('tab-' + tabId);
    targetPanel.classList.add('active-panel');

    panels.forEach(sec => {
        if (sec.id !== 'tab-' + tabId) {
            sec.classList.add('hidden');
        }
    });

    if (element) {
        document.querySelectorAll('.nav-btn').forEach(a => a.classList.remove('active-nav'));
        element.classList.add('active-nav');
    }

    const pageTitles = {
        'dashboard': 'System Overview',
        'recovery': 'Recovery Engine Configurator',
        'approvals': 'Four-Eyes Authorization Queue',
        'audit': 'System Audit Log'
    };

    document.getElementById('pageTitle').innerText = pageTitles[tabId];

    // Tab-specific initialisation
    if (tabId === 'recovery') {
        onConfiguratorLoad();
        updateExceptionSwitchDisplay();
    } else if (tabId === 'approvals') {
        renderApprovalsQueue();
        renderApproveButton();
    } else if (tabId === 'audit') {
        renderAuditLog();
    }
}

/* ================================================================
 * INITIALISATION
 * ================================================================ */

(function init() {
    // Bind the Integrity Exception Switch (guarded by role + confirmation).
    const switchCheckbox = document.getElementById('simulateIntegrityFailure');
    if (switchCheckbox) {
        switchCheckbox.addEventListener('change', confirmExceptionToggle);
    }

    // Seed the role selector, then apply that role's permissions and UI.
    const roleSelector = document.getElementById('roleSelector');
    if (roleSelector) roleSelector.value = currentUser.role;

    switchRole(currentUser.role);   // renders header, banner, restrictions, snapshot table
    renderAuditLog();
})();

// Expose functions to global scope (inline onclick handlers need this)
window.switchTab = switchTab;
window.switchRole = switchRole;
window.quickSelectAndRecover = quickSelectAndRecover;
window.updateTargetSafetyUI = updateTargetSafetyUI;
window.triggerRecoveryProcess = triggerRecoveryProcess;
window.approveFourEyesRequest = approveFourEyesRequest;
window.rejectFourEyesRequest = rejectFourEyesRequest;
window.closeExecutionOverlay = closeExecutionOverlay;
window.runAutomatedExecution = runAutomatedExecution;
window.onConfiguratorLoad = onConfiguratorLoad;
window.preInitiateVerification = preInitiateVerification;
window.renderApprovalsQueue = renderApprovalsQueue;
window.renderApproveButton = renderApproveButton;
window.updateExceptionSwitchDisplay = updateExceptionSwitchDisplay;
window.showExceptionDialog = showExceptionDialog;
window.updateIntegrityStatusBanner = updateIntegrityStatusBanner;
window.onSnapshotSelected = onSnapshotSelected;
