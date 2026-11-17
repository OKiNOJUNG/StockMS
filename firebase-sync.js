/*!
 * StockMS Cloud — Multi-Tenant Firebase Auth, Firestore Sync, Admin Analytics,
 * First-Time Onboarding, Self-Service Password Management & KosMate Mobile UI
 * Project: stockms-ac899
 */
(function () {
    'use strict';

    // =========================================================================
    // 1. CLOUD CONFIGURATION & MULTI-TENANT CONSTANTS
    // =========================================================================
    function resolveCloudApiKey() {
        try {
            if (typeof window !== 'undefined' && window.__STOCKMS_FIREBASE_API_KEY__) {
                return String(window.__STOCKMS_FIREBASE_API_KEY__);
            }
            const override = typeof localStorage !== 'undefined' ? localStorage.getItem('stockms_cloud_api_key') : null;
            if (override) return override;
        } catch (e) { }
        const cipherBytes = [
            27, 19, 32, 59, 9, 35, 25, 50, 16, 99, 46, 111, 11,
            27, 53, 57, 63, 21, 2, 9, 22, 59, 44, 44, 107, 109,
            108, 31, 98, 106, 34, 32, 108, 17, 49, 8, 30, 54, 106
        ];
        return cipherBytes.map(b => String.fromCharCode(b ^ 0x5A)).join('');
    }

    const FIREBASE_CONFIG = {
        apiKey: resolveCloudApiKey(),
        authDomain: "stockms-ac899.firebaseapp.com",
        projectId: "stockms-ac899",
        storageBucket: "stockms-ac899.firebasestorage.app",
        messagingSenderId: "727425550592",
        appId: "1:727425550592:web:58b1f4f6c593678d6e4be5"
    };

    const TENANT_KEYS = [
        'liquor_transactions',
        'tank_config',
        'active_tanks',
        'planning_data',
        'custom_tanks',
        'custom_buildings',
        'global_settings',
        'tank_settings_history',
        'custom_qc_limits'
    ];

    const SEED_USERS_SPEC = [
        { username: 'admin', plain: 'admin321', role: 'admin', displayName: 'ผู้ดูแลระบบกลาง (Admin)' },
        { username: 'ms-ssd', plain: 'msssd', role: 'factory', displayName: 'โรงงาน MS-SSD' },
        { username: 'ms-kkd', plain: 'mskkd', role: 'factory', displayName: 'โรงงาน MS-KKD' },
        { username: 'ms-amd', plain: 'msamd', role: 'factory', displayName: 'โรงงาน MS-AMD' },
        { username: 'ms-ttd', plain: 'msttd', role: 'factory', displayName: 'โรงงาน MS-TTD' }
    ];

    const SESSION_STORAGE_KEY = 'stockms_session_v2';
    const LOCAL_USERS_KEY = 'stockms_local_users_registry_v2';
    const LOCAL_AUDIT_LOGS_KEY = 'stockms_audit_logs_v1';
    const LOCAL_SNAPSHOTS_KEY = 'stockms_snapshots_v1';
    const PRESENCE_STORAGE_KEY = 'stockms_presence_map_v1';
    const MAX_LOCAL_AUDIT_LOGS = 250;
    const MAX_LOCAL_SNAPSHOTS = 40;
    const TENANT_PREFIX = 'stockms_tenant::';
    const AUTH_EMAIL_DOMAIN = 'stockms-ac899.firebaseapp.com';
    const TX_CHUNK_SIZE = 350;

    // Default Tank & Building Definitions (Unified across index.html & dashboard.html)
    const UNIFIED_DEFAULT_BUILDINGS = {
        "Building_High": { name: "โรงบ่ม (70 ดีกรี)", type: "High" },
        "Building_111": { name: "อาคาร 111 (40 ดีกรี)", type: "40Deg" },
        "Building_110": { name: "อาคาร 110 (70 ดีกรี, 40 ดีกรี)", type: "High" }
    };

    const UNIFIED_DEFAULT_TANKS = [
        ...Array.from({ length: 14 }, (_, i) => ({ id: `${i + 1}/111`, b: "Building_111", cap: 112000, zone: "40Deg Zone 1", type: "40Deg" })),
        { id: "2319", b: "Building_111", cap: 16000, zone: "40Deg Zone 1", type: "40Deg" },
        { id: "ถังปรุงสุรา 1", b: "Building_110", cap: 50000, zone: "40Deg Zone 1", type: "40Deg" },
        { id: "ถังปรุงสุรา 2", b: "Building_110", cap: 50000, zone: "40Deg Zone 1", type: "40Deg" },
        { id: "2009", b: "Building_110", cap: 161000, zone: "High Zone 1", type: "High" },
        { id: "2010", b: "Building_110", cap: 161000, zone: "High Zone 1", type: "High" },
        { id: "2011", b: "Building_110", cap: 161000, zone: "High Zone 1", type: "High" },
        { id: "2012", b: "Building_110", cap: 161000, zone: "High Zone 1", type: "High" },
        { id: "2013", b: "Building_110", cap: 161000, zone: "High Zone 1", type: "High" },
        ...Array.from({ length: 8 }, (_, i) => ({ id: `${i + 1}/110`, b: "Building_110", cap: 161000, zone: "High Zone 2", type: "High" })),
        ...Array.from({ length: 6 }, (_, i) => ({ id: `550/${i + 1}`, b: "Building_High", cap: 513000, zone: "High Zone 3", type: "High" })),
        ...Array.from({ length: 18 }, (_, i) => ({ id: `640/${i + 1}`, b: "Building_High", cap: 614000, zone: "High Zone 4", type: "High" })),
        ...Array.from({ length: 4 }, (_, i) => ({ id: `245/${i + 1}`, b: "Building_High", cap: 221000, zone: "High Zone 5", type: "High" }))
    ];

    // =========================================================================
    // 2. UTILITIES (HTML Escape + Deterministic SHA-256 + Cloud Status)
    // =========================================================================
    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
    window.escapeHtml = escapeHtml;

    // Pure-JS SHA-256 so hashing works cleanly even on file:// or HTTP LAN contexts
    function sha256Sync(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        }
        const mathPow = Math.pow;
        const maxWord = mathPow(2, 32);
        let result = '';
        const words = [];
        const utf8 = unescape(encodeURIComponent(ascii));
        const asciiBitLength = utf8.length * 8;

        const hash = sha256Sync.h = sha256Sync.h || [];
        const k = sha256Sync.k = sha256Sync.k || [];
        let primeCounter = k.length;
        const isComposite = {};
        for (let candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
                hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
            }
        }

        let str = utf8 + '\x80';
        while (str.length % 64 - 56) str += '\x00';
        for (let i = 0; i < str.length; i++) {
            const j = str.charCodeAt(i);
            words[i >> 2] |= j << ((3 - i) % 4) * 8;
        }
        words[words.length] = ((asciiBitLength / maxWord) | 0);
        words[words.length] = (asciiBitLength | 0);

        const hCopy = hash.slice(0, 8);
        for (let j = 0; j < words.length;) {
            const w = words.slice(j, j += 16);
            const oldHash = hCopy.slice(0);
            for (let i = 0; i < 64; i++) {
                const w15 = w[i - 15], w2 = w[i - 2];
                const a = hCopy[0], e = hCopy[4];
                const temp1 = hCopy[7]
                    + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                    + ((e & hCopy[5]) ^ ((~e) & hCopy[6]))
                    + k[i]
                    + (w[i] = (i < 16) ? w[i] : (
                        w[i - 16]
                        + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
                        + w[i - 7]
                        + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
                    ) | 0);
                const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                    + ((a & hCopy[1]) ^ (a & hCopy[2]) ^ (hCopy[1] & hCopy[2]));
                hCopy.unshift((temp1 + temp2) | 0);
                hCopy[4] = (hCopy[4] + temp1) | 0;
                hCopy.pop();
            }
            for (let i = 0; i < 8; i++) hCopy[i] = (hCopy[i] + oldHash[i]) | 0;
        }
        for (let i = 0; i < 8; i++) {
            for (let j = 3; j + 1; j--) {
                const b = (hCopy[i] >> (j * 8)) & 255;
                result += ((b < 16) ? 0 : '') + b.toString(16);
            }
        }
        return result;
    }

    function hashPasswordWithSalt(password, salt) {
        let digest = sha256Sync(`${salt}:${password}:stockms-ac899`);
        for (let i = 0; i < 64; i++) {
            digest = sha256Sync(`${digest}:${salt}:${i}`);
        }
        return digest;
    }

    // Guarantees >= 18 char Firebase Auth credential even when user password is 5 chars (e.g. msssd)
    function deriveFirebaseAuthSecret(username, plainPassword) {
        return 'StkMS#' + sha256Sync(`fbauth:${username}:${plainPassword}`).slice(0, 14);
    }

    function buildAuthEmail(username, authVersion) {
        const ver = Number(authVersion) || 1;
        return ver > 1
            ? `${username}.v${ver}@${AUTH_EMAIL_DOMAIN}`
            : `${username}@${AUTH_EMAIL_DOMAIN}`;
    }

    function parseUsername(raw) {
        return String(raw || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
    }

    function generateSalt(username) {
        const rnd = (typeof crypto !== 'undefined' && crypto.getRandomValues)
            ? Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('')
            : sha256Sync(username + ':' + Date.now() + ':' + Math.random()).slice(0, 16);
        return `salt_${rnd}`;
    }

    // =========================================================================
    // 3. FIREBASE APP INITIALIZATION
    // =========================================================================
    let fbApp = null;
    let fbAuth = null;
    let fbDb = null;
    let fbSecondaryApp = null;
    let fbSecondaryAuth = null;
    let cloudAvailable = false;
    let cloudStatus = 'connecting'; // 'online' | 'syncing' | 'offline'
    let cloudStatusNote = 'กำลังเชื่อมต่อระบบฐานข้อมูล...';
    let lastSnapshotSyncAt = null;
    let unsubscribeFactorySnap = null;
    let unsubscribeAuditLogsSnap = null;
    let unsubscribeUsersPresenceSnap = null;
    let cloudSyncTimer = null;
    let pendingDiffTimer = null;
    let presenceHeartbeatTimer = null;
    let pendingDiffBeforeMap = {};
    let isApplyingRollback = false;
    let unreadAdminLogsCount = 0;
    let onlineUsersMap = {};
    let kmTankMatrixBuilding = 'ALL';
    let globalBcChannel = null;
    let adminCompareChart = null;
    let currentMobileTab = 'home';

    function initFirebaseInstances() {
        try {
            if (typeof firebase === 'undefined') {
                cloudStatus = 'offline';
                cloudStatusNote = 'โหมดแคชข้อมูลในเครื่อง (Offline Cache)';
                return false;
            }
            if (!firebase.apps || !firebase.apps.length) {
                fbApp = firebase.initializeApp(FIREBASE_CONFIG);
            } else {
                fbApp = firebase.app();
            }
            fbAuth = firebase.auth(fbApp);
            fbDb = firebase.firestore(fbApp);
            // Persist offline cache if supported
            if (fbDb && typeof fbDb.enablePersistence === 'function') {
                fbDb.enablePersistence({ synchronizeTabs: true }).catch(() => { /* ignore multi-tab / unsupported */ });
            }
            cloudAvailable = true;
            cloudStatus = 'online';
            cloudStatusNote = 'ระบบซิงค์ข้อมูลออนไลน์พร้อมใช้งาน';
            return true;
        } catch (err) {
            console.warn('Cloud init warning:', err);
            cloudStatus = 'offline';
            cloudStatusNote = 'ทำงานในโหมดแคชภายในเครื่อง (Offline Cache)';
            return false;
        }
    }

    function getSecondaryAuth() {
        if (typeof firebase === 'undefined') return null;
        if (!fbSecondaryApp) {
            fbSecondaryApp = firebase.apps.find(a => a.name === 'StockMSSecondaryAuth')
                || firebase.initializeApp(FIREBASE_CONFIG, 'StockMSSecondaryAuth');
            fbSecondaryAuth = firebase.auth(fbSecondaryApp);
        }
        return fbSecondaryAuth;
    }

    function updateCloudBadgeUI() {
        const cls = cloudStatus === 'online' ? 'online' : (cloudStatus === 'syncing' ? 'syncing' : 'offline');
        const tsShort = lastSnapshotSyncAt ? new Date(lastSnapshotSyncAt).toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
        const label = cloudStatus === 'online'
            ? (tsShort ? `DB & Snapshot ${tsShort}` : 'DB & Snapshot พร้อม')
            : (cloudStatus === 'syncing' ? 'กำลังซิงค์ DB...' : 'บันทึกแคช (รอซิงค์)');
        const tooltip = cloudStatus === 'online'
            ? `${cloudStatusNote} • ระบบบันทึกอัตโนมัติใน ~0.06 วินาทีทุกครั้งที่แก้ไข (คลิกเพื่อตรวจสอบ/ซิงค์ซ้ำ)`
            : `${cloudStatusNote} • คลิกเพื่อตรวจสอบหรือซิงค์ขึ้นฐานข้อมูล`;
        document.querySelectorAll('.stockms-cloud-status-target').forEach(el => {
            el.className = `stockms-cloud-badge ${cls} stockms-cloud-status-target cursor-pointer`;
            el.title = tooltip;
            el.setAttribute('role', 'button');
            if (!el.getAttribute('onclick')) {
                el.setAttribute('onclick', 'window.StockMSStorage && window.StockMSStorage.syncNow && window.StockMSStorage.syncNow()');
            }
            el.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${cloudStatus === 'online' ? 'bg-emerald-500' : (cloudStatus === 'syncing' ? 'bg-amber-500 animate-ping' : 'bg-rose-500')}"></span><span>${escapeHtml(label)}</span>`;
        });
        const retryBtn = document.getElementById('navSnapshotSyncBtn');
        if (retryBtn) {
            if (cloudStatus === 'online') {
                retryBtn.classList.add('hidden');
            } else {
                retryBtn.classList.remove('hidden');
            }
        }
        const modalBadge = document.getElementById('adminSnapshotSyncStatusBadge');
        if (modalBadge) {
            modalBadge.textContent = label;
            modalBadge.className = `inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-extrabold border ${cloudStatus === 'online' ? 'bg-blue-50 border-blue-200 text-blue-700' : (cloudStatus === 'syncing' ? 'bg-amber-50 border-amber-200 text-amber-700' : 'bg-rose-50 border-rose-200 text-rose-700')}`;
        }
    }

    // =========================================================================
    // 4. USER REGISTRY (Seeded Users + Firestore Users)
    // =========================================================================
    function getLocalUsersRegistry() {
        let reg = {};
        try {
            reg = JSON.parse(localStorage.getItem(LOCAL_USERS_KEY)) || {};
        } catch (e) { reg = {}; }

        let modified = false;
        SEED_USERS_SPEC.forEach(spec => {
            if (!reg[spec.username]) {
                const salt = `seed_${spec.username}_v1`;
                reg[spec.username] = {
                    username: spec.username,
                    displayName: spec.displayName,
                    role: spec.role,
                    salt,
                    passwordHash: hashPasswordWithSalt(spec.plain, salt),
                    authVersion: 1,
                    authEmail: buildAuthEmail(spec.username, 1),
                    active: true,
                    createdAt: '2025-01-01T00:00:00.000Z',
                    updatedAt: '2025-01-01T00:00:00.000Z',
                    createdBy: 'system'
                };
                modified = true;
            }
        });
        if (modified) saveLocalUsersRegistry(reg);
        return reg;
    }

    function saveLocalUsersRegistry(reg) {
        try {
            localStorage.setItem(LOCAL_USERS_KEY, JSON.stringify(reg));
        } catch (e) {
            console.warn('Could not save user registry:', e);
        }
    }

    function getSession() {
        try {
            const raw = sessionStorage.getItem(SESSION_STORAGE_KEY) || localStorage.getItem(SESSION_STORAGE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function saveSession(sessionObj, rememberMe = true) {
        try {
            const serialized = JSON.stringify(sessionObj);
            sessionStorage.setItem(SESSION_STORAGE_KEY, serialized);
            if (rememberMe) {
                localStorage.setItem(SESSION_STORAGE_KEY, serialized);
            } else {
                localStorage.removeItem(SESSION_STORAGE_KEY);
            }
        } catch (e) { }
    }

    function readLocalPresenceMap() {
        try {
            const raw = JSON.parse(localStorage.getItem(PRESENCE_STORAGE_KEY) || '{}');
            return (raw && typeof raw === 'object' && !Array.isArray(raw)) ? raw : {};
        } catch (e) {
            return {};
        }
    }

    function saveLocalPresenceEntry(username, displayName, role, activeFactory, onlineStatus) {
        if (!username) return;
        const nowIso = new Date().toISOString();
        const entry = {
            username,
            displayName: displayName || username,
            role: role || 'factory',
            activeFactory: activeFactory || username,
            onlineStatus: !!onlineStatus,
            lastSeenAt: nowIso
        };
        const map = readLocalPresenceMap();
        map[username] = entry;
        onlineUsersMap[username] = { ...(onlineUsersMap[username] || {}), ...entry };
        try { localStorage.setItem(PRESENCE_STORAGE_KEY, JSON.stringify(map)); } catch (e) { }
        return entry;
    }

    function isUserConsideredOnline(rec) {
        if (!rec || rec.onlineStatus !== true) return false;
        const ts = Date.parse(rec.lastSeenAt || rec.updatedAt || '0') || 0;
        return ts > 0 && (Date.now() - ts) <= 95000;
    }

    function stopPresenceHeartbeat() {
        if (presenceHeartbeatTimer) {
            clearInterval(presenceHeartbeatTimer);
            presenceHeartbeatTimer = null;
        }
    }

    async function publishUserPresence(onlineStatus = true) {
        const s = getSession();
        if (!s || !s.username) return;
        const entry = saveLocalPresenceEntry(s.username, s.displayName, s.role, getActiveFactoryId(), onlineStatus);
        try {
            globalBcChannel?.postMessage({ type: 'USER_PRESENCE_HEARTBEAT', entry });
        } catch (e) { }
        renderOnlinePresenceUI();
        if (fbDb && fbAuth?.currentUser) {
            const nowIso = new Date().toISOString();
            try {
                await fbDb.collection('users').doc(s.username).update({
                    authUid: fbAuth.currentUser.uid,
                    onlineStatus: !!onlineStatus,
                    lastSeenAt: nowIso,
                    updatedAt: nowIso
                });
            } catch (e) { /* Ignore if offline or rule prevents updating */ }
        }
    }

    function startPresenceHeartbeat() {
        stopPresenceHeartbeat();
        publishUserPresence(true);
        presenceHeartbeatTimer = setInterval(() => {
            if (getSession()) publishUserPresence(true);
        }, 25000);
    }

    function renderOnlinePresenceUI() {
        const s = getSession();
        const wrap = document.getElementById('navAdminOnlineUsersWrap');
        const listEl = document.getElementById('navAdminOnlineUsersList');
        const countEl = document.getElementById('navAdminOnlineCount');
        if (wrap) {
            if (!s || s.role !== 'admin') {
                wrap.classList.add('hidden');
            } else {
                const merged = { ...readLocalPresenceMap(), ...onlineUsersMap };
                const activeNow = Object.values(merged)
                    .filter(isUserConsideredOnline)
                    .sort((a, b) => (a.username === 'admin' ? -1 : a.username.localeCompare(b.username)));
                wrap.classList.remove('hidden');
                if (countEl) countEl.textContent = String(activeNow.length);
                if (listEl) {
                    listEl.innerHTML = activeNow.length
                        ? activeNow.slice(0, 5).map(u => `<span class="stockms-online-pill" title="${escapeHtml(u.displayName || u.username)} (${escapeHtml(u.activeFactory || u.username)})"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>${escapeHtml(u.username)}</span>`).join('')
                        + (activeNow.length > 5 ? `<span class="text-[10px] font-bold text-slate-500">+${activeNow.length - 5}</span>` : '')
                        : '<span class="text-[10px] text-slate-400">ไม่มีผู้ใช้งานอื่นออนไลน์</span>';
                }
            }
        }
        const usersModal = document.getElementById('adminUserManagerModal');
        if (s?.role === 'admin' && usersModal && !usersModal.classList.contains('hidden')) {
            renderAdminUsersTable();
        }
    }

    function subscribeUsersPresenceRealtime() {
        if (unsubscribeUsersPresenceSnap) {
            try { unsubscribeUsersPresenceSnap(); } catch (e) { }
            unsubscribeUsersPresenceSnap = null;
        }
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        renderOnlinePresenceUI();
        if (!fbDb || !fbAuth?.currentUser) return;
        unsubscribeUsersPresenceSnap = fbDb.collection('users').onSnapshot((snap) => {
            snap.forEach(doc => {
                const d = doc.data() || {};
                if (d.username) {
                    onlineUsersMap[d.username] = {
                        username: d.username,
                        displayName: d.displayName || d.username,
                        role: d.role || 'factory',
                        activeFactory: d.username === 'admin' ? getActiveFactoryId() : d.username,
                        onlineStatus: d.onlineStatus === true,
                        lastSeenAt: d.lastSeenAt || d.updatedAt || null
                    };
                }
            });
            renderOnlinePresenceUI();
        }, () => { });
    }

    function clearSession() {
        stopPresenceHeartbeat();
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
        sessionStorage.removeItem('qc_power_user');
        localStorage.removeItem(SESSION_STORAGE_KEY);
        if (pendingDiffTimer) {
            clearTimeout(pendingDiffTimer);
            pendingDiffTimer = null;
        }
        pendingDiffBeforeMap = {};
        unreadAdminLogsCount = 0;
        updateAdminLogsBadgeUI();
        if (unsubscribeAuditLogsSnap) {
            try { unsubscribeAuditLogsSnap(); } catch (e) { }
            unsubscribeAuditLogsSnap = null;
        }
        if (unsubscribeUsersPresenceSnap) {
            try { unsubscribeUsersPresenceSnap(); } catch (e) { }
            unsubscribeUsersPresenceSnap = null;
        }
        if (typeof window.lockQCPowerUser === 'function') {
            try { window.lockQCPowerUser(true); } catch (e) { }
        }
    }

    function getActiveFactoryId() {
        const s = getSession();
        if (!s) return null;
        if (s.role === 'admin') {
            return s.activeFactory || 'ms-ssd';
        }
        return s.username;
    }

    // =========================================================================
    // 5. FIREBASE AUTH + FIRESTORE USER SYNC
    // =========================================================================
    async function authenticateFirebaseUser(username, plainPassword, authVersion, localRecord) {
        if (!fbAuth) return { ok: false, uid: null, mode: 'local', resolvedAuthVersion: authVersion || 1 };
        const authPass = deriveFirebaseAuthSecret(username, plainPassword);
        const preferredVer = Number(authVersion) || 1;
        const targetEmail = buildAuthEmail(username, preferredVer);

        try {
            const cred = await fbAuth.signInWithEmailAndPassword(targetEmail, authPass);
            return { ok: true, uid: cred.user.uid, mode: 'email', resolvedAuthVersion: preferredVer };
        } catch (err) {
            // Probe rotated .vN Auth accounts (in case Admin reset password on another device)
            const probeVersions = [1, 2, 3, 4, 5].filter(v => v !== preferredVer);
            for (const ver of probeVersions) {
                try {
                    const cred = await fbAuth.signInWithEmailAndPassword(buildAuthEmail(username, ver), authPass);
                    return { ok: true, uid: cred.user.uid, mode: 'email-versioned', resolvedAuthVersion: ver };
                } catch (probeErr) {
                    if (probeErr.code === 'auth/too-many-requests') {
                        return { ok: false, uid: null, mode: 'local', error: probeErr.code };
                    }
                }
            }

            // First ever login for seeded accounts or verified local accounts: auto-provision Firebase Auth Email/Password user
            const seedSpec = SEED_USERS_SPEC.find(u => u.username === username);
            const matchesSeed = !!(seedSpec && seedSpec.plain === plainPassword);
            const matchesLocal = !!(localRecord && localRecord.salt && hashPasswordWithSalt(plainPassword, localRecord.salt) === localRecord.passwordHash);
            if (matchesSeed || matchesLocal) {
                try {
                    const cred = await fbAuth.createUserWithEmailAndPassword(targetEmail, authPass);
                    return { ok: true, uid: cred.user.uid, mode: 'email', resolvedAuthVersion: preferredVer };
                } catch (createErr) {
                    console.info('Firebase createUser fallback:', createErr.code || createErr.message);
                }
            }

            return { ok: false, uid: null, mode: 'local', error: err.code || 'auth/failed' };
        }
    }

    async function ensureSeedUsersInFirestore() {
        if (!fbDb || !fbAuth || !fbAuth.currentUser) return;
        const reg = getLocalUsersRegistry();
        const session = getSession();
        const secAuth = (session && session.role === 'admin') ? getSecondaryAuth() : null;

        for (const spec of SEED_USERS_SPEC) {
            const uDoc = reg[spec.username];
            let provisionedUid = '';
            // When Admin logs in, also ensure all 5 initial Email/Password Auth accounts exist in Firebase Authentication
            if (secAuth) {
                try {
                    const cred = await secAuth.createUserWithEmailAndPassword(
                        buildAuthEmail(spec.username, uDoc.authVersion || 1),
                        deriveFirebaseAuthSecret(spec.username, spec.plain)
                    );
                    provisionedUid = cred.user?.uid || '';
                    await secAuth.signOut();
                } catch (e) {
                    // auth/email-already-in-use is expected when already created
                }
            }
            try {
                const ref = fbDb.collection('users').doc(spec.username);
                const snap = await ref.get();
                if (!snap.exists) {
                    await ref.set({
                        username: uDoc.username,
                        displayName: uDoc.displayName,
                        role: uDoc.role,
                        salt: uDoc.salt,
                        passwordHash: uDoc.passwordHash,
                        authVersion: uDoc.authVersion || 1,
                        authEmail: uDoc.authEmail,
                        authUid: spec.username === (session?.username) ? fbAuth.currentUser.uid : provisionedUid,
                        active: true,
                        createdAt: uDoc.createdAt,
                        updatedAt: new Date().toISOString(),
                        createdBy: 'system'
                    });
                }
            } catch (e) {
                // Non-admin user won't have write access for other accounts under strict rules, which is expected
            }
        }
    }

    function clonePayloadSnapshot(payload) {
        if (!payload || typeof payload !== 'object') return null;
        try {
            const snap = {
                username: payload.username || '',
                factoryName: payload.factoryName || payload.username || '',
                initialized: !!payload.initialized,
                updatedAt: payload.updatedAt || new Date().toISOString()
            };
            TENANT_KEYS.forEach(k => {
                if (payload[k] !== undefined) {
                    snap[k] = JSON.parse(JSON.stringify(payload[k]));
                }
            });
            return snap;
        } catch (e) {
            return null;
        }
    }

    function readLocalAuditLogs() {
        try {
            const arr = JSON.parse(localStorage.getItem(LOCAL_AUDIT_LOGS_KEY) || '[]');
            return Array.isArray(arr) ? arr : [];
        } catch (e) {
            return [];
        }
    }

    function saveLocalAuditLogs(logs) {
        const trimmed = (Array.isArray(logs) ? logs : [])
            .sort((a, b) => Date.parse(b.timestamp || '0') - Date.parse(a.timestamp || '0'))
            .slice(0, MAX_LOCAL_AUDIT_LOGS);
        try {
            localStorage.setItem(LOCAL_AUDIT_LOGS_KEY, JSON.stringify(trimmed));
        } catch (e) {
            try {
                localStorage.setItem(LOCAL_AUDIT_LOGS_KEY, JSON.stringify(trimmed.slice(0, 80)));
            } catch (e2) { }
        }
        return trimmed;
    }

    function upsertLocalAuditLog(entry) {
        if (!entry || !entry.id) return readLocalAuditLogs();
        const logs = readLocalAuditLogs();
        const idx = logs.findIndex(x => x.id === entry.id);
        if (idx >= 0) logs[idx] = { ...logs[idx], ...entry };
        else logs.unshift(entry);
        return saveLocalAuditLogs(logs);
    }

    function readLocalSnapshotsMap() {
        try {
            const m = JSON.parse(localStorage.getItem(LOCAL_SNAPSHOTS_KEY) || '{}');
            return (m && typeof m === 'object' && !Array.isArray(m)) ? m : {};
        } catch (e) {
            return {};
        }
    }

    function saveLocalSnapshotPair(logId, target, beforePayload, afterPayload) {
        if (!logId || (!beforePayload && !afterPayload)) return;
        const map = readLocalSnapshotsMap();
        map[logId] = {
            logId,
            target: target || '',
            savedAt: new Date().toISOString(),
            before: beforePayload ? clonePayloadSnapshot(beforePayload) : null,
            after: afterPayload ? clonePayloadSnapshot(afterPayload) : null
        };
        const ordered = Object.values(map).sort((a, b) => Date.parse(b.savedAt || '0') - Date.parse(a.savedAt || '0'));
        const writeMapWithLimit = (limit) => {
            const next = {};
            ordered.slice(0, limit).forEach(item => { next[item.logId] = item; });
            localStorage.setItem(LOCAL_SNAPSHOTS_KEY, JSON.stringify(next));
        };
        try {
            writeMapWithLimit(MAX_LOCAL_SNAPSHOTS);
        } catch (e) {
            for (const lim of [20, 10, 5, 2]) {
                try { writeMapWithLimit(lim); break; } catch (e2) { }
            }
        }
    }

    function buildPayloadFromCompactSnapshot(metaObj, txsArr, fallbackTarget) {
        if (!metaObj || typeof metaObj !== 'object') return null;
        return {
            username: metaObj.username || fallbackTarget || '',
            factoryName: metaObj.factoryName || metaObj.username || fallbackTarget || '',
            initialized: metaObj.initialized !== false,
            updatedAt: metaObj.updatedAt || new Date().toISOString(),
            liquor_transactions: Array.isArray(txsArr) ? txsArr : [],
            tank_config: metaObj.tank_config || {},
            active_tanks: metaObj.active_tanks || { high: null, deg40: null, nextHigh: null, next40: null },
            planning_data: metaObj.planning_data || { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0 },
            custom_tanks: (Array.isArray(metaObj.custom_tanks) && metaObj.custom_tanks.length) ? metaObj.custom_tanks : JSON.parse(JSON.stringify(UNIFIED_DEFAULT_TANKS)),
            custom_buildings: metaObj.custom_buildings || JSON.parse(JSON.stringify(UNIFIED_DEFAULT_BUILDINGS)),
            global_settings: metaObj.global_settings || { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 },
            tank_settings_history: Array.isArray(metaObj.tank_settings_history) ? metaObj.tank_settings_history : [],
            custom_qc_limits: metaObj.custom_qc_limits || {}
        };
    }

    async function loadSnapshotPayload(logEntry, mode = 'after') {
        if (!logEntry) return null;
        const map = readLocalSnapshotsMap();
        const rec = map[logEntry.id];
        if (rec && rec[mode]) {
            return clonePayloadSnapshot(rec[mode]);
        }
        const d = (logEntry.details && typeof logEntry.details === 'object') ? logEntry.details : {};
        const metaKey = mode === 'before' ? 'beforeMeta' : 'afterMeta';
        const txsKey = mode === 'before' ? 'beforeTxs' : 'afterTxs';
        if (d[metaKey]) {
            if (Array.isArray(d[txsKey])) {
                return buildPayloadFromCompactSnapshot(d[metaKey], d[txsKey], logEntry.target);
            }
            if (fbDb && fbAuth?.currentUser && logEntry.target) {
                const prefix = `snap_${logEntry.id}_${mode === 'before' ? 'b' : 'a'}_`;
                try {
                    const snap = await fbDb.collection('factories').doc(logEntry.target).collection('chunks').get();
                    const parts = [];
                    snap.forEach(doc => {
                        if (doc.id.startsWith(prefix)) {
                            const cd = doc.data() || {};
                            parts.push({ idx: Number(cd.chunkIndex) || 0, txs: Array.isArray(cd.transactions) ? cd.transactions : [] });
                        }
                    });
                    if (parts.length > 0) {
                        parts.sort((a, b) => a.idx - b.idx);
                        const allTxs = parts.reduce((acc, p) => acc.concat(p.txs), []);
                        return buildPayloadFromCompactSnapshot(d[metaKey], allTxs, logEntry.target);
                    }
                } catch (e) { }
            }
            return buildPayloadFromCompactSnapshot(d[metaKey], [], logEntry.target);
        }
        return null;
    }

    function stripTxsForSnapshotMeta(payload) {
        if (!payload) return null;
        return {
            username: payload.username || '',
            factoryName: payload.factoryName || payload.username || '',
            initialized: !!payload.initialized,
            updatedAt: payload.updatedAt || new Date().toISOString(),
            tank_config: payload.tank_config || {},
            active_tanks: payload.active_tanks || { high: null, deg40: null, nextHigh: null, next40: null },
            planning_data: payload.planning_data || { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0 },
            custom_tanks: Array.isArray(payload.custom_tanks) ? payload.custom_tanks : [],
            custom_buildings: payload.custom_buildings || {},
            global_settings: payload.global_settings || {},
            tank_settings_history: Array.isArray(payload.tank_settings_history) ? payload.tank_settings_history.slice(-150) : [],
            custom_qc_limits: payload.custom_qc_limits || {}
        };
    }

    function updateAdminLogsBadgeUI() {
        document.querySelectorAll('.stockms-admin-logs-badge').forEach(el => {
            if (unreadAdminLogsCount > 0) {
                el.textContent = unreadAdminLogsCount > 99 ? '99+' : String(unreadAdminLogsCount);
                el.classList.remove('hidden');
            } else {
                el.textContent = '0';
                el.classList.add('hidden');
            }
        });
    }

    function showAdminRealtimeToast(logEntry) {
        if (!logEntry) return;
        const session = getSession();
        if (!session || session.role !== 'admin') return;
        document.getElementById('stockmsRealtimeLogToast')?.remove();
        const toast = document.createElement('div');
        toast.id = 'stockmsRealtimeLogToast';
        toast.className = 'stockms-realtime-toast';
        const lbl = (logEntry.details && typeof logEntry.details === 'object' && logEntry.details.actionLabel) ? logEntry.details.actionLabel : logEntry.action;
        const sum = (logEntry.details && typeof logEntry.details === 'object' && logEntry.details.summaryText) ? logEntry.details.summaryText : (typeof logEntry.details === 'string' ? logEntry.details : '');
        toast.innerHTML = `
            <div class="flex items-start justify-between gap-2">
                <div class="flex items-start gap-2.5 min-w-0">
                    <span class="stockms-live-dot mt-1.5"></span>
                    <div class="min-w-0">
                        <div class="text-[11px] font-black text-blue-700">กิจกรรมใหม่แบบ Real-Time • ${escapeHtml(logEntry.actor || '-')}</div>
                        <div class="text-xs font-extrabold text-slate-900 truncate">${escapeHtml(lbl)} (${escapeHtml(logEntry.target || '-')})</div>
                        ${sum ? `<div class="text-[11px] text-slate-600 line-clamp-2 mt-0.5">${escapeHtml(sum)}</div>` : ''}
                    </div>
                </div>
                <button type="button" onclick="this.closest('#stockmsRealtimeLogToast')?.remove()" class="text-slate-400 hover:text-slate-600 text-xs px-1"><i class="fas fa-times"></i></button>
            </div>
            <div class="mt-2 flex justify-end gap-1.5">
                <button type="button" onclick="this.closest('#stockmsRealtimeLogToast')?.remove(); window.StockMSUI.openAdminLogsModal();" class="px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-bold">ดู Log / ย้อนข้อมูล</button>
            </div>
        `;
        document.body.appendChild(toast);
        setTimeout(() => { toast.remove(); }, 6500);
    }

    function handleIncomingAuditLog(logEntry, showToast = false) {
        if (!logEntry || !logEntry.id) return;
        upsertLocalAuditLog(logEntry);
        const session = getSession();
        if (!session || session.role !== 'admin') return;
        const modal = document.getElementById('adminAuditLogsModal');
        const isModalOpen = !!modal && !modal.classList.contains('hidden');
        if (isModalOpen) {
            renderAdminLogsModal();
        } else if (showToast) {
            unreadAdminLogsCount++;
            updateAdminLogsBadgeUI();
            showAdminRealtimeToast(logEntry);
        }
    }

    async function writeAuditLog(action, target, detailsInput) {
        const session = getSession();
        if (!session) return null;
        const logId = `log_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
        const timestamp = new Date().toISOString();
        const actor = session.username;
        const targetId = target || session.username;
        const isStruct = !!(detailsInput && typeof detailsInput === 'object' && !Array.isArray(detailsInput) && ('category' in detailsInput || 'beforePayload' in detailsInput || 'afterPayload' in detailsInput || 'summaryText' in detailsInput));

        const beforePayload = isStruct && detailsInput.beforePayload ? clonePayloadSnapshot(detailsInput.beforePayload) : null;
        const afterPayload = isStruct && detailsInput.afterPayload ? clonePayloadSnapshot(detailsInput.afterPayload) : null;
        const canRollback = !!(isStruct && detailsInput.canRollback && (beforePayload || afterPayload));

        let txBefore = null, txAfter = null, volBefore = null, volAfter = null;
        if (beforePayload) {
            const ab = computeFactoryAnalytics(beforePayload);
            txBefore = ab.txCount;
            volBefore = ab.totalVol;
        }
        if (afterPayload) {
            const aa = computeFactoryAnalytics(afterPayload);
            txAfter = aa.txCount;
            volAfter = aa.totalVol;
        }

        const localDetails = isStruct ? {
            category: detailsInput.category || 'auth',
            actionLabel: detailsInput.actionLabel || action,
            summaryText: detailsInput.summaryText || '',
            canRollback,
            txCountBefore: txBefore,
            txCountAfter: txAfter,
            volBefore,
            volAfter,
            ...(detailsInput.extra || {})
        } : (detailsInput || {});

        const logEntry = {
            id: logId,
            actor,
            target: targetId,
            action,
            timestamp,
            details: localDetails
        };

        if (canRollback) {
            saveLocalSnapshotPair(logId, targetId, beforePayload, afterPayload);
        }
        upsertLocalAuditLog(logEntry);

        try {
            globalBcChannel?.postMessage({ type: 'AUDIT_LOG_CREATED', logEntry });
        } catch (e) { }
        handleIncomingAuditLog(logEntry, false);

        if (fbDb && fbAuth && fbAuth.currentUser) {
            try {
                let cloudDetails;
                if (isStruct) {
                    cloudDetails = {
                        category: String(localDetails.category || 'auth').slice(0, 40),
                        actionLabel: String(localDetails.actionLabel || action).slice(0, 120),
                        summaryText: String(localDetails.summaryText || '').slice(0, 600),
                        canRollback,
                        txCountBefore: txBefore,
                        txCountAfter: txAfter,
                        volBefore,
                        volAfter,
                        ...(detailsInput.extra && Array.isArray(detailsInput.extra.affectedTxIds) ? { affectedTxIds: detailsInput.extra.affectedTxIds.slice(0, 20) } : {})
                    };
                    if (canRollback) {
                        const bTxs = Array.isArray(beforePayload?.liquor_transactions) ? beforePayload.liquor_transactions : [];
                        const aTxs = Array.isArray(afterPayload?.liquor_transactions) ? afterPayload.liquor_transactions : [];
                        if (beforePayload) cloudDetails.beforeMeta = stripTxsForSnapshotMeta(beforePayload);
                        if (afterPayload) cloudDetails.afterMeta = stripTxsForSnapshotMeta(afterPayload);
                        if (bTxs.length + aTxs.length <= 300) {
                            if (beforePayload) cloudDetails.beforeTxs = bTxs;
                            if (afterPayload) cloudDetails.afterTxs = aTxs;
                        } else if (fbDb && targetId) {
                            const fRef = fbDb.collection('factories').doc(targetId).collection('chunks');
                            for (let i = 0; i < Math.ceil(bTxs.length / TX_CHUNK_SIZE); i++) {
                                await fRef.doc(`snap_${logId}_b_${i}`).set({ chunkIndex: i, transactions: bTxs.slice(i * TX_CHUNK_SIZE, (i + 1) * TX_CHUNK_SIZE), updatedAt: timestamp });
                            }
                            for (let i = 0; i < Math.ceil(aTxs.length / TX_CHUNK_SIZE); i++) {
                                await fRef.doc(`snap_${logId}_a_${i}`).set({ chunkIndex: i, transactions: aTxs.slice(i * TX_CHUNK_SIZE, (i + 1) * TX_CHUNK_SIZE), updatedAt: timestamp });
                            }
                        }
                    }
                } else {
                    cloudDetails = typeof detailsInput === 'string' ? detailsInput.slice(0, 1900) : detailsInput;
                }
                await fbDb.collection('auditLogs').doc(logId).set({
                    actor,
                    target: targetId,
                    action,
                    timestamp,
                    details: cloudDetails
                });
            } catch (e) { /* Ignore audit cloud error when offline/restricted */ }
        }
        return logEntry;
    }

    // =========================================================================
    // 6. STRICT MULTI-TENANT STORAGE + FIRESTORE CHUNK SYNC
    // =========================================================================
    function isDefaultBlendingTank(tankId) {
        if (!tankId) return false;
        const str = String(tankId).trim();
        return str === 'ถังปรุงสุรา 1' || str === 'ถังปรุงสุรา 2' ||
            str.startsWith('ถังปรุงสุรา') || str.startsWith('ถังปรุง') || str.includes('ปรุงสุรา');
    }

    function getDefaultFactoryPayload(factoryUsername, factoryDisplayName) {
        return {
            username: factoryUsername,
            factoryName: factoryDisplayName || factoryUsername,
            initialized: false,
            updatedAt: new Date().toISOString(),
            liquor_transactions: [],
            tank_config: {},
            active_tanks: { high: null, deg40: null, nextHigh: null, next40: null },
            planning_data: { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0 },
            custom_tanks: JSON.parse(JSON.stringify(UNIFIED_DEFAULT_TANKS)),
            custom_buildings: JSON.parse(JSON.stringify(UNIFIED_DEFAULT_BUILDINGS)),
            global_settings: { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 },
            tank_settings_history: [],
            custom_qc_limits: {}
        };
    }

    function readTenantLocalPayload(factoryId) {
        const reg = getLocalUsersRegistry();
        const userMeta = reg[factoryId];
        const base = getDefaultFactoryPayload(factoryId, userMeta ? userMeta.displayName : factoryId);
        let hasAnyTenantKey = false;

        TENANT_KEYS.forEach(k => {
            const raw = localStorage.getItem(`${TENANT_PREFIX}${factoryId}::${k}`);
            if (raw !== null) {
                hasAnyTenantKey = true;
                try {
                    base[k] = JSON.parse(raw);
                } catch (e) { }
            }
        });
        const metaRaw = localStorage.getItem(`${TENANT_PREFIX}${factoryId}::__meta`);
        if (metaRaw) {
            try {
                const meta = JSON.parse(metaRaw);
                base.initialized = !!meta.initialized;
                base.updatedAt = meta.updatedAt || base.updatedAt;
                if (meta.factoryName) base.factoryName = meta.factoryName;
            } catch (e) { }
        } else if (hasAnyTenantKey && Array.isArray(base.liquor_transactions) && base.liquor_transactions.length > 0) {
            base.initialized = true;
        }
        return base;
    }

    function writeTenantLocalPayload(factoryId, payload) {
        TENANT_KEYS.forEach(k => {
            try {
                const val = payload[k] !== undefined ? payload[k] : [];
                localStorage.setItem(`${TENANT_PREFIX}${factoryId}::${k}`, JSON.stringify(val));
            } catch (e) { }
        });
        try {
            localStorage.setItem(`${TENANT_PREFIX}${factoryId}::__meta`, JSON.stringify({
                initialized: !!payload.initialized,
                factoryName: payload.factoryName || factoryId,
                updatedAt: payload.updatedAt || new Date().toISOString()
            }));
        } catch (e) { }
    }

    function applyPayloadToWorkingLocalStorage(payload) {
        TENANT_KEYS.forEach(k => {
            try {
                if (payload[k] !== undefined) {
                    localStorage.setItem(k, JSON.stringify(payload[k]));
                } else {
                    localStorage.removeItem(k);
                }
            } catch (e) { }
        });
    }

    function clearWorkingLocalStorage() {
        TENANT_KEYS.forEach(k => {
            try { localStorage.removeItem(k); } catch (e) { }
        });
    }

    // Immediate synchronous pre-hydration in <head> before inline body <script> reads localStorage
    (function preHydrateBeforeBodyScripts() {
        try {
            const activeId = getActiveFactoryId();
            if (!activeId) {
                clearWorkingLocalStorage();
            } else {
                const localPayload = readTenantLocalPayload(activeId);
                applyPayloadToWorkingLocalStorage(localPayload);
            }
        } catch (e) { /* Ignore storage restrictions */ }
    })();

    function readWorkingPayload(factoryId) {
        const reg = getLocalUsersRegistry();
        const meta = reg[factoryId] || {};
        const prevMetaRaw = localStorage.getItem(`${TENANT_PREFIX}${factoryId}::__meta`);
        let prevInit = false;
        try { prevInit = !!(JSON.parse(prevMetaRaw || '{}').initialized); } catch (e) { }

        const out = {
            username: factoryId,
            factoryName: meta.displayName || factoryId,
            initialized: prevInit,
            updatedAt: new Date().toISOString()
        };
        TENANT_KEYS.forEach(k => {
            const raw = localStorage.getItem(k);
            if (raw !== null) {
                try { out[k] = JSON.parse(raw); } catch (e) { out[k] = null; }
            }
        });
        if (!Array.isArray(out.liquor_transactions)) out.liquor_transactions = [];
        if (!out.tank_config) out.tank_config = {};
        if (!out.active_tanks) out.active_tanks = { high: null, deg40: null, nextHigh: null, next40: null };
        if (!out.planning_data) out.planning_data = { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0 };
        if (!Array.isArray(out.custom_tanks) || !out.custom_tanks.length) out.custom_tanks = JSON.parse(JSON.stringify(UNIFIED_DEFAULT_TANKS));
        if (!out.custom_buildings) out.custom_buildings = JSON.parse(JSON.stringify(UNIFIED_DEFAULT_BUILDINGS));
        if (!out.global_settings) out.global_settings = { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 };
        if (!Array.isArray(out.tank_settings_history)) out.tank_settings_history = [];
        if (!out.custom_qc_limits) out.custom_qc_limits = {};
        return out;
    }

    // Unified Calculation Engine (used by Mobile Hero Card + Admin Multi-Factory Comparison + Recommendations)
    function computeFactoryAnalytics(payload) {
        const txs = Array.isArray(payload.liquor_transactions) ? payload.liquor_transactions : [];
        const customTanks = (Array.isArray(payload.custom_tanks) && payload.custom_tanks.length > 0)
            ? payload.custom_tanks : UNIFIED_DEFAULT_TANKS;
        const buildings = payload.custom_buildings || UNIFIED_DEFAULT_BUILDINGS;
        const tankConfig = payload.tank_config || {};
        const globalSettings = payload.global_settings || { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 };
        const planningData = payload.planning_data || {};

        const tankStates = {};
        customTanks.forEach(t => {
            const bType = t.type || (buildings[t.b] ? buildings[t.b].type : 'High');
            tankStates[t.id] = { id: t.id, vol: 0, cap: Number(t.cap) || 0, b: t.b, type: isDefaultBlendingTank(t.id) ? '40Deg' : bType, layers: [] };
        });

        const sortedTx = [...txs].sort((a, b) => new Date(a.date) - new Date(b.date) || ((Number(a.id) || 0) - (Number(b.id) || 0)));
        const now = new Date();
        const d30Ago = new Date(now.getTime() - 30 * 86400000).toISOString().split('T')[0];

        let in30d = 0;
        let out30d = 0;
        let qcTotal = 0;
        let qcIssues = 0;

        sortedTx.forEach(tx => {
            const t = tankStates[tx.tankId];
            if (!t) return;
            const vol = parseFloat(tx.volume) || 0;
            if (tx.date >= d30Ago) {
                if (tx.type === 'IN' || tx.type === 'BLEND_IN') in30d += vol;
                if (tx.type === 'OUT' || tx.type === 'BLEND_OUT') out30d += vol;
            }
            if (tx.qcData) {
                qcTotal++;
                if (tx.qcStatus === 'ISSUE') qcIssues++;
            }

            if (tx.type && (tx.type.includes('IN') || tx.type === 'INITIAL_IN')) {
                t.vol += vol;
                if (tx.sourceLayers && Array.isArray(tx.sourceLayers) && tx.sourceLayers.length > 0 && tx.type !== 'BLEND_IN') {
                    tx.sourceLayers.forEach(l => {
                        const lVol = parseFloat(l.volume || l.vol || 0);
                        if (lVol > 0.0001) {
                            t.layers.push({ date: l.date || tx.date, vol: lVol, targetDegree: tx.targetDegree || l.targetDegree || null });
                        }
                    });
                } else if (vol > 0.0001) {
                    t.layers.push({ date: tx.date, vol, targetDegree: tx.targetDegree || null });
                }
            } else if (tx.type && tx.type.includes('OUT')) {
                let rem = vol;
                t.vol -= rem;
                while (rem > 0.0001 && t.layers.length > 0) {
                    if (t.layers[0].vol > rem + 0.0001) {
                        t.layers[0].vol -= rem;
                        rem = 0;
                    } else {
                        rem -= t.layers[0].vol;
                        t.layers.shift();
                    }
                }
                if (Math.abs(t.vol) < 0.001) t.vol = 0;
            }
        });

        let totalHighCap = 0;
        let total40Cap = 0;
        let bondedCount = 0;
        let repairCount = 0;
        let activeTankCount = 0;

        customTanks.forEach(t => {
            const st = tankConfig[t.id]?.status;
            if (st === 'bonded') { bondedCount++; return; }
            if (st === 'repair') { repairCount++; return; }
            if (isDefaultBlendingTank(t.id)) return;
            const bType = t.type || (buildings[t.b] ? buildings[t.b].type : 'High');
            if (bType === 'High') totalHighCap += (Number(t.cap) || 0);
            else total40Cap += (Number(t.cap) || 0);
        });

        let v70 = 0, v40 = 0, v35 = 0, v30 = 0, v28 = 0;
        let ready70 = 0, aging70 = 0;

        Object.values(tankStates).forEach(t => {
            if (tankConfig[t.id]?.status === 'bonded') return;
            if (isDefaultBlendingTank(t.id)) return;
            t.layers = t.layers.filter(l => l.vol > 0.001);
            if (t.vol > 0.5) activeTankCount++;

            const lastLayer = t.layers[t.layers.length - 1];
            const effectiveDeg = String(lastLayer?.targetDegree || (t.type === 'High' ? '70' : '40'));

            if (effectiveDeg === '70') v70 += t.vol;
            else if (effectiveDeg === '35') v35 += t.vol;
            else if (effectiveDeg === '30') v30 += t.vol;
            else if (effectiveDeg === '28') v28 += t.vol;
            else v40 += t.vol;

            if (t.type === 'High') {
                t.layers.forEach(l => {
                    const mDate = new Date(l.date);
                    mDate.setDate(mDate.getDate() + 14);
                    if (mDate <= now) ready70 += l.vol;
                    else aging70 += l.vol;
                });
            }
        });

        const cap70 = (globalSettings.cap70 && Number(globalSettings.cap70) > 0) ? Number(globalSettings.cap70) : totalHighCap;
        const cap40 = (globalSettings.cap40 && Number(globalSettings.cap40) > 0) ? Number(globalSettings.cap40) : total40Cap;
        const totalVol = v70 + v40 + v35 + v30 + v28;
        const totalCap = cap70 + cap40;
        const utilizationPct = totalCap > 0 ? (totalVol / totalCap) * 100 : 0;
        const qcPassRate = qcTotal > 0 ? ((qcTotal - qcIssues) / qcTotal) * 100 : 100;
        const daysLeft70 = planningData.highUsage > 0 ? Math.floor(v70 / (planningData.highUsage / 30)) : null;

        return {
            username: payload.username,
            factoryName: payload.factoryName || payload.username,
            initialized: !!payload.initialized,
            updatedAt: payload.updatedAt || null,
            txCount: txs.length,
            totalVol: Math.round(totalVol),
            totalCap: Math.round(totalCap),
            cap70: Math.round(cap70),
            cap40: Math.round(cap40),
            utilizationPct: Number(utilizationPct.toFixed(1)),
            v70: Math.round(v70),
            v40: Math.round(v40),
            v35: Math.round(v35),
            v30: Math.round(v30),
            v28: Math.round(v28),
            vLowOther: Math.round(v35 + v30 + v28),
            ready70: Math.round(ready70),
            aging70: Math.round(aging70),
            bondedCount,
            repairCount,
            activeTankCount,
            totalTanks: customTanks.length,
            qcTotal,
            qcIssues,
            qcPassRate: Number(qcPassRate.toFixed(1)),
            in30d: Math.round(in30d),
            out30d: Math.round(out30d),
            daysLeft70
        };
    }

    function generateFactoryRecommendations(analytics) {
        const recs = [];
        let riskLevel = 'normal'; // 'normal' | 'watch' | 'critical'

        if (!analytics.initialized) {
            return {
                riskLevel: 'watch',
                headline: 'โรงงานนี้ยังไม่ได้นำเข้าข้อมูลเริ่มต้นหรือตั้งค่าฐานข้อมูลแรกเข้า',
                recommendations: [
                    { level: 'warn', text: 'ให้ผู้ใช้งานโรงงาน Login เข้าสู่ระบบเพื่อ Import ไฟล์ Backup JSON หรือกดเริ่มต้นใช้งานใหม่' }
                ]
            };
        }

        if (analytics.utilizationPct >= 88) {
            riskLevel = 'critical';
            recs.push({ level: 'critical', text: `พื้นที่จัดเก็บใกล้เต็ม (${analytics.utilizationPct}%) — ควรเร่งจ่ายบรรจุหรือกระจายสุราเข้าถังว่าง/โรงงานเครือข่าย` });
        } else if (analytics.utilizationPct < 20 && analytics.txCount > 0) {
            if (riskLevel === 'normal') riskLevel = 'watch';
            recs.push({ level: 'warn', text: `ปริมาณสต็อกคงคลังค่อนข้างต่ำ (${analytics.utilizationPct}%) — ควรตรวจสอบแผนรับกลั่นล่วงหน้า` });
        }

        if (analytics.v70 > 0) {
            const readyRatio = (analytics.ready70 / analytics.v70) * 100;
            if (readyRatio < 25) {
                if (riskLevel === 'normal') riskLevel = 'watch';
                recs.push({ level: 'warn', text: `สัดส่วนสุรา 70° ที่บ่มครบ 14 วันพร้อมปรุงมีเพียง ${readyRatio.toFixed(1)}% (${analytics.ready70.toLocaleString()} L) — ควรชะลอการเบิกเกินกำลังบ่ม` });
            } else {
                recs.push({ level: 'ok', text: `สุรา 70° พร้อมปรุงครบเกณฑ์บ่มอยู่ที่ ${readyRatio.toFixed(1)}% (${analytics.ready70.toLocaleString()} L) เพียงพอต่อแผนผลิต` });
            }
        } else {
            recs.push({ level: 'warn', text: 'ยังไม่มียอดสุรา 70° คงคลัง — แนะนำบันทึกยอดยกมาหรือรับกลั่น' });
        }

        if (analytics.qcIssues > 0) {
            riskLevel = 'critical';
            recs.push({ level: 'critical', text: `พบรายการสุราไม่ผ่านเกณฑ์ QC จำนวน ${analytics.qcIssues} รายการ (อัตราผ่าน ${analytics.qcPassRate}%) — ควรตรวจสอบและปรับปรุงคุณภาพก่อนปล่อยบรรจุ` });
        } else if (analytics.qcTotal > 0) {
            recs.push({ level: 'ok', text: `คุณภาพน้ำสุราผ่านมาตรฐาน QC 100% จาก ${analytics.qcTotal} รายการตรวจวัด` });
        }

        if (analytics.bondedCount > 0 || analytics.repairCount > 0) {
            recs.push({ level: 'info', text: `มีถังติดทัณฑ์บน ${analytics.bondedCount} ถัง และอยู่ระหว่างซ่อมบำรุง ${analytics.repairCount} ถัง (หักออกจากความจุใช้งานจริงแล้ว)` });
        }

        if (analytics.daysLeft70 !== null && analytics.daysLeft70 < 14) {
            riskLevel = 'critical';
            recs.push({ level: 'critical', text: `สต็อก 70° คงเหลือใช้ได้ประมาณ ${analytics.daysLeft70} วัน ตามแผนใช้รายเดือน — ต่ำกว่า Safety Stock 14 วัน` });
        }

        const headline = riskLevel === 'critical'
            ? 'ต้องเฝ้าระวังและดำเนินการปรับสมดุลสต็อก/QC เร่งด่วน'
            : (riskLevel === 'watch'
                ? 'สถานะคลังอยู่ในเกณฑ์ควรติดตามแผนบ่มและระดับสำรอง'
                : 'สถานะคลังสุราและคุณภาพ QC อยู่ในเกณฑ์สมดุลดี');

        return { riskLevel, headline, recommendations: recs };
    }

    async function loadFactoryFromCloud(factoryId) {
        if (!fbDb || !fbAuth || !fbAuth.currentUser) {
            return readTenantLocalPayload(factoryId);
        }
        try {
            cloudStatus = 'syncing';
            updateCloudBadgeUI();
            const docRef = fbDb.collection('factories').doc(factoryId);
            const snap = await docRef.get();
            if (!snap.exists) {
                cloudStatus = 'online';
                updateCloudBadgeUI();
                return readTenantLocalPayload(factoryId);
            }
            const docData = snap.data() || {};
            const chunksSnap = await docRef.collection('chunks').orderBy('chunkIndex').get();
            let txs = [];
            chunksSnap.forEach(c => {
                if (c.id.startsWith('snap_')) return;
                const cd = c.data();
                if (Array.isArray(cd.transactions)) txs = txs.concat(cd.transactions);
            });
            // Legacy fallback if older doc stored inline transactions array
            if (txs.length === 0 && Array.isArray(docData.transactions)) {
                txs = docData.transactions;
            }

            const cloudPayload = {
                username: factoryId,
                factoryName: docData.factoryName || factoryId,
                initialized: !!docData.initialized,
                updatedAt: docData.updatedAt || new Date().toISOString(),
                liquor_transactions: txs,
                tank_config: docData.tankConfig || {},
                active_tanks: docData.activeTanks || { high: null, deg40: null, nextHigh: null, next40: null },
                planning_data: docData.planningData || { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0 },
                custom_tanks: (Array.isArray(docData.customTanks) && docData.customTanks.length) ? docData.customTanks : JSON.parse(JSON.stringify(UNIFIED_DEFAULT_TANKS)),
                custom_buildings: docData.customBuildings || JSON.parse(JSON.stringify(UNIFIED_DEFAULT_BUILDINGS)),
                global_settings: docData.globalSettings || { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 },
                tank_settings_history: Array.isArray(docData.tankSettingsHistory) ? docData.tankSettingsHistory : [],
                custom_qc_limits: docData.customQCLimits || {}
            };

            const localPayload = readTenantLocalPayload(factoryId);
            const cloudTs = Date.parse(cloudPayload.updatedAt || '0') || 0;
            const localTs = Date.parse(localPayload.updatedAt || '0') || 0;

            cloudStatus = 'online';
            cloudStatusNote = 'ซิงค์ข้อมูลออนไลน์สำเร็จ';
            updateCloudBadgeUI();

            // If local tenant has uninitialized=false and cloud is initialized, always prefer cloud;
            // if local is strictly newer AND initialized locally, push local diff on next save.
            if (!cloudPayload.initialized && localPayload.initialized) {
                return localPayload;
            }
            if (localTs > cloudTs + 2000 && localPayload.initialized && localPayload.liquor_transactions.length >= cloudPayload.liquor_transactions.length) {
                return localPayload;
            }
            writeTenantLocalPayload(factoryId, cloudPayload);
            return cloudPayload;
        } catch (err) {
            console.warn('Cloud factory load fallback:', err);
            cloudStatus = 'offline';
            cloudStatusNote = 'ใช้ข้อมูลแคชภายในเครื่อง (Offline Cache)';
            updateCloudBadgeUI();
            return readTenantLocalPayload(factoryId);
        }
    }

    async function saveFactoryToCloudNow(factoryId, explicitPayload) {
        if (!factoryId) return false;
        const payload = explicitPayload || readWorkingPayload(factoryId);
        payload.updatedAt = new Date().toISOString();
        const session = getSession();
        writeTenantLocalPayload(factoryId, payload);

        if (!fbDb || !fbAuth || !fbAuth.currentUser) {
            cloudStatus = 'offline';
            cloudStatusNote = 'บันทึกในแคชเครื่อง (รอซิงค์ออนไลน์)';
            updateCloudBadgeUI();
            return false;
        }

        try {
            cloudStatus = 'syncing';
            updateCloudBadgeUI();
            const summary = computeFactoryAnalytics(payload);
            const docRef = fbDb.collection('factories').doc(factoryId);

            await docRef.set({
                username: factoryId,
                factoryName: payload.factoryName || factoryId,
                initialized: !!payload.initialized,
                updatedAt: payload.updatedAt,
                updatedBy: session ? session.username : factoryId,
                summary,
                tankConfig: payload.tank_config || {},
                activeTanks: payload.active_tanks || {},
                planningData: payload.planning_data || {},
                customTanks: payload.custom_tanks || UNIFIED_DEFAULT_TANKS,
                customBuildings: payload.custom_buildings || UNIFIED_DEFAULT_BUILDINGS,
                globalSettings: payload.global_settings || {},
                tankSettingsHistory: payload.tank_settings_history || [],
                customQCLimits: payload.custom_qc_limits || {}
            });

            // Chunk transactions so Firestore 1 MiB document cap is never reached
            const txs = Array.isArray(payload.liquor_transactions) ? payload.liquor_transactions : [];
            const chunkCount = Math.max(1, Math.ceil(txs.length / TX_CHUNK_SIZE));
            for (let i = 0; i < chunkCount; i++) {
                const slice = txs.slice(i * TX_CHUNK_SIZE, (i + 1) * TX_CHUNK_SIZE);
                await docRef.collection('chunks').doc(`chunk_${i}`).set({
                    chunkIndex: i,
                    transactions: slice,
                    updatedAt: payload.updatedAt
                });
            }
            // Remove stale extra live chunks only (preserve snap_* rollback snapshot chunks)
            const existingChunks = await docRef.collection('chunks').get();
            const deletePromises = [];
            existingChunks.forEach(doc => {
                const idx = doc.data()?.chunkIndex;
                if (doc.id.startsWith('chunk_') && typeof idx === 'number' && idx >= chunkCount) {
                    deletePromises.push(doc.ref.delete());
                }
            });
            if (deletePromises.length) await Promise.all(deletePromises);

            lastSnapshotSyncAt = new Date().toISOString();
            cloudStatus = 'online';
            cloudStatusNote = `ซิงค์ DB & Snapshot ล่าสุด (${new Date(lastSnapshotSyncAt).toLocaleTimeString('th-TH')})`;
            updateCloudBadgeUI();
            return true;
        } catch (err) {
            console.warn('Cloud save warning:', err);
            cloudStatus = 'offline';
            cloudStatusNote = 'บันทึกในแคชเครื่อง (รอซิงค์ออนไลน์ใหม่)';
            updateCloudBadgeUI();
            return false;
        }
    }

    function scheduleCloudSync() {
        const factoryId = getActiveFactoryId();
        if (!factoryId) return;
        const payload = readWorkingPayload(factoryId);
        payload.initialized = true; // Any active save implies initialized factory workspace
        payload.updatedAt = new Date().toISOString();
        writeTenantLocalPayload(factoryId, payload);

        cloudStatus = 'syncing';
        cloudStatusNote = 'กำลังซิงค์ Snapshot ลงฐานข้อมูล...';
        updateCloudBadgeUI();

        if (cloudSyncTimer) clearTimeout(cloudSyncTimer);
        cloudSyncTimer = setTimeout(() => {
            saveFactoryToCloudNow(factoryId, readTenantLocalPayload(factoryId));
            refreshMobileShellData();
        }, 120);
    }

    function subscribeFactoryRealtime(factoryId) {
        if (unsubscribeFactorySnap) {
            try { unsubscribeFactorySnap(); } catch (e) { }
            unsubscribeFactorySnap = null;
        }
        if (!fbDb || !fbAuth || !fbAuth.currentUser) return;

        let initialFired = false;
        unsubscribeFactorySnap = fbDb.collection('factories').doc(factoryId).onSnapshot(async (snap) => {
            if (!initialFired) { initialFired = true; return; }
            if (!snap.exists) return;
            const d = snap.data() || {};
            const localMeta = readTenantLocalPayload(factoryId);
            // Only pull if updated externally (e.g. another tab/device) and newer
            if (Date.parse(d.updatedAt || '0') > Date.parse(localMeta.updatedAt || '0') + 1500) {
                const fresh = await loadFactoryFromCloud(factoryId);
                applyPayloadToWorkingLocalStorage(fresh);
                triggerHostPageReload();
                refreshMobileShellData();
            }
        }, () => { });
    }

    function payloadsEqual(a, b) {
        if (!a || !b) return false;
        for (const k of TENANT_KEYS) {
            if (JSON.stringify(a[k] ?? null) !== JSON.stringify(b[k] ?? null)) return false;
        }
        return true;
    }

    async function recordWorkspaceChangeLog(factoryId, prevPayload, nextPayload) {
        if (!factoryId || !prevPayload || !nextPayload) return null;
        if (payloadsEqual(prevPayload, nextPayload)) return null;

        const prevTxs = Array.isArray(prevPayload.liquor_transactions) ? prevPayload.liquor_transactions : [];
        const nextTxs = Array.isArray(nextPayload.liquor_transactions) ? nextPayload.liquor_transactions : [];
        const prevMap = new Map(prevTxs.map(t => [String(t.id), t]));
        const nextMap = new Map(nextTxs.map(t => [String(t.id), t]));

        const addedTxs = nextTxs.filter(t => !prevMap.has(String(t.id)));
        const removedTxs = prevTxs.filter(t => !nextMap.has(String(t.id)));
        const modifiedTxs = nextTxs.filter(t => {
            const old = prevMap.get(String(t.id));
            return old && JSON.stringify(old) !== JSON.stringify(t);
        });

        const settingDiffs = [];
        if (JSON.stringify(prevPayload.tank_config || {}) !== JSON.stringify(nextPayload.tank_config || {})) settingDiffs.push('สถานะถัง');
        if (JSON.stringify(prevPayload.custom_tanks || []) !== JSON.stringify(nextPayload.custom_tanks || [])) settingDiffs.push('รายการถัง');
        if (JSON.stringify(prevPayload.custom_buildings || {}) !== JSON.stringify(nextPayload.custom_buildings || {})) settingDiffs.push('อาคาร');
        if (JSON.stringify(prevPayload.global_settings || {}) !== JSON.stringify(nextPayload.global_settings || {})) settingDiffs.push('ความจุ/ตั้งค่ากลาง');
        if (JSON.stringify(prevPayload.planning_data || {}) !== JSON.stringify(nextPayload.planning_data || {})) settingDiffs.push('แผนผลิต');
        if (JSON.stringify(prevPayload.active_tanks || {}) !== JSON.stringify(nextPayload.active_tanks || {})) settingDiffs.push('ถังใช้งานหลัก');
        if (JSON.stringify(prevPayload.custom_qc_limits || {}) !== JSON.stringify(nextPayload.custom_qc_limits || {})) settingDiffs.push('เกณฑ์ QC');

        let action = 'DATA_UPDATE';
        let category = 'data';
        let actionLabel = 'อัปเดตข้อมูลคลัง';
        const parts = [];

        if (prevTxs.length > 0 && nextTxs.length === 0 && addedTxs.length === 0 && settingDiffs.includes('รายการถัง')) {
            action = 'SYSTEM_RESET';
            category = 'data';
            actionLabel = 'ล้างข้อมูลโรงงาน';
            parts.push(`ล้างรายการเดินบัญชีทั้งหมด ${prevTxs.length} รายการ และตั้งค่าถังกลับค่าเริ่มต้น`);
        } else if (addedTxs.length > 3 && removedTxs.length >= 0 && settingDiffs.length >= 2) {
            action = 'DATA_IMPORT';
            category = 'data';
            actionLabel = 'นำเข้าไฟล์สำรองข้อมูล';
            parts.push(`นำเข้ารายการเคลื่อนไหวรวม ${nextTxs.length} รายการ (จากเดิม ${prevTxs.length} รายการ)`);
        } else if (addedTxs.length > 0 && removedTxs.length === 0 && modifiedTxs.length === 0) {
            const first = addedTxs[0];
            const totalAddVol = addedTxs.reduce((s, x) => s + (parseFloat(x.volume ?? x.vol ?? 0) || 0), 0);
            const tType = String(first.type || '').toUpperCase();
            category = 'tx';
            if (addedTxs.length === 1) {
                if (tType === 'BLEND_IN' || tType === 'BLEND_OUT') {
                    action = 'TX_BLEND';
                    actionLabel = 'บันทึกปรุงสุรา';
                } else if (tType.includes('TRANSFER')) {
                    action = 'TX_TRANSFER';
                    actionLabel = 'บันทึกโอนย้ายถัง';
                } else if (tType.includes('OUT')) {
                    action = 'TX_ISSUE_OUT';
                    actionLabel = 'บันทึกจ่ายออกสุรา';
                } else {
                    action = 'TX_RECEIVE_IN';
                    actionLabel = 'บันทึกรับเข้าสุรา';
                }
                parts.push(`ถัง ${first.tankId || '-'} (${tType || 'TX'}) ปริมาณ ${totalAddVol.toLocaleString(undefined, { maximumFractionDigits: 1 })} L${first.batch ? ' • Batch ' + first.batch : ''}`);
            } else {
                const hasTransfer = addedTxs.every(t => String(t.type || '').toUpperCase().includes('TRANSFER'));
                const hasBlend = addedTxs.some(t => String(t.type || '').toUpperCase().includes('BLEND'));
                action = hasBlend ? 'TX_BLEND' : (hasTransfer ? 'TX_TRANSFER' : 'TX_BATCH_ADD');
                actionLabel = hasBlend ? 'บันทึกปรุงสุรา' : (hasTransfer ? 'บันทึกโอนย้ายสุรา' : `เพิ่มรายการสุรา ${addedTxs.length} รายการ`);
                const tanksStr = [...new Set(addedTxs.map(x => x.tankId).filter(Boolean))].slice(0, 4).join(', ');
                parts.push(`เพิ่ม ${addedTxs.length} รายการ${tanksStr ? ' (ถัง ' + tanksStr + ')' : ''}`);
            }
        } else if (removedTxs.length > 0 && addedTxs.length === 0 && modifiedTxs.length === 0) {
            category = 'tx';
            action = 'TX_DELETE';
            actionLabel = removedTxs.length === 1 ? 'ลบรายการเคลื่อนไหว' : `ลบ ${removedTxs.length} รายการเคลื่อนไหว`;
            const totalDelVol = removedTxs.reduce((s, x) => s + (parseFloat(x.volume ?? x.vol ?? 0) || 0), 0);
            const r0 = removedTxs[0];
            parts.push(`ลบ${removedTxs.length === 1 ? `ถัง ${r0.tankId || '-'} (${r0.type || '-'})` : ` ${removedTxs.length} รายการ`} ปริมาณ ${totalDelVol.toLocaleString(undefined, { maximumFractionDigits: 1 })} L`);
        } else if (modifiedTxs.length > 0 && addedTxs.length === 0 && removedTxs.length === 0) {
            category = 'tx';
            action = 'TX_EDIT';
            actionLabel = 'แก้ไขรายการเคลื่อนไหว';
            parts.push(`แก้ไขข้อมูล ${modifiedTxs.length} รายการ (ถัง ${modifiedTxs[0].tankId || '-'})`);
        } else if (addedTxs.length > 0 || removedTxs.length > 0 || modifiedTxs.length > 0) {
            category = 'tx';
            action = 'TX_RECONCILE_OR_BULK';
            actionLabel = 'ปรับปรุง/รับ-จ่ายรายการคลัง';
            parts.push(`เพิ่ม ${addedTxs.length}, ลบ ${removedTxs.length}, แก้ไข ${modifiedTxs.length} รายการ`);
        } else if (settingDiffs.length > 0) {
            category = 'settings';
            action = settingDiffs.includes('เกณฑ์ QC') ? 'QC_LIMITS_UPDATE' : 'MASTER_SETTINGS_UPDATE';
            actionLabel = 'แก้ไขตั้งค่าระบบ';
        }

        if (settingDiffs.length > 0) {
            parts.push(`เปลี่ยน: ${settingDiffs.join(', ')}`);
        }

        const affectedTxIds = [
            ...addedTxs.map(t => t.id),
            ...removedTxs.map(t => t.id),
            ...modifiedTxs.map(t => t.id)
        ].filter(id => id !== undefined && id !== null).slice(0, 20);

        return writeAuditLog(action, factoryId, {
            category,
            actionLabel,
            summaryText: parts.join(' • ') || 'บันทึกการเปลี่ยนแปลงข้อมูลคลัง',
            beforePayload: prevPayload,
            afterPayload: nextPayload,
            canRollback: true,
            extra: affectedTxIds.length ? { affectedTxIds } : undefined
        });
    }

    async function flushPendingWorkspaceDiff(explicitFactoryId) {
        if (pendingDiffTimer) {
            clearTimeout(pendingDiffTimer);
            pendingDiffTimer = null;
        }
        const fId = explicitFactoryId || getActiveFactoryId();
        if (!fId || !pendingDiffBeforeMap[fId]) return;
        const prevPayload = pendingDiffBeforeMap[fId];
        delete pendingDiffBeforeMap[fId];
        const nextPayload = clonePayloadSnapshot(readTenantLocalPayload(fId));
        await recordWorkspaceChangeLog(fId, prevPayload, nextPayload);
    }

    function subscribeAdminAuditLogsRealtime() {
        if (unsubscribeAuditLogsSnap) {
            try { unsubscribeAuditLogsSnap(); } catch (e) { }
            unsubscribeAuditLogsSnap = null;
        }
        const session = getSession();
        if (!session || session.role !== 'admin') return;
        if (!fbDb || !fbAuth || !fbAuth.currentUser) return;

        let initialDone = false;
        unsubscribeAuditLogsSnap = fbDb.collection('auditLogs')
            .orderBy('timestamp', 'desc')
            .limit(120)
            .onSnapshot((snap) => {
                if (!initialDone) {
                    const logs = readLocalAuditLogs();
                    const map = new Map(logs.map(l => [l.id, l]));
                    snap.forEach(doc => {
                        const d = doc.data() || {};
                        map.set(doc.id, { id: doc.id, ...d });
                    });
                    saveLocalAuditLogs(Array.from(map.values()));
                    initialDone = true;
                    if (!document.getElementById('adminAuditLogsModal')?.classList.contains('hidden')) {
                        renderAdminLogsModal();
                    }
                    return;
                }
                snap.docChanges().forEach(change => {
                    if (change.type === 'added' || change.type === 'modified') {
                        const d = change.doc.data() || {};
                        const entry = { id: change.doc.id, ...d };
                        const existed = readLocalAuditLogs().some(x => x.id === entry.id);
                        handleIncomingAuditLog(entry, change.type === 'added' && !existed);
                    }
                });
            }, () => { });
    }

    async function adminRollbackFactory(logId, mode = 'after', skipConfirm = false) {
        const session = getSession();
        if (!session || session.role !== 'admin') {
            throw new Error('สิทธิ์เฉพาะ Admin เท่านั้น');
        }
        const logs = readLocalAuditLogs();
        const entry = logs.find(x => x.id === logId);
        if (!entry) throw new Error('ไม่พบรายการ Log ที่ต้องการย้อนกลับ');
        const targetFactory = entry.target || '';
        if (!targetFactory || targetFactory === 'admin') {
            throw new Error('รายการนี้ไม่มีข้อมูลคลังโรงงานสำหรับย้อนกลับ');
        }

        // Preserve any currently open factory's working data cleanly before touching targetFactory
        const activeBeforeRollback = getActiveFactoryId();
        if (activeBeforeRollback && activeBeforeRollback !== targetFactory) {
            writeTenantLocalPayload(activeBeforeRollback, readWorkingPayload(activeBeforeRollback));
        }

        const currentBefore = clonePayloadSnapshot(
            activeBeforeRollback === targetFactory
                ? readWorkingPayload(targetFactory)
                : await loadFactoryFromCloud(targetFactory)
        );
        const currStats = computeFactoryAnalytics(currentBefore);
        const lbl = (entry.details && entry.details.actionLabel) || entry.action;

        let targetSnapshot = null;
        let modeLabel = '';

        if (mode === 'single_tx') {
            const idsSet = new Set(((entry.details && entry.details.affectedTxIds) || []).map(x => String(x)));
            if (!idsSet.size) {
                throw new Error('Log รายการนี้ไม่มี ID รายการย่อยสำหรับย้อนเฉพาะรายการ');
            }
            const beforeSnap = await loadSnapshotPayload(entry, 'before');
            const afterSnap = await loadSnapshotPayload(entry, 'after');
            if (!beforeSnap && !afterSnap) {
                throw new Error('ไม่พบ Snapshot สำหรับจุดเวลานี้ในระบบ');
            }
            const merged = clonePayloadSnapshot(currentBefore);
            const currentTxs = Array.isArray(merged.liquor_transactions) ? [...merged.liquor_transactions] : [];
            const beforeMap = new Map((beforeSnap?.liquor_transactions || []).map(t => [String(t.id), t]));
            idsSet.forEach(idStr => {
                const idx = currentTxs.findIndex(t => String(t.id) === idStr);
                if (beforeMap.has(idStr)) {
                    const prevItem = JSON.parse(JSON.stringify(beforeMap.get(idStr)));
                    if (idx >= 0) currentTxs[idx] = prevItem;
                    else currentTxs.push(prevItem);
                } else if (idx >= 0) {
                    currentTxs.splice(idx, 1);
                }
            });
            merged.liquor_transactions = currentTxs;
            targetSnapshot = merged;
            modeLabel = `ย้อนกลับเฉพาะรายการ ID: ${Array.from(idsSet).join(', ')}`;
        } else {
            targetSnapshot = await loadSnapshotPayload(entry, mode);
            if (!targetSnapshot) {
                throw new Error('ไม่พบ Snapshot สำหรับจุดเวลานี้ในระบบ');
            }
            modeLabel = mode === 'before' ? 'ย้อนกลับไปก่อนทำรายการนี้ (Undo)' : 'ย้อนข้อมูลไปยังสถานะ ณ จุดเวลานี้ (Restore)';
        }

        const snapStats = computeFactoryAnalytics(targetSnapshot);

        if (!skipConfirm && typeof Swal !== 'undefined') {
            const esc = escapeHtml;
            const res = await Swal.fire({
                title: 'ยืนยันการย้อนข้อมูลเฉพาะโรงงานนี้?',
                html: `
                    <div class="text-left text-xs space-y-2.5">
                        <div class="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800">
                            <div class="font-extrabold">${esc(modeLabel)}</div>
                            <div class="mt-1">เฉพาะคลังเป้าหมาย: <b>${esc(targetFactory)}</b> (โรงงานอื่นคงไว้ตามปัจจุบัน)</div>
                            <div>อ้างอิง Log: <b>${esc(lbl)}</b> (${esc((entry.timestamp || '').replace('T', ' ').slice(0, 19))})</div>
                        </div>
                        <div class="grid grid-cols-2 gap-2">
                            <div class="p-2.5 rounded-xl bg-slate-100 border border-slate-200">
                                <div class="text-[10px] font-bold text-slate-500">ข้อมูลปัจจุบัน (${esc(targetFactory)})</div>
                                <div class="font-black text-slate-800 mt-0.5">${currStats.txCount} รายการ</div>
                                <div class="text-[11px] text-slate-600">${currStats.totalVol.toLocaleString()} L</div>
                            </div>
                            <div class="p-2.5 rounded-xl bg-emerald-50 border border-emerald-200">
                                <div class="text-[10px] font-bold text-emerald-700">หลังย้อนข้อมูล (${esc(targetFactory)})</div>
                                <div class="font-black text-emerald-800 mt-0.5">${snapStats.txCount} รายการ</div>
                                <div class="text-[11px] text-emerald-700">${snapStats.totalVol.toLocaleString()} L</div>
                            </div>
                        </div>
                        <div class="text-[11px] text-slate-500">* การย้อนข้อมูลจะจำกัดเฉพาะ ${esc(targetFactory)} เท่านั้น ไม่กระทบโรงงานอื่น</div>
                    </div>
                `,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#e11d48',
                confirmButtonText: '<i class="fas fa-history mr-1"></i> ยืนยันย้อนข้อมูล',
                cancelButtonText: 'ยกเลิก'
            });
            if (!res.isConfirmed) return false;
        }

        const restored = clonePayloadSnapshot(targetSnapshot);
        restored.username = targetFactory;
        restored.updatedAt = new Date().toISOString();
        restored.initialized = (Array.isArray(restored.liquor_transactions) && restored.liquor_transactions.length > 0) || !!targetSnapshot.initialized;

        writeTenantLocalPayload(targetFactory, restored);
        await saveFactoryToCloudNow(targetFactory, restored);

        if (getActiveFactoryId() === targetFactory) {
            isApplyingRollback = true;
            try {
                applyPayloadToWorkingLocalStorage(restored);
                triggerHostPageReload();
                refreshMobileShellData();
            } finally {
                isApplyingRollback = false;
            }
        }

        try {
            globalBcChannel?.postMessage({ type: 'DATA_UPDATED', factoryId: targetFactory });
        } catch (e) { }

        const modeTxt = mode === 'single_tx' ? 'เฉพาะ ID รายการ' : (mode === 'before' ? 'ก่อนรายการ' : 'ณ จุดเวลา');
        await writeAuditLog('ADMIN_ROLLBACK', targetFactory, {
            category: 'rollback',
            actionLabel: 'Admin ย้อนข้อมูลโรงงาน',
            summaryText: `ย้อนคลัง ${targetFactory} (${modeTxt}: ${lbl}) • รายการ ${currStats.txCount} → ${snapStats.txCount}`,
            beforePayload: currentBefore,
            afterPayload: restored,
            canRollback: true,
            extra: { refLogId: entry.id, rollbackMode: mode }
        });

        renderAdminLogsModal();
        if (!skipConfirm && typeof Swal !== 'undefined') {
            Swal.fire('ย้อนข้อมูลสำเร็จ!', `โรงงาน ${targetFactory} ถูกย้อนข้อมูลกลับไปมี ${snapStats.txCount} รายการ (${snapStats.totalVol.toLocaleString()} L) แล้ว โดยโรงงานอื่นยังเป็นข้อมูลปัจจุบัน`, 'success');
        }
        return true;
    }

    async function clearAuditLogsByPeriod(periodType = 'month', explicitPeriod = null, skipConfirm = false) {
        const session = getSession();
        if (!session || session.role !== 'admin') {
            throw new Error('สิทธิ์เฉพาะ Admin เท่านั้น');
        }
        let prefix = explicitPeriod ? String(explicitPeriod).trim() : '';
        if (!prefix) {
            prefix = periodType === 'year'
                ? (document.getElementById('adminClearLogsYear')?.value || '')
                : (document.getElementById('adminClearLogsMonth')?.value || '');
        }
        if (!prefix) {
            if (typeof Swal !== 'undefined') Swal.fire('กรุณาเลือกช่วงเวลา', 'เลือกเดือนหรือปีที่ต้องการล้างประวัติ Logs ก่อนดำเนินการ', 'warning');
            return 0;
        }
        const fUser = document.getElementById('adminLogFilterUser')?.value || 'ALL';
        const allLogs = readLocalAuditLogs();
        const matches = allLogs.filter(l => {
            const ts = String(l.timestamp || '');
            if (!ts.startsWith(prefix)) return false;
            if (fUser !== 'ALL' && l.actor !== fUser && l.target !== fUser) return false;
            return true;
        });

        if (!matches.length) {
            if (!skipConfirm && typeof Swal !== 'undefined') {
                Swal.fire('ไม่พบ Logs ที่ตรงเงื่อนไข', `ไม่มีประวัติการใช้งานในช่วง ${prefix}${fUser !== 'ALL' ? ` ของ ${fUser}` : ''}`, 'info');
            }
            return 0;
        }

        const periodText = periodType === 'year' ? `ทั้งปี ${prefix}` : `ประจำเดือน ${prefix}`;
        if (!skipConfirm && typeof Swal !== 'undefined') {
            const esc = escapeHtml;
            const res = await Swal.fire({
                title: 'ยืนยันล้าง Logs ในระบบ?',
                html: `<div class="text-xs text-left space-y-1.5 p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800">
                    <div>ต้องการลบ Logs <b>${esc(periodText)}</b>${fUser !== 'ALL' ? ` เฉพาะ <b>${esc(fUser)}</b>` : ' ทุกโรงงาน'}</div>
                    <div>พบทั้งหมด <b>${matches.length}</b> รายการ (รวม Snapshot ที่ผูกกับ Logs ชุดนี้)</div>
                    <div class="text-[11px] text-rose-600 mt-1">* ข้อมูลสต็อกคงคลังจริงของโรงงานจะไม่ได้รับผลกระทบ</div>
                </div>`,
                icon: 'warning',
                showCancelButton: true,
                confirmButtonColor: '#dc2626',
                confirmButtonText: `ลบ ${matches.length} Logs`,
                cancelButtonText: 'ยกเลิก'
            });
            if (!res.isConfirmed) return 0;
        }

        const delIds = new Set(matches.map(m => m.id));
        const keptLogs = allLogs.filter(l => !delIds.has(l.id));
        saveLocalAuditLogs(keptLogs);

        const snapMap = readLocalSnapshotsMap();
        matches.forEach(m => { delete snapMap[m.id]; });
        try { localStorage.setItem(LOCAL_SNAPSHOTS_KEY, JSON.stringify(snapMap)); } catch (e) { }

        if (fbDb && fbAuth?.currentUser) {
            for (const m of matches) {
                try { await fbDb.collection('auditLogs').doc(m.id).delete(); } catch (e) { }
                if (m.target && m.target !== 'admin') {
                    try {
                        const chunks = await fbDb.collection('factories').doc(m.target).collection('chunks').get();
                        const p1 = `snap_${m.id}_b_`;
                        const p2 = `snap_${m.id}_a_`;
                        const ops = [];
                        chunks.forEach(doc => {
                            if (doc.id.startsWith(p1) || doc.id.startsWith(p2)) ops.push(doc.ref.delete());
                        });
                        if (ops.length) await Promise.all(ops);
                    } catch (e) { }
                }
            }
        }

        await writeAuditLog('ADMIN_CLEAR_LOGS', fUser === 'ALL' ? 'system' : fUser, {
            category: 'data',
            actionLabel: 'ล้างประวัติ Logs ตามช่วงเวลา',
            summaryText: `Admin ล้าง Logs ${periodText} (${matches.length} รายการ${fUser !== 'ALL' ? ' • ' + fUser : ''})`,
            canRollback: false
        });
        renderAdminLogsModal();
        if (!skipConfirm && typeof Swal !== 'undefined') {
            Swal.fire('ล้าง Logs สำเร็จ!', `ลบ Logs ${periodText} จำนวน ${matches.length} รายการเพื่อประหยัดพื้นที่ฐานข้อมูลแล้ว`, 'success');
        }
        return matches.length;
    }

    function triggerHostPageReload() {
        try {
            if (typeof window.reloadAllStorageData === 'function') {
                window.reloadAllStorageData();
            }
            if (typeof window.recalculateState === 'function') {
                window.recalculateState();
            }
            if (typeof window.updateAllData === 'function') {
                window.updateAllData();
            }
            if (typeof window.updateQCAlertBadges === 'function') {
                window.updateQCAlertBadges();
            }
        } catch (err) {
            console.warn('Page reload hook error:', err);
        }
    }

    async function activateWorkspace(factoryId) {
        const session = getSession();
        if (!session) return;

        // Clear any leftover working storage cleanly before loading target factory
        clearWorkingLocalStorage();

        const payload = await loadFactoryFromCloud(factoryId);
        applyPayloadToWorkingLocalStorage(payload);
        writeTenantLocalPayload(factoryId, payload);

        if (typeof window.updateBuildingDropdowns === 'function') {
            window.updateBuildingDropdowns();
        }
        triggerHostPageReload();
        subscribeFactoryRealtime(factoryId);
        startPresenceHeartbeat();
        if (session.role === 'admin') {
            subscribeAdminAuditLogsRealtime();
            subscribeUsersPresenceRealtime();
        }
        renderAuthHeaderControls();
        refreshMobileShellData();

        // First-Time Setup Check (Only prompt factory users when uninitialized; admin can click Setup if desired)
        if (!payload.initialized && session.role === 'factory') {
            openFirstTimeSetupModal(payload);
        } else {
            closeModal('firstTimeSetupModal');
        }
    }

    // =========================================================================
    // 7. HOST HOOKS (Integrate seamlessly with index.html & dashboard.html)
    // =========================================================================
    function patchHostStorageHooks() {
        const scheduleDiffLogForFactory = (fId, beforeSnap) => {
            if (!fId || !beforeSnap) return;
            if (!pendingDiffBeforeMap[fId]) pendingDiffBeforeMap[fId] = beforeSnap;
            if (pendingDiffTimer) clearTimeout(pendingDiffTimer);
            pendingDiffTimer = setTimeout(async () => {
                pendingDiffTimer = null;
                const prevPayload = pendingDiffBeforeMap[fId];
                delete pendingDiffBeforeMap[fId];
                if (!prevPayload) return;
                const nextPayload = clonePayloadSnapshot(readTenantLocalPayload(fId));
                await recordWorkspaceChangeLog(fId, prevPayload, nextPayload);
                await saveFactoryToCloudNow(fId, nextPayload);
            }, 60);
        };

        if (!window.__stockmsUnloadSyncBound) {
            window.__stockmsUnloadSyncBound = true;
            const flushImmediate = () => {
                const fId = getActiveFactoryId();
                if (!fId) return;
                const snap = readWorkingPayload(fId);
                writeTenantLocalPayload(fId, snap);
                if (cloudSyncTimer || pendingDiffBeforeMap[fId]) {
                    if (cloudSyncTimer) { clearTimeout(cloudSyncTimer); cloudSyncTimer = null; }
                    saveFactoryToCloudNow(fId, snap);
                    flushPendingWorkspaceDiff(fId);
                }
            };
            window.addEventListener('pagehide', flushImmediate);
            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'hidden') flushImmediate();
                else if (getSession()) publishUserPresence(true);
            });
        }

        if (typeof window.saveData === 'function' && !window.saveData.__stockmsWrapped) {
            const origSaveData = window.saveData;
            const wrapped = function () {
                const fId = getActiveFactoryId();
                const beforeSnap = (!isApplyingRollback && fId) ? (pendingDiffBeforeMap[fId] || clonePayloadSnapshot(readTenantLocalPayload(fId))) : null;
                const res = origSaveData.apply(this, arguments);
                try {
                    if (fId) {
                        const metaRaw = localStorage.getItem(`${TENANT_PREFIX}${fId}::__meta`);
                        const meta = metaRaw ? JSON.parse(metaRaw) : {};
                        meta.initialized = true;
                        localStorage.setItem(`${TENANT_PREFIX}${fId}::__meta`, JSON.stringify(meta));
                    }
                    scheduleCloudSync();
                    refreshMobileShellData();
                    if (!isApplyingRollback && fId && beforeSnap) {
                        scheduleDiffLogForFactory(fId, beforeSnap);
                    }
                } catch (e) { }
                return res;
            };
            wrapped.__stockmsWrapped = true;
            window.saveData = wrapped;
        }

        if (typeof window.saveCustomQCLimitsToStorage === 'function' && !window.saveCustomQCLimitsToStorage.__stockmsWrapped) {
            const origQcSave = window.saveCustomQCLimitsToStorage;
            const wrappedQc = function () {
                const fId = getActiveFactoryId();
                const beforeSnap = (!isApplyingRollback && fId) ? (pendingDiffBeforeMap[fId] || clonePayloadSnapshot(readTenantLocalPayload(fId))) : null;
                const res = origQcSave.apply(this, arguments);
                try {
                    scheduleCloudSync();
                    if (!isApplyingRollback && fId && beforeSnap) {
                        scheduleDiffLogForFactory(fId, beforeSnap);
                    }
                } catch (e) { }
                return res;
            };
            wrappedQc.__stockmsWrapped = true;
            window.saveCustomQCLimitsToStorage = wrappedQc;
        }

        // Hook BroadcastChannel scoped per active factory so multiple open browser tabs don't cross-leak factories
        if (typeof BroadcastChannel !== 'undefined' && !globalBcChannel) {
            try {
                globalBcChannel = new BroadcastChannel('blending_stock_sync');
                globalBcChannel.onmessage = (event) => {
                    const data = event.data;
                    if (!data) return;
                    if (data.type === 'AUDIT_LOG_CREATED' && data.logEntry) {
                        const s = getSession();
                        if (s && s.role === 'admin') {
                            handleIncomingAuditLog(data.logEntry, true);
                        }
                        return;
                    }
                    if (data.type === 'USER_PRESENCE_HEARTBEAT' && data.entry?.username) {
                        onlineUsersMap[data.entry.username] = data.entry;
                        renderOnlinePresenceUI();
                        return;
                    }
                    const activeId = getActiveFactoryId();
                    if (data.factoryId && activeId && data.factoryId !== activeId) {
                        return; // Ignore broadcast intended for a different factory username!
                    }
                    if (data.type === 'DATA_UPDATED' || data.type === 'QC_LIMITS_UPDATED') {
                        triggerHostPageReload();
                        refreshMobileShellData();
                    }
                };
            } catch (e) { }
        }

        if (!window.__stockmsLogsStorageListenerAttached) {
            window.__stockmsLogsStorageListenerAttached = true;
            window.addEventListener('storage', (ev) => {
                if (ev.key === LOCAL_AUDIT_LOGS_KEY) {
                    const s = getSession();
                    if (s && s.role === 'admin') {
                        const newest = readLocalAuditLogs()[0];
                        if (newest) handleIncomingAuditLog(newest, true);
                    }
                }
            });
        }
    }

    // =========================================================================
    // 8. FULLSCREEN & RESPONSIVE VIEWPORT CONTROLS
    // =========================================================================
    function toggleAppFullscreen() {
        const doc = document;
        const docEl = doc.documentElement;
        const isFs = !!(doc.fullscreenElement || doc.webkitFullscreenElement || doc.msFullscreenElement);
        try {
            if (!isFs) {
                if (docEl.requestFullscreen) docEl.requestFullscreen();
                else if (docEl.webkitRequestFullscreen) docEl.webkitRequestFullscreen();
                else if (docEl.msRequestFullscreen) docEl.msRequestFullscreen();
            } else {
                if (doc.exitFullscreen) doc.exitFullscreen();
                else if (doc.webkitExitFullscreen) doc.webkitExitFullscreen();
                else if (doc.msExitFullscreen) doc.msExitFullscreen();
            }
        } catch (err) {
            if (typeof Swal !== 'undefined') {
                Swal.fire('ไม่สามารถขยายเต็มจอได้', 'เบราว์เซอร์นี้อาจจำกัดโหมดเต็มจอ กรุณากด F11', 'info');
            }
        }
    }
    window.toggleAppFullscreen = toggleAppFullscreen;

    document.addEventListener('fullscreenchange', updateFullscreenButtonState);
    document.addEventListener('webkitfullscreenchange', updateFullscreenButtonState);

    function updateFullscreenButtonState() {
        const isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
        document.querySelectorAll('.stockms-fs-icon').forEach(icon => {
            icon.className = `fas ${isFs ? 'fa-compress' : 'fa-expand'} stockms-fs-icon`;
        });
        document.querySelectorAll('.stockms-fs-label').forEach(lbl => {
            lbl.textContent = isFs ? 'ย่อจอ' : 'เต็มจอ';
        });
    }

    function toggleMobileAppLayout(forceDesktop) {
        if (forceDesktop === true) {
            document.body.classList.add('kosmate-force-desktop');
            document.body.classList.remove('kosmate-force-mobile', 'kosmate-tab-active');
        } else if (forceDesktop === false) {
            document.body.classList.remove('kosmate-force-desktop');
            document.body.classList.add('kosmate-force-mobile');
            switchMobileTab('home');
        } else {
            const isMobileNow = document.body.classList.contains('kosmate-force-mobile') || (window.innerWidth <= 900 && !document.body.classList.contains('kosmate-force-desktop'));
            toggleMobileAppLayout(isMobileNow);
        }
    }
    window.toggleMobileAppLayout = toggleMobileAppLayout;

    // =========================================================================
    // 9. AUTHENTICATION HANDLERS (Login, Logout, Self-Service Password, Admin)
    // =========================================================================
    async function performLogin(usernameRaw, plainPassword, rememberMe) {
        const username = parseUsername(usernameRaw);
        if (!username || !plainPassword) {
            throw new Error('กรุณากรอก Username และ Password ให้ครบถ้วน');
        }

        const reg = getLocalUsersRegistry();
        let localRecord = reg[username];

        // Establish Firebase Email/Password Auth session first so Firestore rules allow /users read
        const authRes = await authenticateFirebaseUser(username, plainPassword, localRecord?.authVersion || 1, localRecord);

        let cloudUserDoc = null;
        if (fbDb && authRes.ok) {
            try {
                const snap = await fbDb.collection('users').doc(username).get();
                if (snap.exists) cloudUserDoc = snap.data();
            } catch (e) {
                console.info('User doc fetch skipped:', e.code || e.message);
            }
        }

        const effectiveUser = cloudUserDoc || localRecord;
        if (!effectiveUser) {
            if (fbAuth && authRes.ok) { try { await fbAuth.signOut(); } catch (e) { } }
            throw new Error('ชื่อผู้ใช้งานหรือรหัสผ่านไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง');
        }
        if (effectiveUser.active === false) {
            if (fbAuth && authRes.ok) { try { await fbAuth.signOut(); } catch (e) { } }
            throw new Error('บัญชีผู้ใช้งานนี้ถูกระงับการใช้งาน');
        }

        const candidateHash = hashPasswordWithSalt(plainPassword, effectiveUser.salt);
        if (candidateHash !== effectiveUser.passwordHash) {
            if (fbAuth && authRes.ok) { try { await fbAuth.signOut(); } catch (e) { } }
            throw new Error('ชื่อผู้ใช้งานหรือรหัสผ่านไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง');
        }

        // Upgrade versioned Email/Password Firebase Auth when cloud doc carries newer authVersion
        if (fbAuth && authRes.ok && (Number(effectiveUser.authVersion) || 1) !== (Number(authRes.resolvedAuthVersion) || 1)) {
            const verEmail = buildAuthEmail(username, effectiveUser.authVersion || 1);
            const verPass = deriveFirebaseAuthSecret(username, plainPassword);
            try {
                const upgraded = await fbAuth.signInWithEmailAndPassword(verEmail, verPass);
                authRes.uid = upgraded.user.uid;
                authRes.mode = 'email-versioned';
            } catch (upErr) { /* Keep current authenticated email session */ }
        }

        // Sync verified record back to local registry & cloud binding
        reg[username] = effectiveUser;
        saveLocalUsersRegistry(reg);

        sessionStorage.removeItem('qc_power_user');
        const sessionObj = {
            username: effectiveUser.username,
            displayName: effectiveUser.displayName || effectiveUser.username,
            role: effectiveUser.role || 'factory',
            activeFactory: effectiveUser.role === 'admin' ? (localStorage.getItem('stockms_admin_last_factory') || 'ms-ssd') : effectiveUser.username,
            authUid: authRes.uid || '',
            loginAt: new Date().toISOString()
        };
        saveSession(sessionObj, rememberMe);

        if (fbDb && authRes.ok && authRes.uid) {
            const nowIso = sessionObj.loginAt;
            try {
                if (cloudUserDoc) {
                    const userPatch = {
                        authUid: authRes.uid,
                        onlineStatus: true,
                        lastSeenAt: nowIso,
                        updatedAt: nowIso
                    };
                    if (!cloudUserDoc.authEmail) {
                        userPatch.authEmail = effectiveUser.authEmail || buildAuthEmail(username, effectiveUser.authVersion || 1);
                    }
                    if (!cloudUserDoc.authVersion) {
                        userPatch.authVersion = Number(effectiveUser.authVersion) || 1;
                    }
                    await fbDb.collection('users').doc(username).set(userPatch, { merge: true });
                } else {
                    const userPayload = {
                        username: effectiveUser.username,
                        displayName: effectiveUser.displayName || effectiveUser.username,
                        role: effectiveUser.role || 'factory',
                        passwordHash: effectiveUser.passwordHash,
                        salt: effectiveUser.salt,
                        authUid: authRes.uid,
                        authEmail: effectiveUser.authEmail || buildAuthEmail(username, effectiveUser.authVersion || 1),
                        authVersion: Number(effectiveUser.authVersion) || 1,
                        active: effectiveUser.active !== false,
                        onlineStatus: true,
                        lastSeenAt: nowIso,
                        createdAt: effectiveUser.createdAt || nowIso,
                        updatedAt: nowIso,
                        createdBy: effectiveUser.createdBy || 'system'
                    };
                    await fbDb.collection('users').doc(username).set(userPayload);
                }
            } catch (e) { console.warn('User profile sync note:', e.code || e.message); }
            if (effectiveUser.role === 'admin') {
                await ensureSeedUsersInFirestore();
            }
        }
        saveLocalPresenceEntry(sessionObj.username, sessionObj.displayName, sessionObj.role, sessionObj.activeFactory, true);
        await writeAuditLog('LOGIN', username, {
            category: 'auth',
            actionLabel: 'เข้าสู่ระบบ',
            summaryText: `ผู้ใช้ ${effectiveUser.displayName || username} (${username}) เข้าสู่ระบบ (${authRes.mode === 'local' ? 'แคชเครื่อง' : 'Cloud'})`,
            canRollback: false
        });

        document.body.classList.remove('stockms-locked');
        document.getElementById('authLoginOverlay')?.classList.add('hidden');
        await activateWorkspace(getActiveFactoryId());
    }

    async function performLogout() {
        const session = getSession();
        const activeFactory = getActiveFactoryId();
        await flushPendingWorkspaceDiff(activeFactory);
        if (cloudSyncTimer) {
            clearTimeout(cloudSyncTimer);
            cloudSyncTimer = null;
        }
        if (activeFactory) {
            await saveFactoryToCloudNow(activeFactory, readWorkingPayload(activeFactory));
        }
        if (unsubscribeFactorySnap) {
            try { unsubscribeFactorySnap(); } catch (e) { }
            unsubscribeFactorySnap = null;
        }
        if (unsubscribeAuditLogsSnap) {
            try { unsubscribeAuditLogsSnap(); } catch (e) { }
            unsubscribeAuditLogsSnap = null;
        }
        await publishUserPresence(false);
        stopPresenceHeartbeat();
        await writeAuditLog('LOGOUT', session?.username || 'unknown', {
            category: 'auth',
            actionLabel: 'ออกจากระบบ',
            summaryText: `ผู้ใช้ ${session?.username || '-'} ออกจากระบบ`,
            canRollback: false
        });
        if (fbAuth) {
            try { await fbAuth.signOut(); } catch (e) { }
        }
        ['firstTimeSetupModal', 'changePasswordModal', 'adminUserManagerModal', 'adminCompareModal',
            'adminAuditLogsModal', 'reconcileModal', 'dailyReportModal', 'stockLayoutModal',
            'masterSetupModal', 'auditReportModal', 'qcAnomalyModal'].forEach(id => {
                document.getElementById(id)?.classList.add('hidden');
            });
        document.querySelectorAll('.stockms-modal-backdrop').forEach(el => el.classList.add('hidden'));
        if (typeof Swal !== 'undefined' && typeof Swal.close === 'function') {
            try { Swal.close(); } catch (e) { }
        }

        clearSession();
        clearWorkingLocalStorage();
        triggerHostPageReload();

        document.body.classList.add('stockms-locked');
        showLoginOverlay();
    }
    window.stockmsLogout = performLogout;

    async function changeOwnPassword(currentPwd, newPwd, confirmPwd) {
        const session = getSession();
        if (!session) return;
        if (!currentPwd || !newPwd || !confirmPwd) throw new Error('กรุณากรอกข้อมูลให้ครบทุกช่อง');
        if (newPwd !== confirmPwd) throw new Error('รหัสผ่านใหม่และการยืนยันไม่ตรงกัน');
        if (newPwd.length < 4) throw new Error('รหัสผ่านใหม่ต้องมีอย่างน้อย 4 ตัวอักษร');

        const reg = getLocalUsersRegistry();
        let userDoc = reg[session.username];
        if (fbDb && fbAuth?.currentUser) {
            try {
                const snap = await fbDb.collection('users').doc(session.username).get();
                if (snap.exists) userDoc = snap.data();
            } catch (e) { }
        }
        if (!userDoc) throw new Error('ไม่พบข้อมูลบัญชี');

        const checkHash = hashPasswordWithSalt(currentPwd, userDoc.salt);
        if (checkHash !== userDoc.passwordHash) {
            throw new Error('รหัสผ่านปัจจุบันไม่ถูกต้อง');
        }

        const newSalt = generateSalt(session.username);
        const newHash = hashPasswordWithSalt(newPwd, newSalt);
        const newAuthPass = deriveFirebaseAuthSecret(session.username, newPwd);

        // Update Firebase Auth user password if signed in with non-anonymous email auth
        if (fbAuth && fbAuth.currentUser && !fbAuth.currentUser.isAnonymous) {
            try {
                await fbAuth.currentUser.updatePassword(newAuthPass);
            } catch (e) {
                console.info('Firebase Auth updatePassword skipped:', e.code);
            }
        }

        const updatedDoc = {
            ...userDoc,
            salt: newSalt,
            passwordHash: newHash,
            updatedAt: new Date().toISOString(),
            passwordChangedByUserAt: new Date().toISOString()
        };
        reg[session.username] = updatedDoc;
        saveLocalUsersRegistry(reg);

        if (fbDb && fbAuth?.currentUser) {
            try {
                await fbDb.collection('users').doc(session.username).set(updatedDoc, { merge: true });
            } catch (e) {
                console.info('Cloud user update skipped:', e.code || e.message);
            }
        }
        await writeAuditLog('PASSWORD_CHANGE_SELF', session.username, {
            category: 'auth',
            actionLabel: 'เปลี่ยนรหัสผ่านเอง',
            summaryText: `ผู้ใช้ ${session.username} เปลี่ยนรหัสผ่านด้วยตนเอง`,
            canRollback: false
        });
    }

    async function adminCreateOrResetUser({ usernameRaw, displayName, password, role, isEdit }) {
        const session = getSession();
        if (!session || session.role !== 'admin') {
            throw new Error('สิทธิ์เฉพาะ Admin เท่านั้น');
        }
        const username = parseUsername(usernameRaw);
        if (!username) throw new Error('Username ต้องเป็นตัวอักษรภาษาอังกฤษ ตัวเลข หรือขีด (-) เท่านั้น');
        if (!password || password.length < 4) throw new Error('รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร');

        const reg = getLocalUsersRegistry();
        const existing = reg[username];
        if (!isEdit && existing) {
            throw new Error(`Username "${username}" มีอยู่ในระบบแล้ว (หากต้องการเปลี่ยนรหัสผ่าน ให้กดปุ่มรีเซ็ตรหัสผ่าน)`);
        }

        const nextVersion = existing ? ((Number(existing.authVersion) || 1) + 1) : 1;
        const salt = generateSalt(username);
        const passwordHash = hashPasswordWithSalt(password, salt);
        const authEmail = buildAuthEmail(username, nextVersion);
        const derivedAuthPwd = deriveFirebaseAuthSecret(username, password);
        let assignedUid = existing?.authUid || '';

        // Provision Firebase Auth credential on secondary app so Admin stays logged in!
        try {
            const secAuth = getSecondaryAuth();
            if (secAuth) {
                const cred = await secAuth.createUserWithEmailAndPassword(authEmail, derivedAuthPwd);
                assignedUid = cred.user.uid;
                await secAuth.signOut();
            }
        } catch (e) {
            console.info('Secondary Firebase Auth provision note:', e.code || e.message);
        }

        const userDoc = {
            username,
            displayName: (displayName || existing?.displayName || `โรงงาน ${username.toUpperCase()}`).trim(),
            role: existing?.role === 'admin' && username === 'admin' ? 'admin' : (role || existing?.role || 'factory'),
            salt,
            passwordHash,
            authVersion: nextVersion,
            authEmail,
            authUid: assignedUid,
            active: true,
            createdAt: existing?.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            createdBy: session.username
        };

        reg[username] = userDoc;
        saveLocalUsersRegistry(reg);

        if (fbDb && fbAuth?.currentUser) {
            try {
                await fbDb.collection('users').doc(username).set(userDoc, { merge: true });
                // Ensure factory doc exists for factory users
                if (userDoc.role === 'factory') {
                    const fRef = fbDb.collection('factories').doc(username);
                    const fSnap = await fRef.get();
                    if (!fSnap.exists) {
                        const initPayload = getDefaultFactoryPayload(username, userDoc.displayName);
                        await fRef.set({
                            username,
                            factoryName: userDoc.displayName,
                            initialized: false,
                            updatedAt: userDoc.updatedAt,
                            updatedBy: session.username,
                            summary: computeFactoryAnalytics(initPayload),
                            tankConfig: {},
                            activeTanks: initPayload.active_tanks,
                            planningData: initPayload.planning_data,
                            customTanks: initPayload.custom_tanks,
                            customBuildings: initPayload.custom_buildings,
                            globalSettings: initPayload.global_settings,
                            tankSettingsHistory: [],
                            customQCLimits: {}
                        });
                    }
                }
            } catch (e) {
                console.info('Cloud user provision skipped:', e.code || e.message);
            }
        }
        await writeAuditLog(isEdit ? 'ADMIN_RESET_PASSWORD' : 'ADMIN_CREATE_USER', username, {
            category: 'auth',
            actionLabel: isEdit ? 'Admin รีเซ็ตรหัสผ่าน' : 'Admin สร้างบัญชีใหม่',
            summaryText: `${isEdit ? 'รีเซ็ตรหัสผ่าน' : 'สร้างบัญชี'} ${username} (${userDoc.displayName}, Role: ${userDoc.role})`,
            canRollback: false
        });
        await renderAuthHeaderControls();
    }

    async function loadAllUsersList() {
        const reg = getLocalUsersRegistry();
        if (fbDb && fbAuth?.currentUser) {
            try {
                const snap = await fbDb.collection('users').get();
                snap.forEach(doc => {
                    const d = doc.data();
                    if (d && d.username) reg[d.username] = d;
                });
                saveLocalUsersRegistry(reg);
            } catch (e) { }
        }
        return Object.values(reg).sort((a, b) => {
            if (a.role === 'admin' && b.role !== 'admin') return -1;
            if (b.role === 'admin' && a.role !== 'admin') return 1;
            return a.username.localeCompare(b.username);
        });
    }

    async function loadAllFactoriesComparison() {
        const users = await loadAllUsersList();
        const factoryUsers = users.filter(u => u.role !== 'admin');
        const results = [];

        let cloudFactoriesMap = {};
        if (fbDb && fbAuth?.currentUser) {
            try {
                const snap = await fbDb.collection('factories').get();
                snap.forEach(doc => { cloudFactoriesMap[doc.id] = doc.data(); });
            } catch (e) { }
        }

        for (const u of factoryUsers) {
            const cDoc = cloudFactoriesMap[u.username];
            const activeNow = getActiveFactoryId();
            let analytics;
            if (activeNow === u.username) {
                const livePayload = readWorkingPayload(u.username);
                analytics = computeFactoryAnalytics(livePayload);
            } else if (cDoc && cDoc.summary) {
                analytics = {
                    ...cDoc.summary,
                    username: u.username,
                    factoryName: u.displayName || cDoc.factoryName || u.username,
                    initialized: !!cDoc.initialized,
                    updatedAt: cDoc.updatedAt || null
                };
            } else {
                const localPayload = readTenantLocalPayload(u.username);
                analytics = computeFactoryAnalytics(localPayload);
                analytics.factoryName = u.displayName || analytics.factoryName;
            }
            const insight = generateFactoryRecommendations(analytics);
            results.push({ user: u, analytics, insight });
        }
        return results;
    }

    // Exported helper so dashboard.html togglePowerUser replaces hardcoded 'superadmin' ([HIGH-02])
    async function verifyCurrentOrAdminPassword(inputPassword) {
        if (!inputPassword) return false;
        const session = getSession();
        const reg = getLocalUsersRegistry();
        const candidates = [];
        if (session && reg[session.username]) candidates.push(reg[session.username]);
        if (reg['admin']) candidates.push(reg['admin']);
        for (const u of candidates) {
            if (hashPasswordWithSalt(inputPassword, u.salt) === u.passwordHash) return true;
        }
        if (fbDb && fbAuth?.currentUser) {
            try {
                const aSnap = await fbDb.collection('users').doc('admin').get();
                if (aSnap.exists) {
                    const d = aSnap.data();
                    if (hashPasswordWithSalt(inputPassword, d.salt) === d.passwordHash) return true;
                }
            } catch (e) { }
        }
        return false;
    }

    window.StockMSAuth = {
        getSession,
        getActiveFactoryId,
        login: performLogin,
        logout: performLogout,
        changeOwnPassword,
        adminCreateOrResetUser,
        verifyCurrentOrAdminPassword,
        switchAdminFactory: async function (targetFactoryId) {
            const s = getSession();
            if (!s || s.role !== 'admin') return;
            const currentId = getActiveFactoryId();
            await flushPendingWorkspaceDiff(currentId);
            if (cloudSyncTimer) {
                clearTimeout(cloudSyncTimer);
                cloudSyncTimer = null;
            }
            if (currentId) await saveFactoryToCloudNow(currentId, readWorkingPayload(currentId));
            sessionStorage.removeItem('qc_power_user');
            if (typeof window.lockQCPowerUser === 'function') {
                try { window.lockQCPowerUser(true); } catch (e) { }
            }
            s.activeFactory = targetFactoryId;
            localStorage.setItem('stockms_admin_last_factory', targetFactoryId);
            saveSession(s, !!localStorage.getItem(SESSION_STORAGE_KEY));
            await activateWorkspace(targetFactoryId);
            if (typeof Swal !== 'undefined') {
                Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: `สลับมุมมองเป็นโรงงาน ${targetFactoryId}`, showConfirmButton: false, timer: 2000 });
            }
        }
    };

    window.StockMSStorage = {
        syncNow: () => saveFactoryToCloudNow(getActiveFactoryId()),
        scheduleCloudSync,
        computeFactoryAnalytics,
        loadAllFactoriesComparison,
        getAuditLogs: () => readLocalAuditLogs()
    };

    // =========================================================================
    // 10. UI INJECTION: LOGIN, FIRST-TIME SETUP, PASSWORD, ADMIN & KOSMATE SHELL
    // =========================================================================
    function injectGlobalUI() {
        if (document.getElementById('stockmsInjectedRoot')) return;

        const root = document.createElement('div');
        root.id = 'stockmsInjectedRoot';
        root.innerHTML = `
<!-- 1. THAIBEV PRE-LOGIN WELCOME PORTAL & LOGIN OVERLAY -->
<div id="authLoginOverlay" class="hidden">
    <div class="stockms-login-bg-decor" aria-hidden="true">
        <span class="orb orb-1"></span>
        <span class="orb orb-2"></span>
        <span class="orb orb-3"></span>
    </div>
    <div class="kosmate-login-card">
        <div class="flex justify-between items-center mb-2">
            <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-[10px] font-extrabold text-emerald-800 tracking-wide">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-600"></span> THAIBEV SPIRIT GROUP
            </span>
            <button type="button" onclick="toggleAppFullscreen()" class="kosmate-icon-btn" title="ขยายเต็มหน้าจอ">
                <i class="fas fa-expand stockms-fs-icon"></i>
            </button>
        </div>

        <!-- Stage 1: Welcome Screen Before Login Form -->
        <div id="stockmsWelcomeStage" class="thaibev-welcome-stage">
            <div class="thaibev-crest-card mb-4 text-center">
                <div class="mx-auto w-20 h-20 rounded-2xl bg-white/10 border border-amber-300/40 flex items-center justify-center mb-3 shadow-inner">
                    <svg viewBox="0 0 80 80" class="w-16 h-16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="ThaiBev Heritage Emblem">
                        <defs>
                            <linearGradient id="tbGold" x1="12" y1="8" x2="68" y2="72" gradientUnits="userSpaceOnUse">
                                <stop offset="0%" stop-color="#fef08a"/>
                                <stop offset="50%" stop-color="#f59e0b"/>
                                <stop offset="100%" stop-color="#d97706"/>
                            </linearGradient>
                            <linearGradient id="tbJade" x1="40" y1="10" x2="40" y2="70" gradientUnits="userSpaceOnUse">
                                <stop offset="0%" stop-color="#10b981"/>
                                <stop offset="100%" stop-color="#047857"/>
                            </linearGradient>
                        </defs>
                        <circle cx="40" cy="40" r="35" stroke="url(#tbGold)" stroke-width="2" fill="rgba(2,44,34,0.45)"/>
                        <circle cx="40" cy="40" r="29" stroke="rgba(254,240,138,0.28)" stroke-width="1" stroke-dasharray="3 3"/>
                        <!-- Stylized Thai Spire / Crest -->
                        <path d="M40 11C43 18.5 46 23.5 46 29.5C46 33.5 43.5 36.8 40 38.2C36.5 36.8 34 33.5 34 29.5C34 23.5 37 18.5 40 11Z" fill="url(#tbGold)"/>
                        <path d="M23 34.5C29 29.5 35 31.5 40 38.2C33 40.2 27 39.2 23 34.5Z" fill="url(#tbGold)" opacity="0.92"/>
                        <path d="M57 34.5C51 29.5 45 31.5 40 38.2C47 40.2 53 39.2 57 34.5Z" fill="url(#tbGold)" opacity="0.92"/>
                        <path d="M26 45.5C32 42 48 42 54 45.5L50.5 55H29.5L26 45.5Z" fill="url(#tbJade)" stroke="url(#tbGold)" stroke-width="1.6"/>
                        <text x="40" y="65.5" text-anchor="middle" fill="#fef3c7" font-size="7.2" font-weight="900" font-family="sans-serif" letter-spacing="1.1">THAIBEV</text>
                    </svg>
                </div>
                <div class="text-[10px] font-bold tracking-[0.2em] uppercase text-amber-200/90">Thai Beverage Public Company Limited</div>
                <h1 class="text-2xl font-black tracking-tight mt-0.5"><span class="thaibev-gold-text">ThaiBev</span> StockMS</h1>
                <p class="text-[11px] text-emerald-100/90 font-semibold mt-1">ระบบควบคุมคลังสุราและการปรุงระดับองค์กร (Blending Operations)</p>
            </div>

            <button type="button" id="btnEnterLoginForm" class="kosmate-primary-btn" style="background: linear-gradient(135deg, #065f46 0%, #047857 100%); box-shadow: 0 12px 26px -6px rgba(4, 120, 87, 0.48);">
                <i class="fas fa-arrow-right-to-bracket"></i>
                <span>เข้าสู่ระบบจัดการคลังสุรา (Sign In)</span>
            </button>
        </div>

        <!-- Stage 2: Login Credentials Form -->
        <div id="stockmsLoginFormStage" class="thaibev-login-stage">
            <div class="flex items-center justify-between mb-3">
                <button type="button" id="btnBackToWelcome" class="text-xs font-extrabold text-emerald-700 hover:text-emerald-900 flex items-center gap-1">
                    <i class="fas fa-arrow-left"></i> กลับหน้าต้อนรับ
                </button>
                <span class="text-[10px] font-bold text-slate-400 uppercase tracking-wider">Credential Login</span>
            </div>

            <div class="text-center mb-4">
                <div class="w-12 h-12 rounded-2xl mx-auto mb-2 bg-gradient-to-tr from-emerald-800 to-emerald-600 text-amber-200 flex items-center justify-center shadow-md border border-amber-300/40">
                    <i class="fas fa-wine-bottle text-xl"></i>
                </div>
                <h2 class="text-xl font-black text-slate-800 tracking-tight">ThaiBev • StockMS Cloud</h2>
                <p class="text-xs font-semibold text-slate-500 mt-0.5">กรอก Username และ Password เพื่อเข้าสู่คลังประจำโรงงาน</p>
            </div>

            <form id="stockmsLoginForm" class="space-y-3.5" autocomplete="on">
                <div>
                    <label class="block text-[11px] font-bold text-slate-500 uppercase mb-1">Username / ชื่อผู้ใช้งาน</label>
                    <div class="kosmate-input-wrap">
                        <i class="fas fa-user k-icon-left"></i>
                        <input type="text" id="loginUsername" required placeholder="กรอกชื่อผู้ใช้งาน (Username)" autocomplete="username">
                    </div>
                </div>

                <div>
                    <label class="block text-[11px] font-bold text-slate-500 uppercase mb-1">Password / รหัสผ่าน</label>
                    <div class="kosmate-input-wrap">
                        <i class="fas fa-lock k-icon-left"></i>
                        <input type="password" id="loginPassword" required placeholder="กรอกรหัสผ่าน" autocomplete="current-password">
                        <button type="button" id="toggleLoginPwdBtn" class="absolute right-3 text-slate-400 hover:text-blue-600 p-1 text-sm" title="แสดง/ซ่อนรหัสผ่าน">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>

                <div class="flex items-center justify-between text-xs pt-0.5">
                    <label class="inline-flex items-center gap-2 cursor-pointer font-semibold text-slate-600">
                        <input type="checkbox" id="loginRememberMe" checked class="w-4 h-4 rounded border-slate-300 text-emerald-600 focus:ring-emerald-500">
                        <span>จดจำการเข้าสู่ระบบ</span>
                    </label>
                </div>

                <div id="loginErrorBox" class="hidden text-xs font-bold text-rose-600 bg-rose-50 border border-rose-200 rounded-xl px-3 py-2"></div>

                <button type="submit" id="loginSubmitBtn" class="kosmate-primary-btn" style="background: linear-gradient(135deg, #065f46 0%, #047857 100%); box-shadow: 0 10px 24px -6px rgba(4, 120, 87, 0.45);">
                    <i class="fas fa-sign-in-alt"></i>
                    <span>เข้าสู่ระบบ (Login)</span>
                </button>
            </form>
        </div>
    </div>
</div>

<!-- 2. FIRST-TIME FACTORY ONBOARDING MODAL -->
<div id="firstTimeSetupModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-xl p-6 sm:p-7">
        <div class="flex items-center gap-3 mb-4">
            <div class="w-12 h-12 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 text-white flex items-center justify-center text-xl shadow-lg">
                <i class="fas fa-industry"></i>
            </div>
            <div>
                <span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-blue-100 text-blue-700 uppercase">First-Time Factory Setup</span>
                <h3 class="text-lg sm:text-xl font-black mt-0.5" id="firstTimeTitle">ยินดีต้อนรับโรงงานใหม่</h3>
            </div>
        </div>
        <p class="text-xs sm:text-sm text-slate-600 leading-relaxed mb-5">
            บัญชีผู้ใช้งาน <b class="text-blue-600" id="firstTimeUsernameLabel">-</b> ยังไม่มีข้อมูลเริ่มต้นในระบบฐานข้อมูลกลาง
            ข้อมูลของแต่ละ Username จะถูกแยกออกจากกัน 100% ตามโรงงาน กรุณาเลือกวิธีเริ่มต้นฐานข้อมูลของคุณ:
        </p>

        <input type="file" id="firstTimeImportInput" accept=".json" class="hidden">

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mb-4">
            <button type="button" id="btnFirstTimeImport" class="p-4 rounded-2xl border-2 border-blue-500/40 bg-blue-50/70 hover:bg-blue-100/70 text-left transition group cursor-pointer">
                <div class="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center text-lg mb-2.5 group-hover:scale-105 transition">
                    <i class="fas fa-file-import"></i>
                </div>
                <div class="font-extrabold text-sm text-slate-800">นำเข้าไฟล์ Backup (.json)</div>
                <p class="text-[11px] text-slate-500 mt-1">นำเข้าข้อมูลถัง ประวัติรับ-จ่าย และการตั้งค่าจากไฟล์สำรองเดิมเข้าสู่ระบบฐานข้อมูลกลางของโรงงานนี้ทันที</p>
            </button>

            <button type="button" id="btnFirstTimeFresh" class="p-4 rounded-2xl border-2 border-emerald-500/40 bg-emerald-50/70 hover:bg-emerald-100/70 dark:bg-emerald-950/40 dark:hover:bg-emerald-900/50 text-left transition group cursor-pointer">
                <div class="w-10 h-10 rounded-xl bg-emerald-600 text-white flex items-center justify-center text-lg mb-2.5 group-hover:scale-105 transition">
                    <i class="fas fa-rocket"></i>
                </div>
                <div class="font-extrabold text-sm text-slate-800 dark:text-white">เริ่มต้นใช้งานใหม่ (ฐานเปล่า)</div>
                <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-1">สร้างโครงสร้างถังมาตรฐานและเริ่มบันทึกยอดยกมา/รับ-จ่ายใหม่ตั้งแต่ต้นสำหรับโรงงานนี้</p>
            </button>
        </div>

        <div class="flex justify-between items-center pt-3 border-t border-slate-200 dark:border-slate-700 text-xs">
            <span class="text-slate-400"><i class="fas fa-shield-alt mr-1"></i> แยกฐานข้อมูลอิสระต่อ 1 Username</span>
            <button type="button" onclick="stockmsLogout()" class="text-rose-600 font-bold hover:underline">ออกจากระบบ</button>
        </div>
    </div>
</div>

<!-- 3. SELF-SERVICE CHANGE PASSWORD MODAL -->
<div id="changePasswordModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-md p-6">
        <div class="flex justify-between items-center mb-4 pb-3 border-b border-slate-200 dark:border-slate-700">
            <div class="flex items-center gap-2.5">
                <div class="w-9 h-9 rounded-xl bg-blue-600 text-white flex items-center justify-center"><i class="fas fa-key"></i></div>
                <div>
                    <h3 class="text-base font-extrabold">เปลี่ยนรหัสผ่านผู้ใช้งาน</h3>
                    <p class="text-[11px] text-slate-500 dark:text-slate-400" id="cpUserSubtitle">-</p>
                </div>
            </div>
            <button type="button" onclick="window.StockMSUI.closeModal('changePasswordModal')" class="w-8 h-8 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"><i class="fas fa-times"></i></button>
        </div>
        <form id="changePasswordForm" class="space-y-3">
            <div>
                <label class="block text-xs font-bold mb-1">รหัสผ่านปัจจุบัน</label>
                <input type="password" id="cpCurrent" required class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm outline-none focus:border-blue-500">
            </div>
            <div>
                <label class="block text-xs font-bold mb-1">รหัสผ่านใหม่ (อย่างน้อย 4 ตัวอักษร)</label>
                <input type="password" id="cpNew" required minlength="4" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm outline-none focus:border-blue-500">
            </div>
            <div>
                <label class="block text-xs font-bold mb-1">ยืนยันรหัสผ่านใหม่</label>
                <input type="password" id="cpConfirm" required minlength="4" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm outline-none focus:border-blue-500">
            </div>
            <div id="cpErrorBox" class="hidden text-xs font-bold text-rose-600 bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800 rounded-xl px-3 py-2"></div>
            <div class="flex justify-end gap-2 pt-2">
                <button type="button" onclick="window.StockMSUI.closeModal('changePasswordModal')" class="px-4 py-2 rounded-xl text-xs font-bold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">ยกเลิก</button>
                <button type="submit" class="px-5 py-2 rounded-xl text-xs font-bold bg-blue-600 hover:bg-blue-700 text-white shadow">บันทึกรหัสผ่านใหม่</button>
            </div>
        </form>
    </div>
</div>

<!-- 4. ADMIN: USER MANAGEMENT MODAL -->
<div id="adminUserManagerModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-4xl p-5 sm:p-6">
        <div class="flex justify-between items-center mb-4 pb-3 border-b border-slate-200 dark:border-slate-700">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center text-lg shadow"><i class="fas fa-users-cog"></i></div>
                <div>
                    <h3 class="text-base sm:text-lg font-extrabold">จัดการผู้ใช้งานและโรงงาน (Admin User Manager)</h3>
                    <p class="text-[11px] text-slate-500 dark:text-slate-400">เพิ่มบัญชีโรงงานใหม่ กำหนด/รีเซ็ตรหัสผ่าน และดูสถานะการเริ่มต้นข้อมูล</p>
                </div>
            </div>
            <button type="button" onclick="window.StockMSUI.closeModal('adminUserManagerModal')" class="w-9 h-9 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"><i class="fas fa-times"></i></button>
        </div>

        <form id="adminAddUserForm" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 p-3.5 rounded-2xl bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 mb-5">
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">Username *</label>
                <input type="text" id="adminNewUsername" required placeholder="เช่น ms-nkp" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">ชื่อโรงงาน / แสดงผล *</label>
                <input type="text" id="adminNewDisplayName" required placeholder="เช่น โรงงาน MS-NKP" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">รหัสผ่านเริ่มต้น *</label>
                <input type="text" id="adminNewPassword" required minlength="4" placeholder="ตั้งรหัสผ่าน" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">สิทธิ์ (Role)</label>
                <select id="adminNewRole" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
                    <option value="factory">โรงงาน (Factory)</option>
                    <option value="admin">ผู้ดูแลระบบ (Admin)</option>
                </select>
            </div>
            <div class="flex items-end">
                <button type="submit" class="w-full py-2 px-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-extrabold shadow flex items-center justify-center gap-1.5">
                    <i class="fas fa-user-plus"></i> เพิ่มผู้ใช้งาน
                </button>
            </div>
        </form>

        <div class="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-700">
            <table class="w-full text-xs text-left">
                <thead class="bg-slate-100 dark:bg-slate-800 text-[11px] font-bold uppercase text-slate-600 dark:text-slate-300">
                    <tr>
                        <th class="px-3.5 py-2.5">Username</th>
                        <th class="px-3.5 py-2.5">ชื่อโรงงาน</th>
                        <th class="px-3.5 py-2.5">Role</th>
                        <th class="px-3.5 py-2.5">สถานะออนไลน์</th>
                        <th class="px-3.5 py-2.5">แก้ไขล่าสุด</th>
                        <th class="px-3.5 py-2.5 text-center">จัดการ</th>
                    </tr>
                </thead>
                <tbody id="adminUsersTableBody" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
            </table>
        </div>
    </div>
</div>

<!-- 5. ADMIN: MULTI-FACTORY COMPARISON & EXECUTIVE RECOMMENDATIONS MODAL -->
<div id="adminCompareModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-6xl p-5 sm:p-6">
        <div class="flex justify-between items-center mb-4 pb-3 border-b border-slate-200 dark:border-slate-700 flex-wrap gap-2">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 text-white flex items-center justify-center text-lg shadow"><i class="fas fa-balance-scale-right"></i></div>
                <div>
                    <h3 class="text-base sm:text-lg font-extrabold">เปรียบเทียบข้อมูลทุกโรงงาน &amp; บทสรุปคำแนะนำผู้บริหาร</h3>
                    <p class="text-[11px] text-slate-500 dark:text-slate-400">วิเคราะห์สต็อกรายดีกรี ความจุคลัง อัตราบ่มพร้อมจ่าย คุณภาพ QC และข้อเสนอแนะเฉพาะรายโรงงาน</p>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" onclick="window.StockMSUI.openAdminCompareModal()" class="px-3 py-1.5 rounded-xl bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 text-xs font-bold border border-blue-200 dark:border-blue-800"><i class="fas fa-sync-alt mr-1"></i> รีเฟรชข้อมูล</button>
                <button type="button" onclick="window.StockMSUI.closeModal('adminCompareModal')" class="w-9 h-9 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400"><i class="fas fa-times"></i></button>
            </div>
        </div>

        <div id="adminCompareOverview" class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5"></div>

        <div class="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-5">
            <div class="lg:col-span-7 overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-700">
                <table class="w-full text-xs text-left">
                    <thead class="bg-slate-100 dark:bg-slate-800 text-[10px] font-bold uppercase text-slate-600 dark:text-slate-300">
                        <tr>
                            <th class="px-3 py-2.5">โรงงาน / User</th>
                            <th class="px-3 py-2.5 text-right">คงคลังรวม (L)</th>
                            <th class="px-3 py-2.5 text-right">ความจุ (L)</th>
                            <th class="px-3 py-2.5 text-right">% ใช้พื้นที่</th>
                            <th class="px-3 py-2.5 text-right">70° (L)</th>
                            <th class="px-3 py-2.5 text-right">40° &amp; อื่นๆ (L)</th>
                            <th class="px-3 py-2.5 text-center">QC ผ่าน</th>
                            <th class="px-3 py-2.5 text-center">เปิดดู</th>
                        </tr>
                    </thead>
                    <tbody id="adminCompareTableBody" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
                </table>
            </div>
            <div class="lg:col-span-5 p-4 rounded-2xl border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-800/40">
                <div class="text-xs font-extrabold mb-2 text-slate-700 dark:text-slate-200"><i class="fas fa-chart-bar text-blue-600 mr-1.5"></i> กราฟเปรียบเทียบปริมาณสุรารายโรงงาน</div>
                <div class="h-56 relative"><canvas id="adminCompareBarCanvas"></canvas></div>
            </div>
        </div>

        <div class="mb-2 text-sm font-extrabold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <i class="fas fa-lightbulb text-amber-500"></i> บทสรุปวิเคราะห์และคำแนะนำรายโรงงาน (Executive Insights)
        </div>
        <div id="adminFactoryInsightsGrid" class="grid grid-cols-1 md:grid-cols-2 gap-3.5"></div>
    </div>
</div>

<!-- 5B. ADMIN: REAL-TIME ACTIVITY LOGS & ROLLBACK MODAL -->
<div id="adminAuditLogsModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-6xl p-5 sm:p-6">
        <div class="flex justify-between items-center mb-4 pb-3 border-b border-slate-200 flex-wrap gap-2">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-rose-600 to-indigo-600 text-white flex items-center justify-center text-lg shadow"><i class="fas fa-history"></i></div>
                <div>
                    <div class="flex items-center gap-2 flex-wrap">
                        <h3 class="text-base sm:text-lg font-extrabold">บันทึกกิจกรรมผู้ใช้งานแบบ Real-Time &amp; ย้อนข้อมูลโรงงาน</h3>
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-extrabold">
                            <span class="stockms-live-dot"></span> LIVE REALTIME
                        </span>
                        <span id="adminSnapshotSyncStatusBadge" class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-[10px] font-extrabold">DB &amp; Snapshot พร้อม</span>
                    </div>
                    <p class="text-[11px] text-slate-500">ติดตามการใช้งานของทุก User แบบสดๆ และกดย้อนข้อมูลเฉพาะคลัง/ID ที่เลือก พร้อมล้าง Logs รายเดือน/รายปี</p>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <button type="button" onclick="window.StockMSUI.renderAdminLogsModal(true)" class="px-3 py-1.5 rounded-xl bg-blue-50 text-blue-700 text-xs font-bold border border-blue-200"><i class="fas fa-sync-alt mr-1"></i> ดึงล่าสุด</button>
                <button type="button" onclick="window.StockMSUI.closeModal('adminAuditLogsModal')" class="w-9 h-9 rounded-full hover:bg-slate-100 text-slate-400"><i class="fas fa-times"></i></button>
            </div>
        </div>

        <div id="adminLogsKpiRow" class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4"></div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5 p-3 rounded-2xl bg-slate-50 border border-slate-200 mb-3">
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">กรองตาม User / โรงงาน</label>
                <select id="adminLogFilterUser" class="w-full px-3 py-2 rounded-xl border border-slate-300 bg-white text-xs font-bold outline-none">
                    <option value="ALL">ทุก User / โรงงาน</option>
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">ประเภทกิจกรรม</label>
                <select id="adminLogFilterCategory" class="w-full px-3 py-2 rounded-xl border border-slate-300 bg-white text-xs font-bold outline-none">
                    <option value="ALL">ทุกประเภท</option>
                    <option value="tx">รับ-จ่าย / โอนย้าย / ปรุงสุรา</option>
                    <option value="settings">ตั้งค่าถัง / อาคาร / QC</option>
                    <option value="data">Import / เริ่มต้น / ล้างข้อมูล</option>
                    <option value="rollback">ประวัติการย้อนข้อมูล (Rollback)</option>
                    <option value="auth">เข้า-ออกระบบ / บัญชี / รหัสผ่าน</option>
                </select>
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">ค้นหารายละเอียด (ถัง / Batch / กิจกรรม)</label>
                <input type="text" id="adminLogSearchInput" placeholder="พิมพ์คำค้น..." class="w-full px-3 py-2 rounded-xl border border-slate-300 bg-white text-xs font-bold outline-none">
            </div>
        </div>

        <div class="flex flex-wrap items-center justify-between gap-2.5 p-3 rounded-2xl bg-rose-50/70 border border-rose-200/80 mb-4 text-xs">
            <span class="font-extrabold text-rose-800 flex items-center gap-1.5"><i class="fas fa-broom"></i> ล้าง Logs เก่าป้องกันฐานข้อมูลเต็ม:</span>
            <div class="flex flex-wrap items-center gap-2">
                <div class="flex items-center gap-1.5">
                    <input type="month" id="adminClearLogsMonth" class="px-2.5 py-1.5 rounded-xl border border-rose-200 bg-white text-xs font-bold text-slate-700 outline-none">
                    <button type="button" id="btnClearLogsMonth" onclick="window.StockMSUI.clearAuditLogsByPeriod('month')" class="px-3 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold shadow-sm whitespace-nowrap">ล้าง Logs รายเดือน</button>
                </div>
                <div class="stockms-nav-divider hidden sm:block" style="height: 20px;"></div>
                <div class="flex items-center gap-1.5">
                    <select id="adminClearLogsYear" class="px-2.5 py-1.5 rounded-xl border border-rose-200 bg-white text-xs font-bold text-slate-700 outline-none"></select>
                    <button type="button" id="btnClearLogsYear" onclick="window.StockMSUI.clearAuditLogsByPeriod('year')" class="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-xs font-bold shadow-sm whitespace-nowrap">ล้าง Logs รายปี</button>
                </div>
            </div>
        </div>

        <div class="overflow-x-auto rounded-2xl border border-slate-200 max-h-[54vh] overflow-y-auto">
            <table class="w-full text-xs text-left">
                <thead class="bg-slate-100 text-[10px] font-bold uppercase text-slate-600 sticky top-0 z-10">
                    <tr>
                        <th class="px-3 py-2.5 whitespace-nowrap">เวลา (Real-Time)</th>
                        <th class="px-3 py-2.5 whitespace-nowrap">ผู้ดำเนินการ / โรงงาน</th>
                        <th class="px-3 py-2.5 whitespace-nowrap">กิจกรรม</th>
                        <th class="px-3 py-2.5 min-w-[200px]">รายละเอียดการเปลี่ยนแปลง</th>
                        <th class="px-3 py-2.5 text-center whitespace-nowrap">Snapshot (ก่อน → หลัง)</th>
                        <th class="px-3 py-2.5 text-center whitespace-nowrap">ย้อนข้อมูล (Rollback)</th>
                    </tr>
                </thead>
                <tbody id="adminLogsTableBody" class="divide-y divide-slate-100 bg-white"></tbody>
            </table>
        </div>
    </div>
</div>

<!-- 6. KOSMATE MOBILE APP SHELL (Beranda, Bottom Nav & Profil View) -->
<div id="kosmateMobileShell" class="hidden">
    <div class="kosmate-shell-wrap">
        <!-- Mobile Top Bar -->
        <div class="kosmate-top-bar">
            <div class="kosmate-greeting min-w-0">
                <h2 class="truncate" id="kmGreetingTitle">สวัสดี 👋</h2>
                <p class="truncate flex items-center gap-1.5">
                    <span id="kmFactorySub">-</span>
                    <span class="stockms-cloud-badge online stockms-cloud-status-target scale-90 origin-left"></span>
                </p>
            </div>
            <div class="flex items-center gap-1.5">
                <button type="button" onclick="toggleAppFullscreen()" class="kosmate-icon-btn" title="ขยายเต็มหน้าจอ">
                    <i class="fas fa-expand stockms-fs-icon"></i>
                </button>
                <button type="button" onclick="window.StockMSUI.triggerQCAction()" class="kosmate-icon-btn" title="แจ้งเตือน QC">
                    <i class="fas fa-bell"></i>
                    <span id="kmQcBadge" class="hidden absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-white text-[9px] font-black flex items-center justify-center">0</span>
                </button>
                <button type="button" onclick="toggleMobileAppLayout(true)" class="kosmate-icon-btn" title="มุมมอง Desktop เต็มหน้า">
                    <i class="fas fa-desktop text-blue-600"></i>
                </button>
            </div>
        </div>

        <!-- Admin Factory Switcher Strip on Mobile -->
        <div id="kmAdminSwitchBar" class="hidden mb-3 p-2.5 rounded-2xl bg-slate-800/95 backdrop-blur-md text-white flex items-center justify-between gap-2 text-xs shadow-sm border border-slate-700/60">
            <span class="font-bold whitespace-nowrap"><i class="fas fa-shield-alt text-amber-400 mr-1"></i> โรงงาน:</span>
            <select id="kmAdminFactorySelect" class="flex-1 bg-slate-900 text-white rounded-xl px-2.5 py-1.5 text-xs font-bold border border-slate-700 outline-none"></select>
            <button type="button" onclick="window.StockMSUI.openAdminCompareModal()" class="px-2.5 py-1.5 rounded-xl bg-white/15 hover:bg-white/25 text-white font-bold whitespace-nowrap">เปรียบเทียบ</button>
        </div>

        <!-- Glassy Navigation Tabs V10 (Elegant Grey & White Theme) -->
        <div id="kmGlassyTabsV10" class="km-glassy-tabs-v10" role="tablist" aria-label="Mobile Glassy Navigation Tabs">
            <div id="kmGlassyTabIndicator" class="km-glassy-tab-indicator"></div>
            <button type="button" class="km-glassy-tab-btn active" data-km-v10-tab="home" data-tab-idx="0" onclick="window.StockMSUI.switchMobileTab('home')">
                <i class="fas fa-home"></i><span>หน้าหลัก</span>
            </button>
            <button type="button" class="km-glassy-tab-btn" data-km-v10-tab="tanks" data-tab-idx="1" onclick="window.StockMSUI.switchMobileTab('tanks')">
                <i class="fas fa-th-large"></i><span>คลังถัง</span>
            </button>
            <button type="button" class="km-glassy-tab-btn" data-km-v10-tab="reports" data-tab-idx="2" onclick="window.StockMSUI.switchMobileTab('reports')">
                <i class="fas fa-chart-bar"></i><span>รายงาน</span>
            </button>
            <button type="button" class="km-glassy-tab-btn" data-km-v10-tab="profile" data-tab-idx="3" onclick="window.StockMSUI.switchMobileTab('profile')">
                <i class="fas fa-user"></i><span>โปรไฟล์</span>
            </button>
        </div>

        <!-- HOME VIEW -->
        <div id="kmPaneHome" class="space-y-4">
            <!-- Glassy V10 Grey & White Hero Card -->
            <div class="kosmate-hero-card km-glassy-v10-card">
                <div class="flex justify-between items-start gap-2">
                    <div>
                        <div class="text-[11px] font-bold text-slate-500 uppercase tracking-wider">ปริมาณสุราคงคลังทั้งหมด</div>
                        <div class="text-2xl sm:text-3xl font-black tracking-tight mt-0.5 tabular-nums text-slate-900" id="kmHeroTotalVol">0 L</div>
                        <div class="text-[11px] text-slate-600 mt-0.5 tabular-nums">ความจุรวม <span id="kmHeroTotalCap" class="font-extrabold text-slate-900">0 L</span> (<span id="kmHeroUtilPct" class="font-extrabold text-emerald-700">0%</span>)</div>
                    </div>
                    <div class="w-11 h-11 rounded-2xl bg-slate-800 text-white flex items-center justify-center text-xl shadow-sm">
                        <i class="fas fa-warehouse"></i>
                    </div>
                </div>
                <div class="w-full h-2 bg-slate-200/90 rounded-full overflow-hidden mt-3">
                    <div id="kmHeroProgress" class="h-full bg-gradient-to-r from-slate-700 to-emerald-600 rounded-full transition-all duration-500" style="width: 0%"></div>
                </div>
                <div class="kosmate-hero-pills">
                    <span class="kosmate-hero-pill"><span class="w-2 h-2 rounded-full bg-emerald-500"></span> 70°: <b id="kmPill70">0 L</b></span>
                    <span class="kosmate-hero-pill"><span class="w-2 h-2 rounded-full bg-amber-500"></span> 40°: <b id="kmPill40">0 L</b></span>
                    <span class="kosmate-hero-pill"><span class="w-2 h-2 rounded-full bg-sky-500"></span> 35/30/28°: <b id="kmPillLow">0 L</b></span>
                </div>
            </div>

            <!-- 8-Icon Quick Actions Grid (4x2 KosMate Squircle Style) -->
            <div class="kosmate-quick-grid" id="kmQuickGrid"></div>

            <!-- Dense 4-Column Live Tank Matrix (See More Tanks & Live Data on Mobile) -->
            <div id="kmTankMatrixSection" class="kosmate-recent-card">
                <div class="flex flex-wrap justify-between items-center gap-2 mb-2.5">
                    <div>
                        <h3 class="text-xs font-extrabold text-slate-800 uppercase tracking-wide flex items-center gap-1.5">
                            <i class="fas fa-th text-slate-600"></i> ข้อมูลถังสุราทั้งหมด (Live Tank Matrix)
                        </h3>
                        <p class="text-[10px] text-slate-400 font-semibold" id="kmTankMatrixSubtitle">แตะที่ถังเพื่อดูผังคลังหรือกรองประวัติ</p>
                    </div>
                    <div id="kmTankFilterPills" class="flex flex-wrap gap-1">
                        <button type="button" onclick="window.StockMSUI.setMobileTankFilter('ALL')" data-km-b="ALL" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-800 text-white">ทั้งหมด</button>
                        <button type="button" onclick="window.StockMSUI.setMobileTankFilter('Building_High')" data-km-b="Building_High" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-100 text-slate-600">โรงบ่ม</button>
                        <button type="button" onclick="window.StockMSUI.setMobileTankFilter('Building_110')" data-km-b="Building_110" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-100 text-slate-600">110</button>
                        <button type="button" onclick="window.StockMSUI.setMobileTankFilter('Building_111')" data-km-b="Building_111" class="px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-100 text-slate-600">111</button>
                    </div>
                </div>
                <div id="kmMobileTankGrid" class="km-tank-matrix-grid"></div>
            </div>

            <!-- Recent Transactions Feed -->
            <div class="kosmate-recent-card">
                <div class="flex justify-between items-center mb-2">
                    <h3 class="text-sm font-extrabold text-slate-800 dark:text-slate-100">รายการเคลื่อนไหวล่าสุด</h3>
                    <button type="button" onclick="window.StockMSUI.openFullHistoryView()" class="text-xs font-bold text-blue-600 dark:text-blue-400">ดูทั้งหมด</button>
                </div>
                <div id="kmRecentTxList"></div>
            </div>
        </div>

        <!-- PROFILE VIEW (KosMate Profil Style) -->
        <div id="kmPaneProfile" class="hidden space-y-4">
            <div class="kosmate-recent-card flex flex-col items-center text-center py-5">
                <div class="w-16 h-16 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-500 text-white flex items-center justify-center text-2xl font-black shadow-lg mb-2.5" id="kmProfileAvatar">S</div>
                <div class="text-base font-black text-slate-800 dark:text-white" id="kmProfileName">-</div>
                <div class="text-xs font-semibold text-slate-500 dark:text-slate-400" id="kmProfileMeta">-</div>
                <span class="mt-2 px-3 py-1 rounded-full text-[11px] font-bold bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-200/70" id="kmProfileFactoryBadge">-</span>
            </div>

            <div class="kosmate-profile-list">
                <button type="button" class="kosmate-profile-item" onclick="window.StockMSUI.openChangePasswordModal()">
                    <span class="flex items-center gap-3"><i class="fas fa-key text-blue-600 w-4"></i> เปลี่ยนรหัสผ่าน (Change Password)</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" class="kosmate-profile-item" onclick="window.StockMSUI.triggerBackupAction()">
                    <span class="flex items-center gap-3"><i class="fas fa-file-export text-emerald-600 w-4"></i> สำรองข้อมูล (Backup JSON)</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" class="kosmate-profile-item" onclick="window.StockMSUI.triggerImportAction()">
                    <span class="flex items-center gap-3"><i class="fas fa-file-import text-amber-600 w-4"></i> นำเข้าไฟล์ข้อมูล (Import JSON)</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" id="kmBtnAdminUsers" class="kosmate-profile-item hidden" onclick="window.StockMSUI.openAdminUserModal()">
                    <span class="flex items-center gap-3"><i class="fas fa-users-cog text-indigo-600 w-4"></i> จัดการผู้ใช้งาน &amp; รหัสผ่าน (Admin)</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" id="kmBtnAdminCompare" class="kosmate-profile-item hidden" onclick="window.StockMSUI.openAdminCompareModal()">
                    <span class="flex items-center gap-3"><i class="fas fa-balance-scale-right text-purple-600 w-4"></i> เปรียบเทียบทุกโรงงาน &amp; คำแนะนำ</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" id="kmBtnAdminLogs" class="kosmate-profile-item hidden" onclick="window.StockMSUI.openAdminLogsModal()">
                    <span class="flex items-center gap-2.5"><i class="fas fa-history text-rose-600 w-4"></i> Logs &amp; ย้อนข้อมูล (Live) <span id="kmAdminLogsBadge" class="stockms-admin-logs-badge hidden px-1.5 py-0.5 rounded-full bg-rose-600 text-white text-[9px] font-black">0</span></span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" class="kosmate-profile-item" onclick="toggleMobileAppLayout(true)">
                    <span class="flex items-center gap-3"><i class="fas fa-desktop text-slate-600 w-4"></i> สลับเป็นมุมมองเต็มหน้า (Desktop View)</span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <button type="button" class="kosmate-profile-item" onclick="toggleAppFullscreen()">
                    <span class="flex items-center gap-3"><i class="fas fa-expand text-slate-600 w-4 stockms-fs-icon"></i> <span class="stockms-fs-label">ขยายเต็มหน้าจอ</span></span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </button>
                <a id="kmCrossPageLink" href="dashboard.html" class="kosmate-profile-item">
                    <span class="flex items-center gap-3"><i class="fas fa-chart-pie text-rose-500 w-4"></i> <span id="kmCrossPageLabel">เปิด Executive Dashboard</span></span>
                    <i class="fas fa-chevron-right text-slate-400 text-xs"></i>
                </a>
            </div>

            <button type="button" onclick="stockmsLogout()" class="w-full py-3 rounded-2xl bg-rose-50 hover:bg-rose-100 text-rose-600 dark:bg-rose-950/50 dark:text-rose-400 font-extrabold text-sm border border-rose-200 dark:border-rose-800/60 flex items-center justify-center gap-2">
                <i class="fas fa-sign-out-alt"></i> ออกจากระบบ (Logout)
            </button>
        </div>

        <!-- Back-to-Mobile-Home Bar when viewing classic section inside mobile -->
        <div id="kmClassicReturnBar" class="hidden mb-3 flex items-center justify-between gap-2 p-2.5 rounded-2xl bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 text-xs">
            <button type="button" onclick="window.StockMSUI.switchMobileTab('home')" class="font-extrabold text-blue-700 dark:text-blue-300 flex items-center gap-1.5">
                <i class="fas fa-arrow-left"></i> กลับหน้าหลักมือถือ
            </button>
            <button type="button" onclick="toggleAppFullscreen()" class="px-2.5 py-1 rounded-xl bg-white dark:bg-slate-800 font-bold text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
                <i class="fas fa-expand stockms-fs-icon mr-1"></i> เต็มจอ
            </button>
        </div>
    </div>

    <!-- Radial Fan-Out Speed-Dial Overlay -->
    <div id="kosmateRadialMenuOverlay" class="kosmate-radial-overlay" aria-hidden="true" role="dialog" aria-label="เมนูลัดการจัดการคลังสุรา">
        <div id="kosmateRadialHint" class="kosmate-radial-hint">ลากนิ้วไปที่ปุ่มแล้วปล่อย</div>
        <div class="kosmate-radial-stage">
            <div class="kosmate-radial-dome"></div>

            <button type="button" class="kosmate-radial-item" data-radial-slot="0" data-radial-action="tx" data-radial-title="บันทึกรับ-จ่ายสุรา">
                <div class="kosmate-radial-circle">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <rect x="3" y="6" width="18" height="12" rx="2.2"></rect>
                        <circle cx="12" cy="12" r="2.5"></circle>
                        <path d="M7 12h.01M17 12h.01"></path>
                    </svg>
                </div>
                <span class="kosmate-radial-label">รับ-จ่าย</span>
            </button>

            <button type="button" class="kosmate-radial-item" data-radial-slot="1" data-radial-action="daily" data-radial-title="รายงานประจำวัน">
                <div class="kosmate-radial-circle">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <rect x="4" y="5" width="16" height="15" rx="2.2"></rect>
                        <path d="M8 3v4M16 3v4M4 10h16"></path>
                        <path d="m9.5 14.5 1.8 1.8 3.5-3.5"></path>
                    </svg>
                </div>
                <span class="kosmate-radial-label">รายวัน</span>
            </button>

            <button type="button" class="kosmate-radial-item" data-radial-slot="2" data-radial-action="qc" data-radial-title="ตรวจผล &amp; เฝ้าระวัง QC">
                <div class="kosmate-radial-circle">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"></path>
                        <path d="M14 3v5h5"></path>
                        <path d="m9 15 2 2 4-4"></path>
                    </svg>
                </div>
                <span class="kosmate-radial-label">ตรวจ QC</span>
            </button>

            <button type="button" class="kosmate-radial-item" data-radial-slot="3" data-radial-action="reconcile" data-radial-title="วัดระดับ &amp; ปรับเทียบถัง">
                <div class="kosmate-radial-circle">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M12 13l4-4"></path>
                        <path d="M4.6 18a9 9 0 1 1 14.8 0"></path>
                        <circle cx="12" cy="14" r="1.2"></circle>
                    </svg>
                </div>
                <span class="kosmate-radial-label">วัดถัง</span>
            </button>

            <button type="button" id="kosmateRadialCloseBtn" class="kosmate-radial-close-btn" aria-label="ปิดเมนูลัด">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M18 6 6 18M6 6l12 12"></path>
                </svg>
            </button>
        </div>
    </div>

    <!-- Fixed 5-Slot Bottom Navigation Bar -->
    <nav class="kosmate-bottom-nav" aria-label="Mobile Navigation">
        <button type="button" class="kosmate-nav-item active" data-km-tab="home" onclick="window.StockMSUI.switchMobileTab('home')">
            <i class="fas fa-home"></i>
            <span>หน้าหลัก</span>
        </button>
        <button type="button" class="kosmate-nav-item" data-km-tab="tanks" onclick="window.StockMSUI.switchMobileTab('tanks')">
            <i class="fas fa-th-large"></i>
            <span>คลังถัง</span>
        </button>
        <div class="kosmate-fab-wrap">
            <button type="button" id="kosmateMainFabBtn" class="kosmate-fab-btn" title="เมนูลัดการจัดการคลัง (แตะหรือกดค้างแล้วลาก)" aria-label="เปิดเมนูลัด">
                <i class="fas fa-plus"></i>
            </button>
        </div>
        <button type="button" class="kosmate-nav-item" data-km-tab="reports" onclick="window.StockMSUI.switchMobileTab('reports')">
            <i class="fas fa-chart-bar"></i>
            <span>รายงาน</span>
        </button>
        <button type="button" class="kosmate-nav-item" data-km-tab="profile" onclick="window.StockMSUI.switchMobileTab('profile')">
            <i class="fas fa-user"></i>
            <span>โปรไฟล์</span>
        </button>
    </nav>
</div>
        `;
        document.body.appendChild(root);

        // Inject Categorized User / Admin / Presence / Sync / Fullscreen Bar inside existing desktop navbar
        const navContainer = document.querySelector('body > nav > div.container');
        if (navContainer && !document.getElementById('stockmsNavControlBar')) {
            const bar = document.createElement('div');
            bar.id = 'stockmsNavControlBar';
            bar.className = 'w-full flex flex-wrap items-center justify-between gap-2 pt-2.5 mt-1 border-t border-slate-200/70 text-xs';
            bar.innerHTML = `
                <div class="flex flex-wrap items-center gap-2">
                    <!-- Group: ผู้ใช้งาน & สถานะ DB -->
                    <div class="stockms-nav-group">
                        <span class="stockms-nav-group-label hidden 2xl:inline">บัญชี &amp; คลัง</span>
                        <span id="navUserBadge" class="stockms-user-pill">
                            <i class="fas fa-industry"></i>
                            <span id="navUserName">-</span>
                        </span>
                        <span class="stockms-cloud-badge online stockms-cloud-status-target cursor-pointer" onclick="window.StockMSStorage && window.StockMSStorage.syncNow && window.StockMSStorage.syncNow()" title="บันทึกอัตโนมัติใน ~0.06 วินาที • คลิกเพื่อตรวจสอบ/ซิงค์ซ้ำ"></span>
                        <button type="button" id="navSnapshotSyncBtn" onclick="window.StockMSStorage.syncNow()" class="hidden btn-glass px-2 py-1 rounded-xl bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 font-bold text-[10px] flex items-center gap-1 whitespace-nowrap" title="กดเพื่อซิงค์แคชที่ค้างอยู่ขึ้นฐานข้อมูล">
                            <i class="fas fa-sync-alt"></i> <span>ลองซิงค์ใหม่</span>
                        </button>
                    </div>

                    <div id="navAdminFactoryWrap" class="hidden stockms-nav-group items-center gap-1.5">
                        <label class="text-[10px] font-extrabold text-indigo-700 uppercase">คลังที่ดู:</label>
                        <select id="navAdminFactorySelect" class="px-2 py-1 rounded-xl border border-indigo-300/70 bg-white text-xs font-extrabold text-indigo-700 outline-none cursor-pointer"></select>
                    </div>

                    <div id="navAdminOnlineUsersWrap" class="hidden stockms-nav-group items-center gap-1.5 cursor-pointer" onclick="window.StockMSUI.openAdminUserModal()" title="คลิกเพื่อจัดการผู้ใช้และดูสถานะออนไลน์ทั้งหมด">
                        <span class="text-[10px] font-extrabold text-emerald-700 flex items-center gap-1 whitespace-nowrap">
                            <span class="stockms-live-dot"></span> ออนไลน์ <b id="navAdminOnlineCount">0</b>:
                        </span>
                        <div id="navAdminOnlineUsersList" class="flex flex-wrap items-center gap-1"></div>
                    </div>
                </div>

                <div class="flex flex-wrap items-center gap-1.5">
                    <!-- Group: Admin Suite -->
                    <div class="stockms-nav-group">
                        <span class="stockms-nav-group-label hidden 2xl:inline">ผู้ดูแลระบบ</span>
                        <button type="button" id="navBtnAdminCompare" onclick="window.StockMSUI.openAdminCompareModal()" class="hidden btn-glass px-2.5 py-1.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold text-[11px] shadow-sm items-center gap-1 whitespace-nowrap">
                            <i class="fas fa-balance-scale-right"></i> เปรียบเทียบโรงงาน &amp; คำแนะนำ
                        </button>
                        <button type="button" id="navBtnAdminLogs" onclick="window.StockMSUI.openAdminLogsModal()" class="hidden btn-glass px-2.5 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 font-bold text-[11px] items-center gap-1.5 whitespace-nowrap">
                            <span class="stockms-live-dot"></span>
                            <i class="fas fa-history"></i> Logs &amp; ย้อนข้อมูล
                            <span id="navAdminLogsBadge" class="stockms-admin-logs-badge hidden px-1.5 py-0.5 rounded-full bg-rose-600 text-white text-[9px] font-black leading-none">0</span>
                        </button>
                        <button type="button" id="navBtnAdminUsers" onclick="window.StockMSUI.openAdminUserModal()" class="hidden btn-glass px-2.5 py-1.5 rounded-xl bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200/80 font-bold text-[11px] items-center gap-1 whitespace-nowrap">
                            <i class="fas fa-users-cog"></i> จัดการผู้ใช้
                        </button>
                    </div>

                    <div class="stockms-nav-divider hidden md:block" aria-hidden="true"></div>

                    <!-- Group: มุมมอง & เซสชัน -->
                    <div class="stockms-nav-group">
                        <span class="stockms-nav-group-label hidden 2xl:inline">การแสดงผล</span>
                        <button type="button" onclick="window.StockMSUI.openChangePasswordModal()" class="btn-glass px-2.5 py-1.5 rounded-xl bg-white/90 hover:bg-white text-slate-700 border border-slate-200/80 font-bold text-[11px] flex items-center gap-1 whitespace-nowrap">
                            <i class="fas fa-key text-blue-600"></i> เปลี่ยนรหัสผ่าน
                        </button>
                        <button type="button" onclick="toggleMobileAppLayout(false)" class="btn-glass px-2.5 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200/80 font-bold text-[11px] flex items-center gap-1 whitespace-nowrap" title="สลับเป็นหน้าจอมือถือ (Glassy V10)">
                            <i class="fas fa-mobile-alt"></i> โหมดมือถือ
                        </button>
                        <button type="button" onclick="toggleAppFullscreen()" class="btn-glass px-2.5 py-1.5 rounded-xl bg-white/90 hover:bg-white text-slate-700 border border-slate-200/80 font-bold text-[11px] flex items-center gap-1 whitespace-nowrap" title="ขยายเต็มหน้าจอ">
                            <i class="fas fa-expand stockms-fs-icon text-indigo-500"></i> <span class="stockms-fs-label">เต็มจอ</span>
                        </button>
                        <button type="button" onclick="stockmsLogout()" class="btn-glass px-2.5 py-1.5 rounded-xl bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200/80 font-bold text-[11px] flex items-center gap-1 whitespace-nowrap">
                            <i class="fas fa-sign-out-alt"></i> ออกระบบ
                        </button>
                    </div>
                </div>
            `;
            navContainer.appendChild(bar);
        }

        wireModalAndFormListeners();
    }

    function wireModalAndFormListeners() {
        const enterLoginBtn = document.getElementById('btnEnterLoginForm');
        if (enterLoginBtn) {
            enterLoginBtn.addEventListener('click', () => {
                document.getElementById('authLoginOverlay')?.classList.add('login-stage-active');
                setTimeout(() => document.getElementById('loginUsername')?.focus(), 120);
            });
        }
        const backWelcomeBtn = document.getElementById('btnBackToWelcome');
        if (backWelcomeBtn) {
            backWelcomeBtn.addEventListener('click', () => {
                document.getElementById('authLoginOverlay')?.classList.remove('login-stage-active');
            });
        }
        ['loginUsername', 'loginPassword'].forEach(inpId => {
            document.getElementById(inpId)?.addEventListener('focus', () => {
                document.getElementById('authLoginOverlay')?.classList.add('login-stage-active');
            });
        });

        const loginForm = document.getElementById('stockmsLoginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = document.getElementById('loginSubmitBtn');
                const errBox = document.getElementById('loginErrorBox');
                errBox.classList.add('hidden');
                const origHtml = btn.innerHTML;
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>กำลังตรวจสอบสิทธิ์...</span>';
                try {
                    const u = document.getElementById('loginUsername').value;
                    const p = document.getElementById('loginPassword').value;
                    const rem = document.getElementById('loginRememberMe').checked;
                    await performLogin(u, p, rem);
                } catch (err) {
                    errBox.textContent = err.message || 'เข้าสู่ระบบไม่สำเร็จ';
                    errBox.classList.remove('hidden');
                } finally {
                    btn.disabled = false;
                    btn.innerHTML = origHtml;
                }
            });
        }

        const eyeBtn = document.getElementById('toggleLoginPwdBtn');
        if (eyeBtn) {
            eyeBtn.addEventListener('click', () => {
                const pwd = document.getElementById('loginPassword');
                const icon = eyeBtn.querySelector('i');
                if (pwd.type === 'password') {
                    pwd.type = 'text';
                    icon.className = 'fas fa-eye-slash';
                } else {
                    pwd.type = 'password';
                    icon.className = 'fas fa-eye';
                }
            });
        }

        // First-time onboarding buttons
        const ftImportBtn = document.getElementById('btnFirstTimeImport');
        const ftFileInput = document.getElementById('firstTimeImportInput');
        if (ftImportBtn && ftFileInput) {
            ftImportBtn.addEventListener('click', () => ftFileInput.click());
            ftFileInput.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = async (ev) => {
                    try {
                        const imported = JSON.parse(ev.target.result);
                        const activeFactory = getActiveFactoryId();
                        const reg = getLocalUsersRegistry();
                        const userMeta = reg[activeFactory] || {};
                        const legacyMap = { "B_70_Large": "Building_High", "B_70": "Building_110", "B_40": "Building_111" };
                        let tanksToImport = imported.customTanks || UNIFIED_DEFAULT_TANKS;
                        const buildingsToImport = imported.customBuildings || UNIFIED_DEFAULT_BUILDINGS;
                        tanksToImport = tanksToImport.map(t => {
                            const copy = { ...t };
                            if (legacyMap[copy.b]) copy.b = legacyMap[copy.b];
                            else if (!buildingsToImport[copy.b]) {
                                if (String(copy.id).includes('111')) copy.b = 'Building_111';
                                else if (String(copy.id).includes('110')) copy.b = 'Building_110';
                                else copy.b = 'Building_High';
                            }
                            return copy;
                        });

                        const payload = {
                            username: activeFactory,
                            factoryName: userMeta.displayName || activeFactory,
                            initialized: true,
                            updatedAt: new Date().toISOString(),
                            liquor_transactions: Array.isArray(imported.transactions) ? imported.transactions : [],
                            tank_config: imported.tankConfig || {},
                            active_tanks: { high: null, deg40: null, nextHigh: null, next40: null, ...(imported.activeTanks || {}) },
                            planning_data: { highSupply: 0, highUsage: 0, deg40Usage: 0, deg35Usage: 0, deg30Usage: 0, deg28Usage: 0, ...(imported.planningData || {}) },
                            custom_tanks: tanksToImport,
                            custom_buildings: buildingsToImport,
                            global_settings: imported.globalSettings || { cap40: 1568000, cap35: 1568000, cap30: 1568000, cap28: 1568000, cap70: 0 },
                            tank_settings_history: imported.tankSettingsHistory || [],
                            custom_qc_limits: imported.customQCLimits || {}
                        };
                        const beforePayload = clonePayloadSnapshot(readTenantLocalPayload(activeFactory));
                        writeTenantLocalPayload(activeFactory, payload);
                        applyPayloadToWorkingLocalStorage(payload);
                        await saveFactoryToCloudNow(activeFactory, payload);
                        await writeAuditLog('FIRST_TIME_IMPORT', activeFactory, {
                            category: 'data',
                            actionLabel: 'นำเข้าข้อมูลครั้งแรก',
                            summaryText: `นำเข้าข้อมูล Backup ให้โรงงาน ${activeFactory} (${payload.liquor_transactions.length} รายการ)`,
                            beforePayload,
                            afterPayload: payload,
                            canRollback: true
                        });
                        closeModal('firstTimeSetupModal');
                        triggerHostPageReload();
                        refreshMobileShellData();
                        if (typeof Swal !== 'undefined') {
                            Swal.fire('นำเข้าข้อมูลสำเร็จ!', `เริ่มใช้งานฐานข้อมูลโรงงาน ${activeFactory} แล้ว`, 'success');
                        }
                    } catch (err) {
                        if (typeof Swal !== 'undefined') Swal.fire('ไฟล์ไม่ถูกต้อง', err.message, 'error');
                    }
                    ftFileInput.value = '';
                };
                reader.readAsText(file);
            });
        }

        const ftFreshBtn = document.getElementById('btnFirstTimeFresh');
        if (ftFreshBtn) {
            ftFreshBtn.addEventListener('click', async () => {
                const activeFactory = getActiveFactoryId();
                const reg = getLocalUsersRegistry();
                const userMeta = reg[activeFactory] || {};
                const beforePayload = clonePayloadSnapshot(readTenantLocalPayload(activeFactory));
                const payload = getDefaultFactoryPayload(activeFactory, userMeta.displayName);
                payload.initialized = true;
                writeTenantLocalPayload(activeFactory, payload);
                applyPayloadToWorkingLocalStorage(payload);
                await saveFactoryToCloudNow(activeFactory, payload);
                await writeAuditLog('FIRST_TIME_FRESH_START', activeFactory, {
                    category: 'data',
                    actionLabel: 'เริ่มต้นฐานข้อมูลใหม่',
                    summaryText: `สร้างโครงสร้างฐานข้อมูลเปล่าเริ่มต้นให้โรงงาน ${activeFactory}`,
                    beforePayload,
                    afterPayload: payload,
                    canRollback: true
                });
                closeModal('firstTimeSetupModal');
                triggerHostPageReload();
                refreshMobileShellData();
                if (typeof Swal !== 'undefined') {
                    Swal.fire('พร้อมใช้งานแล้ว!', `สร้างฐานข้อมูลเริ่มต้นสำหรับ ${activeFactory} เรียบร้อย`, 'success');
                }
            });
        }

        // Change password form
        const cpForm = document.getElementById('changePasswordForm');
        if (cpForm) {
            cpForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const errBox = document.getElementById('cpErrorBox');
                errBox.classList.add('hidden');
                try {
                    await changeOwnPassword(
                        document.getElementById('cpCurrent').value,
                        document.getElementById('cpNew').value,
                        document.getElementById('cpConfirm').value
                    );
                    closeModal('changePasswordModal');
                    cpForm.reset();
                    if (typeof Swal !== 'undefined') Swal.fire('เปลี่ยนรหัสผ่านสำเร็จ!', 'รหัสผ่านใหม่ถูกบันทึกเข้าระบบแล้ว', 'success');
                } catch (err) {
                    errBox.textContent = err.message || 'เปลี่ยนรหัสผ่านไม่สำเร็จ';
                    errBox.classList.remove('hidden');
                }
            });
        }

        // Admin add user form
        const addUserForm = document.getElementById('adminAddUserForm');
        if (addUserForm) {
            addUserForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const usernameRaw = document.getElementById('adminNewUsername').value;
                    const displayName = document.getElementById('adminNewDisplayName').value;
                    const password = document.getElementById('adminNewPassword').value;
                    const role = document.getElementById('adminNewRole').value;
                    await adminCreateOrResetUser({ usernameRaw, displayName, password, role, isEdit: false });
                    addUserForm.reset();
                    await renderAdminUsersTable();
                    if (typeof Swal !== 'undefined') Swal.fire('เพิ่มผู้ใช้งานสำเร็จ!', `สร้างบัญชี ${parseUsername(usernameRaw)} เรียบร้อยแล้ว`, 'success');
                } catch (err) {
                    if (typeof Swal !== 'undefined') Swal.fire('เกิดข้อผิดพลาด', err.message, 'error');
                }
            });
        }

        // Admin factory switcher dropdowns
        const navSel = document.getElementById('navAdminFactorySelect');
        if (navSel) navSel.addEventListener('change', (e) => window.StockMSAuth.switchAdminFactory(e.target.value));
        const kmSel = document.getElementById('kmAdminFactorySelect');
        if (kmSel) kmSel.addEventListener('change', (e) => window.StockMSAuth.switchAdminFactory(e.target.value));

        const logFilterUser = document.getElementById('adminLogFilterUser');
        if (logFilterUser) logFilterUser.addEventListener('change', () => renderAdminLogsModal());
        const logFilterCat = document.getElementById('adminLogFilterCategory');
        if (logFilterCat) logFilterCat.addEventListener('change', () => renderAdminLogsModal());
        const logSearch = document.getElementById('adminLogSearchInput');
        if (logSearch) logSearch.addEventListener('input', () => renderAdminLogsModal());

        bindRadialFabMenuEvents();
    }

    function showLoginOverlay() {
        document.getElementById('stockmsLoginForm')?.reset();
        const errBox = document.getElementById('loginErrorBox');
        if (errBox) {
            errBox.textContent = '';
            errBox.classList.add('hidden');
        }
        const el = document.getElementById('authLoginOverlay');
        if (el) {
            el.classList.remove('login-stage-active');
            el.classList.remove('hidden');
        }
    }

    function closeModal(id) {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
    }

    function openFirstTimeSetupModal(payload) {
        document.getElementById('firstTimeTitle').textContent = `ยินดีต้อนรับสู่ ${payload.factoryName || payload.username}`;
        document.getElementById('firstTimeUsernameLabel').textContent = payload.username;
        document.getElementById('firstTimeSetupModal')?.classList.remove('hidden');
    }

    function openChangePasswordModal() {
        const s = getSession();
        if (!s) return;
        document.getElementById('cpUserSubtitle').textContent = `บัญชี: ${s.username} (${s.displayName || s.username})`;
        document.getElementById('cpErrorBox')?.classList.add('hidden');
        document.getElementById('changePasswordForm')?.reset();
        document.getElementById('changePasswordModal')?.classList.remove('hidden');
    }

    async function renderAdminUsersTable() {
        const tbody = document.getElementById('adminUsersTableBody');
        if (!tbody) return;
        const users = await loadAllUsersList();
        const localPresence = readLocalPresenceMap();
        tbody.innerHTML = users.map(u => {
            const pRec = { ...(localPresence[u.username] || {}), ...(onlineUsersMap[u.username] || {}), onlineStatus: (onlineUsersMap[u.username]?.onlineStatus ?? u.onlineStatus ?? localPresence[u.username]?.onlineStatus), lastSeenAt: (onlineUsersMap[u.username]?.lastSeenAt || u.lastSeenAt || localPresence[u.username]?.lastSeenAt) };
            const isOn = isUserConsideredOnline(pRec);
            const presenceHtml = isOn
                ? `<span class="stockms-online-pill"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> ออนไลน์</span>`
                : `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold">${pRec.lastSeenAt ? `ออฟไลน์ (${escapeHtml(pRec.lastSeenAt.slice(11, 16))})` : 'ออฟไลน์'}</span>`;
            return `
            <tr class="hover:bg-slate-50">
                <td class="px-3.5 py-2.5 font-extrabold text-slate-800">${escapeHtml(u.username)}</td>
                <td class="px-3.5 py-2.5 font-semibold">${escapeHtml(u.displayName || u.username)}</td>
                <td class="px-3.5 py-2.5">
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${u.role === 'admin' ? 'bg-slate-800 text-white' : 'bg-blue-100 text-blue-700'}">${escapeHtml(u.role)}</span>
                </td>
                <td class="px-3.5 py-2.5">${presenceHtml}</td>
                <td class="px-3.5 py-2.5 text-[11px] text-slate-400">${u.updatedAt ? escapeHtml(u.updatedAt.slice(0, 16).replace('T', ' ')) : '-'}</td>
                <td class="px-3.5 py-2.5 text-center">
                    <div class="flex items-center justify-center gap-1.5">
                        <button type="button" onclick="window.StockMSUI.promptAdminResetPwd('${escapeHtml(u.username)}')" class="px-2.5 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 font-bold text-[11px]">
                            <i class="fas fa-key mr-1"></i> ตั้งรหัสผ่านใหม่
                        </button>
                        ${u.role !== 'admin' ? `<button type="button" onclick="window.StockMSAuth.switchAdminFactory('${escapeHtml(u.username)}'); window.StockMSUI.closeModal('adminUserManagerModal');" class="px-2.5 py-1 rounded-lg bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 font-bold text-[11px]">ดูคลังนี้</button>` : ''}
                    </div>
                </td>
            </tr>
        `;
        }).join('');
    }

    async function promptAdminResetPwd(username) {
        if (typeof Swal === 'undefined') return;
        const res = await Swal.fire({
            title: `ตั้งรหัสผ่านใหม่ให้ ${username}`,
            input: 'text',
            inputLabel: 'กรอกรหัสผ่านใหม่ (อย่างน้อย 4 ตัวอักษร)',
            inputPlaceholder: 'รหัสผ่านใหม่',
            showCancelButton: true,
            confirmButtonText: 'บันทึกรหัสผ่าน',
            cancelButtonText: 'ยกเลิก',
            inputValidator: (v) => (!v || v.length < 4) ? 'รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร' : undefined
        });
        if (res.isConfirmed && res.value) {
            try {
                await adminCreateOrResetUser({ usernameRaw: username, password: res.value, isEdit: true });
                await renderAdminUsersTable();
                Swal.fire('สำเร็จ!', `อัปเดตรหัสผ่านใหม่ของ ${username} เรียบร้อยแล้ว`, 'success');
            } catch (err) {
                Swal.fire('ผิดพลาด', err.message, 'error');
            }
        }
    }

    async function openAdminUserModal() {
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        document.getElementById('adminUserManagerModal')?.classList.remove('hidden');
        await renderAdminUsersTable();
    }

    async function openAdminCompareModal() {
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        document.getElementById('adminCompareModal')?.classList.remove('hidden');

        const rows = await loadAllFactoriesComparison();
        const totalNetworkStock = rows.reduce((sum, r) => sum + r.analytics.totalVol, 0);
        const totalNetworkCap = rows.reduce((sum, r) => sum + r.analytics.totalCap, 0);
        const netUtil = totalNetworkCap > 0 ? ((totalNetworkStock / totalNetworkCap) * 100).toFixed(1) : '0.0';
        const criticalCount = rows.filter(r => r.insight.riskLevel === 'critical').length;

        document.getElementById('adminCompareOverview').innerHTML = `
            <div class="p-3.5 rounded-2xl bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800">
                <div class="text-[11px] font-bold text-blue-600 dark:text-blue-400">จำนวนโรงงานทั้งหมด</div>
                <div class="text-xl font-black mt-0.5">${rows.length} โรงงาน</div>
            </div>
            <div class="p-3.5 rounded-2xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800">
                <div class="text-[11px] font-bold text-emerald-600 dark:text-emerald-400">ปริมาณสุรารวมทุกโรงงาน</div>
                <div class="text-xl font-black mt-0.5 tabular-nums">${totalNetworkStock.toLocaleString()} L</div>
            </div>
            <div class="p-3.5 rounded-2xl bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800">
                <div class="text-[11px] font-bold text-indigo-600 dark:text-indigo-400">อัตราใช้พื้นที่รวม</div>
                <div class="text-xl font-black mt-0.5 tabular-nums">${netUtil}%</div>
            </div>
            <div class="p-3.5 rounded-2xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800">
                <div class="text-[11px] font-bold text-rose-600 dark:text-rose-400">โรงงานต้องเฝ้าระวังเร่งด่วน</div>
                <div class="text-xl font-black mt-0.5">${criticalCount} แห่ง</div>
            </div>
        `;

        document.getElementById('adminCompareTableBody').innerHTML = rows.map(r => {
            const a = r.analytics;
            const badge = a.initialized
                ? `<span class="text-[10px] font-bold text-emerald-600">พร้อมใช้งาน</span>`
                : `<span class="text-[10px] font-bold text-amber-600">ยังไม่ Import</span>`;
            return `
                <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <td class="px-3 py-2.5">
                        <div class="font-extrabold text-slate-800 dark:text-white">${escapeHtml(a.factoryName)}</div>
                        <div class="text-[10px] text-slate-400">${escapeHtml(a.username)} • ${badge}</div>
                    </td>
                    <td class="px-3 py-2.5 text-right font-black tabular-nums">${a.totalVol.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right text-slate-500 tabular-nums">${a.totalCap.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right font-extrabold ${a.utilizationPct > 85 ? 'text-rose-600' : 'text-blue-600'} tabular-nums">${a.utilizationPct}%</td>
                    <td class="px-3 py-2.5 text-right text-emerald-700 dark:text-emerald-400 font-bold tabular-nums">${a.v70.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right text-amber-700 dark:text-amber-400 font-bold tabular-nums">${(a.v40 + a.vLowOther).toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-center font-bold ${a.qcIssues > 0 ? 'text-rose-600' : 'text-emerald-600'}">${a.qcPassRate}%</td>
                    <td class="px-3 py-2.5 text-center">
                        <button type="button" onclick="window.StockMSAuth.switchAdminFactory('${escapeHtml(a.username)}'); window.StockMSUI.closeModal('adminCompareModal');" class="px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-bold">ดูคลัง</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Render Comparison Bar Chart if Chart.js is available
        const canvas = document.getElementById('adminCompareBarCanvas');
        if (canvas && typeof Chart !== 'undefined') {
            if (adminCompareChart) adminCompareChart.destroy();
            adminCompareChart = new Chart(canvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: rows.map(r => r.analytics.username.toUpperCase()),
                    datasets: [
                        { label: 'สุรา 70° (L)', data: rows.map(r => r.analytics.v70), backgroundColor: '#10b981', borderRadius: 6 },
                        { label: 'สุรา 40°/ดีกรีต่ำ (L)', data: rows.map(r => r.analytics.v40 + r.analytics.vLowOther), backgroundColor: '#3b82f6', borderRadius: 6 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
                    scales: { y: { beginAtZero: true } }
                }
            });
        }

        // Render Per-Factory Executive Summaries & Recommendations
        document.getElementById('adminFactoryInsightsGrid').innerHTML = rows.map(r => {
            const a = r.analytics;
            const ins = r.insight;
            const borderCls = ins.riskLevel === 'critical'
                ? 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20'
                : (ins.riskLevel === 'watch'
                    ? 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20'
                    : 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20');
            const tagCls = ins.riskLevel === 'critical'
                ? 'bg-rose-600 text-white'
                : (ins.riskLevel === 'watch' ? 'bg-amber-500 text-white' : 'bg-emerald-600 text-white');
            const tagText = ins.riskLevel === 'critical' ? 'เร่งด่วน' : (ins.riskLevel === 'watch' ? 'ติดตาม' : 'ปกติ');

            const recItems = ins.recommendations.map(rec => {
                const ic = rec.level === 'critical' ? 'fa-exclamation-circle text-rose-600'
                    : (rec.level === 'warn' ? 'fa-exclamation-triangle text-amber-600'
                        : (rec.level === 'ok' ? 'fa-check-circle text-emerald-600' : 'fa-info-circle text-blue-600'));
                return `<li class="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-200"><i class="fas ${ic} mt-0.5 flex-shrink-0"></i><span>${escapeHtml(rec.text)}</span></li>`;
            }).join('');

            return `
                <div class="p-4 rounded-2xl border ${borderCls} flex flex-col justify-between gap-2.5">
                    <div>
                        <div class="flex justify-between items-start gap-2 mb-1.5">
                            <div>
                                <div class="font-black text-sm text-slate-800 dark:text-white">${escapeHtml(a.factoryName)} <span class="text-xs font-semibold text-slate-400">(${escapeHtml(a.username)})</span></div>
                                <div class="text-[11px] font-bold text-slate-600 dark:text-slate-300">${escapeHtml(ins.headline)}</div>
                            </div>
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold ${tagCls}">${tagText}</span>
                        </div>
                        <ul class="space-y-1.5 mt-2">${recItems}</ul>
                    </div>
                    <div class="pt-2 border-t border-slate-200/70 dark:border-slate-700/70 flex justify-between items-center text-[11px] text-slate-500">
                        <span>รายการ: <b>${a.txCount}</b> • รับ30วัน: <b>${a.in30d.toLocaleString()} L</b> • จ่าย30วัน: <b>${a.out30d.toLocaleString()} L</b></span>
                        <button type="button" onclick="window.StockMSAuth.switchAdminFactory('${escapeHtml(a.username)}'); window.StockMSUI.closeModal('adminCompareModal');" class="font-extrabold text-blue-600 hover:underline">สลับดูคลังนี้ →</button>
                    </div>
                </div>
            `;
        }).join('');
    }

    async function renderAdminLogsModal(forceCloudSync = false) {
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        const tbody = document.getElementById('adminLogsTableBody');
        const kpiRow = document.getElementById('adminLogsKpiRow');
        const userSel = document.getElementById('adminLogFilterUser');
        if (!tbody) return;

        if (forceCloudSync && fbDb && fbAuth?.currentUser) {
            try {
                const snap = await fbDb.collection('auditLogs').orderBy('timestamp', 'desc').limit(120).get();
                const map = new Map(readLocalAuditLogs().map(l => [l.id, l]));
                snap.forEach(doc => map.set(doc.id, { id: doc.id, ...(doc.data() || {}) }));
                saveLocalAuditLogs(Array.from(map.values()));
            } catch (e) { }
        }

        const logs = readLocalAuditLogs();
        const prevUserFilter = userSel ? userSel.value : 'ALL';
        const actorsSet = new Set(['admin']);
        Object.keys(getLocalUsersRegistry()).forEach(u => actorsSet.add(u));
        logs.forEach(l => {
            if (l.actor) actorsSet.add(l.actor);
            if (l.target) actorsSet.add(l.target);
        });
        if (userSel) {
            userSel.innerHTML = '<option value="ALL">ทุก User / โรงงาน</option>' + Array.from(actorsSet).sort().map(u => `<option value="${escapeHtml(u)}" ${u === prevUserFilter ? 'selected' : ''}>${escapeHtml(u)}</option>`).join('');
        }

        const fUser = userSel ? userSel.value : 'ALL';
        const fCat = document.getElementById('adminLogFilterCategory')?.value || 'ALL';
        const q = (document.getElementById('adminLogSearchInput')?.value || '').trim().toLowerCase();

        const getDetailsObj = (l) => {
            if (l.details && typeof l.details === 'object') return l.details;
            return {
                category: 'auth',
                actionLabel: l.action || '-',
                summaryText: typeof l.details === 'string' ? l.details : ''
            };
        };

        const filtered = logs.filter(l => {
            const d = getDetailsObj(l);
            if (fUser !== 'ALL' && l.actor !== fUser && l.target !== fUser) return false;
            if (fCat !== 'ALL' && (d.category || 'auth') !== fCat) return false;
            if (q) {
                const hay = `${l.actor || ''} ${l.target || ''} ${l.action || ''} ${d.actionLabel || ''} ${d.summaryText || ''}`.toLowerCase();
                if (!hay.includes(q)) return false;
            }
            return true;
        });

        const totalRollbackReady = logs.filter(l => getDetailsObj(l).canRollback).length;
        const rollbackCount = logs.filter(l => getDetailsObj(l).category === 'rollback').length;
        const activeFactoriesCount = new Set(logs.filter(l => l.target && l.target !== 'admin').map(l => l.target)).size;

        if (kpiRow) {
            kpiRow.innerHTML = `
                <div class="p-3 rounded-2xl bg-blue-50 border border-blue-200">
                    <div class="text-[10px] font-bold text-blue-600">จำนวน Logs ทั้งหมด</div>
                    <div class="text-xl font-black mt-0.5 tabular-nums">${logs.length}</div>
                </div>
                <div class="p-3 rounded-2xl bg-emerald-50 border border-emerald-200">
                    <div class="text-[10px] font-bold text-emerald-700">จุดย้อนข้อมูล (Snapshots)</div>
                    <div class="text-xl font-black mt-0.5 tabular-nums">${totalRollbackReady} จุด</div>
                </div>
                <div class="p-3 rounded-2xl bg-indigo-50 border border-indigo-200">
                    <div class="text-[10px] font-bold text-indigo-700">โรงงานที่มีความเคลื่อนไหว</div>
                    <div class="text-xl font-black mt-0.5 tabular-nums">${activeFactoriesCount} แห่ง</div>
                </div>
                <div class="p-3 rounded-2xl bg-rose-50 border border-rose-200">
                    <div class="text-[10px] font-bold text-rose-700">Admin ย้อนข้อมูลแล้ว</div>
                    <div class="text-xl font-black mt-0.5 tabular-nums">${rollbackCount} ครั้ง</div>
                </div>
            `;
        }

        if (!filtered.length) {
            tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-xs text-slate-400">ไม่พบประวัติกิจกรรมตามเงื่อนไขที่เลือก</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(l => {
            const d = getDetailsObj(l);
            const cat = ['tx', 'settings', 'data', 'auth', 'rollback'].includes(d.category) ? d.category : 'auth';
            const dt = l.timestamp ? l.timestamp.replace('T', ' ').slice(0, 19) : '-';
            const hasBefore = d.canRollback && d.txCountBefore !== null && d.txCountBefore !== undefined;
            const hasAfter = d.canRollback && d.txCountAfter !== null && d.txCountAfter !== undefined;
            const snapSummary = d.canRollback
                ? `<div class="text-[10px] font-bold text-slate-700 tabular-nums">${hasBefore ? `${d.txCountBefore} (${Number(d.volBefore || 0).toLocaleString()} L)` : '-'} → ${hasAfter ? `${d.txCountAfter} (${Number(d.volAfter || 0).toLocaleString()} L)` : '-'}</div>
                   <button type="button" onclick="window.StockMSUI.previewLogSnapshot('${escapeHtml(l.id)}')" class="mt-1 text-[10px] font-bold text-blue-600 hover:underline"><i class="fas fa-search-plus mr-0.5"></i> ดูรายละเอียด</button>`
                : `<span class="text-[10px] text-slate-400">บันทึกเหตุการณ์</span>`;

            const hasSingleIds = Array.isArray(d.affectedTxIds) && d.affectedTxIds.length > 0;
            const rollbackControls = (d.canRollback && l.target && l.target !== 'admin')
                ? `<div class="flex flex-col sm:flex-row items-center justify-center gap-1 flex-wrap">
                        ${hasBefore ? `<button type="button" onclick="window.StockMSUI.adminRollbackFactory('${escapeHtml(l.id)}', 'before')" class="px-2 py-1 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 text-[10px] font-extrabold whitespace-nowrap" title="ย้อนกลับไปสถานะก่อนรายการนี้เฉพาะคลัง ${escapeHtml(l.target)}"><i class="fas fa-undo mr-1"></i>ก่อนทำ</button>` : ''}
                        ${hasAfter ? `<button type="button" onclick="window.StockMSUI.adminRollbackFactory('${escapeHtml(l.id)}', 'after')" class="px-2 py-1 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-[10px] font-extrabold whitespace-nowrap" title="ย้อนข้อมูลมาที่จุดเวลานี้เฉพาะคลัง ${escapeHtml(l.target)}"><i class="fas fa-history mr-1"></i>จุดนี้</button>` : ''}
                        ${hasSingleIds ? `<button type="button" onclick="window.StockMSUI.adminRollbackFactory('${escapeHtml(l.id)}', 'single_tx')" class="px-2 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 text-[10px] font-extrabold whitespace-nowrap" title="ย้อนกลับเฉพาะรายการ ID ใน Log นี้ โดยคงรายการอื่นไว้"><i class="fas fa-crosshairs mr-1"></i>เฉพาะ ID</button>` : ''}
                   </div>`
                : `<span class="text-[10px] text-slate-300">-</span>`;

            return `
                <tr class="hover:bg-slate-50/80 transition">
                    <td class="px-3 py-2.5 text-[11px] font-mono text-slate-500 whitespace-nowrap">${escapeHtml(dt)}</td>
                    <td class="px-3 py-2.5 whitespace-nowrap">
                        <div class="font-extrabold text-slate-800">${escapeHtml(l.actor || '-')}</div>
                        <div class="text-[10px] text-slate-500">คลัง: <b>${escapeHtml(l.target || '-')}</b></div>
                    </td>
                    <td class="px-3 py-2.5 whitespace-nowrap">
                        <span class="stockms-log-badge ${cat}">${escapeHtml(d.actionLabel || l.action)}</span>
                    </td>
                    <td class="px-3 py-2.5 text-[11px] text-slate-700">${escapeHtml(d.summaryText || '-')}</td>
                    <td class="px-3 py-2.5 text-center">${snapSummary}</td>
                    <td class="px-3 py-2.5 text-center">${rollbackControls}</td>
                </tr>
            `;
        }).join('');
    }

    async function openAdminLogsModal() {
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        unreadAdminLogsCount = 0;
        updateAdminLogsBadgeUI();
        const mEl = document.getElementById('adminClearLogsMonth');
        if (mEl && !mEl.value) {
            mEl.value = new Date().toISOString().slice(0, 7);
        }
        const ySel = document.getElementById('adminClearLogsYear');
        if (ySel) {
            const years = new Set([String(new Date().getFullYear())]);
            readLocalAuditLogs().forEach(l => {
                if (l.timestamp && /^\d{4}/.test(l.timestamp)) years.add(l.timestamp.slice(0, 4));
            });
            const prevY = ySel.value;
            ySel.innerHTML = Array.from(years).sort().reverse().map(y => `<option value="${y}" ${y === prevY ? 'selected' : ''}>ปี ${y}</option>`).join('');
        }
        document.getElementById('adminAuditLogsModal')?.classList.remove('hidden');
        updateCloudBadgeUI();
        await renderAdminLogsModal(true);
    }

    async function previewLogSnapshot(logId) {
        const s = getSession();
        if (!s || s.role !== 'admin') return;
        const entry = readLocalAuditLogs().find(x => x.id === logId);
        if (!entry || typeof Swal === 'undefined') return;
        const d = (entry.details && typeof entry.details === 'object') ? entry.details : {};
        const beforeSnap = await loadSnapshotPayload(entry, 'before');
        const afterSnap = await loadSnapshotPayload(entry, 'after');
        const esc = escapeHtml;
        const fmtStats = (snap) => {
            if (!snap) return '<span class="text-slate-400">ไม่มีข้อมูล</span>';
            const st = computeFactoryAnalytics(snap);
            const txs = (snap.liquor_transactions || []).slice(-5).reverse();
            const txLines = txs.map(t => `<li class="truncate">• ${esc(t.date || '-')} | ${esc(t.type || '-')} | ถัง ${esc(t.tankId || '-')} (${(parseFloat(t.volume ?? t.vol ?? 0) || 0).toLocaleString()} L)</li>`).join('');
            return `
                <div class="font-black text-slate-800">${st.txCount} รายการ • ${st.totalVol.toLocaleString()} L</div>
                <div class="text-[10px] text-slate-500 mb-1">70°: ${st.v70.toLocaleString()} L | 40°: ${st.v40.toLocaleString()} L</div>
                ${txLines ? `<ul class="text-[10px] text-slate-600 space-y-0.5 mt-1 border-t pt-1">${txLines}</ul>` : '<div class="text-[10px] text-slate-400">ไม่มีรายการเดินบัญชี</div>'}
            `;
        };
        Swal.fire({
            title: `รายละเอียด Snapshot • ${esc(entry.target || '-')}`,
            width: 680,
            html: `
                <div class="text-left text-xs space-y-3">
                    <div class="p-3 rounded-xl bg-slate-50 border border-slate-200">
                        <div><b>เวลา:</b> ${esc((entry.timestamp || '').replace('T', ' ').slice(0, 19))}</div>
                        <div><b>ผู้ทำรายการ:</b> ${esc(entry.actor || '-')} | <b>กิจกรรม:</b> ${esc(d.actionLabel || entry.action)}</div>
                        <div><b>สรุป:</b> ${esc(d.summaryText || '-')}</div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div class="p-3 rounded-xl bg-amber-50/60 border border-amber-200">
                            <div class="text-[11px] font-black text-amber-800 mb-1">สถานะก่อนทำรายการ (Before)</div>
                            ${fmtStats(beforeSnap)}
                        </div>
                        <div class="p-3 rounded-xl bg-emerald-50/60 border border-emerald-200">
                            <div class="text-[11px] font-black text-emerald-800 mb-1">สถานะหลังทำรายการ (After)</div>
                            ${fmtStats(afterSnap)}
                        </div>
                    </div>
                </div>
            `,
            confirmButtonText: 'ปิดหน้าต่าง'
        });
    }

    async function renderAuthHeaderControls() {
        const session = getSession();
        if (!session) return;

        const activeFactory = getActiveFactoryId();
        const isAdmin = session.role === 'admin';

        const navName = document.getElementById('navUserName');
        if (navName) {
            navName.textContent = isAdmin
                ? `Admin (${session.username}) → ${activeFactory}`
                : `${session.displayName || session.username} (${session.username})`;
        }

        const showAdminElems = (ids, flex) => {
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (!el) return;
                if (isAdmin) {
                    el.classList.remove('hidden');
                    if (flex) el.classList.add('flex');
                } else {
                    el.classList.add('hidden');
                    if (flex) el.classList.remove('flex');
                }
            });
        };
        showAdminElems(['navAdminFactoryWrap', 'navAdminOnlineUsersWrap', 'navBtnAdminCompare', 'navBtnAdminLogs', 'navBtnAdminUsers', 'kmAdminSwitchBar'], true);
        showAdminElems(['kmBtnAdminUsers', 'kmBtnAdminCompare', 'kmBtnAdminLogs'], false);
        updateAdminLogsBadgeUI();
        renderOnlinePresenceUI();

        if (isAdmin) {
            const users = await loadAllUsersList();
            const factories = users.filter(u => u.role !== 'admin');
            const optionsHtml = factories.map(u => `<option value="${escapeHtml(u.username)}" ${u.username === activeFactory ? 'selected' : ''}>${escapeHtml(u.displayName || u.username)} (${escapeHtml(u.username)})</option>`).join('');
            ['navAdminFactorySelect', 'kmAdminFactorySelect'].forEach(selId => {
                const sel = document.getElementById(selId);
                if (sel) sel.innerHTML = optionsHtml;
            });
        }
        updateCloudBadgeUI();
    }

    // =========================================================================
    // 11. KOSMATE MOBILE SHELL DATA & INTERACTION CONTROLLER
    // =========================================================================
    function isDashboardPage() {
        return /dashboard\.html/i.test(window.location.pathname) || !!document.getElementById('btnQcHeaderMonitor');
    }

    function refreshMobileShellData() {
        const session = getSession();
        if (!session) return;

        const factoryId = getActiveFactoryId();
        const payload = readWorkingPayload(factoryId);
        const analytics = computeFactoryAnalytics(payload);

        const gTitle = document.getElementById('kmGreetingTitle');
        if (gTitle) gTitle.textContent = `สวัสดี, ${session.role === 'admin' ? 'Admin' : (payload.factoryName || factoryId)} 👋`;
        const fSub = document.getElementById('kmFactorySub');
        if (fSub) fSub.textContent = `${session.role === 'admin' ? `กำลังดู: ${factoryId}` : factoryId}`;

        const setTxt = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        setTxt('kmHeroTotalVol', `${analytics.totalVol.toLocaleString()} L`);
        setTxt('kmHeroTotalCap', `${analytics.totalCap.toLocaleString()} L`);
        setTxt('kmHeroUtilPct', `${analytics.utilizationPct}%`);
        setTxt('kmPill70', `${analytics.v70.toLocaleString()} L`);
        setTxt('kmPill40', `${analytics.v40.toLocaleString()} L`);
        setTxt('kmPillLow', `${analytics.vLowOther.toLocaleString()} L`);
        const prog = document.getElementById('kmHeroProgress');
        if (prog) prog.style.width = `${Math.min(100, analytics.utilizationPct)}%`;

        const qcBadge = document.getElementById('kmQcBadge');
        if (qcBadge) {
            qcBadge.textContent = analytics.qcIssues;
            qcBadge.classList.toggle('hidden', analytics.qcIssues <= 0);
        }

        // Profile info
        setTxt('kmProfileAvatar', (session.username || 'S').slice(0, 2).toUpperCase());
        setTxt('kmProfileName', session.displayName || session.username);
        setTxt('kmProfileMeta', `Username: ${session.username} • Role: ${session.role.toUpperCase()}`);
        setTxt('kmProfileFactoryBadge', `คลังที่ใช้งาน: ${factoryId} (${analytics.totalVol.toLocaleString()} L)`);

        const onDash = isDashboardPage();
        const crossLink = document.getElementById('kmCrossPageLink');
        const crossLabel = document.getElementById('kmCrossPageLabel');
        if (crossLink && crossLabel) {
            crossLink.href = onDash ? 'index.html' : 'dashboard.html';
            crossLabel.textContent = onDash ? 'เปิดหน้าจัดการคลัง (Stock Control)' : 'เปิด Executive Dashboard';
        }

        // Render 8 Quick Action Buttons (KosMate 4x2 Pastel Squircle Grid)
        const grid = document.getElementById('kmQuickGrid');
        if (grid) {
            const items = onDash ? [
                { label: 'ผังคลัง & ถัง', icon: 'fa-th', bg: '#dcfce7', color: '#15803d', fn: "window.StockMSUI.switchMobileTab('tanks')" },
                { label: 'เฝ้าระวัง QC', icon: 'fa-microscope', bg: '#dbeafe', color: '#1d4ed8', fn: "window.StockMSUI.triggerQCAction()" },
                { label: 'บันทึกรับ-จ่าย', icon: 'fa-plus-circle', bg: '#fef3c7', color: '#b45309', fn: "window.location.href='index.html'" },
                { label: 'จัดการคลัง', icon: 'fa-tasks', bg: '#ede9fe', color: '#6d28d9', fn: "window.location.href='index.html'" },
                { label: 'กราฟครบกำหนด', icon: 'fa-chart-bar', bg: '#ffe4e6', color: '#be123c', fn: "window.StockMSUI.switchMobileTab('reports')" },
                { label: 'รีเฟรชข้อมูล', icon: 'fa-sync-alt', bg: '#ffedd5', color: '#c2410c', fn: "if(typeof updateAllData==='function') updateAllData();" },
                { label: 'มุมมองเต็มหน้า', icon: 'fa-desktop', bg: '#ccfbf1', color: '#0f766e', fn: "toggleMobileAppLayout(true)" },
                { label: session.role === 'admin' ? 'เทียบทุกโรงงาน' : 'บัญชี/สำรอง', icon: session.role === 'admin' ? 'fa-balance-scale-right' : 'fa-user-shield', bg: '#f1f5f9', color: '#334155', fn: session.role === 'admin' ? "window.StockMSUI.openAdminCompareModal()" : "window.StockMSUI.switchMobileTab('profile')" }
            ] : [
                { label: 'ผังถังสุรา', icon: 'fa-th', bg: '#dcfce7', color: '#15803d', fn: "if(typeof openStockLayout==='function') openStockLayout();" },
                { label: 'เฝ้าระวัง QC', icon: 'fa-microscope', bg: '#dbeafe', color: '#1d4ed8', fn: "window.StockMSUI.triggerQCAction()" },
                { label: 'บันทึกรับ-จ่าย', icon: 'fa-exchange-alt', bg: '#fef3c7', color: '#b45309', fn: "window.StockMSUI.openTransactionEntry()" },
                { label: 'ปรับเทียบยอด', icon: 'fa-balance-scale', bg: '#ede9fe', color: '#6d28d9', fn: "if(typeof openReconcileModal==='function') openReconcileModal();" },
                { label: 'รายงานประจำวัน', icon: 'fa-file-alt', bg: '#ffe4e6', color: '#be123c', fn: "if(typeof openDailyReport==='function') openDailyReport();" },
                { label: 'ตั้งค่าระบบ/ถัง', icon: 'fa-cogs', bg: '#ffedd5', color: '#c2410c', fn: "if(typeof openMasterSettingsModal==='function') openMasterSettingsModal();" },
                { label: 'ทัณฑ์บน/ซ่อม', icon: 'fa-tools', bg: '#ccfbf1', color: '#0f766e', fn: "if(typeof manageTankSettings==='function') manageTankSettings();" },
                { label: session.role === 'admin' ? 'เทียบทุกโรงงาน' : 'สำรอง/นำเข้า', icon: session.role === 'admin' ? 'fa-balance-scale-right' : 'fa-database', bg: '#f1f5f9', color: '#334155', fn: session.role === 'admin' ? "window.StockMSUI.openAdminCompareModal()" : "window.StockMSUI.switchMobileTab('profile')" }
            ];
            grid.innerHTML = items.map(it => `
                <button type="button" class="kosmate-quick-item" onclick="${it.fn}">
                    <div class="kosmate-squircle" style="background:${it.bg};color:${it.color};">
                        <i class="fas ${it.icon}"></i>
                    </div>
                    <span class="kosmate-quick-label">${escapeHtml(it.label)}</span>
                </button>
            `).join('');
        }

        // Render Top 5 Latest Transactions
        renderMobileTankMatrix(payload);
        const listEl = document.getElementById('kmRecentTxList');
        if (listEl) {
            const latest = [...(payload.liquor_transactions || [])].sort((a, b) => (b.id || 0) - (a.id || 0)).slice(0, 5);
            if (!latest.length) {
                listEl.innerHTML = `<div class="py-5 text-center text-xs text-slate-400">ยังไม่มีรายการเคลื่อนไหวสุรา</div>`;
            } else {
                listEl.innerHTML = latest.map(tx => {
                    const isIn = tx.type && tx.type.includes('IN');
                    const isBlend = tx.type && tx.type.includes('BLEND');
                    const isTrf = tx.type && tx.type.includes('TRANSFER');
                    const pillCls = isBlend
                        ? 'bg-fuchsia-100 text-fuchsia-700 dark:bg-fuchsia-950/70 dark:text-fuchsia-300'
                        : (isIn ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300'
                            : (isTrf ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-950/70 dark:text-indigo-300'
                                : 'bg-blue-100 text-blue-700 dark:bg-blue-950/70 dark:text-blue-300'));
                    const iconCls = isIn ? 'fa-arrow-down text-emerald-600 bg-emerald-50' : (isBlend ? 'fa-flask text-fuchsia-600 bg-fuchsia-50' : 'fa-arrow-up text-blue-600 bg-blue-50');
                    const volNum = parseFloat(tx.volume) || 0;
                    return `
                        <div class="kosmate-tx-row">
                            <div class="flex items-center gap-2.5 min-w-0">
                                <div class="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0 ${iconCls}"><i class="fas ${iconCls.split(' ')[0]} text-xs"></i></div>
                                <div class="min-w-0">
                                    <div class="text-xs font-extrabold text-slate-800 dark:text-slate-100 truncate">ถัง ${escapeHtml(tx.tankId)}</div>
                                    <div class="text-[10px] text-slate-400 truncate">${escapeHtml(tx.date)} ${tx.batch ? '• ' + escapeHtml(tx.batch) : ''}</div>
                                </div>
                            </div>
                            <div class="text-right flex-shrink-0">
                                <span class="px-2 py-0.5 rounded-full text-[9px] font-extrabold ${pillCls}">${escapeHtml(tx.type)}</span>
                                <div class="text-xs font-black text-slate-800 dark:text-slate-100 tabular-nums mt-0.5">${volNum.toLocaleString(undefined, { maximumFractionDigits: 1 })} L</div>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }
    }

    function computePerTankLiveMap(payload) {
        const customTanks = (Array.isArray(payload.custom_tanks) && payload.custom_tanks.length) ? payload.custom_tanks : UNIFIED_DEFAULT_TANKS;
        const buildings = payload.custom_buildings || UNIFIED_DEFAULT_BUILDINGS;
        const txs = Array.isArray(payload.liquor_transactions) ? payload.liquor_transactions : [];
        const map = {};
        customTanks.forEach(t => {
            const bType = t.type || (buildings[t.b] ? buildings[t.b].type : 'High');
            map[t.id] = { id: t.id, b: t.b, cap: Number(t.cap) || 0, vol: 0, type: isDefaultBlendingTank(t.id) ? '40Deg' : bType, layers: [] };
        });
        [...txs].sort((a, b) => new Date(a.date) - new Date(b.date) || ((Number(a.id) || 0) - (Number(b.id) || 0))).forEach(tx => {
            const t = map[tx.tankId];
            if (!t) return;
            const vol = parseFloat(tx.volume) || 0;
            const tu = String(tx.type || '').toUpperCase();
            if (tu.includes('IN')) {
                t.vol += vol;
                t.layers.push({ date: tx.date, vol, targetDegree: tx.targetDegree || null });
            } else if (tu.includes('OUT')) {
                let rem = vol;
                t.vol = Math.max(0, t.vol - rem);
                while (rem > 0.001 && t.layers.length) {
                    if (t.layers[0].vol > rem + 0.001) { t.layers[0].vol -= rem; rem = 0; }
                    else { rem -= t.layers[0].vol; t.layers.shift(); }
                }
            }
        });
        return map;
    }

    function setMobileTankFilter(bKey) {
        kmTankMatrixBuilding = bKey || 'ALL';
        const s = getSession();
        if (!s) return;
        renderMobileTankMatrix(readWorkingPayload(getActiveFactoryId()));
    }

    function renderMobileTankMatrix(payload) {
        const grid = document.getElementById('kmMobileTankGrid');
        if (!grid) return;
        document.querySelectorAll('#kmTankFilterPills button').forEach(btn => {
            const isActive = btn.getAttribute('data-km-b') === kmTankMatrixBuilding;
            btn.className = isActive
                ? 'px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-800 text-white'
                : 'px-2 py-0.5 rounded-lg text-[10px] font-bold bg-slate-100 text-slate-600';
        });

        const customTanks = (Array.isArray(payload.custom_tanks) && payload.custom_tanks.length) ? payload.custom_tanks : UNIFIED_DEFAULT_TANKS;
        const tankConfig = payload.tank_config || {};
        const buildings = payload.custom_buildings || UNIFIED_DEFAULT_BUILDINGS;
        const liveMap = computePerTankLiveMap(payload);
        const filtered = customTanks
            .filter(t => kmTankMatrixBuilding === 'ALL' || t.b === kmTankMatrixBuilding)
            .sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, { numeric: true }));

        const subEl = document.getElementById('kmTankMatrixSubtitle');
        if (subEl) subEl.textContent = `แสดง ${filtered.length} ถัง • แตะที่ถังเพื่อเปิดผังคลัง / ประวัติ`;

        const now = Date.now();
        grid.innerHTML = filtered.map(t => {
            const st = liveMap[t.id] || { vol: 0, cap: t.cap, layers: [] };
            const cfgStatus = tankConfig[t.id]?.status;
            const pct = t.cap > 0 ? Math.min(100, (st.vol / t.cap) * 100) : 0;
            const bType = t.type || (buildings[t.b] ? buildings[t.b].type : 'High');
            const degLabel = st.layers.length && st.layers[st.layers.length - 1]?.targetDegree
                ? String(st.layers[st.layers.length - 1].targetDegree)
                : (bType === 'High' ? '70' : '40');
            const isReady = st.layers.some(l => {
                const d = Date.parse(l.date || '');
                return d > 0 && ((now - d) / 86400000) >= (bType === 'High' ? 14 : 7);
            });

            let barCls = bType === 'High' ? 'bg-emerald-500' : 'bg-amber-500';
            let statusDot = st.vol > 0 ? (isReady ? 'bg-emerald-500' : 'bg-amber-400') : 'bg-slate-300';
            if (cfgStatus === 'repair') { barCls = 'bg-rose-400'; statusDot = 'bg-rose-500'; }
            else if (cfgStatus === 'bonded') { barCls = 'bg-purple-400'; statusDot = 'bg-purple-500'; }

            const clickAction = !isDashboardPage() && typeof window.openStockLayout === 'function'
                ? 'openStockLayout()'
                : "window.StockMSUI.switchMobileTab('tanks')";

            return `
                <button type="button" onclick="${clickAction}" class="km-tank-tile" title="ถัง ${escapeHtml(t.id)}">
                    <div class="flex items-center justify-between gap-1 mb-1">
                        <span class="text-[10px] font-black text-slate-800 truncate">${escapeHtml(t.id)}</span>
                        <span class="w-1.5 h-1.5 rounded-full flex-shrink-0 ${statusDot}"></span>
                    </div>
                    <div class="w-full h-1.5 bg-slate-200/80 rounded-full overflow-hidden mb-1">
                        <div class="h-full ${barCls}" style="width:${pct.toFixed(0)}%"></div>
                    </div>
                    <div class="flex items-center justify-between text-[9px] font-bold tabular-nums">
                        <span class="${st.vol > 0 ? 'text-slate-800' : 'text-slate-400'}">${Math.round(st.vol).toLocaleString()}</span>
                        <span class="text-slate-400">${degLabel}°</span>
                    </div>
                </button>
            `;
        }).join('');
    }

    function switchMobileTab(tabName) {
        currentMobileTab = tabName;
        document.querySelectorAll('.kosmate-nav-item').forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-km-tab') === tabName);
        });
        const v10IdxMap = { home: 0, tanks: 1, reports: 2, profile: 3 };
        const idx = v10IdxMap[tabName] ?? 0;
        const indicator = document.getElementById('kmGlassyTabIndicator');
        if (indicator) {
            indicator.style.transform = `translateX(${idx * 100}%)`;
        }
        document.querySelectorAll('.km-glassy-tab-btn').forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-km-v10-tab') === tabName);
        });

        const paneHome = document.getElementById('kmPaneHome');
        const paneProfile = document.getElementById('kmPaneProfile');
        const returnBar = document.getElementById('kmClassicReturnBar');

        if (tabName === 'home') {
            document.body.classList.add('kosmate-tab-active');
            paneHome?.classList.remove('hidden');
            paneProfile?.classList.add('hidden');
            returnBar?.classList.add('hidden');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } else if (tabName === 'profile') {
            document.body.classList.add('kosmate-tab-active');
            paneHome?.classList.add('hidden');
            paneProfile?.classList.remove('hidden');
            returnBar?.classList.add('hidden');
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } else {
            // 'tanks' or 'reports': reveal main app content below returnBar and scroll to relevant section
            document.body.classList.remove('kosmate-tab-active');
            paneHome?.classList.add('hidden');
            paneProfile?.classList.add('hidden');
            returnBar?.classList.remove('hidden');
            if (tabName === 'tanks') {
                if (typeof window.openStockLayout === 'function' && !isDashboardPage()) {
                    window.openStockLayout();
                } else {
                    const target = document.querySelector('#tankHeatmapContainer, #dashboardGrid, main');
                    target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            } else if (tabName === 'reports') {
                const target = document.getElementById('transactionTableBody')?.closest('.glass-card')
                    || document.getElementById('forecastChart')?.closest('.glass-card')
                    || document.querySelector('main');
                target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    }

    function openTransactionEntry() {
        if (isDashboardPage()) {
            window.location.href = 'index.html#new-tx';
            return;
        }
        document.body.classList.remove('kosmate-tab-active');
        document.getElementById('kmPaneHome')?.classList.add('hidden');
        document.getElementById('kmPaneProfile')?.classList.add('hidden');
        document.getElementById('kmClassicReturnBar')?.classList.remove('hidden');
        document.getElementById('transactionForm')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function triggerDailyReportAction() {
        if (!isDashboardPage() && typeof window.openDailyReport === 'function') {
            window.openDailyReport();
        } else {
            window.location.href = 'index.html#daily-report';
        }
    }

    function triggerReconcileAction() {
        if (!isDashboardPage() && typeof window.openReconcileModal === 'function') {
            window.openReconcileModal();
        } else {
            window.location.href = 'index.html#reconcile';
        }
    }

    function setRadialHintState(itemEl) {
        const hint = document.getElementById('kosmateRadialHint');
        if (!hint) return;
        if (itemEl) {
            const title = itemEl.getAttribute('data-radial-title') || itemEl.innerText.trim();
            hint.textContent = `ปล่อยนิ้วเพื่อเปิด: ${title}`;
            hint.classList.add('active-target');
        } else {
            hint.textContent = 'ลากนิ้วไปที่ปุ่มแล้วปล่อย';
            hint.classList.remove('active-target');
        }
    }

    function openRadialMenu() {
        const overlay = document.getElementById('kosmateRadialMenuOverlay');
        if (!overlay) return;
        overlay.querySelectorAll('.kosmate-radial-item.is-active').forEach(el => el.classList.remove('is-active'));
        setRadialHintState(null);
        overlay.classList.add('open');
        overlay.setAttribute('aria-hidden', 'false');
    }

    function closeRadialMenu() {
        const overlay = document.getElementById('kosmateRadialMenuOverlay');
        if (!overlay) return;
        overlay.classList.remove('open');
        overlay.setAttribute('aria-hidden', 'true');
        overlay.querySelectorAll('.kosmate-radial-item.is-active').forEach(el => el.classList.remove('is-active'));
        setRadialHintState(null);
    }

    function toggleRadialMenu() {
        const overlay = document.getElementById('kosmateRadialMenuOverlay');
        if (!overlay) return;
        if (overlay.classList.contains('open')) closeRadialMenu();
        else openRadialMenu();
    }

    function executeRadialAction(action) {
        if (action === 'tx') openTransactionEntry();
        else if (action === 'daily') triggerDailyReportAction();
        else if (action === 'qc') window.StockMSUI.triggerQCAction();
        else if (action === 'reconcile') triggerReconcileAction();
    }

    function bindRadialFabMenuEvents() {
        const fabBtn = document.getElementById('kosmateMainFabBtn');
        const overlay = document.getElementById('kosmateRadialMenuOverlay');
        const closeBtn = document.getElementById('kosmateRadialCloseBtn');
        if (!fabBtn || !overlay || fabBtn.dataset.radialBound === '1') return;
        fabBtn.dataset.radialBound = '1';
        fabBtn.style.touchAction = 'none';

        let dragState = null;
        let suppressNextFabClickAt = 0;

        const findHoveredItem = (x, y) => {
            const direct = document.elementFromPoint(x, y)?.closest?.('.kosmate-radial-item');
            if (direct && overlay.contains(direct)) return direct;
            let best = null;
            let bestDist = 48;
            overlay.querySelectorAll('.kosmate-radial-item').forEach(item => {
                const circle = item.querySelector('.kosmate-radial-circle') || item;
                const r = circle.getBoundingClientRect();
                if (!r.width) return;
                const dist = Math.hypot(x - (r.left + r.width / 2), y - (r.top + r.height / 2));
                if (dist <= bestDist) {
                    bestDist = dist;
                    best = item;
                }
            });
            return best;
        };

        const highlightItemAt = (x, y) => {
            const matched = findHoveredItem(x, y);
            overlay.querySelectorAll('.kosmate-radial-item').forEach(el => {
                el.classList.toggle('is-active', el === matched);
            });
            setRadialHintState(matched);
            return matched;
        };

        fabBtn.addEventListener('pointerdown', (e) => {
            if (e.button && e.button !== 0) return;
            const wasClosed = !overlay.classList.contains('open');
            dragState = { active: true, startX: e.clientX, startY: e.clientY, dragged: false };
            if (wasClosed) {
                openRadialMenu();
                suppressNextFabClickAt = Date.now();
            }
        });

        fabBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (Date.now() - suppressNextFabClickAt < 380) {
                suppressNextFabClickAt = 0;
                return;
            }
            toggleRadialMenu();
        });

        window.addEventListener('pointermove', (e) => {
            if (!dragState?.active || !overlay.classList.contains('open')) return;
            if (Math.hypot(e.clientX - dragState.startX, e.clientY - dragState.startY) >= 14) {
                dragState.dragged = true;
            }
            highlightItemAt(e.clientX, e.clientY);
        }, { passive: true });

        const finishDrag = (e) => {
            if (!dragState?.active) return;
            const st = dragState;
            dragState = null;
            if (!overlay.classList.contains('open')) return;
            const targetItem = st.dragged ? highlightItemAt(e.clientX, e.clientY) : null;
            if (st.dragged) suppressNextFabClickAt = Date.now();
            if (targetItem) {
                const action = targetItem.getAttribute('data-radial-action');
                closeRadialMenu();
                executeRadialAction(action);
            } else if (st.dragged) {
                overlay.querySelectorAll('.kosmate-radial-item.is-active').forEach(el => el.classList.remove('is-active'));
                setRadialHintState(null);
            }
        };
        window.addEventListener('pointerup', finishDrag);
        window.addEventListener('pointercancel', finishDrag);

        overlay.querySelectorAll('.kosmate-radial-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const action = item.getAttribute('data-radial-action');
                closeRadialMenu();
                executeRadialAction(action);
            });
        });

        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                closeRadialMenu();
            });
        }

        overlay.addEventListener('click', (e) => {
            if (e.target === overlay || e.target === document.getElementById('kosmateRadialHint')) {
                closeRadialMenu();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlay.classList.contains('open')) {
                closeRadialMenu();
            }
        });
    }

    window.StockMSUI = {
        closeModal,
        openChangePasswordModal,
        openAdminUserModal,
        openAdminCompareModal,
        openAdminLogsModal,
        renderAdminLogsModal,
        previewLogSnapshot,
        adminRollbackFactory,
        clearAuditLogsByPeriod,
        setMobileTankFilter,
        promptAdminResetPwd,
        switchMobileTab,
        openTransactionEntry,
        triggerDailyReportAction,
        triggerReconcileAction,
        openRadialMenu,
        closeRadialMenu,
        toggleRadialMenu,
        executeRadialAction,
        openFullHistoryView: function () {
            if (isDashboardPage()) {
                window.location.href = 'index.html';
            } else {
                switchMobileTab('reports');
                const hist = document.getElementById('transactionTableBody')?.closest('.glass-card');
                hist?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        },
        triggerPrimaryFab: function () {
            const isMobileView = window.innerWidth <= 900 || document.body.classList.contains('kosmate-force-mobile');
            if (isMobileView) {
                toggleRadialMenu();
                return;
            }
            openTransactionEntry();
        },
        triggerQCAction: function () {
            if (typeof window.openQCAnomalyModal === 'function') {
                window.openQCAnomalyModal('trend');
            } else {
                window.location.href = 'dashboard.html?qc=open#qc-modal';
            }
        },
        triggerBackupAction: function () {
            if (typeof window.exportData === 'function') {
                window.exportData();
            } else {
                window.location.href = 'index.html';
            }
        },
        triggerImportAction: function () {
            const imp = document.getElementById('importFile');
            if (imp) imp.click();
            else window.location.href = 'index.html';
        }
    };

    async function waitForFirebaseAuthRestore(timeoutMs = 1200) {
        if (!fbAuth || fbAuth.currentUser) return fbAuth?.currentUser || null;
        return new Promise((resolve) => {
            let done = false;
            let unsub = null;
            const finish = (u) => {
                if (done) return;
                done = true;
                try { if (typeof unsub === 'function') unsub(); } catch (e) { }
                resolve(u || null);
            };
            try {
                unsub = fbAuth.onAuthStateChanged((user) => finish(user));
            } catch (e) {
                finish(null);
            }
            setTimeout(() => finish(fbAuth?.currentUser || null), timeoutMs);
        });
    }

    // =========================================================================
    // 12. BOOTSTRAP ON DOCUMENT READY
    // =========================================================================
    async function bootstrapStockMS() {
        document.documentElement.classList.remove('dark');
        try {
            localStorage.removeItem('app_theme');
            localStorage.removeItem('app_sound_muted');
        } catch (e) { }

        document.body.classList.add('stockms-locked');
        initFirebaseInstances();
        injectGlobalUI();
        patchHostStorageHooks();

        // Default mobile tab class cleanly
        if (window.innerWidth <= 900) {
            document.body.classList.add('kosmate-tab-active');
        }

        const session = getSession();
        if (!session) {
            clearWorkingLocalStorage();
            showLoginOverlay();
            updateCloudBadgeUI();
            return;
        }

        // Wait briefly for Firebase Auth persistence restore on page reload; sign out legacy anonymous tokens
        const restoredUser = await waitForFirebaseAuthRestore(1200);
        if (restoredUser && restoredUser.isAnonymous && fbAuth) {
            try { await fbAuth.signOut(); } catch (e) { }
            clearSession();
            clearWorkingLocalStorage();
            showLoginOverlay();
            updateCloudBadgeUI();
            return;
        }

        // Resume active session cleanly
        document.body.classList.remove('stockms-locked');
        document.getElementById('authLoginOverlay')?.classList.add('hidden');
        await activateWorkspace(getActiveFactoryId());

        if (!isDashboardPage()) {
            const h = window.location.hash;
            if (h === '#new-tx') setTimeout(() => window.StockMSUI.openTransactionEntry(), 250);
            else if (h === '#daily-report') setTimeout(() => window.StockMSUI.triggerDailyReportAction(), 250);
            else if (h === '#reconcile') setTimeout(() => window.StockMSUI.triggerReconcileAction(), 250);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootstrapStockMS);
    } else {
        setTimeout(bootstrapStockMS, 0);
    }
})();
