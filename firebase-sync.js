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
    const FULLSCREEN_PREF_KEY = 'stockms_immersive_fullscreen';
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
        const activeFactory = getActiveFactoryId();
        const entry = saveLocalPresenceEntry(s.username, s.displayName, s.role, activeFactory, onlineStatus);
        try {
            globalBcChannel?.postMessage({ type: 'USER_PRESENCE_HEARTBEAT', entry });
        } catch (e) { }
        renderOnlinePresenceUI();
        if (fbDb && fbAuth?.currentUser) {
            const nowIso = new Date().toISOString();
            const presencePayload = {
                username: s.username,
                displayName: s.displayName || s.username,
                role: s.role || 'factory',
                activeFactory: activeFactory || s.username,
                onlineStatus: !!onlineStatus,
                lastSeenAt: nowIso,
                updatedAt: nowIso
            };
            try {
                await fbDb.collection('presence').doc(s.username).set(presencePayload, { merge: true });
            } catch (e) { /* Ignore if offline */ }
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

    function getMergedPresenceList() {
        const merged = { ...readLocalPresenceMap(), ...onlineUsersMap };
        return Object.values(merged)
            .filter(isUserConsideredOnline)
            .sort((a, b) => (a.username === 'admin' ? -1 : a.username.localeCompare(b.username)));
    }

    function renderOnlinePresenceUI() {
        const s = getSession();
        const wrap = document.getElementById('navAdminOnlineUsersWrap');
        const listEl = document.getElementById('navAdminOnlineUsersList');
        const countEl = document.getElementById('navAdminOnlineCount');
        const activeNow = getMergedPresenceList();

        if (wrap) {
            if (!s) {
                wrap.classList.add('hidden');
                wrap.classList.remove('flex');
            } else {
                wrap.classList.remove('hidden');
                wrap.classList.add('flex');
                if (countEl) countEl.textContent = String(activeNow.length);
                if (listEl) {
                    listEl.innerHTML = activeNow.length
                        ? activeNow.slice(0, 5).map(u => `<span class="stockms-online-pill" title="${escapeHtml(u.displayName || u.username)} (${escapeHtml(u.activeFactory || u.username)})"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>${escapeHtml(u.username)}</span>`).join('')
                        + (activeNow.length > 5 ? `<span class="text-[10px] font-bold text-slate-500">+${activeNow.length - 5}</span>` : '')
                        : '<span class="text-[10px] text-slate-400">ออนไลน์: 0</span>';
                }
            }
        }

        const kmOnlineCount = document.getElementById('kmOnlineCount');
        const kmOnlinePills = document.getElementById('kmOnlineUsersPills');
        if (kmOnlineCount) kmOnlineCount.textContent = String(activeNow.length);
        if (kmOnlinePills) {
            kmOnlinePills.innerHTML = activeNow.length
                ? activeNow.slice(0, 6).map(u => `<span class="stockms-online-pill"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>${escapeHtml(u.username)}</span>`).join('')
                + (activeNow.length > 6 ? `<span class="text-[10px] font-bold text-slate-500">+${activeNow.length - 6}</span>` : '')
                : '<span class="text-[10px] text-slate-400">ยังไม่มีผู้ใช้งานออนไลน์</span>';
        }

        const usersModal = document.getElementById('adminUserManagerModal');
        if (s?.role === 'admin' && usersModal && !usersModal.classList.contains('hidden')) {
            renderAdminUsersTable();
        }
        const onlineModal = document.getElementById('onlineUsersModal');
        if (s && onlineModal && !onlineModal.classList.contains('hidden')) {
            renderOnlineUsersModalBody();
        }
    }

    function subscribeUsersPresenceRealtime() {
        if (unsubscribeUsersPresenceSnap) {
            try { unsubscribeUsersPresenceSnap(); } catch (e) { }
            unsubscribeUsersPresenceSnap = null;
        }
        const s = getSession();
        if (!s) return;
        renderOnlinePresenceUI();
        if (!fbDb || !fbAuth?.currentUser) return;

        const handlePresenceDoc = (d) => {
            if (!d || !d.username) return;
            const prev = onlineUsersMap[d.username] || {};
            const prevTs = Date.parse(prev.lastSeenAt || prev.updatedAt || '0') || 0;
            const nextTs = Date.parse(d.lastSeenAt || d.updatedAt || '0') || 0;
            if (nextTs >= prevTs || !prev.lastSeenAt) {
                onlineUsersMap[d.username] = {
                    username: d.username,
                    displayName: d.displayName || d.username,
                    role: d.role || 'factory',
                    activeFactory: d.activeFactory || (d.username === 'admin' ? getActiveFactoryId() : d.username),
                    onlineStatus: d.onlineStatus === true,
                    lastSeenAt: d.lastSeenAt || d.updatedAt || null
                };
            }
        };

        const unsubPresence = fbDb.collection('presence').onSnapshot((snap) => {
            snap.forEach(doc => handlePresenceDoc(doc.data() || {}));
            renderOnlinePresenceUI();
        }, () => { });

        let unsubUsers = null;
        if (s.role === 'admin') {
            unsubUsers = fbDb.collection('users').onSnapshot((snap) => {
                snap.forEach(doc => handlePresenceDoc(doc.data() || {}));
                renderOnlinePresenceUI();
            }, () => { });
        }

        unsubscribeUsersPresenceSnap = () => {
            try { unsubPresence(); } catch (e) { }
            if (unsubUsers) try { unsubUsers(); } catch (e) { }
        };
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
        const v40Total = v40 + v35 + v30 + v28;
        const totalVol = v70 + v40Total;
        const totalCap = cap70 + cap40;
        const utilizationPct = totalCap > 0 ? (totalVol / totalCap) * 100 : 0;
        const util70Pct = cap70 > 0 ? (v70 / cap70) * 100 : 0;
        const util40Pct = cap40 > 0 ? (v40Total / cap40) * 100 : 0;
        const freeCap70 = Math.max(0, Math.round(cap70 - v70));
        const freeCap40 = Math.max(0, Math.round(cap40 - v40Total));
        const freeCapTotal = Math.max(0, Math.round(totalCap - totalVol));
        const shortfallTo95 = Math.max(0, Math.round((totalCap * 0.95) - totalVol));
        const shortfall70To95 = Math.max(0, Math.round((cap70 * 0.95) - v70));
        const shortfall40To95 = Math.max(0, Math.round((cap40 * 0.95) - v40Total));
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
            util70Pct: Number(util70Pct.toFixed(1)),
            util40Pct: Number(util40Pct.toFixed(1)),
            v70: Math.round(v70),
            v40: Math.round(v40),
            v40Total: Math.round(v40Total),
            v35: Math.round(v35),
            v30: Math.round(v30),
            v28: Math.round(v28),
            vLowOther: Math.round(v35 + v30 + v28),
            freeCap70,
            freeCap40,
            freeCapTotal,
            shortfallTo95,
            shortfall70To95,
            shortfall40To95,
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
                    { level: 'warn', text: '1) ตั้งค่าฐานข้อมูล: ให้ผู้ใช้งานโรงงาน Login เข้าสู่ระบบเพื่อ Import ไฟล์ Backup JSON หรือกดเริ่มต้นใช้งานใหม่' }
                ]
            };
        }

        const cap70 = Number(analytics.cap70) || 0;
        const cap40 = Number(analytics.cap40) || 0;
        const v70 = Number(analytics.v70) || 0;
        const v40Total = Number(analytics.v40Total !== undefined ? analytics.v40Total : ((analytics.v40 || 0) + (analytics.vLowOther || 0)));
        const freeCap70 = Number(analytics.freeCap70 !== undefined ? analytics.freeCap70 : Math.max(0, cap70 - v70));
        const freeCap40 = Number(analytics.freeCap40 !== undefined ? analytics.freeCap40 : Math.max(0, cap40 - v40Total));
        const util70 = Number(analytics.util70Pct !== undefined ? analytics.util70Pct : (cap70 > 0 ? (v70 / cap70) * 100 : 0));
        const util40 = Number(analytics.util40Pct !== undefined ? analytics.util40Pct : (cap40 > 0 ? (v40Total / cap40) * 100 : 0));
        const shortfall95 = Number(analytics.shortfallTo95 !== undefined ? analytics.shortfallTo95 : Math.max(0, Math.round((analytics.totalCap * 0.95) - analytics.totalVol)));
        const shortfall70 = Number(analytics.shortfall70To95 !== undefined ? analytics.shortfall70To95 : Math.max(0, Math.round((cap70 * 0.95) - v70)));
        const shortfall40 = Number(analytics.shortfall40To95 !== undefined ? analytics.shortfall40To95 : Math.max(0, Math.round((cap40 * 0.95) - v40Total)));

        // Topic 1: Policy Compliance (>= 95% Factory Stock Level)
        if (analytics.utilizationPct >= 95) {
            recs.push({ level: 'ok', text: `1) นโยบายสต็อก ≥95%: ผ่านเกณฑ์ตามนโยบาย (${analytics.utilizationPct}% ของความจุรวม, เหลือพื้นที่ว่างรวม ${(analytics.freeCapTotal ?? (freeCap70 + freeCap40)).toLocaleString()} L) ควรคุมรับ-จ่ายให้สมดุลไม่ให้เกิน Working Volume 100%` });
        } else if (analytics.utilizationPct >= 85) {
            if (riskLevel === 'normal') riskLevel = 'watch';
            recs.push({ level: 'warn', text: `1) นโยบายสต็อก ≥95%: อยู่ที่ ${analytics.utilizationPct}% (ต่ำกว่านโยบาย 95% อยู่ ${(95 - analytics.utilizationPct).toFixed(1)}%) — ต้องเร่งเติมสต็อกเพิ่มอีก ${shortfall95.toLocaleString()} L` });
        } else {
            riskLevel = 'critical';
            recs.push({ level: 'critical', text: `1) นโยบายสต็อก ≥95%: ต่ำกว่าเกณฑ์นโยบายมาก (${analytics.utilizationPct}%) — ขาดจากเป้า 95% อีก ${shortfall95.toLocaleString()} L (โซน 70° ${shortfall70.toLocaleString()} L / โซน 40° ${shortfall40.toLocaleString()} L)` });
        }

        // Topic 2: Zone Remaining Free Space & Working Volume 100% Balance (70° vs 40°)
        recs.push({
            level: (util70 < 95 || util40 < 95) ? 'warn' : 'info',
            text: `2) พื้นที่ว่างคงเหลือรายโซน: โซน 70° ว่าง ${freeCap70.toLocaleString()} L (ใช้ไป ${util70.toFixed(1)}%) • โซน 40° ว่าง ${freeCap40.toLocaleString()} L (ใช้ไป ${util40.toFixed(1)}%) — จัดสรรเติมเข้าถังให้ครบเกณฑ์ ≥95% โดยไม่เกิน Working Volume 100%`
        });

        // Topic 3: Quality (QC) & 14-Day Maturation Readiness
        if (analytics.qcIssues > 0) {
            riskLevel = 'critical';
            recs.push({ level: 'critical', text: `3) คุณภาพ QC & อายุบ่ม 14 วัน: พบไม่ผ่านเกณฑ์ QC ${analytics.qcIssues} รายการ (ผ่าน ${analytics.qcPassRate}%) — ต้องปรับปรุงคุณภาพก่อนบรรจุ ขณะที่ 70° บ่มครบ 14 วันอยู่ที่ ${analytics.ready70.toLocaleString()} L` });
        } else {
            const readyRatio = v70 > 0 ? (analytics.ready70 / v70) * 100 : 0;
            if (v70 > 0 && readyRatio < 25 && riskLevel === 'normal') riskLevel = 'watch';
            recs.push({
                level: (v70 > 0 && readyRatio >= 25) ? 'ok' : 'warn',
                text: `3) คุณภาพ QC & อายุบ่ม 14 วัน: ผล QC ผ่าน ${analytics.qcPassRate}% (${analytics.qcTotal} ครั้ง) • สุรา 70° บ่มครบพร้อมปรุง ${readyRatio.toFixed(1)}% (${analytics.ready70.toLocaleString()} L)`
            });
        }

        // Topic 4 (New): 30-Day Inbound/Outbound Velocity & Replenishment Balance
        const net30d = (analytics.in30d || 0) - (analytics.out30d || 0);
        const velOk = analytics.utilizationPct >= 95 ? net30d >= -Math.round((analytics.totalCap || 0) * 0.03) : net30d > 0;
        if (!velOk && analytics.utilizationPct < 95 && riskLevel === 'normal') riskLevel = 'watch';
        recs.push({
            level: velOk ? 'ok' : 'warn',
            text: `4) ดุลการหมุนเวียน 30 วัน: รับเข้า ${analytics.in30d.toLocaleString()} L vs จ่ายออก ${analytics.out30d.toLocaleString()} L (สุทธิ ${net30d >= 0 ? '+' : ''}${net30d.toLocaleString()} L) — ${net30d < 0 && analytics.utilizationPct < 95 ? 'อัตราเบิกสูงกว่ารับ ทำให้สต็อกหลุดเกณฑ์ 95% ควรเพิ่มรอบรับกลั่น' : 'ความเร็วเติม-จ่ายสอดคล้องกับแผนคงสต็อก ≥95%'}`
        });

        // Topic 5 (New): Tank Fleet Utilization & Special Tank Impact
        const availTanks = Math.max(0, (analytics.totalTanks || 0) - (analytics.bondedCount || 0) - (analytics.repairCount || 0));
        const emptyTanks = Math.max(0, availTanks - (analytics.activeTankCount || 0));
        recs.push({
            level: (analytics.repairCount > 2 || analytics.bondedCount > 2) ? 'warn' : 'info',
            text: `5) ประสิทธิภาพการใช้ถัง (Tank Fleet): ใช้งานอยู่ ${analytics.activeTankCount}/${availTanks} ถังพร้อมใช้ (ถังว่าง ${emptyTanks} ถัง • ทัณฑ์บน ${analytics.bondedCount} • ซ่อม ${analytics.repairCount}) — ${emptyTanks > 0 && analytics.utilizationPct < 95 ? `มีถังว่าง ${emptyTanks} ถังรองรับการเติมสต็อกให้ถึงเป้า 95%` : 'กระจายสต็อกเต็มกำลังถังที่มีประสิทธิภาพ'}`
        });

        // Topic 6 (New): Blending Continuity & 70° Buffer Coverage
        const runRateText = analytics.daysLeft70 !== null
            ? (analytics.daysLeft70 < 14
                ? (riskLevel = 'critical', `สำรอง 70° อยู่ได้อีกเพียง ${analytics.daysLeft70} วัน (ต่ำกว่า Safety Stock 14 วัน) ต้องประสานส่งน้ำสุราด่วน`)
                : `สำรอง 70° รองรับแผนปรุงได้ ${analytics.daysLeft70} วัน (สูงกว่า Safety Stock 14 วัน)`)
            : 'ยังไม่ได้ตั้งค่าแผนใช้วัตถุดิบต่อเดือน แนะนำตั้งค่า Planning Data เพื่อคำนวณวันสำรองอัตโนมัติ';
        recs.push({
            level: (analytics.daysLeft70 !== null && analytics.daysLeft70 < 14) ? 'critical' : 'info',
            text: `6) ความมั่นคงวัตถุดิบปรุง (70° Buffer): ${runRateText} และติดตามรอบ FIFO เก่าก่อนใหม่ลดความเสี่ยงอายุบ่มขาดช่วง`
        });

        const headline = riskLevel === 'critical'
            ? 'ต่ำกว่านโยบาย ≥95% หรือมีประเด็น QC/Buffer — ต้องเร่งเติมสต็อกและแก้ไขเร่งด่วน'
            : (riskLevel === 'watch'
                ? 'อยู่ระหว่างติดตามให้เข้าเกณฑ์นโยบายคงโรง ≥95% และสมดุลรายโซน'
                : 'ผ่านนโยบายสต็อกคงโรง ≥95% และคุณภาพ QC อยู่ในเกณฑ์ดีเยี่ยม');

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
            if (typeof refreshQcPendingReminders === 'function') {
                refreshQcPendingReminders();
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
        subscribeUsersPresenceRealtime();
        if (session.role === 'admin') {
            subscribeAdminAuditLogsRealtime();
        }
        renderAuthHeaderControls();
        refreshMobileShellData();
        refreshQcPendingReminders();

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
                    refreshQcPendingReminders();
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
    // 8. FULLSCREEN (iOS + SEAMLESS CROSS-PAGE) & DYNAMIC MODAL STACK MANAGER
    // =========================================================================
    let topModalZIndex = 8700;

    function bringModalToFront(el) {
        if (!el || !el.style) return;
        topModalZIndex += 10;
        el.style.zIndex = String(topModalZIndex);
        // Keep SweetAlert2 containers above any dynamic modal
        document.querySelectorAll('.swal2-container').forEach(sw => {
            sw.style.zIndex = '999990';
        });
    }
    window.bringModalToFront = bringModalToFront;

    function installDynamicModalStackObserver() {
        if (window.__stockmsModalStackObserverBound || typeof MutationObserver === 'undefined') return;
        window.__stockmsModalStackObserverBound = true;
        const obs = new MutationObserver((mutations) => {
            for (const m of mutations) {
                const target = m.target;
                if (!target || target.nodeType !== 1) continue;
                if (m.type === 'attributes' && m.attributeName === 'class') {
                    const isModal = target.classList.contains('stockms-modal-backdrop')
                        || (target.id && /Modal$/i.test(target.id))
                        || target.classList.contains('kosmate-radial-overlay');
                    if (isModal && !target.classList.contains('hidden')) {
                        bringModalToFront(target);
                    }
                } else if (m.type === 'childList') {
                    m.addedNodes.forEach(node => {
                        if (node && node.nodeType === 1 && node.classList?.contains('swal2-container')) {
                            node.style.zIndex = '999990';
                        }
                    });
                }
            }
        });
        obs.observe(document.body, {
            attributes: true,
            attributeFilter: ['class'],
            subtree: true,
            childList: true
        });
    }

    function isImmersiveFullscreenActive() {
        if (window.parent && window.parent !== window) {
            try {
                if (window.parent.document.documentElement.classList.contains('stockms-immersive-fs')) return true;
                if (window.parent.document.fullscreenElement || window.parent.document.webkitFullscreenElement) return true;
            } catch (e) { }
        }
        const doc = document;
        const nativeFs = !!(doc.fullscreenElement || doc.webkitFullscreenElement || doc.msFullscreenElement);
        let pref = false;
        try { pref = localStorage.getItem(FULLSCREEN_PREF_KEY) === '1'; } catch (e) { }
        return nativeFs || pref || document.documentElement.classList.contains('stockms-immersive-fs');
    }

    function applyImmersiveFullscreenClasses(enabled) {
        document.documentElement.classList.toggle('stockms-immersive-fs', !!enabled);
        document.body.classList.toggle('stockms-immersive-fs', !!enabled);
        try {
            localStorage.setItem(FULLSCREEN_PREF_KEY, enabled ? '1' : '0');
        } catch (e) { }
        if (enabled && /iPhone|iPad|iPod/i.test(navigator.userAgent || '')) {
            setTimeout(() => { try { window.scrollTo(0, 1); } catch (e) { } }, 60);
        }
        updateFullscreenButtonState();
    }

    async function requestNativeFullscreenSafe(targetDocEl) {
        const el = targetDocEl || document.documentElement;
        try {
            if (el.requestFullscreen) { await el.requestFullscreen(); return true; }
            if (el.webkitRequestFullscreen) { el.webkitRequestFullscreen(); return true; }
            if (el.msRequestFullscreen) { el.msRequestFullscreen(); return true; }
        } catch (e) { }
        return false;
    }

    async function exitNativeFullscreenSafe(targetDoc) {
        const d = targetDoc || document;
        try {
            if (d.exitFullscreen) { await d.exitFullscreen(); return true; }
            if (d.webkitExitFullscreen) { d.webkitExitFullscreen(); return true; }
            if (d.msExitFullscreen) { d.msExitFullscreen(); return true; }
        } catch (e) { }
        return false;
    }

    async function toggleAppFullscreen() {
        if (window.parent && window.parent !== window && typeof window.parent.toggleAppFullscreen === 'function') {
            return window.parent.toggleAppFullscreen();
        }
        const currentlyActive = isImmersiveFullscreenActive();
        if (!currentlyActive) {
            applyImmersiveFullscreenClasses(true);
            const enteredNative = await requestNativeFullscreenSafe(document.documentElement);
            if (!enteredNative && typeof Swal !== 'undefined') {
                Swal.fire({
                    toast: true,
                    position: 'top',
                    icon: 'success',
                    title: 'เปิดโหมดเต็มหน้าจอแล้ว (หากใช้ iPhone แนะนำกด Share > Add to Home Screen เพื่อซ่อนแถบ Safari ถาวร)',
                    showConfirmButton: false,
                    timer: 2600
                });
            }
        } else {
            applyImmersiveFullscreenClasses(false);
            await exitNativeFullscreenSafe(document);
        }
        updateFullscreenButtonState();
    }
    window.toggleAppFullscreen = toggleAppFullscreen;

    function handleNativeFullscreenChange() {
        const doc = document;
        const nativeFs = !!(doc.fullscreenElement || doc.webkitFullscreenElement || doc.msFullscreenElement);
        if (!nativeFs && window.__stockmsWasNativeFs) {
            applyImmersiveFullscreenClasses(false);
        }
        window.__stockmsWasNativeFs = nativeFs;
        updateFullscreenButtonState();
    }
    document.addEventListener('fullscreenchange', handleNativeFullscreenChange);
    document.addEventListener('webkitfullscreenchange', handleNativeFullscreenChange);

    function updateFullscreenButtonState() {
        const isFs = isImmersiveFullscreenActive();
        document.querySelectorAll('.stockms-fs-icon').forEach(icon => {
            icon.className = `fas ${isFs ? 'fa-compress' : 'fa-expand'} stockms-fs-icon`;
        });
        document.querySelectorAll('.stockms-fs-label').forEach(lbl => {
            lbl.textContent = isFs ? 'ย่อจอ' : 'เต็มจอ';
        });
    }

    function restorePersistentFullscreen() {
        let pref = false;
        try { pref = localStorage.getItem(FULLSCREEN_PREF_KEY) === '1'; } catch (e) { }
        if (!pref) {
            updateFullscreenButtonState();
            return;
        }
        applyImmersiveFullscreenClasses(true);
        // Also try re-acquiring native Fullscreen API silently on next user interaction if browser exited it on reload
        if (window === window.top && !document.fullscreenElement && !document.webkitFullscreenElement) {
            const tryReacquire = async () => {
                if (localStorage.getItem(FULLSCREEN_PREF_KEY) === '1' && !document.fullscreenElement && !document.webkitFullscreenElement) {
                    await requestNativeFullscreenSafe(document.documentElement);
                    updateFullscreenButtonState();
                }
            };
            ['pointerdown', 'keydown'].forEach(evt => {
                window.addEventListener(evt, tryReacquire, { once: true, capture: true, passive: true });
            });
        }
    }

    function navigateSeamlessly(targetUrl) {
        if (!targetUrl) return;
        let resolved;
        try {
            resolved = new URL(targetUrl, window.location.href);
        } catch (e) {
            window.location.href = targetUrl;
            return;
        }
        if (resolved.origin !== window.location.origin) {
            window.location.href = targetUrl;
            return;
        }

        // Inside child host frame -> ask top host frame to switch or close seamlessly!
        if (window.parent && window.parent !== window && typeof window.parent.StockMSUI?.handleSeamlessHostNav === 'function') {
            window.parent.StockMSUI.handleSeamlessHostNav(resolved.pathname + resolved.search + resolved.hash);
            return;
        }

        // Top window: if fullscreen is active and navigating to the sibling page, host it in #stockmsSeamlessHostFrame so fullscreen NEVER breaks!
        if (isImmersiveFullscreenActive()) {
            handleSeamlessHostNav(resolved.pathname + resolved.search + resolved.hash);
            return;
        }

        window.location.href = resolved.pathname + resolved.search + resolved.hash;
    }

    function handleSeamlessHostNav(relUrl) {
        let resolved;
        try { resolved = new URL(relUrl, window.location.href); } catch (e) { window.location.href = relUrl; return; }
        const curFile = (window.location.pathname.split('/').pop() || 'index.html').toLowerCase();
        const dstFile = (resolved.pathname.split('/').pop() || 'index.html').toLowerCase();
        const frame = document.getElementById('stockmsSeamlessHostFrame');

        // If returning to the exact top-level page without extra query/hash, reveal top window & refresh
        if (frame && dstFile === curFile && !resolved.search && !resolved.hash) {
            frame.classList.add('hidden');
            try { frame.src = 'about:blank'; } catch (e) { }
            triggerHostPageReload();
            refreshMobileShellData();
            refreshQcPendingReminders();
            return;
        }

        if (frame) {
            frame.src = resolved.pathname + resolved.search + resolved.hash;
            frame.classList.remove('hidden');
            frame.style.zIndex = '9400';
            return;
        }
        window.location.href = resolved.pathname + resolved.search + resolved.hash;
    }

    function installSeamlessLinkInterceptor() {
        if (window.__stockmsLinkInterceptorBound) return;
        window.__stockmsLinkInterceptorBound = true;
        document.addEventListener('click', (e) => {
            const anchor = e.target?.closest?.('a[href]');
            if (!anchor) return;
            const href = anchor.getAttribute('href') || '';
            if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
            if (/^(index\.html|dashboard\.html)/i.test(href.split('/').pop().split('?')[0].split('#')[0])) {
                if (isImmersiveFullscreenActive() || (window.parent && window.parent !== window)) {
                    e.preventDefault();
                    navigateSeamlessly(href);
                }
            }
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
            'adminAuditLogsModal', 'onlineUsersModal', 'qcPendingReminderModal', 'stockmsSeamlessHostFrame',
            'reconcileModal', 'dailyReportModal', 'stockLayoutModal',
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

    async function adminUpdateExistingUser({ originalUsernameRaw, usernameRaw, displayName, password, role }) {
        const session = getSession();
        if (!session || session.role !== 'admin') {
            throw new Error('สิทธิ์เฉพาะ Admin เท่านั้น');
        }
        const origUsername = parseUsername(originalUsernameRaw);
        const newUsername = parseUsername(usernameRaw);
        if (!origUsername || !newUsername) {
            throw new Error('Username ต้องเป็นตัวอักษรภาษาอังกฤษ ตัวเลข หรือขีด (-) เท่านั้น');
        }
        const reg = getLocalUsersRegistry();
        const existing = reg[origUsername];
        if (!existing) throw new Error(`ไม่พบบัญชี "${origUsername}" ในระบบ`);

        if (origUsername === 'admin' && newUsername !== 'admin') {
            throw new Error('บัญชีผู้ดูแลหลัก "admin" ไม่สามารถเปลี่ยน Username ได้');
        }
        if (origUsername === 'admin' && role !== 'admin') {
            throw new Error('บัญชีผู้ดูแลหลัก "admin" ต้องมีสิทธิ์เป็น Admin เท่านั้น');
        }
        if (newUsername !== origUsername && reg[newUsername]) {
            throw new Error(`Username "${newUsername}" ถูกใช้งานแล้ว กรุณาใช้ชื่ออื่น`);
        }
        if (password && password.length < 4) {
            throw new Error('รหัสผ่านต้องมีอย่างน้อย 4 ตัวอักษร');
        }

        const nowIso = new Date().toISOString();
        const isRename = newUsername !== origUsername;
        const effectiveRole = (newUsername === 'admin') ? 'admin' : (role === 'admin' ? 'admin' : 'factory');
        const effectiveDisplay = (displayName || existing.displayName || newUsername).trim();

        let nextSalt = existing.salt;
        let nextHash = existing.passwordHash;
        let nextVer = isRename ? 1 : (Number(existing.authVersion) || 1);
        let nextAuthEmail = existing.authEmail || buildAuthEmail(newUsername, nextVer);
        let assignedUid = existing.authUid || '';

        if (password && password.length >= 4) {
            nextVer = isRename ? 1 : ((Number(existing.authVersion) || 1) + 1);
            nextSalt = generateSalt(newUsername);
            nextHash = hashPasswordWithSalt(password, nextSalt);
            nextAuthEmail = buildAuthEmail(newUsername, nextVer);
            try {
                const secAuth = getSecondaryAuth();
                if (secAuth) {
                    const cred = await secAuth.createUserWithEmailAndPassword(nextAuthEmail, deriveFirebaseAuthSecret(newUsername, password));
                    assignedUid = cred.user.uid;
                    await secAuth.signOut();
                }
            } catch (e) {
                console.info('Secondary Firebase Auth update note:', e.code || e.message);
            }
        } else if (isRename) {
            throw new Error('เมื่อเปลี่ยน Username กรุณากรอกรหัสผ่านใหม่ (อย่างน้อย 4 ตัวอักษร) เพื่อสร้างรหัสยืนยันบัญชีใหม่');
        }

        const updatedDoc = {
            username: newUsername,
            displayName: effectiveDisplay,
            role: effectiveRole,
            salt: nextSalt,
            passwordHash: nextHash,
            authVersion: nextVer,
            authEmail: nextAuthEmail,
            authUid: assignedUid,
            active: existing.active !== false,
            createdAt: existing.createdAt || nowIso,
            updatedAt: nowIso,
            createdBy: existing.createdBy || session.username
        };

        if (isRename) {
            // Migrate local tenant payload
            const oldPayload = readTenantLocalPayload(origUsername);
            oldPayload.username = newUsername;
            oldPayload.factoryName = effectiveDisplay;
            writeTenantLocalPayload(newUsername, oldPayload);
            try { localStorage.removeItem(`${TENANT_PREFIX}${origUsername}::__meta`); } catch (e) { }
            TENANT_KEYS.forEach(k => { try { localStorage.removeItem(`${TENANT_PREFIX}${origUsername}::${k}`); } catch (e) { } });
            delete reg[origUsername];
        }
        reg[newUsername] = updatedDoc;
        saveLocalUsersRegistry(reg);

        // Migrate cloud Firestore docs if connected
        if (fbDb && fbAuth?.currentUser) {
            try {
                await fbDb.collection('users').doc(newUsername).set(updatedDoc, { merge: true });
                if (effectiveRole === 'factory') {
                    if (isRename) {
                        const oldFRef = fbDb.collection('factories').doc(origUsername);
                        const oldFSnap = await oldFRef.get();
                        const newFRef = fbDb.collection('factories').doc(newUsername);
                        const baseData = oldFSnap.exists ? oldFSnap.data() : {};
                        await newFRef.set({
                            ...baseData,
                            username: newUsername,
                            factoryName: effectiveDisplay,
                            updatedAt: nowIso,
                            updatedBy: session.username
                        }, { merge: true });
                        if (oldFSnap.exists) {
                            const oldChunks = await oldFRef.collection('chunks').get();
                            for (const cDoc of oldChunks.docs) {
                                await newFRef.collection('chunks').doc(cDoc.id).set(cDoc.data());
                            }
                            await oldFRef.delete();
                        }
                    } else {
                        await fbDb.collection('factories').doc(newUsername).set({
                            factoryName: effectiveDisplay,
                            updatedAt: nowIso,
                            updatedBy: session.username
                        }, { merge: true });
                    }
                }
                if (isRename) {
                    try { await fbDb.collection('users').doc(origUsername).delete(); } catch (e) { }
                    try { await fbDb.collection('presence').doc(origUsername).delete(); } catch (e) { }
                }
            } catch (e) {
                console.info('Cloud user edit sync note:', e.code || e.message);
            }
        }

        // If currently viewing the renamed factory, switch session factory pointer cleanly
        if (isRename && getActiveFactoryId() === origUsername) {
            session.activeFactory = newUsername;
            localStorage.setItem('stockms_admin_last_factory', newUsername);
            saveSession(session, !!localStorage.getItem(SESSION_STORAGE_KEY));
            await activateWorkspace(newUsername);
        }

        await writeAuditLog('ADMIN_EDIT_USER', newUsername, {
            category: 'auth',
            actionLabel: 'Admin แก้ไขข้อมูลผู้ใช้งาน',
            summaryText: `แก้ไขบัญชี ${isRename ? `${origUsername} -> ${newUsername}` : newUsername} (${effectiveDisplay}, Role: ${effectiveRole}${password ? ', อัปเดตรหัสผ่าน' : ''})`,
            canRollback: false
        });
        await renderAuthHeaderControls();
        return updatedDoc;
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
        adminUpdateExistingUser,
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

        <div id="adminEditModeBanner" class="hidden mb-2.5 px-3.5 py-2 rounded-xl bg-amber-50 border border-amber-300 text-amber-900 text-xs flex flex-wrap items-center justify-between gap-2">
            <span class="font-extrabold flex items-center gap-1.5"><i class="fas fa-user-edit text-amber-600"></i> โหมดแก้ไขข้อมูลผู้ใช้เดิม: <b id="adminEditBannerTarget">-</b></span>
            <button type="button" id="adminCancelEditBtn" onclick="window.StockMSUI.cancelAdminEditUser()" class="px-2.5 py-1 rounded-lg bg-white hover:bg-amber-100 border border-amber-300 text-amber-800 font-bold text-[11px]">ยกเลิกการแก้ไข</button>
        </div>

        <form id="adminAddUserForm" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 p-3.5 rounded-2xl bg-slate-50 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-700 mb-5">
            <input type="hidden" id="adminEditOriginalUsername" value="">
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">Username *</label>
                <input type="text" id="adminNewUsername" required placeholder="เช่น ms-nkp" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1">ชื่อโรงงาน / แสดงผล *</label>
                <input type="text" id="adminNewDisplayName" required placeholder="เช่น โรงงาน MS-NKP" class="w-full px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-xs font-bold">
            </div>
            <div>
                <label class="block text-[10px] font-bold uppercase text-slate-500 mb-1" id="adminNewPasswordLabel">รหัสผ่านเริ่มต้น *</label>
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
                <button type="submit" id="adminUserFormSubmitBtn" class="w-full py-2 px-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-extrabold shadow flex items-center justify-center gap-1.5">
                    <i class="fas fa-user-plus"></i> <span>เพิ่มผู้ใช้งาน</span>
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

        <div id="adminCompareOverview" class="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3 mb-4 sm:mb-5"></div>

        <div class="grid grid-cols-1 xl:grid-cols-12 gap-4 mb-5">
            <div class="xl:col-span-7 stockms-compare-table-scroll rounded-2xl border border-slate-200 dark:border-slate-700 bg-white">
                <table class="w-full text-xs text-left">
                    <thead class="bg-slate-100 dark:bg-slate-800 text-[10px] font-bold uppercase text-slate-600 dark:text-slate-300">
                        <tr>
                            <th class="px-3 py-2.5">โรงงาน / User</th>
                            <th class="px-3 py-2.5 text-right">คงคลังรวม (L)</th>
                            <th class="px-3 py-2.5 text-right">ความจุ (L)</th>
                            <th class="px-3 py-2.5 text-right">% คงโรง (≥95%)</th>
                            <th class="px-3 py-2.5 text-right text-emerald-700">70° คงคลัง</th>
                            <th class="px-3 py-2.5 text-right text-emerald-700">พื้นที่ว่าง 70° (L)</th>
                            <th class="px-3 py-2.5 text-right text-blue-700">40° คงคลัง</th>
                            <th class="px-3 py-2.5 text-right text-blue-700">พื้นที่ว่าง 40° (L)</th>
                            <th class="px-3 py-2.5 text-center">QC ผ่าน</th>
                            <th class="px-3 py-2.5 text-center">เปิดดู</th>
                        </tr>
                    </thead>
                    <tbody id="adminCompareTableBody" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
                </table>
            </div>
            <div class="xl:col-span-5 p-3.5 sm:p-4 rounded-2xl border border-slate-200 dark:border-slate-700 bg-slate-50/70 dark:bg-slate-800/40">
                <div class="text-xs font-extrabold mb-1 text-slate-700 dark:text-slate-200 flex items-center justify-between gap-2 flex-wrap">
                    <span><i class="fas fa-chart-bar text-blue-600 mr-1.5"></i> ปริมาณสุรารายโรงงาน vs ลิมิต Working Volume</span>
                    <span class="text-[10px] font-bold text-slate-600 bg-white px-2 py-0.5 rounded-full border border-slate-200">เส้นขีดบน = ลิมิตความจุใช้งาน</span>
                </div>
                <div class="h-64 sm:h-72 relative"><canvas id="adminCompareBarCanvas"></canvas></div>
            </div>
        </div>

        <div class="mb-2.5 text-xs sm:text-sm font-extrabold text-slate-800 dark:text-slate-100 flex flex-wrap items-center justify-between gap-2">
            <span class="flex items-center gap-2"><i class="fas fa-lightbulb text-amber-500"></i> บทสรุปวิเคราะห์และคำแนะนำรายโรงงาน (Executive Insights)</span>
            <span class="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200">นโยบายบริษัท: สต็อกคงโรงไม่ต่ำกว่า 95%</span>
        </div>
        <div id="adminFactoryInsightsGrid" class="grid grid-cols-1 lg:grid-cols-2 gap-3.5"></div>
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

<!-- 5C. ALL-USERS ONLINE PRESENCE MODAL -->
<div id="onlineUsersModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-lg p-5">
        <div class="flex justify-between items-center mb-3.5 pb-3 border-b border-slate-200">
            <div class="flex items-center gap-2.5">
                <div class="w-9 h-9 rounded-xl bg-emerald-600 text-white flex items-center justify-center shadow"><i class="fas fa-signal"></i></div>
                <div>
                    <h3 class="text-sm sm:text-base font-extrabold">ผู้ใช้งานที่กำลังออนไลน์ในระบบ</h3>
                    <p class="text-[11px] text-slate-500">อัปเดตสถานะแบบ Real-Time ทุก 25 วินาที</p>
                </div>
            </div>
            <button type="button" onclick="window.StockMSUI.closeModal('onlineUsersModal')" class="w-8 h-8 rounded-full hover:bg-slate-100 text-slate-400"><i class="fas fa-times"></i></button>
        </div>
        <div id="onlineUsersModalBody" class="space-y-2 max-h-[60vh] overflow-y-auto text-xs"></div>
    </div>
</div>

<!-- 5D. 24-HOUR QC REMINDER MODAL (TANK >= 95% REPRESENTATIVE SAMPLE) -->
<div id="qcPendingReminderModal" class="stockms-modal-backdrop hidden">
    <div class="stockms-modal-card max-w-3xl p-4 sm:p-6">
        <div class="flex justify-between items-center mb-3.5 pb-3 border-b border-slate-200 gap-2">
            <div class="flex items-center gap-2.5">
                <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 to-rose-600 text-white flex items-center justify-center text-lg shadow"><i class="fas fa-vials"></i></div>
                <div>
                    <h3 class="text-sm sm:text-base font-extrabold text-slate-800">แจ้งเตือนกรอกผลวิเคราะห์ QC ตัวแทนถัง (≥95% ครบ 24 ชม.)</h3>
                    <p class="text-[11px] text-slate-500">รายการรับปรุง/รับกลั่นที่ปริมาตรถังเกิน 95% เกิน 24 ชั่วโมงแล้ว แต่ยังไม่ได้กรอกผลตรวจจากห้อง Lab</p>
                </div>
            </div>
            <button type="button" onclick="window.StockMSUI.closeModal('qcPendingReminderModal')" class="w-8 h-8 rounded-full hover:bg-slate-100 text-slate-400 flex-shrink-0"><i class="fas fa-times"></i></button>
        </div>

        <div id="qcPendingSummaryRow" class="grid grid-cols-1 sm:grid-cols-3 gap-2.5 mb-3.5"></div>

        <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
            <div class="flex flex-wrap gap-1.5">
                <button type="button" id="qcRemTabOverdue" onclick="window.StockMSUI.switchPendingQcTab('overdue')" class="px-3 py-1.5 rounded-xl bg-rose-600 text-white text-xs font-extrabold shadow-xs">เกิน 24 ชม. (แจ้งเตือน)</button>
                <button type="button" id="qcRemTabWaiting" onclick="window.StockMSUI.switchPendingQcTab('waiting')" class="px-3 py-1.5 rounded-xl bg-slate-100 text-slate-600 text-xs font-bold">รอผล Lab (&lt; 24 ชม.)</button>
            </div>
            <div class="flex flex-wrap gap-1.5">
                <button type="button" onclick="window.StockMSUI.setPendingQcCatFilter('ALL')" data-qcrem-cat="ALL" class="px-2.5 py-1 rounded-lg bg-slate-800 text-white text-[11px] font-bold">ทุกประเภท</button>
                <button type="button" onclick="window.StockMSUI.setPendingQcCatFilter('BLEND')" data-qcrem-cat="BLEND" class="px-2.5 py-1 rounded-lg bg-fuchsia-50 text-fuchsia-700 border border-fuchsia-200 text-[11px] font-bold">ถังปรุงสุรา</button>
                <button type="button" onclick="window.StockMSUI.setPendingQcCatFilter('HIGH_70')" data-qcrem-cat="HIGH_70" class="px-2.5 py-1 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 text-[11px] font-bold">ถังเก็บบ่ม 70°</button>
            </div>
        </div>

        <div id="qcPendingListBody" class="space-y-2.5 max-h-[54vh] overflow-y-auto pr-1 text-xs"></div>
    </div>
</div>

<!-- SEAMLESS CROSS-PAGE FULLSCREEN HOST FRAME -->
<iframe id="stockmsSeamlessHostFrame" class="hidden" title="StockMS Seamless View"></iframe>

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
                <button type="button" id="kmBtnPendingQcReminder" onclick="window.StockMSUI.openQcPendingReminderModal()" class="kosmate-icon-btn stockms-qc-alert-btn" title="แจ้งเตือนกรอกผล QC ถัง ≥95% (เกิน 24 ชม.)">
                    <span id="kmPendingQcBadge" class="stockms-qc-alert-badge hidden bg-rose-600 text-white mr-0.5 text-[9px] min-w-[16px] h-[16px] px-1">0</span>
                    <i class="fas fa-flask text-amber-600"></i>
                </button>
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

            <!-- Live Online Users Strip (Visible to ALL logged-in users) -->
            <div id="kmOnlineUsersStrip" onclick="window.StockMSUI.openOnlinePresenceAction()" class="p-2.5 rounded-2xl bg-white/90 border border-slate-200/80 shadow-xs flex flex-wrap items-center justify-between gap-2 cursor-pointer text-xs">
                <div class="flex items-center gap-1.5 font-extrabold text-emerald-700 whitespace-nowrap">
                    <span class="stockms-live-dot"></span>
                    <span>ผู้ใช้งานออนไลน์ (<b id="kmOnlineCount">0</b>):</span>
                </div>
                <div id="kmOnlineUsersPills" class="flex flex-wrap items-center gap-1"></div>
            </div>

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

                    <div id="navAdminOnlineUsersWrap" class="hidden stockms-nav-group items-center gap-1.5 cursor-pointer" onclick="window.StockMSUI.openOnlinePresenceAction()" title="คลิกเพื่อดูผู้ใช้งานออนไลน์ทั้งหมด">
                        <span class="text-[10px] font-extrabold text-emerald-700 flex items-center gap-1 whitespace-nowrap">
                            <span class="stockms-live-dot"></span> ออนไลน์ <b id="navAdminOnlineCount">0</b>:
                        </span>
                        <div id="navAdminOnlineUsersList" class="flex flex-wrap items-center gap-1"></div>
                    </div>

                    <button type="button" id="navBtnPendingQcReminder" onclick="window.StockMSUI.openQcPendingReminderModal()" class="hidden btn-glass stockms-qc-alert-btn px-2.5 py-1 rounded-xl bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300/90 font-bold text-[11px] items-center gap-1.5 whitespace-nowrap" title="แจ้งเตือนกรอกผลวิเคราะห์ถัง ≥95% (เกิน 24 ชั่วโมง)">
                        <span id="navPendingQcBadge" class="stockms-qc-alert-badge hidden bg-rose-600 text-white">0</span>
                        <i class="fas fa-flask text-rose-500"></i>
                        <span>รอผลวิเคราะห์ (≥95%)</span>
                    </button>
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

        // Admin add or edit user form
        const addUserForm = document.getElementById('adminAddUserForm');
        if (addUserForm) {
            addUserForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const origUsername = document.getElementById('adminEditOriginalUsername')?.value || '';
                    const usernameRaw = document.getElementById('adminNewUsername').value;
                    const displayName = document.getElementById('adminNewDisplayName').value;
                    const password = document.getElementById('adminNewPassword').value;
                    const role = document.getElementById('adminNewRole').value;
                    if (origUsername) {
                        await adminUpdateExistingUser({
                            originalUsernameRaw: origUsername,
                            usernameRaw,
                            displayName,
                            password,
                            role
                        });
                        cancelAdminEditUser();
                        await renderAdminUsersTable();
                        if (typeof Swal !== 'undefined') Swal.fire('อัปเดตสำเร็จ!', `แก้ไขข้อมูลบัญชี ${parseUsername(usernameRaw)} เรียบร้อยแล้ว`, 'success');
                    } else {
                        await adminCreateOrResetUser({ usernameRaw, displayName, password, role, isEdit: false });
                        addUserForm.reset();
                        await renderAdminUsersTable();
                        if (typeof Swal !== 'undefined') Swal.fire('เพิ่มผู้ใช้งานสำเร็จ!', `สร้างบัญชี ${parseUsername(usernameRaw)} เรียบร้อยแล้ว`, 'success');
                    }
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
                    <div class="flex items-center justify-center gap-1.5 flex-wrap">
                        <button type="button" onclick="window.StockMSUI.openAdminEditUser('${escapeHtml(u.username)}')" class="px-2.5 py-1 rounded-lg bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 font-bold text-[11px]">
                            <i class="fas fa-user-edit mr-1"></i> แก้ไขข้อมูล
                        </button>
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

    async function openAdminEditUser(username) {
        const users = await loadAllUsersList();
        const u = users.find(x => x.username === username);
        if (!u) return;

        const origEl = document.getElementById('adminEditOriginalUsername');
        const userEl = document.getElementById('adminNewUsername');
        const dispEl = document.getElementById('adminNewDisplayName');
        const pwdEl = document.getElementById('adminNewPassword');
        const pwdLbl = document.getElementById('adminNewPasswordLabel');
        const roleEl = document.getElementById('adminNewRole');
        const banner = document.getElementById('adminEditModeBanner');
        const bannerTarget = document.getElementById('adminEditBannerTarget');
        const submitBtn = document.getElementById('adminUserFormSubmitBtn');

        if (origEl) origEl.value = u.username;
        if (userEl) {
            userEl.value = u.username;
            userEl.readOnly = (u.username === 'admin');
            userEl.classList.toggle('bg-slate-100', u.username === 'admin');
        }
        if (dispEl) dispEl.value = u.displayName || u.username;
        if (roleEl) {
            roleEl.value = u.role || 'factory';
            roleEl.disabled = (u.username === 'admin');
        }

        // Pre-fill known seed password only if stored hash still matches initial seed
        const seedSpec = SEED_USERS_SPEC.find(sp => sp.username === u.username);
        const matchesSeed = !!(seedSpec && u.salt && hashPasswordWithSalt(seedSpec.plain, u.salt) === u.passwordHash);
        if (pwdEl) {
            pwdEl.required = false;
            pwdEl.value = matchesSeed ? seedSpec.plain : '';
            pwdEl.placeholder = matchesSeed ? 'แก้ไขหรือใช้รหัสเริ่มต้นนี้' : 'กรอกรหัสผ่านใหม่ (เว้นว่าง = คงเดิม)';
        }
        if (pwdLbl) pwdLbl.textContent = 'รหัสผ่าน (แก้หรือเว้นว่าง)';
        if (banner) banner.classList.remove('hidden');
        if (bannerTarget) bannerTarget.textContent = `${u.username} (${u.displayName || u.username})`;
        if (submitBtn) {
            submitBtn.className = 'w-full py-2 px-3 rounded-xl bg-amber-600 hover:bg-amber-700 text-white text-xs font-extrabold shadow flex items-center justify-center gap-1.5';
            submitBtn.innerHTML = '<i class="fas fa-save"></i> <span>บันทึกการแก้ไข</span>';
        }
        userEl?.focus();
    }

    function cancelAdminEditUser() {
        const origEl = document.getElementById('adminEditOriginalUsername');
        const userEl = document.getElementById('adminNewUsername');
        const pwdEl = document.getElementById('adminNewPassword');
        const pwdLbl = document.getElementById('adminNewPasswordLabel');
        const roleEl = document.getElementById('adminNewRole');
        const banner = document.getElementById('adminEditModeBanner');
        const submitBtn = document.getElementById('adminUserFormSubmitBtn');

        if (origEl) origEl.value = '';
        document.getElementById('adminAddUserForm')?.reset();
        if (userEl) {
            userEl.readOnly = false;
            userEl.classList.remove('bg-slate-100');
        }
        if (roleEl) roleEl.disabled = false;
        if (pwdEl) {
            pwdEl.required = true;
            pwdEl.placeholder = 'ตั้งรหัสผ่าน';
        }
        if (pwdLbl) pwdLbl.textContent = 'รหัสผ่านเริ่มต้น *';
        if (banner) banner.classList.add('hidden');
        if (submitBtn) {
            submitBtn.className = 'w-full py-2 px-3 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-extrabold shadow flex items-center justify-center gap-1.5';
            submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> <span>เพิ่มผู้ใช้งาน</span>';
        }
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
            <div class="p-3 sm:p-3.5 rounded-2xl bg-blue-50 dark:bg-blue-950/50 border border-blue-200 dark:border-blue-800">
                <div class="text-[10px] sm:text-[11px] font-bold text-blue-600 dark:text-blue-400">จำนวนโรงงานทั้งหมด</div>
                <div class="text-lg sm:text-xl font-black mt-0.5">${rows.length} โรงงาน</div>
            </div>
            <div class="p-3 sm:p-3.5 rounded-2xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800">
                <div class="text-[10px] sm:text-[11px] font-bold text-emerald-600 dark:text-emerald-400">ปริมาณสุรารวมทุกโรงงาน</div>
                <div class="text-lg sm:text-xl font-black mt-0.5 tabular-nums">${totalNetworkStock.toLocaleString()} L</div>
            </div>
            <div class="p-3 sm:p-3.5 rounded-2xl bg-indigo-50 dark:bg-indigo-950/50 border border-indigo-200 dark:border-indigo-800">
                <div class="text-[10px] sm:text-[11px] font-bold text-indigo-600 dark:text-indigo-400">คงคลังรวมเทียบเป้า (≥95%)</div>
                <div class="text-lg sm:text-xl font-black mt-0.5 tabular-nums ${Number(netUtil) >= 95 ? 'text-emerald-700' : 'text-amber-600'}">${netUtil}%</div>
            </div>
            <div class="p-3 sm:p-3.5 rounded-2xl bg-rose-50 dark:bg-rose-950/50 border border-rose-200 dark:border-rose-800">
                <div class="text-[10px] sm:text-[11px] font-bold text-rose-600 dark:text-rose-400">ต่ำกว่าเกณฑ์/ต้องเร่งแก้</div>
                <div class="text-lg sm:text-xl font-black mt-0.5">${criticalCount} แห่ง</div>
            </div>
        `;

        document.getElementById('adminCompareTableBody').innerHTML = rows.map(r => {
            const a = r.analytics;
            const v40Tot = Number(a.v40Total !== undefined ? a.v40Total : (a.v40 + a.vLowOther));
            const free70 = Number(a.freeCap70 !== undefined ? a.freeCap70 : Math.max(0, (a.cap70 || 0) - a.v70));
            const free40 = Number(a.freeCap40 !== undefined ? a.freeCap40 : Math.max(0, (a.cap40 || 0) - v40Tot));
            const utilCls = a.utilizationPct >= 95 ? 'text-emerald-600' : (a.utilizationPct >= 85 ? 'text-amber-600' : 'text-rose-600');
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
                    <td class="px-3 py-2.5 text-right font-extrabold ${utilCls} tabular-nums">${a.utilizationPct}%</td>
                    <td class="px-3 py-2.5 text-right text-emerald-700 dark:text-emerald-400 font-bold tabular-nums">${a.v70.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right text-emerald-600 font-extrabold tabular-nums bg-emerald-50/40">${free70.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right text-blue-700 dark:text-blue-400 font-bold tabular-nums">${v40Tot.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-right text-blue-600 font-extrabold tabular-nums bg-blue-50/40">${free40.toLocaleString()}</td>
                    <td class="px-3 py-2.5 text-center font-bold ${a.qcIssues > 0 ? 'text-rose-600' : 'text-emerald-600'}">${a.qcPassRate}%</td>
                    <td class="px-3 py-2.5 text-center">
                        <button type="button" onclick="window.StockMSAuth.switchAdminFactory('${escapeHtml(a.username)}'); window.StockMSUI.closeModal('adminCompareModal');" class="px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-[10px] font-bold">ดูคลัง</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Render Comparison Bar Chart with Working Volume Top-Cap Limit Lines (70° & 40°, no overlapping labels)
        const canvas = document.getElementById('adminCompareBarCanvas');
        if (canvas && typeof Chart !== 'undefined') {
            if (adminCompareChart) adminCompareChart.destroy();
            const cap70Arr = rows.map(r => r.analytics.cap70 || 0);
            const cap40Arr = rows.map(r => r.analytics.cap40 || 0);

            const workingVolLimitPlugin = {
                id: 'stockmsWorkingVolCaps',
                afterDatasetsDraw(chart) {
                    const { ctx, scales } = chart;
                    const yScale = scales.y;
                    if (!yScale) return;
                    const meta70 = chart.getDatasetMeta(0);
                    const meta40 = chart.getDatasetMeta(1);
                    ctx.save();
                    rows.forEach((r, idx) => {
                        const drawCap = (barEl, capVal, strokeColor) => {
                            if (!barEl || !capVal) return;
                            const yPos = yScale.getPixelForValue(capVal);
                            const halfW = Math.max(7, (barEl.width || 16) * 0.46);
                            ctx.strokeStyle = strokeColor;
                            ctx.lineWidth = 2;
                            ctx.setLineDash([4, 2]);
                            ctx.beginPath();
                            ctx.moveTo(barEl.x - halfW, yPos);
                            ctx.lineTo(barEl.x + halfW, yPos);
                            ctx.stroke();

                            ctx.setLineDash([]);
                            ctx.beginPath();
                            ctx.moveTo(barEl.x - halfW, yPos - 3);
                            ctx.lineTo(barEl.x - halfW, yPos + 3);
                            ctx.moveTo(barEl.x + halfW, yPos - 3);
                            ctx.lineTo(barEl.x + halfW, yPos + 3);
                            ctx.stroke();
                        };
                        if (meta70 && !meta70.hidden && meta70.data?.[idx]) drawCap(meta70.data[idx], r.analytics.cap70, '#047857');
                        if (meta40 && !meta40.hidden && meta40.data?.[idx]) drawCap(meta40.data[idx], r.analytics.cap40, '#1d4ed8');
                    });
                    ctx.restore();
                }
            };

            adminCompareChart = new Chart(canvas.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: rows.map(r => r.analytics.username.toUpperCase()),
                    datasets: [
                        { label: 'คงคลัง 70° (L)', data: rows.map(r => r.analytics.v70), backgroundColor: '#10b981', borderRadius: 6, barPercentage: 0.72, categoryPercentage: 0.76, order: 2, datalabels: { display: false } },
                        { label: 'คงคลัง 40°/ต่ำกว่า (L)', data: rows.map(r => Number(r.analytics.v40Total !== undefined ? r.analytics.v40Total : (r.analytics.v40 + r.analytics.vLowOther))), backgroundColor: '#3b82f6', borderRadius: 6, barPercentage: 0.72, categoryPercentage: 0.76, order: 2, datalabels: { display: false } },
                        { label: 'ลิมิต WV (70°)', data: cap70Arr, type: 'line', showLine: false, borderColor: '#047857', backgroundColor: '#047857', borderDash: [4, 2], borderWidth: 2, pointStyle: 'line', pointRadius: 0, pointHoverRadius: 0, fill: false, order: 1, datalabels: { display: false } },
                        { label: 'ลิมิต WV (40°)', data: cap40Arr, type: 'line', showLine: false, borderColor: '#1d4ed8', backgroundColor: '#1d4ed8', borderDash: [4, 2], borderWidth: 2, pointStyle: 'line', pointRadius: 0, pointHoverRadius: 0, fill: false, order: 1, datalabels: { display: false } }
                    ]
                },
                plugins: [workingVolLimitPlugin],
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    layout: { padding: { top: 12, right: 8, left: 4, bottom: 2 } },
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        datalabels: { display: false },
                        legend: {
                            position: 'bottom',
                            labels: { usePointStyle: true, boxWidth: 14, padding: 10, font: { size: 10, family: 'Sarabun', weight: 'bold' } }
                        },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => `${ctx.dataset.label}: ${Number(ctx.parsed.y || 0).toLocaleString()} L`
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { font: { size: 10, family: 'Sarabun', weight: 'bold' } }
                        },
                        y: {
                            beginAtZero: true,
                            suggestedMax: Math.max(...cap70Arr, ...cap40Arr, 1000) * 1.12,
                            grid: { color: 'rgba(148, 163, 184, 0.18)' },
                            ticks: {
                                font: { size: 10, family: 'Sarabun' },
                                callback: (v) => {
                                    const num = Number(v);
                                    if (num >= 1000000) return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
                                    if (num >= 1000) return Math.round(num / 1000) + 'k';
                                    return num;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Render Per-Factory Executive Summaries & Recommendations (Mobile-friendly wrapping & spacing)
        document.getElementById('adminFactoryInsightsGrid').innerHTML = rows.map(r => {
            const a = r.analytics;
            const ins = r.insight;
            const free70 = Number(a.freeCap70 !== undefined ? a.freeCap70 : Math.max(0, (a.cap70 || 0) - a.v70));
            const free40 = Number(a.freeCap40 !== undefined ? a.freeCap40 : Math.max(0, (a.cap40 || 0) - (a.v40 + a.vLowOther)));
            const borderCls = ins.riskLevel === 'critical'
                ? 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20'
                : (ins.riskLevel === 'watch'
                    ? 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20'
                    : 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20');
            const tagCls = ins.riskLevel === 'critical'
                ? 'bg-rose-600 text-white'
                : (ins.riskLevel === 'watch' ? 'bg-amber-500 text-white' : 'bg-emerald-600 text-white');
            const tagText = ins.riskLevel === 'critical' ? 'ต่ำกว่า 95% / เร่งด่วน' : (ins.riskLevel === 'watch' ? 'ติดตามเป้า 95%' : 'ผ่านเกณฑ์ ≥95%');

            const recItems = ins.recommendations.map(rec => {
                const ic = rec.level === 'critical' ? 'fa-exclamation-circle text-rose-600'
                    : (rec.level === 'warn' ? 'fa-exclamation-triangle text-amber-600'
                        : (rec.level === 'ok' ? 'fa-check-circle text-emerald-600' : 'fa-info-circle text-blue-600'));
                return `<li class="flex items-start gap-2 text-xs leading-relaxed text-slate-700 dark:text-slate-200"><i class="fas ${ic} mt-1 flex-shrink-0"></i><span class="break-words">${escapeHtml(rec.text)}</span></li>`;
            }).join('');

            return `
                <div class="p-3.5 sm:p-4 rounded-2xl border ${borderCls} flex flex-col justify-between gap-2.5">
                    <div>
                        <div class="flex flex-wrap justify-between items-start gap-2 mb-2">
                            <div class="min-w-0">
                                <div class="font-black text-sm text-slate-800 dark:text-white break-words">${escapeHtml(a.factoryName)} <span class="text-xs font-semibold text-slate-400">(${escapeHtml(a.username)})</span></div>
                                <div class="text-[11px] font-bold text-slate-600 dark:text-slate-300 leading-snug mt-0.5">${escapeHtml(ins.headline)}</div>
                            </div>
                            <span class="px-2.5 py-0.5 rounded-full text-[10px] font-extrabold whitespace-nowrap ${tagCls}">${tagText}</span>
                        </div>
                        <div class="grid grid-cols-2 gap-1.5 mb-2.5 text-[10px] font-bold">
                            <div class="px-2.5 py-1.5 rounded-xl bg-white/80 border border-emerald-200 text-emerald-800 tabular-nums">ว่าง 70°: <b>${free70.toLocaleString()} L</b></div>
                            <div class="px-2.5 py-1.5 rounded-xl bg-white/80 border border-blue-200 text-blue-800 tabular-nums">ว่าง 40°: <b>${free40.toLocaleString()} L</b></div>
                        </div>
                        <ul class="space-y-2 mt-2">${recItems}</ul>
                    </div>
                    <div class="pt-2 border-t border-slate-200/70 dark:border-slate-700/70 flex flex-wrap justify-between items-center gap-2 text-[11px] text-slate-500">
                        <span>รายการ: <b>${a.txCount}</b> • รับ30วัน: <b>${a.in30d.toLocaleString()} L</b> • จ่าย30วัน: <b>${a.out30d.toLocaleString()} L</b></span>
                        <button type="button" onclick="window.StockMSAuth.switchAdminFactory('${escapeHtml(a.username)}'); window.StockMSUI.closeModal('adminCompareModal');" class="font-extrabold text-blue-600 hover:underline whitespace-nowrap">สลับดูคลังนี้ →</button>
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

    function renderOnlineUsersModalBody() {
        const body = document.getElementById('onlineUsersModalBody');
        if (!body) return;
        const merged = { ...readLocalPresenceMap(), ...onlineUsersMap };
        const allEntries = Object.values(merged).sort((a, b) => {
            const onA = isUserConsideredOnline(a) ? 0 : 1;
            const onB = isUserConsideredOnline(b) ? 0 : 1;
            if (onA !== onB) return onA - onB;
            return String(a.username || '').localeCompare(String(b.username || ''));
        });
        if (!allEntries.length) {
            body.innerHTML = '<div class="py-6 text-center text-slate-400">ยังไม่มีข้อมูลผู้ใช้งานออนไลน์</div>';
            return;
        }
        body.innerHTML = allEntries.map(u => {
            const isOn = isUserConsideredOnline(u);
            const tStr = u.lastSeenAt ? u.lastSeenAt.replace('T', ' ').slice(0, 19) : '-';
            return `
                <div class="p-3 rounded-xl border ${isOn ? 'border-emerald-200 bg-emerald-50/50' : 'border-slate-200 bg-slate-50'} flex items-center justify-between gap-2">
                    <div class="min-w-0">
                        <div class="font-extrabold text-slate-800 truncate">${escapeHtml(u.displayName || u.username)} <span class="text-slate-400 font-semibold">(${escapeHtml(u.username)})</span></div>
                        <div class="text-[11px] text-slate-500">สิทธิ์: <b>${escapeHtml(u.role || 'factory')}</b> • คลังที่ดู: <b>${escapeHtml(u.activeFactory || u.username)}</b></div>
                    </div>
                    <div class="text-right flex-shrink-0">
                        ${isOn
                    ? '<span class="stockms-online-pill"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> ออนไลน์</span>'
                    : '<span class="inline-flex px-2 py-0.5 rounded-full bg-slate-200 text-slate-600 text-[10px] font-bold">ออฟไลน์</span>'}
                        <div class="text-[10px] text-slate-400 mt-1">${escapeHtml(tStr)}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function openOnlinePresenceAction() {
        const s = getSession();
        if (!s) return;
        const modal = document.getElementById('onlineUsersModal');
        if (modal) {
            renderOnlineUsersModalBody();
            modal.classList.remove('hidden');
            bringModalToFront(modal);
        }
    }

    // =========================================================================
    // 10B. 24-HOUR QC PENDING REMINDER ENGINE (TANK >= 95% REPRESENTATIVE SAMPLE)
    // =========================================================================
    let pendingQcModalTab = 'overdue'; // 'overdue' | 'waiting'
    let pendingQcCatFilter = 'ALL'; // 'ALL' | 'BLEND' | 'HIGH_70'

    function hasValidRepresentativeQc(qcData) {
        if (!qcData || typeof qcData !== 'object') return false;
        const keys = ['degree', 'ph', 'acid', 'aldehyde', 'fusel', 'turbidity'];
        return keys.some(k => {
            const v = qcData[k];
            if (v === null || v === undefined || String(v).trim() === '' || String(v).trim() === '-') return false;
            const n = parseFloat(v);
            return !isNaN(n) && n > 0;
        });
    }

    function resolveTxRecordedEpochMs(tx) {
        if (!tx) return 0;
        if (tx.createdAt) {
            const p = Date.parse(tx.createdAt);
            if (!isNaN(p) && p > 0) return p;
        }
        const rg = Number(tx.relatedGroup);
        if (!isNaN(rg) && rg > 1000000000000) return rg;
        const idNum = Number(tx.id);
        if (!isNaN(idNum) && idNum > 1000000000000) return idNum;
        let ds = String(tx.date || '').trim();
        if (ds.startsWith('2569-')) ds = '2026-' + ds.substring(5);
        if (/^\d{4}-\d{2}-\d{2}/.test(ds)) {
            const p = Date.parse(ds.slice(0, 10) + 'T08:00:00');
            if (!isNaN(p) && p > 0) return p;
        }
        return 0;
    }

    function formatDateThaiReadable(dateStr) {
        if (!dateStr) return '-';
        let norm = String(dateStr).trim().slice(0, 10);
        if (norm.startsWith('2569-')) norm = '2026-' + norm.substring(5);
        const parts = norm.split('-');
        if (parts.length !== 3) return norm;
        const months = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.'];
        const y = Number(parts[0]) + 543;
        const m = months[(Number(parts[1]) || 1) - 1] || parts[1];
        const d = Number(parts[2]) || parts[2];
        return `${d} ${m} ${y} (${norm})`;
    }

    function computePendingQcReminders(payload) {
        const p = payload || readWorkingPayload(getActiveFactoryId());
        const txs = Array.isArray(p.liquor_transactions) ? p.liquor_transactions : [];
        const customTanks = (Array.isArray(p.custom_tanks) && p.custom_tanks.length) ? p.custom_tanks : UNIFIED_DEFAULT_TANKS;
        const buildings = p.custom_buildings || UNIFIED_DEFAULT_BUILDINGS;
        const tankConfig = p.tank_config || {};

        const tankMap = {};
        customTanks.forEach(t => {
            const bType = t.type || (buildings[t.b] ? buildings[t.b].type : 'High');
            tankMap[t.id] = {
                id: t.id,
                cap: Number(t.cap) || 0,
                bType: isDefaultBlendingTank(t.id) ? '40Deg' : bType,
                vol: 0,
                lastIntakeOver95: null,
                anyQcInCurrentStack: false
            };
        });

        const sorted = [...txs].sort((a, b) => {
            const da = String(a.date || '').localeCompare(String(b.date || ''));
            if (da !== 0) return da;
            return (Number(a.id) || 0) - (Number(b.id) || 0);
        });

        sorted.forEach(tx => {
            const st = tankMap[tx.tankId];
            if (!st || st.cap <= 0) return;
            const cfgSt = tankConfig[tx.tankId]?.status;
            if (cfgSt === 'bonded' || cfgSt === 'repair') return;

            const typeU = String(tx.type || '').toUpperCase();
            const vol = parseFloat(tx.volume) || 0;
            if (typeU.includes('IN') || typeU === 'INITIAL_IN') {
                st.vol += vol;
                if (hasValidRepresentativeQc(tx.qcData)) {
                    st.anyQcInCurrentStack = true;
                }
                const ratio = st.vol / st.cap;
                const isBlendCategory = typeU === 'BLEND_IN';
                const isHighStorageCategory = st.bType === 'High' && (typeU === 'IN' || typeU === 'TRANSFER_IN' || typeU === 'INITIAL_IN');
                if (ratio >= 0.95 && (isBlendCategory || isHighStorageCategory)) {
                    st.lastIntakeOver95 = {
                        tx,
                        category: isBlendCategory ? 'BLEND' : 'HIGH_70',
                        fillPctAtTx: Number((ratio * 100).toFixed(1))
                    };
                }
            } else if (typeU.includes('OUT')) {
                st.vol = Math.max(0, st.vol - vol);
                if (st.vol < 0.001) {
                    st.vol = 0;
                    st.lastIntakeOver95 = null;
                    st.anyQcInCurrentStack = false;
                }
            }
        });

        const nowMs = Date.now();
        const items = [];
        Object.values(tankMap).forEach(st => {
            if (!st.lastIntakeOver95) return;
            const liveRatio = st.cap > 0 ? (st.vol / st.cap) : 0;
            if (liveRatio < 0.95) return; // Only full / >= 95% tanks require representative analysis
            const { tx, category } = st.lastIntakeOver95;
            if (hasValidRepresentativeQc(tx.qcData) || st.anyQcInCurrentStack) return;

            const recordedAtMs = resolveTxRecordedEpochMs(tx);
            const elapsedMs = recordedAtMs > 0 ? Math.max(0, nowMs - recordedAtMs) : 0;
            const elapsedHours = Math.floor(elapsedMs / 3600000);
            const isOverdue24h = elapsedMs >= 24 * 3600 * 1000;

            items.push({
                txId: tx.id,
                tx,
                tankId: st.id,
                cap: st.cap,
                liveVol: Math.round(st.vol),
                fillPct: Number((liveRatio * 100).toFixed(1)),
                category,
                categoryLabel: category === 'BLEND' ? `ถังปรุงสุรา (${tx.targetDegree || '40'}°)` : 'ถังเก็บบ่มดีกรีสูง (70°)',
                dateRaw: String(tx.date || '').slice(0, 10),
                dateFormatted: formatDateThaiReadable(tx.date),
                batch: tx.batch || '-',
                recordedAtMs,
                elapsedHours,
                isOverdue24h
            });
        });

        items.sort((a, b) => (a.recordedAtMs || 0) - (b.recordedAtMs || 0));
        const overdue = items.filter(x => x.isOverdue24h);
        const waiting = items.filter(x => !x.isOverdue24h);
        return {
            all: items,
            overdue,
            waiting,
            overdueTotal: overdue.length,
            overdueBlend: overdue.filter(x => x.category === 'BLEND').length,
            overdueHigh70: overdue.filter(x => x.category === 'HIGH_70').length,
            waitingTotal: waiting.length
        };
    }

    function refreshQcPendingReminders() {
        const s = getSession();
        if (!s) return null;
        const summary = computePendingQcReminders();

        const navBtn = document.getElementById('navBtnPendingQcReminder');
        const navBadge = document.getElementById('navPendingQcBadge');
        if (navBtn) {
            navBtn.classList.remove('hidden');
            navBtn.classList.add('inline-flex');
        }
        if (navBadge) {
            navBadge.textContent = String(summary.overdueTotal);
            navBadge.classList.toggle('hidden', summary.overdueTotal <= 0);
        }

        const kmBadge = document.getElementById('kmPendingQcBadge');
        if (kmBadge) {
            kmBadge.textContent = String(summary.overdueTotal);
            kmBadge.classList.toggle('hidden', summary.overdueTotal <= 0);
        }

        const modal = document.getElementById('qcPendingReminderModal');
        if (modal && !modal.classList.contains('hidden')) {
            renderPendingQcModalBody(summary);
        }
        return summary;
    }

    function renderPendingQcModalBody(explicitSummary) {
        const summary = explicitSummary || computePendingQcReminders();
        const sumRow = document.getElementById('qcPendingSummaryRow');
        const listEl = document.getElementById('qcPendingListBody');
        if (!sumRow || !listEl) return;

        sumRow.innerHTML = `
            <div class="p-3 rounded-2xl bg-rose-50 border border-rose-200">
                <div class="text-[10px] font-bold text-rose-600 uppercase">ค้างกรอกเกิน 24 ชม. (ทั้งหมด)</div>
                <div class="text-xl font-black text-rose-700 mt-0.5 tabular-nums">${summary.overdueTotal} รายการ</div>
            </div>
            <div class="p-3 rounded-2xl bg-fuchsia-50 border border-fuchsia-200">
                <div class="text-[10px] font-bold text-fuchsia-700 uppercase">ถังปรุงสุรา ≥95% (เกิน 24 ชม.)</div>
                <div class="text-xl font-black text-fuchsia-800 mt-0.5 tabular-nums">${summary.overdueBlend} รายการ</div>
            </div>
            <div class="p-3 rounded-2xl bg-emerald-50 border border-emerald-200">
                <div class="text-[10px] font-bold text-emerald-700 uppercase">ถังเก็บบ่ม 70° ≥95% (เกิน 24 ชม.)</div>
                <div class="text-xl font-black text-emerald-800 mt-0.5 tabular-nums">${summary.overdueHigh70} รายการ</div>
            </div>
        `;

        const overBtn = document.getElementById('qcRemTabOverdue');
        const waitBtn = document.getElementById('qcRemTabWaiting');
        if (overBtn && waitBtn) {
            overBtn.textContent = `เกิน 24 ชม. (${summary.overdueTotal})`;
            waitBtn.textContent = `รอครบ 24 ชม. (${summary.waitingTotal})`;
            overBtn.className = pendingQcModalTab === 'overdue'
                ? 'px-3 py-1.5 rounded-xl bg-rose-600 text-white text-xs font-extrabold shadow-xs'
                : 'px-3 py-1.5 rounded-xl bg-slate-100 text-slate-600 text-xs font-bold';
            waitBtn.className = pendingQcModalTab === 'waiting'
                ? 'px-3 py-1.5 rounded-xl bg-amber-500 text-white text-xs font-extrabold shadow-xs'
                : 'px-3 py-1.5 rounded-xl bg-slate-100 text-slate-600 text-xs font-bold';
        }

        document.querySelectorAll('[data-qcrem-cat]').forEach(btn => {
            const c = btn.getAttribute('data-qcrem-cat');
            btn.classList.toggle('ring-2', c === pendingQcCatFilter);
            btn.classList.toggle('ring-offset-1', c === pendingQcCatFilter);
            btn.classList.toggle('ring-slate-500', c === pendingQcCatFilter);
        });

        const baseList = pendingQcModalTab === 'waiting' ? summary.waiting : summary.overdue;
        const filtered = baseList.filter(it => pendingQcCatFilter === 'ALL' || it.category === pendingQcCatFilter);

        if (!filtered.length) {
            listEl.innerHTML = `<div class="py-8 text-center text-slate-400 font-bold border border-dashed border-slate-200 rounded-2xl">${pendingQcModalTab === 'overdue' ? 'ไม่มีรายการค้างกรอกผลวิเคราะห์ QC ที่เกิน 24 ชั่วโมงแล้ว' : 'ไม่มีถัง ≥95% ที่อยู่ระหว่างรอผล Lab < 24 ชั่วโมง'}</div>`;
            return;
        }

        listEl.innerHTML = filtered.map(it => {
            const catCls = it.category === 'BLEND'
                ? 'bg-fuchsia-100 text-fuchsia-800 border-fuchsia-300'
                : 'bg-emerald-100 text-emerald-800 border-emerald-300';
            const days = Math.floor(it.elapsedHours / 24);
            const hrs = it.elapsedHours % 24;
            const elapsedText = days > 0 ? `${days} วัน ${hrs} ชม.` : `${it.elapsedHours} ชม.`;
            return `
                <div onclick="window.StockMSUI.openQuickQcEntryModal('${escapeHtml(String(it.txId))}')" class="p-3.5 rounded-2xl border ${it.isOverdue24h ? 'border-rose-200 bg-rose-50/40 hover:bg-rose-50' : 'border-amber-200 bg-amber-50/40 hover:bg-amber-50'} transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div class="space-y-1 min-w-0">
                        <div class="flex flex-wrap items-center gap-1.5">
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold border ${catCls}">${escapeHtml(it.categoryLabel)}</span>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-black bg-slate-800 text-white">ถัง ${escapeHtml(it.tankId)}</span>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-blue-100 text-blue-800">${it.fillPct}% (${it.liveVol.toLocaleString()} / ${it.cap.toLocaleString()} L)</span>
                        </div>
                        <div class="text-slate-700 font-bold">วันเดือนปีที่ทำรายการ: <span class="text-indigo-700 font-black">${escapeHtml(it.dateFormatted)}</span> • Batch: <b>${escapeHtml(it.batch)}</b></div>
                        <div class="text-[11px] text-slate-500">รอผล Lab มาแล้ว <b class="${it.isOverdue24h ? 'text-rose-600' : 'text-amber-600'}">${elapsedText}</b> • รายการ: ${escapeHtml(it.tx.type || '-')}</div>
                    </div>
                    <button type="button" onclick="event.stopPropagation(); window.StockMSUI.openQuickQcEntryModal('${escapeHtml(String(it.txId))}')" class="px-3.5 py-2 rounded-xl bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white font-extrabold text-xs shadow-sm whitespace-nowrap flex items-center justify-center gap-1.5">
                        <i class="fas fa-edit"></i> กรอกผลวิเคราะห์ทันที
                    </button>
                </div>
            `;
        }).join('');
    }

    function openQcPendingReminderModal() {
        const s = getSession();
        if (!s) return;
        const modal = document.getElementById('qcPendingReminderModal');
        if (!modal) return;
        const summary = refreshQcPendingReminders();
        pendingQcModalTab = (summary.overdueTotal === 0 && summary.waitingTotal > 0) ? 'waiting' : 'overdue';
        renderPendingQcModalBody(summary);
        modal.classList.remove('hidden');
        bringModalToFront(modal);
    }

    function switchPendingQcTab(tab) {
        pendingQcModalTab = tab === 'waiting' ? 'waiting' : 'overdue';
        renderPendingQcModalBody();
    }

    function setPendingQcCatFilter(cat) {
        pendingQcCatFilter = ['BLEND', 'HIGH_70'].includes(cat) ? cat : 'ALL';
        renderPendingQcModalBody();
    }

    async function openQuickQcEntryModal(txIdRaw) {
        if (typeof Swal === 'undefined') return;
        const fId = getActiveFactoryId();
        const payload = readWorkingPayload(fId);
        const txs = Array.isArray(payload.liquor_transactions) ? payload.liquor_transactions : [];
        const txIdx = txs.findIndex(t => String(t.id) === String(txIdRaw));
        if (txIdx < 0) {
            Swal.fire('ไม่พบรายการ', 'ไม่พบ Transaction ที่ต้องการกรอกผล QC ในคลังปัจจุบัน', 'error');
            return;
        }
        const tx = txs[txIdx];
        const prevQc = tx.qcData || {};

        const { value: qcValues } = await Swal.fire({
            title: `กรอกผลวิเคราะห์ QC • ถัง ${escapeHtml(tx.tankId || '-')}`,
            width: 560,
            html: `
                <div class="text-left text-xs space-y-3">
                    <div class="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                        <div><b>วันเดือนปีที่ทำรายการ:</b> ${escapeHtml(formatDateThaiReadable(tx.date))}</div>
                        <div><b>ประเภท:</b> ${escapeHtml(tx.type || '-')} • <b>Batch:</b> ${escapeHtml(tx.batch || '-')} • <b>ปริมาตร:</b> ${(parseFloat(tx.volume) || 0).toLocaleString()} L</div>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">ดีกรีแอลกอฮอล์ (°)</label><input id="qqc_deg" type="number" step="0.01" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.degree ?? '')}" placeholder="${tx.type === 'BLEND_IN' ? (tx.targetDegree || '40.0') : '70.0'}"></div>
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">ค่า pH</label><input id="qqc_ph" type="number" step="0.01" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.ph ?? '')}" placeholder="4.50"></div>
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">ค่ากรดรวม (% Acid)</label><input id="qqc_acid" type="number" step="0.0001" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.acid ?? '')}" placeholder="0.025"></div>
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">แอลดีไฮด์ (mg/L)</label><input id="qqc_ald" type="number" step="0.01" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.aldehyde ?? '')}" placeholder="30"></div>
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">ฟิวเซลออยล์ (mg/L)</label><input id="qqc_fus" type="number" step="1" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.fusel ?? '')}" placeholder="1500"></div>
                        <div><label class="block text-[10px] font-bold text-slate-500 mb-1">ความขุ่น (NTU)</label><input id="qqc_tur" type="number" step="0.01" class="w-full px-2.5 py-2 border border-slate-300 rounded-xl font-bold" value="${escapeHtml(prevQc.turbidity ?? '')}" placeholder="0.50"></div>
                    </div>
                </div>
            `,
            showCancelButton: true,
            confirmButtonColor: '#2563eb',
            confirmButtonText: '<i class="fas fa-save mr-1"></i> บันทึกผลวิเคราะห์ QC',
            cancelButtonText: 'ยกเลิก',
            preConfirm: () => {
                const qc = {
                    degree: document.getElementById('qqc_deg').value.trim(),
                    ph: document.getElementById('qqc_ph').value.trim(),
                    acid: document.getElementById('qqc_acid').value.trim(),
                    aldehyde: document.getElementById('qqc_ald').value.trim(),
                    fusel: document.getElementById('qqc_fus').value.trim(),
                    turbidity: document.getElementById('qqc_tur').value.trim()
                };
                if (!hasValidRepresentativeQc(qc)) {
                    Swal.showValidationMessage('กรุณากรอกค่าผลวิเคราะห์อย่างน้อย 1 รายการ (เช่น Degree / pH)');
                    return false;
                }
                return qc;
            }
        });

        if (!qcValues) return;

        // Persist to localStorage, sync host in-memory lexical `transactions` via reloadAllStorageData(), then trigger saveData()
        const beforeSnap = clonePayloadSnapshot(readTenantLocalPayload(fId));
        txs[txIdx].qcData = qcValues;
        localStorage.setItem('liquor_transactions', JSON.stringify(txs));
        if (typeof window.reloadAllStorageData === 'function') {
            window.reloadAllStorageData();
        }

        if (typeof window.saveData === 'function' && window.saveData.__stockmsWrapped) {
            window.saveData();
        } else {
            const nextPayload = readWorkingPayload(fId);
            nextPayload.initialized = true;
            writeTenantLocalPayload(fId, nextPayload);
            scheduleCloudSync();
            await recordWorkspaceChangeLog(fId, beforeSnap, nextPayload);
        }

        triggerHostPageReload();
        refreshMobileShellData();
        refreshQcPendingReminders();
        Swal.fire('บันทึกผลวิเคราะห์สำเร็จ!', `อัปเดตผลตรวจ QC ของถัง ${tx.tankId} เรียบร้อยแล้ว`, 'success');
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
        showAdminElems(['navAdminFactoryWrap', 'navBtnAdminCompare', 'navBtnAdminLogs', 'navBtnAdminUsers', 'kmAdminSwitchBar'], true);
        showAdminElems(['kmBtnAdminUsers', 'kmBtnAdminCompare', 'kmBtnAdminLogs'], false);
        updateAdminLogsBadgeUI();
        renderOnlinePresenceUI();
        refreshQcPendingReminders();

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
                { label: 'บันทึกรับ-จ่าย', icon: 'fa-plus-circle', bg: '#fef3c7', color: '#b45309', fn: "window.StockMSUI.navigateSeamlessly('index.html')" },
                { label: 'จัดการคลัง', icon: 'fa-tasks', bg: '#ede9fe', color: '#6d28d9', fn: "window.StockMSUI.navigateSeamlessly('index.html')" },
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
            navigateSeamlessly('index.html#new-tx');
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
            navigateSeamlessly('index.html#daily-report');
        }
    }

    function triggerReconcileAction() {
        if (!isDashboardPage() && typeof window.openReconcileModal === 'function') {
            window.openReconcileModal();
        } else {
            navigateSeamlessly('index.html#reconcile');
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
        bringModalToFront,
        openChangePasswordModal,
        openAdminUserModal,
        openAdminEditUser,
        cancelAdminEditUser,
        openOnlinePresenceAction,
        openQcPendingReminderModal,
        switchPendingQcTab,
        setPendingQcCatFilter,
        openQuickQcEntryModal,
        computePendingQcReminders,
        refreshQcPendingReminders,
        navigateSeamlessly,
        handleSeamlessHostNav,
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
                navigateSeamlessly('index.html');
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
                navigateSeamlessly('dashboard.html?qc=open#qc-modal');
            }
        },
        triggerBackupAction: function () {
            if (typeof window.exportData === 'function') {
                window.exportData();
            } else {
                navigateSeamlessly('index.html');
            }
        },
        triggerImportAction: function () {
            const imp = document.getElementById('importFile');
            if (imp) imp.click();
            else navigateSeamlessly('index.html');
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
        installDynamicModalStackObserver();
        restorePersistentFullscreen();
        installSeamlessLinkInterceptor();
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

        // Periodically refresh 24h QC pending badge every 60s
        if (!window.__stockmsQcReminderInterval) {
            window.__stockmsQcReminderInterval = setInterval(() => {
                if (getSession()) refreshQcPendingReminders();
            }, 60000);
        }

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
