// Firebase imports are loaded dynamically so the split app can run as a classic script.
(async () => {
"use strict";

const firebaseAppModule = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js");
const firestoreModule = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js");
const authModule = await import("https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js");

const { initializeApp, getApps } = firebaseAppModule;
const { initializeFirestore, persistentLocalCache, getFirestore, collection, collectionGroup, addDoc, getDocs, getDocsFromServer, serverTimestamp, deleteDoc, doc, updateDoc, setDoc, getDoc, getDocFromServer, runTransaction, query, where, onSnapshot } = firestoreModule;
const { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged, signOut, sendEmailVerification, sendPasswordResetEmail, fetchSignInMethodsForEmail, deleteUser, updateProfile, EmailAuthProvider, linkWithCredential, GoogleAuthProvider, signInWithPopup } = authModule;

// 🔥 Your Firebase Config
const firebaseConfig = {
  apiKey: "AIzaSyCirCkRGlsODEExB9VLVY08Zw7b84zm_Qc",
  authDomain: "novaafix-86912.firebaseapp.com",
  projectId: "novaafix-86912",
  storageBucket: "novaafix-86912.firebasestorage.app",
  messagingSenderId: "699084708640",
  appId: "1:699084708640:web:401f5d6990d818551e1545",
  measurementId: "G-WHHXFW3N7R"
};

// 🔥 Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
let db;
try {
  db = initializeFirestore(app, {
    localCache: persistentLocalCache()
  });
} catch (_) {
  db = getFirestore(app);
}
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: "select_account"
});

const TRANSFER_APP_NAME = "novafix-transfer";
let transferAuth = null;
let transferDb = null;
const IMPORT_SECURITY_ALERT_TYPE = "source_snapshot_imported";
const PENDING_REQUEST_LOGIN_ALERT_FLAG_KEY = "novafix_pending_request_login_alert";

let pendingRequestLoginAlertArmedMemory = false;

function markPendingRequestLoginAlertForNextSessionStart() {
  pendingRequestLoginAlertArmedMemory = true;
  try {
    sessionStorage.setItem(PENDING_REQUEST_LOGIN_ALERT_FLAG_KEY, "1");
  } catch (_) {}
}

function consumePendingRequestLoginAlertFlag() {
  let armed = pendingRequestLoginAlertArmedMemory;
  pendingRequestLoginAlertArmedMemory = false;
  try {
    if (sessionStorage.getItem(PENDING_REQUEST_LOGIN_ALERT_FLAG_KEY) === "1") {
      armed = true;
      sessionStorage.removeItem(PENDING_REQUEST_LOGIN_ALERT_FLAG_KEY);
    }
  } catch (_) {}
  return armed;
}

function clearPendingRequestLoginAlertFlag() {
  pendingRequestLoginAlertArmedMemory = false;
  try {
    sessionStorage.removeItem(PENDING_REQUEST_LOGIN_ALERT_FLAG_KEY);
  } catch (_) {}
}

// ---------- Firestore schema validators & safe wrappers ----------
const FIRESTORE_SCHEMAS = {
  profile: {
    required: ["googleIdentitySetupCompleted","updatedAt"],
    types: {
      googleIdentitySetupCompleted: 'boolean',
      googleIdentitySetupCompletedAt: 'timestamp',
      googleLegacyPasswordRequired: 'boolean',
      googleImportPasswordEnabled: 'boolean',
      googleImportPasswordEnabledAt: 'timestamp',
      displayNameDashboardChangedAt: 'timestamp',
      displayNameDashboardChangedAtMs: 'number',
      displayNameDashboardCooldownUntilMs: 'number',
      updatedAt: 'timestamp'
    }
  },
  onboarding: {
    types: {
      welcomeGuideCompleted: 'boolean',
      welcomeGuideVersion: 'number',
      welcomeGuideCompletedAt: 'timestamp',
      updatedAt: 'timestamp'
    }
  },
  dailyUsage: {
    types: {
      dateKey: 'string',
      moodCount: 'number',
      taskCount: 'number',
      sleepCount: 'number',
      waterCount: 'number',
      reminderCount: 'number',
      gratitudeCount: 'number',
      updatedAt: 'timestamp'
    }
  },
  aiUsage: {
    types: {
      dateKeyLocal: 'string',
      dateKeyGMT: 'string',
      count: 'number',
      updatedAt: 'timestamp'
    }
  },
  dailyChallenge: {
    types: {
      challenge: 'string',
      completed: 'boolean',
      dateKey: 'string',
      timeZone: 'string',
      updatedAt: 'timestamp'
    }
  },
  friend: {
    types: {
      friendUid: 'string',
      friendEmail: 'string',
      status: 'string',
      connectedAt: 'timestamp',
      unfriendedAt: 'timestamp',
      updatedAt: 'timestamp',
      updatedAtMs: 'number'
    }
  },
  friendUnfriended: {
    types: {
      friendUid: 'string',
      status: 'string',
      unfriendedBy: 'string',
      unfriendedAt: 'timestamp',
      updatedAt: 'timestamp'
    }
  },
  friendRequest: {
    types: {
      fromUid: 'string',
      fromEmail: 'string',
      fromName: 'string',
      fromUsername: 'string',
      fromDisplayName: 'string',
      toUid: 'string',
      toEmail: 'string',
      toName: 'string',
      toUsername: 'string',
      toDisplayName: 'string',
      status: 'string',
      createdAt: 'timestamp',
      updatedAt: 'timestamp',
      createdAtMs: 'number',
      updatedAtMs: 'number',
      requestNonce: 'string'
    }
  },
  friendRequestsSent: {
    types: {
      fromUid: 'string',
      fromEmail: 'string',
      toUid: 'string',
      toEmail: 'string',
      status: 'string',
      createdAt: 'timestamp',
      updatedAt: 'timestamp'
    }
  },
  friendRequestDot: {
    types: {
      seenKeys: 'array',
      updatedAt: 'timestamp'
    }
  },
  securityAlerts: {
    types: {
      type: 'string',
      seen: 'boolean',
      seenAt: 'timestamp',
      destinationUid: 'string',
      createdAt: 'timestamp'
    }
  },
  userDirectory: {
    types: {
      uid: 'string',
      email: 'string',
      username: 'string',
      name: 'string',
      displayName: 'string',
      updatedAt: 'timestamp'
    }
  },
  usernameDirectory: {
    types: {
      uid: 'string',
      email: 'string',
      username: 'string',
      name: 'string',
      displayName: 'string',
      updatedAt: 'timestamp'
    }
  },
  water: {
    types: {
      goal: 'number',
      goalDateKey: 'string',
      lastResetDateKey: 'string',
      updatedAt: 'timestamp'
    }
  },
  weeklyTargets: {
    types: {
      waterGoal: 'number',
      sleepTarget: 'number',
      taskTarget: 'number',
      updatedAt: 'timestamp'
    }
  },
  habitQuest: {
    types: {
      xp: 'number',
      shield: 'boolean',
      streakCount: 'number',
      lastStreakDateKey: 'string',
      weekStartKey: 'string',
      weeklyQuestUsedIds: 'array',
      completedDateKeys: 'array',
      dateKey: 'string',
      quests: 'array',
      updatedAt: 'timestamp'
    }
  },
  startupUsage: {
    types: {
      planDateKey: 'string',
      planCount: 'number',
      reportWeekKey: 'string',
      reportCount: 'number',
      updatedAt: 'timestamp'
    }
  },
  startupPack: {
    types: {
      updatedAt: 'timestamp'
    }
  },
  timeSync: {
    types: {
      clientNow: 'number',
      serverNow: 'timestamp',
      updatedAt: 'timestamp'
    }
  },
  barGraphs: {
    types: {
      updatedAt: 'timestamp'
    }
  },
  current: {
    types: {
      updatedAt: 'timestamp'
    }
  }
};

function isTimestampLike(v){
  if (!v) return false;
  if (v instanceof Date) return true;
  if (typeof v === 'number') return true;
  if (typeof v === 'object') {
    return ('seconds' in v) || ('_seconds' in v) || ('_nanoseconds' in v);
  }
  return false;
}

function validateSchema(schemaName, obj = {}){
  const schema = FIRESTORE_SCHEMAS[schemaName];
  const errors = [];
  if (!schema) return { ok: true, errors: [], data: obj };
  const types = schema.types || {};
  for(const key of Object.keys(obj)){
    const expected = types[key];
    if (!expected) continue;
    const val = obj[key];
    if (val === null || val === undefined) continue;
    switch(expected){
      case 'string': if (typeof val !== 'string') errors.push(`${key} expected string`); break;
      case 'number': if (typeof val !== 'number') errors.push(`${key} expected number`); break;
      case 'boolean': if (typeof val !== 'boolean') errors.push(`${key} expected boolean`); break;
      case 'timestamp': if (!isTimestampLike(val)) errors.push(`${key} expected timestamp-like`); break;
      default: break;
    }
  }
  const required = schema.required || [];
  for(const r of required){ if (!(r in obj)) errors.push(`missing required ${r}`); }
  return { ok: errors.length === 0, errors, data: obj };
}

class FirestoreValidationError extends Error { constructor(schema, errors){ super(`Schema validation failed for ${schema}: ${errors.join('; ')}`); this.name = 'FirestoreValidationError'; this.schema = schema; this.errors = errors; }}

async function safeGetDoc(ref, schemaName){
  const snap = await getDoc(ref);
  if (!snap.exists()) return { exists:false, data:null, snap };
  const data = snap.data();
  const v = validateSchema(schemaName, data);
  if (!v.ok) console.warn('Firestore read validation failed', schemaName, v.errors, ref.path);
  return { exists:true, data:v.data, snap, validation:v };
}

async function safeSetDoc(ref, data, schemaName, options){
  if (schemaName){
    const v = validateSchema(schemaName, data);
    if (!v.ok) throw new FirestoreValidationError(schemaName, v.errors);
  }
  return await setDoc(ref, data, options || {});
}

async function safeUpdateDoc(ref, data, schemaName){
  if (schemaName){
    const v = validateSchema(schemaName, data);
    if (!v.ok) throw new FirestoreValidationError(schemaName, v.errors);
  }
  return await updateDoc(ref, data);
}

// ---------- Error categorization framework ----------
// Classify errors as critical (require immediate attention) vs recoverable (can retry/skip)
function categorizeError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  const code = err?.code || "";
  
  // Critical errors - require user attention and cannot be silently handled
  const criticalPatterns = [
    /permission-denied/, /unauthenticated/, /invalid-api-key/,
    /quota-exceeded/, /resource-exhausted/, /internal/
  ];
  
  // Recoverable errors - can retry or skip gracefully
  const recoverablePatterns = [
    /network|timeout|unavailable|not-found|failed-precondition/
  ];
  
  const isCritical = criticalPatterns.some(p => p.test(msg) || p.test(code));
  const isRecoverable = recoverablePatterns.some(p => p.test(msg) || p.test(code));
  
  return {
    isCritical: isCritical || (!isRecoverable && msg.includes('error')),
    isRecoverable: isRecoverable || msg.includes('timeout') || msg.includes('network'),
    errorType: isCritical ? 'CRITICAL' : isRecoverable ? 'RECOVERABLE' : 'UNKNOWN',
    code: code || 'unknown_error'
  };
}

// Helper: log and categorize error, optionally notify user
function handleFirestoreError(err, operationCode, context = {}) {
  const category = categorizeError(err);
  const logLevel = category.isCritical ? 'error' : 'warn';
  
  structuredLog(logLevel, operationCode, err?.message || String(err), {
    ...context,
    errorType: category.errorType,
    errorCode: category.code
  });
  
  if (category.isCritical && context.userId) {
    // Notify user of critical errors - these need attention
    const msg = 'A critical error occurred. Please try again or contact support.';
    notifyFirestoreError(msg);
  }
  
  return category;
}

// ---------- Structured logging + centralized Firestore access wrappers ----------
function structuredLog(level, code, message, meta = {}){
  try {
    const entry = {
      ts: new Date().toISOString(),
      level: String(level || "info").toLowerCase(),
      code: String(code || ""),
      message: String(message || ""),
      meta
    };
    // Keep logs readable in console but structured for ingestion if needed
    if (entry.level === 'error') console.error('LOG', entry);
    else if (entry.level === 'warn') console.warn('LOG', entry);
    else console.log('LOG', entry);
  } catch (_) {}
}

async function fsGetDoc(ref, schemaName = null){
  try{
    const res = await safeGetDoc(ref, schemaName);
    structuredLog('info', 'fs.get', 'read', { path: ref.path, schema: schemaName, exists: !!res.exists });
    return res;
  } catch (err){
    structuredLog('error', 'fs.get.error', err?.message || String(err), { path: ref?.path, schema: schemaName });
    notifyFirestoreError(err);
    throw err;
  }
}

async function fsGetDocs(q, schemaName = null){
  try{
    const snap = await getDocs(q);
    structuredLog('info', 'fs.getDocs', 'query', { size: snap.size });
    return snap;
  } catch(err){
    structuredLog('error', 'fs.getDocs.error', err?.message || String(err));
    notifyFirestoreError(err);
    throw err;
  }
}

async function fsSetDoc(ref, data, schemaName = null, options = {}){
  try{
    const res = await safeSetDoc(ref, data, schemaName, options);
    structuredLog('info', 'fs.set', 'write', { path: ref.path, schema: schemaName });
    return res;
  } catch(err){
    structuredLog('error', 'fs.set.error', err?.message || String(err), { path: ref?.path, schema: schemaName, data });
    notifyFirestoreError(err);
    throw err;
  }
}

async function fsUpdateDoc(ref, data, schemaName = null){
  try{
    const res = await safeUpdateDoc(ref, data, schemaName);
    structuredLog('info', 'fs.update', 'update', { path: ref.path, schema: schemaName });
    return res;
  } catch(err){
    structuredLog('error', 'fs.update.error', err?.message || String(err), { path: ref?.path, schema: schemaName, data });
    notifyFirestoreError(err);
    throw err;
  }
}

async function fsRunTransaction(dbInstance, updateFn){
  try{
    const result = await runTransaction(dbInstance, async (tx) => {
      return await updateFn(tx);
    });
    structuredLog('info', 'fs.tx', 'transaction_success');
    return result;
  } catch(err){
    structuredLog('error', 'fs.tx.error', err?.message || String(err));
    notifyFirestoreError(err);
    throw err;
  }
}

async function fsDeleteDoc(ref){
  try{
    const res = await deleteDoc(ref);
    structuredLog('info', 'fs.delete', 'delete', { path: ref.path });
    return res;
  } catch(err){
    structuredLog('error', 'fs.delete.error', err?.message || String(err), { path: ref?.path });
    notifyFirestoreError(err);
    throw err;
  }
}

// ========== SERVICE LAYER ==========
// Clear separation of concerns with namespaced service objects
// This structure enables future modularization into separate files
//
// SERVICE LAYER ARCHITECTURE:
// ├── MigrationService: Data normalization, versioning, schema migrations
// ├── AuthService: Auth flows, TOS, Google identity setup
// ├── ProfileService: Profile data, directory entries, settings
// ├── FriendService: Friend requests, connections, relationships
// └── DataService: Import/export, snapshots, data transfers
//
// USAGE PATTERNS:
// 1. UI handlers call service methods: await FriendService.addFriend(username)
// 2. Services wrap operations with LoadingStateManager.withLoading()
// 3. Services use handleFirestoreError() for consistent error handling
// 4. Services return { ok, error } or boolean for status
// 5. UI components handle empty/error states via UIStateHelpers
//
// MIGRATION PATH TO MODULES:
// When moving to module system (webpack/vite), extract each service
// into its own file (services/authService.js, services/friendService.js, etc.)
// and import as ES6 modules. The structure is already in place.

// ---------- MIGRATION SERVICE ----------
// Handles data normalization, versioning, and schema migrations
const MigrationService = {
  async migrate(userId) {
    if (!userId) return false;
    try {
      await migrateUserDocument(userId);
      structuredLog('info', 'migration.service', 'user_migration_complete', { userId });
      return true;
    } catch (err) {
      handleFirestoreError(err, 'migration.service.error', { userId });
      return false;
    }
  }
};

// ---------- PROFILE SERVICE ----------
// Handles user profile data, directory entries, and settings management
const ProfileService = {
  async updateProfile(userId, profileData) {
    if (!userId || !profileData) return false;
    try {
      await LoadingStateManager.withLoading(`profile_update_${userId}`, 'profile', async () => {
        await updateProfileData(userId, profileData);
      });
      structuredLog('info', 'profile.service', 'profile_updated', { userId });
      return true;
    } catch (err) {
      handleFirestoreError(err, 'profile.service.update', { userId });
      return false;
    }
  },
  
  async loadWeeklyTargets(userId) {
    if (!userId) return null;
    try {
      return await LoadingStateManager.withLoading(`targets_load_${userId}`, 'profile', async () => {
        await loadWeeklyTargets(userId);
        return weeklyTargets;
      });
    } catch (err) {
      handleFirestoreError(err, 'profile.service.targets', { userId });
      return null;
    }
  }
};

// ---------- AUTH SERVICE ----------
// Handles authentication flows, TOS, and Google identity setup
const AuthService = {
  async ensureTosAccepted(userId) {
    if (!userId) return false;
    try {
      const accepted = await ensureTosAccepted(userId);
      structuredLog('info', 'auth.service', 'tos_check', { userId, accepted });
      return accepted;
    } catch (err) {
      handleFirestoreError(err, 'auth.service.tos', { userId });
      return false;
    }
  },
  
  async setupGoogleIdentity(user) {
    if (!user?.uid) return false;
    try {
      return await LoadingStateManager.withLoading(`google_setup_${user.uid}`, 'profile', async () => {
        await ensureGoogleIdentitySetupIfNeeded(user);
        return true;
      });
    } catch (err) {
      handleFirestoreError(err, 'auth.service.google_setup', { userId: user.uid });
      return false;
    }
  },
  
  async initializeSession(user) {
    if (!user?.uid) return false;
    try {
      await initializeAuthenticatedSession(user);
      structuredLog('info', 'auth.service', 'session_init', { userId: user.uid });
      return true;
    } catch (err) {
      handleFirestoreError(err, 'auth.service.init', { userId: user.uid });
      return false;
    }
  }
};

// ---------- FRIEND SERVICE ----------
// Handles friend requests, connections, and friend relationship management
const FriendService = {
  async addFriend(username) {
    if (!username) return { ok: false, error: 'Username required' };
    try {
      return await LoadingStateManager.withLoading(`friend_add_${username}`, 'friend', async () => {
        return await addFriendByUsername(username);
      });
    } catch (err) {
      handleFirestoreError(err, 'friend.service.add', { username });
      return { ok: false, error: err?.message || 'Failed to add friend' };
    }
  },
  
  async respondToRequest(requesterId, accept = true) {
    if (!requesterId) return false;
    try {
      return await LoadingStateManager.withLoading(`friend_respond_${requesterId}`, 'friend', async () => {
        accept ? await acceptFriendRequest(requesterId) : await declineFriendRequest(requesterId);
        return true;
      });
    } catch (err) {
      handleFirestoreError(err, 'friend.service.respond', { requesterId, accept });
      return false;
    }
  },
  
  async unfriend(friendUid) {
    if (!friendUid) return false;
    try {
      return await LoadingStateManager.withLoading(`friend_remove_${friendUid}`, 'friend', async () => {
        await unfriendByUid(friendUid);
        return true;
      });
    } catch (err) {
      handleFirestoreError(err, 'friend.service.unfriend', { friendUid });
      return false;
    }
  },
  
  async loadFriendsData(userId) {
    if (!userId) return false;
    try {
      return await LoadingStateManager.withLoading(`friends_load_${userId}`, 'friend', async () => {
        await loadFriendsInsights(userId);
        return true;
      });
    } catch (err) {
      handleFirestoreError(err, 'friend.service.load', { userId });
      return false;
    }
  }
};

// ---------- DATA IMPORT/EXPORT SERVICE ----------
// Handles data snapshots, imports, and exports
const DataService = {
  async buildExport(userId) {
    if (!userId) return null;
    try {
      return await LoadingStateManager.withLoading(`data_export_${userId}`, 'import', async () => {
        return await buildExportPayloadForUser(userId);
      });
    } catch (err) {
      handleFirestoreError(err, 'data.service.export', { userId });
      return null;
    }
  },
  
  async importSnapshot(userId, data) {
    if (!userId || !data) return false;
    try {
      return await LoadingStateManager.withLoading(`data_import_${userId}`, 'import', async () => {
        return await importSnapshot(userId, data);
      });
    } catch (err) {
      handleFirestoreError(err, 'data.service.import', { userId });
      return false;
    }
  }
};

// ---------- Data normalization & migration system ----------
function normalizeTimestamp(value){
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value === 'number') return new Date(value);
  if (typeof value === 'object' && ('seconds' in value || '_seconds' in value)) {
    const secs = value.seconds || value._seconds || 0;
    return new Date(secs * 1000);
  }
  return null;
}

function ensureTimestamp(value){
  if (!value) return serverTimestamp();
  if (value instanceof Date) return value;
  if (typeof value === 'number') return value;
  if (typeof value === 'object' && ('seconds' in value || '_seconds' in value)) return value;
  return serverTimestamp();
}

async function migrateUserDocument(userId){
  if (!userId) return;
  const docPath = `users/${userId}/settings/migrationVersion`;
  const versionRef = doc(db, docPath);
  
  try {
    const versionRes = await fsGetDoc(versionRef, null);
    if (versionRes.exists && (versionRes.data?.version >= 2)) return;
  } catch (_) {
    // Version doc doesn't exist or error reading it - proceed with migration
  }

  structuredLog('info', 'migration.start', 'Starting user data normalization', { userId });

  try {
    // Migrate profile
    try {
      const profileRef = doc(db, `users/${userId}/settings/profile`);
      const profileRes = await fsGetDoc(profileRef, 'profile');
      if (profileRes.exists) {
        const data = profileRes.data || {};
        const normalized = {
          ...data,
          googleIdentitySetupCompleted: !!data.googleIdentitySetupCompleted,
          googleIdentitySetupCompletedAt: data.googleIdentitySetupCompletedAt ? ensureTimestamp(data.googleIdentitySetupCompletedAt) : null,
          googleLegacyPasswordRequired: !!data.googleLegacyPasswordRequired,
          googleImportPasswordEnabled: !!data.googleImportPasswordEnabled,
          googleImportPasswordEnabledAt: data.googleImportPasswordEnabledAt ? ensureTimestamp(data.googleImportPasswordEnabledAt) : null,
          displayNameDashboardChangedAt: data.displayNameDashboardChangedAt ? ensureTimestamp(data.displayNameDashboardChangedAt) : null,
          displayNameDashboardChangedAtMs: Number(data.displayNameDashboardChangedAtMs) || 0,
          displayNameDashboardCooldownUntilMs: Number(data.displayNameDashboardCooldownUntilMs) || 0,
          updatedAt: ensureTimestamp(data.updatedAt),
          version: 2
        };
        await fsSetDoc(profileRef, normalized, 'profile', { merge: true });
        structuredLog('info', 'migration.profile', 'Profile normalized', { userId });
      }
    } catch (err) {
      structuredLog('warn', 'migration.profile.error', err?.message || String(err), { userId });
    }

    // Migrate onboarding
    try {
      const onboardingRef = doc(db, `users/${userId}/settings/onboarding`);
      const onboardingRes = await fsGetDoc(onboardingRef, 'onboarding');
      if (onboardingRes.exists) {
        const data = onboardingRes.data || {};
        const normalized = {
          ...data,
          welcomeGuideCompleted: !!data.welcomeGuideCompleted,
          welcomeGuideVersion: Number(data.welcomeGuideVersion) || 1,
          welcomeGuideCompletedAt: data.welcomeGuideCompletedAt ? ensureTimestamp(data.welcomeGuideCompletedAt) : null,
          tosAccepted: !!data.tosAccepted,
          tosAcceptedAt: data.tosAcceptedAt ? ensureTimestamp(data.tosAcceptedAt) : null,
          updatedAt: ensureTimestamp(data.updatedAt),
          version: 2
        };
        await fsSetDoc(onboardingRef, normalized, 'onboarding', { merge: true });
        structuredLog('info', 'migration.onboarding', 'Onboarding normalized', { userId });
      }
    } catch (err) {
      structuredLog('warn', 'migration.onboarding.error', err?.message || String(err), { userId });
    }

    // Migrate water settings
    try {
      const waterRef = doc(db, `users/${userId}/settings/water`);
      const waterRes = await fsGetDoc(waterRef, 'water');
      if (waterRes.exists) {
        const data = waterRes.data || {};
        const normalized = {
          goal: Number(data.goal) || 0,
          goalDateKey: String(data.goalDateKey || ""),
          lastResetDateKey: String(data.lastResetDateKey || ""),
          updatedAt: ensureTimestamp(data.updatedAt),
          version: 2
        };
        await fsSetDoc(waterRef, normalized, 'water', { merge: true });
      }
    } catch (err) {
      structuredLog('warn', 'migration.water.error', err?.message || String(err));
    }

    // Migrate weeklyTargets
    try {
      const weeklyRef = doc(db, `users/${userId}/settings/weeklyTargets`);
      const weeklyRes = await fsGetDoc(weeklyRef, 'weeklyTargets');
      if (weeklyRes.exists) {
        const data = weeklyRes.data || {};
        const normalized = {
          waterGoal: Number(data.waterGoal) || 0,
          sleepTarget: Number(data.sleepTarget) || 8,
          taskTarget: Number(data.taskTarget) || 5,
          updatedAt: ensureTimestamp(data.updatedAt),
          version: 2
        };
        await fsSetDoc(weeklyRef, normalized, 'weeklyTargets', { merge: true });
      }
    } catch (err) {
      structuredLog('warn', 'migration.weeklyTargets.error', err?.message || String(err));
    }

    // Mark migration as complete
    await fsSetDoc(versionRef, { version: 2, migratedAt: serverTimestamp() }, null, { merge: true });
    structuredLog('info', 'migration.complete', 'User data normalization complete', { userId });
  } catch (err) {
    structuredLog('error', 'migration.fatal', err?.message || String(err), { userId });
  }
}

function getTransferClients() {
  let transferApp = getApps().find((entry) => entry.name === TRANSFER_APP_NAME);
  if (!transferApp) {
    transferApp = initializeApp(firebaseConfig, TRANSFER_APP_NAME);
  }
  if (!transferAuth) transferAuth = getAuth(transferApp);
  if (!transferDb) transferDb = getFirestore(transferApp);
  return { transferAuth, transferDb };
}

// ---------- DOM REFERENCES ----------
const emailInput = document.getElementById("emailInput");
const passwordInput = document.getElementById("passwordInput");
const usernameInput = document.getElementById("usernameInput");
const displayNameInput = document.getElementById("displayNameInput");
const googleIdentityModal = document.getElementById("googleIdentityModal");
const googleIdentityTitle = document.getElementById("googleIdentityTitle");
const googleIdentityNote = document.getElementById("googleIdentityNote");
const googleIdentityUsernameInput = document.getElementById("googleIdentityUsernameInput");
const googleIdentityDisplayNameInput = document.getElementById("googleIdentityDisplayNameInput");
const googleIdentityPasswordInput = document.getElementById("googleIdentityPasswordInput");
const googleIdentitySaveBtn = document.getElementById("googleIdentitySaveBtn");
const googleIdentityError = document.getElementById("googleIdentityError");
const googleAuthButton = document.getElementById("googleAuthButton");
const resetPasswordButton = document.getElementById("resetPasswordButton");
const resendVerificationButton = document.getElementById("resendVerificationButton");
const splash = document.getElementById("splash");
const signInModal = document.getElementById("signInModal");
const dashboard = document.querySelector(".dashboard");
const accountBtn = document.getElementById("accountBtn");
const accountOverlay = document.getElementById("accountOverlay");
const accountPanel = document.getElementById("accountPanel");
const accountTabButtons = Array.from(document.querySelectorAll(".account-tab-btn"));
const accountTabPanels = Array.from(document.querySelectorAll(".account-tab-panel"));
const friendsTabBtn = accountTabButtons.find((buttonEl) => String(buttonEl?.dataset?.accountTab || "").trim().toLowerCase() === "friends") || null;
const APP_VERSION = "v11.3.2";
const aboutAppVersion = document.getElementById("aboutAppVersion");
const reportRedirectConfirmModal = document.getElementById("reportRedirectConfirmModal");
const importTransferModal = document.getElementById("importTransferModal");
const importSourceEmailInput = document.getElementById("importSourceEmail");
const importSourcePasswordInput = document.getElementById("importSourcePassword");
const importTransferError = document.getElementById("importTransferError");
const importTransferConfirmBtn = document.getElementById("importTransferConfirmBtn");
const importTransferCancelBtn = document.getElementById("importTransferCancelBtn");
const exportDataBtn = document.getElementById("exportDataBtn");
const addFriendModal = document.getElementById("addFriendModal");
const addFriendEmailInput = document.getElementById("addFriendEmail");
const addFriendError = document.getElementById("addFriendError");
const addFriendConfirmBtn = document.getElementById("addFriendConfirmBtn");
const addFriendCancelBtn = document.getElementById("addFriendCancelBtn");
const addFriendsBtn = document.getElementById("addFriendsBtn");
const reverseFriendRequestModal = document.getElementById("reverseFriendRequestModal");
const reverseFriendRequestPreview = document.getElementById("reverseFriendRequestPreview");
const friendRequestsList = document.getElementById("friendRequestsList");
const sentRequestsList = document.getElementById("sentRequestsList");
const currentFriendsList = document.getElementById("currentFriendsList");
const keyboardShortcutsBox = document.getElementById("keyboardShortcutsBox");
const keyboardShortcutsSubtitle = document.getElementById("keyboardShortcutsSubtitle");
const keyboardShortcutsList = document.getElementById("keyboardShortcutsList");
const keyboardShortcutsToggleBtn = document.getElementById("keyboardShortcutsToggleBtn");
const friendsInsightsList = document.getElementById("friendsInsightsList");
if (aboutAppVersion) aboutAppVersion.innerText = APP_VERSION;
const welcomeGuideModal = document.getElementById("welcomeGuideModal");
const tosModal = document.getElementById("tosModal");
const tosAgreeBtn = document.getElementById("tosAgreeBtn");
const tosError = document.getElementById("tosError");
const guideStepCounter = document.getElementById("guideStepCounter");
const guideStepTitle = document.getElementById("guideStepTitle");
const guideStepText = document.getElementById("guideStepText");
const guideStepTip = document.getElementById("guideStepTip");
const guideDots = document.getElementById("guideDots");
const guidePrevBtn = document.getElementById("guidePrevBtn");
const guideNextBtn = document.getElementById("guideNextBtn");
const crashAlertBanner = document.getElementById("crashAlertBanner");
const crashBannerText = document.getElementById("crashBannerText");
const crashAlertDismissBtn = document.getElementById("crashAlertDismissBtn");
const crashRiskValue = document.getElementById("crashRiskValue");
const crashRiskFill = document.getElementById("crashRiskFill");
const crashRiskLevel = document.getElementById("crashRiskLevel");
const crashRiskReason = document.getElementById("crashRiskReason");
const crashRescuePlan = document.getElementById("crashRescuePlan");
const weeklyRange = document.getElementById("weeklyRange");
const weeklyImproved = document.getElementById("weeklyImproved");
const weeklyDropped = document.getElementById("weeklyDropped");
const weeklyActions = document.getElementById("weeklyActions");
const weeklyPatternInsights = document.getElementById("weeklyPatternInsights");
const weeklyGoalScorecard = document.getElementById("weeklyGoalScorecard");
const progressMilestones = document.getElementById("progressMilestones");
const weeklyTargetsDisplay = document.getElementById("weeklyTargetsDisplay");
const questXpEl = document.getElementById("questXp");
const questStreakEl = document.getElementById("questStreak");
const questWeekStreakLabels = document.getElementById("questWeekStreakLabels");
const questWeekStreakCircles = document.getElementById("questWeekStreakCircles");
const questProgressFill = document.getElementById("questProgressFill");
const questShieldEl = document.getElementById("questShield");
const questProgressHintEl = document.getElementById("questProgressHint");
const questListEl = document.getElementById("questList");
const burnoutRiskEl = document.getElementById("burnoutRisk");
const burnoutWindowEl = document.getElementById("burnoutWindow");
const burnoutReasonEl = document.getElementById("burnoutReason");
const burnoutScheduleEl = document.getElementById("burnoutSchedule");
const accountName = document.getElementById("accountName");
const accountDisplayName = document.getElementById("accountDisplayName");
const accountDisplayNameError = document.getElementById("accountDisplayNameError");
const editDisplayNameBtn = document.getElementById("editDisplayNameBtn");
const accountEmail = document.getElementById("accountEmail");
const accountVerifyStatus = document.getElementById("accountVerifyStatus");
const accountUid = document.getElementById("accountUid");
const clearDataBtn = document.getElementById("clearDataBtn");
const signOutBtn = document.getElementById("signOutBtn");
const chat = document.getElementById("chat");
const aiInput = document.getElementById("aiInput");
const aiTalkBtn = document.getElementById("aiTalkBtn");
const aiClearBtn = document.getElementById("aiClearBtn");
const aiLimitError = document.getElementById("aiLimitError");
const reminderText = document.getElementById("reminderText");
const reminderMinutes = document.getElementById("reminderMinutes");
const reminderUnit = document.getElementById("reminderUnit");
const reminderSetBtn = document.getElementById("reminderSetBtn");
const reminderLimitError = document.getElementById("reminderLimitError");
const reminders = document.getElementById("reminders");
const task = document.getElementById("task");
const taskAddBtn = document.getElementById("taskAddBtn");
const taskLimitError = document.getElementById("taskLimitError");
const taskFriendInsight = document.getElementById("taskFriendInsight");
const taskList = document.getElementById("taskList");
const gCost = document.getElementById("gCost");
const gMonths = document.getElementById("gMonths");
const buffer = document.getElementById("buffer");
const financeResult = document.getElementById("financeResult");
const mood = document.getElementById("mood");
const moodSaveBtn = document.getElementById("moodSaveBtn");
const moodLimitError = document.getElementById("moodLimitError");
const moodResetCountdown = document.getElementById("moodResetCountdown");
const moodFriendInsight = document.getElementById("moodFriendInsight");
const moodLogs = document.getElementById("moodLogs");
const waterGoalInput = document.getElementById("waterGoalInput");
const waterInput = document.getElementById("waterInput");
const waterTrackBtn = document.getElementById("waterTrackBtn");
const waterLimitError = document.getElementById("waterLimitError");
const waterFriendInsight = document.getElementById("waterFriendInsight");
const waterProgress = document.getElementById("waterProgress");
const waterClearBtn = document.getElementById("waterClearBtn");
const waterGoalResetCountdown = document.getElementById("waterGoalResetCountdown");
const sleepInput = document.getElementById("sleepInput");
const sleepSaveBtn = document.getElementById("sleepSaveBtn");
const bedtimeTimeInput = document.getElementById("bedtimeTimeInput");
const bedtimeSetBtn = document.getElementById("bedtimeSetBtn");
const bedtimeInputError = document.getElementById("bedtimeInputError");
const sleepResetCountdown = document.getElementById("sleepResetCountdown");
const sleepLimitError = document.getElementById("sleepLimitError");
const sleepFriendInsight = document.getElementById("sleepFriendInsight");
const sleepResult = document.getElementById("sleepResult");
const bedtimeReminderModal = document.getElementById("bedtimeReminderModal");
const bedtimeReminderPreview = document.getElementById("bedtimeReminderPreview");
const wellnessMusicFrame = document.getElementById("wellnessMusicFrame");
const futureTask = document.getElementById("futureTask");
const timeMirror = document.getElementById("timeMirror");
const timeMirrorClearBtn = document.getElementById("timeMirrorClearBtn");
const timeMirrorCheckBtn = document.getElementById("timeMirrorCheckBtn");
const quoteDisplay = document.getElementById("quoteDisplay");
const gratitudeInput = document.getElementById("gratitudeInput");
const gratitudeSaveBtn = document.getElementById("gratitudeSaveBtn");
const gratitudeResetCountdown = document.getElementById("gratitudeResetCountdown");
const gratitudeLimitError = document.getElementById("gratitudeLimitError");
const gratitudeLogs = document.getElementById("gratitudeLogs");
const gratitudeFriendInsight = document.getElementById("gratitudeFriendInsight");
const dailyChallengeElement = document.getElementById("dailyChallenge");
const challengeResultElement = document.getElementById("challengeResult");
const challengeCompleteBtn = document.getElementById("challengeCompleteBtn");
const dailyChallengeResetCountdown = document.getElementById("dailyChallengeResetCountdown");
const dailyChallengeFriendInsight = document.getElementById("dailyChallengeFriendInsight");
const wellnessScoreEl = document.getElementById("wellnessScore");
const wellnessStatusEl = document.getElementById("wellnessStatus");
const wellnessScoreResetCountdown = document.getElementById("wellnessScoreResetCountdown");
const wellnessReassuranceEl = document.getElementById("wellnessReassurance");
const wellnessDoNowEl = document.getElementById("wellnessDoNow");
const wellnessActionsEl = document.getElementById("wellnessActions");
const wellnessFriendInsight = document.getElementById("wellnessFriendInsight");
const insightsCard = document.getElementById("insightsCard");
const insightTaskTopLabel = document.getElementById("insightTaskTopLabel");
const insightTaskTopBar = document.getElementById("insightTaskTopBar");
const insightMetricTitle = document.getElementById("insightMetricTitle");
const insightMetricLabel = document.getElementById("insightMetricLabel");
const insightWeeklyResetCountdown = document.getElementById("insightWeeklyResetCountdown");
const insightLineGraph = document.getElementById("insightLineGraph");
const insightAxisLayer = document.getElementById("insightAxisLayer");
const insightBarLayer = document.getElementById("insightBarLayer");
const insightBarLabelLayer = document.getElementById("insightBarLabelLayer");
const insightGraphTrack = document.getElementById("insightGraphTrack");
const insightGraphScroll = document.getElementById("insightGraphScroll");
const uxToast = document.getElementById("uxToast");
const uxToastText = document.getElementById("uxToastText");
const uxToastAction = document.getElementById("uxToastAction");
const startupDailyPlanList = document.getElementById("startupDailyPlanList");
const startupPlanMeta = document.getElementById("startupPlanMeta");
const startupRefreshPlanBtn = document.getElementById("startupRefreshPlanBtn");
const startupWeeklyReportText = document.getElementById("startupWeeklyReportText");
const startupGenerateReportBtn = document.getElementById("startupGenerateReportBtn");
const startupBehaviorMemory = document.getElementById("startupBehaviorMemory");
const startupPlanResetCountdown = document.getElementById("startupPlanResetCountdown");
const startupReportResetCountdown = document.getElementById("startupReportResetCountdown");

// ---------- SPLASH + AUTH CHECK ----------
document.body.style.overflow = "hidden";
if ("scrollRestoration" in history) history.scrollRestoration = "manual";
let splashRemoved = false;
let appBackGuardInitialized = false;

function hasAppBackGuardState() {
  return !!(history?.state && history.state.__novaBackGuard === true);
}

function ensureAppBackGuardState(reason = "guard", forcePush = false) {
  try {
    if (!forcePush && hasAppBackGuardState()) return;
    history.pushState({
      ...(history.state && typeof history.state === "object" ? history.state : {}),
      __novaBackGuard: true,
      reason,
      ts: Date.now()
    }, "", location.href);
  } catch (_) {}
}

function closeTopLayerForSystemBack() {
  if (isEditableElementActive()) {
    const active = document.activeElement;
    if (active && typeof active.blur === "function") active.blur();
    return true;
  }

  if (welcomeGuideModal && welcomeGuideModal.style.display === "flex") {
    closeWelcomeGuide();
    return true;
  }

  if (reverseFriendRequestModal && reverseFriendRequestModal.style.display === "flex") {
    closeReverseFriendRequestModal(null, true, "dismiss");
    return true;
  }

  if (addFriendModal && addFriendModal.style.display === "flex") {
    closeAddFriendModal(null, true);
    return true;
  }

  if (importTransferModal && importTransferModal.style.display === "flex") {
    closeImportTransferModal(null, true);
    return true;
  }

  if (bedtimeReminderModal && bedtimeReminderModal.style.display === "flex") {
    closeBedtimeReminderModal(null, true);
    return true;
  }

  if (googleIdentityModal && googleIdentityModal.style.display === "flex") {
    closeGoogleIdentitySetupModal();
    return true;
  }

  if (reportRedirectConfirmModal && reportRedirectConfirmModal.style.display === "flex") {
    closeReportRedirectConfirm(null, true);
    return true;
  }

  if (tosModal && tosModal.style.display === "flex") {
    return true;
  }

  if (accountPanel && accountPanel.style.display === "block") {
    closeAccountPanel();
    return true;
  }

  if (signInModal && signInModal.style.display === "flex" && authMode === "signup") {
    toggleAuth();
    return true;
  }

  return false;
}

function initializeUniversalBackHandling() {
  if (appBackGuardInitialized) return;
  appBackGuardInitialized = true;

  ensureAppBackGuardState("init");

  window.addEventListener("popstate", () => {
    const consumed = closeTopLayerForSystemBack();
    if (consumed) ensureAppBackGuardState("consumed");
  });

  document.addEventListener("focusin", () => {
    if (!isEditableElementActive()) return;
    ensureAppBackGuardState("input-focus");
  });
}

function hideSplash() {
  if (splashRemoved || !splash) return;
  splash.classList.add("hide");
  setTimeout(() => {
    if (!splashRemoved) {
      splash.remove();
      splashRemoved = true;
      document.body.style.overflow = "auto";
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    }
  }, 1000);
}

function updateAccountButtonScrollState() {
  if (!accountBtn) return;
  const isScrolled = window.scrollY > 18;
  accountBtn.classList.toggle("account-btn-scrolled", isScrolled);
}

window.addEventListener("scroll", updateAccountButtonScrollState, { passive: true });
window.addEventListener("resize", updateAccountButtonScrollState);
updateAccountButtonScrollState();

function toggleAccountPanel() {
  if (!accountPanel || !accountOverlay) return;
  const isOpen = accountPanel.style.display === "block";
  accountPanel.style.display = isOpen ? "none" : "block";
  accountOverlay.style.display = isOpen ? "none" : "block";
  if (!isOpen) ensureAppBackGuardState("account-panel", true);
  if (!isOpen) {
  }
  if (isOpen) {
    accountPanel.scrollTop = 0;
    return;
  }

  accountPanel.scrollTop = 0;
  if (!isOpen) {
    setAccountTab("general");
    const user = auth.currentUser;
    if (user?.uid) {
      loadFriendRequests(user.uid);
      loadSentFriendRequests(user.uid);
      loadFriendsInsights(user.uid);
    }
  }
}

function closeAccountPanel() {
  if (!accountPanel || !accountOverlay) return;
  accountPanel.scrollTop = 0;
  accountPanel.style.display = "none";
  accountOverlay.style.display = "none";
}

function setAccountTab(tabKey = "general") {
  const safeTab = String(tabKey || "general").trim().toLowerCase();
  accountTabButtons.forEach((buttonEl) => {
    const buttonTab = String(buttonEl?.dataset?.accountTab || "").trim().toLowerCase();
    buttonEl.classList.toggle("active", buttonTab === safeTab);
  });
  accountTabPanels.forEach((panelEl) => {
    const panelTab = String(panelEl?.dataset?.accountPanel || "").trim().toLowerCase();
    panelEl.classList.toggle("active", panelTab === safeTab);
  });

  if (safeTab === "friends") {
    const user = auth.currentUser;
    if (user?.uid) loadFriendRequests(user.uid);
  }
}

if (accountTabButtons.length) {
  accountTabButtons.forEach((buttonEl) => {
    buttonEl.addEventListener("click", () => {
      setAccountTab(buttonEl?.dataset?.accountTab || "general");
    });
  });
}

function setAccountDisplayNameError(message = "") {
  if (!accountDisplayNameError) return;
  const text = String(message || "").trim();
  accountDisplayNameError.innerText = text;
  accountDisplayNameError.style.display = text ? "block" : "none";
}

function updateAccountPanel(user) {
  if (!user) {
    if (accountName) accountName.innerText = "-";
    if (accountDisplayName) accountDisplayName.innerText = "-";
    setAccountDisplayNameError("");
    if (accountEmail) accountEmail.innerText = "-";
    if (accountVerifyStatus) accountVerifyStatus.innerText = "-";
    if (accountUid) accountUid.innerText = "-";
    if (clearDataBtn) {
      clearDataBtn.disabled = true;
      clearDataBtn.title = "No data to clear";
    }
    applyAccountPasswordResetCooldownUI(0);
    return;
  }

  const providerIds = Array.isArray(user.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  const isGoogleAccount = providerIds.includes("google.com");
  const fallbackName = (isGoogleAccount
    ? (buildUsernameSeedFromDisplayName(user.displayName) || "user")
    : ((user.email || "").split("@")[0] || "User"));
  const rawDisplayName = String(user.displayName || "").trim();
  const rawDisplayValidation = validateSignupDisplayName(rawDisplayName);
  if (accountName) accountName.innerText = fallbackName;
  if (accountDisplayName) accountDisplayName.innerText = normalizeDisplayNameValue(rawDisplayName) || fallbackName;
  if (accountEmail) accountEmail.innerText = user.email || "Not available";
  const isVerifiedForDisplay = !!user.emailVerified || isGoogleAccount;
  if (accountVerifyStatus) accountVerifyStatus.innerText = isVerifiedForDisplay ? "Verified ✅" : "Not verified ⚠️";
  if (accountUid) accountUid.innerText = user.uid || "Not available";
  updateAccountPasswordResetCooldownTicker();
  if (rawDisplayName && !rawDisplayValidation.ok) {
    setAccountDisplayNameError("Legacy display name contains unsupported symbols. Edit Display Name to fix it.");
  } else {
    setAccountDisplayNameError("");
  }

  void syncAccountIdentityFromProfile(user);
}

async function syncAccountIdentityFromProfile(user) {
  const activeUid = String(user?.uid || "").trim();
  if (!activeUid) return;

  const safeEmail = String(user?.email || "").trim().toLowerCase();
  const providerIds = Array.isArray(user?.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  const isGoogleAccount = providerIds.includes("google.com");
  const emailLocal = safeEmail.split("@")[0] || "User";
  const emailLocalIdentity = getEmailLocalIdentity(safeEmail);
  const googleSeed = buildUsernameSeedFromDisplayName(user?.displayName) || "user";
  const normalizeResolvedUsername = (value) => {
    const normalized = normalizeUsernameForLookup(value);
    if (!normalized) return "";
    if (isGoogleAccount && emailLocalIdentity && normalized === emailLocalIdentity) return "";
    return normalized;
  };
  let usernameValue = normalizeResolvedUsername(accountName?.innerText || "")
    || (isGoogleAccount ? googleSeed : normalizeUsernameForLookup(emailLocal))
    || "user";
  let displayNameValue = normalizeDisplayNameValue(user?.displayName) || usernameValue;
  let hasLegacyInvalidDisplayName = false;

  try {
    const profileRes = await fsGetDoc(doc(db, "users", activeUid, "settings", "profile"), 'profile');
    if (profileRes.exists) {
      const profileData = profileRes.data || {};
      const profileDisplayRaw = String(profileData.displayName || "").trim();
      if (profileDisplayRaw && !validateSignupDisplayName(profileDisplayRaw).ok) {
        hasLegacyInvalidDisplayName = true;
      }
      usernameValue = normalizeResolvedUsername(profileData.username || profileData.name || "")
        || usernameValue;
      displayNameValue = normalizeDisplayNameValue(profileData.displayName)
        || normalizeDisplayNameValue(user?.displayName)
        || usernameValue;
    }

    // Canonical source of truth for username is usernameDirectory doc id.
    const usernameByUidSnap = await fsGetDocs(query(
      collection(db, "usernameDirectory"),
      where("uid", "==", activeUid)
    ));
    const canonicalDoc = Array.isArray(usernameByUidSnap?.docs) ? usernameByUidSnap.docs.find((docSnap) => {
      const candidate = normalizeResolvedUsername(docSnap?.id || "");
      return !!candidate;
    }) : null || (usernameByUidSnap?.docs && usernameByUidSnap.docs[0]);
    const canonicalUsername = normalizeResolvedUsername(canonicalDoc?.id || "");
    if (canonicalUsername) {
      usernameValue = canonicalUsername;
    }
  } catch (_) {
    // Non-blocking: keep fallback values.
  }

  const stillActive = String(auth.currentUser?.uid || "").trim() === activeUid;
  if (!stillActive) return;

  if (accountName) accountName.innerText = usernameValue;
  if (accountDisplayName) accountDisplayName.innerText = displayNameValue;
  if (hasLegacyInvalidDisplayName) {
    setAccountDisplayNameError("Legacy display name contains unsupported symbols. Edit Display Name to fix it.");
  }
}

document.addEventListener("click", (event) => {
  if (!accountPanel || !accountBtn) return;
  const clickedInside = accountPanel.contains(event.target) || accountBtn.contains(event.target);
  if (!clickedInside) closeAccountPanel();
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  closeAccountPanel();
  closeAddFriendModal();
  if (welcomeGuideModal && welcomeGuideModal.style.display === "flex") {
    closeWelcomeGuide();
  }
});

if (aiInput) {
  aiInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void aiChat();
  });
}

if (gratitudeInput) {
  gratitudeInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void saveGratitude();
  });
}

if (waterGoalInput) {
  waterGoalInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void setWaterGoal();
  });
}

if (waterInput) {
  waterInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void saveWater();
  });
}

if (task) {
  task.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void addTask();
  });
}

if (sleepInput) {
  sleepInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void saveSleep();
  });
}

if (addFriendEmailInput) {
  addFriendEmailInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    void submitAddFriendRequest();
  });
}

function getReminderAmountInputValue() {
  if (!reminderMinutes) return 0;
  const rawValue = String(reminderMinutes.value || "").trim();
  if (!rawValue) return 0;
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) return 0;
  return parsed;
}

function setReminderInputError(message = "") {
  if (!reminderLimitError) return;
  if (reminderLimitError.dataset.liveCountdown === "1") return;
  const text = String(message || "").trim();
  reminderLimitError.innerText = text;
  reminderLimitError.classList.toggle("show", !!text);
  if (text) reminderLimitError.dataset.reminderInputError = "1";
  else delete reminderLimitError.dataset.reminderInputError;
}

function clearReminderInputError() {
  if (!reminderLimitError) return;
  if (reminderLimitError.dataset.liveCountdown === "1") return;
  if (reminderLimitError.dataset.reminderInputError !== "1") return;
  reminderLimitError.innerText = "";
  reminderLimitError.classList.remove("show");
  delete reminderLimitError.dataset.reminderInputError;
}

if (reminderMinutes) {
  reminderMinutes.addEventListener("input", clearReminderInputError);
}
if (reminderText) {
  reminderText.addEventListener("input", clearReminderInputError);
}
if (reminderUnit) {
  reminderUnit.addEventListener("change", clearReminderInputError);
}

if (bedtimeTimeInput) {
  bedtimeTimeInput.addEventListener("input", () => {
    const normalized = normalizeBedtimeTimeText(bedtimeTimeInput.value || "");
    if (bedtimeTimeInput.value !== normalized) {
      bedtimeTimeInput.value = normalized;
    }
    bedtimeInputTouchedSinceSync = true;
    if (bedtimeInputError) {
      bedtimeInputError.innerText = "";
      bedtimeInputError.classList.remove("show");
    }
    updateBedtimeSetButtonState();
  });

  bedtimeTimeInput.addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const parsed = parseBedtimeInput(bedtimeTimeInput.value || "");
    if (!parsed.ok) {
      bedtimeInputTouchedSinceSync = true;
      setBedtimeInputError(parsed.message);
      updateBedtimeSetButtonState();
      return;
    }
    if (bedtimeSetBtn?.disabled) return;
    await setBedtimeReminder();
  });
}

async function clearAllAccountData() {
  const user = auth.currentUser;
  if (!user) {
    alert("Please sign in first.");
    return;
  }

  const warningOne = confirm("⚠️ Warning: Clear All Data also removes your friends, incoming/outgoing friend requests, and related social data. It will permanently delete your NovaFix app data (tasks, mood, water, sleep, gratitude, reminders, AI chats, and insights). All STREAKS will also be cleared. Daily limits for AI, mood, sleep, water, tasks, reminders, and gratitude will NOT be reset. Continue?");
  if (!warningOne) return;

  const warningTwo = confirm("Final warning: this cannot be undone. Your account will stay signed in, but all app data and social links (friends, sent requests, pending requests) will be erased. Proceed?");
  if (!warningTwo) return;

  const pendingToastId = showPendingToast("Hang on, clearing data...");
  try {
    const previousChallengeText = String(currentChallengeText || "");
    await syncServerClock(user.uid);
    clearCrashAlertDismissal(user.uid);
    clearAllReminderTimers();

    const aiUsageRef = doc(db, "users", user.uid, "settings", "aiUsage");
    const dailyUsageRef = doc(db, "users", user.uid, "settings", "dailyUsage");
    let preservedAiUsage = null;
    let preservedDailyUsage = null;
    try {
      const aiUsageRes = await fsGetDoc(aiUsageRef, 'aiUsage');
      preservedAiUsage = aiUsageRes.exists ? aiUsageRes.data : null;
    } catch (err) {
      structuredLog('warn', 'clearAll.aiUsage.read', err?.message || String(err), { uid: user?.uid });
      preservedAiUsage = null;
    }
    try {
      const dailyUsageRes = await fsGetDoc(dailyUsageRef, 'dailyUsage');
      preservedDailyUsage = dailyUsageRes.exists ? dailyUsageRes.data : null;
    } catch (err) {
      structuredLog('warn', 'clearAll.dailyUsage.read', err?.message || String(err), { uid: user?.uid });
      preservedDailyUsage = null;
    }

    const todayKey = getTodayKey();
    let remindersTodayCount = 0;
    try {
      const remindersSnap = await fsGetDocs(collection(db, "users", user.uid, "reminders"));
      remindersTodayCount = countTodayRemindersFromDocs((remindersSnap?.docs||[]));
    } catch (err) {
      structuredLog('warn', 'clearAll.reminders.read', err?.message || String(err), { uid: user?.uid });
      remindersTodayCount = 0;
    }
    const moodTodayCount = countTodayFromDates(moodDates);
    const taskTodayCount = taskEntries.reduce((total, entry) => (dateToKey(entry.time) === todayKey ? total + 1 : total), 0);
    const sleepTodayCount = countTodayFromDates(sleepDates);
    const waterTodayCount = countTodayFromDates(waterDates);
    const gratitudeTodayCount = gratitudeEntries.reduce((total, entry) => (dateToKey(entry.time) === todayKey ? total + 1 : total), 0);

    let friendIds = [];
    const relationshipFriendIds = new Set();
    const friendEmailByUid = new Map();
    let sentRequestTargetIds = [];
    let incomingRequestSourceIds = [];
    let queueRequestDocIds = [];
    const userEmail = String(user.email || "").trim().toLowerCase();
    try {
      const friendsSnap = await fsGetDocs(collection(db, "users", user.uid, "friends"), 'friend');
      friendsSnap.docs.forEach((docSnap) => {
        const data = docSnap.data() || {};
        const friendUid = String(data.friendUid || docSnap.id || "").trim();
        const friendEmail = String(data.friendEmail || "").trim().toLowerCase();
        if (!friendUid) return;
        relationshipFriendIds.add(friendUid);
        if (friendEmail) friendEmailByUid.set(friendUid, friendEmail);
      });
      friendIds = [...relationshipFriendIds];
    } catch (_) {
      friendIds = [];
    }

    try {
      const sentSnap = await fsGetDocs(collection(db, "users", user.uid, "friendRequestsSent"));
      sentRequestTargetIds = (sentSnap?.docs || [])
        .map((docSnap) => {
          const data = docSnap.data() || {};
          const toUid = String(data.toUid || docSnap.id || "").trim();
          const toEmail = String(data.toEmail || "").trim().toLowerCase();
          if (toUid) relationshipFriendIds.add(toUid);
          if (toUid && toEmail) friendEmailByUid.set(toUid, toEmail);
          return toUid;
        })
        .filter(Boolean);
    } catch (err) {
      structuredLog('warn', 'friends.sent.load', err?.message || String(err), { uid: user?.uid });
      sentRequestTargetIds = [];
    }

    try {
      const incomingSnap = await fsGetDocs(collection(db, "users", user.uid, "friendRequests"));
      incomingRequestSourceIds = (incomingSnap?.docs || [])
        .map((docSnap) => {
          const data = docSnap.data() || {};
          const fromUid = String(data.fromUid || docSnap.id || "").trim();
          const fromEmail = String(data.fromEmail || "").trim().toLowerCase();
          if (fromUid) relationshipFriendIds.add(fromUid);
          if (fromUid && fromEmail) friendEmailByUid.set(fromUid, fromEmail);
          return fromUid;
        })
        .filter(Boolean);
    } catch (err) {
      structuredLog('warn', 'friends.incoming.load', err?.message || String(err), { uid: user?.uid });
      incomingRequestSourceIds = [];
    }

    try {
      const queueQueries = [
        fsGetDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", user.uid))),
        fsGetDocs(query(collection(db, "friendRequestsQueue"), where("toUid", "==", user.uid)))
      ];
      if (userEmail) {
        queueQueries.push(fsGetDocs(query(collection(db, "friendRequestsQueue"), where("toEmail", "==", userEmail))));
      }
      const queueSnapshots = await Promise.all(queueQueries);
      queueSnapshots.forEach((snap) => {
        (snap?.docs || []).forEach((docSnap) => {
          const data = docSnap.data() || {};
          const fromUid = String(data.fromUid || "").trim();
          const toUid = String(data.toUid || "").trim();
          const fromEmail = String(data.fromEmail || "").trim().toLowerCase();
          const toEmail = String(data.toEmail || "").trim().toLowerCase();
          const friendUid = fromUid === user.uid ? toUid : fromUid;
          const friendEmail = fromUid === user.uid ? toEmail : fromEmail;
          if (friendUid) relationshipFriendIds.add(friendUid);
          if (friendUid && friendEmail) friendEmailByUid.set(friendUid, friendEmail);
        });
      });
      queueRequestDocIds = [...new Set([
        ...queueSnapshots.flatMap((snap) => snap.docs.map((docSnap) => String(docSnap.id || "")))
      ].filter(Boolean))];
    } catch (_) {
      queueRequestDocIds = [];
    }
    friendIds = [...relationshipFriendIds].filter((friendUid) => friendUid && friendUid !== user.uid);

    if (friendIds.length) {
      await Promise.allSettled(friendIds.map((friendUid) => {
        return markFriendshipUnfriendedForAccountClear(user, friendUid, {
          friendEmail: friendEmailByUid.get(friendUid) || ""
        });
      }));
    }

    const targetCollections = [
      "moods",
      "tasks",
      "waterIntake",
      "sleepLogs",
      "musicSessions",
      "gratitudeLogs",
      "aiChats",
      "reminders",
      "challengeHistory",
      "rescueEvents",
      "friends",
      "friendRequests",
      "friendRequestsSent",
      "friendRequestDecisions"
    ];

    await Promise.all(targetCollections.map((name) => clearUserCollection(user.uid, name)));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "water")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/water` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "sleep")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/sleep` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "dailyChallenge")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/dailyChallenge` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "weeklyTargets")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/weeklyTargets` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "habitQuest")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/habitQuest` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "settings", "startupPack")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/settings/startupPack` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "insights", "current")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/insights/current` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "insights", "barGraphs")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/insights/barGraphs` }));
    await fsDeleteDoc(doc(db, "users", user.uid, "social", "profile")).catch((err) => structuredLog('warn', 'fs.delete.silent', err?.message || String(err), { path: `users/${user?.uid}/social/profile` }));
    persistedBarGraphs = null;
    persistedBehaviorPatterns = null;

    if (friendIds.length) {
      await Promise.all(friendIds.map((friendUid) => {
        return fsDeleteDoc(doc(db, "users", friendUid, "friends", user.uid)).catch((err) => structuredLog('warn', 'clearAll.delete.friend', err?.message || String(err)));
      }));
    }

    if (sentRequestTargetIds.length) {
      await Promise.all(sentRequestTargetIds.map((targetUid) => {
        return fsDeleteDoc(doc(db, "users", targetUid, "friendRequests", user.uid)).catch((err) => structuredLog('warn', 'clearAll.delete.sent', err?.message || String(err)));
      }));
    }

    if (incomingRequestSourceIds.length) {
      await Promise.all(incomingRequestSourceIds.map((sourceUid) => {
        return fsDeleteDoc(doc(db, "users", sourceUid, "friendRequestsSent", user.uid)).catch((err) => structuredLog('warn', 'clearAll.delete.incoming', err?.message || String(err)));
      }));
    }

    if (queueRequestDocIds.length) {
      await Promise.all(queueRequestDocIds.map((requestId) => {
        return fsDeleteDoc(doc(db, "friendRequestsQueue", requestId)).catch((err) => structuredLog('warn', 'clearAll.delete.queue', err?.message || String(err)));
      }));
    }

    if (preservedAiUsage && Number.isFinite(Number(preservedAiUsage.count))) {
      await safeSetDoc(aiUsageRef, {
        dateKeyLocal: preservedAiUsage.dateKeyLocal || preservedAiUsage.dateKeyGMT || getTodayKeyGMT(),
        dateKeyGMT: preservedAiUsage.dateKeyGMT || preservedAiUsage.dateKeyLocal || getTodayKeyGMT(),
        count: Number(preservedAiUsage.count) || 0,
        updatedAt: serverTimestamp()
      }, 'aiUsage', { merge: true });
    }
    const preservedDateKey = preservedDailyUsage?.dateKey || "";
    const preservedMoodCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.moodCount) || 0) : 0;
    const preservedTaskCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.taskCount) || 0) : 0;
    const preservedSleepCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.sleepCount) || 0) : 0;
    const preservedWaterCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.waterCount) || 0) : 0;
    const preservedReminderCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.reminderCount) || 0) : 0;
    const preservedGratitudeCount = preservedDateKey === todayKey ? (Number(preservedDailyUsage?.gratitudeCount) || 0) : 0;

    await safeSetDoc(dailyUsageRef, {
      dateKey: todayKey,
      moodCount: Math.max(preservedMoodCount, moodTodayCount),
      taskCount: Math.max(preservedTaskCount, taskTodayCount),
      sleepCount: Math.max(preservedSleepCount, sleepTodayCount),
      waterCount: Math.max(preservedWaterCount, waterTodayCount),
      reminderCount: Math.max(preservedReminderCount, remindersTodayCount),
      gratitudeCount: Math.max(preservedGratitudeCount, gratitudeTodayCount),
      updatedAt: serverTimestamp()
    }, 'dailyUsage', { merge: true });

    moodLogs.innerHTML = "";
    chat.innerHTML = "";
    taskList.innerHTML = "";
    reminders.innerHTML = "";
    gratitudeLogs.innerHTML = "";
    if (friendRequestsList) friendRequestsList.innerHTML = "";
    if (sentRequestsList) sentRequestsList.innerHTML = "";
    if (currentFriendsList) currentFriendsList.innerHTML = "";
    if (friendsInsightsList) friendsInsightsList.innerHTML = "";
    friendInsightProfiles = [];
    renderFriendMetricCardInsights();
    waterProgress.innerText = "";
    sleepResult.innerText = "";
    if (timeMirror) timeMirror.innerHTML = "";
    setTimeMirrorClearButtonState(false);
    bedtimeSettings = { timeText: "", enabled: false };
    bedtimeReminderLastTriggeredKey = "";
    bedtimeInputTouchedSinceSync = false;
    bedtimeAllowUnchangedResubmit = false;
    if (bedtimeReminderTimeoutId) {
      clearTimeout(bedtimeReminderTimeoutId);
      bedtimeReminderTimeoutId = null;
    }
    if (bedtimeTimeInput) bedtimeTimeInput.value = "";
    if (bedtimeInputError) {
      bedtimeInputError.innerText = "";
      bedtimeInputError.classList.remove("show");
    }
    if (bedtimeReminderModal) bedtimeReminderModal.style.display = "none";
    challengeResultElement.innerText = "";
    waterGoalInput.value = "";
    waterInput.value = "";
    sleepInput.value = "";
    task.value = "";
    reminderText.value = "";
    reminderMinutes.value = "";
    gratitudeInput.value = "";

    moodHistory.length = 0;
    waterHistory.length = 0;
    sleepHistory.length = 0;
    moodDates.length = 0;
    waterDates.length = 0;
    sleepDates.length = 0;
    taskEntries.length = 0;
    gratitudeEntries.length = 0;
    challengeDates.length = 0;
    aiRecentPrompts.length = 0;
    aiRecentResponseSignatures.length = 0;
    aiVariantHistory.clear();
    habitQuests.length = 0;
    burnoutRecoveryPlan.length = 0;
    wellnessActionBoost = 0;
    crashRiskActionRelief = 0;
    dailyChallengeCompleted = false;
    currentChallengeText = "";
    currentChallengeDateKey = "";
    questDateKey = "";
    questXp = 0;
    questShieldAvailable = false;
    waterGoal = 0;

    await Promise.all([
      assignFreshDailyChallenge(user.uid, previousChallengeText),
      loadDailyUsage(user.uid),
      loadMoods(user.uid),
      loadAiUsage(user.uid),
      loadAiChats(user.uid),
      loadTasks(user.uid),
      loadReminders(user.uid),
      loadWaterData(user.uid),
      loadSleepData(user.uid),
      loadBedtimeSettings(user.uid),
      loadGratitude(user.uid),
      loadWeeklyTargets(user.uid),
      loadRescueEvents(user.uid),
      loadHabitQuest(user.uid),
      loadStartupUsageState(user.uid),
      loadStartupFeatureState(user.uid)
    ]);

    updateClearDataButtonState();
    updateCrashPreventionUI();

    closeAccountPanel();
    alert("✅ All account data cleared. You are still signed in.");
  } catch (err) {
    notifyFirestoreError(err);
  } finally {
    clearPendingToast(pendingToastId);
  }
}

const SPLASH_MIN_VISIBLE_MS = 2000;
const splashBootStartedAtMs = Date.now();

function getRemainingSplashDelayMs() {
  return Math.max(0, SPLASH_MIN_VISIBLE_MS - (Date.now() - splashBootStartedAtMs));
}

try {
  onAuthStateChanged(auth, (user) => {
    authStateChangeSequence += 1;
    const currentAuthSequence = authStateChangeSequence;
    if (authStateDelayTimer) {
      clearTimeout(authStateDelayTimer);
      authStateDelayTimer = null;
    }
    const splashDelayMs = getRemainingSplashDelayMs();
    authStateDelayTimer = setTimeout(async () => {
      authStateDelayTimer = null;
      if (currentAuthSequence !== authStateChangeSequence) return;
      hideSplash();
      if (user) {
        if (signupFlowInProgress) {
          return;
        }
        const hasGoogleProvider = isGoogleProviderUser(user);
        let skipEmailVerificationGate = hasGoogleProvider;
        if (!skipEmailVerificationGate && !user.emailVerified) {
          skipEmailVerificationGate = await isGoogleRegisteredEmail(user.email);
        }
        if (!user.emailVerified && !skipEmailVerificationGate) {
          await user.reload().catch((err) => structuredLog('warn', 'auth.reload.1', err?.message || String(err)));
          const suppressUnverifiedPrompt = Date.now() < Number(suppressUnverifiedSigninPromptUntilMs || 0);
          if (suppressUnverifiedPrompt) {
            return;
          }
          const verificationError = document.getElementById("signInError");
          if (verificationError) {
            verificationError.style.display = "block";
            verificationError.style.color = "#ff6b6b";
            verificationError.innerText = "Please verify your email before signing in.";
          }
          await signOut(auth);
          return;
        }

        const googleIdentityReady = await ensureGoogleIdentitySetupIfNeeded(user);
        if (!googleIdentityReady) {
          return;
        }
        if (currentAuthSequence !== authStateChangeSequence) return;

        await initializeAuthenticatedSession(user);
      } else {
        if (lastAuthenticatedUserId) {
          clearCrashAlertDismissal(lastAuthenticatedUserId);
          lastAuthenticatedUserId = "";
        }
        if (tosPendingUserId) {
          // During TOS-gate race conditions, keep auth modal hidden and preserve dashboard shell.
          if (signInModal) signInModal.style.display = "none";
          if (dashboard) {
            dashboard.style.display = "grid";
            dashboard.classList.add("preload-shell");
          }
          setPageTitle("dashboard");
          return;
        }
        // Only close TOS modal if it's not in a pending acceptance state
        if (!tosPendingUserId) {
          closeTosModal(true);
          resolveTosPendingWaiters(false);
          showTosError("");
        }
        stopSentRequestExpiryTicker();
        stopDailyChallengeWatcher();
        stopFriendInsightsWatcher();
        clearDailyChallengeResetSchedule();
        clearDailyQuestResetSchedule();
        clearDailySystemResetSchedule();
        clearWeeklyGraphResetSchedule();
        stopWeeklyGraphResetCountdown();
        stopStartupResetCountdown();
        startExportCooldown(0);
        startDisplayNameEditCooldown(0);
        startVerificationCooldown(0);
        startAccountPasswordResetCooldown(0);
        clearWaterGoalResetSchedule();
        clearSleepDailyResetSchedule();
        clearMoodDailyResetSchedule();
        clearBedtimeReminderSchedule();
        closeBedtimeReminderModal(null, true);
        bedtimeSettings = { timeText: "", enabled: false };
        bedtimeReminderLastTriggeredKey = "";
        bedtimeInputTouchedSinceSync = false;
        bedtimeAllowUnchangedResubmit = false;
        wellnessActionBoost = 0;
        crashRiskActionRelief = 0;
        if (pendingFriendProfileSyncTimer) {
          clearTimeout(pendingFriendProfileSyncTimer);
          pendingFriendProfileSyncTimer = null;
        }
        pendingFriendProfileSnapshot = null;
        closeAccountPanel();
        closeAddFriendModal(null, true);
        closeGoogleIdentitySetupModal();
        friendRequestLoginAlertShown = false;
        clearPendingRequestLoginAlertFlag();
        updateAccountPanel(null);
        signInModal.style.display = "flex";
        setPageTitle("signin");
        dashboard.style.display = "none";
        dashboard.classList.remove("preload-shell");
        accountBtn.style.display = "none";
        moodLogs.innerHTML = "";
        chat.innerHTML = "";
        setAiClearButtonState(false);
        taskList.innerHTML = "";
        reminders.innerHTML = "";
        gratitudeLogs.innerHTML = "";
        clearAllReminderTimers();
        waterProgress.innerText = "";
        sleepResult.innerText = "";
        if (timeMirror) timeMirror.innerHTML = "";
        setTimeMirrorClearButtonState(false);
        if (bedtimeTimeInput) bedtimeTimeInput.value = "";
        setBedtimeInputError("");
        wellnessScoreEl.innerText = "0/100";
        wellnessStatusEl.innerText = "Needs Focus";
        wellnessActionsEl.innerHTML = "<li>Log your first check-in for today.</li><li>Set your water target and drink one glass.</li><li>Add one gratitude note tonight.</li>";
        if (crashAlertBanner) crashAlertBanner.style.display = "none";
        if (crashRiskValue) crashRiskValue.innerText = "0/100";
        if (crashRiskFill) crashRiskFill.style.width = "0%";
        if (crashRiskLevel) crashRiskLevel.innerText = "Low Risk";
        if (crashRiskReason) crashRiskReason.innerText = "Log your first entries to generate risk analysis.";
        if (crashRescuePlan) crashRescuePlan.innerHTML = "";
        rescueEvents.length = 0;
        habitQuests.length = 0;
        burnoutRecoveryPlan.length = 0;
        questDateKey = "";
        questXp = 0;
        questShieldAvailable = false;
        questStreakCount = 0;
        questLastStreakDateKey = "";
        questWeekStartKey = "";
        weeklyQuestUsedIds = [];
        questCompletedDateKeys = [];
        weeklyTargets = { waterGoal: 0, sleepTarget: 8, taskTarget: 5 };
        startupFeatureState = getDefaultStartupFeatureState();
        startupCurrentPlan = [];
        startupWeeklyReportCache = "";
        startupPlanGeneratedOnce = false;
        startupReportGeneratedOnce = false;
        startupUsageState = getDefaultStartupUsageState();
        refreshStartupFeatures();
        if (weeklyRange) weeklyRange.innerText = "Last 7 days review";
        if (weeklyTargetsDisplay) weeklyTargetsDisplay.innerText = "Targets: Water -, Sleep -, Tasks -";
        if (weeklyImproved) weeklyImproved.innerHTML = "";
        if (weeklyDropped) weeklyDropped.innerHTML = "";
        if (weeklyActions) weeklyActions.innerHTML = "";
        if (weeklyPatternInsights) weeklyPatternInsights.innerHTML = "";
        if (weeklyGoalScorecard) weeklyGoalScorecard.innerHTML = "";
        if (progressMilestones) progressMilestones.innerHTML = "";
        if (questXpEl) questXpEl.innerText = "XP 0/100";
        if (questStreakEl) questStreakEl.innerText = "Streak 0 🔥";
        if (questProgressFill) questProgressFill.style.width = "0%";
        if (questShieldEl) questShieldEl.innerText = "Streak shield: Inactive";
        if (questListEl) questListEl.innerHTML = "";
        closeWelcomeGuide();
        welcomeGuideStepIndex = 0;
        welcomeGuideUserId = "";
        welcomeGuideCheckedThisSession = false;
        if (burnoutRiskEl) burnoutRiskEl.innerText = "0/100";
        if (burnoutWindowEl) burnoutWindowEl.innerText = "Low Risk • Stable window";
        if (burnoutReasonEl) burnoutReasonEl.innerText = "Forecast appears stable right now.";
        if (burnoutScheduleEl) burnoutScheduleEl.innerHTML = "";
        challengeResultElement.innerText = "";
        moodHistory.length = 0;
        waterHistory.length = 0;
        sleepHistory.length = 0;
        musicSessionDates.length = 0;
        moodDates.length = 0;
        waterDates.length = 0;
        sleepDates.length = 0;
        musicSessionDayKeys.clear();
        taskEntries.length = 0;
        gratitudeEntries.length = 0;
        challengeDates.length = 0;
        if (friendRequestsList) friendRequestsList.innerHTML = "";
        if (sentRequestsList) sentRequestsList.innerHTML = "";
        if (currentFriendsList) currentFriendsList.innerHTML = "";
        if (friendsInsightsList) friendsInsightsList.innerHTML = "";
        if (accountBtn) accountBtn.classList.remove("has-pending-request");
        seenFriendRequestKeys = new Set();
        acknowledgeFriendRequestsOnNextRender = false;
        seenFriendRequestKeysLoadedForUid = "";
        seenFriendRequestKeysLoadingForUid = "";
        seenFriendRequestKeysLoadPromise = null;
        friendInsightProfiles = [];
        renderFriendMetricCardInsights();
        dailyChallengeCompleted = false;
        currentChallengeDateKey = "";
        persistedBarGraphs = null;
        persistedBehaviorPatterns = null;
        waterGoal = 0;
        aiUsageDateKeyGMT = "";
        aiUsageCount = 0;
        aiUsageStateLoaded = false;
        aiAbuseStrikeCount = 0;
        aiAbuseCooldownUntilMs = 0;
        stopAiAbuseCooldownTicker();
        dailyUsageDateKey = "";
        moodDailyUsageCount = 0;
        taskDailyUsageCount = 0;
        sleepDailyUsageCount = 0;
        waterDailyUsageCount = 0;
        reminderDailyUsageCount = 0;
        gratitudeDailyUsageCount = 0;
        dailyUsageLoaded = false;
        waterGoalInput.value = "";
        resetAllLimitUIs();
        updateClearDataButtonState();
      }
    }, splashDelayMs);
  });
} catch (_) {
  const splashDelayMs = getRemainingSplashDelayMs();
  setTimeout(() => {
    hideSplash();
    signInModal.style.display = "flex";
    setPageTitle("signin");
    dashboard.style.display = "none";
    dashboard.classList.remove("preload-shell");
    accountBtn.style.display = "none";
    setAiClearButtonState(false);
    startExportCooldown(0);
    startDisplayNameEditCooldown(0);
    closeAccountPanel();
    updateAccountPanel(null);
  }, splashDelayMs);
}

setTimeout(hideSplash, 2000);
initializeUniversalBackHandling();

// ---------- SIGN-IN / SIGN-UP ----------
let authMode="signin";
let authModalErrorKind = "";
let signupFlowInProgress = false;
let suppressUnverifiedSigninPromptUntilMs = 0;
let usernameLiveCheckTimer = null;
let usernameLiveCheckSequence = 0;
let googleIdentitySetupInProgress = false;
let googleIdentitySetupUserId = "";
let googleIdentityPasswordOnlyMode = false;
let googleIdentityRequirePassword = false;
const GOOGLE_IDENTITY_STRICT_ENFORCED = false;
let googleIdentityUsernameLiveCheckTimer = null;
let googleIdentityUsernameLiveCheckSequence = 0;
let authEmailProviderCheckTimer = null;
let authEmailProviderCheckSequence = 0;
let signInBackoffCooldownEmail = "";
let signInBackoffCooldownIntervalId = null;

function showAuthModalError(message, kind = "generic", color = "#ff6b6b") {
  const error = document.getElementById("signInError");
  if (!error) return;
  const nextKind = String(kind || "generic");
  if (nextKind !== "signin_backoff") stopSignInBackoffCountdown();
  authModalErrorKind = nextKind;
  error.style.display = "block";
  error.style.color = color;
  error.innerText = String(message || "Something went wrong.");
}

function hideAuthModalError() {
  const error = document.getElementById("signInError");
  stopSignInBackoffCountdown();
  if (!error) return;
  authModalErrorKind = "";
  error.style.display = "none";
  error.innerText = "";
}

function clearAuthProgressMessage() {
  if (authModalErrorKind === "auth_progress") {
    hideAuthModalError();
  }
}

function clearAuthModalErrorOnInput(fieldName) {
  const field = String(fieldName || "");
  const error = document.getElementById("signInError");
  if (!error || error.style.display === "none") return;

  if (authModalErrorKind === "username_exists") {
    if (field === "username") hideAuthModalError();
    return;
  }

  if (authModalErrorKind === "signin_backoff") {
    if (field === "email") hideAuthModalError();
    return;
  }

  if (authModalErrorKind === "credentials") {
    if (field === "email" || field === "password") hideAuthModalError();
    return;
  }

  hideAuthModalError();
}

function canOverrideAuthUsernameMessage() {
  return !authModalErrorKind
    || authModalErrorKind === "username"
    || authModalErrorKind === "username_exists"
    || authModalErrorKind === "username_check"
    || authModalErrorKind === "username_available";
}

function canOverrideAuthDisplayNameMessage() {
  return !authModalErrorKind
    || authModalErrorKind === "display_name"
    || authModalErrorKind === "display_name_valid";
}

function validateSignupUsername(usernameValue) {
  const raw = String(usernameValue || "").trim();
  const candidate = raw.startsWith("@") ? raw.slice(1).trim() : raw;
  if (!raw) {
    return { ok: false, message: "Username is required for sign up!", normalized: "" };
  }

  if (candidate.length < 1 || candidate.length > 20) {
    return { ok: false, message: "Username must be 1-20 characters.", normalized: "" };
  }

  if (candidate.includes(" ")) {
    return { ok: false, message: "Spaces are not allowed in username.", normalized: "" };
  }

  const allowedPattern = /^[A-Za-z0-9_-]+$/;
  if (!allowedPattern.test(candidate)) {
    return { ok: false, message: "Username can only use letters, numbers, underscores, and dashes.", normalized: "" };
  }

  return { ok: true, message: "", normalized: normalizeUsernameForLookup(candidate) };
}

function validateSignupDisplayName(displayNameValue) {
  const raw = String(displayNameValue || "").trim().replace(/\s+/g, " ");
  if (!raw) {
    return { ok: false, message: "Display name is required for sign up!", normalized: "" };
  }

  if (raw.length < 1 || raw.length > 20) {
    return { ok: false, message: "Display name must be 1-20 characters.", normalized: "" };
  }

  const allowedPattern = /^[A-Za-z0-9 _-]+$/;
  if (!allowedPattern.test(raw)) {
    return { ok: false, message: "Display name can only use letters, numbers, spaces, underscores, and dashes.", normalized: "" };
  }

  if (/[_-]{3,}/.test(raw)) {
    return { ok: false, message: "Display name cannot contain long symbol runs.", normalized: "" };
  }

  const normalizedKey = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
  const reservedNames = new Set(["admin", "administrator", "owner", "support", "system", "novafix", "mod", "moderator"]);
  if (reservedNames.has(normalizedKey)) {
    return { ok: false, message: "That display name is reserved. Choose another one.", normalized: "" };
  }

  return { ok: true, message: "", normalized: raw };
}

function isValidUsernameKey(usernameKey) {
  const value = String(usernameKey || "").trim();
  return /^[a-z0-9_-]{1,20}$/.test(value);
}

async function getDocWithFreshFallback(ref) {
  try {
    return await getDocFromServer(ref);
  } catch (err) {
    const code = String(err?.code || "").toLowerCase();
    const fallbackAllowed = code.includes("unavailable")
      || code.includes("deadline-exceeded")
      || code.includes("failed-precondition");
    if (!fallbackAllowed) throw err;
    return getDoc(ref);
  }
}

async function getDocsWithFreshFallback(q) {
  try {
    return await getDocsFromServer(q);
  } catch (err) {
    const code = String(err?.code || "").toLowerCase();
    const fallbackAllowed = code.includes("unavailable")
      || code.includes("deadline-exceeded")
      || code.includes("failed-precondition");
    if (!fallbackAllowed) throw err;
    return getDocs(q);
  }
}

async function usernameExistsLiveInFirestore(usernameKey) {
  if (!usernameKey) return false;
  const normalized = normalizeUsernameForLookup(usernameKey);
  if (!normalized) return false;
  try {
    const resolved = await resolveUserDirectoryByUsername(normalized, {
      forceRefresh: true,
      preferServer: true
    });
    return !!resolved;
  } catch (err) {
    if (isFirestorePermissionDeniedError(err)) return false;
    throw err;
  }
}

function scheduleLiveUsernameAvailabilityCheck() {
  if (usernameLiveCheckTimer) {
    clearTimeout(usernameLiveCheckTimer);
    usernameLiveCheckTimer = null;
  }

  const localSeq = ++usernameLiveCheckSequence;
  usernameLiveCheckTimer = setTimeout(async () => {
    if (authMode !== "signup") return;
    const validation = validateSignupUsername(usernameInput?.value || "");
    if (!validation.ok) {
      const hasAnyText = String(usernameInput?.value || "").trim().length > 0;
      if (hasAnyText && canOverrideAuthUsernameMessage()) {
        showAuthModalError(validation.message, "username");
      }
      return;
    }
    const usernameKey = validation.normalized;
    if (!usernameKey) return;

    if (canOverrideAuthUsernameMessage()) {
      showAuthModalError("Checking username...", "username_check", "#9fd0ff");
    }

    try {
      const exists = await usernameExistsLiveInFirestore(usernameKey);
      if (localSeq !== usernameLiveCheckSequence || authMode !== "signup") return;

      if (exists) {
        showAuthModalError("This username already exists. Choose a different username.", "username_exists");
      } else if (canOverrideAuthUsernameMessage()) {
        showAuthModalError("Username is available.", "username_available", "#7CFFB2");
      }
    } catch (err) {
      if (localSeq !== usernameLiveCheckSequence || authMode !== "signup") return;
      if (canOverrideAuthUsernameMessage()) {
        showAuthModalError(err?.message || "Could not verify username right now.", "username_check");
      }
    }
  }, 320);
}

if (emailInput) {
  emailInput.addEventListener("input", () => {
    clearAuthModalErrorOnInput("email");
    scheduleAuthEmailProviderCheck();
  });
}
if (passwordInput) {
  passwordInput.addEventListener("input", () => clearAuthModalErrorOnInput("password"));
}
if (usernameInput) {
  usernameInput.addEventListener("input", () => {
    clearAuthModalErrorOnInput("username");
    if (authMode === "signup") {
      scheduleLiveUsernameAvailabilityCheck();
    }
  });
}
if (displayNameInput) {
  displayNameInput.addEventListener("input", () => {
    clearAuthModalErrorOnInput("display_name");
    if (authMode !== "signup") return;
    const raw = String(displayNameInput.value || "").trim();
    if (!raw) return;
    const validation = validateSignupDisplayName(raw);
    if (!validation.ok) {
      showAuthModalError(validation.message, "display_name");
      return;
    }
    if (canOverrideAuthDisplayNameMessage()) {
      showAuthModalError("Display name looks good.", "display_name_valid", "#7CFFB2");
    }
  });
}

function shouldSubmitAuthOnEnter(event) {
  if (!signInModal || signInModal.style.display !== "flex") return false;
  if (event.key !== "Enter") return false;
  if (event.shiftKey || event.ctrlKey || event.metaKey || event.isComposing) return false;
  return true;
}

function bindAuthEnterSubmit(inputEl) {
  if (!inputEl) return;
  inputEl.addEventListener("keydown", (event) => {
    if (!shouldSubmitAuthOnEnter(event)) return;
    event.preventDefault();
    void handleAuth();
  });
}

bindAuthEnterSubmit(emailInput);
bindAuthEnterSubmit(passwordInput);
bindAuthEnterSubmit(usernameInput);
bindAuthEnterSubmit(displayNameInput);

const PAGE_TITLES = {
  dashboard: "NovaFix - Dashboard",
  signup: "NovaFix - Sign Up",
  signin: "NovaFix - Sign In"
};

function setPageTitle(view = "signin") {
  const normalizedView = String(view || "signin").toLowerCase();
  const safeKey = Object.prototype.hasOwnProperty.call(PAGE_TITLES, normalizedView)
    ? normalizedView
    : "signin";
  const titleText = PAGE_TITLES[safeKey];
  document.title = titleText;
  const titleEl = document.getElementById("appPageTitle") || document.querySelector("head > title");
  if (titleEl) titleEl.textContent = titleText;
}

setPageTitle("signin");

function isGoogleProviderUser(user) {
  const providerIds = Array.isArray(user?.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  return providerIds.includes("google.com");
}

async function isGoogleRegisteredEmail(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  if (!safeEmail) return false;
  try {
    const methods = await fetchSignInMethodsForEmail(auth, safeEmail);
    return methods.includes("google.com");
  } catch (_) {
    return false;
  }
}

function hasPasswordProviderLinked(user) {
  const providerIds = Array.isArray(user?.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  return providerIds.includes("password");
}

async function isGoogleOnlySignInEmail(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  if (!safeEmail) return false;
  try {
    const methods = await fetchSignInMethodsForEmail(auth, safeEmail);
    return methods.includes("google.com") && !methods.includes("password");
  } catch (_) {
    return false;
  }
}

function scheduleAuthEmailProviderCheck() {
  if (authEmailProviderCheckTimer) {
    clearTimeout(authEmailProviderCheckTimer);
    authEmailProviderCheckTimer = null;
  }

  const localSeq = ++authEmailProviderCheckSequence;
  authEmailProviderCheckTimer = setTimeout(async () => {
    if (localSeq !== authEmailProviderCheckSequence) return;
    if (authMode !== "signin") return;

    const email = String(emailInput?.value || "").trim().toLowerCase();
    if (!email || !email.includes("@")) return;

    const googleOnly = await isGoogleOnlySignInEmail(email);
    if (localSeq !== authEmailProviderCheckSequence || authMode !== "signin") return;
    if (!googleOnly) return;

    showAuthModalError(
      "This email was signed up with Google. Use Sign In with Google to continue.",
      "credentials",
      "#ffb37a"
    );
  }, 260);
}

function showGoogleIdentityError(message, color = "#ff6b6b") {
  if (!googleIdentityError) return;
  googleIdentityError.style.display = "block";
  googleIdentityError.style.color = color;
  googleIdentityError.innerText = String(message || "Please review your details and try again.");
}

function hideGoogleIdentityError() {
  if (!googleIdentityError) return;
  googleIdentityError.style.display = "none";
  googleIdentityError.innerText = "";
}

function closeGoogleIdentitySetupModal() {
  if (googleIdentityModal) googleIdentityModal.style.display = "none";
  hideGoogleIdentityError();
  if (googleIdentityUsernameLiveCheckTimer) {
    clearTimeout(googleIdentityUsernameLiveCheckTimer);
    googleIdentityUsernameLiveCheckTimer = null;
  }
  googleIdentityUsernameLiveCheckSequence += 1;
  if (googleIdentityUsernameInput) googleIdentityUsernameInput.value = "";
  if (googleIdentityDisplayNameInput) googleIdentityDisplayNameInput.value = "";
  if (googleIdentityPasswordInput) googleIdentityPasswordInput.value = "";
  if (googleIdentityUsernameInput) googleIdentityUsernameInput.style.display = "block";
  if (googleIdentityDisplayNameInput) googleIdentityDisplayNameInput.style.display = "block";
  if (googleIdentityPasswordInput) googleIdentityPasswordInput.style.display = "block";
  if (googleIdentityTitle) googleIdentityTitle.innerText = "Set Your Profile";
  if (googleIdentityNote) {
    googleIdentityNote.innerText = "Choose your username and display name.";
  }
  googleIdentityPasswordOnlyMode = false;
  googleIdentityRequirePassword = false;
  googleIdentitySetupInProgress = false;
  googleIdentitySetupUserId = "";
}

function scheduleGoogleIdentityUsernameAvailabilityCheck() {
  if (googleIdentityUsernameLiveCheckTimer) {
    clearTimeout(googleIdentityUsernameLiveCheckTimer);
    googleIdentityUsernameLiveCheckTimer = null;
  }

  const localSeq = ++googleIdentityUsernameLiveCheckSequence;
  googleIdentityUsernameLiveCheckTimer = setTimeout(async () => {
    if (!googleIdentitySetupInProgress || !googleIdentityModal || googleIdentityModal.style.display !== "flex") return;
    const validation = validateSignupUsername(googleIdentityUsernameInput?.value || "");
    const hasAnyText = String(googleIdentityUsernameInput?.value || "").trim().length > 0;
    if (!validation.ok) {
      if (hasAnyText) {
        showGoogleIdentityError(validation.message);
      } else {
        hideGoogleIdentityError();
      }
      return;
    }

    const usernameKey = validation.normalized;
    if (!usernameKey) return;
    showGoogleIdentityError("Checking username...", "#9fd0ff");

    try {
      const exists = await usernameExistsLiveInFirestore(usernameKey);
      if (localSeq !== googleIdentityUsernameLiveCheckSequence || !googleIdentitySetupInProgress) return;

      if (!exists) {
        showGoogleIdentityError("Username is available.", "#7CFFB2");
        return;
      }

      const activeUid = String(auth.currentUser?.uid || "").trim();
      const resolvedUsername = await resolveUserDirectoryByUsername(usernameKey, {
        forceRefresh: true,
        preferServer: true
      }).catch(() => null);
      if (localSeq !== googleIdentityUsernameLiveCheckSequence || !googleIdentitySetupInProgress) return;

      const ownerUid = String(resolvedUsername?.uid || "").trim();
      if (ownerUid && activeUid && ownerUid === activeUid) {
        showGoogleIdentityError("Username is available.", "#7CFFB2");
        return;
      }

      showGoogleIdentityError("Username is taken.");
    } catch (err) {
      if (localSeq !== googleIdentityUsernameLiveCheckSequence || !googleIdentitySetupInProgress) return;
      showGoogleIdentityError(err?.message || "Could not verify username right now.");
    }
  }, 320);
}

function openGoogleIdentitySetupModal(user, defaults = {}) {
  const activeUserId = String(user?.uid || "").trim();
  if (!googleIdentityModal || !activeUserId) return;
  const forceFullSetup = GOOGLE_IDENTITY_STRICT_ENFORCED || !!defaults?.forceFullSetup;
  const passwordOnly = forceFullSetup ? false : !!defaults?.passwordOnly;
  googleIdentityPasswordOnlyMode = passwordOnly;
  googleIdentityRequirePassword = forceFullSetup ? true : (passwordOnly || !!defaults?.requirePassword);
  if (googleIdentityUsernameInput) googleIdentityUsernameInput.value = "";
  if (googleIdentityDisplayNameInput) googleIdentityDisplayNameInput.value = "";
  if (googleIdentityPasswordInput) googleIdentityPasswordInput.value = "";
  if (googleIdentityUsernameInput) googleIdentityUsernameInput.style.display = passwordOnly ? "none" : "block";
  if (googleIdentityDisplayNameInput) googleIdentityDisplayNameInput.style.display = passwordOnly ? "none" : "block";
  if (googleIdentityPasswordInput) googleIdentityPasswordInput.style.display = "block";
  if (googleIdentityTitle) {
    googleIdentityTitle.innerText = forceFullSetup ? "Confirm Your Profile" : (passwordOnly ? "Set Account Password" : "Set Your Profile");
  }
  if (googleIdentityNote) {
    googleIdentityNote.innerText = forceFullSetup
      ? "For security, type username, display name, and password to continue."
      : passwordOnly
      ? "Set a password below to continue."
      : "Choose your username and display name, then set a password to continue.";
  }
  hideGoogleIdentityError();
  googleIdentityModal.style.display = "flex";
  ensureAppBackGuardState("google-identity", true);
  signInModal.style.display = "none";
  googleIdentitySetupInProgress = true;
  googleIdentitySetupUserId = activeUserId;
  scheduleGoogleIdentityUsernameAvailabilityCheck();
}

async function ensureGoogleIdentitySetupIfNeeded(user) {
  const activeUserId = String(user?.uid || "").trim();
  if (!activeUserId) return true;
  if (!isGoogleProviderUser(user)) return true;

  if (googleIdentitySetupInProgress && googleIdentitySetupUserId === activeUserId) {
    return false;
  }

  let profileData = {};
  try {
    const profileRes = await fsGetDoc(doc(db, "users", activeUserId, "settings", "profile"), 'profile');
    if (profileRes.exists) {
      profileData = profileRes.data || {};
    }
  } catch (_) {
    profileData = {};
  }

  const hasPasswordProvider = hasPasswordProviderLinked(user);
  const setupCompleted = profileData.googleIdentitySetupCompleted === true;
  const profileUsername = normalizeUsernameForLookup(profileData.username || profileData.name || "");
  const profileDisplayName = normalizeDisplayNameValue(profileData.displayName || "");
  const hasProfileIdentity = !!profileUsername && !!profileDisplayName;
  const isIdentityFullyConfigured = setupCompleted && hasPasswordProvider && hasProfileIdentity;

  if (isIdentityFullyConfigured) {
    return true;
  }

  if (GOOGLE_IDENTITY_STRICT_ENFORCED) {
    openGoogleIdentitySetupModal(user, {
      username: "",
      displayName: "",
      passwordOnly: false,
      requirePassword: true,
      forceFullSetup: true
    });
    return false;
  }

  openGoogleIdentitySetupModal(user, {
    username: "",
    displayName: "",
    passwordOnly: false,
    requirePassword: true,
    forceFullSetup: true
  });
  return false;
}

const DASHBOARD_CARD_LOAD_DELAY_MS = 1000;
const DASHBOARD_CARD_LOAD_TIMEOUT_MS = 5000;
let dashboardCardLoadTimeoutId = null;

function clearDashboardCardLoadTimeout() {
  if (dashboardCardLoadTimeoutId) {
    clearTimeout(dashboardCardLoadTimeoutId);
    dashboardCardLoadTimeoutId = null;
  }
}

function forceCardContainerLoad(containerEl, itemSelector, emptyMessage) {
  if (!containerEl) return;
  clearStatusState(containerEl);
  if (!containerEl.querySelector(itemSelector)) {
    setEmptyState(containerEl, emptyMessage);
  }
}

function forceDashboardCardLoad(sessionUserId) {
  const activeUser = auth.currentUser;
  if (!activeUser?.uid || activeUser.uid !== sessionUserId) return;

  dashboard.style.display = "grid";
  dashboard.classList.remove("preload-shell");

  forceCardContainerLoad(chat, ".chat-message", "No conversations yet. Start the first one to get AI help.");
  forceCardContainerLoad(reminders, ".item-row", "No reminders yet. Add one to keep things moving.");
  forceCardContainerLoad(taskList, ".item-row", "No tasks yet. Add one small task to start.");
  forceCardContainerLoad(moodLogs, ".mood-item", "No mood logs yet. Add today’s check-in.");
  forceCardContainerLoad(gratitudeLogs, ".item-row", "No gratitude notes yet. Add your first one.");
  forceCardContainerLoad(questListEl, ".quest-item", "No quests yet. Log today’s stats to generate quests.");

  updateWeeklyReview();
  refreshStartupFeatures();
  renderFriendMetricCardInsights();
  updateCrashPreventionUI();
  updateClearDataButtonState();
}

async function initializeAuthenticatedSession(user) {
  const sessionUserId = String(user?.uid || "").trim();
  if (!sessionUserId) return;
  lastAuthenticatedUserId = sessionUserId;
  clearAuthProgressMessage();

  if (signInModal) signInModal.style.display = "none";
  dashboard.style.display = "grid";
  dashboard.classList.add("preload-shell");
  accountBtn.style.display = "none";

  const tosAccepted = await ensureTosAccepted(sessionUserId);
  const activeUserAfterTos = auth.currentUser;
  if (!tosAccepted || !activeUserAfterTos?.uid || activeUserAfterTos.uid !== sessionUserId) {
    return;
  }

  dashboard.style.display = "grid";
  dashboard.classList.add("preload-shell");
  setPageTitle("dashboard");
  accountBtn.style.display = "block";
  closeAccountPanel();
  closeGoogleIdentitySetupModal();
  updateAccountPanel(user);
  signInModal.style.display = "none";
  clearDashboardCardLoadTimeout();
  dashboardCardLoadTimeoutId = setTimeout(() => {
    dashboardCardLoadTimeoutId = null;
    forceDashboardCardLoad(sessionUserId);
  }, DASHBOARD_CARD_LOAD_TIMEOUT_MS);

  await new Promise((resolve) => setTimeout(resolve, DASHBOARD_CARD_LOAD_DELAY_MS));
  const activeUserAfterShell = auth.currentUser;
  if (!activeUserAfterShell?.uid || activeUserAfterShell.uid !== sessionUserId) {
    dashboard.classList.remove("preload-shell");
    clearDashboardCardLoadTimeout();
    return;
  }

  dashboard.classList.remove("preload-shell");
  setInitialLoadingStates();
  updateClearDataButtonState();
  const sessionPrepPromise = Promise.allSettled([
    migrateUserDocument(user.uid),
    syncServerClock(user.uid),
    refreshExportCooldownState(user.uid),
    refreshDisplayNameEditCooldownState(user.uid),
    upsertUserDirectoryProfile(user),
    loadPersistedBarGraphs(user.uid)
  ]);
  const resetCatchupPromise = ensureDateBoundResetCatchup(user.uid);
  void Promise.allSettled([sessionPrepPromise, resetCatchupPromise]).then(() => {
    const activeUser = auth.currentUser;
    if (!activeUser?.uid || activeUser.uid !== user.uid) return;
    updateAccountPanel(activeUser);
  }).catch((err) => structuredLog('warn', 'session.prep', err?.message || String(err)));
  const initialDataLoadPromises = [
    loadDailyChallenge(user.uid),
    loadDailyUsage(user.uid),
    loadMoods(user.uid),
    loadAiUsage(user.uid),
    loadAiChats(user.uid),
    loadTasks(user.uid),
    loadReminders(user.uid),
    loadWeeklyTargets(user.uid),
    loadRescueEvents(user.uid),
    loadHabitQuest(user.uid),
    loadStartupUsageState(user.uid),
    loadStartupFeatureState(user.uid),
    loadWaterData(user.uid),
    loadSleepData(user.uid),
    loadMusicSessions(user.uid),
    loadBedtimeSettings(user.uid),
    loadGratitude(user.uid)
  ];
  const shouldShowPendingRequestLoginAlert = consumePendingRequestLoginAlertFlag();
  friendRequestLoginAlertShown = false;
  loadFriendRequests(user.uid, shouldShowPendingRequestLoginAlert);
  loadSentFriendRequests(user.uid);
  loadFriendsInsights(user.uid);
  startFriendInsightsWatcher(user.uid);
  showPendingImportSecurityWarnings(user.uid);
  startDailyChallengeWatcher();
  scheduleDailyChallengeReset(user.uid);
  scheduleDailyQuestReset(user.uid);
  scheduleDailySystemReset(user.uid);
  startWeeklyGraphResetCountdown();
  startStartupResetCountdown();
  scheduleWeeklyGraphReset(user.uid);
  scheduleWaterGoalReset(user.uid);
  scheduleSleepDailyReset(user.uid);
  scheduleMoodDailyReset(user.uid);
  void Promise.allSettled(initialDataLoadPromises).then(async () => {
    const activeUser = auth.currentUser;
    if (!activeUser?.uid || activeUser.uid !== user.uid) return;
    updateCrashPreventionUI();
    await forceSyncFriendProfileFromLocalSnapshot(activeUser);
    await loadFriendsInsights(activeUser.uid);
    updateCrashPreventionUI();
  }).finally(() => {
    clearDashboardCardLoadTimeout();
  }).catch((err) => structuredLog('warn', 'initialLoad.error', err?.message || String(err)));
  await maybeShowWelcomeGuide(user.uid).catch((err) => structuredLog('warn', 'welcome.guide', err?.message || String(err)));
}

async function submitGoogleIdentitySetup() {
  const user = auth.currentUser;
  if (!user?.uid) {
    showGoogleIdentityError("Your session expired. Please sign in again.");
    return;
  }

  const usernameRaw = String(googleIdentityUsernameInput?.value || "").trim();
  const displayNameRaw = String(googleIdentityDisplayNameInput?.value || "").trim();
  const googlePasswordRaw = String(googleIdentityPasswordInput?.value || "");
  const hasPasswordProvider = hasPasswordProviderLinked(user);
  const requireFullProfileFields = GOOGLE_IDENTITY_STRICT_ENFORCED || !googleIdentityPasswordOnlyMode;
  const requiresTypedPassword = GOOGLE_IDENTITY_STRICT_ENFORCED || googleIdentityRequirePassword;
  const needsPasswordSetup = googleIdentityRequirePassword && !hasPasswordProvider;
  if (requiresTypedPassword && googlePasswordRaw.length < 6) {
    showGoogleIdentityError("Set a password with at least 6 characters.");
    return;
  }

  const usernameValidation = requireFullProfileFields
    ? validateSignupUsername(usernameRaw)
    : { ok: true, normalized: "" };
  if (!usernameValidation.ok) {
    showGoogleIdentityError(usernameValidation.message);
    return;
  }

  const displayValidation = requireFullProfileFields
    ? validateSignupDisplayName(displayNameRaw)
    : { ok: true, normalized: "" };
  if (!displayValidation.ok) {
    showGoogleIdentityError(displayValidation.message);
    return;
  }

  const usernameKey = usernameValidation.normalized;
  const normalizedDisplayName = requireFullProfileFields
    ? normalizeDisplayNameValue(displayValidation.normalized)
    : normalizeDisplayNameValue(user.displayName || "");
  if (requireFullProfileFields && (!usernameKey || !normalizedDisplayName)) {
    showGoogleIdentityError("Please enter valid profile details.");
    return;
  }

  if (googleIdentitySaveBtn) googleIdentitySaveBtn.disabled = true;
  hideGoogleIdentityError();

  try {
    if (requireFullProfileFields) {
      try {
        const usernameExists = await usernameExistsLiveInFirestore(usernameKey);
        if (usernameExists) {
          const resolvedUsername = await resolveUserDirectoryByUsername(usernameKey, {
            forceRefresh: true,
            preferServer: true
          }).catch(() => null);
          if (resolvedUsername?.uid && resolvedUsername.uid !== user.uid) {
            showGoogleIdentityError("This username already exists. Choose a different username.");
            return;
          }
        }
      } catch (lookupErr) {
        if (!isFirestorePermissionDeniedError(lookupErr)) {
          showGoogleIdentityError(lookupErr?.message || "Could not verify username right now.");
          return;
        }
        // If pre-check is blocked by rules, transactional claim below is still the source of truth.
      }
    }

    const safeEmail = String(user.email || "").trim().toLowerCase();
    if (!safeEmail) {
      showGoogleIdentityError("Could not read your Google account email. Sign out and try again.");
      return;
    }

    let passwordLinkedNow = hasPasswordProvider;
    if (needsPasswordSetup) {
      const credential = EmailAuthProvider.credential(safeEmail, googlePasswordRaw);
      try {
        await linkWithCredential(user, credential);
        passwordLinkedNow = true;
      } catch (linkErr) {
        const linkCode = String(linkErr?.code || "");
        if (linkCode !== "auth/provider-already-linked") {
          throw linkErr;
        }
        passwordLinkedNow = true;
      }

      // Confirm provider linkage so setup cannot finish in a half-saved state.
      await user.reload().catch((err) => structuredLog('warn', 'auth.reload.2', err?.message || String(err)));
      passwordLinkedNow = hasPasswordProviderLinked(auth.currentUser || user) || passwordLinkedNow;
      if (!passwordLinkedNow) {
        showGoogleIdentityError("Password setup could not be confirmed. Please try again.");
        return;
      }
    }

    const displayNameChangeAppliedAtMs = getServerNowDate().getTime();
    if (requireFullProfileFields) {
      await claimUsernameDirectoryEntry(user.uid, usernameKey, safeEmail, normalizedDisplayName);
      await updateProfile(user, { displayName: normalizedDisplayName });
      await upsertUserDirectoryProfile(user, {
        username: usernameKey,
        displayName: normalizedDisplayName
      });
    }

    const hasPasswordAfterSetup = hasPasswordProviderLinked(auth.currentUser || user) || passwordLinkedNow;

    if (googleIdentityRequirePassword && !hasPasswordAfterSetup) {
      showGoogleIdentityError("Password is required. Please set it to continue.");
      return;
    }

    await safeSetDoc(doc(db, "users", user.uid, "settings", "profile"), {
      googleIdentitySetupCompleted: true,
      googleIdentitySetupCompletedAt: serverTimestamp(),
      googleLegacyPasswordRequired: false,
      googleImportPasswordEnabled: hasPasswordAfterSetup,
      googleImportPasswordEnabledAt: hasPasswordAfterSetup ? serverTimestamp() : null,
      ...(requireFullProfileFields ? {
        displayNameDashboardChangedAt: serverTimestamp(),
        displayNameDashboardChangedAtMs: displayNameChangeAppliedAtMs,
        displayNameDashboardCooldownUntilMs: displayNameChangeAppliedAtMs + DISPLAY_NAME_EDIT_COOLDOWN_MS
      } : {}),
      updatedAt: serverTimestamp()
    }, 'profile', { merge: true });

    // Verify the profile write succeeded before proceeding
    let verifyAttempts = 0;
    let profileSaveVerified = false;
    while (verifyAttempts < 3 && !profileSaveVerified) {
      try {
        const verifyRes = await fsGetDoc(doc(db, "users", user.uid, "settings", "profile"), 'profile');
        if (verifyRes.exists && (verifyRes.data?.googleIdentitySetupCompleted === true)) {
          profileSaveVerified = true;
          break;
        }
      } catch (_) {}
      if (!profileSaveVerified) {
        verifyAttempts++;
        if (verifyAttempts < 3) {
          await new Promise(r => setTimeout(r, 200 * verifyAttempts));
        }
      }
    }

    if (!profileSaveVerified) {
      showGoogleIdentityError("Profile save could not be verified. Please try again.");
      return;
    }

    await user.reload().catch((err) => structuredLog('warn', 'auth.reload.3', err?.message || String(err)));
    await initializeAuthenticatedSession(user);
  } catch (err) {
    const claimCode = String(err?.message || "");
    if (claimCode === "USERNAME_TAKEN") {
      showGoogleIdentityError("This username already exists. Choose a different username.");
      return;
    }
    if (err?.code === "auth/weak-password") {
      showGoogleIdentityError("Password must be at least 6 characters.");
      return;
    }
    if (isFirestorePermissionDeniedError(err)) {
      showGoogleIdentityError("Identity setup is blocked by Firestore rules. Allow writes to usernameDirectory/profile and try again.");
      return;
    }
    showGoogleIdentityError(err?.message || "Could not save your profile right now.");
  } finally {
    if (googleIdentitySaveBtn) googleIdentitySaveBtn.disabled = false;
  }
}

async function cancelGoogleIdentitySetup() {
  closeGoogleIdentitySetupModal();
  await signOut(auth).catch((err) => structuredLog('warn', 'auth.signout.1', err?.message || String(err)));
}

if (googleIdentityUsernameInput) {
  googleIdentityUsernameInput.addEventListener("input", () => {
    scheduleGoogleIdentityUsernameAvailabilityCheck();
  });
}
if (googleIdentityDisplayNameInput) {
  googleIdentityDisplayNameInput.addEventListener("input", () => hideGoogleIdentityError());
}
if (googleIdentityPasswordInput) {
  googleIdentityPasswordInput.addEventListener("input", () => hideGoogleIdentityError());
}

let verificationCooldownTimer = null;
let verificationCooldownRemaining = 0;
const VERIFICATION_AUTO_RESEND_WINDOW_MS = 10 * 60 * 1000;
const AUTH_BACKOFF_FAIL_THRESHOLD = 3;
const AUTH_SIGNIN_BACKOFF_FAIL_THRESHOLD = 7;
const AUTH_BACKOFF_BASE_MS = 15 * 1000;
const AUTH_BACKOFF_MAX_MS = 10 * 60 * 1000;
const AUTH_BACKOFF_STORAGE_PREFIX = "novafix_auth_backoff_";
const DEVICE_INFO_SOURCE = String(
  navigator.userAgentData?.platform
  || navigator.platform
  || navigator.userAgent
  || ""
).toLowerCase();
const IS_MAC_OS = /mac/i.test(DEVICE_INFO_SOURCE);
const IS_MOBILE_DEVICE = (() => {
  const mobileUa = /(android|iphone|ipad|ipod|mobile|phone|windows\s+phone)/i.test(String(navigator.userAgent || ""));
  const hasTouch = Number(navigator.maxTouchPoints || 0) > 1;
  const narrowScreen = typeof window !== "undefined"
    ? (window.matchMedia?.("(max-width: 900px)")?.matches || Math.min(window.innerWidth, window.innerHeight) <= 900)
    : false;
  return mobileUa || (hasTouch && narrowScreen);
})();
document.documentElement.classList.toggle("mobile-device", IS_MOBILE_DEVICE);
const SHORTCUT_MOD_LABEL = IS_MAC_OS ? "Option" : "Alt";
const CARD_SHORTCUTS = [
  { cardIndex: 0, keys: ["a", "i"], label: "AI Companion" },
  { cardIndex: 1, keys: ["r", "e"], label: "Reminders" },
  { cardIndex: 2, keys: ["p", "r"], label: "Productivity" },
  { cardIndex: 3, keys: ["g", "f"], label: "Grocery Financing" },
  { cardIndex: 4, keys: ["m", "t"], label: "Mood Tracker" },
  { cardIndex: 5, keys: ["w", "t"], label: "Water Intake" },
  { cardIndex: 6, keys: ["s", "l"], label: "Sleep" },
  { cardIndex: 7, keys: ["m", "u"], label: "Wellness Music" },
  { cardIndex: 8, keys: ["t", "m"], label: "Time Traveller Mirror" },
  { cardIndex: 9, keys: ["q", "t"], label: "Motivational Quotes" },
  { cardIndex: 10, keys: ["g", "j"], label: "Gratitude Journal" },
  { cardIndex: 11, keys: ["d", "c"], label: "Daily Challenge" },
  { cardIndex: 12, keys: ["w", "s"], label: "Daily Wellness Score" },
  { cardIndex: 13, keys: ["m", "c"], label: "Mood Crash Prevention" },
  { cardIndex: 14, keys: ["w", "r"], label: "Weekly Review + AI Coach" },
  { cardIndex: 15, keys: ["h", "q"], label: "Adaptive Habit Quest" },
  { cardIndex: 16, keys: ["b", "r"], label: "Predictive Burnout Radar" },
  { cardIndex: 17, keys: ["i", "s"], label: "Insights & Streaks" },
  { cardIndex: 18, keys: ["d", "p"], label: "Personalized Daily Plan" },
  { cardIndex: 19, keys: ["s", "r"], label: "Weekly Startup Report" },
  { cardIndex: 20, keys: ["b", "g"], label: "Behavior Memory Graph" }
];
let welcomeGuideStepIndex = 0;
let welcomeGuideUserId = "";
let welcomeGuideCheckedThisSession = false;
const WELCOME_GUIDE_VERSION = 1;
const TOS_VERSION = "2026";

// ---------- Loading state manager for UI feedback ----------
const LoadingStateManager = {
  activeOperations: new Map(), // { operationId: { startTime, type, context } }
  
  start(operationId, type = 'default', context = {}) {
    this.activeOperations.set(operationId, {
      startTime: Date.now(),
      type,
      context
    });
    this.updateUI();
  },
  
  end(operationId) {
    this.activeOperations.delete(operationId);
    this.updateUI();
  },
  
  isLoading(operationId = null) {
    if (operationId) return this.activeOperations.has(operationId);
    return this.activeOperations.size > 0;
  },
  
  getActive() {
    return Array.from(this.activeOperations.entries()).map(([id, data]) => ({ id, ...data }));
  },
  
  updateUI() {
    const isLoading = this.isLoading();
    const operations = this.getActive();
    
    // Show/hide loading indicators based on operation types
    const friendOps = operations.filter(op => op.type === 'friend');
    const profileOps = operations.filter(op => op.type === 'profile');
    const importOps = operations.filter(op => op.type === 'import');
    const aiOps = operations.filter(op => op.type === 'ai');
    
    // Wire to UI elements (update specific sections based on operation type)
    if (friendOps.length) {
      // Show loading in friends section
      if (friendsList) friendsList.style.opacity = '0.6';
    } else {
      if (friendsList) friendsList.style.opacity = '1';
    }
    
    if (profileOps.length) {
      // Show loading in profile section
      if (profileDataContainer) profileDataContainer.style.opacity = '0.6';
    } else {
      if (profileDataContainer) profileDataContainer.style.opacity = '1';
    }
  },
  
  // Helper: wrap async operations with auto start/end
  async withLoading(operationId, type, fn) {
    try {
      this.start(operationId, type);
      return await fn();
    } finally {
      this.end(operationId);
    }
  }
};

// ---------- UI State helpers for empty/error/loading states ----------
const UIStateHelpers = {
  // Render empty state in a container
  showEmpty(container, message = 'No data available') {
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:20px; opacity:0.6;"><small>${escapeHtml(message)}</small></div>`;
  },
  
  // Render error state in a container
  showError(container, message = 'An error occurred') {
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:20px; color:#ff6b6b;"><small>⚠️ ${escapeHtml(message)}</small></div>`;
  },
  
  // Render loading state in a container
  showLoading(container) {
    if (!container) return;
    container.innerHTML = `<div style="text-align:center; padding:20px;"><small>Loading...</small></div>`;
  },
  
  // Clear container (for rendering actual data)
  clear(container) {
    if (!container) return;
    container.innerHTML = '';
  },
  
  // Generic render with state management
  render(container, data, renderFn, { emptyMessage = 'No data', errorOnNull = false } = {}) {
    if (!container) return;
    
    if (!data) {
      if (errorOnNull) {
        this.showError(container, 'Failed to load data');
      } else {
        this.showEmpty(container, emptyMessage);
      }
      return;
    }
    
    if (Array.isArray(data) && data.length === 0) {
      this.showEmpty(container, emptyMessage);
      return;
    }
    
    this.clear(container);
    try {
      renderFn(container, data);
    } catch (err) {
      structuredLog('warn', 'ui.render', err?.message || String(err));
      this.showError(container, 'Error rendering data');
    }
  }
};

let tosResolvePendingQueue = [];
let tosPendingUserId = "";
let authStateChangeSequence = 0;
let authStateDelayTimer = null;
let lastAuthenticatedUserId = "";
const WELCOME_GUIDE_STEPS = [
  {
    title: "Dashboard Overview",
    text: "Use the cards to log mood, water, sleep, reminders, tasks, gratitude, and more in one flow.",
    tip: "Tip: Start with Mood, Water, and Sleep every day for the fastest progress gains. Use Shift+Enter to add a new line in text boxes."
  },
  {
    title: "Daily Limits",
    text: "Each tracker has a daily safety limit and reset timer to keep entries realistic and consistent.",
    tip: "Tip: If a button is disabled, the countdown note shows when it resets."
  },
  {
    title: "Habit Quest",
    text: "You get 4 random quests each day. Complete all 4 to lock the streak day and activate your streak shield.",
    tip: "Tip: Finish all quests before today’s reset countdown ends to keep your streak momentum."
  },
  {
    title: "Insights & Weekly Review",
    text: "Your logs feed into weekly insight bars and AI coaching so you can spot patterns quickly.",
    tip: "Tip: Use the Insights Next button to switch mood/water/sleep views."
  },
  {
    title: "Friends & Requests",
    text: "Open Account to send friend requests by username, accept or decline incoming requests, and view current friends.",
    tip: "Tip: Friends unlock shared progress insights so you can stay accountable together."
  },
  {
    title: "Account Controls",
    text: "Use the Account button to export/import data, change password, or clear app data when needed.",
    tip: "Tip: Account also contains your shortcuts box with OS-aware key combos."
  },
  {
    title: "Keyboard Shortcuts",
    text: "All dashboard cards have shortcuts. Hold {shortcut_mod}, then press two letters quickly to jump to a card, including Personalized Daily Plan, Weekly Startup Report, and Behavior Memory Graph.",
    tip: "Shortcut list is shown below.",
    showShortcutList: true
  },
  {
    title: "Bug Reporting",
    text: "Found a bug or glitch? Report it any time at <span class=\"support-email-highlight\">support.novafix@gmail.com</span>.",
    tip: "Tip: Include what happened and what you expected so we can fix it faster."
  }
];

function getWelcomeGuideSteps() {
  if (!IS_MOBILE_DEVICE) return WELCOME_GUIDE_STEPS;
  return WELCOME_GUIDE_STEPS.filter((step) => !step.showShortcutList);
}

function formatShortcutAwareText(text = "") {
  return String(text || "")
    .replaceAll("{shortcut_mod}", SHORTCUT_MOD_LABEL);
}

function getShortcutDisplay(def) {
  const keys = Array.isArray(def?.keys) ? def.keys : [];
  const first = String(keys[0] || "").toUpperCase();
  const second = String(keys[1] || "").toUpperCase();
  return `${SHORTCUT_MOD_LABEL} + ${first} + ${second}`;
}

function getShortcutOverviewText() {
  return CARD_SHORTCUTS
    .map((def) => {
      const keys = Array.isArray(def?.keys) ? def.keys : [];
      const first = escapeHtml(String(keys[0] || "").toUpperCase());
      const second = escapeHtml(String(keys[1] || "").toUpperCase());
      const mod = escapeHtml(SHORTCUT_MOD_LABEL);
      const label = escapeHtml(String(def?.label || "Card"));
      return `
        <div class="guide-shortcut-item">
          <div class="guide-shortcut-keys">
            <span class="guide-shortcut-key">${mod}</span>
            <span class="guide-shortcut-key">${first}</span>
            <span class="guide-shortcut-key">${second}</span>
          </div>
          <div class="guide-shortcut-label">${label}</div>
        </div>
      `;
    })
    .join("");
}

let keyboardShortcutsExpanded = false;

function toggleKeyboardShortcutsVisibility() {
  keyboardShortcutsExpanded = !keyboardShortcutsExpanded;
  renderKeyboardShortcutsBox();
}

if (keyboardShortcutsToggleBtn) {
  keyboardShortcutsToggleBtn.addEventListener("click", () => {
    toggleKeyboardShortcutsVisibility();
  });
}

function renderKeyboardShortcutsBox() {
  if (keyboardShortcutsBox) {
    keyboardShortcutsBox.style.display = IS_MOBILE_DEVICE ? "none" : "block";
  }
  if (IS_MOBILE_DEVICE) return;

  if (keyboardShortcutsSubtitle) {
    keyboardShortcutsSubtitle.innerText = `Showing ${IS_MAC_OS ? "macOS" : "Windows/Linux"} shortcuts for this device. Hold ${SHORTCUT_MOD_LABEL}, then press the two letters. Includes Personalized Daily Plan, Weekly Startup Report, and Behavior Memory Graph shortcuts.`;
  }
  if (!keyboardShortcutsList) return;
  const visibleShortcuts = keyboardShortcutsExpanded ? CARD_SHORTCUTS : CARD_SHORTCUTS.slice(0, 3);
  keyboardShortcutsList.innerHTML = visibleShortcuts.map((def) => `
    <div class="friend-row">
      <strong>${getShortcutDisplay(def)}</strong>
      <small>Jump to ${def.label}.</small>
    </div>
  `).join("");

  if (keyboardShortcutsToggleBtn) {
    const canExpand = CARD_SHORTCUTS.length > 3;
    keyboardShortcutsToggleBtn.style.display = canExpand ? "block" : "none";
    keyboardShortcutsToggleBtn.innerText = keyboardShortcutsExpanded ? "Hide shortcuts" : "Show all shortcuts";
  }
}

function getVerificationSentStorageKey(email) {
  return `novafix_verification_sent_${String(email || "").toLowerCase()}`;
}

function getVerificationLastSentMs(email) {
  try {
    const raw = localStorage.getItem(getVerificationSentStorageKey(email));
    const value = Number(raw);
    return Number.isFinite(value) ? value : 0;
  } catch (_) {
    return 0;
  }
}

function markVerificationSentNow(email) {
  try {
    localStorage.setItem(getVerificationSentStorageKey(email), String(Date.now()));
  } catch (_) {}
}

function canAutoResendVerification(email) {
  const lastSentMs = getVerificationLastSentMs(email);
  if (!lastSentMs) return true;
  return (Date.now() - lastSentMs) >= VERIFICATION_AUTO_RESEND_WINDOW_MS;
}

function getAuthBackoffStorageKey(scope, identifier) {
  return `${AUTH_BACKOFF_STORAGE_PREFIX}${String(scope || "global").toLowerCase()}_${String(identifier || "").toLowerCase().trim()}`;
}

function readAuthBackoffState(scope, identifier) {
  const defaultState = { failCount: 0, lockUntilMs: 0 };
  const key = getAuthBackoffStorageKey(scope, identifier);
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return defaultState;
    const parsed = JSON.parse(raw);
    const failCount = Math.max(0, Number(parsed?.failCount) || 0);
    const lockUntilMs = Math.max(0, Number(parsed?.lockUntilMs) || 0);
    return { failCount, lockUntilMs };
  } catch (_) {
    return defaultState;
  }
}

function writeAuthBackoffState(scope, identifier, state) {
  const key = getAuthBackoffStorageKey(scope, identifier);
  try {
    localStorage.setItem(key, JSON.stringify({
      failCount: Math.max(0, Number(state?.failCount) || 0),
      lockUntilMs: Math.max(0, Number(state?.lockUntilMs) || 0)
    }));
  } catch (_) {}
}

function clearAuthBackoffState(scope, identifier) {
  const key = getAuthBackoffStorageKey(scope, identifier);
  try {
    localStorage.removeItem(key);
  } catch (_) {}
  const normalizedScope = String(scope || "").toLowerCase();
  const normalizedIdentifier = String(identifier || "").toLowerCase().trim();
  if (normalizedScope === "signin" && normalizedIdentifier === signInBackoffCooldownEmail) {
    stopSignInBackoffCountdown();
  }
}

function getAuthBackoffRemainingMs(scope, identifier) {
  const state = readAuthBackoffState(scope, identifier);
  const normalizedScope = String(scope || "").toLowerCase();
  const failThreshold = normalizedScope === "signin"
    ? AUTH_SIGNIN_BACKOFF_FAIL_THRESHOLD
    : AUTH_BACKOFF_FAIL_THRESHOLD;
  if ((Number(state.failCount) || 0) < failThreshold) return 0;
  return Math.max(0, state.lockUntilMs - Date.now());
}

function getCurrentSignInBackoffEmail() {
  return String(emailInput?.value || "").trim().toLowerCase();
}

function getSignInBackoffMessage(remainingMs) {
  return `Too many failed sign-in attempts. Try again in ${formatCountdownClock(remainingMs)}.`;
}

function stopSignInBackoffCountdown() {
  if (signInBackoffCooldownIntervalId) {
    clearInterval(signInBackoffCooldownIntervalId);
    signInBackoffCooldownIntervalId = null;
  }
  signInBackoffCooldownEmail = "";
}

function updateSignInBackoffCountdown() {
  const lockedEmail = String(signInBackoffCooldownEmail || "").trim().toLowerCase();
  if (!lockedEmail || authMode !== "signin") {
    if (authModalErrorKind === "signin_backoff") hideAuthModalError();
    else stopSignInBackoffCountdown();
    return;
  }

  const currentEmail = getCurrentSignInBackoffEmail();
  if (currentEmail !== lockedEmail) {
    if (authModalErrorKind === "signin_backoff") hideAuthModalError();
    else stopSignInBackoffCountdown();
    return;
  }

  const remainingMs = getAuthBackoffRemainingMs("signin", lockedEmail);
  if (remainingMs <= 0) {
    if (authModalErrorKind === "signin_backoff") hideAuthModalError();
    else stopSignInBackoffCountdown();
    return;
  }

  showAuthModalError(getSignInBackoffMessage(remainingMs), "signin_backoff");
}

function startSignInBackoffCountdown(email, remainingMs = 0) {
  const lockedEmail = String(email || "").trim().toLowerCase();
  if (!lockedEmail) {
    stopSignInBackoffCountdown();
    return;
  }

  const safeRemaining = Math.max(0, Number(remainingMs) || getAuthBackoffRemainingMs("signin", lockedEmail));
  if (safeRemaining <= 0) {
    stopSignInBackoffCountdown();
    return;
  }

  signInBackoffCooldownEmail = lockedEmail;
  updateSignInBackoffCountdown();
  if (!signInBackoffCooldownIntervalId) {
    signInBackoffCooldownIntervalId = setInterval(updateSignInBackoffCountdown, 1000);
  }
}

function registerAuthBackoffFailure(scope, identifier) {
  const now = Date.now();
  const state = readAuthBackoffState(scope, identifier);
  const nextFailCount = Math.max(0, Number(state.failCount) || 0) + 1;
  let lockUntilMs = 0;

  const normalizedScope = String(scope || "").toLowerCase();
  const failThreshold = normalizedScope === "signin"
    ? AUTH_SIGNIN_BACKOFF_FAIL_THRESHOLD
    : AUTH_BACKOFF_FAIL_THRESHOLD;

  if (nextFailCount >= failThreshold) {
    const exponent = nextFailCount - failThreshold;
    const lockMs = Math.min(AUTH_BACKOFF_MAX_MS, AUTH_BACKOFF_BASE_MS * (2 ** exponent));
    lockUntilMs = now + lockMs;
  }

  writeAuthBackoffState(scope, identifier, { failCount: nextFailCount, lockUntilMs });
  return {
    failCount: nextFailCount,
    remainingMs: Math.max(0, lockUntilMs - now)
  };
}

function setResendVerificationButtonState() {
  if (!resendVerificationButton) return;
  if (verificationCooldownRemaining > 0) {
    resendVerificationButton.disabled = true;
    resendVerificationButton.innerText = `Resend Verification (${verificationCooldownRemaining}s)`;
    return;
  }
  resendVerificationButton.disabled = false;
  resendVerificationButton.innerText = "Resend Verification Email";
}

function startVerificationCooldown(seconds = 110) {
  verificationCooldownRemaining = Math.max(0, Number(seconds) || 0);
  setResendVerificationButtonState();
  if (verificationCooldownTimer) clearInterval(verificationCooldownTimer);
  if (verificationCooldownRemaining <= 0) return;

  verificationCooldownTimer = setInterval(() => {
    verificationCooldownRemaining = Math.max(0, verificationCooldownRemaining - 1);
    setResendVerificationButtonState();
    if (verificationCooldownRemaining <= 0) {
      clearInterval(verificationCooldownTimer);
      verificationCooldownTimer = null;
    }
  }, 1000);
}

function getAuthActionUrl() {
  return window.location.protocol === "file:"
    ? "https://novaafix-86912.firebaseapp.com"
    : window.location.origin;
}

async function sendVerificationEmailReliable(user) {
  const actionCodeSettings = {
    url: getAuthActionUrl(),
    handleCodeInApp: false
  };

  try {
    await sendEmailVerification(user, actionCodeSettings);
    return { ok: true, mode: "custom" };
  } catch (err) {
    const code = String(err?.code || "");
    const shouldFallback = code.includes("unauthorized-continue-uri") || code.includes("invalid-continue-uri") || code.includes("unauthorized-domain");
    if (!shouldFallback) {
      return { ok: false, error: err };
    }

    try {
      await sendEmailVerification(user);
      return { ok: true, mode: "default" };
    } catch (fallbackErr) {
      return { ok: false, error: fallbackErr };
    }
  }
}

async function sendPasswordResetReliable(email) {
  const actionCodeSettings = {
    url: getAuthActionUrl(),
    handleCodeInApp: false
  };

  try {
    await sendPasswordResetEmail(auth, email, actionCodeSettings);
    return { ok: true, mode: "custom" };
  } catch (err) {
    const code = String(err?.code || "");
    const shouldFallback = code.includes("unauthorized-continue-uri") || code.includes("invalid-continue-uri") || code.includes("unauthorized-domain");
    if (!shouldFallback) {
      return { ok: false, error: err };
    }

    try {
      await sendPasswordResetEmail(auth, email);
      return { ok: true, mode: "default" };
    } catch (fallbackErr) {
      return { ok: false, error: fallbackErr };
    }
  }
}

async function queueSourceImportSecurityAlert(sourceUserId, destinationUserEmail, destinationUserId = "", dbInstance = db) {
  const sourceUid = String(sourceUserId || "").trim();
  const destUid = String(destinationUserId || "").trim();
  if (!sourceUid || !dbInstance) return { ok: false, skipped: true };

  try {
    await addDoc(collection(dbInstance, "users", sourceUid, "securityAlerts"), {
      type: IMPORT_SECURITY_ALERT_TYPE,
      destinationEmail: String(destinationUserEmail || "").trim().toLowerCase() || null,
      destinationUid: destUid || null,
      seen: false,
      createdAt: serverTimestamp()
    });
    return { ok: true };
  } catch (err) {
    console.error("Failed to queue source import security alert:", err);
    return { ok: false, error: err };
  }
}

async function showPendingImportSecurityWarnings(userId) {
  const uid = String(userId || "").trim();
  if (!uid) return;

  try {
    const snapshot = await fsGetDocs(collection(db, "users", uid, "securityAlerts"));
    const pending = (snapshot?.docs || []).filter((docSnap) => {
      const data = docSnap.data() || {};
      const isImportAlert = data.type === IMPORT_SECURITY_ALERT_TYPE && !data.seen;
      if (!isImportAlert) return false;
      
      // Skip warning if data was imported INTO the same account it was exported FROM
      const destUid = String(data.destinationUid || "").trim();
      if (destUid && destUid === uid) return false;
      
      return true;
    });

    if (!pending.length) return;

    alert("⚠️ Security warning: your data snapshot was imported into another account. If this wasn't you, change your password from Account → Change Password.");

    await Promise.all(pending.map((docSnap) => fsUpdateDoc(docSnap.ref, {
      seen: true,
      seenAt: serverTimestamp()
    }).catch((err) => structuredLog('warn', 'securityAlerts.update', err?.message || String(err), { ref: docSnap.ref?.path }))));
  } catch (err) {
    console.warn("Could not load import security warnings:", err);
  }
}

function renderWelcomeGuideStep() {
  if (!welcomeGuideModal || !guideStepCounter || !guideStepTitle || !guideStepText || !guideStepTip || !guideDots || !guideNextBtn || !guidePrevBtn) return;
  const steps = getWelcomeGuideSteps();
  const total = steps.length;
  if (!total) return;
  const safeIndex = Math.max(0, Math.min(total - 1, welcomeGuideStepIndex));
  const current = steps[safeIndex];
  guideStepCounter.innerText = `Step ${safeIndex + 1}/${total}`;
  guideStepTitle.innerText = current.title;
  const guideText = formatShortcutAwareText(current.text);
  if (/<[^>]+>/.test(guideText)) guideStepText.innerHTML = guideText;
  else guideStepText.innerText = guideText;
  if (current.showShortcutList && !IS_MOBILE_DEVICE) {
    guideStepTip.style.whiteSpace = "normal";
    guideStepTip.classList.add("shortcut-mode");
    guideStepTip.innerHTML = `<div class="guide-shortcut-list">${getShortcutOverviewText()}</div>`;
  } else {
    guideStepTip.style.whiteSpace = "normal";
    guideStepTip.classList.remove("shortcut-mode");
    guideStepTip.innerText = formatShortcutAwareText(current.tip);
  }
  guidePrevBtn.disabled = safeIndex === 0;
  guideNextBtn.innerText = safeIndex === total - 1 ? "Finish" : "Next";

  guideDots.innerHTML = "";
  for (let i = 0; i < total; i += 1) {
    const dot = document.createElement("span");
    dot.className = `welcome-guide-dot${i === safeIndex ? " active" : ""}`;
    guideDots.appendChild(dot);
  }
}

function openWelcomeGuide(userId = "") {
  if (!welcomeGuideModal) return;
  welcomeGuideUserId = String(userId || welcomeGuideUserId || "");
  welcomeGuideStepIndex = 0;
  renderWelcomeGuideStep();
  welcomeGuideModal.style.display = "flex";
  ensureAppBackGuardState("welcome-guide", true);
}

function closeWelcomeGuide() {
  if (!welcomeGuideModal) return;
  welcomeGuideModal.style.display = "none";
}

function isEditableElementActive() {
  const active = document.activeElement;
  if (!active) return false;
  const tagName = String(active.tagName || "").toLowerCase();
  if (tagName === "input" || tagName === "textarea" || tagName === "select") return true;
  return !!active.isContentEditable;
}

const activeShortcutKeys = new Set();
let activeShortcutLastKeyAt = 0;
let wellnessActionBoost = 0;
let crashRiskActionRelief = 0;

function resetActiveShortcutSequence() {
  activeShortcutKeys.clear();
  activeShortcutLastKeyAt = 0;
}

function getShortcutLetterFromEvent(event) {
  const code = String(event?.code || "");
  const match = code.match(/^Key([A-Z])$/);
  if (!match) return "";
  return String(match[1] || "").toLowerCase();
}

function activateCardShortcut(definition) {
  if (!dashboard || getComputedStyle(dashboard).display === "none") return;
  if (!definition) return;

  const cards = dashboard.querySelectorAll(".card");
  const card = cards[Number(definition.cardIndex)];
  if (!card) return;

  if (accountPanel && accountPanel.style.display === "block") {
    closeAccountPanel();
  }

  scrollToCardWithShortcutAnimation(card);

  const firstFocusable = card.querySelector("input, textarea, select, button");
  if (firstFocusable && typeof firstFocusable.focus === "function") {
    setTimeout(() => {
      try {
        firstFocusable.focus({ preventScroll: true });
      } catch (_) {
        firstFocusable.focus();
      }
    }, 160);
  }
}

function scrollToCardWithShortcutAnimation(card, options = {}) {
  if (!card) return;
  scrollCardToViewportCenterReliably(card, options);
  if (card.classList) {
    card.classList.remove("shortcut-focus");
    void card.offsetWidth;
    card.classList.add("shortcut-focus");
    setTimeout(() => {
      try {
        card.classList.remove("shortcut-focus");
      } catch (_) {}
    }, 1250);
  }
}

function scrollCardToViewportCenterReliably(card, options = {}) {
  const target = card;
  if (!target || typeof target.getBoundingClientRect !== "function") return;

  const repeats = Math.max(1, Number(options.repeats) || 5);
  const delayMs = Math.max(40, Number(options.delayMs) || 120);
  const viewportHeight = Math.max(window.innerHeight || 0, 1);
  const targetRect = target.getBoundingClientRect();
  const absoluteTop = targetRect.top + window.scrollY;
  const desiredTop = Math.max(0, absoluteTop - ((viewportHeight - targetRect.height) / 2));

  const runScroll = (behavior) => {
    try {
      window.scrollTo({ top: desiredTop, behavior });
    } catch (_) {
      window.scrollTo(0, desiredTop);
    }
  };

  runScroll("smooth");
  for (let i = 1; i < repeats; i += 1) {
    setTimeout(() => runScroll(i === repeats - 1 ? "auto" : "smooth"), i * delayMs);
  }
}

function handleGlobalShortcut(event) {
  if (!event.altKey) {
    resetActiveShortcutSequence();
    return;
  }

  const letter = getShortcutLetterFromEvent(event);
  if (!letter) return;

  // Alt + letter shortcuts should never type into focused inputs.
  event.preventDefault();
  event.stopPropagation();
  if (event.repeat) return;

  const now = Date.now();
  const sequenceTimeoutMs = 1600;
  if (now - activeShortcutLastKeyAt > sequenceTimeoutMs) {
    resetActiveShortcutSequence();
  }
  activeShortcutLastKeyAt = now;

  if (!activeShortcutKeys.has(letter)) {
    activeShortcutKeys.add(letter);
    if (activeShortcutKeys.size > 2) {
      const currentKeys = Array.from(activeShortcutKeys);
      activeShortcutKeys.clear();
      activeShortcutKeys.add(currentKeys[currentKeys.length - 2]);
      activeShortcutKeys.add(currentKeys[currentKeys.length - 1]);
    }
  }

  if (activeShortcutKeys.size < 2) return;

  const [first, second] = Array.from(activeShortcutKeys);
  const matchedShortcut = CARD_SHORTCUTS.find((def) => def.keys[0] === first && def.keys[1] === second);
  if (!matchedShortcut) return;

  event.preventDefault();
  activateCardShortcut(matchedShortcut);
  resetActiveShortcutSequence();
}

function handleGlobalShortcutKeyup(event) {
  const releasedKey = String(event.key || "").toLowerCase();
  if (releasedKey === "alt") {
    resetActiveShortcutSequence();
  }
}

document.addEventListener("keydown", handleGlobalShortcut);
document.addEventListener("keyup", handleGlobalShortcutKeyup);
window.addEventListener("blur", () => {
  resetActiveShortcutSequence();
});

renderKeyboardShortcutsBox();

async function completeWelcomeGuide() {
  const activeUserId = String(welcomeGuideUserId || auth.currentUser?.uid || "");
  if (activeUserId) {
    try {
      await safeSetDoc(doc(db, "users", activeUserId, "settings", "onboarding"), {
        welcomeGuideCompleted: true,
        welcomeGuideVersion: WELCOME_GUIDE_VERSION,
        welcomeGuideCompletedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      }, 'onboarding', { merge: true });
    } catch (_) {}
  }
  closeWelcomeGuide();
}

async function nextWelcomeGuideStep() {
  const total = getWelcomeGuideSteps().length;
  if (welcomeGuideStepIndex >= total - 1) {
    await completeWelcomeGuide();
    return;
  }
  welcomeGuideStepIndex += 1;
  renderWelcomeGuideStep();
}

function prevWelcomeGuideStep() {
  if (welcomeGuideStepIndex <= 0) return;
  welcomeGuideStepIndex -= 1;
  renderWelcomeGuideStep();
}

async function skipWelcomeGuide() {
  await completeWelcomeGuide();
}

function openWelcomeGuideFromHelp() {
  const activeUserId = String(auth.currentUser?.uid || "").trim();
  closeAccountPanel();
  openWelcomeGuide(activeUserId);
}

function showTosError(message = "") {
  if (!tosError) return;
  tosError.innerText = String(message || "").trim();
}

function openTosModal(userId = "") {
  if (!tosModal) return;
  tosPendingUserId = String(userId || "").trim();
  showTosError("");
  if (tosAgreeBtn) tosAgreeBtn.disabled = false;
  // Keep auth modal hidden and show dashboard shell behind TOS gate.
  if (signInModal) signInModal.style.display = "none";
  if (dashboard) {
    dashboard.style.display = "grid";
    dashboard.classList.add("preload-shell");
  }
  setPageTitle("dashboard");
  tosModal.style.display = "flex";
  ensureAppBackGuardState("tos-gate", true);
}

function closeTosModal(force = false) {
  if (!tosModal) return;
  if (!force) return;
  tosModal.style.display = "none";
  ensureAppBackGuardState("tos-gate", false);
}

function resolveTosPendingWaiters(value) {
  const waiters = Array.isArray(tosResolvePendingQueue)
    ? [...tosResolvePendingQueue]
    : [];
  tosResolvePendingQueue = [];
  waiters.forEach((resolve) => {
    try {
      if (typeof resolve === "function") resolve(value);
    } catch (_) {}
  });
}

async function acceptTosAgreement() {
  const userId = String(tosPendingUserId || auth.currentUser?.uid || "").trim();
  if (!userId) {
    showTosError("Your session expired. Please sign in again.");
    return;
  }

  if (tosAgreeBtn) tosAgreeBtn.disabled = true;
  showTosError("");

  let retries = 0;
  const maxRetries = 2;

  async function attemptSave() {
    try {
      const activeUser = auth.currentUser;
      if (!activeUser?.uid || String(activeUser.uid) !== userId) {
        const authRaceErr = new Error("Auth session is not ready.");
        authRaceErr.code = "unauthenticated";
        throw authRaceErr;
      }

      await safeSetDoc(doc(db, "users", userId, "settings", "onboarding"), {
        tosAccepted: true,
        tosAcceptedAt: serverTimestamp(),
        tosVersion: TOS_VERSION,
        updatedAt: serverTimestamp()
      }, 'onboarding', { merge: true });

      closeTosModal(true);
      tosPendingUserId = "";
      resolveTosPendingWaiters(true);
      return true;
    } catch (err) {
      const authCode = String(err?.code || "").toLowerCase();
      const authRace = authCode.includes("unauthenticated") || authCode.includes("auth/");
      if (isFirestorePermissionDeniedError(err) || authRace) {
        if (retries < maxRetries) {
          retries++;
          await new Promise(r => setTimeout(r, 350 * retries));
          return await attemptSave();
        }
        showTosError(authRace ? "Session refresh issue. Please tap Agree again." : "Permission issue. Contact support if this persists.");
      } else if (err?.code === "unavailable" || err?.code === "failed-precondition") {
        showTosError("Connection issue. Please try again.");
      } else {
        notifyFirestoreError(err);
        showTosError("Could not save agreement. Please try again.");
      }
      return false;
    }
  }

  await attemptSave();
  if (tosAgreeBtn) tosAgreeBtn.disabled = false;
}

async function ensureTosAccepted(userId) {
  const activeUserId = String(userId || "").trim();
  if (!activeUserId) return false;
  
  // Guard: ensure auth state is stable before reading
  if (!auth.currentUser?.uid) {
    structuredLog('warn', 'tos.auth_check', 'User logged out during TOS check');
    return false;
  }

  try {
    const snap = await fsGetDoc(doc(db, "users", activeUserId, "settings", "onboarding"), 'onboarding');
    const data = snap.exists ? (snap.data || {}) : {};
    if (data.tosAccepted === true) return true;
  } catch (err) {
    structuredLog('warn', 'tos.read', err?.message || String(err), { userId: activeUserId });
    // If onboarding read fails, keep gate visible and require explicit agree action.
  }

  openTosModal(activeUserId);
  return await new Promise((resolve) => {
    tosResolvePendingQueue.push(resolve);
  });
}

function openReportRedirectConfirm() {
  if (!reportRedirectConfirmModal) return;
  reportRedirectConfirmModal.style.display = "flex";
  ensureAppBackGuardState("report-redirect-confirm", true);
}

function closeReportRedirectConfirm(event, force = false) {
  if (!reportRedirectConfirmModal) return;
  if (!force && event && event.target !== reportRedirectConfirmModal) return;
  reportRedirectConfirmModal.style.display = "none";
}

function continueReportRedirect() {
  closeReportRedirectConfirm(null, true);
  window.open("https://mail.google.com/mail/?view=cm&fs=1&to=support.novafix@gmail.com", "_blank", "noopener,noreferrer");
}

async function maybeShowWelcomeGuide(userId) {
  const activeUserId = String(userId || "").trim();
  if (!activeUserId || !welcomeGuideModal || welcomeGuideCheckedThisSession) return;
  
  // Guard: verify auth state stability
  if (auth.currentUser?.uid !== activeUserId) {
    structuredLog('warn', 'welcome.auth_mismatch', 'Auth state changed before welcome guide');
    return;
  }
  
  welcomeGuideCheckedThisSession = true;
  welcomeGuideUserId = activeUserId;

  try {
    const snap = await fsGetDoc(doc(db, "users", activeUserId, "settings", "onboarding"), 'onboarding');
    const data = snap.exists ? (snap.data || {}) : {};
    
    // Defensive: check if data is actually an object
    if (typeof data !== 'object' || data === null) {
      structuredLog('warn', 'welcome.data_shape', 'Onboarding data malformed', { type: typeof data });
      openWelcomeGuide(activeUserId);
      return;
    }
    
    if (!data.welcomeGuideCompleted) {
      const [waterSnap, weeklySnap] = await Promise.all([
        fsGetDoc(doc(db, "users", activeUserId, "settings", "water"), 'water'),
        fsGetDoc(doc(db, "users", activeUserId, "settings", "weeklyTargets"), 'weeklyTargets')
      ]);

      if (!waterSnap.exists) {
        await fsSetDoc(doc(db, "users", activeUserId, "settings", "water"), {
          goal: 8,
          goalDateKey: getTodayKey(),
          lastResetDateKey: getTodayKey(),
          updatedAt: serverTimestamp()
        }, 'water', { merge: true });
      }

      if (!weeklySnap.exists) {
        await fsSetDoc(doc(db, "users", activeUserId, "settings", "weeklyTargets"), {
          waterGoal: 8,
          sleepTarget: 8,
          taskTarget: 5,
          updatedAt: serverTimestamp()
        }, 'weeklyTargets', { merge: true });
      }

      openWelcomeGuide(activeUserId);
    }
  } catch (err) {
    structuredLog('warn', 'welcome.init', err?.message || String(err), { userId: activeUserId });
    openWelcomeGuide(activeUserId);
  }
}

function toggleAuth(){
  stopSignInBackoffCountdown();
  if (authMode === "signin") ensureAppBackGuardState("auth-signup", true);
  authMode=authMode==="signin"?"signup":"signin";
  authEmailProviderCheckSequence += 1;
  if (authEmailProviderCheckTimer) {
    clearTimeout(authEmailProviderCheckTimer);
    authEmailProviderCheckTimer = null;
  }
  if (usernameLiveCheckTimer) {
    clearTimeout(usernameLiveCheckTimer);
    usernameLiveCheckTimer = null;
  }
  usernameLiveCheckSequence += 1;
  const title=document.getElementById("modalTitle");
  const button=document.getElementById("actionButton");
  const toggleText=document.getElementById("toggleText");
  hideAuthModalError();
  if(authMode==="signup"){
    title.innerText="Create a NovaFix Account 🌟";
    button.innerText="Sign Up";
    googleAuthButton.innerText = "Sign Up with Google";
    toggleText.innerText="Already have an account? Sign In";
    usernameInput.style.display = "block";
    if (displayNameInput) displayNameInput.style.display = "block";
    if (resetPasswordButton) resetPasswordButton.style.display = "none";
    setPageTitle("signup");
  } else {
    title.innerText="Welcome to NovaFix 🌟";
    button.innerText="Sign In";
    googleAuthButton.innerText = "Sign In with Google";
    toggleText.innerText="Don't have an account? Sign Up";
    usernameInput.style.display = "none";
    if (resetPasswordButton) resetPasswordButton.style.display = "block";
    if (displayNameInput) {
      displayNameInput.style.display = "none";
      displayNameInput.value = "";
    }
    setPageTitle("signin");
  }
  setResendVerificationButtonState();
}

async function resendVerificationEmailFromModal() {
  const email = emailInput.value.trim().toLowerCase();
  const password = passwordInput.value.trim();
  const error = document.getElementById("signInError");
  error.style.display = "none";

  if (verificationCooldownRemaining > 0) return;

  if (!email || !password) {
    error.style.display = "block";
    error.style.color = "#ff6b6b";
    error.innerText = "Enter email and password to resend verification.";
    return;
  }

  try {
    showAuthModalError("Hang on, resending verification email...", "auth_progress", "#9fd0ff");
    const credential = await signInWithEmailAndPassword(auth, email, password);
    await credential.user.reload();

    if (credential.user.emailVerified) {
      error.style.display = "block";
      error.style.color = "#7CFFB2";
      error.innerText = "This email is already verified. You can sign in now.";
      await signOut(auth);
      return;
    }

    const verifyResult = await sendVerificationEmailReliable(credential.user);
    await signOut(auth);

    if (!verifyResult.ok) {
      throw verifyResult.error;
    }

    markVerificationSentNow(email);
    startVerificationCooldown(110);
    error.style.display = "block";
    error.style.color = "#7CFFB2";
    error.innerText = "Verification email resent. It may take up to 10 minutes; check Inbox/Spam/Promotions.";
  } catch (err) {
    error.style.display = "block";
    error.style.color = "#ff6b6b";
    error.innerText = err?.message || "Could not resend verification email.";
  } finally {
    clearAuthProgressMessage();
  }
}

async function handleAuth() {
  const username = usernameInput.value.trim();
  const displayNameRaw = String(displayNameInput?.value || "").trim();
  let usernameKey = normalizeUsernameForLookup(username);
  const email = emailInput.value.trim().toLowerCase();
  const password = passwordInput.value.trim();
  const error = document.getElementById("signInError");
  let startedSignupAuthFlow = false;

  if (!email || !password) {
    showAuthModalError("Email and password are required!", "credentials");
    return;
  }

  if (authMode === "signup") {
    const validation = validateSignupUsername(username);
    if (!validation.ok) {
      showAuthModalError(validation.message, "username");
      return;
    }
    const displayValidation = validateSignupDisplayName(displayNameRaw);
    if (!displayValidation.ok) {
      showAuthModalError(displayValidation.message, "display_name");
      return;
    }
    usernameKey = validation.normalized;
  }

  const signupDisplayName = normalizeDisplayNameValue(displayNameRaw);

  if (authMode === "signin") {
    const remaining = getAuthBackoffRemainingMs("signin", email);
    if (remaining > 0) {
      startSignInBackoffCountdown(email, remaining);
      return;
    }
  }

  try {
    showAuthModalError(
      authMode === "signup" ? "Hang on, signing up..." : "Hang on, signing in...",
      "auth_progress",
      "#9fd0ff"
    );
    if (authMode === "signup") {
      try {
        const usernameExists = await usernameExistsLiveInFirestore(usernameKey);
        if (usernameExists) {
          showAuthModalError("This username already exists. Choose a different username.", "username_exists");
          return;
        }
      } catch (lookupErr) {
        if (!isFirestorePermissionDeniedError(lookupErr)) {
          showAuthModalError(lookupErr?.message || "Could not verify username right now.");
          return;
        }
        // If pre-check is blocked for unauthenticated signup, continue.
        // The transactional claim below is the source of truth for uniqueness.
      }

      signupFlowInProgress = true;
      suppressUnverifiedSigninPromptUntilMs = Date.now() + (2 * 60 * 1000);
      startedSignupAuthFlow = true;
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      try {
        await claimUsernameDirectoryEntry(userCredential.user.uid, usernameKey, email, signupDisplayName);
      } catch (claimErr) {
        const claimCode = String(claimErr?.message || "");
        if (claimCode === "USERNAME_TAKEN") {
          try { await deleteUser(userCredential.user); } catch (_) {}
          await signOut(auth).catch((err) => structuredLog('warn', 'auth.signout.2', err?.message || String(err)));
          showAuthModalError("This username already exists. Choose a different username.", "username_exists");
          return;
        }
        if (isFirestorePermissionDeniedError(claimErr)) {
          try { await deleteUser(userCredential.user); } catch (_) {}
          await signOut(auth).catch((err) => structuredLog('warn', 'auth.signout.3', err?.message || String(err)));
          showAuthModalError("Username setup is blocked by Firestore rules. Allow users to write usernameDirectory, then try again.");
          return;
        }
        throw claimErr;
      }

      await updateProfile(userCredential.user, { displayName: signupDisplayName });
      const displayNameChangeAppliedAtMs = getServerNowDate().getTime();
      await safeSetDoc(doc(db, "users", userCredential.user.uid, "settings", "profile"), {
        // For email/password signup, Google identity setup is not yet completed.
        googleIdentitySetupCompleted: false,
        displayNameDashboardChangedAt: new Date(),
        displayNameDashboardChangedAtMs: displayNameChangeAppliedAtMs,
        displayNameDashboardCooldownUntilMs: displayNameChangeAppliedAtMs + DISPLAY_NAME_EDIT_COOLDOWN_MS,
        updatedAt: new Date()
      }, 'profile', { merge: true });
      await upsertUserDirectoryProfile(userCredential.user, {
        username,
        displayName: signupDisplayName
      });
      const verifyResult = await sendVerificationEmailReliable(userCredential.user);

      await signOut(auth);
      authMode = "signin";
      const title = document.getElementById("modalTitle");
      const button = document.getElementById("actionButton");
      const toggleText = document.getElementById("toggleText");
      title.innerText = "Welcome to NovaFix 🌟";
      button.innerText = "Sign In";
      googleAuthButton.innerText = "Sign In with Google";
      toggleText.innerText = "Don't have an account? Sign Up";
      usernameInput.style.display = "none";
      if (resetPasswordButton) resetPasswordButton.style.display = "block";
      if (displayNameInput) {
        displayNameInput.style.display = "none";
        displayNameInput.value = "";
      }
      setPageTitle("signin");

      clearAuthProgressMessage();
      authModalErrorKind = "";
      error.style.display = "block";
      error.style.color = verifyResult.ok ? "#7CFFB2" : "#ff6b6b";
      error.innerText = verifyResult.ok
        ? "Account created. Verification email sent. Check Inbox/Spam/Promotions, then sign in."
        : `Account created, but verification email failed: ${verifyResult.error?.message || "Please use Forgot Password flow or try again later."}`;
      if (verifyResult.ok) {
        markVerificationSentNow(email);
        startVerificationCooldown(110);
      }
      return;
    } else {
      markPendingRequestLoginAlertForNextSessionStart();
      const credential = await signInWithEmailAndPassword(auth, email, password);
      await credential.user.reload();
      clearAuthBackoffState("signin", email);
      let skipEmailVerificationGate = isGoogleProviderUser(credential.user);
      if (!skipEmailVerificationGate && !credential.user.emailVerified) {
        skipEmailVerificationGate = await isGoogleRegisteredEmail(email);
      }

      if (!credential.user.emailVerified && !skipEmailVerificationGate) {
        let verifyResult = { ok: true, skipped: true };
        if (canAutoResendVerification(email)) {
          verifyResult = await sendVerificationEmailReliable(credential.user);
          if (verifyResult.ok) markVerificationSentNow(email);
        }
        await signOut(auth);
        clearPendingRequestLoginAlertFlag();
        error.style.display = "block";
        error.style.color = "#ff6b6b";
        error.innerText = verifyResult.ok
          ? (verifyResult.skipped
            ? "Please verify your email before signing in. A verification email was recently sent — check Inbox/Spam/Promotions."
            : "Please verify your email before signing in. Verification email sent.")
          : `Please verify your email before signing in. Could not send verification email: ${verifyResult.error?.message || "try again later."}`;
        if (verifyResult.ok) startVerificationCooldown(110);
        return;
      }
    }
  } catch (err) {
    if (authMode === "signin") {
      clearPendingRequestLoginAlertFlag();
    }
    const code = String(err?.code || "");
    const credentialError = code === "auth/invalid-credential"
      || code === "auth/user-not-found"
      || code === "auth/wrong-password"
      || code === "auth/invalid-email";

    if (authMode === "signin" && credentialError) {
      const googleOnlyEmail = await isGoogleOnlySignInEmail(email);
      if (googleOnlyEmail) {
        showAuthModalError("This email was signed up with Google. Use Sign In with Google to continue.", "credentials");
        return;
      }
    }

    if (authMode === "signin") {
      const authFailure = credentialError || code === "auth/too-many-requests";

      if (authFailure) {
        const backoff = registerAuthBackoffFailure("signin", email);
        if (backoff.remainingMs > 0) {
          startSignInBackoffCountdown(email, backoff.remainingMs);
          return;
        }
      }
    }

    if (credentialError) {
      showAuthModalError("The email or password you entered is incorrect.", "credentials");
      return;
    }

    if (authMode === "signup" && code === "auth/email-already-in-use") {
      showAuthModalError("Email already exists. Sign in instead or use a different email.", "credentials");
      return;
    }

    if (authMode === "signup" && code === "auth/weak-password") {
      showAuthModalError("Password must be at least 6 characters.", "credentials");
      return;
    }

    showAuthModalError(err?.message || "Could not sign in right now.");
  } finally {
    if (startedSignupAuthFlow) {
      signupFlowInProgress = false;
    }
  }
}

async function signOutUser() {
  const shouldSignOut = confirm("Sign out of your account now?");
  if (!shouldSignOut) return;

  const signingOutUserId = String(auth.currentUser?.uid || lastAuthenticatedUserId || "").trim();
  closeAccountPanel();
  closeAddFriendModal(null, true);
  const pendingToastId = showPendingToast("Hang on, signing out...");
  try {
    await signOut(auth);
    if (signingOutUserId) {
      clearCrashAlertDismissal(signingOutUserId);
      lastAuthenticatedUserId = "";
    }
  } catch (_) {
    showToast("Could not sign out right now.");
  } finally {
    clearPendingToast(pendingToastId);
  }
}

function isLocalhostGoogleAuthBlocked() {
  const host = String(window.location.hostname || "").toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

async function handleGoogleAuth() {
  const error = document.getElementById("signInError");
  error.style.display = "none";

  if (window.location.protocol === "file:" || isLocalhostGoogleAuthBlocked()) {
    clearPendingRequestLoginAlertFlag();
    showAuthModalError(
      "Google sign-in is disabled on local preview. Use email/password here, or test Google auth on the hosted site.",
      "credentials"
    );
    return;
  }

  try {
    showAuthModalError(
      authMode === "signup"
        ? "Hang on, signing up with Google..."
        : "Hang on, signing in with Google...",
      "auth_progress",
      "#9fd0ff"
    );
    markPendingRequestLoginAlertForNextSessionStart();
    await signInWithPopup(auth, googleProvider);
  } catch (err) {
    clearAuthProgressMessage();
    clearPendingRequestLoginAlertFlag();
    const errCode = String(err?.code || "").toLowerCase();
    if (errCode === "auth/popup-closed-by-user" || errCode === "auth/cancelled-popup-request") {
      hideAuthModalError();
      return;
    }
    const currentOrigin = window.location.origin || "unknown-origin";
    const currentHost = window.location.hostname || "unknown-host";
    const isUnauthorizedDomain = (err?.code || "").includes("unauthorized-domain");
    error.style.display = "block";
    error.innerText = isUnauthorizedDomain
      ? "Unauthorized domain. Current origin: " + currentOrigin + ". Add '" + currentHost + "' in Firebase Auth > Settings > Authorized domains, then hard refresh."
      : (err.message || "Google authentication failed.");
  } finally {
    clearAuthProgressMessage();
  }
}

async function sendResetPasswordEmail() {
  const email = emailInput.value.trim().toLowerCase();
  const error = document.getElementById("signInError");
  error.style.display = "none";

  if (!email) {
    error.style.display = "block";
    error.style.color = "#ff6b6b";
    error.innerText = "Enter your email first, then tap Reset Password.";
    return;
  }

  try {
    showAuthModalError("Hang on, sending reset password email...", "auth_progress", "#9fd0ff");
    const methods = await fetchSignInMethodsForEmail(auth, email);
    if (methods.includes("google.com") && !methods.includes("password")) {
      error.style.display = "block";
      error.style.color = "#ff6b6b";
      error.innerText = "This email uses Google sign-in. Use Google login (no password to reset).";
      return;
    }

    const resetResult = await sendPasswordResetReliable(email);
    if (!resetResult.ok) {
      throw resetResult.error;
    }
    error.style.display = "block";
    error.style.color = "#7CFFB2";
    error.innerText = "Password reset email sent. Check Inbox/Spam/Promotions.";
  } catch (err) {
    error.style.display = "block";
    error.style.color = "#ff6b6b";
    error.innerText = err?.message || "Could not send reset email.";
    console.error("Reset password error:", err?.code || err);
  } finally {
    clearAuthProgressMessage();
  }
}

async function sendAccountResetPasswordEmail() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const cooldownRemaining = accountPasswordResetCooldownUntilMs - getServerNowDate().getTime();
  if (cooldownRemaining > 0) {
    showToast(`Please wait ${formatCountdownClock(cooldownRemaining)} before sending another reset email.`);
    applyAccountPasswordResetCooldownUI(cooldownRemaining);
    return;
  }

  const email = (user.email || accountEmail?.innerText || "").trim().toLowerCase();
  if (!email || email === "-") {
    showToast("No email found for this account.");
    return;
  }

  let pendingToastId = 0;
  try {
    pendingToastId = showPendingToast("Hang on, sending reset password email...");
    const methods = await fetchSignInMethodsForEmail(auth, email);
    if (methods.includes("google.com") && !methods.includes("password")) {
      clearPendingToast(pendingToastId);
      pendingToastId = 0;
      showToast("This account uses Google sign-in, so no password reset is needed.");
      return;
    }

    const resetResult = await sendPasswordResetReliable(email);
    if (!resetResult.ok) {
      throw resetResult.error;
    }
    startAccountPasswordResetCooldown(PASSWORD_RESET_COOLDOWN_MS);
    clearPendingToast(pendingToastId);
    pendingToastId = 0;
    showToast(`Password reset email sent to ${email}.`);
  } catch (err) {
    console.error("Account reset password error:", err?.code || err);
    clearPendingToast(pendingToastId);
    pendingToastId = 0;
    showToast(err?.message || "Could not send reset email.");
  } finally {
    clearPendingToast(pendingToastId);
    if (!pendingToastId) {
      setTimeout(() => {
        if (activePendingToastId === 0) hideToast();
      }, 0);
    }
  }
}

async function editAccountDisplayName() {
  const user = auth.currentUser;
  if (!user?.uid) {
    showToast("Please sign in first.");
    return;
  }

  const cooldownRemaining = Math.max(0, displayNameEditCooldownUntilMs - getServerNowDate().getTime());
  if (cooldownRemaining > 0) {
    setAccountDisplayNameError(`Display name can be changed again in ${formatDisplayNameCooldownClock(cooldownRemaining)}.`);
    return;
  }

  const refreshedCooldownRemaining = await getDisplayNameEditCooldownRemainingFromProfile(user.uid, true);
  if (refreshedCooldownRemaining > 0) {
    startDisplayNameEditCooldown(refreshedCooldownRemaining);
    setAccountDisplayNameError(`Display name can be changed again in ${formatDisplayNameCooldownClock(refreshedCooldownRemaining)}.`);
    return;
  }

  const currentDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || user.displayName || "")
    || "";
  let nextDisplayName = "";
  let promptSeed = currentDisplayName;
  while (true) {
    const nextRaw = prompt(
      "Enter display name (1-20 chars; letters, numbers, spaces, underscores, dashes).",
      promptSeed
    );
    if (nextRaw === null) return;

    const nextTrimmed = String(nextRaw || "").trim();
    if (!nextTrimmed) {
      alert("Display name is required.");
      promptSeed = "";
      continue;
    }

    const validation = validateSignupDisplayName(nextTrimmed);
    if (!validation.ok) {
      alert(validation.message || "Invalid display name.");
      promptSeed = nextTrimmed;
      continue;
    }

    nextDisplayName = validation.normalized || normalizeDisplayNameValue(nextTrimmed);
    if (!nextDisplayName) {
      alert("Display name is required.");
      promptSeed = nextTrimmed;
      continue;
    }
    break;
  }

  if (nextDisplayName === currentDisplayName) {
    showToast("Display name is unchanged.");
    return;
  }

  try {
    await updateProfile(user, { displayName: nextDisplayName });
    if (accountDisplayName) accountDisplayName.innerText = nextDisplayName;
    setAccountDisplayNameError("");

    const cooldownUntilMs = getServerNowDate().getTime() + DISPLAY_NAME_EDIT_COOLDOWN_MS;
    startDisplayNameEditCooldown(DISPLAY_NAME_EDIT_COOLDOWN_MS);

    await upsertUserDirectoryProfile(user, {
      displayName: nextDisplayName
    });

    await safeSetDoc(doc(db, "users", user.uid, "settings", "profile"), {
      displayName: nextDisplayName,
      displayNameDashboardChangedAt: serverTimestamp(),
      displayNameDashboardChangedAtMs: getServerNowDate().getTime(),
      displayNameDashboardCooldownUntilMs: cooldownUntilMs,
      updatedAt: serverTimestamp()
    }, 'profile', { merge: true });

    const socialProfile = buildUserSocialProfileSnapshot(user);
    await Promise.allSettled([
      safeSetDoc(doc(db, "users", user.uid, "social", "profile"), {
        ...socialProfile,
        updatedAt: serverTimestamp()
      }, null, { merge: true }),
      syncSocialProfileToFriendQueue(user, socialProfile),
      syncSocialProfileToFriendsMirror(user, socialProfile)
    ]);

    await Promise.allSettled([
      loadFriendRequests(user.uid),
      loadSentFriendRequests(user.uid),
      loadFriendsInsights(user.uid)
    ]);

    showToast("Display name updated.");
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function setAddFriendError(message = "") {
  if (!addFriendError) return;
  addFriendError.innerText = String(message || "");
  addFriendError.style.display = message ? "block" : "none";
}

function setAddFriendBusy(isBusy) {
  addFriendSubmitting = !!isBusy;
  if (addFriendConfirmBtn) {
    addFriendConfirmBtn.disabled = !!isBusy;
    addFriendConfirmBtn.innerText = isBusy ? "Sending..." : "Send Request";
  }
  if (addFriendCancelBtn) addFriendCancelBtn.disabled = !!isBusy;
  if (addFriendEmailInput) addFriendEmailInput.disabled = !!isBusy;
}

function closeAddFriendModal(event, force = false) {
  if (event?.target && event.target !== addFriendModal) return;
  if (addFriendSubmitting && !force) return;
  if (addFriendModal) addFriendModal.style.display = "none";
  setAddFriendError("");
}

function startAddFriendRequest() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }
  if (addFriendModal) addFriendModal.style.display = "flex";
  ensureAppBackGuardState("add-friend", true);
  setAddFriendBusy(false);
  setAddFriendError("");
  if (addFriendEmailInput) {
    addFriendEmailInput.value = "";
    addFriendEmailInput.focus();
  }
}

function setReverseFriendRequestPromptBusy(isBusy) {
  reverseFriendRequestPromptBusy = !!isBusy;
  if (!reverseFriendRequestPreview) return;
  const actionButtons = reverseFriendRequestPreview.querySelectorAll("button[data-reverse-request-action]");
  actionButtons.forEach((button) => {
    button.disabled = !!isBusy;
  });
}

function closeReverseFriendRequestModal(event, force = false, result = "dismiss") {
  if (event?.target && event.target !== reverseFriendRequestModal) return;
  if (reverseFriendRequestPromptBusy && !force) return;
  if (reverseFriendRequestModal) reverseFriendRequestModal.style.display = "none";
  if (reverseFriendRequestPreview) reverseFriendRequestPreview.innerHTML = "";
  setReverseFriendRequestPromptBusy(false);

  if (typeof reverseFriendRequestPromptResolver === "function") {
    const resolver = reverseFriendRequestPromptResolver;
    reverseFriendRequestPromptResolver = null;
    resolver(String(result || "dismiss"));
  }
}

async function openReverseFriendRequestPrompt(requestEntry) {
  const entry = requestEntry && typeof requestEntry === "object" ? requestEntry : null;
  if (!entry?.fromUid) return "dismiss";

  // Hide Add Friend overlay so app background remains visible behind this prompt.
  if (addFriendModal) addFriendModal.style.display = "none";

  if (!reverseFriendRequestModal || !reverseFriendRequestPreview) {
    const fallbackSenderName = getFriendDisplayName({
      uid: entry.fromUid,
      email: entry.fromEmail,
      name: entry.fromName
    }, "Friend");
    const shouldAcceptNow = confirm(`${fallbackSenderName} has already sent you a friend request. Accept it now?`);
    if (shouldAcceptNow) {
      await respondToFriendRequest(entry, "accept");
      return "accept";
    }
    return "dismiss";
  }

  if (typeof reverseFriendRequestPromptResolver === "function") {
    closeReverseFriendRequestModal(null, true, "dismiss");
  }

  return new Promise((resolve) => {
    reverseFriendRequestPromptResolver = resolve;
    setReverseFriendRequestPromptBusy(false);

    const senderName = escapeHtml(getFriendDisplayName({
      displayName: entry.fromDisplayName,
      uid: entry.fromUid,
      email: entry.fromEmail,
      name: entry.fromName
    }, "Friend"));
    const senderHandle = escapeHtml(formatUsernameHandle(entry.fromUsername, entry.fromEmail));

    const row = document.createElement("div");
    row.className = "friend-row";
    row.innerHTML = `<strong>${senderName}</strong><small>${senderHandle}</small><small>Pending friend request</small>`;

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const acceptBtn = document.createElement("button");
    acceptBtn.innerText = "Accept";
    acceptBtn.setAttribute("data-reverse-request-action", "accept");
    acceptBtn.onclick = async () => {
      if (reverseFriendRequestPromptBusy) return;
      setReverseFriendRequestPromptBusy(true);
      await respondToFriendRequest(entry, "accept");
      closeReverseFriendRequestModal(null, true, "accept");
    };

    const declineBtn = document.createElement("button");
    declineBtn.className = "import-transfer-cancel";
    declineBtn.innerText = "Decline";
    declineBtn.setAttribute("data-reverse-request-action", "decline");
    declineBtn.onclick = async () => {
      if (reverseFriendRequestPromptBusy) return;
      setReverseFriendRequestPromptBusy(true);
      await respondToFriendRequest(entry, "decline");
      closeReverseFriendRequestModal(null, true, "decline");
    };

    actions.append(acceptBtn, declineBtn);
    row.append(actions);

    reverseFriendRequestPreview.innerHTML = "";
    reverseFriendRequestPreview.appendChild(row);
    reverseFriendRequestModal.style.display = "flex";
  });
}

async function getActiveFriendCount(userId, userEmail = "") {
  const safeUserId = String(userId || "").trim();
  const safeUserEmail = String(userEmail || "").trim().toLowerCase();
  if (!safeUserId) return 0;

  const acceptedFriends = new Set();
  try {
    const friendsSnap = await fsGetDocs(collection(db, "users", safeUserId, "friends"), 'friend');
    friendsSnap.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const status = String(data.status || "accepted").trim().toLowerCase();
      const friendUid = String(data.friendUid || docSnap.id || "").trim();
      if (status === "accepted" && friendUid) {
        acceptedFriends.add(friendUid);
      }
    });
  } catch (_) {}

  const queueAccepted = new Set();
  const unfriendedFriendUids = new Set();
  try {
    const [sentQueueSnap, receivedQueueSnap, receivedByEmailSnap] = await Promise.all([
      getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", safeUserId))),
      getDocs(query(collection(db, "friendRequestsQueue"), where("toUid", "==", safeUserId))),
      safeUserEmail
        ? getDocs(query(collection(db, "friendRequestsQueue"), where("toEmail", "==", safeUserEmail)))
        : Promise.resolve({ docs: [] })
    ]);

    [...sentQueueSnap.docs, ...receivedQueueSnap.docs, ...receivedByEmailSnap.docs].forEach((docSnap) => {
      const data = docSnap.data() || {};
      const fromUid = String(data.fromUid || "").trim();
      const toUid = String(data.toUid || "").trim();
      const status = String(data.status || "").trim().toLowerCase();
      const isSender = fromUid === safeUserId;
      const friendUid = isSender ? toUid : fromUid;
      if (!friendUid) return;

      if (status === "unfriended") {
        unfriendedFriendUids.add(friendUid);
        return;
      }
      if (status === "accepted") {
        queueAccepted.add(friendUid);
      }
    });
  } catch (_) {}

  queueAccepted.forEach((friendUid) => {
    if (!unfriendedFriendUids.has(friendUid)) acceptedFriends.add(friendUid);
  });
  unfriendedFriendUids.forEach((friendUid) => acceptedFriends.delete(friendUid));

  return acceptedFriends.size;
}

function getMoodStateMeta(moodValue) {
  const moodText = String(moodValue || "").toLowerCase();
  if (!moodText) {
    return {
      logged: false,
      label: "Not logged",
      score: 0,
      wellnessFactor: 0,
      crashRisk: 0,
      burnoutBoost: 0,
      riskReason: ""
    };
  }

  if (/�|\bangry\b|\bfurious\b|\brage\b|\bmad\b/.test(moodText)) {
    return {
      logged: true,
      label: "Angry",
      score: 1,
      wellnessFactor: 0.08,
      crashRisk: 40,
      burnoutBoost: 18,
      riskReason: "Anger spike detected"
    };
  }

  if (/😔|\bsad\b|\blow\b|\bdown\b|\bdepressed\b|\bdrained\b|\btired\b/.test(moodText)) {
    return {
      logged: true,
      label: "Low",
      score: 2,
      wellnessFactor: 0.3,
      crashRisk: 24,
      burnoutBoost: 10,
      riskReason: "Low mood detected"
    };
  }

  if (/😣|\bstressed\b|\bstress\b|\boverwhelmed\b|\banxious\b|\banxiety\b/.test(moodText)) {
    return {
      logged: true,
      label: "Stressed",
      score: 3,
      wellnessFactor: 0.18,
      crashRisk: 32,
      burnoutBoost: 14,
      riskReason: "Stress spike detected"
    };
  }

  if (/😐|\bneutral\b|\bnuetral\b|\bok\b|\bokay\b|\bmeh\b/.test(moodText)) {
    return {
      logged: true,
      label: "Neutral",
      score: 4,
      wellnessFactor: 0.65,
      crashRisk: 10,
      burnoutBoost: 4,
      riskReason: ""
    };
  }

  if (/😊|\bhappy\b|\bgood\b|\bgreat\b|\bawesome\b|\bfine\b|\benergized\b|\bpumped\b/.test(moodText)) {
    return {
      logged: true,
      label: "Happy",
      score: 5,
      wellnessFactor: 1,
      crashRisk: 0,
      burnoutBoost: 0,
      riskReason: ""
    };
  }

  if (/🤩|\bexcited\b|\bthrilledl\b|\belated\b|\bovejoyed\b|\bstoked\b|\beuphoricl\b/.test(moodText)) {
    return {
      logged: true,
      label: "Excited",
      score: 6,
      wellnessFactor: 1.2,
      crashRisk: -2,
      burnoutBoost: -3,
      riskReason: ""
    };
  }

  return {
    logged: true,
    label: "Low",
    score: 2,
    wellnessFactor: 0.3,
    crashRisk: 24,
    burnoutBoost: 10,
    riskReason: "Low mood detected"
  };
}

function getMoodWellnessFactorFromScore(scoreValue) {
  const score = Number(scoreValue) || 0;
  if (score >= 5.5) return 1.2;
  if (score >= 4.5) return 1;
  if (score >= 3.5) return 0.65;
  if (score >= 2.5) return 0.18;
  if (score >= 1.5) return 0.3;
  if (score > 0) return 0.08;
  return 0;
}

function getMoodLabelFromScore(scoreValue) {
  const score = Number(scoreValue) || 0;
  if (score >= 5.5) return "Excited";
  if (score >= 4.5) return "Happy";
  if (score >= 3.5) return "Neutral";
  if (score >= 2.5) return "Stressed";
  if (score >= 1.5) return "Low";
  if (score > 0) return "Angry";
  return "Not enough data";
}

function isEmailLike(value) {
  const text = String(value || "").trim();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(text);
}

function normalizeUsernameCandidate(nameValue, relatedEmail = "") {
  const text = String(nameValue || "").trim();
  if (!text) return "";
  if (isEmailLike(text)) return "";

  const emailLocal = String(relatedEmail || "").trim().toLowerCase().split("@")[0] || "";
  if (emailLocal && text.toLowerCase() === emailLocal) return "";
  return text;
}

function normalizeDisplayNameValue(displayNameValue) {
  const text = String(displayNameValue || "").trim().replace(/\s+/g, " ");
  if (!text) return "";
  const sliced = text.slice(0, 20);
  const allowedPattern = /^[A-Za-z0-9 _-]+$/;
  if (!allowedPattern.test(sliced)) return "";
  if (/[_-]{3,}/.test(sliced)) return "";
  return sliced;
}

function getEmailLocalIdentity(emailValue) {
  const safeEmail = String(emailValue || "").trim().toLowerCase();
  if (!safeEmail.includes("@")) return "";
  return normalizeUsernameForLookup(safeEmail.split("@")[0] || "");
}

function getNormalizedUsernameIdentity(usernameValue, emailValue = "") {
  const fromUsername = normalizeUsernameForLookup(usernameValue);
  if (fromUsername) return fromUsername;
  return getEmailLocalIdentity(emailValue);
}

function formatUsernameHandle(usernameValue, emailValue = "") {
  const normalized = getNormalizedUsernameIdentity(usernameValue, emailValue);
  return normalized ? `@${normalized}` : "@friend";
}

function getSafeUsernameForAuthenticatedUser(user, usernameCandidate = "", emailCandidate = "") {
  const safeEmail = String(emailCandidate || user?.email || "").trim().toLowerCase();
  const normalizedCandidate = normalizeUsernameForLookup(usernameCandidate);
  const providerIds = Array.isArray(user?.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  const isGoogleAccount = providerIds.includes("google.com");
  const emailLocalIdentity = getEmailLocalIdentity(safeEmail);

  if (normalizedCandidate && !(isGoogleAccount && emailLocalIdentity && normalizedCandidate === emailLocalIdentity)) {
    return normalizedCandidate;
  }

  if (isGoogleAccount) {
    return buildUsernameSeedFromDisplayName(user?.displayName) || "user";
  }

  return emailLocalIdentity || "user";
}

function normalizeUsernameForLookup(usernameValue) {
  const raw = String(usernameValue || "").trim();
  if (!raw) return "";
  const withoutAt = raw.startsWith("@") ? raw.slice(1) : raw;
  // Dots are deprecated in usernames; normalize legacy dotted usernames to dotless.
  return withoutAt
    .toLowerCase()
    .replace(/\s+/g, "")
    .replace(/\./g, "")
    .trim();
}

function getCaseSensitiveUsernameInputValue(usernameValue) {
  const raw = String(usernameValue || "").trim();
  if (!raw) return "";
  const withoutAt = raw.startsWith("@") ? raw.slice(1) : raw;
  return withoutAt.trim();
}

function buildUsernameSeedFromDisplayName(displayNameValue) {
  const raw = String(displayNameValue || "").trim().toLowerCase();
  if (!raw) return "";
  const withoutSpaces = raw.replace(/\s+/g, "");
  const allowedOnly = withoutSpaces.replace(/[^a-z0-9_-]/g, "");
  return normalizeUsernameForLookup(allowedOnly).slice(0, 20);
}

function buildUsernameCandidate(baseUsername, suffix = "") {
  const base = normalizeUsernameForLookup(baseUsername) || "user";
  const safeSuffix = normalizeUsernameForLookup(suffix);
  const maxBaseLength = Math.max(1, 20 - safeSuffix.length);
  const clippedBase = base.slice(0, maxBaseLength);
  return normalizeUsernameForLookup(`${clippedBase}${safeSuffix}`).slice(0, 20);
}

function buildUsernameClaimCandidateList(preferredUsername) {
  const base = normalizeUsernameForLookup(preferredUsername) || "user";
  const candidates = [];
  const seen = new Set();
  const pushCandidate = (value) => {
    const normalized = normalizeUsernameForLookup(value);
    if (!normalized || !isValidUsernameKey(normalized) || seen.has(normalized)) return;
    seen.add(normalized);
    candidates.push(normalized);
  };

  pushCandidate(base);
  for (let index = 1; index <= 80; index += 1) {
    pushCandidate(buildUsernameCandidate(base, String(index)));
    pushCandidate(buildUsernameCandidate(base, `_${index}`));
    pushCandidate(buildUsernameCandidate(base, `-${index}`));
  }
  return candidates;
}

function buildStableUidUsernameFingerprint(userId) {
  const cleaned = String(userId || "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
  if (!cleaned) return "";
  if (cleaned.length <= 12) return cleaned;
  return `${cleaned.slice(0, 6)}${cleaned.slice(-6)}`;
}

async function claimUsernameWithFallback(options = {}) {
  const safeUserId = String(options.userId || "").trim();
  const safeEmail = String(options.email || "").trim().toLowerCase();
  const safeDisplayName = normalizeDisplayNameValue(options.displayName || "") || "User";
  const preferredUsername = normalizeUsernameForLookup(options.preferredUsername || "");
  const allowSuffixFallback = !!options.allowSuffixFallback;
  if (!safeUserId) throw new Error("INVALID_USERNAME");

  const baseUsername = preferredUsername || "user";
  const candidates = allowSuffixFallback
    ? buildUsernameClaimCandidateList(baseUsername)
    : [baseUsername];

  if (allowSuffixFallback) {
    const seen = new Set(candidates);
    const pushCandidate = (value) => {
      const normalized = normalizeUsernameForLookup(value);
      if (!normalized || seen.has(normalized)) return;
      seen.add(normalized);
      candidates.push(normalized);
    };

    const uidFingerprint = buildStableUidUsernameFingerprint(safeUserId);
    if (uidFingerprint) {
      pushCandidate(buildUsernameCandidate(baseUsername, `_${uidFingerprint}`));
      pushCandidate(buildUsernameCandidate(baseUsername, `-${uidFingerprint}`));
      pushCandidate(buildUsernameCandidate(baseUsername, uidFingerprint));
      pushCandidate(buildUsernameCandidate("user", uidFingerprint));
    }

    // Extra entropy tail to avoid collisions even in very high-occupancy namespaces.
    for (let index = 0; index < 200; index += 1) {
      const entropy = (Date.now() + index).toString(36).slice(-4);
      pushCandidate(buildUsernameCandidate(baseUsername, `_${entropy}`));
      pushCandidate(buildUsernameCandidate(baseUsername, `${entropy}`));
    }
  }

  let lastTakenError = null;
  for (const candidate of candidates) {
    try {
      const claimed = await claimUsernameDirectoryEntry(safeUserId, candidate, safeEmail, safeDisplayName);
      return claimed;
    } catch (err) {
      const errCode = String(err?.message || "");
      if (errCode === "USERNAME_TAKEN") {
        lastTakenError = err;
        continue;
      }
      throw err;
    }
  }

  throw (lastTakenError || new Error("USERNAME_TAKEN"));
}

async function resolveUserDirectoryByUsername(usernameValue, options = {}) {
  const rawInput = String(usernameValue || "").trim();
  const rawWithoutAt = rawInput.startsWith("@") ? rawInput.slice(1).trim() : rawInput;
  const usernameKey = normalizeUsernameForLookup(usernameValue);
  const legacyDottedKey = rawWithoutAt.replace(/\s+/g, "").trim();
  const forceRefresh = !!options?.forceRefresh;
  const preferServer = !!options?.preferServer;
  if (!usernameKey) return null;

  const cached = forceRefresh ? null : usernameDirectoryCache.get(usernameKey);
  if (cached && String(cached.uid || "").trim()) {
    return cached;
  }

  const buildResolved = (dataLike, fallbackUsername = usernameKey) => {
    const data = dataLike || {};
    const email = String(data.email || "").trim().toLowerCase();
    const uid = String(data.uid || "").trim();
    if (!uid) return null;
    const rawUsername = getCaseSensitiveUsernameInputValue(data.username || data.name || fallbackUsername);
    const normalizedUsername = normalizeUsernameForLookup(data.username || data.name || fallbackUsername) || fallbackUsername;
    const displayName = normalizeDisplayNameValue(data.displayName)
      || normalizeDisplayNameValue(data.name)
      || normalizedUsername;
    return {
      uid,
      email,
      name: normalizedUsername,
      username: normalizedUsername,
      usernameExact: rawUsername || normalizedUsername,
      displayName
    };
  };

  let resolved = null;
  let permissionDeniedSeen = false;
  try {
    const usernameRef = doc(db, "usernameDirectory", usernameKey);
    const usernameSnap = preferServer
      ? await getDocWithFreshFallback(usernameRef)
      : await getDoc(usernameRef);
    if (usernameSnap.exists()) {
      const usernameData = usernameSnap.data() || {};
      resolved = buildResolved(usernameData, usernameKey);

      if (!resolved) {
        const fallbackEmail = String(usernameData.email || "").trim().toLowerCase();
        if (fallbackEmail) {
          try {
            const directoryRef = doc(db, "userDirectory", fallbackEmail);
            const directorySnap = preferServer
              ? await getDocWithFreshFallback(directoryRef)
              : await getDoc(directoryRef);
            if (directorySnap.exists()) {
              const directoryData = directorySnap.data() || {};
              const fallbackUid = String(directoryData.uid || "").trim();
              if (fallbackUid) {
                resolved = {
                  uid: fallbackUid,
                  email: fallbackEmail,
                  name: usernameKey,
                  username: usernameKey,
                  usernameExact: getCaseSensitiveUsernameInputValue(usernameData.username || usernameData.name || usernameKey) || usernameKey,
                  displayName: normalizeDisplayNameValue(usernameData.displayName)
                    || normalizeDisplayNameValue(usernameData.name)
                    || usernameKey
                };
              }
            }
          } catch (err) {
            if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
          }
        }
      }
    }

    // Legacy compatibility: old usernames could contain dots in doc IDs.
    if (!resolved && legacyDottedKey && legacyDottedKey !== usernameKey) {
      try {
        const legacyRef = doc(db, "usernameDirectory", legacyDottedKey);
        const legacySnap = preferServer
          ? await getDocWithFreshFallback(legacyRef)
          : await getDoc(legacyRef);
        if (legacySnap.exists()) {
          resolved = buildResolved(legacySnap.data() || {}, usernameKey);
        }
      } catch (err) {
        if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
      }
    }

    if (!resolved) {
      try {
        const usernameFieldQuery = query(
          collection(db, "usernameDirectory"),
          where("username", "==", usernameKey)
        );
        const usernameFieldSnap = preferServer
          ? await getDocsWithFreshFallback(usernameFieldQuery)
          : await getDocs(usernameFieldQuery);
        for (const docSnap of usernameFieldSnap.docs) {
          const candidate = buildResolved(docSnap.data() || {}, usernameKey);
          if (candidate) {
            resolved = candidate;
            break;
          }
        }
      } catch (err) {
        if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
      }
    }

    if (!resolved) {
      try {
        const userDirectoryNameQuery = query(
          collection(db, "userDirectory"),
          where("name", "==", usernameKey)
        );
        const userDirectoryNameSnap = preferServer
          ? await getDocsWithFreshFallback(userDirectoryNameQuery)
          : await getDocs(userDirectoryNameQuery);
        for (const docSnap of userDirectoryNameSnap.docs) {
          const data = docSnap.data() || {};
          const uid = String(data.uid || "").trim();
          const email = String(data.email || docSnap.id || "").trim().toLowerCase();
          if (!uid) continue;
          resolved = {
            uid,
            email,
            name: usernameKey,
            username: usernameKey,
            usernameExact: getCaseSensitiveUsernameInputValue(data.username || data.name || rawWithoutAt || usernameKey) || usernameKey,
            displayName: normalizeDisplayNameValue(data.displayName)
              || normalizeDisplayNameValue(data.name)
              || usernameKey
          };
          break;
        }
      } catch (err) {
        if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
      }
    }

    // Legacy case-preserving fallback for older rows.
    if (!resolved && rawWithoutAt && rawWithoutAt !== usernameKey) {
      try {
        const userDirectoryRawNameQuery = query(
          collection(db, "userDirectory"),
          where("name", "==", rawWithoutAt)
        );
        const userDirectoryRawNameSnap = preferServer
          ? await getDocsWithFreshFallback(userDirectoryRawNameQuery)
          : await getDocs(userDirectoryRawNameQuery);
        for (const docSnap of userDirectoryRawNameSnap.docs) {
          const data = docSnap.data() || {};
          const uid = String(data.uid || "").trim();
          const email = String(data.email || docSnap.id || "").trim().toLowerCase();
          if (!uid) continue;
          resolved = {
            uid,
            email,
            name: usernameKey,
            username: usernameKey,
            usernameExact: getCaseSensitiveUsernameInputValue(data.username || data.name || rawWithoutAt || usernameKey) || usernameKey,
            displayName: normalizeDisplayNameValue(data.displayName)
              || normalizeDisplayNameValue(data.name)
              || rawWithoutAt
          };
          break;
        }
      } catch (err) {
        if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
      }
    }

    // Last resort for old mixed-case userDirectory rows.
    if (!resolved && forceRefresh) {
      try {
        const allDirectorySnap = preferServer
          ? await getDocsWithFreshFallback(collection(db, "userDirectory"))
          : await fsGetDocs(collection(db, "userDirectory"), 'userDirectory');
        for (const docSnap of allDirectorySnap.docs) {
          const data = docSnap.data() || {};
          const uid = String(data.uid || "").trim();
          const email = String(data.email || docSnap.id || "").trim().toLowerCase();
          if (!uid) continue;

          const nameKey = normalizeUsernameForLookup(data.name || "");
          const emailLocalKey = normalizeUsernameForLookup(email.split("@")[0] || "");
          if (nameKey !== usernameKey && emailLocalKey !== usernameKey) continue;

          resolved = {
            uid,
            email,
            name: usernameKey,
            username: usernameKey,
            usernameExact: getCaseSensitiveUsernameInputValue(data.username || data.name || rawWithoutAt || usernameKey) || usernameKey,
            displayName: normalizeDisplayNameValue(data.displayName)
              || normalizeDisplayNameValue(data.name)
              || usernameKey
          };
          break;
        }
      } catch (err) {
        if (isFirestorePermissionDeniedError(err)) permissionDeniedSeen = true;
      }
    }
  } catch (err) {
    if (isFirestorePermissionDeniedError(err)) {
      throw err;
    }
    resolved = null;
  }

  if (!resolved && permissionDeniedSeen) {
    const permissionErr = new Error("Missing or insufficient permissions.");
    permissionErr.code = "permission-denied";
    throw permissionErr;
  }

  if (resolved && String(resolved.uid || "").trim()) {
    if (!String(resolved.usernameExact || "").trim()) {
      resolved.usernameExact = getCaseSensitiveUsernameInputValue(resolved.username || resolved.name || "")
        || String(resolved.username || resolved.name || "");
    }
    // Self-heal for current session: alias normalized key to resolved legacy profile.
    usernameDirectoryCache.set(usernameKey, resolved);
  } else {
    usernameDirectoryCache.delete(usernameKey);
  }
  return resolved;
}

async function claimUsernameDirectoryEntry(userId, usernameValue, emailValue, displayNameValue) {
  const safeUserId = String(userId || "").trim();
  const usernameValidation = validateSignupUsername(usernameValue);
  const usernameKey = usernameValidation.normalized;
  const safeEmail = String(emailValue || "").trim().toLowerCase();
  const safeUsername = usernameKey;
  const safeDisplayName = normalizeDisplayNameValue(displayNameValue) || safeUsername;
  if (!safeUserId || !usernameKey || !usernameValidation.ok || !isValidUsernameKey(usernameKey)) {
    throw new Error("INVALID_USERNAME");
  }

  const usernameRef = doc(db, "usernameDirectory", usernameKey);
  await runTransaction(db, async (transaction) => {
    const usernameSnap = await transaction.get(usernameRef);
    const existingData = usernameSnap.exists() ? (usernameSnap.data() || {}) : null;
    const existingUid = String(existingData?.uid || "").trim();
    if (existingUid && existingUid !== safeUserId) {
      throw new Error("USERNAME_TAKEN");
    }

    transaction.set(usernameRef, {
      uid: safeUserId,
      email: safeEmail,
      name: safeUsername,
      username: usernameKey,
      displayName: safeDisplayName,
      createdAt: existingData?.createdAt || serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true });
  });

  usernameDirectoryCache.set(usernameKey, {
    uid: safeUserId,
    email: safeEmail,
    name: safeUsername,
    username: usernameKey,
    displayName: safeDisplayName
  });

  try {
    const ownedUsernameSnap = await getDocs(query(
      collection(db, "usernameDirectory"),
      where("uid", "==", safeUserId)
    ));
    const sameEmailSnap = safeEmail
      ? await getDocs(query(
        collection(db, "usernameDirectory"),
        where("email", "==", safeEmail)
      ))
      : { docs: [] };

    const staleByUid = ownedUsernameSnap.docs.filter((docSnap) => String(docSnap.id || "") !== usernameKey);
    const staleByEmail = (sameEmailSnap.docs || []).filter((docSnap) => String(docSnap.id || "") !== usernameKey);
    const staleMap = new Map();
    [...staleByUid, ...staleByEmail].forEach((docSnap) => {
      const key = String(docSnap.id || "").trim();
      if (key && !staleMap.has(key)) staleMap.set(key, docSnap);
    });
    const staleEntries = [...staleMap.values()];
    if (staleEntries.length) {
      await Promise.all(staleEntries.map((docSnap) => {
        const staleKey = String(docSnap.id || "").trim();
        if (staleKey) usernameDirectoryCache.delete(staleKey);
        return deleteDoc(docSnap.ref);
      }));
    }
  } catch (_) {
    // Best-effort cleanup. If Firestore rules block deletes, the active username claim still remains valid.
  }

  return usernameKey;
}

function getFriendDisplayName(profileLike, fallbackName = "") {
  const safeEmail = String(profileLike?.email || "").trim().toLowerCase();
  const normalizedDisplayName = normalizeDisplayNameValue(profileLike?.displayName);
  const isGenericDisplayName = /^(friend|unknown|your friend|user)$/i.test(String(normalizedDisplayName || "").trim());
  const normalizedProfileName = normalizeUsernameCandidate(profileLike?.name, safeEmail);
  const isGenericProfileName = /^(friend|unknown|your friend|user)$/i.test(String(normalizedProfileName || "").trim());
  const normalizedFallback = normalizeUsernameCandidate(fallbackName, safeEmail);
  const isGenericFallback = /^(friend|unknown|your friend|user)$/i.test(String(normalizedFallback || "").trim());
  const preferred = (isGenericDisplayName ? "" : normalizedDisplayName)
    || (isGenericProfileName ? "" : normalizedProfileName)
    || (isGenericFallback ? "" : normalizedFallback);
  if (preferred) return preferred;

  const emailLocal = safeEmail.split("@")[0] || "";
  if (emailLocal) return `@${emailLocal}`;

  const uid = String(profileLike?.uid || "").trim();
  if (uid) return `Friend ${uid.slice(0, 6)}`;
  return "Friend";
}

async function resolveUsernameFromDirectoryEmail(emailValue) {
  const identity = await resolveDirectoryIdentityByEmail(emailValue);
  return String(identity?.username || "");
}

async function resolveDirectoryIdentityByEmail(emailValue) {
  const safeEmail = String(emailValue || "").trim().toLowerCase();
  if (!safeEmail) {
    return { username: "", displayName: "" };
  }
  if (userDirectoryIdentityCache.has(safeEmail)) {
    return userDirectoryIdentityCache.get(safeEmail) || { username: "", displayName: "" };
  }

  let identity = { username: "", displayName: "" };
  try {
    const directoryRes = await fsGetDoc(doc(db, "userDirectory", safeEmail), 'userDirectory');
    if (directoryRes.exists) {
      const data = directoryRes.data || {};
      const resolvedUsername = getNormalizedUsernameIdentity(data.username || data.name, safeEmail);
      const resolvedDisplayName = normalizeDisplayNameValue(data.displayName)
        || normalizeDisplayNameValue(data.name)
        || resolvedUsername;
      identity = {
        username: resolvedUsername,
        displayName: resolvedDisplayName
      };
    }
  } catch (_) {
    identity = { username: "", displayName: "" };
  }

  userDirectoryNameCache.set(safeEmail, identity.username || "");
  userDirectoryIdentityCache.set(safeEmail, identity);
  return identity;
}

function calculateWellnessScoreValue() {
  const todayKey = getTodayKey();
  const waterToday = getTodayWater();
  const effectiveWaterGoal = waterGoal > 0 ? waterGoal : 8;
  const waterRatio = Math.min(1, waterToday / effectiveWaterGoal);
  const waterPoints = Math.round(waterRatio * 30);

  const sleepToday = getTodaySleep();
  const sleepRatio = Math.min(1, sleepToday / 8);
  const sleepPoints = Math.round(sleepRatio * 25);

  const moodToday = getTodayMood();
  const moodFactor = Number(getMoodStateMeta(moodToday).wellnessFactor) || 0;
  const moodPoints = Math.round(moodFactor * 20);

  const totalTasks = taskEntries.length;
  const doneTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const taskRatio = totalTasks ? doneTasks / totalTasks : 0;
  const taskPoints = Math.round(taskRatio * 15);

  const hasGratitudeToday = gratitudeEntries.some((entry) => dateToKey(entry.time) === todayKey);
  const gratitudePoints = hasGratitudeToday ? 10 : 0;
  const challengePoints = dailyChallengeCompleted ? 10 : 0;

  return Math.max(0, Math.min(100, waterPoints + sleepPoints + moodPoints + taskPoints + gratitudePoints + challengePoints));
}

function calculateWellnessScoreFromMetrics(metrics = {}) {
  const waterToday = Math.max(0, Number(metrics?.waterToday) || 0);
  const sleepToday = Math.max(0, Number(metrics?.sleepToday) || 0);
  const moodToday = String(metrics?.moodToday || "");
  const avgMoodScore = Math.max(0, Number(metrics?.avgMoodScore) || 0);
  const totalTasksLogged = Math.max(0, Number(metrics?.totalTasksLogged) || 0);
  const completedTasks = Math.max(0, Number(metrics?.completedTasks) || 0);
  const gratitudeToday = Math.max(0, Number(metrics?.gratitudeToday) || 0);
  const dailyChallengeCompletedToday = Math.max(0, Number(metrics?.dailyChallengeCompletedToday) || 0);

  const hasSignal = waterToday > 0
    || sleepToday > 0
    || !!moodToday
    || avgMoodScore > 0
    || totalTasksLogged > 0
    || completedTasks > 0
    || gratitudeToday > 0
    || dailyChallengeCompletedToday > 0;
  if (!hasSignal) return null;

  const waterPoints = Math.round(Math.min(1, waterToday / 8) * 30);
  const sleepPoints = Math.round(Math.min(1, sleepToday / 8) * 25);

  let moodFactor = 0;
  if (moodToday) moodFactor = Number(getMoodStateMeta(moodToday).wellnessFactor) || 0;
  else moodFactor = getMoodWellnessFactorFromScore(avgMoodScore);
  const moodPoints = Math.round(moodFactor * 20);

  const safeTotalTasks = Math.max(0, totalTasksLogged);
  const safeCompletedTasks = Math.min(safeTotalTasks, Math.max(0, completedTasks));
  const taskRatio = safeTotalTasks ? (safeCompletedTasks / safeTotalTasks) : 0;
  const taskPoints = Math.round(taskRatio * 15);

  const gratitudePoints = gratitudeToday > 0 ? 10 : 0;
  const challengePoints = dailyChallengeCompletedToday > 0 ? 10 : 0;

  return Math.max(0, Math.min(100, waterPoints + sleepPoints + moodPoints + taskPoints + gratitudePoints + challengePoints));
}

function buildUserSocialProfileSnapshot(user = auth.currentUser) {
  const activeUser = user || auth.currentUser;
  const email = String(activeUser?.email || "").trim().toLowerCase();
  const username = getSafeUsernameForAuthenticatedUser(activeUser, accountName?.innerText || "", email);
  const displayName = normalizeDisplayNameValue(activeUser?.displayName)
    || normalizeDisplayNameValue(accountDisplayName?.innerText || "")
    || username;
  const uid = String(activeUser?.uid || "").trim();

  const maps = buildPatternMetricMaps(14);
  const dayKeys = maps.dayKeys || [];
  const sleepValues = dayKeys.map((key) => Number(maps.sleepByDay.get(key)) || 0).filter((value) => value > 0);
  const moodValues = dayKeys.map((key) => Number(maps.moodByDay.get(key)) || 0).filter((value) => value > 0);
  const waterValues = dayKeys.map((key) => Number(maps.waterByDay.get(key)) || 0);
  const taskValues = dayKeys.map((key) => Number(maps.tasksDoneByDay.get(key)) || 0);

  const avgSleepHours = Number(safeAvg(sleepValues).toFixed(1));
  const avgMoodScore = Number(safeAvg(moodValues).toFixed(2));
  const avgWaterDaily = Number(safeAvg(waterValues).toFixed(1));
  const avgTasksCompletedDaily = Number(safeAvg(taskValues).toFixed(1));
  const totalTasksLogged = taskEntries.length;
  const completedTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const todayKey = getTodayKey();
  const tasksToday = Number(maps.tasksDoneByDay.get(todayKey)) || 0;
  const sleepToday = Number(getTodaySleep()) || Number(maps.sleepByDay.get(todayKey)) || 0;
  const avgMoodToday = Number((Number(maps.moodByDay.get(todayKey)) || getTodayMoodAverageScore() || 0).toFixed(2));
  let waterToday = 0;
  for (let index = waterHistory.length - 1; index >= 0; index -= 1) {
    if (dateToKey(waterDates[index]) !== todayKey) continue;
    waterToday = Number(waterHistory[index]) || 0;
    break;
  }
  waterToday = Number(waterToday.toFixed(1));
  const gratitudeToday = getTodayGratitudeCount();
  const dailyChallengeCompletedToday = dailyChallengeCompleted ? 1 : 0;
  const moodToday = getTodayMood();
  const wellnessScoreToday = calculateWellnessScoreValue();

  return {
    uid,
    email,
    name: displayName,
    username,
    displayName,
    metrics: {
      totalTasksLogged,
      completedTasks,
      tasksToday,
      waterToday,
      sleepToday,
      moodToday,
      avgMoodToday,
      gratitudeToday,
      dailyChallengeCompletedToday,
      wellnessScoreToday,
      avgWaterDaily,
      avgSleepHours,
      avgMoodScore,
      avgMoodLabel: getMoodLabelFromScore(avgMoodScore),
      avgTasksCompletedDaily,
      sampleDays: dayKeys.length
    },
    generatedAtMs: Date.now()
  };
}

function buildFriendMotivationLine(friendProfile, myProfile) {
  const friendName = getFriendDisplayName(friendProfile, "Your friend");
  const friendMetrics = friendProfile?.metrics || {};
  const myMetrics = myProfile?.metrics || {};

  const friendMood = Number(friendMetrics.avgMoodScore) || 0;
  const myMood = Number(myMetrics.avgMoodScore) || 0;
  const friendSleep = Number(friendMetrics.avgSleepHours) || 0;
  const mySleep = Number(myMetrics.avgSleepHours) || 0;
  const friendWater = Number(friendMetrics.avgWaterDaily) || 0;
  const myWater = Number(myMetrics.avgWaterDaily) || 0;
  const friendTasks = Number(friendMetrics.avgTasksCompletedDaily) || 0;
  const myTasks = Number(myMetrics.avgTasksCompletedDaily) || 0;

  if (friendMood > myMood + 0.12) {
    return `${friendName}'s average mood is ${friendMetrics.avgMoodLabel || "higher"} and yours is ${myMetrics.avgMoodLabel || "lower"}. Try improving sleep + hydration consistency today.`;
  }
  if (friendSleep > mySleep + 0.4) {
    return `${friendName} averages ${friendSleep.toFixed(1)}h sleep while you average ${mySleep.toFixed(1)}h. Better sleep can lift mood and focus.`;
  }
  if (friendWater > myWater + 0.5) {
    return `${friendName} averages ${friendWater.toFixed(1)} cups/day and you average ${myWater.toFixed(1)}. Match hydration pace to stay competitive.`;
  }
  if (friendTasks > myTasks + 0.3) {
    return `${friendName} completes about ${friendTasks.toFixed(1)} tasks/day vs your ${myTasks.toFixed(1)}. One extra focused sprint can close the gap.`;
  }
  return `You and ${friendName} are close right now. Keep your consistency to stay ahead.`;
}

function pickBestFriendMetric(profileRows, metricKey, todayMetricKey = "") {
  if (!Array.isArray(profileRows) || !profileRows.length) return null;
  const hasTodaySignal = !!todayMetricKey && profileRows.some((profile) => (Number(profile?.metrics?.[todayMetricKey]) || 0) > 0);
  const selectedMetricKey = hasTodaySignal ? todayMetricKey : metricKey;
  let best = null;
  profileRows.forEach((profile) => {
    const value = Number(profile?.metrics?.[selectedMetricKey]) || 0;
    if (!best || value > best.value) {
      best = {
        profile,
        value,
        selectedMetricKey
      };
    }
  });
  return best;
}

function formatFriendDelta(delta, digits = 1) {
  return Math.abs(Number(delta) || 0).toFixed(digits);
}

function getComparisonFriendProfiles(profileRows, maxCount = MAX_FRIENDS) {
  if (!Array.isArray(profileRows) || !profileRows.length) return [];
  const unique = [];
  const seen = new Set();
  profileRows.forEach((profile, index) => {
    const uid = String(profile?.uid || "").trim();
    const email = String(profile?.email || "").trim().toLowerCase();
    const key = uid || email || `row_${index}`;
    if (!key || seen.has(key)) return;
    seen.add(key);
    unique.push(profile);
  });
  return unique.slice(0, Math.max(1, Number(maxCount) || 5));
}

function formatLeaderNames(names) {
  const unique = [...new Set((names || []).filter(Boolean))];
  if (!unique.length) return "A friend";
  if (unique.length === 1) return unique[0];
  if (unique.length === 2) return `${unique[0]} and ${unique[1]}`;
  return `${unique.slice(0, -1).join(", ")}, and ${unique[unique.length - 1]}`;
}

function buildNumericFriendComparisonText({
  friends,
  myValue,
  unit,
  digits = 1,
  leadThreshold = 0.2,
  noDataMessage = "no comparison data yet"
}) {
  const compareFriends = Array.isArray(friends) ? friends : [];
  const friendNames = compareFriends.map((entry) => entry.name);
  const header = `You vs ${friendNames.join(" vs ")}`;
  const allValues = [Number(myValue) || 0, ...compareFriends.map((entry) => Number(entry.value) || 0)];
  const hasAnyData = allValues.some((value) => value > 0);
  if (!hasAnyData) {
    return `${header}: ${noDataMessage}.`;
  }

  const formatValue = (value) => {
    const safe = Number(value) || 0;
    return digits <= 0 ? `${Math.round(safe)}` : safe.toFixed(digits);
  };

  const toComparableValue = (value) => {
    const safe = Number(value) || 0;
    return digits <= 0 ? Math.round(safe) : Number(safe.toFixed(digits));
  };

  const mySafeValue = Number(myValue) || 0;
  const myComparableValue = toComparableValue(mySafeValue);
  const friendComparableRows = compareFriends.map((entry) => {
    const rawValue = Number(entry.value) || 0;
    return {
      name: entry.name,
      rawValue,
      comparableValue: toComparableValue(rawValue)
    };
  });
  const friendSummary = compareFriends
    .map((entry) => `${entry.name} ${formatValue(entry.value)}`)
    .join("; ");

  const topComparableValue = Math.max(
    myComparableValue,
    ...friendComparableRows.map((entry) => entry.comparableValue)
  );
  const iAmTop = myComparableValue === topComparableValue;
  const topFriendNames = friendComparableRows
    .filter((entry) => entry.comparableValue === topComparableValue)
    .map((entry) => entry.name);
  const tieWithFriends = iAmTop && topFriendNames.length > 0;

  const closestGap = Math.abs(topComparableValue - myComparableValue);
  let motivation = "Comparison is close. Stay consistent and push one more small win.";
  if (tieWithFriends) {
    const tpl = pickNonRepeatingVariant(FRIEND_MOTIVATION_TIED_POOL, 'friend_tied') || `You are tied with ${formatLeaderNames(topFriendNames)}. One small action now can put you ahead.`;
    motivation = tpl.replaceAll('{names}', formatLeaderNames(topFriendNames)).replaceAll('{gap}', formatValue(topComparableValue - myComparableValue));
  } else if (iAmTop) {
    const tpl = pickNonRepeatingVariant(FRIEND_MOTIVATION_LEADING_POOL, 'friend_leading') || "You are leading. Keep the momentum going.";
    motivation = tpl.replaceAll('{names}', formatLeaderNames(topFriendNames)).replaceAll('{gap}', formatValue(topComparableValue - myComparableValue));
  } else if (closestGap > leadThreshold) {
    const tpl = pickNonRepeatingVariant(FRIEND_MOTIVATION_BEHIND_POOL, 'friend_behind') || `${formatLeaderNames(topFriendNames)} ${topFriendNames.length > 1 ? "are" : "is"} currently ahead by ${formatValue(topComparableValue - myComparableValue)}. One focused push now can close the gap.`;
    motivation = tpl.replaceAll('{names}', formatLeaderNames(topFriendNames)).replaceAll('{gap}', formatValue(topComparableValue - myComparableValue));
  }

  return `${header}: You ${formatValue(mySafeValue)} ${unit}; ${friendSummary} ${unit}. ${motivation}`;
}

function renderFriendMetricCardInsights() {
  if (!taskFriendInsight && !waterFriendInsight && !sleepFriendInsight && !moodFriendInsight && !gratitudeFriendInsight && !dailyChallengeFriendInsight && !wellnessFriendInsight) return;
  const user = auth.currentUser;
  if (!user) {
    if (taskFriendInsight) taskFriendInsight.innerText = "";
    if (waterFriendInsight) waterFriendInsight.innerText = "";
    if (sleepFriendInsight) sleepFriendInsight.innerText = "";
    if (moodFriendInsight) moodFriendInsight.innerText = "";
    if (gratitudeFriendInsight) gratitudeFriendInsight.innerText = "";
    if (dailyChallengeFriendInsight) dailyChallengeFriendInsight.innerText = "";
    if (wellnessFriendInsight) wellnessFriendInsight.innerText = "";
    return;
  }

  if (!Array.isArray(friendInsightProfiles) || !friendInsightProfiles.length) {
    if (taskFriendInsight) taskFriendInsight.innerText = "Friend benchmark: add a friend to compare productivity pace.";
    if (waterFriendInsight) waterFriendInsight.innerText = "Friend benchmark: add a friend to compare hydration consistency.";
    if (sleepFriendInsight) sleepFriendInsight.innerText = "Friend benchmark: add a friend to compare sleep consistency.";
    if (moodFriendInsight) moodFriendInsight.innerText = "Friend benchmark: add a friend to compare average mood of the day.";
    if (gratitudeFriendInsight) gratitudeFriendInsight.innerText = "Friend benchmark: add a friend to compare gratitude consistency.";
    if (dailyChallengeFriendInsight) dailyChallengeFriendInsight.innerText = "Friend benchmark: add a friend to compare daily challenge consistency.";
    if (wellnessFriendInsight) wellnessFriendInsight.innerText = "Friend benchmark: add a friend to compare daily wellness score.";
    return;
  }

  const myProfile = buildUserSocialProfileSnapshot(user);
  const myMetrics = myProfile?.metrics || {};

  const compareProfiles = getComparisonFriendProfiles(friendInsightProfiles, MAX_FRIENDS);
  if (!compareProfiles.length) {
    if (taskFriendInsight) taskFriendInsight.innerText = "Friend benchmark: add a friend to compare productivity pace.";
    if (waterFriendInsight) waterFriendInsight.innerText = "Friend benchmark: add a friend to compare hydration consistency.";
    if (sleepFriendInsight) sleepFriendInsight.innerText = "Friend benchmark: add a friend to compare sleep consistency.";
    if (moodFriendInsight) moodFriendInsight.innerText = "Friend benchmark: add a friend to compare average mood of the day.";
    if (gratitudeFriendInsight) gratitudeFriendInsight.innerText = "Friend benchmark: add a friend to compare gratitude consistency.";
    if (dailyChallengeFriendInsight) dailyChallengeFriendInsight.innerText = "Friend benchmark: add a friend to compare daily challenge consistency.";
    if (wellnessFriendInsight) wellnessFriendInsight.innerText = "Friend benchmark: add a friend to compare daily wellness score.";
    return;
  }

  const friendNames = compareProfiles.map((profile) => getFriendDisplayName(profile, "Friend"));
  const header = `You vs ${friendNames.join(" vs ")}`;

  if (taskFriendInsight) {
    const myToday = Number(myMetrics.tasksToday) || 0;
    const hasFriendToday = compareProfiles.some((profile) => (Number(profile?.metrics?.tasksToday) || 0) > 0);
    const useToday = myToday > 0 || hasFriendToday;
    const taskUnit = useToday ? "tasks today" : "tasks/day";
    const taskFriends = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      value: useToday
        ? (Number(profile?.metrics?.tasksToday) || 0)
        : (Number(profile?.metrics?.avgTasksCompletedDaily) || 0)
    }));
    const myValue = useToday ? myToday : (Number(myMetrics.avgTasksCompletedDaily) || 0);
    taskFriendInsight.innerText = buildNumericFriendComparisonText({
      friends: taskFriends,
      myValue,
      unit: taskUnit,
      digits: 1,
      leadThreshold: 0.2,
      noDataMessage: "no productivity comparison data yet. Log and complete your first task today to start the race"
    });
  }

  if (waterFriendInsight) {
    const myToday = Number(myMetrics.waterToday) || 0;
    const hasFriendToday = compareProfiles.some((profile) => (Number(profile?.metrics?.waterToday) || 0) > 0);
    const useToday = myToday > 0 || hasFriendToday;
    const waterUnit = useToday ? "cups today" : "cups/day";
    const waterFriends = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      value: useToday
        ? (Number(profile?.metrics?.waterToday) || 0)
        : (Number(profile?.metrics?.avgWaterDaily) || 0)
    }));
    const myValue = useToday ? myToday : (Number(myMetrics.avgWaterDaily) || 0);
    waterFriendInsight.innerText = buildNumericFriendComparisonText({
      friends: waterFriends,
      myValue,
      unit: waterUnit,
      digits: 1,
      leadThreshold: 0.3,
      noDataMessage: "no hydration comparison yet. Start with one glass now and build your streak"
    });
  }

  if (sleepFriendInsight) {
    const myToday = Number(myMetrics.sleepToday) || 0;
    const sleepUnit = "h today";
    const sleepFriends = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      value: Number(profile?.metrics?.sleepToday) || 0
    }));
    const myValue = myToday;
    sleepFriendInsight.innerText = buildNumericFriendComparisonText({
      friends: sleepFriends,
      myValue,
      unit: sleepUnit,
      digits: 1,
      leadThreshold: 0.3,
      noDataMessage: "no sleep comparison yet. Log sleep today to start today-only comparison"
    });
  }

  if (moodFriendInsight) {
    const scoreFromMetrics = (metrics) => {
      const directAverage = Number(metrics?.avgMoodToday);
      if (directAverage > 0) return directAverage;
      const moodSignal = moodToScore(String(metrics?.moodToday || ""));
      return moodSignal > 0 ? moodSignal : 0;
    };

    const moodRows = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      value: scoreFromMetrics(profile?.metrics || {})
    }));

    const myMoodAverageToday = Number(myMetrics.avgMoodToday) || 0;
    const myMoodFromLabel = moodToScore(String(myMetrics.moodToday || ""));
    const myValue = myMoodAverageToday > 0
      ? myMoodAverageToday
      : (myMoodFromLabel > 0 ? myMoodFromLabel : getTodayMoodAverageScore());

    const availableMoodRows = moodRows.filter((entry) => (Number(entry.value) || 0) > 0);
    if (!availableMoodRows.length && !(Number(myValue) > 0)) {
      moodFriendInsight.innerText = `${header}: No mood comparison yet. Add a mood check-in and track your average mood of the day.`;
    } else {
      const myComparable = Number((Number(myValue) || 0).toFixed(2));
      const topComparable = Math.max(
        myComparable,
        ...availableMoodRows.map((entry) => Number((Number(entry.value) || 0).toFixed(2)))
      );
      const leaders = availableMoodRows
        .filter((entry) => Number((Number(entry.value) || 0).toFixed(2)) === topComparable)
        .map((entry) => entry.name);
      const iAmLeading = myComparable === topComparable;
      const tied = iAmLeading && leaders.length > 0;

      const myMoodLabel = Number(myValue) > 0 ? getMoodLabelFromScore(myValue) : "Not logged";
      const yourMoodLine = Number(myValue) > 0
        ? `Your average mood of the day was ${myMoodLabel}`
        : "Your average mood of the day is not logged yet";

      const friendSummary = availableMoodRows.length
        ? availableMoodRows.map((entry) => {
          const friendName = String(entry.name || "Friend");
          const possessiveName = /s$/i.test(friendName) ? `${friendName}'` : `${friendName}'s`;
          return `${possessiveName} average mood of the day was ${getMoodLabelFromScore(entry.value)}`;
        }).join("; ")
        : "No friend mood data yet";

      let motivation = "Consistency in logging helps improve this benchmark.";
      if (tied) {
        motivation = `You are tied with ${formatLeaderNames(leaders)}. One positive reset now can move you ahead.`;
      } else if (iAmLeading) {
        motivation = "You are currently leading on mood quality today.";
      } else {
        motivation = `${formatLeaderNames(leaders)} ${leaders.length > 1 ? "are" : "is"} currently ahead. A small reset can close the gap.`;
      }

      moodFriendInsight.innerText = `Friend benchmark: ${header}: ${yourMoodLine}; ${friendSummary}. ${motivation}`;
    }
  }

  if (gratitudeFriendInsight) {
    const gratitudeRows = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      count: Math.max(0, Number(profile?.metrics?.gratitudeToday) || 0)
    }));
    const myCount = Math.max(0, Number(myMetrics.gratitudeToday) || 0);
    const allCounts = [myCount, ...gratitudeRows.map((entry) => entry.count)];
    const hasAnyData = allCounts.some((value) => value > 0);

    if (!hasAnyData) {
      gratitudeFriendInsight.innerText = `${header}: no gratitude comparison yet. Add one gratitude note now to start your consistency streak.`;
    } else {
      const friendSummary = gratitudeRows
        .map((entry) => `${entry.name} wrote ${entry.count} gratitude note${entry.count === 1 ? "" : "s"} today`)
        .join("; ");

      const topFriendCount = Math.max(0, ...gratitudeRows.map((entry) => entry.count));
      const leaders = gratitudeRows
        .filter((entry) => entry.count === topFriendCount && topFriendCount > 0)
        .map((entry) => entry.name);

      let motivation = "Great consistency. Keep logging one more gratitude note to build momentum.";
      if (myCount > topFriendCount) {
        motivation = "You are ahead right now. Keep the streak strong and inspire your circle.";
      } else if (myCount === topFriendCount && topFriendCount > 0) {
        motivation = `You are tied with ${formatLeaderNames(leaders)}. One more gratitude note puts you in front.`;
      } else if (myCount < topFriendCount) {
        const gap = topFriendCount - myCount;
        motivation = `${formatLeaderNames(leaders)} ${leaders.length > 1 ? "are" : "is"} ahead by ${gap} note${gap === 1 ? "" : "s"}. Add one now and close the gap.`;
      }

      gratitudeFriendInsight.innerText = `${header}: You wrote ${myCount} gratitude note${myCount === 1 ? "" : "s"} today; ${friendSummary}. ${motivation}`;
    }
  }

  if (dailyChallengeFriendInsight) {
    const myCompleted = (Number(myMetrics.dailyChallengeCompletedToday) || 0) > 0;
    const challengeRows = compareProfiles.map((profile, index) => ({
      name: friendNames[index],
      completed: (Number(profile?.metrics?.dailyChallengeCompletedToday) || 0) > 0
    }));
    const friendStatuses = challengeRows
      .map((entry) => `${entry.name}: ${entry.completed ? "Completed" : "Pending"}`)
      .join("; ");
    const anyFriendCompleted = challengeRows.some((entry) => entry.completed);
    let motivation = "Nobody has completed it yet. Be first today and set the tone.";
    if (myCompleted && challengeRows.every((entry) => !entry.completed)) {
      motivation = "You are currently ahead. Strong discipline, keep the streak going.";
    } else if (!myCompleted && anyFriendCompleted) {
      const firstCompletedFriend = challengeRows.find((entry) => entry.completed)?.name || "A friend";
      motivation = `${firstCompletedFriend} has already completed their daily challenge. Finish yours now and match that momentum.`;
    } else if (myCompleted && anyFriendCompleted) {
      motivation = "Multiple people are already completed. Elite consistency from your circle.";
    }

    dailyChallengeFriendInsight.innerText = `${header}: You: ${myCompleted ? "Completed" : "Pending"}; ${friendStatuses}. ${motivation}`;
  }

  if (wellnessFriendInsight) {
    const wellnessFriendsWithSync = compareProfiles.map((profile, index) => {
      const metrics = profile?.metrics || {};
      const hasLiveWellness = Object.prototype.hasOwnProperty.call(metrics, "wellnessScoreToday");
      const directValue = Number(metrics?.wellnessScoreToday);
      const derivedValue = calculateWellnessScoreFromMetrics(metrics);
      const effectiveValue = (hasLiveWellness && Number.isFinite(directValue))
        ? directValue
        : derivedValue;
      return {
        name: friendNames[index],
        hasLiveWellness,
        value: Number.isFinite(effectiveValue)
          ? Math.max(0, Math.min(100, Math.round(effectiveValue)))
          : null
      };
    });

    const availableWellnessFriends = wellnessFriendsWithSync.filter((entry) => Number.isFinite(entry.value));
    if (!availableWellnessFriends.length) {
      wellnessFriendInsight.innerText = "Wellness benchmark sync in progress. Friends need to open the app once to share live wellness metrics.";
      return;
    }

    const myHasLiveWellness = Object.prototype.hasOwnProperty.call(myMetrics, "wellnessScoreToday");
    const myRawWellness = Number(myMetrics.wellnessScoreToday);
    const myValue = (myHasLiveWellness && Number.isFinite(myRawWellness))
      ? Math.max(0, Math.min(100, Math.round(myRawWellness)))
      : calculateWellnessScoreValue();

    let comparisonText = buildNumericFriendComparisonText({
      friends: availableWellnessFriends,
      myValue,
      unit: "wellness score today",
      digits: 0,
      leadThreshold: 2,
      noDataMessage: "no wellness comparison yet. Log mood, sleep, water, and tasks to generate your score"
    });

    const pendingSyncCount = wellnessFriendsWithSync.length - availableWellnessFriends.length;
    if (pendingSyncCount > 0) {
      comparisonText += ` ${pendingSyncCount} friend${pendingSyncCount === 1 ? "" : "s"} pending live sync.`;
    }

    wellnessFriendInsight.innerText = comparisonText;
  }
}

function renderFriendRequests(rows) {
  const safeRows = Array.isArray(rows) ? rows : [];

  const hasUnseen = safeRows.length > 0;
  if (accountBtn) accountBtn.classList.toggle("has-pending-request", hasUnseen);
  if (friendsTabBtn) friendsTabBtn.classList.toggle("has-pending-request", hasUnseen);
  if (!friendRequestsList) return;
  if (!safeRows.length) {
    friendRequestsList.innerHTML = `<div class="friend-row"><small>No pending requests yet.</small></div>`;
    return;
  }

  friendRequestsList.innerHTML = "";
  safeRows.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "friend-row";
    const senderDisplayName = escapeHtml(getFriendDisplayName({
      displayName: entry.fromDisplayName,
      name: entry.fromName,
      email: entry.fromEmail,
      uid: entry.fromUid
    }, "Unknown"));
    const senderHandle = escapeHtml(formatUsernameHandle(entry.fromUsername, entry.fromEmail));
    row.innerHTML = `<strong>${senderDisplayName}</strong><small>${senderHandle}</small><small>Pending friend request</small>`;

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const acceptBtn = document.createElement("button");
    acceptBtn.innerText = "Accept";
    acceptBtn.onclick = () => respondToFriendRequest(entry, "accept");

    const declineBtn = document.createElement("button");
    declineBtn.className = "import-transfer-cancel";
    declineBtn.innerText = "Decline";
    declineBtn.onclick = () => respondToFriendRequest(entry, "decline");

    actions.append(acceptBtn, declineBtn);
    row.append(actions);
    friendRequestsList.appendChild(row);
  });
}

function renderFriendsInsights(rows, myProfile) {
  if (!friendsInsightsList) return;
  if (!rows.length) {
    friendsInsightsList.innerHTML = `<div class="friend-row"><small>No friends linked yet. Send a request to start shared progress.</small></div>`;
    return;
  }

  friendsInsightsList.innerHTML = "";
  rows.forEach((entry) => {
    const profile = entry.profile || {};
    const metrics = profile.metrics || {};
    const friendName = escapeHtml(getFriendDisplayName({
      ...profile,
      uid: profile.uid || entry.friendUid,
      email: profile.email || entry.friendEmail,
      name: profile.name || entry.friendName
    }, "Friend"));
    const moodLabel = escapeHtml(String(metrics.avgMoodLabel || getMoodLabelFromScore(metrics.avgMoodScore)));
    const moodTodayAverage = Number(metrics.avgMoodToday) || moodToScore(metrics.moodToday);
    const moodTodayAverageText = moodTodayAverage > 0 ? getMoodLabelFromScore(moodTodayAverage) : "Not logged";
    const latestMoodMeta = getMoodStateMeta(metrics.moodToday);
    const latestMoodText = escapeHtml(latestMoodMeta.logged ? latestMoodMeta.label : "Not logged");
    const motivation = escapeHtml(buildFriendMotivationLine(profile, myProfile));

    const row = document.createElement("div");
    row.className = "friend-row";
    row.innerHTML = `
      <strong>${friendName}</strong>
      <small>Tasks logged: ${Number(metrics.totalTasksLogged) || 0} • Avg tasks/day: ${(Number(metrics.avgTasksCompletedDaily) || 0).toFixed(1)}</small>
      <small>Water avg: ${(Number(metrics.avgWaterDaily) || 0).toFixed(1)} cups/day • Sleep avg: ${(Number(metrics.avgSleepHours) || 0).toFixed(1)}h</small>
      <small>Mood avg: ${moodLabel}</small>
      <small>Average mood of the day: ${moodTodayAverageText}</small>
      <small>Latest mood today: ${latestMoodText}</small>
      <small>${motivation}</small>
    `;
    friendsInsightsList.appendChild(row);
  });
}

function renderCurrentFriends(rows) {
  if (!currentFriendsList) return;
  if (!rows.length) {
    currentFriendsList.innerHTML = `<div class="friend-row"><small>No friends linked yet.</small></div>`;
    return;
  }

  currentFriendsList.innerHTML = "";
  rows.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "friend-row";
    const friendDisplayName = escapeHtml(getFriendDisplayName({
      displayName: entry.friendDisplayName,
      uid: entry.friendUid,
      email: entry.friendEmail,
      name: entry.friendName
    }, "Friend"));
    const friendHandle = escapeHtml(formatUsernameHandle(entry.friendUsername, entry.friendEmail));
    row.innerHTML = `<strong>${friendDisplayName}</strong><small>${friendHandle}</small><small>Connected friend</small>`;

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const unfriendBtn = document.createElement("button");
    unfriendBtn.className = "import-transfer-cancel";
    unfriendBtn.innerText = "Unfriend";
    unfriendBtn.onclick = async () => {
      const confirmText = `Remove ${friendDisplayName.replace(/&amp;/g, "&")} from your friends list?`;
      if (!confirm(confirmText)) return;
      await unfriendByUid(String(entry.friendUid || ""));
    };

    actions.appendChild(unfriendBtn);
    row.append(actions);
    currentFriendsList.appendChild(row);
  });
}

function formatRequestExpiryLabel(entry) {
  const createdMs = Number(entry?.createdAtMs)
    || getOptionalTimestampMs(entry?.createdAt)
    || Number(entry?.updatedAtMs)
    || getOptionalTimestampMs(entry?.updatedAt)
    || getServerNowDate().getTime();
  const remainingMs = Math.max(0, (createdMs + FRIEND_REQUEST_EXPIRY_MS) - getServerNowDate().getTime());
  const hours = Math.ceil(remainingMs / (60 * 60 * 1000));
  if (hours <= 24) return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  const days = Math.ceil(hours / 24);
  return `${days} ${days === 1 ? "day" : "days"}`;
}

function stopSentRequestExpiryTicker() {
  if (!sentRequestExpiryTicker) return;
  clearInterval(sentRequestExpiryTicker);
  sentRequestExpiryTicker = null;
}

function refreshSentRequestExpiryLabels() {
  if (!sentRequestsList) return;
  const expiryEls = sentRequestsList.querySelectorAll(".sent-request-expiry[data-created-ms]");
  if (!expiryEls.length) {
    stopSentRequestExpiryTicker();
    return;
  }

  expiryEls.forEach((el) => {
    const createdMs = Number(el.getAttribute("data-created-ms")) || getServerNowDate().getTime();
    el.textContent = formatRequestExpiryLabel({ createdAtMs: createdMs });
  });
}

function ensureSentRequestExpiryTicker() {
  if (sentRequestExpiryTicker) return;
  sentRequestExpiryTicker = setInterval(() => {
    refreshSentRequestExpiryLabels();
  }, 60 * 1000);
}

function getFriendRequestActorKey(uidValue, emailValue) {
  const uid = String(uidValue || "").trim();
  if (uid) return `uid:${uid}`;
  const email = String(emailValue || "").trim().toLowerCase();
  return email ? `email:${email}` : "";
}

function isTerminalFriendRequestStatus(statusValue) {
  const status = String(statusValue || "").trim().toLowerCase();
  return status === "accepted"
    || status === "declined"
    || status === "cancelled"
    || status === "expired"
    || status === "unfriended";
}

function renderSentFriendRequests(rows) {
  if (!sentRequestsList) return;
  if (!rows.length) {
    stopSentRequestExpiryTicker();
    sentRequestsList.innerHTML = `<div class="friend-row"><small>No pending sent requests.</small></div>`;
    return;
  }

  sentRequestsList.innerHTML = "";
  rows.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "friend-row";
    const friendDisplayName = escapeHtml(getFriendDisplayName({
      displayName: entry.toDisplayName,
      uid: entry.toUid,
      email: entry.toEmail,
      name: entry.toName
    }, "Friend"));
    const friendHandle = escapeHtml(formatUsernameHandle(entry.toUsername, entry.toEmail));
    const createdMs = Number(entry?.createdAtMs)
      || getOptionalTimestampMs(entry?.createdAt)
      || Number(entry?.updatedAtMs)
      || getOptionalTimestampMs(entry?.updatedAt)
      || getServerNowDate().getTime();
    const expiry = escapeHtml(formatRequestExpiryLabel({ createdAtMs: createdMs }));
    row.innerHTML = `<strong>${friendDisplayName}</strong><small>${friendHandle}</small><small>Pending request • Expires in <span class="sent-request-expiry" data-created-ms="${createdMs}">${expiry}</span></small>`;

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const cancelBtn = document.createElement("button");
    cancelBtn.className = "import-transfer-cancel";
    cancelBtn.innerText = "Cancel Request";
    cancelBtn.onclick = async () => {
      if (!confirm(`Cancel request to ${friendDisplayName.replace(/&amp;/g, "&")}?`)) return;
      await cancelSentFriendRequest(entry);
    };

    actions.appendChild(cancelBtn);
    row.append(actions);
    sentRequestsList.appendChild(row);
  });

  refreshSentRequestExpiryLabels();
  ensureSentRequestExpiryTicker();
}

async function loadSentFriendRequests(userId) {
  if (!sentRequestsList || !userId) return;

  try {
    const userEmail = String(auth.currentUser?.email || "").trim().toLowerCase();
    let queueRows = [];
    try {
      const queueSnap = await getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", userId)));
      queueRows = queueSnap.docs.map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }));
    } catch (_) {
      // Fallback to sender-owned sent docs only when queue read is unavailable.
      queueRows = [];
    }
    const queueStatusByTarget = new Map();
    queueRows.forEach((entry) => {
      const toUid = String(entry.toUid || "").trim();
      const toEmail = String(entry.toEmail || "").trim().toLowerCase();
      const status = String(entry.status || "").trim().toLowerCase();
      const requestNonce = String(entry.requestNonce || "").trim();
      const updatedAtMs = Number(entry.updatedAtMs)
        || Number(entry.createdAtMs)
        || getOptionalTimestampMs(entry.updatedAt)
        || getOptionalTimestampMs(entry.respondedAt)
        || getOptionalTimestampMs(entry.cancelledAt)
        || getOptionalTimestampMs(entry.expiredAt)
        || getOptionalTimestampMs(entry.createdAt)
        || 0;

      const keys = [];
      if (toUid) keys.push(`uid:${toUid}`);
      if (toEmail) keys.push(`email:${toEmail}`);
      keys.forEach((key) => {
        const existing = queueStatusByTarget.get(key);
        if (!existing || updatedAtMs >= Number(existing.updatedAtMs || 0)) {
          queueStatusByTarget.set(key, { status, updatedAtMs, requestNonce });
        }
      });
    });

    const snap = await getDocs(collection(db, "users", userId, "friendRequestsSent"));
    const nowMs = getServerNowDate().getTime();
    const expiryUpdates = [];
    const statusSyncUpdates = [];
    const nonceBackfillUpdates = [];
    let rows = snap.docs
      .map((docSnap) => ({ ref: docSnap.ref, id: docSnap.id, ...docSnap.data() }))
      .map((entry) => {
        const pending = String(entry.status || "pending") === "pending";
        const existingNonce = String(entry.requestNonce || "").trim();
        if (!pending || existingNonce) return entry;

        const fallbackNonce = `legacy_${String(entry.id || "request")}_${Date.now().toString(36)}`;
        const toUid = String(entry.toUid || "").trim();
        const toEmail = String(entry.toEmail || "").trim().toLowerCase();
        nonceBackfillUpdates.push(setDoc(entry.ref, {
          requestNonce: fallbackNonce,
          updatedAt: serverTimestamp(),
          updatedAtMs: Date.now()
        }, { merge: true }).catch((err) => structuredLog('warn', 'sent.nonce.backfill', err?.message || String(err))));

        const queueKeys = [];
        if (toUid) queueKeys.push(toUid);
        if (toEmail) queueKeys.push(`email_${encodeURIComponent(toEmail)}`);
        [...new Set(queueKeys)].forEach((key) => {
          const queueId = `${userId}__${key}`;
          nonceBackfillUpdates.push(setDoc(doc(db, "friendRequestsQueue", queueId), {
            requestNonce: fallbackNonce,
            updatedAt: serverTimestamp(),
            updatedAtMs: Date.now(),
            queueId,
            targetKey: key
          }, { merge: true }).catch((err) => structuredLog('warn', 'queue.nonce', err?.message || String(err))));
        });

        return { ...entry, requestNonce: fallbackNonce };
      })
      .filter((entry) => {
        const pending = String(entry.status || "pending") === "pending";
        if (!pending) return false;

        const toUid = String(entry.toUid || "").trim();
        const toEmail = String(entry.toEmail || "").trim().toLowerCase();
        const queueCandidates = [
          toUid ? queueStatusByTarget.get(`uid:${toUid}`) : null,
          toEmail ? queueStatusByTarget.get(`email:${toEmail}`) : null
        ].filter(Boolean);
        queueCandidates.sort((a, b) => Number(b?.updatedAtMs || 0) - Number(a?.updatedAtMs || 0));
        const queueStatusEntry = queueCandidates[0] || null;
        const queueStatus = String(queueStatusEntry?.status || "");
        const sentRequestNonce = String(entry.requestNonce || "").trim();
        const queueRequestNonce = String(queueStatusEntry?.requestNonce || "").trim();
        const queueStatusUpdatedAtMs = Number(queueStatusEntry?.updatedAtMs || 0);
        const sentEntryUpdatedAtMs = Number(entry.updatedAtMs)
          || Number(entry.createdAtMs)
          || getOptionalTimestampMs(entry.updatedAt)
          || getOptionalTimestampMs(entry.createdAt)
          || 0;
        const nonceMismatch = !!sentRequestNonce && !!queueRequestNonce && sentRequestNonce !== queueRequestNonce;
        const missingQueueNonceForKnownSent = !!sentRequestNonce && !queueRequestNonce;
        const terminalQueueStatus = isTerminalFriendRequestStatus(queueStatus);
        if (terminalQueueStatus
          && !nonceMismatch
          && !missingQueueNonceForKnownSent) {
          statusSyncUpdates.push(setDoc(entry.ref, {
            status: queueStatus,
            updatedAt: serverTimestamp(),
            updatedAtMs: Date.now()
          }, { merge: true }).catch((err) => structuredLog('warn', 'sent.statusSync', err?.message || String(err))));
          return false;
        }

        const expired = isFriendRequestExpired(entry, nowMs);
        if (expired) {
          const requestNonce = String(entry.requestNonce || "").trim();
          expiryUpdates.push(setDoc(entry.ref, {
            status: "expired",
            expiredAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            updatedAtMs: Date.now(),
            ...(requestNonce ? { requestNonce } : {})
          }, { merge: true }).catch((err) => structuredLog('warn', 'sent.expiry', err?.message || String(err))));

          const queueKeys = [];
          if (toUid) queueKeys.push(toUid);
          if (toEmail) queueKeys.push(`email_${encodeURIComponent(toEmail)}`);
          [...new Set(queueKeys)].forEach((key) => {
            const queueId = `${userId}__${key}`;
            expiryUpdates.push(setDoc(doc(db, "friendRequestsQueue", queueId), {
              status: "expired",
              expiredAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
              updatedAtMs: Date.now(),
              ...(requestNonce ? { requestNonce } : {}),
              queueId,
              targetKey: key
            }, { merge: true }).catch((err) => structuredLog('warn', 'queue.expiry', err?.message || String(err))));
          });

          if (toUid) {
            expiryUpdates.push(setDoc(doc(db, "users", toUid, "friendRequests", userId), {
              status: "expired",
              expiredAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
              updatedAtMs: Date.now(),
              ...(requestNonce ? { requestNonce } : {})
            }, { merge: true }).catch((err) => structuredLog('warn', 'incoming.expiry', err?.message || String(err))));
          }
        }
        return !expired;
      })
      .sort((a, b) => {
        const aMs = getOptionalTimestampMs(a.createdAt) || 0;
        const bMs = getOptionalTimestampMs(b.createdAt) || 0;
        return bMs - aMs;
      });
    await Promise.all([...expiryUpdates, ...statusSyncUpdates, ...nonceBackfillUpdates]);

    const emailSet = [...new Set(rows
      .map((entry) => String(entry.toEmail || "").trim().toLowerCase())
      .filter(Boolean))];
    const toEmailIdentityMap = new Map();
    await Promise.all(emailSet.map(async (email) => {
      const identity = await resolveDirectoryIdentityByEmail(email);
      toEmailIdentityMap.set(email, identity || { username: "", displayName: "" });
    }));

    rows = rows.map((entry) => {
      const toEmail = String(entry.toEmail || "").trim().toLowerCase();
      const identity = toEmailIdentityMap.get(toEmail) || { username: "", displayName: "" };
      const toUsername = getNormalizedUsernameIdentity(
        entry.toUsername || entry?.toProfile?.username || identity.username,
        toEmail
      ) || identity.username
        || getEmailLocalIdentity(toEmail);
      const toDisplayName = normalizeDisplayNameValue(entry.toDisplayName)
        || normalizeDisplayNameValue(entry?.toProfile?.displayName)
        || normalizeDisplayNameValue(entry.toName)
        || identity.displayName
        || (toEmail === userEmail ? "You" : "")
        || toUsername
        || "Friend";
      return {
        ...entry,
        toEmail,
        toUsername,
        toDisplayName,
        toName: toDisplayName
      };
    });

    renderSentFriendRequests(rows);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function cancelSentFriendRequest(entry) {
  const user = auth.currentUser;
  if (!user?.uid) return;

  const entryId = String(entry?.id || "").trim();
  const toUid = String(entry?.toUid || "").trim();
  const toEmail = String(entry?.toEmail || "").trim().toLowerCase();
  if (!entryId) return;

  try {
    const requestNonce = String(entry?.requestNonce || "").trim();
    await setDoc(doc(db, "users", user.uid, "friendRequestsSent", entryId), {
      status: "cancelled",
      cancelledAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now(),
      ...(requestNonce ? { requestNonce } : {})
    }, { merge: true });

    const queueKeys = [];
    if (toUid) queueKeys.push(toUid);
    if (toEmail) queueKeys.push(`email_${encodeURIComponent(toEmail)}`);
    const uniqueKeys = [...new Set(queueKeys)];
    await Promise.all(uniqueKeys.map((key) => {
      const queueId = `${user.uid}__${key}`;
      return setDoc(doc(db, "friendRequestsQueue", queueId), {
        status: "cancelled",
        cancelledAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        updatedAtMs: Date.now(),
        ...(requestNonce ? { requestNonce } : {}),
        queueId,
        targetKey: key
      }, { merge: true }).catch((err) => structuredLog('warn', 'queue.cancel', err?.message || String(err)));
    }));

    if (toUid) {
      await setDoc(doc(db, "users", toUid, "friendRequests", user.uid), {
        status: "cancelled",
        cancelledAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
        updatedAtMs: Date.now(),
        ...(requestNonce ? { requestNonce } : {})
      }, { merge: true }).catch((err) => structuredLog('warn', 'incoming.cancel', err?.message || String(err)));
    }

    showToast("Sent request cancelled.");
    await loadSentFriendRequests(user.uid);
    await loadFriendRequests(user.uid);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function unfriendByUid(friendUid) {
  const user = auth.currentUser;
  const safeFriendUid = String(friendUid || "").trim();
  if (!user?.uid || !safeFriendUid) return;

  try {
    const userEmail = String(user.email || "").trim().toLowerCase();
    let friendEmail = "";
    try {
      const myFriendRes = await fsGetDoc(doc(db, "users", user.uid, "friends", safeFriendUid), 'friend');
      if (myFriendRes.exists) {
        friendEmail = String(myFriendRes.data?.friendEmail || "").trim().toLowerCase();
      }
    } catch (_) {
      friendEmail = "";
    }

    // Persistent local block so background self-heal/history recovery cannot resurrect this friendship.
    await setDoc(doc(db, "users", user.uid, "friendUnfriended", safeFriendUid), {
      friendUid: safeFriendUid,
      status: "unfriended",
      unfriendedBy: user.uid,
      unfriendedAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true }).catch((err) => structuredLog('warn', 'friend.unfriend.local', err?.message || String(err)));

    // Best-effort remote block so reverse-side recovery also stays blocked.
    await setDoc(doc(db, "users", safeFriendUid, "friendUnfriended", user.uid), {
      friendUid: user.uid,
      status: "unfriended",
      unfriendedBy: user.uid,
      unfriendedAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true }).catch((err) => structuredLog('warn', 'friend.unfriend.remote', err?.message || String(err)));

    // Local safety mark: if delete is blocked/transient, this keeps it hidden from accepted-only views.
    await setDoc(doc(db, "users", user.uid, "friends", safeFriendUid), {
      status: "unfriended",
      unfriendedAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true }).catch((err) => structuredLog('warn', 'friend.unfriend.mark', err?.message || String(err)));

    await deleteDoc(doc(db, "users", user.uid, "friends", safeFriendUid)).catch((err) => structuredLog('warn', 'friend.delete.local', err?.message || String(err)));
    await deleteDoc(doc(db, "users", safeFriendUid, "friends", user.uid)).catch((err) => structuredLog('warn', 'friend.delete.remote', err?.message || String(err)));

    const sentDocsSnap = await fsGetDocs(collection(db, "users", user.uid, "friendRequestsSent"), 'friendRequestsSent');
    const sentUpdates = [];
    sentDocsSnap.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const sameUid = String(data.toUid || "") === safeFriendUid;
      const sameEmail = friendEmail && String(data.toEmail || "").trim().toLowerCase() === friendEmail;
      if (!sameUid && !sameEmail) return;
      sentUpdates.push(setDoc(docSnap.ref, {
        status: "unfriended",
        unfriendedAt: serverTimestamp(),
        updatedAt: serverTimestamp()
      }, { merge: true }).catch((err) => structuredLog('warn', 'sent.unfriend', err?.message || String(err))));
    });
    await Promise.all(sentUpdates);

    await setDoc(doc(db, "users", user.uid, "friendRequests", safeFriendUid), {
      status: "unfriended",
      unfriendedAt: serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true }).catch((err) => structuredLog('warn', 'incoming.unfriend', err?.message || String(err)));

    await setDoc(doc(db, "users", user.uid, "friendRequestDecisions", safeFriendUid), {
      fromUid: safeFriendUid,
      status: "unfriended",
      updatedAt: serverTimestamp()
    }, { merge: true }).catch((err) => structuredLog('warn', 'decision.unfriend', err?.message || String(err)));

    // Mark queue relationship entries as unfriended on both directions when available.
    const [myToFriendQueue, friendToMeQueue, friendToMeByEmailQueue] = await Promise.all([
      getDocs(query(
        collection(db, "friendRequestsQueue"),
        where("fromUid", "==", user.uid)
      )),
      getDocs(query(
        collection(db, "friendRequestsQueue"),
        where("toUid", "==", user.uid)
      )),
      userEmail
        ? getDocs(query(
          collection(db, "friendRequestsQueue"),
          where("toEmail", "==", userEmail)
        ))
        : Promise.resolve({ docs: [] })
    ]);

    const queueUpdates = [];
    myToFriendQueue.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const sameUid = String(data.toUid || "") === safeFriendUid;
      const sameEmail = !!friendEmail && String(data.toEmail || "").trim().toLowerCase() === friendEmail;
      if (sameUid || sameEmail) {
        queueUpdates.push(setDoc(docSnap.ref, {
          status: "unfriended",
          unfriendedBy: user.uid,
          updatedAt: serverTimestamp()
        }, { merge: true }));
      }
    });
    friendToMeQueue.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      if (String(data.fromUid || "") === safeFriendUid) {
        queueUpdates.push(setDoc(docSnap.ref, {
          status: "unfriended",
          unfriendedBy: user.uid,
          updatedAt: serverTimestamp()
        }, { merge: true }));
      }
    });
    friendToMeByEmailQueue.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      if (String(data.fromUid || "") === safeFriendUid) {
        queueUpdates.push(setDoc(docSnap.ref, {
          status: "unfriended",
          unfriendedBy: user.uid,
          updatedAt: serverTimestamp()
        }, { merge: true }));
      }
    });
    await Promise.all(queueUpdates.map((promise) => promise.catch((err) => structuredLog('warn', 'queue.update', err?.message || String(err)))));

    showToast("Friend removed.");
    await loadSentFriendRequests(user.uid);
    await loadFriendRequests(user.uid);
    await loadFriendsInsights(user.uid);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function markFriendshipUnfriendedForAccountClear(user, friendUid, options = {}) {
  const userId = String(user?.uid || "").trim();
  const safeFriendUid = String(friendUid || "").trim();
  if (!userId || !safeFriendUid || safeFriendUid === userId) return;

  const userEmail = String(user?.email || "").trim().toLowerCase();
  let friendEmail = String(options.friendEmail || "").trim().toLowerCase();
  if (!friendEmail) {
    try {
      const myFriendRes = await fsGetDoc(doc(db, "users", userId, "friends", safeFriendUid), 'friend');
      if (myFriendRes.exists) {
        friendEmail = String(myFriendRes.data?.friendEmail || "").trim().toLowerCase();
      }
    } catch (_) {
      friendEmail = "";
    }
  }

  const unfriendedPayload = {
    status: "unfriended",
    unfriendedBy: userId,
    unfriendedAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  await Promise.allSettled([
    setDoc(doc(db, "users", userId, "friendUnfriended", safeFriendUid), {
      friendUid: safeFriendUid,
      ...unfriendedPayload
    }, { merge: true }),
    setDoc(doc(db, "users", safeFriendUid, "friendUnfriended", userId), {
      friendUid: userId,
      ...unfriendedPayload
    }, { merge: true }),
    setDoc(doc(db, "users", userId, "friends", safeFriendUid), unfriendedPayload, { merge: true }),
    setDoc(doc(db, "users", safeFriendUid, "friends", userId), unfriendedPayload, { merge: true })
  ]);

  await Promise.allSettled([
    deleteDoc(doc(db, "users", userId, "friends", safeFriendUid)),
    deleteDoc(doc(db, "users", safeFriendUid, "friends", userId))
  ]);

  const queueQueries = [
    getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", userId))),
    getDocs(query(collection(db, "friendRequestsQueue"), where("toUid", "==", userId))),
    getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", safeFriendUid))),
    getDocs(query(collection(db, "friendRequestsQueue"), where("toUid", "==", safeFriendUid)))
  ];
  if (userEmail) queueQueries.push(getDocs(query(collection(db, "friendRequestsQueue"), where("toEmail", "==", userEmail))));
  if (friendEmail) queueQueries.push(getDocs(query(collection(db, "friendRequestsQueue"), where("toEmail", "==", friendEmail))));

  const requestCollectionReads = [
    getDocs(collection(db, "users", userId, "friendRequestsSent")),
    getDocs(collection(db, "users", userId, "friendRequests")),
    getDocs(collection(db, "users", safeFriendUid, "friendRequestsSent")),
    getDocs(collection(db, "users", safeFriendUid, "friendRequests"))
  ];

  const [queueResults, requestResults] = await Promise.all([
    Promise.allSettled(queueQueries),
    Promise.allSettled(requestCollectionReads)
  ]);

  const queueDocs = queueResults
    .filter((result) => result.status === "fulfilled")
    .flatMap((result) => result.value.docs || []);
  const queueDeletes = [];
  const seenQueueDocIds = new Set();
  queueDocs.forEach((docSnap) => {
    const queueId = String(docSnap.id || "");
    if (queueId && seenQueueDocIds.has(queueId)) return;
    if (queueId) seenQueueDocIds.add(queueId);
    const data = docSnap.data() || {};
    const fromUid = String(data.fromUid || "").trim();
    const toUid = String(data.toUid || "").trim();
    const toEmail = String(data.toEmail || "").trim().toLowerCase();
    const matchesPair =
      (fromUid === userId && toUid === safeFriendUid)
      || (fromUid === safeFriendUid && toUid === userId)
      || (fromUid === userId && friendEmail && toEmail === friendEmail)
      || (fromUid === safeFriendUid && userEmail && toEmail === userEmail);
    if (!matchesPair) return;
    queueDeletes.push(fsDeleteDoc(docSnap.ref));
  });

  const requestDocs = requestResults
    .filter((result) => result.status === "fulfilled")
    .flatMap((result) => result.value.docs || []);
  const requestDeletes = [];
  requestDocs.forEach((docSnap) => {
    const data = docSnap.data() || {};
    const fromUid = String(data.fromUid || "").trim();
    const toUid = String(data.toUid || "").trim();
    const fromEmail = String(data.fromEmail || "").trim().toLowerCase();
    const toEmail = String(data.toEmail || "").trim().toLowerCase();
    const docId = String(docSnap.id || "").trim();
    const ownerMatch = String(docSnap.ref?.path || "").match(/users\/([^/]+)\//);
    const ownerUid = String(ownerMatch?.[1] || "").trim();
    const matchesPair =
      (fromUid === userId && (toUid === safeFriendUid || docId === safeFriendUid || (friendEmail && toEmail === friendEmail)))
      || (fromUid === safeFriendUid && (toUid === userId || docId === userId || (userEmail && toEmail === userEmail)))
      || (ownerUid === userId && docId === safeFriendUid)
      || (ownerUid === safeFriendUid && docId === userId)
      || (userEmail && friendEmail && (
        (fromEmail === userEmail && toEmail === friendEmail)
        || (fromEmail === friendEmail && toEmail === userEmail)
      ));
    if (!matchesPair) return;
    requestDeletes.push(fsDeleteDoc(docSnap.ref));
  });

  await Promise.allSettled([
    ...queueDeletes,
    ...requestDeletes,
    setDoc(doc(db, "users", userId, "friendRequestDecisions", safeFriendUid), {
      fromUid: safeFriendUid,
      status: "unfriended",
      unfriendedBy: userId,
      updatedAt: serverTimestamp()
    }, { merge: true }),
    setDoc(doc(db, "users", safeFriendUid, "friendRequestDecisions", userId), {
      fromUid: userId,
      status: "unfriended",
      unfriendedBy: userId,
      updatedAt: serverTimestamp()
    }, { merge: true })
  ]);
}

async function upsertUserDirectoryProfile(user, options = {}) {
  if (!user?.uid) return;
  const safeEmail = String(user.email || "").trim().toLowerCase();
  const emailLocalIdentity = getEmailLocalIdentity(safeEmail);
  const providerIds = Array.isArray(user.providerData)
    ? user.providerData.map((entry) => String(entry?.providerId || "").trim().toLowerCase())
    : [];
  const isGoogleAccount = providerIds.includes("google.com");

  let existingProfileData = {};
  try {
    const existingProfileRes = await fsGetDoc(doc(db, "users", user.uid, "settings", "profile"), 'profile');
    if (existingProfileRes.exists) {
      existingProfileData = existingProfileRes.data || {};
    }
  } catch (_) {
    existingProfileData = {};
  }

  let existingUsernameFromDirectory = "";
  let existingDisplayNameFromDirectory = "";
  if (!normalizeUsernameCandidate(existingProfileData.username, safeEmail)
    && !normalizeUsernameCandidate(existingProfileData.name, safeEmail)) {
    try {
      const usernameByUidSnap = await fsGetDocs(query(
        collection(db, "usernameDirectory"),
        where("uid", "==", user.uid)
      ));
      const firstMatch = (usernameByUidSnap?.docs || [])[0];
      if (firstMatch) {
        const usernameData = firstMatch.data() || {};
        existingUsernameFromDirectory = getNormalizedUsernameIdentity(usernameData.username || usernameData.name || firstMatch.id, safeEmail);
        existingDisplayNameFromDirectory = normalizeDisplayNameValue(usernameData.displayName);
      }
    } catch (_) {
      existingUsernameFromDirectory = "";
      existingDisplayNameFromDirectory = "";
    }
  }

  const isEmailLocalUsername = (value) => {
    const normalized = getNormalizedUsernameIdentity(value, safeEmail);
    return !!normalized && !!emailLocalIdentity && normalized === emailLocalIdentity;
  };

  const optionUsernameRaw = getNormalizedUsernameIdentity(options?.username, safeEmail);
  const optionUsernameLegacyRaw = String(options?.username || "").trim();
  const optionUsernameHadDot = optionUsernameLegacyRaw.includes(".");
  const existingProfileUsernameLegacyRaw = String(existingProfileData.username || existingProfileData.name || "").trim();
  const existingProfileUsernameHadDot = existingProfileUsernameLegacyRaw.includes(".");
  const existingDirectoryUsernameLegacyRaw = String(existingUsernameFromDirectory || "").trim();
  const existingDirectoryUsernameHadDot = existingDirectoryUsernameLegacyRaw.includes(".");
  const existingProfileUsernameRaw = getNormalizedUsernameIdentity(existingProfileData.username || existingProfileData.name, safeEmail);
  const existingDirectoryUsernameRaw = getNormalizedUsernameIdentity(existingUsernameFromDirectory, safeEmail);

  const optionUsername = (isGoogleAccount && isEmailLocalUsername(optionUsernameRaw)) ? "" : optionUsernameRaw;
  const existingProfileUsername = (isGoogleAccount && isEmailLocalUsername(existingProfileUsernameRaw)) ? "" : existingProfileUsernameRaw;
  const existingDirectoryUsername = (isGoogleAccount && isEmailLocalUsername(existingDirectoryUsernameRaw)) ? "" : existingDirectoryUsernameRaw;

  const googleNameSeed = isGoogleAccount ? buildUsernameSeedFromDisplayName(user.displayName) : "";

  const safeUsername = optionUsername
    || existingProfileUsername
    || existingDirectoryUsername
    || googleNameSeed
    || (!isGoogleAccount ? getEmailLocalIdentity(safeEmail) : "")
    || "user";
  const legacyDotMigration = optionUsernameHadDot || existingProfileUsernameHadDot || existingDirectoryUsernameHadDot;

  const safeDisplayName = normalizeDisplayNameValue(options?.displayName)
    || normalizeDisplayNameValue(existingProfileData.displayName)
    || existingDisplayNameFromDirectory
    || normalizeDisplayNameValue(user.displayName)
    || safeUsername;

  const profilePayload = {
    uid: user.uid,
    email: safeEmail,
    name: safeUsername,
    username: safeUsername,
    displayName: safeDisplayName,
    updatedAt: serverTimestamp()
  };

  try {
    await setDoc(doc(db, "users", user.uid, "settings", "profile"), profilePayload, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
    return;
  }

  if (safeEmail) {
    try {
      await setDoc(doc(db, "userDirectory", safeEmail), profilePayload, { merge: true });
    } catch (_) {
      // Non-critical sync path; avoid surfacing global crash alert for directory mirror failures.
    }
  }

  try {
    const claimedUsername = await claimUsernameWithFallback({
      userId: user.uid,
      email: safeEmail,
      displayName: safeDisplayName,
      preferredUsername: safeUsername,
      allowSuffixFallback: (isGoogleAccount && !!googleNameSeed) || legacyDotMigration
    });

    if (accountName && claimedUsername) {
      accountName.innerText = claimedUsername;
    }

    if (claimedUsername && claimedUsername !== safeUsername) {
      const mergedProfilePayload = {
        ...profilePayload,
        name: claimedUsername,
        username: claimedUsername,
        updatedAt: serverTimestamp()
      };
      await setDoc(doc(db, "users", user.uid, "settings", "profile"), mergedProfilePayload, { merge: true });
      if (safeEmail) {
        await setDoc(doc(db, "userDirectory", safeEmail), mergedProfilePayload, { merge: true }).catch((err) => structuredLog('warn', 'profile.directory', err?.message || String(err)));
      }
    }
  } catch (claimErr) {
    const claimCode = String(claimErr?.message || "");
    if (claimCode === "USERNAME_TAKEN" || isFirestorePermissionDeniedError(claimErr)) {
      // Keep app usable when username claim cannot be refreshed in background sync.
      return;
    }
    notifyFirestoreError(claimErr);
  }
}

async function loadFriendRequests(userId, showLoginAlert = false) {
  if (!friendRequestsList || !userId) return;

  try {
    const nowMs = getServerNowDate().getTime();
    const userEmail = String(auth.currentUser?.email || "").trim().toLowerCase();

    const legacySnap = await safeGetDocs(collection(db, "users", userId, "friendRequests"));
    const legacyRawRows = legacySnap.docs
      .map((docSnap) => ({ ref: docSnap.ref, id: docSnap.id, ...docSnap.data() }));

    const queueTerminalStatusByActorKey = new Map();
    let queueRows = [];
    try {
      const [queueByUid, queueByEmail] = await Promise.all([
        safeGetDocs(query(
          collection(db, "friendRequestsQueue"),
          where("toUid", "==", userId)
        )),
        userEmail
          ? safeGetDocs(query(
            collection(db, "friendRequestsQueue"),
            where("toEmail", "==", userEmail)
          ))
          : Promise.resolve({ docs: [] })
      ]);

      const queueAddressedRows = [...queueByUid.docs, ...queueByEmail.docs]
        .map((docSnap) => ({ ref: docSnap.ref, id: docSnap.id, ...docSnap.data() }))
        .filter((entry) => {
          const toUid = String(entry.toUid || "");
          const toEmail = String(entry.toEmail || "").trim().toLowerCase();
          const addressedToMe = toUid === userId || (userEmail && toEmail === userEmail);
          return addressedToMe;
        });

      const latestQueueStatusByActorKey = new Map();
      queueAddressedRows.forEach((entry) => {
        const actorKey = getFriendRequestActorKey(entry.fromUid, entry.fromEmail);
        if (!actorKey) return;
        const status = String(entry.status || "pending").trim().toLowerCase();
        const updatedAtMs = Number(entry.updatedAtMs)
          || Number(entry.createdAtMs)
          || getOptionalTimestampMs(entry.updatedAt)
          || getOptionalTimestampMs(entry.respondedAt)
          || getOptionalTimestampMs(entry.cancelledAt)
          || getOptionalTimestampMs(entry.expiredAt)
          || getOptionalTimestampMs(entry.createdAt)
          || 0;
        const existing = latestQueueStatusByActorKey.get(actorKey);
        if (!existing || updatedAtMs >= Number(existing.updatedAtMs || 0)) {
          latestQueueStatusByActorKey.set(actorKey, { status, updatedAtMs });
        }
      });

      latestQueueStatusByActorKey.forEach((entry, actorKey) => {
        if (isTerminalFriendRequestStatus(entry.status)) {
          queueTerminalStatusByActorKey.set(actorKey, entry.status);
        }
      });

      queueRows = queueAddressedRows
        .filter((entry) => {
          const pending = !!entry.fromUid && String(entry.status || "pending") === "pending";
          if (!pending) return false;
          return !isFriendRequestExpired(entry, nowMs);
        })
        .map((entry) => ({
          ...entry,
          source: "queue",
          requestId: String(entry.id || "")
        }));
    } catch (_) {
      queueRows = [];
    }

    const legacyExpiryUpdates = [];
    const legacyTerminalSyncUpdates = [];
    const legacyRows = legacyRawRows
      .filter((entry) => {
        const pending = String(entry.status || "pending") === "pending" && !!entry.fromUid;
        if (!pending) return false;

        const actorKey = getFriendRequestActorKey(entry.fromUid, entry.fromEmail);
        const queueTerminalStatus = actorKey ? String(queueTerminalStatusByActorKey.get(actorKey) || "") : "";
        if (queueTerminalStatus) {
          legacyTerminalSyncUpdates.push(setDoc(entry.ref, {
            status: queueTerminalStatus,
            updatedAt: serverTimestamp()
          }, { merge: true }).catch((err) => structuredLog('warn', 'legacy.sync', err?.message || String(err))));
          return false;
        }

        const expired = isFriendRequestExpired(entry, nowMs);
        if (expired) {
          legacyExpiryUpdates.push(setDoc(entry.ref, {
            status: "expired",
            expiredAt: serverTimestamp(),
            updatedAt: serverTimestamp()
          }, { merge: true }).catch((err) => structuredLog('warn', 'legacy.expiry', err?.message || String(err))));
        }
        return !expired;
      })
      .map((entry) => ({
        ...entry,
        source: "legacy",
        requestId: String(entry.id || entry.fromUid || "")
      }));
    await Promise.all([...legacyExpiryUpdates, ...legacyTerminalSyncUpdates]);

    let sentFeedRows = [];
    try {
      const [sentByUidSnap, sentByEmailSnap] = await Promise.all([
        safeGetDocs(query(
          collectionGroup(db, "friendRequestsSent"),
          where("toUid", "==", userId)
        )),
        userEmail
          ? safeGetDocs(query(
            collectionGroup(db, "friendRequestsSent"),
            where("toEmail", "==", userEmail)
          ))
          : Promise.resolve({ docs: [] })
      ]);

      sentFeedRows = [...sentByUidSnap.docs, ...sentByEmailSnap.docs]
        .map((docSnap) => {
          const data = docSnap.data() || {};
          const parentUid = docSnap.ref?.parent?.parent?.id || "";
          return {
            id: docSnap.id,
            ref: docSnap.ref,
            ...data,
            fromUid: String(data.fromUid || parentUid || ""),
            fromEmail: String(data.fromEmail || ""),
            fromName: String(data.fromName || data.fromEmail || "Friend"),
            toUid: String(data.toUid || userId),
            toEmail: String(data.toEmail || "").trim().toLowerCase(),
            status: String(data.status || "pending"),
            source: "sentFeed",
            requestId: String(docSnap.id || "")
          };
        })
        .filter((entry) => {
          const matchesUser = entry.toUid === userId || (userEmail && entry.toEmail === userEmail);
          const pending = !!entry.fromUid && entry.status === "pending" && !!matchesUser;
          if (!pending) return false;

          const actorKey = getFriendRequestActorKey(entry.fromUid, entry.fromEmail);
          if (actorKey && queueTerminalStatusByActorKey.has(actorKey)) return false;

          return !isFriendRequestExpired(entry, nowMs);
        });
    } catch (_) {
      sentFeedRows = [];
    }

    const seen = new Set();
    let rows = [...legacyRows, ...queueRows, ...sentFeedRows]
      .filter((entry) => {
        const actorKey = getFriendRequestActorKey(entry.fromUid, entry.fromEmail)
          || `${String(entry.fromUid || "")}|${String(entry.fromEmail || "").trim().toLowerCase()}`;
        const key = actorKey;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .sort((a, b) => {
        const aMs = getOptionalTimestampMs(a.createdAt) || 0;
        const bMs = getOptionalTimestampMs(b.createdAt) || 0;
        return bMs - aMs;
      });

    const fromEmails = [...new Set(rows
      .map((entry) => String(entry.fromEmail || "").trim().toLowerCase())
      .filter(Boolean))];
    const fromEmailIdentityMap = new Map();
    await Promise.all(fromEmails.map(async (email) => {
      const identity = await resolveDirectoryIdentityByEmail(email);
      fromEmailIdentityMap.set(email, identity || { username: "", displayName: "" });
    }));

    rows = rows.map((entry) => {
      const fromEmail = String(entry.fromEmail || "").trim().toLowerCase();
      const identity = fromEmailIdentityMap.get(fromEmail) || { username: "", displayName: "" };
      const fromUsername = getNormalizedUsernameIdentity(
        entry.fromUsername || entry?.fromProfile?.username || identity.username,
        fromEmail
      ) || identity.username
        || getEmailLocalIdentity(fromEmail);
      const fromDisplayName = normalizeDisplayNameValue(entry.fromDisplayName)
        || normalizeDisplayNameValue(entry?.fromProfile?.displayName)
        || normalizeDisplayNameValue(entry.fromName)
        || identity.displayName
        || fromUsername
        || "Friend";
      return {
        ...entry,
        fromEmail,
        fromUsername,
        fromDisplayName,
        fromName: fromDisplayName
      };
    });

    renderFriendRequests(rows);
    if (rows.length && showLoginAlert && !friendRequestLoginAlertShown) {
      friendRequestLoginAlertShown = true;
      alert(`You have ${rows.length} pending friend request${rows.length === 1 ? "" : "s"}. Open Account -> Friend Requests to accept or decline.`);
    }
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadFriendsInsights(userId) {
  if (!userId) return;

  try {
    const myProfile = buildUserSocialProfileSnapshot(auth.currentUser);
    const userEmail = String(auth.currentUser?.email || "").trim().toLowerCase();
    const profileFreshnessMs = (profile) => Number(profile?.generatedAtMs) || 0;
    const profileSignalScore = (profile) => {
      const metrics = profile?.metrics || {};
      return (Number(metrics.totalTasksLogged) || 0)
        + (Number(metrics.tasksToday) || 0)
        + (Number(metrics.waterToday) || 0)
        + (Number(metrics.sleepToday) || 0)
        + (Number(metrics.gratitudeToday) || 0)
        + (Number(metrics.dailyChallengeCompletedToday) || 0)
        + (Number(metrics.wellnessScoreToday) || 0)
        + (Number(metrics.avgWaterDaily) || 0)
        + (Number(metrics.avgSleepHours) || 0)
        + (Number(metrics.avgMoodToday) || 0)
        + (Number(metrics.avgMoodScore) || 0)
        + (Number(metrics.avgTasksCompletedDaily) || 0);
    };
    const pickBetterSharedProfile = (currentProfile, candidateProfile) => {
      const current = currentProfile && typeof currentProfile === "object" ? currentProfile : null;
      const candidate = candidateProfile && typeof candidateProfile === "object" ? candidateProfile : null;
      if (!current) return candidate;
      if (!candidate) return current;

      const currentFreshness = profileFreshnessMs(current);
      const candidateFreshness = profileFreshnessMs(candidate);
      if (candidateFreshness > currentFreshness) return candidate;
      if (currentFreshness > candidateFreshness) return current;

      const currentSignal = profileSignalScore(current);
      const candidateSignal = profileSignalScore(candidate);
      if (candidateSignal > currentSignal) return candidate;
      return current;
    };
    let locallyUnfriendedFriendUids = new Set();
    try {
      const unfriendedSnap = await fsGetDocs(collection(db, "users", userId, "friendUnfriended"), 'friendUnfriended');
      locallyUnfriendedFriendUids = new Set(
        unfriendedSnap.docs
          .map((docSnap) => ({ id: docSnap.id, ...(docSnap.data() || {}) }))
          .filter((entry) => String(entry.status || "unfriended").trim().toLowerCase() === "unfriended")
          .map((entry) => String(entry.friendUid || entry.id || "").trim())
          .filter(Boolean)
      );
    } catch (_) {
      locallyUnfriendedFriendUids = new Set();
    }

    const friendsSnap = await getDocs(collection(db, "users", userId, "friends"));
    const persistedFriends = friendsSnap.docs
      .map((docSnap) => {
        const data = docSnap.data() || {};
        return {
          id: docSnap.id,
          ...data,
          friendUid: String(data.friendUid || docSnap.id || "").trim(),
          friendEmail: String(data.friendEmail || "").trim().toLowerCase(),
          friendName: String(data.friendName || "").trim()
        };
      });
    let friends = persistedFriends
      .filter((entry) => String(entry.status || "accepted") === "accepted" && !!entry.friendUid)
      .filter((entry) => !locallyUnfriendedFriendUids.has(String(entry.friendUid || "").trim()));

    // Clean up resurrected local docs that were re-added by stale remote self-heal/history flows.
    if (locallyUnfriendedFriendUids.size) {
      await Promise.all([...locallyUnfriendedFriendUids].map((blockedUid) => {
        if (!blockedUid) return Promise.resolve();
        return deleteDoc(doc(db, "users", userId, "friends", blockedUid)).catch((err) => structuredLog('warn', 'cleanup.unfriended', err?.message || String(err)));
      }));
    }

    const persistedFriendUids = new Set(friends.map((entry) => String(entry.friendUid || "")).filter(Boolean));

    // Self-heal one-sided friendships: if I have an accepted friend doc,
    // try to ensure the reciprocal accepted doc also exists.
    const resolvedMyUsername = normalizeUsernameForLookup(await resolveUsernameFromDirectoryEmail(userEmail));
    const myUsername = resolvedMyUsername
      || getSafeUsernameForAuthenticatedUser(auth.currentUser, accountName?.innerText || "", userEmail);
    const myDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || "")
      || normalizeDisplayNameValue(auth.currentUser?.displayName)
      || myUsername;
    await Promise.all(friends.map((entry) => {
      const friendUid = String(entry.friendUid || "").trim();
      if (!friendUid || friendUid === userId) return Promise.resolve();
      return setDoc(doc(db, "users", friendUid, "friends", userId), {
        friendUid: userId,
        friendEmail: userEmail,
        friendName: myDisplayName,
        friendUsername: myUsername,
        friendDisplayName: myDisplayName,
        status: "accepted",
        updatedAt: serverTimestamp()
      }, { merge: true }).catch(() => {});
    }));

    let queueFriends = [];
    const latestQueueProfileByFriendUid = new Map();
    const unfriendedFriendUids = new Set(locallyUnfriendedFriendUids);
    try {
      const [sentAcceptedSnap, receivedAcceptedSnap, receivedAcceptedByEmailSnap] = await Promise.all([
        getDocs(query(
          collection(db, "friendRequestsQueue"),
          where("fromUid", "==", userId)
        )),
        getDocs(query(
          collection(db, "friendRequestsQueue"),
          where("toUid", "==", userId)
        )),
        userEmail
          ? getDocs(query(
            collection(db, "friendRequestsQueue"),
            where("toEmail", "==", userEmail)
          ))
          : Promise.resolve({ docs: [] })
      ]);

      const queueRelationshipRowsRaw = [...sentAcceptedSnap.docs, ...receivedAcceptedSnap.docs, ...receivedAcceptedByEmailSnap.docs]
        .map((docSnap) => docSnap.data() || {})
        .map((entry) => {
          const isSender = String(entry.fromUid || "") === userId;
          const friendUid = String(isSender ? entry.toUid : entry.fromUid || "");
          const status = String(entry.status || "").trim().toLowerCase();
          const sharedProfileRaw = isSender ? (entry.toProfile || null) : (entry.fromProfile || null);
          const sharedMetricsRaw = sharedProfileRaw?.metrics && typeof sharedProfileRaw.metrics === "object"
            ? sharedProfileRaw.metrics
            : {};
          const sharedProfile = sharedProfileRaw && typeof sharedProfileRaw === "object"
            ? {
              uid: String(sharedProfileRaw.uid || friendUid || ""),
              email: String(sharedProfileRaw.email || (isSender ? entry.toEmail : entry.fromEmail) || "").trim().toLowerCase(),
              username: getNormalizedUsernameIdentity(sharedProfileRaw.username || sharedProfileRaw.name, String(sharedProfileRaw.email || (isSender ? entry.toEmail : entry.fromEmail) || "").trim().toLowerCase()),
              displayName: normalizeDisplayNameValue(sharedProfileRaw.displayName || sharedProfileRaw.name),
              name: String(sharedProfileRaw.name || "").trim(),
              metrics: {
                totalTasksLogged: Number(sharedMetricsRaw.totalTasksLogged) || 0,
                completedTasks: Number(sharedMetricsRaw.completedTasks) || 0,
                tasksToday: Number(sharedMetricsRaw.tasksToday) || 0,
                waterToday: Number(sharedMetricsRaw.waterToday) || 0,
                sleepToday: Number(sharedMetricsRaw.sleepToday) || 0,
                moodToday: String(sharedMetricsRaw.moodToday || ""),
                gratitudeToday: Number(sharedMetricsRaw.gratitudeToday) || 0,
                dailyChallengeCompletedToday: Number(sharedMetricsRaw.dailyChallengeCompletedToday) || 0,
                ...(Object.prototype.hasOwnProperty.call(sharedMetricsRaw, "wellnessScoreToday")
                  ? { wellnessScoreToday: Number(sharedMetricsRaw.wellnessScoreToday) || 0 }
                  : {}),
                avgWaterDaily: Number(sharedMetricsRaw.avgWaterDaily) || 0,
                avgSleepHours: Number(sharedMetricsRaw.avgSleepHours) || 0,
                avgMoodToday: Number(sharedMetricsRaw.avgMoodToday) || 0,
                avgMoodScore: Number(sharedMetricsRaw.avgMoodScore) || 0,
                avgMoodLabel: String(sharedMetricsRaw.avgMoodLabel || "Not enough data"),
                avgTasksCompletedDaily: Number(sharedMetricsRaw.avgTasksCompletedDaily) || 0,
                sampleDays: Number(sharedMetricsRaw.sampleDays) || 0
              },
              generatedAtMs: Number(sharedProfileRaw.generatedAtMs) || Date.now()
            }
            : null;
          const updatedAtMs = getOptionalTimestampMs(entry.updatedAt)
            || getOptionalTimestampMs(entry.respondedAt)
            || getOptionalTimestampMs(entry.createdAt)
            || 0;
          return {
            ...entry,
            friendUid,
            status,
            sharedProfile,
            updatedAtMs,
            friendEmail: String(isSender ? entry.toEmail : entry.fromEmail || "").trim().toLowerCase(),
            friendName: String(isSender ? (entry.toName || entry.toEmail || "Friend") : (entry.fromName || entry.fromEmail || "Friend")),
            friendUsername: String(isSender ? (entry.toUsername || "") : (entry.fromUsername || "")).trim(),
            friendDisplayName: String(isSender ? (entry.toDisplayName || "") : (entry.fromDisplayName || "")).trim()
          };
        })
        .filter((entry) => !!entry.friendUid || !!entry.friendEmail);

      const queueRelationshipRows = await Promise.all(queueRelationshipRowsRaw.map(async (entry) => {
        if (entry.friendUid) return entry;
        const friendEmail = String(entry.friendEmail || "").trim().toLowerCase();
        if (!friendEmail) return entry;

        try {
          const directoryRes = await fsGetDoc(doc(db, "userDirectory", friendEmail), 'userDirectory');
          if (!directoryRes.exists) return entry;
          const resolvedUid = String(directoryRes.data?.uid || "").trim();
          if (!resolvedUid) return entry;
          return { ...entry, friendUid: resolvedUid };
        } catch (_) {
          return entry;
        }
      }));

      const latestQueueStatusByFriendUid = new Map();
      queueRelationshipRows.forEach((entry) => {
        const friendUid = String(entry.friendUid || "");
        if (!friendUid) return;
        const existing = latestQueueStatusByFriendUid.get(friendUid);
        if (!existing || Number(entry.updatedAtMs) >= Number(existing.updatedAtMs)) {
          latestQueueStatusByFriendUid.set(friendUid, entry);
        }

        const hasProfile = entry.sharedProfile && typeof entry.sharedProfile === "object";
        if (hasProfile) {
          const existingProfileEntry = latestQueueProfileByFriendUid.get(friendUid);
          const mergedProfile = pickBetterSharedProfile(existingProfileEntry?.sharedProfile || null, entry.sharedProfile);
          if (!existingProfileEntry || mergedProfile !== existingProfileEntry.sharedProfile) {
            latestQueueProfileByFriendUid.set(friendUid, {
              sharedProfile: mergedProfile,
              updatedAtMs: Math.max(
                Number(entry.updatedAtMs || 0),
                Number(existingProfileEntry?.updatedAtMs || 0)
              )
            });
          }
        }
      });

      [...latestQueueStatusByFriendUid.values()].forEach((entry) => {
        if (entry.status === "unfriended") {
          unfriendedFriendUids.add(String(entry.friendUid || ""));
        }
      });

      queueFriends = [...latestQueueStatusByFriendUid.values()]
        .filter((entry) => entry.status === "accepted")
        .map((entry) => ({
          friendUid: String(entry.friendUid || ""),
          friendEmail: String(entry.friendEmail || "").trim().toLowerCase(),
          friendName: String(entry.friendName || "Friend"),
          friendUsername: String(entry.friendUsername || "").trim(),
          friendDisplayName: String(entry.friendDisplayName || "").trim(),
          status: "accepted",
          sharedProfile: pickBetterSharedProfile(
            entry.sharedProfile || null,
            latestQueueProfileByFriendUid.get(String(entry.friendUid || ""))?.sharedProfile || null
          )
        }))
        .filter((entry) => {
          const uid = String(entry.friendUid || "");
          if (!uid) return false;
          // Do not let stale queue-only unfriended state hide a valid accepted local friend doc.
          return !unfriendedFriendUids.has(uid) || persistedFriendUids.has(uid);
        });
    } catch (_) {
      queueFriends = [];
    }

    // If accepted relationships are visible in queue but missing in persistent friends docs,
    // backfill them so friendships remain after sign-out/sign-in cycles.
    const queueOnlyAccepted = queueFriends.filter((entry) => {
      const uid = String(entry.friendUid || "");
      return !!uid && !persistedFriendUids.has(uid);
    });
    if (queueOnlyAccepted.length) {
      await Promise.all(queueOnlyAccepted.map((entry) => {
        const friendUid = String(entry.friendUid || "").trim();
        if (!friendUid) return Promise.resolve();
        const fallbackName = getFriendDisplayName({
          uid: friendUid,
          email: String(entry.friendEmail || "").trim().toLowerCase(),
          name: String(entry.friendName || "").trim()
        }, "Friend");
        return setDoc(doc(db, "users", userId, "friends", friendUid), {
          friendUid,
          friendEmail: String(entry.friendEmail || "").trim().toLowerCase(),
          friendName: fallbackName,
          friendUsername: getNormalizedUsernameIdentity(entry.friendUsername || fallbackName, entry.friendEmail),
          friendDisplayName: normalizeDisplayNameValue(entry.friendDisplayName || fallbackName) || fallbackName,
          status: "accepted",
          updatedAt: serverTimestamp()
        }, { merge: true }).catch(() => {});
      }));
      queueOnlyAccepted.forEach((entry) => {
        const uid = String(entry.friendUid || "").trim();
        if (uid) persistedFriendUids.add(uid);
      });
    }

    // Recovery path: if cross-user friend mirror write failed earlier,
    // reconstruct active friends from accepted request history.
    let historicalAcceptedFriends = [];
    try {
      const [inboxSnap, sentSnap] = await Promise.all([
        getDocs(collection(db, "users", userId, "friendRequests")),
        getDocs(collection(db, "users", userId, "friendRequestsSent"))
      ]);

      const fromInbox = inboxSnap.docs
        .map((docSnap) => ({ id: docSnap.id, ...(docSnap.data() || {}) }))
        .filter((entry) => String(entry.status || "").trim().toLowerCase() === "accepted")
        .map((entry) => ({
          friendUid: String(entry.fromUid || entry.id || "").trim(),
          friendEmail: String(entry.fromEmail || "").trim().toLowerCase(),
          friendName: String(entry.fromName || "").trim(),
          friendUsername: String(entry.fromUsername || "").trim(),
          friendDisplayName: String(entry.fromDisplayName || "").trim(),
          status: "accepted"
        }));

      const fromSent = sentSnap.docs
        .map((docSnap) => ({ id: docSnap.id, ...(docSnap.data() || {}) }))
        .filter((entry) => String(entry.status || "").trim().toLowerCase() === "accepted")
        .map((entry) => ({
          friendUid: String(entry.toUid || "").trim(),
          friendEmail: String(entry.toEmail || "").trim().toLowerCase(),
          friendName: String(entry.toName || "").trim(),
          friendUsername: String(entry.toUsername || "").trim(),
          friendDisplayName: String(entry.toDisplayName || "").trim(),
          status: "accepted"
        }));

      const deduped = new Map();
      [...fromInbox, ...fromSent].forEach((entry) => {
        const friendUid = String(entry.friendUid || "").trim();
        if (!friendUid || unfriendedFriendUids.has(friendUid)) return;
        if (!deduped.has(friendUid)) deduped.set(friendUid, entry);
      });
      historicalAcceptedFriends = [...deduped.values()];
    } catch (_) {
      historicalAcceptedFriends = [];
    }

    const historicalOnlyAccepted = historicalAcceptedFriends.filter((entry) => {
      const uid = String(entry.friendUid || "").trim();
      return !!uid && !persistedFriendUids.has(uid) && !unfriendedFriendUids.has(uid);
    });
    if (historicalOnlyAccepted.length) {
      await Promise.all(historicalOnlyAccepted.map((entry) => {
        const friendUid = String(entry.friendUid || "").trim();
        if (!friendUid) return Promise.resolve();
        const fallbackName = getFriendDisplayName({
          uid: friendUid,
          email: String(entry.friendEmail || "").trim().toLowerCase(),
          name: String(entry.friendName || "").trim()
        }, "Friend");
        return setDoc(doc(db, "users", userId, "friends", friendUid), {
          friendUid,
          friendEmail: String(entry.friendEmail || "").trim().toLowerCase(),
          friendName: fallbackName,
          friendUsername: getNormalizedUsernameIdentity(entry.friendUsername || fallbackName, entry.friendEmail),
          friendDisplayName: normalizeDisplayNameValue(entry.friendDisplayName || fallbackName) || fallbackName,
          status: "accepted",
          updatedAt: serverTimestamp()
        }, { merge: true }).catch(() => {});
      }));

      historicalOnlyAccepted.forEach((entry) => {
        const uid = String(entry.friendUid || "").trim();
        if (!uid) return;
        persistedFriendUids.add(uid);
        friends.push({
          friendUid: uid,
          friendEmail: String(entry.friendEmail || "").trim().toLowerCase(),
          friendName: String(entry.friendName || "").trim(),
          friendUsername: String(entry.friendUsername || "").trim(),
          friendDisplayName: String(entry.friendDisplayName || "").trim(),
          status: "accepted"
        });
      });
    }

    const mergedByFriendUid = new Map();
    [...queueFriends, ...friends].forEach((entry) => {
      if (!entry?.friendUid) return;
      const key = String(entry.friendUid);
      const queueProfile = latestQueueProfileByFriendUid.get(key)?.sharedProfile || null;
      const existing = mergedByFriendUid.get(key);
      if (!existing) {
        mergedByFriendUid.set(key, {
          ...entry,
          sharedProfile: pickBetterSharedProfile(entry.sharedProfile || null, queueProfile)
        });
        return;
      }
      mergedByFriendUid.set(key, {
        ...existing,
        ...entry,
        friendEmail: String(entry.friendEmail || existing.friendEmail || ""),
        friendName: String(entry.friendName || existing.friendName || ""),
        friendUsername: String(entry.friendUsername || existing.friendUsername || ""),
        friendDisplayName: String(entry.friendDisplayName || existing.friendDisplayName || ""),
        sharedProfile: pickBetterSharedProfile(
          pickBetterSharedProfile(existing.sharedProfile || null, entry.sharedProfile || null),
          queueProfile
        )
      });
    });
    const mergedFriends = [...mergedByFriendUid.values()];

    if (!mergedFriends.length) {
      friendInsightProfiles = [];
      renderFriendMetricCardInsights();
      renderCurrentFriends([]);
      renderFriendsInsights([], myProfile);
      return;
    }

    const enriched = await Promise.all(mergedFriends.map(async (entry) => {
      let profile = entry.sharedProfile || null;
      const hasLiveWellnessMetric = (candidateProfile) => {
        const metrics = candidateProfile?.metrics;
        return !!metrics
          && typeof metrics === "object"
          && Object.prototype.hasOwnProperty.call(metrics, "wellnessScoreToday");
      };

      // Always check remote social profile and choose the fresher signal source.
      // This prevents stale sharedProfile rows from hiding recent mood updates.
      try {
        const profileRef = doc(db, "users", entry.friendUid, "social", "profile");
        let profileSnap = null;
        try {
          profileSnap = await getDocFromServer(profileRef);
        } catch (_) {
          profileSnap = await getDoc(profileRef).catch(() => null);
        }

        if (profileSnap?.exists && profileSnap.exists()) {
          const remoteProfile = profileSnap.data() || null;
          if (!profile) {
            profile = remoteProfile;
          } else {
            const localHasWellness = hasLiveWellnessMetric(profile);
            const remoteHasWellness = hasLiveWellnessMetric(remoteProfile);
            const localFreshness = Number(profile?.generatedAtMs) || 0;
            const remoteFreshness = Number(remoteProfile?.generatedAtMs) || 0;
            const localSignal = profileSignalScore(profile);
            const remoteSignal = profileSignalScore(remoteProfile);

            if (
              (remoteHasWellness && !localHasWellness)
              || remoteFreshness > localFreshness
              || (remoteFreshness === localFreshness && remoteSignal > localSignal)
            ) {
              profile = remoteProfile;
            }
          }
        }
      } catch (_) {
        // Keep existing shared profile if remote read fails.
      }

      const friendEmail = String(entry.friendEmail || profile?.email || "").trim().toLowerCase();
      const directoryIdentity = await resolveDirectoryIdentityByEmail(friendEmail);
      const resolvedFriendUsername = getNormalizedUsernameIdentity(
        profile?.username || entry.friendUsername || entry.friendName,
        friendEmail
      ) || directoryIdentity.username || "friend";
      const resolvedFriendDisplayName = normalizeDisplayNameValue(profile?.displayName)
        || normalizeDisplayNameValue(entry.friendDisplayName)
        || normalizeDisplayNameValue(profile?.name)
        || normalizeDisplayNameValue(entry.friendName)
        || directoryIdentity.displayName
        || resolvedFriendUsername
        || "Friend";

      if (!profile) {
        profile = {
          uid: entry.friendUid,
          email: friendEmail || entry.friendEmail || "",
          name: resolvedFriendDisplayName,
          username: resolvedFriendUsername,
          displayName: resolvedFriendDisplayName,
          metrics: {
            totalTasksLogged: 0,
            avgTasksCompletedDaily: 0,
            tasksToday: 0,
            avgWaterDaily: 0,
            waterToday: 0,
            avgSleepHours: 0,
            sleepToday: 0,
            moodToday: "",
            gratitudeToday: 0,
            dailyChallengeCompletedToday: 0,
            avgMoodToday: 0,
            avgMoodScore: 0,
            avgMoodLabel: "Not enough data"
          }
        };
      } else {
        profile = {
          ...profile,
          email: friendEmail || String(profile.email || "").trim().toLowerCase(),
          name: resolvedFriendDisplayName,
          username: resolvedFriendUsername,
          displayName: resolvedFriendDisplayName
        };
      }

      return {
        ...entry,
        friendUsername: resolvedFriendUsername,
        friendDisplayName: resolvedFriendDisplayName,
        profile
      };
    }));

    renderCurrentFriends(enriched.map((entry) => ({
      friendUid: String(entry.friendUid || entry.profile?.uid || ""),
      friendEmail: String(entry.profile?.email || entry.friendEmail || "").trim().toLowerCase(),
      friendUsername: getNormalizedUsernameIdentity(
        entry.friendUsername || entry.profile?.username || entry.friendName,
        entry.profile?.email || entry.friendEmail
      ),
      friendDisplayName: normalizeDisplayNameValue(entry.friendDisplayName || entry.profile?.displayName || entry.profile?.name || entry.friendName),
      friendName: getFriendDisplayName({
        displayName: entry.profile?.displayName || entry.friendDisplayName,
        uid: entry.profile?.uid || entry.friendUid,
        email: entry.profile?.email || entry.friendEmail,
        name: entry.profile?.name || entry.friendName
      }, "Friend")
    })));

    friendInsightProfiles = enriched.map((entry) => ({
      ...(entry.profile || {}),
      uid: String(entry?.profile?.uid || entry?.friendUid || ""),
      email: String(entry?.profile?.email || entry?.friendEmail || "").trim().toLowerCase(),
      username: getNormalizedUsernameIdentity(entry?.profile?.username || entry?.friendUsername || entry?.profile?.name, entry?.profile?.email || entry?.friendEmail),
      displayName: normalizeDisplayNameValue(entry?.profile?.displayName || entry?.friendDisplayName || entry?.profile?.name),
      name: getFriendDisplayName({
        displayName: entry?.profile?.displayName || entry?.friendDisplayName,
        uid: entry?.profile?.uid || entry?.friendUid,
        email: entry?.profile?.email || entry?.friendEmail,
        name: entry?.profile?.name || entry?.friendName
      }, "Friend")
    }));
    renderFriendMetricCardInsights();
    renderFriendsInsights(enriched, myProfile);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function submitAddFriendRequest() {
  if (addFriendSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    setAddFriendError("Please sign in first.");
    return;
  }

  const targetUsernameInput = String(addFriendEmailInput?.value || "").trim();
  const targetUsernameExactInput = getCaseSensitiveUsernameInputValue(targetUsernameInput);
  const targetUsernameValidation = validateSignupUsername(targetUsernameInput);
  const targetUsernameKey = targetUsernameValidation.normalized;
  const senderEmail = String(user.email || "").trim().toLowerCase();
  if (!targetUsernameInput) {
    setAddFriendError("Friend username is required.");
    return;
  }
  if (!targetUsernameValidation.ok || !targetUsernameKey) {
    setAddFriendError("Enter a valid username (letters, numbers, underscores, dashes; 1-20 chars).");
    return;
  }

  setAddFriendBusy(true);
  setAddFriendError("");
  try {
    const currentFriendCount = await getActiveFriendCount(user.uid, senderEmail);
    if (currentFriendCount >= MAX_FRIENDS) {
      setAddFriendError(`You can only have ${MAX_FRIENDS} friends. Unfriend someone first to add a new friend.`);
      return;
    }

    let targetUid = "";
    let targetName = "Friend";
    let targetUsername = targetUsernameKey;
    let targetDisplayName = "Friend";
    let targetEmail = "";
    const targetDirectory = await resolveUserDirectoryByUsername(targetUsernameKey, {
      forceRefresh: true,
      preferServer: true
    });
    if (targetDirectory) {
      const directoryCaseSensitiveUsername = getCaseSensitiveUsernameInputValue(
        targetDirectory.usernameExact || targetDirectory.username || targetDirectory.name || ""
      );
      if (targetUsernameExactInput && directoryCaseSensitiveUsername && targetUsernameExactInput !== directoryCaseSensitiveUsername) {
        setAddFriendError(`No account found with exact case \"${targetUsernameExactInput}\". Try \"${directoryCaseSensitiveUsername}\".`);
        return;
      }

      targetUid = String(targetDirectory.uid || "").trim();
      targetEmail = String(targetDirectory.email || "").trim().toLowerCase();
      targetUsername = getNormalizedUsernameIdentity(targetDirectory.username || targetDirectory.name || targetUsernameKey, targetEmail)
        || targetUsernameKey;
      targetDisplayName = normalizeDisplayNameValue(targetDirectory.displayName)
        || normalizeDisplayNameValue(targetDirectory.name)
        || targetUsername
        || "Friend";
      targetName = targetDisplayName;

      // Best-effort session self-heal: keep alias cache warm for legacy usernames.
      usernameDirectoryCache.set(targetUsernameKey, {
        uid: targetUid,
        email: targetEmail,
        name: targetUsername,
        username: targetUsername,
        displayName: targetDisplayName
      });
    }

    if (!targetUid) {
      setAddFriendError("No account found with this username. Ask them to sign up first.");
      return;
    }

    if (targetUid === user.uid) {
      setAddFriendError("You cannot add your own account.");
      return;
    }

    const sentByMeSnap = await fsGetDocs(collection(db, "users", user.uid, "friendRequestsSent"), 'friendRequestsSent');
    let alreadyPendingToEmail = false;
    let activePendingSentCount = 0;
    const sentExpiryUpdates = [];
    const sentStatusSyncUpdates = [];

    const queueStatusByTarget = new Map();
    try {
      const queueSnap = await getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", user.uid)));
      queueSnap.docs.forEach((docSnap) => {
        const entry = docSnap.data() || {};
        const toUid = String(entry.toUid || "").trim();
        const toEmail = String(entry.toEmail || "").trim().toLowerCase();
        const status = String(entry.status || "").trim().toLowerCase();
        const updatedAtMs = Number(entry.updatedAtMs)
          || Number(entry.createdAtMs)
          || getOptionalTimestampMs(entry.updatedAt)
          || getOptionalTimestampMs(entry.respondedAt)
          || getOptionalTimestampMs(entry.cancelledAt)
          || getOptionalTimestampMs(entry.expiredAt)
          || getOptionalTimestampMs(entry.createdAt)
          || 0;

        const keys = [];
        if (toUid) keys.push(`uid:${toUid}`);
        if (toEmail) keys.push(`email:${toEmail}`);
        keys.forEach((key) => {
          const existing = queueStatusByTarget.get(key);
          if (!existing || updatedAtMs >= Number(existing.updatedAtMs || 0)) {
            queueStatusByTarget.set(key, { status, updatedAtMs });
          }
        });
      });
    } catch (_) {}

    sentByMeSnap.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const pending = String(data.status || "pending") === "pending";
      if (!pending) return;

      const toUid = String(data.toUid || "").trim();
      const toEmail = String(data.toEmail || "").trim().toLowerCase();
      const queueCandidates = [
        toUid ? queueStatusByTarget.get(`uid:${toUid}`) : null,
        toEmail ? queueStatusByTarget.get(`email:${toEmail}`) : null
      ].filter(Boolean);
      queueCandidates.sort((a, b) => Number(b?.updatedAtMs || 0) - Number(a?.updatedAtMs || 0));
      const queueStatusEntry = queueCandidates[0] || null;
      const queueStatus = String(queueStatusEntry?.status || "");
      const queueStatusUpdatedAtMs = Number(queueStatusEntry?.updatedAtMs || 0);
      const sentUpdatedAtMs = Number(data.updatedAtMs)
        || Number(data.createdAtMs)
        || getOptionalTimestampMs(data.updatedAt)
        || getOptionalTimestampMs(data.createdAt)
        || 0;
      const terminalQueueStatus = isTerminalFriendRequestStatus(queueStatus);
      if (terminalQueueStatus && queueStatusUpdatedAtMs > 0 && queueStatusUpdatedAtMs >= sentUpdatedAtMs) {
        sentStatusSyncUpdates.push(setDoc(docSnap.ref, {
          status: queueStatus,
          updatedAt: serverTimestamp(),
          updatedAtMs: Date.now()
        }, { merge: true }).catch(() => {}));
        return;
      }

      if (isFriendRequestExpired(data)) {
        sentExpiryUpdates.push(setDoc(docSnap.ref, {
          status: "expired",
          expiredAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          updatedAtMs: Date.now()
        }, { merge: true }).catch(() => {}));
        return;
      }

      activePendingSentCount += 1;
      if (toUid === targetUid || (targetEmail && toEmail === targetEmail)) alreadyPendingToEmail = true;
    });
    await Promise.all([...sentExpiryUpdates, ...sentStatusSyncUpdates]);

    if (activePendingSentCount >= MAX_PENDING_SENT_REQUESTS) {
      setAddFriendError(`You can only have ${MAX_PENDING_SENT_REQUESTS} pending sent requests. Wait for one to be accepted/declined/cancelled/expired first.`);
      return;
    }

    if (alreadyPendingToEmail) {
      setAddFriendError("Request already sent and pending.");
      return;
    }

    if (targetUid) {
      const localUnfriendedRes = await fsGetDoc(doc(db, "users", user.uid, "friendUnfriended", targetUid), 'friendUnfriended').catch(() => ({ exists: false, data: null }));
      const localUnfriendedStatus = String(localUnfriendedRes.data?.status || "").trim().toLowerCase();
      const locallyUnfriended = !!localUnfriendedRes.exists && localUnfriendedStatus === "unfriended";

      const existingFriend = await fsGetDoc(doc(db, "users", user.uid, "friends", targetUid), 'friend');
      if (existingFriend.exists) {
        const existingFriendData = existingFriend.data || {};
        const existingFriendStatus = String(existingFriendData.status || "accepted").trim().toLowerCase();
        const queueStatusByUid = String(queueStatusByTarget.get(`uid:${targetUid}`)?.status || "").trim().toLowerCase();
        const queueStatusByEmail = targetEmail
          ? String(queueStatusByTarget.get(`email:${targetEmail}`)?.status || "").trim().toLowerCase()
          : "";
        const queueStatus = queueStatusByUid || queueStatusByEmail;

        const activeFriendByDoc = existingFriendStatus === "accepted";
        const queueMarkedUnfriended = queueStatus === "unfriended";
        if (activeFriendByDoc && !queueMarkedUnfriended && !locallyUnfriended) {
          await loadFriendsInsights(user.uid);
          closeAddFriendModal(null, true);
          showToast("You are already friends with this account.");
          return;
        }
      }
    }

    if (targetUid) {
      const reverseRequestRes = await fsGetDoc(doc(db, "users", user.uid, "friendRequests", targetUid), 'friendRequest');
      const reverseData = reverseRequestRes.exists ? (reverseRequestRes.data || {}) : null;
      if (reverseData && String(reverseData.status || "") === "pending" && !isFriendRequestExpired(reverseData)) {
        const reverseAction = await openReverseFriendRequestPrompt({
          ...reverseData,
          fromUid: targetUid,
          source: "legacy",
          requestId: targetUid,
          fromEmail: reverseData.fromEmail || targetEmail,
          fromName: reverseData.fromName || targetName
        });
        if (reverseAction === "accept" || reverseAction === "decline") {
          closeAddFriendModal(null, true);
          return;
        }
        return;
      }
      if (reverseData && String(reverseData.status || "") === "pending" && isFriendRequestExpired(reverseData)) {
        await setDoc(doc(db, "users", user.uid, "friendRequests", targetUid), {
          status: "expired",
          expiredAt: serverTimestamp(),
          updatedAt: serverTimestamp()
        }, { merge: true }).catch(() => {});
      }
    }

    if (targetUid) {
      try {
        const senderEmailLower = String(user.email || "").trim().toLowerCase();
        const [reverseQueueByUid, reverseQueueByEmail] = await Promise.all([
          getDocs(query(
            collection(db, "friendRequestsQueue"),
            where("toUid", "==", user.uid)
          )),
          senderEmailLower
            ? getDocs(query(
              collection(db, "friendRequestsQueue"),
              where("toEmail", "==", senderEmailLower)
            ))
            : Promise.resolve({ docs: [] })
        ]);
        const reversePendingEntry = [...reverseQueueByUid.docs, ...reverseQueueByEmail.docs]
          .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
          .find((data) => {
            const fromUidMatches = String(data.fromUid || "") === targetUid;
            const pending = String(data.status || "pending") === "pending" && !isFriendRequestExpired(data);
            return fromUidMatches && pending;
          });
        if (reversePendingEntry) {
          const reverseAction = await openReverseFriendRequestPrompt({
            ...reversePendingEntry,
            fromUid: String(reversePendingEntry.fromUid || targetUid),
            fromEmail: reversePendingEntry.fromEmail || targetEmail,
            fromName: reversePendingEntry.fromName || targetName,
            source: "queue",
            requestId: String(reversePendingEntry.id || "")
          });
          if (reverseAction === "accept" || reverseAction === "decline") {
            closeAddFriendModal(null, true);
            return;
          }
          return;
        }
        const hasReversePending = [...reverseQueueByUid.docs, ...reverseQueueByEmail.docs].some((docSnap) => {
          const data = docSnap.data() || {};
          const fromUidMatches = String(data.fromUid || "") === targetUid;
          const pending = String(data.status || "pending") === "pending" && !isFriendRequestExpired(data);
          return fromUidMatches && pending;
        });
        if (hasReversePending) {
          setAddFriendError("This user has already sent you a request. Open Friend Requests to accept or decline it.");
          return;
        }
      } catch (_) {}
    }

    const incomingRef = targetUid ? doc(db, "users", targetUid, "friendRequests", user.uid) : null;
    if (incomingRef) {
      try {
        const incomingRes = await fsGetDoc(incomingRef, 'friendRequest');
        if (incomingRes.exists && String(incomingRes.data?.status || "") === "pending") {
          setAddFriendError("Request already sent and pending.");
          return;
        }
      } catch (_) {}
    }

    const resolvedFromUsername = normalizeUsernameForLookup(await resolveUsernameFromDirectoryEmail(senderEmail));
    const fromUsername = resolvedFromUsername
      || getSafeUsernameForAuthenticatedUser(user, accountName?.innerText || "", senderEmail);
    const fromDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || "")
      || normalizeDisplayNameValue(user.displayName)
      || fromUsername;
    const fromName = fromDisplayName;
    const fromProfileSnapshot = buildUserSocialProfileSnapshot(user);
    const requestNowMs = Date.now();
    const requestNonce = `${user.uid}_${requestNowMs}_${Math.random().toString(36).slice(2, 8)}`;
    const requestPayload = {
      fromUid: user.uid,
      fromEmail: senderEmail,
      fromName,
      fromUsername,
      fromDisplayName,
      fromProfile: fromProfileSnapshot,
      toUid: targetUid,
      toEmail: targetEmail,
      toName: targetName,
      toUsername: targetUsername,
      toDisplayName: targetDisplayName,
      status: "pending",
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      createdAtMs: requestNowMs,
      updatedAtMs: requestNowMs,
      requestNonce
    };

    const sentRequestDocId = targetUid || `email_${targetEmail}`;

    await setDoc(doc(db, "users", user.uid, "friendRequestsSent", sentRequestDocId), {
      ...requestPayload,
      status: "pending",
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      createdAtMs: requestNowMs,
      updatedAtMs: requestNowMs
    }, { merge: true });

    let deliveredToInbox = false;
    let queuedFallback = false;

    const queueKeys = [];
    if (targetUid) queueKeys.push(targetUid);
    if (targetEmail) queueKeys.push(`email_${encodeURIComponent(targetEmail)}`);
    const uniqueQueueKeys = [...new Set(queueKeys)];
    if (uniqueQueueKeys.length) {
      const queueResults = await Promise.allSettled(uniqueQueueKeys.map((key) => {
        const queueId = `${user.uid}__${key}`;
        return setDoc(doc(db, "friendRequestsQueue", queueId), {
          ...requestPayload,
          queueId,
          delivery: "queued",
          targetKey: key,
          updatedAt: serverTimestamp(),
          updatedAtMs: requestNowMs,
          createdAtMs: requestNowMs
        }, { merge: true });
      }));
      queuedFallback = queueResults.some((result) => result.status === "fulfilled");
    } else {
      queuedFallback = false;
    }

    try {
      if (incomingRef) {
        await setDoc(incomingRef, {
          ...requestPayload,
          updatedAtMs: requestNowMs,
          createdAtMs: requestNowMs
        }, { merge: true });
        deliveredToInbox = true;
      }
    } catch (err) {
      const code = String(err?.code || "");
      const permissionDenied = code.includes("permission-denied") || code.includes("unauthenticated");
      if (!permissionDenied) throw err;

      // queue fallback attempted above; keep existing state
    }

    if (!deliveredToInbox && !queuedFallback) {
      setAddFriendError("Could not deliver this request due Firestore permissions. Enable friend request queue access in Firestore rules.");
      return;
    }

    closeAddFriendModal(null, true);
    await loadSentFriendRequests(user.uid);
    showToast(deliveredToInbox
      ? "Friend request sent. They will see it in-app on next login."
      : "Friend request queued in-app. They will see it on next login.");
  } catch (err) {
    notifyFirestoreError(err);
    setAddFriendError(
      isFirestorePermissionDeniedError(err)
        ? "Friend lookup is blocked by Firestore rules. Allow signed-in users to read usernameDirectory."
        : (err?.message || "Could not send friend request right now.")
    );
  } finally {
    setAddFriendBusy(false);
  }
}

async function respondToFriendRequest(requestEntry, action) {
  const user = auth.currentUser;
  const entry = typeof requestEntry === "object" && requestEntry ? requestEntry : null;
  const fromUid = typeof requestEntry === "string"
    ? requestEntry
    : String(entry?.fromUid || "");
  const source = typeof requestEntry === "string"
    ? "legacy"
    : String(entry?.source || "legacy");
  const requestId = typeof requestEntry === "string"
    ? fromUid
    : String(entry?.requestId || entry?.id || fromUid);

  if (!user?.uid || !fromUid) return;

  const accepted = action === "accept";
  try {
    const requestRef = source === "queue"
      ? doc(db, "friendRequestsQueue", requestId)
      : source === "sentFeed"
        ? doc(db, "users", fromUid, "friendRequestsSent", requestId)
      : doc(db, "users", user.uid, "friendRequests", fromUid);
    let requestData = entry || {};
    if (source !== "sentFeed") {
      const requestRes = await fsGetDoc(requestRef, 'friendRequest');
      if (!requestRes.exists) return;
      requestData = requestRes.data || {};
    }

    if (accepted) {
      const currentFriendCount = await getActiveFriendCount(user.uid, user.email || "");
      if (currentFriendCount >= MAX_FRIENDS) {
        showToast(`Failed to accept. You have hit your friend list limit (${MAX_FRIENDS}).`);
        return;
      }

      const senderEmailForLimitCheck = String(requestData.fromEmail || "").trim().toLowerCase();
      const senderFriendCount = await getActiveFriendCount(fromUid, senderEmailForLimitCheck);
      if (senderFriendCount >= MAX_FRIENDS) {
        let senderUsernameForLimit = getNormalizedUsernameIdentity(
          requestData.fromUsername || requestData?.fromProfile?.username || "",
          senderEmailForLimitCheck
        );
        if (!senderUsernameForLimit && senderEmailForLimitCheck) {
          senderUsernameForLimit = normalizeUsernameForLookup(await resolveUsernameFromDirectoryEmail(senderEmailForLimitCheck));
        }
        senderUsernameForLimit = normalizeUsernameForLookup(senderUsernameForLimit) || "friend";
        showToast(`Failed to accept. @${senderUsernameForLimit} has hit their friend list limit (${MAX_FRIENDS}).`);
        return;
      }

      const userEmail = String(user.email || "").trim().toLowerCase();
      const resolvedMyUsername = normalizeUsernameForLookup(await resolveUsernameFromDirectoryEmail(userEmail));
      const myUsername = resolvedMyUsername
        || getSafeUsernameForAuthenticatedUser(user, accountName?.innerText || "", userEmail);
      const myDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || "")
        || normalizeDisplayNameValue(user.displayName)
        || myUsername;
      const myProfileSnapshot = buildUserSocialProfileSnapshot(user);
      const friendEmail = String(requestData.fromEmail || "").trim().toLowerCase();
      const friendUsername = getNormalizedUsernameIdentity(
        requestData.fromUsername || requestData?.fromProfile?.username || requestData.fromName,
        friendEmail
      ) || await resolveUsernameFromDirectoryEmail(friendEmail)
        || getEmailLocalIdentity(friendEmail)
        || "friend";
      const friendDisplayName = normalizeDisplayNameValue(requestData.fromDisplayName)
        || normalizeDisplayNameValue(requestData?.fromProfile?.displayName)
        || normalizeDisplayNameValue(requestData.fromName)
        || friendUsername;
      const friendName = friendDisplayName;
      const senderProfileSnapshot = (requestData?.fromProfile && typeof requestData.fromProfile === "object")
        ? {
          ...requestData.fromProfile,
          uid: String(requestData.fromProfile.uid || fromUid || "").trim(),
          email: String(requestData.fromProfile.email || friendEmail || "").trim().toLowerCase(),
          username: getNormalizedUsernameIdentity(requestData.fromProfile.username || friendUsername, friendEmail) || friendUsername,
          displayName: normalizeDisplayNameValue(requestData.fromProfile.displayName) || friendDisplayName,
          name: getFriendDisplayName({
            displayName: requestData.fromProfile.displayName || friendDisplayName,
            uid: String(requestData.fromProfile.uid || fromUid || "").trim(),
            email: String(requestData.fromProfile.email || friendEmail || "").trim().toLowerCase(),
            name: String(requestData.fromProfile.name || friendName || "")
          }, "Friend")
        }
        : {
          uid: fromUid,
          email: friendEmail,
          username: friendUsername,
          displayName: friendDisplayName,
          name: friendName,
          metrics: {
            totalTasksLogged: 0,
            completedTasks: 0,
            tasksToday: 0,
            waterToday: 0,
            sleepToday: 0,
            moodToday: "",
            gratitudeToday: 0,
            dailyChallengeCompletedToday: 0,
            avgMoodToday: 0,
            avgWaterDaily: 0,
            avgSleepHours: 0,
            avgMoodScore: 0,
            avgMoodLabel: "Not enough data",
            avgTasksCompletedDaily: 0,
            sampleDays: 0
          },
          generatedAtMs: Date.now()
        };

      await setDoc(doc(db, "users", user.uid, "friends", fromUid), {
        friendUid: fromUid,
        friendEmail,
        friendName,
        friendUsername,
        friendDisplayName,
        sharedProfile: senderProfileSnapshot,
        status: "accepted",
        since: serverTimestamp(),
        updatedAt: serverTimestamp()
      }, { merge: true });

      await setDoc(doc(db, "users", fromUid, "friends", user.uid), {
        friendUid: user.uid,
        friendEmail: String(user.email || "").trim().toLowerCase(),
        friendName: myDisplayName,
        friendUsername: myUsername,
        friendDisplayName: myDisplayName,
        sharedProfile: myProfileSnapshot,
        status: "accepted",
        since: serverTimestamp(),
        updatedAt: serverTimestamp()
      }, { merge: true }).catch((err) => structuredLog('warn', 'friend.accept.update', err?.message || String(err)));

      requestData.fromProfile = senderProfileSnapshot;
      requestData.toProfile = myProfileSnapshot;

      // Explicit accept re-opens this relationship after a previous unfriend block.
      await deleteDoc(doc(db, "users", user.uid, "friendUnfriended", fromUid)).catch((err) => structuredLog('warn', 'friend.unblock.local', err?.message || String(err)));
      await deleteDoc(doc(db, "users", fromUid, "friendUnfriended", user.uid)).catch((err) => structuredLog('warn', 'friend.unblock.remote', err?.message || String(err)));
    }

    // Keep queue docs in sync so accepted/declined state is visible to both users.
    const senderEmail = String(requestData.fromEmail || "").trim().toLowerCase();
    const senderUsername = getNormalizedUsernameIdentity(
      requestData.fromUsername || requestData?.fromProfile?.username || requestData.fromName,
      senderEmail
    ) || getEmailLocalIdentity(senderEmail)
      || "friend";
    const senderDisplayName = normalizeDisplayNameValue(requestData.fromDisplayName)
      || normalizeDisplayNameValue(requestData?.fromProfile?.displayName)
      || normalizeDisplayNameValue(requestData.fromName)
      || senderUsername;
    const senderName = senderDisplayName;
    const recipientEmail = String(user.email || requestData.toEmail || "").trim().toLowerCase();
    const recipientCandidateUsername = normalizeUsernameForLookup(accountName?.innerText || requestData.toUsername || requestData.toName);
    const resolvedRecipientUsername = normalizeUsernameForLookup(await resolveUsernameFromDirectoryEmail(recipientEmail));
    const recipientUsername = resolvedRecipientUsername
      || getSafeUsernameForAuthenticatedUser(user, recipientCandidateUsername, recipientEmail);
    const recipientDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || "")
      || normalizeDisplayNameValue(user.displayName)
      || normalizeDisplayNameValue(requestData.toDisplayName)
      || normalizeDisplayNameValue(requestData.toName)
      || recipientUsername;
    const recipientName = recipientDisplayName;
    const queueToUid = String(requestData.toUid || user.uid || "").trim();
    const queueToEmail = String(requestData.toEmail || recipientEmail || "").trim().toLowerCase();
    const queueMutablePayload = {
      fromUid,
      fromEmail: senderEmail,
      fromName: senderName,
      fromUsername: senderUsername,
      fromDisplayName: senderDisplayName,
      fromProfile: requestData.fromProfile || null,
      toUid: queueToUid,
      toEmail: queueToEmail,
      toName: recipientName,
      toUsername: recipientUsername,
      toDisplayName: recipientDisplayName,
      toProfile: requestData.toProfile || null,
      status: accepted ? "accepted" : "declined",
      respondedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now(),
      requestNonce: String(requestData.requestNonce || "").trim()
    };
    const queueKeys = [];
    if (queueToUid) queueKeys.push(queueToUid);
    if (queueToEmail) queueKeys.push(`email_${encodeURIComponent(queueToEmail)}`);
    const uniqueQueueKeys = [...new Set(queueKeys)];
    await Promise.all(uniqueQueueKeys.map((key) => {
      const queueId = `${fromUid}__${key}`;
      return setDoc(doc(db, "friendRequestsQueue", queueId), {
        ...queueMutablePayload,
        queueId,
        targetKey: key
      }, { merge: true }).catch((err) => structuredLog('warn', 'respond.queue', err?.message || String(err)));
    }));

    await setDoc(requestRef, {
      status: accepted ? "accepted" : "declined",
      respondedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true }).catch((err) => structuredLog('warn', 'respond.request', err?.message || String(err)));

    await setDoc(doc(db, "users", user.uid, "friendRequestDecisions", fromUid), {
      fromUid,
      status: accepted ? "accepted" : "declined",
      respondedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true }).catch((err) => structuredLog('warn', 'respond.decision', err?.message || String(err)));

    await setDoc(doc(db, "users", user.uid, "friendRequests", fromUid), {
      status: accepted ? "accepted" : "declined",
      respondedAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true }).catch((err) => structuredLog('warn', 'respond.incoming', err?.message || String(err)));

    // Ensure sender-side pending list clears regardless of sent doc ID strategy.
    const recipientEmailForSenderSync = recipientEmail;
    try {
      const senderSentSnap = await fsGetDocs(collection(db, "users", fromUid, "friendRequestsSent"), 'friendRequestsSent');
      const senderUpdates = [];
      senderSentSnap.docs.forEach((docSnap) => {
        const data = docSnap.data() || {};
        const toUidMatches = String(data.toUid || "") === user.uid;
        const toEmailMatches = recipientEmailForSenderSync && String(data.toEmail || "").trim().toLowerCase() === recipientEmailForSenderSync;
        if (!toUidMatches && !toEmailMatches) return;

        senderUpdates.push(setDoc(docSnap.ref, {
          status: accepted ? "accepted" : "declined",
          respondedAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
          updatedAtMs: Date.now()
        }, { merge: true }).catch(() => {}));
      });
      await Promise.all(senderUpdates);
    } catch (_) {}

    await loadFriendRequests(user.uid);
    await loadSentFriendRequests(user.uid);
    await loadFriendsInsights(user.uid);
    showToast(accepted ? "Friend request accepted." : "Friend request declined.");
  } catch (err) {
    notifyFirestoreError(err);
  }
}

// ---------- DASHBOARD JS ----------
const moodHistory=[],waterHistory=[],sleepHistory=[];
const moodDates=[];
const waterDates=[];
const sleepDates=[];
const musicSessionDates=[];
const musicSessionDayKeys = new Set();
const taskEntries=[];
const gratitudeEntries=[];
const rescueEvents=[];
const habitQuests=[];
const burnoutRecoveryPlan=[];
const aiRecentPrompts=[];
const aiRecentResponseSignatures=[];
const aiVariantHistory = new Map();
const aiSessionState = {
  lastIntent: "",
  lastAdvice: [],
  userEmotion: "",
  userEmotionDetailed: "neutral",
  lastUserMessage: "",
  turnCount: 0,
  userFacts: {
    name: "",
    goal: "",
    likes: [],
    dislikes: []
  },
  lastSnapshot: null,
  conversationSummary: "",
  topicHistory: [],
  memoryPairs: []
};
const AI_MODE_PRESETS = {
  balanced: { depth: 2, style: "balanced" },
  coach: { depth: 3, style: "coach" },
  strict: { depth: 3, style: "strict" },
  creative: { depth: 3, style: "creative" },
  ultra: { depth: 4, style: "ultra" }
};
let aiReasoningMode = "ultra";
const AI_CASUAL_MODE = false;
const AI_CLARIFY_INTENT_THRESHOLD = 0.68;
const AI_COMMAND_HELP_LINE = "I can help with logging tasks, water, mood, sleep, reminders, and quick account actions.";
const AI_RESPONSE_VARIANT_MIN = 100;
const AI_RESPONSE_VARIANT_MAX = 150;
const AI_RESPONSE_REPEAT_HISTORY_LIMIT = 120;
const AI_RESPONSE_SIGNATURE_HISTORY_LIMIT = 150;
const AI_RESPONSE_SIGNATURE_COMPARE_WINDOW = 80;
const CRASH_ALERT_BANNER_MIN_RISK = 45;
const CRASH_ALERT_DISMISS_STORAGE_PREFIX = "novafixCrashAlertDismissedDate:";
const challengeDates=[];
let dailyChallengeCompleted=false;
let currentChallengeText="";
let currentChallengeDateKey="";
let challengeWatcherInterval=null;
let friendInsightsWatcherIntervalId = null;
let friendRealtimeUnsubscribers = [];
let friendRealtimeRefreshTimerId = null;
let friendRealtimeRefreshInFlight = false;
let friendRealtimeRefreshQueued = false;
let seenFriendRequestKeys = new Set();
let acknowledgeFriendRequestsOnNextRender = false;
let seenFriendRequestKeysLoadedForUid = "";
let seenFriendRequestKeysLoadingForUid = "";
let seenFriendRequestKeysLoadPromise = null;
let dailyChallengeResetTimeoutId = null;
let weeklyGraphResetTimeoutId = null;
let weeklyGraphCountdownIntervalId = null;
let startupResetCountdownIntervalId = null;
let insightsPersistTimer=null;
let waterGoalResetTimeoutId = null;
let sleepDailyResetTimeoutId = null;
let moodDailyResetTimeoutId = null;
let insightMetricIndex = 0;
let questDateKey = "";
let questXp = 0;
let questShieldAvailable = false;
let questStreakCount = 0;
let questLastStreakDateKey = "";
let questWeekStartKey = "";
let weeklyQuestUsedIds = [];
let questCompletedDateKeys = [];
let dailyQuestResetTimeoutId = null;
let dailySystemResetTimeoutId = null;
let dailySystemResetWatcherIntervalId = null;
let dailySystemResetInFlight = false;
let dailySystemResetKey = "";
let weeklyTargets = {
  waterGoal: 0,
  sleepTarget: 8,
  taskTarget: 5
};
const userTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "local";
const FIRESTORE_CRASH_MESSAGE = "Something went wrong. Please try again later.";
const AI_DAILY_LIMIT = 20;
const MOOD_DAILY_LIMIT = 20;
const REMINDER_DAILY_LIMIT = 30;
const TASK_DAILY_LIMIT = 50;
const GRATITUDE_DAILY_LIMIT = 30;
const WATER_DAILY_LIMIT = 40;
const WATER_MAX_GLASSES_PER_ENTRY = 10;
const MAX_FRIENDS = 10;
const MAX_PENDING_SENT_REQUESTS = 10;
const FRIEND_REQUEST_EXPIRY_MS = 3 * 24 * 60 * 60 * 1000;
const REMINDER_MAX_MINUTES = 525600;
const REMINDER_MAX_TEXT_LENGTH = 140;
const SLEEP_DAILY_LIMIT = 8;
const STARTUP_PLAN_DAILY_LIMIT = 1;
const STARTUP_REPORT_WEEKLY_LIMIT = 1;
const MAX_REMINDER_ENTRIES = 500;
const MAX_TASK_ENTRIES = 1500;
const MAX_GRATITUDE_ENTRIES = 1200;
const MAX_WATER_ENTRIES = 1500;
const MAX_SLEEP_ENTRIES = 800;
const MAX_MOOD_ENTRIES = 1200;
const SERVER_CLOCK_RESYNC_MS = 5 * 60 * 1000;
let aiUsageDateKeyGMT = "";
let aiUsageCount = 0;
let aiUsageStateLoaded = false;
let dailyUsageDateKey = "";
let moodDailyUsageCount = 0;
let taskDailyUsageCount = 0;
let sleepDailyUsageCount = 0;
let waterDailyUsageCount = 0;
let reminderDailyUsageCount = 0;
let gratitudeDailyUsageCount = 0;
let dailyUsageLoaded = false;
let serverTimeOffsetMs = 0;
let serverTimeSyncedAt = 0;
let limitCountdownInterval = null;
let lastFirestoreErrorAlertAt = 0;
let persistedBarGraphs = null;
let persistedBehaviorPatterns = null;
const reminderIntervals = new Map();
let uxToastTimer = null;
let uxToastActionHandler = null;
let pendingToastCounter = 0;
let activePendingToastId = 0;
let activePendingToastShownAtMs = 0;
let pendingAiClearOperation = null;
let pendingWaterClearOperation = null;
let bedtimeReminderTimeoutId = null;
let bedtimeReminderLastTriggeredKey = "";
let bedtimeSettings = {
  timeText: "",
  enabled: false
};
let bedtimeInputTouchedSinceSync = false;
let bedtimeAllowUnchangedResubmit = false;
let aiChatSubmitting = false;
let aiAbuseStrikeCount = 0;
let aiAbuseCooldownUntilMs = 0;
let aiAbuseCooldownIntervalId = null;
let reminderSubmitting = false;
let taskSubmitting = false;
let moodSubmitting = false;
let waterSubmitting = false;
let sleepSubmitting = false;
let gratitudeSubmitting = false;
let importTransferSubmitting = false;
let addFriendSubmitting = false;
let importBackoffCooldownEmail = "";
let importBackoffCooldownIntervalId = null;
let friendRequestLoginAlertShown = false;
let friendInsightProfiles = [];
let lastFriendQueueProfileSyncAt = 0;
let pendingFriendProfileSyncTimer = null;
let pendingFriendProfileSnapshot = null;
let sentRequestExpiryTicker = null;
let reminderAudioDuckRestoreTimer = null;
let reminderDuckedMediaEntries = [];
let reverseFriendRequestPromptResolver = null;
let reverseFriendRequestPromptBusy = false;
const userDirectoryNameCache = new Map();
const userDirectoryIdentityCache = new Map();
const usernameDirectoryCache = new Map();
let exportCooldownUntilMs = 0;
let exportCooldownIntervalId = null;
let displayNameEditCooldownUntilMs = 0;
let displayNameEditCooldownIntervalId = null;
let accountPasswordResetCooldownUntilMs = 0;
let accountPasswordResetCooldownIntervalId = null;

function buildFriendRequestSeenKey(entry) {
  const source = entry && typeof entry === "object" ? entry : {};
  const requestId = String(source.requestId || source.id || "").trim();
  if (requestId) return `id:${requestId}`;
  const uid = String(source.fromUid || "").trim();
  const email = String(source.fromEmail || "").trim().toLowerCase();
  const createdAtMs = Number(source.createdAtMs) || getOptionalTimestampMs(source.createdAt) || 0;
  return `actor:${uid}|${email}|${createdAtMs}`;
}

async function loadSeenFriendRequestKeysForUser(userId) {
  const safeUid = String(userId || "").trim();
  if (!safeUid) {
    seenFriendRequestKeys = new Set();
    seenFriendRequestKeysLoadedForUid = "";
    seenFriendRequestKeysLoadingForUid = "";
    seenFriendRequestKeysLoadPromise = null;
    return;
  }
  if (seenFriendRequestKeysLoadedForUid === safeUid) return;
  if (seenFriendRequestKeysLoadingForUid === safeUid && seenFriendRequestKeysLoadPromise) {
    await seenFriendRequestKeysLoadPromise;
    return;
  }

  seenFriendRequestKeysLoadingForUid = safeUid;
  seenFriendRequestKeysLoadPromise = (async () => {
    const loadedKeys = new Set();
    try {
      const seenRes = await fsGetDoc(doc(db, "users", safeUid, "settings", "friendRequestDot"), 'friendRequestDot');
      if (seenRes.exists) {
        const parsed = seenRes.data?.seenKeys;
        if (Array.isArray(parsed)) {
          parsed.forEach((key) => {
            const safeKey = String(key || "").trim();
            if (safeKey) loadedKeys.add(safeKey);
          });
        }
      }
    } catch (_) {}

    if (seenFriendRequestKeysLoadingForUid === safeUid) {
      seenFriendRequestKeys = loadedKeys;
      seenFriendRequestKeysLoadedForUid = safeUid;
      seenFriendRequestKeysLoadingForUid = "";
      seenFriendRequestKeysLoadPromise = null;
    }
  })();

  await seenFriendRequestKeysLoadPromise;
}

async function persistSeenFriendRequestKeysForUser(userId) {
  const safeUid = String(userId || "").trim();
  if (!safeUid) return;
  try {
    const seenKeys = [...seenFriendRequestKeys].slice(-300);
    await setDoc(doc(db, "users", safeUid, "settings", "friendRequestDot"), {
      seenKeys,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (_) {}
}

const DISPLAY_NAME_EDIT_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000;
const REMINDER_AUDIO_DUCK_FACTOR = 0.2;
const REMINDER_AUDIO_DUCK_DEFAULT_MS = 2600;
const REMINDER_ALERT_REPEAT_COUNT = 1;
const REMINDER_ALERT_REPEAT_GAP_MS = 700;

const AI_ABUSE_COOLDOWN_MS = 2 * 60 * 1000;
const AI_ABUSE_TERMS = ["fuck", "fuk", "fucc", "shit", "bitch", "asshole", "bastard", "motherfucker", "niga", "fucker"];

function getDefaultStartupFeatureState() {
  return {};
}

let startupFeatureState = getDefaultStartupFeatureState();
let startupCurrentPlan = [];
let startupWeeklyReportCache = "";
let startupPlanGeneratedOnce = false;
let startupReportGeneratedOnce = false;
let startupUsageState = getDefaultStartupUsageState();

function getStartupWeekKey(dateValue = getServerNowDate()) {
  const date = toDateSafe(dateValue) || getServerNowDate();
  const sunday = new Date(date);
  sunday.setUTCHours(0, 0, 0, 0);
  sunday.setUTCDate(sunday.getUTCDate() - sunday.getUTCDay());
  return dateToKey(sunday) || getTodayKey();
}

function getDefaultStartupUsageState() {
  return {
    planDateKey: getTodayKey(),
    planCount: 0,
    reportWeekKey: getStartupWeekKey(),
    reportCount: 0
  };
}

function normalizeStartupUsageState(input) {
  const source = input && typeof input === "object" ? input : {};
  const normalized = {
    planDateKey: String(source.planDateKey || getTodayKey()),
    planCount: Math.max(0, Number(source.planCount) || 0),
    reportWeekKey: String(source.reportWeekKey || getStartupWeekKey()),
    reportCount: Math.max(0, Number(source.reportCount) || 0)
  };

  if (normalized.planDateKey !== getTodayKey()) {
    normalized.planDateKey = getTodayKey();
    normalized.planCount = 0;
  }
  if (normalized.reportWeekKey !== getStartupWeekKey()) {
    normalized.reportWeekKey = getStartupWeekKey();
    normalized.reportCount = 0;
  }

  return normalized;
}

async function saveStartupUsageState(userId) {
  if (!userId) return;
  try {
    await setDoc(doc(db, "users", userId, "settings", "startupUsage"), {
      ...startupUsageState,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadStartupUsageState(userId) {
  startupUsageState = getDefaultStartupUsageState();
  if (!userId) return;

  let changed = false;
  try {
    const snapshot = await fsGetDoc(doc(db, "users", userId, "settings", "startupUsage"), 'startupUsage');
    if (snapshot.exists) {
      const raw = snapshot.data || {};
      startupUsageState = normalizeStartupUsageState(raw);
      changed = String(raw?.planDateKey || "") !== startupUsageState.planDateKey
        || Number(raw?.planCount) !== startupUsageState.planCount
        || String(raw?.reportWeekKey || "") !== startupUsageState.reportWeekKey
        || Number(raw?.reportCount) !== startupUsageState.reportCount;
    } else {
      changed = true;
    }
  } catch (err) {
    notifyFirestoreError(err);
    return;
  }

  if (changed) await saveStartupUsageState(userId);
  refreshStartupFeatures();
}

async function ensureStartupUsageCurrent(userId) {
  if (!userId) return;
  let changed = false;

  const todayKey = getTodayKey();
  const weekKey = getStartupWeekKey();

  if (startupUsageState.planDateKey !== todayKey) {
    startupUsageState.planDateKey = todayKey;
    startupUsageState.planCount = 0;
    changed = true;
  }

  if (startupUsageState.reportWeekKey !== weekKey) {
    startupUsageState.reportWeekKey = weekKey;
    startupUsageState.reportCount = 0;
    changed = true;
  }

  if (changed) await saveStartupUsageState(userId);
}

const SUCCESS_CHEERS = [
  "Nice work — momentum is building.",
  "Great consistency today.",
  "Solid progress — keep going.",
  "Good job, you’re on track.",
  "Small step done, big win later."
];

function getRandomCheer() {
  const index = Math.floor(Math.random() * SUCCESS_CHEERS.length);
  return SUCCESS_CHEERS[index] || "Nice work.";
}

function showToast(message, options = {}) {
  if (!uxToast || !uxToastText || !uxToastAction) return;

  const duration = Math.max(1200, Number(options.duration) || 2600);
  uxToastText.innerText = String(message || "");

  if (uxToastTimer) {
    clearTimeout(uxToastTimer);
    uxToastTimer = null;
  }

  uxToastActionHandler = typeof options.onAction === "function" ? options.onAction : null;
  if (options.actionLabel && uxToastActionHandler) {
    uxToastAction.style.display = "inline-flex";
    uxToastAction.innerText = String(options.actionLabel);
  } else {
    uxToastAction.style.display = "none";
    uxToastAction.innerText = "";
  }

  uxToast.style.display = "flex";
  uxToastTimer = setTimeout(() => {
    hideToast();
  }, duration);
}

function hideToast() {
  if (!uxToast) return;
  uxToast.style.display = "none";
  if (uxToastTimer) {
    clearTimeout(uxToastTimer);
    uxToastTimer = null;
  }
  uxToastActionHandler = null;
  if (uxToastAction) {
    uxToastAction.style.display = "none";
    uxToastAction.innerText = "";
  }
}

function showPendingToast(message) {
  pendingToastCounter += 1;
  activePendingToastId = pendingToastCounter;
  activePendingToastShownAtMs = Date.now();
  showToast(message, { duration: 600000 });
  return activePendingToastId;
}

function clearPendingToast(pendingId) {
  if (!pendingId) return;
  if (activePendingToastId !== pendingId) return;

  const minVisibleMs = 900;
  const elapsedMs = Date.now() - Number(activePendingToastShownAtMs || 0);
  const waitMs = Math.max(0, minVisibleMs - elapsedMs);

  const finalize = () => {
    if (activePendingToastId !== pendingId) return;
    activePendingToastId = 0;
    activePendingToastShownAtMs = 0;
    hideToast();
  };

  if (waitMs > 0) {
    setTimeout(finalize, waitMs);
    return;
  }
  finalize();
}

if (uxToastAction) {
  uxToastAction.onclick = () => {
    if (typeof uxToastActionHandler === "function") {
      const handler = uxToastActionHandler;
      uxToastActionHandler = null;
      handler();
    }
    hideToast();
  };
}

if (wellnessMusicFrame) {
  let userStartedMusic = false;

  const logMusicSessionIntent = async () => {
    const user = auth.currentUser;
    if (!user?.uid) return;
    const dayKey = getTodayKey();
    if (!dayKey || musicSessionDayKeys.has(dayKey)) return;

    musicSessionDayKeys.add(dayKey);
    musicSessionDates.push(getServerNowDate());
    updateWeeklyReview();

    try {
      await setDoc(doc(db, "users", user.uid, "musicSessions", dayKey), {
        dayKey,
        played: true,
        time: serverTimestamp(),
        updatedAt: serverTimestamp()
      }, { merge: true });
    } catch (_) {}
  };

  const onUserMusicIntent = () => {
    if (userStartedMusic) return;
    userStartedMusic = true;
    void logMusicSessionIntent();
  };

  wellnessMusicFrame.addEventListener("pointerdown", onUserMusicIntent, { passive: true });
  wellnessMusicFrame.addEventListener("focus", onUserMusicIntent);
}

function setEmptyState(containerEl, message) {
  if (!containerEl) return;
  containerEl.innerHTML = `<div class="status-empty">${message}</div>`;
}

function setLoadingState(containerEl, message = "Loading...") {
  if (!containerEl) return;
  containerEl.innerHTML = `<div class="status-loading">${message}</div>`;
}

function clearStatusState(containerEl) {
  if (!containerEl) return;
  const placeholders = containerEl.querySelectorAll(".status-empty, .status-loading");
  placeholders.forEach((node) => node.remove());
}

function scheduleEmptyState(containerEl, itemSelector, message, delayMs = 220) {
  if (!containerEl) return;
  setTimeout(() => {
    if (!containerEl || !containerEl.isConnected) return;
    if (containerEl.querySelector(".status-loading")) return;
    if (containerEl.querySelector(itemSelector)) return;
    setEmptyState(containerEl, message);
  }, Math.max(0, Number(delayMs) || 0));
}

function setInitialLoadingStates() {
  setLoadingState(chat, "Loading your AI conversations...");
  setLoadingState(reminders, "Loading reminders...");
  setLoadingState(taskList, "Loading tasks...");
  setLoadingState(moodLogs, "Loading mood logs...");
  setLoadingState(gratitudeLogs, "Loading gratitude notes...");
  if (questListEl) setLoadingState(questListEl, "Preparing today’s habit quests...");
}

function hasAnyClearableData() {
  const hasAiChats = !!chat?.querySelector?.(".chat-message");
  const hasReminders = !!reminders?.querySelector?.(".item-row");
  const hasTasks = taskEntries.length > 0 || !!taskList?.querySelector?.(".item-row");
  const hasMoods = moodHistory.length > 0 || !!moodLogs?.querySelector?.(".mood-item");
  const hasWaterLogs = waterHistory.length > 0;
  const hasSleepLogs = sleepHistory.length > 0;
  const hasGratitudeLogs = gratitudeEntries.length > 0 || !!gratitudeLogs?.querySelector?.(".item-row");
  const hasChallengeHistory = challengeDates.length > 0;
  const hasRescueHistory = rescueEvents.length > 0;
  const hasQuestProgress = questXp > 0 || questStreakCount > 0 || !!questShieldAvailable || (questCompletedDateKeys || []).length > 0;
  const hasWaterGoal = (Number(waterGoal) || 0) > 0;

  return !!(
    hasAiChats ||
    hasReminders ||
    hasTasks ||
    hasMoods ||
    hasWaterLogs ||
    hasSleepLogs ||
    hasGratitudeLogs ||
    hasChallengeHistory ||
    hasRescueHistory ||
    hasQuestProgress ||
    hasWaterGoal
  );
}

function updateClearDataButtonState() {
  if (!clearDataBtn) return;
  const hasData = hasAnyClearableData();
  clearDataBtn.disabled = !hasData;
  clearDataBtn.title = hasData ? "" : "No data to clear";
}

function notifyFirestoreError(err) {
  console.error("Firestore operation failed:", err);
  const authUser = auth?.currentUser || null;
  if (!authUser && isFirestorePermissionDeniedError(err)) {
    // Ignore post-signout auth races that surface as permission-denied.
    return;
  }
  const now = Date.now();
  if (now - lastFirestoreErrorAlertAt > 4000) {
    alert(FIRESTORE_CRASH_MESSAGE);
    lastFirestoreErrorAlertAt = now;
  }
}

function isFirestorePermissionDeniedError(err) {
  const code = String(err?.code || "").toLowerCase();
  const message = String(err?.message || "").toLowerCase();
  return code.includes("permission-denied")
    || code.includes("unauthenticated")
    || message.includes("missing or insufficient permissions");
}

function isFirestoreInternalAssertionError(err) {
  const message = String(err?.message || "").toLowerCase();
  return message.includes("internal assertion failed") || message.includes("unexpected state");
}

async function safeGetDocs(refOrQuery) {
  try {
    return await getDocs(refOrQuery);
  } catch (err) {
    if (!isFirestoreInternalAssertionError(err)) throw err;
    return await getDocsFromServer(refOrQuery);
  }
}

function dateToKey(dateValue) {
  const date = toDateSafe(dateValue);
  if (!date) return null;
  if (Number.isNaN(date.getTime())) return null;
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function formatCountdownClock(milliseconds) {
  const safeMs = Math.max(0, Number(milliseconds) || 0);
  const totalSeconds = Math.floor(safeMs / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

function formatDisplayNameCooldownClock(milliseconds) {
  const safeMs = Math.max(0, Number(milliseconds) || 0);
  const totalSeconds = Math.floor(safeMs / 1000);
  if (totalSeconds >= 86400) {
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    return `${days}d ${hours}h ${String(minutes).padStart(2, "0")}m`;
  }
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  return `${hours}h ${minutes}m ${seconds}s`;
}

function getDailyResetCountdownText() {
  return formatCountdownClock(getMillisecondsUntilNextMidnight());
}

function getWeeklyResetCountdownText() {
  return formatWeeklyResetCountdown(getMillisecondsUntilNextSundayMidnight());
}

function buildDailyLimitCountdownMessage(baseText) {
  return `${baseText}. Resets in ${getDailyResetCountdownText()}.`;
}

function buildWeeklyLimitCountdownMessage(baseText) {
  return `${baseText}. Resets in ${getWeeklyResetCountdownText()}.`;
}

function getAiAbuseCooldownRemainingMs() {
  return Math.max(0, Number(aiAbuseCooldownUntilMs || 0) - Date.now());
}

function buildAiAbuseCooldownMessage(remainingMs = getAiAbuseCooldownRemainingMs()) {
  return `AI chat is temporarily paused for abusive language. Try again in ${formatCountdownClock(remainingMs)}.`;
}

function stopAiAbuseCooldownTicker() {
  if (aiAbuseCooldownIntervalId) {
    clearInterval(aiAbuseCooldownIntervalId);
    aiAbuseCooldownIntervalId = null;
  }
}

function ensureAiAbuseCooldownTicker() {
  if (aiAbuseCooldownIntervalId) return;
  aiAbuseCooldownIntervalId = setInterval(() => {
    const remaining = getAiAbuseCooldownRemainingMs();
    if (remaining <= 0) {
      aiAbuseCooldownUntilMs = 0;
      aiAbuseStrikeCount = 0;
      stopAiAbuseCooldownTicker();
    }
    updateAiLimitUI();
  }, 1000);
}

function updateLimitCountdownNote(noteEl) {
  if (!noteEl) return;
  const baseMessage = noteEl.dataset.baseMessage || "";
  if (!baseMessage) return;
  noteEl.innerText = buildDailyLimitCountdownMessage(baseMessage);
}

function ensureLimitCountdownTicker() {
  if (limitCountdownInterval) return;
  limitCountdownInterval = setInterval(() => {
    const notes = document.querySelectorAll(".limit-note.show[data-live-countdown='1']");
    notes.forEach((noteEl) => updateLimitCountdownNote(noteEl));
  }, 1000);
}

function applyLimitState(noteEl, controls, limited, message) {
  if (noteEl) {
    if (limited) {
      const needsLiveCountdown = /Resets in countdown\.?$/i.test(message || "");
      if (needsLiveCountdown) {
        noteEl.dataset.liveCountdown = "1";
        noteEl.dataset.baseMessage = String(message || "").replace(/\s*Resets in countdown\.?$/i, "").trim();
        updateLimitCountdownNote(noteEl);
        ensureLimitCountdownTicker();
      } else {
        noteEl.innerText = message || "";
        delete noteEl.dataset.liveCountdown;
        delete noteEl.dataset.baseMessage;
      }
    } else {
      noteEl.innerText = "";
      delete noteEl.dataset.liveCountdown;
      delete noteEl.dataset.baseMessage;
    }
    noteEl.classList.toggle("show", !!limited);
  }
  (controls || []).forEach((control) => {
    if (!control) return;
    control.disabled = !!limited;
  });
}

function countTodayFromDates(dateValues) {
  const todayKey = getTodayKey();
  return (dateValues || []).reduce((count, value) => {
    return dateToKey(value) === todayKey ? count + 1 : count;
  }, 0);
}

function getMoodDailyCount() {
  const logsCount = countTodayFromDates(moodDates);
  return Math.max(logsCount, moodDailyUsageCount);
}

function getTaskDailyCount() {
  const todayKey = getTodayKey();
  const logsCount = taskEntries.reduce((total, entry) => (dateToKey(entry.time) === todayKey ? total + 1 : total), 0);
  return Math.max(logsCount, taskDailyUsageCount);
}

function getSleepDailyCount() {
  const logsCount = countTodayFromDates(sleepDates);
  return Math.max(logsCount, sleepDailyUsageCount);
}

function getWaterDailyCount() {
  const logsCount = countTodayFromDates(waterDates);
  return Math.max(logsCount, waterDailyUsageCount);
}

function countTodayRemindersFromDocs(reminderDocs) {
  const todayKey = getTodayKey();
  return (reminderDocs || []).reduce((total, docSnap) => {
    const data = typeof docSnap.data === "function" ? docSnap.data() : docSnap;
    const dateValue = toDateSafe(data.createdAt)
      || (Number(data.targetAtMs) ? new Date(Number(data.targetAtMs)) : null)
      || getServerNowDate();
    return dateToKey(dateValue) === todayKey ? total + 1 : total;
  }, 0);
}

function getGratitudeDailyCount() {
  const todayKey = getTodayKey();
  const logsCount = gratitudeEntries.reduce((total, entry) => (dateToKey(entry.time) === todayKey ? total + 1 : total), 0);
  return Math.max(logsCount, gratitudeDailyUsageCount);
}

function setRemoveButtonsDisabled(containerEl, disabled) {
  if (!containerEl) return;
  const buttons = containerEl.querySelectorAll(".remove-entry-btn");
  buttons.forEach((button) => {
    button.disabled = !!disabled;
  });
}

function updateMoodLimitUI() {
  const count = getMoodDailyCount();
  const limited = count >= MOOD_DAILY_LIMIT;
  applyLimitState(moodLimitError, [mood, moodSaveBtn], limited, `You’ve reached today’s mood log limit (${MOOD_DAILY_LIMIT}/day). Resets in countdown.`);
  setRemoveButtonsDisabled(moodLogs, limited);
}

function updateTaskLimitUI() {
  const count = getTaskDailyCount();
  const limited = count >= TASK_DAILY_LIMIT;
  applyLimitState(taskLimitError, [task, taskAddBtn], limited, `You’ve reached today’s task limit (${TASK_DAILY_LIMIT}/day). Resets in countdown.`);
  setRemoveButtonsDisabled(taskList, limited);
}

function updateGratitudeLimitUI() {
  const count = getGratitudeDailyCount();
  const limited = count >= GRATITUDE_DAILY_LIMIT;
  applyLimitState(gratitudeLimitError, [gratitudeInput, gratitudeSaveBtn], limited, `You’ve reached today’s gratitude limit (${GRATITUDE_DAILY_LIMIT}/day). Resets in countdown.`);
  setRemoveButtonsDisabled(gratitudeLogs, limited);
}

function updateWaterLimitUI() {
  const count = getWaterDailyCount();
  const limited = count >= WATER_DAILY_LIMIT;
  applyLimitState(waterLimitError, [waterInput, waterTrackBtn], limited, `You’ve reached today’s water log limit (${WATER_DAILY_LIMIT}/day). Resets in countdown.`);
}

function updateSleepLimitUI() {
  const count = getSleepDailyCount();
  const limited = count >= SLEEP_DAILY_LIMIT;
  applyLimitState(sleepLimitError, [sleepInput, sleepSaveBtn], limited, `You’ve reached today’s sleep log limit (${SLEEP_DAILY_LIMIT}/day). Resets in countdown.`);
}

function updateAiLimitUI() {
  const dailyLimit = getCurrentAiDailyLimit();
  const limited = aiUsageCount >= dailyLimit;
  applyLimitState(aiLimitError, [aiInput, aiTalkBtn], limited, `Daily AI limit reached (${dailyLimit}/${dailyLimit}). Resets in countdown.`);

  const abuseCooldownRemainingMs = getAiAbuseCooldownRemainingMs();
  const abuseBlocked = abuseCooldownRemainingMs > 0;
  if (abuseBlocked) {
    ensureAiAbuseCooldownTicker();
    if (aiLimitError) {
      aiLimitError.innerText = buildAiAbuseCooldownMessage(abuseCooldownRemainingMs);
      aiLimitError.classList.add("show");
      delete aiLimitError.dataset.liveCountdown;
      delete aiLimitError.dataset.baseMessage;
    }
    if (aiTalkBtn) {
      aiTalkBtn.disabled = true;
      aiTalkBtn.title = `Temporarily paused (${formatCountdownClock(abuseCooldownRemainingMs)})`;
    }
  } else {
    stopAiAbuseCooldownTicker();
    if (aiTalkBtn && !limited) aiTalkBtn.title = "";
  }

  const editButtons = chat?.querySelectorAll?.(".chat-edit-btn") || [];
  editButtons.forEach((button) => {
    button.disabled = !!limited;
    if (limited) button.title = "AI daily limit reached";
    else button.removeAttribute("title");
  });
}

function getCurrentAiDailyLimit() {
  return AI_DAILY_LIMIT;
}

async function updateReminderLimitUI(userId) {
  if (!userId) {
    applyLimitState(reminderLimitError, [reminderText, reminderMinutes, reminderUnit, reminderSetBtn], false, "");
    setRemoveButtonsDisabled(reminders, false);
    return;
  }

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "reminders"));
    const count = Math.max(countTodayRemindersFromDocs(snapshot.docs), reminderDailyUsageCount);

    const limited = count >= REMINDER_DAILY_LIMIT;
    applyLimitState(reminderLimitError, [reminderText, reminderMinutes, reminderUnit, reminderSetBtn], limited, `You’ve reached today’s reminder limit (${REMINDER_DAILY_LIMIT}/day). Resets in countdown.`);
    setRemoveButtonsDisabled(reminders, limited);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function resetAllLimitUIs() {
  stopAiAbuseCooldownTicker();
  applyLimitState(aiLimitError, [aiInput, aiTalkBtn], false, "");
  applyLimitState(reminderLimitError, [reminderText, reminderMinutes, reminderUnit, reminderSetBtn], false, "");
  applyLimitState(taskLimitError, [task, taskAddBtn], false, "");
  applyLimitState(moodLimitError, [mood, moodSaveBtn], false, "");
  applyLimitState(waterLimitError, [waterInput, waterTrackBtn], false, "");
  applyLimitState(sleepLimitError, [sleepInput, sleepSaveBtn], false, "");
  applyLimitState(gratitudeLimitError, [gratitudeInput, gratitudeSaveBtn], false, "");
  setRemoveButtonsDisabled(reminders, false);
  setRemoveButtonsDisabled(taskList, false);
  setRemoveButtonsDisabled(moodLogs, false);
  setRemoveButtonsDisabled(gratitudeLogs, false);
}

function calcStreak(dateValues) {
  const daySet = new Set(
    dateValues
      .map((value) => dateToKey(value))
      .filter(Boolean)
  );

  let streak = 0;
  const today = getServerNowDate();
  today.setUTCHours(0, 0, 0, 0);

  while (true) {
    const dayKey = dateToKey(today);
    if (!daySet.has(dayKey)) break;
    streak++;
    today.setUTCDate(today.getUTCDate() - 1);
  }

  return streak;
}

function setInsightBar(element, percent) {
  const bounded = Math.max(0, Math.min(100, percent));
  element.style.width = `${bounded}%`;
}

function getCurrentWeekDates() {
  const now = getServerNowDate();
  const currentDayIndex = now.getUTCDay();
  const sunday = new Date(now);
  sunday.setUTCDate(now.getUTCDate() - currentDayIndex);
  sunday.setUTCHours(0, 0, 0, 0);

  return Array.from({ length: 7 }, (_, index) => {
    const day = new Date(sunday);
    day.setUTCDate(sunday.getUTCDate() + index);
    return day;
  });
}

function moodToScore(value) {
  return Number(getMoodStateMeta(value).score) || 0;
}

function buildMoodAverageByDayMap(dayKeys = null) {
  const daySet = dayKeys instanceof Set
    ? dayKeys
    : (Array.isArray(dayKeys) ? new Set(dayKeys) : null);

  const buckets = new Map();
  moodHistory.forEach((entry, index) => {
    const key = dateToKey(moodDates[index]);
    if (!key || (daySet && !daySet.has(key))) return;
    const score = moodToScore(entry);
    if (!score) return;
    const bucket = buckets.get(key) || { sum: 0, count: 0 };
    bucket.sum += score;
    bucket.count += 1;
    buckets.set(key, bucket);
  });

  const averages = new Map();
  buckets.forEach((bucket, key) => {
    if (!bucket?.count) return;
    averages.set(key, Number((bucket.sum / bucket.count).toFixed(2)));
  });
  return averages;
}

function getInsightSeries(metricType) {
  const days = getCurrentWeekDates();
  const labels = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  if (metricType === "tasks") {
    const values = days.map((day) => {
      const dayKey = dateToKey(day);
      const dayTasks = taskEntries.filter((entry) => dateToKey(entry.time) === dayKey);
      if (!dayTasks.length) return 0;
      const completedCount = dayTasks.filter((entry) => !!entry.completed).length;
      return Math.round((completedCount / dayTasks.length) * 100);
    });
    return { labels, values, maxValue: 100 };
  }

  if (metricType === "sleep") {
    const values = days.map((day) => {
      const dayKey = dateToKey(day);
      let latest = 0;
      sleepHistory.forEach((value, index) => {
        if (dateToKey(sleepDates[index]) === dayKey) latest = Number(value) || latest;
      });
      return Number(latest.toFixed(1));
    });
    return { labels, values, maxValue: 12 };
  }

  if (metricType === "mood") {
    const moodByDay = buildMoodAverageByDayMap(days.map((day) => dateToKey(day)).filter(Boolean));
    const values = days.map((day) => {
      const dayKey = dateToKey(day);
      return Number(moodByDay.get(dayKey)) || 0;
    });
    return { labels, values, maxValue: 3 };
  }

  const values = days.map((day) => {
    const dayKey = dateToKey(day);
    let latestValue = 0;
    for (let index = waterHistory.length - 1; index >= 0; index -= 1) {
      if (dateToKey(waterDates[index]) !== dayKey) continue;
      latestValue = Number(waterHistory[index]) || 0;
      break;
    }
    return Number(latestValue.toFixed(1));
  });
  const waterScaleMax = Math.max(8, ...values.map((value) => Number(value) || 0));
  return { labels, values, maxValue: waterScaleMax };
}

function getCurrentWeekRangeKeys() {
  const weekDates = getCurrentWeekDates();
  return {
    weekStartKey: dateToKey(weekDates[0]) || getTodayKey(),
    weekEndKey: dateToKey(weekDates[weekDates.length - 1]) || getTodayKey()
  };
}

function getSeriesWithPersistedFallback(metricName, computedSeries, weekRange) {
  const baseSeries = computedSeries && !Array.isArray(computedSeries)
    ? computedSeries
    : { labels: [], values: [], maxValue: 0 };

  const computedValues = Array.isArray(baseSeries.values) ? baseSeries.values : [];
  const hasComputedSignal = computedValues.some((value) => Math.abs(Number(value) || 0) > 0);
  if (hasComputedSignal) return baseSeries;

  const persisted = persistedBarGraphs;
  if (!persisted || persisted.weekStartKey !== weekRange.weekStartKey || persisted.weekEndKey !== weekRange.weekEndKey) {
    return baseSeries;
  }

  const metricPayload = persisted?.[metricName];
  if (!metricPayload || !Array.isArray(metricPayload.values)) return baseSeries;

  return {
    labels: Array.isArray(persisted.labels) ? persisted.labels : (Array.isArray(baseSeries.labels) ? baseSeries.labels : []),
    values: metricPayload.values,
    maxValue: Number(metricPayload.maxValue) || Number(baseSeries.maxValue) || 0
  };
}

function renderInsightMetricView(payload) {
  if (insightMetricTitle) insightMetricTitle.innerText = payload.title;
  if (insightMetricLabel) insightMetricLabel.innerText = payload.label;
  if (insightAxisLayer && insightBarLayer && insightBarLabelLayer && insightLineGraph) {
    const seriesPayload = payload.series && !Array.isArray(payload.series)
      ? payload.series
      : { labels: [], values: Array.isArray(payload.series) ? payload.series : [], maxValue: 0 };
    const labels = Array.isArray(seriesPayload.labels) && seriesPayload.labels.length ? seriesPayload.labels : ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    const sourceValues = Array.isArray(seriesPayload.values) ? seriesPayload.values : [];
    const values = sourceValues.length ? sourceValues : new Array(labels.length).fill(0);

    const yAxisX = 52;
    const chartRightPadding = 20;
    const chartTop = 16;
    const chartBottom = 150;
    const labelY = 172;
    const valueOffset = 6;
    const chartHeight = Math.max(1, chartBottom - chartTop);
    const providedMax = Math.max(0, Number(seriesPayload.maxValue) || 0);
    const rawMaxValue = Math.max(1, providedMax, ...values.map((value) => Number(value) || 0));
    const yMaxValue = rawMaxValue <= 5 ? 5 : Math.ceil(rawMaxValue / 5) * 5;
    const usableWidth = Math.max(520, 82 * labels.length);
    const graphWidth = Math.max(640, yAxisX + usableWidth + chartRightPadding);
    const viewBoxHeight = 188;
    const barAreaWidth = Math.max(1, graphWidth - yAxisX - chartRightPadding);
    const slotWidth = barAreaWidth / labels.length;
    const barWidth = Math.min(28, Math.max(14, slotWidth * 0.38));

    if (insightGraphTrack) {
      insightGraphTrack.style.width = `${graphWidth}px`;
      insightGraphTrack.style.minWidth = `${graphWidth}px`;
    }
    insightLineGraph.style.width = "100%";
    insightLineGraph.style.minWidth = "100%";
    insightLineGraph.setAttribute("viewBox", `0 0 ${graphWidth} ${viewBoxHeight}`);

    insightAxisLayer.innerHTML = "";
    insightBarLayer.innerHTML = "";
    insightBarLabelLayer.innerHTML = "";

    const yTicks = 5;
    for (let tick = 0; tick <= yTicks; tick += 1) {
      const ratio = tick / yTicks;
      const y = chartBottom - (ratio * chartHeight);
      const tickValue = Math.round(yMaxValue * ratio);

      const tickLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
      tickLabel.setAttribute("x", (yAxisX - 8).toFixed(2));
      tickLabel.setAttribute("y", (y + 3).toFixed(2));
      tickLabel.setAttribute("text-anchor", "end");
      tickLabel.setAttribute("class", "insight-tick-label");
      tickLabel.textContent = String(tickValue);
      insightAxisLayer.appendChild(tickLabel);
    }

    const yAxis = document.createElementNS("http://www.w3.org/2000/svg", "line");
    yAxis.setAttribute("x1", yAxisX.toFixed(2));
    yAxis.setAttribute("y1", chartTop.toFixed(2));
    yAxis.setAttribute("x2", yAxisX.toFixed(2));
    yAxis.setAttribute("y2", chartBottom.toFixed(2));
    yAxis.setAttribute("class", "insight-axis-line");
    insightAxisLayer.appendChild(yAxis);

    const xAxis = document.createElementNS("http://www.w3.org/2000/svg", "line");
    xAxis.setAttribute("x1", yAxisX.toFixed(2));
    xAxis.setAttribute("y1", chartBottom.toFixed(2));
    xAxis.setAttribute("x2", (graphWidth - chartRightPadding).toFixed(2));
    xAxis.setAttribute("y2", chartBottom.toFixed(2));
    xAxis.setAttribute("class", "insight-axis-line");
    insightAxisLayer.appendChild(xAxis);

    values.forEach((rawValue, index) => {
      const value = Math.max(0, Number(rawValue) || 0);
      const normalized = Math.max(0, Math.min(1, value / yMaxValue));
      const barHeight = normalized > 0 ? Math.max(3, normalized * chartHeight) : 0;
      const slotStart = yAxisX + (index * slotWidth);
      const x = slotStart + ((slotWidth - barWidth) / 2);
      const y = chartBottom - barHeight;

      const bar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      bar.setAttribute("x", x.toFixed(2));
      bar.setAttribute("y", y.toFixed(2));
      bar.setAttribute("width", barWidth.toFixed(2));
      bar.setAttribute("height", barHeight.toFixed(2));
      bar.setAttribute("rx", "6");
      bar.setAttribute("ry", "6");
      bar.setAttribute("class", "insight-column");
      insightBarLayer.appendChild(bar);

      const valueLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
      valueLabel.setAttribute("x", (x + (barWidth / 2)).toFixed(2));
      valueLabel.setAttribute("y", (Math.max(chartTop, y - valueOffset)).toFixed(2));
      valueLabel.setAttribute("class", "insight-bar-value");
      valueLabel.textContent = Number.isInteger(value) ? String(value) : value.toFixed(1);
      insightBarLabelLayer.appendChild(valueLabel);

      const dayLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
      dayLabel.setAttribute("x", (x + (barWidth / 2)).toFixed(2));
      dayLabel.setAttribute("y", labelY.toFixed(2));
      dayLabel.setAttribute("class", "insight-bar-label");
      dayLabel.textContent = labels[index] || "";
      insightBarLabelLayer.appendChild(dayLabel);
    });

    if (insightGraphScroll) {
      insightGraphScroll.scrollLeft = 0;
    }
  }
}

function nextInsightMetric() {
  insightMetricIndex = (insightMetricIndex + 1) % 4;
  updateInsights();
  if (insightsCard?.scrollIntoView) {
    insightsCard.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function dateKeyToDate(dateKey) {
  if (!dateKey || typeof dateKey !== "string") return null;
  const [year, month, day] = dateKey.split("-").map(Number);
  if (!year || !month || !day) return null;
  const parsed = new Date(year, month - 1, day, 12, 0, 0, 0);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function toDateSafe(value) {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const viaToDate = value?.toDate?.();
  if (viaToDate instanceof Date && !Number.isNaN(viaToDate.getTime())) return viaToDate;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

async function trimCollectionToMaxEntries(userId, collectionName, maxEntries, getEntryTimeMs) {
  if (!userId || !collectionName || !maxEntries) return;

  try {
    const snapshot = await getDocs(collection(db, "users", userId, collectionName));
    const docs = snapshot.docs.map((docSnap) => {
      const payload = { id: docSnap.id, ...docSnap.data() };
      const ms = Number(getEntryTimeMs(payload)) || 0;
      return { ...payload, _ms: ms };
    });

    if (docs.length <= maxEntries) return;

    docs.sort((a, b) => a._ms - b._ms);
    const toDelete = docs.slice(0, docs.length - maxEntries);
    await Promise.all(toDelete.map((entry) => deleteDoc(doc(db, "users", userId, collectionName, entry.id))));
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function isInRange(dateValue, startDate, endDate) {
  const parsed = toDateSafe(dateValue);
  if (!parsed) return false;
  return parsed >= startDate && parsed <= endDate;
}

function getWeekRanges() {
  const now = getServerNowDate();
  const currentStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
  currentStart.setUTCDate(currentStart.getUTCDate() - currentStart.getUTCDay());

  const currentEnd = new Date(currentStart);
  currentEnd.setUTCDate(currentStart.getUTCDate() + 6);
  currentEnd.setUTCHours(23, 59, 59, 999);

  const previousStart = new Date(currentStart);
  previousStart.setUTCDate(currentStart.getUTCDate() - 7);
  previousStart.setUTCHours(0, 0, 0, 0);

  const previousEnd = new Date(previousStart);
  previousEnd.setUTCDate(previousStart.getUTCDate() + 6);
  previousEnd.setUTCHours(23, 59, 59, 999);

  return {
    currentStart,
    currentEnd,
    previousStart,
    previousEnd
  };
}

function computeWeekMetrics(startDate, endDate) {
  const dayKeys = buildWeekDayKeys(startDate, 7);
  const moodByDay = buildMoodAverageByDayMap(new Set(dayKeys));
  const moodDailyValues = dayKeys
    .map((key) => Number(moodByDay.get(key)) || 0)
    .filter((value) => value > 0);

  let sleepSum = 0;
  let sleepCount = 0;
  sleepHistory.forEach((entry, index) => {
    const sleepDate = sleepDates[index];
    if (!isInRange(sleepDate, startDate, endDate)) return;
    sleepSum += Number(entry) || 0;
    sleepCount += 1;
  });

  const waterByDay = new Map();
  waterHistory.forEach((entry, index) => {
    const waterDate = waterDates[index];
    if (!isInRange(waterDate, startDate, endDate)) return;
    const dayKey = dateToKey(waterDate);
    if (!dayKey) return;
    waterByDay.set(dayKey, (waterByDay.get(dayKey) || 0) + (Number(entry) || 0));
  });

  const tasksInPeriod = taskEntries.filter((entry) => {
    const taskDate = toDateSafe(entry.time);
    return isInRange(taskDate, startDate, endDate);
  });
  const completedInPeriod = tasksInPeriod.filter((entry) => !!entry.completed).length;

  const rescuesInPeriod = rescueEvents.filter((entry) => isInRange(entry.time, startDate, endDate)).length;

  return {
    moodScore: moodDailyValues.length ? safeAvg(moodDailyValues) : 0,
    sleepAvg: sleepCount ? sleepSum / sleepCount : 0,
    waterDailyAvg: waterByDay.size ? [...waterByDay.values()].reduce((a, b) => a + b, 0) / 7 : 0,
    taskCompletion: tasksInPeriod.length ? completedInPeriod / tasksInPeriod.length : 0,
    rescues: rescuesInPeriod,
    taskCount: tasksInPeriod.length
  };
}

function setListItems(listElement, items, fallbackText) {
  if (!listElement) return;
  if (!items.length) {
    listElement.innerHTML = `<li>${fallbackText}</li>`;
    return;
  }
  listElement.innerHTML = items.map((item) => `<li>${item}</li>`).join("");
}

function renderWeeklyTargets() {
  if (!weeklyTargetsDisplay) return;
  weeklyTargetsDisplay.innerText = `Targets: Water ${weeklyTargets.waterGoal || "-"} glasses/day • Sleep ${weeklyTargets.sleepTarget || "-"} hrs • Tasks ${weeklyTargets.taskTarget || "-"}/day`;
}

function buildWeekDayKeys(startDate, totalDays = 7) {
  const keys = [];
  const cursor = new Date(startDate);
  cursor.setUTCHours(0, 0, 0, 0);
  for (let index = 0; index < totalDays; index += 1) {
    const dayKey = dateToKey(cursor);
    if (dayKey) keys.push(dayKey);
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return keys;
}

function renderWeeklyGoalScorecard(currentStart, currentEnd) {
  if (!weeklyGoalScorecard) return;

  const dayKeys = buildWeekDayKeys(currentStart, 7);
  if (!dayKeys.length) {
    setListItems(weeklyGoalScorecard, [], "No scorecard data yet.");
    return;
  }

  const waterByDay = new Map();
  waterHistory.forEach((entry, index) => {
    const waterDate = waterDates[index];
    if (!isInRange(waterDate, currentStart, currentEnd)) return;
    const dayKey = dateToKey(waterDate);
    if (!dayKey) return;
    waterByDay.set(dayKey, (waterByDay.get(dayKey) || 0) + (Number(entry) || 0));
  });

  const sleepByDay = new Map();
  sleepHistory.forEach((entry, index) => {
    const sleepDate = sleepDates[index];
    if (!isInRange(sleepDate, currentStart, currentEnd)) return;
    const dayKey = dateToKey(sleepDate);
    if (!dayKey) return;
    sleepByDay.set(dayKey, Number(entry) || 0);
  });

  const tasksDoneByDay = new Map();
  taskEntries.forEach((entry) => {
    const taskDate = toDateSafe(entry.time);
    if (!isInRange(taskDate, currentStart, currentEnd)) return;
    if (!entry.completed) return;
    const dayKey = dateToKey(taskDate);
    if (!dayKey) return;
    tasksDoneByDay.set(dayKey, (tasksDoneByDay.get(dayKey) || 0) + 1);
  });

  const waterTarget = Math.max(1, Number(weeklyTargets.waterGoal) || 8);
  const sleepTarget = Math.max(1, Number(weeklyTargets.sleepTarget) || 8);
  const taskTarget = Math.max(1, Number(weeklyTargets.taskTarget) || 5);

  const hydrationHits = dayKeys.filter((key) => (Number(waterByDay.get(key)) || 0) >= waterTarget).length;
  const sleepHits = dayKeys.filter((key) => (Number(sleepByDay.get(key)) || 0) >= sleepTarget).length;
  const taskHits = dayKeys.filter((key) => (Number(tasksDoneByDay.get(key)) || 0) >= taskTarget).length;

  const totalDays = dayKeys.length;
  const scoreItems = [
    `Hydration: ${hydrationHits}/${totalDays} days (${Math.round((hydrationHits / totalDays) * 100)}%) • target ${waterTarget} glasses/day`,
    `Sleep: ${sleepHits}/${totalDays} days (${Math.round((sleepHits / totalDays) * 100)}%) • target ${sleepTarget}h/day`,
    `Tasks: ${taskHits}/${totalDays} days (${Math.round((taskHits / totalDays) * 100)}%) • target ${taskTarget} done/day`
  ];

  setListItems(weeklyGoalScorecard, scoreItems, "No scorecard data yet.");
}

function updateWeeklyReview() {
  const user = auth.currentUser;
  if (!user) return;

  const { currentStart, currentEnd, previousStart, previousEnd } = getWeekRanges();
  const current = computeWeekMetrics(currentStart, currentEnd);
  const previous = computeWeekMetrics(previousStart, previousEnd);

  if (weeklyRange) {
    const startLabelDate = dateKeyToDate(dateToKey(currentStart)) || currentStart;
    const endLabelDate = dateKeyToDate(dateToKey(currentEnd)) || currentEnd;
    weeklyRange.innerText = `Review window: ${startLabelDate.toLocaleDateString()} - ${endLabelDate.toLocaleDateString()}`;
  }

  const improved = [];
  if (current.sleepAvg > previous.sleepAvg + 0.2) improved.push(`Sleep improved to ${current.sleepAvg.toFixed(1)}h avg.`);
  if (current.waterDailyAvg > previous.waterDailyAvg + 0.4) improved.push(`Hydration improved to ${current.waterDailyAvg.toFixed(1)} glasses/day.`);
  if (current.taskCompletion > previous.taskCompletion + 0.08) improved.push(`Task completion improved to ${Math.round(current.taskCompletion * 100)}%.`);
  if (current.moodScore > previous.moodScore + 0.15) improved.push("Mood trend improved this week.");
  if (current.rescues < previous.rescues) improved.push("Fewer rescue triggers than last week.");

  const dropped = [];
  if (current.sleepAvg < previous.sleepAvg - 0.2) dropped.push(`Sleep dropped to ${current.sleepAvg.toFixed(1)}h avg.`);
  if (current.waterDailyAvg < previous.waterDailyAvg - 0.4) dropped.push(`Hydration dipped to ${current.waterDailyAvg.toFixed(1)} glasses/day.`);
  if (current.taskCompletion < previous.taskCompletion - 0.08) dropped.push(`Task completion dropped to ${Math.round(current.taskCompletion * 100)}%.`);
  if (current.moodScore < previous.moodScore - 0.15) dropped.push("Mood trend dipped this week.");
  if (current.rescues > previous.rescues) dropped.push("Rescue triggers increased this week.");

  const actions = [];
  if (current.sleepAvg < 7) actions.push("Set wind-down reminder 60 minutes before sleep for 5 nights.");
  if (current.waterDailyAvg < Math.max(8, weeklyTargets.waterGoal || 8)) actions.push("Hit hydration target by scheduling 3 fixed water check-ins.");
  if (current.taskCompletion < 0.7) actions.push("Limit daily priority tasks to 3 and finish one before noon.");
  if (current.moodScore < 2) actions.push("Log mood twice daily and run one 2-minute rescue when stress rises.");
  if (current.rescues >= 3) actions.push("Use preventive reset every afternoon before the usual dip window.");
  while (actions.length < 3) actions.push("Keep the current routine and protect your strongest streak.");

  const patternInsights = [];
  const behaviorPatterns = buildBehaviorPatternMemoryFromLocal(30);

  if (behaviorPatterns?.waterMood && (behaviorPatterns.waterMood.highCount >= 2) && (behaviorPatterns.waterMood.lowCount >= 2)) {
    const hydrationHigher = Number(behaviorPatterns.waterMood.highAvg) >= Number(behaviorPatterns.waterMood.lowAvg);
    patternInsights.push(
      hydrationHigher
        ? "Your mood increases when your water intake is high and drops when your water intake is low."
        : "Your mood increases when your water intake is low and drops when your water intake is high."
    );
  } else {
    patternInsights.push("Your mood and water-intake pattern needs more logged days to lock a high/low signal.");
  }

  if (behaviorPatterns?.sleepMood && (behaviorPatterns.sleepMood.highCount >= 2) && (behaviorPatterns.sleepMood.lowCount >= 2)) {
    const sleepHigher = Number(behaviorPatterns.sleepMood.highAvg) >= Number(behaviorPatterns.sleepMood.lowAvg);
    patternInsights.push(
      sleepHigher
        ? "Your mood increases when your sleep is high and drops when your sleep is low."
        : "Your mood increases when your sleep is low and drops when your sleep is high."
    );
  } else {
    patternInsights.push("Your mood and sleep pattern needs more logged days to lock a high/low signal.");
  }

  {
    const musicDayKeys = new Set([...musicSessionDayKeys]);
    const moodByDay = buildMoodAverageByDayMap(new Set(getRecentDayKeys(30)));
    const moodWithMusic = [];
    const moodWithoutMusic = [];

    moodByDay.forEach((moodAvg, dayKey) => {
      const value = Number(moodAvg) || 0;
      if (value <= 0) return;
      if (musicDayKeys.has(dayKey)) moodWithMusic.push(value);
      else moodWithoutMusic.push(value);
    });

    if (moodWithMusic.length >= 2 && moodWithoutMusic.length >= 2) {
      const withMusicAvg = safeAvg(moodWithMusic);
      const withoutMusicAvg = safeAvg(moodWithoutMusic);
      const improvesWithMusic = withMusicAvg >= withoutMusicAvg;
      patternInsights.push(
        improvesWithMusic
          ? "Your mood increases when you listen to music."
          : "Your mood drops when you listen to music."
      );
    } else {
      patternInsights.push("Your music-mood pattern needs more music sessions to confirm whether mood drops or increases.");
    }
  }

  setListItems(weeklyImproved, improved, "No major gains yet — consistency this week will unlock visible progress.");
  setListItems(weeklyDropped, dropped, "No clear drops this week — maintain the trend.");
  setListItems(weeklyActions, actions.slice(0, 3), "Set one small target and repeat it daily.");
  setListItems(weeklyPatternInsights, patternInsights.slice(0, 3), "Pattern analysis will appear after enough logs.");
  renderWeeklyGoalScorecard(currentStart, currentEnd);
  renderWeeklyTargets();
}

async function loadWeeklyTargets(userId) {
  weeklyTargets = { waterGoal: 0, sleepTarget: 8, taskTarget: 5 };
  try {
    const snap = await fsGetDoc(doc(db, "users", userId, "settings", "weeklyTargets"), 'weeklyTargets');
    if (snap.exists) {
      const data = snap.data || {};
      weeklyTargets = {
        waterGoal: Number(data.waterGoal) || 0,
        sleepTarget: Number(data.sleepTarget) || 8,
        taskTarget: Number(data.taskTarget) || 5
      };
    }
  } catch (err) {
    notifyFirestoreError(err);
  }
  renderWeeklyTargets();
  updateWeeklyReview();
}

async function loadRescueEvents(userId) {
  rescueEvents.length = 0;
  try {
    const snap = await getDocs(collection(db, "users", userId, "rescueEvents"));
    snap.docs.forEach((docSnap) => {
      const data = docSnap.data();
      const time = toDateSafe(data.time);
      if (!time) return;
      rescueEvents.push({
        id: docSnap.id,
        time,
        level: data.level || ""
      });
    });
  } catch (err) {
    notifyFirestoreError(err);
  }
  updateWeeklyReview();
  updateClearDataButtonState();
}

async function loadMusicSessions(userId) {
  musicSessionDates.length = 0;
  musicSessionDayKeys.clear();
  if (!userId) {
    updateWeeklyReview();
    return;
  }

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "musicSessions"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = getOptionalTimestampMs(a.time) || 0;
        const bTime = getOptionalTimestampMs(b.time) || 0;
        return aTime - bTime;
      });

    docs.forEach((entry) => {
      const dayKey = String(entry.dayKey || entry.id || "").trim();
      if (!dayKey) return;
      musicSessionDayKeys.add(dayKey);
      const playedAt = toDateSafe(entry.time) || dateKeyToDate(dayKey) || getServerNowDate();
      musicSessionDates.push(playedAt);
    });
  } catch (err) {
    notifyFirestoreError(err);
  }

  updateWeeklyReview();
}

async function setNextWeekTargets() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const { currentStart, currentEnd } = getWeekRanges();
  const current = computeWeekMetrics(currentStart, currentEnd);
  const waterGoalTarget = Math.max(8, Math.min(16, Math.round(current.waterDailyAvg || 8) + 1));
  const sleepTarget = Math.max(7, Math.min(9, Math.round(((current.sleepAvg || 7) + 0.5) * 2) / 2));
  const taskTarget = Math.max(3, Math.min(10, Math.round((current.taskCount / 7) || 4)));

  weeklyTargets = {
    waterGoal: waterGoalTarget,
    sleepTarget,
    taskTarget
  };

  try {
    await setDoc(doc(db, "users", user.uid, "settings", "weeklyTargets"), {
      ...weeklyTargets,
      updatedAt: serverTimestamp()
    }, { merge: true });

    waterGoal = waterGoalTarget;
    waterGoalInput.value = String(waterGoalTarget);
    await setDoc(doc(db, "users", user.uid, "settings", "water"), {
      goal: waterGoalTarget,
      goalDateKey: getTodayKey()
    }, { merge: true });

    updateWaterProgress();
    updateWeeklyReview();
    showToast(`Targets set: Water ${waterGoalTarget}, Sleep ${sleepTarget}h, Tasks ${taskTarget}/day.`);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

const QUEST_LIBRARY = [
  { id: "sleep60_1", text: "Log at least 6 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 6 } },
  { id: "sleep60_2", text: "Hit a 6-hour sleep minimum tonight.", type: "recovery", requirement: { kind: "sleep", min: 6 } },
  { id: "sleep65_1", text: "Log at least 6.5 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 6.5 } },
  { id: "sleep65_2", text: "Get to 6.5+ hours of rest today.", type: "recovery", requirement: { kind: "sleep", min: 6.5 } },
  { id: "sleep70_1", text: "Log at least 7 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 7 } },
  { id: "sleep70_2", text: "Reach a full 7 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 7 } },
  { id: "sleep75_1", text: "Log at least 7.5 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 7.5 } },
  { id: "sleep75_2", text: "Aim for 7.5+ sleep hours today.", type: "recovery", requirement: { kind: "sleep", min: 7.5 } },
  { id: "sleep80_1", text: "Log at least 8 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 8 } },
  { id: "sleep80_2", text: "Sleep 8 hours today for full recovery.", type: "recovery", requirement: { kind: "sleep", min: 8 } },
  { id: "sleep85_1", text: "Log at least 8.5 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 8.5 } },
  { id: "sleep85_2", text: "Stretch sleep to 8.5 hours today.", type: "recovery", requirement: { kind: "sleep", min: 8.5 } },
  { id: "sleep90_1", text: "Log at least 9 hours of sleep today.", type: "recovery", requirement: { kind: "sleep", min: 9 } },
  { id: "sleep90_2", text: "Reach 9 sleep hours today.", type: "recovery", requirement: { kind: "sleep", min: 9 } },

  { id: "water5_1", text: "Log at least 5 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 5 } },
  { id: "water5_2", text: "Drink and log 5 glasses today.", type: "hydration", requirement: { kind: "water", min: 5 } },
  { id: "water6_1", text: "Log at least 6 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 6 } },
  { id: "water6_2", text: "Hit 6 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 6 } },
  { id: "water7_1", text: "Log at least 7 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 7 } },
  { id: "water7_2", text: "Reach 7 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 7 } },
  { id: "water8_1", text: "Log at least 8 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 8 } },
  { id: "water8_2", text: "Get to 8 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 8 } },
  { id: "water9_1", text: "Log at least 9 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 9 } },
  { id: "water9_2", text: "Push hydration to 9 glasses today.", type: "hydration", requirement: { kind: "water", min: 9 } },
  { id: "water10_1", text: "Log at least 10 glasses of water today.", type: "hydration", requirement: { kind: "water", min: 10 } },
  { id: "water10_2", text: "Complete a 10-glass hydration day.", type: "hydration", requirement: { kind: "water", min: 10 } },

  { id: "mood_1", text: "Log your mood at least once today.", type: "mind", requirement: { kind: "mood" } },
  { id: "mood_2", text: "Check in with your mood today.", type: "mind", requirement: { kind: "mood" } },
  { id: "mood_3", text: "Record one mood entry for today.", type: "mind", requirement: { kind: "mood" } },
  { id: "mood_4", text: "Track your emotional state once today.", type: "mind", requirement: { kind: "mood" } },

  { id: "grat1_1", text: "Write one gratitude note today.", type: "mind", requirement: { kind: "gratitude", min: 1 } },
  { id: "grat1_2", text: "Capture 1 gratitude win today.", type: "mind", requirement: { kind: "gratitude", min: 1 } },
  { id: "grat2_1", text: "Write two gratitude notes today.", type: "mind", requirement: { kind: "gratitude", min: 2 } },
  { id: "grat2_2", text: "List 2 things you are thankful for today.", type: "mind", requirement: { kind: "gratitude", min: 2 } },
  { id: "grat3_1", text: "Write three gratitude notes today.", type: "mind", requirement: { kind: "gratitude", min: 3 } },
  { id: "grat3_2", text: "Log 3 gratitude moments today.", type: "mind", requirement: { kind: "gratitude", min: 3 } },
  { id: "grat4_1", text: "Write four gratitude notes today.", type: "mind", requirement: { kind: "gratitude", min: 4 } },
  { id: "grat4_2", text: "Complete 4 gratitude entries today.", type: "mind", requirement: { kind: "gratitude", min: 4 } },
  { id: "grat5_1", text: "Write five gratitude notes today.", type: "mind", requirement: { kind: "gratitude", min: 5 } },
  { id: "grat5_2", text: "Log 5 gratitude points today.", type: "mind", requirement: { kind: "gratitude", min: 5 } },
  { id: "grat6_1", text: "Write six gratitude notes today.", type: "mind", requirement: { kind: "gratitude", min: 6 } },
  { id: "grat6_2", text: "Hit 6 gratitude entries today.", type: "mind", requirement: { kind: "gratitude", min: 6 } },

  { id: "task1_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task1_2", text: "Finish all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task2_1", text: "Wrap up all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task2_2", text: "Clear your full task list today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task3_1", text: "Complete all pending tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task3_2", text: "Close every task on your list today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task4_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task4_2", text: "Finish all your tasks before day-end.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task5_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task5_2", text: "Get every task done today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task6_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task6_2", text: "Clear all unfinished tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task7_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task7_2", text: "Finish your complete task list today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task8_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task8_2", text: "Complete every open task today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task9_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task9_2", text: "End the day with all tasks completed.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task10_1", text: "Complete all your tasks today.", type: "focus", requirement: { kind: "tasksAll" } },
  { id: "task10_2", text: "Finish all tasks on your plate today.", type: "focus", requirement: { kind: "tasksAll" } },

  { id: "challenge_1", text: "Complete today’s daily challenge.", type: "consistency", requirement: { kind: "challenge" } },
  { id: "challenge_2", text: "Finish the daily challenge today.", type: "consistency", requirement: { kind: "challenge" } },
  { id: "challenge_3", text: "Secure your day by completing today’s challenge.", type: "consistency", requirement: { kind: "challenge" } },
  { id: "challenge_4", text: "Check off the daily challenge before day-end.", type: "consistency", requirement: { kind: "challenge" } },

  { id: "rescue1_1", text: "Run one mood crash rescue today.", type: "resilience", requirement: { kind: "rescue", min: 1 } },
  { id: "rescue1_2", text: "Complete 1 rescue action today.", type: "resilience", requirement: { kind: "rescue", min: 1 } },
  { id: "rescue2_1", text: "Run two mood crash rescues today.", type: "resilience", requirement: { kind: "rescue", min: 2 } },
  { id: "rescue2_2", text: "Do 2 rescue interventions today.", type: "resilience", requirement: { kind: "rescue", min: 2 } },
  { id: "rescue3_1", text: "Run three mood crash rescues today.", type: "resilience", requirement: { kind: "rescue", min: 3 } },
  { id: "rescue3_2", text: "Complete 3 rescue attempts today.", type: "resilience", requirement: { kind: "rescue", min: 3 } }
];

function getQuestWeekStartKeySunday(dateValue = getServerNowDate()) {
  const date = toDateSafe(dateValue) || getServerNowDate();
  const sunday = new Date(date);
  sunday.setUTCHours(0, 0, 0, 0);
  sunday.setUTCDate(sunday.getUTCDate() - sunday.getUTCDay());
  return dateToKey(sunday) || getTodayKey();
}

function getQuestWeekDatesSundayStart() {
  const startKey = getQuestWeekStartKeySunday();
  const startDate = dateKeyToDate(startKey) || getServerNowDate();
  startDate.setUTCHours(0, 0, 0, 0);
  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date(startDate);
    date.setUTCDate(startDate.getUTCDate() + index);
    return date;
  });
}

function pickRandomQuests(pool, count) {
  const shuffled = [...pool];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const randomIndex = Math.floor(Math.random() * (index + 1));
    [shuffled[index], shuffled[randomIndex]] = [shuffled[randomIndex], shuffled[index]];
  }
  return shuffled.slice(0, count);
}

function generateAdaptiveQuests(todayKey = getTodayKey()) {
  const weekStartKey = getQuestWeekStartKeySunday();
  if (questWeekStartKey !== weekStartKey) {
    questWeekStartKey = weekStartKey;
    weeklyQuestUsedIds = [];
    questCompletedDateKeys = [];
    questStreakCount = 0;
    questLastStreakDateKey = "";
  }

  const selected = pickRandomQuests(QUEST_LIBRARY, 4).map((item, index) => ({
    id: `${item.id}-${todayKey}-${index + 1}`,
    baseId: item.id,
    text: item.text,
    type: item.type,
    requirement: item.requirement || null,
    completed: false
  }));

  habitQuests.length = 0;
  selected.forEach((quest) => habitQuests.push(quest));
}

function renderQuestWeekStreak(animatedDateKey = "") {
  if (!questWeekStreakLabels || !questWeekStreakCircles) return;

  const weekDates = getQuestWeekDatesSundayStart();
  const labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const completedSet = new Set((questCompletedDateKeys || []).filter(Boolean));

  questWeekStreakLabels.innerHTML = "";
  questWeekStreakCircles.innerHTML = "";

  weekDates.forEach((date, index) => {
    const key = dateToKey(date);

    const label = document.createElement("span");
    label.className = "challenge-streak-day";
    label.innerText = labels[index] || "";
    questWeekStreakLabels.appendChild(label);

    const circle = document.createElement("span");
    circle.className = "challenge-streak-circle";
    if (completedSet.has(key)) {
      circle.classList.add("filled");
      const fire = document.createElement("span");
      fire.className = "challenge-streak-fire";
      fire.innerText = "🔥";
      circle.appendChild(fire);
      if (animatedDateKey && key === animatedDateKey) {
        circle.classList.add("fire-fill");
      }
    }
    questWeekStreakCircles.appendChild(circle);
  });
}

function renderHabitQuestUI(animatedDateKey = "") {
  if (questXpEl) questXpEl.innerText = `XP ${questXp}/100`;
  const allDoneToday = habitQuests.length > 0 && habitQuests.every((entry) => !!entry.completed);
  if (questStreakEl) questStreakEl.innerText = allDoneToday ? `Streak ${questStreakCount} 🔥` : "Complete all 4 quests to lock today’s streak";
  const progressPercent = allDoneToday ? 100 : Math.max(0, Math.min(100, questXp));
  if (questProgressFill) questProgressFill.style.width = `${progressPercent}%`;
  if (questShieldEl) questShieldEl.innerText = `Streak shield: ${questShieldAvailable ? "Active" : "Inactive"}`;
  if (questProgressHintEl) {
    questProgressHintEl.innerText = allDoneToday
      ? "Perfect day complete — streak secured."
      : `Progress ${progressPercent}% • complete all 4 quests to lock today’s streak.`;
  }
  renderQuestWeekStreak(animatedDateKey);

  if (!questListEl) return;
  questListEl.innerHTML = "";

  if (!habitQuests.length) {
    questListEl.innerHTML = "<li class=\"quest-item\"><span class=\"quest-text\">No quests yet. Log today’s stats to generate quests.</span></li>";
    return;
  }

  habitQuests.forEach((quest, index) => {
    const item = document.createElement("li");
    item.className = "quest-item";

    const text = document.createElement("span");
    text.className = `quest-text${quest.completed ? " quest-done" : ""}`;
    text.textContent = quest.text;

    const button = document.createElement("button");
    button.textContent = quest.completed ? "Done" : "Complete";
    button.disabled = !!quest.completed;
    button.onclick = () => completeHabitQuest(index);

    item.append(text, button);
    questListEl.appendChild(item);
  });
}

async function saveHabitQuestState(userId) {
  if (!userId) return;
  try {
    await setDoc(doc(db, "users", userId, "settings", "habitQuest"), {
      dateKey: questDateKey,
      weekStartKey: questWeekStartKey,
      xp: questXp,
      shield: questShieldAvailable,
      streakCount: questStreakCount,
      lastStreakDateKey: questLastStreakDateKey,
      weeklyQuestUsedIds,
      completedDateKeys: questCompletedDateKeys,
      quests: habitQuests,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function dayDiffFromKeys(fromKey, toKey) {
  if (!fromKey || !toKey) return Infinity;
  const fromDate = new Date(`${fromKey}T00:00:00.000Z`);
  const toDate = new Date(`${toKey}T00:00:00.000Z`);
  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(toDate.getTime())) return Infinity;
  return Math.floor((toDate.getTime() - fromDate.getTime()) / 86400000);
}

function normalizeQuestStreakForToday(todayKey = getTodayKey()) {
  const currentWeekStart = getQuestWeekStartKeySunday();
  if (questWeekStartKey !== currentWeekStart) {
    questWeekStartKey = currentWeekStart;
    questStreakCount = 0;
    questLastStreakDateKey = "";
    weeklyQuestUsedIds = [];
    questCompletedDateKeys = [];
    return;
  }

  if (!questLastStreakDateKey) {
    questStreakCount = 0;
    return;
  }
  const diff = dayDiffFromKeys(questLastStreakDateKey, todayKey);
  if (diff > 1 || diff < 0) questStreakCount = 0;
}

function awardQuestStreakForToday(todayKey = getTodayKey()) {
  if (questLastStreakDateKey === todayKey) return false;
  const diff = dayDiffFromKeys(questLastStreakDateKey, todayKey);
  if (diff === 1) {
    questStreakCount += 1;
  } else {
    questStreakCount = 1;
  }
  questLastStreakDateKey = todayKey;
  return true;
}

function triggerQuestStreakCelebration() {
  if (questStreakEl) {
    questStreakEl.classList.remove("streak-pop");
    void questStreakEl.offsetWidth;
    questStreakEl.classList.add("streak-pop");
    setTimeout(() => questStreakEl.classList.remove("streak-pop"), 700);
  }
}

async function loadHabitQuest(userId) {
  questDateKey = getTodayKey();
  const currentWeekStart = getQuestWeekStartKeySunday();

  try {
    const snap = await fsGetDoc(doc(db, "users", userId, "settings", "habitQuest"), 'habitQuest');
    if (snap.exists) {
      const data = snap.data;
      questXp = Number(data.xp) || 0;
      questShieldAvailable = !!data.shield;
      questStreakCount = Math.max(0, Number(data.streakCount) || 0);
      questLastStreakDateKey = String(data.lastStreakDateKey || "");
      questWeekStartKey = String(data.weekStartKey || "");
      weeklyQuestUsedIds = Array.isArray(data.weeklyQuestUsedIds) ? data.weeklyQuestUsedIds.map((id) => String(id || "")).filter(Boolean) : [];
      questCompletedDateKeys = Array.isArray(data.completedDateKeys) ? data.completedDateKeys.map((key) => String(key || "")).filter(Boolean) : [];

      if (questWeekStartKey !== currentWeekStart) {
        questWeekStartKey = currentWeekStart;
        weeklyQuestUsedIds = [];
        questCompletedDateKeys = [];
        questStreakCount = 0;
        questLastStreakDateKey = "";
      }

      normalizeQuestStreakForToday(questDateKey);

      if (data.dateKey === questDateKey && Array.isArray(data.quests) && data.quests.length >= 4) {
        habitQuests.length = 0;
        data.quests.forEach((quest) => {
          const baseId = String(quest.baseId || String(quest.id || "").split("-")[0] || "");
          habitQuests.push({
            id: String(quest.id || ""),
            baseId,
            text: String(quest.text || "Daily quest"),
            type: String(quest.type || "general"),
            requirement: quest.requirement || null,
            completed: !!quest.completed
          });
        });
      } else {
        questXp = 0;
        questShieldAvailable = false;
        generateAdaptiveQuests(questDateKey);
        await saveHabitQuestState(userId);
      }
    } else {
      questXp = 0;
      questShieldAvailable = false;
      questStreakCount = 0;
      questLastStreakDateKey = "";
      questWeekStartKey = currentWeekStart;
      weeklyQuestUsedIds = [];
      questCompletedDateKeys = [];
      generateAdaptiveQuests(questDateKey);
      await saveHabitQuestState(userId);
    }
  } catch (err) {
    notifyFirestoreError(err);
  }

  renderHabitQuestUI();
}

function getTodayCompletedTaskCount() {
  const todayKey = getTodayKey();
  return taskEntries.filter((entry) => !!entry.completed && dateToKey(entry.time) === todayKey).length;
}

function getTodayRescueCount() {
  const todayKey = getTodayKey();
  return rescueEvents.filter((entry) => dateToKey(entry.time) === todayKey).length;
}

function getTodayGratitudeCount() {
  const todayKey = getTodayKey();
  return gratitudeEntries.filter((entry) => dateToKey(entry.time) === todayKey).length;
}

function validateHabitQuestCompletion(quest) {
  const requirement = quest?.requirement || null;
  const snapshot = getWellnessSnapshot();

  if (!requirement?.kind) {
    const baseId = String(quest?.id || "").split("-")[0];
    if (baseId === "water" || baseId === "water8") {
      const min = baseId === "water8" ? 8 : snapshot.todayGoal;
      if (snapshot.waterToday < min) return { valid: false, message: `Log at least ${min} glasses first (current: ${snapshot.waterToday}).` };
      return { valid: true };
    }
    if (baseId === "sleep") {
      if (snapshot.sleepToday < 7) return { valid: false, message: `Log at least 7 hours sleep first (current: ${snapshot.sleepToday}).` };
      return { valid: true };
    }
    if (baseId === "mood") {
      if (!snapshot.moodToday) return { valid: false, message: "Log your mood first." };
      return { valid: true };
    }
    if (baseId === "gratitude") {
      const count = getTodayGratitudeCount();
      if (count < 1) return { valid: false, message: `Add a gratitude note first (current: ${count}).` };
      return { valid: true };
    }
    if (baseId === "task" || baseId === "tasks2") {
      const min = baseId === "tasks2" ? 2 : 1;
      const completed = getTodayCompletedTaskCount();
      if (completed < min) return { valid: false, message: `Complete at least ${min} task${min > 1 ? "s" : ""} first (current: ${completed}).` };
      return { valid: true };
    }
    if (baseId === "challenge") {
      if (!dailyChallengeCompleted) return { valid: false, message: "Complete today’s daily challenge first." };
      return { valid: true };
    }
    if (baseId === "rescue") {
      const rescues = getTodayRescueCount();
      if (rescues < 1) return { valid: false, message: `Run mood crash rescue first (current: ${rescues}).` };
      return { valid: true };
    }
    return { valid: false, message: "This quest cannot be verified yet. Refresh to get a measurable quest." };
  }

  if (requirement.kind === "water") {
    const min = Math.max(1, Number(requirement.min) || 1);
    if (snapshot.waterToday < min) return { valid: false, message: `Log at least ${min} glasses first (current: ${snapshot.waterToday}).` };
    return { valid: true };
  }
  if (requirement.kind === "sleep") {
    const min = Math.max(1, Number(requirement.min) || 7);
    if (snapshot.sleepToday < min) return { valid: false, message: `Log at least ${min} hours sleep first (current: ${snapshot.sleepToday}).` };
    return { valid: true };
  }
  if (requirement.kind === "mood") {
    if (!snapshot.moodToday) return { valid: false, message: "Log your mood first." };
    return { valid: true };
  }
  if (requirement.kind === "gratitude") {
    const min = Math.max(1, Number(requirement.min) || 1);
    const count = getTodayGratitudeCount();
    if (count < min) return { valid: false, message: `Add at least ${min} gratitude note${min > 1 ? "s" : ""} first (current: ${count}).` };
    return { valid: true };
  }
  if (requirement.kind === "tasksCompleted") {
    const min = Math.max(1, Number(requirement.min) || 1);
    const completed = getTodayCompletedTaskCount();
    if (completed < min) return { valid: false, message: `Complete at least ${min} task${min > 1 ? "s" : ""} first (current: ${completed}).` };
    return { valid: true };
  }
  if (requirement.kind === "tasksAll") {
    const pending = Math.max(0, Number(snapshot.pendingTasks) || 0);
    if (pending > 0) {
      return { valid: false, message: `Complete all your tasks first (${pending} still pending).` };
    }
    return { valid: true };
  }
  if (requirement.kind === "challenge") {
    if (!dailyChallengeCompleted) return { valid: false, message: "Complete today’s daily challenge first." };
    return { valid: true };
  }
  if (requirement.kind === "rescue") {
    const min = Math.max(1, Number(requirement.min) || 1);
    const rescues = getTodayRescueCount();
    if (rescues < min) return { valid: false, message: `Run mood crash rescue at least ${min} time${min > 1 ? "s" : ""} first (current: ${rescues}).` };
    return { valid: true };
  }

  return { valid: false, message: "This quest requirement is not trackable yet." };
}

async function completeHabitQuest(index) {
  const user = auth.currentUser;
  if (!user) return;
  const quest = habitQuests[index];
  if (!quest || quest.completed) return;

  const validation = validateHabitQuestCompletion(quest);
  if (!validation.valid) {
    alert(`❌ ${validation.message}`);
    return;
  }

  quest.completed = true;
  questXp += 20;

  const allDone = habitQuests.length > 0 && habitQuests.every((entry) => entry.completed);
  if (allDone) {
    const todayKey = getTodayKey();
    if (!questCompletedDateKeys.includes(todayKey)) {
      questCompletedDateKeys.push(todayKey);
    }
    questXp += 20;
    questShieldAvailable = true;
    const streakAdvanced = awardQuestStreakForToday(todayKey);
    if (streakAdvanced) triggerQuestStreakCelebration();
    while (questCompletedDateKeys.length > 7) questCompletedDateKeys.shift();
    renderHabitQuestUI(todayKey);
  } else {
    renderHabitQuestUI();
  }

  while (questXp >= 100) questXp -= 100;

  await saveHabitQuestState(user.uid);
  updateInsights();
}

function ensureHabitQuestCurrent() {
  const todayKey = getTodayKey();
  const currentWeekStart = getQuestWeekStartKeySunday();
  if (questWeekStartKey !== currentWeekStart) {
    questWeekStartKey = currentWeekStart;
    questStreakCount = 0;
    questLastStreakDateKey = "";
    weeklyQuestUsedIds = [];
    questCompletedDateKeys = [];
  }

  if (!questDateKey) {
    questDateKey = todayKey;
    if (!habitQuests.length) generateAdaptiveQuests(todayKey);
    renderHabitQuestUI();
    return;
  }

  if (questDateKey !== todayKey) {
    questDateKey = todayKey;
    normalizeQuestStreakForToday(todayKey);
    questXp = 0;
    questShieldAvailable = false;
    generateAdaptiveQuests(todayKey);
    const user = auth.currentUser;
    if (user) saveHabitQuestState(user.uid);
  }

  renderHabitQuestUI();
}

function updateBurnoutRadarUI() {
  const crash = getCrashRiskSnapshot();
  const moodMeta = getMoodStateMeta(getTodayMood());

  const rescueLast3Days = rescueEvents.filter((entry) => {
    const time = toDateSafe(entry.time);
    if (!time) return false;
    const threshold = getServerNowDate();
    threshold.setUTCDate(threshold.getUTCDate() - 3);
    return time >= threshold;
  }).length;

  let forecast = Math.round(crash.risk * 0.75);
  if (moodMeta.logged) forecast += Number(moodMeta.burnoutBoost) || 0;
  if (rescueLast3Days >= 2) forecast += 12;
  if (sleepHistory.length > 1) {
    const recent = Number(sleepHistory[sleepHistory.length - 1]) || 0;
    const prev = Number(sleepHistory[sleepHistory.length - 2]) || 0;
    if (recent < prev - 1) forecast += 8;
  }
  forecast = Math.max(0, Math.min(100, forecast));

  const level = forecast >= 75 ? "High Risk" : forecast >= 50 ? "Moderate Risk" : "Low Risk";
  const planFocus =
    forecast >= 75 ? "Reduce load now" :
    forecast >= 50 ? "Simplify today" :
    "Keep steady";
  let reason =
    forecast >= 75 ? "Your workload and stress signals are high. Cut pressure before adding anything new." :
    forecast >= 50 ? "Early fatigue signs are showing. Keep the day smaller and easier to finish." :
    "Burnout pressure is low. Stay steady and protect a clean finish.";
  if (moodMeta.label === "Angry" || moodMeta.label === "Stressed") {
    reason += ` ${moodMeta.label} mood means your next step should be lighter, not bigger.`;
  }

  burnoutRecoveryPlan.length = 0;
  if (forecast >= 75) {
    burnoutRecoveryPlan.push(
      "Stop adding new tasks for today; finish or park one current task only.",
      "Take a 5-minute no-screen reset: stand, loosen shoulders, look away from the device.",
      "Pick one closure action that would make the day feel less heavy.",
      "Move one optional task to later so recovery has space."
    );
  } else if (forecast >= 50) {
    burnoutRecoveryPlan.push(
      "Choose one priority task and make it half-size.",
      "Do one short movement reset before the next focus block.",
      "Remove one non-urgent item from today’s list.",
      "Write a 2-line shutdown note: done today, next tomorrow."
    );
  } else {
    burnoutRecoveryPlan.push(
      "Keep working in one-task blocks instead of multitasking.",
      "Take a short screen break before fatigue builds.",
      "Close the day with a simple done/waiting list."
    );
  }

  if (burnoutRiskEl) burnoutRiskEl.innerText = `${forecast}/100`;
  if (burnoutWindowEl) burnoutWindowEl.innerText = `${level} • ${planFocus}`;
  if (burnoutReasonEl) burnoutReasonEl.innerText = reason;
  if (burnoutScheduleEl) {
    burnoutScheduleEl.innerHTML = burnoutRecoveryPlan
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
  }
}

async function applyRecoverySchedule() {
  const user = auth.currentUser;
  if (!user) {
    alert("Please sign in first.");
    return;
  }

  if (!burnoutRecoveryPlan.length) updateBurnoutRadarUI();
  const activePlan = burnoutRecoveryPlan.length
    ? [...burnoutRecoveryPlan]
    : ["Choose one priority task and make it smaller.", "Take a short screen break.", "Close with a simple done/waiting list."];

  wellnessActionBoost = Math.min(20, (Number(wellnessActionBoost) || 0) + 2);
  crashRiskActionRelief = Math.min(30, (Number(crashRiskActionRelief) || 0) + 4);
  updateWellnessScore();
  updateCrashPreventionUI();

  burnoutRecoveryPlan.length = 0;
  burnoutRecoveryPlan.push(...activePlan);
  if (burnoutWindowEl) burnoutWindowEl.innerText = "Recovery plan active • Keep it simple";
  if (burnoutReasonEl) burnoutReasonEl.innerText = "Follow these steps inside this card before adding more work. No reminders were created.";
  if (burnoutScheduleEl) {
    burnoutScheduleEl.innerHTML = burnoutRecoveryPlan
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
  }

  alert("✅ Simple recovery plan started inside this card. No reminders were created.");
}

function pickChallengeForDate(dateKey) {
  const sum = [...dateKey].reduce((total, char) => total + char.charCodeAt(0), 0);
  return dailyChallenges[sum % dailyChallenges.length];
}

async function syncSocialProfileToFriendQueue(user, socialProfile) {
  const userId = String(user?.uid || "").trim();
  const userEmail = String(user?.email || "").trim().toLowerCase();
  if (!userId || !socialProfile || typeof socialProfile !== "object") return;

  const safeProfile = {
    uid: String(socialProfile.uid || userId),
    email: String(socialProfile.email || user?.email || "").trim().toLowerCase(),
    username: getNormalizedUsernameIdentity(socialProfile.username || socialProfile.name, String(socialProfile.email || user?.email || "").trim().toLowerCase()),
    displayName: normalizeDisplayNameValue(socialProfile.displayName || socialProfile.name),
    name: getFriendDisplayName({
      displayName: String(socialProfile.displayName || ""),
      uid: String(socialProfile.uid || userId),
      email: String(socialProfile.email || user?.email || "").trim().toLowerCase(),
      name: String(socialProfile.name || "")
    }, "User"),
    metrics: {
      totalTasksLogged: Number(socialProfile?.metrics?.totalTasksLogged) || 0,
      completedTasks: Number(socialProfile?.metrics?.completedTasks) || 0,
      tasksToday: Number(socialProfile?.metrics?.tasksToday) || 0,
      waterToday: Number(socialProfile?.metrics?.waterToday) || 0,
      sleepToday: Number(socialProfile?.metrics?.sleepToday) || 0,
      moodToday: String(socialProfile?.metrics?.moodToday || ""),
      gratitudeToday: Number(socialProfile?.metrics?.gratitudeToday) || 0,
      dailyChallengeCompletedToday: Number(socialProfile?.metrics?.dailyChallengeCompletedToday) || 0,
      wellnessScoreToday: Number(socialProfile?.metrics?.wellnessScoreToday) || 0,
      avgWaterDaily: Number(socialProfile?.metrics?.avgWaterDaily) || 0,
      avgSleepHours: Number(socialProfile?.metrics?.avgSleepHours) || 0,
      avgMoodToday: Number(socialProfile?.metrics?.avgMoodToday) || 0,
      avgMoodScore: Number(socialProfile?.metrics?.avgMoodScore) || 0,
      avgMoodLabel: String(socialProfile?.metrics?.avgMoodLabel || "Not enough data"),
      avgTasksCompletedDaily: Number(socialProfile?.metrics?.avgTasksCompletedDaily) || 0,
      sampleDays: Number(socialProfile?.metrics?.sampleDays) || 0
    },
    generatedAtMs: Number(socialProfile.generatedAtMs) || Date.now(),
    updatedAtMs: Date.now()
  };

  try {
    const [fromSnap, toSnap, toEmailSnap] = await Promise.all([
      getDocs(query(collection(db, "friendRequestsQueue"), where("fromUid", "==", userId))),
      getDocs(query(collection(db, "friendRequestsQueue"), where("toUid", "==", userId))),
      userEmail
        ? getDocs(query(collection(db, "friendRequestsQueue"), where("toEmail", "==", userEmail)))
        : Promise.resolve({ docs: [] })
    ]);

    const updates = [];
    fromSnap.docs.forEach((docSnap) => {
      updates.push(setDoc(docSnap.ref, {
        fromName: safeProfile.name,
        fromUsername: safeProfile.username,
        fromDisplayName: safeProfile.displayName || safeProfile.name,
        fromProfile: safeProfile,
        updatedAt: serverTimestamp()
      }, { merge: true }).catch(() => {}));
    });
    toSnap.docs.forEach((docSnap) => {
      updates.push(setDoc(docSnap.ref, {
        toName: safeProfile.name,
        toUsername: safeProfile.username,
        toDisplayName: safeProfile.displayName || safeProfile.name,
        toProfile: safeProfile,
        updatedAt: serverTimestamp()
      }, { merge: true }).catch(() => {}));
    });
    toEmailSnap.docs.forEach((docSnap) => {
      updates.push(setDoc(docSnap.ref, {
        toName: safeProfile.name,
        toUsername: safeProfile.username,
        toDisplayName: safeProfile.displayName || safeProfile.name,
        toProfile: safeProfile,
        updatedAt: serverTimestamp()
      }, { merge: true }).catch(() => {}));
    });

    await Promise.all(updates);
  } catch (_) {}
}

async function syncSocialProfileToFriendsMirror(user, socialProfile) {
  const userId = String(user?.uid || "").trim();
  const userEmail = String(user?.email || "").trim().toLowerCase();
  if (!userId || !socialProfile || typeof socialProfile !== "object") return;

  const safeProfile = {
    uid: String(socialProfile.uid || userId),
    email: String(socialProfile.email || user?.email || "").trim().toLowerCase(),
    username: getNormalizedUsernameIdentity(socialProfile.username || socialProfile.name, String(socialProfile.email || user?.email || "").trim().toLowerCase()),
    displayName: normalizeDisplayNameValue(socialProfile.displayName || socialProfile.name),
    name: getFriendDisplayName({
      displayName: String(socialProfile.displayName || ""),
      uid: String(socialProfile.uid || userId),
      email: String(socialProfile.email || user?.email || "").trim().toLowerCase(),
      name: String(socialProfile.name || "")
    }, "User"),
    metrics: {
      totalTasksLogged: Number(socialProfile?.metrics?.totalTasksLogged) || 0,
      completedTasks: Number(socialProfile?.metrics?.completedTasks) || 0,
      tasksToday: Number(socialProfile?.metrics?.tasksToday) || 0,
      waterToday: Number(socialProfile?.metrics?.waterToday) || 0,
      sleepToday: Number(socialProfile?.metrics?.sleepToday) || 0,
      moodToday: String(socialProfile?.metrics?.moodToday || ""),
      gratitudeToday: Number(socialProfile?.metrics?.gratitudeToday) || 0,
      dailyChallengeCompletedToday: Number(socialProfile?.metrics?.dailyChallengeCompletedToday) || 0,
      wellnessScoreToday: Number(socialProfile?.metrics?.wellnessScoreToday) || 0,
      avgWaterDaily: Number(socialProfile?.metrics?.avgWaterDaily) || 0,
      avgSleepHours: Number(socialProfile?.metrics?.avgSleepHours) || 0,
      avgMoodToday: Number(socialProfile?.metrics?.avgMoodToday) || 0,
      avgMoodScore: Number(socialProfile?.metrics?.avgMoodScore) || 0,
      avgMoodLabel: String(socialProfile?.metrics?.avgMoodLabel || "Not enough data"),
      avgTasksCompletedDaily: Number(socialProfile?.metrics?.avgTasksCompletedDaily) || 0,
      sampleDays: Number(socialProfile?.metrics?.sampleDays) || 0
    },
    generatedAtMs: Number(socialProfile.generatedAtMs) || Date.now(),
    updatedAtMs: Date.now()
  };

  try {
    const friendsSnap = await getDocs(collection(db, "users", userId, "friends"));
    const updates = [];
    friendsSnap.docs.forEach((docSnap) => {
      const data = docSnap.data() || {};
      const friendUid = String(data.friendUid || docSnap.id || "").trim();
      const status = String(data.status || "accepted").trim().toLowerCase();
      if (!friendUid || status !== "accepted") return;

      updates.push(setDoc(doc(db, "users", friendUid, "friends", userId), {
        friendUid: userId,
        friendEmail: userEmail,
        friendName: safeProfile.name,
        friendUsername: safeProfile.username,
        friendDisplayName: safeProfile.displayName || safeProfile.name,
        status: "accepted",
        sharedProfile: safeProfile,
        updatedAt: serverTimestamp()
      }, { merge: true }).catch(() => {}));
    });

    await Promise.all(updates);
  } catch (_) {}
}

async function forceSyncFriendProfileFromLocalSnapshot(user) {
  const userId = String(user?.uid || "").trim();
  if (!userId) return;

  const socialProfile = buildUserSocialProfileSnapshot(user);
  if (!socialProfile || typeof socialProfile !== "object") return;

  try {
    await Promise.allSettled([
      setDoc(doc(db, "users", userId, "social", "profile"), {
        ...socialProfile,
        updatedAt: serverTimestamp()
      }, { merge: true }),
      syncSocialProfileToFriendQueue(user, socialProfile),
      syncSocialProfileToFriendsMirror(user, socialProfile)
    ]);
    lastFriendQueueProfileSyncAt = Date.now();
  } catch (_) {}
}

async function syncFriendProfileSnapshotNow(user, socialProfile) {
  if (!user || !socialProfile || typeof socialProfile !== "object") return;
  lastFriendQueueProfileSyncAt = Date.now();
  await Promise.allSettled([
    syncSocialProfileToFriendQueue(user, socialProfile),
    syncSocialProfileToFriendsMirror(user, socialProfile)
  ]);
}

function queueFriendProfileSnapshotSync(user, socialProfile) {
  if (!user || !socialProfile || typeof socialProfile !== "object") return;
  pendingFriendProfileSnapshot = socialProfile;

  const nowMs = Date.now();
  const waitMs = Math.max(0, 12000 - (nowMs - lastFriendQueueProfileSyncAt));

  if (pendingFriendProfileSyncTimer) {
    clearTimeout(pendingFriendProfileSyncTimer);
    pendingFriendProfileSyncTimer = null;
  }

  if (waitMs === 0) {
    const snapshotToSync = pendingFriendProfileSnapshot;
    pendingFriendProfileSnapshot = null;
    void syncFriendProfileSnapshotNow(user, snapshotToSync);
    return;
  }

  pendingFriendProfileSyncTimer = setTimeout(() => {
    pendingFriendProfileSyncTimer = null;
    const snapshotToSync = pendingFriendProfileSnapshot;
    pendingFriendProfileSnapshot = null;
    if (!snapshotToSync) return;
    void syncFriendProfileSnapshotNow(user, snapshotToSync);
  }, waitMs);
}

function queueInsightsPersist(payload) {
  if (insightsPersistTimer) clearTimeout(insightsPersistTimer);
  insightsPersistTimer = setTimeout(async () => {
    const user = auth.currentUser;
    if (!user) return;
    try {
      if (payload?.barGraphs) {
        persistedBarGraphs = payload.barGraphs;
      }
      if (payload?.patternMemory) {
        persistedBehaviorPatterns = payload.patternMemory;
      }

      await setDoc(doc(db, "users", user.uid, "insights", "current"), {
        ...payload,
        updatedAt: serverTimestamp()
      }, { merge: true });

      if (payload?.barGraphs) {
        await setDoc(doc(db, "users", user.uid, "insights", "barGraphs"), {
          ...payload.barGraphs,
          updatedAt: serverTimestamp()
        }, { merge: true });
      }

      if (payload?.socialProfile) {
        await setDoc(doc(db, "users", user.uid, "social", "profile"), {
          ...payload.socialProfile,
          updatedAt: serverTimestamp()
        }, { merge: true });
        queueFriendProfileSnapshotSync(user, payload.socialProfile);
      }
    } catch (err) {
      notifyFirestoreError(err);
    }
  }, 350);
}

async function loadPersistedBarGraphs(userId) {
  if (!userId) return;

  try {
    const barGraphsSnap = await fsGetDoc(doc(db, "users", userId, "insights", "barGraphs"), 'barGraphs');
    if (barGraphsSnap.exists) {
      persistedBarGraphs = barGraphsSnap.data || null;
    } else {
      persistedBarGraphs = null;
    }

    const currentSnap = await fsGetDoc(doc(db, "users", userId, "insights", "current"), 'current');
    const currentData = currentSnap.exists ? currentSnap.data : null;
    if (!persistedBarGraphs) persistedBarGraphs = currentData?.barGraphs || null;
    persistedBehaviorPatterns = currentData?.patternMemory || null;
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function getTodayKey() {
  const now = getServerNowDate();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const day = String(now.getUTCDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function getTodayKeyGMT() {
  return getTodayKey();
}

function getServerNowDate() {
  return new Date(Date.now() + serverTimeOffsetMs);
}

async function syncServerClock(userId) {
  if (!userId) return;

  try {
    const clockRef = doc(db, "users", userId, "settings", "timeSync");
    const clientNow = Date.now();
    await setDoc(clockRef, {
      clientNow,
      serverNow: serverTimestamp(),
      updatedAt: serverTimestamp()
    }, { merge: true });

    const snapshot = await fsGetDoc(clockRef, 'timeSync');
    if (!snapshot.exists) return;
    const data = snapshot.data || {};
    const serverNowDate = toDateSafe(data.serverNow);
    const clientNowAtWrite = Number(data.clientNow) || clientNow;
    if (!serverNowDate) return;

    serverTimeOffsetMs = serverNowDate.getTime() - clientNowAtWrite;
    serverTimeSyncedAt = Date.now();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function ensureServerClockCurrent(userId) {
  if (!serverTimeSyncedAt || (Date.now() - serverTimeSyncedAt) > SERVER_CLOCK_RESYNC_MS) {
    await syncServerClock(userId);
  }
}

async function saveAiUsage(userId) {
  try {
    await setDoc(doc(db, "users", userId, "settings", "aiUsage"), {
      dateKeyLocal: aiUsageDateKeyGMT,
      dateKeyGMT: aiUsageDateKeyGMT,
      count: aiUsageCount,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function saveDailyUsage(userId) {
  try {
    await setDoc(doc(db, "users", userId, "settings", "dailyUsage"), {
      dateKey: dailyUsageDateKey,
      moodCount: Number(moodDailyUsageCount) || 0,
      taskCount: Number(taskDailyUsageCount) || 0,
      sleepCount: Number(sleepDailyUsageCount) || 0,
      waterCount: Number(waterDailyUsageCount) || 0,
      reminderCount: Number(reminderDailyUsageCount) || 0,
      gratitudeCount: Number(gratitudeDailyUsageCount) || 0,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadDailyUsage(userId) {
  dailyUsageLoaded = false;
  dailyUsageDateKey = getTodayKey();
  moodDailyUsageCount = 0;
  taskDailyUsageCount = 0;
  sleepDailyUsageCount = 0;
  waterDailyUsageCount = 0;
  reminderDailyUsageCount = 0;
  gratitudeDailyUsageCount = 0;

  try {
    const res = await fsGetDoc(doc(db, "users", userId, "settings", "dailyUsage"), 'dailyUsage');
    if (res.exists) {
      const data = res.data || {};
      if (data.dateKey === dailyUsageDateKey) {
        moodDailyUsageCount = Number(data.moodCount) || 0;
        taskDailyUsageCount = Number(data.taskCount) || 0;
        sleepDailyUsageCount = Number(data.sleepCount) || 0;
        waterDailyUsageCount = Number(data.waterCount) || 0;
        reminderDailyUsageCount = Number(data.reminderCount) || 0;
        gratitudeDailyUsageCount = Number(data.gratitudeCount) || 0;
      } else {
        await saveDailyUsage(userId);
      }
    } else {
      await saveDailyUsage(userId);
    }
  } catch (err) {
    notifyFirestoreError(err);
  } finally {
    dailyUsageLoaded = true;
    updateMoodLimitUI();
    updateTaskLimitUI();
    updateSleepLimitUI();
    updateWaterLimitUI();
    updateGratitudeLimitUI();
    await updateReminderLimitUI(userId);
  }
}

async function ensureDailyUsageCurrent(userId, options = {}) {
  await ensureServerClockCurrent(userId);

  if (!dailyUsageLoaded) {
    await loadDailyUsage(userId);
  }

  const todayKey = getTodayKey();
  if (dailyUsageDateKey !== todayKey) {
    dailyUsageDateKey = todayKey;
    moodDailyUsageCount = 0;
    taskDailyUsageCount = 0;
    sleepDailyUsageCount = 0;
    waterDailyUsageCount = 0;
    reminderDailyUsageCount = 0;
    gratitudeDailyUsageCount = 0;
    await saveDailyUsage(userId);
  }

  updateMoodLimitUI();
  updateTaskLimitUI();
  updateSleepLimitUI();
  updateWaterLimitUI();
  updateGratitudeLimitUI();
  if (!options.skipReminderRefresh) {
    await updateReminderLimitUI(userId);
  }
}

async function ensureWaterDayCurrent(userId, todayKey = getTodayKey()) {
  if (!userId) return;

  try {
    const waterRef = doc(db, "users", userId, "settings", "water");
    const waterSettingsSnap = await fsGetDoc(waterRef, 'water');

    if (!waterSettingsSnap.exists) {
      await setDoc(waterRef, {
        goal: 0,
        goalDateKey: todayKey,
        lastResetDateKey: todayKey
      }, { merge: true });
      return;
    }

    const settings = waterSettingsSnap.data || {};
    const savedGoal = Number(settings.goal) || 0;
    const goalDateKey = String(settings.goalDateKey || "");
    const lastResetDateKey = String(settings.lastResetDateKey || "");

    let shouldReset = false;
    if (lastResetDateKey && lastResetDateKey !== todayKey) {
      shouldReset = true;
    }
    if (!shouldReset && savedGoal > 0 && goalDateKey && goalDateKey !== todayKey) {
      shouldReset = true;
    }

    if (shouldReset) {
      await resetWaterDayData(userId, todayKey);
      return;
    }

    const patch = {};
    if (!goalDateKey) patch.goalDateKey = todayKey;
    if (!lastResetDateKey) patch.lastResetDateKey = todayKey;
    if (Object.keys(patch).length) {
      await setDoc(waterRef, patch, { merge: true });
    }
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function ensureDailyChallengeCurrent(userId, todayKey = getTodayKey()) {
  if (!userId) return;

  const activeBeforeRead = auth.currentUser;
  if (!activeBeforeRead || activeBeforeRead.uid !== userId) return;

  try {
    const challengeRef = doc(db, "users", userId, "settings", "dailyChallenge");
    const challengeSnap = await fsGetDoc(challengeRef, 'dailyChallenge');

    const activeBeforeWrite = auth.currentUser;
    if (!activeBeforeWrite || activeBeforeWrite.uid !== userId) return;

    const currentDateKey = String(challengeSnap.data?.dateKey || "");
    if (currentDateKey === todayKey) return;

    await safeSetDoc(challengeRef, {
      challenge: pickChallengeForDate(todayKey),
      completed: false,
      dateKey: todayKey,
      timeZone: userTimeZone,
      updatedAt: serverTimestamp()
    }, 'dailyChallenge', { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function ensureDateBoundResetCatchup(userId) {
  if (!userId) return;

  await ensureDailyUsageCurrent(userId, { skipReminderRefresh: true });
  await Promise.allSettled([
    ensureWaterDayCurrent(userId),
    ensureDailyChallengeCurrent(userId)
  ]);
}

async function loadAiUsage(userId) {
  aiUsageStateLoaded = false;
  aiUsageDateKeyGMT = getTodayKeyGMT();
  aiUsageCount = 0;

  try {
    const res = await fsGetDoc(doc(db, "users", userId, "settings", "aiUsage"), 'aiUsage');
    if (res.exists) {
      const data = res.data || {};
      const storedDayKey = data.dateKeyLocal || data.dateKeyGMT || "";
      if (storedDayKey === aiUsageDateKeyGMT) {
        aiUsageCount = Number(data.count) || 0;
      } else {
        aiUsageCount = 0;
        await saveAiUsage(userId);
      }
    } else {
      await saveAiUsage(userId);
    }
  } catch (err) {
    notifyFirestoreError(err);
  } finally {
    aiUsageStateLoaded = true;
    updateAiLimitUI();
  }
}

async function ensureAiUsageCurrent(userId) {
  await ensureServerClockCurrent(userId);

  if (!aiUsageStateLoaded) {
    await loadAiUsage(userId);
  }

  const todayKeyGMT = getTodayKeyGMT();
  if (aiUsageDateKeyGMT !== todayKeyGMT) {
    aiUsageDateKeyGMT = todayKeyGMT;
    aiUsageCount = 0;
    await saveAiUsage(userId);
  }
  updateAiLimitUI();
}

function getDailyUsageCountersFromRaw(rawData = {}, todayKey = getTodayKey()) {
  const sameDay = String(rawData?.dateKey || "") === todayKey;
  return {
    dateKey: todayKey,
    moodCount: sameDay ? Math.max(0, Number(rawData?.moodCount) || 0) : 0,
    taskCount: sameDay ? Math.max(0, Number(rawData?.taskCount) || 0) : 0,
    sleepCount: sameDay ? Math.max(0, Number(rawData?.sleepCount) || 0) : 0,
    waterCount: sameDay ? Math.max(0, Number(rawData?.waterCount) || 0) : 0,
    reminderCount: sameDay ? Math.max(0, Number(rawData?.reminderCount) || 0) : 0,
    gratitudeCount: sameDay ? Math.max(0, Number(rawData?.gratitudeCount) || 0) : 0
  };
}

function syncDailyUsageLocalsFromCounters(counters) {
  dailyUsageDateKey = String(counters?.dateKey || getTodayKey());
  moodDailyUsageCount = Math.max(0, Number(counters?.moodCount) || 0);
  taskDailyUsageCount = Math.max(0, Number(counters?.taskCount) || 0);
  sleepDailyUsageCount = Math.max(0, Number(counters?.sleepCount) || 0);
  waterDailyUsageCount = Math.max(0, Number(counters?.waterCount) || 0);
  reminderDailyUsageCount = Math.max(0, Number(counters?.reminderCount) || 0);
  gratitudeDailyUsageCount = Math.max(0, Number(counters?.gratitudeCount) || 0);
  dailyUsageLoaded = true;
}

async function reserveDailyQuota(userId, quotaField, limit) {
  if (!userId || !quotaField || !Number.isFinite(limit)) {
    return { ok: false, count: 0 };
  }

  const todayKey = getTodayKey();
  const usageRef = doc(db, "users", userId, "settings", "dailyUsage");

  try {
    const result = await runTransaction(db, async (transaction) => {
      const snapshot = await transaction.get(usageRef);
      const counters = getDailyUsageCountersFromRaw(snapshot.exists() ? snapshot.data() : {}, todayKey);
      const current = Math.max(0, Number(counters[quotaField]) || 0);
      if (current >= limit) {
        return { ok: false, counters, count: current };
      }

      counters[quotaField] = current + 1;
      transaction.set(usageRef, {
        ...counters,
        updatedAt: serverTimestamp()
      }, { merge: true });

      return { ok: true, counters, count: counters[quotaField] };
    });

    if (result?.counters) syncDailyUsageLocalsFromCounters(result.counters);
    return result || { ok: false, count: 0 };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, count: 0, error: err };
  }
}

async function rollbackDailyQuota(userId, quotaField) {
  if (!userId || !quotaField) return;

  const todayKey = getTodayKey();
  const usageRef = doc(db, "users", userId, "settings", "dailyUsage");

  try {
    const result = await runTransaction(db, async (transaction) => {
      const snapshot = await transaction.get(usageRef);
      if (!snapshot.exists()) return null;

      const counters = getDailyUsageCountersFromRaw(snapshot.data(), todayKey);
      const current = Math.max(0, Number(counters[quotaField]) || 0);
      if (current <= 0) return counters;

      counters[quotaField] = current - 1;
      transaction.set(usageRef, {
        ...counters,
        updatedAt: serverTimestamp()
      }, { merge: true });

      return counters;
    });

    if (result) syncDailyUsageLocalsFromCounters(result);
  } catch (_) {}
}

async function reserveAiQuota(userId, limit) {
  if (!userId || !Number.isFinite(limit)) return { ok: false, count: 0 };

  const todayKey = getTodayKeyGMT();
  const usageRef = doc(db, "users", userId, "settings", "aiUsage");

  try {
    const result = await runTransaction(db, async (transaction) => {
      const snapshot = await transaction.get(usageRef);
      const data = snapshot.exists() ? (snapshot.data() || {}) : {};
      const storedDayKey = String(data.dateKeyLocal || data.dateKeyGMT || "");
      let count = storedDayKey === todayKey ? Math.max(0, Number(data.count) || 0) : 0;

      if (count >= limit) {
        return { ok: false, count };
      }

      count += 1;
      transaction.set(usageRef, {
        dateKeyLocal: todayKey,
        dateKeyGMT: todayKey,
        count,
        updatedAt: serverTimestamp()
      }, { merge: true });

      return { ok: true, count };
    });

    if (result) {
      aiUsageDateKeyGMT = todayKey;
      aiUsageCount = Math.max(0, Number(result.count) || 0);
      aiUsageStateLoaded = true;
      updateAiLimitUI();
    }

    return result || { ok: false, count: 0 };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, count: 0, error: err };
  }
}

async function rollbackAiQuota(userId) {
  if (!userId) return;

  const todayKey = getTodayKeyGMT();
  const usageRef = doc(db, "users", userId, "settings", "aiUsage");

  try {
    const result = await runTransaction(db, async (transaction) => {
      const snapshot = await transaction.get(usageRef);
      if (!snapshot.exists()) return null;

      const data = snapshot.data() || {};
      const storedDayKey = String(data.dateKeyLocal || data.dateKeyGMT || "");
      let count = storedDayKey === todayKey ? Math.max(0, Number(data.count) || 0) : 0;
      if (count <= 0) return { count: 0 };

      count -= 1;
      transaction.set(usageRef, {
        dateKeyLocal: todayKey,
        dateKeyGMT: todayKey,
        count,
        updatedAt: serverTimestamp()
      }, { merge: true });

      return { count };
    });

    if (result) {
      aiUsageDateKeyGMT = todayKey;
      aiUsageCount = Math.max(0, Number(result.count) || 0);
      aiUsageStateLoaded = true;
      updateAiLimitUI();
    }
  } catch (_) {}
}

function startDailyChallengeWatcher() {
  if (challengeWatcherInterval) clearInterval(challengeWatcherInterval);
  challengeWatcherInterval = setInterval(async () => {
    const user = auth.currentUser;
    if (!user) return;
    const todayKey = getTodayKey();
    if (todayKey !== currentChallengeDateKey) {
      await loadDailyChallenge(user.uid);
    }
  }, 30000);
}

function stopDailyChallengeWatcher() {
  if (challengeWatcherInterval) {
    clearInterval(challengeWatcherInterval);
    challengeWatcherInterval = null;
  }
}

function startFriendInsightsWatcher(userId) {
  stopFriendInsightsWatcher();
  const targetUid = String(userId || "").trim();
  if (!targetUid) return;

  const queueRealtimeRefresh = () => {
    if (friendRealtimeRefreshTimerId) {
      clearTimeout(friendRealtimeRefreshTimerId);
      friendRealtimeRefreshTimerId = null;
    }

    friendRealtimeRefreshTimerId = setTimeout(async () => {
      friendRealtimeRefreshTimerId = null;
      const activeUser = auth.currentUser;
      if (!activeUser || activeUser.uid !== targetUid) {
        stopFriendInsightsWatcher();
        return;
      }

      if (friendRealtimeRefreshInFlight) {
        friendRealtimeRefreshQueued = true;
        return;
      }

      friendRealtimeRefreshInFlight = true;
      try {
        await Promise.all([
          loadFriendRequests(targetUid),
          loadSentFriendRequests(targetUid),
          loadFriendsInsights(targetUid)
        ]);
      } finally {
        friendRealtimeRefreshInFlight = false;
        if (friendRealtimeRefreshQueued) {
          friendRealtimeRefreshQueued = false;
          queueRealtimeRefresh();
        }
      }
    }, 220);
  };

  const queueRef = collection(db, "friendRequestsQueue");
  const activeEmail = String(auth.currentUser?.email || "").trim().toLowerCase();

  friendRealtimeUnsubscribers.push(
    onSnapshot(collection(db, "users", targetUid, "friendRequests"), queueRealtimeRefresh),
    onSnapshot(collection(db, "users", targetUid, "friendRequestsSent"), queueRealtimeRefresh),
    onSnapshot(collection(db, "users", targetUid, "friends"), queueRealtimeRefresh),
    onSnapshot(query(queueRef, where("toUid", "==", targetUid)), queueRealtimeRefresh),
    onSnapshot(query(queueRef, where("fromUid", "==", targetUid)), queueRealtimeRefresh)
  );

  if (activeEmail) {
    friendRealtimeUnsubscribers.push(
      onSnapshot(query(queueRef, where("toEmail", "==", activeEmail)), queueRealtimeRefresh)
    );
  }

  queueRealtimeRefresh();

  friendInsightsWatcherIntervalId = setInterval(async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== targetUid) {
      stopFriendInsightsWatcher();
      return;
    }
    queueRealtimeRefresh();
  }, 30000);
}

function stopFriendInsightsWatcher() {
  if (friendRealtimeRefreshTimerId) {
    clearTimeout(friendRealtimeRefreshTimerId);
    friendRealtimeRefreshTimerId = null;
  }
  friendRealtimeRefreshInFlight = false;
  friendRealtimeRefreshQueued = false;
  if (friendRealtimeUnsubscribers.length) {
    friendRealtimeUnsubscribers.forEach((unsubscribe) => {
      try {
        if (typeof unsubscribe === "function") unsubscribe();
      } catch (_) {}
    });
    friendRealtimeUnsubscribers = [];
  }
  if (friendInsightsWatcherIntervalId) {
    clearInterval(friendInsightsWatcherIntervalId);
    friendInsightsWatcherIntervalId = null;
  }
}

function clearDailyQuestResetSchedule() {
  if (dailyQuestResetTimeoutId) {
    clearTimeout(dailyQuestResetTimeoutId);
    dailyQuestResetTimeoutId = null;
  }
}

function clearDailySystemResetSchedule() {
  if (dailySystemResetTimeoutId) {
    clearTimeout(dailySystemResetTimeoutId);
    dailySystemResetTimeoutId = null;
  }
  if (dailySystemResetWatcherIntervalId) {
    clearInterval(dailySystemResetWatcherIntervalId);
    dailySystemResetWatcherIntervalId = null;
  }
  dailySystemResetInFlight = false;
}

function scheduleDailyQuestReset(userId) {
  clearDailyQuestResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleDailyQuestReset(userId);
      return;
    }

    await loadHabitQuest(userId);
    scheduleDailyQuestReset(userId);
  };

  dailyQuestResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
}

async function runDailySystemReset(userId, options = {}) {
  if (!userId || dailySystemResetInFlight) return;
  dailySystemResetInFlight = true;
  try {
    await ensureServerClockCurrent(userId);
    const todayKey = getTodayKey();
    if (!options.force && dailySystemResetKey === todayKey) return;
    dailySystemResetKey = todayKey;
    clearCrashAlertDismissal(userId);

    await Promise.allSettled([
      ensureDailyUsageCurrent(userId),
      ensureAiUsageCurrent(userId),
      ensureWaterDayCurrent(userId, todayKey),
      ensureDailyChallengeCurrent(userId, todayKey)
    ]);

    await Promise.allSettled([
      loadMoods(userId),
      loadSleepData(userId),
      loadWaterData(userId),
      loadGratitude(userId)
    ]);

    updateWellnessScore();
    updateCrashPreventionUI();
    updateInsights();
  } finally {
    dailySystemResetInFlight = false;
  }
}

async function scheduleDailySystemReset(userId) {
  clearDailySystemResetSchedule();
  if (!userId) return;

  await ensureServerClockCurrent(userId);
  dailySystemResetKey = getTodayKey();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleDailySystemReset(userId);
      return;
    }

    await runDailySystemReset(userId, { force: true });
    scheduleDailySystemReset(userId);
  };

  dailySystemResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
  dailySystemResetWatcherIntervalId = setInterval(() => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) return;
    void runDailySystemReset(userId);
  }, 60000);
}

function clearDailyChallengeResetSchedule() {
  if (dailyChallengeResetTimeoutId) {
    clearTimeout(dailyChallengeResetTimeoutId);
    dailyChallengeResetTimeoutId = null;
  }
}

function scheduleDailyChallengeReset(userId) {
  clearDailyChallengeResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleDailyChallengeReset(userId);
      return;
    }

    await loadDailyChallenge(userId);
    scheduleDailyChallengeReset(userId);
  };

  dailyChallengeResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
}

function clearWaterGoalResetSchedule() {
  if (waterGoalResetTimeoutId) {
    clearTimeout(waterGoalResetTimeoutId);
    waterGoalResetTimeoutId = null;
  }
}

function clearSleepDailyResetSchedule() {
  if (sleepDailyResetTimeoutId) {
    clearTimeout(sleepDailyResetTimeoutId);
    sleepDailyResetTimeoutId = null;
  }
}

function clearMoodDailyResetSchedule() {
  if (moodDailyResetTimeoutId) {
    clearTimeout(moodDailyResetTimeoutId);
    moodDailyResetTimeoutId = null;
  }
}

function getMillisecondsUntilNextMidnight() {
  const now = getServerNowDate();
  const nextMidnight = new Date(now);
  nextMidnight.setUTCHours(24, 0, 0, 0);
  return Math.max(1, nextMidnight.getTime() - now.getTime());
}

function getMillisecondsUntilNextSundayMidnight() {
  const now = getServerNowDate();
  const nextSunday = new Date(now);
  nextSunday.setUTCHours(0, 0, 0, 0);
  const day = nextSunday.getUTCDay();
  const daysUntilSunday = day === 0 ? 7 : (7 - day);
  nextSunday.setUTCDate(nextSunday.getUTCDate() + daysUntilSunday);
  return Math.max(1, nextSunday.getTime() - now.getTime());
}

function formatWeeklyResetCountdown(milliseconds) {
  const safeMs = Math.max(0, Number(milliseconds) || 0);
  const totalSeconds = Math.floor(safeMs / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (safeMs >= 86400000) {
    return `${days}d ${String(hours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m`;
  }
  const totalHours = Math.floor(totalSeconds / 3600);
  return `${String(totalHours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s`;
}

function updateWeeklyGraphResetCountdownNote() {
  if (!insightWeeklyResetCountdown) return;
  const remaining = getMillisecondsUntilNextSundayMidnight();
  insightWeeklyResetCountdown.innerText = `Weekly bar graph reset in ${formatWeeklyResetCountdown(remaining)}`;
}

function updateStartupResetCountdownNotes() {
  if (waterGoalResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    waterGoalResetCountdown.innerText = `Water + goal reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (sleepResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    sleepResetCountdown.innerText = `Sleep reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (moodResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    moodResetCountdown.innerText = `Mood reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (gratitudeResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    gratitudeResetCountdown.innerText = `Gratitude reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (dailyChallengeResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    dailyChallengeResetCountdown.innerText = `Daily challenge reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (wellnessScoreResetCountdown) {
    const dailyRemaining = getMillisecondsUntilNextMidnight();
    wellnessScoreResetCountdown.innerText = `Daily wellness score reset in ${formatCountdownClock(dailyRemaining)}`;
  }

  if (startupPlanResetCountdown) {
    const planLimited = (Number(startupUsageState?.planCount) || 0) >= STARTUP_PLAN_DAILY_LIMIT;
    if (planLimited) {
      const dailyRemaining = getMillisecondsUntilNextMidnight();
      startupPlanResetCountdown.innerText = `Daily planner reset in ${formatCountdownClock(dailyRemaining)}`;
    } else {
      startupPlanResetCountdown.innerText = "";
    }
  }
  if (startupReportResetCountdown) {
    const reportLimited = (Number(startupUsageState?.reportCount) || 0) >= STARTUP_REPORT_WEEKLY_LIMIT;
    if (reportLimited) {
      const weeklyRemaining = getMillisecondsUntilNextSundayMidnight();
      startupReportResetCountdown.innerText = `Weekly report reset in ${formatWeeklyResetCountdown(weeklyRemaining)}`;
    } else {
      startupReportResetCountdown.innerText = "";
    }
  }
}

function startStartupResetCountdown() {
  stopStartupResetCountdown();
  updateStartupResetCountdownNotes();
  startupResetCountdownIntervalId = setInterval(updateStartupResetCountdownNotes, 1000);
}

function stopStartupResetCountdown() {
  if (startupResetCountdownIntervalId) {
    clearInterval(startupResetCountdownIntervalId);
    startupResetCountdownIntervalId = null;
  }
  if (waterGoalResetCountdown) waterGoalResetCountdown.innerText = "";
  if (sleepResetCountdown) sleepResetCountdown.innerText = "";
  if (moodResetCountdown) moodResetCountdown.innerText = "";
  if (gratitudeResetCountdown) gratitudeResetCountdown.innerText = "";
  if (dailyChallengeResetCountdown) dailyChallengeResetCountdown.innerText = "";
  if (wellnessScoreResetCountdown) wellnessScoreResetCountdown.innerText = "";
  if (startupPlanResetCountdown) startupPlanResetCountdown.innerText = "";
  if (startupReportResetCountdown) startupReportResetCountdown.innerText = "";
}

function startWeeklyGraphResetCountdown() {
  stopWeeklyGraphResetCountdown();
  updateWeeklyGraphResetCountdownNote();
  weeklyGraphCountdownIntervalId = setInterval(updateWeeklyGraphResetCountdownNote, 1000);
}

function stopWeeklyGraphResetCountdown() {
  if (weeklyGraphCountdownIntervalId) {
    clearInterval(weeklyGraphCountdownIntervalId);
    weeklyGraphCountdownIntervalId = null;
  }
  if (insightWeeklyResetCountdown) {
    insightWeeklyResetCountdown.innerText = "";
  }
}

function clearWeeklyGraphResetSchedule() {
  if (weeklyGraphResetTimeoutId) {
    clearTimeout(weeklyGraphResetTimeoutId);
    weeklyGraphResetTimeoutId = null;
  }
}

async function resetWeeklyBarGraphData(userId) {
  const weekRange = getCurrentWeekRangeKeys();
  const labels = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const zeroBarGraphs = {
    weekStartKey: weekRange.weekStartKey,
    weekEndKey: weekRange.weekEndKey,
    labels,
    tasks: { values: [0, 0, 0, 0, 0, 0, 0], maxValue: 100 },
    sleep: { values: [0, 0, 0, 0, 0, 0, 0], maxValue: 12 },
    water: { values: [0, 0, 0, 0, 0, 0, 0], maxValue: 8 },
    mood: { values: [0, 0, 0, 0, 0, 0, 0], maxValue: 3 }
  };

  persistedBarGraphs = zeroBarGraphs;

  try {
    await Promise.all([
      setDoc(doc(db, "users", userId, "insights", "barGraphs"), {
        ...zeroBarGraphs,
        updatedAt: serverTimestamp()
      }, { merge: true }),
      setDoc(doc(db, "users", userId, "insights", "current"), {
        barGraphs: zeroBarGraphs,
        updatedAt: serverTimestamp()
      }, { merge: true })
    ]);
  } catch (err) {
    notifyFirestoreError(err);
  }

  updateInsights();
}

function scheduleWeeklyGraphReset(userId) {
  clearWeeklyGraphResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleWeeklyGraphReset(userId);
      return;
    }

    await resetWeeklyBarGraphData(userId);
    scheduleWeeklyGraphReset(userId);
  };

  weeklyGraphResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextSundayMidnight());
}

async function resetWaterDayData(userId, dateKey = getTodayKey()) {
  try {
    await setDoc(doc(db, "users", userId, "settings", "water"), {
      goal: 0,
      goalDateKey: dateKey,
      lastResetDateKey: dateKey
    }, { merge: true });

    const activeUser = auth.currentUser;
    if (activeUser && activeUser.uid === userId) {
      waterHistory.length = 0;
      waterDates.length = 0;
      waterGoal = 0;
      waterGoalInput.value = "";
      waterInput.value = "";
      updateWaterProgress();
      updateWaterLimitUI();
      updateWaterClearButtonState();
    }
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function scheduleWaterGoalReset(userId) {
  clearWaterGoalResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleWaterGoalReset(userId);
      return;
    }

    await ensureServerClockCurrent(userId);
    await resetWaterDayData(userId, getTodayKey());

    scheduleWaterGoalReset(userId);
  };

  waterGoalResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
}

async function resetSleepDayData(userId) {
  const activeUser = auth.currentUser;
  if (!activeUser || activeUser.uid !== userId) return;
  sleepInput.value = "";
  sleepResult.innerText = "";
  await loadSleepData(userId);
}

function scheduleSleepDailyReset(userId) {
  clearSleepDailyResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleSleepDailyReset(userId);
      return;
    }

    await resetSleepDayData(userId);
    scheduleSleepDailyReset(userId);
  };

  sleepDailyResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
}

async function resetMoodDayData(userId) {
  const activeUser = auth.currentUser;
  if (!activeUser || activeUser.uid !== userId) return;
  await loadMoods(userId);
}

function scheduleMoodDailyReset(userId) {
  clearMoodDailyResetSchedule();

  const runReset = async () => {
    const activeUser = auth.currentUser;
    if (!activeUser || activeUser.uid !== userId) {
      scheduleMoodDailyReset(userId);
      return;
    }

    await resetMoodDayData(userId);
    scheduleMoodDailyReset(userId);
  };

  moodDailyResetTimeoutId = setTimeout(runReset, getMillisecondsUntilNextMidnight());
}

function updateWellnessScore() {
  const todayKey = getTodayKey();

  const waterToday = waterHistory.reduce((sum, value, index) => {
    const dateKey = dateToKey(waterDates[index]);
    return dateKey === todayKey ? sum + value : sum;
  }, 0);
  const effectiveWaterGoal = waterGoal > 0 ? waterGoal : 8;
  const hasCustomWaterGoal = waterGoal > 0;
  const waterRatio = Math.min(1, waterToday / effectiveWaterGoal);
  const waterPoints = Math.round(waterRatio * 30);

  const sleepToday = sleepHistory.reduce((lastValue, value, index) => {
    const dateKey = dateToKey(sleepDates[index]);
    return dateKey === todayKey ? value : lastValue;
  }, 0);
  const sleepRatio = Math.min(1, sleepToday / 8);
  const sleepPoints = Math.round(sleepRatio * 25);

  const moodToday = moodHistory.reduce((lastMood, value, index) => {
    const dateKey = dateToKey(moodDates[index]);
    return dateKey === todayKey ? value : lastMood;
  }, "");
  const moodMeta = getMoodStateMeta(moodToday);
  const moodFactor = Number(moodMeta.wellnessFactor) || 0;
  const moodPoints = Math.round(moodFactor * 20);

  const totalTasks = taskEntries.length;
  const doneTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const taskRatio = totalTasks ? doneTasks / totalTasks : 0;
  const taskPoints = Math.round(taskRatio * 15);

  const hasGratitudeToday = gratitudeEntries.some((entry) => dateToKey(entry.time) === todayKey);
  const gratitudePoints = hasGratitudeToday ? 10 : 0;
  const challengePoints = dailyChallengeCompleted ? 10 : 0;

  const actionBoost = Math.max(0, Number(wellnessActionBoost) || 0);
  const totalScore = Math.max(0, Math.min(100, waterPoints + sleepPoints + moodPoints + taskPoints + gratitudePoints + challengePoints + actionBoost));

  const waterGap = Math.max(0, effectiveWaterGoal - waterToday);
  const waterGapSeverity = waterGap > 0 ? Math.min(1, waterGap / Math.max(1, effectiveWaterGoal)) : 0;
  const sleepGapSeverity = sleepToday < 7 ? Math.min(1, (7 - sleepToday) / 7) : 0;
  const taskGapSeverity = taskRatio < 0.7 ? Math.min(1, 0.7 - taskRatio) : 0;
  const moodGapSeverity = !moodMeta.logged
    ? 1
    : moodMeta.label === "Angry"
      ? 0.95
      : moodMeta.label === "Stressed"
        ? 0.85
        : moodMeta.label === "Low"
          ? 0.7
          : moodMeta.label === "Neutral"
            ? 0.2
            : 0;
  const gratitudeGapSeverity = hasGratitudeToday ? 0 : 0.45;
  const challengeGapSeverity = dailyChallengeCompleted ? 0 : 0.5;
  const biggestOtherGapSeverity = Math.max(
    sleepGapSeverity,
    taskGapSeverity,
    moodGapSeverity,
    gratitudeGapSeverity,
    challengeGapSeverity
  );
  const waterIsBiggestGap = waterGapSeverity > 0 && waterGapSeverity >= biggestOtherGapSeverity;

  wellnessScoreEl.innerText = `${totalScore}/100`;

  let status = "Needs Focus";
  if (totalScore >= 80) status = "Excellent";
  else if (totalScore >= 60) status = "Good";
  wellnessStatusEl.innerText = status;
  if (wellnessReassuranceEl) {
    wellnessReassuranceEl.innerText =
      totalScore >= 80 ? "You’re on track today — protect this rhythm." :
      totalScore >= 60 ? "You’re moving well — one more check-in can lift this further." :
      "A small action now can shift your whole day upward.";
  }

  const rankedActions = [];
  const addRankedAction = (text, urgency, ease, stateFit = 0, category = text) => {
    const score = (Number(urgency) || 0) * 2 + (Number(ease) || 0) + (Number(stateFit) || 0);
    rankedActions.push({
      text,
      category,
      score,
      urgency: Number(urgency) || 0
    });
  };

  if (!moodMeta.logged) {
    addRankedAction("Log your mood right now.", 10, 10, 3, "mood");
  } else if (moodMeta.label === "Angry") {
    addRankedAction("Run a 2-minute rescue now before continuing work.", 10, 9, 4, "mood");
  } else if (moodMeta.label === "Stressed") {
    addRankedAction("Take a 2-minute breathing reset before your next task.", 9, 9, 4, "mood");
  } else if (moodMeta.label === "Low") {
    addRankedAction("Take a 10-minute walk or breathing reset now.", 8, 7, 3, "mood");
  } else if (moodMeta.label === "Neutral") {
    addRankedAction("Use one calming reset to keep your mood steady.", 4, 9, 1, "mood");
  }

  if (waterRatio < 1) {
    const remaining = Math.max(0, effectiveWaterGoal - waterToday);
    if (hasCustomWaterGoal) {
      addRankedAction(
        `Drink ${remaining} more glass${remaining === 1 ? "" : "es"} to hit your goal.`,
        waterIsBiggestGap ? (waterToday === 0 ? 8 : remaining <= 2 ? 7 : 6) : 3,
        waterIsBiggestGap ? (waterToday === 0 ? 10 : 7) : 8,
        2,
        "water"
      );
    } else {
      addRankedAction(
        waterToday === 0
          ? "Log one glass of water to start hydration."
          : "Drink one more glass of water to keep hydration moving.",
        waterIsBiggestGap ? (waterToday === 0 ? 7 : 5) : 2,
        waterIsBiggestGap ? (waterToday === 0 ? 10 : 7) : 8,
        2,
        "water"
      );
    }
  }

  if (sleepToday < 7) {
    addRankedAction(
      sleepToday > 0
        ? "Protect your sleep window tonight so tomorrow feels easier."
        : "Set tonight’s sleep target to at least 7-8 hours.",
      sleepToday <= 5 ? 8 : 6,
      5,
      1,
      "sleep"
    );
  }

  if (taskRatio < 0.7) {
    const pendingCount = Math.max(0, totalTasks - doneTasks);
    addRankedAction(
      pendingCount > 0
        ? pendingCount === 1
          ? "Complete your top pending task now."
          : `Complete one of your ${pendingCount} pending tasks now.`
        : "Add a small task so today has one clear win.",
      pendingCount >= 5 ? 8 : 6,
      7,
      2,
      "tasks"
    );
  }

  if (!hasGratitudeToday) addRankedAction("Write one gratitude note now.", 5, 9, 1, "gratitude");
  if (!dailyChallengeCompleted) addRankedAction("Complete today’s daily challenge.", 6, 6, 1, "challenge");

  if (waterToday > 0 && moodMeta.logged && !hasGratitudeToday) {
    addRankedAction("Stack a gratitude note after your last check-in.", 4, 9, 1, "gratitude");
  }

  if (moodMeta.logged && !dailyChallengeCompleted && taskRatio >= 0.7) {
    addRankedAction("Finish today’s daily challenge to lock the streak.", 5, 7, 1, "challenge");
  }

  if (!rankedActions.length) {
    addRankedAction("Protect momentum with one quick check-in now.", 6, 10, 2, "momentum");
    addRankedAction("Finish one small task before your next break.", 5, 8, 1, "tasks");
    addRankedAction("Hydrate once more to maintain your streak.", 4, 9, 1, "water");
    addRankedAction("Write one gratitude note to close the loop.", 4, 9, 1, "gratitude");
  }

  rankedActions.sort((a, b) => b.score - a.score || b.urgency - a.urgency || a.text.localeCompare(b.text));

  const uniqueActions = [];
  const seenCategories = new Set();
  rankedActions.forEach((entry) => {
    const category = String(entry.category || entry.text || "").toLowerCase();
    if (seenCategories.has(category)) return;
    seenCategories.add(category);
    uniqueActions.push(entry.text);
  });

  const fallbackActions = [
    "Take a 2-minute breathing reset.",
    "Add one gratitude note to round out today.",
    "Drink a glass of water if you’re behind.",
    "Clear one small task before your next break.",
    "Set tonight’s sleep target before you log off."
  ];

  const primaryAction = uniqueActions[0] || "Protect momentum with one quick check-in now.";
  const secondaryActions = uniqueActions.slice(1, 6);
  while (secondaryActions.length < 5) {
    const nextFallback = fallbackActions[secondaryActions.length] || "Keep your current streak alive with one small check-in.";
    if (!secondaryActions.includes(nextFallback)) secondaryActions.push(nextFallback);
    else secondaryActions.push("Keep your current streak alive with one small check-in.");
  }

  if (wellnessDoNowEl) {
    wellnessDoNowEl.innerHTML = `<b>DO NOW:</b> ${escapeHtml(primaryAction)}`;
  }
  wellnessActionsEl.innerHTML = secondaryActions
    .map((item) => `<li class="wellness-secondary-task">${escapeHtml(item)}</li>`)
    .join("");
}

function getCrashRiskSnapshot() {
  const todayKey = getTodayKey();

  const waterToday = waterHistory.reduce((sum, value, index) => {
    const dateKey = dateToKey(waterDates[index]);
    return dateKey === todayKey ? sum + value : sum;
  }, 0);
  const hasWaterLoggedToday = waterDates.some((entry) => dateToKey(entry) === todayKey);
  const hasCustomWaterGoal = Number(waterGoal) > 0;
  const effectiveWaterGoal = waterGoal > 0 ? waterGoal : 8;
  const waterRatio = Math.min(1, waterToday / effectiveWaterGoal);

  const sleepToday = sleepHistory.reduce((lastValue, value, index) => {
    const dateKey = dateToKey(sleepDates[index]);
    return dateKey === todayKey ? value : lastValue;
  }, 0);
  const hasSleepLoggedToday = sleepDates.some((entry) => dateToKey(entry) === todayKey);

  const moodToday = moodHistory.reduce((lastMood, value, index) => {
    const dateKey = dateToKey(moodDates[index]);
    return dateKey === todayKey ? value : lastMood;
  }, "");
  const moodMeta = getMoodStateMeta(moodToday);

  const totalTasks = taskEntries.length;
  const doneTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const pendingRatio = totalTasks ? Math.max(0, (totalTasks - doneTasks) / totalTasks) : 0;
  const gratitudeToday = gratitudeEntries.some((entry) => dateToKey(entry.time) === todayKey);

  let risk = 0;
  const reasons = [];

  if (!hasSleepLoggedToday) {
    risk += 8;
    reasons.push("Sleep not logged yet");
  } else if (sleepToday < 6) {
    risk += 30;
    reasons.push("Very low sleep");
  } else if (sleepToday < 7) {
    risk += 16;
    reasons.push("Sleep slightly below recovery zone");
  }

  if (!hasWaterLoggedToday) {
    risk += 6;
    reasons.push("Water not logged yet");
  } else {
    const hydrationRisk = Math.round((1 - waterRatio) * 25);
    risk += hydrationRisk;
    if (hydrationRisk >= 10) {
      reasons.push(hasCustomWaterGoal ? "Hydration below target" : "Hydration low today");
    }
  }

  if (!moodMeta.logged) {
    risk += 14;
    reasons.push("Mood not logged yet");
  } else {
    risk += Number(moodMeta.crashRisk) || 0;
    if (moodMeta.riskReason) reasons.push(moodMeta.riskReason);
  }

  const taskRisk = Math.round(pendingRatio * 20);
  risk += taskRisk;
  if (taskRisk >= 10) reasons.push("Too many pending tasks");

  if (!gratitudeToday) risk += 6;
  if (!dailyChallengeCompleted) risk += 4;

  const wellnessScore = Number((wellnessScoreEl?.innerText || "0/100").split("/")[0]) || 0;
  if (wellnessScore < 50) {
    risk += 10;
    reasons.push("Wellness score currently low");
  }

  const relief = Math.max(0, Number(crashRiskActionRelief) || 0);
  risk = Math.max(0, Math.min(100, risk - relief));
  const level = risk >= 70 ? "High Risk" : risk >= 45 ? "Medium Risk" : "Low Risk";

  return {
    risk,
    level,
    reasons,
    waterToday,
    sleepToday,
    wellnessScore
  };
}

function getCrashAlertDismissStorageKey(userId = "") {
  const safeUserId = String(userId || "").trim();
  return safeUserId ? `${CRASH_ALERT_DISMISS_STORAGE_PREFIX}${safeUserId}` : "";
}

function getCrashAlertDismissedDateKey(userId = "") {
  const safeUserId = String(userId || "").trim();
  const storageKey = getCrashAlertDismissStorageKey(safeUserId);
  if (!storageKey) return "";

  try {
    return String(localStorage.getItem(storageKey) || "");
  } catch (_) {
    return "";
  }
}

function setCrashAlertDismissedForToday(userId = "") {
  const safeUserId = String(userId || "").trim();
  const storageKey = getCrashAlertDismissStorageKey(safeUserId);
  if (!storageKey) return "";

  const todayKey = getTodayKey();
  try {
    localStorage.setItem(storageKey, todayKey);
  } catch (_) {}
  return todayKey;
}

function clearCrashAlertDismissal(userId = "") {
  const safeUserId = String(userId || "").trim();
  const storageKey = getCrashAlertDismissStorageKey(safeUserId);
  if (!storageKey) return;

  try {
    localStorage.removeItem(storageKey);
  } catch (_) {}
}

function isCrashAlertDismissedForToday(userId = "") {
  const safeUserId = String(userId || auth.currentUser?.uid || "").trim();
  if (!safeUserId) return false;

  const dismissedDateKey = getCrashAlertDismissedDateKey(safeUserId);
  if (!dismissedDateKey) return false;

  const todayKey = getTodayKey();
  if (dismissedDateKey === todayKey) return true;

  clearCrashAlertDismissal(safeUserId);
  return false;
}

async function dismissCrashAlertBanner() {
  const user = auth.currentUser;
  const userId = String(user?.uid || "").trim();
  if (!userId) {
    if (crashAlertBanner) crashAlertBanner.style.display = "none";
    return;
  }

  if (crashAlertDismissBtn) crashAlertDismissBtn.disabled = true;
  try {
    await ensureServerClockCurrent(userId);
    setCrashAlertDismissedForToday(userId);
    if (crashAlertBanner) crashAlertBanner.style.display = "none";
    showToast("Mood crash warning dismissed until tomorrow.");
  } finally {
    if (crashAlertDismissBtn) crashAlertDismissBtn.disabled = false;
  }
}

function updateCrashPreventionUI() {
  if (!crashRiskValue || !crashRiskLevel || !crashRiskReason || !crashAlertBanner || !crashBannerText) return;

  const snapshot = getCrashRiskSnapshot();
  crashRiskValue.innerText = `${snapshot.risk}/100`;
  crashRiskLevel.innerText = snapshot.level;
  if (crashRiskFill) crashRiskFill.style.width = `${snapshot.risk}%`;
  crashRiskReason.innerText = snapshot.reasons[0] || "Keep your streaks active to maintain resilience.";

  const shortReason = snapshot.reasons.slice(0, 2).join(" • ") || "Stay consistent with your health basics.";
  const userId = String(auth.currentUser?.uid || "").trim();
  const dismissed = isCrashAlertDismissedForToday(userId);
  if (snapshot.risk >= CRASH_ALERT_BANNER_MIN_RISK && !dismissed) {
    crashAlertBanner.style.display = "block";
    crashBannerText.innerText = `${snapshot.level}: ${shortReason}`;
  } else {
    crashAlertBanner.style.display = "none";
    crashBannerText.innerText = "Your dip risk is elevated right now.";
  }
}

function renderProgressMilestones() {
  if (!progressMilestones) return;

  const currentScore = Number((wellnessScoreEl?.innerText || "0/100").split("/")[0]) || 0;
  const completedTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const moodStreak = calcStreak(moodDates);
  const waterStreak = calcStreak(waterDates);
  const gratitudeStreak = calcStreak(gratitudeEntries.map((entry) => entry.time));
  const challengeStreak = calcStreak(challengeDates);

  const unlocked = [];
  if (moodStreak >= 3) unlocked.push(`✅ Mood Streak unlocked (${moodStreak} days).`);
  if (waterStreak >= 3) unlocked.push(`✅ Hydration Streak unlocked (${waterStreak} days).`);
  if (gratitudeStreak >= 3) unlocked.push(`✅ Gratitude Streak unlocked (${gratitudeStreak} days).`);
  if (challengeStreak >= 3) unlocked.push(`✅ Challenge Streak unlocked (${challengeStreak} days).`);
  if (completedTasks >= 25) unlocked.push(`✅ Productivity Milestone unlocked (${completedTasks} tasks completed).`);
  if (currentScore >= 80) unlocked.push(`✅ Wellness Milestone unlocked (score ${currentScore}/100).`);

  if (unlocked.length) {
    setListItems(progressMilestones, unlocked.slice(0, 5), "");
    return;
  }

  const upcoming = [
    `Next: Mood streak ${Math.max(0, 3 - moodStreak)} more day(s) to unlock.`,
    `Next: Hydration streak ${Math.max(0, 3 - waterStreak)} more day(s) to unlock.`,
    `Next: Complete ${Math.max(0, 25 - completedTasks)} more tasks for productivity milestone.`,
    `Next: Reach wellness score +${Math.max(0, 80 - currentScore)} to unlock wellness milestone.`
  ];

  setListItems(progressMilestones, upcoming, "No milestones yet — start with one log today.");
}

async function runCrashRescueFlow(options = {}) {
  const showAlert = options.showAlert !== false;
  const user = auth.currentUser;
  if (!user) {
    if (showAlert) alert("Please sign in first.");
    return { ok: false, message: "Please sign in first." };
  }

  const snapshot = getCrashRiskSnapshot();
  const steps = [
    "Do 6 breathing rounds (inhale 4s • hold 4s • exhale 6s).",
    "Drink 1 glass of water now.",
    "Start one 10-minute micro-task.",
    "Check in after 20 minutes and log your mood again."
  ];

  if (crashRescuePlan) {
    crashRescuePlan.innerHTML = steps.map((step) => `<li>${step}</li>`).join("");
  }

  try {
    const reminderLabel = `Rescue check-in (${snapshot.level})`;
    const targetAtMs = getServerNowDate().getTime() + (20 * 60 * 1000);
    const ref = await addDoc(collection(db, "users", user.uid, "reminders"), {
      text: reminderLabel,
      minutes: 20,
      targetAtMs,
      createdAt: serverTimestamp()
    });
    renderReminder({ id: ref.id, text: reminderLabel, minutes: 20, targetAtMs }, { insertAtTop: true });

    const rescueRef = await addDoc(collection(db, "users", user.uid, "rescueEvents"), {
      level: snapshot.level,
      reason: (snapshot.reasons && snapshot.reasons[0]) || "",
      time: serverTimestamp()
    });
    rescueEvents.push({ id: rescueRef.id, time: getServerNowDate(), level: snapshot.level });

    wellnessActionBoost = Math.min(20, (Number(wellnessActionBoost) || 0) + 2);
    updateWellnessScore();
    updateCrashPreventionUI();
    updateWeeklyReview();
    if (showAlert) {
      alert("✅ Rescue protocol started. A 20-minute recovery reminder is now set.");
    }
    return {
      ok: true,
      level: snapshot.level,
      reason: (snapshot.reasons && snapshot.reasons[0]) || "General resilience support"
    };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, message: "Could not start rescue right now." };
  }
}

function updateInsights() {
  ensureHabitQuestCurrent();
  const moodStreak = calcStreak(moodDates);
  const waterStreak = calcStreak(waterDates);
  const gratitudeStreak = calcStreak(gratitudeEntries.map((entry) => entry.time));
  const challengeStreak = calcStreak(challengeDates);

  const totalTasks = taskEntries.length;
  const doneTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const taskCompletion = totalTasks ? Math.round((doneTasks / totalTasks) * 100) : 0;

  const avgSleep = sleepHistory.length
    ? sleepHistory.reduce((a, b) => a + b, 0) / sleepHistory.length
    : 0;
  const sleepPercent = Math.round(Math.min(100, (avgSleep / 8) * 100));

  const waterSum = waterHistory.reduce((a, b) => a + b, 0);
  const waterPercent = waterGoal > 0 ? Math.round((waterSum / waterGoal) * 100) : 0;

  if (insightTaskTopLabel) {
    insightTaskTopLabel.innerText = `Tasks completed ${doneTasks}/${totalTasks}`;
  }
  if (insightTaskTopBar) {
    setInsightBar(insightTaskTopBar, taskCompletion);
  }

  const weekRange = getCurrentWeekRangeKeys();
  const taskSeries = getSeriesWithPersistedFallback("tasks", getInsightSeries("tasks"), weekRange);
  const sleepSeries = getSeriesWithPersistedFallback("sleep", getInsightSeries("sleep"), weekRange);
  const waterSeries = getSeriesWithPersistedFallback("water", getInsightSeries("water"), weekRange);
  const moodSeries = getSeriesWithPersistedFallback("mood", getInsightSeries("mood"), weekRange);
  const moodValuesForWeek = Array.isArray(moodSeries?.values)
    ? moodSeries.values.map((value) => Number(value) || 0).filter((value) => value > 0)
    : [];
  const weeklyMoodAvgScore = safeAvg(moodValuesForWeek);
  const hasWeeklyMoodLogs = moodValuesForWeek.length > 0;
  const moodWeeklyLabel = hasWeeklyMoodLogs
    ? getMoodLabelFromScore(weeklyMoodAvgScore)
    : "Not logged";
  const moodPercent = hasWeeklyMoodLogs
    ? Math.max(0, Math.min(100, Math.round((weeklyMoodAvgScore / 3) * 100)))
    : 0;

  const taskValues = Array.isArray(taskSeries?.values) ? taskSeries.values.map((value) => Number(value) || 0) : [];
  const taskLabels = Array.isArray(taskSeries?.labels) ? taskSeries.labels : [];
  let bestTaskIndex = -1;
  let bestTaskValue = -1;
  taskValues.forEach((value, index) => {
    if (value > bestTaskValue) {
      bestTaskValue = value;
      bestTaskIndex = index;
    }
  });
  const bestProductivityLabel = bestTaskValue > 0
    ? `Best productivity day: ${taskLabels[bestTaskIndex] || "-"} (${Math.round(bestTaskValue)}% completion)`
    : "Best productivity day: no completion data yet";

  const sleepValues = Array.isArray(sleepSeries?.values)
    ? sleepSeries.values.map((value) => Number(value) || 0).filter((value) => value > 0)
    : [];
  const weeklySleepAvg = safeAvg(sleepValues);
  const weeklySleepLabel = `Average sleep this week: ${weeklySleepAvg.toFixed(1)} hrs`;

  const { currentStart, currentEnd, previousStart, previousEnd } = getWeekRanges();
  const currentWeekMetrics = computeWeekMetrics(currentStart, currentEnd);
  const previousWeekMetrics = computeWeekMetrics(previousStart, previousEnd);
  const moodChangePct = previousWeekMetrics.moodScore > 0
    ? ((currentWeekMetrics.moodScore - previousWeekMetrics.moodScore) / previousWeekMetrics.moodScore) * 100
    : (currentWeekMetrics.moodScore > 0 ? 100 : 0);
  const roundedMoodChange = Math.round(moodChangePct);
  const moodChangeLabel = previousWeekMetrics.moodScore > 0
    ? `Mood ${roundedMoodChange >= 0 ? "improving" : "down"}: ${roundedMoodChange >= 0 ? "+" : ""}${roundedMoodChange}% vs last week`
    : (hasWeeklyMoodLogs
      ? `Mood baseline this week: ${moodWeeklyLabel} (${weeklyMoodAvgScore.toFixed(2)})`
      : "Mood baseline this week: Not logged yet");

  const metricViews = [
    {
      title: "Productivity Trend",
      label: bestProductivityLabel,
      percent: taskCompletion,
      series: taskSeries
    },
    {
      title: "Sleep Trend",
      label: weeklySleepLabel,
      percent: sleepPercent,
      series: sleepSeries
    },
    {
      title: "Water Intake Trend",
      label: `Hydration trend • goal progress ${waterPercent}%`,
      percent: waterPercent,
      series: waterSeries
    },
    {
      title: "Mood Trend",
      label: moodChangeLabel,
      percent: moodPercent,
      series: moodSeries
    }
  ];

  if (insightMetricIndex < 0 || insightMetricIndex >= metricViews.length) insightMetricIndex = 0;
  renderInsightMetricView(metricViews[insightMetricIndex]);

  updateWellnessScore();
  renderFriendMetricCardInsights();
  if (moodFriendInsight && !String(moodFriendInsight.innerText || "").trim()) {
    moodFriendInsight.innerText = "Friend benchmark: add a friend to compare average mood of the day.";
  }
  updateCrashPreventionUI();
  updateBurnoutRadarUI();
  updateWeeklyReview();
  renderProgressMilestones();

  const weekStartKey = weekRange.weekStartKey;
  const weekEndKey = weekRange.weekEndKey;
  const currentScore = Number((wellnessScoreEl?.innerText || "0/100").split("/")[0]) || 0;
  const patternMemory = buildBehaviorPatternMemoryFromLocal(35);
  const socialProfile = buildUserSocialProfileSnapshot(auth.currentUser);
  queueInsightsPersist({
    moodStreak,
    waterStreak,
    gratitudeStreak,
    challengeStreak,
    taskCompletion,
    avgSleep: Number(avgSleep.toFixed(1)),
    waterGoalProgress: waterPercent,
    wellnessScore: currentScore,
    wellnessStatus: wellnessStatusEl.innerText || "Needs Focus",
    dailyChallengeCompleted,
    dailyChallenge: currentChallengeText || "",
    patternMemory,
    socialProfile,
    barGraphs: {
      weekStartKey,
      weekEndKey,
      labels: Array.isArray(taskSeries?.labels) ? taskSeries.labels : [],
      tasks: {
        values: Array.isArray(taskSeries?.values) ? taskSeries.values : [],
        maxValue: Number(taskSeries?.maxValue) || 100
      },
      sleep: {
        values: Array.isArray(sleepSeries?.values) ? sleepSeries.values : [],
        maxValue: Number(sleepSeries?.maxValue) || 12
      },
      water: {
        values: Array.isArray(waterSeries?.values) ? waterSeries.values : [],
        maxValue: Number(waterSeries?.maxValue) || 8
      },
      mood: {
        values: Array.isArray(moodSeries?.values) ? moodSeries.values : [],
        maxValue: Number(moodSeries?.maxValue) || 3
      }
    }
  });

  refreshStartupFeatures();
  updateClearDataButtonState();
}

function normalizeStartupFeatureState(input) {
  return getDefaultStartupFeatureState();
}

async function saveStartupFeatureState(userId) {
  if (!userId) return;
  try {
    await setDoc(doc(db, "users", userId, "settings", "startupPack"), {
      ...startupFeatureState,
      updatedAt: serverTimestamp()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadStartupFeatureState(userId) {
  startupFeatureState = getDefaultStartupFeatureState();
  if (!userId) {
    refreshStartupFeatures();
    return;
  }

  try {
    const snapshot = await fsGetDoc(doc(db, "users", userId, "settings", "startupPack"), 'startupPack');
    if (snapshot.exists) {
      startupFeatureState = normalizeStartupFeatureState(snapshot.data || {});
    }
  } catch (err) {
    notifyFirestoreError(err);
  }

  refreshStartupFeatures();
}

function buildStartupPlanItems() {
  const snapshot = getWellnessSnapshot();
  const trends = buildTrendSignals();
  const board = buildPriorityBoard(snapshot, trends);
  return board.slice(0, 3).map((entry) => entry.action);
}

function renderStartupPlan() {
  if (!startupDailyPlanList) return;
  if (!startupPlanGeneratedOnce) {
    startupDailyPlanList.innerHTML = "<li>Generate plan to see your personalized priorities.</li>";
    if (startupPlanMeta) {
      startupPlanMeta.innerText = "Generate plan to unlock your personalized priorities.";
    }
    return;
  }

  if (!startupCurrentPlan.length) startupCurrentPlan = buildStartupPlanItems();
  startupDailyPlanList.innerHTML = startupCurrentPlan.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  if (startupPlanMeta) {
    const trends = buildTrendSignals();
    const signal = [
      trends.taskDelta < 0 ? "Task trend dipped" : "Task trend stable",
      trends.sleepDelta < 0 ? "Sleep needs protection" : "Sleep trend steady"
    ].join(" • ");
    startupPlanMeta.innerText = `Signal: ${signal}.`;
  }
}

function buildStartupWeeklyReport() {
  const snapshot = getWellnessSnapshot();
  const trends = buildTrendSignals();
  const plan = buildStartupPlanItems();
  const trendWord = (delta) => {
    const value = Number(delta) || 0;
    if (Math.abs(value) < 0.15) return "steady";
    return value > 0 ? "up" : "down";
  };
  return [
    `Week of ${getStartupWeekKey()}`,
    `Wellness score today: ${snapshot.score}/100.`,
    `Today snapshot: water ${snapshot.waterToday}/${snapshot.todayGoal}, sleep ${snapshot.sleepToday || 0}h, tasks ${snapshot.doneTasks}/${snapshot.totalTasks}.`,
    `7-day trend: tasks ${trendWord(trends.taskDelta)}, sleep ${trendWord(trends.sleepDelta)}, water ${trendWord(trends.waterDelta)}, mood ${trendWord(trends.moodDelta)}.`,
    `Focus 1: ${plan[0] || "Lock in one meaningful task."}`,
    `Focus 2: ${plan[1] || "Protect sleep and hydration."}`,
    `Focus 3: ${plan[2] || "End the day with a short reset and plan."}`
  ];
}

function renderStartupBehaviorMemory() {
  if (!startupBehaviorMemory) return;
  const trends = buildTrendSignals();
  const todayKey = getTodayKey();
  const todayDate = dateKeyToDate(todayKey) || getServerNowDate();
  const dayKeys = [];
  for (let offset = 13; offset >= 0; offset -= 1) {
    const day = new Date(todayDate);
    day.setUTCDate(todayDate.getUTCDate() - offset);
    const key = dateToKey(day);
    if (key) dayKeys.push(key);
  }

  const moodByDay = buildMoodAverageByDayMap(dayKeys);

  const waterByDay = new Map();
  waterHistory.forEach((entry, index) => {
    const key = dateToKey(waterDates[index]);
    if (!key || !dayKeys.includes(key)) return;
    waterByDay.set(key, (waterByDay.get(key) || 0) + (Number(entry) || 0));
  });

  const sleepByDay = new Map();
  sleepHistory.forEach((entry, index) => {
    const key = dateToKey(sleepDates[index]);
    if (!key || !dayKeys.includes(key)) return;
    sleepByDay.set(key, Number(entry) || 0);
  });

  const tasksDoneByDay = new Map();
  taskEntries.forEach((entry) => {
    if (!entry?.completed) return;
    const key = dateToKey(entry.completedAt || entry.time);
    if (!key || !dayKeys.includes(key)) return;
    tasksDoneByDay.set(key, (tasksDoneByDay.get(key) || 0) + 1);
  });

  const memories = [];
  const activeDays = dayKeys.filter((key) => moodByDay.has(key) || waterByDay.has(key) || sleepByDay.has(key) || tasksDoneByDay.has(key));
  memories.push(`Analyzed ${activeDays.length} active day${activeDays.length === 1 ? "" : "s"} from your recent logs.`);

  const sleepMoodInsight = buildSleepMoodPatternInsight(14);
  if (sleepMoodInsight) {
    memories.push(sleepMoodInsight.summary);
  } else {
    const sleepMoodPairCount = dayKeys.filter((key) => sleepByDay.has(key) && moodByDay.has(key)).length;
    if (sleepMoodPairCount > 0) {
      memories.push(`Sleep-mood threshold is still forming (${sleepMoodPairCount} matched days). Keep logging to sharpen this pattern.`);
    }
  }

  const hydrationTarget = waterGoal > 0 ? waterGoal : 8;
  const waterTaskPairs = dayKeys
    .filter((key) => waterByDay.has(key) || tasksDoneByDay.has(key))
    .map((key) => ({
      water: Number(waterByDay.get(key)) || 0,
      tasks: Number(tasksDoneByDay.get(key)) || 0
    }));
  if (waterTaskPairs.length) {
    const highHydrationTaskAvg = safeAvg(waterTaskPairs.filter((pair) => pair.water >= hydrationTarget).map((pair) => pair.tasks));
    const lowHydrationTaskAvg = safeAvg(waterTaskPairs.filter((pair) => pair.water < hydrationTarget).map((pair) => pair.tasks));
    if (highHydrationTaskAvg > 0 || lowHydrationTaskAvg > 0) {
      memories.push(`Task completion on hydration-target days: ${highHydrationTaskAvg.toFixed(1)} vs ${lowHydrationTaskAvg.toFixed(1)} on lower-hydration days.`);
    }
  }

  let bestKey = "";
  let bestScore = -1;
  dayKeys.forEach((key) => {
    const moodScore = (Number(moodByDay.get(key)) || 0) * 20;
    const sleepScore = Math.min(8, Number(sleepByDay.get(key)) || 0) * 8;
    const waterScore = Math.min(1, (Number(waterByDay.get(key)) || 0) / hydrationTarget) * 20;
    const taskScore = Math.min(4, Number(tasksDoneByDay.get(key)) || 0) * 6;
    const score = moodScore + sleepScore + waterScore + taskScore;
    if (score > bestScore) {
      bestScore = score;
      bestKey = key;
    }
  });
  if (bestKey) {
    memories.push(`Best pattern day (${bestKey}): sleep ${Number(sleepByDay.get(bestKey)) || 0}h, water ${Number(waterByDay.get(bestKey)) || 0}, tasks ${Number(tasksDoneByDay.get(bestKey)) || 0}.`);
  }

  if (trends.taskDelta > 0) memories.push("Recent task trend is rising — keep the same work blocks.");
  if (trends.sleepDelta < 0) memories.push("Sleep trend dipped recently — protect bedtime consistency this week.");
  if (trends.waterDelta < 0) memories.push("Hydration trend is softening — schedule fixed water checkpoints.");
  if (trends.moodDelta < 0) memories.push("Mood trend dipped — add an early recovery break in the first half of the day.");

  if (!activeDays.length) {
    memories.length = 0;
    memories.push("No recent logs detected yet — first memory will unlock after your next check-in.");
  }

  startupBehaviorMemory.innerHTML = memories.slice(0, 5).map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function refreshStartupFeatures() {
  renderStartupPlan();
  renderStartupBehaviorMemory();
  if (startupRefreshPlanBtn) {
    startupRefreshPlanBtn.innerText = startupPlanGeneratedOnce ? "Regenerate Plan" : "Generate Plan";
    const planLimited = startupUsageState.planCount >= STARTUP_PLAN_DAILY_LIMIT;
    startupRefreshPlanBtn.disabled = planLimited;
    startupRefreshPlanBtn.title = planLimited ? buildDailyLimitCountdownMessage(`Daily planner limit reached (${STARTUP_PLAN_DAILY_LIMIT}/day)`) : "";
  }
  if (startupApplyPlanBtn) {
    startupApplyPlanBtn.disabled = !startupPlanGeneratedOnce || !startupCurrentPlan.length;
    startupApplyPlanBtn.title = startupApplyPlanBtn.disabled ? "Generate a plan first" : "";
  }
  if (startupGenerateReportBtn) {
    startupGenerateReportBtn.innerText = startupReportGeneratedOnce ? "Regenerate Report" : "Generate Report";
    const reportLimited = startupUsageState.reportCount >= STARTUP_REPORT_WEEKLY_LIMIT;
    startupGenerateReportBtn.disabled = reportLimited;
    startupGenerateReportBtn.title = reportLimited ? buildWeeklyLimitCountdownMessage(`Weekly startup report limit reached (${STARTUP_REPORT_WEEKLY_LIMIT}/week)`) : "";
  }
  if (startupWeeklyReportText && !startupWeeklyReportCache) {
    startupWeeklyReportText.innerHTML = "<li>No report generated yet.</li>";
  }
}

async function refreshStartupPlan() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  await ensureStartupUsageCurrent(user.uid);
  if (startupUsageState.planCount >= STARTUP_PLAN_DAILY_LIMIT) {
    showToast(buildDailyLimitCountdownMessage(`Daily planner limit reached (${STARTUP_PLAN_DAILY_LIMIT}/day)`));
    refreshStartupFeatures();
    return;
  }

  startupPlanGeneratedOnce = true;
  startupCurrentPlan = buildStartupPlanItems();
  startupUsageState.planCount += 1;
  await saveStartupUsageState(user.uid);
  renderStartupPlan();
  refreshStartupFeatures();
}

async function applyStartupPlanAsTasks() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  if (!startupPlanGeneratedOnce || !startupCurrentPlan.length) {
    showToast("Generate your personalized plan first.");
    refreshStartupFeatures();
    return;
  }

  for (let index = 0; index < startupCurrentPlan.length; index += 1) {
    const raw = startupCurrentPlan[index].trim();
    task.value = raw.length > 90 ? `${raw.slice(0, 87)}...` : raw;
    await addTask();
  }
  showToast("Startup plan added to tasks.");
}

async function generateStartupWeeklyReport() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  await ensureStartupUsageCurrent(user.uid);
  if (startupUsageState.reportCount >= STARTUP_REPORT_WEEKLY_LIMIT) {
    showToast(buildWeeklyLimitCountdownMessage(`Weekly startup report limit reached (${STARTUP_REPORT_WEEKLY_LIMIT}/week)`));
    refreshStartupFeatures();
    return;
  }

  startupReportGeneratedOnce = true;
  startupWeeklyReportCache = buildStartupWeeklyReport();
  startupUsageState.reportCount += 1;
  await saveStartupUsageState(user.uid);
  if (startupWeeklyReportText) {
    startupWeeklyReportText.innerHTML = startupWeeklyReportCache
      .map((line) => `<li>${escapeHtml(line)}</li>`)
      .join("");
  }
  if (startupGenerateReportBtn) startupGenerateReportBtn.innerText = "Regenerate Report";
  refreshStartupFeatures();
  showToast("Weekly report generated.");
}

async function copyStartupWeeklyReport() {
  if (!startupWeeklyReportCache) {
    showToast("Generate weekly report first.");
    return;
  }
  try {
    const reportText = ["NovaFix Weekly Report", ...startupWeeklyReportCache].map((line) => `- ${line}`).join("\n");
    await navigator.clipboard.writeText(reportText);
    showToast("Weekly report copied.");
  } catch (_) {
    showToast("Could not copy report right now.");
  }
}

// AI Companion
function escapeHtml(text) {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getUserName(user) {
  const displayName = getPreferredAiDisplayName(user);
  if (displayName) return sanitizeAiAddressName(displayName, "there");
  return "there";
}

function getPreferredAiDisplayName(user) {
  const accountPanelDisplayName = normalizeDisplayNameValue(accountDisplayName?.innerText || "");
  if (accountPanelDisplayName && accountPanelDisplayName !== "-") return accountPanelDisplayName;

  const profileDisplayName = normalizeDisplayNameValue(user?.displayName || "");
  if (profileDisplayName) return profileDisplayName;
  return "";
}

function isClearChatCommand(inputText) {
  const text = String(inputText || "")
    .trim()
    .toLowerCase()
    .replace(/[!?.,;:]+$/g, "");
  if (!text) return false;

  const hasNegatedClear = /\b(?:do\s*not|don't|dont|never)\b[\s\S]*\b(?:clear|delete|wipe|reset|remove)\b[\s\S]*\b(?:chat|conversation)s?\b/.test(text);
  if (hasNegatedClear) return false;

  const clearChatIntent = /\b(?:clear|delete|wipe|reset|remove)\b[\s\S]*\b(?:the\s+)?(?:ai\s+)?chat(?:s)?\b/.test(text)
    || /\b(?:clear|delete|wipe|reset|remove)\b[\s\S]*\b(?:my\s+)?conversation(?:s)?\b/.test(text)
    || /\bclear\b[\s\S]*\bthe\s+chat\b/.test(text);

  return clearChatIntent;
}

const AI_TYPO_FUZZY_KEYWORDS = [
  "thank", "thanks", "appreciate",
  "hello", "hey", "hi", "play", "music", "song", "songs", "spotify", "playlist",
  "task", "tasks", "todo", "todos", "add", "create", "new", "log", "save", "track",
  "reminder", "remind", "water", "hydrate", "hydration", "sleep", "bedtime", "downtime",
  "mood", "happy", "neutral", "low", "gratitude", "grateful", "thankful", "analyze",
  "summary", "summarize", "delete", "remove", "clear", "reset", "memory", "remember",
  "name", "plan", "focus", "productivity", "study", "work", "complete", "reopen",
  "finish", "help", "commands", "date", "time", "today", "stress", "anxious", "angry",
  "update", "edit", "rename", "setting", "settings"
];

function applyTokenCasePattern(sourceToken, replacementToken) {
  if (!sourceToken) return replacementToken;
  if (sourceToken === sourceToken.toUpperCase()) return replacementToken.toUpperCase();
  if (sourceToken[0] === sourceToken[0].toUpperCase()) {
    return replacementToken.charAt(0).toUpperCase() + replacementToken.slice(1);
  }
  return replacementToken;
}

function boundedLevenshteinDistance(a, b, maxDistance) {
  if (a === b) return 0;
  const aLen = a.length;
  const bLen = b.length;
  if (!aLen) return bLen;
  if (!bLen) return aLen;
  if (Math.abs(aLen - bLen) > maxDistance) return maxDistance + 1;

  const prev = new Array(bLen + 1);
  const curr = new Array(bLen + 1);

  for (let j = 0; j <= bLen; j += 1) prev[j] = j;

  for (let i = 1; i <= aLen; i += 1) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= bLen; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + cost
      );
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    for (let j = 0; j <= bLen; j += 1) prev[j] = curr[j];
  }

  return prev[bLen];
}

function fuzzyCorrectAiToken(token) {
  const lower = String(token || "").toLowerCase();
  if (!lower || lower.length < 3 || lower.length > 24) return "";
  if (/\d/.test(lower)) return "";

  const maxDistance = lower.length <= 4 ? 1 : 2;
  let bestMatch = "";
  let bestDistance = maxDistance + 1;

  for (let index = 0; index < AI_TYPO_FUZZY_KEYWORDS.length; index += 1) {
    const keyword = AI_TYPO_FUZZY_KEYWORDS[index];
    if (Math.abs(keyword.length - lower.length) > maxDistance) continue;
    const distance = boundedLevenshteinDistance(lower, keyword, maxDistance);
    if (distance < bestDistance) {
      bestDistance = distance;
      bestMatch = keyword;
      if (distance === 1) break;
    }
  }

  if (!bestMatch || bestDistance > maxDistance) return "";
  return bestMatch;
}

function normalizeTyposForAi(text) {
  const map = {
    analize: "analyze",
    analyz: "analyze",
    anlyze: "analyze",
    sumarize: "summarize",
    summrize: "summarize",
    delet: "delete",
    delte: "delete",
    delee: "delete",
    deltet: "delete",
    rember: "remember",
    remembr: "remember",
    remeber: "remember",
    remidner: "reminder",
    remnder: "reminder",
    happi: "happy",
    happyness: "happiness",
    sadnes: "sadness",
    stres: "stress",
    strees: "stress",
    angy: "angry",
    anxios: "anxious",
    gratitute: "gratitude",
    gratefull: "grateful",
    procastination: "procrastination",
    prodctivity: "productivity",
    produtivity: "productivity",
    watre: "water",
    hyration: "hydration",
    dehydratd: "dehydrated",
    slep: "sleep",
    sllep: "sleep",
    sleeep: "sleep",
    musc: "music",
    msuic: "music",
    blay: "play",
    helo: "hello",
    hellow: "hello",
    thank: "thanks",
    thanks: "thanks",
    thankss: "thanks",
    thanx: "thanks",
    thnks: "thanks",
    becuase: "because",
    dont: "don't",
    cant: "can't",
    wont: "won't"
  };

  return String(text || "").replace(/\b[a-z]{3,}\b/gi, (token) => {
    const lower = token.toLowerCase();
    const deStretched = lower.replace(/([a-z])\1{2,}/g, "$1$1");

    // Preserve gratitude intent tokens; never fuzzy-map these to task/productivity words.
    if (/^(?:thank|thanks+|thankyou|thx|ty|tysm|appreciate)$/.test(lower)) {
      return applyTokenCasePattern(token, "thanks");
    }

    const direct = map[lower] || map[deStretched];
    if (direct) return applyTokenCasePattern(token, direct);

    const fuzzy = fuzzyCorrectAiToken(deStretched);
    if (fuzzy && fuzzy !== lower) return applyTokenCasePattern(token, fuzzy);

    return token;
  });
}

function shouldSkipAiTypoNormalizationForPlannerInput(inputText) {
  const lower = String(inputText || "").trim().toLowerCase();
  if (!lower) return false;

  return /^(?:add|create|new|log)\s+(?:a\s+)?(?:(?:productivity|work|study)\s+)?(?:task|todo)\b/.test(lower)
    || /^(?:task|todo)\s*[:\-]/.test(lower)
    || /^(?:i\s+(?:need|have|want|plan)\s+to|need\s+to|todo\s*[:\-]?|to\s*do\s*[:\-]?)/.test(lower)
    || /^(?:remind\s+me|set\s+(?:a\s+)?reminder|add\s+reminder|create\s+reminder|reminder\s*[:\-]?|in\s+\d+(?:\.\d+)?\s*(?:s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)\s+(?:remind\s+me(?:\s+to)?|set\s+(?:a\s+)?reminder(?:\s+to)?))/i.test(lower);
}

function rememberPrompt(promptText) {
  if (!promptText) return;
  aiRecentPrompts.push(promptText);
  if (aiRecentPrompts.length > 6) aiRecentPrompts.shift();
}

function pickNonRepeatingVariant(pool, key = "default") {
  const list = Array.isArray(pool) ? pool.filter(Boolean) : [];
  if (!list.length) return "";
  if (list.length === 1) return list[0];

  const history = Array.isArray(aiVariantHistory.get(key))
    ? aiVariantHistory.get(key)
    : [];
  const avoidCount = list.length >= AI_RESPONSE_VARIANT_MIN
    ? Math.min(list.length - 1, Math.ceil(list.length * 0.6), AI_RESPONSE_REPEAT_HISTORY_LIMIT)
    : Math.min(list.length - 1, 3);
  const recent = history.slice(-avoidCount);

  const candidates = list
    .map((value, index) => ({ value, index }))
    .filter((entry) => !recent.includes(entry.index));
  const source = candidates.length ? candidates : list.map((value, index) => ({ value, index }));
  const picked = source[Math.floor(Math.random() * source.length)] || source[0];
  const historyLimit = list.length >= AI_RESPONSE_VARIANT_MIN
    ? Math.min(AI_RESPONSE_REPEAT_HISTORY_LIMIT, Math.max(8, list.length - 1))
    : 8;
  const nextHistory = [...history, picked.index].slice(-historyLimit);
  aiVariantHistory.set(key, nextHistory);
  return picked.value;
}

const AI_NAME_BLACKLIST = new Set([
  "stressed", "stress", "anxious", "anxiety", "overwhelmed", "sad", "depressed", "down", "angry", "frustrated", "tired", "drained", "burnt", "burnout", "hopeless", "empty", "lost", "confused", "low", "meh", "fine", "good", "okay", "ok"
]);

function isValidLearnedName(rawValue) {
  const value = String(rawValue || "").trim().toLowerCase();
  if (!value) return false;
  if (value.length < 2 || value.length > 24) return false;
  if (AI_NAME_BLACKLIST.has(value)) return false;
  if (/\b(?:stressed|sad|anxious|angry|overwhelmed|tired|drained|depressed|confused|low|meh)\b/.test(value)) return false;
  const parts = value.split(/\s+/).filter(Boolean);
  if (parts.length > 3) return false;
  return /^[a-z][a-z\s'\-]+$/.test(value);
}

function pushTopicHistory(topic) {
  if (!topic) return;
  aiSessionState.topicHistory.push(topic);
  if (aiSessionState.topicHistory.length > 12) aiSessionState.topicHistory.shift();
}

function tokenizeText(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function jaccardSimilarity(a, b) {
  const aSet = new Set(tokenizeText(a));
  const bSet = new Set(tokenizeText(b));
  if (!aSet.size || !bSet.size) return 0;
  let intersection = 0;
  aSet.forEach((token) => {
    if (bSet.has(token)) intersection += 1;
  });
  const union = new Set([...aSet, ...bSet]).size;
  return union ? intersection / union : 0;
}

function rememberUserFact(type, value) {
  if (!value) return;

  if (type === "name") {
    const candidate = String(value || "").trim();
    if (!isValidLearnedName(candidate)) return;
    aiSessionState.userFacts.name = candidate;
    return;
  }

  if (type === "goal") {
    aiSessionState.userFacts.goal = value.trim();
    return;
  }

  if (type === "likes") {
    const normalized = value.trim().toLowerCase();
    if (!normalized) return;
    if (!aiSessionState.userFacts.likes.includes(normalized)) {
      aiSessionState.userFacts.likes.push(normalized);
      if (aiSessionState.userFacts.likes.length > 8) aiSessionState.userFacts.likes.shift();
    }
    return;
  }

  if (type === "dislikes") {
    const normalized = value.trim().toLowerCase();
    if (!normalized) return;
    if (!aiSessionState.userFacts.dislikes.includes(normalized)) {
      aiSessionState.userFacts.dislikes.push(normalized);
      if (aiSessionState.userFacts.dislikes.length > 8) aiSessionState.userFacts.dislikes.shift();
    }
  }
}

function learnFromUserInput(input) {
  const text = String(input || "").trim();
  if (!text) return;

  const nameMatch = text.match(/(?:my name is|call me|i am called|i'm called)\s+([a-z][a-z\s'-]{1,24})/i);
  if (nameMatch?.[1] && isValidLearnedName(nameMatch[1])) {
    rememberUserFact("name", nameMatch[1]);
  }

  const goalMatch = text.match(/(?:my goal is|i want to|i need to|i plan to)\s+(.+)/i);
  if (goalMatch?.[1] && goalMatch[1].length < 120) {
    rememberUserFact("goal", goalMatch[1]);
  }

  const likeMatch = text.match(/(?:i like|i love)\s+(.+)/i);
  if (likeMatch?.[1] && likeMatch[1].length < 80) {
    rememberUserFact("likes", likeMatch[1]);
  }

  const dislikeMatch = text.match(/(?:i dislike|i hate|i don't like)\s+(.+)/i);
  if (dislikeMatch?.[1] && dislikeMatch[1].length < 80) {
    rememberUserFact("dislikes", dislikeMatch[1]);
  }
}

function buildUserContextLabel(defaultName) {
  const memoryName = sanitizeAiAddressName(aiSessionState.userFacts.name, "");
  if (!memoryName && aiSessionState.userFacts.name) {
    aiSessionState.userFacts.name = "";
  }
  if (memoryName) return memoryName;
  return defaultName;
}

function sanitizeAiAddressName(nameValue, fallback = "there") {
  const candidate = String(nameValue || "").trim();
  if (!candidate) return fallback;
  if (!isValidLearnedName(candidate)) return fallback;
  return candidate;
}

function calculateExpressionFromText(text) {
  const match = text.match(/(?:calculate|solve|what is|what's)\s*([\d+\-*/().%\s]+)/i);
  if (!match || !match[1]) return null;
  const expression = match[1].trim();
  if (!/^[\d+\-*/().%\s]+$/.test(expression)) return null;

  try {
    const result = Function(`"use strict"; return (${expression});`)();
    if (typeof result !== "number" || !Number.isFinite(result)) return null;
    return { expression, result };
  } catch (_) {
    return null;
  }
}

function normalizeLocalIntentText(input) {
  const raw = String(input || "");
  const source = (shouldSkipAiTypoNormalizationForPlannerInput(raw) ? raw : normalizeTyposForAi(raw)).toLowerCase();
  return source
    .replace(/\bu\b/g, "you")
    .replace(/\bur\b/g, "your")
    .replace(/\bidk\b/g, "i do not know")
    .replace(/\bik\b/g, "i know")
    .replace(/\bikr\b/g, "i know right")
    .replace(/\bwanna\b/g, "want to")
    .replace(/\bgonna\b/g, "going to")
    .replace(/\bim\b/g, "i am")
    .replace(/\bpls\b|\bplz\b/g, "please")
    .replace(/[!?.,;:]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const LOCAL_INTENT_TEMPLATES = {
  greeting: ["hi", "hello", "hey there"],
  "smalltalk-casual": ["lol", "sup", "wassup", "bro", "ikr"],
  "smalltalk-health": ["how are you", "how you doing"],
  "smalltalk-activity": ["what are you doing", "what are you up to"],
  "date-local": ["what day is it", "what date is it", "today date", "today day", "what time is it"],
  bored: ["i am bored", "nothing to do"],
  celebrate: ["lets go", "yay"],
  "emotional-personal": ["i feel stuck", "i feel low", "i feel anxious"],
  analysis: ["analyze my progress", "give me a summary", "find my patterns"],
  plan: ["make me a plan", "what should i do today"],
  decision: ["which option is better", "help me decide"],
  why: ["why this", "what caused this"],
  optimize: ["optimize this", "improve faster"],
  stress: ["i am stressed", "i am overwhelmed"],
  sleep: ["sleep advice", "sleep help"],
  water: ["water check", "hydration check"],
  productivity: ["productivity help", "focus task"],
  gratitude: ["gratitude prompt"],
  capabilities: ["what can you do", "help commands"],
  followup: ["do it", "that one", "next step", "continue"],
  joke: ["tell a joke", "make me laugh"],
  thanks: ["thanks", "thank you"],
  bye: ["bye", "see you"]
};

function getTemplateIntentScore(msg, intentKey) {
  const templates = LOCAL_INTENT_TEMPLATES[intentKey] || [];
  return templates.reduce((best, phrase) => Math.max(best, jaccardSimilarity(msg, phrase)), 0);
}

function detectEmotionFromText(text) {
  const detailed = detectDetailedEmotionFromText(text);
  if (detailed === "positive") return "positive";
  if (detailed === "neutral") return "neutral";
  return "low";
}

function detectDetailedEmotionFromText(text) {
  const normalized = normalizeLocalIntentText(text);
  if (/\b(angry|anger|furious|rage|mad|irritated)\b/.test(normalized)) return "angry";
  if (/\b(anxious|anxiety|panic|nervous|worried|fear|scared)\b/.test(normalized)) return "anxious";
  if (/\b(overwhelm|overwhelmed|too much|cannot handle|out of control)\b/.test(normalized)) return "overwhelmed";
  if (/\b(stress|stressed|pressure|tense)\b/.test(normalized)) return "stressed";
  if (/\b(sad|sadness|down|depressed|hopeless|lonely|empty)\b/.test(normalized)) return "sad";
  if (/\b(tired|drained|exhausted|burnout|burned out|fatigue|meh|numb|worthless)\b/.test(normalized)) return "drained";
  if (/\b(good|great|awesome|amazing|happy|happiness|motivated|energized|fine|yay|let'?s\s*go|woo+|nice|pumped)\b/.test(normalized)) return "positive";
  return "neutral";
}

function lowerFirstAiVariantText(text) {
  const safeText = String(text || "").trim();
  if (!safeText) return "";
  return safeText.charAt(0).toLowerCase() + safeText.slice(1);
}

const AI_RESPONSE_VARIANT_FRAMES = [
  (text) => text,
  (text) => `Right now, ${lowerFirstAiVariantText(text)}`,
  (text) => `Best next move: ${lowerFirstAiVariantText(text)}`,
  (text) => `Keep it simple: ${lowerFirstAiVariantText(text)}`,
  (text) => `No overthinking: ${lowerFirstAiVariantText(text)}`,
  (text) => `Use this reset: ${lowerFirstAiVariantText(text)}`,
  (text) => `For the next 10 minutes, ${lowerFirstAiVariantText(text)}`,
  (text) => `Small win mode: ${lowerFirstAiVariantText(text)}`,
  (text) => `Make it concrete: ${lowerFirstAiVariantText(text)}`,
  (text) => `Start here: ${lowerFirstAiVariantText(text)}`
];

function expandAiResponsePool(basePool, options = {}) {
  const baseList = Array.isArray(basePool)
    ? basePool.map((entry) => String(entry || "").trim()).filter(Boolean)
    : [];
  if (!baseList.length) return [];

  const minTarget = Math.max(1, Number(options.min) || AI_RESPONSE_VARIANT_MIN);
  const maxTarget = Math.max(minTarget, Number(options.max) || AI_RESPONSE_VARIANT_MAX);
  const frames = Array.isArray(options.frames) && options.frames.length
    ? options.frames
    : AI_RESPONSE_VARIANT_FRAMES;
  const variants = [];
  const seen = new Set();

  const addVariant = (value) => {
    const cleanValue = String(value || "").replace(/\s+/g, " ").trim();
    const key = cleanValue.toLowerCase();
    if (!cleanValue || seen.has(key) || variants.length >= maxTarget) return;
    seen.add(key);
    variants.push(cleanValue);
  };

  baseList.forEach(addVariant);

  for (let cycle = 0; variants.length < maxTarget && cycle < 24; cycle += 1) {
    baseList.forEach((baseText, index) => {
      const frame = frames[(cycle + index) % frames.length];
      const framed = typeof frame === "function" ? frame(baseText, cycle, index) : baseText;
      addVariant(framed);
    });
  }

  return variants.length >= minTarget ? variants : variants.slice(0, maxTarget);
}

const AI_SHORT_THANKS_REPLIES = [
  "Anytime.",
  "You’re welcome.",
  "Got you.",
  "Happy to help.",
  "Always."
];

// Base pools for common quick actions. These are expanded into 100-150
// response variants using `expandAiResponsePool` so replies feel diverse.
const AI_TASK_ADDED_BASE = [
  "✅ Added task: {task}.",
  "Got it — {task} is in your list.",
  "Saved: {task} — nice one.",
  "Task recorded: {task}.",
  "Done — {task} added.",
  "I put {task} on your task list.",
  "Noted: {task} — you can tackle it next.",
  "{task} saved — small wins add up.",
  "Added {task} — momentum incoming.",
  "Great choice. I've added: {task}.",
  "Task captured: {task} — you're set.",
  "Alright — {task} is queued in your tasks."
];

const AI_REMINDER_ADDED_BASE = [
  "⏰ Reminder set: {text} in {minutes} minute(s).",
  "Reminder scheduled: {text} — I'll ping you in {minutes} minute(s).",
  "Saved reminder: {text} (in {minutes} min).",
  "All set: I'll remind you about {text} in {minutes} minutes.",
  "Reminder queued: {text} — {minutes} minute(s) from now.",
  "Your reminder for '{text}' is on the clock (in {minutes}m).",
  "I've scheduled it: {text} — expect a reminder in {minutes} minutes.",
  "Noted: {text}. I'll remind you in {minutes} minute(s).",
  "Reminder added: {text} (in {minutes}m).",
  "Set: {text} — reminder will fire in {minutes} minutes."
];

const AI_MOOD_LOGGED_BASE = [
  "Logged Mood [{mood}]",
  "Mood logged: {mood}.",
  "Mood saved: {mood}.",
  "Checked in: {mood}.",
  "Mood recorded: {mood}.",
  "Saved mood: {mood}.",
  "Mood noted: {mood}.",
  "All set — {mood} is logged.",
  "Nice check-in: {mood}.",
  "Mood update: {mood}."
];

const AI_MOOD_LOGGED_FRAMES = [
  (text) => text,
  (text) => `Logged Mood [${text}]`,
  (text) => `Mood log: ${text}`,
  (text) => `Mood check-in saved: ${text}`,
  (text) => `Mood update saved: ${text}`,
  (text) => `Mood record: ${text}`,
  (text) => `Saved mood note: ${text}`,
  (text) => `Checked mood: ${text}`,
  (text) => `Thanks for logging: ${text}`,
  (text) => `All set: ${text}`,
  (text) => `Mood in the log: ${text}`,
  (text) => `Good check-in: ${text}`
];

const AI_WATER_LOGGED_BASE = [
  "💧 Logged {amount} cup(s) of water.",
  "Nice — {amount} cup(s) added to your water log.",
  "Hydration recorded: {amount} cup(s).",
  "Got it — {amount} cup(s) logged.",
  "{amount} cup(s) saved to your hydration for today.",
  "Water logged: {amount} cup(s). Keep it up.",
  "Recorded {amount} cup(s) — you hydrated.",
  "Added {amount} cup(s) to your water intake.",
  "Saved: {amount} cup(s) of water.",
  "Hydration update: {amount} cup(s) logged."
];

const AI_GREETING_BASE = [
  "Hey", "Hi", "Hello", "Yo", "Hiya", "Howdy", "Greetings"
];

// Rich greeting templates (use placeholders: {name}, {score}, {pending}, {waterStatus}, {timeOfDay})
const AI_GREETING_FULL_BASE = [
  "Hey {name} — you’re at {score}/100. {waterStatus} {pending} task(s) left. Want a quick 3-step plan?",
  "Hi {name}! Score: {score}/100. {waterStatus} You have {pending} pending task(s). Want a short plan?",
  "Hello {name}, I see you're at {score}/100. {waterStatus} {pending} tasks remain. Need a 3-step plan?",
  "Yo {name} — score ${score}/100. {waterStatus} {pending} task(s) left. Want a tiny plan?",
  "Hiya {name}! You're at {score}/100. {waterStatus} {pending} remaining — quick plan?",
  "{timeOfDay}, {name}! Score: {score}/100. {waterStatus} {pending} tasks left. Shall I suggest a plan?",
  "Good to see you, {name}. You're at {score}/100. {waterStatus} {pending} tasks — need a quick plan?",
  "Hey {name}, quick check: score {score}/100, {waterStatus} and {pending} tasks. Want a short plan?",
  "Hello {name} — I'm here. Your dashboard: {score}/100, {waterStatus}, {pending} tasks. Ready for a quick plan?",
  "Hi {name}, you're doing fine: {score}/100. {waterStatus} {pending} pending. Want a focused 3-step plan?"
];

const AI_GREETING_FULL_POOL = expandAiResponsePool(AI_GREETING_FULL_BASE, { min: 8, max: 48 });

// Friend comparison motivation pools
const FRIEND_MOTIVATION_TIED_BASE = [
  "You're tied with {names}. One small action now can put you ahead.",
  "Tied with {names} — a tiny win pushes you in front.",
  "It's neck-and-neck with {names}. Do one thing now to lead.",
  "Evenly matched with {names}. A single small push wins it.",
  "You're level with {names}. Try a quick positive reset to pull ahead."
];

const FRIEND_MOTIVATION_LEADING_BASE = [
  "You're leading right now. Keep the streak strong and inspire your circle.",
  "Nice — you're ahead. Maintain momentum and set the pace.",
  "You're on top for now. One small consistent move keeps you there.",
  "Leading the pack — keep your routine steady to stay ahead.",
  "Top performer — hold this advantage with a tiny repeatable habit."
];

const FRIEND_MOTIVATION_BEHIND_BASE = [
  "{names} are ahead by {gap}. One focused push now can close the gap.",
  "You're a bit behind {names} by {gap}. Try a short sprint to catch up.",
  "{names} lead by {gap}. A quick reset and one task could close it.",
  "Close gap: {names} are ahead by {gap}. Add one focused action to move up.",
  "Slight gap vs {names} ({gap}). A small win brings you level."
];

// Expand pools to target 100-150 variants for diverse replies
const AI_TASK_ADDED_POOL = expandAiResponsePool(AI_TASK_ADDED_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const AI_REMINDER_ADDED_POOL = expandAiResponsePool(AI_REMINDER_ADDED_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const AI_MOOD_LOGGED_POOL = expandAiResponsePool(AI_MOOD_LOGGED_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX, frames: AI_MOOD_LOGGED_FRAMES });
const AI_WATER_LOGGED_POOL = expandAiResponsePool(AI_WATER_LOGGED_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const AI_GREETING_POOL = expandAiResponsePool(AI_GREETING_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });

const FRIEND_MOTIVATION_TIED_POOL = expandAiResponsePool(FRIEND_MOTIVATION_TIED_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const FRIEND_MOTIVATION_LEADING_POOL = expandAiResponsePool(FRIEND_MOTIVATION_LEADING_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const FRIEND_MOTIVATION_BEHIND_POOL = expandAiResponsePool(FRIEND_MOTIVATION_BEHIND_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });
const AI_BENEFIT_PLAN_OPENERS = [
  "Direct plan based on your current data:",
  "No fluff — here is the best move stack:",
  "This is the short plan to feel better fast:",
  "Here is the plan that compounds quickly:",
  "This is your must-do plan for real benefit in 2-3 days:",
  "Focus plan for steady improvement:",
  "Simple, high-impact plan for the next 48 hours:"
];

// Strategic response base templates — include placeholders to be filled with live data.
const AI_STRATEGIC_RESPONSE_BASE = [
  `🧠 <b>Strategic Response</b><br>Hey {name}, here is your best move stack now:<br>1) {plan0}<br>2) {plan1}<br>3) {plan2}<br>4) {plan3}{goalLine}<br><br>Reply with <i>execute step 1</i>, <i>mode strict</i>, or ask a direct comparison like <i>A vs B</i>.{why}`,
  `🧠 <b>Strategic Response</b><br>{name}, best move stack for right now:<br>1) {plan0}<br>2) {plan1}<br>3) {plan2}<br>4) {plan3}{goalLine}<br><br>Do: <i>execute step 1</i> or ask for <i>A vs B</i>.{why}`,
  `Hey {name}, strategic stack:
1) {plan0}
2) {plan1}
3) {plan2}
4) {plan3}{goalLine}

Reply: execute step 1, mode strict, or ask A vs B.{why}`,
  `{name}, quick high-leverage plan:\n1) {plan0}\n2) {plan1}\n3) {plan2}\n4) {plan3}{goalLine}\n\nDo now: execute step 1. {why}`,
  `🧠 Strategic: {name} — immediate plan:\n• Do now (under 10 min): {plan0}\n• Expected by tonight: {outcomeTonight}\n• Tomorrow checkpoint: {tomorrowCheckpoint}{goalLine}\n\nReply with execute step 1, mode strict, or ask A vs B.{why}`,
  `No fluff — {name}, here is the concise plan:\n1) {plan0}\n2) {plan1}\n3) {plan2}\n4) {plan3}{goalLine}\n\nWhy: {why}\nReply: execute step 1 or ask a comparison.`
];

const AI_STRATEGIC_RESPONSE_POOL = expandAiResponsePool(AI_STRATEGIC_RESPONSE_BASE, { min: AI_RESPONSE_VARIANT_MIN, max: AI_RESPONSE_VARIANT_MAX });

const AI_DETAILED_EMOTION_RESPONSES_BASE = {
  angry: [
    "Pause 60 seconds first: unclench jaw, slow exhale, then do one tiny controlled action: {step}",
    "Channel the anger into structure: 3 deep breaths, water, then {step}",
    "Use anger as signal, not steering wheel: reset body first, then {step}",
    "Fast de-escalation: shoulders down, long exhale, then one focused move: {step}",
    "You need control, not force: calm your body for 1 minute, then {step}",
    "Rage-proof sequence: breathe out longer than in, drink water, then {step}",
    "Protect decisions while angry: wait 2 minutes, then do {step}",
    "Convert intensity into output: start a timer and do {step}",
    "Reset first, act second: 6 breaths, water, then {step}",
    "Keep this clean: no arguing now, just execute {step}",
    "Anger spike protocol: pause, breathe, then take this action: {step}",
    "Do not react yet. Regulate first, then run {step}",
    "Minute 1 calm, minute 2 action: {step}",
    "Ground your body, then ship one win: {step}",
    "Take control quickly: breathing reset, hydration, then {step}"
  ],
  anxious: [
    "Anxiety reset: 4-4-6 breathing for 6 rounds, then {step}",
    "Shrink uncertainty: do one concrete move now -> {step}",
    "When anxious, make scope smaller: {step}",
    "You are safe to go small: breathe, hydrate, then {step}",
    "Stop forecasting everything. Complete this one action: {step}",
    "Nervous system first: long exhale, then {step}",
    "Reduce mental load now: write next step, then execute {step}",
    "Anxiety hates clarity. Give it clarity: {step}",
    "Calm + action pairing: one breath cycle, one sip, then {step}",
    "No overthinking for 10 minutes. Just do {step}",
    "Anchor yourself in one controllable move: {step}",
    "Body calm, task small, momentum on: {step}",
    "Micro-plan now: breathe, water, {step}",
    "Pull attention from fear to execution: {step}",
    "Keep it simple under anxiety: start {step} for 10 minutes"
  ],
  overwhelmed: [
    "Overwhelm protocol: cut scope to one small task -> {step}",
    "Too much at once. Do this only: {step}",
    "Clear overload fast: breathe, pick one lane, run {step}",
    "When overloaded, sequence beats intensity. Start {step}",
    "Single-thread mode: ignore everything else and do {step}",
    "Break the freeze with one simple action: {step}",
    "Reduce pressure by shrinking target: {step}",
    "You do not need full plan now, just {step}",
    "Stabilize first, then act once: {step}",
    "Choose one thing and finish it: {step}",
    "Overwhelm exits through execution. Begin {step}",
    "Your only job for 10 minutes: {step}",
    "Keep the bar low but real: {step}",
    "One clear lane now: {step}",
    "Drop complexity. Run this: {step}"
  ],
  stressed: [
    "Stress reset: 60 seconds breathing, then {step}",
    "Lower stress load with one decisive move: {step}",
    "Stress management now: hydrate, exhale, execute {step}",
    "Treat stress like signal to simplify: {step}",
    "Regulate first, produce second: {step}",
    "Get back in control with this next action: {step}",
    "Fast stress breaker: breathe, water, then {step}",
    "Keep your pace steady: start {step}",
    "Stress gets smaller when action gets clearer: {step}",
    "One focused sprint now: {step}",
    "Use a 10-minute timer and run {step}",
    "Prevent spiral: do {step} immediately",
    "Pressure down, clarity up: execute {step}",
    "Small execution beats stress loops: {step}",
    "Reset body and finish this move: {step}"
  ],
  sad: [
    "Go very gentle: one glass of water, then {step}",
    "Low mood day plan: tiny action first -> {step}",
    "Be kind and concrete: start {step}",
    "No pressure for big wins; do this small win: {step}",
    "Stability before intensity: breathe, then {step}",
    "Mood support through momentum: {step}",
    "Tiny progress is enough right now: {step}",
    "Hold a soft pace and complete {step}",
    "You only need one doable action now: {step}",
    "A small completion can lift mood. Try {step}",
    "Today is about gentle consistency: {step}",
    "Keep the task lightweight: {step}",
    "One calm win now: {step}",
    "Mood first, performance second: do {step}",
    "Stabilize with one micro-action: {step}"
  ],
  drained: [
    "Energy is low, so use micro-steps: {step}",
    "Do the smallest useful version now: {step}",
    "Protect energy: hydrate and run {step}",
    "Low battery mode: 10-minute action -> {step}",
    "Keep effort minimal but real: {step}",
    "You do not need intensity, just consistency: {step}",
    "Recover momentum with a short move: {step}",
    "Exhaustion plan: pause, breathe, then {step}",
    "Use a soft start: {step}",
    "Energy-saving execution: {step}",
    "Do one low-friction action now: {step}",
    "Stabilize and continue gently with {step}",
    "When drained, finish one tiny task: {step}",
    "Pick the easiest win and do it: {step}",
    "Small action, real progress: {step}"
  ],
  positive: [
    "Great momentum. Lock it in with: {step}",
    "Energy is high, convert it now: {step}",
    "Perfect time to stack a win: {step}",
    "Use this motivation while it is hot: {step}",
    "Keep the streak alive with: {step}",
    "Strong state. Make it tangible: {step}",
    "Momentum move: {step}",
    "Capitalize on this energy: {step}",
    "Great vibe. Ship one visible action: {step}",
    "Hold the rhythm and do {step}",
    "Turn motivation into result: {step}",
    "Nice energy. Keep it practical: {step}",
    "Now is the window. Execute {step}",
    "Good state detected. Next move: {step}",
    "Keep the upward trend by doing {step}"
  ],
  neutral: [
    "Quick progress move: {step}",
    "Stable state. Best next action: {step}",
    "Keep it simple and do {step}",
    "One practical step now: {step}",
    "Use this steady state for {step}",
    "Execution now: {step}",
    "Small but meaningful move: {step}",
    "Keep momentum clean: {step}",
    "Action first: {step}",
    "You are ready for this: {step}",
    "Next concrete step: {step}",
    "Stay consistent and do {step}",
    "Use 10 focused minutes on {step}",
    "Low-friction progress: {step}",
    "Best move right now: {step}"
  ]
};

const AI_DETAILED_EMOTION_RESPONSES = Object.fromEntries(
  Object.entries(AI_DETAILED_EMOTION_RESPONSES_BASE).map(([emotion, responses]) => [
    emotion,
    expandAiResponsePool(responses, {
      min: AI_RESPONSE_VARIANT_MIN,
      max: AI_RESPONSE_VARIANT_MAX
    })
  ])
);

function buildEmotionSupportResponse(detailedEmotion, coachingMoves = [], options = {}) {
  const safeEmotion = AI_DETAILED_EMOTION_RESPONSES[detailedEmotion]
    ? detailedEmotion
    : "neutral";
  const topMove = String(coachingMoves?.[0] || "complete one 10-minute tiny win now");
  const template = pickNonRepeatingVariant(AI_DETAILED_EMOTION_RESPONSES[safeEmotion], `emotion_${safeEmotion}`)
    || `Start with this now: ${topMove}`;
  const line = template.replaceAll("{step}", topMove);
  if (options.short) return line;
  return `${line} Reply "next" for the next step.`;
}

function buildDeviceLocalDateReply() {
  const now = new Date();
  const dayName = new Intl.DateTimeFormat(undefined, { weekday: "long" }).format(now);
  const dateLabel = new Intl.DateTimeFormat(undefined, {
    month: "long",
    day: "numeric",
    year: "numeric"
  }).format(now);
  const timeLabel = new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit"
  }).format(now);
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "local timezone";
  return `Today is ${dayName}, ${dateLabel}. Local time is ${timeLabel} (${timezone}).`;
}

function getTimeOfDayGreeting(dateValue = getServerNowDate(), timeZone = userTimeZone) {
  const now = toDateSafe(dateValue) || getServerNowDate();
  let hour = now.getHours();

  try {
    const resolvedTimeZone = String(timeZone || "").trim();
    const formatter = resolvedTimeZone && resolvedTimeZone !== "local"
      ? new Intl.DateTimeFormat("en-US", { hour: "numeric", hour12: false, timeZone: resolvedTimeZone })
      : new Intl.DateTimeFormat("en-US", { hour: "numeric", hour12: false });
    const hourPart = formatter.formatToParts(now).find((part) => part.type === "hour")?.value;
    const parsedHour = Number(hourPart);
    if (Number.isFinite(parsedHour)) hour = parsedHour;
  } catch (_) {
    // Fallback uses Date#getHours above.
  }

  if (hour < 5) return "Good night";
  if (hour < 12) return "Good morning";
  if (hour < 17) return "Good afternoon";
  if (hour < 21) return "Good evening";
  return "Good night";
}

function classifyIntent(input) {
  const msg = normalizeLocalIntentText(input);
  const hasAdviceHistory = Array.isArray(aiSessionState?.lastAdvice) && aiSessionState.lastAdvice.length > 0;

  const intents = [
    { key: "greeting", score: /\b(hi|hello|hey|yo|hola)\b/.test(msg) ? 0.95 : 0 },
    { key: "smalltalk-casual", score: /\b(lol|lmao|rofl|ikr|fr|frfr|omg|sup|wassup|wsg|bro|bruh|brb|ttyl|rn|haha+|hehe+)\b/.test(msg) ? 0.965 : 0 },
    { key: "bored", score: /\b(i\s*am\s*)?bored\b|nothing\s+to\s+do|boring|i do not know\s+what\s+to\s+do/.test(msg) ? 0.97 : 0 },
    { key: "celebrate", score: /\b(yay+|woo+|let'?s\s+go|nice+|awesome+)\b/.test(msg) ? 0.955 : 0 },
    { key: "smalltalk-health", score: /\b(how are you|how are u|how's it going|how you doing|how r you|hru)\b/.test(msg) ? 0.98 : 0 },
    { key: "smalltalk-activity", score: /\b(what are you doing|what are u doing|wyd|wyd rn|what you doing|what you up to)\b/.test(msg) ? 0.97 : 0 },
    {
      key: "date-local",
      score: /\b(what(?:'s| is)\s+(?:the\s+)?(?:day|date|time)(?:\s+is)?(?:\s+it)?(?:\s+today)?|what\s+day\s+is\s+it|what\s+date\s+is\s+it|what\s+time\s+is\s+it|today(?:'s)?\s+(?:day|date)|which\s+(?:day|date)\s+is\s+it|day\s*\/\s*date\b)\b/.test(msg)
        ? 0.995
        : 0
    },
    { key: "emotional-personal", score: /\b(i feel|i am feeling|feeling very|feeling really)\b.*\b(stuck|low|sad|angry|frustrated|lonely|empty|hopeless|scared|anxious|overwhelmed|lost|confused|unmotivated|drained)\b/.test(msg) ? 0.985 : 0 },
    { key: "identity", score: /who are you|what are you|your name|are you ai|are you real/.test(msg) ? 0.94 : 0 },
    { key: "analysis", score: /analyze|analysis|report|conclude|insight|summary|score|pattern|patterns|trend/.test(msg) ? 0.93 : 0 },
    { key: "plan", score: /plan|routine|today|schedule|what should i do/.test(msg) ? 0.92 : 0 },
    { key: "decision", score: /decide|choose|which should i|best option|priority|first/.test(msg) ? 0.925 : 0 },
    { key: "why", score: /why|reason|because|explain|what caused/.test(msg) ? 0.915 : 0 },
    { key: "optimize", score: /optimize|improve faster|maximize|best strategy|upgrade/.test(msg) ? 0.905 : 0 },
    { key: "stress", score: /stress|anxious|anxiety|overwhelm|panic|sad|depressed|down/.test(msg) ? 0.91 : 0 },
    { key: "sleep", score: /sleep|tired|exhausted|fatigue|insomnia/.test(msg) ? 0.9 : 0 },
    { key: "water", score: /water|hydrate|hydration|thirsty/.test(msg) ? 0.89 : 0 },
    { key: "productivity", score: /task|focus|productivity|procrastin|work|study/.test(msg) ? 0.88 : 0 },
    { key: "gratitude", score: /gratitude|thankful|grateful/.test(msg) ? 0.87 : 0 },
    { key: "capabilities", score: /help|what can you do|features|assist|commands/.test(msg) ? 0.86 : 0 },
    { key: "followup", score: /\b(and then|then what|what next|next step|continue|go deeper|do it|that one|same one|next one|step\s*\d+|option\s*\d+|yes|sure|okay|ok)\b/.test(msg) ? 0.9 : 0 },
    { key: "joke", score: /\b(joke|make me laugh|funny)\b/.test(msg) ? 0.84 : 0 },
    {
      key: "thanks",
      score: (() => {
        const hasThanks = /\b(thanks+|thank\s+you|thx|ty|tysm|appreciate(?:\s+it|\s+you)?)\b/.test(msg);
        if (!hasThanks) return 0;
        const tokenCount = tokenizeText(msg).length;
        return tokenCount <= 10 ? 0.99 : 0.9;
      })()
    },
    { key: "bye", score: /\b(bye|goodbye|see you|cya|gn|good night)\b/.test(msg) ? 0.82 : 0 }
  ].map((entry) => {
    const templateScore = getTemplateIntentScore(msg, entry.key);
    let boostedScore = Math.min(0.995, entry.score + (templateScore * 0.35));

    if (entry.key === "followup" && hasAdviceHistory) {
      const tokenCount = tokenizeText(msg).length;
      if (tokenCount <= 7 && /\b(do it|that|same|next|continue|step|option|yes|sure|ok|okay)\b/.test(msg)) {
        boostedScore = Math.max(boostedScore, 0.975);
      }
    }

    return { ...entry, score: boostedScore };
  });

  const sorted = intents.sort((a, b) => b.score - a.score);
  const best = sorted[0];
  const second = sorted[1] || { key: "fallback", score: 0 };
  if (!best || best.score < 0.5) {
    return {
      key: "fallback",
      confidence: 0,
      secondaryKey: second.key || "fallback",
      secondaryConfidence: Number(second.score) || 0,
      ambiguous: true
    };
  }

  const confidenceGap = Number(best.score) - Number(second.score || 0);
  const ambiguous = best.key !== "followup"
    && best.score < AI_CLARIFY_INTENT_THRESHOLD
    && confidenceGap < 0.08;

  return {
    key: best.key,
    confidence: best.score,
    secondaryKey: second.key || "fallback",
    secondaryConfidence: Number(second.score) || 0,
    ambiguous
  };
}

function getIntentLabel(intentKey) {
  const labels = {
    greeting: "chat",
    "smalltalk-casual": "casual chat",
    "smalltalk-health": "status check",
    "smalltalk-activity": "status check",
    "date-local": "date/time",
    bored: "anti-bored ideas",
    celebrate: "motivation",
    "emotional-personal": "emotional support",
    analysis: "quick analysis",
    plan: "quick plan",
    decision: "decision help",
    why: "explain why",
    optimize: "optimization",
    stress: "stress reset",
    sleep: "sleep help",
    water: "water help",
    productivity: "productivity",
    gratitude: "gratitude",
    capabilities: "commands",
    followup: "follow-up",
    joke: "joke",
    thanks: "reply",
    bye: "sign off",
    fallback: "quick help"
  };
  return labels[intentKey] || "quick help";
}

function shouldAskIntentClarification(intentInfo, rawInput) {
  if (!AI_CASUAL_MODE) return false;
  if (!intentInfo) return true;
  const text = normalizeLocalIntentText(rawInput);
  if (!text) return false;

  if (intentInfo.key === "fallback") return true;
  if (!intentInfo.ambiguous) return false;

  const tokenCount = tokenizeText(text).length;
  if (tokenCount > 16) return false;
  if (/\b(help|what can you do|commands)\b/.test(text)) return false;
  return true;
}

function buildIntentClarificationMessage(intentInfo) {
  const first = getIntentLabel(intentInfo?.key || "fallback");
  const second = getIntentLabel(intentInfo?.secondaryKey || "plan");
  return `Want quick help with ${first} or ${second}? You can also ask directly like: \"make me a plan\", \"log mood happy\", or \"set reminder call mom in 20 min\".`;
}

function buildAdaptiveTone(userEmotion, turnCount) {
  if (userEmotion === "low") return "supportive";
  if (turnCount > 8) return "compact";
  return "energetic";
}

function getAiModePreset() {
  return AI_MODE_PRESETS[aiReasoningMode] || AI_MODE_PRESETS.balanced;
}

function setAiMode(nextMode) {
  const normalized = String(nextMode || "").toLowerCase().trim();
  if (!AI_MODE_PRESETS[normalized]) return false;
  aiReasoningMode = normalized;
  return true;
}

function parseModeFromInput(input) {
  const match = String(input || "").toLowerCase().match(/(?:mode|style)\s*(?:to)?\s*(ultra|balanced|coach|strict|creative)/);
  return match?.[1] || null;
}

function getMemorySummary() {
  const safeName = sanitizeAiAddressName(aiSessionState.userFacts.name, "");
  const { goal, likes, dislikes } = aiSessionState.userFacts;
  const lines = [];
  if (safeName) lines.push(`Name: ${safeName}`);
  if (goal) lines.push(`Goal: ${goal}`);
  if (likes.length) lines.push(`Likes: ${likes.slice(-3).join(", ")}`);
  if (dislikes.length) lines.push(`Dislikes: ${dislikes.slice(-3).join(", ")}`);
  if (!lines.length) return "No remembered user facts yet.";
  return lines.join(" | ");
}

function parseCompareRequest(input) {
  const text = String(input || "").trim();
  const versusMatch = text.match(/(.+?)\s+(?:vs|versus|or)\s+(.+)/i);
  if (!versusMatch) return null;
  const left = versusMatch[1].replace(/^(compare|difference between|choose between)\s+/i, "").trim();
  const right = versusMatch[2].trim();
  if (!left || !right) return null;
  if (left.length > 60 || right.length > 60) return null;
  return { left, right };
}

function buildComparisonResponse(left, right, snapshot) {
  const remainingWater = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
  const hydrationClause = snapshot.hasWaterGoal
    ? (remainingWater > 0
      ? `(${remainingWater} cup${remainingWater === 1 ? "" : "s"} left today)`
      : "and maintain hydration")
    : "and set a water goal when ready";
  return {
    summary: `If your priority is fast execution today, choose the option with lower setup friction right now.`,
    prosLeft: [
      `${left} may be easier to start immediately.`,
      `${left} can create quicker momentum if you’re low on energy.`,
      `${left} likely has lower cognitive overhead.`
    ],
    prosRight: [
      `${right} may provide stronger long-term upside.`,
      `${right} can improve skill depth if sustained consistently.`,
      `${right} might align better if your energy is high right now.`
    ],
    decisionRule: `Decision rule: pick the option you can start in <10 minutes, then hydrate ${hydrationClause}.`
  };
}

function buildModeAwarePrefix(tone) {
  const preset = getAiModePreset();
  if (preset.style === "strict") return "Direct answer: ";
  if (preset.style === "coach") return "Coach mode: ";
  if (preset.style === "creative") return "Creative mode: ";
  if (preset.style === "ultra") return "Focused mode: ";
  if (tone === "supportive") return "I’m with you. ";
  if (tone === "compact") return "Quick answer: ";
  return "Let’s go: ";
}

function getRequestedAdviceIndex(inputText, adviceLength) {
  const text = normalizeLocalIntentText(inputText);
  if (!adviceLength || adviceLength <= 0) return 0;

  const numbered = text.match(/(?:step|option|point|number|#)\s*(\d+)/i);
  if (numbered?.[1]) {
    const index = Math.max(0, Math.min(adviceLength - 1, Number(numbered[1]) - 1));
    return Number.isFinite(index) ? index : 0;
  }

  if (/\b(last|final)\b/.test(text)) return adviceLength - 1;
  if (/\b(next|another)\b/.test(text)) return Math.min(adviceLength - 1, 1);
  if (/\b(second|2nd)\b/.test(text)) return Math.min(adviceLength - 1, 1);
  if (/\b(third|3rd)\b/.test(text)) return Math.min(adviceLength - 1, 2);
  return 0;
}

function buildLocalFollowupResponse(inputText) {
  const advice = Array.isArray(aiSessionState.lastAdvice) ? aiSessionState.lastAdvice.filter(Boolean) : [];
  if (!advice.length) return null;

  const text = normalizeLocalIntentText(inputText);
  const hasFollowupCue = /\b(do it|do this|that one|same one|next|continue|go on|step|option|yes|sure|okay|ok)\b/.test(text);
  if (!hasFollowupCue) return null;

  const selectedIndex = getRequestedAdviceIndex(text, advice.length);
  const selected = String(advice[selectedIndex] || advice[0] || "").trim();
  if (!selected) return null;

  const total = advice.length;
  return {
    lastIntent: "followup",
    advice,
    response: `Nice, let’s do this now: ${selected}${total > 1 ? ` (step ${selectedIndex + 1}/${total})` : ""}`,
    isHtml: false
  };
}

function buildCasualAiResponse(context) {
  const {
    input,
    msg,
    intent,
    emotion,
    name,
    greeting,
    snapshot,
    coachingMoves,
    deepPlan,
    trendSignals,
    priorityBoard,
    sleepMoodInsight,
    behaviorPatterns,
    knowledgeAnswer,
    compareRequest,
    mathResult
  } = context;

  const waterLeft = Math.max(0, (Number(snapshot.todayGoal) || 0) - (Number(snapshot.waterToday) || 0));
  const pending = Number(snapshot.pendingTasks) || 0;
  const hydration = buildHydrationPaceInsight(snapshot);
  const followupFromHistory = buildLocalFollowupResponse(input);

  if (mathResult) {
    return {
      lastIntent: "math",
      advice: coachingMoves.slice(0, 1),
      response: `${mathResult.expression} = ${mathResult.result} 🧮`,
      isHtml: false
    };
  }

  if (compareRequest) {
    return {
      lastIntent: "compare",
      advice: ["Pick the option you can start in under 10 minutes."],
      response: `Quick take: ${compareRequest.left} vs ${compareRequest.right} -> pick whichever you can start in under 10 min. If both are equal, go with ${compareRequest.right}.`,
      isHtml: false
    };
  }

  const key = intent?.key || "fallback";

  switch (key) {
    case "greeting":
      {
        // Prefer a full greeting template from the full pool; fallback to single-word pool
        const fullTpl = pickNonRepeatingVariant(AI_GREETING_FULL_POOL, 'greeting_full');
        if (fullTpl) {
          const timeOfDay = getTimeOfDayGreeting();
          const waterStatus = getAiWaterStatusText(snapshot);
          const filled = String(fullTpl || "")
            .replaceAll('{name}', escapeHtml(name))
            .replaceAll('{score}', String(Number(snapshot.score) || 0))
            .replaceAll('{pending}', String(Number(pending) || 0))
            .replaceAll('{waterStatus}', escapeHtml(waterStatus))
            .replaceAll('{timeOfDay}', escapeHtml(timeOfDay));
          return { lastIntent: key, advice: coachingMoves.slice(0, 2), response: filled, isHtml: false };
        }

        const greetStart = pickNonRepeatingVariant(AI_GREETING_POOL, 'greeting') || greeting || "Hey";
        return {
          lastIntent: key,
          advice: coachingMoves.slice(0, 2),
          response: `${greetStart}, ${name} 👋 You are at ${snapshot.score}/100. ${pending} task${pending === 1 ? "" : "s"} left, and ${getAiWaterStatusText(snapshot)}. Want a quick 3-step plan?`,
          isHtml: false
        };
      }
    case "smalltalk-health":
      return {
        lastIntent: key,
        response: `I am doing good tbh 😄 Just vibing here and tracking your dashboard. You are at ${snapshot.score}/100 right now.`,
        isHtml: false
      };
    case "smalltalk-activity":
      return {
        lastIntent: key,
        response: `Just hanging with your stats rn - tasks ${snapshot.doneTasks}/${snapshot.totalTasks}, ${getAiWaterStatusText(snapshot)}, sleep ${snapshot.sleepToday || 0}h.`,
        isHtml: false
      };
    case "date-local":
      return {
        lastIntent: key,
        response: `${buildDeviceLocalDateReply()} (Using your device local clock.)`,
        isHtml: false
      };
    case "smalltalk-casual":
      if (/\bbrb|ttyl\b/.test(msg)) {
        return { lastIntent: key, response: `Bet, catch you in a bit 👋`, isHtml: false };
      }
      if (aiSessionState.lastIntent === "date-local" && /\b(i know right|ikr|right)\b/.test(msg)) {
        return { lastIntent: key, response: `Yep, exactly 😄`, isHtml: false };
      }
      if (/\bsup|wassup|wsg\b/.test(msg)) {
        return { lastIntent: key, response: `yooo ${name} 😄 all good here. wanna do a quick best move now?`, isHtml: false };
      }
      if (/\bikr|fr|frfr|lol|lmao\b/.test(msg)) {
        return { lastIntent: key, advice: coachingMoves.slice(0, 1), response: `fr 😌 wanna turn that into momentum? do this now: ${coachingMoves[0]}`, isHtml: false };
      }
      return { lastIntent: key, response: `yep 😎 what vibe are we on - chill check-in or quick action plan?`, isHtml: false };
    case "thanks":
      {
        const pick = pickNonRepeatingVariant(AI_SHORT_THANKS_REPLIES, "thanks_short") || "Anytime.";
        return { lastIntent: key, advice: coachingMoves.slice(0, 1), response: pick, isHtml: false };
      }
    case "bye":
      return { lastIntent: key, response: `cool, see ya ${name} 👋`, isHtml: false };
    case "joke":
      return { lastIntent: key, response: `why was the task calm? because it took things one checkbox at a time 😄`, isHtml: false };
    case "bored":
      return {
        lastIntent: key,
        advice: coachingMoves.slice(0, 3),
        response: `Bored mode fix:<br>1) ${coachingMoves[0]}<br>2) ${coachingMoves[1]}<br>3) ${coachingMoves[2]}<br><br>Say "do step 1" and I got you.`,
        isHtml: true
      };
    case "celebrate":
      return {
        lastIntent: key,
        advice: coachingMoves.slice(0, 2),
        response: `let's gooo 🔥 keep it rolling with this: ${coachingMoves[0]}`,
        isHtml: false
      };
    case "emotional-personal":
    case "stress":
      return {
        lastIntent: key,
        advice: ["6 slow breaths", "one glass of water", "10-minute tiny win"],
        response: buildEmotionSupportResponse(detectDetailedEmotionFromText(msg), coachingMoves, { short: true }),
        isHtml: false
      };
    case "analysis":
      {
        const patternLines = Array.isArray(behaviorPatterns?.summaryLines)
          ? behaviorPatterns.summaryLines.slice(0, 2)
          : [];
        const sleepMoodLine = patternLines.length
          ? `<br>• ${escapeHtml(patternLines.join(" "))}`
          : (sleepMoodInsight ? `<br>• pattern: mood tends to dip when sleep is under ${sleepMoodInsight.thresholdLabel}h` : "");
      return {
        lastIntent: key,
        advice: priorityBoard.slice(0, 3).map((entry) => entry.action),
        response: `Quick read:<br>• score ${snapshot.score}/100<br>• tasks ${snapshot.doneTasks}/${snapshot.totalTasks}<br>• water ${snapshot.waterToday}/${snapshot.todayGoal}<br>• hydration pace: ${escapeHtml(hydration.summary)}<br>• sleep ${snapshot.sleepToday || 0}h${sleepMoodLine}<br><br>Best move rn: ${priorityBoard[0].action}`,
        isHtml: true
      };
      }
    case "decision":
      return {
        lastIntent: key,
        advice: priorityBoard.slice(0, 3).map((entry) => entry.action),
        response: `Honestly, do this first: ${priorityBoard[0].action}`,
        isHtml: false
      };
    case "why": {
      const firstPattern = Array.isArray(behaviorPatterns?.summaryLines) ? behaviorPatterns.summaryLines[0] : "";
      const reasonBits = [];
      if (firstPattern) reasonBits.push(firstPattern);
      if (sleepMoodInsight) reasonBits.push(`mood tends to dip under ${sleepMoodInsight.thresholdLabel}h sleep`);
      if (trendSignals.taskDelta < 0) reasonBits.push("tasks dipped recently");
      if (trendSignals.sleepDelta < 0) reasonBits.push("sleep trend dipped");
      if (trendSignals.waterDelta < 0) reasonBits.push("hydration slipped");
      if (!reasonBits.length) reasonBits.push("your pattern is mostly stable");
      return {
        lastIntent: key,
        advice: coachingMoves.slice(0, 1),
        response: `Quick why: ${reasonBits.slice(0, 2).join(" + ")}. Best next move: ${coachingMoves[0]}`,
        isHtml: false
      };
    }
    case "optimize":
    case "plan":
    case "followup":
      if (followupFromHistory) {
        return followupFromHistory;
      }
      return {
        lastIntent: key,
        advice: deepPlan.slice(0, 3),
        response: `Easy plan:<br>1) ${deepPlan[0]}<br>2) ${deepPlan[1]}<br>3) ${deepPlan[2]}<br><br>Want me to keep it even shorter?`,
        isHtml: true
      };
    case "sleep":
      {
        const sleepPattern = behaviorPatterns?.sleepMood;
        const thresholdLabel = sleepPattern?.threshold
          ? (Number.isInteger(sleepPattern.threshold) ? String(sleepPattern.threshold) : String(sleepPattern.threshold).replace(/\.0$/, ""))
          : "";
        const patternHint = thresholdLabel
          ? ` Pattern: mood tends to drop when sleep is below ${thresholdLabel}h.`
          : (sleepMoodInsight ? ` Also, your logs suggest mood usually drops under ${sleepMoodInsight.thresholdLabel}h.` : "");
      return {
        lastIntent: key,
        response: `Sleep analysis: keep low light 1 hour pre-bed, avoid doomscrolling in bed, and cut caffeine after 2 PM.${patternHint}`,
        isHtml: false
      };
      }
    case "water":
      return {
        lastIntent: key,
        response: `Hydration check 💧 ${hydration.summary} You are at ${snapshot.waterToday}/${snapshot.todayGoal}, left ${waterLeft}. Want me to set reminders?`,
        isHtml: false
      };
    case "productivity":
      {
        const productivityPattern = behaviorPatterns?.sleepProductivity;
        const thresholdLabel = productivityPattern?.threshold
          ? (Number.isInteger(productivityPattern.threshold) ? String(productivityPattern.threshold) : String(productivityPattern.threshold).replace(/\.0$/, ""))
          : "";
        const productivityHint = thresholdLabel && Number(productivityPattern?.diff) >= 0
          ? ` Your pattern says productivity improves at ${thresholdLabel}h+ sleep.`
          : "";
      return {
        lastIntent: key,
        response: `Focus move: pick one task, 25 min sprint, 5 min break.${productivityHint}`,
        isHtml: false
      };
      }
    case "gratitude":
      return {
        lastIntent: key,
        response: `Drop one line: "today i am grateful for ..." and I can save it for you 🙏`,
        isHtml: false
      };
    case "identity":
      return {
        lastIntent: key,
        response: "I am NovaFix AI. I can help you plan, log, and stay on track.",
        isHtml: false
      };
    case "capabilities":
      return {
        lastIntent: key,
        response: "I can help with tasks, water, mood, sleep, reminders, and quick app actions. Tell me what to do in one line.",
        isHtml: false
      };
    default:
      if (followupFromHistory) {
        return followupFromHistory;
      }
      if (knowledgeAnswer) {
        return {
          lastIntent: "knowledge",
          advice: coachingMoves.slice(0, 1),
          response: `${knowledgeAnswer} Quick move for you now: ${coachingMoves[0]}`,
          isHtml: false
        };
      }
      if (emotion === "low") {
        return {
          lastIntent: "emotional-support",
          advice: coachingMoves.slice(0, 1),
          response: `hey, be kind to yourself for a sec. tiny step now: ${coachingMoves[0]}`,
          isHtml: false
        };
      }
      return {
        lastIntent: "fallback",
        advice: coachingMoves.slice(0, 2),
        response: `Got you 😌 quick move right now: ${coachingMoves[0]}`,
        isHtml: false
      };
  }
}

function buildUltraFallback(snapshot, name) {
  const plan = buildDeepPlan(snapshot);
  const goalLine = aiSessionState.userFacts.goal
    ? `<br>🎯 Goal alignment: <i>${escapeHtml(aiSessionState.userFacts.goal)}</i>`
    : "";
  const tpl = pickNonRepeatingVariant(AI_STRATEGIC_RESPONSE_POOL, 'strategic_fallback') || "🧠 <b>Strategic Response</b><br>Hey {name}, here is your best move stack now:<br>1) {plan0}<br>2) {plan1}<br>3) {plan2}<br>4) {plan3}{goalLine}<br><br>Reply with <i>execute step 1</i>, <i>mode strict</i>, or ask a direct comparison like <i>A vs B</i>.";
  return tpl
    .replaceAll('{name}', escapeHtml(name))
    .replaceAll('{plan0}', escapeHtml(plan[0] || ''))
    .replaceAll('{plan1}', escapeHtml(plan[1] || ''))
    .replaceAll('{plan2}', escapeHtml(plan[2] || ''))
    .replaceAll('{plan3}', escapeHtml(plan[3] || ''))
    .replaceAll('{goalLine}', goalLine)
    .replaceAll('{outcomeTonight}', escapeHtml(buildImmediateBenefitOutcome(snapshot, plan[0]) || ''))
    .replaceAll('{tomorrowCheckpoint}', escapeHtml(buildTomorrowCheckpoint(snapshot) || ''))
    .replaceAll('{why}', buildWhySuggestionLine(true, tpl));
}

function buildKnowledgeAnswer(input) {
  const text = normalizeLocalIntentText(String(input || ""));
  const knowledge = [
    {
      topic: "sleep",
      triggers: ["sleep", "insomnia", "tired", "fatigue", "bed"],
      answer: "For better sleep: keep a fixed sleep window, reduce bright light 60 minutes before bed, avoid caffeine after afternoon, and use a short wind-down ritual (breathing + low-stimulation activity)."
    },
    {
      topic: "focus",
      triggers: ["focus", "procrastination", "deep work", "study", "work"],
      answer: "Use the 25-5 cycle: define one outcome, remove distractions, sprint 25 minutes, then 5-minute reset. Repeat 2-3 rounds before checking messages."
    },
    {
      topic: "stress",
      triggers: ["stress", "anxiety", "panic", "overwhelmed"],
      answer: "When stressed, reduce physiological load first: long exhale breathing, hydration, and one very small actionable step. Momentum usually lowers anxiety faster than overthinking."
    },
    {
      topic: "hydration",
      triggers: ["water", "hydration", "dehydrated", "thirsty"],
      answer: "Hydration works best with timing: one glass after waking, one with each meal, and one before evening wind-down. Small consistent doses beat large late intake."
    },
    {
      topic: "habits",
      triggers: ["habit", "consistency", "discipline", "routine"],
      answer: "Build habits with tiny minimums: define a trigger, make the action small, and track daily completion. Consistency compounds faster than intensity."
    },
    {
      topic: "decision",
      triggers: ["decide", "decision", "choose", "which is better", "priority"],
      answer: "Use this decision filter: choose the option you can start in under 10 minutes, has visible progress in 25 minutes, and aligns with your top goal."
    },
    {
      topic: "planning",
      triggers: ["plan", "schedule", "roadmap", "organize", "what should i do"],
      answer: "Strong plans are sequence-first: one priority task, one health action (water or movement), one closure action (reflection or gratitude). Keep each block time-bound."
    },
    {
      topic: "burnout",
      triggers: ["burnout", "drained", "exhausted", "no energy", "crash"],
      answer: "For burnout signals, lower pressure first: stabilize with breathing and hydration, then complete one tiny, clear task to restore control before taking on complex work."
    }
  ];

  const scored = knowledge
    .map((entry) => {
      const triggerScore = entry.triggers.reduce((score, trigger) => {
        const escaped = trigger.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const regex = new RegExp(`\\b${escaped}\\b`, "i");
        return score + (regex.test(text) ? 1.15 : 0);
      }, 0);
      const similarity = jaccardSimilarity(text, `${entry.topic} ${entry.triggers.join(" ")}`);
      const conversationalBoost = /\b(explain|help|advice|tips|guide|best way|how to)\b/.test(text) ? 0.2 : 0;
      return { ...entry, score: triggerScore + similarity + conversationalBoost };
    })
    .sort((a, b) => b.score - a.score);

  if (!scored[0] || scored[0].score < 0.6) return null;

  const topMatches = scored.filter((entry) => entry.score >= 0.9).slice(0, 2);
  const selected = topMatches.length ? topMatches : [scored[0]];
  selected.forEach((entry) => pushTopicHistory(entry.topic));

  if (selected.length === 1) return selected[0].answer;
  return `${selected[0].answer} Also, ${selected[1].answer.charAt(0).toLowerCase()}${selected[1].answer.slice(1)}`;
}

function isAppComplaintMessage(input) {
  const text = normalizeLocalIntentText(String(input || ""));
  if (!text) return false;

  const complaintWords = /\b(?:bug|issue|problem|glitch|broken|bad|ugly|trash|garbage|mess|awful|horrible|terrible|stupid|useless|weird)\b/;
  const appWords = /\b(?:app|ui|interface|screen|layout|design|dashboard|site|page|thing|that|this)\b/;

  if (/^what\s+(?:is|'s)?\s+this\s+(?:app|ui|interface|screen|layout|design|dashboard|site|page|thing|that)\b/.test(text)) {
    return true;
  }

  if (/\bwhat\s+(?:is|'s)?\s+this\b/.test(text) && /\b(?:app|ui|interface|screen|layout|design|dashboard|site|page)\b/.test(text)) {
    return true;
  }

  return complaintWords.test(text) && appWords.test(text);
}

function buildActionCoaching(snapshot) {
  const actions = [];
  const hydration = buildHydrationPaceInsight(snapshot);
  if (snapshot.pendingTasks > 0) actions.push("Pick 1 pending task and do a focused 25-minute sprint.");
  if (snapshot.waterToday < snapshot.todayGoal) {
    const left = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
    if (hydration.onTrack) {
      actions.push(`Hydration pace is okay (${hydration.logged}/${hydration.goal} cups). Log ${Math.max(1, Math.ceil(left))} cup${Math.max(1, Math.ceil(left)) === 1 ? "" : "s"} to stay ahead.`);
    } else {
      actions.push(`${hydration.summary} Log ${Math.max(1, Math.ceil(left))} cup${Math.max(1, Math.ceil(left)) === 1 ? "" : "s"} now.`);
    }
  }
  if (snapshot.sleepToday < 7) actions.push("Plan an earlier wind-down to target 7–8 hours sleep.");
  if (!snapshot.gratitudeToday) actions.push("Write one gratitude line before bed.");
  if (!snapshot.moodToday) actions.push("Log your mood to improve your daily insights.");
  while (actions.length < 3) actions.push("Keep momentum with one small healthy action right now.");
  return actions.slice(0, 3);
}

function buildDeepPlan(snapshot) {
  const waterLeft = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
  return [
    snapshot.pendingTasks > 0
      ? "Block 1 (0-25 min): close one pending task with single-task focus."
      : "Block 1 (0-25 min): define and start one meaningful task.",
    waterLeft > 0
      ? `Block 2 (25-35 min): drink ${Math.max(1, waterLeft)} glass(es) and reset posture/breathing.`
      : "Block 2 (25-35 min): movement + posture reset.",
    snapshot.sleepToday < 7
      ? "Block 3 (35-50 min): finish priority work and set a wind-down reminder."
      : "Block 3 (35-50 min): second deep-focus sprint.",
    snapshot.gratitudeToday
      ? "Block 4 (50-60 min): quick reflection and tomorrow’s first action."
      : "Block 4 (50-60 min): write one gratitude line and set tomorrow’s first action."
  ];
}

function safeAvg(numbers) {
  const source = Array.isArray(numbers) ? numbers.filter((value) => Number.isFinite(Number(value))) : [];
  if (!source.length) return 0;
  return source.reduce((sum, value) => sum + Number(value), 0) / source.length;
}

function getRecentDayKeys(totalDays = 30) {
  const days = Math.max(7, Math.min(120, Number(totalDays) || 30));
  const todayDate = dateKeyToDate(getTodayKey()) || getServerNowDate();
  todayDate.setUTCHours(0, 0, 0, 0);

  const dayKeys = [];
  for (let offset = days - 1; offset >= 0; offset -= 1) {
    const day = new Date(todayDate);
    day.setUTCDate(todayDate.getUTCDate() - offset);
    const key = dateToKey(day);
    if (key) dayKeys.push(key);
  }
  return dayKeys;
}

function buildSleepMoodPatternInsight(maxDays = 30) {
  const dayKeys = getRecentDayKeys(maxDays);
  if (!dayKeys.length) return null;
  const daySet = new Set(dayKeys);

  const moodBuckets = new Map();
  moodHistory.forEach((entry, index) => {
    const key = dateToKey(moodDates[index]);
    if (!key || !daySet.has(key)) return;
    const score = moodToScore(entry);
    if (!score) return;
    const bucket = moodBuckets.get(key) || { sum: 0, count: 0 };
    bucket.sum += score;
    bucket.count += 1;
    moodBuckets.set(key, bucket);
  });

  const sleepByDay = new Map();
  sleepHistory.forEach((entry, index) => {
    const key = dateToKey(sleepDates[index]);
    if (!key || !daySet.has(key)) return;
    sleepByDay.set(key, Number(entry) || 0);
  });

  const pairs = dayKeys
    .filter((key) => sleepByDay.has(key) && moodBuckets.has(key))
    .map((key) => {
      const bucket = moodBuckets.get(key);
      const moodAvg = bucket && bucket.count ? bucket.sum / bucket.count : 0;
      return {
        key,
        sleep: Number(sleepByDay.get(key)) || 0,
        mood: Number(moodAvg) || 0
      };
    })
    .filter((entry) => entry.mood > 0);

  if (pairs.length < 5) return null;

  const thresholds = [5.5, 6, 6.5, 7, 7.5, 8];
  let best = null;

  thresholds.forEach((threshold) => {
    const lowMoods = pairs.filter((pair) => pair.sleep < threshold).map((pair) => pair.mood);
    const highMoods = pairs.filter((pair) => pair.sleep >= threshold).map((pair) => pair.mood);
    if (lowMoods.length < 2 || highMoods.length < 2) return;

    const lowAvg = safeAvg(lowMoods);
    const highAvg = safeAvg(highMoods);
    const diff = highAvg - lowAvg;
    const supportBalance = Math.min(lowMoods.length, highMoods.length) / pairs.length;
    const signalScore = diff + (supportBalance * 0.35);

    if (!best || signalScore > best.signalScore) {
      best = {
        threshold,
        lowAvg,
        highAvg,
        diff,
        lowCount: lowMoods.length,
        highCount: highMoods.length,
        pairCount: pairs.length,
        signalScore
      };
    }
  });

  if (!best || best.diff < 0.18) return null;

  const thresholdLabel = Number.isInteger(best.threshold)
    ? String(best.threshold)
    : best.threshold.toFixed(1).replace(/\.0$/, "");

  return {
    threshold: best.threshold,
    thresholdLabel,
    pairCount: best.pairCount,
    lowAvg: best.lowAvg,
    highAvg: best.highAvg,
    diff: best.diff,
    summary: `Your mood tends to drop when sleep is below ${thresholdLabel}h (avg mood ${best.lowAvg.toFixed(2)} below vs ${best.highAvg.toFixed(2)} at/above, based on ${best.pairCount} matched days).`,
    shortSummary: `Mood usually dips when sleep is under ${thresholdLabel}h.`
  };
}

function buildPatternMetricMaps(maxDays = 30) {
  const dayKeys = getRecentDayKeys(maxDays);
  const daySet = new Set(dayKeys);
  const moodByDay = buildMoodAverageByDayMap(daySet);

  const sleepByDay = new Map();
  sleepHistory.forEach((entry, index) => {
    const key = dateToKey(sleepDates[index]);
    if (!key || !daySet.has(key)) return;
    sleepByDay.set(key, Number(entry) || 0);
  });

  const waterByDay = new Map();
  waterHistory.forEach((entry, index) => {
    const key = dateToKey(waterDates[index]);
    if (!key || !daySet.has(key)) return;
    waterByDay.set(key, (waterByDay.get(key) || 0) + (Number(entry) || 0));
  });

  const tasksDoneByDay = new Map();
  taskEntries.forEach((entry) => {
    if (!entry?.completed) return;
    const key = dateToKey(entry.completedAt || entry.time);
    if (!key || !daySet.has(key)) return;
    tasksDoneByDay.set(key, (tasksDoneByDay.get(key) || 0) + 1);
  });

  return {
    dayKeys,
    moodByDay,
    sleepByDay,
    waterByDay,
    tasksDoneByDay
  };
}

function findBestThresholdSplit(entries, thresholds, minPerSide = 2) {
  if (!Array.isArray(entries) || entries.length < (minPerSide * 2)) return null;
  let best = null;

  thresholds.forEach((threshold) => {
    const low = entries.filter((entry) => Number(entry.x) < threshold).map((entry) => Number(entry.y) || 0);
    const high = entries.filter((entry) => Number(entry.x) >= threshold).map((entry) => Number(entry.y) || 0);
    if (low.length < minPerSide || high.length < minPerSide) return;

    const lowAvg = safeAvg(low);
    const highAvg = safeAvg(high);
    const diff = highAvg - lowAvg;
    const support = Math.min(low.length, high.length) / entries.length;
    const score = Math.abs(diff) * (1 + support);

    if (!best || score > best.score) {
      best = {
        threshold,
        lowAvg,
        highAvg,
        diff,
        lowCount: low.length,
        highCount: high.length,
        total: entries.length,
        score
      };
    }
  });

  return best;
}

function buildBehaviorPatternMemoryFromLocal(maxDays = 30) {
  const { dayKeys, moodByDay, sleepByDay, waterByDay, tasksDoneByDay } = buildPatternMetricMaps(maxDays);
  const activeDays = dayKeys.filter((key) => {
    return moodByDay.has(key) || sleepByDay.has(key) || waterByDay.has(key) || tasksDoneByDay.has(key);
  }).length;

  const sleepMoodPairs = dayKeys
    .filter((key) => sleepByDay.has(key) && moodByDay.has(key))
    .map((key) => ({ x: Number(sleepByDay.get(key)) || 0, y: Number(moodByDay.get(key)) || 0 }));
  const waterMoodPairs = dayKeys
    .filter((key) => waterByDay.has(key) && moodByDay.has(key))
    .map((key) => ({ x: Number(waterByDay.get(key)) || 0, y: Number(moodByDay.get(key)) || 0 }));
  const sleepTaskPairs = dayKeys
    .filter((key) => sleepByDay.has(key) && tasksDoneByDay.has(key))
    .map((key) => ({ x: Number(sleepByDay.get(key)) || 0, y: Number(tasksDoneByDay.get(key)) || 0 }));
  const waterTaskPairs = dayKeys
    .filter((key) => waterByDay.has(key) && tasksDoneByDay.has(key))
    .map((key) => ({ x: Number(waterByDay.get(key)) || 0, y: Number(tasksDoneByDay.get(key)) || 0 }));

  const sleepMood = findBestThresholdSplit(sleepMoodPairs, [5.5, 6, 6.5, 7, 7.5, 8]);
  const waterMood = findBestThresholdSplit(waterMoodPairs, [3, 4, 5, 6, 7, 8, 10]);
  const sleepProductivity = findBestThresholdSplit(sleepTaskPairs, [5.5, 6, 6.5, 7, 7.5, 8]);
  const waterProductivity = findBestThresholdSplit(waterTaskPairs, [3, 4, 5, 6, 7, 8, 10]);

  const summaryLines = [];

  if (sleepMood && Math.abs(sleepMood.diff) >= 0.12) {
    const thresholdLabel = Number.isInteger(sleepMood.threshold)
      ? String(sleepMood.threshold)
      : String(sleepMood.threshold).replace(/\.0$/, "");
    if (sleepMood.diff >= 0) {
      summaryLines.push(`Mood tends to drop when sleep is below ${thresholdLabel}h (mood ${sleepMood.lowAvg.toFixed(2)} vs ${sleepMood.highAvg.toFixed(2)} at/above).`);
    } else {
      summaryLines.push(`Mood tends to improve when sleep is below ${thresholdLabel}h (mood ${sleepMood.lowAvg.toFixed(2)} vs ${sleepMood.highAvg.toFixed(2)} at/above).`);
    }
  }

  if (waterMood && Math.abs(waterMood.diff) >= 0.1) {
    const thresholdLabel = Number.isInteger(waterMood.threshold)
      ? String(waterMood.threshold)
      : waterMood.threshold.toFixed(1).replace(/\.0$/, "");
    if (waterMood.diff >= 0) {
      summaryLines.push(`Mood tends to dip when hydration is below ${thresholdLabel} cups/day.`);
    } else {
      summaryLines.push(`Mood tends to improve even below ${thresholdLabel} cups/day; current pattern may be influenced by other factors.`);
    }
  }

  if (sleepProductivity && Math.abs(sleepProductivity.diff) >= 0.2) {
    const thresholdLabel = Number.isInteger(sleepProductivity.threshold)
      ? String(sleepProductivity.threshold)
      : String(sleepProductivity.threshold).replace(/\.0$/, "");
    if (sleepProductivity.diff >= 0) {
      summaryLines.push(`Productivity tends to improve when sleep is at least ${thresholdLabel}h (tasks ${sleepProductivity.highAvg.toFixed(1)} vs ${sleepProductivity.lowAvg.toFixed(1)}).`);
    } else {
      summaryLines.push(`Productivity is currently higher below ${thresholdLabel}h sleep; workload timing may be skewing this pattern.`);
    }
  }

  if (waterProductivity && Math.abs(waterProductivity.diff) >= 0.15) {
    const thresholdLabel = Number.isInteger(waterProductivity.threshold)
      ? String(waterProductivity.threshold)
      : waterProductivity.threshold.toFixed(1).replace(/\.0$/, "");
    if (waterProductivity.diff >= 0) {
      summaryLines.push(`Task completion is stronger on ${thresholdLabel}+ cup hydration days.`);
    }
  }

  if (!summaryLines.length && activeDays > 0) {
    summaryLines.push(`Pattern confidence is still building from ${activeDays} active day${activeDays === 1 ? "" : "s"}.`);
  }

  return {
    source: "live",
    generatedAtMs: Date.now(),
    windowDays: maxDays,
    activeDays,
    summaryLines: summaryLines.slice(0, 5),
    sleepMood,
    waterMood,
    sleepProductivity,
    waterProductivity
  };
}

function getBehaviorPatternMemory(maxDays = 30) {
  const live = buildBehaviorPatternMemoryFromLocal(maxDays);
  if (live?.summaryLines?.length && live.activeDays >= 3) return live;

  const stored = persistedBehaviorPatterns;
  if (stored && Array.isArray(stored.summaryLines) && stored.summaryLines.length) {
    return {
      ...stored,
      source: "stored"
    };
  }

  return live;
}

function buildTrendSignals() {
  const todayKey = getTodayKey();
  const last7Keys = [];
  const anchor = dateKeyToDate(todayKey) || getServerNowDate();
  anchor.setUTCHours(0, 0, 0, 0);
  for (let index = 6; index >= 0; index -= 1) {
    const date = new Date(anchor);
    date.setUTCDate(anchor.getUTCDate() - index);
    const key = dateToKey(date);
    if (key) last7Keys.push(key);
  }

  const moodByDay = buildMoodAverageByDayMap(last7Keys);

  const waterByDay = new Map();
  waterHistory.forEach((entry, index) => {
    const key = dateToKey(waterDates[index]);
    if (!key || !last7Keys.includes(key)) return;
    waterByDay.set(key, (waterByDay.get(key) || 0) + (Number(entry) || 0));
  });

  const sleepByDay = new Map();
  sleepHistory.forEach((entry, index) => {
    const key = dateToKey(sleepDates[index]);
    if (!key || !last7Keys.includes(key)) return;
    sleepByDay.set(key, Number(entry) || 0);
  });

  const tasksByDay = new Map();
  taskEntries.forEach((entry) => {
    if (!entry?.completed) return;
    const key = dateToKey(entry.completedAt || entry.time);
    if (!key || !last7Keys.includes(key)) return;
    tasksByDay.set(key, (tasksByDay.get(key) || 0) + 1);
  });

  const firstHalf = last7Keys.slice(0, 3);
  const secondHalf = last7Keys.slice(-3);
  const avgFor = (map, keys) => safeAvg(keys.map((key) => Number(map.get(key)) || 0));

  const moodDelta = avgFor(moodByDay, secondHalf) - avgFor(moodByDay, firstHalf);
  const waterDelta = avgFor(waterByDay, secondHalf) - avgFor(waterByDay, firstHalf);
  const sleepDelta = avgFor(sleepByDay, secondHalf) - avgFor(sleepByDay, firstHalf);
  const taskDelta = avgFor(tasksByDay, secondHalf) - avgFor(tasksByDay, firstHalf);

  return {
    moodDelta,
    waterDelta,
    sleepDelta,
    taskDelta,
    moodAvg: avgFor(moodByDay, last7Keys),
    waterAvg: avgFor(waterByDay, last7Keys),
    sleepAvg: avgFor(sleepByDay, last7Keys),
    taskAvg: avgFor(tasksByDay, last7Keys)
  };
}

function buildPriorityBoard(snapshot, trends) {
  const waterLeft = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
  const hydration = buildHydrationPaceInsight(snapshot);
  const candidates = [
    {
      id: "task",
      action: snapshot.pendingTasks > 0 ? "Finish one pending task in a 25-minute sprint." : "Create one meaningful task and start it now.",
      impact: snapshot.pendingTasks > 0 ? 82 : 62,
      urgency: snapshot.pendingTasks > 2 ? 22 : 10,
      trendBoost: trends.taskDelta < 0 ? 10 : 0
    },
    {
      id: "water",
      action: waterLeft > 0
        ? (hydration.onTrack
          ? `You logged ${hydration.logged} cups today. Keep pace and add ${Math.max(1, Math.ceil(waterLeft))} cup${Math.max(1, Math.ceil(waterLeft)) === 1 ? "" : "s"} to stay on target.`
          : `${hydration.summary} Add ${Math.max(1, Math.ceil(waterLeft))} cup${Math.max(1, Math.ceil(waterLeft)) === 1 ? "" : "s"} now.`)
        : "Hydration is on track — maintain steady intake.",
      impact: waterLeft > 0 ? 74 : 44,
      urgency: waterLeft >= 3 ? 18 : waterLeft > 0 ? 10 : 0,
      trendBoost: trends.waterDelta < 0 ? 12 : 0
    },
    {
      id: "sleep",
      action: snapshot.sleepToday < 7 ? "Protect tonight’s sleep window (7-8h) and set wind-down alarm." : "Keep sleep quality stable with a fixed bedtime.",
      impact: snapshot.sleepToday < 7 ? 79 : 46,
      urgency: snapshot.sleepToday < 6 ? 22 : snapshot.sleepToday < 7 ? 12 : 0,
      trendBoost: trends.sleepDelta < 0 ? 11 : 0
    },
    {
      id: "mood",
      action: !snapshot.moodToday ? "Log your mood now to improve your guidance accuracy." : "Run a 2-minute reset to keep emotional stability high.",
      impact: !snapshot.moodToday ? 63 : 50,
      urgency: !snapshot.moodToday ? 15 : 6,
      trendBoost: trends.moodDelta < 0 ? 14 : 0
    },
    {
      id: "gratitude",
      action: !snapshot.gratitudeToday ? "Write one gratitude line to lock a positive close." : "Maintain gratitude consistency before day-end.",
      impact: !snapshot.gratitudeToday ? 55 : 38,
      urgency: !snapshot.gratitudeToday ? 8 : 3,
      trendBoost: 0
    }
  ];

  return candidates
    .map((entry) => ({ ...entry, score: entry.impact + entry.urgency + entry.trendBoost }))
    .sort((a, b) => b.score - a.score);
}

function buildWhySummary(snapshot, trends) {
  const drivers = [];
  const hydration = buildHydrationPaceInsight(snapshot);
  if (snapshot.pendingTasks > 2) drivers.push("task load is currently high");
  if (snapshot.sleepToday < 7) drivers.push("sleep is below recovery zone");
  if (snapshot.hasWaterGoal && snapshot.waterToday < snapshot.todayGoal) {
    if (hydration.onTrack) drivers.push("hydration is below target but pace is acceptable for this time");
    else drivers.push(`hydration pace suggests you may miss goal by ~${hydration.missBy.toFixed(1)} cups`);
  } else if (!snapshot.hasWaterGoal) {
    drivers.push("water goal is not set yet");
  }
  if (!snapshot.moodToday) drivers.push("mood signal is missing for today");
  if (trends.taskDelta < 0) drivers.push("recent task completion trend is softening");
  if (trends.sleepDelta < 0) drivers.push("sleep trend dipped in the last few days");
  if (trends.waterDelta < 0) drivers.push("hydration trend is dropping");
  if (!drivers.length) drivers.push("your current inputs are relatively stable");
  return drivers.slice(0, 4);
}

function getTodayWater() {
  const todayKey = getTodayKey();
  return waterHistory.reduce((sum, value, index) => {
    const dateKey = dateToKey(waterDates[index]);
    return dateKey === todayKey ? sum + value : sum;
  }, 0);
}

function getTodayMood() {
  const todayKey = getTodayKey();
  return moodHistory.reduce((lastMood, value, index) => {
    const dateKey = dateToKey(moodDates[index]);
    return dateKey === todayKey ? value : lastMood;
  }, "");
}

function getTodayMoodAverageScore() {
  const todayKey = getTodayKey();
  const moodByDay = buildMoodAverageByDayMap([todayKey]);
  return Number(moodByDay.get(todayKey)) || 0;
}

function getTodaySleep() {
  const todayKey = getTodayKey();
  return sleepHistory.reduce((lastSleep, value, index) => {
    const dateKey = dateToKey(sleepDates[index]);
    return dateKey === todayKey ? value : lastSleep;
  }, 0);
}

function getWellnessSnapshot() {
  const waterToday = getTodayWater();
  const hasWaterGoal = waterGoal > 0;
  const todayGoal = hasWaterGoal ? waterGoal : 8;
  const moodToday = getTodayMood();
  const sleepToday = getTodaySleep();
  const totalTasks = taskEntries.length;
  const doneTasks = taskEntries.filter((entry) => !!entry.completed).length;
  const pendingTasks = taskEntries.filter((entry) => !entry.completed).length;
  const gratitudeToday = gratitudeEntries.some((entry) => dateToKey(entry.time) === getTodayKey());
  const score = calculateWellnessScoreValue();

  return {
    waterToday,
    hasWaterGoal,
    todayGoal,
    moodToday,
    sleepToday,
    totalTasks,
    doneTasks,
    pendingTasks,
    gratitudeToday,
    score
  };
}

function getAiWaterStatusText(snapshot) {
  const safeSnapshot = snapshot && typeof snapshot === "object" ? snapshot : getWellnessSnapshot();
  const waterToday = Math.max(0, Number(safeSnapshot.waterToday) || 0);
  if (!safeSnapshot.hasWaterGoal) {
    return `you logged ${waterToday} cup${waterToday === 1 ? "" : "s"}, and no water goal is set yet`;
  }
  const goal = Math.max(1, Number(safeSnapshot.todayGoal) || 8);
  const waterLeft = Math.max(0, goal - waterToday);
  return `you logged ${waterToday}/${goal} cups, with ${waterLeft} cup${waterLeft === 1 ? "" : "s"} left`;
}

function normalizeReminderUnitValue(unitRaw) {
  const unit = String(unitRaw || "minute").toLowerCase();
  if (/^(s|sec|secs|second|seconds)$/.test(unit)) return "second";
  if (/^(m|min|mins|minute|minutes)$/.test(unit)) return "minute";
  if (/^(h|hr|hrs|hour|hours)$/.test(unit)) return "hour";
  if (/^(d|day|days)$/.test(unit)) return "day";
  if (/^(w|wk|wks|week|weeks)$/.test(unit)) return "week";
  if (/^(mo|mon|mons|month|months)$/.test(unit)) return "month";
  return "minute";
}

function parseDurationToMinutes(amountRaw, unitRaw) {
  const amount = Number(amountRaw);
  if (!Number.isFinite(amount) || amount < 1) return 0;
  const normalizedUnit = normalizeReminderUnitValue(unitRaw);
  if (normalizedUnit === "second") return amount / 60;
  if (normalizedUnit === "month") return amount * 43200;
  if (normalizedUnit === "hour") return amount * 60;
  if (normalizedUnit === "day") return amount * 1440;
  if (normalizedUnit === "week") return amount * 10080;
  return amount;
}

function restoreReminderAudioDucking() {
  if (reminderAudioDuckRestoreTimer) {
    clearTimeout(reminderAudioDuckRestoreTimer);
    reminderAudioDuckRestoreTimer = null;
  }

  if (!Array.isArray(reminderDuckedMediaEntries) || !reminderDuckedMediaEntries.length) {
    reminderDuckedMediaEntries = [];
    return;
  }

  reminderDuckedMediaEntries.forEach((entry) => {
    const media = entry?.media;
    if (!media) return;
    try {
      media.volume = Math.max(0, Math.min(1, Number(entry.originalVolume) || 1));
      media.muted = !!entry.originalMuted;
    } catch (_) {}
  });
  reminderDuckedMediaEntries = [];
}

function startReminderAudioDucking(durationMs = REMINDER_AUDIO_DUCK_DEFAULT_MS) {
  restoreReminderAudioDucking();

  const reminderAudio = document.getElementById("reminderSound");
  const mediaNodes = Array.from(document.querySelectorAll("audio, video"));
  const duckedEntries = [];

  mediaNodes.forEach((media) => {
    if (!media || media === reminderAudio) return;
    if (media.paused) return;
    const originalVolume = Number(media.volume);
    if (!Number.isFinite(originalVolume) || originalVolume <= 0) return;

    duckedEntries.push({
      media,
      originalVolume,
      originalMuted: !!media.muted
    });

    try {
      media.muted = false;
      media.volume = Math.max(0.04, Math.min(originalVolume * REMINDER_AUDIO_DUCK_FACTOR, originalVolume));
    } catch (_) {}
  });

  reminderDuckedMediaEntries = duckedEntries;
  const safeDuration = Math.max(1200, Number(durationMs) || REMINDER_AUDIO_DUCK_DEFAULT_MS);
  reminderAudioDuckRestoreTimer = setTimeout(() => {
    restoreReminderAudioDucking();
  }, safeDuration);
}

function playReminderFallbackTone() {
  try {
    const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextCtor) return false;
    const ctx = new AudioContextCtor();
    const master = ctx.createGain();
    master.gain.value = 0.18;
    master.connect(ctx.destination);

    const beep = (startOffset, freq, duration) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, ctx.currentTime + startOffset);
      gain.gain.setValueAtTime(0.0001, ctx.currentTime + startOffset);
      gain.gain.exponentialRampToValueAtTime(0.35, ctx.currentTime + startOffset + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + startOffset + duration);
      osc.connect(gain);
      gain.connect(master);
      osc.start(ctx.currentTime + startOffset);
      osc.stop(ctx.currentTime + startOffset + duration + 0.02);
    };

    beep(0, 880, 0.17);
    beep(0.2, 1046, 0.2);
    setTimeout(() => {
      try {
        ctx.close();
      } catch (_) {}
    }, 700);
    return true;
  } catch (_) {
    return false;
  }
}

function triggerReminderAttentionSignals(reminderTextValue = "") {
  try {
    if (navigator?.vibrate) {
      navigator.vibrate([180, 120, 220, 120, 260]);
    }
  } catch (_) {}

  try {
    const speech = window.speechSynthesis;
    if (speech && typeof SpeechSynthesisUtterance === "function") {
      const utterance = new SpeechSynthesisUtterance(`Reminder. ${String(reminderTextValue || "") || "Check your reminder now."}`);
      utterance.rate = 1;
      utterance.pitch = 1;
      utterance.volume = 1;
      speech.cancel();
      speech.speak(utterance);
    }
  } catch (_) {}

  try {
    if (typeof Notification === "function" && Notification.permission === "granted") {
      const body = String(reminderTextValue || "").trim() || "Time's up.";
      const n = new Notification("NovaFix Reminder", {
        body,
        tag: `novafix-reminder-${Date.now()}`,
        renotify: true,
        requireInteraction: false
      });
      setTimeout(() => {
        try {
          n.close();
        } catch (_) {}
      }, 9000);
    } else if (typeof Notification === "function" && Notification.permission === "default") {
      Notification.requestPermission().catch(() => {});
    }
  } catch (_) {}
}

async function playReminderChimeWithAudioDucking(reminderTextValue = "") {
  const audio = document.getElementById("reminderSound");
  const audioDurationMs = Number(audio?.duration) > 0 ? (Number(audio.duration) * 1000) : 0;
  const totalAlertWindowMs = Math.max(
    REMINDER_AUDIO_DUCK_DEFAULT_MS,
    ((audioDurationMs > 0 ? audioDurationMs : 550) * REMINDER_ALERT_REPEAT_COUNT) + (REMINDER_ALERT_REPEAT_GAP_MS * (REMINDER_ALERT_REPEAT_COUNT - 1)) + 900
  );
  startReminderAudioDucking(totalAlertWindowMs);

  let playedAtLeastOnce = false;
  for (let attempt = 0; attempt < REMINDER_ALERT_REPEAT_COUNT; attempt += 1) {
    if (audio) {
      try {
        audio.currentTime = 0;
        audio.muted = false;
        audio.volume = 1;
        await audio.play();
        playedAtLeastOnce = true;
      } catch (_) {
        playedAtLeastOnce = playReminderFallbackTone() || playedAtLeastOnce;
      }
    } else {
      playedAtLeastOnce = playReminderFallbackTone() || playedAtLeastOnce;
    }

    if (attempt < REMINDER_ALERT_REPEAT_COUNT - 1) {
      await new Promise((resolve) => setTimeout(resolve, REMINDER_ALERT_REPEAT_GAP_MS));
    }
  }

  triggerReminderAttentionSignals(reminderTextValue);
  return playedAtLeastOnce;
}

function parseTimelineFromInput(text) {
  const raw = String(text || "").toLowerCase();
  if (!raw) return null;

  if (/\btomorrow\b/.test(raw)) {
    return { minutes: 24 * 60, label: "tomorrow" };
  }
  if (/\bnext\s+week\b/.test(raw)) {
    return { minutes: 7 * 24 * 60, label: "next week" };
  }
  if (/\bnext\s+month\b/.test(raw)) {
    return { minutes: 30 * 24 * 60, label: "next month" };
  }

  const durationMatch = raw.match(/\bin\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)\b/i);
  if (!durationMatch) return null;

  const minutes = parseDurationToMinutes(durationMatch[1], durationMatch[2]);
  if (!minutes) return null;

  return {
    minutes,
    label: `in ${durationMatch[1]} ${durationMatch[2]}`
  };
}

function extractPrepTopicFromInput(text) {
  const raw = String(text || "").trim();
  if (!raw) return "your goal";

  const timelinePattern = "(?:tomorrow|next\\s+week|next\\s+month|in\\s+\\d+(?:\\.\\d+)?\\s*(?:s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months))";
  const patterns = [
    new RegExp(`\\b(?:study|studying|prepare|preparing|prep|revision|revise)\\s+(?:for\\s+)?(.+?)\\s+${timelinePattern}`, "i"),
    new RegExp(`\\bi\\s+(?:have|got)\\s+(?:an?\\s+)?(.+?)\\s+${timelinePattern}`, "i"),
    new RegExp(`\\bfor\\s+(.+?)\\s+${timelinePattern}`, "i")
  ];

  let topic = "";
  for (let index = 0; index < patterns.length; index += 1) {
    const match = raw.match(patterns[index]);
    if (match?.[1]) {
      topic = match[1];
      break;
    }
  }

  if (!topic) {
    const fallback = raw.match(/\b(exam|test|quiz|interview|presentation|assignment|project|deadline|meeting|course|certification|paper|module|subject)\b/i);
    if (fallback?.[1]) topic = fallback[1];
  }

  const cleaned = String(topic || "your goal")
    .replace(/\b(?:an?|the|my|for)\b/gi, " ")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned || "your goal";
}

function buildHydrationPaceInsight(snapshot) {
  const source = snapshot && typeof snapshot === "object" ? snapshot : getWellnessSnapshot();
  const hasWaterGoal = !!source.hasWaterGoal;
  const goal = Math.max(1, Number(source.todayGoal) || 8);
  const logged = Math.max(0, Number(source.waterToday) || 0);
  const remaining = Math.max(0, goal - logged);

  const now = getServerNowDate();
  const dayStart = new Date(now);
  dayStart.setUTCHours(0, 0, 0, 0);
  const elapsedHours = Math.max(0.25, (now.getTime() - dayStart.getTime()) / 3600000);
  const projectedByDayEnd = logged * (24 / elapsedHours);
  const missByRaw = Math.max(0, goal - projectedByDayEnd);
  const missBy = Math.round(missByRaw * 10) / 10;
  const onTrack = projectedByDayEnd >= goal || remaining <= 0;

  const cupWord = logged === 1 ? "cup" : "cups";
  const missCupWord = missBy === 1 ? "cup" : "cups";

  const summary = !hasWaterGoal
    ? `You logged ${logged} ${cupWord} today. Set a water goal to get pace tracking.`
    : onTrack
    ? `You logged ${logged} ${cupWord} today and your pace looks on track.`
    : `You logged only ${logged} ${cupWord} today. At this pace, you may miss your goal by about ${missBy.toFixed(1)} ${missCupWord}.`;

  return {
    goal,
    logged,
    remaining,
    elapsedHours,
    projectedByDayEnd,
    missBy,
    onTrack,
    summary
  };
}

async function addReminderFromAi(text, minutes) {
  const safeText = String(text || "").trim();
  const safeMinutes = Math.max(1, Math.min(REMINDER_MAX_MINUTES, Math.round(Number(minutes) || 0)));
  if (!safeText || !safeMinutes) return false;

  const beforeCount = reminders?.querySelectorAll?.(".item-row")?.length || 0;
  const previousUnit = String(reminderUnit?.value || "minute");
  reminderText.value = safeText;
  reminderMinutes.value = String(safeMinutes);
  if (reminderUnit) reminderUnit.value = "minute";
  await addReminder();
  if (reminderUnit) reminderUnit.value = previousUnit;
  const afterCount = reminders?.querySelectorAll?.(".item-row")?.length || 0;
  return afterCount > beforeCount;
}

async function createAutoPrepPlanFromAi(user, inputText) {
  if (!user?.uid) return null;

  if (/^\s*(?:set|add|create|remind|reminder)\b/i.test(String(inputText || ""))) {
    return null;
  }

  const timeline = parseTimelineFromInput(inputText);
  if (!timeline) return null;

  const prepSignal = /\b(exam|test|quiz|interview|presentation|assignment|project|deadline|study|studying|prepare|preparing|prep|revision|course|certification|meeting|paper|module|subject)\b/i.test(inputText);
  if (!prepSignal) return null;

  const topic = extractPrepTopicFromInput(inputText);
  const totalMinutes = Math.max(30, Number(timeline.minutes) || 0);

  const taskTemplates = [
    `Plan ${topic}: outline topics and priority weak spots (timeline ${timeline.label}).`,
    `Run a 50-minute focused session for ${topic}, then review mistakes for 10 minutes.`,
    `Create a one-page revision sheet for ${topic} and revise it once daily.`,
    `Final review for ${topic} before ${timeline.label}.`
  ];

  let addedTasks = 0;
  for (let index = 0; index < taskTemplates.length; index += 1) {
    const beforeCount = taskEntries.length;
    task.value = taskTemplates[index];
    await addTask();
    if (taskEntries.length > beforeCount) addedTasks += 1;
  }

  const midpointMinutes = Math.max(60, Math.round(totalMinutes * 0.5));
  const sleepPrepMinutes = Math.max(90, totalMinutes - (8 * 60));
  const reminderTemplates = [
    { text: `Start ${topic}: first 50-minute focus block now.`, minutes: 15 },
    { text: `Break schedule: take a 10-minute reset after this ${topic} focus block.`, minutes: 55 },
    { text: `${topic} checkpoint: quick self-test and adjust weak areas.`, minutes: midpointMinutes },
    { text: `Sleep reminder for ${topic}: wind down early and protect 7-8h sleep.`, minutes: sleepPrepMinutes },
    { text: `Final prep window for ${topic} is now (${timeline.label}).`, minutes: totalMinutes }
  ];

  const seenMinutes = new Set();
  let addedReminders = 0;
  for (let index = 0; index < reminderTemplates.length; index += 1) {
    const reminder = reminderTemplates[index];
    const safeMinutes = Math.max(1, Math.min(REMINDER_MAX_MINUTES, Math.round(reminder.minutes)));
    if (seenMinutes.has(safeMinutes)) continue;
    seenMinutes.add(safeMinutes);
    const ok = await addReminderFromAi(reminder.text, safeMinutes);
    if (ok) addedReminders += 1;
  }

  return {
    topic,
    timelineLabel: timeline.label,
    addedTasks,
    addedReminders
  };
}

function mapMoodFromInput(text) {
  const lower = String(text || "").toLowerCase();
  if (/😤|\bangry\b|\bfurious\b|\brage\b|\bmad\b/.test(lower)) return "😤 Angry";
  if (/😣|\bstressed\b|\bstress\b|\boverwhelmed\b|\banxious\b|\banxiety\b/.test(lower)) return "😣 Stressed";
  if (/😊|\bhappy\b|\bgood\b|\bgreat\b|\bawesome\b|\bfine\b|\benergized\b|\bpumped\b/.test(lower)) return "😊 Happy";
  if (/😔|\bsad\b|\blow\b|\bdown\b|\bdepressed\b|\btired\b|\bdrained\b/.test(lower)) return "😔 Low";
  if (/😐|\bneutral\b|\bnuetral\b|\bok\b|\bokay\b|\bmeh\b/.test(lower)) return "😐 Neutral";
  return "";
}

async function editTaskFromAi(user, query, nextText) {
  if (!user?.uid) return { ok: false, message: "Please sign in first." };
  if (!taskEntries.length) return { ok: false, message: "No tasks found." };

  const rawQuery = stripWrappingQuotes(String(query || "").trim());
  const rawNextText = stripWrappingQuotes(String(nextText || "").trim());
  if (!rawQuery || !rawNextText) return { ok: false, message: "Tell me which task and the new text." };

  let target = null;
  if (/^\d+$/.test(rawQuery)) {
    const index = Number(rawQuery) - 1;
    if (index >= 0 && index < taskEntries.length) target = taskEntries[index];
  }

  if (!target) {
    const lowered = rawQuery.toLowerCase();
    target = taskEntries.find((entry) => String(entry.text || "").toLowerCase().includes(lowered));
  }

  if (!target || !target.id) return { ok: false, message: "No matching task found." };

  try {
    await updateDoc(doc(db, "users", user.uid, "tasks", target.id), { text: rawNextText });
    await loadTasks(user.uid);
    return { ok: true, message: `✅ Updated task to: ${rawNextText}` };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, message: "Could not update task right now." };
  }
}

async function setTaskCompletionFromAi(user, query, completed) {
  if (!user?.uid) return { ok: false, message: "Please sign in first." };
  if (!taskEntries.length) return { ok: false, message: "No tasks found." };

  const rawQuery = String(query || "").trim();
  let target = null;

  if (/^\d+$/.test(rawQuery)) {
    const index = Number(rawQuery) - 1;
    if (index >= 0 && index < taskEntries.length) {
      target = taskEntries[index];
    }
  }

  if (!target && rawQuery) {
    const lowered = rawQuery.toLowerCase();
    target = taskEntries.find((entry) => String(entry.text || "").toLowerCase().includes(lowered));
  }

  if (!target) {
    target = taskEntries.find((entry) => (!!entry.completed) !== (!!completed));
  }

  if (!target || !target.id) return { ok: false, message: "No matching task found." };

  if (!!target.completed === !!completed) {
    return {
      ok: true,
      message: completed
        ? `Task already completed: ${target.text || "Task"}`
        : `Task already open: ${target.text || "Task"}`
    };
  }

  try {
    await updateDoc(doc(db, "users", user.uid, "tasks", target.id), {
      completed: !!completed,
      completedAt: completed ? serverTimestamp() : null
    });
    await loadTasks(user.uid);
    return {
      ok: true,
      message: completed
        ? `✅ Marked task done: ${target.text || "Task"}`
        : `↩️ Reopened task: ${target.text || "Task"}`
    };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, message: "Could not update task right now." };
  }
}

function parseGreetingAndActionText(inputText) {
  const text = String(inputText || "").trim();
  const match = text.match(/^\s*(hey|hello|hi)\b[\s,.!:-]*(?:and\s+|btw\s+|then\s+|please\s+)?([\s\S]*)$/i);
  if (!match) {
    return {
      hasGreeting: false,
      greeting: "",
      actionText: text
    };
  }

  const greetingRaw = String(match[1] || "").toLowerCase();
  const greeting = greetingRaw === "hi"
    ? "Hi"
    : greetingRaw === "hello"
      ? "Hello"
      : "Hey";

  return {
    hasGreeting: true,
    greeting,
    actionText: String(match[2] || "").trim()
  };
}

function splitAiTaskItems(taskText) {
  return String(taskText || "")
    .split(/\s*(?:,|;|\band\b|\bthen\b|&)\s*/i)
    .map((part) => stripWrappingQuotes(String(part || "").replace(/^[-*•\d.)\s]+/, "").trim()))
    .filter(Boolean)
    .slice(0, 8);
}

function stripWrappingQuotes(value) {
  let text = String(value || "").trim();
  if (!text) return "";

  const pairs = [
    ["\"", "\""],
    ["'", "'"],
    ["“", "”"],
    ["‘", "’"],
    ["`", "`"]
  ];

  let trimmed = text;
  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 0; i < pairs.length; i += 1) {
      const [open, close] = pairs[i];
      if (trimmed.startsWith(open) && trimmed.endsWith(close) && trimmed.length >= 2) {
        trimmed = trimmed.slice(open.length, trimmed.length - close.length).trim();
        changed = true;
      }
    }
  }

  return trimmed;
}

function splitAiActionClauses(inputText) {
  const raw = String(inputText || "").trim();
  if (!raw) return [];

  const coarseParts = raw
    .split(/\s*(?:\n+|;|&&|\band\s+then\b|\bthen\b)\s*/i)
    .map((part) => String(part || "").trim())
    .filter(Boolean);

  const actionStarter = /^(?:add|create|new|log|save|track|set|update|play|start|open|remind|complete|done|finish|mark|reopen|undo|uncheck|delete|remove|clear|list|show|view|please|can\s+you|could\s+you|would\s+you|kindly)\b/i;
  const finerParts = [];

  for (let index = 0; index < coarseParts.length; index += 1) {
    const segment = coarseParts[index];
    const splitByAnd = segment.split(/\s+\band\b\s+/i).map((part) => part.trim()).filter(Boolean);
    if (splitByAnd.length <= 1) {
      finerParts.push(segment);
      continue;
    }

    const actionableCount = splitByAnd.reduce((total, part) => total + (actionStarter.test(part) ? 1 : 0), 0);
    if (actionableCount >= 2) {
      finerParts.push(...splitByAnd);
    } else {
      finerParts.push(segment);
    }
  }

  return finerParts
    .map((part) => part
      .replace(/^[-*•\d.)\s]+/, "")
      .replace(/^(?:please\s+|can\s+you\s+|could\s+you\s+|would\s+you\s+|kindly\s+)/i, "")
      .trim())
    .filter(Boolean)
    .slice(0, 5);
}

async function tryAiAction(input, user, options = {}) {
  const skipMultiSplit = !!options.skipMultiSplit;
  const skipGreeting = !!options.skipGreeting;
  const retryAfterPoliteStrip = !!options.retryAfterPoliteStrip;
  const rawInput = String(input || "").trim();
  const parsedInput = shouldSkipAiTypoNormalizationForPlannerInput(rawInput)
    ? rawInput
    : normalizeTyposForAi(rawInput);
  const msg = parsedInput.replace(/[!?]+$/g, "");
  const greetingInfo = parseGreetingAndActionText(msg);
  const effectiveMsg = greetingInfo.actionText || msg;
  const politeStrippedMsg = effectiveMsg.replace(/^\s*(?:please\s+|can\s+you\s+|could\s+you\s+|would\s+you\s+|kindly\s+)/i, "").trim();
  const commandMsg = politeStrippedMsg || effectiveMsg;
  const lower = commandMsg.toLowerCase();
  const isReminderIntent = /\b(remind|reminder)\b/.test(lower);
  const withGreeting = (text) => {
    if (skipGreeting) return text;
    return greetingInfo.hasGreeting ? `${greetingInfo.greeting}! ${text}` : text;
  };

  if (!skipMultiSplit) {
    const clauses = splitAiActionClauses(effectiveMsg);
    if (clauses.length > 1) {
      const outputs = [];
      for (let index = 0; index < clauses.length; index += 1) {
        const clause = clauses[index];
        const result = await tryAiAction(clause, user, { skipMultiSplit: true, skipGreeting: true });
        if (typeof result === "string" && result.trim()) {
          outputs.push(result.trim());
        }
      }

      if (outputs.length) {
        const deduped = [];
        for (let index = 0; index < outputs.length; index += 1) {
          const entry = outputs[index];
          if (!deduped.includes(entry)) deduped.push(entry);
        }
        return withGreeting(deduped.join(" | "));
      }
    }
  }

  if (greetingInfo.hasGreeting && !greetingInfo.actionText) {
    const displayName = getPreferredAiDisplayName(user) || getUserName(user) || "there";
    return `${greetingInfo.greeting} ${displayName}! Tell me what you want to do, for example: play music, add task, or set reminder.`;
  }

  if (/^(?:what(?:'s|\s+is)\s+my\s+name|who\s+am\s+i)(?:\?)?$/i.test(effectiveMsg)) {
    const displayName = getPreferredAiDisplayName(user);
    if (displayName) {
      return withGreeting(`Your name is ${displayName}.`);
    }
    return withGreeting("I could not find your name yet. Set or update it from Account.");
  }

  if (isClearChatCommand(commandMsg)) {
    return withGreeting("Clearing chat now.");
  }

  const requestedMode = parseModeFromInput(commandMsg);
  if (requestedMode) {
    const changed = setAiMode(requestedMode);
    if (changed) {
      return withGreeting("✅ Response style updated.");
    }
    return withGreeting("ℹ️ Unknown mode. Use: balanced, coach, strict, creative, ultra.");
  }

  const rememberMatch = commandMsg.match(/^remember\s+(?:that\s+)?(.+)/i);
  if (rememberMatch?.[1]) {
    learnFromUserInput(rememberMatch[1]);
    return withGreeting(`✅ Saved memory: ${escapeHtml(rememberMatch[1].trim())}`);
  }

  if (/^(?:what do you remember|recall memory|memory|show memory)$/i.test(commandMsg)) {
    return withGreeting(`🧠 Memory: ${escapeHtml(getMemorySummary())}`);
  }

  if (/^(start\s+reset|reset\s+me|calm\s+me)$/i.test(commandMsg)) {
    return withGreeting("✅ 60-second reset: inhale 4s → hold 4s → exhale 6s for 6 rounds, drink a glass of water, then do one 10-minute micro-task.");
  }

  const musicPlayIntent =
    /\b(?:play|start|put\s+on|turn\s+on|turn\s+up|open)\b[\s\S]{0,40}\b(?:music|song|songs|spotify|playlist)\b/i.test(lower)
    || /\b(?:music|song|songs|spotify|playlist)\b[\s\S]{0,20}\b(?:play|start|on)\b/i.test(lower)
    || /\bturn\s+on\s+the\s+music\b/i.test(lower);
  if (musicPlayIntent && !isReminderIntent) {
    try {
      if (document.activeElement === aiInput && aiInput && typeof aiInput.blur === "function") {
        try {
          aiInput.blur();
        } catch (_) {}
      }

      const musicCard = (wellnessMusicFrame && typeof wellnessMusicFrame.closest === "function"
        ? wellnessMusicFrame.closest(".card")
        : null)
        || document.querySelector(".wellness-music-card");

      if (musicCard) {
        scrollCardToViewportCenterReliably(musicCard, { repeats: 6, delayMs: 120 });
        if (musicCard.classList) {
          musicCard.classList.remove("shortcut-focus");
          void musicCard.offsetWidth;
          musicCard.classList.add("shortcut-focus");
          setTimeout(() => {
            try {
              musicCard.classList.remove("shortcut-focus");
            } catch (_) {}
          }, 1250);
        }
      }

    } catch (_) {
      // Keep AI action resilient: never let music UI errors break chat flow.
    }

    return withGreeting("🎵 Opened Wellness Music. Tap play on the music player.");
  }

  if (/^(?:run|start|do|begin|trigger)\s+(?:the\s+)?(?:mood\s+)?(?:crash\s+)?rescue$/i.test(commandMsg) && !isReminderIntent) {
    const rescueResult = await runCrashRescueFlow({ showAlert: false });
    if (!rescueResult?.ok) {
      return withGreeting(`ℹ️ ${rescueResult?.message || "Could not start rescue right now."}`);
    }
    return withGreeting(`🛟 Mood crash rescue started (${rescueResult.level}). A 20-minute recovery reminder is now set. Focus now: ${rescueResult.reason}.`);
  }

  let taskText = "";
  const taskMatch = commandMsg.match(/^(?:add|create|new|log)\s+(?:a\s+)?(?:(?:productivity|work|study)\s+)?(?:task|todo)\s*[:\-]?\s*(.+)$/i);
  if (taskMatch?.[1]) taskText = taskMatch[1].trim();
  if (!taskText && /^(?:add|create|new|log)\s+(?:a\s+)?(?:(?:productivity|work|study)\s+)?(?:task|todo)\s*[:\-]?\s*$/i.test(commandMsg)) {
    return withGreeting("ℹ️ Tell me the task text too, like: add task finish assignment.");
  }
  if (!taskText) {
    const quickTaskMatch = commandMsg.match(/^(?:task|todo)\s*[:\-]\s*(.+)$/i);
    if (quickTaskMatch?.[1]) taskText = quickTaskMatch[1].trim();
  }
  if (!taskText) {
    const naturalTaskMatch = commandMsg.match(/^(?:i\s+(?:need|have|want|plan)\s+to|need\s+to|todo\s*[:\-]?|to\s*do\s*[:\-]?)\s+(.+)$/i);
    if (naturalTaskMatch?.[1]) taskText = naturalTaskMatch[1].trim();
  }
  if (taskText) {
    const taskItems = splitAiTaskItems(stripWrappingQuotes(taskText));
    const addedTasks = [];
    for (let index = 0; index < taskItems.length; index += 1) {
      const item = taskItems[index];
      const beforeCount = taskEntries.length;
      task.value = item;
      await addTask();
      if (taskEntries.length > beforeCount) addedTasks.push(item);
    }
    if (!addedTasks.length) {
      return withGreeting("ℹ️ Could not add tasks right now. Please try again.");
    }
    if (addedTasks.length === 1) {
      const msg = pickNonRepeatingVariant(AI_TASK_ADDED_POOL, 'task_added').replaceAll('{task}', addedTasks[0]);
      return withGreeting(msg);
    }
    const multiTemplate = pickNonRepeatingVariant(AI_TASK_ADDED_POOL, 'task_added_multi') || `✅ Added {count} tasks: {list}`;
    const multiMsg = multiTemplate.replaceAll('{count}', String(addedTasks.length)).replaceAll('{list}', addedTasks.join(' | '));
    return withGreeting(multiMsg);
  }

  if (/^(?:list|show|view)\s+(?:my\s+)?(?:tasks|todos|productivity\s+tasks)$/i.test(msg)) {
    if (!taskEntries.length) return "ℹ️ You have no tasks right now.";
    const lines = taskEntries.slice(0, 12).map((entry, index) => {
      const mark = entry.completed ? "[x]" : "[ ]";
      return `${index + 1}) ${mark} ${entry.text || "Task"}`;
    });
    return `🗂 Tasks:\n${lines.join("\n")}`;
  }

  const completeTaskMatch = msg.match(/^(?:complete|done|finish|mark)\s+(?:my\s+)?(?:(?:productivity|work|study)\s+)?(?:task|todo)\s*#?\s*(.+)$/i);
  if (completeTaskMatch?.[1]) {
    const result = await setTaskCompletionFromAi(user, completeTaskMatch[1], true);
    return result.message;
  }
  if (/^(?:complete|done|finish|mark)\s+(?:my\s+)?(?:(?:productivity|work|study)\s+)?(?:task|todo)\b/i.test(msg)) {
    return "ℹ️ Tell me which task, for example: complete task 2 or complete task gym.";
  }

  const editTaskMatch = msg.match(/^(?:edit|update|rename)\s+(?:my\s+)?(?:task|todo)\s*#?\s*(.+?)\s+(?:to|as)\s+(.+)$/i);
  if (editTaskMatch?.[1] && editTaskMatch?.[2]) {
    const result = await editTaskFromAi(user, editTaskMatch[1], editTaskMatch[2]);
    return result.message;
  }
  if (/^(?:edit|update|rename)\s+(?:my\s+)?(?:task|todo)\b/i.test(msg)) {
    return "ℹ️ Tell me which task and the new text, like: edit task 2 to Swimming.";
  }

  const reopenTaskMatch = msg.match(/^(?:reopen|undo|uncomplete|uncheck)\s+(?:my\s+)?(?:task|todo)\s*#?\s*(.+)$/i);
  if (reopenTaskMatch?.[1]) {
    const result = await setTaskCompletionFromAi(user, reopenTaskMatch[1], false);
    return result.message;
  }
  if (/^(?:reopen|undo|uncomplete|uncheck)\s+(?:my\s+)?(?:task|todo)\b/i.test(msg)) {
    return "ℹ️ Tell me which task to reopen, like: reopen task 2.";
  }

  const waterGoalMatch = lower.match(/(?:set|update)\s+(?:my\s+)?water\s+goal\s+(?:to\s+)?(\d+(?:\.\d+)?)/i)
    || lower.match(/water\s+goal\s*[:\-]?\s*(\d+(?:\.\d+)?)/i);
  if (waterGoalMatch && !isReminderIntent) {
    const nextGoal = Number(waterGoalMatch[1]) || 0;
    waterGoalInput.value = String(nextGoal);
    await setWaterGoal();
    return `✅ Water goal updated to ${nextGoal} glasses.`;
  }

  const waterLogMatch = lower.match(/(?:log|add|track|drink|drank|had|have\s+had)\s+(\d+(?:\.\d+)?)\s*(?:glass|glasses|cup|cups)?\s*(?:of\s+)?(?:water)?(?:\s+just\s+now)?/i)
    || lower.match(/\bi\s+(?:just\s+)?(?:drank|drink|had)\s+(\d+(?:\.\d+)?)\s*(?:glass|glasses|cup|cups)(?:\s+of\s+water)?/i);
  const waterSignal = /\b(water|hydrate|hydration|glass|glasses|cup|cups|drink|drank)\b/.test(lower);
  if (waterLogMatch && waterSignal && !isReminderIntent) {
    const loggedAmount = Math.max(0, Number(waterLogMatch[1]) || 0);
    const isIncrementCommand = /\b(more|additional|another)\b/.test(lower);
    const latestTodayValue = (() => {
      const todayKey = getTodayKey();
      for (let index = waterHistory.length - 1; index >= 0; index -= 1) {
        if (dateToKey(waterDates[index]) !== todayKey) continue;
        return Number(waterHistory[index]) || 0;
      }
      return 0;
    })();

    const nextWaterValue = isIncrementCommand
      ? Number((latestTodayValue + loggedAmount).toFixed(1))
      : loggedAmount;
    waterInput.value = String(nextWaterValue);
    await saveWater();
    if (isIncrementCommand) {
      const incMsg = pickNonRepeatingVariant(AI_WATER_LOGGED_POOL, 'water_logged').replaceAll('{amount}', String(loggedAmount)).replaceAll('{total}', String(nextWaterValue));
      return withGreeting(incMsg);
    }
    const singleMsg = pickNonRepeatingVariant(AI_WATER_LOGGED_POOL, 'water_logged').replaceAll('{amount}', String(nextWaterValue)).replaceAll('{total}', String(nextWaterValue));
    return withGreeting(singleMsg);
  }
  if (waterSignal && /\b(log|add|track|drink|drank|had)\b/.test(lower) && !waterLogMatch && !isReminderIntent) {
    return "ℹ️ Tell me how much water, like: I drank 2 glasses just now.";
  }

  const bedtimeCommandMatch = msg.match(/(?:set|save|update|add)\s+(?:my\s+)?(?:bed\s*time|bedtime|sleep\s*time|down\s*time|downtime)\s*(?:to|at)?\s*(\d{1,2}:\d{2})(?:\s*(am|pm))?/i)
    || msg.match(/^(?:bed\s*time|bedtime|sleep\s*time|down\s*time|downtime)\s*[:\-]?\s*(\d{1,2}:\d{2})(?:\s*(am|pm))?/i);
  if (bedtimeCommandMatch?.[1] && !isReminderIntent) {
    const aiTime = bedtimeCommandMatch[1];
    const bedtimeResult = await setBedtimeReminder(aiTime, bedtimeCommandMatch[2] || "");
    if (!bedtimeResult.ok) return `ℹ️ ${bedtimeResult.message}`;
    return `✅ Bed time set to ${bedtimeResult.label}. I will remind you in-app at that time.`;
  }
  if (/(?:set|save|update|add)\b.*\b(?:bed\s*time|bedtime|sleep\s*time|down\s*time|downtime)\b/i.test(msg) && !bedtimeCommandMatch && !isReminderIntent) {
    return "ℹ️ Use 24-hour format HH:MM, like: set sleep time 22:30.";
  }

  const sleepMatch = lower.match(/(?:log|save|track|set)\s+(?:my\s+)?sleep\s*(?:to\s+|for\s+)?(\d+(?:\.\d+)?)\s*(?:h|hr|hrs|hour|hours)?(?:\s+of\s+sleep)?(?:\s+right\s+now)?/i)
    || lower.match(/(?:log|save|track|set)\s+(\d+(?:\.\d+)?)\s*(?:h|hr|hrs|hour|hours)\s*(?:of\s+)?sleep(?:\s+right\s+now)?/i)
    || lower.match(/(?:slept|sleep)\s*(?:for\s+)?(\d+(?:\.\d+)?)\s*(?:h|hr|hrs|hour|hours)\b/i)
    || lower.match(/(\d+(?:\.\d+)?)\s*(?:h|hr|hrs|hour|hours)\s*(?:sleep|slept)\b/i);
  if (sleepMatch?.[1] && !isReminderIntent) {
    sleepInput.value = sleepMatch[1];
    await saveSleep();
    return `✅ Sleep logged: ${sleepMatch[1]} hours.`;
  }
  if (/\b(log|save|track|set)\b.*\bsleep\b/.test(lower) && !sleepMatch && !isReminderIntent) {
    return "ℹ️ Tell me sleep hours too, like: log sleep 7.5h.";
  }

  const moodActionRequested = /(?:log|set|save|track|update)\s+(?:my\s+)?(?:mood|feeling)|^mood\s*[:\-]/i.test(msg);
  const mappedMood = mapMoodFromInput(msg);
  if (moodActionRequested && mappedMood && !isReminderIntent) {
    mood.value = mappedMood;
    await saveMood();
    const moodReply = pickNonRepeatingVariant(AI_MOOD_LOGGED_POOL, 'mood_logged').replaceAll('{mood}', mood.value);
    return withGreeting(moodReply);
  }
  if (moodActionRequested && !mappedMood && !isReminderIntent) {
    return "ℹ️ Mood options: happy, neutral, or low.";
  }

  const gratitudeMatch = msg.match(/^(?:add|log|save)\s+gratitude\s*[:\-]?\s*(.+)$/i);
  if (gratitudeMatch && gratitudeMatch[1] && !isReminderIntent) {
    gratitudeInput.value = gratitudeMatch[1].trim();
    await saveGratitude();
    return `✅ Gratitude saved.`;
  }

  const autoPrepPlan = await createAutoPrepPlanFromAi(user, msg);
  if (autoPrepPlan) {
    return `✅ Auto prep plan created for ${autoPrepPlan.topic} (${autoPrepPlan.timelineLabel}). Added ${autoPrepPlan.addedTasks} tasks + ${autoPrepPlan.addedReminders} reminders (focus, breaks, sleep, final review).`;
  }

  const reminderNaturalMatch = msg.match(/^(?:remind\s+me|set\s+(?:a\s+)?reminder)\s+(?:in|after)\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)\s+(?:to\s+)?(.+)$/i)
    || msg.match(/^in\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)\s+(?:remind\s+me(?:\s+to)?|set\s+(?:a\s+)?reminder(?:\s+to)?)\s+(.+)$/i);
  if (reminderNaturalMatch) {
    const amount = Number(reminderNaturalMatch[1]);
    const unitValue = normalizeReminderUnitValue(reminderNaturalMatch[2]);
    const reminderLabel = String(reminderNaturalMatch[3] || "")
      .trim()
      .replace(/^["'`“”‘’]+|["'`“”‘’]+$/g, "")
      .trim();
    if (!reminderLabel) {
      return "ℹ️ Reminder text is empty. Try: remind me in 20 min to drink water.";
    }
    const minutes = parseDurationToMinutes(amount, unitValue);
    if (!minutes) return "ℹ️ Reminder time should be at least 1 unit.";
    const previousUnit = String(reminderUnit?.value || "minute");
    reminderText.value = reminderLabel;
    reminderMinutes.value = String(amount);
    if (reminderUnit) reminderUnit.value = unitValue;
    await addReminder();
    if (reminderUnit) reminderUnit.value = previousUnit;
    return `✅ Reminder set: ${reminderLabel} in ${formatReminderDurationFromMinutes(minutes)}.`;
  }

  const reminderMatch = msg.match(/^remind\s+me\s+to\s+(.+?)\s+(?:in|after)\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)$/i)
    || msg.match(/^(?:set|add|create)\s+(?:a\s+)?reminder\s*(?:to)?\s*[:\-]?\s*(.+?)\s+(?:in|after)\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)$/i)
    || msg.match(/^reminder\s*[:\-]?\s*(.+?)\s+(?:in|after)\s+(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|wks|week|weeks|mo|mon|mons|month|months)$/i);
  if (reminderMatch) {
    const reminderLabel = reminderMatch[1]
      .trim()
      .replace(/^["'`“”‘’]+|["'`“”‘’]+$/g, "")
      .trim();
    if (!reminderLabel) {
      return "ℹ️ Reminder text is empty. Try: set reminder drink water in 20 min.";
    }
    const amount = Number(reminderMatch[2]);
    const unitValue = normalizeReminderUnitValue(reminderMatch[3]);
    const minutes = parseDurationToMinutes(amount, unitValue);
    if (!minutes) return "ℹ️ Reminder time should be at least 1 unit.";
    const previousUnit = String(reminderUnit?.value || "minute");
    reminderText.value = reminderLabel;
    reminderMinutes.value = String(amount);
    if (reminderUnit) reminderUnit.value = unitValue;
    await addReminder();
    if (reminderUnit) reminderUnit.value = previousUnit;
    return `✅ Reminder set: ${reminderLabel} in ${formatReminderDurationFromMinutes(minutes)}.`;
  }
  if (/^(?:remind\s+me\s+to|set\s+reminder|add\s+reminder|create\s+reminder|reminder\s*[:\-]?)/i.test(msg)) {
    return "ℹ️ Include time too, like: set reminder submit assignment in 45 sec or 45 min.";
  }

  const reminderDeleteMatch = msg.match(/^(?:delete|remove|cancel|clear)\s+(?:the\s+)?reminder\b(.*)$/i);
  if (reminderDeleteMatch && user?.uid) {
    const rawQuery = (reminderDeleteMatch[1] || "")
      .replace(/^\s*(?:for|about|named|:)\s*/i, "")
      .trim();

    const result = await deleteReminderFromAi(user.uid, rawQuery);
    if (result.ok) {
      const label = result.entry?.text || "selected reminder";
      return `✅ Deleted reminder: ${label}`;
    }
    return `ℹ️ ${result.message}`;
  }

  if (/^(?:list|show|view)\s+reminders$/i.test(msg) && user?.uid) {
    try {
      const snapshot = await getDocs(collection(db, "users", user.uid, "reminders"));
      const items = snapshot.docs
        .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
        .sort((a, b) => getReminderSortMs(b) - getReminderSortMs(a));

      if (!items.length) return "ℹ️ You have no reminders right now.";

      const lines = items.slice(0, 8).map((entry, index) => `${index + 1}) ${entry.text || "Reminder"}`);
      return `⏰ Reminders:\n${lines.join("\n")}`;
    } catch (err) {
      notifyFirestoreError(err);
      return "ℹ️ Could not load reminders right now.";
    }
  }

  if (/^(?:clear|delete|remove)\s+all\s+reminders$/i.test(msg) && user?.uid) {
    try {
      const snapshot = await getDocs(collection(db, "users", user.uid, "reminders"));
      await Promise.all(snapshot.docs.map((docSnap) => deleteDoc(docSnap.ref)));
      clearAllReminderTimers();
      reminders.innerHTML = "";
      scheduleEmptyState(reminders, ".item-row", "No reminders set yet — add one small prompt for today.");
      updateClearDataButtonState();
      return "✅ Cleared all reminders.";
    } catch (err) {
      notifyFirestoreError(err);
      return "ℹ️ Could not clear reminders right now.";
    }
  }

  if (!retryAfterPoliteStrip && politeStrippedMsg && politeStrippedMsg !== effectiveMsg) {
    const retried = await tryAiAction(politeStrippedMsg, user, {
      ...options,
      skipMultiSplit: true,
      skipGreeting: true,
      retryAfterPoliteStrip: true
    });
    if (retried) return withGreeting(retried);
  }

  return null;
}

async function buildSmartAiResponse(input, user) {
  const rawInput = String(input || "").trim();
  const normalizedInput = shouldSkipAiTypoNormalizationForPlannerInput(rawInput)
    ? rawInput
    : normalizeTyposForAi(rawInput).trim();
  let actionResult = null;
  try {
    actionResult = await tryAiAction(normalizedInput, user);
  } catch (_) {
    actionResult = null;
  }
  if (actionResult) {
    aiSessionState.lastIntent = "action";
    aiSessionState.lastAdvice = [];
    const greetingInfo = parseGreetingAndActionText(normalizedInput);
    if (
      greetingInfo.hasGreeting
      && greetingInfo.actionText
      && typeof actionResult === "string"
      && !new RegExp(`^${greetingInfo.greeting}\\!\\s`, "i").test(actionResult)
    ) {
      actionResult = `${greetingInfo.greeting}! ${actionResult}`;
    }
    const pickActionReplyEmoji = (actionText, inputText) => {
      const source = `${String(actionText || "")} ${String(inputText || "")}`.toLowerCase();
      if (/\b(?:water|hydrate|hydration|glass|glasses|cup|cups)\b/.test(source)) return "💧";
      if (/\b(?:sleep|bed\s*time|bedtime|downtime)\b/.test(source)) return "😴";
      if (/\b(?:reminder|remind|alarm)\b/.test(source)) return "⏰";
      if (/\b(?:task|todo|productivity|study|work)\b/.test(source)) return "✅";
      if (/\b(?:music|song|playlist|spotify)\b/.test(source)) return "🎵";
      if (/\b(?:mood|feeling|emotion)\b/.test(source)) return "🙂";
      if (/\b(?:gratitude|thankful|grateful)\b/.test(source)) return "🙏";
      if (/\b(?:memory|remember|name)\b/.test(source)) return "🧠";
      if (/\b(?:clear\s+chat|reset)\b/.test(source)) return "🧹";
      if (/\b(?:could\s+not|unknown|invalid|try\s+again|tell\s+me|include)\b/.test(source)) return "📝";
      return "✨";
    };
    const actionEmoji = pickActionReplyEmoji(actionResult, normalizedInput);
    return {
      response: `${actionResult} ${actionEmoji}`,
      isHtml: false
    };
  }

  const msg = normalizeLocalIntentText(normalizedInput);
  const baseName = getUserName(user);
  learnFromUserInput(normalizedInput);
  const name = buildUserContextLabel(baseName);
  const greeting = getTimeOfDayGreeting();
  const snapshot = getWellnessSnapshot();
  aiSessionState.lastSnapshot = snapshot;
  const recentContext = aiRecentPrompts.slice(-3).join(" • ");
  const mathResult = calculateExpressionFromText(normalizedInput);
  const emotion = detectEmotionFromText(msg);
  const detailedEmotion = detectDetailedEmotionFromText(msg);
  const intent = classifyIntent(normalizedInput);
  const tone = buildAdaptiveTone(emotion, aiSessionState.turnCount);
  const knowledgeAnswer = buildKnowledgeAnswer(normalizedInput);
  const compareRequest = parseCompareRequest(normalizedInput);
  const modePreset = getAiModePreset();
  const trendSignals = buildTrendSignals();
  const priorityBoard = buildPriorityBoard(snapshot, trendSignals);
  const sleepMoodInsight = buildSleepMoodPatternInsight(30);
  const behaviorPatterns = getBehaviorPatternMemory(35);

  if (/\b(?:thanks+|thank\s+you|thx|ty|tysm|appreciate(?:\s+it|\s+you)?)\b/i.test(msg)) {
    const thanksReply = pickNonRepeatingVariant(AI_SHORT_THANKS_REPLIES, "thanks_short") || "Anytime.";
    aiSessionState.lastIntent = "thanks";
    aiSessionState.lastAdvice = [];
    return {
      response: thanksReply,
      isHtml: false
    };
  }

  if (isAppComplaintMessage(msg)) {
    aiSessionState.lastIntent = "bug-report";
    aiSessionState.lastAdvice = [];
    return {
      response: `You can report a bug at <span class="support-email-highlight">support.novafix@gmail.com</span> and we’ll check it quickly.`,
      isHtml: true
    };
  }

  if (/\b(?:report|found|have|there(?:'s|\s+is)|noticed|seeing|raise)\b[\s\S]{0,28}\b(?:bug|issue|problem|glitch|error)\b|\b(?:bug|issue|problem|glitch|error)\b[\s\S]{0,20}\b(?:report|reported|reporting)\b/i.test(msg)) {
    aiSessionState.lastIntent = "bug-report";
    return {
      response: `You can report a bug at <span class="support-email-highlight">support.novafix@gmail.com</span> and we’ll check it quickly.`,
      isHtml: true
    };
  }

  aiSessionState.turnCount += 1;
  aiSessionState.lastUserMessage = normalizedInput;
  aiSessionState.userEmotion = emotion;
  aiSessionState.userEmotionDetailed = detailedEmotion;
  pushTopicHistory(intent.key);

  if (shouldAskIntentClarification(intent, normalizedInput)) {
    aiSessionState.lastIntent = "clarify";
    aiSessionState.lastAdvice = [];
    aiSessionState.conversationSummary = `Need clarification: ${intent.key} vs ${intent.secondaryKey || "fallback"}`;
    return {
      response: buildIntentClarificationMessage(intent),
      isHtml: false
    };
  }

  const coachingMoves = buildActionCoaching(snapshot);
  const deepPlan = buildDeepPlan(snapshot);

  const stylePrefix = buildModeAwarePrefix(tone);

  if (AI_CASUAL_MODE) {
    const casualResult = buildCasualAiResponse({
      input,
      msg,
      intent,
      emotion,
      name,
      greeting,
      snapshot,
      coachingMoves,
      deepPlan,
      trendSignals,
      priorityBoard,
      sleepMoodInsight,
      behaviorPatterns,
      knowledgeAnswer,
      compareRequest,
      mathResult
    });

    if (casualResult) {
      aiSessionState.lastIntent = casualResult.lastIntent || intent.key || "casual";
      aiSessionState.lastAdvice = Array.isArray(casualResult.advice) && casualResult.advice.length
        ? casualResult.advice
        : coachingMoves.slice(0, 3);
      aiSessionState.conversationSummary = `Last topic: ${aiSessionState.lastIntent}; mood: ${emotion}; score: ${snapshot.score}`;
      return {
        response: String(casualResult.response || ""),
        isHtml: !!casualResult.isHtml
      };
    }
  }

  if (compareRequest) {
    const comparison = buildComparisonResponse(compareRequest.left, compareRequest.right, snapshot);
    aiSessionState.lastIntent = "compare";
    aiSessionState.lastAdvice = [comparison.decisionRule];
    return {
      response: `⚖️ <b>Comparison: ${escapeHtml(compareRequest.left)} vs ${escapeHtml(compareRequest.right)}</b><br><br><b>Summary</b>: ${comparison.summary}<br><br><b>${escapeHtml(compareRequest.left)} Pros</b><br>• ${comparison.prosLeft.join("<br>• ")}<br><br><b>${escapeHtml(compareRequest.right)} Pros</b><br>• ${comparison.prosRight.join("<br>• ")}<br><br><b>Decision Rule</b>: ${comparison.decisionRule}`,
      isHtml: true
    };
  }

  if (intent.key === "greeting") {
    const pending = snapshot.pendingTasks;
    aiSessionState.lastIntent = "greeting";
    return {
      response: `Hey ${name}! Quick check: you’re at ${snapshot.score}/100, ${pending} pending task${pending === 1 ? "" : "s"}, and ${getAiWaterStatusText(snapshot)}. Want me to line up a quick 3-step game plan?`,
      isHtml: false
    };
  }

  if (intent.key === "smalltalk-health") {
    aiSessionState.lastIntent = "smalltalk-health";
    return {
      response: `${stylePrefix}I’m sharp and fully focused, ${name}. I’m tracking your live pattern (tasks, hydration, sleep, mood) and helping you make high-quality decisions quickly. You’re at ${snapshot.score}/100 right now.`,
      isHtml: false
    };
  }

  if (intent.key === "smalltalk-activity") {
    aiSessionState.lastIntent = "smalltalk-activity";
    return {
      response: `${stylePrefix}I’m analyzing your dashboard state in real time: tasks (${snapshot.doneTasks}/${snapshot.totalTasks}), hydration (${snapshot.waterToday}/${snapshot.todayGoal}), sleep (${snapshot.sleepToday || 0}h), and mood. I can either reason deeply or execute direct commands for you.`,
      isHtml: false
    };
  }

  if (intent.key === "date-local") {
    aiSessionState.lastIntent = "date-local";
    return {
      response: buildDeviceLocalDateReply(),
      isHtml: false
    };
  }

  if (intent.key === "smalltalk-casual") {
    aiSessionState.lastIntent = "smalltalk-casual";
    const waterSummary = getAiWaterStatusText(snapshot);
    if (/\bbrb|ttyl\b/.test(msg)) {
      return {
        response: `Got you. When you’re back, say "plan now" and I’ll generate the fastest high-impact sequence from your live data.`,
        isHtml: false
      };
    }
    if (/\bsup|wassup|wsg\b/.test(msg)) {
      return {
        response: `${greeting}, ${name}. I’m live and tracking your dashboard. Say "best move now" for a direct high-impact action.`,
        isHtml: false
      };
    }
    if (/\bikr|fr|frfr\b/.test(msg)) {
      return {
        response: `Exactly. Let’s convert that into progress right now: ${coachingMoves[0]}`,
        isHtml: false
      };
    }
    return {
      response: `Locked in. Current state: score ${snapshot.score}/100, tasks ${snapshot.doneTasks}/${snapshot.totalTasks}, ${waterSummary}. If you want speed, ask: "best move now".`,
      isHtml: false
    };
  }

  if (intent.key === "emotional-personal") {
    aiSessionState.lastIntent = "emotional-personal";
    return {
      response: `Thanks for sharing that, ${name}. You’re not weak — you’re overloaded. Let’s stabilize first:<br>1) 6 slow breaths (4-4-6 pattern).<br>2) Drink one glass of water.<br>3) Do one tiny win for 10 minutes: ${coachingMoves[0]}<br><br>If you want, say "guide me step by step" and I’ll stay with you through it.`,
      isHtml: true
    };
  }

  if (intent.key === "bored") {
    aiSessionState.lastIntent = "bored";
    const boredomStack = [
      snapshot.pendingTasks > 0 ? "Do one pending task for exactly 12 minutes." : "Create one meaningful task and do 12 focused minutes.",
      snapshot.waterToday < snapshot.todayGoal ? "Drink one glass of water now." : "Do a 2-minute stretch + posture reset.",
      !snapshot.gratitudeToday ? "Write one gratitude line to shift mental state." : "Run one 10-minute focused sprint on your top goal."
    ];
    return {
      response: `Boredom usually means low stimulation + unclear next action. Use this anti-bored stack now:<br>1) ${boredomStack[0]}<br>2) ${boredomStack[1]}<br>3) ${boredomStack[2]}<br><br>Reply "execute 1" and I’ll guide it.`,
      isHtml: true
    };
  }

  if (intent.key === "celebrate") {
    aiSessionState.lastIntent = "celebrate";
    return {
      response: `Love that energy. Convert it into momentum now: 1) ${coachingMoves[0]} 2) ${coachingMoves[1]} 3) ${coachingMoves[2]}.`,
      isHtml: false
    };
  }

  if (intent.key === "identity") {
    aiSessionState.lastIntent = "identity";
    return {
      response: "I am NovaFix AI — your strategic assistant. I reason over your live dashboard data, retain relevant memory, compare options, and execute supported actions directly.",
      isHtml: false
    };
  }

  if (intent.key === "thanks") {
    aiSessionState.lastIntent = "thanks";
    const pick = pickNonRepeatingVariant(AI_SHORT_THANKS_REPLIES, "thanks_short") || "Anytime.";
    return {
      response: pick,
      isHtml: false
    };
  }

  if (intent.key === "bye") {
    aiSessionState.lastIntent = "bye";
    return {
      response: `See you soon, ${name} 👋 Before you go: ${coachingMoves[0]}`,
      isHtml: false
    };
  }

  if (intent.key === "joke") {
    aiSessionState.lastIntent = "joke";
    return {
      response: "Why did the task finally get done? It stopped dating ‘later’ and committed to ‘now.’ 😄",
      isHtml: false
    };
  }

  if (mathResult) {
    aiSessionState.lastIntent = "math";
    return {
      response: `🧠 ${mathResult.expression} = ${mathResult.result}`,
      isHtml: false
    };
  }

  if (intent.key === "analysis") {
    const waterPct = Math.round((snapshot.waterToday / snapshot.todayGoal) * 100);
    const taskPct = snapshot.totalTasks ? Math.round((snapshot.doneTasks / snapshot.totalTasks) * 100) : 0;
    const moodText = snapshot.moodToday || "Not logged";
    const hydration = buildHydrationPaceInsight(snapshot);

    let actions = [];
    if (snapshot.waterToday < snapshot.todayGoal) {
      const remaining = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
      actions.push(`${hydration.summary} Log ${Math.max(1, Math.ceil(remaining))} cup${Math.max(1, Math.ceil(remaining)) === 1 ? "" : "s"} soon.`);
    }
    if (snapshot.sleepToday < 7) actions.push("Target 7–8 hours sleep tonight.");
    if (snapshot.pendingTasks > 0) actions.push("Finish 1 pending task in the next 25 minutes.");
    if (!snapshot.gratitudeToday) actions.push("Add one gratitude line before bed.");
    if (!snapshot.moodToday) actions.push("Log your mood to improve prediction quality.");
    while (actions.length < 3) actions.push("Keep momentum with one small healthy action now.");

    aiSessionState.lastIntent = "analysis";
    aiSessionState.lastAdvice = actions.slice(0, 3);
    const patternLines = Array.isArray(behaviorPatterns?.summaryLines)
      ? behaviorPatterns.summaryLines.slice(0, 3)
      : [];
    const sleepMoodPatternLine = sleepMoodInsight
      ? `<br><br><b>Pattern observed</b><br>• ${escapeHtml(sleepMoodInsight.summary)}`
      : "";
    const behaviorPatternBlock = patternLines.length
      ? `<br><br><b>Behavior patterns (${escapeHtml(behaviorPatterns?.source || "live")})</b><br>• ${patternLines.map((line) => escapeHtml(line)).join("<br>• ")}`
      : "";

    return {
      response: `📊 <b>Deep Wellness Analysis</b><br>⭐ Score: <b>${snapshot.score}/100</b><br>💧 Water: ${snapshot.waterToday}/${snapshot.todayGoal} (${Math.max(0, waterPct)}%)<br>💧 Pace signal: ${escapeHtml(hydration.summary)}<br>💤 Sleep trend avg: ${trendSignals.sleepAvg.toFixed(1)} hrs<br>🧘 Mood: ${moodText}<br>📌 Tasks done: ${snapshot.doneTasks}/${snapshot.totalTasks} (${taskPct}%)<br>🙏 Gratitude today: ${snapshot.gratitudeToday ? "Yes" : "No"}<br><br><b>Priority ranking (smart order)</b><br>1) ${priorityBoard[0].action}<br>2) ${priorityBoard[1].action}<br>3) ${priorityBoard[2].action}<br><br><b>Best next moves</b><br>1) ${actions[0]}<br>2) ${actions[1]}<br>3) ${actions[2]}${behaviorPatternBlock}${sleepMoodPatternLine}${recentContext ? `<br><br>🧠 Recent context: <i>${escapeHtml(recentContext)}</i>` : ""}`,
      isHtml: true
    };
  }

  if (intent.key === "decision") {
    aiSessionState.lastIntent = "decision";
    aiSessionState.lastAdvice = priorityBoard.slice(0, 3).map((entry) => entry.action);
    return {
      response: `🧭 <b>Best decision right now</b><br>Primary move: <b>${priorityBoard[0].action}</b><br><br><b>Why this wins</b><br>• Impact score: ${priorityBoard[0].impact}<br>• Urgency score: ${priorityBoard[0].urgency}<br>• Trend boost: ${priorityBoard[0].trendBoost}<br><br><b>Backup moves</b><br>2) ${priorityBoard[1].action}<br>3) ${priorityBoard[2].action}`,
      isHtml: true
    };
  }

  if (intent.key === "why") {
    const reasons = buildWhySummary(snapshot, trendSignals);
    aiSessionState.lastIntent = "why";
    aiSessionState.lastAdvice = reasons;
    const patternLine = Array.isArray(behaviorPatterns?.summaryLines) && behaviorPatterns.summaryLines.length
      ? `<br>• ${escapeHtml(behaviorPatterns.summaryLines[0])}`
      : "";
    const sleepMoodPatternLine = sleepMoodInsight
      ? `<br>• ${escapeHtml(sleepMoodInsight.shortSummary)} (${sleepMoodInsight.pairCount} matched days)`
      : "";
    return {
      response: `🔍 <b>Why this is your current state</b><br>• ${reasons.join("<br>• ")}<br><br><b>Trend signals</b><br>• Mood delta: ${trendSignals.moodDelta.toFixed(2)}<br>• Water delta: ${trendSignals.waterDelta.toFixed(2)}<br>• Sleep delta: ${trendSignals.sleepDelta.toFixed(2)}h<br>• Task delta: ${trendSignals.taskDelta.toFixed(2)} completed/day${patternLine}${sleepMoodPatternLine}<br><br><b>Most leverage move</b>: ${priorityBoard[0].action}`,
      isHtml: true
    };
  }

  if (intent.key === "optimize") {
    aiSessionState.lastIntent = "optimize";
    aiSessionState.lastAdvice = priorityBoard.slice(0, 4).map((entry) => entry.action);
    return {
      response: `⚙️ <b>Optimization plan (high leverage)</b><br>1) ${priorityBoard[0].action}<br>2) ${priorityBoard[1].action}<br>3) ${priorityBoard[2].action}<br>4) ${priorityBoard[3].action}<br><br><b>Execution rule</b>: finish step 1 fully before switching context.` ,
      isHtml: true
    };
  }

  if (intent.key === "plan") {
    const planItems = deepPlan;
    aiSessionState.lastIntent = "plan";
    aiSessionState.lastAdvice = planItems;
    const depthNote = modePreset.depth >= 4
      ? "<br><b>Extra layer</b>: execute step 1 immediately, then re-evaluate after 25 minutes."
      : "";
    return {
      response: `🗂️ <b>Your 60-min execution plan</b><br>• ${planItems[0]}<br>• ${planItems[1]}<br>• ${planItems[2]}<br>• ${planItems[3]}${depthNote}<br><br><b>Command mode</b>: say <i>add task ...</i> or <i>remind me to ... in 25 min</i> and I’ll execute instantly.`,
      isHtml: true
    };
  }

  if (intent.key === "followup") {
    aiSessionState.lastIntent = "followup";
    const advice = aiSessionState.lastAdvice.length ? aiSessionState.lastAdvice : coachingMoves;
    return {
      response: `Perfect. Next level plan:<br>1) ${advice[0]}<br>2) ${advice[1]}<br>3) ${advice[2]}<br><br><b>If-then guardrail</b>: if you stall for 5+ minutes, switch to this immediate move — ${priorityBoard[0].action}<br><br>If you want execution, use direct commands and I’ll run them immediately.`,
      isHtml: true
    };
  }

  if (intent.key === "stress") {
    aiSessionState.lastIntent = "stress";
    aiSessionState.lastAdvice = [
      "Do 6 rounds of 4-4-6 breathing.",
      "Drink one glass of water.",
      "Start one 10-minute micro-task."
    ];
    return {
      response: buildEmotionSupportResponse(detailedEmotion, coachingMoves),
      isHtml: false
    };
  }

  if (intent.key === "sleep") {
    aiSessionState.lastIntent = "sleep";
    const sleepPattern = behaviorPatterns?.sleepMood;
    const thresholdLabel = sleepPattern?.threshold
      ? (Number.isInteger(sleepPattern.threshold) ? String(sleepPattern.threshold) : String(sleepPattern.threshold).replace(/\.0$/, ""))
      : "";
    const sleepPatternHint = thresholdLabel
      ? ` Pattern: mood tends to drop when sleep is below ${thresholdLabel}h.`
      : (sleepMoodInsight ? ` Your logs suggest mood tends to dip below ${sleepMoodInsight.thresholdLabel}h.` : "");
    return {
      response: `Sleep analysis: no caffeine after 2 PM, dim lights 60 min pre-bed, and no scrolling in bed.${sleepPatternHint} Recent sleep average is ${trendSignals.sleepAvg.toFixed(1)}h.`,
      isHtml: false
    };
  }

  if (intent.key === "water") {
    const hydration = buildHydrationPaceInsight(snapshot);
    const pick = pickNonRepeatingVariant(AI_SHORT_THANKS_REPLIES, "thanks_short") || "Anytime.";
    return {
      response: `Hydration check 💧 ${hydration.summary}${waterPatternHint} You’re at ${snapshot.waterToday}/${snapshot.todayGoal}. Remaining: ${left} cup${left === 1 ? "" : "s"}. Want me to set a reminder right now?`,
      isHtml: false
    };
  }

  if (intent.key === "productivity") {
    aiSessionState.lastIntent = "productivity";
    const sleepProductivity = behaviorPatterns?.sleepProductivity;
    const productivityThresholdLabel = sleepProductivity?.threshold
      ? (Number.isInteger(sleepProductivity.threshold) ? String(sleepProductivity.threshold) : String(sleepProductivity.threshold).replace(/\.0$/, ""))
      : "";
    const productivityPatternHint = productivityThresholdLabel && Number(sleepProductivity?.diff) >= 0
      ? ` Pattern: task completion tends to improve at ${productivityThresholdLabel}h+ sleep.`
      : "";
    return {
      response: `Focus mode ⚡ Completed ${snapshot.doneTasks}/${snapshot.totalTasks}.${productivityPatternHint} Try: pick one pending task, 25-min timer, then 5-min break. Say “add task …” and I’ll add it instantly.`,
      isHtml: false
    };
  }

  if (intent.key === "gratitude") {
    aiSessionState.lastIntent = "gratitude";
    return {
      response: "Gratitude prompt: ‘One small thing that made today easier was…’ Want me to save your line now? Say: add gratitude <your text> 🙏",
      isHtml: false
    };
  }

  if (intent.key === "capabilities") {
    aiSessionState.lastIntent = "capabilities";
    return {
      response: "I run fully local and can execute app actions directly. Tell me the action in one line and I will do it.",
      isHtml: false
    };
  }

  if (knowledgeAnswer) {
    aiSessionState.lastIntent = "knowledge";
    aiSessionState.lastAdvice = coachingMoves;
    return {
      response: `${stylePrefix}${knowledgeAnswer}<br><br><b>Applied to you now</b>: ${coachingMoves[0]}`,
      isHtml: true
    };
  }

  if (emotion === "low") {
    aiSessionState.lastIntent = "emotional-support";
    aiSessionState.lastAdvice = [
      "Slow breathing for 60–90 seconds.",
      "Hydrate now.",
      "Start a tiny 10-minute task."
    ];
    return {
      response: buildEmotionSupportResponse(detailedEmotion, coachingMoves),
      isHtml: false
    };
  }

  if (emotion === "positive") {
    aiSessionState.lastIntent = "positive-momentum";
    return {
      response: buildEmotionSupportResponse("positive", coachingMoves),
      isHtml: false
    };
  }

  aiSessionState.lastIntent = "fallback";
  aiSessionState.conversationSummary = `Last topic: ${intent.key}; mood: ${emotion}; score: ${snapshot.score}`;
  const personalGoal = aiSessionState.userFacts.goal ? `<br>🎯 Your stated goal: <i>${escapeHtml(aiSessionState.userFacts.goal)}</i>` : "";

  if (modePreset.style === "ultra") {
    return {
      response: buildUltraFallback(snapshot, name),
      isHtml: true
    };
  }

  const riskDrivers = buildWhySummary(snapshot, trendSignals).slice(0, 3);

  return {
    response: `🧠 <b>Strategic synthesis</b><br><b>State</b>: score ${snapshot.score}/100, tasks ${snapshot.doneTasks}/${snapshot.totalTasks}, water ${snapshot.waterToday}/${snapshot.todayGoal}, sleep ${snapshot.sleepToday || 0}h.<br><b>Main constraints</b>: ${riskDrivers.join(" • ")}<br><b>Execution order</b>:<br>1) ${coachingMoves[0]}<br>2) ${coachingMoves[1]}<br>3) ${coachingMoves[2]}${personalGoal}<br><br>Ask for <i>deeper reasoning</i>, <i>A vs B</i>, or a <i>step-by-step plan</i>.`,
    isHtml: true
  };
}

function hasActionableSuggestionText(responseText, isHtml = false) {
  const text = String(responseText || "");
  if (!text.trim()) return false;
  const normalized = (isHtml ? text.replace(/<[^>]+>/g, " ") : text).toLowerCase().replace(/\s+/g, " ").trim();
  if (!normalized) return false;

  if (/\b(?:what can you do|quick status|today is|local time|i am doing good|i'm doing good|you are at)\b/.test(normalized)) {
    return false;
  }

  if (/\b(?:next easy win|best move|most leverage move|execution order|top 3|step\s*\d|do this now|start with|try this|action plan|focus now)\b/.test(normalized)) {
    return true;
  }

  if (/(?:^|\s)(?:1\)|2\)|3\)|1\.|2\.|3\.)/.test(normalized)) {
    return true;
  }

  return /\b(?:do|start|focus|drink|log|set|complete|apply|track|review|schedule|plan|action)\b/.test(normalized);
}

function normalizeAiResponseSignature(text, isHtml = false) {
  const plain = String(text || "");
  const normalized = (isHtml ? plain.replace(/<[^>]+>/g, " ") : plain)
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\b\d+\b/g, "#")
    .replace(/\s+/g, " ")
    .trim();
  return normalized.slice(0, 220);
}

function rememberAiResponseSignature(text, isHtml = false) {
  const signature = normalizeAiResponseSignature(text, isHtml);
  if (!signature) return;
  aiRecentResponseSignatures.push(signature);
  if (aiRecentResponseSignatures.length > AI_RESPONSE_SIGNATURE_HISTORY_LIMIT) {
    aiRecentResponseSignatures.splice(0, aiRecentResponseSignatures.length - AI_RESPONSE_SIGNATURE_HISTORY_LIMIT);
  }
}

function isWeakGenericAiResponse(text, isHtml = false) {
  const plain = (isHtml ? String(text || "").replace(/<[^>]+>/g, " ") : String(text || ""))
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
  if (!plain) return true;
  if (plain.length < 60) return true;

  const weakPatterns = [
    /^(?:got you|i got you|noted|cool|sure|okay|ok)[.!\s]*$/,
    /\b(?:you are doing great|keep going|you got this)\b/,
    /\b(?:let me know if you need anything|anything else\?)\b/,
    /\b(?:quick answer|direct answer)\b.*\b(?:ask me anything)\b/
  ];
  if (weakPatterns.some((pattern) => pattern.test(plain))) return true;

  return false;
}

function hasRecentResponseRepetition(text, isHtml = false) {
  const signature = normalizeAiResponseSignature(text, isHtml);
  if (!signature) return false;
  const recent = aiRecentResponseSignatures.slice(-AI_RESPONSE_SIGNATURE_COMPARE_WINDOW);
  return recent.some((item) => item === signature);
}

function buildImmediateBenefitOutcome(snapshot, topAction) {
  const pendingTasks = Number(snapshot?.pendingTasks) || 0;
  const waterToday = Number(snapshot?.waterToday) || 0;
  const waterGoalNow = Number(snapshot?.todayGoal) || 8;
  const waterGap = Math.max(0, waterGoalNow - waterToday);
  const sleepNow = Number(snapshot?.sleepToday) || 0;

  if (pendingTasks > 0) {
    return `You should feel more in control tonight after reducing pending tasks by 1 and finishing one focused sprint.`;
  }
  if (waterGap > 0) {
    return `You should feel calmer tonight by closing at least ${Math.max(1, Math.ceil(waterGap / 2))} cup${Math.max(1, Math.ceil(waterGap / 2)) === 1 ? "" : "s"} of your hydration gap.`;
  }
  if (sleepNow < 7) {
    return "You should feel steadier tomorrow morning by protecting a 7-8 hour sleep window tonight.";
  }
  return `You should feel more organized tonight by completing this first: ${topAction}`;
}

function buildTomorrowCheckpoint(snapshot) {
  const pendingTasks = Number(snapshot?.pendingTasks) || 0;
  const waterToday = Number(snapshot?.waterToday) || 0;
  const waterGoalNow = Number(snapshot?.todayGoal) || 8;
  const sleepNow = Number(snapshot?.sleepToday) || 0;

  if (pendingTasks >= 2) {
    return "Tomorrow check: start with one 25-minute task sprint before opening distractions.";
  }
  if (waterToday < waterGoalNow) {
    return "Tomorrow check: drink one glass in the first hour after waking and keep a visible water target.";
  }
  if (sleepNow < 7) {
    return "Tomorrow check: wake at a fixed time and avoid snooze loops to stabilize energy.";
  }
  return "Tomorrow check: repeat the same first win within your first hour for consistency.";
}

function getHealthFirstTopAction(snapshot, trends, priorityBoard = []) {
  const currentIntent = String(aiSessionState?.lastIntent || "").toLowerCase();
  const lowEmotion = String(aiSessionState?.userEmotion || "").toLowerCase() === "low";
  const stressIntent = currentIntent === "stress" || currentIntent === "emotional-personal";
  const moodRisk = Number(trends?.moodDelta) < 0;
  const sleepLow = (Number(snapshot?.sleepToday) || 0) > 0 && (Number(snapshot?.sleepToday) || 0) < 7;
  const hydrationGap = Math.max(0, (Number(snapshot?.todayGoal) || 8) - (Number(snapshot?.waterToday) || 0));

  const shouldForceHealthFirst = lowEmotion || stressIntent || moodRisk;
  if (!shouldForceHealthFirst) {
    return priorityBoard?.[0]?.action || "Complete one 10-minute focused task now.";
  }

  if (sleepLow) {
    return "Do a 2-minute calm-down reset now and protect a 7-8 hour sleep window tonight.";
  }

  if (hydrationGap > 0) {
    return `Drink ${Math.max(1, Math.ceil(Math.min(2, hydrationGap)))} cup${Math.max(1, Math.ceil(Math.min(2, hydrationGap))) === 1 ? "" : "s"} of water now, then do one 10-minute low-pressure task.`;
  }

  if (!snapshot?.moodToday) {
    return "Log your mood now, do 6 slow breaths, then complete one 10-minute calming task.";
  }

  return "Take a 2-minute breathing reset, then complete one small task to regain control.";
}

function buildMustDoBenefitBlock(baseText, baseIsHtml, inputText) {
  const snapshot = aiSessionState.lastSnapshot || getWellnessSnapshot();
  const trends = buildTrendSignals();
  const priorityBoard = buildPriorityBoard(snapshot, trends);
  const topAction = getHealthFirstTopAction(snapshot, trends, priorityBoard);
  const plan = buildDeepPlan(snapshot);
  const outcomeTonight = buildImmediateBenefitOutcome(snapshot, topAction);
  const lowEmotion = String(aiSessionState?.userEmotion || "").toLowerCase() === "low";
  const tomorrowCheckpoint = lowEmotion
    ? "Tomorrow check: repeat a calm first hour (water + no-rush first task) before high-pressure work."
    : buildTomorrowCheckpoint(snapshot);

  const opener = pickNonRepeatingVariant(AI_BENEFIT_PLAN_OPENERS, "benefit_plan_openers")
    || "Direct plan based on your current data:";

  // Use strategic response templates so replies sound varied but remain data-driven.
  const strategicTpl = pickNonRepeatingVariant(AI_STRATEGIC_RESPONSE_POOL, 'strategic_mustdo') || null;
  const goalLine = aiSessionState.userFacts.goal ? (baseIsHtml ? `<br>🎯 Goal alignment: <i>${escapeHtml(aiSessionState.userFacts.goal)}</i>` : `\n\n🎯 Goal alignment: ${escapeHtml(aiSessionState.userFacts.goal)}`) : "";
  if (strategicTpl) {
    const filled = strategicTpl
      .replaceAll('{name}', escapeHtml(String(getUserName() || "there")))
      .replaceAll('{plan0}', escapeHtml(String(topAction || '')))
      .replaceAll('{plan1}', escapeHtml(String(plan[1] || '')))
      .replaceAll('{plan2}', escapeHtml(String(plan[2] || '')))
      .replaceAll('{plan3}', escapeHtml(String(plan[3] || '')))
      .replaceAll('{topAction}', escapeHtml(String(topAction || '')))
      .replaceAll('{outcomeTonight}', escapeHtml(String(outcomeTonight || '')))
      .replaceAll('{tomorrowCheckpoint}', escapeHtml(String(tomorrowCheckpoint || '')))
      .replaceAll('{goalLine}', goalLine)
      .replaceAll('{opener}', escapeHtml(opener))
      .replaceAll('{why}', buildWhySuggestionLine(baseIsHtml, strategicTpl));
    return filled;
  }

  // Fallback to original formatting if no strategic template available.
  if (baseIsHtml) {
    const safeBase = String(baseText || "").trim();
    return `${safeBase}<br><br><b>${escapeHtml(opener)}</b><br><b>Do now (under 10 min)</b>: ${escapeHtml(topAction)}<br><b>Expected by tonight</b>: ${escapeHtml(outcomeTonight)}<br><b>Tomorrow checkpoint</b>: ${escapeHtml(tomorrowCheckpoint)}`;
  }

  const safeBase = String(baseText || "").trim();
  return `${safeBase}\n\n${opener}\nDo now (under 10 min): ${topAction}\nExpected by tonight: ${outcomeTonight}\nTomorrow checkpoint: ${tomorrowCheckpoint}`;
}

function enforceAiResponseQuality(inputText, responseText, isHtml = false) {
  const currentIntent = String(aiSessionState?.lastIntent || "").toLowerCase();
  const exemptIntents = new Set([
    "thanks",
    "bye",
    "joke",
    "date-local",
    "action",
    "action-log",
    "action-set",
    "action-reminder",
    "bug-report",
    "identity",
    "capabilities",
    "greeting",
    "smalltalk-health",
    "smalltalk-activity",
    "smalltalk-casual",
    "math",
    "compare",
    "knowledge",
    "clarify"
  ]);
  const eligibleIntents = new Set([
    "plan",
    "optimize",
    "analysis",
    "decision",
    "why",
    "stress",
    "emotional-personal",
    "productivity",
    "water",
    "sleep",
    "followup",
    "fallback",
    "bored",
    "celebrate"
  ]);
  const shouldEnforceBenefitBlock = !exemptIntents.has(currentIntent) && eligibleIntents.has(currentIntent);

  let nextText = String(responseText || "");
  let nextIsHtml = !!isHtml;

  const weakGeneric = isWeakGenericAiResponse(nextText, nextIsHtml);
  const nonActionable = !hasActionableSuggestionText(nextText, nextIsHtml);
  const repeated = hasRecentResponseRepetition(nextText, nextIsHtml);

  if (shouldEnforceBenefitBlock && (weakGeneric || nonActionable || repeated)) {
    nextText = buildMustDoBenefitBlock(nextText, nextIsHtml, inputText);
    nextIsHtml = nextIsHtml || /<[^>]+>/.test(nextText);
  } else if (shouldEnforceBenefitBlock && !/Expected by tonight|Tomorrow checkpoint|Do now \(under 10 min\)/i.test(String(nextText))) {
    nextText = buildMustDoBenefitBlock(nextText, nextIsHtml, inputText);
    nextIsHtml = nextIsHtml || /<[^>]+>/.test(nextText);
  }

  rememberAiResponseSignature(nextText, nextIsHtml);
  return { text: nextText, isHtml: nextIsHtml };
}

function buildWhySuggestionLine(isHtml = true, suggestionText = "") {
  const snapshot = aiSessionState.lastSnapshot || getWellnessSnapshot();
  const trend = buildTrendSignals();
  const reasons = [];
  const contextText = String(suggestionText || "").replace(/<[^>]+>/g, " ").toLowerCase();

  const mentionsHydration = /\b(?:water|hydrate|hydration|glass|glasses|cup|cups)\b/.test(contextText);
  const mentionsSleep = /\b(?:sleep|bedtime|rest|downtime)\b/.test(contextText);
  const mentionsTasks = /\b(?:task|tasks|todo|focus|productivity|work|study)\b/.test(contextText);
  const mentionsMood = /\b(?:mood|emotion|stress|anxious|calm)\b/.test(contextText);
  const mentionsGratitude = /\b(?:gratitude|grateful|thankful)\b/.test(contextText);

  const targetGoal = snapshot.hasWaterGoal ? Math.max(1, Number(snapshot.todayGoal) || 8) : 0;
  const waterGap = Math.max(0, targetGoal - (Number(snapshot.waterToday) || 0));
  if (snapshot.hasWaterGoal) {
    if (mentionsHydration ? waterGap > 0 : waterGap >= 2) reasons.push(`${waterGap} glass hydration gap`);
  } else if (mentionsHydration) {
    reasons.push("water goal not set");
  }

  const sleepLow = (Number(snapshot.sleepToday) || 0) > 0 && (Number(snapshot.sleepToday) || 0) < 7;
  if (mentionsSleep ? sleepLow : sleepLow && (Number(snapshot.sleepToday) || 0) <= 6.5) reasons.push("sleep below 7h");

  const pendingTasks = Number(snapshot.pendingTasks) || 0;
  if (mentionsTasks ? pendingTasks > 0 : pendingTasks >= 2) {
    reasons.push(`${pendingTasks} pending task${pendingTasks === 1 ? "" : "s"}`);
  }

  if (mentionsGratitude && !snapshot.gratitudeToday) reasons.push("gratitude not logged today");
  if (mentionsMood && trend.moodDelta < 0) reasons.push("mood trend dipped");
  if (mentionsTasks && trend.taskDelta < 0) reasons.push("task trend softened");

  if (!reasons.length) {
    if (snapshot.hasWaterGoal && waterGap > 0) reasons.push(`${waterGap} glass hydration gap`);
    else if (pendingTasks > 0) reasons.push(`${pendingTasks} pending task${pendingTasks === 1 ? "" : "s"}`);
    else if (!snapshot.gratitudeToday) reasons.push("gratitude not logged today");
  }

  const shortReasons = reasons.slice(0, 3);
  if (!shortReasons.length) shortReasons.push("you’re in momentum mode — this keeps consistency high");

  if (isHtml) {
    return `<br><br><b>Why this suggestion</b>: ${shortReasons.join(" • ")}`;
  }
  return `\n\nWhy this suggestion: ${shortReasons.join(" • ")}`;
}

function setChatText(textNode, text, isHtml) {
  if (isHtml) textNode.innerHTML = text;
  else textNode.textContent = text;
}

function renderChatMessage(role, messageText, isHtml, chatId, fieldName) {
  clearStatusState(chat);
  const row = document.createElement("div");
  row.className = "chat-message";
  row.classList.add(role === "user" ? "is-user" : "is-ai");

  const textNode = document.createElement("div");
  textNode.className = "chat-text";
  let displayText = messageText;
  let displayIsHtml = !!isHtml;
  if (role === "ai") {
    const safeOutput = applyAiOutputSafetyFilter(messageText, isHtml);
    displayText = safeOutput.text;
    displayIsHtml = safeOutput.isHtml;
  }
  textNode.dataset.rawText = displayText;
  setChatText(textNode, `${role === "user" ? "You" : "AI"}: ${displayText}`, displayIsHtml);

  row.append(textNode);

  if (role === "user") {
    const editBtn = document.createElement("button");
    editBtn.className = "chat-edit-btn";
    editBtn.textContent = "Edit";
    editBtn.onclick = () => editChatMessage(chatId, fieldName, textNode, role);
    row.append(editBtn);
  }

  chat.appendChild(row);
  setAiClearButtonState(true);
  updateAiLimitUI();
  chat.scrollTop = chat.scrollHeight;
}

async function editChatMessage(chatId, fieldName, textNode, role) {
  const user = auth.currentUser;
  if (user) {
    await ensureAiUsageCurrent(user.uid);
    const dailyLimit = getCurrentAiDailyLimit();
    if (aiUsageCount >= dailyLimit) {
      updateAiLimitUI();
      alert(buildDailyLimitCountdownMessage(`Daily AI limit reached (${dailyLimit}/${dailyLimit})`));
      return;
    }
  }

  const currentText = textNode.dataset.rawText || "";
  const updatedText = prompt("Edit message", currentText);
  if (updatedText === null) return;

  const nextText = updatedText.trim();
  if (!nextText) {
    alert("Message cannot be empty.");
    return;
  }

  const moderation = getAiAbuseModerationResult(nextText);
  if (moderation.blocked) {
    alert(moderation.message);
    return;
  }

  textNode.dataset.rawText = nextText;
  setChatText(textNode, `${role === "user" ? "You" : "AI"}: ${nextText}`, false);

  if (!user || !chatId) return;

  try {
    const snapshot = await getDocs(collection(db, "users", user.uid, "aiChats"));
    const chatEntries = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = a.createdAt?.toMillis?.() ?? new Date(a.createdAt || 0).getTime();
        const bTime = b.createdAt?.toMillis?.() ?? new Date(b.createdAt || 0).getTime();
        return aTime - bTime;
      });

    const editedIndex = chatEntries.findIndex((entry) => entry.id === chatId);
    if (editedIndex < 0) return;

    const smart = await buildSmartAiResponse(nextText, user);
    const safeEdited = applyAiOutputSafetyFilter(smart.response, smart.isHtml);
    await updateDoc(doc(db, "users", user.uid, "aiChats", chatId), {
      userMessage: nextText,
      aiResponse: safeEdited.text,
      aiResponseIsHtml: safeEdited.isHtml,
      updatedAt: serverTimestamp()
    });

    const entriesAfterEdited = chatEntries.slice(editedIndex + 1);
    if (entriesAfterEdited.length) {
      await Promise.all(
        entriesAfterEdited.map((entry) =>
          deleteDoc(doc(db, "users", user.uid, "aiChats", entry.id))
        )
      );
    }

    await loadAiChats(user.uid);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function renderChatPair(entry) {
  renderChatMessage("user", entry.userMessage || "", false, entry.id, "userMessage");
  renderChatMessage("ai", entry.aiResponse || "", !!entry.aiResponseIsHtml, entry.id, "aiResponse");

  aiSessionState.memoryPairs.push({
    user: String(entry.userMessage || ""),
    ai: String(entry.aiResponse || "")
  });
  if (aiSessionState.memoryPairs.length > 24) {
    aiSessionState.memoryPairs.splice(0, aiSessionState.memoryPairs.length - 24);
  }
}

function setAiClearButtonState(hasChats) {
  if (!aiClearBtn) return;
  const canClear = !!hasChats && !pendingAiClearOperation;
  aiClearBtn.disabled = !canClear;
  aiClearBtn.title = canClear ? "" : "No AI chats to clear";
}

function setTimeMirrorClearButtonState(hasContent) {
  if (!timeMirrorClearBtn) return;
  const canClear = !!hasContent;
  timeMirrorClearBtn.disabled = !canClear;
  timeMirrorClearBtn.title = canClear ? "" : "No time mirror content to clear";
  if (futureTask) futureTask.style.display = canClear ? "none" : "block";
  if (timeMirrorCheckBtn) timeMirrorCheckBtn.style.display = canClear ? "none" : "inline-block";
}

function clearTimeMirror() {
  if (!timeMirror || timeMirrorClearBtn?.disabled) return;
  const confirmed = confirm("Clear Time Traveller Mirror output?");
  if (!confirmed) return;
  timeMirror.innerHTML = "";
  setTimeMirrorClearButtonState(false);
}

setTimeMirrorClearButtonState(!!String(timeMirror?.textContent || "").trim());

function containsAbusiveLanguage(inputText) {
  const raw = String(inputText || "").toLowerCase();
  if (!raw) return false;

  const maskedProfanity = /\bf[\W_]*u[\W_]*\*+|\bs[\W_]*h[\W_]*\*+|\bb[\W_]*\*+[\W_]*t[\W_]*c[\W_]*h\b/i;
  if (maskedProfanity.test(raw)) return true;

  const lettersOnly = raw.replace(/[^a-z]/g, "");
  return AI_ABUSE_TERMS.some((term) => lettersOnly.includes(term));
}

function getAiAbuseModerationResult(inputText) {
  const now = Date.now();
  if (aiAbuseCooldownUntilMs && now >= aiAbuseCooldownUntilMs) {
    aiAbuseCooldownUntilMs = 0;
    aiAbuseStrikeCount = 0;
  }
  if (now < aiAbuseCooldownUntilMs) {
    return {
      blocked: true,
      message: buildAiAbuseCooldownMessage(aiAbuseCooldownUntilMs - now)
    };
  }

  const isAbusive = containsAbusiveLanguage(inputText);
  if (!isAbusive) {
    aiAbuseStrikeCount = 0;
    return { blocked: false, message: "" };
  }

  aiAbuseStrikeCount += 1;
  if (aiAbuseStrikeCount === 1) {
    return {
      blocked: true,
      message: "Please keep messages respectful. I can help with your goals if you rephrase."
    };
  }

  if (aiAbuseStrikeCount === 2) {
    return {
      blocked: true,
      message: "I can’t respond to abusive language. Try a clean version of your request."
    };
  }

  aiAbuseCooldownUntilMs = now + AI_ABUSE_COOLDOWN_MS;
  return {
    blocked: true,
    message: buildAiAbuseCooldownMessage(AI_ABUSE_COOLDOWN_MS)
  };
}

function detectUnsafeAiOutputCategory(outputText) {
  const text = String(outputText || "").toLowerCase();
  if (!text.trim()) return "";

  const selfHarmPattern = /(how\s+to|ways\s+to|steps\s+to|best\s+way\s+to).{0,45}(suicide|self\s*harm|harm\s*yourself|kill\s*yourself|kys)/i;
  if (selfHarmPattern.test(text) || /\byou\s+should\s+(kill\s+yourself|kys)\b/i.test(text)) return "self-harm";

  const hatePattern = /(kill\s+all|attack|eliminate|exterminate).{0,35}(people|group|race|religion|women|men|gay|trans|immigrant)/i;
  if (hatePattern.test(text)) return "hate";

  const sexualViolencePattern = /(how\s+to|ways\s+to|steps\s+to|tips\s+to).{0,45}(rape|sexual\s+assault|molest|force\s+sex|coerce\s+sex)/i;
  if (sexualViolencePattern.test(text)) return "sexual-violence";

  return "";
}

function applyAiOutputSafetyFilter(outputText, isHtml) {
  const category = detectUnsafeAiOutputCategory(outputText);
  if (!category) {
    return {
      text: outputText,
      isHtml: !!isHtml,
      blocked: false,
      category: ""
    };
  }

  return {
    text: "I can’t help with harmful content. I can help with safety, emotional support, and healthy next steps.",
    isHtml: false,
    blocked: true,
    category
  };
}

async function loadAiChats(userId) {
  chat.innerHTML = "";
  aiRecentPrompts.length = 0;
  aiRecentResponseSignatures.length = 0;
  aiVariantHistory.clear();
  aiSessionState.lastIntent = "";
  aiSessionState.lastAdvice = [];
  aiSessionState.lastUserMessage = "";
  aiSessionState.conversationSummary = "";
  aiSessionState.topicHistory.length = 0;
  aiSessionState.memoryPairs.length = 0;

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "aiChats"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = a.createdAt?.toMillis?.() ?? new Date(a.createdAt || 0).getTime();
        const bTime = b.createdAt?.toMillis?.() ?? new Date(b.createdAt || 0).getTime();
        return aTime - bTime;
      });

    docs.forEach((entry) => {
      if (entry.userMessage) rememberPrompt(entry.userMessage);
      renderChatPair(entry);
    });
    if (!docs.length) {
      setEmptyState(chat, "No AI chats yet — ask one question to get started.");
    }
    setAiClearButtonState(docs.length > 0);
    updateAiLimitUI();
    updateClearDataButtonState();
  } catch (err) {
    setAiClearButtonState(false);
    notifyFirestoreError(err);
  }
}

async function storeAiChat(userId, userMessage, aiResponse, aiResponseIsHtml) {
  try {
    const ref = await addDoc(
      collection(db, "users", userId, "aiChats"),
      {
        userMessage,
        aiResponse,
        aiResponseIsHtml,
        createdAt: serverTimestamp()
      }
    );
    return ref.id;
  } catch (err) {
    notifyFirestoreError(err);
    return null;
  }
}

async function clearAiChats(options = {}) {
  const skipConfirm = !!options?.skipConfirm;
  const user = auth.currentUser;
  if (!user) return false;

  if (aiClearBtn?.disabled) {
    showToast("There was nothing to clear.");
    return false;
  }

  if (!skipConfirm && !confirm("Clear all AI conversations?")) return false;

  try {
    const snapshot = await getDocs(collection(db, "users", user.uid, "aiChats"));
    if (!snapshot.docs.length) {
      setEmptyState(chat, "No AI chats yet — ask one question to get started.");
      showToast("There was nothing to clear.");
      setAiClearButtonState(false);
      updateClearDataButtonState();
      return false;
    }

    if (pendingAiClearOperation?.timerId) {
      clearTimeout(pendingAiClearOperation.timerId);
      pendingAiClearOperation = null;
    }

    const docsToDelete = snapshot.docs.map((docSnap) => ({ id: docSnap.id, ref: docSnap.ref, data: docSnap.data() }));

    chat.innerHTML = "";
    aiRecentPrompts.length = 0;
    aiRecentResponseSignatures.length = 0;
    aiVariantHistory.clear();
    aiSessionState.lastIntent = "";
    aiSessionState.lastAdvice = [];
    aiSessionState.lastUserMessage = "";
    aiSessionState.conversationSummary = "";
    aiSessionState.topicHistory.length = 0;
    setAiClearButtonState(false);

    const finalizeDelete = async () => {
      try {
        await Promise.all(docsToDelete.map((entry) => deleteDoc(entry.ref)));
      } catch (err) {
        notifyFirestoreError(err);
      }
      pendingAiClearOperation = null;
      scheduleEmptyState(chat, ".chat-message", "No AI chats yet — ask one question to get started.");
      setAiClearButtonState(false);
      updateClearDataButtonState();
    };

    const timerId = setTimeout(finalizeDelete, 5000);
    pendingAiClearOperation = { timerId };

    showToast("AI chats cleared.", {
      actionLabel: "Undo",
      duration: 5000,
      onAction: async () => {
        if (pendingAiClearOperation?.timerId) clearTimeout(pendingAiClearOperation.timerId);
        pendingAiClearOperation = null;
        await loadAiChats(user.uid);
        showToast("AI chats restored.");
        updateClearDataButtonState();
      }
    });
    return true;
  } catch (err) {
    setAiClearButtonState(chat?.querySelectorAll?.(".chat-message")?.length > 0);
    notifyFirestoreError(err);
    return false;
  }
}

async function aiChat(){
  if (aiChatSubmitting) return;
  const input = aiInput.value.trim();
  if(!input) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  if (isClearChatCommand(input)) {
    await clearAiChats();
    aiInput.value = "";
    return;
  }

  const moderation = getAiAbuseModerationResult(input);
  if (moderation.blocked) {
    renderChatMessage("ai", moderation.message, false, null, null);
    aiInput.value = "";
    updateAiLimitUI();
    return;
  }

  aiChatSubmitting = true;
  if (aiTalkBtn) aiTalkBtn.disabled = true;

  try {
    await ensureAiUsageCurrent(user.uid);
    const dailyLimit = getCurrentAiDailyLimit();
    const quotaResult = await reserveAiQuota(user.uid, dailyLimit);
    if (!quotaResult.ok) {
      renderChatMessage("ai", buildDailyLimitCountdownMessage("Daily AI limit reached for now"), false, null, null);
      updateAiLimitUI();
      aiInput.value = "";
      return;
    }

    try {
      const smart = await buildSmartAiResponse(input, user);
      let response = smart.response;
      let responseIsHtml = smart.isHtml;
      const qualityResult = enforceAiResponseQuality(input, response, responseIsHtml);
      response = qualityResult.text;
      responseIsHtml = qualityResult.isHtml;
      const shouldAttachWhy =
        !AI_CASUAL_MODE
        &&
        !!aiSessionState.lastSnapshot
        && aiSessionState.lastIntent !== "why"
        && hasActionableSuggestionText(response, responseIsHtml)
        && !/I can also run:|I can also do:/i.test(String(response || ""));
      if (shouldAttachWhy) {
        response = `${response}${buildWhySuggestionLine(responseIsHtml, response)}`;
      }

      const safeOutput = applyAiOutputSafetyFilter(response, responseIsHtml);
      response = safeOutput.text;
      responseIsHtml = safeOutput.isHtml;
      rememberPrompt(input);

      const chatId = await storeAiChat(user.uid, input, response, responseIsHtml);
      if (!chatId) {
        await rollbackAiQuota(user.uid);
        return;
      }

      renderChatPair({
        id: chatId,
        userMessage: input,
        aiResponse: response,
        aiResponseIsHtml: responseIsHtml
      });
      updateAiLimitUI();
      updateClearDataButtonState();
      aiInput.value="";
    } catch (err) {
      await rollbackAiQuota(user.uid);
      renderChatMessage("ai", "I hit a quick issue processing that. Please try once more.", false, null, null);
      notifyFirestoreError(err);
    }
  } finally {
    aiChatSubmitting = false;
    updateAiLimitUI();
  }
}

// Reminders
function clearReminderTimer(reminderId) {
  const timerId = reminderIntervals.get(reminderId);
  if (timerId) {
    clearInterval(timerId);
    reminderIntervals.delete(reminderId);
  }
}

function clearAllReminderTimers() {
  reminderIntervals.forEach((timerId) => clearInterval(timerId));
  reminderIntervals.clear();
}

function getReminderSortMs(entry) {
  const createdMs = toDateSafe(entry?.createdAt)?.getTime?.()
    || toDateSafe(entry?.time)?.getTime?.()
    || 0;
  if (createdMs) return createdMs;
  return Number(entry?.targetAtMs) || 0;
}

function formatReminderDurationFromSeconds(totalSeconds) {
  let remaining = Math.max(0, Math.ceil(Number(totalSeconds) || 0));
  if (!remaining) return "0 sec";

  const units = [
    { label: "year", seconds: 365 * 24 * 60 * 60 },
    { label: "month", seconds: 30 * 24 * 60 * 60 },
    { label: "week", seconds: 7 * 24 * 60 * 60 },
    { label: "day", seconds: 24 * 60 * 60 },
    { label: "hr", seconds: 60 * 60 },
    { label: "min", seconds: 60 },
    { label: "sec", seconds: 1 }
  ];

  const parts = [];
  for (const unit of units) {
    if (remaining < unit.seconds) continue;
    const value = Math.floor(remaining / unit.seconds);
    remaining -= value * unit.seconds;
    const suffix = value === 1 ? "" : "s";
    parts.push(`${value} ${unit.label}${suffix}`);
    if (parts.length >= 2) break;
  }

  return parts.length ? parts.join(" ") : "0 sec";
}

function formatReminderDurationFromMinutes(totalMinutes) {
  const safeMinutes = Math.max(0, Number(totalMinutes) || 0);
  return formatReminderDurationFromSeconds(safeMinutes * 60);
}

async function deleteReminderFromAi(userId, query) {
  try {
    const snapshot = await getDocs(collection(db, "users", userId, "reminders"));
    const remindersList = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => getReminderSortMs(b) - getReminderSortMs(a));

    if (!remindersList.length) {
      return { ok: false, message: "No reminders found." };
    }

    const trimmedQuery = (query || "").trim();
    let targetReminder = null;

    if (!trimmedQuery) {
      targetReminder = remindersList[0];
    } else if (/^\d+$/.test(trimmedQuery)) {
      const index = Number(trimmedQuery) - 1;
      if (index >= 0 && index < remindersList.length) {
        targetReminder = remindersList[index];
      }
    }

    if (!targetReminder && trimmedQuery) {
      const lowered = trimmedQuery.toLowerCase();
      targetReminder = remindersList.find((entry) => (entry.text || "").toLowerCase().includes(lowered));
    }

    if (!targetReminder) {
      return { ok: false, message: `No reminder matched \"${trimmedQuery}\".` };
    }

    await deleteDoc(doc(db, "users", userId, "reminders", targetReminder.id));
    clearReminderTimer(targetReminder.id);
    await loadReminders(userId);

    return { ok: true, entry: targetReminder };
  } catch (err) {
    notifyFirestoreError(err);
    return { ok: false, message: "Could not delete reminder right now." };
  }
}

function renderReminder(entry, options = {}) {
  const insertAtTop = options.insertAtTop !== false;
  clearStatusState(reminders);
  const li = document.createElement("li");
  li.className = "item-row";

  const label = document.createElement("span");
  label.className = "item-text";
  let reminderTextValue = entry.text || "Reminder";
  const reminderMinutes = Number(entry.minutes) || 0;
  const targetAtMs = Number(entry.targetAtMs) || (getServerNowDate().getTime() + reminderMinutes * 60000);

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const editBtn = document.createElement("button");
  editBtn.textContent = "✏️";
  editBtn.onclick = async () => {
    const nextText = prompt("Edit reminder", reminderTextValue);
    if (!nextText || !nextText.trim()) return;

    const user = auth.currentUser;
    const trimmedText = nextText.trim();

    if (user && entry.id) {
      try {
        await updateDoc(doc(db, "users", user.uid, "reminders", entry.id), {
          text: trimmedText
        });
      } catch (err) {
        notifyFirestoreError(err);
        return;
      }
    }

    reminderTextValue = trimmedText;
    entry.text = trimmedText;
    setLabelText(secondsRemaining);
  };

  const deleteBtn = document.createElement("button");
  deleteBtn.className = "remove-entry-btn";
  deleteBtn.textContent = "🗑️";
  deleteBtn.onclick = async () => {
    if (!confirm(`Delete reminder "${reminderTextValue}"?`)) return;
    const user = auth.currentUser;
    clearReminderTimer(entry.id);

    if (user && entry.id) {
      try {
        await deleteDoc(doc(db, "users", user.uid, "reminders", entry.id));
        await updateReminderLimitUI(user.uid);
      } catch (err) {
        notifyFirestoreError(err);
      }
    }
    li.remove();
    scheduleEmptyState(reminders, ".item-row", "No reminders set yet — add one small prompt for today.");
    updateClearDataButtonState();

    if (user) {
      await updateReminderLimitUI(user.uid);
    }
  };

  const setLabelText = (secondsLeft) => {
    if (secondsLeft <= 0) {
      label.textContent = `• ${reminderTextValue} – Time's up!`;
      return;
    }
    label.textContent = `• ${reminderTextValue} – ${formatReminderDurationFromSeconds(secondsLeft)} left`;
  };

  let secondsRemaining = Math.max(0, Math.ceil((targetAtMs - getServerNowDate().getTime()) / 1000));
  setLabelText(secondsRemaining);

  if (secondsRemaining > 0) {
    const timer = setInterval(() => {
      secondsRemaining -= 1;
      if (secondsRemaining <= 0) {
        clearReminderTimer(entry.id);
        setLabelText(0);
        void playReminderChimeWithAudioDucking(reminderTextValue);
        return;
      }
      setLabelText(secondsRemaining);
    }, 1000);
    if (entry.id) reminderIntervals.set(entry.id, timer);
  }

  actions.append(editBtn, deleteBtn);
  li.append(label, actions);
  if (insertAtTop && reminders.firstChild) {
    reminders.insertBefore(li, reminders.firstChild);
  } else {
    reminders.appendChild(li);
  }
}

async function loadReminders(userId) {
  reminders.innerHTML = "";
  clearAllReminderTimers();

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "reminders"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => getReminderSortMs(b) - getReminderSortMs(a));

    docs.forEach((entry) => renderReminder(entry, { insertAtTop: false }));
    if (!docs.length) {
      setEmptyState(reminders, "No reminders set yet — add one small prompt for today.");
    }
    await updateReminderLimitUI(userId);
    updateClearDataButtonState();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function addReminder() {
  if (reminderSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const t = reminderText.value.trim();
  const rawAmount = getReminderAmountInputValue();
  const rawUnit = String(reminderUnit?.value || "minute");
  const m = parseDurationToMinutes(rawAmount, rawUnit);
  clearReminderInputError();
  if (!t) return;
  if (rawAmount < 1 || m <= 0) {
    setReminderInputError("Reminder time must be at least 1 unit.");
    showToast("Reminder time must be at least 1 unit.");
    return;
  }

  if (t.length > REMINDER_MAX_TEXT_LENGTH) {
    showToast(`Reminder text is too long. Maximum is ${REMINDER_MAX_TEXT_LENGTH} characters.`);
    return;
  }

  if (m > REMINDER_MAX_MINUTES) {
    showToast(`Reminder time is too high. Maximum is ${formatReminderDurationFromMinutes(REMINDER_MAX_MINUTES)}.`);
    return;
  }

  reminderSubmitting = true;
  if (reminderSetBtn) reminderSetBtn.disabled = true;

  try {
    await ensureDailyUsageCurrent(user.uid, { skipReminderRefresh: true });

    const quotaResult = await reserveDailyQuota(user.uid, "reminderCount", REMINDER_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s reminder limit (${REMINDER_DAILY_LIMIT}/day)`));
      await updateReminderLimitUI(user.uid);
      return;
    }

    const targetAtMs = getServerNowDate().getTime() + (m * 60 * 1000);

    try {
      const ref = await addDoc(collection(db, "users", user.uid, "reminders"), {
        text: t,
        minutes: m,
        targetAtMs,
        createdAt: serverTimestamp()
      });

      renderReminder({ id: ref.id, text: t, minutes: m, targetAtMs }, { insertAtTop: true });
      reminderText.value = "";
      reminderMinutes.value = "";
      const reminderMsg = pickNonRepeatingVariant(AI_REMINDER_ADDED_POOL, 'reminder_set')
        .replaceAll('{text}', t)
        .replaceAll('{minutes}', String(m));
      showToast(reminderMsg);
      await trimCollectionToMaxEntries(user.uid, "reminders", MAX_REMINDER_ENTRIES, (entry) => {
        return Number(entry.targetAtMs) || toDateSafe(entry.createdAt)?.getTime?.() || 0;
      });
      await updateReminderLimitUI(user.uid);
      updateClearDataButtonState();
    } catch (err) {
      await rollbackDailyQuota(user.uid, "reminderCount");
      notifyFirestoreError(err);
    }
  } finally {
    reminderSubmitting = false;
    await updateReminderLimitUI(user.uid);
  }
}

// Tasks
function getTaskSortTimestamp(entry) {
  const completedAtMs = toDateSafe(entry?.completedAt)?.getTime?.() || 0;
  const createdAtMs = toDateSafe(entry?.time)?.getTime?.() || 0;
  return completedAtMs || createdAtMs || 0;
}

function sortTasksForDisplay(entries = []) {
  return [...entries].sort((a, b) => {
    const aCompleted = !!a?.completed;
    const bCompleted = !!b?.completed;
    if (aCompleted !== bCompleted) return aCompleted ? 1 : -1;
    return getTaskSortTimestamp(b) - getTaskSortTimestamp(a);
  });
}

function renderTaskList() {
  if (!taskList) return;
  taskList.innerHTML = "";
  const sortedTasks = sortTasksForDisplay(taskEntries);
  if (!sortedTasks.length) {
    setEmptyState(taskList, "No tasks yet — add one quick win to begin.");
    return;
  }
  sortedTasks.forEach((entry) => renderTask(entry, { insertAtTop: false }));
}

function renderTask(entry, options = {}) {
  const insertAtTop = options.insertAtTop !== false;
  clearStatusState(taskList);
  const li = document.createElement("li");
  li.className = "item-row";
  const span = document.createElement("span");
  span.className = "item-text";
  span.textContent = entry.text;
  if (entry.completed) span.classList.add("task-done");

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const toggleBtn = document.createElement("button");
  toggleBtn.textContent = entry.completed ? "✅" : "⬜";
  toggleBtn.title = "Toggle complete";
  toggleBtn.onclick = async () => {
    entry.completed = !entry.completed;
    entry.completedAt = entry.completed ? getServerNowDate() : null;
    span.classList.toggle("task-done", entry.completed);
    toggleBtn.textContent = entry.completed ? "✅" : "⬜";

    const listIndex = taskEntries.findIndex((taskItem) => taskItem.id === entry.id);
    if (listIndex >= 0) {
      taskEntries[listIndex].completed = entry.completed;
      taskEntries[listIndex].completedAt = entry.completedAt;
    }
    renderTaskList();
    updateInsights();

    const user = auth.currentUser;
    if (!user || !entry.id) return;
    try {
      await updateDoc(doc(db, "users", user.uid, "tasks", entry.id), {
        completed: entry.completed,
        completedAt: entry.completed ? serverTimestamp() : null
      });
    } catch (err) {
      notifyFirestoreError(err);
    }
  };

  const editBtn = document.createElement("button");
  editBtn.textContent = "✏️";
  editBtn.onclick = async () => {
    const newText = prompt("Edit task", span.textContent);
    if (!newText || !newText.trim()) return;
    span.textContent = newText.trim();

    const user = auth.currentUser;
    if (!user || !entry.id) return;
    try {
      await updateDoc(doc(db, "users", user.uid, "tasks", entry.id), { text: newText.trim() });
    } catch (err) {
      notifyFirestoreError(err);
    }
  };

  const deleteBtn = document.createElement("button");
  deleteBtn.classList.add("remove-entry-btn");
  deleteBtn.textContent = "🗑️";
  deleteBtn.onclick = async () => {
    if (!confirm(`Delete task "${entry.text || "Task"}"?`)) return;
    const user = auth.currentUser;
    if (!user || !entry.id) {
      const fallbackIndex = taskEntries.findIndex((taskItem) => taskItem.id === entry.id);
      if (fallbackIndex >= 0) taskEntries.splice(fallbackIndex, 1);
      renderTaskList();
      updateInsights();
      updateTaskLimitUI();
      return;
    }
    try {
      await deleteDoc(doc(db, "users", user.uid, "tasks", entry.id));
      const listIndex = taskEntries.findIndex((taskItem) => taskItem.id === entry.id);
      if (listIndex >= 0) taskEntries.splice(listIndex, 1);
      renderTaskList();
      updateInsights();
      updateTaskLimitUI();
    } catch (err) {
      notifyFirestoreError(err);
    }
  };

  actions.append(toggleBtn, editBtn, deleteBtn);
  li.append(span, actions);
  if (insertAtTop && taskList.firstChild) {
    taskList.insertBefore(li, taskList.firstChild);
  } else {
    taskList.appendChild(li);
  }
}

async function loadTasks(userId) {
  taskList.innerHTML = "";
  taskEntries.length = 0;
  try {
    const snapshot = await getDocs(collection(db, "users", userId, "tasks"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = a.time?.toMillis?.() ?? new Date(a.time || 0).getTime();
        const bTime = b.time?.toMillis?.() ?? new Date(b.time || 0).getTime();
        return bTime - aTime;
      });
    docs.forEach((entry) => {
      const normalized = {
        ...entry,
        completed: !!entry.completed,
        completedAt: toDateSafe(entry.completedAt)
      };
      taskEntries.push(normalized);
    });
    renderTaskList();
    updateTaskLimitUI();
    updateInsights();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function addTask(){
  if (taskSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const t=task.value.trim();
  if(!t)return;

  taskSubmitting = true;
  if (taskAddBtn) taskAddBtn.disabled = true;

  try {
    await ensureDailyUsageCurrent(user.uid, { skipReminderRefresh: true });

    const quotaResult = await reserveDailyQuota(user.uid, "taskCount", TASK_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s task limit (${TASK_DAILY_LIMIT}/day)`));
      updateTaskLimitUI();
      return;
    }

    try {
      const ref = await addDoc(collection(db, "users", user.uid, "tasks"), {
        text: t,
        completed: false,
        completedAt: null,
        time: serverTimestamp()
      });
      const newTask = { id: ref.id, text: t, completed: false, completedAt: null, time: getServerNowDate() };
      taskEntries.push(newTask);
      renderTaskList();
      const taskMsg = pickNonRepeatingVariant(AI_TASK_ADDED_POOL, 'task_added').replaceAll('{task}', t);
      showToast(taskMsg);
      updateInsights();
      task.value="";
      await trimCollectionToMaxEntries(user.uid, "tasks", MAX_TASK_ENTRIES, (entry) => toDateSafe(entry.time)?.getTime?.() || 0);
      updateTaskLimitUI();
    } catch (err) {
      await rollbackDailyQuota(user.uid, "taskCount");
      notifyFirestoreError(err);
    }
  } finally {
    taskSubmitting = false;
    updateTaskLimitUI();
  }
}

// Finance
function calculateFinance(){
  const cost = parseFloat(gCost.value) || 0;
  const months = parseFloat(gMonths.value) || 1;
  const buf = parseFloat(buffer.value) || 0;

  const total = cost * months * (1 + buf/100);
  const monthly = total / months;

  financeResult.innerText = `Total: ₹${total.toFixed(0)} | Monthly: ₹${monthly.toFixed(0)}`;
}

// Mood
function renderMoodLog(entry) {
  clearStatusState(moodLogs);
  const moodRow = document.createElement("div");
  moodRow.className = "mood-item";

  const moodLabel = document.createElement("span");
  const rawTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());
  moodLabel.textContent = `${rawTime.toLocaleTimeString()} - ${entry.mood}`;

  const removeBtn = document.createElement("button");
  removeBtn.className = "mood-remove remove-entry-btn";
  removeBtn.textContent = "Remove";
  removeBtn.onclick = () => deleteMoodLog(entry.id);

  moodRow.append(moodLabel, removeBtn);
  moodLogs.appendChild(moodRow);
}

async function deleteMoodLog(moodId) {
  const user = auth.currentUser;
  if (!user || !moodId) return;

  try {
    await deleteDoc(doc(db, "users", user.uid, "moods", moodId));
    await loadMoods(user.uid);
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadMoods(userId) {
  moodLogs.innerHTML = "";
  moodHistory.length = 0;
  moodDates.length = 0;

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "moods"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = a.time?.toMillis?.() ?? new Date(a.time || 0).getTime();
        const bTime = b.time?.toMillis?.() ?? new Date(b.time || 0).getTime();
        return aTime - bTime;
      });

    const todayKey = getTodayKey();
    let renderedCount = 0;
    docs.forEach((entry) => {
      moodHistory.push(entry.mood);
      const moodTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());
      moodDates.push(moodTime);
      if (dateToKey(moodTime) === todayKey) {
        renderMoodLog({ ...entry, time: moodTime });
        renderedCount += 1;
      }
    });
    if (!renderedCount) {
      setEmptyState(moodLogs, "No mood logs yet — one check-in is enough to start.");
    }
    updateMoodLimitUI();
    updateInsights();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function saveMood() {
  if (moodSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const moodValue = String(mood?.value || "").trim();
  if (!moodValue) {
    showToast("Please select a mood first.");
    return;
  }

  moodSubmitting = true;
  if (moodSaveBtn) moodSaveBtn.disabled = true;

  try {
    await ensureDailyUsageCurrent(user.uid, { skipReminderRefresh: true });

    const quotaResult = await reserveDailyQuota(user.uid, "moodCount", MOOD_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s mood log limit (${MOOD_DAILY_LIMIT}/day)`));
      updateMoodLimitUI();
      return;
    }

    try {
      const moodRef = await addDoc(
        collection(db, "users", user.uid, "moods"),
        {
          mood: moodValue,
          uid: user.uid,
          email: user.email || null,
          time: serverTimestamp()
        }
      );

      moodHistory.push(moodValue);
      moodDates.push(getServerNowDate());
      renderMoodLog({ id: moodRef.id, mood: moodValue, time: getServerNowDate() });
      const moodMsg = `Logged Mood [${moodValue}]`;
      showToast(moodMsg);
      updateInsights();
      await trimCollectionToMaxEntries(user.uid, "moods", MAX_MOOD_ENTRIES, (entry) => toDateSafe(entry.time)?.getTime?.() || 0);
      updateMoodLimitUI();
    } catch (err) {
      await rollbackDailyQuota(user.uid, "moodCount");
      notifyFirestoreError(err);
    }
  } finally {
    moodSubmitting = false;
    updateMoodLimitUI();
  }
}

// Water
let waterGoal=0;
function updateWaterProgress() {
  const todayKey = getTodayKey();
  let latestTodayValue = 0;
  for (let index = waterHistory.length - 1; index >= 0; index -= 1) {
    const dateKey = dateToKey(waterDates[index]);
    if (dateKey === todayKey) {
      latestTodayValue = Number(waterHistory[index]) || 0;
      break;
    }
  }
  const percent = waterGoal > 0 ? Math.round((latestTodayValue / waterGoal) * 100) : 0;
  waterProgress.innerText = `${latestTodayValue}/${waterGoal} (${percent}%)`;
  updateWaterClearButtonState();
  updateInsights();
}

function updateWaterClearButtonState() {
  if (!waterClearBtn) return;
  const hasWaterLogs = waterHistory.length > 0 || waterDates.length > 0;
  const hasGoal = (Number(waterGoal) || 0) > 0;
  waterClearBtn.disabled = !(hasWaterLogs || hasGoal);
}

async function setWaterGoal(){
  const user = auth.currentUser;
  waterGoal = +waterGoalInput.value || 0;
  updateWaterProgress();

  if (waterGoal > 0) {
    alert(`✅ Water goal set to ${waterGoal} glasses.`);
  } else {
    alert("ℹ️ Water goal cleared.");
  }
  waterGoalInput.value = "";

  if (!user) return;
  try {
    const todayKey = getTodayKey();
    await setDoc(doc(db, "users", user.uid, "settings", "water"), {
      goal: waterGoal,
      goalDateKey: todayKey,
      lastResetDateKey: todayKey
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadWaterData(userId) {
  waterHistory.length = 0;
  waterDates.length = 0;

  try {
    const todayKey = getTodayKey();
    let shouldResetDayData = false;
    const waterSettings = await fsGetDoc(doc(db, "users", userId, "settings", "water"), 'water');
    if (waterSettings.exists) {
      const settings = waterSettings.data || {};
      const savedGoal = Number(settings.goal) || 0;
      const goalDateKey = settings.goalDateKey || null;
      const lastResetDateKey = settings.lastResetDateKey || null;

      if (lastResetDateKey && lastResetDateKey !== todayKey) {
        shouldResetDayData = true;
      } else if (!lastResetDateKey) {
        await setDoc(doc(db, "users", userId, "settings", "water"), {
          lastResetDateKey: todayKey
        }, { merge: true });
      }

      if (!shouldResetDayData && savedGoal > 0 && goalDateKey && goalDateKey !== todayKey) {
        shouldResetDayData = true;
      }

      if (shouldResetDayData) {
        await resetWaterDayData(userId, todayKey);
        waterGoal = 0;
      } else {
        waterGoal = savedGoal;
      }
    } else {
      waterGoal = 0;
      await setDoc(doc(db, "users", userId, "settings", "water"), {
        goal: 0,
        goalDateKey: todayKey,
        lastResetDateKey: todayKey
      }, { merge: true });
    }
    waterGoalInput.value = waterGoal || "";

    const snapshot = await getDocs(collection(db, "users", userId, "waterIntake"));
    const docs = snapshot.docs
      .map((docSnap) => docSnap.data())
      .sort((a, b) => {
        const aTime = a.time?.toMillis?.() ?? new Date(a.time || 0).getTime();
        const bTime = b.time?.toMillis?.() ?? new Date(b.time || 0).getTime();
        return aTime - bTime;
      });

    docs.forEach((entry) => {
      if (entry.glasses) {
        waterHistory.push(entry.glasses);
        const waterTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());
        waterDates.push(waterTime);
      }
    });

    updateWaterLimitUI();
    updateWaterProgress();
    updateWaterClearButtonState();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function saveWater() {
  if (waterSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const rawWater = String(waterInput?.value || "").trim();
  if (!rawWater) return;
  const v = Number(rawWater);
  if (!Number.isFinite(v) || v <= 0) {
    showToast("Water amount must be greater than 0.");
    return;
  }
  if (v > WATER_MAX_GLASSES_PER_ENTRY) {
    showToast(`You can log a maximum of ${WATER_MAX_GLASSES_PER_ENTRY} glasses at once.`);
    return;
  }

  waterSubmitting = true;
  if (waterTrackBtn) waterTrackBtn.disabled = true;

  const previousTodayWater = (() => {
    const todayKey = getTodayKey();
    for (let index = waterHistory.length - 1; index >= 0; index -= 1) {
      const dateKey = dateToKey(waterDates[index]);
      if (dateKey === todayKey) {
        return Number(waterHistory[index]) || 0;
      }
    }
    return 0;
  })();

  try {
    await ensureDailyUsageCurrent(user.uid, { skipReminderRefresh: true });

    const quotaResult = await reserveDailyQuota(user.uid, "waterCount", WATER_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s water log limit (${WATER_DAILY_LIMIT}/day)`));
      updateWaterLimitUI();
      return;
    }

    waterHistory.push(v);

    try {
      await addDoc(collection(db, "users", user.uid, "waterIntake"), {
        glasses: v,
        time: serverTimestamp()
      });
      waterDates.push(getServerNowDate());
      updateWaterProgress();

      const target = Number(waterGoal) || 0;
      if (target > 0 && previousTodayWater < target && v >= target) {
        alert("🎉 Water goal complete!");
      }

      waterInput.value = "";
      const prev = Number(previousTodayWater) || 0;
      const totalNow = (prev + v).toFixed(1);
      const waterMsg = pickNonRepeatingVariant(AI_WATER_LOGGED_POOL, 'water_logged')
        .replaceAll('{amount}', String(v))
        .replaceAll('{total}', String(totalNow));
      showToast(waterMsg);
      await trimCollectionToMaxEntries(user.uid, "waterIntake", MAX_WATER_ENTRIES, (entry) => toDateSafe(entry.time)?.getTime?.() || 0);
      updateWaterLimitUI();
    } catch (err) {
      waterHistory.pop();
      await rollbackDailyQuota(user.uid, "waterCount");
      notifyFirestoreError(err);
    }
  } finally {
    waterSubmitting = false;
    updateWaterLimitUI();
  }
}

async function clearWaterData() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const confirmed = confirm("Clear your current water intake and goal?");
  if (!confirmed) return;

  if (pendingWaterClearOperation?.timerId) {
    clearTimeout(pendingWaterClearOperation.timerId);
    pendingWaterClearOperation = null;
  }

  const previousHistory = [...waterHistory];
  const previousDates = [...waterDates];
  const previousGoal = Number(waterGoal) || 0;

  waterHistory.length = 0;
  waterDates.length = 0;
  waterGoal = 0;
  waterGoalInput.value = "";
  waterInput.value = "";
  updateWaterProgress();
  updateWaterLimitUI();
  updateWaterClearButtonState();

  const finalizeDelete = async () => {
    try {
      const intakeSnapshot = await getDocs(collection(db, "users", user.uid, "waterIntake"));
      await Promise.all(intakeSnapshot.docs.map((docSnap) => deleteDoc(docSnap.ref)));
      await setDoc(doc(db, "users", user.uid, "settings", "water"), {
        goal: 0,
        goalDateKey: getTodayKey(),
        lastResetDateKey: getTodayKey()
      }, { merge: true });
    } catch (err) {
      notifyFirestoreError(err);
    }
    pendingWaterClearOperation = null;
  };

  pendingWaterClearOperation = {
    timerId: setTimeout(finalizeDelete, 5000)
  };

  showToast("Water data cleared.", {
    actionLabel: "Undo",
    duration: 5000,
    onAction: async () => {
      if (pendingWaterClearOperation?.timerId) clearTimeout(pendingWaterClearOperation.timerId);
      pendingWaterClearOperation = null;

      waterHistory.length = 0;
      waterDates.length = 0;
      previousHistory.forEach((value) => waterHistory.push(value));
      previousDates.forEach((value) => waterDates.push(value));
      waterGoal = previousGoal;
      waterGoalInput.value = previousGoal ? String(previousGoal) : "";
      waterInput.value = "";
      updateWaterProgress();
      updateWaterLimitUI();
      updateWaterClearButtonState();

      if (previousHistory.length) {
        try {
          const intakeSnapshot = await getDocs(collection(db, "users", user.uid, "waterIntake"));
          await Promise.all(intakeSnapshot.docs.map((docSnap) => deleteDoc(docSnap.ref)));
          for (let i = 0; i < previousHistory.length; i += 1) {
            await addDoc(collection(db, "users", user.uid, "waterIntake"), {
              glasses: Number(previousHistory[i]) || 0,
              time: previousDates[i] || getServerNowDate()
            });
          }
          await setDoc(doc(db, "users", user.uid, "settings", "water"), {
            goal: previousGoal,
            goalDateKey: getTodayKey(),
            lastResetDateKey: getTodayKey()
          }, { merge: true });
        } catch (err) {
          notifyFirestoreError(err);
        }
      }

      showToast("Water data restored.");
    }
  });
}

// Sleep
function normalizeBedtimeMeridiem(value) {
  const raw = String(value || "").trim().toUpperCase();
  if (raw === "AM" || raw === "PM") return raw;
  return "";
}

function normalizeBedtimeTimeText(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";

  const filtered = raw.replace(/[^\d:]/g, "");
  const firstColonIndex = filtered.indexOf(":");

  const normalizeMinutePart = (valuePart) => {
    const digits = String(valuePart || "").replace(/\D/g, "").slice(0, 2);
    if (digits.length <= 1) return digits;
    if (Number(digits[0]) > 5) return digits[0];
    return digits;
  };

  const normalizeHourPart = (valuePart) => {
    const digits = String(valuePart || "").replace(/\D/g, "").slice(0, 2);
    if (digits.length <= 1) return digits;
    if (Number(digits[0]) > 2) return digits[0];
    if (Number(digits[0]) === 2 && Number(digits[1]) > 3) return digits[0];
    return digits;
  };

  if (firstColonIndex !== -1) {
    const hourPart = normalizeHourPart(filtered.slice(0, firstColonIndex));
    if (!hourPart) return "";
    const minutePart = normalizeMinutePart(filtered.slice(firstColonIndex + 1));
    return minutePart.length ? `${hourPart}:${minutePart}` : `${hourPart}:`;
  }

  const digits = filtered.replace(/\D/g, "").slice(0, 4);
  if (!digits) return "";
  if (digits.length === 1) return digits;
  if (digits.length === 2) {
    return normalizeHourPart(digits);
  }

  const firstTwo = digits.slice(0, 2);
  const normalizedFirstTwo = normalizeHourPart(firstTwo);
  const useTwoDigitHour = normalizedFirstTwo.length === 2;
  const hourPart = useTwoDigitHour ? normalizedFirstTwo : normalizeHourPart(digits[0]);
  const minuteSource = useTwoDigitHour ? digits.slice(2) : digits.slice(1, 3);

  const minutePart = normalizeMinutePart(minuteSource);
  return minutePart.length ? `${hourPart}:${minutePart}` : `${hourPart}:`;
}

function parseBedtimeInput(timeText, meridiemValue = "") {
  const safeTime = normalizeBedtimeTimeText(timeText);
  const legacyMeridiem = normalizeBedtimeMeridiem(meridiemValue);
  const match = safeTime.match(/^(\d{1,2}):(\d{2})$/);
  if (!match) {
    return { ok: false, message: "Use bedtime format HH:MM (24h), for example 21:30." };
  }

  let hour = Number(match[1]);
  const minute = Number(match[2]);

  // Legacy migration support: convert stored/input 12h values when AM/PM exists.
  if (legacyMeridiem && Number.isInteger(hour) && hour >= 1 && hour <= 12) {
    hour = (hour % 12) + (legacyMeridiem === "PM" ? 12 : 0);
  }

  if (!Number.isInteger(hour) || hour < 0 || hour > 23) {
    return { ok: false, message: "Bedtime hour must be between 00 and 23." };
  }
  if (!Number.isInteger(minute) || minute < 0 || minute > 59) {
    return { ok: false, message: "Bedtime minutes must be between 00 and 59." };
  }

  const formattedTime = `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
  return {
    ok: true,
    hour,
    minute,
    formattedTime,
    label: formattedTime
  };
}

function setBedtimeInputError(message = "") {
  if (!bedtimeInputError) return;
  const text = String(message || "").trim();
  bedtimeInputError.innerText = text;
  bedtimeInputError.classList.toggle("show", !!text);
  if (text) bedtimeInputError.dataset.bedtimeAlreadySet = "0";
  else delete bedtimeInputError.dataset.bedtimeAlreadySet;
}

function setBedtimeAlreadySetMessage(label) {
  if (!bedtimeInputError) return;
  bedtimeInputError.innerText = `Bed time is already set for ${label}.`;
  bedtimeInputError.classList.add("show");
  bedtimeInputError.dataset.bedtimeAlreadySet = "1";
}

function clearBedtimeAlreadySetMessage() {
  if (!bedtimeInputError) return;
  if (bedtimeInputError.dataset.bedtimeAlreadySet !== "1") return;
  bedtimeInputError.innerText = "";
  bedtimeInputError.classList.remove("show");
  delete bedtimeInputError.dataset.bedtimeAlreadySet;
}

function updateBedtimeSetButtonState() {
  if (!bedtimeSetBtn) return;

  const timeText = String(bedtimeTimeInput?.value || "").trim();
  const currentParsed = parseBedtimeInput(timeText);

  if (!currentParsed.ok) {
    bedtimeSetBtn.disabled = true;
    bedtimeSetBtn.title = "Enter a valid 24-hour bedtime to set.";
    clearBedtimeAlreadySetMessage();
    return;
  }

  const storedParsed = parseBedtimeInput(bedtimeSettings?.timeText || "");
  const hasStoredBedtime = !!bedtimeSettings?.enabled && storedParsed.ok;
  const unchanged = hasStoredBedtime
    && currentParsed.formattedTime === storedParsed.formattedTime;

  if (unchanged) {
    if (bedtimeInputTouchedSinceSync) {
      setBedtimeAlreadySetMessage(storedParsed.label);
    }
    bedtimeSetBtn.disabled = !bedtimeAllowUnchangedResubmit;
    bedtimeSetBtn.title = bedtimeAllowUnchangedResubmit
      ? ""
      : "Already done for this bedtime. Change value or wait for bedtime popup.";
    return;
  }

  clearBedtimeAlreadySetMessage();
  bedtimeSetBtn.disabled = false;
  bedtimeSetBtn.title = "";
}

function closeBedtimeReminderModal(event, force = false) {
  if (event?.target && event.target !== bedtimeReminderModal) return;
  if (bedtimeReminderModal && (force || bedtimeReminderModal.style.display === "flex")) {
    bedtimeReminderModal.style.display = "none";
  }
}

function openBedtimeReminderModal() {
  if (!bedtimeReminderModal || !bedtimeReminderPreview) return;
  const label = bedtimeSettings?.timeText
    ? bedtimeSettings.timeText
    : "your scheduled bedtime";
  const bedtimeMessages = [
    "It is time for bed. Start your wind-down routine now.",
    "Bedtime is approaching. Let's get you ready for quality sleep.",
    "Your bedtime reminder: time to wind down and rest.",
    "Sleep time is here. Prepare your mind and body for rest.",
    "It's bed time. Time to step away and recharge.",
    "Your scheduled bedtime. Close work and relax now."
  ];
  const randomMessage = bedtimeMessages[Math.floor(Math.random() * bedtimeMessages.length)];
  bedtimeReminderPreview.innerHTML = `
    <div class="friend-row">
      <strong>${escapeHtml(label)}</strong>
      <small>${randomMessage}</small>
    </div>
  `;
  bedtimeAllowUnchangedResubmit = true;
  updateBedtimeSetButtonState();
  bedtimeReminderModal.style.display = "flex";
  ensureAppBackGuardState("bedtime-reminder", true);
}

function clearBedtimeReminderSchedule() {
  if (bedtimeReminderTimeoutId) {
    clearTimeout(bedtimeReminderTimeoutId);
    bedtimeReminderTimeoutId = null;
  }
}

async function autoClearBedtimeAfterReminderTrigger(userId = "") {
  const activeUserId = String(userId || auth.currentUser?.uid || "").trim();

  bedtimeSettings = { timeText: "", enabled: false };
  bedtimeInputTouchedSinceSync = false;
  bedtimeAllowUnchangedResubmit = false;
  clearBedtimeReminderSchedule();
  if (bedtimeTimeInput) bedtimeTimeInput.value = "";
  setBedtimeInputError("");
  updateBedtimeSetButtonState();

  if (!activeUserId) return;

  try {
    await setDoc(doc(db, "users", activeUserId, "settings", "sleep"), {
      bedtimeEnabled: false,
      bedtimeTime: "",
      bedtimeMeridiem: "",
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true });
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function scheduleBedtimeReminder() {
  clearBedtimeReminderSchedule();
  if (!bedtimeSettings?.enabled) return;

  const parsed = parseBedtimeInput(bedtimeSettings.timeText);
  if (!parsed.ok) return;

  const now = getServerNowDate();
  const target = new Date(now);
  target.setHours(parsed.hour, parsed.minute, 0, 0);
  if (target.getTime() <= now.getTime()) {
    target.setDate(target.getDate() + 1);
  }

  const delayMs = Math.max(1000, target.getTime() - now.getTime());
  bedtimeReminderTimeoutId = setTimeout(() => {
    bedtimeReminderTimeoutId = null;
    const triggerKey = `${dateToKey(getServerNowDate()) || "today"}_${parsed.label}`;
    if (bedtimeReminderLastTriggeredKey !== triggerKey) {
      bedtimeReminderLastTriggeredKey = triggerKey;
      openBedtimeReminderModal();
      void autoClearBedtimeAfterReminderTrigger(auth.currentUser?.uid || "");
    }
  }, delayMs);
}

async function loadBedtimeSettings(userId) {
  bedtimeSettings = { timeText: "", enabled: false };
  bedtimeReminderLastTriggeredKey = "";
  bedtimeInputTouchedSinceSync = false;
  bedtimeAllowUnchangedResubmit = false;
  if (bedtimeTimeInput) bedtimeTimeInput.value = "";
  setBedtimeInputError("");
  updateBedtimeSetButtonState();
  closeBedtimeReminderModal(null, true);
  clearBedtimeReminderSchedule();

  if (!userId) return;
  
  // Guard: verify auth state
  if (!auth.currentUser?.uid) {
    structuredLog('warn', 'bedtime.auth_check', 'User not authenticated');
    return;
  }

  try {
    const snap = await fsGetDoc(doc(db, "users", userId, "settings", "sleep"), 'sleep');
    if (!snap.exists) return;

    const data = snap.data || {};
    if (typeof data !== 'object' || data === null) {
      structuredLog('warn', 'bedtime.data_shape', 'Sleep settings malformed');
      return;
    }
    
    const parsed = parseBedtimeInput(data.bedtimeTime || "", data.bedtimeMeridiem || "");
    if (!parsed.ok || data.bedtimeEnabled === false) return;

    bedtimeSettings = {
      timeText: parsed.formattedTime,
      enabled: true
    };

    if (bedtimeTimeInput) bedtimeTimeInput.value = "";
    bedtimeInputTouchedSinceSync = false;
    bedtimeAllowUnchangedResubmit = false;
    scheduleBedtimeReminder();
    updateBedtimeSetButtonState();
  } catch (err) {
    notifyFirestoreError(err);
    updateBedtimeSetButtonState();
  }
}

async function setBedtimeReminder(timeOverride = "", meridiemOverride = "") {
  const user = auth.currentUser;
  if (!user?.uid) {
    showToast("Please sign in first.");
    return { ok: false, message: "Please sign in first." };
  }

  const timeText = String(timeOverride || bedtimeTimeInput?.value || "").trim();
  const parsed = parseBedtimeInput(timeText, meridiemOverride || "");
  if (!parsed.ok) {
    setBedtimeInputError(parsed.message);
    updateBedtimeSetButtonState();
    return { ok: false, message: parsed.message };
  }

  setBedtimeInputError("");

  try {
    await setDoc(doc(db, "users", user.uid, "settings", "sleep"), {
      bedtimeEnabled: true,
      bedtimeTime: parsed.formattedTime,
      bedtimeMeridiem: "",
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true });

    bedtimeSettings = {
      timeText: parsed.formattedTime,
      enabled: true
    };

    if (bedtimeTimeInput) bedtimeTimeInput.value = "";
    bedtimeReminderLastTriggeredKey = "";
    bedtimeInputTouchedSinceSync = false;
    bedtimeAllowUnchangedResubmit = false;
    scheduleBedtimeReminder();
    updateBedtimeSetButtonState();

    alert(`✅ Bed time set for ${parsed.label}.`);
    return { ok: true, label: parsed.label };
  } catch (err) {
    notifyFirestoreError(err);
    updateBedtimeSetButtonState();
    return { ok: false, message: "Could not save bed time right now." };
  }
}

async function loadSleepData(userId) {
  sleepHistory.length = 0;
  sleepDates.length = 0;
  sleepResult.innerText = "";

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "sleepLogs"));
    const docs = snapshot.docs
      .map((docSnap) => docSnap.data())
      .sort((a, b) => {
        const aTime = a.time?.toMillis?.() ?? new Date(a.time || 0).getTime();
        const bTime = b.time?.toMillis?.() ?? new Date(b.time || 0).getTime();
        return aTime - bTime;
      });

    docs.forEach((entry) => {
      if (entry.hours) {
        sleepHistory.push(entry.hours);
        const sleepTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());
        sleepDates.push(sleepTime);
      }
    });

    const todayKey = getTodayKey();
    let latestTodaySleep = 0;
    for (let index = sleepHistory.length - 1; index >= 0; index -= 1) {
      const key = dateToKey(sleepDates[index]);
      if (key === todayKey) {
        latestTodaySleep = Number(sleepHistory[index]) || 0;
        break;
      }
    }

    if (latestTodaySleep > 0) {
      sleepResult.innerText = `${latestTodaySleep} hrs 💤`;
    }
    updateSleepLimitUI();
    updateInsights();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function saveSleep(){
  if (sleepSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const rawSleep = String(sleepInput?.value || "").trim();
  if (!rawSleep) return;
  const hours = Number(rawSleep);
  if (!Number.isFinite(hours) || hours <= 0) {
    showToast("Sleep hours must be greater than 0.");
    return;
  }

  sleepSubmitting = true;
  if (sleepSaveBtn) sleepSaveBtn.disabled = true;

  try {
    await ensureDailyUsageCurrent(user.uid, { skipReminderRefresh: true });

    const quotaResult = await reserveDailyQuota(user.uid, "sleepCount", SLEEP_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s sleep log limit (${SLEEP_DAILY_LIMIT}/day)`));
      updateSleepLimitUI();
      return;
    }

    sleepHistory.push(hours);
    sleepDates.push(getServerNowDate());
    sleepResult.innerText = `${hours} hrs 💤`;
    updateInsights();

    try {
      await addDoc(collection(db, "users", user.uid, "sleepLogs"), {
        hours,
        time: serverTimestamp()
      });
      sleepInput.value = "";
      showToast(`Sleep logged. ${getRandomCheer()}`);
      await trimCollectionToMaxEntries(user.uid, "sleepLogs", MAX_SLEEP_ENTRIES, (entry) => toDateSafe(entry.time)?.getTime?.() || 0);
      updateSleepLimitUI();
    } catch (err) {
      sleepHistory.pop();
      sleepDates.pop();
      await rollbackDailyQuota(user.uid, "sleepCount");
      notifyFirestoreError(err);
    }
  } finally {
    sleepSubmitting = false;
    updateSleepLimitUI();
  }
}

async function clearSleepData() {
  const user = auth.currentUser;
  if (!user?.uid) {
    showToast("Please sign in first.");
    return;
  }

  const shouldClear = confirm("Clear all sleep logs and reset your bed time reminder?");
  if (!shouldClear) return;

  // Reset local UI/state first so fields clear even if network cleanup fails.
  sleepHistory.length = 0;
  sleepDates.length = 0;
  if (sleepInput) sleepInput.value = "";
  if (sleepResult) sleepResult.innerText = "";

  bedtimeSettings = { timeText: "", enabled: false };
  bedtimeReminderLastTriggeredKey = "";
  bedtimeInputTouchedSinceSync = false;
  bedtimeAllowUnchangedResubmit = false;
  clearBedtimeReminderSchedule();
  closeBedtimeReminderModal(null, true);
  if (bedtimeTimeInput) bedtimeTimeInput.value = "";
  setBedtimeInputError("");
  updateBedtimeSetButtonState();
  updateSleepLimitUI();
  updateInsights();

  try {
    await Promise.allSettled([
      clearUserCollection(user.uid, "sleepLogs"),
      deleteDoc(doc(db, "users", user.uid, "settings", "sleep"))
    ]);
    showToast("Sleep logs and bed time reminder cleared.");
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function clearBedtimeData() {
  const user = auth.currentUser;
  if (!user?.uid) {
    showToast("Please sign in first.");
    return;
  }

  const shouldClear = confirm("Clear your bed time reminder?");
  if (!shouldClear) return;

  bedtimeSettings = { timeText: "", enabled: false };
  bedtimeReminderLastTriggeredKey = "";
  bedtimeInputTouchedSinceSync = false;
  bedtimeAllowUnchangedResubmit = false;
  clearBedtimeReminderSchedule();
  closeBedtimeReminderModal(null, true);
  if (bedtimeTimeInput) bedtimeTimeInput.value = "";
  setBedtimeInputError("");
  updateBedtimeSetButtonState();

  try {
    await setDoc(doc(db, "users", user.uid, "settings", "sleep"), {
      bedtimeEnabled: false,
      bedtimeTime: "",
      bedtimeMeridiem: "",
      updatedAt: serverTimestamp(),
      updatedAtMs: Date.now()
    }, { merge: true });
    showToast("Bed time reminder cleared.");
  } catch (err) {
    notifyFirestoreError(err);
  }
}

// Time Mirror
const TIME_MIRROR_ACTION_LIBRARY = {
  studying: {
    keywords: ["study", "studying", "exam", "test", "revision", "assignment", "course", "learn"],
    nextMoves: [
      "Open your notes and run a 20-minute focused study sprint on one chapter.",
      "Pick one weak topic and solve 5 questions without switching tabs.",
      "Set a 25-minute timer and revise only high-yield concepts.",
      "Write a one-page summary from memory, then check gaps.",
      "Do one timed mini-test now and review errors immediately.",
      "Start with the hardest topic for 15 minutes while energy is fresh.",
      "Use active recall for one unit before reading anything new.",
      "Solve 3 past-paper questions and mark where you got stuck.",
      "Create flashcards for one topic and test yourself right away.",
      "Pick one objective and complete it in a single deep-work block.",
      "Do one concept drill and explain it out loud in simple words.",
      "Review one chapter, then close with a 5-minute self-quiz.",
      "Start a distraction-free session and finish one sub-topic fully.",
      "Use a 15-5 cycle: 15 min study, 5 min recap, repeat twice.",
      "Begin with one micro-goal: complete one topic map now."
    ],
    plans: [
      "Run 2 focused sprints today, then do a short recall test before sleep.",
      "Complete one topic now, one topic later, and one quick revision at night.",
      "Use three blocks: learn, practice, then test yourself.",
      "Finish one high-priority chapter today and schedule the next at a fixed time.",
      "Do practice first, theory second, and error correction third.",
      "Close today by listing top 3 weak areas for tomorrow.",
      "Use timed questions in block 2 and error logging in block 3.",
      "Protect one no-phone study block each half of the day.",
      "Complete one chapter and one review cycle before day-end.",
      "End with active recall and a mini confidence check.",
      "Run concept -> questions -> correction loop today.",
      "Stack one deep session now and one light revision later.",
      "Build consistency with same-hour study anchors for 3 days.",
      "Use a visible checklist and mark wins after each sprint.",
      "Do one focused session now, then one short recap tonight."
    ],
    wins: [
      "your retention improves and revision pressure drops quickly",
      "your recall speed rises and exam anxiety reduces",
      "you feel more prepared and mentally organized",
      "you gain clarity on weak areas and momentum builds",
      "your confidence increases because progress becomes visible",
      "you reduce last-minute panic and improve control",
      "concept clarity improves and confusion drops",
      "your study rhythm stabilizes and focus improves",
      "you feel calmer because you have a concrete plan",
      "your learning compounds and review becomes faster",
      "you cut cognitive overload and improve execution",
      "you convert effort into measurable progress",
      "you feel more in control of deadlines",
      "your consistency improves and stress declines",
      "you build a stronger 72-hour learning streak"
    ],
    delayCosts: [
      "revision pressure increases and memory decay accelerates",
      "you carry uncertainty into tomorrow and feel heavier",
      "last-minute cramming risk rises",
      "weak topics stay unresolved and confidence drops",
      "the task feels bigger and harder to start later",
      "anxiety builds because the syllabus remains vague",
      "you lose momentum and decision fatigue increases",
      "tomorrow starts with backlog instead of clarity",
      "focus quality drops as urgency rises",
      "you push important work into a stressful window",
      "mental load accumulates and calm decreases",
      "you risk inconsistent preparation",
      "the same topic will take longer tomorrow",
      "you reduce your recovery time before deadlines",
      "progress stalls and pressure compounds"
    ]
  },
  reading: {
    keywords: ["read", "reading", "book", "novel", "chapter", "article"],
    nextMoves: [
      "Read one chapter with zero notifications for 20 minutes.",
      "Start a 15-minute reading sprint and mark 3 key ideas.",
      "Read 5 pages now and write a 2-line takeaway.",
      "Open the book and complete one focused section immediately.",
      "Set a short timer and read with full attention.",
      "Read one chapter and summarize the core message.",
      "Read for 20 minutes, then note one practical insight.",
      "Finish one section before touching your phone.",
      "Start with one page and continue until timer ends.",
      "Read one dense paragraph slowly and extract the main point.",
      "Read now in a quiet spot for one distraction-free block.",
      "Read one chunk and highlight only what matters.",
      "Use a pen and annotate as you read for retention.",
      "Do one focused reading block before any multitasking.",
      "Begin with one clear target: finish this section now."
    ],
    plans: [
      "Read one block now and one lighter block tonight.",
      "Pair reading with a short summary after each section.",
      "Use two timed reading sessions with quick recaps.",
      "Finish one chapter today and queue the next for tomorrow.",
      "Read, reflect, and extract one actionable idea each session.",
      "Run a morning reading block and an evening review block.",
      "Track page targets and close with 3 takeaway bullets.",
      "Use one deep reading session and one skim/review session.",
      "Break content into sections and complete one at a time.",
      "Do reading first, then write a short reflection.",
      "Keep sessions short but daily for compounding retention.",
      "Anchor reading to the same time for 3 days.",
      "Use a visible reading goal and tick it off today.",
      "Complete one section now and one before sleep.",
      "Read with intent: question -> read -> summarize loop."
    ],
    wins: [
      "your focus deepens and mental noise reduces",
      "your knowledge compounds and clarity improves",
      "you feel calmer and more mentally organized",
      "your retention improves with structured reading",
      "you build consistency and confidence quickly",
      "you reduce scattered attention and increase control",
      "your comprehension improves with each block",
      "you feel productive without burnout",
      "your concentration window expands",
      "you turn reading into visible progress",
      "your recall improves for key ideas",
      "you feel less overwhelmed by large material",
      "you strengthen disciplined focus",
      "you gain momentum with low-friction progress",
      "you build a strong learning rhythm"
    ],
    delayCosts: [
      "focus gets fragmented and progress becomes inconsistent",
      "mental clutter stays high and clarity drops",
      "the material feels heavier later",
      "retention weakens without timely repetition",
      "you lose momentum and confidence dips",
      "information overload increases",
      "you push reading into low-energy hours",
      "your attention stays reactive instead of intentional",
      "you postpone a low-friction win",
      "learning quality drops with rushed sessions",
      "your progress feels vague and untracked",
      "the chapter backlog grows",
      "you increase decision fatigue",
      "consistency breaks and restart cost rises",
      "you miss easy compounding gains"
    ]
  },
  dancing: {
    keywords: ["dance", "dancing", "choreo", "choreography"],
    nextMoves: [
      "Play one track and rehearse your first sequence for 15 minutes.",
      "Warm up for 5 minutes, then repeat one combo until smooth.",
      "Run one full song and focus only on timing.",
      "Practice footwork slowly, then increase speed gradually.",
      "Do mirror practice for one routine segment now.",
      "Start with a short mobility warm-up and one repetition loop.",
      "Film one take and review only one improvement point.",
      "Practice transitions between two moves repeatedly.",
      "Run one controlled practice block with no phone breaks.",
      "Start with rhythm drills for 10 minutes, then one combo.",
      "Do one expressive run focused on posture and flow.",
      "Rehearse your hardest 20-second segment first.",
      "Practice one section at half speed for cleaner control.",
      "Do one confidence run from start to finish.",
      "Begin now with one repeatable mini routine."
    ],
    plans: [
      "Today: warm-up, technique block, then one full run.",
      "Practice one segment now and one later with fresh energy.",
      "Use record-review-adjust cycle across two short sessions.",
      "Split your routine into 3 chunks and master one today.",
      "Focus on timing first, style second, stamina third.",
      "Run one technical set and one performance set today.",
      "Lock rehearsal time and prep music playlist in advance.",
      "Use short repeats with hydration breaks.",
      "Practice one anchor move and build outward.",
      "Complete one clean take by day-end.",
      "Train transitions and ending pose in final block.",
      "Use a fixed 20-minute routine for 3 days.",
      "Do one filmed take each day for visible progress.",
      "Pair practice with recovery stretch to reduce fatigue.",
      "Close each session with one confidence run-through."
    ],
    wins: [
      "your body confidence rises and stress drops",
      "your rhythm and coordination improve quickly",
      "you feel energized and mentally lighter",
      "your movement becomes cleaner and more controlled",
      "you gain confidence through visible progress",
      "your consistency improves with short rehearsals",
      "you build flow and reduce hesitation",
      "your endurance improves session by session",
      "you feel more expressive and focused",
      "you improve timing and execution clarity",
      "you get faster at transitions",
      "you reduce performance anxiety with repetition",
      "you improve posture and movement quality",
      "you build a strong practice rhythm",
      "you create a clear 72-hour momentum arc"
    ],
    delayCosts: [
      "timing confidence fades and restarts feel harder",
      "muscle memory weakens between sessions",
      "you lose momentum and feel less sharp",
      "the routine feels less familiar tomorrow",
      "hesitation increases during transitions",
      "confidence dips from inconsistency",
      "practice quality falls under time pressure",
      "small mistakes become sticky",
      "you postpone easy rhythm gains",
      "energy stays restless without structured movement",
      "execution becomes less fluid",
      "you reduce compounding progress",
      "performance readiness drops",
      "your warm-up discipline weakens",
      "recovery and consistency both slip"
    ]
  },
  singing: {
    keywords: ["sing", "singing", "vocal", "song practice", "voice"],
    nextMoves: [
      "Do a 5-minute vocal warm-up, then rehearse one verse.",
      "Practice one song section with controlled breathing.",
      "Run scales for 10 minutes, then one focused take.",
      "Record one short vocal take and review one fix.",
      "Practice pitch on one tricky line repeatedly.",
      "Warm up gently and sing one song at medium intensity.",
      "Focus on diction and breath support for one segment.",
      "Do one rhythm-focused rehearsal now.",
      "Sing one section slowly, then at performance speed.",
      "Train one chorus part until stable and clean.",
      "Run one no-break session for 15 minutes.",
      "Start with humming + resonance, then one verse.",
      "Work one high-note passage with safe control.",
      "Practice one expressive take with relaxed shoulders.",
      "Begin now with one vocal drill and one song pass."
    ],
    plans: [
      "Warm-up, technique, then one performance take today.",
      "Use two sessions: technical work first, musicality later.",
      "Practice one verse now and chorus in the evening.",
      "Record daily and track one improvement point each time.",
      "Run breath control drills before every song attempt.",
      "Use short focused blocks to protect vocal quality.",
      "Do pitch control first and expression second.",
      "Close with one comfortable full-song run.",
      "Train one difficult section until consistent.",
      "Hydrate between sets and keep intensity sustainable.",
      "Build 3-day consistency with fixed practice windows.",
      "Use replay review to tighten one specific issue.",
      "Alternate technical and creative sessions.",
      "Do one clean take by end of day.",
      "Stack one micro-win each session for confidence."
    ],
    wins: [
      "your vocal control improves and confidence rises",
      "your pitch stability and breath support get stronger",
      "you feel calmer and more expressive",
      "your consistency improves with short blocks",
      "you gain confidence through measurable takes",
      "your voice feels more reliable over sessions",
      "you reduce strain with better technique",
      "you build performance readiness steadily",
      "your timing and phrasing improve quickly",
      "you feel more in control of difficult passages",
      "you improve clarity and tone quality",
      "you convert practice into visible progress",
      "you reduce anxiety through repetition",
      "you build a healthier vocal routine",
      "you create strong 72-hour momentum"
    ],
    delayCosts: [
      "vocal confidence drops and restarting feels harder",
      "technique consistency weakens",
      "pitch control becomes less stable",
      "you postpone confidence-building reps",
      "performance anxiety stays high",
      "your progress signal becomes unclear",
      "you lose rhythm in your routine",
      "difficult sections stay unresolved",
      "you increase pressure for tomorrow",
      "warm-up discipline falls off",
      "you reduce quality practice volume",
      "momentum stalls",
      "your tone and breath control regress slightly",
      "consistency gap widens",
      "training becomes more stop-start"
    ]
  },
  coding: {
    keywords: ["code", "coding", "debug", "bug", "feature", "programming", "build app", "development"],
    nextMoves: [
      "Open the project and ship one small bug fix in a 25-minute block.",
      "Define one ticket-sized task and implement only that now.",
      "Reproduce one bug, write the fix, and verify once.",
      "Build one small feature slice end-to-end this session.",
      "Start with the highest-impact TODO and close it fully.",
      "Run one focused coding sprint with notifications off.",
      "Write a minimal implementation, then refine once.",
      "Pick one failing behavior and resolve it before context switching.",
      "Set a timer and complete one pull-request-sized change.",
      "Implement one clear acceptance criterion now.",
      "Do one cleanup pass only after shipping one result.",
      "Open the file and complete one concrete edit now.",
      "Fix one blocker first, then continue feature flow.",
      "Complete one unit of work you can demo today.",
      "Start coding immediately on the smallest valuable step."
    ],
    plans: [
      "Run one build-fix cycle now, then one polish cycle later.",
      "Complete one vertical slice today and queue the next for tomorrow.",
      "Use implement -> test -> verify loop in two sessions.",
      "Ship one visible change before day-end, then document next step.",
      "Do high-impact fix first, then incremental enhancement.",
      "Use two deep-work blocks and one short review block.",
      "Finish one PR-worthy change and prepare next ticket.",
      "Close one bug and one follow-up improvement today.",
      "Keep scope strict: one target outcome per session.",
      "Do code first, cleanup second, extras last.",
      "Use a same-hour coding anchor for 3 days.",
      "End each session with one-line next action.",
      "Ship small and daily for stronger momentum.",
      "Track one completed commit-level outcome today.",
      "Focus on done-quality, not perfect-quality."
    ],
    wins: [
      "your execution confidence increases and backlog stress drops",
      "you get measurable progress and clearer technical direction",
      "you reduce context switching and improve focus quality",
      "you feel more in control through visible shipping",
      "your coding momentum stabilizes quickly",
      "you resolve blockers faster with tighter scope",
      "your productivity improves with shorter cycles",
      "you lower mental clutter by finishing one thing",
      "you build confidence with each closed task",
      "you improve delivery reliability",
      "you turn ambiguity into concrete output",
      "you reduce procrastination through quick starts",
      "you create a stronger 72-hour execution streak",
      "you gain clarity by shipping incrementally",
      "you feel calmer because progress is visible"
    ],
    delayCosts: [
      "technical backlog pressure grows",
      "context decay makes restart harder",
      "the bug/feature feels heavier tomorrow",
      "you lose momentum and confidence dips",
      "priority confusion increases",
      "delivery stress rises near deadlines",
      "you postpone easy wins and compound friction",
      "task-switching overhead increases",
      "progress visibility drops",
      "unresolved blockers steal focus",
      "execution confidence weakens",
      "you risk reactive instead of planned work",
      "the same fix takes longer later",
      "mental load accumulates",
      "consistency breaks and recovery cost rises"
    ]
  },
  writing: {
    keywords: ["write", "writing", "essay", "draft", "article", "blog", "journal", "script"],
    nextMoves: [
      "Write one rough draft section for 20 minutes without editing.",
      "Start with one paragraph and finish the core idea now.",
      "Set a timer and write continuously for one focused block.",
      "Draft the intro and one key body point immediately.",
      "Write one clear outline and complete the first section.",
      "Produce one messy draft now, polish later.",
      "Write one page on the main argument without stopping.",
      "Start with bullet points, then expand one section.",
      "Complete one paragraph with evidence and conclusion.",
      "Open the doc and finish one subsection now.",
      "Write one concrete example to unlock momentum.",
      "Draft first, edit second: start with 15 minutes writing.",
      "Do one no-backspace writing sprint now.",
      "Write the hardest part first while focus is fresh.",
      "Begin with one sentence and build one full block."
    ],
    plans: [
      "Draft now, revise later, and finalize one section tonight.",
      "Split work into outline, draft, and edit blocks.",
      "Complete one section this session and one in the evening.",
      "Use two drafting sprints and one editing sprint.",
      "Finish structure today, refinement tomorrow.",
      "Write first version fast, then improve clarity.",
      "Set a fixed writing window for 3 days.",
      "Close each session with a ready-to-start next sentence.",
      "Run idea dump -> organize -> tighten loop.",
      "Complete one visible written output before day-end.",
      "Use short breaks to preserve writing quality.",
      "Draft one section and review for clarity once.",
      "Aim for consistency over perfection today.",
      "Do one clean revision pass after drafting.",
      "Ship one finished section and lock tomorrow's target."
    ],
    wins: [
      "your clarity improves and blank-page anxiety drops",
      "you gain momentum through visible word output",
      "your ideas organize faster and stress lowers",
      "you feel more in control of deadlines",
      "your writing confidence rises with each section",
      "you reduce overthinking by drafting first",
      "you improve flow and structure quickly",
      "you create measurable progress in one session",
      "you strengthen consistency with low-friction starts",
      "your mental load drops as draft quality improves",
      "you convert ideas into concrete output",
      "you maintain calmer execution with short sprints",
      "you build a reliable 72-hour writing rhythm",
      "you reduce perfection paralysis",
      "you improve completion rate and focus"
    ],
    delayCosts: [
      "blank-page pressure increases",
      "deadline anxiety builds",
      "ideas stay scattered and harder to structure",
      "starting friction rises tomorrow",
      "you lose momentum and confidence dips",
      "editing load grows because drafting is delayed",
      "writing quality drops under rushed conditions",
      "you postpone an easy consistency win",
      "mental clutter remains high",
      "you risk reactive last-minute output",
      "progress visibility disappears",
      "task feels heavier with time",
      "focus weakens from repeated postponement",
      "you reduce recovery time before deadlines",
      "consistency breaks and restart cost rises"
    ]
  }
};

function getTimeMirrorActionKey(goalTextLower = "") {
  const text = String(goalTextLower || "");
  const keys = Object.keys(TIME_MIRROR_ACTION_LIBRARY);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const config = TIME_MIRROR_ACTION_LIBRARY[key] || {};
    const keywords = Array.isArray(config.keywords) ? config.keywords : [];
    if (keywords.some((keyword) => new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}\\b`, "i").test(text))) {
      return key;
    }
  }
  return "";
}

function getTimeMirrorActionLine(actionKey, bucket, fallback, variantSuffix = "") {
  const config = TIME_MIRROR_ACTION_LIBRARY[actionKey] || {};
  const options = Array.isArray(config[bucket]) ? config[bucket] : [];
  if (!options.length) return fallback;
  const key = `time_mirror_${actionKey}_${bucket}${variantSuffix ? `_${variantSuffix}` : ""}`;
  return pickNonRepeatingVariant(options, key) || fallback;
}

function timeTraveller() {
  const goalText = futureTask.value.trim();
  if (!goalText) {
    showToast("Enter a goal to preview your future outcome.");
    return;
  }

  const snapshot = getWellnessSnapshot();
  const lower = goalText.toLowerCase();
  const actionKey = getTimeMirrorActionKey(lower);
  const timeline = parseTimelineFromInput(goalText);
  const moodMeta = getMoodStateMeta(snapshot.moodToday);
  const trends = buildTrendSignals();
  const behaviorPatterns = getBehaviorPatternMemory(35);
  const hydrationInsight = buildHydrationPaceInsight(snapshot);
  const priorityBoard = buildPriorityBoard(snapshot, trends);

  const goalType =
    /study|exam|learn|course|revision|assignment/.test(lower) ? "learning" :
    /workout|gym|run|fitness|exercise|walk/.test(lower) ? "fitness" :
    /project|build|launch|startup|business|client|career/.test(lower) ? "career" :
    /sleep|rest|bed|wake/.test(lower) ? "recovery" :
    /water|hydrate|hydration/.test(lower) ? "hydration" :
    "general";

  const energyState = snapshot.sleepToday >= 7 ? "steady" : "low";
  const focusState = snapshot.pendingTasks <= 2 ? "clear" : "crowded";
  const hydrationLeft = Math.max(0, snapshot.todayGoal - snapshot.waterToday);
  const hydrationState = hydrationLeft > 0 ? "behind" : "good";

  const blockerTag =
    /procrastinat|delay|later|tomorrow/.test(lower) ? "delay" :
    /overwhelm|stuck|confused|unclear/.test(lower) ? "clarity" :
    /anxious|stress|nervous|fear/.test(lower) ? "anxiety" :
    /tired|drained|exhaust|sleepy/.test(lower) ? "fatigue" :
    "none";

  const urgency = (() => {
    if (!timeline?.minutes) return "normal";
    if (timeline.minutes <= 24 * 60) return "high";
    if (timeline.minutes <= 3 * 24 * 60) return "medium";
    return "normal";
  })();

  const typeBoost = {
    learning: "your understanding compounds and recall becomes faster",
    fitness: "your energy improves and stress load drops noticeably",
    career: "your momentum builds and confidence in execution rises",
    recovery: "your nervous system settles and tomorrow starts stronger",
    hydration: "your focus gets sharper and fatigue drops in the next few hours",
    general: "your consistency grows and your confidence rises"
  };

  const skipCost = {
    learning: "you carry cognitive friction and last-minute pressure",
    fitness: "stress stays high and motivation weakens tomorrow",
    career: "momentum stalls and the task feels heavier later",
    recovery: "fatigue compounds and tomorrow starts with lower focus",
    hydration: "mental clarity dips and energy feels flat",
    general: "the task becomes heavier emotionally and mentally"
  };

  const firstStepBase =
    goalType === "learning" ? "Open your notes and do a 15-minute focused sprint." :
    goalType === "fitness" ? "Do a 5-minute warm-up and start the first set." :
    goalType === "career" ? "Break this into one shippable 20-minute action." :
    goalType === "recovery" ? "Set a wind-down alarm and reduce screen/light now." :
    goalType === "hydration" ? "Drink one glass now, then set a 30-minute follow-up." :
    "Do one 10-minute starter action right now.";

  const blockerStep =
    blockerTag === "delay" ? "Use a 5-minute countdown and start before the timer ends." :
    blockerTag === "clarity" ? "Write the task in one sentence, then pick only the very first sub-step." :
    blockerTag === "anxiety" ? "Take 3 slow breaths, then do a tiny version of the task for 8 minutes." :
    blockerTag === "fatigue" ? "Start with a low-friction micro-step for 5 minutes, then reassess." :
    "";

  const urgencyStep =
    urgency === "high" ? "Deadline is close, so protect a 25-minute distraction-free block now." :
    urgency === "medium" ? "Start today with one focused block to avoid deadline compression." :
    "Progress compounds best when you start early and repeat daily.";

  const actionFirstStep = getTimeMirrorActionLine(actionKey, "nextMoves", firstStepBase, "next");
  const firstStep = blockerStep || actionFirstStep;
  const readinessHint = `${energyState === "steady" ? "Energy is usable" : "Energy is low, keep actions tiny"} • ${focusState === "clear" ? "focus lane is clear" : "task load is crowded"} • mood: ${moodMeta.label}${hydrationState === "behind" ? ` • hydrate +${hydrationLeft}` : " • hydration on track"}`;

  const horizonLabel = timeline?.label || "next 24 hours";
  const moodRiskLine = moodMeta.logged && moodMeta.score <= 1
    ? "Emotional load is elevated, so consistency beats intensity today."
    : "Emotional baseline is stable enough for focused execution.";

  const followUpPlanBase =
    goalType === "learning" ? "Block 2 study sprints and close with a 5-minute recall test." :
    goalType === "fitness" ? "Lock workout time and prep clothes/shoes now." :
    goalType === "career" ? "Ship one visible milestone today and define tomorrow's next ship item." :
    goalType === "recovery" ? "Set bedtime trigger and cap screens 45 minutes before sleep." :
    goalType === "hydration" ? "Pair each meal with water and complete the remaining glasses before evening." :
    "Choose one measurable output and finish it before day-end.";
  const followUpPlan = getTimeMirrorActionLine(actionKey, "plans", followUpPlanBase, "plan");

  const actionWin = getTimeMirrorActionLine(actionKey, "wins", typeBoost[goalType], "win");
  const actionDelayCost = getTimeMirrorActionLine(actionKey, "delayCosts", skipCost[goalType], "delay");

  const patternNote = Array.isArray(behaviorPatterns?.summaryLines) && behaviorPatterns.summaryLines.length
    ? behaviorPatterns.summaryLines[0]
    : "Pattern confidence is still building from recent logs.";
  const confidenceScore = (() => {
    let score = 50;
    if (snapshot.sleepToday >= 7) score += 12;
    if (snapshot.pendingTasks <= 2) score += 10;
    if (hydrationInsight.onTrack) score += 10;
    if (moodMeta.logged && moodMeta.score >= 2) score += 10;
    if (trends.taskDelta >= 0) score += 4;
    if (trends.sleepDelta >= 0) score += 4;
    return Math.max(35, Math.min(96, score));
  })();
  const confidenceBand = confidenceScore >= 78 ? "high" : confidenceScore >= 62 ? "medium" : "guarded";
  const likelyWin72h = priorityBoard?.[0]?.action || firstStep;
  const riskTrigger = blockerTag === "anxiety"
    ? "If anxiety spikes, drop intensity and run 3 breathing cycles before restarting."
    : blockerTag === "fatigue"
      ? "If energy crashes, switch to a 5-minute micro-step instead of stopping."
      : blockerTag === "clarity"
        ? "If you feel stuck, rewrite the next step in one sentence and start a 10-minute timer."
        : "If momentum drops, restart with a 10-minute sprint immediately.";
  const trendDirection = `task ${trends.taskDelta >= 0 ? "up" : "down"} (${trends.taskDelta.toFixed(1)}), sleep ${trends.sleepDelta >= 0 ? "up" : "down"} (${trends.sleepDelta.toFixed(1)}h), mood ${trends.moodDelta >= 0 ? "up" : "down"} (${trends.moodDelta.toFixed(2)}).`;

  timeMirror.innerHTML = `
    <p>✨ <b>Likely future if you execute: "${escapeHtml(goalText)}"</b><br>
    By ${escapeHtml(horizonLabel)}: ${escapeHtml(actionWin)}. ${moodRiskLine}</p>
    <p>⏳ <b>If you delay</b><br>
    By ${escapeHtml(horizonLabel)}: ${escapeHtml(actionDelayCost)}.</p>
    <p>🧭 <b>Best next move</b><br>${escapeHtml(firstStep)}<br>${escapeHtml(urgencyStep)}</p>
    <p>📈 <b>Execution plan</b><br>${followUpPlan}</p>
    <p>🗺️ <b>72-hour win path</b><br>Do now: ${escapeHtml(likelyWin72h)}<br>By tonight: protect recovery + finish one visible output.<br>By day 3: your control and consistency should noticeably improve if you repeat the same first-hour anchor.</p>
    <p>🧠 <b>Forecast confidence</b>: ${confidenceBand} (${confidenceScore}/100)<br><small>Trend signal: ${escapeHtml(trendDirection)}</small><br><small>Pattern note: ${escapeHtml(patternNote)}</small></p>
    <p>🛡️ <b>Fallback rule</b><br>${escapeHtml(riskTrigger)}</p>
    <p>📌 <small>${readinessHint}</small></p>
  `;

  setTimeMirrorClearButtonState(true);

  futureTask.value = "";
}

// Quotes
const quotes=[
  "The future depends on what you do today. - Mahatma Gandhi",
  "It always seems impossible until it's done. - Nelson Mandela",
  "Well done is better than well said. - Benjamin Franklin",
  "Action is the foundational key to all success. - Pablo Picasso",
  "Start where you are. Use what you have. Do what you can. - Arthur Ashe",
  "Success is the sum of small efforts, repeated day in and day out. - Robert Collier",
  "The secret of getting ahead is getting started. - Mark Twain",
  "What we think, we become. - Buddha",
  "Quality is not an act, it is a habit. - Aristotle",
  "Do what you can, with what you have, where you are. - Theodore Roosevelt",
  "The best way out is always through. - Robert Frost",
  "Great things are done by a series of small things brought together. - Vincent van Gogh",
  "He who has a why to live can bear almost any how. - Friedrich Nietzsche",
  "The only way to do great work is to love what you do. - Steve Jobs",
  "In the middle of difficulty lies opportunity. - Albert Einstein",
  "Courage is resistance to fear, mastery of fear, not absence of fear. - Mark Twain",
  "Believe you can and you're halfway there. - Theodore Roosevelt",
  "If you are going through hell, keep going. - Winston Churchill",
  "The harder I work, the luckier I get. - Samuel Goldwyn",
  "Energy and persistence conquer all things. - Benjamin Franklin",
  "Success is not final, failure is not fatal: it is the courage to continue that counts. - Winston Churchill",
  "Our greatest glory is not in never falling, but in rising every time we fall. - Confucius",
  "Discipline is the bridge between goals and accomplishment. - Jim Rohn",
  "Do not wait to strike till the iron is hot; but make it hot by striking. - William Butler Yeats",
  "The journey of a thousand miles begins with one step. - Lao Tzu",
  "You miss 100% of the shots you don't take. - Wayne Gretzky",
  "If opportunity doesn't knock, build a door. - Milton Berle",
  "Knowing is not enough; we must apply. Willing is not enough; we must do. - Johann Wolfgang von Goethe",
  "Fortune favors the bold. - Virgil",
  "Do one thing every day that scares you. - Eleanor Roosevelt",
  "One clear action beats ten perfect plans. - NovaFix",
  "Small steps count when they actually happen. - NovaFix",
  "Start before confidence arrives; confidence follows evidence. - NovaFix",
  "The next ten minutes can change the tone of the day. - NovaFix",
  "Momentum is built by returning, not by never slipping. - NovaFix",
  "A tiny win today is still a vote for your future self. - NovaFix",
  "Make the task smaller until starting feels obvious. - NovaFix",
  "Discipline gets easier when the first step is kind. - NovaFix",
  "Do the smallest useful version, then build from there. - NovaFix",
  "Progress likes simple instructions. - NovaFix",
  "You do not need a perfect day to protect the streak. - NovaFix",
  "Energy rises when action becomes clear. - NovaFix",
  "The best reset is one honest next step. - NovaFix",
  "Consistency is quiet, but it changes everything. - NovaFix",
  "Win the minute in front of you. - NovaFix",
  "You can restart without explaining the pause. - NovaFix",
  "Clarity grows after you begin. - NovaFix",
  "Less pressure, more motion. - NovaFix",
  "A focused sprint can rescue a scattered day. - NovaFix",
  "Your future self only needs proof that you showed up. - NovaFix",
  "Drink water, take a breath, do one thing. - NovaFix",
  "When the day feels heavy, lower the bar and keep moving. - NovaFix",
  "Do not wait for a mood; build a rhythm. - NovaFix",
  "The first checkbox is the hardest; make it easy. - NovaFix",
  "You are one small finish away from better momentum. - NovaFix",
  "Start messy, finish cleaner. - NovaFix",
  "A calm pace still reaches the finish line. - NovaFix",
  "Turn worry into one controllable action. - NovaFix",
  "Short effort repeated often becomes identity. - NovaFix",
  "The comeback starts with the next log. - NovaFix",
  "Give your attention one job at a time. - NovaFix",
  "A five-minute start is stronger than a perfect delay. - NovaFix",
  "Protect the basics and the bigger goals get lighter. - NovaFix",
  "You can be tired and still take one gentle step. - NovaFix",
  "Keep promises small enough to keep. - NovaFix",
  "The day is not lost while one action remains possible. - NovaFix",
  "Focus is a door; open it with one task. - NovaFix",
  "Build evidence, not excuses. - NovaFix",
  "If it matters, give it a small beginning. - NovaFix",
  "Your pace is allowed to be realistic. - NovaFix",
  "Finish one thing before judging the whole day. - NovaFix",
  "You get stronger every time you return to the plan. - NovaFix",
  "Make the healthy choice visible and the hard choice harder. - NovaFix",
  "A low-energy day still accepts low-friction progress. - NovaFix",
  "The fastest way out of stuck is specific action. - NovaFix",
  "Let today be simple and real. - NovaFix",
  "You do not need intensity; you need repeatability. - NovaFix",
  "Breathe first, then execute. - NovaFix",
  "The next good choice is enough to begin again. - NovaFix",
  "Small wins stack faster than self-criticism. - NovaFix",
  "Your routine is a safety rail, not a cage. - NovaFix",
  "Motivation fades; systems catch you. - NovaFix",
  "Start with the version you can actually do. - NovaFix",
  "A clean desk is optional; a clear next step is powerful. - NovaFix",
  "Do the action that removes tomorrow's stress. - NovaFix",
  "If you cannot do a lot, do something honest. - NovaFix",
  "Your streak is built by ordinary days. - NovaFix",
  "One glass, one breath, one task. - NovaFix",
  "The best plan is the one you touch today. - NovaFix",
  "A tiny finish is better than another almost. - NovaFix",
  "Choose the action that makes the next action easier. - NovaFix",
  "You are allowed to go slowly without stopping. - NovaFix",
  "Reset your body, then reset the task. - NovaFix",
  "Make progress so small it has no excuse. - NovaFix",
  "Your attention is valuable; spend it on the next move. - NovaFix",
  "Begin where the resistance is lowest. - NovaFix",
  "The work gets lighter after the first honest minute. - NovaFix",
  "Keep the streak human, not heroic. - NovaFix",
  "A planned pause beats an accidental spiral. - NovaFix",
  "The task does not need drama; it needs a start. - NovaFix",
  "Today's small discipline becomes tomorrow's freedom. - NovaFix",
  "Do the boring useful thing and let it compound. - NovaFix",
  "You can change direction with one deliberate choice. - NovaFix",
  "Progress is not loud; it is logged. - NovaFix",
  "Make the next step visible, then take it. - NovaFix",
  "The goal gets closer every time you reduce friction. - NovaFix",
  "Confidence is built in completed minutes. - NovaFix",
  "A good day can start in the middle. - NovaFix",
  "Do not negotiate with the whole mountain; take one step. - NovaFix",
  "Your best effort today may look small, and still count. - NovaFix",
  "Steady beats dramatic when you need something to last. - NovaFix",
  "One useful choice can interrupt a rough pattern. - NovaFix",
  "Keep the promise tiny, then keep it. - NovaFix",
  "The first move is allowed to be imperfect. - NovaFix",
  "Action turns pressure into information. - NovaFix",
  "When motivation is low, make the path shorter. - NovaFix",
  "A ten-minute sprint can reopen the day. - NovaFix",
  "Your habits are built in the moments nobody sees. - NovaFix",
  "Better is built one repeatable action at a time. - NovaFix",
  "If you slipped, make the next choice clean. - NovaFix",
  "You are not behind when you are moving again. - NovaFix",
  "Do one thing that makes bedtime easier. - NovaFix",
  "Choose a small win and protect it. - NovaFix",
  "The next log is a fresh signal. - NovaFix",
  "Stable basics create room for bold goals. - NovaFix",
  "Keep showing up until showing up feels normal. - NovaFix",
  "Small control now prevents bigger stress later. - NovaFix",
  "The simplest next action is usually the strongest. - NovaFix",
  "Your future needs consistency more than perfection. - NovaFix"
];
const QUOTE_HISTORY_STORAGE_KEY = "novafixRecentQuoteHistoryV1";
const QUOTE_REPEAT_HISTORY_LIMIT = 150;
let recentQuoteIndexes = [];

function loadRecentQuoteIndexes() {
  if (recentQuoteIndexes.length) return recentQuoteIndexes;
  try {
    const parsed = JSON.parse(localStorage.getItem(QUOTE_HISTORY_STORAGE_KEY) || "[]");
    recentQuoteIndexes = Array.isArray(parsed)
      ? parsed.map((value) => Number(value)).filter((value) => Number.isInteger(value))
      : [];
  } catch (_) {
    recentQuoteIndexes = [];
  }
  return recentQuoteIndexes;
}

function saveRecentQuoteIndexes() {
  try {
    localStorage.setItem(QUOTE_HISTORY_STORAGE_KEY, JSON.stringify(recentQuoteIndexes));
  } catch (_) {}
}

function pickNonRepeatingQuote() {
  if (!quotes.length) return "";
  const validHistory = loadRecentQuoteIndexes().filter((index) => index >= 0 && index < quotes.length);
  const avoidCount = Math.min(QUOTE_REPEAT_HISTORY_LIMIT, Math.max(0, quotes.length - 1));
  const recent = avoidCount > 0 ? validHistory.slice(-avoidCount) : [];
  const candidates = quotes
    .map((quote, index) => ({ quote, index }))
    .filter((entry) => !recent.includes(entry.index));
  const source = candidates.length ? candidates : quotes.map((quote, index) => ({ quote, index }));
  const picked = source[Math.floor(Math.random() * source.length)] || source[0];
  recentQuoteIndexes = [...validHistory, picked.index].slice(-Math.max(1, avoidCount));
  saveRecentQuoteIndexes();
  return picked.quote || "";
}

function newQuote(){
  const rawQuote = pickNonRepeatingQuote();
  const splitIndex = rawQuote.lastIndexOf(" - ");

  if (!quoteDisplay) return;
  if (splitIndex < 0) {
    quoteDisplay.innerText = rawQuote;
    return;
  }

  const quoteText = rawQuote.slice(0, splitIndex).trim();
  const authorText = rawQuote.slice(splitIndex + 3).trim();
  quoteDisplay.innerHTML = `${escapeHtml(quoteText)}<span style="display:block;text-align:right;margin-top:6px;opacity:.9;">- ${escapeHtml(authorText)}</span>`;
}
newQuote();

// Gratitude
function renderGratitude(entry) {
  clearStatusState(gratitudeLogs);
  const row = document.createElement("div");
  row.className = "item-row";
  const rawTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());

  const label = document.createElement("span");
  label.className = "item-text";
  label.textContent = `${rawTime.toLocaleTimeString()} - ${entry.text}`;

  const actions = document.createElement("div");
  actions.className = "item-actions";

  const editBtn = document.createElement("button");
  editBtn.textContent = "✏️";
  editBtn.onclick = async () => {
    const nextText = prompt("Edit gratitude", entry.text || "");
    if (!nextText || !nextText.trim()) return;

    const user = auth.currentUser;
    if (!user || !entry.id) return;

    try {
      await updateDoc(doc(db, "users", user.uid, "gratitudeLogs", entry.id), {
        text: nextText.trim()
      });
      entry.text = nextText.trim();
      label.textContent = `${rawTime.toLocaleTimeString()} - ${entry.text}`;
      const listIndex = gratitudeEntries.findIndex((item) => item.id === entry.id);
      if (listIndex >= 0) gratitudeEntries[listIndex].text = entry.text;
      updateInsights();
    } catch (err) {
      notifyFirestoreError(err);
    }
  };

  const deleteBtn = document.createElement("button");
  deleteBtn.classList.add("remove-entry-btn");
  deleteBtn.textContent = "🗑️";
  deleteBtn.onclick = async () => {
    const user = auth.currentUser;
    if (!user || !entry.id) {
      const fallbackIndex = gratitudeEntries.findIndex((item) => item.id === entry.id);
      if (fallbackIndex >= 0) gratitudeEntries.splice(fallbackIndex, 1);
      updateInsights();
      row.remove();
      scheduleEmptyState(gratitudeLogs, ".item-row", "No gratitude notes yet — add one small win from today.");
      return;
    }

    try {
      await deleteDoc(doc(db, "users", user.uid, "gratitudeLogs", entry.id));
      const listIndex = gratitudeEntries.findIndex((item) => item.id === entry.id);
      if (listIndex >= 0) gratitudeEntries.splice(listIndex, 1);
      updateInsights();
      updateGratitudeLimitUI();
      row.remove();
      scheduleEmptyState(gratitudeLogs, ".item-row", "No gratitude notes yet — add one small win from today.");
    } catch (err) {
      notifyFirestoreError(err);
    }
  };

  actions.append(editBtn, deleteBtn);
  row.append(label, actions);
  gratitudeLogs.appendChild(row);
}

async function loadGratitude(userId) {
  gratitudeLogs.innerHTML = "";
  gratitudeEntries.length = 0;

  try {
    const snapshot = await getDocs(collection(db, "users", userId, "gratitudeLogs"));
    const docs = snapshot.docs
      .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
      .sort((a, b) => {
        const aTime = a.time?.toMillis?.() ?? new Date(a.time || 0).getTime();
        const bTime = b.time?.toMillis?.() ?? new Date(b.time || 0).getTime();
        return aTime - bTime;
      });

    const todayKey = getTodayKey();
    let renderedCount = 0;
    docs.forEach((entry) => {
      const rawTime = entry.time?.toDate?.() ?? new Date(entry.time || getServerNowDate().getTime());
      gratitudeEntries.push({ ...entry, time: rawTime });
      if (dateToKey(rawTime) === todayKey) {
        renderGratitude({ ...entry, time: rawTime });
        renderedCount += 1;
      }
    });
    if (!renderedCount) {
      setEmptyState(gratitudeLogs, "No gratitude notes yet — add one small win from today.");
    }
    updateGratitudeLimitUI();
    updateInsights();
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function saveGratitude(){
  if (gratitudeSubmitting) return;
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  const t=gratitudeInput.value.trim();
  if(!t)return;

  gratitudeSubmitting = true;
  if (gratitudeSaveBtn) gratitudeSaveBtn.disabled = true;

  try {
    await ensureDailyUsageCurrent(user.uid);

    const quotaResult = await reserveDailyQuota(user.uid, "gratitudeCount", GRATITUDE_DAILY_LIMIT);
    if (!quotaResult.ok) {
      showToast(buildDailyLimitCountdownMessage(`You’ve reached today’s gratitude limit (${GRATITUDE_DAILY_LIMIT}/day)`));
      updateGratitudeLimitUI();
      return;
    }

    try {
      const ref = await addDoc(collection(db, "users", user.uid, "gratitudeLogs"), {
        text: t,
        time: serverTimestamp()
      });
      const entry = { id: ref.id, text: t, time: getServerNowDate() };
      gratitudeEntries.push(entry);
      renderGratitude(entry);
      showToast(`Gratitude saved. ${getRandomCheer()}`);
      updateInsights();
      gratitudeInput.value="";
      await trimCollectionToMaxEntries(user.uid, "gratitudeLogs", MAX_GRATITUDE_ENTRIES, (entryItem) => toDateSafe(entryItem.time)?.getTime?.() || 0);
      updateGratitudeLimitUI();
    } catch (err) {
        await rollbackDailyQuota(user.uid, "gratitudeCount");
      notifyFirestoreError(err);
    }
  } finally {
    gratitudeSubmitting = false;
    updateGratitudeLimitUI();
  }
}

const EXPORT_SNAPSHOT_DOC_ID = "dataSnapshot";
const EXPORT_SNAPSHOT_CHUNK_SIZE = 700000;
const EXPORT_COOLDOWN_MS = 5 * 60 * 1000;
const PASSWORD_RESET_COOLDOWN_MS = 2 * 60 * 1000;
const EXPORT_TARGET_COLLECTIONS = ["moods", "tasks", "waterIntake", "sleepLogs", "musicSessions", "gratitudeLogs", "aiChats", "challengeHistory", "rescueEvents", "reminders"];

function getOptionalTimestampMs(value) {
  if (!value) return null;

  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? ms : null;
  }

  if (typeof value === "string" || typeof value === "number") {
    const asDate = new Date(value);
    const ms = asDate.getTime();
    return Number.isFinite(ms) ? ms : null;
  }

  if (typeof value === "object") {
    if (typeof value.toMillis === "function") {
      const ms = value.toMillis();
      return Number.isFinite(ms) ? ms : null;
    }
    if (typeof value.seconds === "number") {
      return (value.seconds * 1000) + Math.floor((value.nanoseconds || 0) / 1e6);
    }
    if (typeof value._seconds === "number") {
      return (value._seconds * 1000) + Math.floor((value._nanoseconds || 0) / 1e6);
    }
  }

  return null;
}

function isFriendRequestExpired(entry, nowMs = getServerNowDate().getTime()) {
  const createdMs = Number(entry?.createdAtMs)
    || Number(entry?.updatedAtMs)
    || getOptionalTimestampMs(entry?.createdAt)
    || getOptionalTimestampMs(entry?.updatedAt)
    || getOptionalTimestampMs(entry?.time)
    || 0;
  if (!createdMs) return false;
  return (nowMs - createdMs) > FRIEND_REQUEST_EXPIRY_MS;
}

function applyExportCooldownUI(remainingMs) {
  if (!exportDataBtn) return;
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  const coolingDown = safeRemaining > 0;
  exportDataBtn.disabled = coolingDown;
  exportDataBtn.innerText = coolingDown
    ? `Export in ${formatCountdownClock(safeRemaining)}`
    : "Export My Data";
  exportDataBtn.title = coolingDown
    ? "Export cooldown active"
    : "";
}

function stopExportCooldownTicker() {
  if (exportCooldownIntervalId) {
    clearInterval(exportCooldownIntervalId);
    exportCooldownIntervalId = null;
  }
}

function updateExportCooldownTicker() {
  const remaining = exportCooldownUntilMs - getServerNowDate().getTime();
  if (remaining <= 0) {
    exportCooldownUntilMs = 0;
    stopExportCooldownTicker();
    applyExportCooldownUI(0);
    return;
  }
  applyExportCooldownUI(remaining);
}

function startExportCooldown(remainingMs) {
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  if (safeRemaining <= 0) {
    exportCooldownUntilMs = 0;
    stopExportCooldownTicker();
    applyExportCooldownUI(0);
    return;
  }

  exportCooldownUntilMs = getServerNowDate().getTime() + safeRemaining;
  updateExportCooldownTicker();
  if (!exportCooldownIntervalId) {
    exportCooldownIntervalId = setInterval(updateExportCooldownTicker, 1000);
  }
}

function applyDisplayNameEditCooldownUI(remainingMs) {
  if (!editDisplayNameBtn) return;
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  const coolingDown = safeRemaining > 0;
  editDisplayNameBtn.disabled = coolingDown;
  editDisplayNameBtn.innerText = coolingDown
    ? `Edit Display Name in ${formatDisplayNameCooldownClock(safeRemaining)}`
    : "Edit Display Name";
  editDisplayNameBtn.title = coolingDown ? "Display name edit cooldown active" : "";
}

function stopDisplayNameEditCooldownTicker() {
  if (!displayNameEditCooldownIntervalId) return;
  clearInterval(displayNameEditCooldownIntervalId);
  displayNameEditCooldownIntervalId = null;
}

function updateDisplayNameEditCooldownTicker() {
  const remaining = displayNameEditCooldownUntilMs - getServerNowDate().getTime();
  if (remaining <= 0) {
    displayNameEditCooldownUntilMs = 0;
    stopDisplayNameEditCooldownTicker();
    applyDisplayNameEditCooldownUI(0);
    return;
  }
  applyDisplayNameEditCooldownUI(remaining);
}

function startDisplayNameEditCooldown(remainingMs) {
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  if (safeRemaining <= 0) {
    displayNameEditCooldownUntilMs = 0;
    stopDisplayNameEditCooldownTicker();
    applyDisplayNameEditCooldownUI(0);
    return;
  }

  displayNameEditCooldownUntilMs = getServerNowDate().getTime() + safeRemaining;
  updateDisplayNameEditCooldownTicker();
  if (!displayNameEditCooldownIntervalId) {
    displayNameEditCooldownIntervalId = setInterval(updateDisplayNameEditCooldownTicker, 1000);
  }
}

function applyAccountPasswordResetCooldownUI(remainingMs) {
  if (!accountResetPasswordBtn) return;
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  const coolingDown = safeRemaining > 0;
  accountResetPasswordBtn.disabled = coolingDown;
  accountResetPasswordBtn.innerText = coolingDown
    ? `Change Password in ${formatCountdownClock(safeRemaining)}`
    : "Change Password";
  accountResetPasswordBtn.title = coolingDown ? "Password reset cooldown active" : "";
}

function stopAccountPasswordResetCooldownTicker() {
  if (!accountPasswordResetCooldownIntervalId) return;
  clearInterval(accountPasswordResetCooldownIntervalId);
  accountPasswordResetCooldownIntervalId = null;
}

function updateAccountPasswordResetCooldownTicker() {
  const remaining = accountPasswordResetCooldownUntilMs - getServerNowDate().getTime();
  if (remaining <= 0) {
    accountPasswordResetCooldownUntilMs = 0;
    stopAccountPasswordResetCooldownTicker();
    applyAccountPasswordResetCooldownUI(0);
    return;
  }
  applyAccountPasswordResetCooldownUI(remaining);
}

function startAccountPasswordResetCooldown(remainingMs) {
  const safeRemaining = Math.max(0, Number(remainingMs) || 0);
  if (safeRemaining <= 0) {
    accountPasswordResetCooldownUntilMs = 0;
    stopAccountPasswordResetCooldownTicker();
    applyAccountPasswordResetCooldownUI(0);
    return;
  }

  accountPasswordResetCooldownUntilMs = getServerNowDate().getTime() + safeRemaining;
  updateAccountPasswordResetCooldownTicker();
  if (!accountPasswordResetCooldownIntervalId) {
    accountPasswordResetCooldownIntervalId = setInterval(updateAccountPasswordResetCooldownTicker, 1000);
  }
}

function getDisplayNameCooldownUntilFromProfileData(profileData = {}) {
  const explicitCooldownUntil = Math.max(
    0,
    Number(profileData.displayNameDashboardCooldownUntilMs)
    || getOptionalTimestampMs(profileData.displayNameDashboardCooldownUntil)
    || 0
  );

  const changedAtMs = Math.max(
    0,
    Number(profileData.displayNameDashboardChangedAtMs)
    || getOptionalTimestampMs(profileData.displayNameDashboardChangedAt)
    || 0
  );

  const derivedCooldownUntil = changedAtMs > 0
    ? (changedAtMs + DISPLAY_NAME_EDIT_COOLDOWN_MS)
    : 0;

  return Math.max(explicitCooldownUntil, derivedCooldownUntil);
}

async function getDisplayNameEditCooldownRemainingFromProfile(userId, forceFresh = false) {
  const safeUid = String(userId || "").trim();
  if (!safeUid) return 0;

  try {
    const profileRef = doc(db, "users", safeUid, "settings", "profile");
    const profileSnap = forceFresh ? await getDocWithFreshFallback(profileRef) : await getDoc(profileRef);
    if (!profileSnap.exists()) return 0;
    const profileData = profileSnap.data() || {};
    const cooldownUntilMs = getDisplayNameCooldownUntilFromProfileData(profileData);
    if (!cooldownUntilMs) return 0;
    return Math.max(0, cooldownUntilMs - getServerNowDate().getTime());
  } catch (_) {
    return 0;
  }
}

async function refreshDisplayNameEditCooldownState(userId) {
  if (!userId) {
    startDisplayNameEditCooldown(0);
    return;
  }

  try {
    const remaining = await getDisplayNameEditCooldownRemainingFromProfile(userId, false);
    startDisplayNameEditCooldown(remaining);
  } catch (_) {
    startDisplayNameEditCooldown(0);
  }
}

async function refreshExportCooldownState(userId) {
  if (!userId) {
    startExportCooldown(0);
    return;
  }
  
  // Guard: verify auth state
  if (!auth.currentUser?.uid) {
    structuredLog('warn', 'export.auth_check', 'User not authenticated during export cooldown check');
    startExportCooldown(0);
    return;
  }

  try {
    const snapshotMetaRef = doc(db, "users", userId, "settings", EXPORT_SNAPSHOT_DOC_ID);
    const snapshotMeta = await fsGetDoc(snapshotMetaRef, 'exportSnapshot');
    if (!snapshotMeta.exists) {
      startExportCooldown(0);
      return;
    }

    const meta = snapshotMeta.data || {};
    if (typeof meta !== 'object' || meta === null) {
      structuredLog('warn', 'export.cooldown_data', 'Export metadata malformed');
      startExportCooldown(0);
      return;
    }
    
    const lastExportMs = getOptionalTimestampMs(meta.exportedAt) ?? getOptionalTimestampMs(meta.updatedAt);
    if (!lastExportMs) {
      startExportCooldown(0);
      return;
    }

    const elapsed = getServerNowDate().getTime() - lastExportMs;
    const remaining = EXPORT_COOLDOWN_MS - elapsed;
    startExportCooldown(remaining);
  } catch (err) {
    structuredLog('warn', 'export.cooldown', err?.message || String(err), { userId });
    startExportCooldown(0);
  }
}

function toSnapshotRows(snapshot) {
  return snapshot.docs.map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }));
}

function splitSnapshotChunks(serialized) {
  const chunks = [];
  for (let index = 0; index < serialized.length; index += EXPORT_SNAPSHOT_CHUNK_SIZE) {
    chunks.push(serialized.slice(index, index + EXPORT_SNAPSHOT_CHUNK_SIZE));
  }
  return chunks.length ? chunks : ["{}"];
}

async function buildExportPayloadForUser(userId, userMeta = {}, dbInstance = db) {
  const waterSettingsSnap = await fsGetDoc(doc(dbInstance, "users", userId, "settings", "water"), 'water');
  const sleepSettingsSnap = await fsGetDoc(doc(dbInstance, "users", userId, "settings", "sleep"), 'sleep');
  const dailyChallengeSnap = await fsGetDoc(doc(dbInstance, "users", userId, "settings", "dailyChallenge"), 'dailyChallenge');
  const weeklyTargetsSnap = await fsGetDoc(doc(dbInstance, "users", userId, "settings", "weeklyTargets"), 'weeklyTargets');
  const habitQuestSnap = await fsGetDoc(doc(dbInstance, "users", userId, "settings", "habitQuest"), 'habitQuest');
  const insightsSnap = await fsGetDoc(doc(dbInstance, "users", userId, "insights", "current"), 'insightsCurrent');
  const insightsBarGraphsSnap = await fsGetDoc(doc(dbInstance, "users", userId, "insights", "barGraphs"), 'insightsBarGraphs');

  const [
    moodsSnap,
    tasksSnap,
    waterSnap,
    sleepSnap,
    musicSessionsSnap,
    gratitudeSnap,
    aiSnap,
    challengeHistorySnap,
    rescueEventsSnap,
    remindersSnap
  ] = await Promise.all([
    getDocs(collection(dbInstance, "users", userId, "moods")),
    getDocs(collection(dbInstance, "users", userId, "tasks")),
    getDocs(collection(dbInstance, "users", userId, "waterIntake")),
    getDocs(collection(dbInstance, "users", userId, "sleepLogs")),
    getDocs(collection(dbInstance, "users", userId, "musicSessions")),
    getDocs(collection(dbInstance, "users", userId, "gratitudeLogs")),
    getDocs(collection(dbInstance, "users", userId, "aiChats")),
    getDocs(collection(dbInstance, "users", userId, "challengeHistory")),
    getDocs(collection(dbInstance, "users", userId, "rescueEvents")),
    getDocs(collection(dbInstance, "users", userId, "reminders"))
  ]);

  return {
    exportedAt: getServerNowDate().toISOString(),
    user: {
      uid: userMeta.uid || userId,
      email: userMeta.email || null,
      name: userMeta.name || null
    },
    waterSettings: waterSettingsSnap.exists() ? waterSettingsSnap.data() : null,
    sleepSettings: sleepSettingsSnap.exists() ? sleepSettingsSnap.data() : null,
    dailyChallengeSettings: dailyChallengeSnap.exists() ? dailyChallengeSnap.data() : null,
    weeklyTargets: weeklyTargetsSnap.exists() ? weeklyTargetsSnap.data() : null,
    habitQuest: habitQuestSnap.exists() ? habitQuestSnap.data() : null,
    insightsCurrent: insightsSnap.exists() ? insightsSnap.data() : null,
    insightsBarGraphs: insightsBarGraphsSnap.exists() ? insightsBarGraphsSnap.data() : null,
    moods: toSnapshotRows(moodsSnap),
    tasks: toSnapshotRows(tasksSnap),
    waterIntake: toSnapshotRows(waterSnap),
    sleepLogs: toSnapshotRows(sleepSnap),
    musicSessions: toSnapshotRows(musicSessionsSnap),
    gratitudeLogs: toSnapshotRows(gratitudeSnap),
    aiChats: toSnapshotRows(aiSnap),
    challengeHistory: toSnapshotRows(challengeHistorySnap),
    rescueEvents: toSnapshotRows(rescueEventsSnap),
    reminders: toSnapshotRows(remindersSnap)
  };
}

async function replaceUserSnapshotInFirebase(userId, payload, dbInstance = db) {
  const snapshotDocRef = doc(dbInstance, "users", userId, "settings", EXPORT_SNAPSHOT_DOC_ID);
  const chunksRef = collection(snapshotDocRef, "chunks");

  const existingChunkSnap = await getDocs(chunksRef);
  await Promise.all(existingChunkSnap.docs.map((docSnap) => deleteDoc(docSnap.ref)));

  const serialized = JSON.stringify(payload || {});
  const chunks = splitSnapshotChunks(serialized);

  await Promise.all(chunks.map((chunk, index) => setDoc(doc(chunksRef, String(index).padStart(4, "0")), {
    index,
    chunk,
    updatedAt: serverTimestamp()
  }, { merge: true })));

  await setDoc(snapshotDocRef, {
    schemaVersion: 1,
    chunkCount: chunks.length,
    exportedAt: payload?.exportedAt || getServerNowDate().toISOString(),
    updatedAt: serverTimestamp()
  }, { merge: true });
}

async function readUserSnapshotFromFirebase(userId, dbInstance = db) {
  const snapshotDocRef = doc(dbInstance, "users", userId, "settings", EXPORT_SNAPSHOT_DOC_ID);
  const snapshotMeta = await getDoc(snapshotDocRef);
  if (!snapshotMeta.exists()) return null;

  const chunksSnap = await getDocs(collection(snapshotDocRef, "chunks"));
  if (!chunksSnap.size) {
    const legacyPayload = snapshotMeta.data()?.payload;
    return legacyPayload && typeof legacyPayload === "object" ? legacyPayload : null;
  }

  const ordered = chunksSnap.docs
    .map((docSnap) => ({
      index: Number(docSnap.data()?.index) || 0,
      chunk: String(docSnap.data()?.chunk || "")
    }))
    .sort((a, b) => a.index - b.index);

  const serialized = ordered.map((item) => item.chunk).join("");
  if (!serialized.trim()) return null;
  return JSON.parse(serialized);
}

async function exportAllData() {
  const user = auth.currentUser;
  if (!user) {
    showToast("Please sign in first.");
    return;
  }

  try {
    const localRemaining = exportCooldownUntilMs - getServerNowDate().getTime();
    if (localRemaining > 0) {
      showToast(`Export cooldown active. Try again in ${formatCountdownClock(localRemaining)}.`);
      return;
    }

    const snapshotMetaRef = doc(db, "users", user.uid, "settings", EXPORT_SNAPSHOT_DOC_ID);
    const snapshotMeta = await getDoc(snapshotMetaRef);
    if (snapshotMeta.exists()) {
      const meta = snapshotMeta.data() || {};
      const lastExportMs = getOptionalTimestampMs(meta.exportedAt) ?? getOptionalTimestampMs(meta.updatedAt);
      if (lastExportMs) {
        const elapsed = getServerNowDate().getTime() - lastExportMs;
        const remaining = EXPORT_COOLDOWN_MS - elapsed;
        if (remaining > 0) {
          startExportCooldown(remaining);
          showToast(`Export cooldown active. Try again in ${formatCountdownClock(remaining)}.`);
          return;
        }
      }
    }

    const payload = await buildExportPayloadForUser(user.uid, {
      uid: user.uid,
      email: user.email || null,
      name: user.displayName || null
    }, db);
    await replaceUserSnapshotInFirebase(user.uid, payload, db);
    startExportCooldown(EXPORT_COOLDOWN_MS);
    showToast("Export backup saved to Firebase. Previous backup replaced.");
  } catch (err) {
    notifyFirestoreError(err);
  }
}

function normalizeExportTime(value) {
  if (!value) return getServerNowDate();

  if (typeof value === "string" || typeof value === "number") {
    const asDate = new Date(value);
    if (!Number.isNaN(asDate.getTime())) return asDate;
  }

  if (typeof value === "object") {
    if (typeof value.seconds === "number") {
      return new Date((value.seconds * 1000) + Math.floor((value.nanoseconds || 0) / 1e6));
    }
    if (typeof value._seconds === "number") {
      return new Date((value._seconds * 1000) + Math.floor((value._nanoseconds || 0) / 1e6));
    }
  }

  const fallback = new Date(value);
  if (!Number.isNaN(fallback.getTime())) return fallback;
  return getServerNowDate();
}

function setImportTransferError(message = "") {
  const isBackoffMessage = String(message || "").includes("Too many failed import attempts");
  if (!isBackoffMessage) stopImportBackoffCooldownTicker();
  if (!importTransferError) return;
  importTransferError.innerText = message || "";
  importTransferError.style.display = message ? "block" : "none";
}

function stopImportBackoffCooldownTicker() {
  if (importBackoffCooldownIntervalId) {
    clearInterval(importBackoffCooldownIntervalId);
    importBackoffCooldownIntervalId = null;
  }
  importBackoffCooldownEmail = "";
}

function updateImportBackoffCooldownTicker() {
  const sourceEmail = String(importBackoffCooldownEmail || "").trim();
  if (!sourceEmail || importTransferModal?.style?.display !== "flex") {
    stopImportBackoffCooldownTicker();
    return;
  }

  const remainingMs = getAuthBackoffRemainingMs("import", sourceEmail);
  if (remainingMs <= 0) {
    stopImportBackoffCooldownTicker();
    setImportTransferError("");
    return;
  }

  setImportTransferError(`Too many failed import attempts. Try again in ${formatCountdownClock(remainingMs)}.`);
}

function startImportBackoffCooldownTicker(sourceEmail, remainingMs = 0) {
  const normalizedEmail = String(sourceEmail || "").trim();
  if (!normalizedEmail) {
    stopImportBackoffCooldownTicker();
    return;
  }

  const currentRemaining = getAuthBackoffRemainingMs("import", normalizedEmail);
  const safeRemaining = Math.max(Number(remainingMs) || 0, currentRemaining);
  if (safeRemaining <= 0) {
    stopImportBackoffCooldownTicker();
    setImportTransferError("");
    return;
  }

  importBackoffCooldownEmail = normalizedEmail;
  setImportTransferError(`Too many failed import attempts. Try again in ${formatCountdownClock(safeRemaining)}.`);
  if (!importBackoffCooldownIntervalId) {
    importBackoffCooldownIntervalId = setInterval(updateImportBackoffCooldownTicker, 1000);
  }
}

function setImportTransferBusy(isBusy) {
  importTransferSubmitting = !!isBusy;
  if (importTransferConfirmBtn) {
    importTransferConfirmBtn.disabled = !!isBusy;
    importTransferConfirmBtn.innerText = isBusy ? "Importing..." : "Import";
  }
  if (importTransferCancelBtn) {
    importTransferCancelBtn.disabled = !!isBusy;
  }
  if (importSourceEmailInput) importSourceEmailInput.disabled = !!isBusy;
  if (importSourcePasswordInput) importSourcePasswordInput.disabled = !!isBusy;
}

function closeImportTransferModal(event, force = false) {
  if (event?.target && event.target !== importTransferModal) return;
  if (importTransferSubmitting && !force) return;
  if (importTransferModal) importTransferModal.style.display = "none";
  setImportTransferError("");
}

function startImportData() {
  const destinationUser = auth.currentUser;
  if (!destinationUser) {
    showToast("Please sign in first.");
    return;
  }
  if (importTransferModal) importTransferModal.style.display = "flex";
  ensureAppBackGuardState("import-modal", true);
  setImportTransferBusy(false);
  setImportTransferError("");
  if (importSourceEmailInput) {
    importSourceEmailInput.value = "";
    importSourceEmailInput.focus();
  }
  if (importSourcePasswordInput) importSourcePasswordInput.value = "";
}

async function submitImportTransfer() {
  if (importTransferSubmitting) return;

  const destinationUser = auth.currentUser;
  if (!destinationUser) {
    setImportTransferError("Please sign in first.");
    return;
  }

  const sourceEmail = String(importSourceEmailInput?.value || "").trim();
  const sourcePassword = String(importSourcePasswordInput?.value || "");
  if (!sourceEmail) {
    setImportTransferError("Source email is required.");
    return;
  }
  if (!sourcePassword) {
    setImportTransferError("Source password is required.");
    return;
  }

  const importBackoffRemaining = getAuthBackoffRemainingMs("import", sourceEmail);
  if (importBackoffRemaining > 0) {
    startImportBackoffCooldownTicker(sourceEmail, importBackoffRemaining);
    if (importSourcePasswordInput) importSourcePasswordInput.focus();
    return;
  }

  const confirmed = confirm(`Warning: current data will be replaced with the backup from ${sourceEmail}. Continue?`);
  if (!confirmed) return;

  setImportTransferBusy(true);
  setImportTransferError("");

  let payload = null;
  let sourceUserId = "";
  let stage = "auth";
  const { transferAuth, transferDb } = getTransferClients();

  try {
    await signInWithEmailAndPassword(transferAuth, sourceEmail, sourcePassword);
    const sourceUser = transferAuth.currentUser;
    if (!sourceUser) {
      setImportTransferError("Could not authenticate source account.");
      return;
    }

    clearAuthBackoffState("import", sourceEmail);
    sourceUserId = String(sourceUser.uid || "").trim();

    payload = await readUserSnapshotFromFirebase(sourceUser.uid, transferDb);
    if (!payload) {
      setImportTransferError("No export backup found in source account. Export there first.");
      return;
    }
    stage = "import";
    const importSummary = await applyImportPayloadToCurrentUser(destinationUser, payload);
    const alertResult = await queueSourceImportSecurityAlert(sourceUserId, destinationUser.email || "", destinationUser.uid || "", transferDb);
    closeImportTransferModal(null, true);
    if (!alertResult?.ok) {
      showToast("Import complete. Source account warning could not be saved.");
    } else if (!importSummary.hasCoreData) {
      showToast("Import completed. Source account will see a security warning on next login.");
    } else {
      showToast("Data import complete. Source account will see a security warning on next login.");
    }
  } catch (err) {
    if (stage === "auth") {
      const code = String(err?.code || "");
      if (
        code === "auth/invalid-credential"
        || code === "auth/user-not-found"
        || code === "auth/wrong-password"
        || code === "auth/invalid-email"
      ) {
        const backoff = registerAuthBackoffFailure("import", sourceEmail);
        if (backoff.remainingMs > 0) {
          startImportBackoffCooldownTicker(sourceEmail, backoff.remainingMs);
        } else {
          setImportTransferError("Incorrect email or password.");
        }
        if (importSourcePasswordInput) importSourcePasswordInput.value = "";
      } else {
        setImportTransferError("Could not verify source account. Please try again.");
        notifyFirestoreError(err);
      }
    } else {
      setImportTransferError("Import failed. Please try again.");
      notifyFirestoreError(err);
    }
  } finally {
    try {
      if (transferAuth.currentUser) await signOut(transferAuth);
    } catch (_) {}
    setImportTransferBusy(false);
    if (stage === "auth" && importTransferModal?.style?.display === "flex" && importSourcePasswordInput) {
      importSourcePasswordInput.focus();
    }
  }
}

async function clearUserCollection(userId, collectionName) {
  const snapshot = await getDocs(collection(db, "users", userId, collectionName));
  await Promise.all(snapshot.docs.map((docSnap) => deleteDoc(docSnap.ref)));
}

async function applyImportPayloadToCurrentUser(user, payload) {
  if (!user || !payload || typeof payload !== "object") {
    return { hasCoreData: false };
  }

  await Promise.all(EXPORT_TARGET_COLLECTIONS.map((name) => clearUserCollection(user.uid, name)));
  await deleteDoc(doc(db, "users", user.uid, "settings", "water")).catch((err) => structuredLog('warn', 'import.delete.water', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "settings", "sleep")).catch((err) => structuredLog('warn', 'import.delete.sleep', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "settings", "dailyChallenge")).catch((err) => structuredLog('warn', 'import.delete.challenge', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "settings", "weeklyTargets")).catch((err) => structuredLog('warn', 'import.delete.weekly', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "settings", "habitQuest")).catch((err) => structuredLog('warn', 'import.delete.quest', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "insights", "current")).catch((err) => structuredLog('warn', 'import.delete.current', err?.message || String(err)));
  await deleteDoc(doc(db, "users", user.uid, "insights", "barGraphs")).catch((err) => structuredLog('warn', 'import.delete.graphs', err?.message || String(err)));
  persistedBarGraphs = null;
  persistedBehaviorPatterns = null;

  const moods = Array.isArray(payload.moods) ? payload.moods : [];
  const tasks = Array.isArray(payload.tasks) ? payload.tasks : [];
  const waterIntake = Array.isArray(payload.waterIntake) ? payload.waterIntake : [];
  const sleepLogs = Array.isArray(payload.sleepLogs) ? payload.sleepLogs : [];
  const musicSessionsPayload = Array.isArray(payload.musicSessions) ? payload.musicSessions : [];
  const gratitudeLogs = Array.isArray(payload.gratitudeLogs) ? payload.gratitudeLogs : [];
  const aiChats = Array.isArray(payload.aiChats) ? payload.aiChats : [];
  const challengeHistory = Array.isArray(payload.challengeHistory) ? payload.challengeHistory : [];
  const rescueEventsPayload = Array.isArray(payload.rescueEvents) ? payload.rescueEvents : [];
  const remindersPayload = Array.isArray(payload.reminders) ? payload.reminders : [];

  await Promise.all(moods.map((entry) => addDoc(collection(db, "users", user.uid, "moods"), {
    mood: entry.mood || "",
    uid: user.uid,
    email: user.email || null,
    time: normalizeExportTime(entry.time)
  })));

  await Promise.all(tasks.map((entry) => addDoc(collection(db, "users", user.uid, "tasks"), {
    text: entry.text || "",
    completed: !!entry.completed,
    completedAt: entry.completedAt ? normalizeExportTime(entry.completedAt) : null,
    time: normalizeExportTime(entry.time)
  })));

  await Promise.all(waterIntake.map((entry) => addDoc(collection(db, "users", user.uid, "waterIntake"), {
    glasses: Number(entry.glasses) || 0,
    time: normalizeExportTime(entry.time)
  })));

  await Promise.all(sleepLogs.map((entry) => addDoc(collection(db, "users", user.uid, "sleepLogs"), {
    hours: Number(entry.hours) || 0,
    time: normalizeExportTime(entry.time)
  })));

  await Promise.all(musicSessionsPayload.map((entry) => {
    const dayKey = String(entry.dayKey || entry.id || dateToKey(normalizeExportTime(entry.time)) || "").trim();
    if (!dayKey) return Promise.resolve();
    return setDoc(doc(db, "users", user.uid, "musicSessions", dayKey), {
      dayKey,
      played: entry.played !== false,
      time: normalizeExportTime(entry.time || entry.updatedAt),
      updatedAt: normalizeExportTime(entry.updatedAt || entry.time)
    }, { merge: true });
  }));

  await Promise.all(gratitudeLogs.map((entry) => addDoc(collection(db, "users", user.uid, "gratitudeLogs"), {
    text: entry.text || "",
    time: normalizeExportTime(entry.time)
  })));

  await Promise.all(aiChats.map((entry) => addDoc(collection(db, "users", user.uid, "aiChats"), {
    userMessage: entry.userMessage || "",
    aiResponse: entry.aiResponse || "",
    aiResponseIsHtml: !!entry.aiResponseIsHtml,
    createdAt: normalizeExportTime(entry.createdAt)
  })));

  await Promise.all(challengeHistory.map((entry) => {
    const dateKey = entry.dateKey || (typeof entry.id === "string" ? entry.id : "");
    if (!dateKey) return Promise.resolve();
    return setDoc(doc(db, "users", user.uid, "challengeHistory", dateKey), {
      completed: !!entry.completed,
      challenge: entry.challenge || "",
      dateKey,
      updatedAt: normalizeExportTime(entry.updatedAt || entry.time)
    }, { merge: true });
  }));

  await Promise.all(rescueEventsPayload.map((entry) => addDoc(collection(db, "users", user.uid, "rescueEvents"), {
    level: entry.level || "",
    reason: entry.reason || "",
    time: normalizeExportTime(entry.time || entry.createdAt || entry.updatedAt)
  })));

  await Promise.all(remindersPayload.map((entry) => {
    const minutes = Math.max(0, Number(entry.minutes) || 0);
    const targetAtMs = Number(entry.targetAtMs) || (getServerNowDate().getTime() + (minutes * 60000));
    return addDoc(collection(db, "users", user.uid, "reminders"), {
      text: entry.text || "",
      minutes,
      targetAtMs,
      createdAt: normalizeExportTime(entry.createdAt || entry.time),
      completed: !!entry.completed,
      completedAt: entry.completedAt ? normalizeExportTime(entry.completedAt) : null
    });
  }));

  if (payload.waterSettings && typeof payload.waterSettings.goal !== "undefined") {
    await setDoc(doc(db, "users", user.uid, "settings", "water"), {
      goal: Number(payload.waterSettings.goal) || 0
    }, { merge: true });
  }

  if (payload.sleepSettings && typeof payload.sleepSettings === "object") {
    await setDoc(doc(db, "users", user.uid, "settings", "sleep"), {
      bedtimeEnabled: !!payload.sleepSettings.bedtimeEnabled,
      bedtimeTime: String(payload.sleepSettings.bedtimeTime || ""),
      bedtimeMeridiem: ""
    }, { merge: true });
  }

  if (payload.dailyChallengeSettings) {
    await setDoc(doc(db, "users", user.uid, "settings", "dailyChallenge"), {
      challenge: payload.dailyChallengeSettings.challenge || "",
      completed: !!payload.dailyChallengeSettings.completed,
      dateKey: payload.dailyChallengeSettings.dateKey || getTodayKey(),
      updatedAt: normalizeExportTime(payload.dailyChallengeSettings.updatedAt)
    }, { merge: true });
  }

  if (payload.weeklyTargets) {
    await setDoc(doc(db, "users", user.uid, "settings", "weeklyTargets"), {
      waterGoal: Number(payload.weeklyTargets.waterGoal) || 0,
      sleepTarget: Number(payload.weeklyTargets.sleepTarget) || 8,
      taskTarget: Number(payload.weeklyTargets.taskTarget) || 5,
      updatedAt: normalizeExportTime(payload.weeklyTargets.updatedAt)
    }, { merge: true });
  }

  if (payload.habitQuest) {
    await setDoc(doc(db, "users", user.uid, "settings", "habitQuest"), {
      dateKey: payload.habitQuest.dateKey || getTodayKey(),
      xp: Number(payload.habitQuest.xp) || 0,
      level: Number(payload.habitQuest.level) || 1,
      shield: !!payload.habitQuest.shield,
      quests: Array.isArray(payload.habitQuest.quests) ? payload.habitQuest.quests : [],
      updatedAt: normalizeExportTime(payload.habitQuest.updatedAt)
    }, { merge: true });
  }

  if (payload.insightsCurrent) {
    await setDoc(doc(db, "users", user.uid, "insights", "current"), {
      ...payload.insightsCurrent,
      updatedAt: normalizeExportTime(payload.insightsCurrent.updatedAt)
    }, { merge: true });
  }

  if (payload.insightsBarGraphs) {
    await setDoc(doc(db, "users", user.uid, "insights", "barGraphs"), {
      ...payload.insightsBarGraphs,
      updatedAt: normalizeExportTime(payload.insightsBarGraphs.updatedAt)
    }, { merge: true });
    persistedBarGraphs = payload.insightsBarGraphs;
  }

  await Promise.all([
    loadDailyChallenge(user.uid),
    loadDailyUsage(user.uid),
    loadMoods(user.uid),
    loadAiChats(user.uid),
    loadTasks(user.uid),
    loadReminders(user.uid),
    loadWeeklyTargets(user.uid),
    loadRescueEvents(user.uid),
    loadHabitQuest(user.uid),
    loadWaterData(user.uid),
    loadSleepData(user.uid),
    loadMusicSessions(user.uid),
    loadBedtimeSettings(user.uid),
    loadGratitude(user.uid)
  ]);

  const hasCoreData = moods.length || tasks.length || gratitudeLogs.length || remindersPayload.length;
  return { hasCoreData: !!hasCoreData };
}

function importDataFileChange(event) {
  if (event?.target) event.target.value = "";
  showToast("File import is deprecated. Use Import Data and source account email/password.");
}

// Daily Challenge
const dailyChallenges = [
  "Finish 1 small task you’ve been putting off.",
  "Learn 1 new word or fact today.",
  "Clean or organize one small area of your room/desk.",
  "Write down 3 things you’re grateful for.",
  "Smile at 3 people today.",
  "Avoid social media for 1 hour.",
  "Try a new hobby for 15 minutes.",
  "Drink 1 extra glass of water today.",
  "Take a 5-minute stretch break every 2 hours.",
  "Eat a fruit or vegetable with every meal.",
  "Meditate for 5–10 minutes.",
  "Read 5 pages of a book.",
  "Take a 10-minute walk without your phone.",
  "Do 20 squats or 15 push-ups.",
  "Write one short journal entry about your day.",
  "Complete one pending task before noon.",
  "Declutter 10 items from your workspace.",
  "Practice deep breathing for 3 minutes.",
  "Spend 15 minutes learning a new skill.",
  "No sugary drink for the next 12 hours.",
  "Drink water before every meal today.",
  "Sleep 30 minutes earlier tonight.",
  "Send one kind message to a friend or family member.",
  "Do a 5-minute posture check and correction.",
  "Complete one task in a 25-minute focus sprint.",
  "Write your top 3 priorities for tomorrow.",
  "Listen to calming music for 10 minutes.",
  "Avoid doom-scrolling after dinner.",
  "Take a screen break for 20 minutes.",
  "Do a 10-minute room reset.",
  "Try a healthy snack instead of junk food once today.",
  "Spend 10 minutes in sunlight.",
  "Track and finish one important task fully.",
  "Do a quick gratitude walk and notice 3 good things.",
  "Practice a hobby for 20 minutes.",
  "Review your expenses for the day in 5 minutes.",
  "Write one positive affirmation and repeat it 5 times.",
  "No phone for the first 30 minutes after waking up.",
  "Complete your toughest task first.",
  "Do a 5-minute stretching routine before sleep."
];

function pickFreshDailyChallengeText(excludeText = "") {
  const filtered = dailyChallenges.filter((entry) => String(entry || "") !== String(excludeText || ""));
  const pool = filtered.length ? filtered : dailyChallenges;
  const index = Math.floor(Math.random() * pool.length);
  return pool[index] || pickChallengeForDate(getTodayKey());
}

async function assignFreshDailyChallenge(userId, excludeText = "") {
  const todayKey = getTodayKey();
  const challenge = pickFreshDailyChallengeText(excludeText);

  currentChallengeDateKey = todayKey;
  currentChallengeText = challenge;
  dailyChallengeCompleted = false;
  dailyChallengeElement.innerText = challenge;
  challengeResultElement.innerText = "";
  updateChallengeCompleteButtonState();

  if (userId) {
    try {
      await setDoc(doc(db, "users", userId, "settings", "dailyChallenge"), {
        challenge,
        completed: false,
        dateKey: todayKey,
        timeZone: userTimeZone,
        updatedAt: serverTimestamp()
      }, { merge: true });
    } catch (err) {
      notifyFirestoreError(err);
    }
  }

  updateInsights();
}

// ---------- Function to pick a random daily challenge ----------
function pickDailyChallenge() {
  const todayKey = getTodayKey();
  const challenge = pickChallengeForDate(todayKey);
  currentChallengeDateKey = todayKey;
  currentChallengeText = challenge;
  dailyChallengeElement.innerText = challenge;
  challengeResultElement.innerText = "";
  dailyChallengeCompleted = false;
  updateChallengeCompleteButtonState();
  updateInsights();
}

function updateChallengeCompleteButtonState() {
  if (!challengeCompleteBtn) return;
  challengeCompleteBtn.disabled = !!dailyChallengeCompleted;
}

async function saveDailyChallengeState() {
  const user = auth.currentUser;
  if (!user) return;

  const todayKey = getTodayKey();
  try {
    await setDoc(doc(db, "users", user.uid, "settings", "dailyChallenge"), {
      challenge: currentChallengeText,
      completed: dailyChallengeCompleted,
      dateKey: todayKey,
      timeZone: userTimeZone,
      updatedAt: serverTimestamp()
    }, { merge: true });

    if (dailyChallengeCompleted) {
      await setDoc(doc(db, "users", user.uid, "challengeHistory", todayKey), {
        completed: true,
        challenge: currentChallengeText,
        dateKey: todayKey,
        updatedAt: serverTimestamp()
      }, { merge: true });
    }
  } catch (err) {
    notifyFirestoreError(err);
  }
}

async function loadDailyChallenge(userId) {
  const todayKey = getTodayKey();
  challengeDates.length = 0;

  try {
    const [challengeSettingsSnap, historySnap] = await Promise.all([
      getDoc(doc(db, "users", userId, "settings", "dailyChallenge")),
      getDocs(collection(db, "users", userId, "challengeHistory"))
    ]);

    historySnap.docs.forEach((docSnap) => {
      const data = docSnap.data();
      if (!data.completed) return;
      const key = data.dateKey || docSnap.id;
      const parsed = dateKeyToDate(key);
      if (parsed) challengeDates.push(parsed);
    });

    let challenge = pickChallengeForDate(todayKey);
    let completed = false;

    if (challengeSettingsSnap.exists()) {
      const settings = challengeSettingsSnap.data();
      if (settings.dateKey === todayKey) {
        challenge = settings.challenge || challenge;
        completed = !!settings.completed;
      }
    }

    currentChallengeDateKey = todayKey;
    currentChallengeText = challenge;
    dailyChallengeCompleted = completed;
    dailyChallengeElement.innerText = challenge;
    challengeResultElement.innerText = completed ? "✅ Challenge completed! Great job!" : "";
    updateChallengeCompleteButtonState();

    if (completed) {
      const parsedToday = dateKeyToDate(todayKey);
      if (parsedToday && !challengeDates.some((date) => dateToKey(date) === todayKey)) {
        challengeDates.push(parsedToday);
      }
    }

    await saveDailyChallengeState();
    updateInsights();
  } catch (err) {
    notifyFirestoreError(err);
    pickDailyChallenge();
  }
}

// Initialize daily challenge on page load
pickDailyChallenge();

// Complete challenge function
async function completeChallenge() {
  if (dailyChallengeCompleted) {
    challengeResultElement.innerText = "✅ Challenge already completed for today.";
    updateChallengeCompleteButtonState();
    return;
  }

  dailyChallengeCompleted = true;
  const todayKey = getTodayKey();
  const parsedToday = dateKeyToDate(todayKey);
  if (parsedToday && !challengeDates.some((date) => dateToKey(date) === todayKey)) {
    challengeDates.push(parsedToday);
  }

  challengeResultElement.innerText = "✅ Challenge completed! Great job!";
  updateChallengeCompleteButtonState();
  updateInsights();
  await saveDailyChallengeState();
}

Object.assign(window, {
  handleAuth,
  resendVerificationEmailFromModal,
  toggleAuth,
  toggleAccountPanel,
  closeAccountPanel,
  clearAllAccountData,
  runCrashRescueFlow,
  dismissCrashAlertBanner,
  setNextWeekTargets,
  applyRecoverySchedule,
  nextInsightMetric,
  signOutUser,
  aiChat,
  clearAiChats,
  addReminder,
  addTask,
  calculateFinance,
  saveMood,
  setWaterGoal,
  saveWater,
  clearWaterData,
  saveSleep,
  clearSleepData,
  clearBedtimeData,
  setBedtimeReminder,
  closeBedtimeReminderModal,
  clearTimeMirror,
  timeTraveller,
  newQuote,
  saveGratitude,
  completeChallenge,
  exportAllData,
  startImportData,
  closeImportTransferModal,
  submitImportTransfer,
  startAddFriendRequest,
  closeAddFriendModal,
  closeReverseFriendRequestModal,
  submitAddFriendRequest,
  importDataFileChange,
  prevWelcomeGuideStep,
  nextWelcomeGuideStep,
  skipWelcomeGuide,
  openWelcomeGuideFromHelp,
  acceptTosAgreement,
  openReportRedirectConfirm,
  closeReportRedirectConfirm,
  continueReportRedirect,
  handleGoogleAuth,
  submitGoogleIdentitySetup,
  cancelGoogleIdentitySetup,
  sendResetPasswordEmail,
  sendAccountResetPasswordEmail,
  editAccountDisplayName,
  refreshStartupPlan,
  applyStartupPlanAsTasks,
  generateStartupWeeklyReport,
  copyStartupWeeklyReport
});



})().catch((err) => {
  console.error("NovaFix failed to start:", err);
  const splash = document.getElementById("splash");
  if (splash) {
    splash.classList.add("hide");
    setTimeout(() => splash.remove(), 1000);
  }
  const signInModal = document.getElementById("signInModal");
  if (signInModal) signInModal.style.display = "flex";
});
