import {
  CloudConflictInfo,
  CloudflareSyncConfig,
  DecryptedVaultRecord,
  EncryptedVaultPayload,
  LocalStoragePersistenceWarning,
  LocalSyncStateV2,
  RecoverySummaryInfo,
  RemoteVaultProbeResult,
  StagedRemotePullResult,
  SyncErrorCategory,
  SyncStatus,
  VaultCategoryItem,
  VaultHistoryEntry,
  WorkerConnectivityProbeResult,
} from '../types/vault';
import {
  generateVaultId,
  unlockEncryptedVaultPayload,
  validateV2VaultEnvelopeStructure,
} from '../crypto/cryptoEngine';

// Obsolete V1 storage keys to be purged on startup (never call localStorage.clear())
export const OBSOLETE_V1_STORAGE_KEYS = [
  'aegis_zk_vault_ciphertext_v1',
  'aegis_zk_vault_rollback_backup_v1',
  'aegis_zk_sync_config_v1',
  'aegis_zk_sync_token_session_v1',
  'aegis_zk_categories_v1',
] as const;

// V2 Storage Keys
export const VAULT_STORAGE_KEY = 'aegis_zk_vault_v2';
export const VAULT_ROLLBACK_BACKUP_KEY = 'aegis_zk_pre_restore_backup_v2';
export const SYNC_STATE_STORAGE_KEY = 'aegis_zk_sync_state_v2';
export const SYNC_CONFIG_STORAGE_KEY = 'aegis_zk_sync_config_v2';
export const SYNC_TOKEN_SESSION_KEY = 'aegis_zk_sync_token_session_v2';
export const STORAGE_META_KEY = 'aegis_zk_storage_meta_v2';

export const MAX_VAULT_PAYLOAD_BYTES = 1024 * 1024; // 1 MB
export const SYNC_PROTOCOL_VERSION = 2 as const;

// Operation-specific timeouts optimized for high-latency / weak cross-border networks
export const WORKER_TIMEOUT_MS = {
  HEAD_PROBE: 5000,
  GET_VAULT: 12000,
  GET_HISTORY: 12000,
  PUT_VAULT: 15000,
  POST_INIT: 15000,
} as const;

const IDB_DATABASE_NAME = 'aegis_vault_v2_db';
const IDB_DATABASE_VERSION = 1;
const IDB_STORE_VAULT = 'vault_store';
const IDB_STORE_SYNC = 'sync_state_store';
const CROSS_TAB_CHANNEL_NAME = 'aegis_vault_v2_channel';

interface StorageMetaState {
  writeSequence: number;
  resetEpoch: number;
  updatedAt: number;
}

export interface AtomicIdbSnapshot {
  vault: EncryptedVaultPayload | null;
  syncState: LocalSyncStateV2 | null;
  rollbackBackup?: EncryptedVaultPayload | null;
  meta: StorageMetaState;
}

export interface PluggableIdbAdapter {
  readSnapshot(): Promise<AtomicIdbSnapshot | null>;
  writeSnapshotAtomically(snapshot: AtomicIdbSnapshot): Promise<void>;
  clearVaultAtomically(meta: StorageMetaState): Promise<void>;
}

// Volatile runtime memory store for API Token (highest priority during active session)
let runtimeApiTokenMemory = '';

// Monotonic write sequence and reset epoch in memory
let memoryWriteSequence = 0;
let memoryResetEpoch = 0;
let lastPersistenceWarning: LocalStoragePersistenceWarning | null = null;
let pendingIdbWritePromise: Promise<void> = Promise.resolve();
let inFlightPushQueue: Promise<unknown> = Promise.resolve();

// Optional test hooks for deterministic unit testing of IndexedDB failures & custom adapters
let customIdbAdapterForTests: PluggableIdbAdapter | null = null;
let simulatedPersistenceFailureForTests: {
  code: 'QUOTA_EXCEEDED' | 'IDB_TRANSACTION_FAILED' | 'STORAGE_WRITE_FAILED';
  message: string;
} | null = null;

/**
 * Computes a deterministic, synchronous content fingerprint of a V2 EncryptedVaultPayload
 * so `pendingMutationId` is strictly bound to the exact immutable ciphertext snapshot.
 */
export function computePayloadContentSignature(
  payload: EncryptedVaultPayload
): string {
  const canonical = JSON.stringify({
    formatVersion: payload.formatVersion,
    vaultId: payload.vaultId,
    kdf: payload.kdf,
    cipher: payload.cipher,
    verifier: payload.verifier,
    encryptedMetadata: payload.encryptedMetadata,
    encryptedRecords: [...payload.encryptedRecords]
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((r) => ({
        id: r.id,
        recordType: r.recordType,
        iv: r.iv,
        ciphertext: r.ciphertext,
        createdAt: r.createdAt,
        updatedAt: r.updatedAt,
      })),
  });

  // 64-bit FNV-1a dual-hash for fast synchronous deterministic fingerprinting
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < canonical.length; i++) {
    const ch = canonical.charCodeAt(i);
    h1 ^= ch;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= ch ^ (i & 0xff);
    h2 = Math.imul(h2, 0x811c9dc5);
  }
  return `v2sig-${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0)
    .toString(16)
    .padStart(8, '0')}-${canonical.length}`;
}

/**
 * Purges only AegisVault's obsolete V1 keys from localStorage and sessionStorage.
 * Never calls localStorage.clear() so other same-origin data is never harmed.
 */
export function purgeLegacyV1StorageKeys(): void {
  try {
    if (typeof window === 'undefined') return;
    for (const key of OBSOLETE_V1_STORAGE_KEYS) {
      window.localStorage?.removeItem(key);
      window.sessionStorage?.removeItem(key);
    }
  } catch {
    // Ignore storage access errors
  }
}

purgeLegacyV1StorageKeys();

function readLocalStorageMeta(): StorageMetaState {
  if (typeof window === 'undefined') {
    return {
      writeSequence: memoryWriteSequence,
      resetEpoch: memoryResetEpoch,
      updatedAt: 0,
    };
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_META_KEY);
    if (!raw) {
      return {
        writeSequence: memoryWriteSequence,
        resetEpoch: memoryResetEpoch,
        updatedAt: 0,
      };
    }
    const parsed = JSON.parse(raw) as Partial<StorageMetaState>;
    const writeSequence = Math.max(
      memoryWriteSequence,
      typeof parsed.writeSequence === 'number' ? parsed.writeSequence : 0
    );
    const resetEpoch = Math.max(
      memoryResetEpoch,
      typeof parsed.resetEpoch === 'number' ? parsed.resetEpoch : 0
    );
    memoryWriteSequence = writeSequence;
    memoryResetEpoch = resetEpoch;
    return {
      writeSequence,
      resetEpoch,
      updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : 0,
    };
  } catch {
    return {
      writeSequence: memoryWriteSequence,
      resetEpoch: memoryResetEpoch,
      updatedAt: 0,
    };
  }
}

function writeLocalStorageMeta(meta: StorageMetaState): void {
  memoryWriteSequence = Math.max(memoryWriteSequence, meta.writeSequence);
  memoryResetEpoch = Math.max(memoryResetEpoch, meta.resetEpoch);
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(STORAGE_META_KEY, JSON.stringify(meta));
}

/**
 * Opens the browser IndexedDB database with both `vault_store` and `sync_state_store`.
 */
function openVaultIndexedDB(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(IDB_DATABASE_NAME, IDB_DATABASE_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(IDB_STORE_VAULT)) {
          db.createObjectStore(IDB_STORE_VAULT);
        }
        if (!db.objectStoreNames.contains(IDB_STORE_SYNC)) {
          db.createObjectStore(IDB_STORE_SYNC);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

const nativeBrowserIdbAdapter: PluggableIdbAdapter = {
  async readSnapshot(): Promise<AtomicIdbSnapshot | null> {
    const db = await openVaultIndexedDB();
    if (!db) return null;
    return new Promise((resolve) => {
      try {
        const tx = db.transaction(
          [IDB_STORE_VAULT, IDB_STORE_SYNC],
          'readonly'
        );
        const vaultStore = tx.objectStore(IDB_STORE_VAULT);
        const syncStore = tx.objectStore(IDB_STORE_SYNC);

        const vaultReq = vaultStore.get('primary');
        const backupReq = vaultStore.get('rollback_backup');
        const syncReq = syncStore.get('primary');
        const metaReq = syncStore.get('storage_meta');

        tx.oncomplete = () => {
          const rawMeta = (metaReq.result as Partial<StorageMetaState>) ?? {};
          const snapshot: AtomicIdbSnapshot = {
            vault: (vaultReq.result as EncryptedVaultPayload) ?? null,
            syncState: (syncReq.result as LocalSyncStateV2) ?? null,
            rollbackBackup:
              (backupReq.result as EncryptedVaultPayload) ?? null,
            meta: {
              writeSequence:
                typeof rawMeta.writeSequence === 'number'
                  ? rawMeta.writeSequence
                  : 0,
              resetEpoch:
                typeof rawMeta.resetEpoch === 'number' ? rawMeta.resetEpoch : 0,
              updatedAt:
                typeof rawMeta.updatedAt === 'number' ? rawMeta.updatedAt : 0,
            },
          };
          db.close();
          resolve(snapshot);
        };
        tx.onerror = () => {
          db.close();
          resolve(null);
        };
        tx.onabort = () => {
          db.close();
          resolve(null);
        };
      } catch {
        db.close();
        resolve(null);
      }
    });
  },

  async writeSnapshotAtomically(snapshot: AtomicIdbSnapshot): Promise<void> {
    const db = await openVaultIndexedDB();
    if (!db) return;
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(
          [IDB_STORE_VAULT, IDB_STORE_SYNC],
          'readwrite'
        );
        const vaultStore = tx.objectStore(IDB_STORE_VAULT);
        const syncStore = tx.objectStore(IDB_STORE_SYNC);

        // Guard against out-of-order stale async writes or writes from before a vault reset
        const existingMetaReq = syncStore.get('storage_meta');
        existingMetaReq.onsuccess = () => {
          const existingMeta =
            (existingMetaReq.result as Partial<StorageMetaState>) ?? {};
          const existingResetEpoch =
            typeof existingMeta.resetEpoch === 'number'
              ? existingMeta.resetEpoch
              : 0;
          const existingWriteSeq =
            typeof existingMeta.writeSequence === 'number'
              ? existingMeta.writeSequence
              : 0;

          if (
            snapshot.meta.resetEpoch < existingResetEpoch ||
            snapshot.meta. resetEpoch < memoryResetEpoch
          ) {
            // Stale write from before a reset: abort silently without overwriting
            return;
          }
          if (
            snapshot.meta.resetEpoch === existingResetEpoch &&
            snapshot.meta.writeSequence < existingWriteSeq
          ) {
            // Out-of-order older write sequence: skip so newer state is preserved
            return;
          }

          if (snapshot.vault) {
            vaultStore.put(snapshot.vault, 'primary');
          } else {
            vaultStore.delete('primary');
          }

          if (snapshot.rollbackBackup !== undefined) {
            if (snapshot.rollbackBackup) {
              vaultStore.put(snapshot.rollbackBackup, 'rollback_backup');
            } else {
              vaultStore.delete('rollback_backup');
            }
          }

          if (snapshot.syncState) {
            syncStore.put(snapshot.syncState, 'primary');
          } else {
            syncStore.delete('primary');
          }

          syncStore.put(snapshot.meta, 'storage_meta');
        };

        // CRITICAL: Only resolve after tx.oncomplete fires!
        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          const err = tx.error || new Error('IndexedDB 事务写入失败');
          db.close();
          reject(err);
        };
        tx.onabort = () => {
          const err = tx.error || new Error('IndexedDB 事务被中止');
          db.close();
          reject(err);
        };
      } catch (err) {
        db.close();
        reject(err);
      }
    });
  },

  async clearVaultAtomically(meta: StorageMetaState): Promise<void> {
    const db = await openVaultIndexedDB();
    if (!db) return;
    return new Promise((resolve, reject) => {
      try {
        const tx = db.transaction(
          [IDB_STORE_VAULT, IDB_STORE_SYNC],
          'readwrite'
        );
        const vaultStore = tx.objectStore(IDB_STORE_VAULT);
        const syncStore = tx.objectStore(IDB_STORE_SYNC);

        vaultStore.delete('primary');
        syncStore.delete('primary');
        syncStore.put(meta, 'storage_meta');

        tx.oncomplete = () => {
          db.close();
          resolve();
        };
        tx.onerror = () => {
          const err = tx.error || new Error('IndexedDB 清空事务失败');
          db.close();
          reject(err);
        };
        tx.onabort = () => {
          const err = tx.error || new Error('IndexedDB 清空事务被中止');
          db.close();
          reject(err);
        };
      } catch (err) {
        db.close();
        reject(err);
      }
    });
  },
};

function getActiveIdbAdapter(): PluggableIdbAdapter {
  return customIdbAdapterForTests ?? nativeBrowserIdbAdapter;
}

export interface CrossTabVaultEvent {
  type: 'VAULT_UPDATED' | 'SYNC_STATE_UPDATED' | 'VAULT_RESET';
  vaultId: string;
  updatedAt: string;
  revision: number;
  writeSequence?: number;
  resetEpoch?: number;
}

function broadcastCrossTabUpdate(event: CrossTabVaultEvent): void {
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      const bc = new BroadcastChannel(CROSS_TAB_CHANNEL_NAME);
      bc.postMessage(event);
      bc.close();
    }
  } catch {
    // Ignore if BroadcastChannel is unsupported
  }
}

export function subscribeToCrossTabVaultUpdates(
  onUpdate: (event: CrossTabVaultEvent) => void
): () => void {
  let bc: BroadcastChannel | null = null;
  try {
    if (typeof BroadcastChannel !== 'undefined') {
      bc = new BroadcastChannel(CROSS_TAB_CHANNEL_NAME);
      bc.onmessage = (msg) => {
        if (msg.data && typeof msg.data === 'object' && 'type' in msg.data) {
          const incoming = msg.data as CrossTabVaultEvent;
          if (
            typeof incoming.resetEpoch === 'number' &&
            incoming.resetEpoch > memoryResetEpoch
          ) {
            memoryResetEpoch = incoming.resetEpoch;
          }
          if (
            typeof incoming.writeSequence === 'number' &&
            incoming.writeSequence > memoryWriteSequence
          ) {
            memoryWriteSequence = incoming.writeSequence;
          }
          onUpdate(incoming);
        }
      };
    }
  } catch {
    bc = null;
  }

  const handleStorage = (e: StorageEvent) => {
    if (
      e.key === VAULT_STORAGE_KEY ||
      e.key === SYNC_STATE_STORAGE_KEY ||
      e.key === STORAGE_META_KEY
    ) {
      const meta = readLocalStorageMeta();
      const vault = SyncService.getLocalVault();
      const syncState = SyncService.getLocalSyncState();
      if (vault) {
        onUpdate({
          type:
            e.key === VAULT_STORAGE_KEY
              ? 'VAULT_UPDATED'
              : 'SYNC_STATE_UPDATED',
          vaultId: vault.vaultId,
          updatedAt: vault.updatedAt,
          revision: syncState.lastSyncedRevision,
          writeSequence: meta.writeSequence,
          resetEpoch: meta.resetEpoch,
        });
      } else if (e.key === VAULT_STORAGE_KEY && e.newValue === null) {
        onUpdate({
          type: 'VAULT_RESET',
          vaultId: '',
          updatedAt: new Date().toISOString(),
          revision: 0,
          writeSequence: meta.writeSequence,
          resetEpoch: meta.resetEpoch,
        });
      }
    }
  };

  if (
    typeof window !== 'undefined' &&
    typeof window.addEventListener === 'function'
  ) {
    window.addEventListener('storage', handleStorage);
  }

  return () => {
    if (bc) bc.close();
    if (
      typeof window !== 'undefined' &&
      typeof window.removeEventListener === 'function'
    ) {
      window.removeEventListener('storage', handleStorage);
    }
  };
}

/**
 * Validates and normalizes the Cloudflare Worker endpoint URL.
 * Enforces HTTPS in production (allows http://localhost or http://127.0.0.1 for local testing).
 * Rejects URLs with query parameters or embedded credentials.
 */
export function normalizeWorkerEndpoint(
  rawUrl: string,
  subPath: string = ''
): string {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new Error('请先配置有效的 Cloudflare Worker 节点地址');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(
      'Worker 地址格式无效，请输入完整的 https:// 域名地址（开发环境可使用 http://localhost）'
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error('安全策略拒绝：禁止在 Worker URL 中内嵌账号或密码凭证');
  }

  if (parsed.search || parsed.hash) {
    throw new Error(
      '安全策略拒绝：禁止在 Worker URL 查询参数 (?token=...) 中附加任何参数或访问凭证'
    );
  }

  const isLocalhost =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';

  if (
    parsed.protocol !== 'https:' &&
    !(isLocalhost && parsed.protocol === 'http:')
  ) {
    throw new Error(
      '安全策略拒绝：生产环境强制要求使用 HTTPS 加密连接（仅本地 localhost 开发允许 HTTP）'
    );
  }

  const cleanPath = parsed.pathname.replace(/\/+$/, '');
  const baseEndpoint = cleanPath.endsWith('/api/vault')
    ? `${parsed.origin}${cleanPath}`
    : `${parsed.origin}${cleanPath}/api/vault`;

  return `${baseEndpoint}${subPath}`;
}

/**
 * Compares two V2 EncryptedVaultPayloads to determine if their contents or metadata differ.
 */
export function hasEncryptedVaultDivergence(
  a: EncryptedVaultPayload,
  b: EncryptedVaultPayload
): boolean {
  if (a.vaultId !== b.vaultId) return true;
  if (a.kdf.salt !== b.kdf.salt) return true;
  if (a.kdf.iterations !== b.kdf.iterations) return true;
  if (
    a.encryptedMetadata.iv !== b.encryptedMetadata.iv ||
    a.encryptedMetadata.ciphertext !== b.encryptedMetadata.ciphertext
  ) {
    return true;
  }
  if (a.encryptedRecords.length !== b.encryptedRecords.length) return true;

  const mapA = new Map(
    a.encryptedRecords.map((r) => [r.id, `${r.iv}:${r.ciphertext}`])
  );
  for (const recB of b.encryptedRecords) {
    const sigA = mapA.get(recB.id);
    if (!sigA || sigA !== `${recB.iv}:${recB.ciphertext}`) {
      return true;
    }
  }
  return false;
}

/**
 * Executes a fetch request with an explicit AbortController timeout and classifies errors cleanly.
 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

function classifyHttpError(
  status: number
): { category: SyncErrorCategory; retryable: boolean; summary: string } {
  if (status === 401 || status === 403) {
    return {
      category: 'unauthorized',
      retryable: false,
      summary: `鉴权被拒绝 (HTTP ${status})：请检查 API Token 是否正确且未过期`,
    };
  }
  if (status === 409) {
    return {
      category: 'conflict',
      retryable: false,
      summary: '检测到云端版本冲突 (HTTP 409)',
    };
  }
  if (status === 429) {
    return {
      category: 'rate_limited',
      retryable: true,
      summary: '请求过于频繁触发限流保护 (HTTP 429)，请稍后重试',
    };
  }
  if (status === 503) {
    return {
      category: 'unconfigured_server',
      retryable: false,
      summary:
        'Worker 服务端尚未完成配置 (HTTP 503)：请检查 API_TOKEN Secret 或 VAULT_DO 绑定',
    };
  }
  if (status >= 500) {
    return {
      category: 'server_error',
      retryable: true,
      summary: `Cloudflare Worker 服务端暂时异常 (HTTP ${status})`,
    };
  }
  return {
    category: 'validation_error',
    retryable: false,
    summary: `请求被拒绝 (HTTP ${status})`,
  };
}

function classifyNetworkCatchError(
  err: unknown,
  timeoutMs: number
): { category: SyncErrorCategory; retryable: boolean; summary: string } {
  if (err instanceof Error && err.name === 'AbortError') {
    return {
      category: 'timeout',
      retryable: true,
      summary: `连接超时 (${Math.round(
        timeoutMs / 1000
      )}s)：跨境链路拥塞或目标 Worker 节点响应过慢`,
    };
  }
  return {
    category: 'network_unreachable',
    retryable: true,
    summary:
      '无法连接目标 Cloudflare Worker（DNS 解析失败、TLS 握手阻断或当前处于离线状态）',
  };
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class SyncService {
  /**
   * Test helpers for deterministic verification of IndexedDB atomic transactions and failure modes.
   */
  static __setIndexedDBBackendForTests(
    adapter: PluggableIdbAdapter | null
  ): void {
    customIdbAdapterForTests = adapter;
  }

  static __setSimulatePersistenceFailureForTests(
    failure: {
      code: 'QUOTA_EXCEEDED' | 'IDB_TRANSACTION_FAILED' | 'STORAGE_WRITE_FAILED';
      message: string;
    } | null
  ): void {
    simulatedPersistenceFailureForTests = failure;
  }

  static getLastPersistenceWarning(): LocalStoragePersistenceWarning | null {
    return lastPersistenceWarning;
  }

  static clearPersistenceWarning(): void {
    lastPersistenceWarning = null;
  }

  static async flushPendingPersistence(): Promise<void> {
    await pendingIdbWritePromise;
  }

  /**
   * Authoritative Startup Hydration & Reconciliation between IndexedDB and localStorage.
   * Ensures:
   * 1. Vault resets (`resetEpoch`) are honored across both stores and never resurrect deleted vaults.
   * 2. If IndexedDB and localStorage diverge, the state with the higher `writeSequence`,
   *    higher `lastSyncedRevision`, or newer `updatedAt` wins and is atomically synced to both.
   */
  static async hydrateFromIndexedDB(): Promise<EncryptedVaultPayload | null> {
    purgeLegacyV1StorageKeys();
    await pendingIdbWritePromise.catch(() => undefined);

    const adapter = getActiveIdbAdapter();
    const idbSnapshot = await adapter.readSnapshot();
    const lsMeta = readLocalStorageMeta();
    const lsVault = this.getLocalVault();
    const lsSync = this.getLocalSyncState();

    const idbResetEpoch = idbSnapshot?.meta.resetEpoch ?? 0;
    const effectiveResetEpoch = Math.max(
      memoryResetEpoch,
      lsMeta.resetEpoch,
      idbResetEpoch
    );
    memoryResetEpoch = effectiveResetEpoch;

    // If IndexedDB recorded a newer reset epoch than localStorage, purge stale localStorage mirror
    if (idbResetEpoch > lsMeta.resetEpoch && !idbSnapshot?.vault) {
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(VAULT_STORAGE_KEY);
        window.localStorage.removeItem(SYNC_STATE_STORAGE_KEY);
      }
      writeLocalStorageMeta({
        writeSequence: Math.max(
          lsMeta.writeSequence,
          idbSnapshot?.meta.writeSequence ?? 0
        ),
        resetEpoch: effectiveResetEpoch,
        updatedAt: Date.now(),
      });
      return null;
    }

    // If localStorage recorded a newer reset epoch than IndexedDB (e.g. reset right before reload), clear IndexedDB
    if (lsMeta.resetEpoch > idbResetEpoch && !lsVault) {
      const nextMeta: StorageMetaState = {
        writeSequence: Math.max(
          lsMeta.writeSequence,
          idbSnapshot?.meta.writeSequence ?? 0
        ),
        resetEpoch: effectiveResetEpoch,
        updatedAt: Date.now(),
      };
      writeLocalStorageMeta(nextMeta);
      await adapter.clearVaultAtomically(nextMeta).catch(() => undefined);
      return null;
    }

    let validIdbVault: EncryptedVaultPayload | null = null;
    if (idbSnapshot?.vault) {
      const check = validateV2VaultEnvelopeStructure(idbSnapshot.vault);
      if (check.valid && check.payload) {
        validIdbVault = check.payload;
      }
    }

    const idbWriteSeq =
      idbSnapshot?.meta.writeSequence ??
      idbSnapshot?.syncState?.writeSequence ??
      0;
    const lsWriteSeq = lsMeta.writeSequence || lsSync.writeSequence || 0;
    memoryWriteSequence = Math.max(memoryWriteSequence, idbWriteSeq, lsWriteSeq);

    // Case A: Both IndexedDB and localStorage have valid vaults -> reconcile deterministically
    if (validIdbVault && lsVault) {
      const idbRev = idbSnapshot?.syncState?.lastSyncedRevision ?? 0;
      const lsRev = lsSync.lastSyncedRevision ?? 0;
      const idbTime = new Date(validIdbVault.updatedAt).getTime() || 0;
      const lsTime = new Date(lsVault.updatedAt).getTime() || 0;

      // Prefer the record with strictly newer writeSequence, or newer revision, or newer timestamp.
      // When equal, IndexedDB is authoritative.
      const idbWins =
        idbWriteSeq > lsWriteSeq ||
        (idbWriteSeq === lsWriteSeq && idbRev > lsRev) ||
        (idbWriteSeq === lsWriteSeq && idbRev === lsRev && idbTime >= lsTime);

      const winningVault = idbWins ? validIdbVault : lsVault;
      const winningSync: LocalSyncStateV2 = idbWins
        ? {
            ...lsSync,
            ...(idbSnapshot?.syncState ?? {}),
            vaultId: winningVault.vaultId,
            writeSequence: memoryWriteSequence,
          }
        : {
            ...lsSync,
            vaultId: winningVault.vaultId,
            writeSequence: memoryWriteSequence,
          };

      if (typeof window !== 'undefined') {
        window.localStorage.setItem(
          VAULT_STORAGE_KEY,
          JSON.stringify(winningVault)
        );
        window.localStorage.setItem(
          SYNC_STATE_STORAGE_KEY,
          JSON.stringify(winningSync)
        );
      }
      const nextMeta: StorageMetaState = {
        writeSequence: memoryWriteSequence,
        resetEpoch: effectiveResetEpoch,
        updatedAt: Date.now(),
      };
      writeLocalStorageMeta(nextMeta);
      await adapter
        .writeSnapshotAtomically({
          vault: winningVault,
          syncState: winningSync,
          meta: nextMeta,
        })
        .catch(() => undefined);

      return winningVault;
    }

    // Case B: Only IndexedDB has a valid vault (e.g. localStorage was evicted by browser)
    if (validIdbVault && !lsVault) {
      const restoredSync: LocalSyncStateV2 = idbSnapshot?.syncState ?? {
        vaultId: validIdbVault.vaultId,
        lastSyncedRevision: 0,
        pendingMutationId: null,
        pendingMutationPayloadHash: null,
        writeSequence: memoryWriteSequence,
        dirtySince: null,
        lastSyncedAt: null,
        conflictState: null,
        pendingPasswordRotationPurge: false,
      };
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(
          VAULT_STORAGE_KEY,
          JSON.stringify(validIdbVault)
        );
        window.localStorage.setItem(
          SYNC_STATE_STORAGE_KEY,
          JSON.stringify(restoredSync)
        );
      }
      writeLocalStorageMeta({
        writeSequence: memoryWriteSequence,
        resetEpoch: effectiveResetEpoch,
        updatedAt: Date.now(),
      });
      return validIdbVault;
    }

    // Case C: Only localStorage has a valid vault (e.g. legacy V2 data or before first IDB flush) -> migrate to IndexedDB
    if (!validIdbVault && lsVault) {
      const nextSeq = Math.max(1, memoryWriteSequence);
      memoryWriteSequence = nextSeq;
      const syncedState: LocalSyncStateV2 = {
        ...lsSync,
        vaultId: lsVault.vaultId,
        writeSequence: nextSeq,
      };
      const nextMeta: StorageMetaState = {
        writeSequence: nextSeq,
        resetEpoch: effectiveResetEpoch,
        updatedAt: Date.now(),
      };
      writeLocalStorageMeta(nextMeta);
      await adapter
        .writeSnapshotAtomically({
          vault: lsVault,
          syncState: syncedState,
          meta: nextMeta,
        })
        .catch(() => undefined);
      return lsVault;
    }

    return null;
  }

  static getLocalVault(): EncryptedVaultPayload | null {
    if (typeof window === 'undefined') return null;
    purgeLegacyV1StorageKeys();
    const raw = window.localStorage.getItem(VAULT_STORAGE_KEY);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      const validation = validateV2VaultEnvelopeStructure(parsed);
      if (!validation.valid || !validation.payload) return null;
      return validation.payload;
    } catch {
      return null;
    }
  }

  static getLocalSyncState(): LocalSyncStateV2 {
    const localVault = this.getLocalVault();
    const defaultVaultId = localVault?.vaultId || '';
    if (typeof window === 'undefined') {
      return {
        vaultId: defaultVaultId,
        lastSyncedRevision: 0,
        pendingMutationId: null,
        pendingMutationPayloadHash: null,
        writeSequence: memoryWriteSequence,
        dirtySince: null,
        lastSyncedAt: null,
        conflictState: null,
        pendingPasswordRotationPurge: false,
      };
    }

    try {
      const raw = window.localStorage.getItem(SYNC_STATE_STORAGE_KEY);
      if (!raw) {
        return {
          vaultId: defaultVaultId,
          lastSyncedRevision: 0,
          pendingMutationId: null,
          pendingMutationPayloadHash: null,
          writeSequence: memoryWriteSequence,
          dirtySince: null,
          lastSyncedAt: null,
          conflictState: null,
          pendingPasswordRotationPurge: false,
        };
      }
      const parsed = JSON.parse(raw) as Partial<LocalSyncStateV2>;
      if (
        defaultVaultId &&
        parsed.vaultId &&
        parsed.vaultId !== defaultVaultId
      ) {
        return {
          vaultId: defaultVaultId,
          lastSyncedRevision: 0,
          pendingMutationId: null,
          pendingMutationPayloadHash: null,
          writeSequence: memoryWriteSequence,
          dirtySince: null,
          lastSyncedAt: null,
          conflictState: null,
          pendingPasswordRotationPurge: false,
        };
      }
      return {
        vaultId: parsed.vaultId || defaultVaultId,
        lastSyncedRevision:
          typeof parsed.lastSyncedRevision === 'number' &&
          parsed.lastSyncedRevision >= 0
            ? parsed.lastSyncedRevision
            : 0,
        pendingMutationId:
          typeof parsed.pendingMutationId === 'string'
            ? parsed.pendingMutationId
            : null,
        pendingMutationPayloadHash:
          typeof parsed.pendingMutationPayloadHash === 'string'
            ? parsed.pendingMutationPayloadHash
            : null,
        writeSequence:
          typeof parsed.writeSequence === 'number'
            ? parsed.writeSequence
            : memoryWriteSequence,
        dirtySince:
          typeof parsed.dirtySince === 'number' ? parsed.dirtySince : null,
        lastSyncedAt:
          typeof parsed.lastSyncedAt === 'number' ? parsed.lastSyncedAt : null,
        conflictState: parsed.conflictState || null,
        pendingPasswordRotationPurge: Boolean(
          parsed.pendingPasswordRotationPurge
        ),
        lastErrorCategory: parsed.lastErrorCategory,
      };
    } catch {
      return {
        vaultId: defaultVaultId,
        lastSyncedRevision: 0,
        pendingMutationId: null,
        pendingMutationPayloadHash: null,
        writeSequence: memoryWriteSequence,
        dirtySince: null,
        lastSyncedAt: null,
        conflictState: null,
        pendingPasswordRotationPurge: false,
      };
    }
  }

  static saveLocalSyncState(state: LocalSyncStateV2): void {
    if (typeof window === 'undefined') return;
    const meta = readLocalStorageMeta();
    const nextSeq = Math.max(meta.writeSequence, state.writeSequence ?? 0) + 1;
    const enrichedState: LocalSyncStateV2 = {
      ...state,
      writeSequence: nextSeq,
    };
    const nextMeta: StorageMetaState = {
      writeSequence: nextSeq,
      resetEpoch: meta.resetEpoch,
      updatedAt: Date.now(),
    };

    window.localStorage.setItem(
      SYNC_STATE_STORAGE_KEY,
      JSON.stringify(enrichedState)
    );
    writeLocalStorageMeta(nextMeta);

    const currentVault = this.getLocalVault();
    const adapter = getActiveIdbAdapter();
    pendingIdbWritePromise = pendingIdbWritePromise
      .catch(() => undefined)
      .then(() =>
        adapter.writeSnapshotAtomically({
          vault: currentVault,
          syncState: enrichedState,
          meta: nextMeta,
        })
      )
      .catch(() => undefined);

    broadcastCrossTabUpdate({
      type: 'SYNC_STATE_UPDATED',
      vaultId: enrichedState.vaultId,
      updatedAt: new Date().toISOString(),
      revision: enrichedState.lastSyncedRevision,
      writeSequence: nextSeq,
      resetEpoch: nextMeta.resetEpoch,
    });
  }

  static computeSyncStatus(
    config: CloudflareSyncConfig = this.getSyncConfig(),
    isOnline: boolean = typeof navigator !== 'undefined'
      ? navigator.onLine
      : true
  ): SyncStatus {
    const syncState = this.getLocalSyncState();
    if (syncState.conflictState) {
      return 'conflict';
    }
    const hasCloudConfigured = Boolean(
      config.workerUrl.trim() && config.apiToken.trim()
    );
    // Note: navigator.onLine is used only as a non-blocking visual status hint when idle
    if (!isOnline && (syncState.dirtySince !== null || hasCloudConfigured)) {
      return 'offline';
    }
    if (
      syncState.dirtySince !== null &&
      (hasCloudConfigured || syncState.lastSyncedRevision > 0)
    ) {
      return 'sync_pending';
    }
    if (syncState.lastSyncedRevision > 0 && syncState.dirtySince === null) {
      return 'cloud_synced';
    }
    return 'local_saved';
  }

  /**
   * Synchronous local vault save that updates the localStorage mirror immediately
   * and queues an atomic single-transaction IndexedDB commit (`vault_store` + `sync_state_store`).
   * For callers that want to await `tx.oncomplete` and verify IndexedDB durability, use `saveLocalVaultAsync`.
   */
  static saveLocalVault(
    payload: EncryptedVaultPayload,
    options: {
      markDirty?: boolean;
      syncedRevision?: number;
      pendingPasswordRotationPurge?: boolean;
    } = {}
  ): void {
    if (typeof window === 'undefined') return;
    if (simulatedPersistenceFailureForTests) {
      const warning: LocalStoragePersistenceWarning = {
        code: simulatedPersistenceFailureForTests.code,
        message: simulatedPersistenceFailureForTests.message,
        occurredAt: Date.now(),
      };
      lastPersistenceWarning = warning;
      throw new Error(warning.message);
    }

    const validation = validateV2VaultEnvelopeStructure(payload);
    if (!validation.valid || !validation.payload) {
      throw new Error(
        `拒绝写入非法的 V2 密码库结构：${validation.reason || '结构校验未通过'}`
      );
    }

    const serialized = JSON.stringify(validation.payload);
    const byteLength = new TextEncoder().encode(serialized).byteLength;
    if (byteLength > MAX_VAULT_PAYLOAD_BYTES) {
      throw new Error('加密密码库体积超过 1MB 安全上限，拒绝写入');
    }

    const currentSync = this.getLocalSyncState();
    const meta = readLocalStorageMeta();
    const nextSeq = meta.writeSequence + 1;
    const markDirty = options.markDirty ?? true;
    const payloadHash = computePayloadContentSignature(validation.payload);

    // Bind pendingMutationId to the exact payload hash:
    // - If payload is identical to the pending snapshot, preserve the same mutationId for idempotent retry.
    // - If payload changed, generate a fresh mutationId so the new snapshot never collides with an old mutationId.
    let nextMutationId: string | null = null;
    let nextMutationHash: string | null = null;
    if (markDirty) {
      if (
        currentSync.pendingMutationId &&
        currentSync.pendingMutationPayloadHash === payloadHash
      ) {
        nextMutationId = currentSync.pendingMutationId;
      } else {
        nextMutationId = generateVaultId();
      }
      nextMutationHash = payloadHash;
    }

    const updatedSync: LocalSyncStateV2 = {
      vaultId: validation.payload.vaultId,
      lastSyncedRevision:
        typeof options.syncedRevision === 'number'
          ? options.syncedRevision
          : currentSync.vaultId === validation.payload.vaultId
          ? currentSync.lastSyncedRevision
          : 0,
      pendingMutationId: nextMutationId,
      pendingMutationPayloadHash: nextMutationHash,
      writeSequence: nextSeq,
      dirtySince: markDirty ? currentSync.dirtySince || Date.now() : null,
      lastSyncedAt: !markDirty ? Date.now() : currentSync.lastSyncedAt,
      conflictState: !markDirty ? null : currentSync.conflictState,
      pendingPasswordRotationPurge:
        options.pendingPasswordRotationPurge !== undefined
          ? options.pendingPasswordRotationPurge
          : currentSync.pendingPasswordRotationPurge,
    };

    const nextMeta: StorageMetaState = {
      writeSequence: nextSeq,
      resetEpoch: meta.resetEpoch,
      updatedAt: Date.now(),
    };

    try {
      window.localStorage.setItem(VAULT_STORAGE_KEY, serialized);
      window.localStorage.setItem(
        SYNC_STATE_STORAGE_KEY,
        JSON.stringify(updatedSync)
      );
      writeLocalStorageMeta(nextMeta);
      lastPersistenceWarning = null;
    } catch (err) {
      const isQuota =
        err instanceof Error &&
        (err.name === 'QuotaExceededError' ||
          err.message.toLowerCase().includes('quota'));
      const warning: LocalStoragePersistenceWarning = {
        code: isQuota ? 'QUOTA_EXCEEDED' : 'STORAGE_WRITE_FAILED',
        message: isQuota
          ? '浏览器本地存储空间已满 (QuotaExceededError)，当前修改仍保留在内存中，请立即导出加密备份'
          : '写入浏览器本地存储失败，当前修改仍保留在内存中，请立即导出加密备份',
        occurredAt: Date.now(),
      };
      lastPersistenceWarning = warning;
      throw new Error(warning.message);
    }

    const validPayload = validation.payload;
    const adapter = getActiveIdbAdapter();
    pendingIdbWritePromise = pendingIdbWritePromise
      .catch(() => undefined)
      .then(async () => {
        await adapter.writeSnapshotAtomically({
          vault: validPayload,
          syncState: updatedSync,
          meta: nextMeta,
        });
      })
      .catch((err) => {
        const isQuota =
          err instanceof Error &&
          (err.name === 'QuotaExceededError' ||
            err.message.toLowerCase().includes('quota'));
        lastPersistenceWarning = {
          code: isQuota ? 'QUOTA_EXCEEDED' : 'IDB_TRANSACTION_FAILED',
          message: isQuota
            ? 'IndexedDB 存储配额不足 (QuotaExceededError)，请导出加密 JSON 备份以防数据丢失'
            : `IndexedDB 事务提交异常 (${
                err instanceof Error ? err.message : '未知错误'
              })，建议立即导出加密备份`,
          occurredAt: Date.now(),
        };
        throw err;
      });

    broadcastCrossTabUpdate({
      type: 'VAULT_UPDATED',
      vaultId: validation.payload.vaultId,
      updatedAt: validation.payload.updatedAt,
      revision: updatedSync.lastSyncedRevision,
      writeSequence: nextSeq,
      resetEpoch: nextMeta.resetEpoch,
    });
  }

  /**
   * Awaits the full IndexedDB `tx.oncomplete` transaction before resolving.
   * Rejects with a structured error if either localStorage or IndexedDB transaction fails or aborts.
   */
  static async saveLocalVaultAsync(
    payload: EncryptedVaultPayload,
    options: {
      markDirty?: boolean;
      syncedRevision?: number;
      pendingPasswordRotationPurge?: boolean;
    } = {}
  ): Promise<{ writeSequence: number }> {
    this.saveLocalVault(payload, options);
    await pendingIdbWritePromise;
    return { writeSequence: memoryWriteSequence };
  }

  /**
   * Atomically clears all local vault and sync state copies across localStorage and IndexedDB,
   * and increments `resetEpoch` so any in-flight async operations cannot resurrect the deleted vault.
   * Never calls `localStorage.clear()`.
   */
  static clearLocalVault(): void {
    if (typeof window === 'undefined') return;
    const meta = readLocalStorageMeta();
    const nextResetEpoch = meta.resetEpoch + 1;
    const nextSeq = meta.writeSequence + 1;
    const nextMeta: StorageMetaState = {
      writeSequence: nextSeq,
      resetEpoch: nextResetEpoch,
      updatedAt: Date.now(),
    };

    window.localStorage.removeItem(VAULT_STORAGE_KEY);
    window.localStorage.removeItem(SYNC_STATE_STORAGE_KEY);
    writeLocalStorageMeta(nextMeta);

    const adapter = getActiveIdbAdapter();
    pendingIdbWritePromise = pendingIdbWritePromise
      .catch(() => undefined)
      .then(() => adapter.clearVaultAtomically(nextMeta))
      .catch(() => undefined);

    broadcastCrossTabUpdate({
      type: 'VAULT_RESET',
      vaultId: '',
      updatedAt: new Date().toISOString(),
      revision: 0,
      writeSequence: nextSeq,
      resetEpoch: nextResetEpoch,
    });
  }

  static async clearLocalVaultAsync(): Promise<void> {
    this.clearLocalVault();
    await pendingIdbWritePromise;
  }

  static saveRollbackBackup(payload: EncryptedVaultPayload): void {
    if (typeof window === 'undefined') return;
    const validation = validateV2VaultEnvelopeStructure(payload);
    if (validation.valid && validation.payload) {
      window.localStorage.setItem(
        VAULT_ROLLBACK_BACKUP_KEY,
        JSON.stringify(validation.payload)
      );
    }
  }

  static getRollbackBackup(): EncryptedVaultPayload | null {
    if (typeof window === 'undefined') return null;
    const raw = window.localStorage.getItem(VAULT_ROLLBACK_BACKUP_KEY);
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      const validation = validateV2VaultEnvelopeStructure(parsed);
      return validation.valid && validation.payload ? validation.payload : null;
    } catch {
      return null;
    }
  }

  static restoreFromRollbackBackup(): EncryptedVaultPayload | null {
    const backup = this.getRollbackBackup();
    if (!backup) return null;
    this.saveLocalVault(backup, { markDirty: true });
    return backup;
  }

  static getRawStorageCiphertextJson(): string {
    if (typeof window === 'undefined') return '{}';
    const raw = window.localStorage.getItem(VAULT_STORAGE_KEY);
    if (!raw) return '// 当前本地尚未初始化 V2 密码库密文';
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }

  static serializeEncryptedVaultForExport(
    payload?: EncryptedVaultPayload | null
  ): string {
    const target = payload ?? this.getLocalVault();
    if (!target) {
      throw new Error('当前无可导出的加密密码库数据');
    }
    const validation = validateV2VaultEnvelopeStructure(target);
    if (!validation.valid || !validation.payload) {
      throw new Error(`导出数据校验失败：${validation.reason}`);
    }
    return JSON.stringify(validation.payload, null, 2);
  }

  static getBackupFilename(): string {
    const dateStr = new Date().toISOString().slice(0, 10);
    return `aegis-vault-v2-encrypted-${dateStr}.json`;
  }

  /**
   * Reads sync config while enforcing session-only token storage by default.
   */
  static getSyncConfig(): CloudflareSyncConfig {
    if (typeof window === 'undefined') {
      return {
        workerUrl: '',
        apiToken: '',
        rememberToken: false,
        autoSync: false,
        lastSyncedAt: null,
      };
    }

    const raw = window.localStorage.getItem(SYNC_CONFIG_STORAGE_KEY);
    let parsed: Partial<CloudflareSyncConfig> = {};
    if (raw) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = {};
      }
    }

    const rememberToken = Boolean(parsed.rememberToken);
    let sessionToken = '';
    try {
      sessionToken = window.sessionStorage.getItem(SYNC_TOKEN_SESSION_KEY) ?? '';
    } catch {
      sessionToken = '';
    }

    const resolvedToken =
      runtimeApiTokenMemory ||
      sessionToken ||
      (rememberToken && typeof parsed.apiToken === 'string'
        ? parsed.apiToken
        : '');

    if (resolvedToken && !runtimeApiTokenMemory) {
      runtimeApiTokenMemory = resolvedToken;
    }

    return {
      workerUrl: typeof parsed.workerUrl === 'string' ? parsed.workerUrl : '',
      apiToken: resolvedToken,
      rememberToken,
      autoSync: Boolean(parsed.autoSync),
      lastSyncedAt:
        typeof parsed.lastSyncedAt === 'number' ? parsed.lastSyncedAt : null,
    };
  }

  static saveSyncConfig(config: CloudflareSyncConfig): void {
    if (typeof window === 'undefined') return;
    const cleanToken = config.apiToken.trim();
    const rememberToken = Boolean(config.rememberToken);

    runtimeApiTokenMemory = cleanToken;

    try {
      if (cleanToken) {
        window.sessionStorage.setItem(SYNC_TOKEN_SESSION_KEY, cleanToken);
      } else {
        window.sessionStorage.removeItem(SYNC_TOKEN_SESSION_KEY);
      }
    } catch {
      // Ignore if sessionStorage is disabled
    }

    const persistedConfig: CloudflareSyncConfig = {
      workerUrl: config.workerUrl.trim(),
      apiToken: rememberToken ? cleanToken : '',
      rememberToken,
      autoSync: Boolean(config.autoSync),
      lastSyncedAt: config.lastSyncedAt,
    };

    window.localStorage.setItem(
      SYNC_CONFIG_STORAGE_KEY,
      JSON.stringify(persistedConfig)
    );
  }

  static clearApiToken(): CloudflareSyncConfig {
    runtimeApiTokenMemory = '';
    if (typeof window !== 'undefined') {
      try {
        window.sessionStorage.removeItem(SYNC_TOKEN_SESSION_KEY);
      } catch {
        // ignore
      }
      const current = this.getSyncConfig();
      const updated: CloudflareSyncConfig = {
        ...current,
        apiToken: '',
        rememberToken: false,
      };
      window.localStorage.setItem(
        SYNC_CONFIG_STORAGE_KEY,
        JSON.stringify(updated)
      );
      return updated;
    }
    return {
      workerUrl: '',
      apiToken: '',
      rememberToken: false,
      autoSync: false,
      lastSyncedAt: null,
    };
  }

  /**
   * Performs a fast, lightweight HTTP HEAD probe against `/api/vault` for manual connectivity testing.
   * Note: Regular `pushVault` and `pullVault` do NOT depend on this pre-probe.
   */
  static async checkWorkerConnectivity(
    config?: CloudflareSyncConfig,
    timeoutMs: number = WORKER_TIMEOUT_MS.HEAD_PROBE
  ): Promise<WorkerConnectivityProbeResult> {
    const activeConfig = config ?? this.getSyncConfig();

    let endpoint: string;
    try {
      endpoint = normalizeWorkerEndpoint(activeConfig.workerUrl);
    } catch (err) {
      return {
        reachable: false,
        latencyMs: 0,
        status: 'invalid_url',
        message: err instanceof Error ? err.message : 'Worker 地址格式无效',
      };
    }

    const cleanToken = activeConfig.apiToken.trim();
    const headers: Record<string, string> = {};
    if (cleanToken) {
      headers['Authorization'] = `Bearer ${cleanToken}`;
    }

    const startTime = Date.now();

    try {
      const response = await fetchWithTimeout(
        endpoint,
        {
          method: 'HEAD',
          headers,
        },
        timeoutMs
      );
      const latencyMs = Math.max(1, Date.now() - startTime);

      if (response.status === 401 || response.status === 403) {
        return {
          reachable: false,
          latencyMs,
          httpStatus: response.status,
          status: 'unauthorized',
          message: cleanToken
            ? 'Worker 节点在线，但拒绝了访问（HTTP 401/403）：请检查 API Token 是否正确'
            : 'Worker 节点在线，要求提供有效的 Bearer API Token 鉴权凭证',
        };
      }

      if (response.status === 503) {
        return {
          reachable: false,
          latencyMs,
          httpStatus: 503,
          status: 'unconfigured_server',
          message:
            'Worker 节点已响应 (HTTP 503)，但服务端尚未配置 API_TOKEN Secret 或 VAULT_DO 绑定',
        };
      }

      if (!response.ok) {
        return {
          reachable: false,
          latencyMs,
          httpStatus: response.status,
          status: 'http_error',
          message: `Worker 节点返回异常状态码 (HTTP ${response.status})`,
        };
      }

      const initializedHeader = response.headers.get('X-Vault-Initialized');
      const revisionHeader = response.headers.get('X-Vault-Revision');
      const vaultIdHeader = response.headers.get('X-Vault-Id') || undefined;
      const initialized = initializedHeader === 'true';
      const revision = revisionHeader ? Number(revisionHeader) : 0;

      return {
        reachable: true,
        latencyMs,
        httpStatus: response.status,
        initialized,
        revision,
        vaultId: vaultIdHeader,
        status: 'reachable',
        message: initialized
          ? `连接正常 (${latencyMs} ms) · 云端 Durable Object 版本 #${revision}`
          : `连接正常 (${latencyMs} ms) · 云端 Durable Object 尚未初始化 (Revision 0)`,
      };
    } catch (err) {
      const latencyMs = Math.max(1, Date.now() - startTime);
      if (err instanceof Error && err.name === 'AbortError') {
        return {
          reachable: false,
          latencyMs,
          status: 'timeout',
          message: `连接探测超时 (${Math.round(
            timeoutMs / 1000
          )}s)：目标 Worker 无法访问，请检查域名或网络设置`,
        };
      }
      return {
        reachable: false,
        latencyMs,
        status: 'unreachable',
        message:
          '无法连接到目标 Cloudflare Worker：请检查 URL 拼写、HTTPS 证书、CORS 或网络连接',
      };
    }
  }

  /**
   * Explicitly initializes the remote Cloud Durable Object vault at `revision = 1`
   * via `POST /api/vault/init`. Supports idempotent retry on weak networks.
   */
  static async initializeCloudVault(
    payload: EncryptedVaultPayload,
    config?: CloudflareSyncConfig,
    options: {
      timeoutMs?: number;
      maxRetries?: number;
      retryBaseDelayMs?: number;
    } = {}
  ): Promise<{
    ok: boolean;
    status: SyncStatus;
    revision?: number;
    conflict?: CloudConflictInfo;
    errorCategory?: SyncErrorCategory;
    message: string;
  }> {
    this.saveLocalVault(payload, { markDirty: true });
    const activeConfig = config ?? this.getSyncConfig();
    const endpoint = normalizeWorkerEndpoint(activeConfig.workerUrl, '/init');
    const cleanToken = activeConfig.apiToken.trim();
    if (!cleanToken) {
      throw new Error('初始化云端密码库需要配置有效的 API Token');
    }

    const syncState = this.getLocalSyncState();
    const payloadHash = computePayloadContentSignature(payload);
    const mutationId =
      syncState.pendingMutationId &&
      syncState.pendingMutationPayloadHash === payloadHash
        ? syncState.pendingMutationId
        : generateVaultId();

    if (
      syncState.pendingMutationId !== mutationId ||
      syncState.pendingMutationPayloadHash !== payloadHash
    ) {
      this.saveLocalSyncState({
        ...syncState,
        pendingMutationId: mutationId,
        pendingMutationPayloadHash: payloadHash,
      });
    }

    const timeoutMs = options.timeoutMs ?? WORKER_TIMEOUT_MS.POST_INIT;
    const maxRetries = options.maxRetries ?? 2;
    const baseDelayMs = options.retryBaseDelayMs ?? 300;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const jitter = Math.floor(Math.random() * 80);
        await sleepMs(baseDelayMs * Math.pow(2, attempt - 1) + jitter);
      }

      try {
        const response = await fetchWithTimeout(
          endpoint,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${cleanToken}`,
            },
            body: JSON.stringify({
              protocolVersion: SYNC_PROTOCOL_VERSION,
              vaultId: payload.vaultId,
              mutationId,
              vault: payload,
            }),
          },
          timeoutMs
        );

        if (response.status === 409) {
          const conflictData = await response.json().catch(() => ({}));
          const conflictInfo: CloudConflictInfo = {
            code: conflictData.code || 'ALREADY_INITIALIZED',
            message:
              conflictData.error ||
              '云端 Durable Object 已存在密码库，禁止通过初始化接口直接覆盖',
            localVaultId: payload.vaultId,
            localRevision: syncState.lastSyncedRevision,
            serverVaultId: conflictData.serverVaultId,
            serverRevision: Number(conflictData.serverRevision || 0),
            serverUpdatedAt: conflictData.serverUpdatedAt,
            serverVault: conflictData.serverVault,
            detectedAt: Date.now(),
          };
          this.saveLocalSyncState({
            ...this.getLocalSyncState(),
            conflictState: conflictInfo,
            lastErrorCategory: 'conflict',
          });
          return {
            ok: false,
            status: 'conflict',
            conflict: conflictInfo,
            errorCategory: 'conflict',
            message: conflictInfo.message,
          };
        }

        if (!response.ok) {
          const classified = classifyHttpError(response.status);
          if (classified.retryable && attempt < maxRetries) {
            continue;
          }
          this.saveLocalSyncState({
            ...this.getLocalSyncState(),
            lastErrorCategory: classified.category,
          });
          return {
            ok: false,
            status: 'failed',
            errorCategory: classified.category,
            message: `云端初始化失败：${classified.summary}（本地加密数据已安全保存在 IndexedDB）`,
          };
        }

        const data = await response.json();
        const revision = Number(data.revision || 1);
        const now = Date.now();

        // Check if user made a newer local edit while initialization was in flight
        const latestLocal = this.getLocalVault();
        const latestHash = latestLocal
          ? computePayloadContentSignature(latestLocal)
          : payloadHash;
        const hasNewerLocalEdit = latestHash !== payloadHash;

        this.saveLocalSyncState({
          vaultId: payload.vaultId,
          lastSyncedRevision: revision,
          pendingMutationId: hasNewerLocalEdit
            ? this.getLocalSyncState().pendingMutationId || generateVaultId()
            : null,
          pendingMutationPayloadHash: hasNewerLocalEdit ? latestHash : null,
          dirtySince: hasNewerLocalEdit ? Date.now() : null,
          lastSyncedAt: now,
          conflictState: null,
          pendingPasswordRotationPurge: false,
          lastErrorCategory: 'none',
        });

        this.saveSyncConfig({
          ...activeConfig,
          lastSyncedAt: now,
        });

        return {
          ok: true,
          status: hasNewerLocalEdit ? 'sync_pending' : 'cloud_synced',
          revision,
          errorCategory: 'none',
          message: hasNewerLocalEdit
            ? `已完成云端初始化 (Revision #${revision})，检测到更新的本地修改待继续同步`
            : `已完成云端 Durable Object 首次初始化 (Revision #${revision})`,
        };
      } catch (err) {
        const classified = classifyNetworkCatchError(err, timeoutMs);
        if (classified.retryable && attempt < maxRetries) {
          continue;
        }
        this.saveLocalSyncState({
          ...this.getLocalSyncState(),
          lastErrorCategory: classified.category,
        });
        return {
          ok: false,
          status: 'offline',
          errorCategory: classified.category,
          message: `${classified.summary}（本地密码库已安全保存在 IndexedDB，待网络恢复后可继续初始化云端）`,
        };
      }
    }

    return {
      ok: false,
      status: 'offline',
      errorCategory: 'network_unreachable',
      message: '网络中断，密码库已安全保存在本地，待网络恢复后可继续初始化云端',
    };
  }

  /**
   * Pushes the V2 EncryptedVaultPayload to the Cloudflare Worker Durable Object (`PUT /api/vault`).
   * - Executes `PUT /api/vault` directly WITHOUT a mandatory pre-flight `HEAD` request.
   * - Serializes concurrent calls through a single in-flight queue (`inFlightPushQueue`).
   * - Preserves payload-bound `mutationId` across weak-network retries so dropped responses succeed idempotently.
   * - Protects newer local edits made while an upload is in flight from having their `dirtySince` cleared.
   */
  static async pushVault(
    payload: EncryptedVaultPayload,
    config?: CloudflareSyncConfig,
    options: {
      allowAutoInitIfEmpty?: boolean;
      purgePreviousSnapshots?: boolean;
      timeoutMs?: number;
      maxRetries?: number;
      retryBaseDelayMs?: number;
    } = {}
  ): Promise<{
    ok: boolean;
    status: SyncStatus;
    revision?: number;
    requiresInitConfirmation?: boolean;
    conflict?: CloudConflictInfo;
    errorCategory?: SyncErrorCategory;
    idempotentReplay?: boolean;
    message: string;
  }> {
    this.saveLocalVault(payload, { markDirty: true });

    const runPush = async () => {
      const activeConfig = config ?? this.getSyncConfig();

      if (!activeConfig.workerUrl.trim()) {
        return {
          ok: true,
          status: 'local_saved' as SyncStatus,
          errorCategory: 'none' as SyncErrorCategory,
          message:
            '本地已加密保存 (IndexedDB)，当前未配置 Cloudflare Worker 云端同步',
        };
      }

      const cleanToken = activeConfig.apiToken.trim();
      if (!cleanToken) {
        return {
          ok: false,
          status: 'failed' as SyncStatus,
          errorCategory: 'unauthorized' as SyncErrorCategory,
          message:
            '本地已加密保存 (IndexedDB) · 云端同步未执行：缺少 Worker API Token 凭证',
        };
      }

      let endpoint: string;
      try {
        endpoint = normalizeWorkerEndpoint(activeConfig.workerUrl);
      } catch (err) {
        return {
          ok: false,
          status: 'failed' as SyncStatus,
          errorCategory: 'validation_error' as SyncErrorCategory,
          message: `${
            err instanceof Error ? err.message : 'Worker URL 无效'
          }（本地已加密保存在 IndexedDB）`,
        };
      }

      const syncState = this.getLocalSyncState();
      const targetPayload = this.getLocalVault() ?? payload;
      const snapshotHash = computePayloadContentSignature(targetPayload);

      // If local has never synced (lastSyncedRevision === 0):
      // - If allowAutoInitIfEmpty is true, execute POST /api/vault/init directly.
      // - Otherwise, check remote state via GET /api/vault: if empty, require init confirmation; if already initialized, report conflict.
      if (syncState.lastSyncedRevision === 0) {
        if (options.allowAutoInitIfEmpty) {
          return this.initializeCloudVault(targetPayload, activeConfig, {
            timeoutMs: options.timeoutMs,
            maxRetries: options.maxRetries,
            retryBaseDelayMs: options.retryBaseDelayMs,
          });
        }

        try {
          const pulled = await this.pullVault(activeConfig, {
            timeoutMs: options.timeoutMs,
            maxRetries: options.maxRetries,
            retryBaseDelayMs: options.retryBaseDelayMs,
          });
          if (!pulled.initialized || pulled.revision === 0) {
            return {
              ok: false,
              status: 'sync_pending' as SyncStatus,
              requiresInitConfirmation: true,
              errorCategory: 'none' as SyncErrorCategory,
              message:
                '检测到云端 Durable Object 尚未初始化 (Revision 0)。请在云端同步窗口确认首次初始化上传。',
            };
          }

          const conflictInfo: CloudConflictInfo = {
            code:
              pulled.payload && pulled.payload.vaultId !== targetPayload.vaultId
                ? 'VAULT_ID_MISMATCH'
                : 'REVISION_CONFLICT',
            message:
              pulled.payload && pulled.payload.vaultId !== targetPayload.vaultId
                ? `云端已存在另一个独立密码库 (Vault ID: ${pulled.payload.vaultId.slice(
                    0,
                    8
                  )}…)，已阻止直接覆盖`
                : `云端已存在版本 #${pulled.revision}，而本地尚未建立同步基线，请先对比或选择处理方式`,
            localVaultId: targetPayload.vaultId,
            localRevision: 0,
            serverVaultId: pulled.payload?.vaultId,
            serverRevision: pulled.revision,
            serverUpdatedAt: pulled.payload?.updatedAt,
            serverVault: pulled.payload || undefined,
            detectedAt: Date.now(),
          };
          this.saveLocalSyncState({
            ...syncState,
            conflictState: conflictInfo,
            lastErrorCategory: 'conflict',
          });
          return {
            ok: false,
            status: 'conflict' as SyncStatus,
            conflict: conflictInfo,
            errorCategory: 'conflict' as SyncErrorCategory,
            message: conflictInfo.message,
          };
        } catch (err) {
          const classified = classifyNetworkCatchError(
            err,
            options.timeoutMs ?? WORKER_TIMEOUT_MS.GET_VAULT
          );
          return {
            ok: false,
            status: 'offline' as SyncStatus,
            errorCategory: classified.category,
            message: `本地已加密保存 (IndexedDB) · ${classified.summary}`,
          };
        }
      }

      // Ensure pendingMutationId is deterministically bound to snapshotHash
      const mutationId =
        syncState.pendingMutationId &&
        syncState.pendingMutationPayloadHash === snapshotHash
          ? syncState.pendingMutationId
          : generateVaultId();

      if (
        syncState.pendingMutationId !== mutationId ||
        syncState.pendingMutationPayloadHash !== snapshotHash
      ) {
        this.saveLocalSyncState({
          ...syncState,
          pendingMutationId: mutationId,
          pendingMutationPayloadHash: snapshotHash,
        });
      }

      const purgeSnapshots = Boolean(
        options.purgePreviousSnapshots ??
          syncState.pendingPasswordRotationPurge
      );
      const timeoutMs = options.timeoutMs ?? WORKER_TIMEOUT_MS.PUT_VAULT;
      const maxRetries = options.maxRetries ?? 2;
      const baseDelayMs = options.retryBaseDelayMs ?? 300;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        if (attempt > 0) {
          const jitter = Math.floor(Math.random() * 80);
          await sleepMs(baseDelayMs * Math.pow(2, attempt - 1) + jitter);
        }

        try {
          const response = await fetchWithTimeout(
            endpoint,
            {
              method: 'PUT',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${cleanToken}`,
              },
              body: JSON.stringify({
                protocolVersion: SYNC_PROTOCOL_VERSION,
                vaultId: targetPayload.vaultId,
                expectedRevision: syncState.lastSyncedRevision,
                mutationId,
                vault: targetPayload,
                purgePreviousSnapshots: purgeSnapshots,
              }),
            },
            timeoutMs
          );

          if (response.status === 409) {
            const conflictData = await response.json().catch(() => ({}));
            const conflictCode = conflictData.code || 'REVISION_CONFLICT';

            // Remote Durable Object is uninitialized (Revision 0):
            if (
              conflictCode === 'VAULT_NOT_INITIALIZED' ||
              (Number(conflictData.serverRevision || 0) === 0 &&
                !conflictData.serverVaultId)
            ) {
              if (options.allowAutoInitIfEmpty) {
                return this.initializeCloudVault(targetPayload, activeConfig, {
                  timeoutMs: options.timeoutMs,
                  maxRetries: options.maxRetries,
                  retryBaseDelayMs: options.retryBaseDelayMs,
                });
              }
              return {
                ok: false,
                status: 'sync_pending' as SyncStatus,
                requiresInitConfirmation: true,
                errorCategory: 'none' as SyncErrorCategory,
                message:
                  '检测到云端 Durable Object 尚未初始化 (Revision 0)。请在云端同步窗口确认首次初始化上传。',
              };
            }

            const conflictInfo: CloudConflictInfo = {
              code: conflictCode,
              message:
                conflictCode === 'VAULT_ID_MISMATCH'
                  ? `云端已存在另一个独立密码库 (Vault ID: ${String(
                      conflictData.serverVaultId || ''
                    ).slice(0, 8)}…)，已阻止直接覆盖`
                  : conflictData.error ||
                    `云端版本冲突：本地基线版本为 #${syncState.lastSyncedRevision}，云端当前版本为 #${conflictData.serverRevision}`,
              localVaultId: targetPayload.vaultId,
              localRevision: syncState.lastSyncedRevision,
              serverVaultId: conflictData.serverVaultId,
              serverRevision: Number(conflictData.serverRevision || 0),
              serverUpdatedAt: conflictData.serverUpdatedAt,
              serverVault: conflictData.serverVault,
              detectedAt: Date.now(),
            };
            this.saveLocalSyncState({
              ...this.getLocalSyncState(),
              conflictState: conflictInfo,
              lastErrorCategory: 'conflict',
            });
            return {
              ok: false,
              status: 'conflict' as SyncStatus,
              conflict: conflictInfo,
              errorCategory: 'conflict' as SyncErrorCategory,
              message: conflictInfo.message,
            };
          }

          if (!response.ok) {
            const classified = classifyHttpError(response.status);
            if (classified.retryable && attempt < maxRetries) {
              continue;
            }
            this.saveLocalSyncState({
              ...this.getLocalSyncState(),
              lastErrorCategory: classified.category,
            });
            return {
              ok: false,
              status: 'failed' as SyncStatus,
              errorCategory: classified.category,
              message: `本地已加密保存 (IndexedDB) · 云端同步失败：${classified.summary}`,
            };
          }

          const data = await response.json();
          const newRevision = Number(
            data.revision || syncState.lastSyncedRevision + 1
          );
          const idempotentReplay = Boolean(data.idempotentReplay);
          const now = Date.now();

          // Check whether the user modified local records while this PUT request was in flight!
          const currentLocalAfterPush = this.getLocalVault();
          const currentHashAfterPush = currentLocalAfterPush
            ? computePayloadContentSignature(currentLocalAfterPush)
            : snapshotHash;
          const hasNewerLocalModification =
            currentHashAfterPush !== snapshotHash;

          if (hasNewerLocalModification) {
            const latestSync = this.getLocalSyncState();
            const nextMutId =
              latestSync.pendingMutationId &&
              latestSync.pendingMutationId !== mutationId
                ? latestSync.pendingMutationId
                : generateVaultId();
            this.saveLocalSyncState({
              vaultId: targetPayload.vaultId,
              lastSyncedRevision: newRevision,
              pendingMutationId: nextMutId,
              pendingMutationPayloadHash: currentHashAfterPush,
              dirtySince: latestSync.dirtySince || now,
              lastSyncedAt: now,
              conflictState: null,
              pendingPasswordRotationPurge:
                latestSync.pendingPasswordRotationPurge,
              lastErrorCategory: 'none',
            });
            this.saveSyncConfig({
              ...activeConfig,
              lastSyncedAt: now,
            });
            return {
              ok: true,
              status: 'sync_pending' as SyncStatus,
              revision: newRevision,
              idempotentReplay,
              errorCategory: 'none' as SyncErrorCategory,
              message: `版本 #${newRevision} 已同步，检测到同步期间有新的本地修改，已保留在待同步队列`,
            };
          }

          this.saveLocalSyncState({
            vaultId: targetPayload.vaultId,
            lastSyncedRevision: newRevision,
            pendingMutationId: null,
            pendingMutationPayloadHash: null,
            dirtySince: null,
            lastSyncedAt: now,
            conflictState: null,
            pendingPasswordRotationPurge: false,
            lastErrorCategory: 'none',
          });

          this.saveSyncConfig({
            ...activeConfig,
            lastSyncedAt: now,
          });

          return {
            ok: true,
            status: 'cloud_synced' as SyncStatus,
            revision: newRevision,
            idempotentReplay,
            errorCategory: 'none' as SyncErrorCategory,
            message: idempotentReplay
              ? `已通过幂等重试确认云端同步成功 (Revision #${newRevision})`
              : `已同步至 Cloudflare Durable Object (Revision #${newRevision})`,
          };
        } catch (err) {
          const classified = classifyNetworkCatchError(err, timeoutMs);
          if (classified.retryable && attempt < maxRetries) {
            continue;
          }
          this.saveLocalSyncState({
            ...this.getLocalSyncState(),
            lastErrorCategory: classified.category,
          });
          return {
            ok: false,
            status: 'offline' as SyncStatus,
            errorCategory: classified.category,
            message: `本地已加密保存 (IndexedDB) · 云端暂未同步：${classified.summary}（网络恢复后将使用相同 mutationId 幂等重试）`,
          };
        }
      }

      return {
        ok: false,
        status: 'offline' as SyncStatus,
        errorCategory: 'network_unreachable' as SyncErrorCategory,
        message:
          '本地已加密保存 (IndexedDB) · 网络中断，已保存在待同步队列，网络恢复后将幂等重试',
      };
    };

    const queuedPromise = inFlightPushQueue
      .catch(() => undefined)
      .then(() => runPush());
    inFlightPushQueue = queuedPromise;
    return queuedPromise;
  }

  /**
   * Downloads the remote V2 vault snapshot into temporary memory ONLY (`GET /api/vault`).
   * - Executes `GET /api/vault` directly WITHOUT requiring a preliminary `HEAD` request.
   * - Never writes to localStorage/IndexedDB until `commitVerifiedRemotePull` is called.
   */
  static async pullVault(
    config?: CloudflareSyncConfig,
    options: {
      timeoutMs?: number;
      maxRetries?: number;
      retryBaseDelayMs?: number;
    } = {}
  ): Promise<{
    payload: EncryptedVaultPayload | null;
    revision: number;
    initialized: boolean;
    message: string;
  }> {
    const activeConfig = config ?? this.getSyncConfig();
    if (!activeConfig.workerUrl.trim()) {
      throw new Error('请先配置有效的 Cloudflare Worker 节点地址');
    }

    const endpoint = normalizeWorkerEndpoint(activeConfig.workerUrl);
    const cleanToken = activeConfig.apiToken.trim();
    const timeoutMs = options.timeoutMs ?? WORKER_TIMEOUT_MS.GET_VAULT;
    const maxRetries = options.maxRetries ?? 1;
    const baseDelayMs = options.retryBaseDelayMs ?? 250;

    let response: Response | null = null;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const jitter = Math.floor(Math.random() * 60);
        await sleepMs(baseDelayMs * Math.pow(2, attempt - 1) + jitter);
      }

      try {
        const headers: Record<string, string> = {};
        if (cleanToken) {
          headers['Authorization'] = `Bearer ${cleanToken}`;
        }
        response = await fetchWithTimeout(
          endpoint,
          {
            method: 'GET',
            headers,
          },
          timeoutMs
        );

        if (!response.ok) {
          const classified = classifyHttpError(response.status);
          if (classified.retryable && attempt < maxRetries) {
            continue;
          }
          throw new Error(`从云端拉取失败：${classified.summary}`);
        }
        lastError = null;
        break;
      } catch (err) {
        if (
          err instanceof Error &&
          err.message.startsWith('从云端拉取失败：')
        ) {
          throw err;
        }
        const classified = classifyNetworkCatchError(err, timeoutMs);
        lastError = new Error(`从云端拉取失败：${classified.summary}`);
        if (classified.retryable && attempt < maxRetries) {
          continue;
        }
        throw lastError;
      }
    }

    if (!response) {
      throw lastError ?? new Error('从云端拉取失败：无法连接目标 Worker');
    }

    let rawData: Record<string, unknown>;
    try {
      rawData = (await response.json()) as Record<string, unknown>;
    } catch {
      throw new Error('云端返回的 JSON 格式损坏，已中止拉取以保护本地数据');
    }

    if (rawData.initialized === false || rawData.vault === null) {
      return {
        payload: null,
        revision: 0,
        initialized: false,
        message: '云端 Durable Object 尚未初始化密码库',
      };
    }

    const candidateVault = rawData.vault ?? rawData;
    const validation = validateV2VaultEnvelopeStructure(candidateVault);
    if (!validation.valid || !validation.payload) {
      throw new Error(
        `云端 V2 密文结构校验失败（${validation.reason}），已拒绝加载以保护本地数据`
      );
    }

    return {
      payload: validation.payload,
      revision: Number(rawData.revision || 1),
      initialized: true,
      message: '已下载远端 V2 密文快照至临时内存，等待主密钥认证解密',
    };
  }

  /**
   * Authenticates and decrypts the downloaded remote V2 payload in temporary memory.
   */
  static async verifyAndStageRemotePull(params: {
    remotePayload: EncryptedVaultPayload;
    remoteRevision: number;
    masterPassword?: string;
    currentMemoryKey?: CryptoKey | null;
    currentMemorySalt?: string | null;
    localPayload?: EncryptedVaultPayload | null;
  }): Promise<StagedRemotePullResult> {
    const {
      remotePayload,
      remoteRevision,
      masterPassword,
      currentMemoryKey,
      currentMemorySalt,
      localPayload,
    } = params;

    const validation = validateV2VaultEnvelopeStructure(remotePayload);
    if (!validation.valid || !validation.payload) {
      throw new Error(`远端密文结构不合法：${validation.reason}`);
    }

    let unlocked: {
      payload: EncryptedVaultPayload;
      key: CryptoKey;
      records: DecryptedVaultRecord[];
      categories: VaultCategoryItem[];
    };

    if (masterPassword && masterPassword.trim().length > 0) {
      try {
        unlocked = await unlockEncryptedVaultPayload(
          remotePayload,
          masterPassword
        );
      } catch {
        throw new Error(
          '远端密码库主密码验证或 GCM 认证标签校验失败，已保留原有本地密码库'
        );
      }
    } else if (
      currentMemoryKey &&
      currentMemorySalt &&
      currentMemorySalt === remotePayload.kdf.salt
    ) {
      try {
        unlocked = await unlockEncryptedVaultPayload(
          remotePayload,
          currentMemoryKey
        );
      } catch {
        throw new Error(
          '当前会话密钥无法解密远端密文（GCM 认证标签不匹配），已拒绝覆盖本地数据'
        );
      }
    } else {
      throw new Error(
        'REMOTE_SALT_MISMATCH_NEEDS_PASSWORD:远端密码库使用了不同的随机盐值或已轮换主密码，请输入远端密码库的主密码进行认证解密'
      );
    }

    const existingLocal = localPayload ?? this.getLocalVault();
    const syncState = this.getLocalSyncState();
    const hasConflictWithLocal = existingLocal
      ? hasEncryptedVaultDivergence(existingLocal, remotePayload) ||
        syncState.dirtySince !== null
      : false;
    const isDifferentVaultId = existingLocal
      ? existingLocal.vaultId !== remotePayload.vaultId
      : false;

    return {
      remotePayload: unlocked.payload,
      remoteRevision,
      derivedKey: unlocked.key,
      decryptedRecords: unlocked.records,
      decryptedCategories: unlocked.categories,
      hasConflictWithLocal,
      isDifferentVaultId,
      localRecordCount: existingLocal
        ? existingLocal.encryptedRecords.length
        : 0,
      remoteRecordCount: unlocked.records.length,
      remoteUpdatedAt: remotePayload.updatedAt,
    };
  }

  /**
   * Commits a verified StagedRemotePullResult to local storage and updates `lastSyncedRevision`.
   */
  static commitVerifiedRemotePull(
    staged: StagedRemotePullResult,
    config?: CloudflareSyncConfig
  ): void {
    const existingLocal = this.getLocalVault();
    if (existingLocal) {
      this.saveRollbackBackup(existingLocal);
    }

    this.saveLocalVault(staged.remotePayload, {
      markDirty: false,
      syncedRevision: staged.remoteRevision,
      pendingPasswordRotationPurge: false,
    });

    const activeConfig = config ?? this.getSyncConfig();
    this.saveSyncConfig({
      ...activeConfig,
      lastSyncedAt: Date.now(),
    });
  }

  /**
   * Resolves an active 409 Conflict either by adopting the verified Cloud snapshot
   * or by rebasing the local vault onto `serverRevision` and pushing as `serverRevision + 1`.
   */
  static async resolveConflict(params: {
    resolution: 'use_cloud' | 'keep_local_and_push';
    config: CloudflareSyncConfig;
    masterPassword?: string;
    currentMemoryKey?: CryptoKey | null;
    currentMemorySalt?: string | null;
  }): Promise<{
    ok: boolean;
    status: SyncStatus;
    revision?: number;
    stagedCloud?: StagedRemotePullResult;
    message: string;
  }> {
    const syncState = this.getLocalSyncState();
    const conflict = syncState.conflictState;
    if (!conflict) {
      return {
        ok: false,
        status: this.computeSyncStatus(params.config),
        message: '当前没有待处理的云端版本冲突',
      };
    }

    if (params.resolution === 'use_cloud') {
      let remoteVault = conflict.serverVault;
      let remoteRevision = conflict.serverRevision;
      if (!remoteVault) {
        const pulled = await this.pullVault(params.config);
        if (!pulled.payload) {
          throw new Error('云端密码库为空，无法采用云端版本');
        }
        remoteVault = pulled.payload;
        remoteRevision = pulled.revision;
      }

      const staged = await this.verifyAndStageRemotePull({
        remotePayload: remoteVault,
        remoteRevision,
        masterPassword: params.masterPassword,
        currentMemoryKey: params.currentMemoryKey,
        currentMemorySalt: params.currentMemorySalt,
      });

      this.commitVerifiedRemotePull(staged, params.config);
      return {
        ok: true,
        status: 'cloud_synced',
        revision: remoteRevision,
        stagedCloud: staged,
        message: `已验证并采用云端版本 #${remoteRevision}（原本地数据已保存至回滚备份）`,
      };
    }

    // 'keep_local_and_push'
    const localVault = this.getLocalVault();
    if (!localVault) {
      throw new Error('未找到本地密码库，无法推送本地版本');
    }
    if (
      conflict.serverVaultId &&
      conflict.serverVaultId !== localVault.vaultId
    ) {
      throw new Error(
        '云端密码库与本地密码库属于不同的 vaultId，禁止直接覆盖云端。请先导出备份或采用云端密码库。'
      );
    }

    const payloadHash = computePayloadContentSignature(localVault);
    // Rebase expectedRevision onto serverRevision and generate a fresh mutationId
    this.saveLocalSyncState({
      ...syncState,
      lastSyncedRevision: conflict.serverRevision,
      pendingMutationId: generateVaultId(),
      pendingMutationPayloadHash: payloadHash,
      dirtySince: Date.now(),
      conflictState: null,
    });

    const pushRes = await this.pushVault(localVault, params.config);
    return {
      ok: pushRes.ok,
      status: pushRes.status,
      revision: pushRes.revision,
      message: pushRes.message,
    };
  }

  /**
   * Lists bounded historical snapshots stored in the Cloud Durable Object (`GET /api/vault/history`).
   */
  static async listCloudHistory(
    config?: CloudflareSyncConfig,
    timeoutMs: number = WORKER_TIMEOUT_MS.GET_HISTORY
  ): Promise<{
    initialized: boolean;
    vaultId?: string;
    currentRevision: number;
    snapshots: VaultHistoryEntry[];
  }> {
    const activeConfig = config ?? this.getSyncConfig();
    const endpoint = normalizeWorkerEndpoint(activeConfig.workerUrl, '/history');
    const cleanToken = activeConfig.apiToken.trim();
    if (!cleanToken) {
      throw new Error('查看云端历史快照需要提供有效的 API Token');
    }

    let res: Response;
    try {
      res = await fetchWithTimeout(
        endpoint,
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${cleanToken}`,
          },
        },
        timeoutMs
      );
    } catch (err) {
      const classified = classifyNetworkCatchError(err, timeoutMs);
      throw new Error(`获取云端历史版本列表失败：${classified.summary}`);
    }

    if (!res.ok) {
      const classified = classifyHttpError(res.status);
      throw new Error(`获取云端历史版本列表失败：${classified.summary}`);
    }

    const data = await res.json();
    return {
      initialized: Boolean(data.initialized),
      vaultId: data.vaultId,
      currentRevision: Number(data.currentRevision || 0),
      snapshots: Array.isArray(data.snapshots) ? data.snapshots : [],
    };
  }

  /**
   * Fetches and restores a specific historical cloud snapshot (`GET /api/vault/history/:revision`).
   */
  static async restoreCloudHistorySnapshot(params: {
    revision: number;
    config?: CloudflareSyncConfig;
    masterPassword?: string;
    currentMemoryKey?: CryptoKey | null;
    currentMemorySalt?: string | null;
    timeoutMs?: number;
  }): Promise<{
    payload: EncryptedVaultPayload;
    key: CryptoKey;
    records: DecryptedVaultRecord[];
    categories: VaultCategoryItem[];
    newCloudRevision?: number;
    recoverySummary: RecoverySummaryInfo;
  }> {
    const activeConfig = params.config ?? this.getSyncConfig();
    const endpoint = normalizeWorkerEndpoint(
      activeConfig.workerUrl,
      `/history/${params.revision}`
    );
    const cleanToken = activeConfig.apiToken.trim();
    if (!cleanToken) {
      throw new Error('恢复云端历史快照需要提供有效的 API Token');
    }

    const timeoutMs = params.timeoutMs ?? WORKER_TIMEOUT_MS.GET_HISTORY;
    let res: Response;
    try {
      res = await fetchWithTimeout(
        endpoint,
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${cleanToken}`,
          },
        },
        timeoutMs
      );
    } catch (err) {
      const classified = classifyNetworkCatchError(err, timeoutMs);
      throw new Error(`下载云端历史快照失败：${classified.summary}`);
    }

    if (!res.ok) {
      if (res.status === 404) {
        throw new Error(`云端历史快照 #${params.revision} 不存在或已被清理`);
      }
      const classified = classifyHttpError(res.status);
      throw new Error(`下载云端历史快照失败：${classified.summary}`);
    }

    const data = await res.json();
    const validation = validateV2VaultEnvelopeStructure(data.vault);
    if (!validation.valid || !validation.payload) {
      throw new Error(
        `历史快照 #${params.revision} 结构校验失败：${validation.reason}`
      );
    }

    const snapshotVault = validation.payload;
    const currentRevision = Number(data.currentRevision || params.revision);

    let unlocked: {
      payload: EncryptedVaultPayload;
      key: CryptoKey;
      records: DecryptedVaultRecord[];
      categories: VaultCategoryItem[];
    };

    if (params.masterPassword && params.masterPassword.trim()) {
      unlocked = await unlockEncryptedVaultPayload(
        snapshotVault,
        params.masterPassword
      );
    } else if (
      params.currentMemoryKey &&
      params.currentMemorySalt === snapshotVault.kdf.salt
    ) {
      unlocked = await unlockEncryptedVaultPayload(
        snapshotVault,
        params.currentMemoryKey
      );
    } else {
      throw new Error(
        'SNAPSHOT_NEEDS_PASSWORD:该历史快照使用了旧的主密码或不同盐值加密，请输入当时的主密码以解密恢复'
      );
    }

    const existingLocal = this.getLocalVault();
    if (existingLocal) {
      this.saveRollbackBackup(existingLocal);
    }

    const restoredPayload: EncryptedVaultPayload = {
      ...unlocked.payload,
      updatedAt: new Date().toISOString(),
    };

    this.saveLocalVault(restoredPayload, {
      markDirty: true,
      syncedRevision: currentRevision,
    });

    const pushRes = await this.pushVault(restoredPayload, activeConfig);

    const cardCount = unlocked.records.filter(
      (r) => r.recordType === 'card' || r.category === 'bank-card'
    ).length;

    return {
      payload: restoredPayload,
      key: unlocked.key,
      records: unlocked.records,
      categories: unlocked.categories,
      newCloudRevision: pushRes.ok ? pushRes.revision : undefined,
      recoverySummary: {
        source: 'history-snapshot',
        vaultId: restoredPayload.vaultId,
        revision: pushRes.revision ?? params.revision,
        recordCount: unlocked.records.length,
        loginCount: unlocked.records.length - cardCount,
        cardCount,
        categoryCount: unlocked.categories.length,
        hadPreviousLocalVault: Boolean(existingLocal),
        restoredRecordCount: unlocked.records.length,
        restoredAt: Date.now(),
        overwroteExistingLocal: Boolean(existingLocal),
        recordTitlesSample: unlocked.records.slice(0, 5).map((r) => r.title),
      },
    };
  }

  /**
   * Probes remote Worker for cross-device recovery without modifying local storage.
   * Uses a single direct `GET /api/vault` request (no extra pre-flight `HEAD` round-trip)
   * so recovery over high-latency or weak mobile networks is fast and reliable.
   */
  static async probeRemoteVaultForRecovery(
    config: CloudflareSyncConfig,
    timeoutMs: number = WORKER_TIMEOUT_MS.GET_VAULT
  ): Promise<RemoteVaultProbeResult> {
    const cleanToken = config.apiToken.trim();
    if (!cleanToken) {
      return {
        status: 'unauthorized',
        message: '请输入有效的 API Token 访问凭证以连接远端密码库',
      };
    }

    let endpoint: string;
    try {
      endpoint = normalizeWorkerEndpoint(config.workerUrl);
    } catch (err) {
      return {
        status: 'network_error',
        message: err instanceof Error ? err.message : 'Worker 地址格式无效',
      };
    }

    let response: Response;
    try {
      response = await fetchWithTimeout(
        endpoint,
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${cleanToken}`,
          },
        },
        timeoutMs
      );
    } catch (err) {
      const classified = classifyNetworkCatchError(err, timeoutMs);
      return {
        status: 'network_error',
        message: classified.summary,
      };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        status: 'unauthorized',
        message:
          'Worker 节点在线，但拒绝了访问（HTTP 401/403）：请检查 API Token 是否正确',
      };
    }

    if (response.status === 503) {
      return {
        status: 'unconfigured_server',
        message:
          'Worker 节点已响应 (HTTP 503)，但服务端尚未配置 API_TOKEN Secret 或 VAULT_DO 绑定',
      };
    }

    if (!response.ok) {
      const classified = classifyHttpError(response.status);
      return {
        status: 'network_error',
        message: classified.summary,
      };
    }

    let rawData: Record<string, unknown>;
    try {
      rawData = (await response.json()) as Record<string, unknown>;
    } catch {
      return {
        status: 'corrupted_payload',
        message: '云端返回的 JSON 格式损坏，无法解析远端密码库快照',
      };
    }

    if (rawData.initialized === false || rawData.vault === null) {
      return {
        status: 'not_initialized',
        message:
          '远端 Durable Object 尚未初始化（未找到任何已上传的加密密码库）',
      };
    }

    const candidateVault = rawData.vault ?? rawData;
    const validation = validateV2VaultEnvelopeStructure(candidateVault);
    if (!validation.valid || !validation.payload) {
      return {
        status: 'corrupted_payload',
        message: `云端 V2 密文结构校验失败（${validation.reason}）`,
      };
    }

    const remotePayload = validation.payload;
    const remoteRevision = Number(rawData.revision || 1);
    const existingLocal = this.getLocalVault();
    const hasExistingLocalVault = Boolean(existingLocal);
    const hasDifferenceFromLocal = existingLocal
      ? hasEncryptedVaultDivergence(existingLocal, remotePayload)
      : false;
    const isDifferentVaultFromLocal = existingLocal
      ? existingLocal.vaultId !== remotePayload.vaultId
      : false;

    return {
      status: 'ready',
      message:
        '已成功获取远端 V2 加密快照（尚未覆盖本地），请输入原主密码进行本地认证解密',
      candidatePayload: remotePayload,
      metadata: {
        version: 2,
        vaultId: remotePayload.vaultId,
        revision: remoteRevision,
        saltFingerprint: `Vault:${remotePayload.vaultId.slice(
          0,
          8
        )} · Rev#${remoteRevision}`,
        recordCount: remotePayload.encryptedRecords.length,
        localRecordCount: existingLocal
          ? existingLocal.encryptedRecords.length
          : 0,
        updatedAt: remotePayload.updatedAt,
        kdfAlgorithm: `${remotePayload.kdf.algorithm}`,
        kdfIterations: remotePayload.kdf.iterations,
        cipherAlgorithm: `${remotePayload.cipher.algorithm}-${remotePayload.cipher.keyLength}`,
        hasExistingLocalVault,
        hasDifferenceFromLocal,
        isDifferentVaultFromLocal,
      },
    };
  }

  /**
   * Parses an encrypted V2 JSON backup file in temporary memory for full vault recovery.
   */
  static parseBackupFileForRecovery(
    rawJsonText: string
  ): RemoteVaultProbeResult {
    const trimmed = rawJsonText.trim();
    if (!trimmed) {
      return {
        status: 'corrupted_payload',
        message:
          '备份文件内容为空，请选择有效的 AegisVault V2 加密备份 JSON 文件',
      };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return {
        status: 'corrupted_payload',
        message: '文件不是合法的 JSON 格式，无法解析加密密码库信封',
      };
    }

    const validation = validateV2VaultEnvelopeStructure(parsed);
    if (!validation.valid || !validation.payload) {
      return {
        status: 'corrupted_payload',
        message: `加密备份文件结构校验未通过：${validation.reason}`,
      };
    }

    const candidate = validation.payload;
    const existingLocal = this.getLocalVault();
    const hasExistingLocalVault = Boolean(existingLocal);
    const hasDifferenceFromLocal = existingLocal
      ? hasEncryptedVaultDivergence(existingLocal, candidate)
      : false;
    const isDifferentVaultFromLocal = existingLocal
      ? existingLocal.vaultId !== candidate.vaultId
      : false;

    return {
      status: 'ready',
      message:
        '已解析 V2 加密备份文件结构，请输入创建该备份时的主密码进行认证解密',
      candidatePayload: candidate,
      metadata: {
        version: 2,
        vaultId: candidate.vaultId,
        revision: 0,
        saltFingerprint: `Vault:${candidate.vaultId.slice(0, 8)}`,
        recordCount: candidate.encryptedRecords.length,
        localRecordCount: existingLocal
          ? existingLocal.encryptedRecords.length
          : 0,
        updatedAt: candidate.updatedAt,
        kdfAlgorithm: `${candidate.kdf.algorithm}`,
        kdfIterations: candidate.kdf.iterations,
        cipherAlgorithm: `${candidate.cipher.algorithm}-${candidate.cipher.keyLength}`,
        hasExistingLocalVault,
        hasDifferenceFromLocal,
        isDifferentVaultFromLocal,
      },
    };
  }

  /**
   * Verifies the user's original Master Password against a candidate V2 recovery payload,
   * decrypts metadata and all records in temporary memory, and commits to local storage.
   */
  static async verifyAndCommitRecoveryPayload(params: {
    candidatePayload: EncryptedVaultPayload;
    remoteRevision?: number;
    masterPassword: string;
    source: 'cloud' | 'backup-file';
    syncConfigToSave?: CloudflareSyncConfig;
    confirmOverwriteExistingLocal?: boolean;
  }): Promise<{
    payload: EncryptedVaultPayload;
    key: CryptoKey;
    salt: string;
    records: DecryptedVaultRecord[];
    categories: VaultCategoryItem[];
    recoverySummary: RecoverySummaryInfo;
  }> {
    const {
      candidatePayload,
      remoteRevision,
      masterPassword,
      source,
      syncConfigToSave,
      confirmOverwriteExistingLocal,
    } = params;

    const validation = validateV2VaultEnvelopeStructure(candidatePayload);
    if (!validation.valid || !validation.payload) {
      throw new Error(`候选恢复数据校验未通过：${validation.reason}`);
    }

    const existingLocal = this.getLocalVault();
    const hasConflict = existingLocal
      ? hasEncryptedVaultDivergence(existingLocal, candidatePayload)
      : false;

    if (existingLocal && hasConflict && !confirmOverwriteExistingLocal) {
      throw new Error(
        'OVERWRITE_CONFIRM_REQUIRED:当前设备已存在不同的本地加密密码库，请先勾选覆盖确认选项后再执行恢复'
      );
    }

    let unlocked: {
      payload: EncryptedVaultPayload;
      key: CryptoKey;
      records: DecryptedVaultRecord[];
      categories: VaultCategoryItem[];
    };
    try {
      unlocked = await unlockEncryptedVaultPayload(
        candidatePayload,
        masterPassword
      );
    } catch {
      throw new Error(
        '主密码错误或密文完整性校验失败：无法解密恢复数据，当前设备原有数据保持不变'
      );
    }

    if (existingLocal) {
      this.saveRollbackBackup(existingLocal);
    }

    const syncedRev = source === 'cloud' ? Number(remoteRevision || 1) : 0;

    await this.saveLocalVaultAsync(unlocked.payload, {
      markDirty: false,
      syncedRevision: syncedRev,
      pendingPasswordRotationPurge: false,
    });

    if (syncConfigToSave && source === 'cloud') {
      this.saveSyncConfig({
        ...syncConfigToSave,
        lastSyncedAt: Date.now(),
      });
    }

    const cardCount = unlocked.records.filter(
      (r) => r.recordType === 'card' || r.category === 'bank-card'
    ).length;

    return {
      payload: unlocked.payload,
      key: unlocked.key,
      salt: unlocked.payload.kdf.salt,
      records: unlocked.records,
      categories: unlocked.categories,
      recoverySummary: {
        source,
        vaultId: unlocked.payload.vaultId,
        revision: syncedRev > 0 ? syncedRev : undefined,
        recordCount: unlocked.records.length,
        loginCount: unlocked.records.length - cardCount,
        cardCount,
        categoryCount: unlocked.categories.length,
        hadPreviousLocalVault: Boolean(existingLocal && hasConflict),
        restoredRecordCount: unlocked.records.length,
        restoredAt: Date.now(),
        overwroteExistingLocal: Boolean(existingLocal && hasConflict),
        recordTitlesSample: unlocked.records.slice(0, 5).map((r) => r.title),
      },
    };
  }
}
