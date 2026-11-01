import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

import {
  DEFAULT_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  VAULT_FORMAT_VERSION,
  buildEncryptedVaultPayload,
  createEphemeralDemoSession,
  deriveMasterKey,
  generateSaltBase64,
  generateVaultId,
  rotateVaultMasterPassword,
  unlockEncryptedVaultPayload,
  validateV2VaultEnvelopeStructure,
} from './cryptoEngine';
import {
  AtomicIdbSnapshot,
  OBSOLETE_V1_STORAGE_KEYS,
  PluggableIdbAdapter,
  SYNC_CONFIG_STORAGE_KEY,
  SYNC_STATE_STORAGE_KEY,
  SyncService,
  VAULT_STORAGE_KEY,
  computePayloadContentSignature,
  normalizeWorkerEndpoint,
  purgeLegacyV1StorageKeys,
  subscribeToCrossTabVaultUpdates,
} from '../services/syncService';
import {
  getBrandAvatarStyle,
  getWebsiteFaviconUrl,
} from '../utils/brandVisuals';
import { createInitialSeedRecords } from '../utils/seedData';
import { createCustomCategory, getInitialDefaultCategories } from '../utils/categoryManager';
import { detectAndParseImportContent } from '../utils/importVaultUtils';
import workerHandler, { VaultDurableObject } from '../../worker/src/index';
import type {
  DurableObjectIdLike,
  DurableObjectNamespaceLike,
  DurableObjectStateLike,
  SqlStorageCursor,
} from '../../worker/src/VaultDurableObject';
import type { CloudflareSyncConfig, DecryptedVaultRecord } from '../types/vault';

// Use 100,000 iterations in automated tests for fast execution while still exercising full WebCrypto PBKDF2 + AAD
const TEST_ITERATIONS = MIN_PBKDF2_ITERATIONS;
const TEST_API_TOKEN = 'aegis-v2-unit-test-bearer-secret-99887766';
const TEST_WORKER_URL = 'https://vault-v2-test.aegis.example.com';

/**
 * Creates a real SQLite-backed DurableObjectNamespace using Node's built-in `node:sqlite` (`DatabaseSync`).
 * Executes all VaultDurableObject SQL DDL, constraints, unique indexes, and transactions against real SQLite.
 */
function createSqliteDurableObjectNamespace(): DurableObjectNamespaceLike {
  const instances = new Map<string, VaultDurableObject>();

  return {
    idFromName(name: string): DurableObjectIdLike {
      return {
        toString: () => `do-sqlite-${name}`,
      };
    },
    get(id: DurableObjectIdLike) {
      const key = id.toString();
      let instance = instances.get(key);
      if (!instance) {
        const db = new DatabaseSync(':memory:');
        const state: DurableObjectStateLike = {
          storage: {
            sql: {
              exec(query: string, ...bindings: unknown[]): SqlStorageCursor {
                const trimmed = query.trim();
                const stmt = db.prepare(trimmed);
                const isSelect = /^SELECT\b/i.test(trimmed);
                if (isSelect) {
                  const rows = stmt.all(...(bindings as (string | number | null)[]));
                  return {
                    toArray: () => rows as Record<string, unknown>[],
                  };
                }
                stmt.run(...(bindings as (string | number | null)[]));
                return {
                  toArray: () => [],
                };
              },
            },
            transactionSync<T>(closure: () => T): T {
              db.exec('BEGIN IMMEDIATE');
              try {
                const res = closure();
                db.exec('COMMIT');
                return res;
              } catch (err) {
                db.exec('ROLLBACK');
                throw err;
              }
            },
          },
        };
        instance = new VaultDurableObject(state);
        instances.set(key, instance);
      }
      return {
        fetch: (req: Request) => instance!.fetch(req),
      };
    },
  };
}

/**
 * Sets up a clean simulated browser environment (`window`, `localStorage`, `sessionStorage`, `fetch`)
 * connected to the real SQLite-backed Worker + VaultDurableObject.
 */
function setupSimulatedBrowserEnv(options: {
  doNamespace?: DurableObjectNamespaceLike;
  apiToken?: string;
  networkOffline?: boolean;
} = {}) {
  const localStore = new Map<string, string>();
  const sessionStore = new Map<string, string>();
  const storageListeners = new Set<(e: StorageEvent) => void>();

  const mockStorage = (backing: Map<string, string>) => ({
    getItem: (k: string) => (backing.has(k) ? backing.get(k)! : null),
    setItem: (k: string, v: string) => {
      backing.set(k, String(v));
    },
    removeItem: (k: string) => {
      backing.delete(k);
    },
    clear: () => {
      throw new Error('FORBIDDEN: localStorage.clear() must never be called!');
    },
  });

  const doNamespace = options.doNamespace ?? createSqliteDurableObjectNamespace();
  const serverApiToken = options.apiToken ?? TEST_API_TOKEN;
  let isOffline = Boolean(options.networkOffline);

  const mockWindow = {
    crypto: globalThis.crypto,
    localStorage: mockStorage(localStore),
    sessionStorage: mockStorage(sessionStore),
    addEventListener: (type: string, fn: (e: StorageEvent) => void) => {
      if (type === 'storage') storageListeners.add(fn);
    },
    removeEventListener: (type: string, fn: (e: StorageEvent) => void) => {
      if (type === 'storage') storageListeners.delete(fn);
    },
    triggerStorageEvent: (key: string) => {
      for (const fn of storageListeners) {
        fn({ key } as StorageEvent);
      }
    },
  };

  Object.defineProperty(globalThis, 'window', {
    value: mockWindow,
    configurable: true,
    writable: true,
  });

  Object.defineProperty(globalThis, 'fetch', {
    value: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      if (isOffline) {
        throw new TypeError('Failed to fetch: simulated network offline');
      }
      const urlStr = typeof input === 'string' ? input : input.toString();
      const req = new Request(urlStr, init);
      return workerHandler.fetch(req, {
        VAULT_DO: doNamespace,
        API_TOKEN: serverApiToken,
      });
    },
    configurable: true,
    writable: true,
  });

  SyncService.clearApiToken();

  return {
    localStore,
    sessionStore,
    doNamespace,
    mockWindow,
    setOffline: (offline: boolean) => {
      isOffline = offline;
    },
  };
}

function createSampleRecord(overrides: Partial<DecryptedVaultRecord> = {}): DecryptedVaultRecord {
  const now = Date.now();
  return {
    id: overrides.id ?? `rec-${Math.random().toString(36).slice(2, 9)}`,
    recordType: overrides.recordType ?? 'login',
    title: overrides.title ?? 'GitHub Production Account',
    username: overrides.username ?? 'secops@example.invalid',
    password: overrides.password ?? 'V2ZeroKnowledge#9988!xQ',
    url: overrides.url ?? 'https://github.com',
    category: overrides.category ?? 'work',
    tags: overrides.tags ?? ['2FA', '研发'],
    cardDetails: overrides.cardDetails,
    notes: overrides.notes ?? 'Synthetic test credential',
    favorite: overrides.favorite ?? true,
    createdAt: overrides.createdAt ?? now,
    updatedAt: overrides.updatedAt ?? now,
  };
}

describe('AegisVault V2 Zero-Knowledge Crypto, Durable Objects & Sync Protocol Suite', () => {
  beforeEach(() => {
    setupSimulatedBrowserEnv();
  });

  it('1. V2 Vault Creation, AAD Encryption/Decryption, and Default 600,000 PBKDF2 Standard', async () => {
    assert.equal(VAULT_FORMAT_VERSION, 2);
    assert.equal(DEFAULT_PBKDF2_ITERATIONS, 600_000);

    const masterPassword = 'MasterPass#V2_Strong_2026!';
    const salt = generateSaltBase64(16);
    const vaultId = generateVaultId();
    const key = await deriveMasterKey(masterPassword, salt, TEST_ITERATIONS);

    const records = [
      createSampleRecord({ id: 'rec-1', title: 'Cloudflare Zero Trust' }),
      createSampleRecord({
        id: 'rec-2',
        recordType: 'card',
        category: 'bank-card',
        title: 'Test Platinum Card',
        cardDetails: {
          cardholderName: 'TEST USER',
          cardNumber: '4000000000001234',
          expiryDate: '09/29',
          cvv: '000',
          brand: 'Visa',
        },
      }),
    ];

    const { categories } = createCustomCategory(
      getInitialDefaultCategories(),
      '硬件密钥'
    );

    const payload = await buildEncryptedVaultPayload(key, salt, records, {
      vaultId,
      categories,
      iterations: TEST_ITERATIONS,
    });

    assert.equal(payload.formatVersion, 2);
    assert.equal(payload.vaultId, vaultId);
    assert.equal(payload.encryptedRecords.length, 2);
    assert.ok(payload.encryptedMetadata.iv);
    assert.ok(payload.encryptedMetadata.ciphertext);

    // Ensure no plaintext leaked into serialized envelope
    const rawJson = JSON.stringify(payload);
    assert.ok(!rawJson.includes('Cloudflare Zero Trust'));
    assert.ok(!rawJson.includes('4000000000001234'));
    assert.ok(!rawJson.includes('硬件密钥'));

    // Unlock with correct Master Password
    const unlocked = await unlockEncryptedVaultPayload(payload, masterPassword);
    assert.equal(unlocked.records.length, 2);
    const rec1 = unlocked.records.find((r) => r.id === 'rec-1');
    const rec2 = unlocked.records.find((r) => r.id === 'rec-2');
    assert.equal(rec1?.title, 'Cloudflare Zero Trust');
    assert.equal(rec2?.cardDetails?.cardNumber, '4000000000001234');
    assert.ok(unlocked.categories.some((c) => c.label === '硬件密钥'));

    // Wrong Master Password must fail verifier check
    await assert.rejects(
      () => unlockEncryptedVaultPayload(payload, 'WrongPassword#12345'),
      /主密码错误|认证失败/
    );
  });

  it('2. AES-256-GCM AAD Binding: Rejects Tampered vaultId, Record ID, Timestamps, or Cross-Vault Swaps', async () => {
    const password = 'MasterPass#AAD_Binding_Test!';
    const salt = generateSaltBase64(16);
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

    const vaultA = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-a', title: 'Vault A Secret' })],
      { vaultId: generateVaultId(), iterations: TEST_ITERATIONS }
    );

    const vaultB = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-b', title: 'Vault B Secret' })],
      { vaultId: generateVaultId(), iterations: TEST_ITERATIONS }
    );

    // 2a. Tampering with vaultId breaks verifier & metadata AAD
    const tamperedVaultId = {
      ...vaultA,
      vaultId: generateVaultId(),
    };
    await assert.rejects(() => unlockEncryptedVaultPayload(tamperedVaultId, password));

    // 2b. Tampering with record ID or updatedAt timestamp breaks record AAD
    const tamperedRecordId = {
      ...vaultA,
      encryptedRecords: [
        {
          ...vaultA.encryptedRecords[0],
          id: 'rec-tampered-id',
        },
      ],
    };
    await assert.rejects(() => unlockEncryptedVaultPayload(tamperedRecordId, password));

    // 2c. Swapping an encryptedRecord from Vault B into Vault A (even with identical key!) fails AAD verification
    const swappedCrossVault = {
      ...vaultA,
      encryptedRecords: [vaultB.encryptedRecords[0]],
    };
    await assert.rejects(
      () => unlockEncryptedVaultPayload(swappedCrossVault, password),
      /认证标签校验失败/
    );
  });

  it('3. Custom Categories & Tags Encrypted in encryptedMetadata (Zero Plaintext Category Keys in localStorage)', async () => {
    const env = setupSimulatedBrowserEnv();
    const password = 'CategoryZeroKnowledge#2026!';
    const salt = generateSaltBase64(16);
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

    const { categories } = createCustomCategory(
      getInitialDefaultCategories(),
      '瑞士银行私密标签'
    );

    const payload = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ tags: ['瑞士银行私密标签'] })],
      { categories, iterations: TEST_ITERATIONS }
    );

    SyncService.saveLocalVault(payload);

    // Verify no plaintext category key exists in localStorage and no plaintext string appears in any localStorage value
    assert.equal(env.localStore.has('aegis_zk_categories_v1'), false);
    for (const [k, v] of env.localStore.entries()) {
      assert.ok(
        !v.includes('瑞士银行私密标签'),
        `Plaintext category leaked into localStorage key ${k}`
      );
    }

    // Verify unlocking decrypts the custom category from encryptedMetadata
    const unlocked = await unlockEncryptedVaultPayload(
      SyncService.getLocalVault(),
      password
    );
    assert.ok(unlocked.categories.some((c) => c.label === '瑞士银行私密标签'));
  });

  it('4. V2 Master Password Rotation: Preserves vaultId while Rotating Salt, Key, Verifier, Metadata, and Records', async () => {
    const oldPassword = 'OldMasterPassword#2025!';
    const newPassword = 'NewRotatedPassword#2026!';
    const salt = generateSaltBase64(16);
    const originalVaultId = generateVaultId();
    const key = await deriveMasterKey(oldPassword, salt, TEST_ITERATIONS);

    const originalVault = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-rot-1', title: 'Rotation Secret' })],
      { vaultId: originalVaultId, iterations: TEST_ITERATIONS }
    );

    // Wrong old password must be rejected without mutating original vault
    await assert.rejects(
      () =>
        rotateVaultMasterPassword(
          originalVault,
          'IncorrectOldPassword',
          newPassword,
          TEST_ITERATIONS
        ),
      /主密码错误/
    );

    const rotated = await rotateVaultMasterPassword(
      originalVault,
      oldPassword,
      newPassword,
      TEST_ITERATIONS
    );

    // vaultId is preserved, while salt, verifier, metadata, and record ciphertexts are all freshly re-encrypted
    assert.equal(rotated.newPayload.vaultId, originalVaultId);
    assert.notEqual(rotated.newPayload.kdf.salt, originalVault.kdf.salt);
    assert.notEqual(
      rotated.newPayload.verifier.ciphertext,
      originalVault.verifier.ciphertext
    );
    assert.notEqual(
      rotated.newPayload.encryptedMetadata.ciphertext,
      originalVault.encryptedMetadata.ciphertext
    );
    assert.notEqual(
      rotated.newPayload.encryptedRecords[0].ciphertext,
      originalVault.encryptedRecords[0].ciphertext
    );

    // Old password can no longer unlock rotated vault
    await assert.rejects(() =>
      unlockEncryptedVaultPayload(rotated.newPayload, oldPassword)
    );

    // New password unlocks rotated vault and preserves records
    const unlockedNew = await unlockEncryptedVaultPayload(
      rotated.newPayload,
      newPassword
    );
    assert.equal(unlockedNew.records[0].title, 'Rotation Secret');
  });

  it('5. Worker Security Hardening: Rejects Unconfigured Secret, Missing/Wrong Bearer Token, Query Token, Oversized Body, and V1 Format', async () => {
    const doNamespace = createSqliteDurableObjectNamespace();

    // 5a. Unconfigured API_TOKEN fails closed with 503
    const resUnconfigured = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault`, { method: 'GET' }),
      { VAULT_DO: doNamespace, API_TOKEN: '' }
    );
    assert.equal(resUnconfigured.status, 503);

    // 5b. Missing Authorization header -> 401
    const resNoAuth = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault`, { method: 'GET' }),
      { VAULT_DO: doNamespace, API_TOKEN: TEST_API_TOKEN }
    );
    assert.equal(resNoAuth.status, 401);

    // 5c. Wrong Bearer token -> 401
    const resWrongAuth = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault`, {
        method: 'GET',
        headers: { Authorization: 'Bearer wrong-token-value-000000' },
      }),
      { VAULT_DO: doNamespace, API_TOKEN: TEST_API_TOKEN }
    );
    assert.equal(resWrongAuth.status, 401);

    // 5d. Token in URL query parameter -> 400
    const resQueryToken = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault?token=${TEST_API_TOKEN}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${TEST_API_TOKEN}` },
      }),
      { VAULT_DO: doNamespace, API_TOKEN: TEST_API_TOKEN }
    );
    assert.equal(resQueryToken.status, 400);

    // 5e. Legacy V1 payload rejected with 422
    const v1Payload = {
      version: 1,
      updatedAt: new Date().toISOString(),
      kdf: { algorithm: 'PBKDF2', hash: 'SHA-256', iterations: 100000, salt: generateSaltBase64(16) },
      cipher: { algorithm: 'AES-GCM', keyLength: 256, ivLength: 12 },
      verifier: { iv: generateSaltBase64(12), ciphertext: generateSaltBase64(32) },
      records: [],
    };
    const resV1 = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${TEST_API_TOKEN}`,
        },
        body: JSON.stringify({
          protocolVersion: 2,
          vaultId: generateVaultId(),
          mutationId: generateVaultId(),
          vault: v1Payload,
        }),
      }),
      { VAULT_DO: doNamespace, API_TOKEN: TEST_API_TOKEN }
    );
    assert.equal(resV1.status, 422);

    // 5f. Oversized body (> 1MB) rejected with 413
    const oversizedBody = 'x'.repeat(1024 * 1024 + 512);
    const resOversized = await workerHandler.fetch(
      new Request(`${TEST_WORKER_URL}/api/vault/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${TEST_API_TOKEN}`,
        },
        body: oversizedBody,
      }),
      { VAULT_DO: doNamespace, API_TOKEN: TEST_API_TOKEN }
    );
    assert.equal(resOversized.status, 413);
  });

  it('6. Durable Object Lifecycle: Empty Probe, Explicit POST /api/vault/init, Atomic PUT Revisions, and Mutation Idempotency', async () => {
    setupSimulatedBrowserEnv();
    const cfg: CloudflareSyncConfig = {
      workerUrl: TEST_WORKER_URL,
      apiToken: TEST_API_TOKEN,
      rememberToken: false,
      autoSync: true,
      lastSyncedAt: null,
    };

    // 6a. Blank cloud: HEAD returns X-Vault-Initialized: false, revision 0
    const headEmpty = await SyncService.checkWorkerConnectivity(cfg);
    assert.equal(headEmpty.reachable, true);
    assert.equal(headEmpty.initialized, false);
    assert.equal(headEmpty.revision, 0);

    // 6b. Blank cloud: GET returns initialized: false, revision: 0
    const getEmpty = await SyncService.pullVault(cfg);
    assert.equal(getEmpty.initialized, false);
    assert.equal(getEmpty.revision, 0);
    assert.equal(getEmpty.payload, null);

    // 6c. Build V2 vault locally
    const password = 'CloudInitTestPassword#2026!';
    const salt = generateSaltBase64(16);
    const vaultId = generateVaultId();
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);
    const vaultRev1 = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-init-1', title: 'Initial Record' })],
      { vaultId, iterations: TEST_ITERATIONS }
    );

    // 6d. Calling pushVault on uninitialized cloud without allowAutoInitIfEmpty does NOT overwrite or initialize silently
    const pushWithoutInit = await SyncService.pushVault(vaultRev1, cfg, {
      allowAutoInitIfEmpty: false,
    });
    assert.equal(pushWithoutInit.ok, false);
    assert.equal(pushWithoutInit.requiresInitConfirmation, true);
    assert.equal(pushWithoutInit.status, 'sync_pending');

    // 6e. Explicit initialization via POST /api/vault/init creates revision = 1
    const initRes = await SyncService.initializeCloudVault(vaultRev1, cfg);
    assert.equal(initRes.ok, true);
    assert.equal(initRes.revision, 1);
    assert.equal(initRes.status, 'cloud_synced');

    // 6f. Calling POST /api/vault/init a second time with a new mutationId fails with 409 ALREADY_INITIALIZED
    SyncService.saveLocalSyncState({
      ...SyncService.getLocalSyncState(),
      pendingMutationId: generateVaultId(),
    });
    const duplicateInit = await SyncService.initializeCloudVault(vaultRev1, cfg);
    assert.equal(duplicateInit.ok, false);
    assert.equal(duplicateInit.status, 'conflict');
    assert.equal(duplicateInit.conflict?.code, 'ALREADY_INITIALIZED');

    // Clear conflict to test normal PUT revision = 2
    SyncService.saveLocalSyncState({
      ...SyncService.getLocalSyncState(),
      lastSyncedRevision: 1,
      conflictState: null,
      pendingMutationId: null,
    });

    const vaultRev2 = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-init-1', title: 'Initial Record' }),
        createSampleRecord({ id: 'rec-init-2', title: 'Second Record' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );

    const putRes = await SyncService.pushVault(vaultRev2, cfg);
    assert.equal(putRes.ok, true);
    assert.equal(putRes.revision, 2);

    // 6g. Idempotent replay of exact same mutationId & payload returns 200 OK with revision = 2 (no duplicate increment)
    const replayMutationId = generateVaultId();
    const directPutReq = {
      protocolVersion: 2,
      vaultId,
      expectedRevision: 2,
      mutationId: replayMutationId,
      vault: vaultRev2,
    };

    const firstPut = await fetch(`${TEST_WORKER_URL}/api/vault`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_API_TOKEN}`,
      },
      body: JSON.stringify(directPutReq),
    });
    assert.equal(firstPut.status, 200);
    const firstPutData = await firstPut.json();
    assert.equal(firstPutData.revision, 3);

    const replayPut = await fetch(`${TEST_WORKER_URL}/api/vault`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_API_TOKEN}`,
      },
      body: JSON.stringify(directPutReq),
    });
    assert.equal(replayPut.status, 200);
    const replayPutData = await replayPut.json();
    assert.equal(replayPutData.revision, 3);
    assert.equal(replayPutData.idempotentReplay, true);

    // 6h. Same mutationId with different vault payload is rejected with 409 MUTATION_ID_PAYLOAD_MISMATCH
    const differentVault = await buildEncryptedVaultPayload(
      key,
      salt,
      [],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    const mismatchPut = await fetch(`${TEST_WORKER_URL}/api/vault`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_API_TOKEN}`,
      },
      body: JSON.stringify({
        ...directPutReq,
        vault: differentVault,
      }),
    });
    assert.equal(mismatchPut.status, 409);
    const mismatchData = await mismatchPut.json();
    assert.equal(mismatchData.code, 'MUTATION_ID_PAYLOAD_MISMATCH');
  });

  it('7. Multi-Device Revision Conflict (Revision 8 -> 9): Prevents Silent Overwrite & Resolves Cleanly', async () => {
    const sharedDoNamespace = createSqliteDurableObjectNamespace();
    setupSimulatedBrowserEnv({ doNamespace: sharedDoNamespace });

    const cfg: CloudflareSyncConfig = {
      workerUrl: TEST_WORKER_URL,
      apiToken: TEST_API_TOKEN,
      rememberToken: false,
      autoSync: true,
      lastSyncedAt: null,
    };

    const password = 'MultiDeviceSyncPassword#2026!';
    const salt = generateSaltBase64(16);
    const vaultId = generateVaultId();
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

    // Initialize Cloud Vault and advance to Revision 8
    let currentVault = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-base', title: 'Base Record' })],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    await SyncService.initializeCloudVault(currentVault, cfg);

    for (let rev = 2; rev <= 8; rev++) {
      currentVault = await buildEncryptedVaultPayload(
        key,
        salt,
        [createSampleRecord({ id: 'rec-base', title: `Record at Rev ${rev}` })],
        { vaultId, iterations: TEST_ITERATIONS }
      );
      const res = await SyncService.pushVault(currentVault, cfg);
      assert.equal(res.revision, rev);
    }

    // Both Device A and Device B are now at Revision 8
    const baseRev8Vault = currentVault;

    // Device A adds a new record and pushes -> succeeds as Revision 9
    const deviceAVaultRev9 = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-base', title: 'Record at Rev 8' }),
        createSampleRecord({ id: 'rec-device-a', title: 'Added on Device A' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    const deviceAPush = await SyncService.pushVault(deviceAVaultRev9, cfg);
    assert.equal(deviceAPush.ok, true);
    assert.equal(deviceAPush.revision, 9);

    // Simulate Device B still on baseline Revision 8 trying to push its own edit
    setupSimulatedBrowserEnv({ doNamespace: sharedDoNamespace });
    const deviceBVault = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-base', title: 'Record at Rev 8' }),
        createSampleRecord({ id: 'rec-device-b', title: 'Added on Device B' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    SyncService.saveLocalVault(deviceBVault, {
      markDirty: true,
      syncedRevision: 8,
    });

    const deviceBPush = await SyncService.pushVault(deviceBVault, cfg);
    assert.equal(deviceBPush.ok, false);
    assert.equal(deviceBPush.status, 'conflict');
    assert.equal(deviceBPush.conflict?.code, 'REVISION_CONFLICT');
    assert.equal(deviceBPush.conflict?.localRevision, 8);
    assert.equal(deviceBPush.conflict?.serverRevision, 9);

    // Verify Cloud Durable Object still holds Device A's Revision 9 untouched
    const cloudCheck = await SyncService.pullVault(cfg);
    assert.equal(cloudCheck.revision, 9);
    const unlockedCloud = await unlockEncryptedVaultPayload(
      cloudCheck.payload,
      password
    );
    assert.ok(
      unlockedCloud.records.some((r) => r.title === 'Added on Device A')
    );

    // Verify Device B local vault still holds Device B's edit untouched
    const localCheck = await unlockEncryptedVaultPayload(
      SyncService.getLocalVault(),
      password
    );
    assert.ok(
      localCheck.records.some((r) => r.title === 'Added on Device B')
    );
    assert.ok(baseRev8Vault);

    // Resolve conflict on Device B by rebasing & pushing as Revision 10
    const resolved = await SyncService.resolveConflict({
      resolution: 'keep_local_and_push',
      config: cfg,
      currentMemoryKey: key,
      currentMemorySalt: salt,
    });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.status, 'cloud_synced');
    assert.equal(resolved.revision, 10);
  });

  it('8. Cross-Device Recovery, Historical Snapshots, Password Rotation Snapshot Purge, Offline Queue, and Demo Isolation', async () => {
    const sharedDoNamespace = createSqliteDurableObjectNamespace();
    const envA = setupSimulatedBrowserEnv({ doNamespace: sharedDoNamespace });

    const cfg: CloudflareSyncConfig = {
      workerUrl: TEST_WORKER_URL,
      apiToken: TEST_API_TOKEN,
      rememberToken: false,
      autoSync: true,
      lastSyncedAt: null,
    };

    const password = 'CrossDeviceRecovery#2026!';
    const salt = generateSaltBase64(16);
    const vaultId = generateVaultId();
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

    // Device A creates Revision 1 (1 record) and Revision 2 (2 records)
    const rev1Payload = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-1', title: 'Rev 1 Account' })],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    await SyncService.initializeCloudVault(rev1Payload, cfg);

    const rev2Payload = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-1', title: 'Rev 1 Account' }),
        createSampleRecord({ id: 'rec-2', title: 'Rev 2 Account' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    await SyncService.pushVault(rev2Payload, cfg);

    // 8a. Fresh Device B recovers from Cloud Durable Object
    const envB = setupSimulatedBrowserEnv({ doNamespace: sharedDoNamespace });
    const probeB = await SyncService.probeRemoteVaultForRecovery(cfg);
    assert.equal(probeB.status, 'ready');
    assert.equal(probeB.metadata?.revision, 2);
    assert.equal(probeB.metadata?.recordCount, 2);

    // Wrong password during recovery must fail and leave Device B localStorage empty
    await assert.rejects(() =>
      SyncService.verifyAndCommitRecoveryPayload({
        candidatePayload: probeB.candidatePayload!,
        remoteRevision: probeB.metadata!.revision,
        masterPassword: 'WrongRecoveryPassword',
        source: 'cloud',
        syncConfigToSave: cfg,
      })
    );
    assert.equal(SyncService.getLocalVault(), null);

    // Correct password recovers full vault and sets syncedRevision = 2
    const recoveredB = await SyncService.verifyAndCommitRecoveryPayload({
      candidatePayload: probeB.candidatePayload!,
      remoteRevision: probeB.metadata!.revision,
      masterPassword: password,
      source: 'cloud',
      syncConfigToSave: cfg,
    });
    assert.equal(recoveredB.records.length, 2);
    assert.equal(SyncService.getLocalSyncState().lastSyncedRevision, 2);

    // 8b. Historical Snapshots: list history and restore Revision #1
    const historyList = await SyncService.listCloudHistory(cfg);
    assert.equal(historyList.snapshots.length, 2);
    assert.equal(historyList.currentRevision, 2);

    const restoredSnap1 = await SyncService.restoreCloudHistorySnapshot({
      revision: 1,
      config: cfg,
      currentMemoryKey: recoveredB.key,
      currentMemorySalt: recoveredB.salt,
    });
    assert.equal(restoredSnap1.records.length, 1);
    assert.equal(restoredSnap1.records[0].title, 'Rev 1 Account');
    assert.equal(restoredSnap1.newCloudRevision, 3);
    assert.ok(SyncService.getRollbackBackup());

    // 8c. Master Password Rotation with purgePreviousSnapshots: true clears old-key snapshots on push
    const newRotatedPassword = 'NewRotatedCloudPassword#2026!';
    const rotated = await rotateVaultMasterPassword(
      restoredSnap1.payload,
      password,
      newRotatedPassword,
      TEST_ITERATIONS
    );
    const pushRotated = await SyncService.pushVault(rotated.newPayload, cfg, {
      purgePreviousSnapshots: true,
    });
    assert.equal(pushRotated.ok, true);
    assert.equal(pushRotated.revision, 4);

    const historyAfterPurge = await SyncService.listCloudHistory(cfg);
    assert.equal(historyAfterPurge.snapshots.length, 1);
    assert.equal(historyAfterPurge.snapshots[0].revision, 4);

    // 8d. Offline edit -> queues as 'offline' / 'sync_pending', then syncs cleanly when back online
    envB.setOffline(true);
    const rev5Payload = await buildEncryptedVaultPayload(
      rotated.newKey,
      rotated.newSalt,
      [
        createSampleRecord({ id: 'rec-1', title: 'Rev 1 Account' }),
        createSampleRecord({ id: 'rec-offline', title: 'Offline Created Account' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    const offlinePush = await SyncService.pushVault(rev5Payload, cfg);
    assert.equal(offlinePush.ok, false);
    assert.equal(offlinePush.status, 'offline');
    const pendingMutationId = SyncService.getLocalSyncState().pendingMutationId;
    assert.ok(pendingMutationId);

    envB.setOffline(false);
    const onlineRetryPush = await SyncService.pushVault(rev5Payload, cfg);
    assert.equal(onlineRetryPush.ok, true);
    assert.equal(onlineRetryPush.revision, 5);
    assert.equal(SyncService.getLocalSyncState().pendingMutationId, null);

    // 8e. Multi-tab update listener notification
    let crossTabNotified = false;
    const unsub = subscribeToCrossTabVaultUpdates((ev) => {
      if (ev.vaultId === vaultId) {
        crossTabNotified = true;
      }
    });
    envB.mockWindow.triggerStorageEvent(VAULT_STORAGE_KEY);
    assert.equal(crossTabNotified, true);
    unsub();

    // 8f. Isolated Demo Mode never touches formal localStorage or Worker
    const vaultBeforeDemo = JSON.stringify(SyncService.getLocalVault());
    const demoSession = await createEphemeralDemoSession(
      createInitialSeedRecords()
    );
    assert.notEqual(demoSession.ephemeralPayload.vaultId, vaultId);
    assert.equal(JSON.stringify(SyncService.getLocalVault()), vaultBeforeDemo);

    // 8g. Obsolete V1 keys are purged without touching unrelated same-origin keys
    envB.localStore.set('unrelated_other_app_key', 'keep-me-safe');
    for (const v1Key of OBSOLETE_V1_STORAGE_KEYS) {
      envB.localStore.set(v1Key, 'legacy-v1-data');
    }
    purgeLegacyV1StorageKeys();
    assert.equal(envB.localStore.get('unrelated_other_app_key'), 'keep-me-safe');
    for (const v1Key of OBSOLETE_V1_STORAGE_KEYS) {
      assert.equal(envB.localStore.has(v1Key), false);
    }

    // 8h. V1 import payload is strictly rejected by detectAndParseImportContent and validateV2VaultEnvelopeStructure
    const v1ImportRes = await detectAndParseImportContent(
      JSON.stringify({ version: 1, records: [] }),
      null
    );
    assert.equal(v1ImportRes.status, 'error');
    assert.match(v1ImportRes.message, /不再支持旧版 V1/);
    assert.equal(
      validateV2VaultEnvelopeStructure({ version: 1 }).valid,
      false
    );
    assert.ok(SYNC_CONFIG_STORAGE_KEY);
    assert.ok(SYNC_STATE_STORAGE_KEY);
    assert.throws(() =>
      normalizeWorkerEndpoint('http://insecure-remote.example.com')
    );
  });

  it('9. P0 Storage Consistency: Atomic IndexedDB Commit, Eviction Hydration, Conflict Reconciliation, Quota Failure Recovery, and Reset Epoch Protection', async () => {
    const env = setupSimulatedBrowserEnv();

    // Create an in-memory simulated IndexedDB backend with atomic transaction enforcement
    const idbBox: { state: AtomicIdbSnapshot | null; commitCount: number } = {
      state: null,
      commitCount: 0,
    };
    let simulateIdbTxReject = false;

    const mockIdbAdapter: PluggableIdbAdapter = {
      async readSnapshot() {
        return idbBox.state ? JSON.parse(JSON.stringify(idbBox.state)) : null;
      },
      async writeSnapshotAtomically(snapshot) {
        if (simulateIdbTxReject) {
          const err = new Error('QuotaExceededError: IDB disk full');
          err.name = 'QuotaExceededError';
          throw err;
        }
        // Enforce monotonic resetEpoch and writeSequence inside the IDB transaction
        if (idbBox.state) {
          if (snapshot.meta.resetEpoch < idbBox.state.meta.resetEpoch) {
            return;
          }
          if (
            snapshot.meta.resetEpoch === idbBox.state.meta.resetEpoch &&
            snapshot.meta.writeSequence < idbBox.state.meta.writeSequence
          ) {
            return;
          }
        }
        idbBox.state = JSON.parse(JSON.stringify(snapshot));
        idbBox.commitCount++;
      },
      async clearVaultAtomically(meta) {
        idbBox.state = {
          vault: null,
          syncState: null,
          meta: JSON.parse(JSON.stringify(meta)),
        };
        idbBox.commitCount++;
      },
    };

    SyncService.__setIndexedDBBackendForTests(mockIdbAdapter);

    try {
      const password = 'IdbConsistencyMasterPassword#2026!';
      const salt = generateSaltBase64(16);
      const vaultId = generateVaultId();
      const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

      const payloadV1 = await buildEncryptedVaultPayload(
        key,
        salt,
        [createSampleRecord({ id: 'rec-idb-1', title: 'IDB Record 1' })],
        { vaultId, iterations: TEST_ITERATIONS }
      );

      // 9a. Atomic saveLocalVaultAsync commits both vault and syncState to IndexedDB
      const saveRes = await SyncService.saveLocalVaultAsync(payloadV1, {
        markDirty: true,
        syncedRevision: 3,
      });
      assert.ok(saveRes.writeSequence > 0);
      assert.ok(idbBox.state?.vault);
      assert.equal(idbBox.state?.vault?.vaultId, vaultId);
      assert.equal(idbBox.state?.syncState?.lastSyncedRevision, 3);
      assert.ok(idbBox.commitCount >= 1);

      // 9b. If localStorage is evicted by browser, hydrateFromIndexedDB restores vault & syncState from IndexedDB
      env.localStore.delete(VAULT_STORAGE_KEY);
      env.localStore.delete(SYNC_STATE_STORAGE_KEY);
      assert.equal(SyncService.getLocalVault(), null);

      const hydrated = await SyncService.hydrateFromIndexedDB();
      assert.ok(hydrated);
      assert.equal(hydrated.vaultId, vaultId);
      assert.equal(SyncService.getLocalSyncState().lastSyncedRevision, 3);

      // 9c. Out-of-order stale write with lower writeSequence is ignored by IndexedDB transaction guard
      const currentSeq = idbBox.state!.meta.writeSequence;
      await mockIdbAdapter.writeSnapshotAtomically({
        vault: await buildEncryptedVaultPayload(key, salt, [], {
          vaultId,
          iterations: TEST_ITERATIONS,
        }),
        syncState: SyncService.getLocalSyncState(),
        meta: {
          writeSequence: currentSeq - 1,
          resetEpoch: idbBox.state!.meta.resetEpoch,
          updatedAt: Date.now() - 10000,
        },
      });
      assert.equal(idbBox.state!.vault!.encryptedRecords.length, 1);

      // 9d. Simulated IndexedDB QuotaExceededError surfaces warning without silent success
      simulateIdbTxReject = true;
      const payloadV2 = await buildEncryptedVaultPayload(
        key,
        salt,
        [
          createSampleRecord({ id: 'rec-idb-1', title: 'IDB Record 1' }),
          createSampleRecord({ id: 'rec-idb-2', title: 'IDB Record 2' }),
        ],
        { vaultId, iterations: TEST_ITERATIONS }
      );
      await assert.rejects(
        () => SyncService.saveLocalVaultAsync(payloadV2, { markDirty: true }),
        /QuotaExceededError/
      );
      const warning = SyncService.getLastPersistenceWarning();
      assert.ok(warning);
      assert.equal(warning.code, 'QUOTA_EXCEEDED');
      simulateIdbTxReject = false;
      SyncService.clearPersistenceWarning();

      // 9e. Retry local save succeeds and reconciles IndexedDB
      await SyncService.saveLocalVaultAsync(payloadV2, { markDirty: true });
      assert.equal(idbBox.state!.vault!.encryptedRecords.length, 2);

      // 9f. Vault Reset atomically clears both localStorage and IndexedDB and increments resetEpoch;
      // refreshing (hydrateFromIndexedDB) NEVER resurrects the deleted vault!
      const staleSnapshotBeforeReset = JSON.parse(
        JSON.stringify(idbBox.state)
      ) as AtomicIdbSnapshot;

      await SyncService.clearLocalVaultAsync();
      assert.equal(SyncService.getLocalVault(), null);
      assert.equal(idbBox.state?.vault, null);

      // Even if an in-flight async write from before the reset tries to commit late, resetEpoch blocks it
      await mockIdbAdapter.writeSnapshotAtomically(staleSnapshotBeforeReset);
      assert.equal(idbBox.state?.vault, null);

      const afterResetHydrate = await SyncService.hydrateFromIndexedDB();
      assert.equal(afterResetHydrate, null);
    } finally {
      SyncService.__setIndexedDBBackendForTests(null);
      SyncService.__setSimulatePersistenceFailureForTests(null);
    }
  });

  it('10. P0/P1 Mainland China Network & Privacy: Zero External Favicons, Direct PUT/GET Without HEAD Pre-Probe, Dropped-Response Idempotent Retry, and In-Flight Edit Protection', async () => {
    const sharedDoNamespace = createSqliteDurableObjectNamespace();
    setupSimulatedBrowserEnv({ doNamespace: sharedDoNamespace });

    // 10a. Privacy & Mainland Network Guard: getWebsiteFaviconUrl never returns google.com/s2/favicons
    assert.equal(getWebsiteFaviconUrl('https://github.com'), null);
    assert.equal(getWebsiteFaviconUrl('https://account.apple.com'), null);
    const ghBrand = getBrandAvatarStyle('GitHub Enterprise', 'https://github.com');
    assert.equal(ghBrand.iconId, 'github');
    const alipayBrand = getBrandAvatarStyle('支付宝账户', 'https://alipay.com');
    assert.equal(alipayBrand.iconId, 'alipay');
    assert.equal(alipayBrand.monogram, '支');

    const cfg: CloudflareSyncConfig = {
      workerUrl: TEST_WORKER_URL,
      apiToken: TEST_API_TOKEN,
      rememberToken: false,
      autoSync: true,
      lastSyncedAt: null,
    };

    const password = 'MainlandNetworkResilience#2026!';
    const salt = generateSaltBase64(16);
    const vaultId = generateVaultId();
    const key = await deriveMasterKey(password, salt, TEST_ITERATIONS);

    const rev1Vault = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-cn-1', title: 'Alipay Account' })],
      { vaultId, iterations: TEST_ITERATIONS }
    );

    // Track every HTTP method sent to the Worker
    const observedMethods: string[] = [];
    let dropNextPutResponseAfterServerCommit = false;
    let simulateNextRequestTimeout = false;
    let onDuringInFlightPut: (() => Promise<void>) | null = null;

    Object.defineProperty(globalThis, 'fetch', {
      value: async (
        input: RequestInfo | URL,
        init?: RequestInit
      ): Promise<Response> => {
        const urlStr = typeof input === 'string' ? input : input.toString();
        const req = new Request(urlStr, init);
        observedMethods.push(req.method);

        if (simulateNextRequestTimeout) {
          simulateNextRequestTimeout = false;
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          throw abortErr;
        }

        if (req.method === 'PUT' && onDuringInFlightPut) {
          const hook = onDuringInFlightPut;
          onDuringInFlightPut = null;
          await hook();
        }

        const res = await workerHandler.fetch(req, {
          VAULT_DO: sharedDoNamespace,
          API_TOKEN: TEST_API_TOKEN,
        });

        if (req.method === 'PUT' && dropNextPutResponseAfterServerCommit) {
          dropNextPutResponseAfterServerCommit = false;
          // Server already committed the transaction in SQLite, but mobile network drops response!
          throw new TypeError('Network connection lost while reading response');
        }

        return res;
      },
      configurable: true,
      writable: true,
    });

    // 10b. Initialize cloud vault (POST /api/vault/init)
    const initRes = await SyncService.initializeCloudVault(rev1Vault, cfg, {
      retryBaseDelayMs: 10,
    });
    assert.equal(initRes.ok, true);
    assert.equal(initRes.revision, 1);

    // 10c. Verify pushVault and pullVault execute PUT and GET directly with ZERO mandatory HEAD requests!
    observedMethods.length = 0;
    const rev2Vault = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-cn-1', title: 'Alipay Account' }),
        createSampleRecord({ id: 'rec-cn-2', title: 'WeChat Work' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );

    const directPutRes = await SyncService.pushVault(rev2Vault, cfg, {
      retryBaseDelayMs: 10,
    });
    assert.equal(directPutRes.ok, true);
    assert.equal(directPutRes.revision, 2);
    assert.deepEqual(observedMethods, ['PUT']); // Strictly 1 PUT, 0 HEAD!

    observedMethods.length = 0;
    const directPullRes = await SyncService.pullVault(cfg, {
      retryBaseDelayMs: 10,
    });
    assert.equal(directPullRes.initialized, true);
    assert.equal(directPullRes.revision, 2);
    assert.deepEqual(observedMethods, ['GET']); // Strictly 1 GET, 0 HEAD!

    // 10d. Dropped Response Idempotent Recovery:
    // Server commits Revision #3 on first PUT, but response is lost mid-flight.
    // SyncService automatically retries with the exact same payload-bound mutationId,
    // hits Durable Object idempotency (200 OK, idempotentReplay: true), and converges to Revision #3!
    const rev3Vault = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-cn-1', title: 'Alipay Account' }),
        createSampleRecord({ id: 'rec-cn-2', title: 'WeChat Work' }),
        createSampleRecord({ id: 'rec-cn-3', title: 'ICBC Bank Card' }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    dropNextPutResponseAfterServerCommit = true;
    const idempotentPushRes = await SyncService.pushVault(rev3Vault, cfg, {
      maxRetries: 2,
      retryBaseDelayMs: 10,
    });
    assert.equal(idempotentPushRes.ok, true);
    assert.equal(idempotentPushRes.revision, 3);
    assert.equal(idempotentPushRes.idempotentReplay, true);
    assert.equal(idempotentPushRes.status, 'cloud_synced');

    // 10e. Payload-bound mutationId changes when payload changes, but stays stable when saving identical payload
    SyncService.saveLocalVault(rev3Vault, { markDirty: true, syncedRevision: 3 });
    const mutIdA = SyncService.getLocalSyncState().pendingMutationId;
    assert.ok(mutIdA);
    SyncService.saveLocalVault(rev3Vault, { markDirty: true, syncedRevision: 3 });
    const mutIdSame = SyncService.getLocalSyncState().pendingMutationId;
    assert.equal(mutIdSame, mutIdA);

    const rev4Vault = await buildEncryptedVaultPayload(
      key,
      salt,
      [createSampleRecord({ id: 'rec-cn-4', title: 'Modified Payload' })],
      { vaultId, iterations: TEST_ITERATIONS }
    );
    SyncService.saveLocalVault(rev4Vault, { markDirty: true, syncedRevision: 3 });
    const mutIdDifferent = SyncService.getLocalSyncState().pendingMutationId;
    assert.notEqual(mutIdDifferent, mutIdA);
    assert.notEqual(
      computePayloadContentSignature(rev3Vault),
      computePayloadContentSignature(rev4Vault)
    );

    // 10f. In-flight edit protection: If user edits local vault while PUT is in flight,
    // completion of the in-flight PUT updates lastSyncedRevision to 4 but keeps status = 'sync_pending'
    // so the newer local edit is NEVER marked as already synced!
    const rev5LocalEditDuringFlight = await buildEncryptedVaultPayload(
      key,
      salt,
      [
        createSampleRecord({ id: 'rec-cn-4', title: 'Modified Payload' }),
        createSampleRecord({
          id: 'rec-cn-5',
          title: 'Edited While Upload In Flight',
        }),
      ],
      { vaultId, iterations: TEST_ITERATIONS }
    );

    onDuringInFlightPut = async () => {
      SyncService.saveLocalVault(rev5LocalEditDuringFlight, {
        markDirty: true,
      });
    };

    const inFlightRes = await SyncService.pushVault(rev4Vault, cfg, {
      maxRetries: 0,
    });
    assert.equal(inFlightRes.ok, true);
    assert.equal(inFlightRes.revision, 4);
    assert.equal(inFlightRes.status, 'sync_pending');
    assert.notEqual(SyncService.getLocalSyncState().dirtySince, null);
    assert.ok(SyncService.getLocalSyncState().pendingMutationId);

    // Pushing the newer edit now succeeds as Revision #5
    const pushNewerEditRes = await SyncService.pushVault(
      rev5LocalEditDuringFlight,
      cfg,
      { maxRetries: 0 }
    );
    assert.equal(pushNewerEditRes.ok, true);
    assert.equal(pushNewerEditRes.revision, 5);
    assert.equal(pushNewerEditRes.status, 'cloud_synced');

    // 10g. Request timeout (AbortError) with maxRetries: 0 classifies as 'timeout' and preserves local data
    simulateNextRequestTimeout = true;
    const timeoutRes = await SyncService.pushVault(
      rev5LocalEditDuringFlight,
      cfg,
      { maxRetries: 0, timeoutMs: 500 }
    );
    assert.equal(timeoutRes.ok, false);
    assert.equal(timeoutRes.status, 'offline');
    assert.equal(timeoutRes.errorCategory, 'timeout');
    assert.ok(SyncService.getLocalVault());
  });
});

