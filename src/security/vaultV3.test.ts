import { beforeEach, afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { IDBFactory } from 'fake-indexeddb';
import {
  buildEncryptedVaultPayload, deriveMasterKey, generateSaltBase64,
  rotateVaultMasterPassword, unlockEncryptedVaultPayload, validateV2VaultEnvelopeStructure,
} from '../crypto/cryptoEngine';
import { SyncService, VAULT_STORAGE_KEY, LocalVaultConflictError } from '../services/syncService';
import worker from '../../worker/src/index';
import { VaultDurableObject, type DurableObjectStateLike } from '../../worker/src/VaultDurableObject';
import type { DecryptedVaultRecord, EncryptedVaultPayload } from '../types/vault';

const legacy = JSON.parse(readFileSync(new URL('../../tests/fixtures/v2-vault.json', import.meta.url), 'utf8')) as EncryptedVaultPayload;
const password = 'V3-Synthetic-Master#2026!';
const record: DecryptedVaultRecord = { id: 'synthetic-v3-record', recordType: 'login', title: 'V3 账号',
  username: 'synthetic@example.invalid', password: 'Synthetic-record-only!', url: 'https://example.invalid',
  category: 'work', notes: '加密测试', favorite: false, createdAt: 1700000000000, updatedAt: 1700000000000 };

async function createVault(records = [record]) {
  const salt = generateSaltBase64();
  const key = await deriveMasterKey(password, salt, 100_000);
  const payload = await buildEncryptedVaultPayload(key, salt, records, { iterations: 100_000 });
  return { key, salt, payload };
}

function sqliteState(db: DatabaseSync): DurableObjectStateLike {
  return { storage: {
    sql: { exec(query, ...bindings) {
      const statement = db.prepare(query);
      if (/^\s*SELECT\b/i.test(query)) return { toArray: () => statement.all(...bindings as never[]) };
      statement.run(...bindings as never[]);
      return { toArray: () => [] };
    } },
    transactionSync<T>(operation: () => T): T {
      db.exec('BEGIN IMMEDIATE');
      try { const result = operation(); db.exec('COMMIT'); return result; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    },
  } };
}

let storage: Map<string, string>;
const originalFetch = globalThis.fetch;
beforeEach(async () => {
  await SyncService.flushPendingPersistence().catch(() => undefined);
  SyncService.__setIndexedDBBackendForTests(null);
  SyncService.__setSimulatePersistenceFailureForTests(null);
  storage = new Map();
  const makeStorage = (map: Map<string, string>) => ({
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => { map.set(key, value); },
    removeItem: (key: string) => { map.delete(key); },
  });
  Object.defineProperty(globalThis, 'indexedDB', { value: new IDBFactory(), configurable: true });
  Object.defineProperty(globalThis, 'window', { value: {
    crypto: globalThis.crypto, localStorage: makeStorage(storage), sessionStorage: makeStorage(new Map()),
    addEventListener() {}, removeEventListener() {},
  }, configurable: true });
});
afterEach(async () => {
  await SyncService.flushPendingPersistence().catch(() => undefined);
  globalThis.fetch = originalFetch;
  delete (globalThis as Record<string, unknown>).window;
  delete (globalThis as Record<string, unknown>).indexedDB;
});

describe('V3 authenticated snapshots and V2 migration', () => {
  it('opens a frozen V2 backup and migrates all records without changing the master password or vault identity', async () => {
    const old = await unlockEncryptedVaultPayload(legacy, 'LegacyFixture#2026!');
    assert.equal(old.records[0].title, '旧版中文账号');
    const upgraded = await buildEncryptedVaultPayload(old.key, legacy.kdf.salt, old.records, {
      vaultId: legacy.vaultId, previousPayload: legacy, categories: old.categories, iterations: legacy.kdf.iterations,
      createdAt: legacy.createdAt,
    });
    const reopened = await unlockEncryptedVaultPayload(upgraded, 'LegacyFixture#2026!');
    assert.equal(upgraded.formatVersion, 3);
    assert.equal(upgraded.vaultId, legacy.vaultId);
    assert.equal(upgraded.createdAt, legacy.createdAt);
    assert.deepEqual(reopened.records, old.records);
    assert.deepEqual(reopened.categories, old.categories);
  });

  it('rejects deletion, insertion, duplication, reordering, old-record splicing and envelope edits', async () => {
    const { key, salt, payload } = await createVault([record, { ...record, id: 'second' }]);
    const newer = await buildEncryptedVaultPayload(key, salt, [{ ...record, title: 'changed' }, { ...record, id: 'second' }], {
      vaultId: payload.vaultId, previousPayload: payload, iterations: 100_000,
    });
    const variants = [
      { ...newer, encryptedRecords: [] },
      { ...newer, encryptedRecords: newer.encryptedRecords.slice(1) },
      { ...newer, encryptedRecords: [...newer.encryptedRecords, payload.encryptedRecords[0]] },
      { ...newer, encryptedRecords: [...newer.encryptedRecords].reverse() },
      { ...newer, encryptedRecords: [payload.encryptedRecords[0], newer.encryptedRecords[1]] },
      { ...newer, updatedAt: '2026-01-01T00:00:00.000Z' },
      { ...newer, createdAt: '2026-01-01T00:00:00.000Z' },
      { ...newer, snapshotSequence: 999 },
      { ...newer, encryptedMetadata: payload.encryptedMetadata },
      { ...newer, integrity: undefined },
      { ...newer, formatVersion: 2 as const, integrity: undefined, snapshotSequence: undefined },
    ];
    const stripped = { ...newer, formatVersion: 2 as const };
    delete stripped.integrity;
    delete stripped.snapshotSequence;
    variants.push(stripped);
    for (const candidate of variants) await assert.rejects(unlockEncryptedVaultPayload(candidate, key));
    // JSON object formatting and object-key order do not invalidate an authentic snapshot.
    const reorderedKeys = Object.fromEntries(Object.entries(newer).reverse());
    assert.equal((await unlockEncryptedVaultPayload(reorderedKeys, key)).records[0].title, 'changed');
  });

  it('authenticates empty vaults and advances the snapshot sequence during key rotation', async () => {
    const { payload } = await createVault([]);
    assert.equal((await unlockEncryptedVaultPayload(payload, password)).records.length, 0);
    const rotated = await rotateVaultMasterPassword(payload, password, 'New-Synthetic-Master#2026!', 100_000);
    assert.equal(rotated.newPayload.snapshotSequence, payload.snapshotSequence! + 1);
    await assert.rejects(unlockEncryptedVaultPayload(rotated.newPayload, password));
    assert.equal((await unlockEncryptedVaultPayload(rotated.newPayload, rotated.newKey)).records.length, 0);
  });
});

describe('IndexedDB transaction compare-and-swap persistence', () => {
  it('permits only one of two independent tabs to replace the same base snapshot', async () => {
    const { key, salt, payload } = await createVault();
    await SyncService.saveLocalVaultAsync(payload, { expectedPayload: null });
    const otherTab = await import(new URL(`../services/syncService.ts?tab=${crypto.randomUUID()}`, import.meta.url).href);
    const makeEdit = (title: string) => buildEncryptedVaultPayload(key, salt, [{ ...record, title }], {
      vaultId: payload.vaultId, previousPayload: payload, iterations: 100_000,
    });
    const [first, second] = await Promise.all([makeEdit('first writer'), makeEdit('second writer')]);
    const results = await Promise.allSettled([
      SyncService.saveLocalVaultAsync(first, { expectedPayload: payload }),
      otherTab.SyncService.saveLocalVaultAsync(second, { expectedPayload: payload }),
    ]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(results.filter((result) => result.status === 'rejected' && result.reason.name === 'LocalVaultConflictError').length, 1);
    const persisted = await SyncService.hydrateFromIndexedDB();
    const winner = await unlockEncryptedVaultPayload(persisted, key);
    assert.ok(['first writer', 'second writer'].includes(winner.records[0].title));
  });

  it('does not change the mirror or backup if a transaction aborts, and can retry the same candidate', async () => {
    const { key, salt, payload } = await createVault();
    await SyncService.saveLocalVaultAsync(payload, { expectedPayload: null });
    const candidate = await buildEncryptedVaultPayload(key, salt, [], { previousPayload: payload, iterations: 100_000 });
    const { IDBDatabase } = await import('fake-indexeddb');
    const original = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function (...args: Parameters<typeof original>) {
      const transaction = original.apply(this, args);
      if (args[1] === 'readwrite') queueMicrotask(() => transaction.abort());
      return transaction;
    };
    try {
      await assert.rejects(SyncService.saveLocalVaultAsync(candidate, { expectedPayload: payload, rollbackBackup: payload }));
      assert.deepEqual(JSON.parse(storage.get(VAULT_STORAGE_KEY)!), payload);
      assert.equal(SyncService.getRollbackBackup(), null);
    } finally { IDBDatabase.prototype.transaction = original; }
    assert.deepEqual(await SyncService.hydrateFromIndexedDB(), payload);
    await SyncService.saveLocalVaultAsync(candidate, { expectedPayload: payload, rollbackBackup: payload });
    assert.deepEqual(await SyncService.hydrateFromIndexedDB(), candidate);
  });

  it('commits the original V2 backup together with its V3 upgrade and survives mirror eviction', async () => {
    const old = await unlockEncryptedVaultPayload(legacy, 'LegacyFixture#2026!');
    await SyncService.saveLocalVaultAsync(legacy, { expectedPayload: null });
    const upgraded = await buildEncryptedVaultPayload(old.key, legacy.kdf.salt, old.records, {
      previousPayload: legacy, categories: old.categories, iterations: legacy.kdf.iterations, createdAt: legacy.createdAt,
    });
    await SyncService.saveLocalVaultAsync(upgraded, { expectedPayload: legacy, legacyBackup: legacy, rollbackBackup: legacy });
    assert.deepEqual(await SyncService.getLegacyBackup(), legacy);
    storage.clear();
    assert.deepEqual(await SyncService.hydrateFromIndexedDB(), upgraded);
    assert.deepEqual(await SyncService.getLegacyBackup(), legacy);
  });

  it('rejects confirming a staged pull after a local edit and rejects queued writes after reset', async () => {
    const { key, salt, payload } = await createVault();
    await SyncService.saveLocalVaultAsync(payload, { expectedPayload: null });
    const staged = await SyncService.verifyAndStageRemotePull({ remotePayload: payload, remoteRevision: 2, currentMemoryKey: key, currentMemorySalt: salt });
    const edited = await buildEncryptedVaultPayload(key, salt, [], { previousPayload: payload, iterations: 100_000 });
    await SyncService.saveLocalVaultAsync(edited, { expectedPayload: payload });
    await assert.rejects(SyncService.commitVerifiedRemotePull(staged), LocalVaultConflictError);
    assert.deepEqual(await SyncService.hydrateFromIndexedDB(), edited);
    await SyncService.clearLocalVaultAsync();
    await assert.rejects(SyncService.saveLocalVaultAsync(payload, { expectedPayload: edited }), LocalVaultConflictError);
    assert.equal(await SyncService.hydrateFromIndexedDB(), null);
  });
});

describe('Worker V3 rollout and device checkpoints', () => {
  it('migrates the existing SQLite constraint, preserves V2 data and rejects later format downgrade', async () => {
    const db = new DatabaseSync(':memory:');
    db.exec(`CREATE TABLE vault_state (
      singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1), vault_id TEXT NOT NULL,
      revision INTEGER NOT NULL CHECK (revision >= 1), format_version INTEGER NOT NULL CHECK (format_version = 2),
      ciphertext_json TEXT NOT NULL, content_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`);
    db.prepare('INSERT INTO vault_state VALUES (1, ?, 7, 2, ?, ?, ?, ?)').run(legacy.vaultId, JSON.stringify(legacy), 'legacy-hash', legacy.createdAt, legacy.updatedAt);
    const object = new VaultDurableObject(sqliteState(db));
    const before = await (await object.fetch(new Request('https://test.invalid/api/vault'))).json();
    assert.equal(before.revision, 7);
    assert.deepEqual(before.vault, legacy);
    const old = await unlockEncryptedVaultPayload(legacy, 'LegacyFixture#2026!');
    const upgraded = await buildEncryptedVaultPayload(old.key, legacy.kdf.salt, old.records, { previousPayload: legacy, iterations: legacy.kdf.iterations });
    const put = (vault: EncryptedVaultPayload, expectedRevision: number) => object.fetch(new Request('https://test.invalid/api/vault', {
      method: 'PUT', body: JSON.stringify({ protocolVersion: 2, vaultId: vault.vaultId, expectedRevision, mutationId: crypto.randomUUID(), vault }),
    }));
    assert.equal((await put(upgraded, 7)).status, 200);
    assert.equal(db.prepare('SELECT format_version FROM vault_state').get()!.format_version, 3);
    const downgrade = await put(legacy, 8);
    assert.equal(downgrade.status, 409);
    assert.equal((await downgrade.json()).code, 'FORMAT_DOWNGRADE');
    db.close();
  });

  it('rebases a competing V3 device edit with a fresh authenticated sequence', async () => {
    const { payload, key, salt } = await createVault();
    const db = new DatabaseSync(':memory:');
    const object = new VaultDurableObject(sqliteState(db));
    const config = { workerUrl: 'https://fork.example.invalid', apiToken: 'synthetic-fork-token-only-2026', rememberToken: false, autoSync: false, lastSyncedAt: null };
    globalThis.fetch = async (input, init) => worker.fetch(new Request(String(input), init), {
      API_TOKEN: config.apiToken,
      VAULT_DO: { idFromName: (name: string) => ({ toString: () => name }), get: () => ({ fetch: (request: Request) => object.fetch(request) }) },
    });
    await SyncService.saveLocalVaultAsync(payload, { expectedPayload: null });
    await SyncService.initializeCloudVault(payload, config);
    const deviceA = await buildEncryptedVaultPayload(key, salt, [{ ...record, title: 'device A' }], { previousPayload: payload, iterations: 100_000 });
    const deviceB = await buildEncryptedVaultPayload(key, salt, [{ ...record, title: 'device B' }], { previousPayload: payload, iterations: 100_000 });
    await SyncService.saveLocalVaultAsync(deviceA, { expectedPayload: payload });
    assert.equal((await SyncService.pushVault(deviceA, config)).revision, 2);
    // A second device has an independent browser database and the original cloud baseline.
    Object.defineProperty(globalThis, 'indexedDB', { value: new IDBFactory(), configurable: true });
    const deviceStorage = new Map<string, string>();
    Object.defineProperty(window, 'localStorage', { value: {
      getItem: (key: string) => deviceStorage.get(key) ?? null,
      setItem: (key: string, value: string) => { deviceStorage.set(key, value); },
      removeItem: (key: string) => { deviceStorage.delete(key); },
    } as Storage, configurable: true });
    const other = await import(new URL(`../services/syncService.ts?device=${crypto.randomUUID()}`, import.meta.url).href);
    await other.SyncService.saveLocalVaultAsync(deviceB, { expectedPayload: null, syncedRevision: 1 });
    assert.equal((await other.SyncService.pushVault(deviceB, config)).status, 'conflict');
    const resolved = await other.SyncService.resolveConflict({ resolution: 'keep_local_and_push', config, currentMemoryKey: key, currentMemorySalt: salt });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.localPayload.snapshotSequence, 3);
    const current = await (await object.fetch(new Request('https://fork.example.invalid/api/vault'))).json();
    assert.equal(current.revision, 3);
    assert.equal((await unlockEncryptedVaultPayload(current.vault, key)).records[0].title, 'device B');
    db.close();
  });

  it('rejects a signed older snapshot even when a server invents a larger revision, while preserving a local offline edit', async () => {
    const { payload, key, salt } = await createVault();
    const db = new DatabaseSync(':memory:');
    const object = new VaultDurableObject(sqliteState(db));
    const config = { workerUrl: 'https://checkpoint.example.invalid', apiToken: 'synthetic-checkpoint-token-only', rememberToken: false, autoSync: false, lastSyncedAt: null };
    globalThis.fetch = async (input, init) => worker.fetch(new Request(String(input), init), {
      API_TOKEN: config.apiToken,
      VAULT_DO: { idFromName: (name: string) => ({ toString: () => name }), get: () => ({ fetch: (request: Request) => object.fetch(request) }) },
    });
    await SyncService.saveLocalVaultAsync(payload, { expectedPayload: null });
    assert.equal((await SyncService.initializeCloudVault(payload, config)).ok, true);
    const newer = await buildEncryptedVaultPayload(key, salt, [{ ...record, title: 'remote generation two' }], { previousPayload: payload, iterations: 100_000 });
    await SyncService.saveLocalVaultAsync(newer, { expectedPayload: payload });
    assert.equal((await SyncService.pushVault(newer, config)).ok, true);
    const offline = await buildEncryptedVaultPayload(key, salt, [{ ...record, title: 'unsynced generation three' }], { previousPayload: newer, iterations: 100_000 });
    await SyncService.saveLocalVaultAsync(offline, { expectedPayload: newer });
    // A still-current remote generation two can be staged as a conflict with an offline edit.
    const staged = await SyncService.verifyAndStageRemotePull({ remotePayload: newer, remoteRevision: 2, currentMemoryKey: key, currentMemorySalt: salt });
    assert.equal(staged.hasConflictWithLocal, true);
    await assert.rejects(SyncService.verifyAndStageRemotePull({ remotePayload: payload, remoteRevision: 9999, currentMemoryKey: key, currentMemorySalt: salt }), /旧快照|降级/);
    assert.deepEqual(await SyncService.hydrateFromIndexedDB(), offline);
    const restored = await SyncService.restoreCloudHistorySnapshot({ revision: 1, config, currentMemoryKey: key, currentMemorySalt: salt });
    assert.equal(restored.payload.snapshotSequence, offline.snapshotSequence! + 1);
    assert.equal(restored.newCloudRevision, 3);
    assert.equal((await unlockEncryptedVaultPayload(restored.payload, key)).records[0].title, record.title);
    db.close();
  });
});
