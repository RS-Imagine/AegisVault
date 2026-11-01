import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { matchRecordsForAndroidTarget } from '../services/nativePlatformBridge';
import { computePayloadContentSignature } from '../services/syncService';
import { buildEncryptedVaultPayload, deriveMasterKey, generateSaltBase64, validateV2VaultEnvelopeStructure } from '../crypto/cryptoEngine';
import { validateV2VaultPayload } from '../../worker/src/payloadValidator';
import { VaultDurableObject, type DurableObjectStateLike } from '../../worker/src/VaultDurableObject';
import { generateStrongPassword } from '../utils/passwordGenerator';
import { timingSafeEqualStrings } from '../../worker/src/bearerAuth';
import type { DecryptedVaultRecord } from '../types/vault';

const record: DecryptedVaultRecord = {
  id: 'regression-record', recordType: 'login', title: 'Bank',
  username: 'synthetic@example.invalid', password: 'Synthetic-only!',
  url: 'https://bank.example.com', category: 'work', notes: '',
  favorite: false, createdAt: 1, updatedAt: 1,
};

describe('Security regression coverage', () => {
  it('authenticates exact tokens and rejects empty, partial and modified tokens', async () => {
    const expected = 'synthetic-regression-token-only';
    assert.equal(await timingSafeEqualStrings(expected, expected), true);
    for (const supplied of ['', expected.slice(1), `${expected}x`, expected.toUpperCase()]) {
      assert.equal(await timingSafeEqualStrings(supplied, expected), false);
    }
  });
  it('autofill requires an exact web host or explicit Android package association', () => {
    assert.equal(matchRecordsForAndroidTarget([record], { domain: 'bank.example.com' }).length, 1);
    for (const domain of ['example.com', 'evil.bank.example.com', 'bank.example.com.evil.invalid']) {
      assert.deepEqual(matchRecordsForAndroidTarget([record], { domain }), []);
    }
    const packageRecord = { ...record, url: 'android://com.example.bank' };
    assert.equal(matchRecordsForAndroidTarget([packageRecord], { androidPackageName: 'com.example.bank' }).length, 1);
    for (const candidate of [record, { ...record, title: '' }, { ...record, url: 'https://evil.invalid/com.example.bank' }]) {
      assert.deepEqual(matchRecordsForAndroidTarget([candidate], {
        androidPackageName: 'com.example.bank.evil', domain: 'bank.example.com',
      }), []);
    }
  });

  it('rejects plaintext extension fields at every encrypted envelope boundary', async () => {
    const salt = generateSaltBase64();
    const key = await deriveMasterKey('Synthetic-regression-master!', salt, 100_000);
    const payload = await buildEncryptedVaultPayload(key, salt, [record], { iterations: 100_000 });
    assert.equal(validateV2VaultEnvelopeStructure(payload).valid, true);
    assert.equal(validateV2VaultPayload(payload).valid, true);
    const variants = [
      { ...payload, password: 'plaintext' },
      { ...payload, categories: ['private'] },
      { ...payload, kdf: { ...payload.kdf, masterPassword: 'plaintext' } },
      { ...payload, cipher: { ...payload.cipher, derivedKey: 'plaintext' } },
      { ...payload, verifier: { ...payload.verifier, password: 'plaintext' } },
      { ...payload, encryptedMetadata: { ...payload.encryptedMetadata, categories: ['private'] } },
      { ...payload, encryptedRecords: [{ ...payload.encryptedRecords[0], password: 'plaintext' }] },
    ];
    for (const candidate of variants) {
      assert.equal(validateV2VaultEnvelopeStructure(candidate).valid, false);
      assert.equal(validateV2VaultPayload(candidate).valid, false);
    }
    assert.notEqual(computePayloadContentSignature(payload), computePayloadContentSignature({
      ...payload, updatedAt: '2026-11-01T00:00:00.000Z',
    }));
  });

  it('stops reading and cancels an oversized chunked upload before buffering the rest', async () => {
    const state: DurableObjectStateLike = {
      storage: {
        sql: { exec: () => ({ toArray: () => [] }) },
        transactionSync: () => { throw new Error('Oversized uploads must not enter a transaction'); },
      },
    };
    const vault = new VaultDurableObject(state);
    let pulls = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        assert.ok(pulls <= 3, 'Reader continued past the size limit');
        controller.enqueue(new Uint8Array(600_000));
      },
      cancel() { cancelled = true; },
    });
    const request = new Request('https://vault.example.invalid/api/vault/init', {
      method: 'POST', body, duplex: 'half',
    } as RequestInit & { duplex: string });
    const response = await vault.fetch(request);
    assert.equal(response.status, 413);
    assert.equal(cancelled, true);
    assert.ok(pulls <= 3);
  });

  it('generates bounded passwords and includes every selected character class', () => {
    for (const length of [6, 20, 64, Number.NaN, Infinity]) {
      const value = generateStrongPassword({ length, uppercase: true, lowercase: true, numbers: true, symbols: true });
      assert.ok(value.length >= 6 && value.length <= 64);
      assert.match(value, /[A-Z]/);
      assert.match(value, /[a-z]/);
      assert.match(value, /[0-9]/);
      assert.match(value, /[^a-zA-Z0-9]/);
    }
  });

  it('does not activate an incomplete offline shell when precaching fails', async () => {
    const listeners: Record<string, (event: unknown) => void> = {};
    let activated = false;
    vm.runInNewContext(readFileSync(new URL('../../public/sw.js', import.meta.url), 'utf8'), {
      URL, Request,
      self: {
        location: { href: 'https://vault.example.invalid/sw.js' },
        registration: { scope: 'https://vault.example.invalid/', active: null },
        addEventListener: (type: string, listener: (event: unknown) => void) => { listeners[type] = listener; },
        skipWaiting: async () => { activated = true; },
      },
      caches: { open: async () => ({ addAll: async () => { throw new Error('Asset unavailable'); } }) },
    });
    let installation: Promise<void> | undefined;
    listeners.install({ waitUntil: (promise: Promise<void>) => { installation = promise; } });
    await assert.rejects(installation!, /Asset unavailable/);
    assert.equal(activated, false);
  });
});
