/**
 * V3 authenticates the entire encrypted envelope, including record order and
 * snapshot sequence. Versioned AAD keeps V2 readable and prevents stripping a
 * V3 integrity tag to downgrade its ciphertext to V2. Keys stay non-extractable.
 */

import {
  DEFAULT_CATEGORIES,
  DecryptedVaultMetadata,
  DecryptedVaultRecord,
  EncryptedBlob,
  EncryptedVaultPayload,
  EncryptedVaultRecord,
  RecordType,
  VaultCategoryItem,
} from '../types/vault';
import {
  sanitizeCategoriesList,
  syncCategoriesWithRecords,
} from '../utils/categoryManager';
import { canonicalJson, findUnexpectedEnvelopeField } from '../../shared/vaultEnvelopeSchema';

export const VAULT_FORMAT_VERSION = 3 as const;
export type VaultFormatVersion = 2 | 3;
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const MIN_PBKDF2_ITERATIONS = 100_000;
export const MAX_PBKDF2_ITERATIONS = 2_000_000;

const SALT_BYTE_LENGTH = 16; // 128-bit salt
const IV_BYTE_LENGTH = 12; // 96-bit IV recommended by NIST SP 800-38D for AES-GCM
const AUTH_TAG_BIT_LENGTH = 128;
const VERIFIER_MAGIC_TEXT = 'AEGIS_VAULT_V2_ZERO_KNOWLEDGE_VERIFIER_OK';
const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;

function getCrypto(): Crypto {
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  return globalThis.crypto;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  if (
    typeof base64 !== 'string' ||
    base64.length === 0 ||
    base64.length % 4 !== 0 ||
    !BASE64_REGEX.test(base64)
  ) {
    throw new Error('无效的 Base64 密文编码格式');
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function generateSaltBase64(byteLength: number = SALT_BYTE_LENGTH): string {
  const salt = new Uint8Array(byteLength);
  getCrypto().getRandomValues(salt);
  return bytesToBase64(salt);
}

export function generateVaultId(): string {
  const c = getCrypto();
  if (typeof c.randomUUID === 'function') {
    return c.randomUUID();
  }
  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function buildVerifierAAD(
  vaultId: string,
  iterations: number,
  saltBase64: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Uint8Array {
  return new TextEncoder().encode(
    `aegis-v${formatVersion}:verifier:${vaultId}:${formatVersion}:${iterations}:${saltBase64}`
  );
}

export function buildMetadataAAD(vaultId: string, formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION): Uint8Array {
  return new TextEncoder().encode(
    `aegis-v${formatVersion}:metadata:${vaultId}:${formatVersion}`
  );
}

export function buildRecordAAD(
  vaultId: string,
  recordId: string,
  recordType: RecordType,
  createdAt: number,
  updatedAt: number,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Uint8Array {
  return new TextEncoder().encode(
    `aegis-v${formatVersion}:record:${vaultId}:${formatVersion}:${recordId}:${recordType}:${createdAt}:${updatedAt}`
  );
}

/**
 * Derives a non-extractable 256-bit AES-GCM CryptoKey from the user's Master Password.
 */
export async function deriveMasterKey(
  masterPassword: string,
  saltBase64: string,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  if (!masterPassword || typeof masterPassword !== 'string') {
    throw new Error('主密码不能为空');
  }
  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new Error(
      `PBKDF2 迭代次数超出安全范围 (${MIN_PBKDF2_ITERATIONS} ~ ${MAX_PBKDF2_ITERATIONS})`
    );
  }

  const salt = base64ToBytes(saltBase64);
  if (salt.byteLength < SALT_BYTE_LENGTH) {
    throw new Error('KDF 盐值长度不足 128-bit (16 字节)');
  }

  const cryptoObj = getCrypto();
  const encoder = new TextEncoder();
  const passwordKey = await cryptoObj.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return cryptoObj.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a UTF-8 string using AES-256-GCM with Additional Authenticated Data (AAD).
 */
export async function encryptStringWithAAD(
  plaintext: string,
  key: CryptoKey,
  aad?: Uint8Array
): Promise<EncryptedBlob> {
  const cryptoObj = getCrypto();
  const iv = new Uint8Array(IV_BYTE_LENGTH);
  cryptoObj.getRandomValues(iv);
  const encoded = new TextEncoder().encode(plaintext);

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as BufferSource,
    tagLength: AUTH_TAG_BIT_LENGTH,
  };
  if (aad) {
    algorithm.additionalData = aad as BufferSource;
  }

  const ciphertextBuffer = await cryptoObj.subtle.encrypt(
    algorithm,
    key,
    encoded as BufferSource
  );

  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
  };
}

/**
 * Decrypts an EncryptedBlob using AES-256-GCM with Additional Authenticated Data (AAD).
 */
export async function decryptStringWithAAD(
  blob: EncryptedBlob,
  key: CryptoKey,
  aad?: Uint8Array
): Promise<string> {
  if (!blob || typeof blob.iv !== 'string' || typeof blob.ciphertext !== 'string') {
    throw new Error('密文块结构缺失');
  }
  const iv = base64ToBytes(blob.iv);
  if (iv.byteLength !== IV_BYTE_LENGTH) {
    throw new Error('AES-GCM IV 长度必须为 12 字节');
  }
  const ciphertext = base64ToBytes(blob.ciphertext);
  if (ciphertext.byteLength < 16) {
    throw new Error('AES-GCM 密文长度不足 128-bit 认证标签');
  }

  const algorithm: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as BufferSource,
    tagLength: AUTH_TAG_BIT_LENGTH,
  };
  if (aad) {
    algorithm.additionalData = aad as BufferSource;
  }

  const decryptedBuffer = await getCrypto().subtle.decrypt(
    algorithm,
    key,
    ciphertext as BufferSource
  );

  return new TextDecoder().decode(decryptedBuffer);
}

export async function createVaultVerifier(
  key: CryptoKey,
  vaultId: string,
  iterations: number,
  saltBase64: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<EncryptedBlob> {
  const aad = buildVerifierAAD(vaultId, iterations, saltBase64, formatVersion);
  return encryptStringWithAAD(VERIFIER_MAGIC_TEXT, key, aad);
}

export async function verifyVaultKey(
  verifier: EncryptedBlob,
  key: CryptoKey,
  vaultId: string,
  iterations: number,
  saltBase64: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<boolean> {
  try {
    const aad = buildVerifierAAD(vaultId, iterations, saltBase64, formatVersion);
    const result = await decryptStringWithAAD(verifier, key, aad);
    return result === VERIFIER_MAGIC_TEXT;
  } catch {
    return false;
  }
}

export async function encryptVaultMetadata(
  categories: VaultCategoryItem[],
  key: CryptoKey,
  vaultId: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<EncryptedBlob> {
  const metadata: DecryptedVaultMetadata = {
    categories: sanitizeCategoriesList(categories),
    updatedAt: Date.now(),
  };
  const aad = buildMetadataAAD(vaultId, formatVersion);
  return encryptStringWithAAD(JSON.stringify(metadata), key, aad);
}

export async function decryptVaultMetadata(
  encryptedMetadata: EncryptedBlob,
  key: CryptoKey,
  vaultId: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<DecryptedVaultMetadata> {
  const aad = buildMetadataAAD(vaultId, formatVersion);
  const json = await decryptStringWithAAD(encryptedMetadata, key, aad);
  const parsed = JSON.parse(json) as Partial<DecryptedVaultMetadata>;
  if (!parsed || !Array.isArray(parsed.categories)) {
    throw new Error('加密元数据缺少 categories 列表');
  }
  return {
    categories: sanitizeCategoriesList(parsed.categories),
    updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : Date.now(),
  };
}

export async function encryptVaultRecord(
  record: DecryptedVaultRecord,
  key: CryptoKey,
  vaultId: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<EncryptedVaultRecord> {
  const recordType: RecordType =
    record.recordType || (record.category === 'bank-card' ? 'card' : 'login');
  const createdAt = typeof record.createdAt === 'number' ? record.createdAt : Date.now();
  const updatedAt = typeof record.updatedAt === 'number' ? record.updatedAt : Date.now();

  const normalizedRecord: DecryptedVaultRecord = {
    ...record,
    recordType,
    createdAt,
    updatedAt,
  };

  const aad = buildRecordAAD(vaultId, record.id, recordType, createdAt, updatedAt, formatVersion);
  const blob = await encryptStringWithAAD(JSON.stringify(normalizedRecord), key, aad);

  return {
    id: record.id,
    recordType,
    iv: blob.iv,
    ciphertext: blob.ciphertext,
    createdAt,
    updatedAt,
  };
}

export async function decryptVaultRecord(
  encryptedRecord: EncryptedVaultRecord,
  key: CryptoKey,
  vaultId: string,
  formatVersion: VaultFormatVersion = VAULT_FORMAT_VERSION
): Promise<DecryptedVaultRecord> {
  const recordType: RecordType = encryptedRecord.recordType || 'login';
  const aad = buildRecordAAD(
    vaultId,
    encryptedRecord.id,
    recordType,
    encryptedRecord.createdAt,
    encryptedRecord.updatedAt,
    formatVersion
  );
  const json = await decryptStringWithAAD(
    { iv: encryptedRecord.iv, ciphertext: encryptedRecord.ciphertext },
    key,
    aad
  );
  const parsed = JSON.parse(json) as DecryptedVaultRecord;
  if (!parsed || typeof parsed !== 'object' || parsed.id !== encryptedRecord.id) {
    throw new Error('记录完整性校验失败：密文内嵌 ID 与外层信封不一致');
  }
  return parsed;
}

/**
 * Validates a V2 or V3 envelope before decryption or storage.
 * The historical export name is retained for existing callers.
 * Rejects V1 payloads (`version: 1`) or payloads containing plaintext fields.
 */
export function validateV2VaultEnvelopeStructure(
  candidate: unknown
): { valid: boolean; reason?: string; payload?: EncryptedVaultPayload } {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return { valid: false, reason: '密码库密文必须是 JSON 对象' };
  }

  const obj = candidate as Record<string, unknown>;
  if ('version' in obj && !('formatVersion' in obj)) {
    return {
      valid: false,
      reason: '不再支持旧版 V1 密码库格式，请使用 AegisVault V2 格式 (formatVersion: 2)',
    };
  }
  const unexpectedField = findUnexpectedEnvelopeField(obj);
  if (unexpectedField) {
    return { valid: false, reason: `密文信封包含未允许字段：${unexpectedField}` };
  }

  if (obj.formatVersion !== 2 && obj.formatVersion !== 3) {
    return {
      valid: false,
      reason: `不支持的密码库版本 formatVersion: ${String(obj.formatVersion)} (支持版本 2 和 3)`,
    };
  }

  if (
    typeof obj.vaultId !== 'string' ||
    obj.vaultId.trim().length < 16 ||
    obj.vaultId.length > 64
  ) {
    return { valid: false, reason: '缺少有效的独立密码库标识 vaultId' };
  }

  if (typeof obj.createdAt !== 'string' || typeof obj.updatedAt !== 'string' ||
      !Number.isFinite(Date.parse(obj.createdAt)) || !Number.isFinite(Date.parse(obj.updatedAt))) {
    return { valid: false, reason: '缺少 createdAt 或 updatedAt 时间戳' };
  }

  if (!obj.kdf || typeof obj.kdf !== 'object' || Array.isArray(obj.kdf)) {
    return { valid: false, reason: '缺少 KDF 密钥派生参数' };
  }
  const kdf = obj.kdf as Record<string, unknown>;
  if (kdf.algorithm !== 'PBKDF2-HMAC-SHA256' || kdf.hash !== 'SHA-256') {
    return { valid: false, reason: '不支持的 KDF 算法，必须为 PBKDF2-HMAC-SHA256' };
  }
  if (
    typeof kdf.iterations !== 'number' ||
    !Number.isInteger(kdf.iterations) ||
    kdf.iterations < MIN_PBKDF2_ITERATIONS ||
    kdf.iterations > MAX_PBKDF2_ITERATIONS
  ) {
    return {
      valid: false,
      reason: `PBKDF2 迭代次数非法 (允许范围 ${MIN_PBKDF2_ITERATIONS} ~ ${MAX_PBKDF2_ITERATIONS})`,
    };
  }
  if (typeof kdf.salt !== 'string') {
    return { valid: false, reason: '缺少 KDF 盐值 (salt)' };
  }
  try {
    const saltBytes = base64ToBytes(kdf.salt);
    if (saltBytes.byteLength < SALT_BYTE_LENGTH) {
      return { valid: false, reason: 'KDF 盐值长度不足 16 字节' };
    }
  } catch {
    return { valid: false, reason: 'KDF 盐值 Base64 编码损坏' };
  }

  if (!obj.cipher || typeof obj.cipher !== 'object' || Array.isArray(obj.cipher)) {
    return { valid: false, reason: '缺少 cipher 加密参数对象' };
  }
  const cipher = obj.cipher as Record<string, unknown>;
  if (cipher.algorithm !== 'AES-GCM' || cipher.keyLength !== 256 || cipher.ivLength !== 12) {
    return { valid: false, reason: '不支持的对称加密参数，必须为 AES-256-GCM (12-byte IV)' };
  }

  const checkBlob = (blob: unknown, label: string): string | null => {
    if (!blob || typeof blob !== 'object' || Array.isArray(blob)) {
      return `缺少 ${label} 密文对象`;
    }
    const b = blob as Record<string, unknown>;
    if (typeof b.iv !== 'string' || typeof b.ciphertext !== 'string') {
      return `${label} 缺少 iv 或 ciphertext`;
    }
    try {
      const ivBytes = base64ToBytes(b.iv);
      if (ivBytes.byteLength !== IV_BYTE_LENGTH) {
        return `${label} 的 IV 长度必须为 12 字节`;
      }
      const ctBytes = base64ToBytes(b.ciphertext);
      if (ctBytes.byteLength < 16) {
        return `${label} 的密文长度不足 128-bit GCM 认证标签`;
      }
    } catch {
      return `${label} 包含非法的 Base64 编码`;
    }
    return null;
  };

  if (obj.formatVersion === 3) {
    if (!Number.isSafeInteger(obj.snapshotSequence) || Number(obj.snapshotSequence) < 1) {
      return { valid: false, reason: 'V3 快照序号无效' };
    }
    const integrityError = checkBlob(obj.integrity, 'integrity');
    if (integrityError) return { valid: false, reason: integrityError };
  } else if ('integrity' in obj || 'snapshotSequence' in obj) {
    return { valid: false, reason: 'V2 信封不得携带 V3 认证字段' };
  }

  const verifierErr = checkBlob(obj.verifier, 'verifier');
  if (verifierErr) return { valid: false, reason: verifierErr };

  const metaErr = checkBlob(obj.encryptedMetadata, 'encryptedMetadata');
  if (metaErr) return { valid: false, reason: metaErr };

  if (!Array.isArray(obj.encryptedRecords)) {
    return { valid: false, reason: 'encryptedRecords 必须是数组' };
  }

  const seenIds = new Set<string>();
  for (let i = 0; i < obj.encryptedRecords.length; i++) {
    const rec = obj.encryptedRecords[i] as Record<string, unknown>;
    if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
      return { valid: false, reason: `encryptedRecords[${i}] 不是有效对象` };
    }
    if (typeof rec.id !== 'string' || !rec.id.trim()) {
      return { valid: false, reason: `encryptedRecords[${i}].id 无效` };
    }
    if (seenIds.has(rec.id as string)) return { valid: false, reason: '记录 ID 重复' };
    seenIds.add(rec.id as string);
    if (!['login', 'card', 'identity', 'note'].includes(String(rec.recordType))) {
      return { valid: false, reason: `encryptedRecords[${i}].recordType 无效` };
    }
    if (typeof rec.createdAt !== 'number' || typeof rec.updatedAt !== 'number' ||
        !Number.isFinite(rec.createdAt) || !Number.isFinite(rec.updatedAt) || rec.createdAt <= 0 || rec.updatedAt <= 0) {
      return { valid: false, reason: `encryptedRecords[${i}] 时间戳无效` };
    }
    const recErr = checkBlob(
      { iv: rec.iv, ciphertext: rec.ciphertext },
      `encryptedRecords[${i}]`
    );
    if (recErr) return { valid: false, reason: recErr };
  }

  return { valid: true, payload: obj as unknown as EncryptedVaultPayload };
}

/**
 * Builds a versioned encrypted snapshot; new vaults default to V3 whole-vault authentication.
 */
export async function buildEncryptedVaultPayload(
  key: CryptoKey,
  saltBase64: string,
  records: DecryptedVaultRecord[],
  options: {
    vaultId?: string;
    formatVersion?: VaultFormatVersion;
    previousPayload?: EncryptedVaultPayload;
    minimumSequence?: number;
    categories?: VaultCategoryItem[];
    iterations?: number;
    createdAt?: string;
    existingVerifier?: EncryptedBlob;
  } = {}
): Promise<EncryptedVaultPayload> {
  const formatVersion = options.formatVersion ?? VAULT_FORMAT_VERSION;
  const vaultId = options.vaultId || options.previousPayload?.vaultId || generateVaultId();
  const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const nowIso = new Date().toISOString();
  const createdAt = options.createdAt || nowIso;

  const syncedCategories = syncCategoriesWithRecords(
    options.categories || DEFAULT_CATEGORIES,
    records
  );

  const verifier =
    (options.previousPayload?.formatVersion === formatVersion ? options.existingVerifier : undefined) ||
    (await createVaultVerifier(key, vaultId, iterations, saltBase64, formatVersion));

  const encryptedMetadata = await encryptVaultMetadata(
    syncedCategories,
    key,
    vaultId,
    formatVersion
  );

  const encryptedRecords = await Promise.all(
    records.map((r) => encryptVaultRecord(r, key, vaultId, formatVersion))
  );

  const payload: EncryptedVaultPayload = {
    formatVersion,
    vaultId,
    createdAt,
    updatedAt: nowIso,
    kdf: {
      algorithm: 'PBKDF2-HMAC-SHA256',
      hash: 'SHA-256',
      iterations,
      salt: saltBase64,
    },
    cipher: {
      algorithm: 'AES-GCM',
      keyLength: 256,
      ivLength: 12,
    },
    verifier,
    encryptedMetadata,
    encryptedRecords,
  };
  if (formatVersion === 3) {
    payload.snapshotSequence = Math.max(options.previousPayload?.snapshotSequence ?? 0, options.minimumSequence ?? 0) + 1;
    if (!Number.isSafeInteger(payload.snapshotSequence)) throw new Error('快照序号超过安全范围');
    payload.integrity = await encryptStringWithAAD('AEGIS_V3_SNAPSHOT', key, buildSnapshotAAD(payload));
  }
  return payload;
}

export function buildSnapshotAAD(payload: EncryptedVaultPayload): Uint8Array {
  const { integrity: _integrity, ...body } = payload;
  return new TextEncoder().encode(`aegis-v3:snapshot:${canonicalJson(body)}`);
}

/**
 * Unlocks and authenticates an entire V2 EncryptedVaultPayload using a Master Password or derived CryptoKey.
 * Verifies the AAD-bound verifier, decrypts `encryptedMetadata` (categories), and decrypts all `encryptedRecords`.
 */
export async function unlockEncryptedVaultPayload(
  payload: unknown,
  masterPasswordOrKey: string | CryptoKey
): Promise<{
  payload: EncryptedVaultPayload;
  key: CryptoKey;
  records: DecryptedVaultRecord[];
  categories: VaultCategoryItem[];
}> {
  const validation = validateV2VaultEnvelopeStructure(payload);
  if (!validation.valid || !validation.payload) {
    throw new Error(validation.reason || '非法的 V2 密码库密文结构');
  }
  const v2 = validation.payload;

  const key =
    typeof masterPasswordOrKey === 'string'
      ? await deriveMasterKey(
          masterPasswordOrKey,
          v2.kdf.salt,
          v2.kdf.iterations
        )
      : masterPasswordOrKey;

  const isVerifierOk = await verifyVaultKey(
    v2.verifier,
    key,
    v2.vaultId,
    v2.kdf.iterations,
    v2.kdf.salt,
    v2.formatVersion
  );
  if (!isVerifierOk) {
    throw new Error('主密码错误或密文校验器 (Verifier) 认证失败');
  }

  if (v2.formatVersion === 3) {
    try {
      const authenticated = await decryptStringWithAAD(v2.integrity!, key, buildSnapshotAAD(v2));
      if (authenticated !== 'AEGIS_V3_SNAPSHOT') throw new Error('Invalid snapshot verifier');
    } catch {
      throw new Error('整库完整性认证失败：记录清单或快照元数据已被修改，拒绝加载');
    }
  }

  let metadata: DecryptedVaultMetadata;
  try {
    metadata = await decryptVaultMetadata(v2.encryptedMetadata, key, v2.vaultId, v2.formatVersion);
  } catch {
    throw new Error('加密分类元数据 (encryptedMetadata) GCM 认证标签校验失败，数据可能遭篡改');
  }

  let records: DecryptedVaultRecord[];
  try {
    records = await Promise.all(
      v2.encryptedRecords.map((enc) => decryptVaultRecord(enc, key, v2.vaultId, v2.formatVersion))
    );
  } catch {
    throw new Error('密码库记录密文 GCM 认证标签校验失败，拒绝加载不完整数据');
  }

  const categories = syncCategoriesWithRecords(metadata.categories, records);

  return {
    payload: v2,
    key,
    records,
    categories,
  };
}

/**
 * V2 Master Password Change / Key Rotation:
 * 1. Authenticates & decrypts all records and metadata with `oldMasterPassword`.
 * 2. Preserves `vaultId` and `createdAt` so the vault identity remains unchanged.
 * 3. Generates a fresh 16-byte CSPRNG `kdf.salt` and derives a new 256-bit AES-GCM key.
 * 4. Re-encrypts `verifier`, `encryptedMetadata`, and all `encryptedRecords` with fresh IVs.
 * 5. Performs round-trip decryption verification before returning.
 */
export async function rotateVaultMasterPassword(
  currentVault: EncryptedVaultPayload,
  oldMasterPassword: string,
  newMasterPassword: string,
  newIterations: number = DEFAULT_PBKDF2_ITERATIONS,
  minimumSequence: number = 0
): Promise<{
  newPayload: EncryptedVaultPayload;
  newKey: CryptoKey;
  newSalt: string;
  records: DecryptedVaultRecord[];
  categories: VaultCategoryItem[];
}> {
  if (!newMasterPassword || newMasterPassword.length < 8) {
    throw new Error('新主密码长度至少需要 8 个字符');
  }
  if (oldMasterPassword === newMasterPassword) {
    throw new Error('新主密码不能与当前主密码相同');
  }

  // Step 1: Authenticate & decrypt entire current vault
  const unlocked = await unlockEncryptedVaultPayload(
    currentVault,
    oldMasterPassword
  );

  // Step 2: Generate fresh CSPRNG salt and derive new CryptoKey
  const newSalt = generateSaltBase64(16);
  const newKey = await deriveMasterKey(
    newMasterPassword,
    newSalt,
    newIterations
  );

  // Step 3: Build re-encrypted V2 payload while preserving vaultId and createdAt
  const newPayload = await buildEncryptedVaultPayload(
    newKey,
    newSalt,
    unlocked.records,
    {
      vaultId: currentVault.vaultId,
      previousPayload: currentVault,
      minimumSequence,
      categories: unlocked.categories,
      iterations: newIterations,
      createdAt: currentVault.createdAt,
    }
  );

  // Step 4: Verify round-trip decryption with new key
  await unlockEncryptedVaultPayload(newPayload, newKey);

  return {
    newPayload,
    newKey,
    newSalt,
    records: unlocked.records,
    categories: unlocked.categories,
  };
}

/**
 * Creates a strictly isolated, in-memory ephemeral Demo session.
 * Never touches localStorage/IndexedDB and never syncs to Cloudflare Worker.
 */
export async function createEphemeralDemoSession(
  demoRecords: DecryptedVaultRecord[]
): Promise<{
  ephemeralKey: CryptoKey;
  ephemeralSalt: string;
  ephemeralPayload: EncryptedVaultPayload;
  records: DecryptedVaultRecord[];
  categories: VaultCategoryItem[];
}> {
  const randomBytes = new Uint8Array(24);
  getCrypto().getRandomValues(randomBytes);
  const oneTimeSecret = bytesToBase64(randomBytes);
  const ephemeralSalt = generateSaltBase64(16);
  const demoVaultId = generateVaultId();

  // Use MIN_PBKDF2_ITERATIONS (100,000) for fast in-memory sandbox initialization
  const ephemeralKey = await deriveMasterKey(
    oneTimeSecret,
    ephemeralSalt,
    MIN_PBKDF2_ITERATIONS
  );

  const categories = syncCategoriesWithRecords(DEFAULT_CATEGORIES, demoRecords);

  const ephemeralPayload = await buildEncryptedVaultPayload(
    ephemeralKey,
    ephemeralSalt,
    demoRecords,
    {
      vaultId: demoVaultId,
      categories,
      iterations: MIN_PBKDF2_ITERATIONS,
    }
  );

  return {
    ephemeralKey,
    ephemeralSalt,
    ephemeralPayload,
    records: demoRecords,
    categories,
  };
}
