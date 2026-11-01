import {
  InitVaultRequest,
  PutVaultRequest,
  SYNC_PROTOCOL_VERSION,
  V2EncryptedVaultPayload,
  VAULT_FORMAT_VERSION,
} from './types';

const BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const UUID_OR_ID_REGEX = /^[A-Za-z0-9_-]{16,64}$/;
const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 2_000_000;
const MAX_RECORDS_COUNT = 5_000;

export function decodeBase64ByteLength(b64: string): number | null {
  if (
    typeof b64 !== 'string' ||
    b64.length === 0 ||
    b64.length % 4 !== 0 ||
    !BASE64_REGEX.test(b64)
  ) {
    return null;
  }
  try {
    const bin = atob(b64);
    return bin.length;
  } catch {
    return null;
  }
}

function isValidEncryptedBlob(
  blob: unknown,
  minCiphertextBytes: number = 17
): boolean {
  if (!blob || typeof blob !== 'object' || Array.isArray(blob)) return false;
  const b = blob as Record<string, unknown>;
  const ivLen = typeof b.iv === 'string' ? decodeBase64ByteLength(b.iv) : null;
  const ctLen =
    typeof b.ciphertext === 'string' ? decodeBase64ByteLength(b.ciphertext) : null;
  return ivLen === 12 && ctLen !== null && ctLen >= minCiphertextBytes;
}

const FORBIDDEN_PLAINTEXT_FIELDS = [
  'records', // V1 field name
  'version', // V1 field name
  'password',
  'masterPassword',
  'derivedKey',
  'categories', // Plaintext categories forbidden in V2 envelope
  'cardNumber',
  'cvv',
  'username',
] as const;

export function validateV2VaultPayload(
  payload: unknown
): { valid: boolean; reason?: string; vault?: V2EncryptedVaultPayload } {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { valid: false, reason: 'Vault payload must be a JSON object' };
  }

  const obj = payload as Record<string, unknown>;

  for (const forbidden of FORBIDDEN_PLAINTEXT_FIELDS) {
    if (forbidden in obj) {
      return {
        valid: false,
        reason: `Forbidden or legacy field "${forbidden}" present in V2 vault envelope`,
      };
    }
  }

  if (obj.formatVersion !== VAULT_FORMAT_VERSION) {
    return {
      valid: false,
      reason: `Unsupported vault formatVersion (expected ${VAULT_FORMAT_VERSION})`,
    };
  }

  if (typeof obj.vaultId !== 'string' || !UUID_OR_ID_REGEX.test(obj.vaultId)) {
    return {
      valid: false,
      reason: 'Invalid or missing vaultId (expected 16-64 char alphanumeric/UUID string)',
    };
  }

  if (typeof obj.createdAt !== 'string' || Number.isNaN(Date.parse(obj.createdAt))) {
    return { valid: false, reason: 'Invalid createdAt ISO timestamp' };
  }

  if (typeof obj.updatedAt !== 'string' || Number.isNaN(Date.parse(obj.updatedAt))) {
    return { valid: false, reason: 'Invalid updatedAt ISO timestamp' };
  }

  if (!obj.kdf || typeof obj.kdf !== 'object' || Array.isArray(obj.kdf)) {
    return { valid: false, reason: 'Missing kdf parameter object' };
  }
  const kdf = obj.kdf as Record<string, unknown>;
  if (kdf.algorithm !== 'PBKDF2-HMAC-SHA256' || kdf.hash !== 'SHA-256') {
    return { valid: false, reason: 'Unsupported KDF algorithm or hash' };
  }
  if (
    typeof kdf.iterations !== 'number' ||
    !Number.isInteger(kdf.iterations) ||
    kdf.iterations < MIN_PBKDF2_ITERATIONS ||
    kdf.iterations > MAX_PBKDF2_ITERATIONS
  ) {
    return {
      valid: false,
      reason: `KDF iterations out of bounds (${MIN_PBKDF2_ITERATIONS}..${MAX_PBKDF2_ITERATIONS})`,
    };
  }
  const saltLen = typeof kdf.salt === 'string' ? decodeBase64ByteLength(kdf.salt) : null;
  if (saltLen === null || saltLen < 16 || saltLen > 64) {
    return { valid: false, reason: 'Invalid KDF salt Base64 (minimum 16 bytes)' };
  }

  if (!obj.cipher || typeof obj.cipher !== 'object' || Array.isArray(obj.cipher)) {
    return { valid: false, reason: 'Missing cipher parameter object' };
  }
  const cipher = obj.cipher as Record<string, unknown>;
  if (cipher.algorithm !== 'AES-GCM' || cipher.keyLength !== 256 || cipher.ivLength !== 12) {
    return { valid: false, reason: 'Unsupported cipher configuration (expected AES-256-GCM with 12-byte IV)' };
  }

  if (!isValidEncryptedBlob(obj.verifier, 24)) {
    return { valid: false, reason: 'Invalid verifier encrypted blob' };
  }

  if (!isValidEncryptedBlob(obj.encryptedMetadata, 18)) {
    return { valid: false, reason: 'Invalid encryptedMetadata blob' };
  }

  if (!Array.isArray(obj.encryptedRecords)) {
    return { valid: false, reason: 'encryptedRecords must be an array' };
  }
  if (obj.encryptedRecords.length > MAX_RECORDS_COUNT) {
    return { valid: false, reason: 'Too many encrypted records in vault' };
  }

  for (let i = 0; i < obj.encryptedRecords.length; i++) {
    const rec = obj.encryptedRecords[i];
    if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
      return { valid: false, reason: `encryptedRecords[${i}] must be an object` };
    }
    const r = rec as Record<string, unknown>;
    if (typeof r.id !== 'string' || r.id.trim().length === 0 || r.id.length > 128) {
      return { valid: false, reason: `encryptedRecords[${i}].id is invalid` };
    }
    if (!['login', 'card', 'identity', 'note'].includes(String(r.recordType))) {
      return { valid: false, reason: `encryptedRecords[${i}].recordType is invalid` };
    }
    if (typeof r.createdAt !== 'number' || !Number.isFinite(r.createdAt) || r.createdAt <= 0) {
      return { valid: false, reason: `encryptedRecords[${i}].createdAt is invalid` };
    }
    if (typeof r.updatedAt !== 'number' || !Number.isFinite(r.updatedAt) || r.updatedAt <= 0) {
      return { valid: false, reason: `encryptedRecords[${i}].updatedAt is invalid` };
    }
    const ivLen = typeof r.iv === 'string' ? decodeBase64ByteLength(r.iv) : null;
    const ctLen =
      typeof r.ciphertext === 'string' ? decodeBase64ByteLength(r.ciphertext) : null;
    if (ivLen !== 12 || ctLen === null || ctLen < 18) {
      return { valid: false, reason: `encryptedRecords[${i}] has invalid iv or ciphertext` };
    }
  }

  return {
    valid: true,
    vault: obj as unknown as V2EncryptedVaultPayload,
  };
}

export function validateInitVaultRequest(
  body: unknown
): { valid: boolean; reason?: string; request?: InitVaultRequest } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, reason: 'Request body must be a JSON object' };
  }
  const obj = body as Record<string, unknown>;

  if (obj.protocolVersion !== SYNC_PROTOCOL_VERSION) {
    return {
      valid: false,
      reason: `Unsupported protocolVersion (expected ${SYNC_PROTOCOL_VERSION})`,
    };
  }
  if (typeof obj.vaultId !== 'string' || !UUID_OR_ID_REGEX.test(obj.vaultId)) {
    return { valid: false, reason: 'Invalid vaultId in request' };
  }
  if (typeof obj.mutationId !== 'string' || !UUID_OR_ID_REGEX.test(obj.mutationId)) {
    return { valid: false, reason: 'Invalid mutationId in request' };
  }

  const vaultCheck = validateV2VaultPayload(obj.vault);
  if (!vaultCheck.valid || !vaultCheck.vault) {
    return { valid: false, reason: vaultCheck.reason };
  }

  if (vaultCheck.vault.vaultId !== obj.vaultId) {
    return {
      valid: false,
      reason: 'Request vaultId does not match inner vault.vaultId',
    };
  }

  return {
    valid: true,
    request: {
      protocolVersion: SYNC_PROTOCOL_VERSION,
      vaultId: obj.vaultId,
      mutationId: obj.mutationId,
      vault: vaultCheck.vault,
    },
  };
}

export function validatePutVaultRequest(
  body: unknown
): { valid: boolean; reason?: string; request?: PutVaultRequest } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, reason: 'Request body must be a JSON object' };
  }
  const obj = body as Record<string, unknown>;

  if (obj.protocolVersion !== SYNC_PROTOCOL_VERSION) {
    return {
      valid: false,
      reason: `Unsupported protocolVersion (expected ${SYNC_PROTOCOL_VERSION})`,
    };
  }
  if (typeof obj.vaultId !== 'string' || !UUID_OR_ID_REGEX.test(obj.vaultId)) {
    return { valid: false, reason: 'Invalid vaultId in request' };
  }
  if (
    typeof obj.expectedRevision !== 'number' ||
    !Number.isInteger(obj.expectedRevision) ||
    obj.expectedRevision < 1
  ) {
    return {
      valid: false,
      reason: 'expectedRevision must be an integer >= 1 for PUT /api/vault',
    };
  }
  if (typeof obj.mutationId !== 'string' || !UUID_OR_ID_REGEX.test(obj.mutationId)) {
    return { valid: false, reason: 'Invalid mutationId in request' };
  }

  const vaultCheck = validateV2VaultPayload(obj.vault);
  if (!vaultCheck.valid || !vaultCheck.vault) {
    return { valid: false, reason: vaultCheck.reason };
  }

  if (vaultCheck.vault.vaultId !== obj.vaultId) {
    return {
      valid: false,
      reason: 'Request vaultId does not match inner vault.vaultId',
    };
  }

  return {
    valid: true,
    request: {
      protocolVersion: SYNC_PROTOCOL_VERSION,
      vaultId: obj.vaultId,
      expectedRevision: obj.expectedRevision,
      mutationId: obj.mutationId,
      vault: vaultCheck.vault,
      purgePreviousSnapshots: Boolean(obj.purgePreviousSnapshots),
    },
  };
}

/**
 * Computes a deterministic SHA-256 hex digest of a canonical JSON payload.
 */
export async function computeMutationRequestDigest(params: {
  vaultId: string;
  expectedRevision: number;
  mutationId: string;
  vault: V2EncryptedVaultPayload;
  purgePreviousSnapshots?: boolean;
}): Promise<string> {
  const canonical = JSON.stringify({
    vaultId: params.vaultId,
    expectedRevision: params.expectedRevision,
    mutationId: params.mutationId,
    purgePreviousSnapshots: Boolean(params.purgePreviousSnapshots),
    vault: params.vault,
  });
  const bytes = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
