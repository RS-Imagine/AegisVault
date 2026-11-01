/**
 * AegisVault V2 Sync Protocol & Durable Object Storage Types
 *
 * Strictly V2 only (`formatVersion: 2`, `protocolVersion: 2`).
 * Legacy V1 payloads and KV storage are permanently removed.
 */

export const SYNC_PROTOCOL_VERSION = 2 as const;
export const VAULT_FORMAT_VERSION = 2 as const;
export const MAX_VAULT_BODY_BYTES = 1024 * 1024; // 1 MiB
export const MAX_HISTORY_SNAPSHOTS = 15;
export const SINGLETON_DO_INSTANCE_NAME = 'aegis-primary-vault-singleton';

export interface EncryptedBlob {
  iv: string; // Base64 12-byte IV
  ciphertext: string; // Base64 AES-GCM ciphertext + 128-bit authTag
}

export interface V2EncryptedRecordEnvelope {
  id: string;
  recordType: 'login' | 'card' | 'identity' | 'note';
  iv: string; // Base64 12-byte IV
  ciphertext: string; // Base64 AES-GCM ciphertext + 128-bit authTag
  createdAt: number;
  updatedAt: number;
}

export interface V2EncryptedVaultPayload {
  formatVersion: typeof VAULT_FORMAT_VERSION;
  vaultId: string; // Independent 128-bit / UUID identifier
  createdAt: string; // ISO-8601
  updatedAt: string; // ISO-8601
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    hash: 'SHA-256';
    iterations: number;
    salt: string; // Base64 16-byte CSPRNG salt
  };
  cipher: {
    algorithm: 'AES-GCM';
    keyLength: 256;
    ivLength: 12;
  };
  verifier: EncryptedBlob; // Bound via AAD to vaultId, formatVersion, kdf
  encryptedMetadata: EncryptedBlob; // Encrypted custom categories/tags JSON bound via AAD
  encryptedRecords: V2EncryptedRecordEnvelope[];
}

export interface InitVaultRequest {
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  vaultId: string;
  mutationId: string;
  vault: V2EncryptedVaultPayload;
}

export interface PutVaultRequest {
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  vaultId: string;
  expectedRevision: number;
  mutationId: string;
  vault: V2EncryptedVaultPayload;
  /**
   * Optional flag set after a Master Password rotation if the user chooses
   * to purge historical snapshots encrypted under the previous key.
   */
  purgePreviousSnapshots?: boolean;
}

export interface VaultGetResponse {
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  initialized: boolean;
  vaultId?: string;
  revision: number;
  updatedAt?: string;
  contentSha256?: string;
  vault: V2EncryptedVaultPayload | null;
}

export interface VaultWriteResponse {
  ok: true;
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  vaultId: string;
  revision: number;
  updatedAt: string;
  contentSha256: string;
  idempotentReplay?: boolean;
}

export interface VaultConflictResponse {
  error: string;
  code:
    | 'ALREADY_INITIALIZED'
    | 'VAULT_NOT_INITIALIZED'
    | 'VAULT_ID_MISMATCH'
    | 'REVISION_CONFLICT'
    | 'MUTATION_ID_PAYLOAD_MISMATCH';
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  serverVaultId?: string;
  serverRevision: number;
  serverUpdatedAt?: string;
  serverVault?: V2EncryptedVaultPayload;
}

export interface VaultHistoryEntry {
  revision: number;
  vaultId: string;
  contentSha256: string;
  createdAt: string;
  recordCount: number;
}

export interface VaultHistoryListResponse {
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  initialized: boolean;
  vaultId?: string;
  currentRevision: number;
  snapshots: VaultHistoryEntry[];
}

export interface VaultHistorySnapshotResponse {
  protocolVersion: typeof SYNC_PROTOCOL_VERSION;
  vaultId: string;
  revision: number;
  currentRevision: number;
  createdAt: string;
  contentSha256: string;
  vault: V2EncryptedVaultPayload;
}
