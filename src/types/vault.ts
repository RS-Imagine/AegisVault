export type VaultCategory =
  | 'bank-card'
  | 'social'
  | 'work'
  | 'personal'
  | 'finance'
  | 'other'
  | string;

export type FilterCategory = 'all' | 'favorites' | VaultCategory;

export type RecordType = 'login' | 'card' | 'identity' | 'note';

export interface VaultCategoryItem {
  id: string;
  label: string;
  isSystem?: boolean;
  isFallback?: boolean;
}

export const DEFAULT_CATEGORIES: VaultCategoryItem[] = [
  { id: 'bank-card', label: '银行卡', isSystem: true },
  { id: 'work', label: '工作', isSystem: true },
  { id: 'social', label: '社交', isSystem: true },
  { id: 'personal', label: '个人', isSystem: true },
  { id: 'finance', label: '财务', isSystem: true },
  { id: 'other', label: '其他', isSystem: true, isFallback: true },
];

export const CATEGORY_META: Record<string, { label: string }> = {
  'bank-card': { label: '银行卡' },
  work: { label: '工作' },
  social: { label: '社交' },
  personal: { label: '个人' },
  finance: { label: '财务' },
  other: { label: '其他' },
};

export interface PaymentCardDetails {
  cardholderName: string;
  cardNumber: string;
  expiryDate: string; // MM/YY
  cvv: string;
  brand?: string;
}

export interface DecryptedVaultRecord {
  id: string;
  recordType?: RecordType;
  title: string;
  username: string;
  password: string;
  url: string;
  category: VaultCategory;
  tags?: string[];
  cardDetails?: PaymentCardDetails;
  notes: string;
  favorite: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface EncryptedBlob {
  iv: string; // Base64 12-byte IV
  ciphertext: string; // Base64 AES-256-GCM ciphertext + 128-bit authTag
}

export interface EncryptedVaultRecord {
  id: string;
  recordType: RecordType;
  iv: string; // Base64 12-byte IV
  ciphertext: string; // Base64 AES-256-GCM ciphertext + 128-bit authTag (bound via AAD)
  createdAt: number;
  updatedAt: number;
}

export interface DecryptedVaultMetadata {
  categories: VaultCategoryItem[];
  updatedAt: number;
}

/**
 * AegisVault V2 Zero-Knowledge Encrypted Vault Envelope
 * - Strictly formatVersion === 2
 * - Independent CSPRNG `vaultId` preserved across Master Password rotations
 * - `verifier`, `encryptedMetadata`, and `encryptedRecords` bound via AES-GCM AAD
 */
export interface EncryptedVaultPayload {
  formatVersion: 2;
  vaultId: string;
  createdAt: string;
  updatedAt: string;
  kdf: {
    algorithm: 'PBKDF2-HMAC-SHA256';
    hash: 'SHA-256';
    iterations: number;
    salt: string;
  };
  cipher: {
    algorithm: 'AES-GCM';
    keyLength: 256;
    ivLength: 12;
  };
  verifier: EncryptedBlob;
  encryptedMetadata: EncryptedBlob;
  encryptedRecords: EncryptedVaultRecord[];
}

export interface CloudflareSyncConfig {
  workerUrl: string;
  apiToken: string;
  rememberToken?: boolean;
  autoSync: boolean;
  lastSyncedAt: number | null;
}

/**
 * V2 7-State Sync State Machine:
 * - local_saved: Saved locally, Cloud Sync not configured
 * - cloud_synced: Local vault matches Cloud Durable Object revision
 * - sync_pending: Local edits saved, waiting to push to Cloud
 * - syncing: Active network request to Worker / Durable Object
 * - offline: Network unreachable; local edits preserved as pending
 * - conflict: Remote revision or vaultId diverged (HTTP 409); requires user decision
 * - failed: Auth, validation, or server error; local edits remain intact
 */
export type SyncStatus =
  | 'local_saved'
  | 'cloud_synced'
  | 'sync_pending'
  | 'syncing'
  | 'offline'
  | 'conflict'
  | 'failed';

export type SyncErrorCategory =
  | 'none'
  | 'network_unreachable'
  | 'timeout'
  | 'unauthorized'
  | 'conflict'
  | 'rate_limited'
  | 'unconfigured_server'
  | 'server_error'
  | 'validation_error';

export interface LocalStoragePersistenceWarning {
  code: 'QUOTA_EXCEEDED' | 'IDB_TRANSACTION_FAILED' | 'STORAGE_WRITE_FAILED';
  message: string;
  occurredAt: number;
}

export interface CloudConflictInfo {
  code:
    | 'REVISION_CONFLICT'
    | 'VAULT_ID_MISMATCH'
    | 'ALREADY_INITIALIZED'
    | 'VAULT_NOT_INITIALIZED'
    | 'MUTATION_ID_PAYLOAD_MISMATCH';
  message: string;
  localVaultId: string;
  localRevision: number;
  serverVaultId?: string;
  serverRevision: number;
  serverUpdatedAt?: string;
  serverVault?: EncryptedVaultPayload;
  detectedAt: number;
}

export interface LocalSyncStateV2 {
  vaultId: string;
  lastSyncedRevision: number; // 0 if never synced to cloud
  pendingMutationId: string | null;
  pendingMutationPayloadHash?: string | null;
  writeSequence?: number;
  dirtySince: number | null;
  lastSyncedAt: number | null;
  conflictState: CloudConflictInfo | null;
  pendingPasswordRotationPurge?: boolean;
  lastErrorCategory?: SyncErrorCategory;
}

export interface VaultHistoryEntry {
  revision: number;
  vaultId: string;
  contentSha256: string;
  createdAt: string;
  recordCount: number;
}

export interface WorkerConnectivityProbeResult {
  reachable: boolean;
  latencyMs: number;
  httpStatus?: number;
  initialized?: boolean;
  revision?: number;
  vaultId?: string;
  status:
    | 'reachable'
    | 'invalid_url'
    | 'unauthorized'
    | 'unconfigured_server'
    | 'timeout'
    | 'unreachable'
    | 'http_error';
  message: string;
}

export interface RemoteVaultProbeMetadata {
  version: 2;
  vaultId: string;
  revision: number;
  saltFingerprint: string;
  recordCount: number;
  localRecordCount: number;
  updatedAt: string;
  kdfAlgorithm: string;
  kdfIterations: number;
  cipherAlgorithm: string;
  hasExistingLocalVault: boolean;
  hasDifferenceFromLocal: boolean;
  isDifferentVaultFromLocal: boolean;
}

export interface RemoteVaultProbeResult {
  status:
    | 'ready'
    | 'not_initialized'
    | 'empty_remote'
    | 'unauthorized'
    | 'unconfigured_server'
    | 'network_error'
    | 'corrupted_payload';
  message: string;
  candidatePayload?: EncryptedVaultPayload;
  metadata?: RemoteVaultProbeMetadata;
}

export interface StagedRemotePullResult {
  remotePayload: EncryptedVaultPayload;
  remoteRevision: number;
  derivedKey: CryptoKey;
  decryptedRecords: DecryptedVaultRecord[];
  decryptedCategories: VaultCategoryItem[];
  hasConflictWithLocal: boolean;
  isDifferentVaultId: boolean;
  localRecordCount: number;
  remoteRecordCount: number;
  remoteUpdatedAt: string;
}

export interface RecoverySummaryInfo {
  source: 'cloud' | 'backup-file' | 'history-snapshot';
  vaultId: string;
  revision?: number;
  recordCount: number;
  loginCount: number;
  cardCount: number;
  categoryCount: number;
  hadPreviousLocalVault: boolean;
  restoredRecordCount: number;
  restoredAt: number;
  overwroteExistingLocal: boolean;
  recordTitlesSample: string[];
}
