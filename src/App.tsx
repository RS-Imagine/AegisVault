import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  CloudConflictInfo,
  CloudflareSyncConfig,
  DecryptedVaultRecord,
  EncryptedVaultPayload,
  EncryptedVaultRecord,
  LocalStoragePersistenceWarning,
  RecoverySummaryInfo,
  StagedRemotePullResult,
  SyncStatus,
  VaultCategoryItem,
} from './types/vault';
import {
  buildEncryptedVaultPayload,
  createEphemeralDemoSession,
  deriveMasterKey,
  generateSaltBase64,
  generateVaultId,
  rotateVaultMasterPassword,
  unlockEncryptedVaultPayload,
} from './crypto/cryptoEngine';
import {
  SyncService,
  subscribeToCrossTabVaultUpdates,
} from './services/syncService';
import { createInitialSeedRecords } from './utils/seedData';
import {
  createCustomCategory,
  deleteCustomCategory,
  getInitialDefaultCategories,
  renameCustomCategory,
  syncCategoriesWithRecords,
} from './utils/categoryManager';
import { MasterAuthScreen } from './components/MasterAuthScreen';
import { VaultWorkspace } from './components/VaultWorkspace';
import { RecordFormModal } from './components/RecordFormModal';
import { PasswordGeneratorModal } from './components/PasswordGeneratorModal';
import { CiphertextInspectorModal } from './components/CiphertextInspectorModal';
import { CloudSyncModal } from './components/CloudSyncModal';
import { ImportVaultModal } from './components/ImportVaultModal';
import { CategoryManagerModal } from './components/CategoryManagerModal';
import { MasterPasswordModal } from './components/MasterPasswordModal';
import { PWAStatusBanner } from './components/PWAStatusBanner';
import {
  AndroidSaveCredentialRequest,
  exportBackupFileCrossPlatform,
  matchRecordsForAndroidTarget,
  normalizeAndroidSaveRequest,
} from './services/nativePlatformBridge';

export type ThemePreference = 'system' | 'light' | 'dark';

const IDLE_AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes inactivity auto-lock

export default function App() {
  // Theme preference: defaults to 'system' (follows OS/Browser prefers-color-scheme) unless explicitly overridden
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => {
    if (typeof window !== 'undefined') {
      const saved = window.localStorage.getItem('aegis_theme_mode');
      if (saved === 'light' || saved === 'dark' || saved === 'system') {
        return saved;
      }
    }
    return 'system';
  });

  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() => {
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    return true;
  });

  // Listen to OS/browser color scheme changes in real time
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e: MediaQueryListEvent) => {
      setSystemPrefersDark(e.matches);
    };
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  const darkMode =
    themePreference === 'system' ? systemPrefersDark : themePreference === 'dark';

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    const metaTheme = document.getElementById('aegis-theme-color');
    if (metaTheme) {
      metaTheme.setAttribute('content', darkMode ? '#090d16' : '#f8fafc');
    }
    if (typeof window !== 'undefined') {
      if (themePreference === 'system') {
        window.localStorage.removeItem('aegis_theme_mode');
      } else {
        window.localStorage.setItem('aegis_theme_mode', themePreference);
      }
    }
  }, [darkMode, themePreference]);

  const handleToggleDarkMode = useCallback(() => {
    setThemePreference((prev) => {
      if (prev === 'system') {
        return systemPrefersDark ? 'light' : 'dark';
      }
      if (prev === 'light') {
        return systemPrefersDark ? 'system' : 'dark';
      }
      return systemPrefersDark ? 'light' : 'system';
    });
  }, [systemPrefersDark]);

  // Security notice when vault was automatically locked due to inactivity
  const [autoLockNotice, setAutoLockNotice] = useState<string | null>(null);

  // Persistent Production V2 Encrypted Envelope (No plaintext or keys!)
  const [encryptedPayload, setEncryptedPayload] =
    useState<EncryptedVaultPayload | null>(() => SyncService.getLocalVault());

  // Prevent showing "Create New Vault" prematurely if localStorage was empty while IndexedDB is still hydrating
  const [isHydratingStorage, setIsHydratingStorage] = useState<boolean>(
    () => SyncService.getLocalVault() === null
  );

  // Local storage / IndexedDB persistence warning (e.g. QuotaExceededError or transaction abort)
  const [persistenceWarning, setPersistenceWarning] =
    useState<LocalStoragePersistenceWarning | null>(() =>
      SyncService.getLastPersistenceWarning()
    );

  // Strictly Isolated In-Memory Demo Mode State (Never touches localStorage/IndexedDB or Cloudflare Worker)
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);
  const [demoEncryptedPayload, setDemoEncryptedPayload] =
    useState<EncryptedVaultPayload | null>(null);

  // Zero-Knowledge In-Memory State (Destroyed immediately on Lock or Page Reload)
  const [memoryKey, setMemoryKey] = useState<CryptoKey | null>(null);
  const [memorySalt, setMemorySalt] = useState<string | null>(null);
  const [decryptedRecords, setDecryptedRecords] = useState<
    DecryptedVaultRecord[]
  >([]);
  const [categories, setCategories] = useState<VaultCategoryItem[]>(() =>
    getInitialDefaultCategories()
  );

  // V2 7-State Sync State Machine
  const [syncConfig, setSyncConfig] = useState<CloudflareSyncConfig>(() =>
    SyncService.getSyncConfig()
  );
  const [syncStatus, setSyncStatus] = useState<SyncStatus>(() =>
    SyncService.computeSyncStatus()
  );
  const [syncMessage, setSyncMessage] = useState<string>(
    '本地已加密保存 (IndexedDB)'
  );
  const [requiresCloudInitConfirm, setRequiresCloudInitConfirm] =
    useState<boolean>(false);
  const [conflictInfo, setConflictInfo] = useState<CloudConflictInfo | null>(
    () => SyncService.getLocalSyncState().conflictState
  );
  const [stagedPull, setStagedPull] = useState<StagedRemotePullResult | null>(
    null
  );
  const [needsRemotePasswordPrompt, setNeedsRemotePasswordPrompt] =
    useState<boolean>(false);
  const [recoverySummary, setRecoverySummary] =
    useState<RecoverySummaryInfo | null>(null);
  const [hasRollbackBackup, setHasRollbackBackup] = useState<boolean>(() =>
    Boolean(SyncService.getRollbackBackup())
  );

  // Modals State
  const [isRecordModalOpen, setIsRecordModalOpen] = useState(false);
  const [editingRecord, setEditingRecord] =
    useState<DecryptedVaultRecord | null>(null);
  const [prefillRecordDraft, setPrefillRecordDraft] =
    useState<Partial<DecryptedVaultRecord> | null>(null);
  const [isGeneratorModalOpen, setIsGeneratorModalOpen] = useState(false);
  const [isCiphertextModalOpen, setIsCiphertextModalOpen] = useState(false);
  const [isCloudSyncModalOpen, setIsCloudSyncModalOpen] = useState(false);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [isCategoryModalOpen, setIsCategoryModalOpen] = useState(false);
  const [isMasterPasswordModalOpen, setIsMasterPasswordModalOpen] =
    useState(false);

  // Hydrate V2 vault from authoritative IndexedDB on startup & subscribe to cross-tab updates
  useEffect(() => {
    let cancelled = false;
    void SyncService.hydrateFromIndexedDB()
      .then((hydrated) => {
        if (cancelled) return;
        setEncryptedPayload(hydrated);
        setSyncStatus(SyncService.computeSyncStatus());
        setConflictInfo(SyncService.getLocalSyncState().conflictState);
        setIsHydratingStorage(false);
      })
      .catch(() => {
        if (!cancelled) {
          setIsHydratingStorage(false);
        }
      });

    const unsubscribe = subscribeToCrossTabVaultUpdates((event) => {
      if (event.type === 'VAULT_RESET') {
        setEncryptedPayload(null);
        setMemoryKey(null);
        setMemorySalt(null);
        setDecryptedRecords([]);
        setCategories(getInitialDefaultCategories());
        setConflictInfo(null);
        setSyncStatus('local_saved');
        return;
      }

      const latestVault = SyncService.getLocalVault();
      const latestSync = SyncService.getLocalSyncState();
      setEncryptedPayload(latestVault);
      setConflictInfo(latestSync.conflictState);
      setSyncStatus(SyncService.computeSyncStatus());

      // If vault is unlocked with matching key/salt, re-decrypt latest cross-tab snapshot in memory
      if (
        latestVault &&
        memoryKey &&
        memorySalt &&
        latestVault.kdf.salt === memorySalt
      ) {
        void unlockEncryptedVaultPayload(latestVault, memoryKey)
          .then((unlocked) => {
            setDecryptedRecords(unlocked.records);
            setCategories(unlocked.categories);
          })
          .catch(() => {
            // If another tab rotated Master Password (different salt/key), keep safe state
          });
      }
    });

    const handleOnline = () => {
      setSyncStatus(SyncService.computeSyncStatus());
    };
    const handleOffline = () => {
      setSyncStatus(SyncService.computeSyncStatus(SyncService.getSyncConfig(), false));
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      cancelled = true;
      unsubscribe();
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [memoryKey, memorySalt]);

  const activeEncryptedEnvelopePayload = isDemoMode
    ? demoEncryptedPayload
    : encryptedPayload;

  // Map of record id -> encrypted envelope for live per-record ciphertext inspection
  const encryptedRecordsMap = useMemo(() => {
    const map: Record<string, EncryptedVaultRecord> = {};
    if (activeEncryptedEnvelopePayload) {
      for (const enc of activeEncryptedEnvelopePayload.encryptedRecords) {
        map[enc.id] = enc;
      }
    }
    return map;
  }, [activeEncryptedEnvelopePayload]);

  // First-time Production V2 Master Password Setup
  const handleSetupMasterPassword = useCallback(
    async (masterPassword: string, includeSeedData: boolean) => {
      const salt = generateSaltBase64(16);
      const vaultId = generateVaultId();
      const derivedKey = await deriveMasterKey(masterPassword, salt);
      const initialRecords = includeSeedData ? createInitialSeedRecords() : [];
      const initialCategories = syncCategoriesWithRecords(
        getInitialDefaultCategories(),
        initialRecords
      );

      const payload = await buildEncryptedVaultPayload(
        derivedKey,
        salt,
        initialRecords,
        {
          vaultId,
          categories: initialCategories,
        }
      );

      setIsDemoMode(false);
      setDemoEncryptedPayload(null);

      try {
        await SyncService.saveLocalVaultAsync(payload, {
          markDirty: false,
          syncedRevision: 0,
        });
        setPersistenceWarning(null);
        setSyncMessage('已创建 V2 零知识密码库并加密保存至本地存储 (IndexedDB)');
      } catch (err) {
        const warning = SyncService.getLastPersistenceWarning() ?? {
          code: 'STORAGE_WRITE_FAILED',
          message:
            err instanceof Error
              ? err.message
              : '写入本地存储失败，请导出加密备份',
          occurredAt: Date.now(),
        };
        setPersistenceWarning(warning);
        setSyncMessage(`本地存储告警：${warning.message}`);
      }

      setEncryptedPayload(payload);
      setMemoryKey(derivedKey);
      setMemorySalt(salt);
      setDecryptedRecords(initialRecords);
      setCategories(initialCategories);
      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus('local_saved');
    },
    []
  );

  // Unlock Existing Formal V2 Encrypted Vault
  const handleUnlockVault = useCallback(
    async (masterPassword: string) => {
      const localVault =
        SyncService.getLocalVault() ??
        (await SyncService.hydrateFromIndexedDB());
      if (!localVault) {
        throw new Error('未找到本地 V2 加密密码库');
      }

      const unlocked = await unlockEncryptedVaultPayload(
        localVault,
        masterPassword
      );

      setIsDemoMode(false);
      setDemoEncryptedPayload(null);
      setAutoLockNotice(null);
      setEncryptedPayload(unlocked.payload);
      setMemoryKey(unlocked.key);
      setMemorySalt(unlocked.payload.kdf.salt);
      setDecryptedRecords(unlocked.records);
      setCategories(unlocked.categories);
      setSyncStatus(SyncService.computeSyncStatus());
      setConflictInfo(SyncService.getLocalSyncState().conflictState);
    },
    []
  );

  // Enter Strictly Isolated In-Memory Demo Sandbox (Never touches localStorage/IndexedDB or Cloudflare Worker)
  const handleEnterIsolatedDemoMode = useCallback(async () => {
    const demoRecords = createInitialSeedRecords();
    const session = await createEphemeralDemoSession(demoRecords);

    setIsDemoMode(true);
    setAutoLockNotice(null);
    setDemoEncryptedPayload(session.ephemeralPayload);
    setMemoryKey(session.ephemeralKey);
    setMemorySalt(session.ephemeralSalt);
    setDecryptedRecords(session.records);
    setCategories(session.categories);
    setSyncStatus('local_saved');
    setSyncMessage('演示沙盒模式：仅内存运行，已隔离本地正式库与云端同步');
  }, []);

  // Immediate One-Click Lock (Wipes Key, Plaintext, and Demo Sandbox from React State)
  const handleLockVault = useCallback(() => {
    setMemoryKey(null);
    setMemorySalt(null);
    setDecryptedRecords([]);
    setCategories(getInitialDefaultCategories());
    setIsDemoMode(false);
    setDemoEncryptedPayload(null);
    setEncryptedPayload(SyncService.getLocalVault());
    setEditingRecord(null);
    setIsRecordModalOpen(false);
    setIsImportModalOpen(false);
    setIsCategoryModalOpen(false);
    setIsMasterPasswordModalOpen(false);
    setStagedPull(null);
    setNeedsRemotePasswordPrompt(false);
  }, []);

  // Automatic Idle Vault Lock (wipes in-memory CryptoKey & plaintext after 5 minutes of user inactivity)
  useEffect(() => {
    if (!memoryKey || typeof window === 'undefined') {
      return;
    }

    let timeoutId: number | undefined;

    const resetIdleTimer = () => {
      if (timeoutId !== undefined) {
        window.clearTimeout(timeoutId);
      }
      timeoutId = window.setTimeout(() => {
        handleLockVault();
        setAutoLockNotice(
          '因超过 5 分钟无活动操作，AegisVault 已自动安全锁定密码库并擦除内存解密密钥。'
        );
      }, IDLE_AUTO_LOCK_MS);
    };

    const activityEvents: Array<keyof WindowEventMap> = [
      'pointerdown',
      'keydown',
      'wheel',
      'touchstart',
    ];

    activityEvents.forEach((evt) =>
      window.addEventListener(evt, resetIdleTimer, { passive: true })
    );
    resetIdleTimer();

    return () => {
      if (timeoutId !== undefined) {
        window.clearTimeout(timeoutId);
      }
      activityEvents.forEach((evt) =>
        window.removeEventListener(evt, resetIdleTimer)
      );
    };
  }, [memoryKey, handleLockVault]);

  // Reset Local Vault (atomically wipes both IndexedDB and localStorage V2 keys, increments resetEpoch)
  const handleResetVault = useCallback(() => {
    const existing = SyncService.getLocalVault();
    if (existing) {
      SyncService.saveRollbackBackup(existing);
      setHasRollbackBackup(true);
    }
    void SyncService.clearLocalVaultAsync();
    setEncryptedPayload(null);
    setDemoEncryptedPayload(null);
    setIsDemoMode(false);
    setMemoryKey(null);
    setMemorySalt(null);
    setDecryptedRecords([]);
    setCategories(getInitialDefaultCategories());
    setRecoverySummary(null);
    setConflictInfo(null);
    setPersistenceWarning(null);
  }, []);

  // Probe Remote Vault without modifying localStorage
  const handleProbeCloudVault = useCallback(
    async (cfg: CloudflareSyncConfig) => {
      return SyncService.probeRemoteVaultForRecovery(cfg);
    },
    []
  );

  // Parse Encrypted Backup JSON File in temporary memory
  const handleParseBackupFileVault = useCallback((rawJsonText: string) => {
    return SyncService.parseBackupFileForRecovery(rawJsonText);
  }, []);

  // Verify original Master Password, authenticate all record & metadata ciphertexts, and commit recovery
  const handleExecuteVaultRecovery = useCallback(
    async (params: {
      candidatePayload: EncryptedVaultPayload;
      remoteRevision?: number;
      masterPassword: string;
      source: 'cloud' | 'backup-file';
      syncConfigToSave?: CloudflareSyncConfig;
      confirmOverwriteExistingLocal?: boolean;
    }) => {
      const result = await SyncService.verifyAndCommitRecoveryPayload(params);

      setIsDemoMode(false);
      setDemoEncryptedPayload(null);
      setEncryptedPayload(result.payload);
      setMemoryKey(result.key);
      setMemorySalt(result.salt);
      setDecryptedRecords(result.records);
      setCategories(result.categories);
      setRecoverySummary(result.recoverySummary);
      setHasRollbackBackup(Boolean(SyncService.getRollbackBackup()));
      setConflictInfo(null);
      setPersistenceWarning(null);

      if (params.syncConfigToSave && params.source === 'cloud') {
        setSyncConfig(SyncService.getSyncConfig());
        setSyncStatus('cloud_synced');
        setSyncMessage(
          `已从 Cloudflare Durable Object 恢复密码库 (Revision #${
            result.recoverySummary.revision ?? 1
          })`
        );
      } else {
        setSyncStatus('local_saved');
        setSyncMessage('已从 V2 加密备份文件完整恢复密码库至本地存储 (IndexedDB)');
      }

      if (typeof window !== 'undefined') {
        window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
      }
    },
    []
  );

  // Rollback to previous local vault before recovery/overwrite
  const handleRollbackToPreviousLocalVault = useCallback(() => {
    const restored = SyncService.restoreFromRollbackBackup();
    if (!restored) return;
    setMemoryKey(null);
    setMemorySalt(null);
    setDecryptedRecords([]);
    setCategories(getInitialDefaultCategories());
    setIsDemoMode(false);
    setDemoEncryptedPayload(null);
    setEncryptedPayload(restored);
    setRecoverySummary(null);
    setSyncStatus(SyncService.computeSyncStatus());
    setSyncMessage('已回退至覆盖前的原有本地加密密码库，请输入原主密码解锁');
  }, []);

  // V2 Master Password Change / Key Rotation (Preserves vaultId, generates new salt & key, re-encrypts all data)
  const handleRotateMasterPassword = useCallback(
    async (
      oldPassword: string,
      newPassword: string,
      purgePreviousCloudSnapshots: boolean
    ) => {
      if (isDemoMode) {
        throw new Error('演示沙盒不支持主密码轮换，请先返回正式密码库');
      }
      const currentVault = encryptedPayload ?? SyncService.getLocalVault();
      if (!currentVault) {
        throw new Error('未找到可轮换主密码的本地 V2 密码库');
      }

      SyncService.saveRollbackBackup(currentVault);
      setHasRollbackBackup(true);

      try {
        const rotated = await rotateVaultMasterPassword(
          currentVault,
          oldPassword,
          newPassword,
          currentVault.kdf.iterations
        );

        await SyncService.saveLocalVaultAsync(rotated.newPayload, {
          markDirty: true,
          pendingPasswordRotationPurge: purgePreviousCloudSnapshots,
        });

        setPersistenceWarning(null);
        setEncryptedPayload(rotated.newPayload);
        setMemoryKey(rotated.newKey);
        setMemorySalt(rotated.newSalt);
        setDecryptedRecords(rotated.records);
        setCategories(rotated.categories);
        setSyncStatus(SyncService.computeSyncStatus());
        setSyncMessage(
          '已完成 V2 主密码与密钥轮换（vaultId 保持不变，本地 IndexedDB 已更新，待同步云端）'
        );
      } catch (err) {
        SyncService.saveLocalVault(currentVault, { markDirty: false });
        throw err;
      }
    },
    [encryptedPayload, isDemoMode]
  );

  // Persist modified records and/or categories by re-encrypting with in-memory CryptoKey
  const persistUpdatedVault = useCallback(
    async (
      nextRecords: DecryptedVaultRecord[],
      nextCategoriesOverride?: VaultCategoryItem[]
    ) => {
      if (!memoryKey || !memorySalt) {
        throw new Error('密码库已锁定，内存密钥不存在');
      }

      const effectiveCategories = syncCategoriesWithRecords(
        nextCategoriesOverride ?? categories,
        nextRecords
      );

      // Isolated Demo Mode: update only in-memory demo state, NEVER write to localStorage/IndexedDB or Worker!
      if (isDemoMode) {
        const nextDemoPayload = await buildEncryptedVaultPayload(
          memoryKey,
          memorySalt,
          nextRecords,
          {
            vaultId: demoEncryptedPayload?.vaultId,
            categories: effectiveCategories,
            iterations: demoEncryptedPayload?.kdf.iterations,
            createdAt: demoEncryptedPayload?.createdAt,
            existingVerifier: demoEncryptedPayload?.verifier,
          }
        );
        setDemoEncryptedPayload(nextDemoPayload);
        setDecryptedRecords(nextRecords);
        setCategories(effectiveCategories);
        return;
      }

      const nextPayload = await buildEncryptedVaultPayload(
        memoryKey,
        memorySalt,
        nextRecords,
        {
          vaultId: encryptedPayload?.vaultId,
          categories: effectiveCategories,
          iterations: encryptedPayload?.kdf.iterations,
          createdAt: encryptedPayload?.createdAt,
          existingVerifier: encryptedPayload?.verifier,
        }
      );

      // Always keep in-memory state intact even if disk/IndexedDB throws QuotaExceededError
      setEncryptedPayload(nextPayload);
      setDecryptedRecords(nextRecords);
      setCategories(effectiveCategories);

      try {
        await SyncService.saveLocalVaultAsync(nextPayload, { markDirty: true });
        setPersistenceWarning(null);
      } catch (err) {
        const warning = SyncService.getLastPersistenceWarning() ?? {
          code: 'STORAGE_WRITE_FAILED',
          message:
            err instanceof Error
              ? err.message
              : '写入本地 IndexedDB 失败，请立即导出加密备份',
          occurredAt: Date.now(),
        };
        setPersistenceWarning(warning);
        setSyncStatus('failed');
        setSyncMessage(`本地存储写入失败：${warning.message}`);
        return;
      }

      const currentSyncCfg = SyncService.getSyncConfig();
      if (
        currentSyncCfg.autoSync &&
        currentSyncCfg.workerUrl.trim() &&
        currentSyncCfg.apiToken.trim()
      ) {
        setSyncStatus('syncing');
        const res = await SyncService.pushVault(nextPayload, currentSyncCfg);
        setSyncConfig(SyncService.getSyncConfig());
        setSyncStatus(res.status);
        setSyncMessage(res.message);
        setRequiresCloudInitConfirm(Boolean(res.requiresInitConfirmation));
        setConflictInfo(
          res.conflict ?? SyncService.getLocalSyncState().conflictState
        );
      } else {
        setSyncStatus(SyncService.computeSyncStatus(currentSyncCfg));
        setSyncMessage('本地已加密保存 (IndexedDB)');
      }
    },
    [
      memoryKey,
      memorySalt,
      categories,
      isDemoMode,
      demoEncryptedPayload,
      encryptedPayload,
    ]
  );

  // Retry saving in-memory encryptedPayload to local storage after a quota/transaction warning
  const handleRetryLocalSave = useCallback(async () => {
    if (!encryptedPayload || isDemoMode) return;
    try {
      SyncService.__setSimulatePersistenceFailureForTests(null);
      await SyncService.saveLocalVaultAsync(encryptedPayload, {
        markDirty: true,
      });
      SyncService.clearPersistenceWarning();
      setPersistenceWarning(null);
      setSyncStatus(SyncService.computeSyncStatus());
      setSyncMessage('本地已加密保存 (IndexedDB 重试成功)');
    } catch (err) {
      const warning = SyncService.getLastPersistenceWarning() ?? {
        code: 'STORAGE_WRITE_FAILED',
        message:
          err instanceof Error ? err.message : '重试本地写入仍然失败，请先导出备份',
        occurredAt: Date.now(),
      };
      setPersistenceWarning(warning);
    }
  }, [encryptedPayload, isDemoMode]);

  // Create or Update a Record
  const handleSaveRecord = useCallback(
    async (
      recordData: Omit<DecryptedVaultRecord, 'id' | 'createdAt' | 'updatedAt'>,
      existingId?: string
    ) => {
      const now = Date.now();
      let nextRecords: DecryptedVaultRecord[];

      if (existingId) {
        nextRecords = decryptedRecords.map((r) =>
          r.id === existingId
            ? {
                ...r,
                ...recordData,
                updatedAt: now,
              }
            : r
        );
      } else {
        const newRecord: DecryptedVaultRecord = {
          ...recordData,
          id: `rec-${now}-${Math.random().toString(36).slice(2, 7)}`,
          createdAt: now,
          updatedAt: now,
        };
        nextRecords = [newRecord, ...decryptedRecords];
      }

      await persistUpdatedVault(nextRecords);
    },
    [decryptedRecords, persistUpdatedVault]
  );

  // Delete a Record
  const handleDeleteRecord = useCallback(
    async (id: string) => {
      const nextRecords = decryptedRecords.filter((r) => r.id !== id);
      await persistUpdatedVault(nextRecords);
    },
    [decryptedRecords, persistUpdatedVault]
  );

  // Toggle Favorite
  const handleToggleFavorite = useCallback(
    async (record: DecryptedVaultRecord) => {
      const nextRecords = decryptedRecords.map((r) =>
        r.id === record.id
          ? { ...r, favorite: !r.favorite, updatedAt: Date.now() }
          : r
      );
      await persistUpdatedVault(nextRecords);
    },
    [decryptedRecords, persistUpdatedVault]
  );

  // Create Custom Category / Tag (Encrypted inside V2 encryptedMetadata!)
  const handleCreateCategory = useCallback(
    async (label: string): Promise<VaultCategoryItem> => {
      const { categories: nextCategories, created } = createCustomCategory(
        categories,
        label
      );
      await persistUpdatedVault(decryptedRecords, nextCategories);
      return created;
    },
    [categories, decryptedRecords, persistUpdatedVault]
  );

  // Rename Custom Category / Tag & Re-encrypt metadata + matching records
  const handleRenameCategory = useCallback(
    async (targetId: string, newLabel: string) => {
      const { categories: nextCategories, updatedRecords } =
        renameCustomCategory(categories, decryptedRecords, targetId, newLabel);
      await persistUpdatedVault(updatedRecords, nextCategories);
    },
    [categories, decryptedRecords, persistUpdatedVault]
  );

  // Delete Custom Category / Tag & Re-encrypt metadata + matching records
  const handleDeleteCategory = useCallback(
    async (targetId: string) => {
      const { categories: nextCategories, updatedRecords } =
        deleteCustomCategory(categories, decryptedRecords, targetId);
      await persistUpdatedVault(updatedRecords, nextCategories);
    },
    [categories, decryptedRecords, persistUpdatedVault]
  );

  // Save Cloud Sync Config
  const handleSaveSyncConfig = useCallback(
    (newConfig: CloudflareSyncConfig) => {
      SyncService.saveSyncConfig(newConfig);
      const updated = SyncService.getSyncConfig();
      setSyncConfig(updated);
      setSyncStatus(SyncService.computeSyncStatus(updated));
      setSyncMessage(
        newConfig.workerUrl.trim()
          ? `已保存 Cloudflare Durable Objects 节点配置：${newConfig.workerUrl}`
          : '已切换为本地加密存储模式 (IndexedDB)'
      );
    },
    []
  );

  // Clear Worker API Token immediately from memory and storage
  const handleClearApiToken = useCallback(() => {
    const updated = SyncService.clearApiToken();
    setSyncConfig(updated);
    setSyncStatus(SyncService.computeSyncStatus(updated));
    setSyncMessage('已清除保存在当前会话与设备中的 API Token 凭证');
  }, []);

  // Manual Push to Cloud (PUT /api/vault or explicit POST /api/vault/init)
  const handleTriggerPush = useCallback(
    async (
      cfg: CloudflareSyncConfig,
      options?: { allowAutoInitIfEmpty?: boolean }
    ) => {
      if (isDemoMode) {
        setSyncStatus('failed');
        setSyncMessage('演示沙盒模式下禁止上传虚拟数据至 Cloudflare Worker');
        return;
      }

      const currentPayload = encryptedPayload ?? SyncService.getLocalVault();
      if (!currentPayload) return;

      SyncService.saveSyncConfig(cfg);
      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus('syncing');

      const res = await SyncService.pushVault(currentPayload, cfg, options);
      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus(res.status);
      setSyncMessage(res.message);
      setRequiresCloudInitConfirm(Boolean(res.requiresInitConfirmation));
      setConflictInfo(
        res.conflict ?? SyncService.getLocalSyncState().conflictState
      );
    },
    [encryptedPayload, isDemoMode]
  );

  // Safe Staged Manual Pull from Cloud (GET /api/vault)
  const handleTriggerPull = useCallback(
    async (cfg: CloudflareSyncConfig, remoteMasterPassword?: string) => {
      if (isDemoMode) {
        setSyncStatus('failed');
        setSyncMessage('演示沙盒模式下禁止从 Cloudflare Worker 拉取数据');
        return;
      }

      SyncService.saveSyncConfig(cfg);
      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus('syncing');
      setStagedPull(null);

      try {
        const res = await SyncService.pullVault(cfg);
        if (!res.initialized || !res.payload) {
          setSyncStatus('failed');
          setSyncMessage('云端 Durable Object 尚未初始化加密密码库');
          return;
        }

        const staged = await SyncService.verifyAndStageRemotePull({
          remotePayload: res.payload,
          remoteRevision: res.revision,
          masterPassword: remoteMasterPassword,
          currentMemoryKey: memoryKey,
          currentMemorySalt: memorySalt,
          localPayload: encryptedPayload,
        });

        setNeedsRemotePasswordPrompt(false);

        if (staged.hasConflictWithLocal && encryptedPayload) {
          setStagedPull(staged);
          setSyncStatus('conflict');
          setSyncMessage(
            `远端版本 #${staged.remoteRevision} 已通过认证解密校验，检测到与本地存在差异，请确认是否覆盖本地`
          );
          return;
        }

        SyncService.commitVerifiedRemotePull(staged, cfg);
        setSyncConfig(SyncService.getSyncConfig());
        setEncryptedPayload(staged.remotePayload);
        setMemoryKey(staged.derivedKey);
        setMemorySalt(staged.remotePayload.kdf.salt);
        setDecryptedRecords(staged.decryptedRecords);
        setCategories(staged.decryptedCategories);
        setConflictInfo(null);
        setSyncStatus('cloud_synced');
        setSyncMessage(
          `已通过主密码完整性认证并同步至云端版本 #${staged.remoteRevision}`
        );
      } catch (err) {
        const msg =
          err instanceof Error
            ? err.message
            : '从 Cloudflare 拉取或认证解密失败';
        if (msg.startsWith('REMOTE_SALT_MISMATCH_NEEDS_PASSWORD:')) {
          setNeedsRemotePasswordPrompt(true);
          setSyncStatus('failed');
          setSyncMessage(
            msg.replace('REMOTE_SALT_MISMATCH_NEEDS_PASSWORD:', '')
          );
          return;
        }
        setSyncStatus('failed');
        setSyncMessage(msg);
      }
    },
    [isDemoMode, memoryKey, memorySalt, encryptedPayload]
  );

  // Confirm applying a verified staged remote pull over local data
  const handleConfirmStagedPull = useCallback(() => {
    if (!stagedPull) return;
    SyncService.commitVerifiedRemotePull(stagedPull, syncConfig);
    setSyncConfig(SyncService.getSyncConfig());
    setEncryptedPayload(stagedPull.remotePayload);
    setMemoryKey(stagedPull.derivedKey);
    setMemorySalt(stagedPull.remotePayload.kdf.salt);
    setDecryptedRecords(stagedPull.decryptedRecords);
    setCategories(stagedPull.decryptedCategories);
    setHasRollbackBackup(Boolean(SyncService.getRollbackBackup()));
    setStagedPull(null);
    setConflictInfo(null);
    setSyncStatus('cloud_synced');
    setSyncMessage(
      `已确认并用远端版本 #${stagedPull.remoteRevision} 更新本地密码库（原数据已生成回滚备份）`
    );
  }, [stagedPull, syncConfig]);

  // Cancel staged pull and keep existing local vault intact
  const handleCancelStagedPull = useCallback(() => {
    setStagedPull(null);
    setSyncStatus(SyncService.computeSyncStatus(syncConfig));
    setSyncMessage('已取消云端覆盖操作，本地加密密码库保持不变');
  }, [syncConfig]);

  // Resolve HTTP 409 Conflict
  const handleResolveConflict = useCallback(
    async (
      resolution: 'use_cloud' | 'keep_local_and_push',
      remotePassword?: string
    ) => {
      const res = await SyncService.resolveConflict({
        resolution,
        config: syncConfig,
        masterPassword: remotePassword,
        currentMemoryKey: memoryKey,
        currentMemorySalt: memorySalt,
      });

      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus(res.status);
      setSyncMessage(res.message);
      setConflictInfo(SyncService.getLocalSyncState().conflictState);
      setHasRollbackBackup(Boolean(SyncService.getRollbackBackup()));

      if (res.stagedCloud) {
        setEncryptedPayload(res.stagedCloud.remotePayload);
        setMemoryKey(res.stagedCloud.derivedKey);
        setMemorySalt(res.stagedCloud.remotePayload.kdf.salt);
        setDecryptedRecords(res.stagedCloud.decryptedRecords);
        setCategories(res.stagedCloud.decryptedCategories);
      }
    },
    [syncConfig, memoryKey, memorySalt]
  );

  // Restore Historical Cloud Snapshot (`GET /api/vault/history/:revision`)
  const handleRestoreHistorySnapshot = useCallback(
    async (revision: number, snapshotPassword?: string) => {
      const restored = await SyncService.restoreCloudHistorySnapshot({
        revision,
        config: syncConfig,
        masterPassword: snapshotPassword,
        currentMemoryKey: memoryKey,
        currentMemorySalt: memorySalt,
      });

      setEncryptedPayload(restored.payload);
      setMemoryKey(restored.key);
      setMemorySalt(restored.payload.kdf.salt);
      setDecryptedRecords(restored.records);
      setCategories(restored.categories);
      setRecoverySummary(restored.recoverySummary);
      setHasRollbackBackup(Boolean(SyncService.getRollbackBackup()));
      setSyncConfig(SyncService.getSyncConfig());
      setSyncStatus(SyncService.computeSyncStatus());
      setConflictInfo(null);
      setSyncMessage(
        `已从云端历史快照 Revision #${revision} 恢复密码库${
          restored.newCloudRevision
            ? `并同步为最新版本 #${restored.newCloudRevision}`
            : ''
        }`
      );
    },
    [syncConfig, memoryKey, memorySalt]
  );

  // Export Encrypted V2 Vault JSON as a local file for offline backup (Desktop, Windows Portable WebView2, and Android App)
  const handleExportEncryptedVault = useCallback(() => {
    const targetPayload = isDemoMode ? demoEncryptedPayload : encryptedPayload;
    const jsonString =
      SyncService.serializeEncryptedVaultForExport(targetPayload);
    const filename = SyncService.getBackupFilename();
    void exportBackupFileCrossPlatform(jsonString, filename);
  }, [isDemoMode, demoEncryptedPayload, encryptedPayload]);

  // Android Native Bridge: Listen for "Save Credential to AegisVault" & "Autofill Query" events
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleAndroidSaveCredential = (event: Event) => {
      const customEvt = event as CustomEvent<AndroidSaveCredentialRequest>;
      if (!customEvt.detail) return;
      const draft = normalizeAndroidSaveRequest(customEvt.detail);
      setEditingRecord(null);
      setPrefillRecordDraft(draft);
      if (memoryKey) {
        setIsRecordModalOpen(true);
      }
    };

    const handleAndroidAutofillQuery = (event: Event) => {
      const customEvt = event as CustomEvent<{
        domain?: string;
        androidPackageName?: string;
      }>;
      if (!memoryKey || !customEvt.detail) return;
      const candidates = matchRecordsForAndroidTarget(
        decryptedRecords,
        customEvt.detail
      );
      window.AegisAndroidBridge?.onAutofillCandidatesReady?.(
        JSON.stringify(candidates)
      );
    };

    window.addEventListener(
      'aegis:android-save-credential',
      handleAndroidSaveCredential
    );
    window.addEventListener(
      'aegis:android-autofill-query',
      handleAndroidAutofillQuery
    );
    return () => {
      window.removeEventListener(
        'aegis:android-save-credential',
        handleAndroidSaveCredential
      );
      window.removeEventListener(
        'aegis:android-autofill-query',
        handleAndroidAutofillQuery
      );
    };
  }, [memoryKey, decryptedRecords]);

  // If a credential save request arrived while locked, open RecordFormModal automatically once unlocked
  useEffect(() => {
    if (memoryKey && prefillRecordDraft && !isRecordModalOpen) {
      setIsRecordModalOpen(true);
    }
  }, [memoryKey, prefillRecordDraft, isRecordModalOpen]);

  const isUnlocked = Boolean(memoryKey);
  const currentSyncState = SyncService.getLocalSyncState();
  const isAnyModalOpen =
    isRecordModalOpen ||
    isGeneratorModalOpen ||
    isCiphertextModalOpen ||
    isCloudSyncModalOpen ||
    isImportModalOpen ||
    isCategoryModalOpen ||
    isMasterPasswordModalOpen;

  if (isHydratingStorage && !encryptedPayload && !isUnlocked) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-[#090d16] flex items-center justify-center p-6">
        <div className="text-center space-y-2">
          <div className="w-8 h-8 rounded-full border-2 border-blue-500 border-t-transparent animate-spin mx-auto" />
          <p className="text-xs font-mono text-slate-500 dark:text-slate-400">
            正在从本地加密存储 (IndexedDB) 校验密码库状态…
          </p>
        </div>
      </div>
    );
  }

  return (
    <>
      <PWAStatusBanner
        isUnlocked={isUnlocked}
        isEditingOrModalOpen={isAnyModalOpen}
        persistenceWarning={persistenceWarning}
        onRetryLocalSave={encryptedPayload ? handleRetryLocalSave : undefined}
        onExportBackup={
          activeEncryptedEnvelopePayload ? handleExportEncryptedVault : undefined
        }
        onDismissPersistenceWarning={() => {
          SyncService.clearPersistenceWarning();
          setPersistenceWarning(null);
        }}
      />

      {!isUnlocked ? (
        <MasterAuthScreen
          isInitialized={Boolean(encryptedPayload)}
          hasRollbackBackup={hasRollbackBackup}
          initialSyncConfig={syncConfig}
          onSetupMasterPassword={handleSetupMasterPassword}
          onUnlockVault={handleUnlockVault}
          onProbeCloudVault={handleProbeCloudVault}
          onParseBackupFileVault={handleParseBackupFileVault}
          onExecuteVaultRecovery={handleExecuteVaultRecovery}
          onRollbackToPreviousLocalVault={handleRollbackToPreviousLocalVault}
          onExportExistingLocalBackup={
            encryptedPayload ? handleExportEncryptedVault : undefined
          }
          onEnterIsolatedDemoMode={handleEnterIsolatedDemoMode}
          onResetVault={handleResetVault}
          onOpenCiphertextInspector={() => setIsCiphertextModalOpen(true)}
          darkMode={darkMode}
          themePreference={themePreference}
          onToggleDarkMode={handleToggleDarkMode}
          encryptedRecordCount={encryptedPayload?.encryptedRecords.length ?? 0}
          autoLockNotice={autoLockNotice}
          onDismissAutoLockNotice={() => setAutoLockNotice(null)}
        />
      ) : (
        <VaultWorkspace
          records={decryptedRecords}
          encryptedRecordsMap={encryptedRecordsMap}
          categories={categories}
          onLockVault={handleLockVault}
          onOpenNewRecord={() => {
            setEditingRecord(null);
            setPrefillRecordDraft(null);
            setIsRecordModalOpen(true);
          }}
          onOpenEditRecord={(rec) => {
            setEditingRecord(rec);
            setPrefillRecordDraft(null);
            setIsRecordModalOpen(true);
          }}
          onDeleteRecord={handleDeleteRecord}
          onToggleFavorite={handleToggleFavorite}
          onOpenPasswordGenerator={() => setIsGeneratorModalOpen(true)}
          onOpenCiphertextInspector={() => setIsCiphertextModalOpen(true)}
          onOpenImportVault={() => setIsImportModalOpen(true)}
          onOpenCategoryManager={() => setIsCategoryModalOpen(true)}
          onExportVault={handleExportEncryptedVault}
          onOpenCloudSync={() => setIsCloudSyncModalOpen(true)}
          onQuickSync={() => handleTriggerPush(syncConfig)}
          syncConfig={syncConfig}
          syncStatus={syncStatus}
          lastSyncedRevision={currentSyncState.lastSyncedRevision}
          darkMode={darkMode}
          themePreference={themePreference}
          onToggleDarkMode={handleToggleDarkMode}
          isDemoMode={isDemoMode}
          onOpenMasterPasswordModal={() => setIsMasterPasswordModalOpen(true)}
          recoverySummary={recoverySummary}
          onDismissRecoverySummary={() => setRecoverySummary(null)}
          onRollbackRecovery={
            hasRollbackBackup ? handleRollbackToPreviousLocalVault : undefined
          }
        />
      )}

      {/* Modals */}
      <RecordFormModal
        isOpen={isRecordModalOpen}
        onClose={() => {
          setIsRecordModalOpen(false);
          setEditingRecord(null);
          setPrefillRecordDraft(null);
        }}
        onSave={handleSaveRecord}
        editingRecord={editingRecord}
        prefillDraft={prefillRecordDraft}
        categories={categories}
        onOpenCategoryManager={() => setIsCategoryModalOpen(true)}
        onQuickCreateCategory={handleCreateCategory}
      />

      <PasswordGeneratorModal
        isOpen={isGeneratorModalOpen}
        onClose={() => setIsGeneratorModalOpen(false)}
      />

      <CiphertextInspectorModal
        isOpen={isCiphertextModalOpen}
        onClose={() => setIsCiphertextModalOpen(false)}
        onExportVault={
          activeEncryptedEnvelopePayload
            ? handleExportEncryptedVault
            : undefined
        }
      />

      <CloudSyncModal
        isOpen={isCloudSyncModalOpen}
        onClose={() => setIsCloudSyncModalOpen(false)}
        isDemoMode={isDemoMode}
        config={syncConfig}
        syncStatus={syncStatus}
        statusMessage={syncMessage}
        stagedPull={stagedPull}
        needsRemotePasswordPrompt={needsRemotePasswordPrompt}
        requiresCloudInitConfirmation={requiresCloudInitConfirm}
        conflictInfo={conflictInfo}
        onSaveConfig={handleSaveSyncConfig}
        onClearToken={handleClearApiToken}
        onTriggerPush={handleTriggerPush}
        onTriggerPull={handleTriggerPull}
        onConfirmStagedPull={handleConfirmStagedPull}
        onCancelStagedPull={handleCancelStagedPull}
        onResolveConflict={handleResolveConflict}
        onRestoreHistorySnapshot={handleRestoreHistorySnapshot}
        onExportLocalBackup={
          encryptedPayload ? handleExportEncryptedVault : undefined
        }
      />

      <ImportVaultModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        existingRecords={decryptedRecords}
        currentMemoryKey={memoryKey}
        currentEncryptedPayload={activeEncryptedEnvelopePayload}
        onConfirmMerge={persistUpdatedVault}
      />

      <CategoryManagerModal
        isOpen={isCategoryModalOpen}
        onClose={() => setIsCategoryModalOpen(false)}
        categories={categories}
        records={decryptedRecords}
        onCreateCategory={async (label) => {
          await handleCreateCategory(label);
        }}
        onRenameCategory={handleRenameCategory}
        onDeleteCategory={handleDeleteCategory}
      />

      <MasterPasswordModal
        isOpen={isMasterPasswordModalOpen}
        vaultId={encryptedPayload?.vaultId}
        onClose={() => setIsMasterPasswordModalOpen(false)}
        onExportBackupBeforeRotation={handleExportEncryptedVault}
        onRotateMasterPassword={handleRotateMasterPassword}
      />
    </>
  );
}
