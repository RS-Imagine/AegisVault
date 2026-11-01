import React, { useState, useRef } from 'react';
import {
  Shield,
  Eye,
  EyeOff,
  KeyRound,
  FileCode2,
  AlertCircle,
  ShieldAlert,
  ArrowRight,
  Sparkles,
  RotateCcw,
  Sun,
  Moon,
  CloudDownload,
  FileJson,
  CheckCircle2,
  Server,
  Upload,
  Download,
  RefreshCw,
  Undo2,
  Activity,
  Monitor,
  Clock,
} from 'lucide-react';
import {
  CloudflareSyncConfig,
  EncryptedVaultPayload,
  RemoteVaultProbeResult,
  WorkerConnectivityProbeResult,
} from '../types/vault';
import { evaluatePasswordStrength } from '../utils/passwordGenerator';
import { SyncService } from '../services/syncService';

export type AuthEntryTab = 'primary' | 'restore-cloud' | 'restore-file';

interface MasterAuthScreenProps {
  isInitialized: boolean;
  hasRollbackBackup?: boolean;
  initialSyncConfig?: CloudflareSyncConfig;
  onSetupMasterPassword: (
    password: string,
    includeSeedData: boolean
  ) => Promise<void>;
  onUnlockVault: (password: string) => Promise<void>;
  onProbeCloudVault: (
    config: CloudflareSyncConfig
  ) => Promise<RemoteVaultProbeResult>;
  onParseBackupFileVault: (rawJsonText: string) => RemoteVaultProbeResult;
  onExecuteVaultRecovery: (params: {
    candidatePayload: EncryptedVaultPayload;
    remoteRevision?: number;
    masterPassword: string;
    source: 'cloud' | 'backup-file';
    syncConfigToSave?: CloudflareSyncConfig;
    confirmOverwriteExistingLocal?: boolean;
  }) => Promise<void>;
  onRollbackToPreviousLocalVault?: () => void;
  onExportExistingLocalBackup?: () => void;
  onEnterIsolatedDemoMode: () => Promise<void>;
  onResetVault: () => void;
  onOpenCiphertextInspector: () => void;
  darkMode: boolean;
  themePreference?: 'system' | 'light' | 'dark';
  onToggleDarkMode: () => void;
  encryptedRecordCount: number;
  autoLockNotice?: string | null;
  onDismissAutoLockNotice?: () => void;
}

export const MasterAuthScreen: React.FC<MasterAuthScreenProps> = ({
  isInitialized,
  hasRollbackBackup = false,
  initialSyncConfig,
  onSetupMasterPassword,
  onUnlockVault,
  onProbeCloudVault,
  onParseBackupFileVault,
  onExecuteVaultRecovery,
  onRollbackToPreviousLocalVault,
  onExportExistingLocalBackup,
  onEnterIsolatedDemoMode,
  onResetVault,
  onOpenCiphertextInspector,
  darkMode,
  themePreference = 'system',
  onToggleDarkMode,
  encryptedRecordCount,
  autoLockNotice = null,
  onDismissAutoLockNotice,
}) => {
  const [activeTab, setActiveTab] = useState<AuthEntryTab>('primary');

  // Primary Create / Unlock state
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  // Formal vault creation defaults to FALSE (no sample accounts or bank cards injected by default)
  const [includeSeedData, setIncludeSeedData] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);

  // Cloud Recovery state (Independent from Create/Unlock state)
  const [workerUrl, setWorkerUrl] = useState(
    initialSyncConfig?.workerUrl ?? ''
  );
  const [apiToken, setApiToken] = useState(initialSyncConfig?.apiToken ?? '');
  const [rememberToken, setRememberToken] = useState(
    Boolean(initialSyncConfig?.rememberToken)
  );
  const [isProbingCloud, setIsProbingCloud] = useState(false);
  const [isCheckingHeadCloud, setIsCheckingHeadCloud] = useState(false);
  const [cloudHeadProbe, setCloudHeadProbe] =
    useState<WorkerConnectivityProbeResult | null>(null);
  const [cloudProbeResult, setCloudProbeResult] =
    useState<RemoteVaultProbeResult | null>(null);
  const [cloudMasterPassword, setCloudMasterPassword] = useState('');
  const [showCloudPassword, setShowCloudPassword] = useState(false);
  const [cloudConfirmOverwrite, setCloudConfirmOverwrite] = useState(false);
  const [cloudVerifyError, setCloudVerifyError] = useState<string | null>(null);
  const [isRestoringCloud, setIsRestoringCloud] = useState(false);

  // Backup File Recovery state (Independent from Create/Unlock and Cloud Recovery)
  const [backupFileName, setBackupFileName] = useState<string>('');
  const [backupRawJson, setBackupRawJson] = useState<string>('');
  const [fileProbeResult, setFileProbeResult] =
    useState<RemoteVaultProbeResult | null>(null);
  const [fileMasterPassword, setFileMasterPassword] = useState('');
  const [showFilePassword, setShowFilePassword] = useState(false);
  const [fileConfirmOverwrite, setFileConfirmOverwrite] = useState(false);
  const [fileVerifyError, setFileVerifyError] = useState<string | null>(null);
  const [isRestoringFile, setIsRestoringFile] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const strength = evaluatePasswordStrength(password);

  const handleSwitchTab = (tab: AuthEntryTab) => {
    setActiveTab(tab);
    setErrorMsg(null);
    setCloudVerifyError(null);
    setFileVerifyError(null);
  };

  const handleSubmitPrimary = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!isInitialized) {
      if (password.length < 8) {
        setErrorMsg('主密码长度至少需要 8 个字符。');
        return;
      }
      if (password !== confirmPassword) {
        setErrorMsg('两次输入的主密码不一致，请核对后重试。');
        return;
      }
      setIsSubmitting(true);
      try {
        await onSetupMasterPassword(password, includeSeedData);
      } catch (err) {
        setErrorMsg(
          err instanceof Error ? err.message : '初始化密码库失败，请重试。'
        );
      } finally {
        setIsSubmitting(false);
      }
    } else {
      if (!password) {
        setErrorMsg('请输入主密码以解锁密码库。');
        return;
      }
      setIsSubmitting(true);
      try {
        await onUnlockVault(password);
      } catch {
        setErrorMsg('主密码错误，请核对后重试。');
      } finally {
        setIsSubmitting(false);
      }
    }
  };

  // Cloud Step 0: Lightweight HTTP HEAD connectivity check
  const handleHeadProbeCloud = async () => {
    setCloudVerifyError(null);
    setIsCheckingHeadCloud(true);
    try {
      const cfg: CloudflareSyncConfig = {
        workerUrl: workerUrl.trim(),
        apiToken: apiToken.trim(),
        rememberToken,
        autoSync: true,
        lastSyncedAt: null,
      };
      const headRes = await SyncService.checkWorkerConnectivity(cfg);
      setCloudHeadProbe(headRes);
    } finally {
      setIsCheckingHeadCloud(false);
    }
  };

  // Cloud Step 1: Probe remote vault metadata in temporary memory (runs HEAD check first)
  const handleProbeCloud = async (e: React.FormEvent) => {
    e.preventDefault();
    setCloudVerifyError(null);
    setCloudConfirmOverwrite(false);
    setIsProbingCloud(true);

    try {
      const cfg: CloudflareSyncConfig = {
        workerUrl: workerUrl.trim(),
        apiToken: apiToken.trim(),
        rememberToken,
        autoSync: true,
        lastSyncedAt: null,
      };
      const headRes = await SyncService.checkWorkerConnectivity(cfg);
      setCloudHeadProbe(headRes);
      const result = await onProbeCloudVault(cfg);
      setCloudProbeResult(result);
    } catch (err) {
      setCloudProbeResult({
        status: 'network_error',
        message:
          err instanceof Error ? err.message : '检查远端密码库时发生网络异常',
      });
    } finally {
      setIsProbingCloud(false);
    }
  };

  // Cloud Step 2: Verify original Master Password & decrypt all records in memory before saving
  const handleCommitCloudRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cloudProbeResult?.candidatePayload) return;

    setCloudVerifyError(null);
    if (!cloudMasterPassword) {
      setCloudVerifyError('请输入创建该远端密码库时的原主密码。');
      return;
    }

    const needsOverwriteConfirm = Boolean(
      cloudProbeResult.metadata?.hasExistingLocalVault &&
        cloudProbeResult.metadata?.hasDifferenceFromLocal
    );
    if (needsOverwriteConfirm && !cloudConfirmOverwrite) {
      setCloudVerifyError(
        cloudProbeResult.metadata?.isDifferentVaultFromLocal
          ? '检测到远端密码库与当前设备本地密码库属于两个不同的密码库，请先勾选下方覆盖确认框。'
          : '当前设备已有本地密码库，请先勾选下方覆盖确认框后再执行恢复。'
      );
      return;
    }

    setIsRestoringCloud(true);
    try {
      const syncConfigToSave: CloudflareSyncConfig = {
        workerUrl: workerUrl.trim(),
        apiToken: apiToken.trim(),
        rememberToken,
        autoSync: true,
        lastSyncedAt: Date.now(),
      };
      await onExecuteVaultRecovery({
        candidatePayload: cloudProbeResult.candidatePayload,
        remoteRevision: cloudProbeResult.metadata?.revision,
        masterPassword: cloudMasterPassword,
        source: 'cloud',
        syncConfigToSave,
        confirmOverwriteExistingLocal: cloudConfirmOverwrite,
      });
    } catch (err) {
      const rawMsg =
        err instanceof Error ? err.message : '主密码验证或密文解密失败';
      setCloudVerifyError(rawMsg.replace(/^OVERWRITE_CONFIRM_REQUIRED:/, ''));
    } finally {
      setIsRestoringCloud(false);
    }
  };

  // Backup File Step 1: Upload or parse encrypted JSON text
  const handleBackupFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBackupFileName(file.name);
    setFileVerifyError(null);
    setFileConfirmOverwrite(false);

    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      setBackupRawJson(content);
      const parsed = onParseBackupFileVault(content);
      setFileProbeResult(parsed);
    };
    reader.onerror = () => {
      setFileProbeResult({
        status: 'corrupted_payload',
        message: '读取本地备份文件失败，请重试',
      });
    };
    reader.readAsText(file);
  };

  const handleParseBackupText = () => {
    setFileVerifyError(null);
    setFileConfirmOverwrite(false);
    const parsed = onParseBackupFileVault(backupRawJson);
    setFileProbeResult(parsed);
  };

  // Backup File Step 2: Verify original Master Password & decrypt all records before committing
  const handleCommitFileRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fileProbeResult?.candidatePayload) return;

    setFileVerifyError(null);
    if (!fileMasterPassword) {
      setFileVerifyError('请输入创建该加密备份文件时的原主密码。');
      return;
    }

    const needsOverwriteConfirm = Boolean(
      fileProbeResult.metadata?.hasExistingLocalVault &&
        fileProbeResult.metadata?.hasDifferenceFromLocal
    );
    if (needsOverwriteConfirm && !fileConfirmOverwrite) {
      setFileVerifyError(
        fileProbeResult.metadata?.isDifferentVaultFromLocal
          ? '检测到备份文件与当前设备本地密码库属于两个不同的密码库，请先勾选下方覆盖确认框。'
          : '当前设备已有本地密码库，请先勾选下方覆盖确认框后再执行恢复。'
      );
      return;
    }

    setIsRestoringFile(true);
    try {
      await onExecuteVaultRecovery({
        candidatePayload: fileProbeResult.candidatePayload,
        masterPassword: fileMasterPassword,
        source: 'backup-file',
        confirmOverwriteExistingLocal: fileConfirmOverwrite,
      });
    } catch (err) {
      const rawMsg =
        err instanceof Error ? err.message : '主密码验证或备份解密失败';
      setFileVerifyError(rawMsg.replace(/^OVERWRITE_CONFIRM_REQUIRED:/, ''));
    } finally {
      setIsRestoringFile(false);
    }
  };

  const handleStartIsolatedDemo = async () => {
    setErrorMsg(null);
    setIsSubmitting(true);
    try {
      await onEnterIsolatedDemoMode();
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : '启动内存演示沙盒失败'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col justify-between transition-colors">
      {/* Clean Header */}
      <header className="flex items-center justify-between gap-4 px-4 sm:px-6 py-4 border-b border-slate-200 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md">
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white">
            AegisVault
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {isInitialized && (
            <button
              type="button"
              onClick={onOpenCiphertextInspector}
              className="px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 min-h-[40px] cursor-pointer"
            >
              <FileCode2 className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
              <span className="hidden sm:inline">查看底层存储密文</span>
              <span className="sm:hidden">存储密文</span>
            </button>
          )}
          <button
            type="button"
            onClick={onToggleDarkMode}
            aria-label={
              themePreference === 'system'
                ? `当前跟随系统主题 (${darkMode ? '暗色' : '浅色'})，点击切换外观`
                : darkMode
                ? '当前暗色模式，点击切换外观'
                : '当前浅色模式，点击切换外观'
            }
            title={
              themePreference === 'system'
                ? `跟随系统主题 (${darkMode ? '暗色' : '浅色'}) · 点击切换`
                : darkMode
                ? '固定暗色模式 · 点击切换'
                : '固定浅色模式 · 点击切换'
            }
            className="px-2.5 py-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors min-h-[40px] flex items-center gap-1.5 text-xs font-medium cursor-pointer"
          >
            {themePreference === 'system' ? (
              <Monitor className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            ) : darkMode ? (
              <Moon className="w-4 h-4 text-amber-400" />
            ) : (
              <Sun className="w-4 h-4 text-amber-500" />
            )}
            <span className="hidden sm:inline">
              {themePreference === 'system'
                ? '跟随系统'
                : darkMode
                ? '深色'
                : '浅色'}
            </span>
          </button>
        </div>
      </header>

      {/* Centered Focused Auth & Cross-Device Recovery Card */}
      <main className="flex-1 flex items-center justify-center px-3 sm:px-4 py-6 sm:py-10">
        <div className="w-full max-w-xl p-5 sm:p-8 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between space-y-6">
          {/* Idle Auto-Lock Security Notice */}
          {autoLockNotice && (
            <div
              role="status"
              data-testid="idle-auto-lock-notice"
              className="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 text-xs text-amber-900 dark:text-amber-200 flex items-center justify-between gap-2"
            >
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <span>{autoLockNotice}</span>
              </div>
              {onDismissAutoLockNotice && (
                <button
                  type="button"
                  onClick={onDismissAutoLockNotice}
                  className="px-2 py-1 rounded-md bg-amber-100 dark:bg-amber-900/60 hover:bg-amber-200 text-amber-900 dark:text-amber-100 font-semibold shrink-0 cursor-pointer"
                >
                  知道了
                </button>
              )}
            </div>
          )}
          {/* 3 Explicit Entry Points Switcher */}
          <div
            role="tablist"
            aria-label="密码库初始化与恢复入口"
            className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 p-1.5 rounded-xl bg-slate-100 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800"
          >
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'primary'}
              data-testid="auth-mode-primary"
              onClick={() => handleSwitchTab('primary')}
              className={`py-2.5 px-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 whitespace-nowrap transition-all cursor-pointer min-h-[42px] ${
                activeTab === 'primary'
                  ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5 shrink-0" />
              <span>{isInitialized ? '解锁本地密码库' : '创建新密码库'}</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'restore-cloud'}
              data-testid="auth-mode-restore-cloud"
              onClick={() => handleSwitchTab('restore-cloud')}
              className={`py-2.5 px-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 whitespace-nowrap transition-all cursor-pointer min-h-[42px] ${
                activeTab === 'restore-cloud'
                  ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <CloudDownload className="w-3.5 h-3.5 shrink-0" />
              <span>从云端恢复密码库</span>
            </button>

            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'restore-file'}
              data-testid="auth-mode-restore-file"
              onClick={() => handleSwitchTab('restore-file')}
              className={`py-2.5 px-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 whitespace-nowrap transition-all cursor-pointer min-h-[42px] ${
                activeTab === 'restore-file'
                  ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              <FileJson className="w-3.5 h-3.5 shrink-0" />
              <span>从加密备份文件恢复</span>
            </button>
          </div>

          {/* ==============================================================
              TAB 1: CREATE NEW VAULT / UNLOCK EXISTING LOCAL VAULT
             ============================================================== */}
          {activeTab === 'primary' && (
            <form onSubmit={handleSubmitPrimary} className="space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white">
                    {isInitialized ? '解锁私人密码库' : '创建新密码库'}
                  </h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    {isInitialized
                      ? `当前设备共保管 ${encryptedRecordCount} 条加密记录，请输入主密码解锁`
                      : '请设置并牢记您的独立主密码，在本地派生 AES-256-GCM 密钥保护所有账号与银行卡'}
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-blue-600 dark:text-blue-400 shrink-0">
                  <KeyRound className="w-5 h-5" />
                </div>
              </div>

              {errorMsg && (
                <div
                  role="alert"
                  className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300"
                >
                  <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                  <span>{errorMsg}</span>
                </div>
              )}

              <div className="space-y-1.5">
                <label
                  htmlFor="master-password-input"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                >
                  主密码
                </label>
                <div className="relative">
                  <input
                    id="master-password-input"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={
                      isInitialized
                        ? '输入主密码解锁...'
                        : '设置至少 8 位独立主密码...'
                    }
                    autoFocus
                    autoComplete={
                      isInitialized ? 'current-password' : 'new-password'
                    }
                    className="w-full px-3.5 py-2.5 pr-11 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? '隐藏主密码' : '显示主密码'}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg cursor-pointer"
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {!isInitialized && (
                <>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-500 dark:text-slate-400">
                        密码强度：
                        <span
                          className={`font-semibold ml-1 ${strength.colorClass}`}
                        >
                          {strength.label}
                        </span>
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex gap-1">
                      {[1, 2, 3, 4].map((step) => (
                        <div
                          key={step}
                          className={`h-full flex-1 rounded-full transition-colors ${
                            strength.score >= step
                              ? strength.barColorClass
                              : 'bg-slate-200 dark:bg-slate-800'
                          }`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label
                      htmlFor="confirm-master-password-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      确认主密码
                    </label>
                    <input
                      id="confirm-master-password-input"
                      type={showPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="再次输入相同的主密码..."
                      autoComplete="new-password"
                      className="w-full px-3.5 py-2.5 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all"
                    />
                  </div>

                  <label className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={includeSeedData}
                      onChange={(e) => setIncludeSeedData(e.target.checked)}
                      className="mt-0.5 w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    />
                    <div className="text-xs">
                      <div className="font-semibold text-slate-800 dark:text-slate-200">
                        添加虚拟示例模板记录（默认关闭）
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                        正式密码库默认创建为空白库；勾选后将添加虚拟示例数据
                      </div>
                    </div>
                  </label>
                </>
              )}

              <div className="pt-2 space-y-2.5">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white font-semibold text-sm flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer min-h-[44px]"
                >
                  <span>
                    {isSubmitting
                      ? '正在处理...'
                      : isInitialized
                      ? '解锁密码库'
                      : '创建密码库'}
                  </span>
                  <ArrowRight className="w-4 h-4" />
                </button>

                <button
                  type="button"
                  disabled={isSubmitting}
                  data-testid="enter-isolated-demo-btn"
                  onClick={handleStartIsolatedDemo}
                  className="w-full py-2.5 px-4 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-medium text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer min-h-[42px]"
                >
                  <Sparkles className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                  <span>进入隔离演示沙盒（仅内存虚拟数据 · 不改动正式库）</span>
                </button>
              </div>
            </form>
          )}

          {/* ==============================================================
              TAB 2: RESTORE VAULT FROM CLOUDFLARE WORKER
             ============================================================== */}
          {activeTab === 'restore-cloud' && (
            <div
              data-testid="cloud-restore-panel"
              className="space-y-5"
            >
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white">
                    从云端恢复密码库
                  </h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    连接您的 Cloudflare Worker 节点获取加密快照，在本地完成主密码 KDF 派生与全量密文认证解密后落盘
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 flex items-center justify-center text-blue-600 dark:text-blue-400 shrink-0">
                  <CloudDownload className="w-5 h-5" />
                </div>
              </div>

              {/* Step 1 Form: Worker HTTPS URL + API Token */}
              <form onSubmit={handleProbeCloud} className="space-y-4">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <label
                      htmlFor="cloud-restore-url-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      <span className="sm:hidden">1. Worker 同步地址 (HTTPS)</span>
                      <span className="hidden sm:inline">1. Cloudflare Worker 同步地址 (HTTPS)</span>
                    </label>
                    <button
                      type="button"
                      data-testid="cloud-restore-head-probe-btn"
                      disabled={
                        !workerUrl.trim() ||
                        isCheckingHeadCloud ||
                        isProbingCloud
                      }
                      onClick={handleHeadProbeCloud}
                      className="px-2.5 py-1 rounded-lg bg-blue-50 dark:bg-blue-950/60 hover:bg-blue-100 dark:hover:bg-blue-900/60 disabled:opacity-50 text-blue-700 dark:text-blue-300 text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer shrink-0 whitespace-nowrap"
                    >
                      {isCheckingHeadCloud ? (
                        <>
                          <RefreshCw className="w-3 h-3 animate-spin" />
                          <span>探测中...</span>
                        </>
                      ) : (
                        <>
                          <Activity className="w-3 h-3" />
                          <span className="sm:hidden">探测节点</span>
                          <span className="hidden sm:inline">快速探测节点 (HEAD)</span>
                        </>
                      )}
                    </button>
                  </div>
                  <input
                    id="cloud-restore-url-input"
                    data-testid="cloud-restore-url-input"
                    type="url"
                    value={workerUrl}
                    onChange={(e) => {
                      setWorkerUrl(e.target.value);
                      setCloudHeadProbe(null);
                      setCloudProbeResult(null);
                      setCloudVerifyError(null);
                    }}
                    placeholder="https://aegis-vault.your-subdomain.workers.dev"
                    required
                    className="w-full px-3.5 py-2.5 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />

                  {/* Instant HTTP HEAD Connectivity Feedback Badge */}
                  {cloudHeadProbe && (
                    <div
                      role="status"
                      data-testid="cloud-restore-connectivity-badge"
                      className={`mt-2 p-2.5 rounded-xl border text-xs flex items-start justify-between gap-2.5 ${
                        cloudHeadProbe.reachable
                          ? 'bg-emerald-50/70 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800/70 text-emerald-900 dark:text-emerald-200'
                          : 'bg-red-50/80 dark:bg-red-950/30 border-red-200 dark:border-red-900/60 text-red-800 dark:text-red-200'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {cloudHeadProbe.reachable ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                        )}
                        <div className="space-y-0.5">
                          <div className="font-bold">
                            {cloudHeadProbe.reachable
                              ? 'HTTP HEAD 连接探测通过（节点可达）'
                              : 'HTTP HEAD 连接探测未通过'}
                          </div>
                          <div className="text-[11px] opacity-90">
                            {cloudHeadProbe.message}
                          </div>
                        </div>
                      </div>
                      <div className="text-right font-mono text-[11px] shrink-0">
                        {typeof cloudHeadProbe.httpStatus === 'number' && (
                          <div className="font-semibold">
                            HTTP {cloudHeadProbe.httpStatus}
                          </div>
                        )}
                        <div>{cloudHeadProbe.latencyMs} ms</div>
                      </div>
                    </div>
                  )}
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="cloud-restore-token-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    2. API Token (Bearer 鉴权密钥)
                  </label>
                  <input
                    id="cloud-restore-token-input"
                    data-testid="cloud-restore-token-input"
                    type="password"
                    value={apiToken}
                    onChange={(e) => {
                      setApiToken(e.target.value);
                      setCloudHeadProbe(null);
                      setCloudProbeResult(null);
                      setCloudVerifyError(null);
                    }}
                    placeholder="输入 Worker 配置的 API_TOKEN Secret..."
                    autoComplete="off"
                    required
                    className="w-full px-3.5 py-2.5 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                <label className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    data-testid="cloud-restore-remember-token"
                    checked={rememberToken}
                    onChange={(e) => setRememberToken(e.target.checked)}
                    className="mt-0.5 w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                  />
                  <div className="text-xs">
                    <div className="font-semibold text-slate-800 dark:text-slate-200">
                      在此设备上记住 API Token（默认仅保存在当前会话内存）
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                      建议仅在受信任的私人设备上勾选；恢复期间绝不会向云端自动推送任何空库。
                    </div>
                  </div>
                </label>

                <button
                  type="submit"
                  disabled={isProbingCloud || isRestoringCloud}
                  data-testid="cloud-restore-probe-btn"
                  className="w-full py-2.5 px-4 rounded-xl bg-slate-900 dark:bg-slate-800 hover:bg-slate-800 dark:hover:bg-slate-700 disabled:opacity-60 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer min-h-[44px]"
                >
                  {isProbingCloud ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>正在执行 HEAD 探测并检查远端密码库...</span>
                    </>
                  ) : (
                    <>
                      <Server className="w-4 h-4 text-blue-400" />
                      <span>连接并检查远端密码库</span>
                    </>
                  )}
                </button>
              </form>

              {/* Probe Diagnostic Result: Remote Vault Not Initialized (404 / Empty) */}
              {cloudProbeResult &&
                cloudProbeResult.status === 'not_initialized' && (
                  <div
                    role="status"
                    data-testid="cloud-restore-not-initialized"
                    className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/80 space-y-2.5 text-xs text-amber-900 dark:text-amber-100"
                  >
                    <div className="flex items-start gap-2.5">
                      <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <div className="font-bold">远端尚未初始化密码库</div>
                        <p className="leading-relaxed">
                          {cloudProbeResult.message}
                        </p>
                      </div>
                    </div>
                    <div className="pt-1 flex justify-end">
                      <button
                        type="button"
                        onClick={() => handleSwitchTab('primary')}
                        className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs cursor-pointer"
                      >
                        前往创建新密码库
                      </button>
                    </div>
                  </div>
                )}

              {/* Probe Diagnostic Result: Error States (401/403/500/Network/Corrupted) */}
              {cloudProbeResult &&
                cloudProbeResult.status !== 'ready' &&
                cloudProbeResult.status !== 'not_initialized' && (
                  <div
                    role="alert"
                    data-testid="cloud-restore-probe-error"
                    className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300"
                  >
                    <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-bold">远端密码库检查未通过</div>
                      <div className="mt-0.5">{cloudProbeResult.message}</div>
                    </div>
                  </div>
                )}

              {/* Step 2: Ready Snapshot Metadata + Master Password Verification */}
              {cloudProbeResult &&
                cloudProbeResult.status === 'ready' &&
                cloudProbeResult.metadata && (
                  <form
                    onSubmit={handleCommitCloudRecovery}
                    data-testid="cloud-restore-verify-form"
                    className="space-y-4 pt-3 border-t border-slate-200 dark:border-slate-800"
                  >
                    {/* Non-sensitive Remote Snapshot Metadata Card */}
                    <div
                      data-testid="cloud-restore-snapshot-card"
                      className="p-4 rounded-xl bg-emerald-50/70 dark:bg-emerald-950/25 border border-emerald-200 dark:border-emerald-800/60 space-y-2.5"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-900 dark:text-emerald-200">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                          <span>已获取远端加密快照（仅驻留临时内存）</span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/60 text-[11px] font-mono font-semibold text-emerald-800 dark:text-emerald-200">
                          v{cloudProbeResult.metadata.version} ·{' '}
                          {cloudProbeResult.metadata.saltFingerprint}
                        </span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 pt-1 text-xs">
                        <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-emerald-200/60 dark:border-slate-800">
                          <div className="text-slate-500 dark:text-slate-400">
                            远端密文记录数
                          </div>
                          <div
                            data-testid="cloud-snapshot-record-count"
                            className="font-bold text-slate-900 dark:text-white text-sm mt-0.5"
                          >
                            {cloudProbeResult.metadata.recordCount} 条记录
                          </div>
                        </div>
                        <div className="p-2.5 rounded-lg bg-white/80 dark:bg-slate-900/80 border border-emerald-200/60 dark:border-slate-800">
                          <div className="text-slate-500 dark:text-slate-400">
                            KDF 密钥派生参数
                          </div>
                          <div className="font-mono font-semibold text-slate-900 dark:text-white text-xs mt-0.5">
                            {cloudProbeResult.metadata.kdfAlgorithm} ·{' '}
                            {cloudProbeResult.metadata.kdfIterations.toLocaleString()}
                          </div>
                        </div>
                      </div>

                      <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        快照最后更新时间：
                        {new Date(
                          cloudProbeResult.metadata.updatedAt
                        ).toLocaleString('zh-CN')}
                      </div>
                    </div>

                    {/* Local Vault Conflict / Different Vault Identity Warning */}
                    {cloudProbeResult.metadata.hasExistingLocalVault &&
                      cloudProbeResult.metadata.hasDifferenceFromLocal && (
                        <div
                          role="alert"
                          data-testid="restore-local-conflict-warning"
                          className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 space-y-2.5 text-xs text-amber-900 dark:text-amber-100"
                        >
                          <div className="flex items-start gap-2">
                            <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                            <div className="space-y-1">
                              <div className="font-bold">
                                {cloudProbeResult.metadata
                                  .isDifferentVaultFromLocal
                                  ? '警告：远端密码库与当前设备本地密码库属于两个不同的密码库（禁止自动合并）'
                                  : '注意：当前设备已存在本地密码库且内容与远端存在差异'}
                              </div>
                              <p className="leading-relaxed">
                                当前设备本地存有{' '}
                                <strong>
                                  {cloudProbeResult.metadata.localRecordCount} 条
                                </strong>
                                记录，远端快照包含{' '}
                                <strong>
                                  {cloudProbeResult.metadata.recordCount} 条
                                </strong>
                                记录。为确保数据完整性，系统禁止自动合并两个不同密码库；恢复成功后将替换本地库，并自动将原本地库保存至可回退备份。
                              </p>
                            </div>
                          </div>

                          {onExportExistingLocalBackup && (
                            <div className="flex justify-end">
                              <button
                                type="button"
                                onClick={onExportExistingLocalBackup}
                                className="px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-800 border border-amber-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 font-semibold flex items-center gap-1.5 hover:bg-slate-100 cursor-pointer"
                              >
                                <Download className="w-3.5 h-3.5" />
                                <span>先导出当前本地加密备份</span>
                              </button>
                            </div>
                          )}

                          <label className="flex items-start gap-2 pt-1 cursor-pointer select-none font-semibold">
                            <input
                              type="checkbox"
                              data-testid="restore-confirm-overwrite-checkbox"
                              checked={cloudConfirmOverwrite}
                              onChange={(e) =>
                                setCloudConfirmOverwrite(e.target.checked)
                              }
                              className="mt-0.5 w-4 h-4 rounded border-amber-400 text-amber-600 focus:ring-amber-500"
                            />
                            <span>
                              我已知晓上述提示，确认在主密码验证通过后用该远端密码库替换当前本地密码库
                            </span>
                          </label>
                        </div>
                      )}

                    {cloudVerifyError && (
                      <div
                        role="alert"
                        data-testid="restore-verify-error"
                        className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300"
                      >
                        <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                        <span>{cloudVerifyError}</span>
                      </div>
                    )}

                    <div className="space-y-1.5">
                      <label
                        htmlFor="cloud-restore-password-input"
                        className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                      >
                        3. 输入原来的主密码（在本地派生密钥并解密验证全部记录）
                      </label>
                      <div className="relative">
                        <input
                          id="cloud-restore-password-input"
                          data-testid="cloud-restore-password-input"
                          type={showCloudPassword ? 'text' : 'password'}
                          value={cloudMasterPassword}
                          onChange={(e) =>
                            setCloudMasterPassword(e.target.value)
                          }
                          placeholder="输入创建该密码库时的原主密码..."
                          autoComplete="current-password"
                          className="w-full px-3.5 py-2.5 pr-11 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                        <button
                          type="button"
                          onClick={() =>
                            setShowCloudPassword(!showCloudPassword)
                          }
                          aria-label={
                            showCloudPassword ? '隐藏主密码' : '显示主密码'
                          }
                          className="absolute right-1.5 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg cursor-pointer"
                        >
                          {showCloudPassword ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    <button
                      type="submit"
                      disabled={isRestoringCloud}
                      data-testid="cloud-restore-commit-btn"
                      className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white font-semibold text-sm flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer min-h-[44px]"
                    >
                      <span>
                        {isRestoringCloud
                          ? '正在本地验证 KDF 与解密全部记录...'
                          : '验证主密码并恢复到本地密码库'}
                      </span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </form>
                )}
            </div>
          )}

          {/* ==============================================================
              TAB 3: RESTORE ENTIRE VAULT FROM ENCRYPTED BACKUP FILE
             ============================================================== */}
          {activeTab === 'restore-file' && (
            <div
              data-testid="file-restore-panel"
              className="space-y-5"
            >
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white">
                    从加密备份文件恢复
                  </h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    完整密码库恢复模式：验证原主密码与全部 AES-GCM 密文后，完整还原原密码库的盐值、验证块与所有记录
                  </p>
                </div>
                <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-blue-950/60 flex items-center justify-center text-blue-600 dark:text-blue-400 shrink-0">
                  <FileJson className="w-5 h-5" />
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/80 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  模式说明：
                </span>
                此入口用于在空白设备或新环境中<strong>完整恢复整个 AegisVault V2 加密密码库</strong>（<code className="font-mono">formatVersion: 2</code>，含独立 <code className="font-mono">vaultId</code>、加密分类元数据与 AAD 绑定记录）。若您只需将记录导入合并至已解锁的密码库，请先解锁后使用工作台顶部的「导入密码数据」。
              </div>

              <div className="space-y-3">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,application/json"
                  data-testid="file-restore-upload-input"
                  onChange={handleBackupFileUpload}
                  className="hidden"
                />

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="px-4 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-2 transition-colors cursor-pointer min-h-[42px]"
                  >
                    <Upload className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    <span>选择加密备份 JSON 文件</span>
                  </button>
                  {backupFileName && (
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400 truncate max-w-[220px]">
                      已选择：{backupFileName}
                    </span>
                  )}
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="file-restore-textarea"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    或直接粘贴加密备份 JSON 内容：
                  </label>
                  <textarea
                    id="file-restore-textarea"
                    data-testid="file-restore-textarea"
                    rows={4}
                    value={backupRawJson}
                    onChange={(e) => {
                      setBackupRawJson(e.target.value);
                      setFileProbeResult(null);
                      setFileVerifyError(null);
                    }}
                    placeholder='{"formatVersion":2,"vaultId":"...","kdf":{"algorithm":"PBKDF2-HMAC-SHA256",...},"verifier":{...},"encryptedMetadata":{...},"encryptedRecords":[...]}'
                    className="w-full p-3 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                <button
                  type="button"
                  onClick={handleParseBackupText}
                  disabled={!backupRawJson.trim()}
                  data-testid="file-restore-parse-btn"
                  className="w-full py-2.5 px-4 rounded-xl bg-slate-900 dark:bg-slate-800 hover:bg-slate-800 dark:hover:bg-slate-700 disabled:opacity-50 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors cursor-pointer min-h-[42px]"
                >
                  <FileJson className="w-4 h-4 text-blue-400" />
                  <span>解析并校验加密备份快照</span>
                </button>
              </div>

              {fileProbeResult && fileProbeResult.status !== 'ready' && (
                <div
                  role="alert"
                  data-testid="file-restore-probe-error"
                  className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300"
                >
                  <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                  <span>{fileProbeResult.message}</span>
                </div>
              )}

              {fileProbeResult &&
                fileProbeResult.status === 'ready' &&
                fileProbeResult.metadata && (
                  <form
                    onSubmit={handleCommitFileRecovery}
                    data-testid="file-restore-verify-form"
                    className="space-y-4 pt-3 border-t border-slate-200 dark:border-slate-800"
                  >
                    <div
                      data-testid="file-restore-snapshot-card"
                      className="p-4 rounded-xl bg-emerald-50/70 dark:bg-emerald-950/25 border border-emerald-200 dark:border-emerald-800/60 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-900 dark:text-emerald-200">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                          <span>备份结构校验通过（含 {fileProbeResult.metadata.recordCount} 条加密记录）</span>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/60 text-[11px] font-mono font-semibold text-emerald-800 dark:text-emerald-200">
                          v{fileProbeResult.metadata.version} ·{' '}
                          {fileProbeResult.metadata.saltFingerprint}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                        KDF: {fileProbeResult.metadata.kdfAlgorithm} (
                        {fileProbeResult.metadata.kdfIterations.toLocaleString()}{' '}
                        次迭代) · 备份时间：
                        {new Date(
                          fileProbeResult.metadata.updatedAt
                        ).toLocaleString('zh-CN')}
                      </div>
                    </div>

                    {fileProbeResult.metadata.hasExistingLocalVault &&
                      fileProbeResult.metadata.hasDifferenceFromLocal && (
                        <div
                          role="alert"
                          data-testid="file-restore-conflict-warning"
                          className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 space-y-2 text-xs text-amber-900 dark:text-amber-100"
                        >
                          <div className="font-bold">
                            {fileProbeResult.metadata.isDifferentVaultFromLocal
                              ? '警告：该备份文件与当前设备本地密码库属于两个不同的密码库（禁止自动合并）'
                              : '注意：当前设备已存在本地密码库且内容与该备份存在差异'}
                          </div>
                          <p>
                            当前本地共有{' '}
                            <strong>
                              {fileProbeResult.metadata.localRecordCount} 条
                            </strong>
                            记录。完整恢复将替换本地密码库（原本地库将自动保存至可回退备份）。
                          </p>
                          <label className="flex items-start gap-2 pt-1 cursor-pointer select-none font-semibold">
                            <input
                              type="checkbox"
                              data-testid="file-restore-confirm-overwrite-checkbox"
                              checked={fileConfirmOverwrite}
                              onChange={(e) =>
                                setFileConfirmOverwrite(e.target.checked)
                              }
                              className="mt-0.5 w-4 h-4 rounded border-amber-400 text-amber-600 focus:ring-amber-500"
                            />
                            <span>
                              确认在主密码验证通过后用该加密备份替换当前本地密码库
                            </span>
                          </label>
                        </div>
                      )}

                    {fileVerifyError && (
                      <div
                        role="alert"
                        data-testid="file-restore-verify-error"
                        className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-start gap-2.5 text-xs text-red-700 dark:text-red-300"
                      >
                        <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                        <span>{fileVerifyError}</span>
                      </div>
                    )}

                    <div className="space-y-1.5">
                      <label
                        htmlFor="file-restore-password-input"
                        className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                      >
                        输入该加密备份文件的原主密码
                      </label>
                      <div className="relative">
                        <input
                          id="file-restore-password-input"
                          data-testid="file-restore-password-input"
                          type={showFilePassword ? 'text' : 'password'}
                          value={fileMasterPassword}
                          onChange={(e) =>
                            setFileMasterPassword(e.target.value)
                          }
                          placeholder="输入创建该备份时的原主密码..."
                          autoComplete="current-password"
                          className="w-full px-3.5 py-2.5 pr-11 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
                        />
                        <button
                          type="button"
                          onClick={() => setShowFilePassword(!showFilePassword)}
                          aria-label={
                            showFilePassword ? '隐藏主密码' : '显示主密码'
                          }
                          className="absolute right-1.5 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg cursor-pointer"
                        >
                          {showFilePassword ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>

                    <button
                      type="submit"
                      disabled={isRestoringFile}
                      data-testid="file-restore-commit-btn"
                      className="w-full py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white font-semibold text-sm flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer min-h-[44px]"
                    >
                      <span>
                        {isRestoringFile
                          ? '正在验证主密码并解密全部记录...'
                          : '验证主密码并恢复完整密码库'}
                      </span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </form>
                )}
            </div>
          )}

          {/* Footer Controls for Existing Local Vault or Rollback */}
          {(isInitialized || hasRollbackBackup) && (
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-3">
                {isInitialized && (
                  <button
                    type="button"
                    onClick={onOpenCiphertextInspector}
                    className="text-blue-600 dark:text-blue-400 hover:underline font-medium flex items-center gap-1 cursor-pointer"
                  >
                    <FileCode2 className="w-3.5 h-3.5" />
                    <span>查看底层存储密文</span>
                  </button>
                )}

                {hasRollbackBackup && onRollbackToPreviousLocalVault && (
                  <button
                    type="button"
                    data-testid="auth-rollback-restore-btn"
                    onClick={onRollbackToPreviousLocalVault}
                    className="text-amber-600 dark:text-amber-400 hover:underline font-medium flex items-center gap-1 cursor-pointer"
                  >
                    <Undo2 className="w-3.5 h-3.5" />
                    <span>回退至覆盖前的本地密码库</span>
                  </button>
                )}
              </div>

              {isInitialized && (
                <>
                  {!confirmReset ? (
                    <button
                      type="button"
                      onClick={() => setConfirmReset(true)}
                      className="text-slate-400 hover:text-red-600 dark:hover:text-red-400 transition-colors flex items-center gap-1 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>重置本地密码库</span>
                    </button>
                  ) : (
                    <div className="flex items-center gap-2">
                      <span className="text-red-600 dark:text-red-400 font-medium">
                        确认清空？
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          setConfirmReset(false);
                          setPassword('');
                          setConfirmPassword('');
                          setErrorMsg(null);
                          onResetVault();
                        }}
                        className="px-2 py-1 rounded bg-red-600 text-white font-medium hover:bg-red-700 cursor-pointer"
                      >
                        确认重置
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmReset(false)}
                        className="px-2 py-1 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 cursor-pointer"
                      >
                        取消
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </main>

      <footer className="px-6 py-4 border-t border-slate-200 dark:border-slate-800/80 text-center text-xs text-slate-400 dark:text-slate-500">
        AegisVault 零知识私人密码管理器 · 主密码与明文永不离开本地设备
      </footer>
    </div>
  );
};

