import React, { useState, useEffect } from 'react';
import {
  X,
  Cloud,
  UploadCloud,
  DownloadCloud,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Trash2,
  Download,
  Activity,
  RefreshCw,
  History,
  GitCompare,
  Server,
  RotateCcw,
} from 'lucide-react';
import {
  CloudConflictInfo,
  CloudflareSyncConfig,
  SyncStatus,
  StagedRemotePullResult,
  VaultHistoryEntry,
  WorkerConnectivityProbeResult,
} from '../types/vault';
import {
  normalizeWorkerEndpoint,
  SyncService,
} from '../services/syncService';

interface CloudSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  isDemoMode?: boolean;
  config: CloudflareSyncConfig;
  syncStatus: SyncStatus;
  statusMessage: string;
  stagedPull: StagedRemotePullResult | null;
  needsRemotePasswordPrompt: boolean;
  requiresCloudInitConfirmation?: boolean;
  conflictInfo?: CloudConflictInfo | null;
  onSaveConfig: (config: CloudflareSyncConfig) => void;
  onClearToken: () => void;
  onTriggerPush: (
    config: CloudflareSyncConfig,
    options?: { allowAutoInitIfEmpty?: boolean }
  ) => Promise<void>;
  onTriggerPull: (
    config: CloudflareSyncConfig,
    remoteMasterPassword?: string
  ) => Promise<void>;
  onConfirmStagedPull: () => void;
  onCancelStagedPull: () => void;
  onResolveConflict?: (
    resolution: 'use_cloud' | 'keep_local_and_push',
    remotePassword?: string
  ) => Promise<void>;
  onRestoreHistorySnapshot?: (
    revision: number,
    snapshotPassword?: string
  ) => Promise<void>;
  onExportLocalBackup?: () => void;
}

type ModalTab = 'sync' | 'history' | 'deploy-guide';

export const CloudSyncModal: React.FC<CloudSyncModalProps> = ({
  isOpen,
  onClose,
  isDemoMode = false,
  config,
  syncStatus,
  statusMessage,
  stagedPull,
  needsRemotePasswordPrompt,
  requiresCloudInitConfirmation = false,
  conflictInfo = null,
  onSaveConfig,
  onClearToken,
  onTriggerPush,
  onTriggerPull,
  onConfirmStagedPull,
  onCancelStagedPull,
  onResolveConflict,
  onRestoreHistorySnapshot,
  onExportLocalBackup,
}) => {
  const [activeTab, setActiveTab] = useState<ModalTab>('sync');
  const [workerUrl, setWorkerUrl] = useState(config.workerUrl);
  const [apiToken, setApiToken] = useState(config.apiToken);
  const [rememberToken, setRememberToken] = useState(
    Boolean(config.rememberToken)
  );
  const [autoSync, setAutoSync] = useState(config.autoSync);
  const [remoteMasterPassword, setRemoteMasterPassword] = useState('');
  const [conflictPassword, setConflictPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // HTTP HEAD connectivity probe state
  const [isProbingConnectivity, setIsProbingConnectivity] = useState(false);
  const [connectivityResult, setConnectivityResult] =
    useState<WorkerConnectivityProbeResult | null>(null);

  // History snapshots state
  const [historySnapshots, setHistorySnapshots] = useState<VaultHistoryEntry[]>(
    []
  );
  const [historyCurrentRev, setHistoryCurrentRev] = useState<number>(0);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [restoringRevision, setRestoringRevision] = useState<number | null>(
    null
  );
  const [snapshotPasswordPromptRev, setSnapshotPasswordPromptRev] = useState<
    number | null
  >(null);
  const [snapshotPassword, setSnapshotPassword] = useState('');

  useEffect(() => {
    setWorkerUrl(config.workerUrl);
    setApiToken(config.apiToken);
    setRememberToken(Boolean(config.rememberToken));
    setAutoSync(config.autoSync);
  }, [config, isOpen]);

  if (!isOpen) return null;

  const syncState = SyncService.getLocalSyncState();
  const activeConflict = conflictInfo ?? syncState.conflictState;

  const buildCurrentConfig = (): CloudflareSyncConfig => ({
    workerUrl: workerUrl.trim(),
    apiToken: apiToken.trim(),
    rememberToken,
    autoSync,
    lastSyncedAt: config.lastSyncedAt,
  });

  const validateUrlBeforeAction = (): boolean => {
    setLocalError(null);
    if (!workerUrl.trim()) {
      setLocalError('请填写 Cloudflare Worker 节点地址');
      return false;
    }
    try {
      normalizeWorkerEndpoint(workerUrl);
      return true;
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Worker URL 格式无效');
      return false;
    }
  };

  const handleCheckConnectivity = async () => {
    setLocalError(null);
    setIsProbingConnectivity(true);
    try {
      const result = await SyncService.checkWorkerConnectivity(
        buildCurrentConfig()
      );
      setConnectivityResult(result);
    } finally {
      setIsProbingConnectivity(false);
    }
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    if (workerUrl.trim()) {
      try {
        normalizeWorkerEndpoint(workerUrl);
      } catch (err) {
        setLocalError(
          err instanceof Error ? err.message : 'Worker URL 格式无效'
        );
        return;
      }
    }
    onSaveConfig(buildCurrentConfig());
  };

  const handlePushNow = async (allowInit: boolean = false) => {
    if (isDemoMode) return;
    if (!validateUrlBeforeAction()) return;
    if (!apiToken.trim()) {
      setLocalError('同步操作需要提供有效的 Bearer API Token');
      return;
    }
    setIsLoading(true);
    try {
      const probe = await SyncService.checkWorkerConnectivity(
        buildCurrentConfig()
      );
      setConnectivityResult(probe);
      await onTriggerPush(buildCurrentConfig(), {
        allowAutoInitIfEmpty: allowInit,
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handlePullNow = async () => {
    if (isDemoMode) return;
    if (!validateUrlBeforeAction()) return;
    if (!apiToken.trim()) {
      setLocalError('拉取操作需要提供有效的 Bearer API Token');
      return;
    }
    setIsLoading(true);
    try {
      const probe = await SyncService.checkWorkerConnectivity(
        buildCurrentConfig()
      );
      setConnectivityResult(probe);
      await onTriggerPull(
        buildCurrentConfig(),
        remoteMasterPassword.trim() ? remoteMasterPassword : undefined
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearSavedToken = () => {
    setApiToken('');
    setRememberToken(false);
    setConnectivityResult(null);
    onClearToken();
  };

  const handleLoadHistory = async () => {
    if (!validateUrlBeforeAction()) return;
    if (!apiToken.trim()) {
      setHistoryError('查看云端历史快照需要提供有效的 Bearer API Token');
      return;
    }
    setIsLoadingHistory(true);
    setHistoryError(null);
    try {
      const res = await SyncService.listCloudHistory(buildCurrentConfig());
      setHistorySnapshots(res.snapshots);
      setHistoryCurrentRev(res.currentRevision);
    } catch (err) {
      setHistoryError(
        err instanceof Error ? err.message : '加载云端历史快照列表失败'
      );
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const handleTriggerRestoreSnapshot = async (
    revision: number,
    pwd?: string
  ) => {
    if (!onRestoreHistorySnapshot) return;
    setRestoringRevision(revision);
    setHistoryError(null);
    try {
      await onRestoreHistorySnapshot(revision, pwd);
      setSnapshotPasswordPromptRev(null);
      setSnapshotPassword('');
      await handleLoadHistory();
    } catch (err) {
      const msg = err instanceof Error ? err.message : '恢复历史快照失败';
      if (msg.startsWith('SNAPSHOT_NEEDS_PASSWORD:')) {
        setSnapshotPasswordPromptRev(revision);
        setHistoryError(msg.replace('SNAPSHOT_NEEDS_PASSWORD:', ''));
      } else {
        setHistoryError(msg);
      }
    } finally {
      setRestoringRevision(null);
    }
  };

  const handleResolveConflictAction = async (
    resolution: 'use_cloud' | 'keep_local_and_push'
  ) => {
    if (!onResolveConflict) return;
    setIsLoading(true);
    setLocalError(null);
    try {
      await onResolveConflict(
        resolution,
        conflictPassword.trim() ? conflictPassword : undefined
      );
      setConflictPassword('');
    } catch (err) {
      setLocalError(
        err instanceof Error ? err.message : '处理云端版本冲突失败'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cloud-sync-title"
    >
      <div className="w-full max-w-2xl rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-start sm:items-center justify-between gap-2 px-4 sm:px-6 py-3.5 sm:py-4 border-b border-slate-200 dark:border-slate-800 shrink-0">
          <div className="flex items-start sm:items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0 mt-0.5 sm:mt-0">
              <Cloud className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h2
                id="cloud-sync-title"
                className="text-sm sm:text-base font-bold text-slate-900 dark:text-white leading-snug"
              >
                Cloudflare Durable Objects 强一致零知识同步 (V2)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                基于 SQLite Durable Object 原子版本号 (Revision #
                {syncState.lastSyncedRevision}) 与 409 冲突保护
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭云同步配置窗口"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer shrink-0 min-h-[40px] min-w-[40px] flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Navigation Tabs (Single-line on mobile & desktop, never wraps into vertical columns) */}
        <div className="px-4 sm:px-6 pt-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center gap-1.5 sm:gap-2 bg-slate-50/60 dark:bg-slate-950/50 shrink-0 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('sync')}
            className={`px-3 sm:px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer min-h-[40px] ${
              activeTab === 'sync'
                ? 'border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-slate-900'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Cloud className="w-3.5 h-3.5 shrink-0" />
            <span className="sm:hidden">同步控制</span>
            <span className="hidden sm:inline">同步与冲突控制</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('history');
              if (workerUrl.trim() && apiToken.trim()) {
                void handleLoadHistory();
              }
            }}
            className={`px-3 sm:px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer min-h-[40px] ${
              activeTab === 'history'
                ? 'border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-slate-900'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <History className="w-3.5 h-3.5 shrink-0" />
            <span className="sm:hidden">历史快照</span>
            <span className="hidden sm:inline">历史加密快照 (History)</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('deploy-guide')}
            className={`px-3 sm:px-3.5 py-2 text-xs font-semibold rounded-t-lg border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer min-h-[40px] ${
              activeTab === 'deploy-guide'
                ? 'border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-slate-900'
                : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            <Server className="w-3.5 h-3.5 shrink-0" />
            <span className="sm:hidden">部署说明</span>
            <span className="hidden sm:inline">Durable Objects 部署说明</span>
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-5 flex-1">
          {isDemoMode && (
            <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/70 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                <div className="font-bold">
                  演示沙盒模式已彻底隔离云端同步
                </div>
                <p>
                  当前处于非持久化内存演示模式，虚拟演示数据禁止上传至 Cloudflare Worker，也禁止覆盖本地正式密码库。
                </p>
              </div>
            </div>
          )}

          {activeTab === 'sync' && (
            <>
              {/* 409 Conflict Resolution Panel */}
              {activeConflict && (
                <div
                  data-testid="cloud-conflict-panel"
                  className="p-4 rounded-xl bg-red-50 dark:bg-red-950/40 border-2 border-red-300 dark:border-red-800 space-y-3"
                >
                  <div className="flex items-start gap-2.5">
                    <GitCompare className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
                    <div className="text-xs space-y-1">
                      <div className="font-bold text-red-900 dark:text-red-200">
                        检测到云端版本冲突 (HTTP 409 · {activeConflict.code})
                      </div>
                      <p className="text-red-800 dark:text-red-300 leading-relaxed">
                        {activeConflict.message}
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2.5 text-xs font-mono bg-white/80 dark:bg-slate-900/80 p-3 rounded-lg border border-red-200 dark:border-red-900/60">
                    <div>
                      <div className="text-slate-500">本地状态 (Local)</div>
                      <div className="font-semibold text-slate-900 dark:text-white mt-0.5">
                        Revision #{activeConflict.localRevision}
                      </div>
                      <div className="text-slate-500 truncate">
                        Vault ID: {activeConflict.localVaultId.slice(0, 12)}…
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">云端状态 (Server DO)</div>
                      <div className="font-semibold text-blue-600 dark:text-blue-400 mt-0.5">
                        Revision #{activeConflict.serverRevision}
                      </div>
                      <div className="text-slate-500 truncate">
                        Vault ID:{' '}
                        {activeConflict.serverVaultId
                          ? `${activeConflict.serverVaultId.slice(0, 12)}…`
                          : 'N/A'}
                      </div>
                    </div>
                  </div>

                  <div>
                    <label
                      htmlFor="conflict-remote-password"
                      className="block text-xs font-semibold text-red-900 dark:text-red-200 mb-1"
                    >
                      若采用云端版本且云端使用了不同的盐值/主密码，请输入云端主密码（相同主密码可留空）：
                    </label>
                    <input
                      id="conflict-remote-password"
                      type="password"
                      value={conflictPassword}
                      onChange={(e) => setConflictPassword(e.target.value)}
                      placeholder="可选：输入远端密码库主密码以认证解密"
                      className="w-full px-3 py-1.5 text-xs rounded-lg bg-white dark:bg-slate-900 border border-red-300 dark:border-red-800 text-slate-900 dark:text-white"
                    />
                  </div>

                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {onExportLocalBackup && (
                      <button
                        type="button"
                        onClick={onExportLocalBackup}
                        className="px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-xs font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>1. 先导出本地备份</span>
                      </button>
                    )}
                    <button
                      type="button"
                      disabled={isLoading}
                      onClick={() => handleResolveConflictAction('use_cloud')}
                      className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                    >
                      <DownloadCloud className="w-3.5 h-3.5" />
                      <span>
                        采用云端版本 (#{activeConflict.serverRevision})
                      </span>
                    </button>
                    {(!activeConflict.serverVaultId ||
                      activeConflict.serverVaultId ===
                        activeConflict.localVaultId) && (
                      <button
                        type="button"
                        disabled={isLoading}
                        onClick={() =>
                          handleResolveConflictAction('keep_local_and_push')
                        }
                        className="px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                      >
                        <UploadCloud className="w-3.5 h-3.5" />
                        <span>
                          以本地版本为基础推送为 #
                          {activeConflict.serverRevision + 1}
                        </span>
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* Explicit First-Time Cloud Initialization Confirmation */}
              {requiresCloudInitConfirmation && !activeConflict && (
                <div
                  data-testid="cloud-init-confirm-panel"
                  className="p-4 rounded-xl bg-blue-50 dark:bg-blue-950/40 border-2 border-blue-300 dark:border-blue-800 space-y-3"
                >
                  <div className="text-xs text-blue-900 dark:text-blue-200 space-y-1">
                    <div className="font-bold">
                      确认首次初始化云端 Durable Object 密码库 (POST /api/vault/init)
                    </div>
                    <p>
                      探测到目标 Cloudflare Durable Object 当前尚未初始化 (Revision 0)。为防止误将本地密码库写入错误的空节点，请明确确认将当前本地密码库作为云端版本 <code className="font-mono">Revision #1</code> 初始化上传。
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={isLoading}
                      onClick={() => handlePushNow(true)}
                      className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                    >
                      <UploadCloud className="w-3.5 h-3.5" />
                      <span>确认首次初始化云端密码库 (Revision #1)</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Staged Pull Confirmation */}
              {stagedPull && (
                <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border-2 border-amber-300 dark:border-amber-800 space-y-3">
                  <div className="flex items-start gap-2.5">
                    <ShieldAlert className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                    <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                      <div className="font-bold">
                        远端密文已通过认证解密校验（检测到与本地存在差异）
                      </div>
                      <p>
                        远端版本 <code className="font-mono">#{stagedPull.remoteRevision}</code> 包含{' '}
                        <strong>{stagedPull.remoteRecordCount}</strong> 条记录，当前本地包含{' '}
                        <strong>{stagedPull.localRecordCount}</strong> 条记录。确认覆盖前系统将自动为您生成本地回滚备份。
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={onConfirmStagedPull}
                      className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold cursor-pointer"
                    >
                      确认用云端版本更新本地
                    </button>
                    <button
                      type="button"
                      onClick={onCancelStagedPull}
                      className="px-3.5 py-2 rounded-lg bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 text-xs font-medium cursor-pointer"
                    >
                      取消并保留本地数据
                    </button>
                  </div>
                </div>
              )}

              {/* Needs Remote Password Prompt */}
              {needsRemotePasswordPrompt && (
                <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 space-y-3">
                  <label
                    htmlFor="remote-vault-master-password"
                    className="block text-xs font-bold text-amber-900 dark:text-amber-200"
                  >
                    远端密码库使用了不同的随机盐值或主密码，请输入远端密码库的主密码以认证解密：
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id="remote-vault-master-password"
                      type="password"
                      value={remoteMasterPassword}
                      onChange={(e) => setRemoteMasterPassword(e.target.value)}
                      placeholder="输入远端密码库的主密码..."
                      className="flex-1 px-3.5 py-2 text-xs rounded-xl bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-700 text-slate-900 dark:text-white"
                    />
                    <button
                      type="button"
                      disabled={isLoading || !remoteMasterPassword.trim()}
                      onClick={handlePullNow}
                      className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold cursor-pointer"
                    >
                      验证并拉取
                    </button>
                  </div>
                </div>
              )}

              {/* Sync Configuration Form */}
              <form onSubmit={handleSave} className="space-y-4">
                <div>
                  <label
                    htmlFor="worker-url-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    Cloudflare Worker 节点地址 (生产环境强制 HTTPS)
                  </label>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                    <input
                      id="worker-url-input"
                      type="url"
                      value={workerUrl}
                      onChange={(e) => {
                        setWorkerUrl(e.target.value);
                        setConnectivityResult(null);
                      }}
                      placeholder="https://aegis-vault-sync.your-subdomain.workers.dev"
                      className="w-full sm:flex-1 min-w-0 px-3.5 py-2.5 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      disabled={isProbingConnectivity || !workerUrl.trim()}
                      onClick={handleCheckConnectivity}
                      className="w-full sm:w-auto justify-center px-3.5 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-50 text-slate-800 dark:text-slate-200 text-xs font-semibold flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer min-h-[42px]"
                    >
                      <Activity
                        className={`w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 ${
                          isProbingConnectivity ? 'animate-pulse' : ''
                        }`}
                      />
                      <span className="whitespace-nowrap">
                        {isProbingConnectivity ? '探测中...' : '检测连接 (HEAD)'}
                      </span>
                    </button>
                  </div>
                </div>

                {connectivityResult && (
                  <div
                    data-testid="worker-connectivity-banner"
                    className={`p-3 rounded-xl border text-xs flex items-center justify-between gap-2 ${
                      connectivityResult.reachable
                        ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-900/60 text-emerald-800 dark:text-emerald-300'
                        : 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-300'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {connectivityResult.reachable ? (
                        <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                      ) : (
                        <AlertCircle className="w-4 h-4 shrink-0 text-red-600 dark:text-red-400" />
                      )}
                      <span>{connectivityResult.message}</span>
                    </div>
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label
                      htmlFor="worker-token-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      Bearer API Token 访问凭证 (对应 Worker Secret API_TOKEN)
                    </label>
                    {apiToken && (
                      <button
                        type="button"
                        onClick={handleClearSavedToken}
                        className="text-xs text-red-600 dark:text-red-400 hover:underline flex items-center gap-1 cursor-pointer"
                      >
                        <Trash2 className="w-3 h-3" />
                        <span>立即清除凭证</span>
                      </button>
                    )}
                  </div>
                  <input
                    id="worker-token-input"
                    type="password"
                    value={apiToken}
                    onChange={(e) => {
                      setApiToken(e.target.value);
                      setConnectivityResult(null);
                    }}
                    placeholder="输入至少 16 位的随机访问令牌..."
                    className="w-full px-3.5 py-2.5 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                {/* Token Persistence Option */}
                <div className="space-y-2.5 pt-1">
                  <label className="flex items-start gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={rememberToken}
                      onChange={(e) => setRememberToken(e.target.checked)}
                      className="mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    />
                    <div className="text-xs">
                      <span className="font-semibold text-slate-800 dark:text-slate-200">
                        在此受信任设备上持久化记住 API Token
                      </span>
                      <p className="text-slate-500 dark:text-slate-400 mt-0.5">
                        默认不勾选（仅保存在当前会话内存中，关闭标签页自动销毁）。仅在您个人独享的受信任设备上勾选。
                      </p>
                    </div>
                  </label>

                  <label className="flex items-center gap-2.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={autoSync}
                      onChange={(e) => setAutoSync(e.target.checked)}
                      className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                    />
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      本地新增或修改记录时自动推送到云端 Durable Object
                    </span>
                  </label>
                </div>

                {(localError || statusMessage) && (
                  <div
                    className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
                      localError ||
                      syncStatus === 'failed' ||
                      syncStatus === 'conflict'
                        ? 'bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-900/60 text-red-600 dark:text-red-400'
                        : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300'
                    }`}
                  >
                    {localError ||
                    syncStatus === 'failed' ||
                    syncStatus === 'conflict' ? (
                      <AlertCircle className="w-4 h-4 shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500" />
                    )}
                    <span>{localError || statusMessage}</span>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pt-3 border-t border-slate-200 dark:border-slate-800">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      disabled={isDemoMode || isLoading}
                      onClick={() => handlePushNow(false)}
                      className="flex-1 sm:flex-initial justify-center px-3.5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer min-h-[42px] whitespace-nowrap"
                    >
                      <UploadCloud className="w-4 h-4 shrink-0" />
                      <span>立即推送到云端 (PUT)</span>
                    </button>
                    <button
                      type="button"
                      disabled={isDemoMode || isLoading}
                      onClick={handlePullNow}
                      className="flex-1 sm:flex-initial justify-center px-3.5 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-50 text-slate-800 dark:text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer min-h-[42px] whitespace-nowrap"
                    >
                      <DownloadCloud className="w-4 h-4 shrink-0" />
                      <span>从云端拉取并校验 (GET)</span>
                    </button>
                  </div>

                  <button
                    type="submit"
                    className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 text-white text-xs font-semibold transition-colors cursor-pointer min-h-[42px] whitespace-nowrap"
                  >
                    保存配置
                  </button>
                </div>
              </form>
            </>
          )}

          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white leading-snug">
                    云端 Durable Object 历史加密快照 (最多保留最近 15 个版本)
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    恢复任意历史快照前，系统会先在本地进行主密钥认证解密并自动备份当前本地密码库
                  </p>
                </div>
                <button
                  type="button"
                  disabled={isLoadingHistory}
                  onClick={handleLoadHistory}
                  className="self-start sm:self-auto px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer min-h-[38px]"
                >
                  <RefreshCw
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isLoadingHistory ? 'animate-spin' : ''
                    }`}
                  />
                  <span>刷新列表</span>
                </button>
              </div>

              {historyError && (
                <div className="p-3 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 text-xs text-red-600 dark:text-red-400 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{historyError}</span>
                </div>
              )}

              {snapshotPasswordPromptRev !== null && (
                <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 space-y-2">
                  <div className="text-xs font-semibold text-amber-900 dark:text-amber-200">
                    历史快照 Revision #{snapshotPasswordPromptRev}{' '}
                    需要输入创建该快照时的主密码：
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-2">
                    <input
                      type="password"
                      value={snapshotPassword}
                      onChange={(e) => setSnapshotPassword(e.target.value)}
                      placeholder="输入该历史版本对应的主密码..."
                      className="w-full sm:flex-1 px-3 py-2 text-xs rounded-lg bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-700 text-slate-900 dark:text-white"
                    />
                    <button
                      type="button"
                      disabled={!snapshotPassword.trim()}
                      onClick={() =>
                        handleTriggerRestoreSnapshot(
                          snapshotPasswordPromptRev,
                          snapshotPassword
                        )
                      }
                      className="w-full sm:w-auto px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold whitespace-nowrap cursor-pointer"
                    >
                      解密并恢复
                    </button>
                  </div>
                </div>
              )}

              {historySnapshots.length === 0 ? (
                <div className="p-8 text-center rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-500">
                  {isLoadingHistory
                    ? '正在从 Cloudflare Durable Object 读取历史快照...'
                    : '暂无云端历史快照（请先配置 Worker 地址与 Token 并完成同步）'}
                </div>
              ) : (
                <div className="divide-y divide-slate-200 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                  {historySnapshots.map((snap) => {
                    const isCurrent = snap.revision === historyCurrentRev;
                    return (
                      <div
                        key={snap.revision}
                        className="p-3.5 bg-white dark:bg-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs"
                      >
                        <div className="space-y-0.5 min-w-0">
                          <div className="flex items-center flex-wrap gap-2">
                            <span className="font-mono font-bold text-slate-900 dark:text-white whitespace-nowrap">
                              Revision #{snap.revision}
                            </span>
                            {isCurrent && (
                              <span className="px-2 py-0.5 rounded-md bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 text-xs font-semibold whitespace-nowrap">
                                当前云端版本
                              </span>
                            )}
                            <span className="text-slate-500 font-mono whitespace-nowrap">
                              {snap.recordCount} 条记录
                            </span>
                          </div>
                          <div className="text-xs text-slate-400 font-mono break-all">
                            {new Date(snap.createdAt).toLocaleString('zh-CN')} ·
                            SHA256: {snap.contentSha256.slice(0, 16)}…
                          </div>
                        </div>

                        <button
                          type="button"
                          disabled={restoringRevision === snap.revision}
                          onClick={() =>
                            handleTriggerRestoreSnapshot(snap.revision)
                          }
                          className="self-end sm:self-auto px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-blue-600 hover:text-white text-slate-700 dark:text-slate-300 font-semibold flex items-center gap-1 shrink-0 whitespace-nowrap transition-colors cursor-pointer min-h-[36px]"
                        >
                          <RotateCcw className="w-3.5 h-3.5 shrink-0" />
                          <span>
                            {restoringRevision === snap.revision
                              ? '恢复中...'
                              : '恢复此版本'}
                          </span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'deploy-guide' && (
            <div className="space-y-4 text-xs text-slate-600 dark:text-slate-300 leading-relaxed break-words">
              <div className="p-3.5 sm:p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="font-bold text-slate-900 dark:text-white">
                  独立 Cloudflare Worker + SQLite Durable Objects 部署架构
                </div>
                <p className="leading-relaxed">
                  AegisVault V2 已彻底移除具有最终一致性延迟的 Cloudflare KV，全面采用单实例强一致的{' '}
                  <code className="font-mono font-semibold text-blue-600 dark:text-blue-400 break-words">
                    VaultDurableObject (SQLite-backed)
                  </code>
                  ，完全兼容 Cloudflare Workers Free 免费计划（在{' '}
                  <code className="font-mono break-words">worker/wrangler.toml</code> 中使用{' '}
                  <code className="font-mono break-words">
                    new_sqlite_classes = [&quot;VaultDurableObject&quot;]
                  </code>
                  ）。
                </p>
              </div>

              <div className="p-3.5 sm:p-4 rounded-xl bg-slate-950 text-slate-200 font-mono space-y-2 border border-slate-800 overflow-x-auto">
                <div className="text-slate-400 break-words">
                  # 1. 进入仓库独立的 worker/ 目录并部署：
                </div>
                <div className="text-emerald-400 whitespace-nowrap">
                  cd worker &amp;&amp; npx wrangler deploy
                </div>
                <div className="text-slate-400 pt-2 break-words">
                  # 2. 通过 Cloudflare Secrets 配置高熵访问令牌（至少 16 位字符）：
                </div>
                <div className="text-emerald-400 whitespace-nowrap">
                  npx wrangler secret put API_TOKEN
                </div>
              </div>

              <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
                详细协议规范（<code className="font-mono">HEAD /api/vault</code>、
                <code className="font-mono">GET /api/vault</code>、
                <code className="font-mono">POST /api/vault/init</code>、
                <code className="font-mono">PUT /api/vault</code>、
                <code className="font-mono">GET /api/vault/history</code>）与安全说明请参阅项目仓库中的{' '}
                <code className="font-mono font-semibold">worker/README.md</code>。
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
