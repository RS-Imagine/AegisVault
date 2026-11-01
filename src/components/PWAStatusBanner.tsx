import React, { useEffect, useState, useCallback } from 'react';
import {
  AlertTriangle,
  Download,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  WifiOff,
  X,
} from 'lucide-react';
import { LocalStoragePersistenceWarning } from '../types/vault';

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

interface PWAStatusBannerProps {
  isUnlocked: boolean;
  isEditingOrModalOpen: boolean;
  persistenceWarning: LocalStoragePersistenceWarning | null;
  onRetryLocalSave?: () => void;
  onExportBackup?: () => void;
  onDismissPersistenceWarning?: () => void;
}

export const PWAStatusBanner: React.FC<PWAStatusBannerProps> = ({
  isUnlocked,
  isEditingOrModalOpen,
  persistenceWarning,
  onRetryLocalSave,
  onExportBackup,
  onDismissPersistenceWarning,
}) => {
  const [deferredInstallPrompt, setDeferredInstallPrompt] =
    useState<BeforeInstallPromptEvent | null>(null);
  const [installDismissed, setInstallDismissed] = useState(false);
  const [waitingWorker, setWaitingWorker] = useState<ServiceWorker | null>(
    null
  );
  const [swReadyOffline, setSwReadyOffline] = useState(false);
  const [isOfflineHint, setIsOfflineHint] = useState<boolean>(() =>
    typeof navigator !== 'undefined' ? !navigator.onLine : false
  );
  const [dismissedOfflineNotice, setDismissedOfflineNotice] = useState(false);

  useEffect(() => {
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredInstallPrompt(e as BeforeInstallPromptEvent);
    };

    const handleOnline = () => {
      setIsOfflineHint(false);
      setDismissedOfflineNotice(false);
    };
    const handleOffline = () => {
      setIsOfflineHint(true);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Register Service Worker with relative path ('./sw.js') for '/' and '/AegisVault/' support
    if (
      typeof window !== 'undefined' &&
      'serviceWorker' in navigator &&
      (window.location.protocol === 'https:' ||
        window.location.hostname === 'localhost' ||
        window.location.hostname === '127.0.0.1')
    ) {
      navigator.serviceWorker
        .register('./sw.js', { scope: './' })
        .then((registration) => {
          if (registration.active) {
            setSwReadyOffline(true);
          }
          if (registration.waiting) {
            setWaitingWorker(registration.waiting);
          }

          registration.addEventListener('updatefound', () => {
            const installing = registration.installing;
            if (!installing) return;
            installing.addEventListener('statechange', () => {
              if (installing.state === 'installed') {
                if (navigator.serviceWorker.controller) {
                  // New version available; hold in waiting state without interrupting active vault
                  setWaitingWorker(installing);
                } else {
                  setSwReadyOffline(true);
                }
              } else if (installing.state === 'activated') {
                setSwReadyOffline(true);
              }
            });
          });
        })
        .catch(() => {
          // Ignore SW registration failure in restricted iframe environments
        });
    }

    return () => {
      window.removeEventListener(
        'beforeinstallprompt',
        handleBeforeInstallPrompt
      );
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const handleInstallPwa = useCallback(async () => {
    if (!deferredInstallPrompt) return;
    try {
      await deferredInstallPrompt.prompt();
      await deferredInstallPrompt.userChoice;
    } finally {
      setDeferredInstallPrompt(null);
    }
  }, [deferredInstallPrompt]);

  const handleApplySwUpdate = useCallback(() => {
    if (!waitingWorker) return;
    const onControllerChange = () => {
      navigator.serviceWorker.removeEventListener(
        'controllerchange',
        onControllerChange
      );
      window.location.reload();
    };
    navigator.serviceWorker.addEventListener(
      'controllerchange',
      onControllerChange
    );
    waitingWorker.postMessage({ type: 'SKIP_WAITING' });
  }, [waitingWorker]);

  return (
    <>
      {/* P0 Emergency Banner: Local Storage / IndexedDB Quota or Transaction Failure */}
      {persistenceWarning && (
        <div
          data-testid="persistence-warning-banner"
          className="bg-red-500/15 dark:bg-red-950/90 border-b border-red-500/40 px-4 py-2.5 text-xs text-red-900 dark:text-red-200 z-50"
        >
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <div className="flex items-start sm:items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0 mt-0.5 sm:mt-0" />
              <div>
                <span className="font-bold">本地持久化告警：</span>
                <span>{persistenceWarning.message}</span>
                <span className="block sm:inline sm:ml-1.5 text-[11px] opacity-90">
                  （当前会话内存中的解密记录仍完好保留，请勿直接关闭标签页）
                </span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              {onRetryLocalSave && (
                <button
                  type="button"
                  onClick={onRetryLocalSave}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  重试本地保存
                </button>
              )}
              {onExportBackup && (
                <button
                  type="button"
                  onClick={onExportBackup}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white dark:bg-slate-900 border border-red-500/40 text-red-700 dark:text-red-300 font-semibold hover:bg-red-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  导出加密备份 (JSON)
                </button>
              )}
              {onDismissPersistenceWarning && (
                <button
                  type="button"
                  onClick={onDismissPersistenceWarning}
                  className="p-1 rounded-lg hover:bg-red-500/20 text-red-700 dark:text-red-300 cursor-pointer"
                  title="关闭告警"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Offline Cold-Start & Local-First Assurance Banner */}
      {isOfflineHint && !dismissedOfflineNotice && (
        <div
          data-testid="pwa-offline-banner"
          className="bg-amber-500/12 dark:bg-amber-950/60 border-b border-amber-500/30 px-4 py-1.5 text-xs text-amber-900 dark:text-amber-200"
        >
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <WifiOff className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
              <span className="truncate">
                当前处于离线模式 · 本地密码库解锁、查阅、新增编辑与加密导出均完整可用
                {swReadyOffline ? '（PWA 离线壳已就绪）' : ''}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setDismissedOfflineNotice(true)}
              className="p-0.5 rounded hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 shrink-0 cursor-pointer"
              title="隐藏离线提示"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Non-Intrusive Service Worker Update Banner (Never auto-reloads while unlocked/editing) */}
      {waitingWorker && (
        <div
          data-testid="pwa-update-banner"
          className="bg-blue-500/12 dark:bg-blue-950/80 border-b border-blue-500/30 px-4 py-2 text-xs text-blue-900 dark:text-blue-200"
        >
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
              <span>
                AegisVault 新版本离线资源已下载就绪。
                {isUnlocked
                  ? '为保护已解锁会话与未保存修改，系统不会自动刷新。'
                  : '点击右侧按钮即可切换至最新版本。'}
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                disabled={isEditingOrModalOpen}
                onClick={handleApplySwUpdate}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold transition-colors cursor-pointer"
                title={
                  isEditingOrModalOpen
                    ? '请先保存或关闭当前弹窗后再刷新更新'
                    : '应用新版本并重新加载'
                }
              >
                <RefreshCw className="w-3.5 h-3.5" />
                {isEditingOrModalOpen ? '请先完成当前编辑' : '立即更新应用'}
              </button>
              <button
                type="button"
                onClick={() => setWaitingWorker(null)}
                className="px-2 py-1 rounded-lg hover:bg-blue-500/20 text-blue-700 dark:text-blue-300 cursor-pointer"
              >
                稍后
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Optional PWA Install Prompt */}
      {deferredInstallPrompt && !installDismissed && !isEditingOrModalOpen && (
        <div
          data-testid="pwa-install-banner"
          className="bg-slate-900/95 border-b border-slate-800 px-4 py-2 text-xs text-slate-200"
        >
          <div className="max-w-7xl mx-auto flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <Smartphone className="w-4 h-4 text-blue-400 shrink-0" />
              <span className="truncate">
                可将 AegisVault 安装到桌面或手机主屏幕，支持无网离线秒开与本地零知识解锁
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleInstallPwa}
                className="px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-colors cursor-pointer"
              >
                安装离线应用
              </button>
              <button
                type="button"
                onClick={() => setInstallDismissed(true)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 cursor-pointer"
                title="暂不安装"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
