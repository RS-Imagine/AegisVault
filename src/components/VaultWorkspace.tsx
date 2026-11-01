import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import {
  Shield,
  Lock,
  Plus,
  Search,
  Copy,
  Check,
  Eye,
  EyeOff,
  Edit3,
  Trash2,
  ExternalLink,
  Wand2,
  FileCode2,
  Download,
  Upload,
  Cloud,
  RefreshCw,
  Star,
  FolderOpen,
  Briefcase,
  Users,
  Landmark,
  Layers,
  Sun,
  Moon,
  ChevronLeft,
  CheckCircle2,
  AlertCircle,
  KeyRound,
  CreditCard,
  Tag,
  User,
  Monitor,
  Timer,
} from 'lucide-react';
import {
  DecryptedVaultRecord,
  EncryptedVaultRecord,
  FilterCategory,
  VaultCategoryItem,
  DEFAULT_CATEGORIES,
  CloudflareSyncConfig,
  SyncStatus,
  RecoverySummaryInfo,
} from '../types/vault';
import { evaluatePasswordStrength } from '../utils/passwordGenerator';
import {
  formatCardNumberGroups,
  maskCardNumber,
  maskCvvCode,
  isBankCardRecord,
  resolveRecordCardDetails,
} from '../utils/paymentCardUtils';
import {
  computeCategoryCounts,
  getCategoryDisplayLabel,
  recordMatchesCategoryFilter,
} from '../utils/categoryManager';
import { extractDomainFromUrl } from '../utils/brandVisuals';
import {
  RecordWebsiteLogo,
  BankCardMiniBadge,
  CreditCardFace,
} from './RecordVisuals';

interface VaultWorkspaceProps {
  records: DecryptedVaultRecord[];
  encryptedRecordsMap: Record<string, EncryptedVaultRecord>;
  categories?: VaultCategoryItem[];
  onLockVault: () => void;
  onOpenNewRecord: () => void;
  onOpenEditRecord: (record: DecryptedVaultRecord) => void;
  onDeleteRecord: (id: string) => Promise<void>;
  onToggleFavorite: (record: DecryptedVaultRecord) => Promise<void>;
  onOpenPasswordGenerator: () => void;
  onOpenCiphertextInspector: () => void;
  onOpenImportVault: () => void;
  onOpenCategoryManager: () => void;
  onExportVault: () => void;
  onOpenCloudSync: () => void;
  onQuickSync: () => Promise<void>;
  syncConfig: CloudflareSyncConfig;
  syncStatus: SyncStatus;
  lastSyncedRevision?: number;
  darkMode: boolean;
  themePreference?: 'system' | 'light' | 'dark';
  onToggleDarkMode: () => void;
  isDemoMode?: boolean;
  onOpenMasterPasswordModal?: () => void;
  recoverySummary?: RecoverySummaryInfo | null;
  onDismissRecoverySummary?: () => void;
  onRollbackRecovery?: () => void;
}

const BUILTIN_CATEGORY_ICONS: Record<string, React.ReactNode> = {
  all: <Layers className="w-4 h-4" />,
  'bank-card': <CreditCard className="w-4 h-4" />,
  social: <Users className="w-4 h-4" />,
  work: <Briefcase className="w-4 h-4" />,
  personal: <User className="w-4 h-4" />,
  finance: <Landmark className="w-4 h-4" />,
  other: <FolderOpen className="w-4 h-4" />,
};

export const VaultWorkspace: React.FC<VaultWorkspaceProps> = ({
  records,
  encryptedRecordsMap,
  categories = DEFAULT_CATEGORIES,
  onLockVault,
  onOpenNewRecord,
  onOpenEditRecord,
  onDeleteRecord,
  onToggleFavorite,
  onOpenPasswordGenerator,
  onOpenCiphertextInspector,
  onOpenImportVault,
  onOpenCategoryManager,
  onExportVault,
  onOpenCloudSync,
  onQuickSync,
  syncConfig,
  syncStatus,
  lastSyncedRevision = 0,
  darkMode,
  themePreference = 'system',
  onToggleDarkMode,
  isDemoMode = false,
  onOpenMasterPasswordModal,
  recoverySummary = null,
  onDismissRecoverySummary,
  onRollbackRecovery,
}) => {
  const [selectedCategory, setSelectedCategory] =
    useState<FilterCategory>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRecordId, setSelectedRecordId] = useState<string | null>(
    records[0]?.id ?? null
  );
  const [prevRecordCount, setPrevRecordCount] = useState<number>(records.length);
  const [mobileDetailOpen, setMobileDetailOpen] = useState(false);

  if (records.length !== prevRecordCount) {
    setPrevRecordCount(records.length);
    if (records.length > prevRecordCount && records[0]) {
      setSelectedRecordId(records[0].id);
    }
  }

  // Per-action visual feedback state & masking states
  const [revealedPasswords, setRevealedPasswords] = useState<
    Record<string, boolean>
  >({});
  const [revealedCardNumbers, setRevealedCardNumbers] = useState<
    Record<string, boolean>
  >({});
  const [revealedCvvs, setRevealedCvvs] = useState<Record<string, boolean>>({});
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [exportedFeedback, setExportedFeedback] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [verifiedRestoredIds, setVerifiedRestoredIds] = useState<
    Record<string, boolean>
  >({});

  const handleExportClick = () => {
    onExportVault();
    setExportedFeedback(true);
    setTimeout(() => setExportedFeedback(false), 2200);
  };

  const categoryCounts = useMemo(
    () => computeCategoryCounts(records, categories),
    [records, categories]
  );

  // If the currently selected category was deleted, fall back to 'all'
  const effectiveSelectedCategory = useMemo(() => {
    if (selectedCategory === 'all') return 'all';
    const exists = categories.some(
      (c) => c.id === selectedCategory || c.label === selectedCategory
    );
    return exists ? selectedCategory : 'all';
  }, [selectedCategory, categories]);

  const filteredRecords = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return records.filter((rec) => {
      if (
        !recordMatchesCategoryFilter(rec, effectiveSelectedCategory, categories)
      ) {
        return false;
      }
      if (!q) return true;
      const cardMatch = rec.cardDetails
        ? rec.cardDetails.cardholderName.toLowerCase().includes(q) ||
          rec.cardDetails.cardNumber.slice(-4).includes(q) ||
          (rec.cardDetails.brand ?? '').toLowerCase().includes(q)
        : false;
      const tagMatch = Array.isArray(rec.tags)
        ? rec.tags.some((t) => t.toLowerCase().includes(q))
        : false;
      return (
        rec.title.toLowerCase().includes(q) ||
        rec.username.toLowerCase().includes(q) ||
        rec.url.toLowerCase().includes(q) ||
        rec.notes.toLowerCase().includes(q) ||
        cardMatch ||
        tagMatch
      );
    });
  }, [records, effectiveSelectedCategory, categories, searchQuery]);

  const activeRecord = useMemo(() => {
    if (filteredRecords.length === 0) return null;
    const found = filteredRecords.find((r) => r.id === selectedRecordId);
    return found ?? filteredRecords[0];
  }, [filteredRecords, selectedRecordId]);

  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const [clipboardClearSeconds, setClipboardClearSeconds] = useState<
    number | null
  >(null);

  const scrubSensitiveClipboard = useCallback(async () => {
    setClipboardClearSeconds(null);
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Ignore clipboard write errors if window is unfocused
    }
  }, []);

  // Countdown timer to automatically scrub sensitive secrets from clipboard after 30 seconds
  useEffect(() => {
    if (clipboardClearSeconds === null) return;
    if (clipboardClearSeconds <= 0) {
      void scrubSensitiveClipboard();
      return;
    }
    const timer = window.setTimeout(() => {
      setClipboardClearSeconds((prev) =>
        prev !== null && prev > 0 ? prev - 1 : 0
      );
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [clipboardClearSeconds, scrubSensitiveClipboard]);

  const handleImmediateLock = useCallback(() => {
    if (clipboardClearSeconds !== null) {
      void scrubSensitiveClipboard();
    }
    onLockVault();
  }, [clipboardClearSeconds, scrubSensitiveClipboard, onLockVault]);

  // Global keyboard shortcuts: Cmd/Ctrl+K or '/' to focus search, Alt+L or Cmd/Ctrl+Shift+L to lock vault
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isEditable =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable);

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
        return;
      }

      if (!isEditable && e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        searchInputRef.current?.focus();
        return;
      }

      if (
        (e.altKey && e.key.toLowerCase() === 'l') ||
        ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === 'l')
      ) {
        e.preventDefault();
        handleImmediateLock();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleImmediateLock]);

  const handleCopy = async (
    text: string,
    fieldKey: string,
    isSensitive = false
  ) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard fallback in restricted iframe
    }
    setCopiedField(fieldKey);
    if (isSensitive && text) {
      setClipboardClearSeconds(30);
    }
    setTimeout(() => {
      setCopiedField((prev) => (prev === fieldKey ? null : prev));
    }, 2000);
  };

  const toggleRevealPassword = (id: string) => {
    setRevealedPasswords((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const toggleRevealCardNumber = (id: string) => {
    setRevealedCardNumbers((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const toggleRevealCvv = (id: string) => {
    setRevealedCvvs((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const activeEncryptedEnvelope = activeRecord
    ? encryptedRecordsMap[activeRecord.id]
    : undefined;

  const activeStrength = activeRecord
    ? evaluatePasswordStrength(activeRecord.password)
    : null;

  const isActivePaymentCard = isBankCardRecord(activeRecord);
  const activeCardDetails = useMemo(
    () =>
      activeRecord && isActivePaymentCard
        ? resolveRecordCardDetails(activeRecord)
        : null,
    [activeRecord, isActivePaymentCard]
  );

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col transition-colors">
      {/* Top Bar following 3-Zone Contract */}
      <header className="sticky top-0 z-30 flex items-center justify-between gap-2 sm:gap-4 lg:gap-8 px-3 sm:px-6 py-3 sm:py-3.5 border-b border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 backdrop-blur-md">
        {/* Zone 1: Brand Title */}
        <div className="flex items-center gap-2 sm:gap-2.5 whitespace-nowrap shrink-0">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-sm sm:text-base font-bold tracking-tight text-slate-900 dark:text-white">
            AegisVault
          </span>
        </div>

        {/* Zone 2: Concise Single-Line Navigation Links (5 links) */}
        <nav className="hidden md:flex items-center gap-4 lg:gap-6 text-xs font-medium text-slate-600 dark:text-slate-300">
          <button
            type="button"
            onClick={onOpenPasswordGenerator}
            className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer py-1"
          >
            <Wand2 className="w-3.5 h-3.5" />
            <span>随机密码生成器</span>
          </button>
          <button
            type="button"
            onClick={onOpenCiphertextInspector}
            className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer py-1"
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>查看底层存储密文</span>
          </button>
          <button
            type="button"
            onClick={onOpenImportVault}
            className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer py-1"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>导入密码数据</span>
          </button>
          <button
            type="button"
            onClick={handleExportClick}
            className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer py-1"
          >
            {exportedFeedback ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                  已导出密文备份
                </span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5" />
                <span>导出加密备份</span>
              </>
            )}
          </button>
          <button
            type="button"
            onClick={onOpenCloudSync}
            className="hover:text-blue-600 dark:hover:text-blue-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer py-1"
          >
            <Cloud className="w-3.5 h-3.5" />
            <span>云端同步配置</span>
          </button>
        </nav>

        {/* Zone 3: Theme Toggle + 1 Primary Action (Immediate Lock Vault) */}
        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {clipboardClearSeconds !== null && clipboardClearSeconds > 0 && (
            <div
              role="status"
              data-testid="clipboard-autoclear-badge"
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800/70 text-amber-800 dark:text-amber-200 text-xs font-medium"
            >
              <Timer className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
              <span className="font-mono tabular-nums">
                剪贴板 {clipboardClearSeconds}s 后自动擦除
              </span>
              <button
                type="button"
                onClick={() => void scrubSensitiveClipboard()}
                className="ml-1 underline hover:text-amber-950 dark:hover:text-white font-semibold cursor-pointer"
              >
                立即擦除
              </button>
            </div>
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
            className="px-2.5 py-2 rounded-xl text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors min-h-[44px] sm:min-h-[40px] flex items-center gap-1.5 text-xs font-medium cursor-pointer"
          >
            {themePreference === 'system' ? (
              <Monitor className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            ) : darkMode ? (
              <Moon className="w-4 h-4 text-amber-400" />
            ) : (
              <Sun className="w-4 h-4 text-amber-500" />
            )}
            <span className="hidden xl:inline">
              {themePreference === 'system'
                ? '跟随系统'
                : darkMode
                ? '深色'
                : '浅色'}
            </span>
          </button>
          <button
            type="button"
            onClick={handleImmediateLock}
            title="立即锁定密码库并清空内存密钥 (快捷键 Alt+L)"
            className="px-2.5 sm:px-3.5 py-2 text-xs font-semibold text-white bg-slate-900 dark:bg-slate-800 hover:bg-red-600 dark:hover:bg-red-600 rounded-xl transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer min-h-[44px] sm:min-h-[40px]"
          >
            <Lock className="w-3.5 h-3.5 shrink-0" />
            <span className="sm:hidden">
              {isDemoMode ? '退出演示' : '锁定'}
            </span>
            <span className="hidden sm:inline">
              {isDemoMode ? '退出演示沙盒' : '立即锁定密码库'}
            </span>
          </button>
        </div>
      </header>

      {/* Isolated Demo Sandbox Banner */}
      {isDemoMode && (
        <div
          role="status"
          data-testid="isolated-demo-mode-banner"
          className="bg-blue-600 text-white px-3 sm:px-6 py-1.5 sm:py-2 text-xs flex items-center justify-between gap-2"
        >
          <div className="flex items-center gap-2 font-medium min-w-0">
            <Shield className="w-3.5 h-3.5 shrink-0" />
            <span className="sm:hidden truncate">
              <strong>隔离演示沙盒</strong>：仅内存运行，不改动正式密码库
            </span>
            <span className="hidden sm:inline">
              当前处于<strong>隔离演示沙盒</strong>：所有虚拟记录仅在临时内存中运行，不会写入本地正式密码库，且已禁用 Cloudflare Worker 上传。
            </span>
          </div>
          <button
            type="button"
            onClick={onLockVault}
            className="px-2.5 py-1 rounded-lg bg-white/15 hover:bg-white/25 text-white font-semibold transition-colors cursor-pointer shrink-0 min-h-[34px] flex items-center"
          >
            <span className="sm:hidden">退出演示</span>
            <span className="hidden sm:inline">退出演示并返回正式库</span>
          </button>
        </div>
      )}

      {/* P1 Cross-Device Vault Recovery Success & Active Record Verification Banner */}
      {!isDemoMode && recoverySummary && (
        <div
          role="status"
          data-testid="recovery-success-banner"
          className="bg-emerald-50 dark:bg-emerald-950/40 border-b border-emerald-200 dark:border-emerald-800/70 px-4 sm:px-6 py-3 text-xs text-emerald-950 dark:text-emerald-100"
        >
          <div className="max-w-[1440px] mx-auto flex flex-col gap-2.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <div>
                  <span className="font-bold">
                    {recoverySummary.source === 'cloud'
                      ? '已从 Cloudflare Worker 云端安全恢复密码库：'
                      : '已从加密备份文件安全恢复完整密码库：'}
                  </span>
                  <span data-testid="recovery-summary-counts">
                    共恢复 <strong>{recoverySummary.recordCount} 条</strong>记录（
                    {recoverySummary.loginCount} 个账号凭证 ·{' '}
                    {recoverySummary.cardCount} 张银行卡 ·{' '}
                    {recoverySummary.categoryCount} 个分类）
                  </span>
                  <span className="ml-2 text-emerald-700 dark:text-emerald-300">
                    · 建议导出加密备份留存
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={handleExportClick}
                  className="px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-700 text-emerald-800 dark:text-emerald-200 font-semibold hover:bg-emerald-100/60 transition-colors cursor-pointer flex items-center gap-1 min-h-[44px] sm:min-h-[34px]"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>导出本地备份</span>
                </button>
                {recoverySummary.hadPreviousLocalVault && onRollbackRecovery && (
                  <button
                    type="button"
                    data-testid="workspace-rollback-recovery-btn"
                    onClick={onRollbackRecovery}
                    className="px-2.5 py-1.5 rounded-lg bg-amber-100 dark:bg-amber-900/60 text-amber-900 dark:text-amber-100 font-semibold hover:bg-amber-200 transition-colors cursor-pointer min-h-[44px] sm:min-h-[34px]"
                  >
                    回退至恢复前本地密码库
                  </button>
                )}
                {onDismissRecoverySummary && (
                  <button
                    type="button"
                    data-testid="dismiss-recovery-banner-btn"
                    onClick={onDismissRecoverySummary}
                    className="px-2.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold transition-colors cursor-pointer min-h-[44px] sm:min-h-[34px]"
                  >
                    完成核验并关闭
                  </button>
                )}
              </div>
            </div>

            {records.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-emerald-200/60 dark:border-emerald-800/50">
                <span className="text-xs font-semibold text-emerald-800 dark:text-emerald-300 mr-1">
                  点击下方记录主动抽检核验已恢复数据：
                </span>
                {records.slice(0, 6).map((rec) => {
                  const isVerified = Boolean(verifiedRestoredIds[rec.id]);
                  return (
                    <button
                      key={rec.id}
                      type="button"
                      data-testid={`verify-restored-record-${rec.id}`}
                      onClick={() => {
                        setSelectedCategory('all');
                        setSearchQuery('');
                        setSelectedRecordId(rec.id);
                        setMobileDetailOpen(true);
                        setVerifiedRestoredIds((prev) => ({
                          ...prev,
                          [rec.id]: true,
                        }));
                      }}
                      className={`px-2.5 py-1 rounded-md text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer min-h-[36px] ${
                        isVerified
                          ? 'bg-emerald-600 text-white'
                          : 'bg-white dark:bg-slate-900 border border-emerald-300/80 dark:border-emerald-800 text-slate-800 dark:text-slate-200 hover:bg-emerald-100/50'
                      }`}
                    >
                      {isBankCardRecord(rec) ? (
                        <CreditCard className="w-3 h-3 shrink-0" />
                      ) : (
                        <KeyRound className="w-3 h-3 shrink-0" />
                      )}
                      <span className="truncate max-w-[140px]">
                        {rec.title}
                      </span>
                      {isVerified && (
                        <span className="ml-0.5 font-bold">✓ 已核验</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Main Workspace Container (Desktop 3-Pane, Tablet 2-Pane, Mobile Single-Pane + Detail Slide-Over) */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-3 sm:px-6 py-4 sm:py-5 pb-20 md:pb-6 grid grid-cols-1 md:grid-cols-12 gap-4 sm:gap-5 items-stretch md:h-[calc(100vh-65px)]">
        {/* Pane 1: Left Sidebar (Desktop Categories, Primary Add Action & Sync Status) */}
        <aside className="hidden lg:flex lg:col-span-3 flex-col justify-between bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 h-full">
          <div className="space-y-6">
            <button
              type="button"
              onClick={onOpenNewRecord}
              className="w-full py-2.5 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-xs transition-colors cursor-pointer min-h-[42px]"
            >
              <Plus className="w-4 h-4" />
              <span>新建密码或银行卡</span>
            </button>

            {/* Category & Custom Tag Navigation */}
            <div className="space-y-1">
              <div className="px-2.5 pb-1.5 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 dark:text-slate-500">
                  密码库分类与标签筛选
                </span>
                <button
                  type="button"
                  onClick={onOpenCategoryManager}
                  className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                >
                  <Tag className="w-3 h-3" />
                  <span>管理标签</span>
                </button>
              </div>
              <div className="max-h-60 overflow-y-auto space-y-0.5 pr-0.5">
                <button
                  type="button"
                  onClick={() => setSelectedCategory('all')}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                    effectiveSelectedCategory === 'all'
                      ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 font-semibold'
                      : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2.5">
                    {BUILTIN_CATEGORY_ICONS.all}
                    <span>全部记录</span>
                  </span>
                  <span className="font-mono tabular-nums text-xs text-slate-400 dark:text-slate-500">
                    {categoryCounts.all ?? records.length}
                  </span>
                </button>

                {categories.map((cat) => {
                  const isSelected = effectiveSelectedCategory === cat.id;
                  const icon = BUILTIN_CATEGORY_ICONS[cat.id] ?? (
                    <Tag className="w-4 h-4" />
                  );
                  return (
                    <button
                      key={cat.id}
                      type="button"
                      onClick={() => setSelectedCategory(cat.id)}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-colors cursor-pointer ${
                        isSelected
                          ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 font-semibold'
                          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white'
                      }`}
                    >
                      <span className="flex items-center gap-2.5 truncate">
                        {icon}
                        <span className="truncate">
                          {cat.label === '安全密钥' ? '密钥' : cat.label}
                        </span>
                      </span>
                      <span className="font-mono tabular-nums text-xs text-slate-400 dark:text-slate-500 shrink-0">
                        {categoryCounts[cat.id] ?? 0}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Security & Tools Quick Links */}
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-1">
              <div className="px-2.5 pb-1.5 text-xs font-semibold text-slate-400 dark:text-slate-500">
                零知识安全工具箱
              </div>
              <button
                type="button"
                onClick={onOpenCategoryManager}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                <Tag className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>分类与自定义标签管理</span>
              </button>
              <button
                type="button"
                onClick={onOpenPasswordGenerator}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                <Wand2 className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>随机强密码生成器</span>
              </button>
              <button
                type="button"
                onClick={onOpenCiphertextInspector}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                <FileCode2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span>查看底层存储密文</span>
              </button>
              <button
                type="button"
                onClick={onOpenImportVault}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                <Upload className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                <span>导入密码数据 (JSON/CSV)</span>
              </button>
              <button
                type="button"
                onClick={handleExportClick}
                className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
              >
                {exportedFeedback ? (
                  <>
                    <Check className="w-4 h-4 text-emerald-500" />
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                      已下载密文 JSON 文件
                    </span>
                  </>
                ) : (
                  <>
                    <Download className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    <span>导出加密备份 (JSON)</span>
                  </>
                )}
              </button>
              {!isDemoMode && onOpenMasterPasswordModal && (
                <button
                  type="button"
                  onClick={onOpenMasterPasswordModal}
                  className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
                >
                  <KeyRound className="w-4 h-4 text-amber-500" />
                  <span>修改主密码 / 轮换密钥</span>
                </button>
              )}
            </div>
          </div>

          {/* V2 7-State Sync Status Panel */}
          <div className="pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between px-1">
              <div
                data-testid="workspace-sync-status-badge"
                className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                {syncStatus === 'failed' || syncStatus === 'conflict' ? (
                  <AlertCircle className="w-3.5 h-3.5 text-red-500 shrink-0" />
                ) : syncStatus === 'sync_pending' || syncStatus === 'offline' ? (
                  <AlertCircle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                ) : (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                )}
                <span>
                  {syncStatus === 'cloud_synced' &&
                    `已与云端同步 (Rev #${lastSyncedRevision})`}
                  {syncStatus === 'local_saved' && '已保存本地 (未配置云端)'}
                  {syncStatus === 'sync_pending' && '本地已修改 (待同步)'}
                  {syncStatus === 'syncing' && '正在同步至 Durable Object...'}
                  {syncStatus === 'offline' && '当前离线 (待网络恢复)'}
                  {syncStatus === 'conflict' && '云端版本冲突 (HTTP 409)'}
                  {syncStatus === 'failed' && '云端同步失败 (保留本地)'}
                </span>
              </div>
              <button
                type="button"
                onClick={onQuickSync}
                aria-label="立即执行密文同步"
                title="立即同步密文"
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${
                    syncStatus === 'syncing' ? 'animate-spin text-blue-500' : ''
                  }`}
                />
              </button>
            </div>

            <div className="px-1 text-xs text-slate-500 dark:text-slate-400 space-y-1">
              <div className="flex items-center justify-between">
                <span>最后云端同步：</span>
                <span className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
                  {syncConfig.lastSyncedAt
                    ? new Date(syncConfig.lastSyncedAt).toLocaleTimeString(
                        'zh-CN'
                      )
                    : '尚未同步'}
                </span>
              </div>
              <button
                type="button"
                onClick={onOpenCloudSync}
                className="text-blue-600 dark:text-blue-400 hover:underline font-medium block pt-0.5 cursor-pointer"
              >
                {syncStatus === 'conflict'
                  ? '处理云端版本冲突 (409) →'
                  : '管理 Durable Objects 云同步 →'}
              </button>
            </div>
          </div>
        </aside>

        {/* Pane 2: Center Search, Category Filter & Record List */}
        <section className="md:col-span-5 lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl flex flex-col overflow-hidden h-full">
          {/* Search & Mobile Filter Header */}
          <div className="p-3.5 sm:p-4 border-b border-slate-200 dark:border-slate-800 space-y-2.5 shrink-0">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  ref={searchInputRef}
                  type="search"
                  data-testid="vault-search-input"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="搜索标题、账号、卡号尾号或备注... (按 / 或 Ctrl+K)"
                  aria-label="搜索密码记录"
                  className="w-full pl-9 pr-3.5 py-2 text-xs sm:text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 transition-all min-h-[44px] sm:min-h-[38px]"
                />
              </div>
              <button
                type="button"
                onClick={onOpenNewRecord}
                aria-label="新建密码记录"
                className="lg:hidden px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1 shrink-0 min-h-[44px] sm:min-h-[38px] cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>新建</span>
              </button>
            </div>

            {/* Mobile & Tablet (<1024px) Quick Toolbox Bar: Import, Export, Category Manager, Master Password */}
            <div
              data-testid="mobile-vault-toolbox"
              className="lg:hidden flex items-center flex-wrap gap-1.5 pt-0.5"
            >
              <button
                type="button"
                onClick={onOpenImportVault}
                className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px]"
              >
                <Upload className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                <span>导入数据</span>
              </button>

              <button
                type="button"
                onClick={handleExportClick}
                className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px]"
              >
                {exportedFeedback ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                      已导出备份
                    </span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                    <span>导出加密备份</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={onOpenCategoryManager}
                className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px]"
              >
                <Tag className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                <span>管理分类</span>
              </button>

              {!isDemoMode && onOpenMasterPasswordModal && (
                <button
                  type="button"
                  onClick={onOpenMasterPasswordModal}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px]"
                >
                  <KeyRound className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                  <span>改主密码</span>
                </button>
              )}
            </div>

            {/* Interactive Category Segmented Filter Bar (Wraps cleanly so zero tabs are ever clipped) */}
            <div
              className="flex items-center flex-wrap gap-1 p-1 bg-slate-100 dark:bg-slate-950 rounded-xl"
              role="tablist"
              aria-label="按分类过滤密码记录"
            >
              {[
                { id: 'all', label: '全部' },
                ...categories.map((c) => ({
                  id: c.id,
                  label: c.label === '安全密钥' ? '密钥' : c.label,
                })),
              ].map((tab) => {
                const active = effectiveSelectedCategory === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => setSelectedCategory(tab.id)}
                    className={`px-2.5 py-1.5 text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer min-h-[36px] flex items-center ${
                      active
                        ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-2xs font-semibold'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    <span>{tab.label}</span>
                    <span className="ml-1 font-mono tabular-nums text-xs opacity-75">
                      {categoryCounts[tab.id] ?? 0}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Record List */}
          <div className="divide-y divide-slate-100 dark:divide-slate-800/80 flex-1 overflow-y-auto">
            {filteredRecords.length === 0 ? (
              <div className="p-10 text-center space-y-3">
                <div className="w-10 h-10 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-400 flex items-center justify-center mx-auto">
                  <KeyRound className="w-5 h-5" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                    未找到匹配的加密记录
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {searchQuery || selectedCategory !== 'all'
                      ? '尝试清空搜索词或切换至“全部”分类查看'
                      : '点击下方按钮创建您的第一条 AES-256-GCM 加密记录'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    if (searchQuery || selectedCategory !== 'all') {
                      setSearchQuery('');
                      setSelectedCategory('all');
                    } else {
                      onOpenNewRecord();
                    }
                  }}
                  className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-colors cursor-pointer min-h-[44px] sm:min-h-[38px]"
                >
                  {searchQuery || selectedCategory !== 'all'
                    ? '重置筛选条件'
                    : '新建第一条记录'}
                </button>
              </div>
            ) : (
              filteredRecords.map((rec) => {
                const isSelected = activeRecord?.id === rec.id;
                const isCard = isBankCardRecord(rec);
                const cardDetails = isCard ? resolveRecordCardDetails(rec) : null;
                const copyKey = `list-action-${rec.id}`;
                const isCopied = copiedField === copyKey;

                return (
                  <div
                    key={rec.id}
                    data-testid={`record-item-${rec.id}`}
                    onClick={() => {
                      setSelectedRecordId(rec.id);
                      setMobileDetailOpen(true);
                    }}
                    className={`p-3.5 sm:px-4 flex items-center justify-between gap-3 transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-blue-50/70 dark:bg-blue-950/40'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      {isCard && cardDetails ? (
                        <BankCardMiniBadge
                          title={rec.title}
                          cardNumber={cardDetails.cardNumber}
                          brand={cardDetails.brand}
                          url={rec.url}
                          isSelected={isSelected}
                        />
                      ) : (
                        <RecordWebsiteLogo
                          title={rec.title}
                          url={rec.url}
                          size="md"
                          isSelected={isSelected}
                        />
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                            {rec.title}
                          </span>
                          {rec.favorite && (
                            <Star className="w-3.5 h-3.5 text-amber-400 fill-amber-400 shrink-0" />
                          )}
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-400 truncate font-mono tabular-nums">
                          {isCard && cardDetails ? (
                            <>
                              <span className="sm:hidden">
                                •••• {cardDetails.cardNumber.slice(-4)} ·{' '}
                                {cardDetails.cardholderName}
                              </span>
                              <span className="hidden sm:inline">
                                {maskCardNumber(cardDetails.cardNumber)} ·{' '}
                                {cardDetails.cardholderName}
                              </span>
                            </>
                          ) : (
                            rec.username || '未填写账号'
                          )}
                        </div>
                        {/* Clean Concise Metadata (Category, Tags & Website Domain / Card Network) */}
                        <div className="flex items-center flex-wrap gap-1.5 text-xs text-slate-400 dark:text-slate-500 mt-0.5">
                          <span className="text-slate-600 dark:text-slate-300 font-medium">
                            {getCategoryDisplayLabel(rec.category, categories)}
                          </span>
                          {Array.isArray(rec.tags) &&
                            rec.tags
                              .filter(
                                (t) =>
                                  t !==
                                  getCategoryDisplayLabel(
                                    rec.category,
                                    categories
                                  )
                              )
                              .slice(0, 2)
                              .map((t) => (
                                <span
                                  key={t}
                                  className="text-blue-600 dark:text-blue-400 font-medium"
                                >
                                  #{t}
                                </span>
                              ))}
                          {(isCard || extractDomainFromUrl(rec.url)) && (
                            <>
                              <span aria-hidden="true">·</span>
                              <span className="truncate max-w-[140px]">
                                {isCard
                                  ? cardDetails?.brand || '银行卡'
                                  : extractDomainFromUrl(rec.url)}
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Quick Copy Button in Row */}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopy(
                          isCard && cardDetails
                            ? cardDetails.cardNumber
                            : rec.password,
                          copyKey,
                          true
                        );
                      }}
                      aria-label={
                        isCard
                          ? `复制 ${rec.title} 的卡号`
                          : `复制 ${rec.title} 的密码`
                      }
                      title={isCard ? '一键复制卡号' : '一键复制密码'}
                      className={`px-2.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1 shrink-0 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px] ${
                        isCopied
                          ? 'bg-emerald-600 text-white'
                          : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                      }`}
                    >
                      {isCopied ? (
                        <>
                          <Check className="w-3.5 h-3.5" />
                          <span>已复制</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>{isCard ? '卡号' : '密码'}</span>
                        </>
                      )}
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* Pane 3: Right Record Detail Inspector (Desktop & Tablet Persistent + Mobile Slide-Over) */}
        <section
          className={`md:col-span-7 lg:col-span-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-y-auto h-full flex flex-col justify-between ${
            mobileDetailOpen
              ? 'fixed inset-0 z-40 rounded-none md:static md:rounded-2xl'
              : 'hidden md:flex'
          }`}
        >
          {activeRecord ? (
            <div className="p-4 sm:p-6 pb-24 md:pb-6 flex-1 flex flex-col justify-between gap-5 sm:gap-6">
              <div className="space-y-5 sm:space-y-6">
                {/* Mobile Back Button (Only on <768px where Detail is Slide-Over) */}
                <div className="md:hidden flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
                  <button
                    type="button"
                    onClick={() => setMobileDetailOpen(false)}
                    className="flex items-center gap-1 text-xs font-semibold text-blue-600 dark:text-blue-400 py-1.5 min-h-[44px]"
                  >
                    <ChevronLeft className="w-4 h-4" />
                    <span>返回密码列表</span>
                  </button>
                  <span className="text-xs text-slate-400">记录详情</span>
                </div>

                {/* Detail Header (Stacks cleanly on mobile so long titles and dates never truncate or wrap awkwardly) */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3.5 pb-4 sm:pb-5 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-start gap-3.5 min-w-0 flex-1">
                    {isActivePaymentCard && activeCardDetails ? (
                      <BankCardMiniBadge
                        title={activeRecord.title}
                        cardNumber={activeCardDetails.cardNumber}
                        brand={activeCardDetails.brand}
                        url={activeRecord.url}
                      />
                    ) : (
                      <RecordWebsiteLogo
                        title={activeRecord.title}
                        url={activeRecord.url}
                        size="lg"
                      />
                    )}
                    <div className="min-w-0 flex-1">
                      <h2 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white break-words leading-snug">
                        {activeRecord.title}
                      </h2>
                      {/* Unboxed Metadata */}
                      <div className="flex items-center flex-wrap gap-x-2 gap-y-1 text-xs text-slate-500 dark:text-slate-400 mt-1">
                        <span className="font-semibold text-blue-600 dark:text-blue-400 whitespace-nowrap">
                          {getCategoryDisplayLabel(
                            activeRecord.category,
                            categories
                          )}
                        </span>
                        {Array.isArray(activeRecord.tags) &&
                          activeRecord.tags.map((tagLabel) => (
                            <button
                              key={tagLabel}
                              type="button"
                              onClick={() => {
                                const matchedCat = categories.find(
                                  (c) => c.label === tagLabel || c.id === tagLabel
                                );
                                setSelectedCategory(
                                  matchedCat ? matchedCat.id : tagLabel
                                );
                              }}
                              className="text-blue-600 dark:text-blue-400 hover:underline font-medium cursor-pointer whitespace-nowrap"
                            >
                              #{tagLabel}
                            </button>
                          ))}
                        <span aria-hidden="true">·</span>
                        <span className="font-mono tabular-nums whitespace-nowrap">
                          更新于{' '}
                          {new Date(activeRecord.updatedAt).toLocaleDateString(
                            'zh-CN'
                          )}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Record Action Controls */}
                  <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-start">
                    <button
                      type="button"
                      onClick={() => onToggleFavorite(activeRecord)}
                      aria-label={
                        activeRecord.favorite ? '取消星标收藏' : '设为星标收藏'
                      }
                      className="p-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[40px] sm:min-w-[40px] flex items-center justify-center"
                    >
                      <Star
                        className={`w-4 h-4 ${
                          activeRecord.favorite
                            ? 'text-amber-400 fill-amber-400'
                            : ''
                        }`}
                      />
                    </button>
                    <button
                      type="button"
                      onClick={() => onOpenEditRecord(activeRecord)}
                      className="px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer min-h-[44px] sm:min-h-[40px]"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                      <span>编辑</span>
                    </button>
                    {confirmDeleteId === activeRecord.id ? (
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          onClick={async () => {
                            await onDeleteRecord(activeRecord.id);
                            setConfirmDeleteId(null);
                            setMobileDetailOpen(false);
                          }}
                          className="px-2.5 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer min-h-[44px] sm:min-h-[40px]"
                        >
                          确认删除
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteId(null)}
                          className="px-2 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-xs text-slate-600 dark:text-slate-300 cursor-pointer min-h-[44px] sm:min-h-[40px]"
                        >
                          取消
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => setConfirmDeleteId(activeRecord.id)}
                        aria-label={`删除 ${activeRecord.title}`}
                        className="p-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[40px] sm:min-w-[40px] flex items-center justify-center"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {isActivePaymentCard && activeCardDetails ? (
                  /* Dedicated Payment Card Display & Masking Layer */
                  <div className="space-y-5">
                    {/* Realistic CSS 3D Credit Card Face with Issuer Branding, Masked Numbers, Holder Name & Back CVV Strip */}
                    <CreditCardFace
                      title={activeRecord.title}
                      cardholderName={activeCardDetails.cardholderName}
                      cardNumber={activeCardDetails.cardNumber}
                      expiryDate={activeCardDetails.expiryDate}
                      cvv={activeCardDetails.cvv}
                      brand={activeCardDetails.brand}
                      url={activeRecord.url}
                      category={activeRecord.category}
                      revealedNumber={Boolean(
                        revealedCardNumbers[activeRecord.id]
                      )}
                      revealedCvv={Boolean(revealedCvvs[activeRecord.id])}
                      onToggleRevealNumber={() =>
                        toggleRevealCardNumber(activeRecord.id)
                      }
                      onToggleRevealCvv={() => toggleRevealCvv(activeRecord.id)}
                      onCopyCardNumber={() =>
                        handleCopy(
                          activeCardDetails.cardNumber,
                          `detail-cardnum-${activeRecord.id}`,
                          true
                        )
                      }
                      isCopiedNumber={
                        copiedField === `detail-cardnum-${activeRecord.id}`
                      }
                      onCopyCvv={() =>
                        handleCopy(
                          activeCardDetails.cvv,
                          `detail-cvv-${activeRecord.id}`,
                          true
                        )
                      }
                      isCopiedCvv={
                        copiedField === `detail-cvv-${activeRecord.id}`
                      }
                    />

                    {/* Structured Card Fields with Masking & Copy Controls */}
                    <div className="divide-y divide-slate-100 dark:divide-slate-800">
                      {/* Card Number Row (Full-width single-line value row so masked and revealed numbers never wrap) */}
                      <div className="py-3.5 space-y-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                            <span className="sm:hidden">银行卡号 (默认掩码)</span>
                            <span className="hidden sm:inline">
                              银行卡号 (默认掩码仅露尾号 4 位)
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <button
                              type="button"
                              onClick={() =>
                                toggleRevealCardNumber(activeRecord.id)
                              }
                              aria-label={
                                revealedCardNumbers[activeRecord.id]
                                  ? '切换为掩码隐藏卡号'
                                  : '切换为明文显示完整卡号'
                              }
                              className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[38px] sm:min-w-[38px] flex items-center justify-center"
                            >
                              {revealedCardNumbers[activeRecord.id] ? (
                                <EyeOff className="w-4 h-4" />
                              ) : (
                                <Eye className="w-4 h-4" />
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(
                                  activeCardDetails.cardNumber,
                                  `detail-cardnum-${activeRecord.id}`,
                                  true
                                )
                              }
                              className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shrink-0 cursor-pointer min-h-[44px] sm:min-h-[38px] ${
                                copiedField ===
                                `detail-cardnum-${activeRecord.id}`
                                  ? 'bg-emerald-600 text-white'
                                  : 'bg-blue-600 hover:bg-blue-700 text-white'
                              }`}
                            >
                              {copiedField ===
                              `detail-cardnum-${activeRecord.id}` ? (
                                <>
                                  <Check className="w-3.5 h-3.5" />
                                  <span>已复制卡号</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5" />
                                  <span>复制卡号</span>
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                        <div
                          data-testid="detail-card-number"
                          className="text-base sm:text-lg font-mono tabular-nums font-bold text-slate-900 dark:text-white tracking-wider whitespace-nowrap overflow-x-auto select-all"
                        >
                          {revealedCardNumbers[activeRecord.id]
                            ? formatCardNumberGroups(
                                activeCardDetails.cardNumber
                              )
                            : maskCardNumber(activeCardDetails.cardNumber)}
                        </div>
                      </div>

                      {/* Cardholder Name Row */}
                      <div className="py-3.5 flex items-center justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                            持卡人姓名 (Cardholder Name)
                          </div>
                          <div className="text-sm font-mono uppercase text-slate-900 dark:text-white break-words mt-1">
                            {activeCardDetails.cardholderName}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            handleCopy(
                              activeCardDetails.cardholderName,
                              `detail-holder-${activeRecord.id}`
                            )
                          }
                          className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shrink-0 cursor-pointer min-h-[44px] sm:min-h-[38px] ${
                            copiedField === `detail-holder-${activeRecord.id}`
                              ? 'bg-emerald-600 text-white'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700'
                          }`}
                        >
                          {copiedField === `detail-holder-${activeRecord.id}` ? (
                            <>
                              <Check className="w-3.5 h-3.5" />
                              <span>已复制姓名</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>复制姓名</span>
                            </>
                          )}
                        </button>
                      </div>

                      {/* Expiry Date & CVV/CVC Row */}
                      <div className="py-3.5 grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="flex items-center justify-between gap-2">
                          <div>
                            <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                              过期日期 (MM/YY)
                            </div>
                            <div className="text-sm font-mono tabular-nums font-semibold text-slate-900 dark:text-white mt-1">
                              {activeCardDetails.expiryDate}
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() =>
                              handleCopy(
                                activeCardDetails.expiryDate,
                                `detail-exp-${activeRecord.id}`
                              )
                            }
                            className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px] ${
                              copiedField === `detail-exp-${activeRecord.id}`
                                ? 'bg-emerald-600 text-white'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700'
                            }`}
                          >
                            {copiedField === `detail-exp-${activeRecord.id}` ? (
                              <>
                                <Check className="w-3.5 h-3.5" />
                                <span>已复制</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>复制有效期</span>
                              </>
                            )}
                          </button>
                        </div>

                        <div className="flex items-center justify-between gap-2">
                          <div>
                            <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                              CVV / CVC 安全码
                            </div>
                            <div
                              data-testid="detail-card-cvv"
                              className="text-sm font-mono tabular-nums font-semibold text-slate-900 dark:text-white mt-1 tracking-widest"
                            >
                              {revealedCvvs[activeRecord.id]
                                ? activeCardDetails.cvv
                                : maskCvvCode(activeCardDetails.cvv)}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => toggleRevealCvv(activeRecord.id)}
                              aria-label={
                                revealedCvvs[activeRecord.id]
                                  ? '掩码隐藏 CVV 安全码'
                                  : '明文显示 CVV 安全码'
                              }
                              className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[36px] sm:min-w-[36px] flex items-center justify-center"
                            >
                              {revealedCvvs[activeRecord.id] ? (
                                <EyeOff className="w-3.5 h-3.5" />
                              ) : (
                                <Eye className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                handleCopy(
                                  activeCardDetails.cvv,
                                  `detail-cvv-${activeRecord.id}`,
                                  true
                                )
                              }
                              className={`px-2.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1 transition-colors cursor-pointer min-h-[44px] sm:min-h-[36px] ${
                                copiedField === `detail-cvv-${activeRecord.id}`
                                  ? 'bg-emerald-600 text-white'
                                  : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700'
                              }`}
                            >
                              {copiedField ===
                              `detail-cvv-${activeRecord.id}` ? (
                                <>
                                  <Check className="w-3.5 h-3.5" />
                                  <span>已复制</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5" />
                                  <span>复制 CVV</span>
                                </>
                              )}
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* Website URL Field */}
                      {activeRecord.url && (
                        <div className="py-3.5 flex items-center justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                              发卡行网银网址 (Website URL)
                            </div>
                            <div className="text-xs font-mono text-blue-600 dark:text-blue-400 break-all mt-1">
                              {activeRecord.url}
                            </div>
                          </div>
                          <a
                            href={activeRecord.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1.5 shrink-0 min-h-[44px] sm:min-h-[38px]"
                          >
                            <span>访问</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      )}

                      {/* Notes Field */}
                      {activeRecord.notes && (
                        <div className="py-3.5 space-y-1.5">
                          <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                            安全加密备注
                          </div>
                          <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-wrap break-words">
                            {activeRecord.notes}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  /* Standard Login Credentials Section */
                  <div className="divide-y divide-slate-100 dark:divide-slate-800">
                    {/* Username Field (Full-width value row so long emails/usernames are never truncated in detail view) */}
                    <div className="py-3.5 space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                          登录账号 / 用户名
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            handleCopy(
                              activeRecord.username,
                              `detail-user-${activeRecord.id}`
                            )
                          }
                          className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shrink-0 cursor-pointer min-h-[44px] sm:min-h-[38px] ${
                            copiedField === `detail-user-${activeRecord.id}`
                              ? 'bg-emerald-600 text-white'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700'
                          }`}
                        >
                          {copiedField === `detail-user-${activeRecord.id}` ? (
                            <>
                              <Check className="w-3.5 h-3.5" />
                              <span>已复制账号</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>复制账号</span>
                            </>
                          )}
                        </button>
                      </div>
                      <div className="text-sm font-mono text-slate-900 dark:text-white break-all select-all">
                        {activeRecord.username || '—'}
                      </div>
                    </div>

                    {/* Password Field (Full-width value row so password mask dots and long passwords fit cleanly) */}
                    <div className="py-4 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                          加密登录密码
                        </div>

                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            type="button"
                            onClick={() =>
                              toggleRevealPassword(activeRecord.id)
                            }
                            aria-label={
                              revealedPasswords[activeRecord.id]
                                ? '切换为掩码隐藏密码'
                                : '切换为明文显示密码'
                            }
                            className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[38px] sm:min-w-[38px] flex items-center justify-center"
                          >
                            {revealedPasswords[activeRecord.id] ? (
                              <EyeOff className="w-4 h-4" />
                            ) : (
                              <Eye className="w-4 h-4" />
                            )}
                          </button>

                          <button
                            type="button"
                            onClick={() =>
                              handleCopy(
                                activeRecord.password,
                                `detail-pwd-${activeRecord.id}`,
                                true
                              )
                            }
                            className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shrink-0 cursor-pointer min-h-[44px] sm:min-h-[38px] ${
                              copiedField === `detail-pwd-${activeRecord.id}`
                                ? 'bg-emerald-600 text-white'
                                : 'bg-blue-600 hover:bg-blue-700 text-white'
                            }`}
                          >
                            {copiedField === `detail-pwd-${activeRecord.id}` ? (
                              <>
                                <Check className="w-3.5 h-3.5" />
                                <span>已复制密码</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>复制密码</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>

                      <div
                        data-testid="detail-password-value"
                        className="text-sm font-mono font-semibold text-slate-900 dark:text-white break-all tracking-wider select-all"
                      >
                        {revealedPasswords[activeRecord.id]
                          ? activeRecord.password
                          : '••••••••••••••••••••'}
                      </div>

                      {activeStrength && (
                        <div className="flex items-center justify-between text-xs pt-1">
                          <span className="text-slate-500 dark:text-slate-400">
                            密码强度：
                            <span
                              className={`font-semibold ml-1 ${activeStrength.colorClass}`}
                            >
                              {activeStrength.label}
                            </span>
                          </span>
                          <span className="font-mono tabular-nums text-slate-400">
                            {activeRecord.password.length} 位字符
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Website URL Field */}
                    {activeRecord.url && (
                      <div className="py-3.5 flex items-center justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                            关联网址
                          </div>
                          <div className="text-xs font-mono text-blue-600 dark:text-blue-400 break-all mt-1">
                            {activeRecord.url}
                          </div>
                        </div>
                        <a
                          href={activeRecord.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1.5 shrink-0 min-h-[44px] sm:min-h-[38px]"
                        >
                          <span>访问网站</span>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    )}

                    {/* Notes Field */}
                    {activeRecord.notes && (
                      <div className="py-3.5 space-y-1.5">
                        <div className="text-xs font-medium text-slate-400 dark:text-slate-500">
                          备注说明
                        </div>
                        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed whitespace-pre-wrap break-words">
                          {activeRecord.notes}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-400 my-auto">
              从左侧列表选择一条密码记录以解密查看详情
            </div>
          )}
        </section>
      </main>

      {/* Mobile Fixed Bottom Navigation Bar (Strictly <= 15% Viewport Height, >= 44px Touch Hitboxes) */}
      <nav
        aria-label="移动端底部快捷导航"
        className="md:hidden fixed bottom-0 left-0 right-0 z-30 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md border-t border-slate-200 dark:border-slate-800 grid grid-cols-5 items-center h-14 px-1"
      >
        <button
          type="button"
          onClick={onOpenPasswordGenerator}
          className="flex flex-col items-center justify-center min-h-[44px] text-slate-600 dark:text-slate-300 hover:text-blue-600 cursor-pointer"
        >
          <Wand2 className="w-4 h-4" />
          <span className="text-[11px] font-medium mt-0.5">生成器</span>
        </button>
        <button
          type="button"
          onClick={onOpenImportVault}
          className="flex flex-col items-center justify-center min-h-[44px] text-slate-600 dark:text-slate-300 hover:text-blue-600 cursor-pointer"
        >
          <Upload className="w-4 h-4" />
          <span className="text-[11px] font-medium mt-0.5">导入数据</span>
        </button>
        <button
          type="button"
          onClick={handleExportClick}
          className="flex flex-col items-center justify-center min-h-[44px] text-slate-600 dark:text-slate-300 hover:text-blue-600 cursor-pointer"
        >
          <Download className="w-4 h-4" />
          <span className="text-[11px] font-medium mt-0.5">
            {exportedFeedback ? '已导出' : '导出备份'}
          </span>
        </button>
        <button
          type="button"
          onClick={onOpenCloudSync}
          className="flex flex-col items-center justify-center min-h-[44px] text-slate-600 dark:text-slate-300 hover:text-blue-600 cursor-pointer"
        >
          <Cloud className="w-4 h-4" />
          <span className="text-[11px] font-medium mt-0.5">云同步</span>
        </button>
        <button
          type="button"
          onClick={onLockVault}
          className="flex flex-col items-center justify-center min-h-[44px] text-red-600 dark:text-red-400 cursor-pointer"
        >
          <Lock className="w-4 h-4" />
          <span className="text-[11px] font-semibold mt-0.5">立即锁定</span>
        </button>
      </nav>
    </div>
  );
};
