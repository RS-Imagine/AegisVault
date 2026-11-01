import React, { useState, useRef, useMemo } from 'react';
import {
  X,
  Upload,
  FileSpreadsheet,
  FileCode2,
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  KeyRound,
  CreditCard,
  Sparkles,
  Lock,
} from 'lucide-react';
import {
  DecryptedVaultRecord,
  EncryptedVaultPayload,
  CATEGORY_META,
} from '../types/vault';
import {
  CandidateRecordInput,
  ImportDetectionResult,
  MergeDuplicateStrategy,
  SAMPLE_BROWSER_CSV_EXPORT,
  detectAndParseImportContent,
  getRecordFingerprint,
  mergeImportedRecords,
} from '../utils/importVaultUtils';
import { maskCardNumber } from '../utils/paymentCardUtils';
import { SyncService } from '../services/syncService';

interface ImportVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  existingRecords: DecryptedVaultRecord[];
  currentMemoryKey: CryptoKey | null;
  currentEncryptedPayload: EncryptedVaultPayload | null;
  onConfirmMerge: (mergedRecords: DecryptedVaultRecord[]) => Promise<void>;
}

export const ImportVaultModal: React.FC<ImportVaultModalProps> = ({
  isOpen,
  onClose,
  existingRecords,
  currentMemoryKey,
  currentEncryptedPayload,
  onConfirmMerge,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [fileName, setFileName] = useState<string>('');
  const [rawContent, setRawContent] = useState<string>('');
  const [backupPassword, setBackupPassword] = useState<string>('');
  const [detection, setDetection] = useState<ImportDetectionResult | null>(
    null
  );
  const [strategy, setStrategy] =
    useState<MergeDuplicateStrategy>('skip-duplicates');
  const [isParsing, setIsParsing] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitSuccessMsg, setSubmitSuccessMsg] = useState<string | null>(null);
  const [showRawEditor, setShowRawEditor] = useState(false);

  const existingFingerprints = useMemo(
    () => new Set(existingRecords.map((r) => getRecordFingerprint(r))),
    [existingRecords]
  );

  const mergePreview = useMemo(() => {
    if (!detection || detection.parsedRecords.length === 0) {
      return { addedCount: 0, skippedCount: 0, mergedRecords: existingRecords };
    }
    return mergeImportedRecords(
      existingRecords,
      detection.parsedRecords,
      strategy
    );
  }, [detection, existingRecords, strategy]);

  if (!isOpen) return null;

  const runDetection = async (content: string, pwdOverride?: string) => {
    setIsParsing(true);
    setSubmitSuccessMsg(null);
    try {
      const result = await detectAndParseImportContent(
        content,
        currentMemoryKey,
        pwdOverride !== undefined ? pwdOverride : backupPassword || undefined
      );
      setDetection(result);
    } finally {
      setIsParsing(false);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    setBackupPassword('');
    const text = await file.text();
    setRawContent(text);
    await runDetection(text, '');
    e.target.value = '';
  };

  const handleLoadSampleCsv = async () => {
    setFileName('Microsoft-Edge-Passwords-Export.csv');
    setBackupPassword('');
    setRawContent(SAMPLE_BROWSER_CSV_EXPORT);
    await runDetection(SAMPLE_BROWSER_CSV_EXPORT, '');
  };

  const handleLoadCurrentEncryptedBackup = async () => {
    try {
      const jsonStr = SyncService.serializeEncryptedVaultForExport(
        currentEncryptedPayload
      );
      setFileName(SyncService.getBackupFilename());
      setBackupPassword('');
      setRawContent(jsonStr);
      await runDetection(jsonStr, '');
    } catch {
      // ignore if empty
    }
  };

  const handleUnlockBackupWithPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawContent || !backupPassword) return;
    await runDetection(rawContent, backupPassword);
  };

  const handleConfirmImport = async () => {
    if (!detection || detection.parsedRecords.length === 0) return;
    setIsSubmitting(true);
    try {
      const { mergedRecords, addedCount, skippedCount } = mergeImportedRecords(
        existingRecords,
        detection.parsedRecords,
        strategy
      );
      await onConfirmMerge(mergedRecords);
      setSubmitSuccessMsg(
        `已完成零知识加密合并：新增 ${addedCount} 条加密记录${
          skippedCount > 0 ? `，自动跳过 ${skippedCount} 条重复记录` : ''
        }`
      );
      setTimeout(() => {
        onClose();
        setFileName('');
        setRawContent('');
        setDetection(null);
        setSubmitSuccessMsg(null);
      }, 900);
    } finally {
      setIsSubmitting(false);
    }
  };

  const resetModal = () => {
    setFileName('');
    setRawContent('');
    setBackupPassword('');
    setDetection(null);
    setSubmitSuccessMsg(null);
    setShowRawEditor(false);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="import-vault-modal-title"
    >
      <div className="w-full max-w-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 flex items-center justify-center">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h2
                id="import-vault-modal-title"
                className="text-base font-bold text-slate-900 dark:text-white"
              >
                导入并合并密码库记录
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                自动兼容识别 AegisVault 加密 JSON 备份与 Chrome / Edge 浏览器明文 CSV
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={resetModal}
            aria-label="关闭导入窗口"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[78vh] overflow-y-auto">
          {/* Zero-Knowledge Architecture Notice */}
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 flex items-start gap-3">
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              <span className="font-semibold text-slate-900 dark:text-white">
                零知识内存解析承诺：
              </span>
              外部浏览器导出的明文 CSV/JSON 仅在当前浏览器内存中完成瞬时解析，合并后立即使用当前密码库的{' '}
              <span className="font-mono font-semibold text-blue-600 dark:text-blue-400">
                AES-256-GCM
              </span>{' '}
              主密钥逐条生成随机 96-bit IV 并加密为密文存储，绝不向本地磁盘或云端写入任何明文。
            </div>
          </div>

          {/* File Selector & Quick Compatibility Sample Loaders */}
          <div className="space-y-3">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.csv,application/json,text/csv,text/plain"
              onChange={handleFileChange}
              aria-label="选择要导入的密码文件"
              className="hidden"
            />

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="sm:col-span-1 py-3 px-4 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-xs min-h-[42px]"
              >
                <Upload className="w-4 h-4" />
                <span>选择本地文件 (.json / .csv)</span>
              </button>

              <button
                type="button"
                onClick={handleLoadSampleCsv}
                className="py-3 px-3.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer min-h-[42px]"
              >
                <FileSpreadsheet className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                <span>载入 Edge/Chrome CSV 样本</span>
              </button>

              <button
                type="button"
                onClick={handleLoadCurrentEncryptedBackup}
                className="py-3 px-3.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer min-h-[42px]"
              >
                <FileCode2 className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
                <span>载入加密 JSON 备份样本</span>
              </button>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 px-1">
              <span>
                {fileName ? (
                  <>
                    当前载入数据源：
                    <strong className="font-mono text-slate-800 dark:text-slate-200">
                      {fileName}
                    </strong>
                  </>
                ) : (
                  '支持 Chrome、Edge、Brave、Firefox、Bitwarden 导出文件及 AegisVault 加密备份'
                )}
              </span>
              <button
                type="button"
                onClick={() => setShowRawEditor((v) => !v)}
                className="text-blue-600 dark:text-blue-400 hover:underline font-medium cursor-pointer"
              >
                {showRawEditor ? '收起文本粘贴框' : '手动粘贴 CSV / JSON 文本'}
              </button>
            </div>

            {showRawEditor && (
              <div className="space-y-2 pt-1">
                <label
                  htmlFor="import-raw-textarea"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                >
                  粘贴 CSV 内容（含 name,url,username,password 表头）或加密 JSON：
                </label>
                <textarea
                  id="import-raw-textarea"
                  rows={4}
                  value={rawContent}
                  onChange={async (e) => {
                    const val = e.target.value;
                    setFileName('手动粘贴内容');
                    setRawContent(val);
                    await runDetection(val);
                  }}
                  placeholder={`name,url,username,password,note\n"GitHub","https://github.com","dev@example.com","MyPass#123","备注"`}
                  className="w-full px-3.5 py-2.5 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
            )}
          </div>

          {/* Detection Result & Preview */}
          {isParsing && (
            <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400">
              正在内存中识别文件结构并校验加密参数...
            </div>
          )}

          {!isParsing && detection && (
            <div className="space-y-4">
              {/* Format Recognition Banner */}
              <div
                data-testid="import-format-banner"
                className={`p-3.5 rounded-xl border flex items-center justify-between gap-3 ${
                  detection.format === 'unrecognized'
                    ? 'bg-red-50/70 dark:bg-red-950/30 border-red-200 dark:border-red-900/60 text-red-700 dark:text-red-300'
                    : 'bg-blue-50/70 dark:bg-blue-950/30 border-blue-200 dark:border-blue-900/60 text-slate-800 dark:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  {detection.format === 'aegis-encrypted-json' ? (
                    <Lock className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
                  ) : detection.format === 'browser-csv' ? (
                    <FileSpreadsheet className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  ) : (
                    <Sparkles className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
                  )}
                  <div className="text-xs">
                    <span className="text-slate-500 dark:text-slate-400">
                      识别结果：
                    </span>
                    <span className="font-bold text-slate-900 dark:text-white">
                      {detection.format === 'aegis-encrypted-json'
                        ? 'AegisVault V2 加密 JSON 备份'
                        : detection.format === 'browser-csv'
                        ? '浏览器导出 CSV'
                        : detection.format === 'generic-json'
                        ? '通用 JSON 记录'
                        : '未识别格式'}
                    </span>
                  </div>
                </div>
                {detection.parsedRecords.length > 0 && (
                  <span className="text-xs font-mono tabular-nums font-semibold text-blue-600 dark:text-blue-400 shrink-0">
                    共解析 {detection.parsedRecords.length} 条记录
                  </span>
                )}
              </div>

              {/* Password Prompt if Encrypted Backup Uses a Different Key/Salt */}
              {detection.status === 'needs-password' && (
                <form
                  onSubmit={handleUnlockBackupWithPassword}
                  className="p-4 rounded-xl bg-amber-50/80 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/60 space-y-3"
                >
                  <div className="flex items-start gap-2 text-xs text-amber-800 dark:text-amber-300">
                    <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                    <span>
                      {detection.message ||
                        '该加密备份由不同的主密码或盐值生成，请输入该备份的主密码以在内存中解密'}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="password"
                      value={backupPassword}
                      onChange={(e) => setBackupPassword(e.target.value)}
                      placeholder="输入该加密备份文件的原主密码..."
                      aria-label="加密备份文件的原主密码"
                      className="flex-1 px-3.5 py-2 text-xs rounded-xl bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="submit"
                      className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold cursor-pointer shrink-0"
                    >
                      解密预览
                    </button>
                  </div>
                </form>
              )}

              {/* Error Banner for Invalid Files */}
              {detection.status === 'error' && (
                <div className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs text-red-600 dark:text-red-400 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{detection.message}</span>
                </div>
              )}

              {/* Merge Strategy & Record Preview List */}
              {detection.parsedRecords.length > 0 && (
                <div className="space-y-3">
                  {/* Duplicate Strategy Selector */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      合并去重策略：
                    </span>
                    <div className="grid grid-cols-2 gap-1.5 p-1 bg-slate-100 dark:bg-slate-950 rounded-xl">
                      <button
                        type="button"
                        onClick={() => setStrategy('skip-duplicates')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                          strategy === 'skip-duplicates'
                            ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 font-semibold shadow-2xs'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        智能跳过重复项 (推荐)
                      </button>
                      <button
                        type="button"
                        onClick={() => setStrategy('import-all')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                          strategy === 'import-all'
                            ? 'bg-white dark:bg-slate-800 text-blue-600 dark:text-blue-400 font-semibold shadow-2xs'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        全部作为新记录导入
                      </button>
                    </div>
                  </div>

                  {/* Preview List */}
                  <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                      <span>待导入记录预览（密码与卡号默认掩码保护）</span>
                      <span className="font-mono tabular-nums">
                        预计新增 {mergePreview.addedCount} 条 · 跳过重复{' '}
                        {mergePreview.skippedCount} 条
                      </span>
                    </div>
                    <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-52 overflow-y-auto">
                      {detection.parsedRecords.map(
                        (rec: CandidateRecordInput, idx: number) => {
                          const isDup =
                            strategy === 'skip-duplicates' &&
                            existingFingerprints.has(getRecordFingerprint(rec));
                          const isCard =
                            rec.recordType === 'card' &&
                            Boolean(rec.cardDetails);

                          return (
                            <div
                              key={`${rec.title}-${idx}`}
                              className={`px-4 py-2.5 flex items-center justify-between gap-3 text-xs ${
                                isDup ? 'opacity-50' : ''
                              }`}
                            >
                              <div className="flex items-center gap-2.5 min-w-0">
                                <div className="w-7 h-7 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center justify-center shrink-0 font-bold text-xs">
                                  {isCard ? (
                                    <CreditCard className="w-3.5 h-3.5" />
                                  ) : (
                                    <KeyRound className="w-3.5 h-3.5" />
                                  )}
                                </div>
                                <div className="min-w-0">
                                  <div className="font-semibold text-slate-900 dark:text-white truncate">
                                    {rec.title}
                                  </div>
                                  <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate">
                                    {isCard && rec.cardDetails
                                      ? `${rec.cardDetails.cardholderName} · ${maskCardNumber(rec.cardDetails.cardNumber)}`
                                      : `${rec.username || '无用户名'} · ••••••••`}
                                  </div>
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0 text-[11px]">
                                <span className="text-slate-400 dark:text-slate-500">
                                  {CATEGORY_META[rec.category]?.label ??
                                    rec.category}
                                </span>
                                <span aria-hidden="true" className="text-slate-300 dark:text-slate-700">
                                  ·
                                </span>
                                <span
                                  className={
                                    isDup
                                      ? 'text-amber-600 dark:text-amber-400 font-medium'
                                      : 'text-emerald-600 dark:text-emerald-400 font-semibold'
                                  }
                                >
                                  {isDup ? '跳过重复' : '待加密并入'}
                                </span>
                              </div>
                            </div>
                          );
                        }
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {submitSuccessMsg && (
            <div
              data-testid="import-success-alert"
              className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs text-emerald-700 dark:text-emerald-300 flex items-center gap-2 font-semibold"
            >
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{submitSuccessMsg}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={resetModal}
            className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-200/70 dark:hover:bg-slate-800 transition-colors cursor-pointer min-h-[40px]"
          >
            取消
          </button>
          <button
            type="button"
            disabled={
              isSubmitting ||
              !detection ||
              detection.parsedRecords.length === 0 ||
              mergePreview.addedCount === 0
            }
            onClick={handleConfirmImport}
            className="px-5 py-2 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:pointer-events-none transition-colors cursor-pointer flex items-center gap-1.5 min-h-[40px]"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>
              {isSubmitting
                ? '正在执行 AES-256-GCM 加密合并...'
                : `确认加密合并 (${mergePreview.addedCount} 条新记录)`}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
};
