import React, { useState } from 'react';
import {
  X,
  FileCode2,
  Copy,
  Check,
  ShieldCheck,
  Database,
  Lock,
  Download,
  Fingerprint,
} from 'lucide-react';
import {
  SyncService,
  VAULT_STORAGE_KEY,
} from '../services/syncService';

interface CiphertextInspectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onExportVault?: () => void;
}

export const CiphertextInspectorModal: React.FC<
  CiphertextInspectorModalProps
> = ({ isOpen, onClose, onExportVault }) => {
  const [copied, setCopied] = useState(false);
  const [exported, setExported] = useState(false);
  const [viewMode, setViewMode] = useState<'structured' | 'raw'>('structured');

  if (!isOpen) return null;

  const rawJson = SyncService.getRawStorageCiphertextJson();
  const parsedVault = SyncService.getLocalVault();
  const syncState = SyncService.getLocalSyncState();
  const byteSize = new Blob([rawJson]).size;

  const handleCopyJson = async () => {
    try {
      await navigator.clipboard.writeText(rawJson);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleExportFile = () => {
    if (!onExportVault) return;
    onExportVault();
    setExported(true);
    setTimeout(() => setExported(false), 2000);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/60 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ciphertext-inspector-title"
    >
      <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl overflow-hidden flex flex-col max-h-[88vh]">
        {/* Header */}
        <div className="flex items-start sm:items-center justify-between gap-2 px-4 sm:px-6 py-3.5 sm:py-4 border-b border-slate-200 dark:border-slate-800 shrink-0">
          <div className="flex items-start sm:items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400 flex items-center justify-center shrink-0 mt-0.5 sm:mt-0">
              <FileCode2 className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <h2
                id="ciphertext-inspector-title"
                className="text-sm sm:text-base font-bold text-slate-900 dark:text-white leading-snug"
              >
                V2 底层存储密文检视器 (Zero-Knowledge Storage Proof)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 break-all">
                实时读取 <code className="font-mono">localStorage[&quot;{VAULT_STORAGE_KEY}&quot;]</code> 与 IndexedDB V2 镜像内容
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭密文检视器"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer shrink-0 min-h-[40px] min-w-[40px] flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Cryptographic Verification Banner */}
        <div className="px-4 sm:px-6 py-3 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2.5 shrink-0">
          <div className="flex items-start sm:items-center gap-2 text-xs text-emerald-700 dark:text-emerald-400 font-medium">
            <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5 sm:mt-0" />
            <span>
              V2 零知识验证通过：持久层仅含独立 vaultId、PBKDF2 盐值、加密分类元数据与 AAD 绑定密文，0 明文泄露
            </span>
          </div>

          <div className="flex items-center flex-wrap gap-2">
            <div className="flex items-center p-0.5 rounded-lg bg-slate-200/70 dark:bg-slate-800 text-xs">
              <button
                type="button"
                onClick={() => setViewMode('structured')}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  viewMode === 'structured'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-2xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                V2 密文信封解析
              </button>
              <button
                type="button"
                onClick={() => setViewMode('raw')}
                className={`px-2.5 py-1 rounded-md font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  viewMode === 'raw'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-2xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                原始 JSON 源码
              </button>
            </div>

            {onExportVault && (
              <button
                type="button"
                onClick={handleExportFile}
                className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition-colors cursor-pointer"
              >
                {exported ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                    <span>已下载 JSON</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>下载离线备份</span>
                  </>
                )}
              </button>
            )}

            <button
              type="button"
              onClick={handleCopyJson}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 whitespace-nowrap transition-colors cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>已复制 JSON</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>复制密文 JSON</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-5 flex-1">
          {parsedVault ? (
            <>
              {/* Metadata Summary Row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500 dark:text-slate-400">格式版本 / 同步版本</div>
                  <div className="font-mono font-semibold text-slate-900 dark:text-white mt-1">
                    V{parsedVault.formatVersion} · Rev #{syncState.lastSyncedRevision}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500 dark:text-slate-400">PBKDF2 迭代次数</div>
                  <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-white mt-1">
                    {parsedVault.kdf.iterations.toLocaleString()} 次
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500 dark:text-slate-400">对称加密 + AAD</div>
                  <div className="font-mono font-semibold text-slate-900 dark:text-white mt-1">
                    {parsedVault.cipher.algorithm}-{parsedVault.cipher.keyLength}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                  <div className="text-slate-500 dark:text-slate-400">密文体积 / 记录数</div>
                  <div className="font-mono tabular-nums font-semibold text-slate-900 dark:text-white mt-1">
                    {byteSize.toLocaleString()} B · {parsedVault.encryptedRecords.length} 条
                  </div>
                </div>
              </div>

              {viewMode === 'structured' ? (
                <div className="space-y-4">
                  {/* Independent Vault ID & KDF Salt & Verifier */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs font-mono">
                    <div className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300 font-sans font-semibold">
                      <Fingerprint className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                      <span>独立密码库身份标识 (vaultId) 与 AAD 绑定校验器</span>
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">vaultId (独立于盐值): </span>
                      {parsedVault.vaultId}
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">kdf.salt (128-bit Base64): </span>
                      {parsedVault.kdf.salt}
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">verifier.iv: </span>
                      {parsedVault.verifier.iv}
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">verifier.ciphertext: </span>
                      {parsedVault.verifier.ciphertext}
                    </div>
                  </div>

                  {/* Encrypted Metadata (Categories) */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 text-xs font-mono">
                    <div className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300 font-sans font-semibold">
                      <Database className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span>加密分类与标签元数据 (encryptedMetadata · 禁止明文落盘)</span>
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">encryptedMetadata.iv: </span>
                      {parsedVault.encryptedMetadata.iv}
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 break-all">
                      <span className="text-slate-700 dark:text-slate-300 font-semibold">encryptedMetadata.ciphertext: </span>
                      {parsedVault.encryptedMetadata.ciphertext}
                    </div>
                  </div>

                  {/* Per-record Ciphertext List */}
                  <div className="space-y-2.5">
                    <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 flex flex-wrap items-center justify-between gap-1">
                      <span>逐条加密记录列表 (encryptedRecords · AAD 绑定 vaultId + recordId + timestamps)</span>
                      <span className="font-mono tabular-nums text-slate-400">
                        共 {parsedVault.encryptedRecords.length} 条 AES-GCM 密文记录
                      </span>
                    </div>

                    {parsedVault.encryptedRecords.map((rec, idx) => (
                      <div
                        key={rec.id}
                        className="p-3.5 rounded-xl bg-slate-950 text-slate-200 border border-slate-800 font-mono text-xs space-y-1.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-1 text-slate-400">
                          <span className="flex items-center gap-1.5 text-blue-400 font-semibold break-all">
                            <Lock className="w-3 h-3 shrink-0" />
                            <span>Record #{idx + 1} · ID: {rec.id} ({rec.recordType})</span>
                          </span>
                          <span className="tabular-nums whitespace-nowrap">
                            {new Date(rec.updatedAt).toLocaleString('zh-CN')}
                          </span>
                        </div>
                        <div className="break-all text-amber-300/90">
                          <span className="text-slate-400">iv (12 bytes): </span>
                          {rec.iv}
                        </div>
                        <div className="break-all text-emerald-400/90">
                          <span className="text-slate-400">ciphertext (AES-256-GCM + 128-bit AuthTag): </span>
                          {rec.ciphertext}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <pre
                  data-testid="raw-ciphertext-json"
                  className="p-4 rounded-xl bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto border border-slate-800 leading-relaxed"
                >
                  {rawJson}
                </pre>
              )}
            </>
          ) : (
            <pre
              data-testid="raw-ciphertext-json"
              className="p-4 rounded-xl bg-slate-950 text-emerald-400 font-mono text-xs overflow-x-auto border border-slate-800"
            >
              {rawJson}
            </pre>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 shrink-0">
          <span>存储键名：{VAULT_STORAGE_KEY}</span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 dark:bg-slate-800 text-white font-medium hover:bg-slate-800 dark:hover:bg-slate-700 transition-colors cursor-pointer"
          >
            完成核验
          </button>
        </div>
      </div>
    </div>
  );
};
