import React, { useState } from 'react';
import {
  X,
  KeyRound,
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  EyeOff,
  RefreshCw,
} from 'lucide-react';
import { evaluatePasswordStrength } from '../utils/passwordGenerator';

interface MasterPasswordModalProps {
  isOpen: boolean;
  vaultId?: string;
  onClose: () => void;
  onExportBackupBeforeRotation?: () => void;
  onRotateMasterPassword: (
    oldPassword: string,
    newPassword: string,
    purgePreviousCloudSnapshots: boolean
  ) => Promise<void>;
}

export const MasterPasswordModal: React.FC<MasterPasswordModalProps> = ({
  isOpen,
  vaultId,
  onClose,
  onExportBackupBeforeRotation,
  onRotateMasterPassword,
}) => {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [purgeOldSnapshots, setPurgeOldSnapshots] = useState(true);
  const [showPasswords, setShowPasswords] = useState(false);
  const [isRotating, setIsRotating] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const strength = evaluatePasswordStrength(newPassword);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!oldPassword) {
      setErrorMsg('请输入当前主密码以验证身份并解密现有记录。');
      return;
    }
    if (newPassword.length < 8) {
      setErrorMsg('新主密码长度至少需要 8 个字符。');
      return;
    }
    if (newPassword === oldPassword) {
      setErrorMsg('新主密码不能与当前主密码相同。');
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMsg('两次输入的新主密码不一致，请核对。');
      return;
    }

    setIsRotating(true);
    try {
      await onRotateMasterPassword(oldPassword, newPassword, purgeOldSnapshots);
      setSuccessMsg(
        '已完成 V2 主密码与密钥轮换！vaultId 保持不变，已生成全新 128-bit 随机盐值并重加密全部记录与分类元数据。'
      );
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 1400);
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : '主密码轮换失败，原加密数据已完整保留。'
      );
    } finally {
      setIsRotating(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="master-password-rotation-title"
    >
      <div className="w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-blue-600/10 text-blue-600 dark:text-blue-400 flex items-center justify-center shrink-0">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h2
                id="master-password-rotation-title"
                className="text-base font-bold text-slate-900 dark:text-white"
              >
                修改主密码与轮换加密密钥 (V2 Key Rotation)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                保持密码库身份标识 <code className="font-mono">{vaultId ? `${vaultId.slice(0, 8)}…` : 'vaultId'}</code> 不变，重新派生密钥并重加密全库
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="关闭主密码修改窗口"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="p-3.5 rounded-xl bg-blue-50/70 dark:bg-blue-950/30 border border-blue-200/80 dark:border-blue-900/60 text-xs text-slate-700 dark:text-slate-300 space-y-1.5 leading-relaxed">
            <div className="font-semibold text-blue-900 dark:text-blue-300 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
              <span>V2 零知识密钥轮换保证：</span>
            </div>
            <p>
              系统将先使用当前主密码完整验证并解密所有记录与分类元数据，随后生成全新的 128-bit CSPRNG 随机盐值 (<code className="font-mono">kdf.salt</code>) 与 600,000 次 PBKDF2-SHA256 派生密钥，为每条记录重新生成随机 IV 与 AAD 认证标签。若中途发生任何错误，原密文与恢复备份将完好保留。
            </p>
          </div>

          {onExportBackupBeforeRotation && (
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs">
              <span className="text-slate-600 dark:text-slate-400">
                建议在轮换密钥前导出一份当前密码库的离线加密备份：
              </span>
              <button
                type="button"
                onClick={onExportBackupBeforeRotation}
                className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold flex items-center gap-1.5 shrink-0 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>导出当前备份</span>
              </button>
            </div>
          )}

          {/* Current Master Password */}
          <div>
            <label
              htmlFor="rotation-old-password"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
            >
              当前主密码 (用于认证解密现有数据)
            </label>
            <div className="relative">
              <input
                id="rotation-old-password"
                type={showPasswords ? 'text' : 'password'}
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                placeholder="输入当前正在使用的主密码"
                required
                className="w-full px-3.5 py-2.5 pr-10 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="button"
                onClick={() => setShowPasswords((s) => !s)}
                aria-label={showPasswords ? '隐藏密码' : '显示密码'}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
              >
                {showPasswords ? (
                  <EyeOff className="w-4 h-4" />
                ) : (
                  <Eye className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* New Master Password */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label
                htmlFor="rotation-new-password"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                新主密码 (至少 8 位高强度字符)
              </label>
              <span className={`text-xs font-semibold ${strength.colorClass}`}>
                强度：{strength.label} ({strength.entropyBits} bits)
              </span>
            </div>
            <input
              id="rotation-new-password"
              type={showPasswords ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="设置新的高强度主密码"
              required
              className="w-full px-3.5 py-2.5 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {/* Confirm New Master Password */}
          <div>
            <label
              htmlFor="rotation-confirm-password"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
            >
              确认新主密码
            </label>
            <input
              id="rotation-confirm-password"
              type={showPasswords ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="再次输入新主密码"
              required
              className="w-full px-3.5 py-2.5 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {/* Historical Cloud Snapshots Option */}
          <label className="flex items-start gap-2.5 p-3 rounded-xl bg-amber-50/70 dark:bg-amber-950/25 border border-amber-200/80 dark:border-amber-900/60 cursor-pointer">
            <input
              type="checkbox"
              checked={purgeOldSnapshots}
              onChange={(e) => setPurgeOldSnapshots(e.target.checked)}
              className="mt-0.5 rounded border-amber-400 text-blue-600 focus:ring-blue-500"
            />
            <div className="text-xs text-amber-900 dark:text-amber-200 leading-relaxed">
              <div className="font-semibold">
                下次云端同步时清理使用旧主密码加密的历史快照 (推荐)
              </div>
              <div className="text-[11px] text-amber-800/90 dark:text-amber-300/80 mt-0.5">
                注意：修改主密码后，此前保存在云端或本地的旧备份仍由旧主密码加密。勾选此项可在下次同步至 Cloudflare Durable Object 时自动清理旧密钥快照。
              </div>
            </div>
          </label>

          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-xl bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900/60 text-xs text-red-600 dark:text-red-400 flex items-center gap-2"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-900/60 text-xs text-emerald-700 dark:text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={isRotating}
              className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${isRotating ? 'animate-spin' : ''}`}
              />
              <span>
                {isRotating ? '正在重加密全库...' : '确认轮换主密码与密钥'}
              </span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
