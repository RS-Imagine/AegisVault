import React, { useState, useMemo } from 'react';
import {
  X,
  Tag,
  Plus,
  Edit3,
  Trash2,
  Check,
  AlertCircle,
  CheckCircle2,
  FolderOpen,
} from 'lucide-react';
import { DecryptedVaultRecord, VaultCategoryItem } from '../types/vault';
import { computeCategoryCounts } from '../utils/categoryManager';

interface CategoryManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
  categories: VaultCategoryItem[];
  records: DecryptedVaultRecord[];
  onCreateCategory: (label: string) => Promise<void>;
  onRenameCategory: (id: string, newLabel: string) => Promise<void>;
  onDeleteCategory: (id: string) => Promise<void>;
}

const QUICK_SUGGESTED_TAGS = ['加密货币', '开发运维', '服务器', '家庭共享', '购物会员'];

export const CategoryManagerModal: React.FC<CategoryManagerModalProps> = ({
  isOpen,
  onClose,
  categories,
  records,
  onCreateCategory,
  onRenameCategory,
  onDeleteCategory,
}) => {
  const [newLabel, setNewLabel] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingValue, setEditingValue] = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  const counts = useMemo(
    () => computeCategoryCounts(records, categories),
    [records, categories]
  );

  if (!isOpen) return null;

  const showSuccess = (msg: string) => {
    setErrorMsg(null);
    setSuccessMsg(msg);
    setTimeout(() => {
      setSuccessMsg((prev) => (prev === msg ? null : prev));
    }, 2500);
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLabel.trim()) {
      setErrorMsg('请输入要创建的分类或标签名称');
      return;
    }
    setIsBusy(true);
    setErrorMsg(null);
    try {
      const trimmed = newLabel.trim();
      await onCreateCategory(trimmed);
      setNewLabel('');
      showSuccess(`已创建自定义分类标签“${trimmed}”`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '创建分类标签失败');
    } finally {
      setIsBusy(false);
    }
  };

  const handleQuickAdd = async (tagLabel: string) => {
    setIsBusy(true);
    setErrorMsg(null);
    try {
      await onCreateCategory(tagLabel);
      showSuccess(`已添加分类标签“${tagLabel}”`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '添加失败');
    } finally {
      setIsBusy(false);
    }
  };

  const startEditing = (cat: VaultCategoryItem) => {
    setEditingId(cat.id);
    setEditingValue(cat.label);
    setConfirmDeleteId(null);
    setErrorMsg(null);
  };

  const handleSaveRename = async (id: string) => {
    if (!editingValue.trim()) {
      setErrorMsg('重命名后的分类标签名称不能为空');
      return;
    }
    setIsBusy(true);
    setErrorMsg(null);
    try {
      await onRenameCategory(id, editingValue.trim());
      setEditingId(null);
      showSuccess(`已重命名为“${editingValue.trim()}”并同步更新关联加密记录`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '重命名失败');
    } finally {
      setIsBusy(false);
    }
  };

  const handleConfirmDelete = async (cat: VaultCategoryItem) => {
    setIsBusy(true);
    setErrorMsg(null);
    try {
      await onDeleteCategory(cat.id);
      setConfirmDeleteId(null);
      showSuccess(
        `已删除分类标签“${cat.label}”（原关联记录已安全迁移至“其他”并重新加密）`
      );
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '删除分类标签失败');
    } finally {
      setIsBusy(false);
    }
  };

  const existingLabelsSet = new Set(
    categories.map((c) => c.label.toLowerCase())
  );
  const availableSuggestions = QUICK_SUGGESTED_TAGS.filter(
    (t) => !existingLabelsSet.has(t.toLowerCase())
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="category-manager-modal-title"
    >
      <div className="w-full max-w-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600/10 dark:bg-blue-500/15 text-blue-600 dark:text-blue-400 flex items-center justify-center">
              <Tag className="w-4 h-4" />
            </div>
            <div>
              <h2
                id="category-manager-modal-title"
                className="text-base font-bold text-slate-900 dark:text-white"
              >
                分类与自定义标签管理
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                创建、重命名或删除分类标签，变更将自动应用并同步加密至关联记录
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭分类管理窗口"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-4 sm:p-6 space-y-5 max-h-[76vh] overflow-y-auto">
          {/* Create New Category/Tag Form */}
          <form onSubmit={handleAddSubmit} className="space-y-2.5">
            <label
              htmlFor="new-category-label-input"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
            >
              新建自定义分类 / 标签
            </label>
            <div className="flex items-center gap-2">
              <input
                id="new-category-label-input"
                type="text"
                maxLength={20}
                value={newLabel}
                onChange={(e) => {
                  setNewLabel(e.target.value);
                  if (errorMsg) setErrorMsg(null);
                }}
                placeholder="输入新分类或标签名称（例如：个人、财务、开发运维）..."
                className="flex-1 min-w-0 px-3.5 py-2 text-xs sm:text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
              <button
                type="submit"
                disabled={isBusy}
                className="px-3.5 sm:px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5 shrink-0 whitespace-nowrap cursor-pointer min-h-[40px]"
              >
                <Plus className="w-4 h-4" />
                <span>添加标签</span>
              </button>
            </div>

            {availableSuggestions.length > 0 && (
              <div className="flex items-center flex-wrap gap-1.5 pt-1 text-xs">
                <span className="text-xs text-slate-400 dark:text-slate-500">
                  快捷创建推荐标签：
                </span>
                {availableSuggestions.map((sug) => (
                  <button
                    key={sug}
                    type="button"
                    disabled={isBusy}
                    onClick={() => handleQuickAdd(sug)}
                    className="px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium transition-colors cursor-pointer"
                  >
                    + {sug}
                  </button>
                ))}
              </div>
            )}
          </form>

          {/* Feedback Banners */}
          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs text-red-600 dark:text-red-400 flex items-center gap-2"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div
              data-testid="category-manager-success"
              className="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-900 text-xs text-emerald-700 dark:text-emerald-300 flex items-center gap-2 font-medium"
            >
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Category List */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
            <div className="px-3.5 sm:px-4 py-2.5 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-semibold text-slate-500 dark:text-slate-400">
              <span>当前密码库分类与标签 ({categories.length})</span>
              <span>记录数 / 操作</span>
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-72 overflow-y-auto">
              {categories.map((cat) => {
                const isEditing = editingId === cat.id;
                const isConfirmingDelete = confirmDeleteId === cat.id;
                const count = counts[cat.id] ?? 0;
                const isFallback = Boolean(cat.isFallback || cat.id === 'other');

                return (
                  <div
                    key={cat.id}
                    className="px-3.5 sm:px-4 py-3 flex flex-wrap sm:flex-nowrap items-center justify-between gap-2.5"
                  >
                    {isEditing ? (
                      <div className="flex items-center gap-2 flex-1">
                        <input
                          type="text"
                          maxLength={20}
                          value={editingValue}
                          onChange={(e) => setEditingValue(e.target.value)}
                          aria-label={`编辑分类 ${cat.label} 的名称`}
                          autoFocus
                          className="flex-1 min-w-0 px-3 py-1.5 text-xs rounded-lg bg-slate-50 dark:bg-slate-950 border border-blue-500 text-slate-900 dark:text-white focus:outline-none"
                        />
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={() => handleSaveRename(cat.id)}
                          aria-label={`保存分类 ${cat.label} 的新名称`}
                          className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1 shrink-0 cursor-pointer"
                        >
                          <Check className="w-3.5 h-3.5" />
                          <span>保存</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => setEditingId(null)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-xs shrink-0 cursor-pointer"
                        >
                          取消
                        </button>
                      </div>
                    ) : (
                      <>
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className="w-7 h-7 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 flex items-center justify-center shrink-0">
                            <FolderOpen className="w-3.5 h-3.5" />
                          </div>
                          <div className="min-w-0">
                            <div className="text-xs sm:text-sm font-semibold text-slate-900 dark:text-white">
                              {cat.label}
                            </div>
                            <div className="hidden sm:block text-xs text-slate-400 dark:text-slate-500">
                              {isFallback
                                ? '系统默认兜底分类（支持重命名）'
                                : '可用于密码主分类与多标签筛选'}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0 ml-auto">
                          <span className="font-mono tabular-nums text-xs text-slate-500 dark:text-slate-400 mr-0.5 whitespace-nowrap">
                            {count} 条记录
                          </span>

                          <button
                            type="button"
                            onClick={() => startEditing(cat)}
                            aria-label={`重命名分类 ${cat.label}`}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                            <span>重命名</span>
                          </button>

                          {!isFallback && (
                            <>
                              {isConfirmingDelete ? (
                                <div className="flex items-center gap-1">
                                  <button
                                    type="button"
                                    disabled={isBusy}
                                    onClick={() => handleConfirmDelete(cat)}
                                    aria-label={`确认删除分类 ${cat.label}`}
                                    className="px-2.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold cursor-pointer"
                                  >
                                    确认删除
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => setConfirmDeleteId(null)}
                                    className="px-2 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-xs cursor-pointer"
                                  >
                                    取消
                                  </button>
                                </div>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setConfirmDeleteId(cat.id)}
                                  aria-label={`删除分类 ${cat.label}`}
                                  className="p-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors cursor-pointer"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-slate-900 dark:bg-slate-800 hover:bg-slate-800 dark:hover:bg-slate-700 text-white text-xs font-semibold transition-colors cursor-pointer min-h-[40px]"
          >
            完成并关闭
          </button>
        </div>
      </div>
    </div>
  );
};
