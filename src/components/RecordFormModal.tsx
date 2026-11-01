import React, { useState, useEffect } from 'react';
import {
  X,
  Eye,
  EyeOff,
  Wand2,
  RefreshCw,
  ShieldCheck,
  Star,
  AlertCircle,
  CreditCard,
  KeyRound,
  Tag,
  Plus,
} from 'lucide-react';
import {
  DecryptedVaultRecord,
  VaultCategory,
  VaultCategoryItem,
  RecordType,
  DEFAULT_CATEGORIES,
} from '../types/vault';
import {
  generateStrongPassword,
  evaluatePasswordStrength,
  PasswordGeneratorOptions,
} from '../utils/passwordGenerator';
import {
  sanitizeCardNumber,
  formatCardNumberGroups,
  formatExpiryDateInput,
  sanitizeCvvInput,
  detectCardBrand,
  validatePaymentCardFields,
} from '../utils/paymentCardUtils';
import { CreditCardFace } from './RecordVisuals';

interface RecordFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (
    recordData: Omit<DecryptedVaultRecord, 'id' | 'createdAt' | 'updatedAt'>,
    existingId?: string
  ) => Promise<void>;
  editingRecord?: DecryptedVaultRecord | null;
  prefillDraft?: Partial<DecryptedVaultRecord> | null;
  categories?: VaultCategoryItem[];
  onOpenCategoryManager?: () => void;
  onQuickCreateCategory?: (label: string) => Promise<VaultCategoryItem>;
}

export const RecordFormModal: React.FC<RecordFormModalProps> = ({
  isOpen,
  onClose,
  onSave,
  editingRecord,
  prefillDraft = null,
  categories = DEFAULT_CATEGORIES,
  onOpenCategoryManager,
  onQuickCreateCategory,
}) => {
  const [recordType, setRecordType] = useState<RecordType>('login');
  const [title, setTitle] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [category, setCategory] = useState<VaultCategory>('work');
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [inlineNewTag, setInlineNewTag] = useState('');
  const [notes, setNotes] = useState('');
  const [favorite, setFavorite] = useState(false);

  // Payment Card dedicated state
  const [cardholderName, setCardholderName] = useState('');
  const [cardNumberFormatted, setCardNumberFormatted] = useState('');
  const [expiryDate, setExpiryDate] = useState('');
  const [cvv, setCvv] = useState('');
  const [showCardNumber, setShowCardNumber] = useState(true);
  const [showCvv, setShowCvv] = useState(false);
  const [isCardFlipped, setIsCardFlipped] = useState(false);

  const [showPassword, setShowPassword] = useState(false);
  const [showInlineGen, setShowInlineGen] = useState(false);
  const [genOpts, setGenOpts] = useState<PasswordGeneratorOptions>({
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setErrorMsg(null);
      setShowInlineGen(false);
      setIsCardFlipped(false);
      if (editingRecord) {
        const type: RecordType =
          editingRecord.recordType === 'card' ||
          editingRecord.category === 'bank-card' ||
          editingRecord.category === '银行卡'
            ? 'card'
            : 'login';
        setRecordType(type);
        setTitle(editingRecord.title);
        setUsername(editingRecord.username);
        setPassword(editingRecord.password);
        setUrl(editingRecord.url);
        setCategory(editingRecord.category);
        setSelectedTags(
          Array.isArray(editingRecord.tags) ? [...editingRecord.tags] : []
        );
        setInlineNewTag('');
        setNotes(editingRecord.notes);
        setFavorite(Boolean(editingRecord.favorite));

        if (editingRecord.cardDetails) {
          setCardholderName(editingRecord.cardDetails.cardholderName);
          setCardNumberFormatted(
            formatCardNumberGroups(editingRecord.cardDetails.cardNumber)
          );
          setExpiryDate(editingRecord.cardDetails.expiryDate);
          setCvv(editingRecord.cardDetails.cvv);
        } else {
          setCardholderName('');
          setCardNumberFormatted('');
          setExpiryDate('');
          setCvv('');
        }
      } else {
        setRecordType('login');
        setTitle(prefillDraft?.title ?? '');
        setUsername(prefillDraft?.username ?? '');
        setPassword(
          prefillDraft?.password ||
            generateStrongPassword({
              length: 20,
              uppercase: true,
              lowercase: true,
              numbers: true,
              symbols: true,
            })
        );
        setUrl(prefillDraft?.url ?? '');
        setCategory(prefillDraft?.category ?? categories[0]?.id ?? 'work');
        setSelectedTags(
          Array.isArray(prefillDraft?.tags) ? [...prefillDraft.tags] : []
        );
        setInlineNewTag('');
        setNotes(prefillDraft?.notes ?? '');
        setFavorite(Boolean(prefillDraft?.favorite));
        setCardholderName('');
        setCardNumberFormatted('');
        setExpiryDate('');
        setCvv('');
      }
    }
  }, [isOpen, editingRecord, prefillDraft, categories]);

  if (!isOpen) return null;

  const strength = evaluatePasswordStrength(password);
  const detectedBrand = detectCardBrand(cardNumberFormatted);

  const handleSwitchType = (nextType: RecordType) => {
    setRecordType(nextType);
    setErrorMsg(null);
    if (nextType === 'card' && !editingRecord) {
      setCategory('bank-card');
    } else if (
      nextType === 'login' &&
      !editingRecord &&
      category === 'bank-card'
    ) {
      setCategory('work');
    }
  };

  const handleApplyGenerated = (nextOpts: PasswordGeneratorOptions) => {
    setGenOpts(nextOpts);
    const nextPwd = generateStrongPassword(nextOpts);
    setPassword(nextPwd);
    setShowPassword(true);
  };

  const toggleGenCharSet = (
    key: keyof Omit<PasswordGeneratorOptions, 'length'>
  ) => {
    const activeCount = [
      genOpts.uppercase,
      genOpts.lowercase,
      genOpts.numbers,
      genOpts.symbols,
    ].filter(Boolean).length;
    if (genOpts[key] && activeCount <= 1) return;

    const updated = { ...genOpts, [key]: !genOpts[key] };
    handleApplyGenerated(updated);
  };

  const toggleTagSelection = (tagLabel: string) => {
    setSelectedTags((prev) =>
      prev.includes(tagLabel)
        ? prev.filter((t) => t !== tagLabel)
        : [...prev, tagLabel]
    );
  };

  const handleAddInlineTag = async () => {
    const clean = inlineNewTag.trim();
    if (!clean) return;
    setErrorMsg(null);
    try {
      if (onQuickCreateCategory) {
        const existing = categories.find(
          (c) => c.label.toLowerCase() === clean.toLowerCase()
        );
        if (!existing) {
          await onQuickCreateCategory(clean);
        }
      }
      setSelectedTags((prev) => (prev.includes(clean) ? prev : [...prev, clean]));
      setInlineNewTag('');
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '创建自定义标签失败');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!title.trim()) {
      setErrorMsg(
        recordType === 'card'
          ? '请填写支付卡名称（例如：招商银行 Visa 白金卡）。'
          : '请填写记录标题（例如：GitHub、AWS 生产控制台）。'
      );
      return;
    }

    if (recordType === 'card') {
      const cleanDigits = sanitizeCardNumber(cardNumberFormatted);
      const cardValidation = validatePaymentCardFields({
        cardholderName: cardholderName.trim(),
        cardNumber: cleanDigits,
        expiryDate: expiryDate.trim(),
        cvv: cvv.trim(),
      });

      if (!cardValidation.valid) {
        setErrorMsg(cardValidation.error ?? '支付卡字段校验未通过');
        return;
      }

      setIsSaving(true);
      try {
        await onSave(
          {
            recordType: 'card',
            title: title.trim(),
            username: cardholderName.trim(),
            password: password || cleanDigits.slice(-4),
            url: url.trim(),
            category,
            ...(selectedTags.length > 0 ? { tags: selectedTags } : {}),
            notes: notes.trim(),
            cardDetails: {
              cardholderName: cardholderName.trim(),
              cardNumber: cleanDigits,
              expiryDate: expiryDate.trim(),
              cvv: cvv.trim(),
              brand: detectCardBrand(cleanDigits),
            },
            favorite,
          },
          editingRecord?.id
        );
        onClose();
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : '加密并保存支付卡失败');
      } finally {
        setIsSaving(false);
      }
      return;
    }

    if (!password) {
      setErrorMsg('密码字段不能为空。');
      return;
    }

    setIsSaving(true);
    try {
      await onSave(
        {
          recordType: 'login',
          title: title.trim(),
          username: username.trim(),
          password,
          url: url.trim(),
          category,
          ...(selectedTags.length > 0 ? { tags: selectedTags } : {}),
          notes: notes.trim(),
          cardDetails: undefined,
          favorite,
        },
        editingRecord?.id
      );
      onClose();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '加密并保存记录失败');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/60 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="record-form-modal-title"
    >
      <div className="w-full max-w-xl rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl overflow-hidden my-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-4 sm:px-6 py-3.5 sm:py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-600 text-white flex items-center justify-center shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h2
                id="record-form-modal-title"
                className="text-base font-bold text-slate-900 dark:text-white"
              >
                {editingRecord ? '编辑记录' : '新建记录'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                支持保存网站账号凭证与银行卡信息
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭表单弹窗"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors min-h-[40px] min-w-[40px] flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-4 sm:p-6 space-y-4 max-h-[82vh] overflow-y-auto">
          {/* Record Type Segmented Selector */}
          <div
            className="grid grid-cols-2 gap-1.5 p-1 rounded-xl bg-slate-100 dark:bg-slate-950"
            role="tablist"
            aria-label="选择记录类型"
          >
            <button
              type="button"
              role="tab"
              aria-selected={recordType === 'login'}
              onClick={() => handleSwitchType('login')}
              className={`py-2 px-2.5 sm:px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 sm:gap-2 transition-colors whitespace-nowrap cursor-pointer min-h-[38px] ${
                recordType === 'login'
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-2xs'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5 shrink-0" />
              <span className="sm:hidden">登录凭证</span>
              <span className="hidden sm:inline">登录凭证 (账号/密码)</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={recordType === 'card'}
              onClick={() => handleSwitchType('card')}
              className={`py-2 px-2.5 sm:px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 sm:gap-2 transition-colors whitespace-nowrap cursor-pointer min-h-[38px] ${
                recordType === 'card'
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-2xs'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <CreditCard className="w-3.5 h-3.5 shrink-0" />
              <span className="sm:hidden">支付卡/银行卡</span>
              <span className="hidden sm:inline">支付卡 (银行卡/信用卡)</span>
            </button>
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="p-3 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 flex items-center gap-2 text-xs text-red-700 dark:text-red-300"
            >
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Title & Category Row */}
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
            <div className="sm:col-span-7 space-y-1.5">
              <label
                htmlFor="record-title-input"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                {recordType === 'card' ? '支付卡名称 / 发卡行 *' : '标题名称 *'}
              </label>
              <input
                id="record-title-input"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder={
                  recordType === 'card'
                    ? '例如：招商银行 Visa 全币种白金卡'
                    : '例如：GitHub、AWS 生产控制台'
                }
                autoFocus
                className="w-full px-3.5 py-2 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>

            <div className="sm:col-span-5 space-y-1.5">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="record-category-select"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                >
                  主分类
                </label>
                {onOpenCategoryManager && (
                  <button
                    type="button"
                    onClick={onOpenCategoryManager}
                    className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                  >
                    管理分类/标签
                  </button>
                )}
              </div>
              <div className="flex items-center gap-2">
                <select
                  id="record-category-select"
                  value={category}
                  onChange={(e) => {
                    const nextCat = e.target.value as VaultCategory;
                    setCategory(nextCat);
                    if (nextCat === 'bank-card' || nextCat === '银行卡') {
                      setRecordType('card');
                    }
                  }}
                  className="flex-1 px-3 py-2 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600 min-h-[44px] sm:min-h-[40px]"
                >
                  {categories.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => setFavorite(!favorite)}
                  aria-label={favorite ? '取消星标收藏' : '设为星标收藏'}
                  className={`p-2.5 rounded-xl border transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[40px] sm:min-w-[40px] flex items-center justify-center ${
                    favorite
                      ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-500'
                      : 'bg-slate-50 dark:bg-slate-950 border-slate-300 dark:border-slate-700 text-slate-400 hover:text-slate-600'
                  }`}
                >
                  <Star className={`w-4 h-4 ${favorite ? 'fill-amber-400' : ''}`} />
                </button>
              </div>
            </div>
          </div>

          {/* Multi-Tag Assignment & Quick Custom Tag Creator */}
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 space-y-2.5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300">
                <Tag className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" />
                <span>附加自定义标签（可多选，支持在侧边栏按标签筛选）</span>
              </div>
              <div className="flex items-center gap-1.5 w-full sm:w-auto">
                <input
                  type="text"
                  maxLength={16}
                  value={inlineNewTag}
                  onChange={(e) => setInlineNewTag(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddInlineTag();
                    }
                  }}
                  placeholder="新建标签..."
                  aria-label="在表单中快速新建自定义标签"
                  className="flex-1 sm:w-36 px-2.5 py-1.5 text-xs rounded-lg bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-600"
                />
                <button
                  type="button"
                  onClick={handleAddInlineTag}
                  className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1 shrink-0 whitespace-nowrap cursor-pointer"
                >
                  <Plus className="w-3 h-3" />
                  <span>添加</span>
                </button>
              </div>
            </div>

            <div className="flex items-center flex-wrap gap-1.5">
              {categories.map((cat) => {
                const isSelected = selectedTags.includes(cat.label);
                return (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => toggleTagSelection(cat.label)}
                    aria-pressed={isSelected}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      isSelected
                        ? 'bg-blue-600 text-white font-semibold shadow-2xs'
                        : 'bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                    }`}
                  >
                    #{cat.label}
                  </button>
                );
              })}
              {selectedTags
                .filter(
                  (t) => !categories.some((c) => c.label === t)
                )
                .map((extraTag) => (
                  <button
                    key={extraTag}
                    type="button"
                    onClick={() => toggleTagSelection(extraTag)}
                    aria-pressed={true}
                    className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-blue-600 text-white shadow-2xs cursor-pointer"
                  >
                    #{extraTag}
                  </button>
                ))}
            </div>
          </div>

          {recordType === 'card' ? (
            /* Payment Card Dedicated Fields + Live CSS Credit Card Face Preview */
            <div className="space-y-4">
              <CreditCardFace
                compact
                title={title || '招商银行 Visa 全币种白金卡'}
                cardholderName={cardholderName || 'LINUS CHEN'}
                cardNumber={cardNumberFormatted || '4392258801927465'}
                expiryDate={expiryDate || '08/29'}
                cvv={cvv || '842'}
                brand={detectedBrand}
                url={url}
                category={category}
                revealedNumber={showCardNumber}
                revealedCvv={showCvv}
                flipped={isCardFlipped}
                onToggleFlip={(next) => setIsCardFlipped(next)}
                onToggleRevealNumber={() => setShowCardNumber(!showCardNumber)}
                onToggleRevealCvv={() => setShowCvv(!showCvv)}
              />

              {/* Cardholder Name & Card Number */}
              <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                <div className="sm:col-span-5 space-y-1.5">
                  <label
                    htmlFor="cardholder-name-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    持卡人姓名 *
                  </label>
                  <input
                    id="cardholder-name-input"
                    type="text"
                    value={cardholderName}
                    onFocus={() => setIsCardFlipped(false)}
                    onChange={(e) => {
                      setCardholderName(e.target.value);
                      if (errorMsg) setErrorMsg(null);
                    }}
                    placeholder="LINUS CHEN / 张三"
                    className="w-full px-3.5 py-2 text-sm font-mono uppercase rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                <div className="sm:col-span-7 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="card-number-input"
                      className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                    >
                      银行卡号 (13-19 位数字) *
                    </label>
                    <span className="text-[11px] font-mono text-blue-600 dark:text-blue-400 font-semibold">
                      识别类型：{detectedBrand}
                    </span>
                  </div>
                  <div className="relative">
                    <input
                      id="card-number-input"
                      type={showCardNumber ? 'text' : 'password'}
                      inputMode="numeric"
                      value={cardNumberFormatted}
                      onFocus={() => setIsCardFlipped(false)}
                      onChange={(e) => {
                        setCardNumberFormatted(
                          formatCardNumberGroups(e.target.value)
                        );
                        if (errorMsg) setErrorMsg(null);
                      }}
                      placeholder="4392 2588 0192 7465"
                      className="w-full px-3.5 py-2 pr-10 text-sm font-mono tabular-nums rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      onClick={() => setShowCardNumber(!showCardNumber)}
                      aria-label={showCardNumber ? '掩码隐藏卡号' : '明文显示卡号'}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-md"
                    >
                      {showCardNumber ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Expiry Date, CVV/CVC, and Issuing Bank URL */}
              <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                <div className="sm:col-span-4 space-y-1.5">
                  <label
                    htmlFor="card-expiry-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    过期日期 (MM/YY) *
                  </label>
                  <input
                    id="card-expiry-input"
                    type="text"
                    inputMode="numeric"
                    maxLength={5}
                    value={expiryDate}
                    onFocus={() => setIsCardFlipped(false)}
                    onChange={(e) => {
                      setExpiryDate(formatExpiryDateInput(e.target.value));
                      if (errorMsg) setErrorMsg(null);
                    }}
                    placeholder="08/29"
                    className="w-full px-3.5 py-2 text-sm font-mono tabular-nums rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                <div className="sm:col-span-4 space-y-1.5">
                  <label
                    htmlFor="card-cvv-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    CVV / CVC 安全码 *
                  </label>
                  <div className="relative">
                    <input
                      id="card-cvv-input"
                      type={showCvv ? 'text' : 'password'}
                      inputMode="numeric"
                      maxLength={4}
                      value={cvv}
                      onFocus={() => {
                        setIsCardFlipped(true);
                        setShowCvv(true);
                      }}
                      onChange={(e) => {
                        setCvv(sanitizeCvvInput(e.target.value));
                        if (errorMsg) setErrorMsg(null);
                      }}
                      placeholder="3 或 4 位数字"
                      className="w-full px-3.5 py-2 pr-10 text-sm font-mono tabular-nums rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      onClick={() => setShowCvv(!showCvv)}
                      aria-label={showCvv ? '隐藏 CVV 安全码' : '显示 CVV 安全码'}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-md"
                    >
                      {showCvv ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="sm:col-span-4 space-y-1.5">
                  <label
                    htmlFor="record-url-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    网银网址 (可选)
                  </label>
                  <input
                    id="record-url-input"
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://www.cmbchina.com"
                    className="w-full px-3.5 py-2 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>
              </div>
            </div>
          ) : (
            /* Standard Login Fields */
            <>
              {/* Username & URL Row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="record-username-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    登录账号 / 邮箱 / 手机号
                  </label>
                  <input
                    id="record-username-input"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="user@example.com"
                    className="w-full px-3.5 py-2 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="record-url-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    关联网址 (URL)
                  </label>
                  <input
                    id="record-url-input"
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full px-3.5 py-2 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                  />
                </div>
              </div>

              {/* Password Field + Built-in Inline Generator */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="record-password-input"
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
                  >
                    登录密码 *
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowInlineGen(!showInlineGen)}
                    className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    <Wand2 className="w-3.5 h-3.5" />
                    <span>
                      {showInlineGen ? '收起密码生成器' : '展开随机强密码生成器'}
                    </span>
                  </button>
                </div>

                <div className="relative flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      id="record-password-input"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="输入或使用右侧生成器生成高强度密码..."
                      className="w-full px-3.5 py-2 pr-10 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? '隐藏密码' : '显示密码'}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-md"
                    >
                      {showPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleApplyGenerated(genOpts)}
                    title="立即随机生成新密码"
                    className="px-3 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer min-h-[44px] sm:min-h-[38px]"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>随机生成</span>
                  </button>
                </div>

                {/* Password Strength Bar */}
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500 dark:text-slate-400">
                    强度评估：
                    <span className={`font-semibold ml-1 ${strength.colorClass}`}>
                      {strength.label}
                    </span>
                  </span>
                  <span className="font-mono tabular-nums text-slate-400">
                    {strength.entropyBits} bits
                  </span>
                </div>

                {/* Expandable Inline Generator Panel */}
                {showInlineGen && (
                  <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-slate-700 dark:text-slate-300">
                        生成长度：
                        <strong className="font-mono tabular-nums">
                          {genOpts.length}
                        </strong>{' '}
                        位
                      </span>
                      <input
                        type="range"
                        min={8}
                        max={64}
                        value={genOpts.length}
                        onChange={(e) =>
                          handleApplyGenerated({
                            ...genOpts,
                            length: Number(e.target.value),
                          })
                        }
                        aria-label="调整生成密码长度"
                        className="w-44 accent-blue-600 cursor-pointer"
                      />
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={genOpts.uppercase}
                          onChange={() => toggleGenCharSet('uppercase')}
                          className="rounded text-blue-600"
                        />
                        <span>大写 (A-Z)</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={genOpts.lowercase}
                          onChange={() => toggleGenCharSet('lowercase')}
                          className="rounded text-blue-600"
                        />
                        <span>小写 (a-z)</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={genOpts.numbers}
                          onChange={() => toggleGenCharSet('numbers')}
                          className="rounded text-blue-600"
                        />
                        <span>数字 (0-9)</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={genOpts.symbols}
                          onChange={() => toggleGenCharSet('symbols')}
                          className="rounded text-blue-600"
                        />
                        <span>符号 (!@#$)</span>
                      </label>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          {/* Notes Field */}
          <div className="space-y-1.5">
            <label
              htmlFor="record-notes-textarea"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300"
            >
              备注说明
            </label>
            <textarea
              id="record-notes-textarea"
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder={
                recordType === 'card'
                  ? '账单日、还款日、取现密码提示或客服专线...'
                  : '备用恢复码、安全问题答案或二步验证提示...'
              }
              className="w-full px-3.5 py-2 text-sm rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-600 resize-none"
            />
          </div>

          {/* Footer Actions */}
          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer min-h-[44px] sm:min-h-[40px]"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={isSaving}
              className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-xs font-semibold transition-colors cursor-pointer min-h-[44px] sm:min-h-[40px]"
            >
              {isSaving
                ? '正在 AES-GCM 加密写入...'
                : editingRecord
                ? '加密并更新记录'
                : recordType === 'card'
                ? '加密并保存支付卡'
                : '加密并保存记录'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
