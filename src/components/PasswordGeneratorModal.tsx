import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  RefreshCw,
  Copy,
  Check,
  Wand2,
  Sliders,
} from 'lucide-react';
import {
  generateStrongPassword,
  evaluatePasswordStrength,
  PasswordGeneratorOptions,
} from '../utils/passwordGenerator';

interface PasswordGeneratorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectPassword?: (password: string) => void;
}

export const PasswordGeneratorModal: React.FC<PasswordGeneratorModalProps> = ({
  isOpen,
  onClose,
  onSelectPassword,
}) => {
  const [options, setOptions] = useState<PasswordGeneratorOptions>({
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });

  const [generated, setGenerated] = useState('');
  const [copied, setCopied] = useState(false);

  const regenerate = useCallback((opts: PasswordGeneratorOptions) => {
    const next = generateStrongPassword(opts);
    setGenerated(next);
    setCopied(false);
  }, []);

  useEffect(() => {
    if (isOpen) {
      regenerate(options);
    }
  }, [isOpen, options, regenerate]);

  if (!isOpen) return null;

  const strength = evaluatePasswordStrength(generated);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(generated);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback copy
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const toggleOption = (key: keyof Omit<PasswordGeneratorOptions, 'length'>) => {
    const activeCount = [
      options.uppercase,
      options.lowercase,
      options.numbers,
      options.symbols,
    ].filter(Boolean).length;

    // Prevent disabling the last remaining character type
    if (options[key] && activeCount <= 1) {
      return;
    }

    setOptions((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/60 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="pwd-gen-modal-title"
    >
      <div className="w-full max-w-lg my-auto max-h-[90vh] rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 sm:px-6 py-3.5 sm:py-4 border-b border-slate-200 dark:border-slate-800 shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
              <Wand2 className="w-4 h-4" />
            </div>
            <div>
              <h2
                id="pwd-gen-modal-title"
                className="text-base font-bold text-slate-900 dark:text-white"
              >
                随机强密码生成器
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                基于 CSPRNG (window.crypto.getRandomValues) 密码学随机数生成
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭密码生成器"
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer min-h-[44px] min-w-[44px] sm:min-h-[38px] sm:min-w-[38px] flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-5 sm:p-6 space-y-5 overflow-y-auto flex-1">
          {/* Generated Password Display Box */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div
                data-testid="generated-password-output"
                className="font-mono text-base sm:text-lg font-semibold break-all text-slate-900 dark:text-white tracking-wide select-all"
              >
                {generated}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button
                  type="button"
                  onClick={() => regenerate(options)}
                  aria-label="重新生成随机密码"
                  className="p-2.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors min-h-[44px] min-w-[44px] sm:min-h-[40px] sm:min-w-[40px] flex items-center justify-center cursor-pointer"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={handleCopy}
                  className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors min-h-[44px] sm:min-h-[40px] whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>已复制</span>
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

            {/* Strength & Entropy */}
            <div className="pt-2 border-t border-slate-200/70 dark:border-slate-800/80 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="text-slate-500 dark:text-slate-400">安全评级：</span>
                <span className={`font-semibold ${strength.colorClass}`}>
                  {strength.label}
                </span>
              </div>
              <span className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
                信息熵 {strength.entropyBits} bits
              </span>
            </div>
          </div>

          {/* Length Slider */}
          <div className="space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <label
                htmlFor="pwd-length-slider"
                className="text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5"
              >
                <Sliders className="w-3.5 h-3.5 text-slate-400" />
                <span>密码长度 (字符数)</span>
              </label>
              <div className="flex items-center gap-1.5">
                {[12, 16, 24, 32].map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => setOptions((prev) => ({ ...prev, length: preset }))}
                    className={`px-2.5 py-1.5 text-xs font-mono tabular-nums rounded-md transition-colors cursor-pointer min-h-[36px] ${
                      options.length === preset
                        ? 'bg-blue-600 text-white font-semibold'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    {preset}
                  </button>
                ))}
                <span className="ml-1 px-2.5 py-1 rounded-lg bg-slate-900 dark:bg-slate-800 text-white font-mono tabular-nums text-xs font-bold">
                  {options.length}
                </span>
              </div>
            </div>

            <input
              id="pwd-length-slider"
              type="range"
              min={8}
              max={64}
              value={options.length}
              onChange={(e) =>
                setOptions((prev) => ({
                  ...prev,
                  length: Number(e.target.value),
                }))
              }
              className="w-full accent-blue-600 cursor-pointer"
            />
            <div className="flex justify-between text-xs font-mono tabular-nums text-slate-400">
              <span>8 位</span>
              <span>20 位 (推荐)</span>
              <span>36 位</span>
              <span>64 位</span>
            </div>
          </div>

          {/* Character Type Checkboxes */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
              包含字符集类型
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <label className="flex items-center justify-between p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 cursor-pointer select-none min-h-[44px]">
                <div className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={options.uppercase}
                    onChange={() => toggleOption('uppercase')}
                    className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    大写字母
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">A-Z</span>
              </label>

              <label className="flex items-center justify-between p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 cursor-pointer select-none min-h-[44px]">
                <div className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={options.lowercase}
                    onChange={() => toggleOption('lowercase')}
                    className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    小写字母
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">a-z</span>
              </label>

              <label className="flex items-center justify-between p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 cursor-pointer select-none min-h-[44px]">
                <div className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={options.numbers}
                    onChange={() => toggleOption('numbers')}
                    className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    数字字符
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">0-9</span>
              </label>

              <label className="flex items-center justify-between p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 cursor-pointer select-none min-h-[44px]">
                <div className="flex items-center gap-2.5">
                  <input
                    type="checkbox"
                    checked={options.symbols}
                    onChange={() => toggleOption('symbols')}
                    className="w-4 h-4 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-xs font-medium text-slate-800 dark:text-slate-200">
                    特殊符号
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">!@#$%^&*</span>
              </label>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 sm:px-6 py-3.5 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end gap-3 shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-slate-600 dark:text-slate-400 hover:bg-slate-200/70 dark:hover:bg-slate-800 transition-colors cursor-pointer min-h-[44px] sm:min-h-[40px]"
          >
            关闭
          </button>
          {onSelectPassword && (
            <button
              type="button"
              onClick={() => {
                onSelectPassword(generated);
                onClose();
              }}
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold transition-colors cursor-pointer min-h-[44px] sm:min-h-[40px]"
            >
              填入此密码
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
