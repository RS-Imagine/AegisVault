import React, { useState, useEffect } from 'react';
import {
  Wifi,
  Eye,
  EyeOff,
  Copy,
  Check,
  RotateCw,
  RotateCcw,
  ShieldCheck,
} from 'lucide-react';
import {
  extractDomainFromUrl,
  getBrandAvatarStyle,
  LocalBrandIconId,
  resolveBankCardTheme,
} from '../utils/brandVisuals';
import {
  formatCardNumberGroups,
  maskCardNumber,
  maskCvvCode,
  sanitizeCardNumber,
} from '../utils/paymentCardUtils';

interface RecordWebsiteLogoProps {
  title: string;
  url: string;
  size?: 'md' | 'lg';
  isSelected?: boolean;
}

const BuiltInBrandVectorIcon: React.FC<{
  iconId: LocalBrandIconId;
  className?: string;
}> = ({ iconId, className = 'w-5 h-5' }) => {
  switch (iconId) {
    case 'github':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
      );
    case 'cloudflare':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M16.5 17.5h-10a3.5 3.5 0 01-.4-6.97A5.5 5.5 0 0116.7 8.1a4.25 4.25 0 01-.2 9.4z" />
        </svg>
      );
    case 'google':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M21.35 11.1h-9.17v2.73h6.51c-.33 3.81-3.5 5.44-6.5 5.44C8.36 19.27 5 15.65 5 12c0-3.65 3.36-7.27 7.19-7.27 3.09 0 4.9 1.97 4.9 1.97L19 4.72S16.56 2 12.1 2C6.42 2 2.03 6.8 2.03 12c0 5.05 4.13 10 10.22 10 5.35 0 9.25-3.67 9.25-9.09 0-1.15-.15-1.81-.15-1.81z" />
        </svg>
      );
    case 'apple':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.53 4.08zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
        </svg>
      );
    case 'microsoft':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M3 3h8.5v8.5H3V3zm9.5 0H21v8.5h-8.5V3zM3 12.5h8.5V21H3v-8.5zm9.5 0H21V21h-8.5v-8.5z" />
        </svg>
      );
    case 'vercel':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M12 3l10 18H2L12 3z" />
        </svg>
      );
    case 'telegram':
      return (
        <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
          <path d="M20.665 3.717l-17.73 6.837c-1.21.486-1.203 1.161-.222 1.462l4.552 1.42 10.532-6.645c.498-.303.953-.14.579.192l-8.533 7.701h-.002l.002.001-.314 4.692c.46 0 .663-.211.921-.46l2.211-2.15 4.599 3.397c.848.467 1.457.227 1.668-.785l3.019-14.228c.309-1.239-.473-1.8-1.282-1.434z" />
        </svg>
      );
    default:
      return null;
  }
};

/**
 * Displays a purely local, zero-knowledge brand vector icon or monogram avatar.
 * Never makes any third-party favicon HTTP requests (protecting user privacy and
 * ensuring instant rendering in mainland China and offline environments).
 */
export const RecordWebsiteLogo: React.FC<RecordWebsiteLogoProps> = ({
  title,
  url,
  size = 'md',
  isSelected = false,
}) => {
  const domain = extractDomainFromUrl(url);
  const brandStyle = getBrandAvatarStyle(title, url);

  const sizeClasses =
    size === 'lg'
      ? 'w-12 h-12 rounded-2xl text-sm'
      : 'w-10 h-10 rounded-xl text-xs';

  const hasVectorIcon =
    brandStyle.iconId &&
    [
      'github',
      'cloudflare',
      'google',
      'apple',
      'microsoft',
      'vercel',
      'telegram',
    ].includes(brandStyle.iconId);

  return (
    <div
      data-testid="record-website-logo"
      data-domain={domain ?? 'none'}
      data-brand-icon={brandStyle.iconId ?? 'monogram'}
      title={brandStyle.brandLabel || domain || title}
      className={`${sizeClasses} relative flex items-center justify-center font-bold shrink-0 border overflow-hidden transition-colors ${
        isSelected
          ? 'ring-2 ring-blue-500 border-blue-500/40 bg-white dark:bg-slate-900'
          : `${brandStyle.bgClass}`
      }`}
    >
      {hasVectorIcon && brandStyle.iconId ? (
        <span className={`select-none ${brandStyle.textClass}`}>
          <BuiltInBrandVectorIcon
            iconId={brandStyle.iconId}
            className={size === 'lg' ? 'w-6 h-6' : 'w-4.5 h-4.5'}
          />
        </span>
      ) : (
        <span
          className={`select-none font-mono tracking-tight ${brandStyle.textClass}`}
        >
          {brandStyle.monogram}
        </span>
      )}
    </div>
  );
};

interface BankCardMiniBadgeProps {
  title: string;
  cardNumber: string;
  brand?: string;
  url?: string;
  isSelected?: boolean;
}

/**
 * Miniature CSS-based physical bank card thumbnail for list rows and headers.
 */
export const BankCardMiniBadge: React.FC<BankCardMiniBadgeProps> = ({
  title,
  cardNumber,
  brand,
  url,
  isSelected = false,
}) => {
  const theme = resolveBankCardTheme(title, cardNumber, brand, url);
  const last4 = cardNumber.replace(/\D/g, '').slice(-4) || '••••';

  return (
    <div
      data-testid="bank-card-mini-badge"
      className={`w-12 h-8 rounded-lg ${theme.badgeBgClass} text-white p-1.5 flex flex-col justify-between shrink-0 shadow-xs border relative overflow-hidden ${
        isSelected
          ? 'ring-2 ring-blue-500 border-blue-400'
          : 'border-white/20'
      }`}
    >
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(125deg,rgba(255,255,255,0.18)_0%,transparent_55%)]" />
      <div className="relative z-10 flex items-center justify-between">
        <span
          className={`w-2.5 h-2 rounded-[2px] ${
            theme.chipStyle === 'gold'
              ? 'bg-amber-300/95'
              : 'bg-slate-200/95'
          }`}
        />
        <span className="text-[7px] font-mono font-extrabold tracking-tighter opacity-95">
          {theme.issuerCode}
        </span>
      </div>
      <div className="relative z-10 text-[8px] font-mono tabular-nums tracking-tight text-right opacity-95 leading-none">
        {last4}
      </div>
    </div>
  );
};

/**
 * Vector / CSS Card Network Emblem (Mastercard, Visa, UnionPay 银联, Amex, JCB).
 */
export const CardNetworkEmblem: React.FC<{ network: string }> = ({
  network,
}) => {
  if (network === 'Mastercard') {
    return (
      <div
        className="flex items-center"
        aria-label="Mastercard"
        title="Mastercard"
      >
        <div className="w-6 h-6 rounded-full bg-red-500/90 shadow-inner" />
        <div className="w-6 h-6 rounded-full bg-amber-400/90 -ml-2.5 mix-blend-screen shadow-inner" />
      </div>
    );
  }

  if (network.includes('UnionPay') || network.includes('银联')) {
    return (
      <div
        className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-white/10 border border-white/25 text-[10px] font-bold tracking-tight shadow-2xs"
        title="UnionPay 中国银联"
      >
        <span className="w-2 h-3 rounded-[1px] bg-red-500 inline-block -skew-x-12" />
        <span className="w-2 h-3 rounded-[1px] bg-sky-600 inline-block -skew-x-12 -ml-0.5" />
        <span className="w-2 h-3 rounded-[1px] bg-emerald-500 inline-block -skew-x-12 -ml-0.5 mr-1" />
        <span className="text-white font-sans">银联</span>
      </div>
    );
  }

  if (network === 'American Express') {
    return (
      <span className="px-2 py-0.5 rounded bg-sky-500/25 border border-sky-300/35 text-[11px] font-mono font-extrabold tracking-wider text-sky-100">
        AMEX
      </span>
    );
  }

  if (network === 'JCB') {
    return (
      <span className="px-2 py-0.5 rounded bg-white/15 border border-white/25 text-[11px] font-mono font-extrabold tracking-wider text-white">
        JCB
      </span>
    );
  }

  return (
    <span className="text-base sm:text-lg font-mono font-black italic tracking-wider text-white [text-shadow:0_1px_2px_rgba(0,0,0,0.5)]">
      VISA
    </span>
  );
};

/**
 * Pure CSS metallic EMV smart chip with etched contact pad geometry.
 */
const CssEmvChip: React.FC<{ styleType: 'gold' | 'silver' }> = ({
  styleType,
}) => {
  const isGold = styleType === 'gold';
  return (
    <div
      className={`w-12 h-9 rounded-md border flex items-center justify-center relative overflow-hidden shadow-inner ${
        isGold
          ? 'bg-gradient-to-br from-amber-200 via-yellow-400 to-amber-600 border-amber-100/70'
          : 'bg-gradient-to-br from-slate-100 via-slate-300 to-slate-500 border-white/70'
      }`}
      aria-hidden="true"
    >
      <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.45)_0%,transparent_50%,rgba(0,0,0,0.15)_100%)]" />
      <div className="absolute inset-x-0 top-1/3 h-[1px] bg-black/25" />
      <div className="absolute inset-x-0 bottom-1/3 h-[1px] bg-black/25" />
      <div className="absolute inset-y-0 left-1/3 w-[1px] bg-black/25" />
      <div className="absolute inset-y-0 right-1/3 w-[1px] bg-black/25" />
      <div
        className={`w-4 h-5 rounded-[3px] border relative z-10 ${
          isGold
            ? 'border-black/30 bg-amber-300/50'
            : 'border-black/30 bg-slate-200/50'
        }`}
      />
    </div>
  );
};

export interface CreditCardFaceProps {
  title: string;
  cardholderName: string;
  cardNumber: string;
  expiryDate: string;
  cvv: string;
  brand?: string;
  url?: string;
  category?: string;
  revealedNumber?: boolean;
  revealedCvv?: boolean;
  onToggleRevealNumber?: () => void;
  onToggleRevealCvv?: () => void;
  onCopyCardNumber?: () => void;
  isCopiedNumber?: boolean;
  onCopyCvv?: () => void;
  isCopiedCvv?: boolean;
  flipped?: boolean;
  onToggleFlip?: (nextFlipped: boolean) => void;
  compact?: boolean;
}

/**
 * Pure CSS-based realistic 3D Interactive Credit/Bank Card component.
 */
export const CreditCardFace: React.FC<CreditCardFaceProps> = ({
  title,
  cardholderName,
  cardNumber,
  expiryDate,
  cvv,
  brand,
  url,
  category = 'bank-card',
  revealedNumber = false,
  revealedCvv = false,
  onToggleRevealNumber,
  onToggleRevealCvv,
  onCopyCardNumber,
  isCopiedNumber = false,
  onCopyCvv,
  isCopiedCvv = false,
  flipped,
  onToggleFlip,
  compact = false,
}) => {
  const [internalFlipped, setInternalFlipped] = useState(false);

  useEffect(() => {
    setInternalFlipped(false);
  }, [title, cardNumber]);

  const isFlipped = flipped !== undefined ? flipped : internalFlipped;

  const handleSetFlipped = (next: boolean) => {
    if (onToggleFlip) {
      onToggleFlip(next);
    } else {
      setInternalFlipped(next);
    }
  };

  const cleanDigits = sanitizeCardNumber(cardNumber || '4392258801927465');
  const theme = resolveBankCardTheme(title, cleanDigits, brand, url);
  const lastFourDigits = (cleanDigits || '0000').slice(-4);

  const formattedDisplayNumber = revealedNumber
    ? formatCardNumberGroups(cleanDigits || '0000000000000000')
    : maskCardNumber(cleanDigits || '0000000000000000');

  const numberGroups = formattedDisplayNumber.split(' ').filter(Boolean);

  return (
    <div
      data-testid="credit-card-face"
      data-card-category={category}
      data-issuer={theme.bankName}
      data-card-side={isFlipped ? 'back' : 'front'}
      className="relative w-full select-none [perspective:1200px]"
    >
      <div
        className={`relative w-full transition-transform duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] [transform-style:preserve-3d] ${
          isFlipped ? '[transform:rotateY(180deg)]' : '[transform:rotateY(0deg)]'
        }`}
      >
        {/* ==================== FRONT FACE (正面) ==================== */}
        <div
          data-testid="credit-card-front"
          aria-hidden={isFlipped}
          className={`relative rounded-2xl ${
            compact ? 'p-4 sm:p-5 min-h-[198px]' : 'p-5 sm:p-6 min-h-[224px]'
          } text-white border shadow-xl ring-1 ring-inset ring-white/15 overflow-hidden flex flex-col justify-between [backface-visibility:hidden] [-webkit-backface-visibility:hidden] ${
            isFlipped ? 'pointer-events-none' : 'pointer-events-auto'
          } ${theme.gradientClass}`}
        >
          <div
            className="pointer-events-none absolute inset-0 opacity-25 bg-[radial-gradient(rgba(255,255,255,0.16)_1px,transparent_1px)] [background-size:14px_14px]"
            aria-hidden="true"
          />
          <div
            className="pointer-events-none absolute inset-0 bg-[linear-gradient(115deg,transparent_18%,rgba(255,255,255,0.05)_42%,rgba(255,255,255,0.14)_50%,rgba(255,255,255,0.05)_58%,transparent_82%)]"
            aria-hidden="true"
          />
          <div
            className="pointer-events-none absolute -right-12 -top-12 w-48 h-48 rounded-full bg-white/10 blur-2xl"
            aria-hidden="true"
          />
          <div
            className="pointer-events-none absolute -left-10 -bottom-16 w-52 h-52 rounded-full bg-black/30 blur-xl"
            aria-hidden="true"
          />

          <div className="relative z-10 flex flex-col justify-between gap-4 sm:gap-5 flex-1">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 min-w-0">
                <div
                  data-testid="card-issuer-crest"
                  className="w-9 h-9 rounded-xl bg-white/12 border border-white/25 backdrop-blur-xs flex items-center justify-center shrink-0 shadow-inner"
                >
                  <span className="font-mono text-[10px] font-black tracking-tighter text-white">
                    {theme.issuerCode}
                  </span>
                </div>

                <div className="min-w-0">
                  <div
                    data-testid="card-issuer-branding"
                    className="text-sm sm:text-base font-bold tracking-wide text-white truncate [text-shadow:0_1px_2px_rgba(0,0,0,0.45)]"
                  >
                    {title || theme.bankName}
                  </div>
                  <div
                    className={`text-[10px] font-mono tracking-widest uppercase mt-0.5 opacity-85 truncate ${theme.accentColorClass}`}
                  >
                    {theme.bankName} · {theme.cardTier}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                <Wifi
                  className="w-4 h-4 rotate-90 text-white/75"
                  aria-label="支持非接触式闪付"
                />
                <CardNetworkEmblem network={theme.network} />
              </div>
            </div>

            <div className="space-y-3 pt-0.5">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <CssEmvChip styleType={theme.chipStyle} />

                <div className="flex items-center gap-1.5 flex-wrap">
                  {onToggleRevealNumber && (
                    <button
                      type="button"
                      onClick={onToggleRevealNumber}
                      aria-label={revealedNumber ? '切换掩码卡号' : '显示完整卡号'}
                      className="px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/15 text-xs font-medium text-white/95 flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
                    >
                      {revealedNumber ? (
                        <>
                          <EyeOff className="w-3 h-3" />
                          <span>掩码</span>
                        </>
                      ) : (
                        <>
                          <Eye className="w-3 h-3" />
                          <span>显号</span>
                        </>
                      )}
                    </button>
                  )}

                  {onCopyCardNumber && (
                    <button
                      type="button"
                      onClick={onCopyCardNumber}
                      className="px-2.5 py-1 rounded-lg bg-white/15 hover:bg-white/25 border border-white/20 text-xs font-semibold text-white flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
                    >
                      {isCopiedNumber ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-300" />
                          <span>已复制</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>复制卡号</span>
                        </>
                      )}
                    </button>
                  )}

                  <button
                    type="button"
                    data-testid="flip-card-to-back"
                    onClick={() => handleSetFlipped(true)}
                    title="3D 翻转查看卡片背面磁条与 CVV 安全码"
                    className="px-2.5 py-1 rounded-lg bg-black/25 hover:bg-black/40 border border-white/20 text-xs font-medium text-white/95 flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
                  >
                    <RotateCw className="w-3 h-3" />
                    <span>背面 CVV</span>
                  </button>
                </div>
              </div>

              <div
                data-testid="card-preview-number"
                aria-label="信用卡卡号"
                className="font-mono tabular-nums text-base sm:text-2xl font-bold tracking-[0.06em] sm:tracking-[0.14em] text-white [text-shadow:0_2px_3px_rgba(0,0,0,0.65)] select-all pt-1 flex items-center justify-between sm:justify-start flex-nowrap whitespace-nowrap gap-x-2 sm:gap-x-3.5 overflow-x-auto"
              >
                {numberGroups.length > 0 ? (
                  numberGroups.map((group, idx) => (
                    <span
                      key={`${idx}-${group}`}
                      className={
                        !revealedNumber && idx < numberGroups.length - 1
                          ? 'text-white/90 shrink-0'
                          : 'text-white font-extrabold shrink-0'
                      }
                    >
                      {group}
                    </span>
                  ))
                ) : (
                  <span className="shrink-0">{formattedDisplayNumber}</span>
                )}
              </div>
            </div>

            <div className="flex items-end justify-between gap-2 sm:gap-3 pt-3 border-t border-white/15 text-xs">
              <div className="min-w-0 flex-1">
                <div className="text-[9px] font-mono uppercase tracking-wider text-white/60 whitespace-nowrap">
                  CARDHOLDER NAME
                </div>
                <div
                  data-testid="card-preview-holder"
                  className="font-mono font-semibold uppercase truncate mt-0.5 text-white/95 tracking-wider [text-shadow:0_1px_2px_rgba(0,0,0,0.5)]"
                >
                  {cardholderName || 'CARDHOLDER'}
                </div>
              </div>

              <div className="shrink-0">
                <div className="text-[9px] font-mono uppercase tracking-wider text-white/60 whitespace-nowrap">
                  VALID THRU
                </div>
                <div
                  data-testid="card-preview-expiry"
                  className="font-mono tabular-nums font-semibold mt-0.5 text-white/95 whitespace-nowrap [text-shadow:0_1px_2px_rgba(0,0,0,0.5)]"
                >
                  {expiryDate || 'MM/YY'}
                </div>
              </div>

              <div className="shrink-0 text-right">
                <div className="text-[9px] font-mono uppercase tracking-wider text-white/60 flex items-center justify-end gap-1 whitespace-nowrap">
                  <span>CVV / CVC</span>
                </div>
                <div
                  data-testid="card-preview-cvv"
                  onClick={() => {
                    if (onToggleRevealCvv) onToggleRevealCvv();
                  }}
                  title="点击切换显示安全码，或点击上方『背面 CVV』翻转卡片"
                  className="font-mono tabular-nums font-semibold mt-0.5 text-white/95 cursor-pointer hover:text-amber-200 transition-colors whitespace-nowrap [text-shadow:0_1px_2px_rgba(0,0,0,0.5)]"
                >
                  {revealedCvv ? cvv || '•••' : maskCvvCode(cvv)}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ==================== BACK FACE (3D 仿真背面) ==================== */}
        <div
          data-testid="credit-card-back"
          aria-hidden={!isFlipped}
          className={`absolute inset-0 rounded-2xl ${
            compact ? 'py-3.5 px-4 sm:px-5' : 'py-4 px-5 sm:px-6'
          } text-white border shadow-xl ring-1 ring-inset ring-white/15 overflow-hidden flex flex-col justify-between [backface-visibility:hidden] [-webkit-backface-visibility:hidden] [transform:rotateY(180deg)] ${
            isFlipped ? 'pointer-events-auto' : 'pointer-events-none'
          } ${theme.gradientClass}`}
        >
          <div
            className="pointer-events-none absolute inset-0 opacity-20 bg-[radial-gradient(rgba(255,255,255,0.14)_1px,transparent_1px)] [background-size:12px_12px]"
            aria-hidden="true"
          />

          <div className="relative z-10 space-y-1.5">
            <div className="flex items-center justify-between text-[9px] font-mono tracking-wider text-white/60 uppercase">
              <span>{theme.bankName} · AUTHORIZED ISSUER</span>
              <span>ISO/IEC 7810 ID-1</span>
            </div>

            <div
              data-testid="card-magnetic-stripe"
              className="-mx-5 sm:-mx-6 h-10 sm:h-11 bg-gradient-to-r from-neutral-950 via-slate-900 to-neutral-950 border-y border-white/15 shadow-inner relative overflow-hidden flex items-center justify-between px-6"
            >
              <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(110deg,transparent_25%,rgba(255,255,255,0.08)_48%,transparent_70%)]" />
              <span className="font-mono text-[9px] tracking-[0.25em] text-white/20 uppercase select-none">
                MAGSTRIPE · ENCRYPTED TRACK
              </span>
              <span className="font-mono text-[9px] tracking-widest text-white/25">
                •••• {lastFourDigits}
              </span>
            </div>
          </div>

          <div className="relative z-10 space-y-2.5 my-auto pt-1">
            <div className="flex items-center justify-between text-[10px] text-white/75 font-mono">
              <span>AUTHORIZED SIGNATURE · 持卡人签名栏</span>
              <span className="text-amber-200/90 font-semibold">
                SECURITY CODE (CVV/CVC)
              </span>
            </div>

            <div className="flex items-stretch shadow-md rounded-lg overflow-hidden border border-white/25">
              <div className="flex-1 bg-gradient-to-r from-stone-100 via-amber-50 to-stone-200 px-3.5 py-2 flex items-center justify-between relative overflow-hidden">
                <div
                  className="pointer-events-none absolute inset-0 opacity-20 bg-[repeating-linear-gradient(45deg,#475569_0px,#475569_1px,transparent_1px,transparent_6px)]"
                  aria-hidden="true"
                />
                <span className="relative z-10 font-serif italic text-xs sm:text-sm font-semibold text-slate-700 tracking-wider truncate">
                  {cardholderName || 'AUTHORIZED USER'}
                </span>
                <span className="relative z-10 font-mono text-[11px] italic text-slate-500 ml-2 shrink-0">
                  {lastFourDigits}
                </span>
              </div>

              <div
                data-testid="card-back-cvv"
                onClick={() => {
                  if (onToggleRevealCvv) onToggleRevealCvv();
                }}
                title="点击切换明文/掩码显示 CVV 安全码"
                className="px-3.5 py-2 bg-white text-slate-950 border-l-2 border-amber-400 flex items-center gap-2 cursor-pointer hover:bg-amber-50 transition-colors shrink-0"
              >
                <span className="text-[9px] font-mono uppercase tracking-wider text-slate-400 font-bold">
                  CVV
                </span>
                <span className="font-mono tabular-nums text-sm sm:text-base font-black tracking-widest text-slate-900">
                  {revealedCvv ? cvv || '842' : maskCvvCode(cvv)}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between gap-2 pt-0.5 flex-wrap">
              <div className="flex items-center gap-1.5">
                {onToggleRevealCvv && (
                  <button
                    type="button"
                    data-testid="back-toggle-cvv-btn"
                    onClick={onToggleRevealCvv}
                    className="px-2.5 py-1 rounded-lg bg-white/12 hover:bg-white/20 border border-white/20 text-xs font-medium text-white flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
                  >
                    {revealedCvv ? (
                      <>
                        <EyeOff className="w-3 h-3" />
                        <span>隐藏安全码</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-3 h-3" />
                        <span>显示安全码</span>
                      </>
                    )}
                  </button>
                )}

                {onCopyCvv && (
                  <button
                    type="button"
                    data-testid="back-copy-cvv-btn"
                    onClick={onCopyCvv}
                    className="px-2.5 py-1 rounded-lg bg-white/15 hover:bg-white/25 border border-white/20 text-xs font-semibold text-white flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
                  >
                    {isCopiedCvv ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-300" />
                        <span>已复制 CVV</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>复制 CVV</span>
                      </>
                    )}
                  </button>
                )}
              </div>

              <button
                type="button"
                data-testid="flip-card-to-front"
                onClick={() => handleSetFlipped(false)}
                className="px-2.5 py-1 rounded-lg bg-black/30 hover:bg-black/45 border border-white/20 text-xs font-medium text-white flex items-center gap-1 transition-colors cursor-pointer min-h-[34px]"
              >
                <RotateCcw className="w-3 h-3" />
                <span>翻回正面</span>
              </button>
            </div>
          </div>

          <div className="relative z-10 flex items-center justify-between gap-3 pt-2 border-t border-white/15">
            <div className="flex items-center gap-2.5 min-w-0">
              <div
                className="w-10 h-6 rounded-md bg-[linear-gradient(135deg,#38bdf8_0%,#a855f7_35%,#ec4899_68%,#fde047_100%)] border border-white/50 shadow-inner flex items-center justify-center shrink-0"
                title="3D 全息防伪标识"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-white drop-shadow-xs" />
              </div>
              <div className="text-xs text-white/75 truncate leading-tight">
                <div>此卡受 AES-256-GCM 零知识保护</div>
                <div className="font-mono text-[10px] text-white/50">
                  {theme.bankName} · {theme.cardTier}
                </div>
              </div>
            </div>

            <div className="shrink-0">
              <CardNetworkEmblem network={theme.network} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export const BankCardSurface = CreditCardFace;
