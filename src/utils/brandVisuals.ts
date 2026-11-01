import { detectCardBrand } from './paymentCardUtils';

export interface BankCardVisualTheme {
  bankName: string;
  issuerCode: string;
  cardTier: string;
  network: string;
  gradientClass: string;
  accentColorClass: string;
  chipStyle: 'gold' | 'silver';
  badgeBgClass: string;
}

export type LocalBrandIconId =
  | 'github'
  | 'cloudflare'
  | 'google'
  | 'apple'
  | 'microsoft'
  | 'aws'
  | 'gitlab'
  | 'discord'
  | 'telegram'
  | 'slack'
  | 'steam'
  | 'paypal'
  | 'stripe'
  | 'vercel'
  | 'openai'
  | 'notion'
  | 'x'
  | 'binance'
  | 'ibkr'
  | 'alipay'
  | 'wechat'
  | 'taobao'
  | 'jd'
  | 'bilibili'
  | 'netease'
  | 'qq'
  | 'baidu';

export interface BrandAvatarStyle {
  bgClass: string;
  textClass: string;
  monogram: string;
  iconId?: LocalBrandIconId;
  brandLabel?: string;
}

/**
 * Extracts a clean, normalized domain hostname from any URL or domain string.
 * Returns null if the input is empty or not a valid domain.
 */
export function extractDomainFromUrl(rawUrl: string): string | null {
  const trimmed = (rawUrl ?? '').trim();
  if (!trimmed) return null;

  try {
    const withProtocol =
      trimmed.startsWith('http://') || trimmed.startsWith('https://')
        ? trimmed
        : `https://${trimmed}`;
    const parsed = new URL(withProtocol);
    const host = parsed.hostname.toLowerCase().replace(/^www\./, '');
    if (!host || !host.includes('.')) return null;
    return host;
  } catch {
    return null;
  }
}

/**
 * Zero-Knowledge Privacy & Mainland China Network Guard:
 * External favicon fetching (e.g., https://www.google.com/s2/favicons) is strictly disabled
 * so unlocking or browsing the vault never leaks record domains to third-party servers
 * and never hangs or times out in restricted network environments.
 */
export function getWebsiteFaviconUrl(
  _rawUrl: string,
  _size: number = 128
): null {
  return null;
}

const DETERMINISTIC_PALETTES: Array<{ bgClass: string; textClass: string }> = [
  {
    bgClass: 'bg-blue-500/12 dark:bg-blue-500/18 border-blue-500/30',
    textClass: 'text-blue-600 dark:text-blue-400',
  },
  {
    bgClass: 'bg-emerald-500/12 dark:bg-emerald-500/18 border-emerald-500/30',
    textClass: 'text-emerald-600 dark:text-emerald-400',
  },
  {
    bgClass: 'bg-indigo-500/12 dark:bg-indigo-500/18 border-indigo-500/30',
    textClass: 'text-indigo-600 dark:text-indigo-400',
  },
  {
    bgClass: 'bg-amber-500/12 dark:bg-amber-500/18 border-amber-500/30',
    textClass: 'text-amber-600 dark:text-amber-400',
  },
  {
    bgClass: 'bg-purple-500/12 dark:bg-purple-500/18 border-purple-500/30',
    textClass: 'text-purple-600 dark:text-purple-400',
  },
  {
    bgClass: 'bg-cyan-500/12 dark:bg-cyan-500/18 border-cyan-500/30',
    textClass: 'text-cyan-600 dark:text-cyan-400',
  },
  {
    bgClass: 'bg-rose-500/12 dark:bg-rose-500/18 border-rose-500/30',
    textClass: 'text-rose-600 dark:text-rose-400',
  },
  {
    bgClass: 'bg-teal-500/12 dark:bg-teal-500/18 border-teal-500/30',
    textClass: 'text-teal-600 dark:text-teal-400',
  },
];

function computeDeterministicPaletteIndex(seed: string): number {
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash) % DETERMINISTIC_PALETTES.length;
}

function buildDomainMonogram(title: string, domain: string): string {
  const cleanTitle = title.trim();
  if (cleanTitle) {
    // Check if first char is CJK
    const firstChar = cleanTitle.slice(0, 1);
    if (/[\u4e00-\u9fa5]/.test(firstChar)) {
      return firstChar;
    }
    const words = cleanTitle
      .replace(/[^a-zA-Z0-9\s]/g, ' ')
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (words.length >= 2) {
      return `${words[0][0]}${words[1][0]}`.toUpperCase();
    }
    if (words.length === 1 && words[0].length >= 2) {
      return words[0].slice(0, 2).toUpperCase();
    }
    return firstChar.toUpperCase();
  }
  if (domain) {
    const rootSegment = domain
      .replace(/^(account|accounts|login|auth|id|my|sso|mail|console)\./i, '')
      .split('.')[0];
    if (rootSegment && rootSegment.length >= 2) {
      return rootSegment.slice(0, 2).toUpperCase();
    }
    if (rootSegment) {
      return rootSegment.slice(0, 1).toUpperCase();
    }
  }
  return '?';
}

/**
 * Provides a purely local, deterministic brand avatar style (with optional built-in SVG icon ID)
 * based on domain or title. Never triggers any external HTTP requests.
 */
export function getBrandAvatarStyle(
  title: string,
  rawUrl: string
): BrandAvatarStyle {
  const domain = extractDomainFromUrl(rawUrl) ?? '';
  const key = `${domain} ${title}`.toLowerCase();

  if (key.includes('cloudflare')) {
    return {
      bgClass: 'bg-orange-500/15 dark:bg-orange-500/20 border-orange-500/30',
      textClass: 'text-orange-600 dark:text-orange-400',
      monogram: 'CF',
      iconId: 'cloudflare',
      brandLabel: 'Cloudflare',
    };
  }
  if (key.includes('github')) {
    return {
      bgClass:
        'bg-slate-200/80 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
      textClass: 'text-slate-900 dark:text-slate-100',
      monogram: 'GH',
      iconId: 'github',
      brandLabel: 'GitHub',
    };
  }
  if (key.includes('gitlab')) {
    return {
      bgClass: 'bg-orange-500/15 dark:bg-orange-500/20 border-orange-500/30',
      textClass: 'text-orange-600 dark:text-orange-400',
      monogram: 'GL',
      iconId: 'gitlab',
      brandLabel: 'GitLab',
    };
  }
  if (key.includes('google') || key.includes('gmail')) {
    return {
      bgClass: 'bg-blue-500/12 dark:bg-blue-500/20 border-blue-500/30',
      textClass: 'text-blue-600 dark:text-blue-400',
      monogram: 'G',
      iconId: 'google',
      brandLabel: 'Google',
    };
  }
  if (key.includes('apple') || key.includes('icloud')) {
    return {
      bgClass:
        'bg-slate-200/80 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
      textClass: 'text-slate-900 dark:text-slate-100',
      monogram: '',
      iconId: 'apple',
      brandLabel: 'Apple',
    };
  }
  if (
    key.includes('microsoft') ||
    key.includes('outlook') ||
    key.includes('azure') ||
    key.includes('live.com')
  ) {
    return {
      bgClass: 'bg-sky-500/15 dark:bg-sky-500/20 border-sky-500/30',
      textClass: 'text-sky-600 dark:text-sky-400',
      monogram: 'MS',
      iconId: 'microsoft',
      brandLabel: 'Microsoft',
    };
  }
  if (key.includes('amazon') || key.includes('aws')) {
    return {
      bgClass: 'bg-amber-500/15 dark:bg-amber-500/20 border-amber-500/30',
      textClass: 'text-amber-600 dark:text-amber-400',
      monogram: 'AWS',
      iconId: 'aws',
      brandLabel: 'AWS',
    };
  }
  if (key.includes('twitter') || key.includes('x.com')) {
    return {
      bgClass:
        'bg-slate-200/80 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
      textClass: 'text-slate-900 dark:text-slate-100',
      monogram: 'X',
      iconId: 'x',
      brandLabel: 'X',
    };
  }
  if (key.includes('telegram') || key.includes('t.me')) {
    return {
      bgClass: 'bg-sky-500/15 dark:bg-sky-500/20 border-sky-500/30',
      textClass: 'text-sky-600 dark:text-sky-400',
      monogram: 'TG',
      iconId: 'telegram',
      brandLabel: 'Telegram',
    };
  }
  if (key.includes('interactivebrokers') || key.includes('盈透')) {
    return {
      bgClass: 'bg-red-500/15 dark:bg-red-500/20 border-red-500/30',
      textClass: 'text-red-600 dark:text-red-400',
      monogram: 'IB',
      iconId: 'ibkr',
      brandLabel: 'Interactive Brokers',
    };
  }
  if (key.includes('binance') || key.includes('币安')) {
    return {
      bgClass: 'bg-yellow-500/15 dark:bg-yellow-500/20 border-yellow-500/30',
      textClass: 'text-yellow-600 dark:text-yellow-400',
      monogram: 'BN',
      iconId: 'binance',
      brandLabel: 'Binance',
    };
  }
  if (key.includes('discord')) {
    return {
      bgClass: 'bg-indigo-500/15 dark:bg-indigo-500/20 border-indigo-500/30',
      textClass: 'text-indigo-600 dark:text-indigo-400',
      monogram: 'DC',
      iconId: 'discord',
      brandLabel: 'Discord',
    };
  }
  if (key.includes('slack')) {
    return {
      bgClass: 'bg-purple-500/15 dark:bg-purple-500/20 border-purple-500/30',
      textClass: 'text-purple-600 dark:text-purple-400',
      monogram: 'SL',
      iconId: 'slack',
      brandLabel: 'Slack',
    };
  }
  if (key.includes('steam') || key.includes('steampowered')) {
    return {
      bgClass: 'bg-blue-600/15 dark:bg-blue-500/20 border-blue-500/30',
      textClass: 'text-blue-700 dark:text-blue-300',
      monogram: 'ST',
      iconId: 'steam',
      brandLabel: 'Steam',
    };
  }
  if (key.includes('paypal')) {
    return {
      bgClass: 'bg-blue-500/15 dark:bg-blue-500/20 border-blue-500/30',
      textClass: 'text-blue-600 dark:text-blue-400',
      monogram: 'PP',
      iconId: 'paypal',
      brandLabel: 'PayPal',
    };
  }
  if (key.includes('stripe')) {
    return {
      bgClass: 'bg-indigo-500/15 dark:bg-indigo-500/20 border-indigo-500/30',
      textClass: 'text-indigo-600 dark:text-indigo-400',
      monogram: 'ST',
      iconId: 'stripe',
      brandLabel: 'Stripe',
    };
  }
  if (key.includes('vercel')) {
    return {
      bgClass:
        'bg-slate-200/80 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
      textClass: 'text-slate-900 dark:text-slate-100',
      monogram: '▲',
      iconId: 'vercel',
      brandLabel: 'Vercel',
    };
  }
  if (key.includes('openai') || key.includes('chatgpt')) {
    return {
      bgClass: 'bg-emerald-500/15 dark:bg-emerald-500/20 border-emerald-500/30',
      textClass: 'text-emerald-600 dark:text-emerald-400',
      monogram: 'AI',
      iconId: 'openai',
      brandLabel: 'OpenAI',
    };
  }
  if (key.includes('notion')) {
    return {
      bgClass:
        'bg-slate-200/80 dark:bg-slate-800 border-slate-300 dark:border-slate-700',
      textClass: 'text-slate-900 dark:text-slate-100',
      monogram: 'N',
      iconId: 'notion',
      brandLabel: 'Notion',
    };
  }
  if (key.includes('alipay') || key.includes('支付宝')) {
    return {
      bgClass: 'bg-sky-500/15 dark:bg-sky-500/20 border-sky-500/30',
      textClass: 'text-sky-600 dark:text-sky-400',
      monogram: '支',
      iconId: 'alipay',
      brandLabel: '支付宝',
    };
  }
  if (
    key.includes('wechat') ||
    key.includes('weixin') ||
    key.includes('微信')
  ) {
    return {
      bgClass: 'bg-emerald-500/15 dark:bg-emerald-500/20 border-emerald-500/30',
      textClass: 'text-emerald-600 dark:text-emerald-400',
      monogram: '微',
      iconId: 'wechat',
      brandLabel: '微信',
    };
  }
  if (
    key.includes('taobao') ||
    key.includes('tmall') ||
    key.includes('淘宝') ||
    key.includes('天猫')
  ) {
    return {
      bgClass: 'bg-orange-500/15 dark:bg-orange-500/20 border-orange-500/30',
      textClass: 'text-orange-600 dark:text-orange-400',
      monogram: '淘',
      iconId: 'taobao',
      brandLabel: '淘宝',
    };
  }
  if (key.includes('jd.com') || key.includes('京东')) {
    return {
      bgClass: 'bg-red-500/15 dark:bg-red-500/20 border-red-500/30',
      textClass: 'text-red-600 dark:text-red-400',
      monogram: 'JD',
      iconId: 'jd',
      brandLabel: '京东',
    };
  }
  if (key.includes('bilibili') || key.includes('哔哩')) {
    return {
      bgClass: 'bg-pink-500/15 dark:bg-pink-500/20 border-pink-500/30',
      textClass: 'text-pink-600 dark:text-pink-400',
      monogram: 'B',
      iconId: 'bilibili',
      brandLabel: 'Bilibili',
    };
  }
  if (
    key.includes('163.com') ||
    key.includes('126.com') ||
    key.includes('netease') ||
    key.includes('网易')
  ) {
    return {
      bgClass: 'bg-red-500/15 dark:bg-red-500/20 border-red-500/30',
      textClass: 'text-red-600 dark:text-red-400',
      monogram: '易',
      iconId: 'netease',
      brandLabel: '网易',
    };
  }
  if (key.includes('qq.com') || key.includes('tencent') || key.includes('腾讯')) {
    return {
      bgClass: 'bg-blue-500/15 dark:bg-blue-500/20 border-blue-500/30',
      textClass: 'text-blue-600 dark:text-blue-400',
      monogram: 'QQ',
      iconId: 'qq',
      brandLabel: 'QQ',
    };
  }
  if (key.includes('baidu') || key.includes('百度')) {
    return {
      bgClass: 'bg-blue-600/15 dark:bg-blue-500/20 border-blue-500/30',
      textClass: 'text-blue-600 dark:text-blue-400',
      monogram: '度',
      iconId: 'baidu',
      brandLabel: '百度',
    };
  }

  const palette =
    DETERMINISTIC_PALETTES[
      computeDeterministicPaletteIndex(domain || title || 'aegis')
    ];
  return {
    bgClass: palette.bgClass,
    textClass: palette.textClass,
    monogram: buildDomainMonogram(title, domain),
  };
}

/**
 * Resolves a realistic Bank Card visual theme (gradient, bank title, issuerCode, tier, chip color, network)
 * from the record's title, URL, and card number.
 */
export function resolveBankCardTheme(
  title: string,
  cardNumber: string,
  explicitBrand?: string,
  url: string = ''
): BankCardVisualTheme {
  const network =
    explicitBrand && explicitBrand !== '银行卡'
      ? explicitBrand
      : detectCardBrand(cardNumber);
  const combined = `${title} ${url}`.toLowerCase();

  let bankName = '私人银行卡';
  let cardTier = 'PLATINUM DEBIT / CREDIT';

  if (combined.includes('招商') || combined.includes('cmb')) {
    bankName = '招商银行 · CMB';
    cardTier = combined.includes('白金') ? 'INFINITE PLATINUM' : 'GLOBAL CARD';
    return {
      bankName,
      issuerCode: 'CMB',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-rose-900 via-slate-900 to-slate-950 border-rose-500/30',
      accentColorClass: 'text-rose-200',
      chipStyle: 'gold',
      badgeBgClass: 'bg-gradient-to-br from-rose-700 to-slate-900',
    };
  }

  if (
    combined.includes('工商') ||
    combined.includes('icbc') ||
    combined.includes('中国银行') ||
    combined.includes('boc')
  ) {
    const isIcbc = combined.includes('工商') || combined.includes('icbc');
    bankName = isIcbc ? '中国工商银行 · ICBC' : '中国银行 · BOC';
    cardTier = 'PREMIER WEALTH';
    return {
      bankName,
      issuerCode: isIcbc ? 'ICBC' : 'BOC',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-red-900 via-rose-950 to-slate-950 border-red-500/30',
      accentColorClass: 'text-red-200',
      chipStyle: 'gold',
      badgeBgClass: 'bg-gradient-to-br from-red-700 to-rose-950',
    };
  }

  if (
    combined.includes('建设') ||
    combined.includes('ccb') ||
    combined.includes('交通') ||
    combined.includes('浦发')
  ) {
    const isCcb = combined.includes('建设') || combined.includes('ccb');
    bankName = isCcb ? '中国建设银行 · CCB' : '交通银行 · BOCOM';
    cardTier = 'SIGNATURE WORLD';
    return {
      bankName,
      issuerCode: isCcb ? 'CCB' : 'BOCOM',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-blue-900 via-indigo-950 to-slate-950 border-blue-500/30',
      accentColorClass: 'text-blue-200',
      chipStyle: 'silver',
      badgeBgClass: 'bg-gradient-to-br from-blue-700 to-indigo-950',
    };
  }

  if (
    combined.includes('农业') ||
    combined.includes('abc') ||
    combined.includes('邮储')
  ) {
    bankName = '中国农业银行 · ABC';
    cardTier = 'EMERALD PRIVATE';
    return {
      bankName,
      issuerCode: 'ABC',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-emerald-900 via-teal-950 to-slate-950 border-emerald-500/30',
      accentColorClass: 'text-emerald-200',
      chipStyle: 'gold',
      badgeBgClass: 'bg-gradient-to-br from-emerald-700 to-teal-950',
    };
  }

  if (network.includes('UnionPay') || combined.includes('银联')) {
    bankName = title.trim() || '中国银联 · UnionPay';
    cardTier = 'DIAMOND PRESTIGE';
    return {
      bankName,
      issuerCode: 'UP',
      cardTier,
      network: 'UnionPay 银联',
      gradientClass:
        'bg-gradient-to-br from-cyan-950 via-slate-900 to-slate-950 border-cyan-500/30',
      accentColorClass: 'text-cyan-200',
      chipStyle: 'gold',
      badgeBgClass: 'bg-gradient-to-br from-cyan-800 to-slate-900',
    };
  }

  if (network === 'Mastercard') {
    bankName = title.trim() || 'Mastercard World';
    cardTier = 'WORLD ELITE';
    return {
      bankName,
      issuerCode: 'MC',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-stone-800 via-neutral-900 to-slate-950 border-amber-500/30',
      accentColorClass: 'text-amber-200',
      chipStyle: 'gold',
      badgeBgClass: 'bg-gradient-to-br from-amber-700 to-stone-900',
    };
  }

  if (network === 'American Express') {
    bankName = title.trim() || 'American Express';
    cardTier = 'CENTURION PLATINUM';
    return {
      bankName,
      issuerCode: 'AMEX',
      cardTier,
      network,
      gradientClass:
        'bg-gradient-to-br from-slate-700 via-slate-800 to-zinc-950 border-slate-400/30',
      accentColorClass: 'text-slate-200',
      chipStyle: 'silver',
      badgeBgClass: 'bg-gradient-to-br from-slate-600 to-zinc-900',
    };
  }

  return {
    bankName: title.trim() || 'Visa International',
    issuerCode: 'VISA',
    cardTier: 'SIGNATURE PLATINUM',
    network,
    gradientClass:
      'bg-gradient-to-br from-blue-900 via-slate-900 to-slate-950 border-blue-500/30',
    accentColorClass: 'text-blue-200',
    chipStyle: 'gold',
    badgeBgClass: 'bg-gradient-to-br from-blue-700 to-slate-900',
  };
}
