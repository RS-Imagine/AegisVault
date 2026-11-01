export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const CHAR_SETS = {
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijkmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
};

const EXACT_SETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}<>?',
};

function getRandomInt(max: number): number {
  const cryptoObj =
    typeof window !== 'undefined' && window.crypto
      ? window.crypto
      : globalThis.crypto;
  const array = new Uint32Array(1);
  cryptoObj.getRandomValues(array);
  return array[0] % max;
}

export function generateStrongPassword(
  options: PasswordGeneratorOptions
): string {
  const clampedLength = Math.max(6, Math.min(64, Math.floor(options.length)));

  const activePools: string[] = [];
  if (options.uppercase) activePools.push(EXACT_SETS.uppercase);
  if (options.lowercase) activePools.push(EXACT_SETS.lowercase);
  if (options.numbers) activePools.push(EXACT_SETS.numbers);
  if (options.symbols) activePools.push(EXACT_SETS.symbols);

  // Fallback to lowercase + numbers if user unchecked all boxes
  if (activePools.length === 0) {
    activePools.push(EXACT_SETS.lowercase, EXACT_SETS.numbers);
  }

  const combinedPool = activePools.join('');
  const passwordChars: string[] = [];

  // Ensure at least one character from each selected character type
  for (const pool of activePools) {
    if (passwordChars.length < clampedLength) {
      passwordChars.push(pool[getRandomInt(pool.length)]);
    }
  }

  // Fill remaining length
  while (passwordChars.length < clampedLength) {
    passwordChars.push(combinedPool[getRandomInt(combinedPool.length)]);
  }

  // Cryptographic Fisher-Yates shuffle
  for (let i = passwordChars.length - 1; i > 0; i--) {
    const j = getRandomInt(i + 1);
    const temp = passwordChars[i];
    passwordChars[i] = passwordChars[j];
    passwordChars[j] = temp;
  }

  return passwordChars.join('');
}

export interface PasswordStrengthInfo {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  entropyBits: number;
  colorClass: string;
  barColorClass: string;
}

export function evaluatePasswordStrength(password: string): PasswordStrengthInfo {
  if (!password) {
    return {
      score: 0,
      label: '未输入',
      entropyBits: 0,
      colorClass: 'text-slate-400',
      barColorClass: 'bg-slate-300 dark:bg-slate-700',
    };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  const entropyBits = Math.round(
    password.length * Math.log2(Math.max(poolSize, 2))
  );

  if (entropyBits < 40 || password.length < 8) {
    return {
      score: 1,
      label: '较弱',
      entropyBits,
      colorClass: 'text-red-600 dark:text-red-400',
      barColorClass: 'bg-red-500',
    };
  }
  if (entropyBits < 65) {
    return {
      score: 2,
      label: '中等',
      entropyBits,
      colorClass: 'text-amber-600 dark:text-amber-400',
      barColorClass: 'bg-amber-500',
    };
  }
  if (entropyBits < 90) {
    return {
      score: 3,
      label: '强壮',
      entropyBits,
      colorClass: 'text-emerald-600 dark:text-emerald-400',
      barColorClass: 'bg-emerald-500',
    };
  }
  return {
    score: 4,
    label: '极高强度',
    entropyBits,
    colorClass: 'text-blue-600 dark:text-blue-400',
    barColorClass: 'bg-blue-600',
  };
}

export const CHAR_POOL_REFERENCE = CHAR_SETS;
