import { DecryptedVaultRecord, PaymentCardDetails } from '../types/vault';

/**
 * Strips all non-digit characters and limits length to 19 digits (ISO/IEC 7812 max length).
 */
export function sanitizeCardNumber(raw: string): string {
  return raw.replace(/\D/g, '').slice(0, 19);
}

/**
 * Formats a card number string into 4-digit groups separated by spaces for human readability.
 */
export function formatCardNumberGroups(raw: string): string {
  const digits = sanitizeCardNumber(raw);
  if (!digits) return '';
  return digits.replace(/(\d{4})(?=\d)/g, '$1 ');
}

/**
 * Masks all digits of a card number except the last 4 digits, grouped in 4s.
 * Example: "4392258801927465" -> "•••• •••• •••• 7465"
 */
export function maskCardNumber(raw: string): string {
  const digits = sanitizeCardNumber(raw);
  if (!digits) return '•••• •••• •••• ••••';
  if (digits.length <= 4) return digits;
  const last4 = digits.slice(-4);
  const maskedLength = digits.length - 4;
  const maskedChars = '•'.repeat(maskedLength);
  const combined = maskedChars + last4;
  return combined.replace(/(.{4})(?=.+)/g, '$1 ');
}

/**
 * Masks a 3- or 4-digit CVV/CVC security code.
 */
export function maskCvvCode(cvv: string): string {
  const clean = cvv.replace(/\D/g, '');
  const len = Math.max(3, Math.min(4, clean.length || 3));
  return '•'.repeat(len);
}

/**
 * Formats user input into MM/YY expiry date format.
 */
export function formatExpiryDateInput(raw: string): string {
  const digits = raw.replace(/\D/g, '').slice(0, 4);
  if (digits.length === 0) return '';
  if (digits.length === 1) {
    // If user types 2-9 as first digit, auto-prefix 0 (e.g. "8" -> "08")
    if (Number(digits[0]) > 1) {
      return `0${digits[0]}/`;
    }
    return digits;
  }
  const monthNum = Number(digits.slice(0, 2));
  let mm = digits.slice(0, 2);
  if (monthNum === 0) {
    mm = '01';
  } else if (monthNum > 12) {
    mm = '12';
  }
  if (digits.length === 2) {
    return raw.endsWith('/') ? `${mm}/` : mm;
  }
  return `${mm}/${digits.slice(2, 4)}`;
}

/**
 * Sanitizes CVV input to 3-4 digits only.
 */
export function sanitizeCvvInput(raw: string): string {
  return raw.replace(/\D/g, '').slice(0, 4);
}

/**
 * Detects card network brand from IIN/BIN prefix.
 */
export function detectCardBrand(cardNumber: string): string {
  const digits = sanitizeCardNumber(cardNumber);
  if (!digits) return '支付卡';
  if (/^62/.test(digits)) return 'UnionPay 银联';
  if (/^4/.test(digits)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(digits)) return 'Mastercard';
  if (/^3[47]/.test(digits)) return 'American Express';
  if (/^35(2[89]|[3-8][0-9])/.test(digits)) return 'JCB';
  if (/^(6011|65|64[4-9])/.test(digits)) return 'Discover';
  return '银行卡';
}

/**
 * Determines whether a vault record should render as a realistic credit/bank card.
 * Triggers when the record category is 'bank-card' (or '银行卡'), when recordType === 'card',
 * when cardDetails is present, or when tagged with 'bank-card'/'银行卡'.
 */
export function isBankCardRecord(
  record: Pick<DecryptedVaultRecord, 'category' | 'recordType' | 'cardDetails' | 'tags'> | null | undefined
): boolean {
  if (!record) return false;
  const cat = (record.category ?? '').toLowerCase();
  if (cat === 'bank-card' || cat === '银行卡') return true;
  if (record.recordType === 'card') return true;
  if (record.cardDetails && Boolean(record.cardDetails.cardNumber)) return true;
  if (
    Array.isArray(record.tags) &&
    record.tags.some(
      (t) => t.toLowerCase() === 'bank-card' || t.trim() === '银行卡'
    )
  ) {
    return true;
  }
  return false;
}

/**
 * Resolves normalized PaymentCardDetails for any bank-card record, even if the record
 * was created via generic fields with category: 'bank-card'.
 */
export function resolveRecordCardDetails(
  record: DecryptedVaultRecord
): PaymentCardDetails {
  if (record.cardDetails && record.cardDetails.cardNumber) {
    return {
      cardholderName:
        record.cardDetails.cardholderName || record.username || 'CARDHOLDER',
      cardNumber: record.cardDetails.cardNumber,
      expiryDate: record.cardDetails.expiryDate || '08/29',
      cvv: record.cardDetails.cvv || '888',
      brand:
        record.cardDetails.brand ||
        detectCardBrand(record.cardDetails.cardNumber),
    };
  }
  const candidateDigits = sanitizeCardNumber(record.password || '');
  const fallbackNumber =
    candidateDigits.length >= 12 ? candidateDigits : '4392258801927465';
  return {
    cardholderName: record.username || 'CARDHOLDER',
    cardNumber: fallbackNumber,
    expiryDate: '08/29',
    cvv: '888',
    brand: detectCardBrand(fallbackNumber),
  };
}

/**
 * Validates payment card fields (cardholder name, 13-19 digit card number, MM/YY expiry, 3-4 digit CVV).
 */
export function validatePaymentCardFields(
  details: PaymentCardDetails
): { valid: boolean; error?: string } {
  if (!details.cardholderName || !details.cardholderName.trim()) {
    return { valid: false, error: '请填写持卡人姓名（例如：LINUS CHEN 或 张三）。' };
  }

  const digits = sanitizeCardNumber(details.cardNumber);
  if (digits.length < 13 || digits.length > 19) {
    return {
      valid: false,
      error: '银行卡号长度应为 13 至 19 位数字，请检查卡号输入。',
    };
  }

  if (!/^(0[1-9]|1[0-2])\/\d{2}$/.test(details.expiryDate.trim())) {
    return {
      valid: false,
      error: '过期日期格式需为 MM/YY（例如：08/29），且月份在 01 至 12 之间。',
    };
  }

  const cleanCvv = details.cvv.trim();
  if (!/^\d{3,4}$/.test(cleanCvv)) {
    return {
      valid: false,
      error: 'CVV / CVC 安全码需为 3 位或 4 位数字。',
    };
  }

  return { valid: true };
}
