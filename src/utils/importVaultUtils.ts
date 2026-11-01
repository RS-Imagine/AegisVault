import {
  DecryptedVaultRecord,
  EncryptedVaultPayload,
  VaultCategory,
  VaultCategoryItem,
} from '../types/vault';
import {
  unlockEncryptedVaultPayload,
  validateV2VaultEnvelopeStructure,
} from '../crypto/cryptoEngine';
import { detectCardBrand, sanitizeCardNumber } from './paymentCardUtils';

export type MergeDuplicateStrategy = 'skip-duplicates' | 'import-all';

export interface CandidateRecordInput {
  title: string;
  username: string;
  password: string;
  url: string;
  category: VaultCategory;
  tags?: string[];
  notes: string;
  favorite: boolean;
  recordType?: 'login' | 'card';
  cardDetails?: {
    cardholderName: string;
    cardNumber: string;
    expiryDate: string;
    cvv: string;
    brand?: string;
  };
}

export interface ImportDetectionResult {
  format:
    | 'aegis-encrypted-json'
    | 'browser-csv'
    | 'generic-json'
    | 'unrecognized';
  status: 'ready' | 'needs-password' | 'error';
  message: string;
  parsedRecords: CandidateRecordInput[];
  decryptedCategories?: VaultCategoryItem[];
  encryptedRecordCount?: number;
}

export const SAMPLE_BROWSER_CSV_EXPORT = `name,url,username,password,note
"GitHub Developer","https://github.com","dev-sample@aegis-vault.invalid","SampleOnly#Gh91!xK4$pL2","示例导入记录：代码托管平台"
"Cloudflare DNS","https://dash.cloudflare.com","ops-sample@aegis-vault.invalid","SampleOnly#Cf84@mQ7!zR3","示例导入记录：边缘安全节点"
"AWS Root Console","https://console.aws.amazon.com","aws-sample@aegis-vault.invalid","SampleOnly#Aw73$vN9#kL5","示例导入记录：云基础设施"`;

/**
 * RFC 4180 compliant CSV parser supporting quoted fields, embedded commas, and newlines.
 */
export function parseCSVRows(csvText: string): string[][] {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < csvText.length; i++) {
    const ch = csvText[i];
    const next = csvText[i + 1];

    if (inQuotes) {
      if (ch === '"' && next === '"') {
        currentField += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        currentField += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        currentRow.push(currentField.trim());
        currentField = '';
      } else if (ch === '\r' && next === '\n') {
        currentRow.push(currentField.trim());
        if (currentRow.some((cell) => cell.length > 0)) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
        i++;
      } else if (ch === '\n' || ch === '\r') {
        currentRow.push(currentField.trim());
        if (currentRow.some((cell) => cell.length > 0)) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentField = '';
      } else {
        currentField += ch;
      }
    }
  }

  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField.trim());
    if (currentRow.some((cell) => cell.length > 0)) {
      rows.push(currentRow);
    }
  }

  return rows;
}

function inferCategoryFromRecord(
  title: string,
  url: string,
  explicitCategory?: string
): VaultCategory {
  if (explicitCategory && explicitCategory.trim()) {
    return explicitCategory.trim();
  }
  const combined = `${title} ${url}`.toLowerCase();
  if (
    combined.includes('bank') ||
    combined.includes('visa') ||
    combined.includes('mastercard') ||
    combined.includes('银行')
  ) {
    return 'bank-card';
  }
  if (
    combined.includes('ibkr') ||
    combined.includes('stripe') ||
    combined.includes('paypal') ||
    combined.includes('证券') ||
    combined.includes('理财')
  ) {
    return 'finance';
  }
  if (
    combined.includes('github') ||
    combined.includes('cloudflare') ||
    combined.includes('aws') ||
    combined.includes('gitlab') ||
    combined.includes('jira')
  ) {
    return 'work';
  }
  if (
    combined.includes('twitter') ||
    combined.includes('x.com') ||
    combined.includes('telegram') ||
    combined.includes('discord') ||
    combined.includes('reddit')
  ) {
    return 'social';
  }
  return 'personal';
}

/**
 * Detects and parses imported content (AegisVault V2 Encrypted JSON, generic JSON, or Browser CSV).
 * Rejects V1 encrypted payloads (`version: 1`).
 */
export async function detectAndParseImportContent(
  rawContent: string,
  currentMemoryKey: CryptoKey | null,
  backupPassword?: string
): Promise<ImportDetectionResult> {
  const trimmed = rawContent.trim();
  if (!trimmed) {
    return {
      format: 'unrecognized',
      status: 'error',
      message: '导入内容为空，请选择文件或粘贴有效的备份内容。',
      parsedRecords: [],
    };
  }

  // Check if JSON
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);

      // 1. Check if it is an AegisVault Encrypted JSON Envelope
      if (
        parsed &&
        typeof parsed === 'object' &&
        !Array.isArray(parsed) &&
        ('formatVersion' in parsed || 'version' in parsed || 'kdf' in parsed)
      ) {
        const validation = validateV2VaultEnvelopeStructure(parsed);
        if (!validation.valid || !validation.payload) {
          return {
            format: 'aegis-encrypted-json',
            status: 'error',
            message: validation.reason || '加密备份 JSON 结构不合法',
            parsedRecords: [],
          };
        }

        const v2Payload: EncryptedVaultPayload = validation.payload;

        // If user provided a backup password, unlock with that password first
        if (backupPassword && backupPassword.trim()) {
          try {
            const unlocked = await unlockEncryptedVaultPayload(
              v2Payload,
              backupPassword
            );
            return {
              format: 'aegis-encrypted-json',
              status: 'ready',
              message: `已使用备份主密码成功认证解密 ${unlocked.records.length} 条 V2 记录`,
              parsedRecords: unlocked.records.map((r) => ({
                title: r.title,
                username: r.username,
                password: r.password,
                url: r.url,
                category: r.category,
                tags: r.tags,
                notes: r.notes,
                favorite: r.favorite,
                recordType: r.recordType === 'card' ? 'card' : 'login',
                cardDetails: r.cardDetails,
              })),
              decryptedCategories: unlocked.categories,
              encryptedRecordCount: v2Payload.encryptedRecords.length,
            };
          } catch {
            return {
              format: 'aegis-encrypted-json',
              status: 'needs-password',
              message: '备份主密码错误，无法通过 AES-256-GCM 认证解密，请核对后重试。',
              parsedRecords: [],
              encryptedRecordCount: v2Payload.encryptedRecords.length,
            };
          }
        }

        // Try current in-memory CryptoKey if available
        if (currentMemoryKey) {
          try {
            const unlocked = await unlockEncryptedVaultPayload(
              v2Payload,
              currentMemoryKey
            );
            return {
              format: 'aegis-encrypted-json',
              status: 'ready',
              message: `已使用当前密码库主密钥自动认证解密 ${unlocked.records.length} 条 V2 记录`,
              parsedRecords: unlocked.records.map((r) => ({
                title: r.title,
                username: r.username,
                password: r.password,
                url: r.url,
                category: r.category,
                tags: r.tags,
                notes: r.notes,
                favorite: r.favorite,
                recordType: r.recordType === 'card' ? 'card' : 'login',
                cardDetails: r.cardDetails,
              })),
              decryptedCategories: unlocked.categories,
              encryptedRecordCount: v2Payload.encryptedRecords.length,
            };
          } catch {
            return {
              format: 'aegis-encrypted-json',
              status: 'needs-password',
              message:
                '该 V2 加密备份使用了不同的主密码或随机盐值派生密钥，请输入创建该备份时的主密码以解密。',
              parsedRecords: [],
              encryptedRecordCount: v2Payload.encryptedRecords.length,
            };
          }
        }

        return {
          format: 'aegis-encrypted-json',
          status: 'needs-password',
          message: '请输入创建该 V2 加密备份时的主密码以完成认证解密。',
          parsedRecords: [],
          encryptedRecordCount: v2Payload.encryptedRecords.length,
        };
      }

      // 2. Generic JSON array or { items / records }
      const rawArray: unknown[] = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed?.items)
        ? parsed.items
        : Array.isArray(parsed?.records)
        ? parsed.records
        : [];

      const candidates: CandidateRecordInput[] = [];
      for (const item of rawArray) {
        if (!item || typeof item !== 'object') continue;
        const obj = item as Record<string, unknown>;
        const title = String(obj.title || obj.name || obj.url || '导入记录').trim();
        const username = String(
          obj.username || obj.user || obj.email || ''
        ).trim();
        const password = String(obj.password || obj.secret || '');
        const url = String(obj.url || obj.uri || '').trim();
        const notes = String(obj.notes || obj.note || '');
        const category = inferCategoryFromRecord(
          title,
          url,
          typeof obj.category === 'string' ? obj.category : undefined
        );

        const rawCard =
          obj.cardDetails && typeof obj.cardDetails === 'object'
            ? (obj.cardDetails as Record<string, unknown>)
            : null;
        if (rawCard && typeof rawCard.cardNumber === 'string') {
          const cleanDigits = sanitizeCardNumber(rawCard.cardNumber);
          candidates.push({
            title,
            username: String(rawCard.cardholderName || username || 'CARDHOLDER'),
            password: cleanDigits.slice(-4) || password,
            url,
            category: 'bank-card',
            recordType: 'card',
            cardDetails: {
              cardholderName: String(
                rawCard.cardholderName || username || 'CARDHOLDER'
              ),
              cardNumber: cleanDigits,
              expiryDate: String(rawCard.expiryDate || '08/29'),
              cvv: String(rawCard.cvv || '000'),
              brand: String(rawCard.brand || detectCardBrand(cleanDigits)),
            },
            notes,
            favorite: Boolean(obj.favorite),
          });
        } else if (title || username || password || url) {
          candidates.push({
            title,
            username,
            password,
            url,
            category,
            recordType: 'login',
            notes,
            favorite: Boolean(obj.favorite),
          });
        }
      }

      if (candidates.length === 0) {
        return {
          format: 'generic-json',
          status: 'error',
          message: 'JSON 文件中未找到可识别的账号或卡片记录。',
          parsedRecords: [],
        };
      }

      return {
        format: 'generic-json',
        status: 'ready',
        message: `已从 JSON 文件解析出 ${candidates.length} 条记录`,
        parsedRecords: candidates,
      };
    } catch {
      return {
        format: 'unrecognized',
        status: 'error',
        message: 'JSON 语法解析失败，请检查文件内容是否完整。',
        parsedRecords: [],
      };
    }
  }

  // 3. Parse as Browser CSV
  const rows = parseCSVRows(trimmed);
  if (rows.length < 2) {
    return {
      format: 'unrecognized',
      status: 'error',
      message: '未识别的导入格式：CSV 至少需要包含表头行和一行记录。',
      parsedRecords: [],
    };
  }

  const headers = rows[0].map((h) => h.toLowerCase().trim());
  const findCol = (names: string[]) =>
    headers.findIndex((h) => names.some((n) => h === n || h.includes(n)));

  const nameIdx = findCol(['name', 'title', 'service']);
  const urlIdx = findCol(['url', 'website', 'origin', 'login_uri']);
  const userIdx = findCol(['username', 'user', 'email', 'login_username']);
  const passIdx = findCol(['password', 'secret', 'login_password']);
  const noteIdx = findCol(['note', 'notes', 'comment', 'extra']);
  const catIdx = findCol(['category', 'folder', 'group']);

  if (nameIdx === -1 && urlIdx === -1 && userIdx === -1 && passIdx === -1) {
    return {
      format: 'unrecognized',
      status: 'error',
      message:
        'CSV 表头缺少必要列（需包含 name/title、url、username、password 中的至少一项）。',
      parsedRecords: [],
    };
  }

  const parsedRecords: CandidateRecordInput[] = [];
  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    const getCell = (idx: number) => (idx >= 0 && idx < r.length ? r[idx].trim() : '');

    const rawUrl = getCell(urlIdx);
    const username = getCell(userIdx);
    const password = getCell(passIdx);
    const notes = getCell(noteIdx);
    const explicitCat = getCell(catIdx);
    let title = getCell(nameIdx);

    if (!title && rawUrl) {
      try {
        title = new URL(
          rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`
        ).hostname.replace(/^www\./, '');
      } catch {
        title = rawUrl;
      }
    }

    if (!title && !username && !password && !rawUrl) continue;

    parsedRecords.push({
      title: title || username || `导入账号 #${i}`,
      username,
      password,
      url: rawUrl,
      category: inferCategoryFromRecord(title, rawUrl, explicitCat),
      recordType: 'login',
      notes,
      favorite: false,
    });
  }

  if (parsedRecords.length === 0) {
    return {
      format: 'browser-csv',
      status: 'error',
      message: 'CSV 文件中未提取到有效的账号密码行。',
      parsedRecords: [],
    };
  }

  return {
    format: 'browser-csv',
    status: 'ready',
    message: `已成功解析浏览器 CSV 导出文件，共 ${parsedRecords.length} 条记录`,
    parsedRecords,
  };
}

export function getRecordFingerprint(
  record: Pick<
    CandidateRecordInput | DecryptedVaultRecord,
    'title' | 'username' | 'password' | 'url' | 'cardDetails'
  >
): string {
  const cardNum = record.cardDetails?.cardNumber
    ? sanitizeCardNumber(record.cardDetails.cardNumber)
    : '';
  return [
    (record.title || '').trim().toLowerCase(),
    (record.username || '').trim().toLowerCase(),
    record.password || '',
    (record.url || '').trim().toLowerCase().replace(/\/+$/, ''),
    cardNum,
  ].join('|');
}

export function mergeImportedRecords(
  existingRecords: DecryptedVaultRecord[],
  candidates: CandidateRecordInput[],
  strategy: MergeDuplicateStrategy
): {
  mergedRecords: DecryptedVaultRecord[];
  addedCount: number;
  skippedCount: number;
} {
  const seen = new Set(existingRecords.map((r) => getRecordFingerprint(r)));
  const added: DecryptedVaultRecord[] = [];
  let skippedCount = 0;
  const now = Date.now();

  candidates.forEach((cand, idx) => {
    const fp = getRecordFingerprint(cand);
    if (strategy === 'skip-duplicates' && seen.has(fp)) {
      skippedCount++;
      return;
    }
    seen.add(fp);
    added.push({
      id: `rec-imp-${now}-${idx}-${Math.random().toString(36).slice(2, 6)}`,
      recordType: cand.recordType || (cand.cardDetails ? 'card' : 'login'),
      title: cand.title,
      username: cand.username,
      password: cand.password,
      url: cand.url,
      category: cand.category || 'personal',
      tags: cand.tags,
      cardDetails: cand.cardDetails,
      notes: cand.notes || '',
      favorite: Boolean(cand.favorite),
      createdAt: now,
      updatedAt: now,
    });
  });

  return {
    mergedRecords: [...added, ...existingRecords],
    addedCount: added.length,
    skippedCount,
  };
}
