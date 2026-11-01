import { DecryptedVaultRecord } from '../types/vault';
import { extractDomainFromUrl } from '../utils/brandVisuals';

export type RuntimePlatform = 'windows-portable' | 'android-app' | 'web';

/**
 * Payload sent from Android Native AutofillService / WebView when asking the user
 * whether to save a newly entered account & password into AegisVault.
 */
export interface AndroidSaveCredentialRequest {
  title?: string;
  username: string;
  password: string;
  url?: string;
  androidPackageName?: string;
  notes?: string;
}

/**
 * Lightweight candidate returned to Android AutofillService for a given package/domain.
 */
export interface AndroidAutofillCandidate {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown;
    Capacitor?: {
      isNativePlatform?: () => boolean;
      getPlatform?: () => string;
    };
    AegisAndroidBridge?: {
      saveBackupFile?: (filename: string, jsonContent: string) => boolean;
      onAutofillCandidatesReady?: (candidatesJson: string) => void;
    };
  }
}

/**
 * Detects whether AegisVault is running inside:
 * - Windows True Portable EXE (Tauri v2 WebView2)
 * - Android Native App (Capacitor / Android WebView)
 * - Standard Web Browser / PWA
 */
export function detectRuntimePlatform(): RuntimePlatform {
  if (typeof window === 'undefined') return 'web';

  if (window.__TAURI_INTERNALS__) {
    return 'windows-portable';
  }

  if (
    window.Capacitor?.getPlatform?.() === 'android' ||
    Boolean(window.AegisAndroidBridge) ||
    /Android/i.test(window.navigator.userAgent) &&
      window.matchMedia('(display-mode: standalone)').matches
  ) {
    return 'android-app';
  }

  return 'web';
}

/**
 * Cross-platform encrypted backup file export:
 * 1. If running inside Android Native WebView with AegisAndroidBridge, delegates to native file saver.
 * 2. If running on Android / mobile where <a download="blob:..."> is restricted, uses Web Share API with File if supported.
 * 3. Standard <a download> Blob trigger for Windows Portable WebView2 & Desktop Browsers.
 */
export async function exportBackupFileCrossPlatform(
  jsonString: string,
  filename: string
): Promise<void> {
  if (typeof window === 'undefined') return;

  // 1. Native Android Bridge (if injected by MainActivity)
  if (typeof window.AegisAndroidBridge?.saveBackupFile === 'function') {
    const handled = window.AegisAndroidBridge.saveBackupFile(
      filename,
      jsonString
    );
    if (handled) return;
  }

  const blob = new Blob([jsonString], {
    type: 'application/json;charset=utf-8',
  });

  // 2. Android WebView / Mobile Web Share API fallback when running on Android
  const isAndroidUserAgent = /Android/i.test(window.navigator.userAgent || '');
  if (
    isAndroidUserAgent &&
    typeof window.navigator.canShare === 'function' &&
    typeof window.navigator.share === 'function' &&
    typeof File !== 'undefined'
  ) {
    try {
      const file = new File([blob], filename, {
        type: 'application/json',
      });
      if (window.navigator.canShare({ files: [file] })) {
        await window.navigator.share({
          title: 'AegisVault 加密密码库备份',
          text: filename,
          files: [file],
        });
        return;
      }
    } catch (err) {
      // If user cancelled share sheet, stop; otherwise fall through to <a download>
      if (err instanceof Error && err.name === 'AbortError') {
        return;
      }
    }
  }

  // 3. Standard Desktop / Windows Portable WebView2 Blob Download
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Matches decrypted login records against a target web domain or Android package name.
 * Reserved for future Android AutofillService integration.
 */
export function matchRecordsForAndroidTarget(
  records: DecryptedVaultRecord[],
  query: { domain?: string; androidPackageName?: string }
): AndroidAutofillCandidate[] {
  const targetDomain = (query.domain ?? '').trim().toLowerCase();
  const targetPkg = (query.androidPackageName ?? '').trim().toLowerCase();

  if (!targetDomain && !targetPkg) return [];

  return records
    .filter((rec) => {
      if (rec.recordType === 'card' || rec.category === 'bank-card') {
        return false;
      }
      const recUrl = (rec.url ?? '').trim().toLowerCase();
      const recDomain = (extractDomainFromUrl(rec.url) ?? '').toLowerCase();
      const recTitle = rec.title.toLowerCase();

      if (targetDomain && recDomain) {
        if (
          recDomain === targetDomain ||
          recDomain.endsWith(`.${targetDomain}`) ||
          targetDomain.endsWith(`.${recDomain}`)
        ) {
          return true;
        }
      }

      if (targetPkg) {
        if (
          recUrl.includes(targetPkg) ||
          recUrl === `android://${targetPkg}` ||
          targetPkg.includes(recTitle)
        ) {
          return true;
        }
      }

      return false;
    })
    .map((rec) => ({
      id: rec.id,
      title: rec.title,
      username: rec.username,
      password: rec.password,
      url: rec.url,
    }));
}

/**
 * Normalizes an Android "Save Password to AegisVault" request into a pre-filled draft
 * for RecordFormModal.
 */
export function normalizeAndroidSaveRequest(
  req: AndroidSaveCredentialRequest
): Partial<DecryptedVaultRecord> {
  const pkg = req.androidPackageName?.trim();
  const normalizedUrl =
    req.url?.trim() || (pkg ? `android://${pkg}` : '');
  const domainLabel = extractDomainFromUrl(normalizedUrl) ?? '';
  const inferredTitle =
    req.title?.trim() ||
    domainLabel ||
    (pkg ? pkg.split('.').slice(-1)[0] : '') ||
    '新保存账号';

  return {
    recordType: 'login',
    title: inferredTitle,
    username: req.username ?? '',
    password: req.password ?? '',
    url: normalizedUrl,
    notes:
      req.notes?.trim() ||
      (pkg ? `来自安卓应用自动保存 (${pkg})` : '来自客户端快捷保存'),
  };
}
