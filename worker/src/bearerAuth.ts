/**
 * AegisVault V2 Worker Authentication, CORS & Rate Limiting Module
 *
 * Security notes:
 * 1. Fail-closed authentication: rejects all requests if `API_TOKEN` is missing or < 16 chars (HTTP 503).
 * 2. Constant-time Bearer token comparison prevents timing side-channel attacks.
 * 3. Rejects any credential passed in URL query strings (`?token=...`) with HTTP 400.
 * 4. Strict CORS origin validation via `ALLOWED_ORIGINS` (never relies on CORS as authentication).
 * 5. In-memory sliding-window rate limiter provides isolate-local brute-force mitigation;
 *    note that Worker isolate memory is not shared globally across edge PoPs, so production
 *    deployments should pair this with Cloudflare WAF Rate Limiting rules.
 */

const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_AUTH_FAILURES_PER_WINDOW = 10;
const MAX_REQUESTS_PER_WINDOW = 120;

interface RateLimitBucket {
  windowStart: number;
  totalCount: number;
  authFailures: number;
}

const rateLimitStore = new Map<string, RateLimitBucket>();

export function resetWorkerRateLimiterForTests(): void {
  rateLimitStore.clear();
}

export function timingSafeEqualStrings(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  const maxLen = Math.max(aBytes.byteLength, bBytes.byteLength);
  let diff = aBytes.byteLength ^ bBytes.byteLength;
  for (let i = 0; i < maxLen; i++) {
    const byteA = i < aBytes.byteLength ? aBytes[i] : 0;
    const byteB = i < bBytes.byteLength ? bBytes[i] : 0;
    diff |= byteA ^ byteB;
  }
  return diff === 0 && aBytes.byteLength > 0;
}

export function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown-ip'
  );
}

export function buildCorsHeaders(
  request: Request,
  allowedOriginsRaw?: string
): { headers: Record<string, string>; originAllowed: boolean } {
  const requestOrigin = request.headers.get('Origin');
  const rawAllowed = (allowedOriginsRaw ?? '').trim();

  const baseHeaders: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers':
      'X-Vault-Initialized, X-Vault-Revision, X-Vault-Id, X-Protocol-Version',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };

  if (!requestOrigin) {
    return { headers: baseHeaders, originAllowed: true };
  }

  if (!rawAllowed) {
    try {
      const parsedOrigin = new URL(requestOrigin);
      const isLocal =
        parsedOrigin.hostname === 'localhost' ||
        parsedOrigin.hostname === '127.0.0.1';
      if (parsedOrigin.protocol === 'https:' || isLocal) {
        return {
          headers: {
            ...baseHeaders,
            'Access-Control-Allow-Origin': requestOrigin,
          },
          originAllowed: true,
        };
      }
    } catch {
      // Invalid Origin header
    }
    return { headers: baseHeaders, originAllowed: false };
  }

  const allowedList = rawAllowed
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  if (allowedList.includes(requestOrigin)) {
    return {
      headers: {
        ...baseHeaders,
        'Access-Control-Allow-Origin': requestOrigin,
      },
      originAllowed: true,
    };
  }

  return { headers: baseHeaders, originAllowed: false };
}

export function hasForbiddenQueryToken(url: URL): boolean {
  return (
    url.searchParams.has('token') ||
    url.searchParams.has('apiToken') ||
    url.searchParams.has('api_token') ||
    url.searchParams.has('key') ||
    url.searchParams.has('auth')
  );
}

export function verifyRequestAuthAndRateLimit(
  request: Request,
  configuredApiToken: string | undefined,
  corsHeaders: Record<string, string>
): Response | null {
  const clientIp = getClientIp(request);
  const now = Date.now();
  let bucket = rateLimitStore.get(clientIp);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
    bucket = { windowStart: now, totalCount: 0, authFailures: 0 };
    rateLimitStore.set(clientIp, bucket);
  }
  bucket.totalCount += 1;

  if (
    bucket.authFailures >= MAX_AUTH_FAILURES_PER_WINDOW ||
    bucket.totalCount > MAX_REQUESTS_PER_WINDOW
  ) {
    return new Response(
      JSON.stringify({
        error: 'Too Many Requests. Please retry later.',
      }),
      {
        status: 429,
        headers: {
          ...corsHeaders,
          'Retry-After': '60',
          'Content-Type': 'application/json',
        },
      }
    );
  }

  const cleanToken =
    typeof configuredApiToken === 'string' ? configuredApiToken.trim() : '';
  if (!cleanToken || cleanToken.length < 16) {
    return new Response(
      JSON.stringify({
        error:
          'Server authentication is not configured. Configure a strong API_TOKEN secret (>= 16 chars).',
      }),
      {
        status: 503,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  const authHeader = request.headers.get('Authorization') || '';
  const bearerPrefix = 'Bearer ';
  const providedToken = authHeader.startsWith(bearerPrefix)
    ? authHeader.slice(bearerPrefix.length).trim()
    : '';

  if (!providedToken || !timingSafeEqualStrings(providedToken, cleanToken)) {
    bucket.authFailures += 1;
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      {
        status: 401,
        headers: {
          ...corsHeaders,
          'WWW-Authenticate': 'Bearer realm="AegisVaultV2"',
          'Content-Type': 'application/json',
        },
      }
    );
  }

  return null;
}
