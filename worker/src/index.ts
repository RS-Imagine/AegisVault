/**
 * AegisVault V2 Zero-Knowledge Cloud Sync Worker
 *
 * Security & Consistency Architecture:
 * 1. Mandatory Bearer API_TOKEN authentication (fails closed if unconfigured).
 * 2. Constant-time SHA-256 HMAC digest comparison to mitigate timing attacks.
 * 3. SQLite-backed Durable Object (`VaultDurableObject`) for strong consistency,
 *    atomic revision increments, 409 Conflict protection, and bounded snapshot history.
 * 4. Strict CORS allowlist, HTTP method validation, and 1MB payload limit.
 * 5. Per-IP rate limiting against brute-force token guessing.
 */

import {
  buildCorsHeaders,
  hasForbiddenQueryToken,
  verifyRequestAuthAndRateLimit,
} from './bearerAuth';
import {
  DurableObjectNamespaceLike,
  VaultDurableObject,
} from './VaultDurableObject';
import {
  SINGLETON_DO_INSTANCE_NAME,
  SYNC_PROTOCOL_VERSION,
} from './types';

export { VaultDurableObject };

export interface Env {
  VAULT_DO: DurableObjectNamespaceLike;
  API_TOKEN?: string;
  ALLOWED_ORIGINS?: string;
}

function isSupportedRouteAndMethod(pathname: string, method: string): {
  routeMatched: boolean;
  methodAllowed: boolean;
} {
  if (pathname === '/api/vault') {
    return {
      routeMatched: true,
      methodAllowed: ['HEAD', 'GET', 'PUT', 'OPTIONS'].includes(method),
    };
  }
  if (pathname === '/api/vault/init') {
    return {
      routeMatched: true,
      methodAllowed: ['POST', 'OPTIONS'].includes(method),
    };
  }
  if (pathname === '/api/vault/history') {
    return {
      routeMatched: true,
      methodAllowed: ['GET', 'OPTIONS'].includes(method),
    };
  }
  if (/^\/api\/vault\/history\/\d+$/.test(pathname)) {
    return {
      routeMatched: true,
      methodAllowed: ['GET', 'OPTIONS'].includes(method),
    };
  }
  return { routeMatched: false, methodAllowed: false };
}

function attachHeaders(response: Response, extraHeaders: Record<string, string>): Response {
  const merged = new Headers(response.headers);
  for (const [k, v] of Object.entries(extraHeaders)) {
    merged.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: merged,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const cors = buildCorsHeaders(request, env.ALLOWED_ORIGINS);

    if (!cors.originAllowed) {
      return new Response(JSON.stringify({ error: 'Forbidden: Origin not allowed', code: 'CORS_FORBIDDEN' }), {
        status: 403,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    }

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors.headers });
    }

    if (hasForbiddenQueryToken(url)) {
      return new Response(
        JSON.stringify({
          error: 'Bad Request: API Token must never be passed in URL query parameters',
          code: 'QUERY_TOKEN_FORBIDDEN',
        }),
        { status: 400, headers: cors.headers }
      );
    }

    const routeCheck = isSupportedRouteAndMethod(url.pathname, method);
    if (!routeCheck.routeMatched) {
      return new Response(
        JSON.stringify({ error: 'Not Found', code: 'ROUTE_NOT_FOUND' }),
        { status: 404, headers: cors.headers }
      );
    }
    if (!routeCheck.methodAllowed) {
      return new Response(
        JSON.stringify({ error: 'Method Not Allowed', code: 'METHOD_NOT_ALLOWED' }),
        { status: 405, headers: cors.headers }
      );
    }

    const authOrRateError = verifyRequestAuthAndRateLimit(
      request,
      env.API_TOKEN,
      cors.headers
    );
    if (authOrRateError) {
      return authOrRateError;
    }

    if (!env.VAULT_DO) {
      return new Response(
        JSON.stringify({
          error: 'Service Unavailable: Durable Object binding VAULT_DO is not configured',
          code: 'DO_BINDING_MISSING',
        }),
        { status: 503, headers: cors.headers }
      );
    }

    const doId = env.VAULT_DO.idFromName(SINGLETON_DO_INSTANCE_NAME);
    const stub = env.VAULT_DO.get(doId);
    const doResponse = await stub.fetch(request);

    return attachHeaders(doResponse, {
      ...cors.headers,
      'X-Protocol-Version': String(SYNC_PROTOCOL_VERSION),
    });
  },
};
