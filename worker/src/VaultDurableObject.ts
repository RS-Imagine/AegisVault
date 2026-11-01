import {
  MAX_HISTORY_SNAPSHOTS,
  MAX_VAULT_BODY_BYTES,
  SYNC_PROTOCOL_VERSION,
  V2EncryptedVaultPayload,
  VaultConflictResponse,
  VaultGetResponse,
  VaultHistoryListResponse,
  VaultHistorySnapshotResponse,
  VaultWriteResponse,
} from './types';
import {
  computeMutationRequestDigest,
  validateInitVaultRequest,
  validatePutVaultRequest,
} from './payloadValidator';

export interface SqlStorageCursor {
  toArray(): Record<string, unknown>[];
}

export interface SqlStorage {
  exec(query: string, ...bindings: unknown[]): SqlStorageCursor;
}

export interface DurableObjectStorageLike {
  sql: SqlStorage;
  transactionSync<T>(closure: () => T): T;
}

export interface DurableObjectStateLike {
  storage: DurableObjectStorageLike;
}

export interface DurableObjectStubLike {
  fetch(request: Request): Promise<Response>;
}

export interface DurableObjectIdLike {
  toString(): string;
}

export interface DurableObjectNamespaceLike {
  idFromName(name: string): DurableObjectIdLike;
  get(id: DurableObjectIdLike): DurableObjectStubLike;
}

interface VaultStateRow {
  singleton_id: number;
  vault_id: string;
  revision: number;
  format_version: number;
  ciphertext_json: string;
  content_sha256: string;
  created_at: string;
  updated_at: string;
}

function jsonResponse(body: unknown, status: number, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Protocol-Version': String(SYNC_PROTOCOL_VERSION),
      ...extraHeaders,
    },
  });
}

async function computeSha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digestBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digestBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function readBoundedJsonBody(request: Request): Promise<
  | { ok: true; rawText: string; parsed: unknown }
  | { ok: false; status: number; errorCode: string; errorMessage: string }
> {
  const contentLengthHeader = request.headers.get('Content-Length');
  if (contentLengthHeader) {
    const declaredLength = Number(contentLengthHeader);
    if (Number.isFinite(declaredLength) && declaredLength > MAX_VAULT_BODY_BYTES) {
      return {
        ok: false,
        status: 413,
        errorCode: 'PAYLOAD_TOO_LARGE',
        errorMessage: 'Payload Too Large: Maximum size is 1MB',
      };
    }
  }

  let rawText = '';
  try {
    rawText = await request.text();
  } catch {
    return {
      ok: false,
      status: 400,
      errorCode: 'BAD_REQUEST_BODY',
      errorMessage: 'Bad Request: Unable to read request body',
    };
  }

  const byteLength = new TextEncoder().encode(rawText).byteLength;
  if (byteLength > MAX_VAULT_BODY_BYTES) {
    return {
      ok: false,
      status: 413,
      errorCode: 'PAYLOAD_TOO_LARGE',
      errorMessage: 'Payload Too Large: Maximum size is 1MB',
    };
  }

  try {
    const parsed = JSON.parse(rawText);
    return { ok: true, rawText, parsed };
  } catch {
    return {
      ok: false,
      status: 400,
      errorCode: 'INVALID_JSON',
      errorMessage: 'Bad Request: Malformed JSON body',
    };
  }
}

export class VaultDurableObject {
  private readonly ctx: DurableObjectStateLike;
  private schemaInitialized = false;

  constructor(ctx: DurableObjectStateLike, _env?: unknown) {
    this.ctx = ctx;
    this.ensureSchema();
  }

  private ensureSchema(): void {
    if (this.schemaInitialized) return;
    const sql = this.ctx.storage.sql;

    sql.exec(`
      CREATE TABLE IF NOT EXISTS vault_state (
        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
        vault_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        format_version INTEGER NOT NULL CHECK (format_version = 2),
        ciphertext_json TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    sql.exec(`
      CREATE TABLE IF NOT EXISTS vault_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vault_id TEXT NOT NULL,
        revision INTEGER NOT NULL UNIQUE,
        ciphertext_json TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_vault_snapshots_revision_desc
      ON vault_snapshots(revision DESC)
    `);

    sql.exec(`
      CREATE TABLE IF NOT EXISTS mutation_log (
        mutation_id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        expected_revision INTEGER NOT NULL,
        resulting_revision INTEGER NOT NULL,
        request_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    this.schemaInitialized = true;
  }

  private getCurrentStateRow(): VaultStateRow | null {
    this.ensureSchema();
    const rows = this.ctx.storage.sql
      .exec(
        `SELECT singleton_id, vault_id, revision, format_version, ciphertext_json, content_sha256, created_at, updated_at
         FROM vault_state
         WHERE singleton_id = 1`
      )
      .toArray();
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
      singleton_id: Number(row.singleton_id),
      vault_id: String(row.vault_id),
      revision: Number(row.revision),
      format_version: Number(row.format_version),
      ciphertext_json: String(row.ciphertext_json),
      content_sha256: String(row.content_sha256),
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
    };
  }

  async fetch(request: Request): Promise<Response> {
    this.ensureSchema();
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method.toUpperCase();

    if (pathname === '/api/vault' && method === 'HEAD') {
      return this.handleHead();
    }

    if (pathname === '/api/vault' && method === 'GET') {
      return this.handleGet();
    }

    if (pathname === '/api/vault/init' && method === 'POST') {
      return this.handleInit(request);
    }

    if (pathname === '/api/vault' && method === 'PUT') {
      return this.handlePut(request);
    }

    if (pathname === '/api/vault/history' && method === 'GET') {
      return this.handleHistoryList();
    }

    const historyMatch = pathname.match(/^\/api\/vault\/history\/(\d+)$/);
    if (historyMatch && method === 'GET') {
      const targetRevision = Number(historyMatch[1]);
      return this.handleHistoryRevision(targetRevision);
    }

    return jsonResponse(
      {
        error: 'Not Found',
        code: 'ROUTE_NOT_FOUND',
      },
      404
    );
  }

  private handleHead(): Response {
    const state = this.getCurrentStateRow();
    if (!state) {
      return new Response(null, {
        status: 200,
        headers: {
          'Cache-Control': 'no-store',
          'X-Protocol-Version': String(SYNC_PROTOCOL_VERSION),
          'X-Vault-Initialized': 'false',
          'X-Vault-Revision': '0',
        },
      });
    }

    return new Response(null, {
      status: 200,
      headers: {
        'Cache-Control': 'no-store',
        'X-Protocol-Version': String(SYNC_PROTOCOL_VERSION),
        'X-Vault-Initialized': 'true',
        'X-Vault-Revision': String(state.revision),
        'X-Vault-Id': state.vault_id,
      },
    });
  }

  private handleGet(): Response {
    const state = this.getCurrentStateRow();
    if (!state) {
      const uninitialized: VaultGetResponse = {
        protocolVersion: SYNC_PROTOCOL_VERSION,
        initialized: false,
        revision: 0,
        vault: null,
      };
      return jsonResponse(uninitialized, 200, {
        'X-Vault-Initialized': 'false',
        'X-Vault-Revision': '0',
      });
    }

    const parsedVault = JSON.parse(state.ciphertext_json) as V2EncryptedVaultPayload;
    const response: VaultGetResponse = {
      protocolVersion: SYNC_PROTOCOL_VERSION,
      initialized: true,
      vaultId: state.vault_id,
      revision: state.revision,
      updatedAt: state.updated_at,
      contentSha256: state.content_sha256,
      vault: parsedVault,
    };
    return jsonResponse(response, 200, {
      'X-Vault-Initialized': 'true',
      'X-Vault-Revision': String(state.revision),
      'X-Vault-Id': state.vault_id,
    });
  }

  private async handleInit(request: Request): Promise<Response> {
    const bodyResult = await readBoundedJsonBody(request);
    if (!bodyResult.ok) {
      return jsonResponse(
        { error: bodyResult.errorMessage, code: bodyResult.errorCode },
        bodyResult.status
      );
    }

    const validation = validateInitVaultRequest(bodyResult.parsed);
    if (!validation.valid || !validation.request) {
      return jsonResponse(
        {
          error: `Unprocessable Entity: ${validation.reason}`,
          code: 'INVALID_INIT_PAYLOAD',
        },
        422
      );
    }

    const initReq = validation.request;
    const canonicalVaultJson = JSON.stringify(initReq.vault);
    const contentSha256 = await computeSha256Hex(canonicalVaultJson);
    const requestDigest = await computeMutationRequestDigest({
      vaultId: initReq.vaultId,
      expectedRevision: 0,
      mutationId: initReq.mutationId,
      vault: initReq.vault,
    });
    const nowIso = new Date().toISOString();

    type InitTxOutcome =
      | { status: 201 | 200; body: VaultWriteResponse }
      | { status: 409; body: VaultConflictResponse };

    const outcome = this.ctx.storage.transactionSync<InitTxOutcome>(() => {
      const sql = this.ctx.storage.sql;

      // Check idempotent replay in mutation_log
      const existingMutations = sql
        .exec(
          `SELECT mutation_id, vault_id, expected_revision, resulting_revision, request_sha256, created_at
           FROM mutation_log
           WHERE mutation_id = ?`,
          initReq.mutationId
        )
        .toArray();

      const currentState = this.getCurrentStateRow();

      if (existingMutations.length > 0) {
        const mut = existingMutations[0];
        if (String(mut.request_sha256) === requestDigest && currentState) {
          return {
            status: 200,
            body: {
              ok: true,
              protocolVersion: SYNC_PROTOCOL_VERSION,
              vaultId: currentState.vault_id,
              revision: Number(mut.resulting_revision),
              updatedAt: String(mut.created_at),
              contentSha256: currentState.content_sha256,
              idempotentReplay: true,
            },
          };
        }

        const currentVault = currentState
          ? (JSON.parse(currentState.ciphertext_json) as V2EncryptedVaultPayload)
          : undefined;
        return {
          status: 409,
          body: {
            error: 'Conflict: mutationId already used with a different request payload',
            code: 'MUTATION_ID_PAYLOAD_MISMATCH',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverVaultId: currentState?.vault_id,
            serverRevision: currentState ? currentState.revision : 0,
            serverUpdatedAt: currentState?.updated_at,
            serverVault: currentVault,
          },
        };
      }

      if (currentState) {
        const currentVault = JSON.parse(currentState.ciphertext_json) as V2EncryptedVaultPayload;
        return {
          status: 409,
          body: {
            error: 'Conflict: Cloud vault is already initialized. Cannot overwrite with /api/vault/init.',
            code: 'ALREADY_INITIALIZED',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverVaultId: currentState.vault_id,
            serverRevision: currentState.revision,
            serverUpdatedAt: currentState.updated_at,
            serverVault: currentVault,
          },
        };
      }

      sql.exec(
        `INSERT INTO vault_state (
          singleton_id, vault_id, revision, format_version, ciphertext_json, content_sha256, created_at, updated_at
        ) VALUES (1, ?, 1, 2, ?, ?, ?, ?)`,
        initReq.vaultId,
        canonicalVaultJson,
        contentSha256,
        nowIso,
        nowIso
      );

      sql.exec(
        `INSERT INTO vault_snapshots (
          vault_id, revision, ciphertext_json, content_sha256, created_at
        ) VALUES (?, 1, ?, ?, ?)`,
        initReq.vaultId,
        canonicalVaultJson,
        contentSha256,
        nowIso
      );

      sql.exec(
        `INSERT INTO mutation_log (
          mutation_id, vault_id, expected_revision, resulting_revision, request_sha256, created_at
        ) VALUES (?, ?, 0, 1, ?, ?)`,
        initReq.mutationId,
        initReq.vaultId,
        requestDigest,
        nowIso
      );

      return {
        status: 201,
        body: {
          ok: true,
          protocolVersion: SYNC_PROTOCOL_VERSION,
          vaultId: initReq.vaultId,
          revision: 1,
          updatedAt: nowIso,
          contentSha256,
        },
      };
    });

    if (outcome.status === 409) {
      return jsonResponse(outcome.body, 409, {
        'X-Vault-Initialized': 'true',
        'X-Vault-Revision': String(outcome.body.serverRevision),
      });
    }

    return jsonResponse(outcome.body, outcome.status, {
      'X-Vault-Initialized': 'true',
      'X-Vault-Revision': String(outcome.body.revision),
      'X-Vault-Id': outcome.body.vaultId,
    });
  }

  private async handlePut(request: Request): Promise<Response> {
    const bodyResult = await readBoundedJsonBody(request);
    if (!bodyResult.ok) {
      return jsonResponse(
        { error: bodyResult.errorMessage, code: bodyResult.errorCode },
        bodyResult.status
      );
    }

    const validation = validatePutVaultRequest(bodyResult.parsed);
    if (!validation.valid || !validation.request) {
      return jsonResponse(
        {
          error: `Unprocessable Entity: ${validation.reason}`,
          code: 'INVALID_PUT_PAYLOAD',
        },
        422
      );
    }

    const putReq = validation.request;
    const canonicalVaultJson = JSON.stringify(putReq.vault);
    const contentSha256 = await computeSha256Hex(canonicalVaultJson);
    const requestDigest = await computeMutationRequestDigest({
      vaultId: putReq.vaultId,
      expectedRevision: putReq.expectedRevision,
      mutationId: putReq.mutationId,
      vault: putReq.vault,
      purgePreviousSnapshots: putReq.purgePreviousSnapshots,
    });
    const nowIso = new Date().toISOString();

    type PutTxOutcome =
      | { status: 200; body: VaultWriteResponse }
      | { status: 409; body: VaultConflictResponse };

    const outcome = this.ctx.storage.transactionSync<PutTxOutcome>(() => {
      const sql = this.ctx.storage.sql;
      const currentState = this.getCurrentStateRow();

      // Check idempotent replay first
      const existingMutations = sql
        .exec(
          `SELECT mutation_id, vault_id, expected_revision, resulting_revision, request_sha256, created_at
           FROM mutation_log
           WHERE mutation_id = ?`,
          putReq.mutationId
        )
        .toArray();

      if (existingMutations.length > 0) {
        const mut = existingMutations[0];
        if (String(mut.request_sha256) === requestDigest && currentState) {
          return {
            status: 200,
            body: {
              ok: true,
              protocolVersion: SYNC_PROTOCOL_VERSION,
              vaultId: currentState.vault_id,
              revision: Number(mut.resulting_revision),
              updatedAt: String(mut.created_at),
              contentSha256: currentState.content_sha256,
              idempotentReplay: true,
            },
          };
        }

        const currentVault = currentState
          ? (JSON.parse(currentState.ciphertext_json) as V2EncryptedVaultPayload)
          : undefined;
        return {
          status: 409,
          body: {
            error: 'Conflict: mutationId already exists with a different payload digest',
            code: 'MUTATION_ID_PAYLOAD_MISMATCH',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverVaultId: currentState?.vault_id,
            serverRevision: currentState ? currentState.revision : 0,
            serverUpdatedAt: currentState?.updated_at,
            serverVault: currentVault,
          },
        };
      }

      if (!currentState) {
        return {
          status: 409,
          body: {
            error: 'Conflict: Cloud vault is not initialized yet. Use POST /api/vault/init first.',
            code: 'VAULT_NOT_INITIALIZED',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverRevision: 0,
          },
        };
      }

      const currentVault = JSON.parse(currentState.ciphertext_json) as V2EncryptedVaultPayload;

      if (currentState.vault_id !== putReq.vaultId) {
        return {
          status: 409,
          body: {
            error: 'Conflict: Remote vaultId does not match local vaultId.',
            code: 'VAULT_ID_MISMATCH',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverVaultId: currentState.vault_id,
            serverRevision: currentState.revision,
            serverUpdatedAt: currentState.updated_at,
            serverVault: currentVault,
          },
        };
      }

      if (currentState.revision !== putReq.expectedRevision) {
        return {
          status: 409,
          body: {
            error: `Conflict: Expected revision ${putReq.expectedRevision}, but cloud is at revision ${currentState.revision}.`,
            code: 'REVISION_CONFLICT',
            protocolVersion: SYNC_PROTOCOL_VERSION,
            serverVaultId: currentState.vault_id,
            serverRevision: currentState.revision,
            serverUpdatedAt: currentState.updated_at,
            serverVault: currentVault,
          },
        };
      }

      const nextRevision = currentState.revision + 1;

      sql.exec(
        `UPDATE vault_state
         SET revision = ?,
             ciphertext_json = ?,
             content_sha256 = ?,
             updated_at = ?
         WHERE singleton_id = 1`,
        nextRevision,
        canonicalVaultJson,
        contentSha256,
        nowIso
      );

      if (putReq.purgePreviousSnapshots) {
        sql.exec(`DELETE FROM vault_snapshots WHERE vault_id = ?`, putReq.vaultId);
      }

      sql.exec(
        `INSERT INTO vault_snapshots (
          vault_id, revision, ciphertext_json, content_sha256, created_at
        ) VALUES (?, ?, ?, ?, ?)`,
        putReq.vaultId,
        nextRevision,
        canonicalVaultJson,
        contentSha256,
        nowIso
      );

      // Retain at most MAX_HISTORY_SNAPSHOTS latest snapshots
      sql.exec(
        `DELETE FROM vault_snapshots
         WHERE id NOT IN (
           SELECT id FROM vault_snapshots
           ORDER BY revision DESC
           LIMIT ?
         )`,
        MAX_HISTORY_SNAPSHOTS
      );

      sql.exec(
        `INSERT INTO mutation_log (
          mutation_id, vault_id, expected_revision, resulting_revision, request_sha256, created_at
        ) VALUES (?, ?, ?, ?, ?, ?)`,
        putReq.mutationId,
        putReq.vaultId,
        putReq.expectedRevision,
        nextRevision,
        requestDigest,
        nowIso
      );

      return {
        status: 200,
        body: {
          ok: true,
          protocolVersion: SYNC_PROTOCOL_VERSION,
          vaultId: putReq.vaultId,
          revision: nextRevision,
          updatedAt: nowIso,
          contentSha256,
        },
      };
    });

    if (outcome.status === 409) {
      return jsonResponse(outcome.body, 409, {
        'X-Vault-Initialized': outcome.body.serverRevision > 0 ? 'true' : 'false',
        'X-Vault-Revision': String(outcome.body.serverRevision),
      });
    }

    return jsonResponse(outcome.body, 200, {
      'X-Vault-Initialized': 'true',
      'X-Vault-Revision': String(outcome.body.revision),
      'X-Vault-Id': outcome.body.vaultId,
    });
  }

  private handleHistoryList(): Response {
    const state = this.getCurrentStateRow();
    if (!state) {
      const emptyResponse: VaultHistoryListResponse = {
        protocolVersion: SYNC_PROTOCOL_VERSION,
        initialized: false,
        currentRevision: 0,
        snapshots: [],
      };
      return jsonResponse(emptyResponse, 200);
    }

    const rows = this.ctx.storage.sql
      .exec(
        `SELECT revision, vault_id, content_sha256, created_at, ciphertext_json
         FROM vault_snapshots
         WHERE vault_id = ?
         ORDER BY revision DESC
         LIMIT ?`,
        state.vault_id,
        MAX_HISTORY_SNAPSHOTS
      )
      .toArray();

    const snapshots = rows.map((row) => {
      let recordCount = 0;
      try {
        const parsed = JSON.parse(String(row.ciphertext_json)) as V2EncryptedVaultPayload;
        recordCount = Array.isArray(parsed.encryptedRecords) ? parsed.encryptedRecords.length : 0;
      } catch {
        recordCount = 0;
      }
      return {
        revision: Number(row.revision),
        vaultId: String(row.vault_id),
        contentSha256: String(row.content_sha256),
        createdAt: String(row.created_at),
        recordCount,
      };
    });

    const response: VaultHistoryListResponse = {
      protocolVersion: SYNC_PROTOCOL_VERSION,
      initialized: true,
      vaultId: state.vault_id,
      currentRevision: state.revision,
      snapshots,
    };

    return jsonResponse(response, 200);
  }

  private handleHistoryRevision(targetRevision: number): Response {
    if (!Number.isInteger(targetRevision) || targetRevision < 1) {
      return jsonResponse(
        { error: 'Bad Request: Invalid revision number', code: 'INVALID_REVISION' },
        400
      );
    }

    const state = this.getCurrentStateRow();
    if (!state) {
      return jsonResponse(
        { error: 'Not Found: Cloud vault is not initialized', code: 'VAULT_NOT_INITIALIZED' },
        404
      );
    }

    const rows = this.ctx.storage.sql
      .exec(
        `SELECT revision, vault_id, ciphertext_json, content_sha256, created_at
         FROM vault_snapshots
         WHERE vault_id = ? AND revision = ?`,
        state.vault_id,
        targetRevision
      )
      .toArray();

    if (rows.length === 0) {
      return jsonResponse(
        {
          error: `Not Found: Snapshot for revision ${targetRevision} is not available`,
          code: 'SNAPSHOT_NOT_FOUND',
        },
        404
      );
    }

    const row = rows[0];
    const snapshotVault = JSON.parse(String(row.ciphertext_json)) as V2EncryptedVaultPayload;
    const response: VaultHistorySnapshotResponse = {
      protocolVersion: SYNC_PROTOCOL_VERSION,
      vaultId: String(row.vault_id),
      revision: Number(row.revision),
      currentRevision: state.revision,
      createdAt: String(row.created_at),
      contentSha256: String(row.content_sha256),
      vault: snapshotVault,
    };

    return jsonResponse(response, 200);
  }
}
