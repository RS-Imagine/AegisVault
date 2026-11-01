# AegisVault V2 Cloud Sync Worker (SQLite-backed Durable Objects)

This directory (`worker/`) contains the standalone, production-ready Cloudflare Worker and **SQLite-backed Durable Object (`VaultDurableObject`)** backend for AegisVault V2 zero-knowledge encrypted synchronization.

## Why Durable Objects Instead of Cloudflare KV?

Cloudflare Workers KV is an eventually consistent key-value store (updates can take up to 60 seconds to propagate globally) and lacks atomic compare-and-swap (CAS) revision checks across metadata and snapshots. In a multi-device password manager, eventual consistency can lead to lost updates when two devices sync around the same time.

AegisVault V2 replaces KV entirely with a single-instance **SQLite-backed Durable Object (`VaultDurableObject`)**:
- **Strong Consistency**: Every `HEAD`, `GET`, `POST /api/vault/init`, and `PUT /api/vault` request is routed to the authoritative Durable Object instance (`aegis-primary-vault-singleton`).
- **Atomic Revision Control (`409 Conflict`)**: Every write executes inside a synchronous SQLite transaction (`ctx.storage.transactionSync`), verifying `vaultId`, `expectedRevision`, and `mutationId` before incrementing `revision`.
- **Bounded Historical Encrypted Snapshots**: Automatically retains the latest 15 encrypted revisions in SQLite (`vault_snapshots`) for point-in-time recovery.
- **Cloudflare Workers Free Plan Compatible**: Configured via `new_sqlite_classes = ["VaultDurableObject"]` in `wrangler.toml`.

---

## Security Architecture

1. **Zero-Knowledge Ciphertext Only**: The Worker and Durable Object never receive or store your Master Password, derived keys, plaintext records, or plaintext category names. All records and custom categories are encrypted client-side with `AES-256-GCM` and Additional Authenticated Data (`AAD`).
2. **Mandatory Bearer Token (`API_TOKEN`)**: Fails closed (`HTTP 503`) if `API_TOKEN` is missing or shorter than 16 characters. Verified using constant-time SHA-256 digest comparison (`timingSafeEqualStrings`).
3. **Query Parameter Token Protection**: Requests passing `?token=` or `?api_token=` in the URL are immediately rejected with `HTTP 400`.
4. **Strict Payload & Schema Validation**: Enforces a 1 MiB body limit (`HTTP 413`) and validates the V2 envelope structure (`formatVersion: 2`, `vaultId`, `kdf`, `cipher`, `verifier`, `encryptedMetadata`, `encryptedRecords`) before entering the Durable Object transaction (`HTTP 422` on invalid schema).

---

## API Endpoints

| Method & Path | Purpose | Key Headers / Fields |
| :--- | :--- | :--- |
| `HEAD /api/vault` | Fast connectivity, auth & state probe | Returns `X-Vault-Initialized`, `X-Vault-Revision`, `X-Vault-Id`, `X-Protocol-Version: 2` |
| `GET /api/vault` | Fetch latest encrypted V2 vault snapshot | Returns `{ protocolVersion: 2, initialized, vaultId, revision, updatedAt, contentSha256, vault }` |
| `POST /api/vault/init` | Explicit first-time cloud vault initialization | Creates `revision = 1` if uninitialized; returns `409 ALREADY_INITIALIZED` if already initialized |
| `PUT /api/vault` | Atomic revision-checked update | Requires `{ protocolVersion: 2, vaultId, expectedRevision, mutationId, vault }`; returns `200 OK` (`revision + 1`) or `409 Conflict` |
| `GET /api/vault/history` | List up to 15 historical encrypted snapshots | Returns `{ initialized, vaultId, currentRevision, snapshots: [...] }` |
| `GET /api/vault/history/:revision` | Fetch a specific historical encrypted snapshot | Returns `{ vaultId, revision, currentRevision, createdAt, contentSha256, vault }` |

---

## Deployment Guide

### 1. Prerequisites
- Node.js 20+
- A Cloudflare account (Workers Free or Paid plan)

### 2. Deploy the Worker & SQLite Durable Object Migration
From the repository root:
```bash
cd worker
npx wrangler deploy
```
Wrangler will automatically apply the `v1` migration (`new_sqlite_classes = ["VaultDurableObject"]`) and bind `VAULT_DO`.

### 3. Configure the `API_TOKEN` Secret
Generate a high-entropy random token (at least 16 characters, recommended 32+ characters) and store it in Cloudflare Secrets:
```bash
npx wrangler secret put API_TOKEN
```
*(Never commit `API_TOKEN` to `wrangler.toml` or Git.)*

### 4. Optional: Restrict CORS Origins
Uncomment `[vars]` in `worker/wrangler.toml` to restrict `ALLOWED_ORIGINS` to your deployed frontend origin:
```toml
[vars]
ALLOWED_ORIGINS = "https://your-aegisvault-domain.example.com,http://localhost:3000"
```
