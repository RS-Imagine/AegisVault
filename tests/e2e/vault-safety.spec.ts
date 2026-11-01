import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { unlockEncryptedVaultPayload } from '../../src/crypto/cryptoEngine';

const master = 'Browser-Synthetic-Master#2026!';
const fixture = JSON.parse(readFileSync(new URL('../fixtures/v2-vault.json', import.meta.url), 'utf8'));

async function createVault(page: Page) {
  await page.goto('/');
  await page.locator('#master-password-input').fill(master);
  await page.locator('#confirm-master-password-input').fill(master);
  await page.getByRole('button', { name: '创建密码库', exact: true }).click();
  await expect(page.getByRole('button', { name: '新建密码或银行卡', exact: true })).toBeVisible();
}
async function unlock(page: Page, password = master) {
  await page.locator('#master-password-input').fill(password);
  await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
  await expect(page.getByRole('button', { name: '新建密码或银行卡', exact: true })).toBeVisible();
}
async function addRecord(page: Page, title = 'Browser account') {
  await page.getByRole('button', { name: '新建密码或银行卡', exact: true }).click();
  await page.locator('#record-title-input').fill(title);
  await page.locator('#record-category-select').selectOption('work');
  await page.getByPlaceholder('user@example.com', { exact: true }).fill('synthetic@example.invalid');
  await page.getByPlaceholder('输入或使用右侧生成器生成高强度密码...').fill('Synthetic-record-password!');
  await page.getByRole('button', { name: '加密并保存记录', exact: true }).click();
  await expect(page.locator('#record-form-modal-title')).toHaveCount(0);
}
async function storedPayload(page: Page) {
  return page.evaluate(() => JSON.parse(localStorage.getItem('aegis_zk_vault_v2')!));
}
async function injectPayload(page: Page, payload: unknown) {
  await page.evaluate(async (vault) => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open('aegis_vault_v2_db', 1);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('vault_store', 'readwrite');
      tx.objectStore('vault_store').put(vault, 'primary');
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error);
    });
    db.close();
    localStorage.setItem('aegis_zk_vault_v2', JSON.stringify(vault));
  }, payload);
}
async function abortWrites(page: Page, enabled: boolean) {
  await page.evaluate((value) => {
    const state = window as unknown as { __abortWrites?: boolean; __originalTransaction?: typeof IDBDatabase.prototype.transaction };
    state.__abortWrites = value;
    if (!state.__originalTransaction) {
      state.__originalTransaction = IDBDatabase.prototype.transaction;
      IDBDatabase.prototype.transaction = function (...args: Parameters<typeof IDBDatabase.prototype.transaction>) {
        const tx = state.__originalTransaction!.apply(this, args);
        if (state.__abortWrites && args[1] === 'readwrite') queueMicrotask(() => tx.abort());
        return tx;
      };
    }
  }, enabled);
}

test('V2 upgrade commits a recoverable backup, survives an aborted upgrade and reopens offline', async ({ page, context }) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: '创建密码库', exact: true })).toBeVisible();
  await injectPayload(page, fixture);
  await page.reload();
  await unlock(page, 'LegacyFixture#2026!');
  await abortWrites(page, true);
  await page.getByRole('button', { name: '备份并升级到 V3', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  expect((await storedPayload(page)).formatVersion).toBe(2);
  await abortWrites(page, false);
  await page.getByRole('button', { name: '备份并升级到 V3', exact: true }).click();
  await expect.poll(async () => (await storedPayload(page)).formatVersion).toBe(3);
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: '导出升级前的 V2 加密备份', exact: true }).click();
  const file = await downloaded;
  expect(JSON.parse(readFileSync((await file.path())!, 'utf8'))).toEqual(fixture);
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);
  await context.setOffline(true);
  await page.reload();
  await unlock(page, 'LegacyFixture#2026!');
  await expect(page.getByText('旧版中文账号', { exact: true }).first()).toBeVisible();
});

test('an older edit form cannot overwrite a newer record from another tab', async ({ page: first, context }) => {
  await createVault(first);
  await addRecord(first);
  const second = await context.newPage();
  await second.goto('/');
  await unlock(second);
  await first.getByRole('button', { name: '编辑', exact: true }).click();
  await first.locator('#record-title-input').fill('stale first-tab draft');
  await second.getByRole('button', { name: '编辑', exact: true }).click();
  await second.locator('#record-title-input').fill('saved second-tab edit');
  await second.getByRole('button', { name: '加密并更新记录', exact: true }).click();
  await expect(second.locator('#record-form-modal-title')).toHaveCount(0);
  await first.getByRole('button', { name: '加密并更新记录', exact: true }).click();
  await expect(first.getByText(/已阻止覆盖/).first()).toBeVisible();
  await expect(first.locator('#record-title-input')).toHaveValue('stale first-tab draft');
  await first.reload();
  await unlock(first);
  await expect(first.getByText('saved second-tab edit', { exact: true }).first()).toBeVisible();
});

test('an aborted save keeps durable data intact and the encrypted draft can be exported and retried', async ({ page }) => {
  await createVault(page);
  const original = await storedPayload(page);
  await abortWrites(page, true);
  await addRecord(page, 'unsaved but exportable');
  await expect(page.getByTestId('persistence-warning-banner')).toBeVisible();
  expect(await storedPayload(page)).toEqual(original);
  const downloaded = page.waitForEvent('download');
  await page.getByTestId('persistence-warning-banner').getByRole('button', { name: '导出加密备份 (JSON)', exact: true }).click();
  const file = await downloaded;
  const backup = JSON.parse(readFileSync((await file.path())!, 'utf8'));
  const recovered = await unlockEncryptedVaultPayload(backup, master);
  expect(recovered.records[0].title).toBe('unsaved but exportable');
  await abortWrites(page, false);
  await page.getByRole('button', { name: '重试本地保存', exact: true }).click();
  await expect(page.getByTestId('persistence-warning-banner')).toHaveCount(0);
  await page.reload();
  await unlock(page);
  await expect(page.getByText('unsaved but exportable', { exact: true }).first()).toBeVisible();
});

test('a failed localStorage mirror is recovered from the committed IndexedDB snapshot', async ({ page }) => {
  await createVault(page);
  await page.evaluate(() => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      if (key.startsWith('aegis_zk_')) throw new DOMException('Synthetic mirror quota', 'QuotaExceededError');
      original.call(this, key, value);
    };
  });
  await addRecord(page, 'durable despite mirror quota');
  await page.reload();
  await unlock(page);
  await expect(page.getByText('durable despite mirror quota', { exact: true }).first()).toBeVisible();
});

test('removing encrypted records from a V3 snapshot prevents unlock', async ({ page }) => {
  await createVault(page);
  await addRecord(page);
  const payload = await storedPayload(page);
  payload.encryptedRecords = [];
  await injectPayload(page, payload);
  await page.reload();
  await page.locator('#master-password-input').fill(master);
  await page.getByRole('button', { name: '解锁密码库', exact: true }).click();
  await expect(page.getByText(/密码库完整性校验失败/).first()).toBeVisible();
  await expect(page.getByRole('button', { name: '解锁密码库', exact: true })).toBeVisible();
});

test('simultaneous edits are serialized safely even without Web Locks', async ({ page: first, context }) => {
  await context.addInitScript(() => {
    Object.defineProperty(navigator, 'locks', { value: undefined, configurable: true });
  });
  await createVault(first);
  await addRecord(first, 'shared base');
  const second = await context.newPage();
  await second.goto('/');
  await unlock(second);
  await first.getByRole('button', { name: '编辑', exact: true }).click();
  await second.getByRole('button', { name: '编辑', exact: true }).click();
  await first.locator('#record-title-input').fill('concurrent writer A');
  await second.locator('#record-title-input').fill('concurrent writer B');
  await Promise.all([
    first.getByRole('button', { name: '加密并更新记录', exact: true }).click(),
    second.getByRole('button', { name: '加密并更新记录', exact: true }).click(),
  ]);
  await expect.poll(async () => await first.locator('#record-form-modal-title').count() + await second.locator('#record-form-modal-title').count()).toBe(1);
  const payload = await storedPayload(first);
  const unlocked = await unlockEncryptedVaultPayload(payload, master);
  expect(['concurrent writer A', 'concurrent writer B']).toContain(unlocked.records[0].title);
  expect(unlocked.records).toHaveLength(1);
});
