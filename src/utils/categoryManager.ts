/**
 * AegisVault V2 Category Manager
 *
 * Zero-Knowledge Metadata Guarantee:
 * Custom categories and tags are NEVER stored in plaintext localStorage.
 * They are encrypted inside `EncryptedVaultPayload.encryptedMetadata` using AES-256-GCM
 * with AAD binding (`aegis-v2:metadata:${vaultId}:2`).
 */

import {
  DEFAULT_CATEGORIES,
  DecryptedVaultRecord,
  FilterCategory,
  VaultCategoryItem,
} from '../types/vault';

export function getInitialDefaultCategories(): VaultCategoryItem[] {
  return DEFAULT_CATEGORIES.map((c) => ({ ...c }));
}

export function sanitizeCategoriesList(
  candidate: VaultCategoryItem[] | undefined | null
): VaultCategoryItem[] {
  const result: VaultCategoryItem[] = [];
  const seenIds = new Set<string>();
  const seenLabels = new Set<string>();

  const source = Array.isArray(candidate) && candidate.length > 0
    ? candidate
    : DEFAULT_CATEGORIES;

  // Ensure default fallback 'other' is always present
  for (const item of source) {
    if (!item || typeof item !== 'object') continue;
    const id = String(item.id || '').trim();
    const label = String(item.label || '').trim();
    if (!id || !label || label.length > 28) continue;
    const lowerId = id.toLowerCase();
    const lowerLabel = label.toLowerCase();
    if (seenIds.has(lowerId) || seenLabels.has(lowerLabel)) continue;

    seenIds.add(lowerId);
    seenLabels.add(lowerLabel);
    result.push({
      id,
      label,
      isSystem: Boolean(item.isSystem),
      isFallback: Boolean(item.isFallback || id === 'other'),
    });
  }

  for (const def of DEFAULT_CATEGORIES) {
    if (!seenIds.has(def.id.toLowerCase()) && !seenLabels.has(def.label.toLowerCase())) {
      seenIds.add(def.id.toLowerCase());
      seenLabels.add(def.label.toLowerCase());
      result.push({ ...def });
    }
  }

  return result;
}

export function getCategoryDisplayLabel(
  categoryIdOrLabel: string,
  categories: VaultCategoryItem[] = DEFAULT_CATEGORIES
): string {
  const trimmed = (categoryIdOrLabel || '').trim();
  if (!trimmed) return '其他';
  const match = categories.find(
    (c) =>
      c.id.toLowerCase() === trimmed.toLowerCase() ||
      c.label.toLowerCase() === trimmed.toLowerCase()
  );
  return match ? match.label : trimmed;
}

export function recordMatchesCategoryFilter(
  record: DecryptedVaultRecord,
  filter: FilterCategory,
  categories: VaultCategoryItem[] = DEFAULT_CATEGORIES
): boolean {
  if (filter === 'all') return true;
  if (filter === 'favorites') return Boolean(record.favorite);

  const targetCat = categories.find((c) => c.id === filter);
  const targetIdLower = filter.toLowerCase();
  const targetLabelLower = targetCat ? targetCat.label.toLowerCase() : targetIdLower;

  const recCatLower = (record.category || '').toLowerCase();
  if (recCatLower === targetIdLower || recCatLower === targetLabelLower) {
    return true;
  }

  if (Array.isArray(record.tags)) {
    return record.tags.some((t) => {
      const tl = t.trim().toLowerCase();
      return tl === targetIdLower || tl === targetLabelLower;
    });
  }

  return false;
}

export function computeCategoryCounts(
  records: DecryptedVaultRecord[],
  categories: VaultCategoryItem[] = DEFAULT_CATEGORIES
): Record<string, number> {
  const counts: Record<string, number> = {
    all: records.length,
    favorites: records.filter((r) => r.favorite).length,
  };

  for (const cat of categories) {
    counts[cat.id] = records.filter((r) =>
      recordMatchesCategoryFilter(r, cat.id, categories)
    ).length;
  }

  return counts;
}

export function syncCategoriesWithRecords(
  currentCategories: VaultCategoryItem[],
  records: DecryptedVaultRecord[]
): VaultCategoryItem[] {
  const next = [...sanitizeCategoriesList(currentCategories)];
  const existingIds = new Set(next.map((c) => c.id.toLowerCase()));
  const existingLabels = new Set(next.map((c) => c.label.toLowerCase()));

  const ensureTagOrCategory = (raw: string) => {
    const trimmed = (raw || '').trim();
    if (!trimmed) return;
    const lower = trimmed.toLowerCase();
    if (existingIds.has(lower) || existingLabels.has(lower)) return;

    const newItem: VaultCategoryItem = {
      id: trimmed,
      label: trimmed,
      isSystem: false,
    };
    existingIds.add(lower);
    existingLabels.add(lower);

    const otherIdx = next.findIndex((c) => c.isFallback || c.id === 'other');
    if (otherIdx >= 0) {
      next.splice(otherIdx, 0, newItem);
    } else {
      next.push(newItem);
    }
  };

  for (const rec of records) {
    if (rec.category) ensureTagOrCategory(rec.category);
    if (Array.isArray(rec.tags)) {
      rec.tags.forEach(ensureTagOrCategory);
    }
  }

  return next;
}

export function createCustomCategory(
  currentCategories: VaultCategoryItem[],
  rawLabel: string
): { categories: VaultCategoryItem[]; created: VaultCategoryItem } {
  const trimmed = rawLabel.trim();
  if (!trimmed) {
    throw new Error('分类或标签名称不能为空');
  }
  if (trimmed.length > 20) {
    throw new Error('分类或标签名称不能超过 20 个字符');
  }

  const lower = trimmed.toLowerCase();
  if (lower === 'all' || lower === 'favorites' || lower === '全部' || lower === '收藏') {
    throw new Error(`“${trimmed}”为系统保留视图名称`);
  }

  const existing = currentCategories.find(
    (c) => c.id.toLowerCase() === lower || c.label.toLowerCase() === lower
  );
  if (existing) {
    throw new Error(`分类或标签“${trimmed}”已存在`);
  }

  const created: VaultCategoryItem = {
    id: `cat-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 5)}`,
    label: trimmed,
    isSystem: false,
  };

  const next = [...currentCategories];
  const otherIdx = next.findIndex((c) => c.isFallback || c.id === 'other');
  if (otherIdx >= 0) {
    next.splice(otherIdx, 0, created);
  } else {
    next.push(created);
  }

  return { categories: next, created };
}

export function renameCustomCategory(
  currentCategories: VaultCategoryItem[],
  records: DecryptedVaultRecord[],
  targetId: string,
  rawNewLabel: string
): {
  categories: VaultCategoryItem[];
  updatedRecords: DecryptedVaultRecord[];
  recordsChanged: boolean;
} {
  const trimmed = rawNewLabel.trim();
  if (!trimmed) {
    throw new Error('重命名后的分类标签名称不能为空');
  }
  if (trimmed.length > 20) {
    throw new Error('分类标签名称不能超过 20 个字符');
  }

  const target = currentCategories.find((c) => c.id === targetId);
  if (!target) {
    throw new Error('未找到要重命名的分类标签');
  }

  const duplicate = currentCategories.find(
    (c) =>
      c.id !== targetId &&
      (c.label.toLowerCase() === trimmed.toLowerCase() ||
        c.id.toLowerCase() === trimmed.toLowerCase())
  );
  if (duplicate) {
    throw new Error(`分类标签名称“${trimmed}”已存在`);
  }

  const oldLabelLower = target.label.toLowerCase();
  const targetIdLower = target.id.toLowerCase();

  const nextCategories = currentCategories.map((c) =>
    c.id === targetId ? { ...c, label: trimmed } : c
  );

  let recordsChanged = false;
  const now = Date.now();
  const updatedRecords = records.map((rec) => {
    let changed = false;
    let nextCategory = rec.category;

    if (
      !target.isSystem &&
      (rec.category.toLowerCase() === oldLabelLower ||
        rec.category.toLowerCase() === targetIdLower)
    ) {
      nextCategory = target.id;
      changed = true;
    }

    let nextTags = rec.tags;
    if (Array.isArray(rec.tags) && rec.tags.length > 0) {
      const mappedTags = rec.tags.map((t) => {
        if (
          t.trim().toLowerCase() === oldLabelLower ||
          t.trim().toLowerCase() === targetIdLower
        ) {
          changed = true;
          return trimmed;
        }
        return t;
      });
      nextTags = Array.from(new Set(mappedTags));
    }

    if (changed) {
      recordsChanged = true;
      return {
        ...rec,
        category: nextCategory,
        tags: nextTags,
        updatedAt: now,
      };
    }
    return rec;
  });

  return { categories: nextCategories, updatedRecords, recordsChanged };
}

export function deleteCustomCategory(
  currentCategories: VaultCategoryItem[],
  records: DecryptedVaultRecord[],
  targetId: string
): {
  categories: VaultCategoryItem[];
  updatedRecords: DecryptedVaultRecord[];
  recordsChanged: boolean;
} {
  const target = currentCategories.find((c) => c.id === targetId);
  if (!target) {
    throw new Error('未找到要删除的分类标签');
  }
  if (target.isFallback || target.id === 'other') {
    throw new Error('系统兜底分类“其他”不可删除');
  }

  const nextCategories = currentCategories.filter((c) => c.id !== targetId);
  const oldLabelLower = target.label.toLowerCase();
  const targetIdLower = target.id.toLowerCase();

  let recordsChanged = false;
  const now = Date.now();
  const updatedRecords = records.map((rec) => {
    let changed = false;
    let nextCategory = rec.category;

    if (
      rec.category.toLowerCase() === targetIdLower ||
      rec.category.toLowerCase() === oldLabelLower
    ) {
      nextCategory = 'other';
      changed = true;
    }

    let nextTags = rec.tags;
    if (Array.isArray(rec.tags) && rec.tags.length > 0) {
      const filtered = rec.tags.filter(
        (t) =>
          t.trim().toLowerCase() !== oldLabelLower &&
          t.trim().toLowerCase() !== targetIdLower
      );
      if (filtered.length !== rec.tags.length) {
        nextTags = filtered;
        changed = true;
      }
    }

    if (changed) {
      recordsChanged = true;
      return {
        ...rec,
        category: nextCategory,
        tags: nextTags,
        updatedAt: now,
      };
    }
    return rec;
  });

  return { categories: nextCategories, updatedRecords, recordsChanged };
}
