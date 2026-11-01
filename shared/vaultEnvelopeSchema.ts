// Encrypted vault envelopes have no plaintext extension fields. Keep this boundary shared by the
// browser importer and sync server so unknown data cannot enter persisted JSON.
const fields = {
  vault: ['formatVersion', 'vaultId', 'createdAt', 'updatedAt', 'kdf', 'cipher', 'verifier', 'encryptedMetadata', 'encryptedRecords', 'snapshotSequence', 'integrity'],
  kdf: ['algorithm', 'hash', 'iterations', 'salt'],
  cipher: ['algorithm', 'keyLength', 'ivLength'],
  blob: ['iv', 'ciphertext'],
  record: ['id', 'recordType', 'createdAt', 'updatedAt', 'iv', 'ciphertext'],
};

export function findUnexpectedEnvelopeField(candidate: Record<string, unknown>): string | null {
  const check = (value: unknown, allowed: string[], path: string): string | null => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const unexpected = Object.keys(value).find((key) => !allowed.includes(key));
    return unexpected ? `${path}.${unexpected}` : null;
  };
  const checks = [
    check(candidate, fields.vault, 'vault'),
    check(candidate.kdf, fields.kdf, 'kdf'),
    check(candidate.cipher, fields.cipher, 'cipher'),
    check(candidate.verifier, fields.blob, 'verifier'),
    check(candidate.encryptedMetadata, fields.blob, 'encryptedMetadata'),
    check(candidate.integrity, fields.blob, 'integrity'),
  ];
  if (Array.isArray(candidate.encryptedRecords)) {
    candidate.encryptedRecords.forEach((record, index) => {
      checks.push(check(record, fields.record, `encryptedRecords[${index}]`));
    });
  }
  return checks.find((result) => result !== null) ?? null;
}

// Stable object-key ordering makes authentication independent of JSON formatting.
// Array order remains significant, including the complete encrypted record list.
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).filter((key) => object[key] !== undefined).sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
