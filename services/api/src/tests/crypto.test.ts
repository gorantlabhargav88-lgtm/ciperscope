import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword, generateOpaqueToken } from '../utils/crypto';

describe('Crypto Utilities', () => {
  it('should hash and verify a password correctly using Argon2', async () => {
    const password = 'SuperSecurePassword123!';
    const hash = await hashPassword(password);
    
    expect(hash).toBeDefined();
    expect(hash).not.toEqual(password);
    expect(hash.startsWith('$argon2id')).toBe(true);

    const isValid = await verifyPassword(hash, password);
    expect(isValid).toBe(true);
  }, 10000);

  it('should fail to verify with an incorrect password', async () => {
    const hash = await hashPassword('correctPassword');
    const isValid = await verifyPassword(hash, 'wrongPassword');
    expect(isValid).toBe(false);
  }, 10000);

  it('should generate a secure random opaque token', () => {
    const token1 = generateOpaqueToken();
    const token2 = generateOpaqueToken();

    expect(token1).toBeDefined();
    expect(token1.length).toBe(64); // 32 bytes hex encoded = 64 chars
    expect(token1).not.toEqual(token2);
  });
});
