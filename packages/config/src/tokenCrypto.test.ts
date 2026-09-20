import { describe, it, expect } from 'vitest';
import { encryptToken, decryptToken, TokenDecryptionError } from './tokenCrypto';

const KEY = 'a-sufficiently-long-test-encryption-key-1234567890';
const OTHER_KEY = 'a-completely-different-test-encryption-key-abcdefg';

describe('encryptToken / decryptToken', () => {
  it('round-trips a plaintext token exactly', () => {
    const plaintext = 'ya29.a0AfH6SMB-real-looking-access-token-value';
    const encrypted = encryptToken(plaintext, KEY);
    expect(decryptToken(encrypted, KEY)).toBe(plaintext);
  });

  it('the ciphertext never contains the plaintext token', () => {
    const plaintext = 'my-super-secret-refresh-token-abc123';
    const encrypted = encryptToken(plaintext, KEY);
    expect(encrypted).not.toContain(plaintext);
  });

  it('encrypting the same plaintext twice yields different ciphertext (random IV)', () => {
    const plaintext = 'same-token-value';
    const a = encryptToken(plaintext, KEY);
    const b = encryptToken(plaintext, KEY);
    expect(a).not.toBe(b);
    expect(decryptToken(a, KEY)).toBe(plaintext);
    expect(decryptToken(b, KEY)).toBe(plaintext);
  });

  it('fails authentication (throws) when the ciphertext has been tampered with', () => {
    const encrypted = encryptToken('token-value', KEY);
    const parts = encrypted.split(':');
    // Flip a hex character in the ciphertext portion.
    const tamperedHex = parts[3].slice(0, -1) + (parts[3].slice(-1) === '0' ? '1' : '0');
    const tampered = [parts[0], parts[1], parts[2], tamperedHex].join(':');
    expect(() => decryptToken(tampered, KEY)).toThrow(TokenDecryptionError);
  });

  it('fails authentication (throws) when the auth tag has been tampered with', () => {
    const encrypted = encryptToken('token-value', KEY);
    const parts = encrypted.split(':');
    const tamperedTag = parts[2].slice(0, -1) + (parts[2].slice(-1) === '0' ? '1' : '0');
    const tampered = [parts[0], tamperedTag, parts[2], parts[3]].join(':');
    expect(() => decryptToken(tampered, KEY)).toThrow(TokenDecryptionError);
  });

  it('fails with the wrong key rather than returning garbage plaintext', () => {
    const encrypted = encryptToken('token-value', KEY);
    expect(() => decryptToken(encrypted, OTHER_KEY)).toThrow(TokenDecryptionError);
  });

  it('rejects a malformed envelope (wrong segment count)', () => {
    expect(() => decryptToken('not-a-valid-envelope', KEY)).toThrow(TokenDecryptionError);
  });

  it('rejects an unrecognized format version', () => {
    const encrypted = encryptToken('token-value', KEY);
    const parts = encrypted.split(':');
    const wrongVersion = ['v2', parts[1], parts[2], parts[3]].join(':');
    expect(() => decryptToken(wrongVersion, KEY)).toThrow(TokenDecryptionError);
  });

  it('rejects non-hex garbage in the ciphertext/iv/tag segments', () => {
    expect(() => decryptToken('v1:not-hex:not-hex:not-hex', KEY)).toThrow(TokenDecryptionError);
  });
});
