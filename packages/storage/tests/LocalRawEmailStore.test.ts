import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LocalRawEmailStore } from '../src/local/LocalRawEmailStore';
import { Readable } from 'stream';
import fs from 'fs';
import path from 'path';

describe('LocalRawEmailStore', () => {
  const testDir = path.resolve(__dirname, '.test-data');
  let store: LocalRawEmailStore;

  beforeEach(() => {
    store = new LocalRawEmailStore(testDir);
  });

  afterEach(async () => {
    await fs.promises.rm(testDir, { recursive: true, force: true });
  });

  it('should store and retrieve an email', async () => {
    const key = 'org-1/hash123.eml';
    const content = 'Subject: Test\n\nBody';
    
    // Put
    await store.put(key, Readable.from([content]));
    
    // Exists
    const exists = await store.exists(key);
    expect(exists).toBe(true);

    // Get
    const stream = await store.get(key);
    let readContent = '';
    for await (const chunk of stream) {
      readContent += chunk;
    }
    expect(readContent).toBe(content);
  });

  it('should delete an email', async () => {
    const key = 'org-1/hash456.eml';
    await store.put(key, Readable.from(['content']));
    await store.delete(key);
    const exists = await store.exists(key);
    expect(exists).toBe(false);
  });

  it('should reject path traversal attempts', async () => {
    const maliciousKey = '../../etc/passwd';
    await expect(store.put(maliciousKey, Readable.from(['content']))).rejects.toThrow('Path traversal attempt detected');
  });

  it('should return false for non-existent emails', async () => {
    const exists = await store.exists('org-1/non-existent.eml');
    expect(exists).toBe(false);
  });

  it('should throw on get for non-existent emails', async () => {
    await expect(store.get('org-1/non-existent.eml')).rejects.toThrow('Email not found');
  });
});
